//! Bounded blocking workers for cryptographic jobs.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use tokio::sync::oneshot;

use crate::CryptoWorkerError;

/// Worst-case memory reservation charged for each active crypto worker.
pub const CRYPTO_WORKER_RESERVED_BYTES: u64 = 75_497_472;
/// Physical ingress slots reserved for each active crypto worker.
pub const CRYPTO_QUEUE_SLOTS_PER_WORKER: usize = 2;

/// Admission class with its own bounded queue budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobClass {
    /// Channel/E2EE cryptographic work.
    Channel,
    /// OPAQUE, account HPKE, and password-KSF work.
    Opaque,
}

/// One owned blocking job executed outside Tokio runtime workers.
pub trait CryptoJob: Send + 'static {
    /// Job output returned through the asynchronous completion channel.
    type Output: Send + 'static;

    /// Selects the independently bounded admission class.
    fn class(&self) -> JobClass;

    /// Performs the blocking work on an operating-system worker thread.
    fn execute(self) -> Self::Output;
}

/// Runtime-facing nonblocking submission interface.
pub trait CryptoPort<J: CryptoJob> {
    /// Admits a job immediately or returns it unchanged with a closed reason.
    fn try_submit(&self, job: J) -> Result<JobHandle<J::Output>, CryptoSubmissionError<J>>;
}

/// A failed admission that preserves ownership of the unstarted job.
pub struct CryptoSubmissionError<J> {
    reason: CryptoWorkerError,
    job: J,
}

impl<J> CryptoSubmissionError<J> {
    /// Returns the public-safe admission failure.
    #[must_use]
    pub const fn reason(&self) -> CryptoWorkerError {
        self.reason
    }

    /// Recovers the exact job that was never admitted.
    #[must_use]
    pub fn into_job(self) -> J {
        self.job
    }
}

/// Validated fixed worker and queue limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CryptoWorkerConfig {
    channel_job_limit: usize,
    opaque_job_limit: usize,
    workers: usize,
}

impl CryptoWorkerConfig {
    /// Validates the protocol configuration ranges and worker-to-queue bound.
    pub const fn new(
        channel_job_limit: usize,
        opaque_job_limit: usize,
        workers: usize,
    ) -> Result<Self, CryptoWorkerError> {
        if channel_job_limit == 0
            || channel_job_limit > 64
            || opaque_job_limit == 0
            || opaque_job_limit > 128
            || workers == 0
            || workers > 128
        {
            return Err(CryptoWorkerError::InvalidConfiguration);
        }
        let Some(total_job_limit) = channel_job_limit.checked_add(opaque_job_limit) else {
            return Err(CryptoWorkerError::InvalidConfiguration);
        };
        if workers > total_job_limit {
            return Err(CryptoWorkerError::InvalidConfiguration);
        }
        Ok(Self {
            channel_job_limit,
            opaque_job_limit,
            workers,
        })
    }

    /// Returns the complete memory reservation required before pool startup.
    pub fn reserved_memory_bytes(self) -> Result<u64, CryptoWorkerError> {
        let Ok(workers) = u64::try_from(self.workers) else {
            return Err(CryptoWorkerError::InvalidConfiguration);
        };
        let Some(bytes) = workers.checked_mul(CRYPTO_WORKER_RESERVED_BYTES) else {
            return Err(CryptoWorkerError::InvalidConfiguration);
        };
        Ok(bytes)
    }

    fn physical_queue_capacity(self) -> Result<usize, CryptoWorkerError> {
        self.workers
            .checked_mul(CRYPTO_QUEUE_SLOTS_PER_WORKER)
            .ok_or(CryptoWorkerError::InvalidConfiguration)
    }
}

impl Default for CryptoWorkerConfig {
    fn default() -> Self {
        Self {
            channel_job_limit: 4,
            opaque_job_limit: 8,
            workers: 4,
        }
    }
}

struct AdmissionCounters {
    channel: AtomicUsize,
    opaque: AtomicUsize,
    config: CryptoWorkerConfig,
}

impl AdmissionCounters {
    fn try_acquire(&self, class: JobClass) -> bool {
        let (counter, limit) = match class {
            JobClass::Channel => (&self.channel, self.config.channel_job_limit),
            JobClass::Opaque => (&self.opaque, self.config.opaque_job_limit),
        };
        counter
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < limit).then_some(current + 1)
            })
            .is_ok()
    }

    fn release(&self, class: JobClass) -> bool {
        let counter = match class {
            JobClass::Channel => &self.channel,
            JobClass::Opaque => &self.opaque,
        };
        counter
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_sub(1)
            })
            .is_ok()
    }
}

struct WorkItem<J: CryptoJob> {
    job: J,
    class: JobClass,
    cancelled: Arc<AtomicBool>,
    completion: oneshot::Sender<Result<J::Output, CryptoWorkerError>>,
}

/// Fixed-size blocking pool with immediate bounded admission.
pub struct BoundedCryptoPool<J: CryptoJob> {
    sender: Option<SyncSender<WorkItem<J>>>,
    workers: Vec<JoinHandle<()>>,
    counters: Arc<AdmissionCounters>,
    failed: Arc<AtomicBool>,
    shutting_down: Arc<AtomicBool>,
}

/// Pollable ownership of crypto worker threads after admission has closed.
///
/// Normal async shutdown polls until every worker is finished. Dropping is a
/// joined synchronous fallback for startup failure paths outside Tokio.
pub struct CryptoPoolShutdown {
    workers: Vec<JoinHandle<()>>,
}

impl Drop for CryptoPoolShutdown {
    fn drop(&mut self) {
        for worker in self.workers.drain(..) {
            let _join_result = worker.join();
        }
    }
}

impl CryptoPoolShutdown {
    /// Joins workers that have already finished and reports whether all are joined.
    pub fn try_complete(&mut self) -> bool {
        while self.workers.last().is_some_and(JoinHandle::is_finished) {
            let Some(worker) = self.workers.pop() else {
                break;
            };
            let _join_result = worker.join();
        }
        self.workers.is_empty()
    }

    fn wait(mut self) {
        for worker in self.workers.drain(..) {
            let _join_result = worker.join();
        }
    }
}

impl<J: CryptoJob> BoundedCryptoPool<J> {
    /// Starts exactly the validated number of named OS worker threads.
    pub fn start(config: CryptoWorkerConfig) -> Result<Self, CryptoWorkerError> {
        // Only the u64 product is validated here; the pool reserves no memory itself.
        // Stage 06 admission accounting charges this reservation before start.
        let _reserved_bytes = config.reserved_memory_bytes()?;
        let queue_capacity = config.physical_queue_capacity()?;
        let (sender, receiver) = sync_channel(queue_capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        let counters = Arc::new(AdmissionCounters {
            channel: AtomicUsize::new(0),
            opaque: AtomicUsize::new(0),
            config,
        });
        let failed = Arc::new(AtomicBool::new(false));
        let shutting_down = Arc::new(AtomicBool::new(false));
        let mut workers: Vec<JoinHandle<()>> = Vec::new();
        workers
            .try_reserve_exact(config.workers)
            .map_err(|_| CryptoWorkerError::InvalidConfiguration)?;

        for worker_index in 0..config.workers {
            let worker_receiver = Arc::clone(&receiver);
            let worker_counters = Arc::clone(&counters);
            let worker_failed = Arc::clone(&failed);
            let worker_shutting_down = Arc::clone(&shutting_down);
            let thread_name = format!("agenc-crypto-{worker_index}");
            let spawned = thread::Builder::new().name(thread_name).spawn(move || {
                worker_loop(
                    &worker_receiver,
                    &worker_counters,
                    &worker_failed,
                    &worker_shutting_down,
                );
            });
            let Ok(handle) = spawned else {
                shutting_down.store(true, Ordering::Release);
                drop(sender);
                for handle in workers {
                    let _join_result = handle.join();
                }
                return Err(CryptoWorkerError::WorkerSpawnFailed);
            };
            workers.push(handle);
        }

        Ok(Self {
            sender: Some(sender),
            workers,
            counters,
            failed,
            shutting_down,
        })
    }

    /// Refuses new work and joins every worker once its in-flight job finishes.
    ///
    /// This blocks the calling thread for up to one full job per worker, so a
    /// Tokio caller should run it through the runtime's blocking pool. Dropping
    /// the pool performs the same join.
    pub fn shutdown(self) {
        self.into_shutdown().wait();
    }

    /// Refuses new work and transfers workers into a nonblocking shutdown value.
    #[must_use]
    pub fn into_shutdown(mut self) -> CryptoPoolShutdown {
        self.shutting_down.store(true, Ordering::Release);
        drop(self.sender.take());
        CryptoPoolShutdown {
            workers: std::mem::take(&mut self.workers),
        }
    }

    fn join_workers(&mut self) {
        self.shutting_down.store(true, Ordering::Release);
        drop(self.sender.take());
        for handle in self.workers.drain(..) {
            let _join_result = handle.join();
        }
    }
}

impl<J: CryptoJob> CryptoPort<J> for BoundedCryptoPool<J> {
    fn try_submit(&self, job: J) -> Result<JobHandle<J::Output>, CryptoSubmissionError<J>> {
        if self.shutting_down.load(Ordering::Acquire) {
            return Err(CryptoSubmissionError {
                reason: CryptoWorkerError::ShuttingDown,
                job,
            });
        }
        if self.failed.load(Ordering::Acquire) {
            return Err(CryptoSubmissionError {
                reason: CryptoWorkerError::WorkerPanicked,
                job,
            });
        }
        let class = job.class();
        if !self.counters.try_acquire(class) {
            return Err(CryptoSubmissionError {
                reason: CryptoWorkerError::QueueFull,
                job,
            });
        }
        let (completion, receiver) = oneshot::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let item = WorkItem {
            job,
            class,
            cancelled: Arc::clone(&cancelled),
            completion,
        };
        let Some(sender) = self.sender.as_ref() else {
            if !self.counters.release(class) {
                self.failed.store(true, Ordering::Release);
            }
            return Err(CryptoSubmissionError {
                reason: CryptoWorkerError::ShuttingDown,
                job: item.job,
            });
        };
        match sender.try_send(item) {
            Ok(()) => Ok(JobHandle {
                receiver: Some(receiver),
                cancelled,
            }),
            Err(TrySendError::Full(item)) => {
                let reason = if self.counters.release(class) {
                    CryptoWorkerError::QueueFull
                } else {
                    self.failed.store(true, Ordering::Release);
                    CryptoWorkerError::WorkerPanicked
                };
                Err(CryptoSubmissionError {
                    reason,
                    job: item.job,
                })
            }
            Err(TrySendError::Disconnected(item)) => {
                let reason = if self.counters.release(class) {
                    CryptoWorkerError::ShuttingDown
                } else {
                    self.failed.store(true, Ordering::Release);
                    CryptoWorkerError::WorkerPanicked
                };
                Err(CryptoSubmissionError {
                    reason,
                    job: item.job,
                })
            }
        }
    }
}

fn worker_loop<J: CryptoJob>(
    receiver: &Mutex<Receiver<WorkItem<J>>>,
    counters: &AdmissionCounters,
    failed: &AtomicBool,
    shutting_down: &AtomicBool,
) {
    loop {
        let item = match receiver.lock() {
            Ok(receiver) => receiver.recv(),
            Err(poisoned) => {
                failed.store(true, Ordering::Release);
                poisoned.into_inner().recv()
            }
        };
        let Ok(item) = item else {
            return;
        };
        let WorkItem {
            job,
            class,
            cancelled,
            completion,
        } = item;
        let mut outcome = execute_crypto_job(job, &cancelled, failed, shutting_down);
        if !counters.release(class) {
            failed.store(true, Ordering::Release);
            outcome = Err(CryptoWorkerError::WorkerPanicked);
        }
        let _send_result = completion.send(outcome);
    }
}

fn execute_crypto_job<J: CryptoJob>(
    job: J,
    cancelled: &AtomicBool,
    failed: &AtomicBool,
    shutting_down: &AtomicBool,
) -> Result<J::Output, CryptoWorkerError> {
    if failed.load(Ordering::Acquire) {
        return Err(CryptoWorkerError::WorkerPanicked);
    }
    if shutting_down.load(Ordering::Acquire) {
        return Err(CryptoWorkerError::ShuttingDown);
    }
    if cancelled.load(Ordering::Acquire) {
        return Err(CryptoWorkerError::CancelledBeforeStart);
    }
    match catch_unwind(AssertUnwindSafe(|| job.execute())) {
        Ok(output) if !failed.load(Ordering::Acquire) => Ok(output),
        Ok(_output) => Err(CryptoWorkerError::WorkerPanicked),
        Err(_) => {
            failed.store(true, Ordering::Release);
            Err(CryptoWorkerError::WorkerPanicked)
        }
    }
}

/// Dropping performs the same blocking join as [`BoundedCryptoPool::shutdown`].
impl<J: CryptoJob> Drop for BoundedCryptoPool<J> {
    fn drop(&mut self) {
        self.join_workers();
    }
}

/// Cancellation-aware asynchronous completion for one admitted job.
pub struct JobHandle<O> {
    receiver: Option<oneshot::Receiver<Result<O, CryptoWorkerError>>>,
    cancelled: Arc<AtomicBool>,
}

/// Cloneable authority to request cancellation before a worker starts a job.
#[derive(Clone)]
pub struct JobCancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl JobCancellationToken {
    /// Requests cancellation if the worker has not started the job.
    pub fn cancel_before_start(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

impl<O> JobHandle<O> {
    /// Requests cancellation if the worker has not started this job.
    pub fn cancel_before_start(&self) {
        self.cancellation_token().cancel_before_start();
    }

    /// Returns cloneable cancellation authority for a separate waiter owner.
    #[must_use]
    pub fn cancellation_token(&self) -> JobCancellationToken {
        JobCancellationToken {
            cancelled: Arc::clone(&self.cancelled),
        }
    }

    /// Waits without blocking a Tokio worker.
    ///
    /// Dropping the returned future before it resolves drops this handle, which
    /// still requests pre-start cancellation of the queued job.
    pub async fn completion(mut self) -> Result<O, CryptoWorkerError> {
        let Some(receiver) = self.receiver.as_mut() else {
            return Err(CryptoWorkerError::ShuttingDown);
        };
        let outcome = receiver
            .await
            .unwrap_or(Err(CryptoWorkerError::WorkerPanicked));
        self.receiver = None;
        outcome
    }
}

impl<O> Drop for JobHandle<O> {
    fn drop(&mut self) {
        if self.receiver.is_some() {
            self.cancelled.store(true, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tokio::sync::oneshot;

    use super::{
        AdmissionCounters, BoundedCryptoPool, CryptoJob, CryptoPort, CryptoWorkerConfig,
        CryptoWorkerError, JobClass, JobHandle, WorkItem, worker_loop,
    };

    struct AddOne(u64);

    impl CryptoJob for AddOne {
        type Output = u64;

        fn class(&self) -> JobClass {
            JobClass::Opaque
        }

        fn execute(self) -> Self::Output {
            self.0 + 1
        }
    }

    struct BlockingJob {
        started: SyncSender<()>,
        release: Receiver<()>,
    }

    impl CryptoJob for BlockingJob {
        type Output = u64;

        fn class(&self) -> JobClass {
            JobClass::Opaque
        }

        fn execute(self) -> Self::Output {
            let _started = self.started.send(());
            let _released = self.release.recv();
            1
        }
    }

    struct PanicJob;

    impl CryptoJob for PanicJob {
        type Output = u64;

        fn class(&self) -> JobClass {
            JobClass::Opaque
        }

        fn execute(self) -> Self::Output {
            assert!(std::hint::black_box(false), "deliberate worker-panic test");
            0
        }
    }

    struct FailAfterWork {
        failed: Arc<AtomicBool>,
    }

    impl CryptoJob for FailAfterWork {
        type Output = u64;

        fn class(&self) -> JobClass {
            JobClass::Opaque
        }

        fn execute(self) -> Self::Output {
            self.failed.store(true, Ordering::Release);
            1
        }
    }

    fn admission_counters() -> Arc<AdmissionCounters> {
        Arc::new(AdmissionCounters {
            channel: AtomicUsize::new(0),
            opaque: AtomicUsize::new(0),
            config: CryptoWorkerConfig {
                channel_job_limit: 1,
                opaque_job_limit: 1,
                workers: 1,
            },
        })
    }

    #[test]
    fn admission_release_rejects_underflow_without_wrapping() {
        let counters = admission_counters();
        assert!(!counters.release(JobClass::Opaque));
        assert_eq!(counters.opaque.load(Ordering::Acquire), 0);
        assert!(counters.try_acquire(JobClass::Opaque));
        assert!(counters.release(JobClass::Opaque));
        assert_eq!(counters.opaque.load(Ordering::Acquire), 0);
    }

    fn work_item<J: CryptoJob>(
        job: J,
    ) -> (
        WorkItem<J>,
        oneshot::Receiver<Result<J::Output, CryptoWorkerError>>,
    ) {
        let (completion, receiver) = oneshot::channel();
        (
            WorkItem {
                class: job.class(),
                job,
                cancelled: Arc::new(AtomicBool::new(false)),
                completion,
            },
            receiver,
        )
    }

    #[tokio::test]
    async fn returns_completion_through_a_bounded_channel()
    -> Result<(), Box<dyn core::error::Error>> {
        let pool = BoundedCryptoPool::start(CryptoWorkerConfig::new(1, 1, 1)?)?;
        let handle = pool
            .try_submit(AddOne(41))
            .map_err(|error| error.reason())?;
        assert_eq!(handle.completion().await?, 42);
        Ok(())
    }

    #[tokio::test]
    async fn class_limit_counts_active_and_queued_work() -> Result<(), Box<dyn core::error::Error>>
    {
        let pool = BoundedCryptoPool::start(CryptoWorkerConfig::new(1, 1, 1)?)?;
        let (started_sender, started_receiver) = sync_channel(1);
        let (release_sender, release_receiver) = sync_channel(1);
        let first = pool
            .try_submit(BlockingJob {
                started: started_sender,
                release: release_receiver,
            })
            .map_err(|error| error.reason())?;
        started_receiver.recv_timeout(Duration::from_secs(1))?;
        let (unused_started, _unused_started_receiver) = sync_channel(1);
        let (_unused_release, unused_release_receiver) = sync_channel(1);
        let rejected = pool.try_submit(BlockingJob {
            started: unused_started,
            release: unused_release_receiver,
        });
        assert_eq!(
            rejected.err().map(|error| error.reason()),
            Some(CryptoWorkerError::QueueFull)
        );
        release_sender.send(())?;
        assert_eq!(first.completion().await?, 1);
        Ok(())
    }

    #[tokio::test]
    async fn cancellation_before_start_preserves_the_running_job()
    -> Result<(), Box<dyn core::error::Error>> {
        let pool = BoundedCryptoPool::start(CryptoWorkerConfig::new(1, 2, 1)?)?;
        let (started_sender, started_receiver) = sync_channel(1);
        let (release_sender, release_receiver) = sync_channel(1);
        let first = pool
            .try_submit(BlockingJob {
                started: started_sender,
                release: release_receiver,
            })
            .map_err(|error| error.reason())?;
        started_receiver.recv_timeout(Duration::from_secs(1))?;
        let (cancelled_started, _cancelled_started_receiver) = sync_channel(1);
        let (_cancelled_release, cancelled_release_receiver) = sync_channel(1);
        let cancelled = pool
            .try_submit(BlockingJob {
                started: cancelled_started,
                release: cancelled_release_receiver,
            })
            .map_err(|error| error.reason())?;
        cancelled.cancel_before_start();
        release_sender.send(())?;
        assert_eq!(first.completion().await?, 1);
        assert_eq!(
            cancelled.completion().await,
            Err(CryptoWorkerError::CancelledBeforeStart)
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_panicking_worker_poisons_later_admission() -> Result<(), Box<dyn core::error::Error>>
    {
        let pool = BoundedCryptoPool::start(CryptoWorkerConfig::new(1, 1, 1)?)?;
        let panicking = pool.try_submit(PanicJob).map_err(|error| error.reason())?;
        assert_eq!(
            panicking.completion().await,
            Err(CryptoWorkerError::WorkerPanicked)
        );
        assert_eq!(
            pool.try_submit(PanicJob).err().map(|error| error.reason()),
            Some(CryptoWorkerError::WorkerPanicked)
        );
        Ok(())
    }

    #[test]
    fn submission_reports_shutdown_full_and_disconnected_queues() {
        let (sender, _receiver) = sync_channel(1);
        let shutting_down = BoundedCryptoPool {
            sender: Some(sender),
            workers: Vec::new(),
            counters: admission_counters(),
            failed: Arc::new(AtomicBool::new(false)),
            shutting_down: Arc::new(AtomicBool::new(true)),
        };
        assert_eq!(
            shutting_down
                .try_submit(AddOne(1))
                .err()
                .map(|error| error.reason()),
            Some(CryptoWorkerError::ShuttingDown)
        );

        let missing_sender = BoundedCryptoPool {
            sender: None,
            workers: Vec::new(),
            counters: admission_counters(),
            failed: Arc::new(AtomicBool::new(false)),
            shutting_down: Arc::new(AtomicBool::new(false)),
        };
        assert_eq!(
            missing_sender
                .try_submit(AddOne(1))
                .err()
                .map(|error| error.reason()),
            Some(CryptoWorkerError::ShuttingDown)
        );

        let (sender, _receiver) = sync_channel(0);
        let full = BoundedCryptoPool {
            sender: Some(sender),
            workers: Vec::new(),
            counters: admission_counters(),
            failed: Arc::new(AtomicBool::new(false)),
            shutting_down: Arc::new(AtomicBool::new(false)),
        };
        assert_eq!(
            full.try_submit(AddOne(1)).err().map(|error| error.reason()),
            Some(CryptoWorkerError::QueueFull)
        );

        let (sender, receiver) = sync_channel(1);
        drop(receiver);
        let disconnected = BoundedCryptoPool {
            sender: Some(sender),
            workers: Vec::new(),
            counters: admission_counters(),
            failed: Arc::new(AtomicBool::new(false)),
            shutting_down: Arc::new(AtomicBool::new(false)),
        };
        assert_eq!(
            disconnected
                .try_submit(AddOne(1))
                .err()
                .map(|error| error.reason()),
            Some(CryptoWorkerError::ShuttingDown)
        );
    }

    #[test]
    fn worker_loop_reports_poison_shutdown_and_concurrent_failure() {
        let counters = admission_counters();
        counters.opaque.store(1, Ordering::Release);
        let failed = Arc::new(AtomicBool::new(false));
        let shutting_down = AtomicBool::new(false);
        let (sender, receiver) = sync_channel(1);
        let receiver = Arc::new(Mutex::new(receiver));
        let (item, completion) = work_item(AddOne(1));
        assert!(sender.send(item).is_ok());
        drop(sender);
        let poison_target = Arc::clone(&receiver);
        let _panic = catch_unwind(AssertUnwindSafe(|| {
            let _guard = match poison_target.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            assert!(
                std::hint::black_box(false),
                "deliberate receiver-poison test"
            );
        }));
        worker_loop(
            receiver.as_ref(),
            counters.as_ref(),
            failed.as_ref(),
            &shutting_down,
        );
        assert_eq!(
            completion.blocking_recv(),
            Ok(Err(CryptoWorkerError::WorkerPanicked))
        );

        let counters = admission_counters();
        counters.opaque.store(1, Ordering::Release);
        let failed = AtomicBool::new(false);
        let shutting_down = AtomicBool::new(true);
        let (sender, receiver) = sync_channel(1);
        let (item, completion) = work_item(AddOne(1));
        assert!(sender.send(item).is_ok());
        drop(sender);
        worker_loop(
            &Mutex::new(receiver),
            counters.as_ref(),
            &failed,
            &shutting_down,
        );
        assert_eq!(
            completion.blocking_recv(),
            Ok(Err(CryptoWorkerError::ShuttingDown))
        );

        let counters = admission_counters();
        counters.opaque.store(1, Ordering::Release);
        let failed = Arc::new(AtomicBool::new(false));
        let shutting_down = AtomicBool::new(false);
        let (sender, receiver) = sync_channel(1);
        let (item, completion) = work_item(FailAfterWork {
            failed: Arc::clone(&failed),
        });
        assert!(sender.send(item).is_ok());
        drop(sender);
        worker_loop(
            &Mutex::new(receiver),
            counters.as_ref(),
            failed.as_ref(),
            &shutting_down,
        );
        assert_eq!(
            completion.blocking_recv(),
            Ok(Err(CryptoWorkerError::WorkerPanicked))
        );
    }

    #[tokio::test]
    async fn empty_and_disconnected_completion_handles_fail_closed() {
        let empty = JobHandle::<u64> {
            receiver: None,
            cancelled: Arc::new(AtomicBool::new(false)),
        };
        assert_eq!(
            empty.completion().await,
            Err(CryptoWorkerError::ShuttingDown)
        );

        let (sender, receiver) = oneshot::channel();
        drop(sender);
        let disconnected = JobHandle::<u64> {
            receiver: Some(receiver),
            cancelled: Arc::new(AtomicBool::new(false)),
        };
        assert_eq!(
            disconnected.completion().await,
            Err(CryptoWorkerError::WorkerPanicked)
        );
    }

    #[test]
    fn unit_configuration_matrix_and_unobserved_handle_are_closed() {
        for invalid in [
            (0, 1, 1),
            (65, 1, 1),
            (1, 0, 1),
            (1, 129, 1),
            (1, 1, 0),
            (1, 1, 129),
            (1, 1, 3),
        ] {
            assert_eq!(
                CryptoWorkerConfig::new(invalid.0, invalid.1, invalid.2),
                Err(CryptoWorkerError::InvalidConfiguration)
            );
        }

        assert_eq!(
            CryptoWorkerConfig::new(4, 8, 4).and_then(CryptoWorkerConfig::physical_queue_capacity),
            Ok(8)
        );

        let (sender, receiver) = oneshot::channel::<Result<u64, CryptoWorkerError>>();
        let cancelled = Arc::new(AtomicBool::new(false));
        let handle = JobHandle {
            receiver: Some(receiver),
            cancelled: Arc::clone(&cancelled),
        };
        drop(handle);
        assert!(cancelled.load(Ordering::Acquire));
        drop(sender);
    }
}
