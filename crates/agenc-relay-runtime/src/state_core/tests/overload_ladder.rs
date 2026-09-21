//! The complete Section-19.3 overload ladder against one live memory pool.
//!
//! One pool is walked up through 80, 90 and 95 percent and back down through
//! the 85-percent recovery mark. Every rung is asserted through what a client
//! observes and through the state the node kept, never through an internal
//! call count.

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::*;
use crate::admission::{RateLimits, TransportAdmission};
use crate::budget::{
    BoundedMemoryCharges, MemoryBudget, MemoryBudgetPort as _, MemoryCharge, MemoryPermitBatch,
};
use crate::connection::sink::{
    BoundedSharedClientFrames, ClientQueueDemand, ClientQueueReservation, QueueAllocationError,
    SinkReserveError, TentativeClientQueueReservation,
};
use crate::listener::{AcceptAdmission as _, AdmissionVerdict};
use crate::state_core::inbox::CloseReason;
use crate::sync::{Mutex, lock};

/// A sink whose reported queue occupancy is backed by a real permit from the
/// same pool the overload class is measured against, so shedding it returns
/// exactly the bytes it claimed, as destroying a real queue does.
struct LadderSink {
    inner: Arc<FrameSink>,
    budget: Arc<MemoryBudget>,
    queued: AtomicU64,
    charge: Mutex<Option<MemoryPermitBatch>>,
    closed: AtomicBool,
    order: Arc<Mutex<Vec<u64>>>,
}

impl LadderSink {
    fn new(generation: u64, budget: &Arc<MemoryBudget>, order: &Arc<Mutex<Vec<u64>>>) -> Arc<Self> {
        Arc::new(Self {
            inner: FrameSink::new(ConnectionGeneration::new(generation), true),
            budget: Arc::clone(budget),
            queued: AtomicU64::new(0),
            charge: Mutex::new(None),
            closed: AtomicBool::new(false),
            order: Arc::clone(order),
        })
    }

    /// Charges `bytes` to the live pool and reports them as queued output.
    fn fill(&self, bytes: u64) -> TestResult {
        let charges = BoundedMemoryCharges::new(&[MemoryCharge::fixed(bytes)])?;
        let permit = self.budget.try_acquire_batch(charges)?;
        *lock(&self.charge) = Some(permit);
        self.queued.store(bytes, Ordering::SeqCst);
        Ok(())
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

impl ClientSink for LadderSink {
    fn generation(&self) -> ConnectionGeneration {
        self.inner.generation()
    }

    fn try_reserve(
        &self,
        demand: ClientQueueDemand,
    ) -> Result<TentativeClientQueueReservation, SinkReserveError> {
        self.inner.try_reserve(demand)
    }

    fn prepare(
        &self,
        tentative: TentativeClientQueueReservation,
        backing: Option<crate::budget::MemoryPermit>,
    ) -> Result<ClientQueueReservation, QueueAllocationError> {
        self.inner.prepare(tentative, backing)
    }

    fn commit(&self, reservation: ClientQueueReservation, frames: BoundedSharedClientFrames) {
        self.inner.commit(reservation, frames);
    }

    /// Marks the connection closing and destroys its whole queue with it: the
    /// entire claimed charge is returned in one step and no single frame is
    /// dropped on its own.
    fn begin_slow_consumer_close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        lock(&self.order).push(self.inner.generation().get());
        self.queued.store(0, Ordering::SeqCst);
        drop(lock(&self.charge).take());
        self.inner.begin_slow_consumer_close();
    }

    fn close_after_flush(&self, reason: CloseReason) -> crate::connection::FlushAcknowledgement {
        self.inner.close_after_flush(reason)
    }

    fn queue_snapshot(&self) -> crate::connection::ClientQueueSnapshot {
        crate::connection::ClientQueueSnapshot::new(self.queued.load(Ordering::SeqCst), 1_048_576)
    }
}

/// One live pool driven line by line, keeping every connection's line
/// sequence across the whole ladder.
struct Ladder {
    inbox: mpsc::Sender<StateCoreMessage>,
    sinks: Vec<Arc<LadderSink>>,
    sequences: Vec<u64>,
}

impl Ladder {
    fn new(inbox: mpsc::Sender<StateCoreMessage>, sinks: Vec<Arc<LadderSink>>) -> Self {
        let sequences = vec![0_u64; sinks.len()];
        Self {
            inbox,
            sinks,
            sequences,
        }
    }

    fn sink(&self, connection: u64) -> TestResult<Arc<LadderSink>> {
        let index = usize::try_from(connection)? - 1;
        Ok(Arc::clone(self.sinks.get(index).ok_or("unknown sink")?))
    }

    async fn open(&self, connection: u64) -> TestResult {
        let (acknowledgement, accepted) = oneshot::channel();
        send(
            &self.inbox,
            StateCoreMessage::Opened {
                generation: ConnectionGeneration::new(connection),
                purpose: ListenerPurpose::ClientOnion,
                source: SourceAddressKey::onion_listener(),
                sink: Arc::clone(&self.sink(connection)?) as Arc<dyn ClientSink>,
                acknowledgement,
            },
        )
        .await?;
        match accepted.await? {
            ConnectionOpenOutcome::Refused => Err("the core refused the connection".into()),
            ConnectionOpenOutcome::Accepted | ConnectionOpenOutcome::AcceptedInput(_) => Ok(()),
        }
    }

    async fn line(&mut self, connection: u64, line: &str) -> TestResult {
        let index = usize::try_from(connection)? - 1;
        let sequence = self.sequences.get_mut(index).ok_or("unknown sink")?;
        *sequence += 1;
        let message = parse_message(FramedLine::new(line)?)?.ok_or("empty line")?;
        send(
            &self.inbox,
            StateCoreMessage::Line {
                generation: ConnectionGeneration::new(connection),
                sequence: *sequence,
                message: Box::new(message),
            },
        )
        .await
    }

    /// Runs one maintenance tick, which is an ordinary accepted input and so
    /// applies the 95-percent class exactly as a client line does.
    async fn maintenance(&self) -> TestResult {
        send(
            &self.inbox,
            StateCoreMessage::Maintenance(MaintenanceEvent::PrefixErasure),
        )
        .await
    }

    /// Returns how many lines this connection has already received, so a
    /// later assertion reads only what the next command produced.
    fn mark(&self, connection: u64) -> TestResult<usize> {
        Ok(self.sink(connection)?.inner.lines().len())
    }

    async fn wait(&self, connection: u64, needle: &str) -> TestResult {
        let sink = self.sink(connection)?;
        for _ in 0..5_000 {
            if sink.inner.lines().iter().any(|line| line.contains(needle)) {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        Err(format!(
            "connection {connection} never received {needle:?}: {:?}",
            sink.inner.lines()
        )
        .into())
    }

    /// Waits until the named marker arrives and then requires that nothing
    /// delivered since `since` carries a forbidden marker, which is how a
    /// refusal is proved to have left no other observable result behind.
    async fn wait_without(
        &self,
        connection: u64,
        since: usize,
        needle: &str,
        forbidden: &[&str],
    ) -> TestResult {
        self.wait(connection, needle).await?;
        let lines = self.sink(connection)?.inner.lines();
        let produced = lines.get(since..).unwrap_or_default();
        for marker in forbidden {
            if produced.iter().any(|line| line.contains(marker)) {
                return Err(
                    format!("connection {connection} produced {marker:?}: {produced:?}").into(),
                );
            }
        }
        Ok(())
    }

    /// Registers one guest and waits for its welcome.
    async fn register_guest(&mut self, connection: u64, nickname: &str) -> TestResult {
        self.begin_registration(connection, nickname).await?;
        self.wait(connection, " 001 ").await
    }

    async fn begin_registration(&mut self, connection: u64, nickname: &str) -> TestResult {
        for line in [
            "CAP LS 302".to_owned(),
            format!("NICK {nickname}"),
            format!("USER {nickname} 0 * :{nickname}"),
            // Standard replies are what carry the exact refusal codes of
            // Section 19.3 to the client.
            "CAP REQ :standard-replies".to_owned(),
            "CAP END".to_owned(),
        ] {
            self.line(connection, &line).await?;
        }
        Ok(())
    }
}

/// Charges the live pool up to the first byte that reaches `percent` of its
/// capacity, which is the exact boundary the classes switch on.
fn charge_to(budget: &Arc<MemoryBudget>, percent: u64) -> TestResult<MemoryPermitBatch> {
    let target = budget
        .capacity()
        .checked_mul(percent)
        .ok_or("percent overflow")?
        .div_ceil(100);
    let extra = target
        .checked_sub(budget.charged())
        .ok_or("the pool already holds more than the requested percent")?;
    Ok(budget.try_acquire_batch(BoundedMemoryCharges::new(&[MemoryCharge::fixed(extra)])?)?)
}

/// Builds an accept-time authority over the same pool, so the ladder's accept
/// rung is measured against the very bytes the command rungs see.
fn transport(budget: &Arc<MemoryBudget>) -> TestResult<TransportAdmission> {
    Ok(TransportAdmission::new(
        RateLimits::defaults(),
        16,
        Arc::clone(budget),
        Box::new(agenc_relay_testkit::DeterministicMonotonicClock::at(0)),
    )?)
}

fn accepts(admission: &TransportAdmission) -> bool {
    admission.admit(
        ListenerPurpose::ClientOnion,
        SourceAddressKey::onion_listener(),
    ) == AdmissionVerdict::Admit
}

#[tokio::test]
async fn the_eighty_and_ninety_percent_classes_refuse_only_their_own_work() -> TestResult {
    let order = Arc::new(Mutex::new(Vec::new()));
    let (exit, (_inbox, stopped)) = run_core_with(
        true,
        |fixture| Ok(Arc::clone(&fixture.context_mut()?.budget)),
        |inbox, lifecycle, _token, budget| async move {
            let sinks = (1..=4)
                .map(|generation| LadderSink::new(generation, &budget, &order))
                .collect();
            let mut ladder = Ladder::new(inbox, sinks);
            let gate = transport(&budget)?;

            // Below every threshold: a guest registers and creates a channel.
            ladder.open(1).await?;
            ladder.open(2).await?;
            ladder.register_guest(1, "alice").await?;
            ladder.register_guest(2, "bob").await?;
            ladder.line(1, "JOIN #ladder").await?;
            ladder.wait(1, " JOIN #ladder").await?;
            assert!(accepts(&gate), "a node below 80 percent accepts");

            // The 80-percent class: guests and expensive queries only.
            let eighty = charge_to(&budget, 80)?;
            ladder.open(3).await?;
            let carol = ladder.mark(3)?;
            ladder.begin_registration(3, "carol").await?;
            ladder
                .wait_without(
                    3,
                    carol,
                    " FAIL * REGISTRATION_REQUIRED :Registration required",
                    &[" 001 "],
                )
                .await?;
            for (command, needle, forbidden) in [
                (
                    "LIST",
                    " FAIL LIST SERVER_BUSY :Server is busy",
                    &[" 321 ", " 322 "][..],
                ),
                (
                    "WHO #ladder",
                    " FAIL WHO SERVER_BUSY :Server is busy",
                    &[" 352 ", " 315 "],
                ),
                (
                    "NAMES #ladder",
                    " FAIL NAMES SERVER_BUSY :Server is busy",
                    &[" 353 ", " 366 "],
                ),
                (
                    "WHOIS alice",
                    " FAIL WHOIS SERVER_BUSY :Server is busy",
                    &[" 311 ", " 318 "],
                ),
            ] {
                let since = ladder.mark(1)?;
                ladder.line(1, command).await?;
                ladder.wait_without(1, since, needle, forbidden).await?;
            }
            // Authenticated ordinary traffic is untouched at the same rung.
            ladder.line(1, "AWAY :still-here").await?;
            ladder.wait(1, " 306 ").await?;
            ladder.line(1, "TOPIC #ladder :still-open").await?;
            ladder.wait(1, " TOPIC #ladder :still-open").await?;
            assert!(accepts(&gate), "80 percent does not stop new connections");

            // The 90-percent class: new connections and channel creation.
            let ninety = charge_to(&budget, 90)?;
            ladder.line(2, "JOIN #ladder").await?;
            ladder
                .wait(2, " JOIN #ladder")
                .await
                .map_err(|e| format!("joining an existing channel must continue: {e}"))?;
            let refused_join = ladder.mark(1)?;
            ladder.line(1, "JOIN #fresh").await?;
            ladder
                .wait_without(
                    1,
                    refused_join,
                    " FAIL JOIN SERVER_BUSY :Server is busy",
                    &[" JOIN #fresh"],
                )
                .await?;
            assert!(!accepts(&gate), "90 percent stops new connections");

            // Back below every threshold: the node serves the same work again.
            drop(ninety);
            drop(eighty);
            assert!(accepts(&gate), "a recovered node accepts again");
            ladder.line(1, "LIST").await?;
            ladder.wait(1, " 322 alice #ladder ").await?;
            let listed = ladder.sink(1)?.inner.lines();
            assert!(
                !listed.iter().any(|line| line.contains("#fresh")),
                "the refused creation left no channel behind: {listed:?}"
            );
            ladder.line(1, "JOIN #fresh").await?;
            ladder.wait(1, " JOIN #fresh").await?;
            ladder.open(4).await?;
            ladder.register_guest(4, "dave").await?;

            let stopped = lifecycle.request(LifecyclePhase::Stop).await;
            Ok((ladder, stopped))
        },
    )
    .await?;
    assert!(stopped.is_ok());
    assert!(matches!(exit, StateCoreExit::Stopped), "{exit:?}");
    Ok(())
}

#[tokio::test]
async fn the_ninety_five_percent_class_sheds_the_largest_queues_down_to_the_recovery_mark()
-> TestResult {
    let order = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&order);
    let (exit, (_ladder, stopped)) = run_core_with(
        true,
        |fixture| Ok(Arc::clone(&fixture.context_mut()?.budget)),
        |inbox, lifecycle, _token, budget| async move {
            let sinks: Vec<_> = (1..=6)
                .map(|generation| LadderSink::new(generation, &budget, &order))
                .collect();
            let mut ladder = Ladder::new(inbox, sinks);
            let percent = |share: u64| budget.capacity() * share / 100;

            for connection in 1..=4 {
                ladder.open(connection).await?;
            }
            ladder.register_guest(1, "alice").await?;

            // Three consumers hold unequal shares of the same pool; the pool
            // is then pinned at 95 percent.
            ladder.sink(2)?.fill(percent(6))?;
            ladder.sink(3)?.fill(percent(7))?;
            ladder.sink(4)?.fill(percent(3))?;
            let pin = charge_to(&budget, 95)?;

            ladder.maintenance().await?;
            let shed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while !ladder.sink(2).is_ok_and(|sink| sink.is_closed()) {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            })
            .await;
            assert!(shed.is_ok(), "the 95 percent class closed nothing");
            assert!(ladder.sink(3)?.is_closed(), "the largest queue is shed");
            assert!(
                !ladder.sink(4)?.is_closed(),
                "shedding stops at the 85 percent recovery mark"
            );
            assert!(!ladder.sink(1)?.is_closed(), "an empty queue is never shed");
            assert_eq!(
                lock(&observed).clone(),
                vec![3, 2],
                "whole connections are selected in descending charged-queue-byte order"
            );
            // 95 - 7 - 6 = 82 percent, which is below the recovery mark, so a
            // second tick selects nobody and the survivor keeps its bytes.
            ladder.maintenance().await?;
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            assert_eq!(lock(&observed).clone(), vec![3, 2]);
            assert!(!ladder.sink(4)?.is_closed());

            // Still above 80 percent, so guests stay refused; below it, the
            // recovered node accepts a guest again.
            ladder.open(5).await?;
            let erin = ladder.mark(5)?;
            ladder.begin_registration(5, "erin").await?;
            ladder
                .wait_without(5, erin, " FAIL * REGISTRATION_REQUIRED ", &[" 001 "])
                .await?;
            drop(pin);
            ladder.open(6).await?;
            ladder.register_guest(6, "frank").await?;

            let stopped = lifecycle.request(LifecyclePhase::Stop).await;
            Ok((ladder, stopped))
        },
    )
    .await?;
    assert!(stopped.is_ok());
    assert!(matches!(exit, StateCoreExit::Stopped), "{exit:?}");
    Ok(())
}
