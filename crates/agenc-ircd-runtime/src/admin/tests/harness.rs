//! One directly driven administrative session with a scripted state core.
#![forbid(unsafe_code)]

use std::future::Future;
use std::sync::atomic::AtomicU32;

use agenc_ircd_admin::AdminEvent;
use agenc_ircd_testkit::DeterministicWallClock;
use agenc_ircd_types::{ClockError, Revision, UtcSecond};

use super::*;
use crate::state_core::AdminCoreInbox;
use crate::test_support::TestResult;

/// A syntactically valid user, channel, and server identifier.
pub(super) const ENTITY: &str = "AAAAAAAAAAAAAAAAAAAAAA";
/// A syntactically valid account identifier.
pub(super) const ACCOUNT: &str = "a_AAAAAAAAAAAAAAAAAAAAAA";
/// The token the all-zero scripted entropy issues.
pub(super) const ZERO_TOKEN: [u8; 16] = [0; 16];

/// One scripted answer from the state core, in request order.
#[derive(Clone, Copy)]
pub(super) enum CoreReply {
    /// Answers an audit commit, a kill, or a quarantine with this outcome and
    /// a snapshot or revision request with `StorageUnavailable`.
    Next(AdminCoreResult),
    /// Answers a target-revision request with this revision.
    Revision(u64),
    /// Answers a snapshot request with an all-zero snapshot.
    Snapshot,
    /// Answers a mutation commit with this outcome.
    Mutation(AdminCoreResult),
}

pub(super) struct Session {
    pub(super) owner: AdminOwner,
    pub(super) core: AdminCoreInbox,
    pub(super) output: mpsc::Receiver<AdminWrite>,
    pub(super) root: CancellationToken,
    pub(super) generation: ConnectionGeneration,
}

/// A wall clock that answers a fixed number of reads and then fails.
struct ExpiringWallClock {
    reads: AtomicU32,
}

impl WallClock for ExpiringWallClock {
    fn utc_now(&self) -> Result<UtcSecond, ClockError> {
        let left = self.reads.load(Ordering::Relaxed);
        if left == 0 {
            return Err(ClockError::Unavailable);
        }
        self.reads.store(left - 1, Ordering::Relaxed);
        Ok(UtcSecond::from_unix_seconds(1_700_000_000))
    }
}

pub(super) const fn local_peer() -> PeerIdentity {
    PeerIdentity::Local {
        uid: 1000,
        gid: 1000,
    }
}

async fn answer(core: &mut AdminCoreInbox, reply: CoreReply) {
    match reply {
        CoreReply::Next(outcome) => {
            let _event = core.complete_next_for_test(outcome).await;
        }
        CoreReply::Revision(revision) => {
            if let Ok(revision) = Revision::new(revision) {
                let _target = core.complete_target_revision_for_test(revision).await;
            }
        }
        CoreReply::Snapshot => {
            let snapshot = AdminCoreSnapshot::new([0; 9], [0; 14], [0; 10], [0; 8]);
            let _sent = core.complete_snapshot_for_test(snapshot).await;
        }
        CoreReply::Mutation(outcome) => {
            let _commit = core.complete_mutation_for_test(outcome).await;
        }
    }
}

async fn serve(core: &mut AdminCoreInbox, replies: &[CoreReply], served: &Cell<usize>) {
    for reply in replies {
        answer(core, *reply).await;
        served.set(served.get().saturating_add(1));
    }
    std::future::pending::<()>().await;
}

/// Runs `work` while the scripted core answers exactly `replies`.
pub(super) async fn drive<F>(
    work: F,
    core: &mut AdminCoreInbox,
    replies: &[CoreReply],
) -> TestResult
where
    F: Future<Output = ()>,
{
    let served = Cell::new(0_usize);
    let both = async {
        tokio::select! {
            biased;
            () = work => {}
            () = serve(core, replies, &served) => {}
        }
    };
    tokio::time::timeout(Duration::from_secs(5), both).await?;
    if served.get() != replies.len() {
        return Err("the owner left scripted core replies unused".into());
    }
    Ok(())
}

/// Administrative commands the observer counted under `result`.
pub(super) fn handled(metrics: &MetricsRegistry, result: ResultClass) -> TestResult<u64> {
    use crate::observe::metrics::{LabelSet, MetricKey, MetricLabel, MetricName, MetricsView};

    let key = MetricKey {
        name: MetricName::CommandsHandled,
        labels: LabelSet::new(&[
            MetricLabel::CommandClass(CommandClass::Administration),
            MetricLabel::ResultClass(result),
        ])?,
    };
    let counters = metrics.snapshot(MetricsView::Operator).counters;
    Ok(counters
        .into_iter()
        .find_map(|(candidate, count)| (candidate == key).then_some(count))
        .unwrap_or(0))
}

/// Parses one signed command the way an authenticated session would.
pub(super) fn command_event(line: &[u8]) -> TestResult<AdminCommandEvent> {
    let registry = all_permissions_registry()?;
    let mut session = AdminSession::new(binding(), challenge(), local_peer());
    let now = MonotonicTick::from_ticks(0);
    session
        .accept_line(&oper_line()?, now, &registry)
        .map_err(|_| "oper")?;
    match session.accept_line(line, now, &registry) {
        Ok(AdminEvent::Command(event)) => Ok(*event),
        _ => Err("the line is not an accepted command".into()),
    }
}

impl Session {
    /// An admitted session that has received its challenge only.
    pub(super) fn unauthenticated() -> TestResult<Self> {
        let (core, core_inbox) = admin_core_channel();
        let mut owner = lifecycle_owner()?;
        owner.registry = all_permissions_registry()?;
        owner.core = core;
        let generation = ConnectionGeneration::new(40);
        let (sender, mut output) = mpsc::channel(ADMIN_OUTPUT_CAPACITY);
        owner.open(
            generation,
            challenge(),
            local_peer(),
            AdminOutput::new(sender),
        );
        let _challenge = output.try_recv()?;
        Ok(Self {
            owner,
            core: core_inbox,
            output,
            root: CancellationToken::root(),
            generation,
        })
    }

    /// A session whose operator holds every permission.
    pub(super) async fn authenticated() -> TestResult<Self> {
        let mut session = Self::unauthenticated()?;
        session.send(oper_line()?, &[]).await?;
        Ok(session)
    }

    /// Delivers one line while the core answers exactly `replies`.
    pub(super) async fn send(&mut self, line: Vec<u8>, replies: &[CoreReply]) -> TestResult {
        let Self {
            owner,
            core,
            root,
            generation,
            ..
        } = self;
        drive(owner.line(*generation, &line, root), core, replies).await
    }

    /// Delivers one signed command and returns its queued reply text.
    pub(super) async fn command(
        &mut self,
        counter: u64,
        command: &str,
        replies: &[CoreReply],
    ) -> TestResult<String> {
        self.send(signed_line(counter, command)?, replies).await?;
        self.text()
    }

    /// Takes the next queued write.
    pub(super) fn write(&mut self) -> TestResult<AdminWrite> {
        Ok(self.output.try_recv()?)
    }

    /// Takes the next queued write as newline-joined text.
    pub(super) fn text(&mut self) -> TestResult<String> {
        let write = self.write()?;
        let mut lines = Vec::new();
        for line in write.lines {
            lines.push(String::from_utf8(line)?);
        }
        Ok(lines.join("\n"))
    }

    /// Whether nothing is queued for the peer.
    pub(super) fn is_silent(&mut self) -> bool {
        self.output.try_recv().is_err()
    }

    /// Replaces the wall clock with one that cannot be read.
    pub(super) fn break_wall_clock(&mut self) {
        self.owner.wall = Box::new(DeterministicWallClock::unavailable_at(0));
    }

    /// Replaces the wall clock with one that fails after `reads` reads.
    pub(super) fn expire_wall_clock_after(&mut self, reads: u32) {
        self.owner.wall = Box::new(ExpiringWallClock {
            reads: AtomicU32::new(reads),
        });
    }

    /// Replaces the entropy source with an exhausted script.
    pub(super) fn exhaust_entropy(&mut self) -> TestResult {
        self.owner.entropy = Box::new(ScriptedEntropy::new(Vec::new())?);
        Ok(())
    }

    /// Fills the bounded state-core queue with abandoned snapshot requests.
    pub(super) async fn saturate_core(&self) {
        for _ in 0..64_u8 {
            let request = self.owner.core.snapshot(&self.root);
            if tokio::time::timeout(Duration::ZERO, request).await.is_ok() {
                return;
            }
        }
    }

    /// Requests a confirmation token for `command` at process revision 9.
    pub(super) async fn request_confirmation(&mut self, command: &str) -> TestResult {
        let reply = self.command(0, command, &[CoreReply::Revision(9)]).await?;
        if !reply.contains(" CONFIRM AAAAAAAAAAAAAAAAAAAAAA ") {
            return Err("no confirmation token was issued".into());
        }
        Ok(())
    }

    /// Repeats `command` with the issued all-zero confirmation token.
    pub(super) async fn confirm(&mut self, command: &str, replies: &[CoreReply]) -> TestResult {
        let token = ConfirmationToken::from_bytes(ZERO_TOKEN);
        self.send(confirmed_line(1, command, &token)?, replies)
            .await
    }

    /// Installs an observer and returns its metrics and its log writer,
    /// which must outlive the assertions.
    pub(super) fn observe(&mut self) -> (Arc<MetricsRegistry>, LogWriter<DiscardLog>) {
        let correlation = Arc::new(CorrelationSource::new(10));
        let metrics = Arc::new(MetricsRegistry::new());
        let (writer, log) = LogWriter::start(
            DiscardLog,
            LogRetention::DEFAULT,
            LogFilter::new(Severity::Debug),
            binding().server_id,
            Arc::clone(&correlation),
        );
        self.owner.observer = Some(Arc::new(RuntimeObserver::new(
            binding().server_id,
            SystemMonotonicClock::start(),
            correlation,
            log,
            Arc::clone(&metrics),
        )));
        (metrics, writer)
    }

    /// Installs a fatal-signal receiver.
    pub(super) fn watch_fatal(&mut self) -> mpsc::Receiver<()> {
        let (sender, receiver) = mpsc::channel(1);
        self.owner.fatal = Some(sender);
        receiver
    }
}
