//! Client lines through the state core itself, where each line owns a command
//! observation: pre-registration admission and input deferred behind a commit.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use super::test_harness::{TestResult, entropy_script, parsed, saw};
use super::*;
use crate::connection::sink::ClientSink;
use crate::state_core::inbox::{SourceAddressKey, StateCoreMessage};
use crate::test_support::{FrameSink, StateCoreFixture};

/// The instant every test in this file runs at.
const FROZEN_TICKS: u64 = 10;

/// A state core that owns the production registration router.
///
/// `with_registration_router` composes the core for the actor loop, so it runs
/// on the system monotonic clock. These tests step the core by hand and settle
/// each batch with `commit_staged_batch`, which submits the gathering batch
/// itself. On a running clock the one-millisecond gather window can end between
/// two lines; the next step then submits the batch first, the helper submits it
/// again under a second transaction, and the first receipt stops the core with
/// `Indeterminate(TransactionMismatch)`. The clock is therefore frozen before
/// any line is routed: a batch leaves only when the test settles it, and the
/// rate buckets never refill behind the burst assertion.
struct Core {
    fixture: StateCoreFixture,
    sequences: BTreeMap<u64, u64>,
}

impl Core {
    fn new() -> TestResult<Self> {
        let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
        fixture.context_mut()?.set_monotonic_for_test(FROZEN_TICKS);
        Ok(Self {
            fixture,
            sequences: BTreeMap::new(),
        })
    }

    /// Settles the batch the routed lines staged. The batch must still be
    /// gathering: a core that already submitted it would be settled twice.
    async fn settle(&mut self) -> TestResult {
        let context = self.fixture.context_mut()?;
        if context.pending_len() == 0 || context.in_flight() {
            return Err(
                "the staged batch left the gather window before the test settled it".into(),
            );
        }
        self.fixture.commit_staged_batch().await
    }

    fn open(&mut self, number: u64) -> TestResult<Arc<FrameSink>> {
        let generation = ConnectionGeneration::new(number);
        let sink = FrameSink::new(generation, true);
        let (acknowledgement, _accepted) = tokio::sync::oneshot::channel();
        let exit = self
            .fixture
            .state_mut()?
            .step_message(StateCoreMessage::Opened {
                generation,
                purpose: ListenerPurpose::ClientOnion,
                source: SourceAddressKey::onion_listener(),
                sink: Arc::clone(&sink) as Arc<dyn ClientSink>,
                acknowledgement,
            });
        assert!(exit.is_none());
        Ok(sink)
    }

    fn line(&mut self, number: u64, line: &str) -> TestResult {
        let sequence = self.sequences.entry(number).or_insert(0);
        *sequence = sequence.saturating_add(1);
        let message = StateCoreMessage::Line {
            generation: ConnectionGeneration::new(number),
            sequence: *sequence,
            message: Box::new(parsed(line)?),
        };
        let exit = self.fixture.state_mut()?.step_message(message);
        assert!(exit.is_none());
        Ok(())
    }

    /// Whether connection `number` still holds a local JOIN snapshot that
    /// has not been opened.
    fn holds_local_join_seed(&mut self, number: u64) -> TestResult<bool> {
        Ok(self
            .fixture
            .context_mut()?
            .has_local_join_seed(ConnectionGeneration::new(number)))
    }
}

/// The index of the first line that contains `text`.
fn line_index(lines: &[String], text: &str) -> Option<usize> {
    lines.iter().position(|line| line.contains(text))
}

#[tokio::test]
async fn preauth_lines_beyond_the_burst_are_told_to_wait() -> TestResult {
    let mut core = Core::new()?;
    let sink = core.open(1)?;
    core.line(1, "CAP LIST")?;
    assert!(!saw(&sink, " 263 "), "lines: {:?}", sink.lines());
    for _ in 0..4_096 {
        if saw(&sink, " 263 ") {
            break;
        }
        core.line(1, "CAP LIST")?;
    }
    assert!(
        saw(&sink, " 263 * CAP :Please wait a while and try again."),
        "lines: {:?}",
        sink.lines()
    );
    let before = sink.lines().len();
    core.line(1, "NOTICE someone :quiet")?;
    assert_eq!(sink.lines().len(), before, "a NOTICE is never answered");
    Ok(())
}

#[tokio::test]
async fn input_behind_a_pending_registration_runs_after_the_welcome() -> TestResult {
    let mut core = Core::new()?;
    let sink = core.open(1)?;
    core.line(1, "NICK early")?;
    core.line(1, "USER early 0 * :Early")?;
    core.line(1, "PING first")?;
    core.line(1, "NICK")?;
    assert!(!saw(&sink, "PONG"), "lines: {:?}", sink.lines());
    core.settle().await?;
    let lines = sink.lines();
    let welcome = lines.iter().position(|line| line.contains(" 001 early "));
    let pong = lines.iter().position(|line| line.contains("PONG"));
    let refused = lines
        .iter()
        .position(|line| line.contains(" 461 early NICK "));
    assert!(welcome.is_some() && welcome < pong, "lines: {lines:?}");
    assert!(pong < refused, "lines: {lines:?}");
    Ok(())
}

#[tokio::test]
async fn command_behind_an_unfinished_join_waits_for_the_join_response() -> TestResult {
    let mut core = Core::new()?;
    let sink = core.open(1)?;
    core.line(1, "NICK joiner")?;
    core.line(1, "USER joiner 0 * :Joiner")?;
    core.settle().await?;
    core.line(1, "JOIN #room")?;
    core.line(1, "TOPIC #room")?;
    assert!(!saw(&sink, " 331 "), "lines: {:?}", sink.lines());
    core.settle().await?;
    let lines = sink.lines();
    let names_end = lines
        .iter()
        .position(|line| line.contains(" 366 joiner #room "));
    let topic = lines
        .iter()
        .rposition(|line| line.contains(" 331 joiner #room "));
    assert!(names_end.is_some() && names_end < topic, "lines: {lines:?}");
    let topics = lines.iter().filter(|line| line.contains(" 331 ")).count();
    assert_eq!(
        topics, 2,
        "the JOIN and the deferred TOPIC each answer once"
    );
    Ok(())
}

/// AUD-16 behind a response floor. The refused lookup of a missing channel
/// holds its answer until the floor, and the local JOIN sent behind it waits.
/// The floor's timer publishes the refusal and runs the JOIN, which is applied
/// in that same step; its answer must follow at once, not wait for a later
/// line or commit to open its snapshot.
#[tokio::test]
async fn a_local_join_released_by_a_response_floor_answers_in_the_same_step() -> TestResult {
    let mut core = Core::new()?;
    let sink = core.open(1)?;
    core.line(1, "NICK floored")?;
    core.line(1, "USER floored 0 * :Floored")?;
    core.settle().await?;
    core.line(1, "TOPIC #missing")?;
    core.line(1, "JOIN &loc")?;
    assert!(!saw(&sink, " 403 "), "lines: {:?}", sink.lines());
    assert!(!saw(&sink, " JOIN &loc"), "lines: {:?}", sink.lines());
    core.fixture.context_mut()?.set_monotonic_for_test(
        FROZEN_TICKS + crate::state_core::timers::SECRET_CHANNEL_FLOOR_MILLIS,
    );
    assert!(core.fixture.state_mut()?.step_wake().is_none());
    let lines = sink.lines();
    let refused = line_index(&lines, " 403 floored #missing ");
    let names_end = line_index(&lines, " 366 floored &loc ");
    assert!(refused.is_some() && refused < names_end, "lines: {lines:?}");
    assert!(!core.holds_local_join_seed(1)?);
    Ok(())
}

/// AUD-16 at a crypto completion. A keyed JOIN of a local channel waits for
/// its channel-key verification job, whose completion plans the JOIN and
/// applies it in that same step. Nothing else follows to open its snapshot:
/// the completion step must, or the JOIN and every later command on its
/// connection wait.
#[tokio::test]
async fn a_keyed_local_join_answers_in_its_crypto_completion_step() -> TestResult {
    let mut core = Core::new()?;
    let owner = core.open(1)?;
    core.line(1, "NICK owner")?;
    core.line(1, "USER owner 0 * :Owner")?;
    core.settle().await?;
    core.line(1, "JOIN &locked")?;
    assert!(
        saw(&owner, " 366 owner &locked "),
        "lines: {:?}",
        owner.lines()
    );
    core.line(1, "MODE &locked +k secretkey")?;
    assert_eq!(
        core.fixture
            .context_mut()?
            .crypto_mut()
            .snapshot_in_flight(),
        1
    );
    let completion = core.fixture.next_crypto_completion().await?;
    core.fixture.state_mut()?.step_crypto(completion);
    assert!(
        saw(&owner, " MODE &locked +k"),
        "lines: {:?}",
        owner.lines()
    );
    let joiner = core.open(2)?;
    core.line(2, "NICK joiner")?;
    core.line(2, "USER joiner 0 * :Joiner")?;
    core.settle().await?;
    core.line(2, "JOIN &locked secretkey")?;
    assert_eq!(
        core.fixture
            .context_mut()?
            .crypto_mut()
            .snapshot_in_flight(),
        1
    );
    assert!(
        !saw(&joiner, " JOIN &locked"),
        "lines: {:?}",
        joiner.lines()
    );
    let completion = core.fixture.next_crypto_completion().await?;
    core.fixture.state_mut()?.step_crypto(completion);
    let lines = joiner.lines();
    let echo = line_index(&lines, " JOIN &locked");
    let names_end = line_index(&lines, " 366 joiner &locked ");
    assert!(echo.is_some() && echo < names_end, "lines: {lines:?}");
    assert!(!core.holds_local_join_seed(2)?);
    Ok(())
}

/// AUD-16 at a refused batch. A local JOIN deferred behind a staged `#` JOIN
/// resumes in the step where storage refuses that JOIN's batch, and is applied
/// in that same step, which must open its snapshot.
#[tokio::test]
async fn a_local_join_resumed_by_a_refused_batch_answers_in_that_step() -> TestResult {
    let mut core = Core::new()?;
    let sink = core.open(1)?;
    core.line(1, "NICK refused")?;
    core.line(1, "USER refused 0 * :Refused")?;
    core.settle().await?;
    core.line(1, "JOIN #room")?;
    core.line(1, "JOIN &loc")?;
    assert!(!saw(&sink, " JOIN &loc"), "lines: {:?}", sink.lines());
    core.fixture
        .state_mut()?
        .reject_fixture_batch_before_submission(agenc_relay_storage::StorageError::QueueFull)?;
    let lines = sink.lines();
    assert!(
        line_index(&lines, " 366 refused #room ").is_none(),
        "lines: {lines:?}"
    );
    let echo = line_index(&lines, " JOIN &loc");
    let names_end = line_index(&lines, " 366 refused &loc ");
    assert!(echo.is_some() && echo < names_end, "lines: {lines:?}");
    assert!(!core.holds_local_join_seed(1)?);
    Ok(())
}

/// AUD-16 at the NAMES continuation timer. A local JOIN deferred behind a
/// NAMES continuation that waits on a full queue resumes when the timer
/// delivers that continuation's last page, and is applied in that same timer
/// step, which must open its snapshot.
#[tokio::test]
async fn a_local_join_resumed_by_the_names_timer_answers_in_that_step() -> TestResult {
    let mut core = Core::new()?;
    let sink = congested_join(&mut core).await?;
    core.line(1, "JOIN &loc")?;
    assert!(!saw(&sink, " JOIN &loc"), "lines: {:?}", sink.lines());
    sink.set_congested(false);
    let now = core.fixture.context_mut()?.now().get();
    core.fixture.context_mut()?.set_monotonic_for_test(now + 50);
    assert!(core.fixture.state_mut()?.step_wake().is_none());
    let lines = sink.lines();
    let slow = line_index(&lines, " 366 waiter #slow ");
    let local = line_index(&lines, " 366 waiter &loc ");
    assert!(slow.is_some() && slow < local, "lines: {lines:?}");
    assert!(!core.holds_local_join_seed(1)?);
    Ok(())
}

/// AUD-16 behind a staged JOIN. A local JOIN deferred behind a `#` JOIN
/// resumes in the commit step of that JOIN's batch, once its NAMES end, and is
/// applied in that same step. The commit step must open this snapshot too, so
/// the JOIN answers and the TIME behind it runs.
#[tokio::test]
async fn a_local_join_behind_a_staged_join_answers_in_its_commit_step() -> TestResult {
    let mut core = Core::new()?;
    let sink = core.open(1)?;
    core.line(1, "NICK piper")?;
    core.line(1, "USER piper 0 * :Piper")?;
    core.settle().await?;
    core.line(1, "JOIN #room")?;
    core.line(1, "JOIN &loc")?;
    core.line(1, "TIME")?;
    assert!(!saw(&sink, " 366 "), "lines: {:?}", sink.lines());
    core.settle().await?;
    let lines = sink.lines();
    let room = line_index(&lines, " 366 piper #room ");
    let local = line_index(&lines, " 366 piper &loc ");
    let time = line_index(&lines, " 391 piper ");
    assert!(
        room.is_some() && room < local && local < time,
        "lines: {lines:?}"
    );
    assert!(!core.holds_local_join_seed(1)?);
    Ok(())
}

/// AUD-16 at the welcome. A local JOIN sent before registration completes
/// runs in the commit step of the registration, after the welcome, and is
/// applied in that same step. The commit step must open its snapshot, so the
/// JOIN answers and the TIME behind it runs.
#[tokio::test]
async fn a_local_join_sent_before_the_welcome_answers_in_its_commit_step() -> TestResult {
    let mut core = Core::new()?;
    let sink = core.open(1)?;
    core.line(1, "NICK early")?;
    core.line(1, "USER early 0 * :Early")?;
    core.line(1, "JOIN &loc")?;
    core.line(1, "TIME")?;
    core.settle().await?;
    let lines = sink.lines();
    let welcome = line_index(&lines, " 001 early ");
    let local = line_index(&lines, " 366 early &loc ");
    let time = line_index(&lines, " 391 early ");
    assert!(
        welcome.is_some() && welcome < local && local < time,
        "lines: {lines:?}"
    );
    assert!(!core.holds_local_join_seed(1)?);
    Ok(())
}

/// A registered owner of `#locked` whose key MODE is waiting on its
/// channel-key construction job.
async fn pending_key_mode(core: &mut Core) -> TestResult<Arc<FrameSink>> {
    let sink = core.open(1)?;
    core.line(1, "NICK owner")?;
    core.line(1, "USER owner 0 * :Owner")?;
    core.settle().await?;
    core.line(1, "JOIN #locked")?;
    core.settle().await?;
    core.line(1, "MODE #locked +k secretkey")?;
    assert_eq!(
        core.fixture
            .context_mut()?
            .crypto_mut()
            .snapshot_in_flight(),
        1
    );
    Ok(sink)
}

#[tokio::test]
async fn a_channel_key_mode_defers_behind_its_job_and_resumes_when_it_completes() -> TestResult {
    let mut core = Core::new()?;
    let sink = pending_key_mode(&mut core).await?;
    let before = sink.lines().len();
    core.line(1, "MODE #locked +k otherkey")?;
    assert!(
        sink.lines().len() > before,
        "a second key command while one is pending is answered: {:?}",
        sink.lines()
    );
    let completion = core.fixture.next_crypto_completion().await?;
    core.fixture.state_mut()?.step_crypto(completion);
    core.settle().await?;
    assert!(saw(&sink, "+k"), "lines: {:?}", sink.lines());
    Ok(())
}

#[tokio::test]
async fn a_failed_channel_key_job_answers_busy() -> TestResult {
    let mut core = Core::new()?;
    let sink = pending_key_mode(&mut core).await?;
    let before = sink.lines().len();
    let completion = core.fixture.next_crypto_completion().await?;
    core.fixture
        .state_mut()?
        .step_crypto(crate::bridge::CryptoCompletionMessage {
            job_id: completion.job_id,
            output: Err(agenc_relay_crypto::CryptoWorkerError::QueueFull),
        });
    assert!(sink.lines().len() > before, "lines: {:?}", sink.lines());
    assert!(!saw(&sink, "+k"), "lines: {:?}", sink.lines());
    Ok(())
}

#[tokio::test]
async fn a_pending_channel_key_job_expires_at_its_deadline() -> TestResult {
    let mut core = Core::new()?;
    let sink = pending_key_mode(&mut core).await?;
    let before = sink.lines().len();
    core.fixture
        .context_mut()?
        .set_monotonic_for_test(FROZEN_TICKS + 30_000 + 10);
    assert!(core.fixture.state_mut()?.step_wake().is_none());
    assert!(sink.lines().len() > before, "lines: {:?}", sink.lines());
    assert_eq!(core.fixture.context_mut()?.crypto_mut().in_flight(), 0);
    assert!(!saw(&sink, "+k"), "lines: {:?}", sink.lines());
    Ok(())
}

#[tokio::test]
async fn commands_deferred_behind_a_join_stop_at_the_deferral_ceiling() -> TestResult {
    let mut core = Core::new()?;
    let sink = core.open(1)?;
    core.line(1, "NICK stacker")?;
    core.line(1, "USER stacker 0 * :Stacker")?;
    core.settle().await?;
    core.line(1, "JOIN #stack")?;
    for _ in 0..33 {
        core.line(1, "TOPIC #stack")?;
    }
    let open = core
        .fixture
        .context_mut()?
        .sessions()
        .sink_for_generation(ConnectionGeneration::new(1))
        .is_some();
    assert!(!open, "the command over the ceiling closes the connection");
    core.settle().await?;
    let lines = sink.lines();
    let topics = lines.iter().filter(|line| line.contains(" 331 ")).count();
    assert!(topics <= 1, "deferred commands never answer: {lines:?}");
    Ok(())
}

/// Registers one guest and joins it to a fresh channel while its sink reports a
/// queue above half, so the NAMES continuation waits for the queue instead of
/// delivering its page.
async fn congested_join(core: &mut Core) -> TestResult<Arc<FrameSink>> {
    let sink = core.open(1)?;
    core.line(1, "NICK waiter")?;
    core.line(1, "USER waiter 0 * :Waiter")?;
    core.settle().await?;
    sink.set_congested(true);
    core.line(1, "JOIN #slow")?;
    core.settle().await?;
    assert!(saw(&sink, "JOIN"), "lines: {:?}", sink.lines());
    assert!(
        !saw(&sink, " 366 "),
        "the names page waits: {:?}",
        sink.lines()
    );
    Ok(sink)
}

#[tokio::test]
async fn a_names_continuation_waiting_on_a_full_queue_expires_at_its_idle_deadline() -> TestResult {
    let mut core = Core::new()?;
    let sink = congested_join(&mut core).await?;
    let now = core.fixture.context_mut()?.now().get();
    core.fixture.context_mut()?.set_monotonic_for_test(now + 50);
    assert!(core.fixture.state_mut()?.step_wake().is_none());
    assert!(!saw(&sink, " 366 "), "still waiting: {:?}", sink.lines());
    let open = core
        .fixture
        .context_mut()?
        .sessions()
        .sink_for_generation(ConnectionGeneration::new(1))
        .is_some();
    assert!(open, "a waiting continuation keeps its connection");
    core.fixture
        .context_mut()?
        .set_monotonic_for_test(now + 60_000);
    assert!(core.fixture.state_mut()?.step_wake().is_none());
    let open = core
        .fixture
        .context_mut()?
        .sessions()
        .sink_for_generation(ConnectionGeneration::new(1))
        .is_some();
    assert!(!open, "the idle deadline closes the connection");
    assert!(!saw(&sink, " 366 "), "lines: {:?}", sink.lines());
    Ok(())
}

#[tokio::test]
async fn a_names_continuation_delivers_once_the_queue_drains() -> TestResult {
    let mut core = Core::new()?;
    let sink = congested_join(&mut core).await?;
    sink.set_congested(false);
    let now = core.fixture.context_mut()?.now().get();
    core.fixture.context_mut()?.set_monotonic_for_test(now + 50);
    assert!(core.fixture.state_mut()?.step_wake().is_none());
    assert!(
        saw(&sink, " 366 waiter #slow "),
        "lines: {:?}",
        sink.lines()
    );
    let open = core
        .fixture
        .context_mut()?
        .sessions()
        .sink_for_generation(ConnectionGeneration::new(1))
        .is_some();
    assert!(open, "a delivered continuation keeps its connection");
    Ok(())
}

#[tokio::test]
async fn a_published_motd_is_rendered_line_by_line_after_the_welcome() -> TestResult {
    let mut core = Core::new()?;
    core.fixture
        .context_mut()?
        .set_motd_for_test(Some("first line\nsecond line"));
    let sink = core.open(1)?;
    core.line(1, "NICK reader")?;
    core.line(1, "USER reader 0 * :Reader")?;
    core.settle().await?;
    let lines = sink.lines();
    let welcome = lines.iter().position(|line| line.contains(" 001 reader "));
    let start = lines.iter().position(|line| line.contains(" 375 reader "));
    let first = lines
        .iter()
        .position(|line| line.contains(" 372 reader :first line"));
    let second = lines
        .iter()
        .position(|line| line.contains(" 372 reader :second line"));
    let end = lines.iter().position(|line| line.contains(" 376 reader "));
    assert!(welcome < start && start < first, "lines: {lines:?}");
    assert!(first < second && second < end, "lines: {lines:?}");
    assert!(!saw(&sink, " 422 "), "lines: {lines:?}");
    Ok(())
}
