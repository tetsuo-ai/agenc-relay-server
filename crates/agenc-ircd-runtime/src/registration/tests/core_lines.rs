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
