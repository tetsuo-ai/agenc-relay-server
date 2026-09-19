//! Client lines through the state core itself, where each line owns a command
//! observation: pre-registration admission and input deferred behind a commit.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use super::test_harness::{TestResult, entropy_script, parsed, saw};
use super::*;
use crate::connection::sink::ClientSink;
use crate::state_core::inbox::{SourceAddressKey, StateCoreMessage};
use crate::test_support::{FrameSink, StateCoreFixture};

/// A state core that owns the production registration router.
struct Core {
    fixture: StateCoreFixture,
    sequences: BTreeMap<u64, u64>,
}

impl Core {
    fn new() -> TestResult<Self> {
        Ok(Self {
            fixture: StateCoreFixture::with_registration_router(entropy_script())?,
            sequences: BTreeMap::new(),
        })
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
    core.fixture.commit_staged_batch().await?;
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
    core.fixture.commit_staged_batch().await?;
    core.line(1, "JOIN #room")?;
    core.line(1, "TOPIC #room")?;
    assert!(!saw(&sink, " 331 "), "lines: {:?}", sink.lines());
    core.fixture.commit_staged_batch().await?;
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
