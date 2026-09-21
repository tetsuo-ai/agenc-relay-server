//! Single inbox steps: default replies, dropped lines, refused opens and
//! close notices the session table never admitted.
#![forbid(unsafe_code)]

use agenc_relay_client_wire::CapabilityState;

use super::support::{account_plan, empty_fanout, observe};
use super::*;
use crate::budget::{BoundedMemoryCharges, MemoryBudget, MemoryBudgetPort, MemoryCharge};
use crate::observe::adapter::RuntimeObserver;
use crate::observe::metrics::{CommandClass, ResultClass};
use crate::state_core::inbox::{CloseReason, ConnectionStatePermit, PhysicalCloseNotice};
use crate::state_core::{
    BatchStep, CommandObservation, CorruptionCause, StagedOrigin, StateCore, client_input,
};
use crate::test_support::{bind_live_session, seed_session};

fn line(text: &str) -> TestResult<agenc_relay_client_wire::ParsedMessage> {
    Ok(parse_message(FramedLine::new(text)?)?.ok_or("empty line")?)
}

fn open(
    state: &mut StateCore,
    generation: u64,
    admit: bool,
) -> TestResult<(Arc<FrameSink>, ConnectionOpenOutcome)> {
    let generation = ConnectionGeneration::new(generation);
    let sink = FrameSink::new(generation, admit);
    let (acknowledgement, mut accepted) = oneshot::channel();
    let exit = state.step_message(StateCoreMessage::Opened {
        generation,
        purpose: ListenerPurpose::ClientOnion,
        source: SourceAddressKey::onion_listener(),
        sink: Arc::clone(&sink) as Arc<dyn ClientSink>,
        acknowledgement,
    });
    if exit.is_some() {
        return Err(format!("open ended the core: {exit:?}").into());
    }
    Ok((sink, accepted.try_recv()?))
}

fn close_notice(generation: u64) -> TestResult<PhysicalCloseNotice> {
    let budget = MemoryBudget::new(1);
    let mut permits =
        budget.try_acquire_batch(BoundedMemoryCharges::new(&[MemoryCharge::fixed(1)])?)?;
    let permit = permits.split_exact(1).ok_or("memory permit")?;
    let (return_permit, _returned) = oneshot::channel();
    Ok(PhysicalCloseNotice {
        generation: ConnectionGeneration::new(generation),
        reason: CloseReason::TransportLoss,
        closed_at: None,
        final_line_sequence: 0,
        state_permit: ConnectionStatePermit::new(permit, return_permit),
    })
}

fn is_connection_state_failure(exit: Option<StateCoreExit>) -> bool {
    matches!(
        exit,
        Some(StateCoreExit::Corrupt(
            CorruptionCause::ConnectionStateFailed
        ))
    )
}

#[test]
fn the_default_router_tells_a_registered_session_its_command_is_unknown() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let identity = seed_session(fixture.context_mut()?, 5, "quill", None)?;
    let sink = bind_live_session(
        fixture.context_mut()?,
        1,
        identity,
        CapabilityState::default(),
        true,
    )?;
    let state = fixture.state_mut()?;
    assert!(
        state
            .route_line(ConnectionGeneration::new(1), 1, line("BOGUS now")?)
            .is_none()
    );
    assert_eq!(
        sink.lines(),
        [":server.example 421 * BOGUS :Unknown command"]
    );
    Ok(())
}

/// Charges the whole remaining memory budget, largest pieces first.
fn exhaust_budget(state: &StateCore) -> Vec<crate::budget::MemoryPermit> {
    (0..40_u32)
        .rev()
        .filter_map(|shift| state.context.reserve_output_backing(1_usize << shift).ok())
        .collect()
}

#[test]
fn a_default_reply_the_memory_budget_cannot_hold_is_observed_busy() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let observed = observe(fixture.state_mut()?);
    let state = fixture.state_mut()?;
    let (sink, outcome) = open(state, 1, true)?;
    assert!(matches!(outcome, ConnectionOpenOutcome::Accepted));
    let hog = exhaust_budget(state);
    assert!(!hog.is_empty());
    assert!(
        state
            .route_line(ConnectionGeneration::new(1), 1, line("PING :probe")?)
            .is_none()
    );
    assert!(sink.lines().is_empty());
    let class = RuntimeObserver::classify_command("PING");
    assert_eq!(observed.commands(class, ResultClass::Busy)?, 1);
    assert_eq!(observed.commands(class, ResultClass::Rejected)?, 0);
    Ok(())
}

#[test]
fn a_line_is_dropped_unrouted_once_the_core_quiesces() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let state = fixture.state_mut()?;
    let (sink, _outcome) = open(state, 1, true)?;
    state.context.quiescing = true;
    assert!(
        state
            .route_line(ConnectionGeneration::new(1), 1, line("PING :late")?)
            .is_none()
    );
    assert!(sink.lines().is_empty());
    assert_eq!(state.context.counters.lines_dropped, 1);
    assert_eq!(state.context.counters.lines_routed, 0);
    Ok(())
}

#[test]
fn a_line_for_a_connection_nobody_opened_is_dropped() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let state = fixture.state_mut()?;
    assert!(
        state
            .route_line(ConnectionGeneration::new(9), 1, line("PING :ghost")?)
            .is_none()
    );
    assert_eq!(state.context.counters.lines_dropped, 1);
    Ok(())
}

#[test]
fn an_open_beyond_the_client_input_capacity_is_refused() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let state = fixture.state_mut()?;
    state.client_inputs = Some(client_input::ClientInputs::new(
        1,
        state.context.backing_reservations(),
    )?);
    let (_first_sink, first) = open(state, 1, true)?;
    assert!(matches!(first, ConnectionOpenOutcome::AcceptedInput(_)));
    let (_second_sink, second) = open(state, 2, true)?;
    assert!(matches!(second, ConnectionOpenOutcome::Refused));
    assert_eq!(state.context.sessions().len(), 1);
    assert_eq!(state.context.counters.connections_opened, 1);
    drop(first);
    Ok(())
}

#[test]
fn a_second_open_of_a_live_generation_is_refused() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let state = fixture.state_mut()?;
    let (_sink, first) = open(state, 1, true)?;
    assert!(matches!(first, ConnectionOpenOutcome::Accepted));
    let (_duplicate, second) = open(state, 1, true)?;
    assert!(matches!(second, ConnectionOpenOutcome::Refused));
    assert_eq!(state.context.sessions().len(), 1);
    Ok(())
}

#[test]
fn a_close_notice_for_a_connection_nobody_opened_ends_the_core() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let state = fixture.state_mut()?;
    assert!(is_connection_state_failure(
        state.step_physical_close(close_notice(9)?)
    ));
    assert!(is_connection_state_failure(
        state.finish_physical_close(close_notice(9)?)
    ));
    assert_eq!(state.context.counters.connections_closed, 0);
    Ok(())
}

#[test]
fn a_close_notice_releases_its_connection_exactly_once() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let state = fixture.state_mut()?;
    let (_sink, _outcome) = open(state, 1, true)?;
    assert!(state.step_physical_close(close_notice(1)?).is_none());
    assert_eq!(state.context.sessions().len(), 0);
    assert_eq!(state.context.counters.connections_closed, 1);
    assert!(is_connection_state_failure(
        state.step_physical_close(close_notice(1)?)
    ));
    Ok(())
}

#[test]
fn nothing_is_submitted_without_a_gathering_batch() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![9; 64])?;
    let context = fixture.context_mut()?;
    assert!(matches!(context.submit_batch(), Ok(BatchStep::Idle)));
    assert!(matches!(context.drive_batch(), Ok(BatchStep::Idle)));
    assert!(!context.in_flight());
    Ok(())
}

#[test]
fn a_due_batch_without_transaction_entropy_ends_the_core_as_an_observed_error() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let observed = observe(fixture.state_mut()?);
    let state = fixture.state_mut()?;
    let plan = account_plan(&state.context, 7)?;
    let origin = StagedOrigin::silent(ConnectionGeneration::new(1))
        .with_observation(Some(CommandObservation::new(CommandClass::Session)));
    state
        .context
        .stage_durable(plan, empty_fanout()?, Some(origin), 0)
        .map_err(|refused| format!("{refused:?}"))?;
    assert!(
        state.step_wake().is_none(),
        "the gather window is still open"
    );
    state.context.monotonic = Box::new(agenc_relay_testkit::DeterministicMonotonicClock::at(100));
    assert!(matches!(
        state.step_wake(),
        Some(StateCoreExit::Corrupt(CorruptionCause::ProjectionFailed))
    ));
    assert_eq!(state.context.pending_len(), 0);
    assert_eq!(
        observed.commands(CommandClass::Session, ResultClass::Error)?,
        1
    );
    Ok(())
}
