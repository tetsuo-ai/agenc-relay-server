//! Durable and ephemeral staging refuses exactly when its safe point is taken.
#![forbid(unsafe_code)]

use agenc_ircd_domain::DomainError;

use super::support::{account_plan, empty_fanout, observe};
use super::*;
use crate::observe::metrics::{CommandClass, ResultClass};
use crate::state_core::fanout::FanoutRefused;
use crate::state_core::{
    CommandObservation, EphemeralRefused, StageAccepted, StageRefused, StagedOrigin,
};

fn observed_origin() -> StagedOrigin {
    StagedOrigin::silent(ConnectionGeneration::new(1))
        .with_observation(Some(CommandObservation::new(CommandClass::Channel)))
}

#[test]
fn an_ephemeral_plan_is_refused_busy_while_a_durable_batch_gathers() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let context = fixture.context_mut()?;
    let staged = account_plan(context, 7)?;
    let ephemeral = account_plan(context, 8)?;
    assert!(matches!(
        context.stage_durable(staged, empty_fanout()?, None, 0),
        Ok(StageAccepted::Staged { plans_in_batch: 1 })
    ));
    let revision = context.domain().revision();
    let refused = context.apply_ephemeral(ephemeral, empty_fanout()?);
    assert!(
        matches!(
            refused,
            Err(EphemeralRefused::Domain(DomainError::ServerBusy))
        ),
        "{:?}",
        refused.err()
    );
    assert_eq!(context.domain().revision(), revision);
    assert_eq!(context.pending_len(), 1);
    Ok(())
}

#[test]
fn a_shutdown_session_close_without_one_hidden_session_is_refused() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let context = fixture.context_mut()?;
    let plan = account_plan(context, 7)?;
    let refused = context.stage_shutdown_session_close(plan, empty_fanout()?);
    assert!(
        matches!(
            refused,
            Err(StageRefused::Domain(DomainError::InvariantViolation))
        ),
        "{:?}",
        refused.err()
    );
    assert_eq!(context.pending_len(), 0);
    Ok(())
}

#[test]
fn a_plan_chained_on_the_gathering_batch_joins_it() -> TestResult {
    // A twin fixture starts from identical state, so a plan made after the
    // first account exists there chains on the first plan staged here.
    let mut twin = StateCoreFixture::new(Vec::new())?;
    let first_there = account_plan(twin.context_mut()?, 7)?;
    crate::test_support::apply_live_plan(twin.context_mut()?, first_there)?;
    let second = account_plan(twin.context_mut()?, 8)?;

    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let context = fixture.context_mut()?;
    let first = account_plan(context, 7)?;
    assert_eq!(first.resulting_revision(), second.expected_revision());
    assert!(matches!(
        context.stage_durable(first, empty_fanout()?, None, 0),
        Ok(StageAccepted::Staged { plans_in_batch: 1 })
    ));
    assert!(matches!(
        context.stage_durable(second, empty_fanout()?, None, 0),
        Ok(StageAccepted::Staged { plans_in_batch: 2 })
    ));
    assert_eq!(context.pending_len(), 2);
    Ok(())
}

#[test]
fn an_unchained_plan_is_refused_busy_and_its_command_is_observed_busy() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let observed = observe(fixture.state_mut()?);
    let context = fixture.context_mut()?;
    let first = account_plan(context, 7)?;
    let unchained = account_plan(context, 8)?;
    assert!(
        context
            .stage_durable(first, empty_fanout()?, None, 0)
            .is_ok()
    );
    let refused = context.stage_durable(unchained, empty_fanout()?, Some(observed_origin()), 0);
    assert!(
        matches!(refused, Err(StageRefused::Busy)),
        "{:?}",
        refused.err()
    );
    assert_eq!(context.pending_len(), 1);
    assert_eq!(
        observed.commands(CommandClass::Channel, ResultClass::Busy)?,
        1
    );
    Ok(())
}

fn stage_at_the_last_tick(origin: Option<StagedOrigin>) -> TestResult<Option<u64>> {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let observed = observe(fixture.state_mut()?);
    let context = fixture.context_mut()?;
    context.monotonic = Box::new(agenc_ircd_testkit::DeterministicMonotonicClock::at(
        u64::MAX,
    ));
    let plan = account_plan(context, 7)?;
    let refused = context.stage_durable(plan, empty_fanout()?, origin, 0);
    if !matches!(
        refused,
        Err(StageRefused::Fanout(FanoutRefused::Invalid(
            crate::RuntimeError::Overflow
        )))
    ) {
        return Ok(None);
    }
    assert_eq!(context.pending_len(), 0);
    Ok(Some(
        observed.commands(CommandClass::Channel, ResultClass::Error)?,
    ))
}

#[test]
fn a_gather_window_past_the_last_tick_refuses_the_plan_as_an_observed_error() -> TestResult {
    assert_eq!(stage_at_the_last_tick(Some(observed_origin()))?, Some(1));
    assert_eq!(stage_at_the_last_tick(None)?, Some(0));
    Ok(())
}
