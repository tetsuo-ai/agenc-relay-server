//! A committed plan that no longer applies ends the core, a refused edge
//! checkpoint is counted, and a query snapshot never exceeds its reservation.
#![forbid(unsafe_code)]

use agenc_ircd_client_wire::CapabilityState;
use agenc_ircd_crypto::StorageDigest;
use agenc_ircd_storage::{CommitOutcome, CommitReceipt};

use super::support::{account_plan, empty_fanout, observe};
use super::*;
use crate::bridge::StorageCompletionMessage;
use crate::observe::metrics::{CommandClass, ResultClass};
use crate::state_core::{
    BatchStep, CommandObservation, CompletionStep, CorruptionCause, StagedOrigin,
};
use crate::test_support::{apply_live_plan, bind_live_session, seed_session};

fn observed_origin(class: CommandClass) -> StagedOrigin {
    StagedOrigin::silent(ConnectionGeneration::new(1))
        .with_observation(Some(CommandObservation::new(class)))
}

#[test]
fn a_committed_batch_whose_plan_went_stale_ends_the_core_and_errors_every_command() -> TestResult {
    let mut twin = StateCoreFixture::new(Vec::new())?;
    let first_there = account_plan(twin.context_mut()?, 7)?;
    apply_live_plan(twin.context_mut()?, first_there)?;
    let second = account_plan(twin.context_mut()?, 8)?;

    let mut fixture = StateCoreFixture::with_registration_router(vec![7; 4096])?;
    let observed = observe(fixture.state_mut()?);
    let state = fixture.state_mut()?;
    let first = account_plan(&state.context, 7)?;
    let intruder = account_plan(&state.context, 9)?;
    for (plan, class) in [
        (first, CommandClass::Session),
        (second, CommandClass::Channel),
    ] {
        state
            .context
            .stage_durable(plan, empty_fanout()?, Some(observed_origin(class)), 0)
            .map_err(|refused| format!("{refused:?}"))?;
    }
    assert!(matches!(
        state.context.submit_batch(),
        Ok(BatchStep::Submitted)
    ));
    let transaction_id = state
        .context
        .pending
        .as_ref()
        .and_then(|batch| batch.transaction_id())
        .ok_or("no transaction in flight")?;
    // The revision moves underneath the batch storage already holds.
    state.context.apply_plan(intruder)?;
    let step = state.step_completion(StorageCompletionMessage {
        transaction_id,
        outcome: CommitOutcome::Committed(CommitReceipt {
            transaction_id,
            storage_commit_sequence: 2,
            state_generation: 1,
            rollback_guard_hash: StorageDigest::from_bytes([6; 32]),
        }),
    });
    assert!(matches!(
        step,
        CompletionStep::Ready(Some(StateCoreExit::Corrupt(CorruptionCause::ApplyFailed)))
    ));
    assert_eq!(state.context.counters.batches_committed, 0);
    assert_eq!(
        observed.commands(CommandClass::Session, ResultClass::Error)?,
        1
    );
    assert_eq!(
        observed.commands(CommandClass::Channel, ResultClass::Error)?,
        1
    );
    Ok(())
}

#[test]
fn an_edge_checkpoint_refused_by_quiescence_is_counted_not_lost_silently() -> TestResult {
    let mut fixture = StateCoreFixture::with_federation_coordinator(vec![7; 4096], Vec::new())?;
    let context = fixture.context_mut()?;
    let edge = agenc_ircd_types::ServerId::from_bytes(agenc_ircd_testkit::bytes(240));
    context.federation_mut().ok_or("no projector")?.set_edge(
        edge,
        crate::state_core::projector::EdgeDelivery {
            projection_generation: 1,
            next_delivery_sequence: 0,
        },
    );
    context.quiescing = true;
    let _late = seed_session(context, 6, "inkpot", None)?;
    assert_eq!(context.counters.projection_refusals, 1);
    assert_eq!(context.pending_len(), 0, "no checkpoint batch was staged");
    assert_eq!(
        context.domain().session_count(),
        1,
        "the plan still applied"
    );
    Ok(())
}

#[test]
fn a_query_snapshot_larger_than_its_reservation_is_refused() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let context = fixture.context_mut()?;
    let identity = seed_session(context, 5, "quill", None)?;
    let _sink = bind_live_session(context, 1, identity, CapabilityState::default(), true)?;
    let generation = ConnectionGeneration::new(1);
    for (rows, backing) in [(5, 64), (4, 65)] {
        let prepared = context.prepare_query_snapshot(generation, 4, 64)?;
        assert!(matches!(
            prepared.finish(rows, backing),
            Err(crate::RuntimeError::LimitExceeded)
        ));
    }
    let charged = context.backing_budget_for_test().charged();
    let exact = context.prepare_query_snapshot(generation, 4, 64)?;
    assert!(exact.finish(4, 64).is_ok());
    assert_eq!(context.backing_budget_for_test().charged(), charged);
    assert!(matches!(
        context.prepare_query_snapshot(ConnectionGeneration::new(9), 4, 64),
        Err(crate::RuntimeError::InvalidValue)
    ));
    Ok(())
}
