//! Administrative requests are refused at the safe point with one exact
//! failure and never leave a half-submitted commit behind.
#![forbid(unsafe_code)]

use agenc_ircd_admin::{AdminAuditCheckpoint, AdminAuditCheckpointTbs, AdminAuditPhase};
use agenc_ircd_client_wire::CapabilityState;
use agenc_ircd_types::{ServerId, UtcSecond};

use super::support::{account_plan, audit_event, empty_fanout};
use super::*;
use crate::state_core::admin::{
    AdminCoreFailure, AdminCoreRequest, AdminCoreResult, AdminMutation,
};
use crate::state_core::{CorruptionCause, StateCore};
use crate::test_support::{bind_live_session, seed_account, seed_session};

/// Steps one request and returns the core exit with the operator's answer.
fn ask(
    state: &mut StateCore,
    build: impl FnOnce(oneshot::Sender<AdminCoreResult>) -> TestResult<AdminCoreRequest>,
) -> TestResult<(Option<StateCoreExit>, Option<AdminCoreResult>)> {
    let (reply, mut response) = oneshot::channel();
    let exit = state.step_admin_request(build(reply)?);
    Ok((exit, response.try_recv().ok()))
}

fn audit(reply: oneshot::Sender<AdminCoreResult>) -> TestResult<AdminCoreRequest> {
    Ok(AdminCoreRequest::CommitAudit {
        event: Box::new(audit_event(AdminAuditPhase::Observed, b"MOTD")?),
        reply,
    })
}

fn retention(reply: oneshot::Sender<AdminCoreResult>) -> TestResult<AdminCoreRequest> {
    let audit_key = agenc_ircd_crypto::Ed25519SecretKey::from_bytes([22; 32]);
    let key_id = agenc_ircd_crypto::audit_signing_key_id(audit_key.public_key().as_bytes())?;
    let checkpoint = AdminAuditCheckpoint::sign(
        AdminAuditCheckpointTbs {
            network_id: agenc_ircd_types::NetworkId::from_bytes([1; 32]),
            server_id: ServerId::from_bytes([2; 16]),
            audit_signing_key_id: *key_id.as_bytes(),
            checkpoint_sequence: 0,
            created_at: 60,
            deleted_first_sequence: 0,
            deleted_last_sequence: 0,
            deleted_count: 1,
            deleted_last_event_hash: [7; 32],
            next_retained_sequence: 1,
            previous_checkpoint_hash: [0; 32],
        },
        &audit_key,
    )?;
    Ok(AdminCoreRequest::CommitRetention {
        checkpoint: Box::new(checkpoint),
        reply,
    })
}

fn is_projection_failure(exit: Option<StateCoreExit>) -> bool {
    matches!(
        exit,
        Some(StateCoreExit::Corrupt(CorruptionCause::ProjectionFailed))
    )
}

#[test]
fn kill_is_refused_while_quiescing() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let user = seed_session(fixture.context_mut()?, 5, "quill", None)?.user_id;
    let state = fixture.state_mut()?;
    state.context.quiescing = true;
    let (exit, answer) = ask(state, |reply| {
        Ok(AdminCoreRequest::Kill {
            user_id: user,
            reply,
        })
    })?;
    assert!(exit.is_none());
    assert_eq!(answer, Some(Err(AdminCoreFailure::Quiescing)));
    Ok(())
}

#[test]
fn kill_of_a_session_without_a_live_connection_is_an_invalid_target() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let user = seed_session(fixture.context_mut()?, 5, "quill", None)?.user_id;
    let state = fixture.state_mut()?;
    assert_eq!(state.admin_kill(user), Err(AdminCoreFailure::InvalidTarget));
    assert_eq!(state.context.domain().session_count(), 1);
    Ok(())
}

#[test]
fn kill_closes_the_bound_connection_once_and_then_finds_no_target() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let identity = seed_session(fixture.context_mut()?, 5, "quill", None)?;
    let _sink = bind_live_session(
        fixture.context_mut()?,
        1,
        identity,
        CapabilityState::default(),
        true,
    )?;
    let state = fixture.state_mut()?;
    let generation = ConnectionGeneration::new(1);
    assert_eq!(state.admin_kill(identity.user_id), Ok(()));
    assert!(
        state
            .context
            .sessions()
            .sink_for_generation(generation)
            .is_none(),
        "a killed connection receives no later output"
    );
    assert_eq!(
        state.admin_kill(identity.user_id),
        Err(AdminCoreFailure::InvalidTarget)
    );
    Ok(())
}

#[test]
fn peer_quarantine_is_refused_while_quiescing_and_unknown_without_a_federation_role() -> TestResult
{
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let state = fixture.state_mut()?;
    let server = ServerId::from_bytes([4; 16]);
    let (exit, answer) = ask(state, |reply| {
        Ok(AdminCoreRequest::PeerQuarantine { server, reply })
    })?;
    assert!(exit.is_none());
    assert_eq!(answer, Some(Err(AdminCoreFailure::InvalidTarget)));
    state.context.quiescing = true;
    assert_eq!(
        state.admin_peer_quarantine(server),
        Err(AdminCoreFailure::Quiescing)
    );
    Ok(())
}

#[test]
fn account_mutations_are_validated_against_revision_expiry_and_suspension() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let (account_id, _) = seed_account(fixture.context_mut()?, 31, 1)?;
    let state = fixture.state_mut()?;
    let revision = state
        .context
        .domain()
        .account(account_id)
        .ok_or("account")?
        .revision();
    let now = state.context.utc_now()?;
    let expired = AdminMutation::SuspendAccount {
        account_id,
        expires_at: now,
    };
    let live = AdminMutation::SuspendAccount {
        account_id,
        expires_at: UtcSecond::from_unix_seconds(now.get() + 1),
    };
    assert_eq!(
        state.validate_admin_mutation(expired, revision),
        Err(AdminCoreFailure::InvalidTarget)
    );
    assert_eq!(state.validate_admin_mutation(live, revision), Ok(()));
    assert_eq!(
        state.validate_admin_mutation(live, revision.checked_add(1)?),
        Err(AdminCoreFailure::StaleRevision)
    );
    assert_eq!(
        state.validate_admin_mutation(AdminMutation::RestoreAccount(account_id), revision),
        Err(AdminCoreFailure::InvalidTarget)
    );
    Ok(())
}

#[test]
fn a_mutation_whose_audit_event_names_another_command_ends_the_core() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![9; 4096])?;
    let (account_id, _) = seed_account(fixture.context_mut()?, 31, 1)?;
    let state = fixture.state_mut()?;
    let revision = state.context.domain().revision();
    let (exit, answer) = ask(state, |reply| {
        Ok(AdminCoreRequest::CommitMutation {
            event: Box::new(audit_event(AdminAuditPhase::CommittedMutation, b"MOTD")?),
            mutation: AdminMutation::RestoreAccount(account_id),
            expected_revision: revision,
            reply,
        })
    })?;
    assert!(is_projection_failure(exit));
    assert_eq!(answer, None);
    assert!(state.admin_pending.is_none());
    Ok(())
}

#[test]
fn an_audit_commit_is_refused_while_quiescing_and_busy_behind_a_gathering_batch() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![9; 4096])?;
    let state = fixture.state_mut()?;
    let plan = account_plan(&state.context, 7)?;
    state
        .context
        .stage_durable(plan, empty_fanout()?, None, 0)
        .map_err(|refused| format!("{refused:?}"))?;
    let (exit, answer) = ask(state, audit)?;
    assert!(exit.is_none());
    assert_eq!(answer, Some(Err(AdminCoreFailure::Busy)));
    let (exit, answer) = ask(state, retention)?;
    assert!(exit.is_none());
    assert_eq!(answer, Some(Err(AdminCoreFailure::Busy)));

    state.context.quiescing = true;
    let (exit, answer) = ask(state, audit)?;
    assert!(exit.is_none());
    assert_eq!(answer, Some(Err(AdminCoreFailure::Quiescing)));
    assert!(state.admin_pending.is_none());
    Ok(())
}

#[test]
fn an_audit_commit_is_busy_while_an_earlier_admin_commit_is_in_flight() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![9; 4096])?;
    let state = fixture.state_mut()?;
    let (exit, answer) = ask(state, audit)?;
    assert!(exit.is_none());
    assert_eq!(answer, None, "the first commit waits for its receipt");
    let first = state
        .admin_pending
        .as_ref()
        .map(|pending| pending.transaction_id);
    let (exit, answer) = ask(state, audit)?;
    assert!(exit.is_none());
    assert_eq!(answer, Some(Err(AdminCoreFailure::Busy)));
    let (exit, answer) = ask(state, retention)?;
    assert!(exit.is_none());
    assert_eq!(answer, Some(Err(AdminCoreFailure::Busy)));
    assert_eq!(
        state
            .admin_pending
            .as_ref()
            .map(|pending| pending.transaction_id),
        first
    );
    Ok(())
}

#[test]
fn admin_commits_without_transaction_entropy_end_the_core_before_submission() -> TestResult {
    for build in [audit, retention] {
        let mut fixture = StateCoreFixture::new(Vec::new())?;
        let state = fixture.state_mut()?;
        let (exit, answer) = ask(state, build)?;
        assert!(is_projection_failure(exit));
        assert_eq!(answer, None);
        assert!(state.admin_pending.is_none());
    }
    Ok(())
}

#[test]
fn a_retention_checkpoint_over_events_storage_never_held_is_refused() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![9; 4096])?;
    let state = fixture.state_mut()?;
    let (exit, answer) = ask(state, retention)?;
    assert!(exit.is_none(), "{exit:?}");
    assert_eq!(answer, Some(Err(AdminCoreFailure::StorageUnavailable)));
    assert!(state.admin_pending.is_none());
    Ok(())
}
