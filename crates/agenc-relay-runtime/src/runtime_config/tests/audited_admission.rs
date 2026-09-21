//! Reload admission distinguishes unsent requests from lost acknowledgements.
#![forbid(unsafe_code)]

use super::*;
use crate::cancel::CancellationToken;
use crate::test_support::TestResult;
use agenc_relay_admin::{AdminAuditEventTbs, AdminAuditPhase, AdminCommandTbs, AdminSessionId};
use agenc_relay_crypto::audit_signing_key_id;
use agenc_relay_types::{NetworkId, ServerId};

fn activation() -> ReloadActivation {
    ReloadActivation {
        revision: ConfigRevision::INITIAL,
        transaction_id: TransactionId::from_bytes([25; 16]),
        changes_live_state: false,
    }
}

fn event() -> TestResult<AdminAuditEvent> {
    let operator_key = Ed25519SecretKey::from_bytes([21; 32]);
    let audit_key = Ed25519SecretKey::from_bytes([22; 32]);
    let network_id = NetworkId::from_bytes([1; 32]);
    let server_id = ServerId::from_bytes([2; 16]);
    let command_tbs = AdminCommandTbs::new(
        network_id,
        server_id,
        AdminSessionId::from_bytes([23; 16]),
        0,
        None,
        b"REHASH",
    )?;
    let operator_signature = command_tbs.sign(&operator_key)?;
    Ok(AdminAuditEvent::sign(
        AdminAuditEventTbs {
            network_id,
            server_id,
            audit_signing_key_id: *audit_signing_key_id(audit_key.public_key().as_bytes())?
                .as_bytes(),
            audit_sequence: 0,
            created_at: 50,
            operator_id: OperatorId::from_bytes([24; 16]),
            command_tbs,
            operator_signature,
            phase: AdminAuditPhase::Observed,
            previous_event_hash: [0; 32],
        },
        &audit_key,
    )?)
}

async fn activate(port: &ReloadPort) -> TestResult<AuditedReloadStart> {
    let prepared = PreparedReload::new(&snapshot()?, config()?, parts()?)?;
    Ok(port.activate_audited(prepared, event()?, event()?).await)
}

#[tokio::test]
async fn full_reload_queue_rejects_before_submission_and_allows_retry() -> TestResult {
    let (sender, mut inbox) = mpsc::channel(1);
    let port = ReloadPort { sender };
    let (reply, _response) = oneshot::channel();
    port.sender
        .try_send(ReloadCoreRequest::CommitOutcome {
            activation: activation(),
            reply,
        })
        .map_err(|_| "fill queue")?;
    assert_eq!(
        activate(&port).await?,
        AuditedReloadStart::Refused(ReloadRejection::Busy)
    );
    let token = CancellationToken::root();
    assert_eq!(
        port.commit_outcome(activation(), &token).await,
        ReloadAuditCommitOutcome::NotCommitted(ReloadRejection::Busy)
    );
    assert!(matches!(
        inbox.try_recv()?,
        ReloadCoreRequest::CommitOutcome { .. }
    ));
    assert!(inbox.try_recv().is_err());
    let (outcome, handled) = tokio::join!(port.commit_outcome(activation(), &token), async {
        let Some(ReloadCoreRequest::CommitOutcome { reply, .. }) = inbox.recv().await else {
            return Err("retry was not delivered");
        };
        reply
            .send(Ok(AuditedReloadResult::Success))
            .map_err(|_| "reply")
    });
    handled?;
    assert_eq!(
        outcome,
        ReloadAuditCommitOutcome::Committed(AuditedReloadResult::Success)
    );
    Ok(())
}

#[tokio::test]
async fn closed_reload_queue_rejects_before_submission() -> TestResult {
    let (sender, inbox) = mpsc::channel(1);
    let port = ReloadPort { sender };
    drop(inbox);
    assert_eq!(
        activate(&port).await?,
        AuditedReloadStart::Refused(ReloadRejection::StorageUnavailable)
    );
    assert_eq!(
        port.commit_outcome(activation(), &CancellationToken::root())
            .await,
        ReloadAuditCommitOutcome::NotCommitted(ReloadRejection::StorageUnavailable)
    );
    Ok(())
}

#[tokio::test]
async fn lost_reload_reply_after_submission_remains_indeterminate() -> TestResult {
    let (sender, mut inbox) = mpsc::channel(1);
    let port = ReloadPort { sender };
    let (outcome, received) = tokio::join!(activate(&port), async {
        let received = inbox.recv().await;
        assert!(matches!(
            received,
            Some(ReloadCoreRequest::ActivateAudited { .. })
        ));
        drop(received);
    });
    let () = received;
    assert_eq!(outcome?, AuditedReloadStart::Indeterminate);
    let token = CancellationToken::root();
    let (outcome, received) = tokio::join!(port.commit_outcome(activation(), &token), async {
        let received = inbox.recv().await;
        assert!(matches!(
            received,
            Some(ReloadCoreRequest::CommitOutcome { .. })
        ));
        drop(received);
    });
    let () = received;
    assert_eq!(outcome, ReloadAuditCommitOutcome::Indeterminate);
    Ok(())
}
