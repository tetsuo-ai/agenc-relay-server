//! A signed legacy export refuses before any observed append or BATCH output.
#![forbid(unsafe_code)]
#![cfg(test)]

use super::*;
use crate::admin::{
    ADMIN_OUTPUT_CAPACITY, AdminAdmissionSnapshot, AdminOutput, AdminOwner, AdminOwnerClocks,
    AdminOwnerHealth, AdminOwnerRuntime,
};
use crate::budget::{MemoryBudget, MemoryCharge};
use crate::cancel::CancellationToken;
use crate::connection::ConnectionGeneration;
use crate::observe::health::{Liveness, ReadinessGate};
use crate::state_core::{AdminCoreFailure, AdminCoreInbox, admin_core_channel};
use agenc_ircd_admin::{
    AdminChallenge, Challenge, MAX_AUDIT_EXPORT_BYTES, PeerIdentity, TransportBinding,
    TransportKind, encode_base64url, render_admin_tag,
};
use agenc_ircd_testkit::{DeterministicMonotonicClock, DeterministicWallClock, ScriptedEntropy};
use tokio::sync::mpsc;

fn owner(fixture: &Fixture, core: &StateCoreFixture) -> TestResult<(AdminOwner, AdminCoreInbox)> {
    let (port, inbox) = admin_core_channel();
    let scope = fixture.scope();
    let export_backing = MemoryCharge::allocation(MAX_AUDIT_EXPORT_BYTES)?
        .bytes()
        .checked_mul(2)
        .ok_or("export budget overflow")?;
    Ok((
        AdminOwner::new(
            AdminSessionBinding {
                network_id: scope.network_id(),
                server_id: scope.server_id(),
            },
            fixture.operators()?,
            AdminAdmissionSnapshot::new(vec![1_000], Vec::new(), Vec::new()),
            fixture.authority(core)?,
            port,
            AdminOwnerRuntime {
                health: AdminOwnerHealth {
                    readiness: Arc::new(ReadinessGate::new()),
                    liveness: Arc::new(Liveness::new()),
                },
                config: None,
                reload: None,
                backup: None,
                process: None,
                fatal: None,
                observer: None,
                budget: Arc::new(MemoryBudget::new(export_backing)),
                entropy: Box::new(ScriptedEntropy::new(vec![7; 64])?),
                clocks: AdminOwnerClocks {
                    monotonic: Box::new(DeterministicMonotonicClock::at(0)),
                    wall: Box::new(DeterministicWallClock::at(60)),
                },
            },
        ),
        inbox,
    ))
}

#[tokio::test]
async fn signed_legacy_export_returns_only_unavailable_without_requesting_an_observed_commit()
-> TestResult {
    let fixture = Fixture::new();
    let core = core(&fixture.chain()?)?;
    let (mut owner, mut core_inbox) = owner(&fixture, &core)?;
    let expected_cursor = owner.audit.cursor;
    let generation = ConnectionGeneration::new(91);
    let challenge = AdminChallenge::new(
        AdminSessionId::from_bytes([3; 16]),
        Challenge::from_bytes([4; 32]),
        TransportKind::Local,
        TransportBinding::from_bytes([5; 32]),
    );
    let token = CancellationToken::root();
    let (sender, mut output) = mpsc::channel(ADMIN_OUTPUT_CAPACITY);
    owner.open(
        generation,
        challenge,
        PeerIdentity::Local {
            uid: 1_000,
            gid: 1_000,
        },
        AdminOutput::new(sender),
    );
    let initial = output.try_recv()?;
    assert!(
        initial
            .lines
            .first()
            .is_some_and(|line| line.starts_with(b"NOTE OPER CHALLENGE "))
    );
    let signature = challenge.sign_oper(
        fixture.scope().network_id(),
        fixture.scope().server_id(),
        &fixture.operator,
    )?;
    let oper = format!(
        "OPER {} {}\r\n",
        fixture.operator_id.to_base64url(),
        encode_base64url(signature.as_bytes())
    );
    owner.line(generation, oper.as_bytes(), &token).await;
    assert!(owner.sessions.get(&generation).is_some_and(|session| {
        session
            .session
            .operator()
            .is_some_and(|(id, _)| id == fixture.operator_id)
    }));
    assert!(matches!(
        output.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    let tbs = AdminCommandTbs::new(
        fixture.scope().network_id(),
        fixture.scope().server_id(),
        challenge.session_id(),
        0,
        None,
        b"AUDIT EXPORT 0 2",
    )?;
    let signed = format!(
        "{} AUDIT EXPORT 0 2\r\n",
        render_admin_tag(0, &tbs.sign(&fixture.operator)?, None)
    );
    let no_commit = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        tokio::select! {
            () = owner.line(generation, signed.as_bytes(), &token) => true,
            _ = core_inbox.complete_next_for_test(Err(AdminCoreFailure::StorageUnavailable)) => false,
        }
    }).await?;
    assert!(
        no_commit,
        "legacy refusal must precede any observed audit submission"
    );
    let refusal = output.try_recv()?;
    assert_eq!(
        refusal.lines,
        vec![b"FAIL AUDIT UNAVAILABLE :Audit export unavailable".to_vec()]
    );
    assert!(refusal.close.is_none());
    assert!(output.try_recv().is_err());
    assert_eq!(owner.audit.cursor, expected_cursor);
    assert_eq!(fixture.authority(&core)?.cursor, expected_cursor);
    Ok(())
}

mod maintenance_export;
