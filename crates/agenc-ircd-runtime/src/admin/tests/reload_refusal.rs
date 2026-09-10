//! An unsubmitted reload still requires a durable failure audit.
#![forbid(unsafe_code)]

use super::*;
use crate::runtime_config::{PreparedReload, reload_preparation_channel};
use crate::test_support::{
    StateCoreFixture, TestResult, golden_config, golden_parts, golden_snapshot,
};

#[tokio::test]
async fn refused_reload_waits_for_its_failure_audit() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let handle = RuntimeConfigHandle::new(golden_snapshot("AgenC", None)?);
    let (activation, _) = fixture.install_reload_port(handle.clone())?;
    let (reload, mut preparation) = reload_preparation_channel(activation);
    drop(fixture);
    let (core, mut core_inbox) = admin_core_channel();
    let mut owner = lifecycle_owner()?;
    owner.registry = all_permissions_registry()?;
    owner.core = core;
    owner.reload = Some(reload);
    let (port, inbox) = admin_transport_channel(binding());
    let (_lifecycle, lifecycle_inbox) = admin_lifecycle_channel();
    let root = CancellationToken::root();
    let task = tokio::spawn(owner.run(inbox, lifecycle_inbox, root.clone()));
    let generation = ConnectionGeneration::new(12);
    let (sender, mut output) = mpsc::channel(ADMIN_OUTPUT_CAPACITY);
    port.opened(
        generation,
        challenge(),
        PeerIdentity::Local {
            uid: 1000,
            gid: 1000,
        },
        AdminOutput::new(sender),
        &root,
    )
    .await
    .map_err(|_| "open")?;
    let _challenge = output.recv().await.ok_or("challenge")?;
    port.line(generation, oper_line()?, &root)
        .await
        .map_err(|_| "oper")?;
    port.line(generation, signed_line(0, "REHASH :reload now")?, &root)
        .await
        .map_err(|_| "rehash")?;
    let prepared = PreparedReload::new(
        &handle.load(),
        golden_config()?,
        golden_parts("Changed", None)?,
    )?;
    tokio::time::timeout(Duration::from_secs(2), preparation.recv())
        .await?
        .ok_or("preparation")?
        .send(Ok(prepared));
    let intent = tokio::time::timeout(
        Duration::from_secs(2),
        core_inbox.complete_next_for_test(Ok(())),
    )
    .await?
    .ok_or("intent")?;
    assert_eq!(intent.tbs().phase, AdminAuditPhase::Intent);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), output.recv())
            .await
            .is_err(),
        "a reload refusal must wait for its durable audit acknowledgement"
    );
    let failure = tokio::time::timeout(
        Duration::from_secs(2),
        core_inbox.complete_next_for_test(Ok(())),
    )
    .await?
    .ok_or("failure")?;
    assert_eq!(failure.tbs().phase, AdminAuditPhase::OutcomeFailure);
    assert_eq!(
        failure.tbs().audit_sequence,
        intent.tbs().audit_sequence + 1
    );
    let response = tokio::time::timeout(Duration::from_secs(2), output.recv())
        .await?
        .ok_or("response")?;
    assert!(response.lines.iter().any(|line| {
        line.windows(b"FAIL REHASH STORAGE_UNAVAILABLE".len())
            .any(|window| window == b"FAIL REHASH STORAGE_UNAVAILABLE")
    }));
    root.cancel();
    task.await?;
    Ok(())
}
