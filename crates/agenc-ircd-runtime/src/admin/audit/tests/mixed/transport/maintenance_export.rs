//! Signed opt-in export remains gated by its own observed audit receipt.
#![forbid(unsafe_code)]

use super::*;

#[tokio::test]
async fn signed_maintenance_export_requires_observed_commit_before_any_batch() -> TestResult {
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
        b"AUDIT EXPORT 0 2 maintenance-v1",
    )?;
    let signed = format!(
        "{} AUDIT EXPORT 0 2 maintenance-v1\r\n",
        render_admin_tag(0, &tbs.sign(&fixture.operator)?, None)
    );
    let submitted = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let request = owner.line(generation, signed.as_bytes(), &token);
        tokio::pin!(request);
        tokio::select! {
            () = &mut request => false,
            observed = core_inbox.complete_next_for_test(Err(AdminCoreFailure::StorageUnavailable)) => {
                assert!(observed.is_some());
                request.await;
                true
            },
        }
    }).await?;
    assert!(
        submitted,
        "maintenance export must reach its observed audit submission"
    );
    let refusal = output.try_recv()?;
    assert_eq!(
        refusal.lines,
        vec![b"FAIL AUDIT STORAGE_UNAVAILABLE :Administrative audit unavailable".to_vec()]
    );
    assert!(refusal.close.is_none());
    assert!(output.try_recv().is_err());
    assert_eq!(owner.audit.cursor, expected_cursor);
    assert_eq!(fixture.authority(&core)?.cursor, expected_cursor);
    Ok(())
}

#[tokio::test]
async fn signed_maintenance_export_publishes_exact_mixed_bytes_after_real_storage_commit()
-> TestResult {
    let fixture = Fixture::new();
    let mut core = core(&fixture.chain()?)?;
    let (mut owner, core_inbox) = owner(&fixture, &core)?;
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
        b"AUDIT EXPORT 0 3 maintenance-v1",
    )?;
    let signed = format!(
        "{} AUDIT EXPORT 0 3 maintenance-v1\r\n",
        render_admin_tag(0, &tbs.sign(&fixture.operator)?, None)
    );

    use crate::state_core::StateCoreExit;
    use crate::state_core::inbox::{LifecyclePhase, connection_close_channel, lifecycle_channel};
    core.state_mut()?.install_admin_inbox(core_inbox)?;
    let mut parts = core.take_run_parts()?;
    let (_inbox, inbox_receiver) = mpsc::channel(8);
    let (_close_port, close_inbox) = connection_close_channel();
    let (lifecycle, lifecycle_receiver) = lifecycle_channel();
    let run_token = token.child()?;
    let run = parts.state.run(
        inbox_receiver,
        close_inbox,
        lifecycle_receiver,
        parts.storage,
        parts.storage_reads,
        parts.checkpoints,
        parts.crypto,
        run_token,
    );
    let drive = async {
        owner.line(generation, signed.as_bytes(), &token).await;
        lifecycle.request(LifecyclePhase::Stop).await
    };
    let (exit, stopped) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(run, drive)
    })
    .await?;
    assert!(stopped.is_ok());
    assert!(matches!(exit, StateCoreExit::Stopped), "{exit:?}");
    let batch = output.try_recv()?;
    assert!(batch.close.is_none());
    assert_eq!(batch.lines.len(), 6);
    let id = encode_base64url(&[7; 16]);
    assert_eq!(
        batch.lines.first().ok_or("batch start")?,
        format!("BATCH +{id} agenc.ag/audit-maintenance-v1 0 3 4 0").as_bytes()
    );
    for (index, event) in fixture.chain()?.iter().enumerate() {
        let (kind, label) = match event {
            AuditEvent::Admin(_) => ("EVENT", "Audit event"),
            AuditEvent::Maintenance(_) => ("MAINTENANCE", "Maintenance audit event"),
        };
        let expected = format!(
            "@batch={id} NOTE AUDIT {kind} {} :{label}",
            encode_base64url(&event.encode()?)
        );
        assert_eq!(
            batch.lines.get(index + 1).ok_or("event line")?,
            expected.as_bytes()
        );
    }
    assert_eq!(
        batch.lines.last().ok_or("terminator")?,
        format!("BATCH -{id}").as_bytes()
    );
    assert!(output.try_recv().is_err());
    assert_eq!(
        owner.audit.cursor.next_sequence,
        expected_cursor.next_sequence + 1
    );
    assert_eq!(fixture.authority(&core)?.cursor, owner.audit.cursor);
    let source = core.audit_source()?;
    let mut observed = None;
    scan_events(&source.storage, &source.keys, |event| {
        if event.audit_sequence() == expected_cursor.next_sequence {
            observed = Some(event);
        }
        Ok(())
    })?;
    let observed = observed.ok_or("durable observed event")?;
    assert!(matches!(&observed, AuditEvent::Admin(event)
        if event.tbs().command_tbs.canonical_command() == b"AUDIT EXPORT 0 3 maintenance-v1"));
    assert_eq!(
        batch.lines.get(4).ok_or("observed line")?,
        format!(
            "@batch={id} NOTE AUDIT EVENT {} :Audit event",
            encode_base64url(&observed.encode()?)
        )
        .as_bytes()
    );
    Ok(())
}
