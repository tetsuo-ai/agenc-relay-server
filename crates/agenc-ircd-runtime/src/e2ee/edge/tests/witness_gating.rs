#![forbid(unsafe_code)]

//! Durable witness metadata keeps companion recovery closed across owners.

use super::*;
use crate::e2ee::edge::{Phase, SessionFacts};
use agenc_ircd_client_wire::{
    CapabilityProfile, CapabilitySpec, CapabilityState, FramedLine, parse_message,
};

fn stage_witness_rows(
    fixture: &mut WitnessFixture,
    writes: Vec<AccountServiceDurableWrite>,
) -> TestResult {
    let context = fixture.core.context_mut()?;
    let plan = context.domain().plan_account_service_checkpoint()?;
    let writes = writes
        .into_iter()
        .map(|write| write.at_revision(plan.resulting_revision().get()))
        .collect::<Result<Vec<_>, _>>()?;
    let fanout = crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())?;
    context
        .stage_durable_with_account_service(plan, fanout, None, 0, writes)
        .map_err(|error| format!("witness fixture checkpoint: {error:?}"))?;
    Ok(())
}

async fn persist_original_cut(fixture: &mut WitnessFixture) -> TestResult {
    let mut writes = Vec::new();
    fixture
        .companion
        .checkpoint_witnesses([CONVERSATION], &mut writes)
        .map_err(|refusal| refusal.code.to_string())?;
    writes.push(
        crate::e2ee::edge::events::cursor_write(
            &fixture.companion.config,
            &fixture.companion.delivery,
        )
        .map_err(|code| code.to_string())?,
    );
    stage_witness_rows(fixture, writes)?;
    fixture.core.commit_staged_batch().await?;
    Ok(())
}

async fn durable_fault() -> TestResult<WitnessFixture> {
    let mut fixture = WitnessFixture::new().await?;
    persist_original_cut(&mut fixture).await?;
    fixture.violate()?;
    assert_eq!(fixture.staged_witness()?.observed_sequence, 6);
    fixture.core.commit_staged_batch().await?;
    assert!(
        fixture
            .companion
            .batch_applied(fixture.core.context_mut()?, &mut fixture.base,)
            .is_empty()
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(1), fixture.queue.recv())
            .await?
            .is_none()
    );
    Ok(fixture)
}

async fn assert_reconnect_gated(fixture: &mut WitnessFixture, link_id: u64) -> TestResult {
    let (replacement, mut queue) = link_queue(1 << 20);
    establish(&mut fixture.core, &mut fixture.base, &replacement, link_id)?;
    while let Ok(line) = tokio::time::timeout(Duration::from_millis(5), queue.recv()).await {
        let line = line.ok_or("replacement base link closed")?;
        assert!(!line.as_str().contains(" ERESUME "));
    }
    assert!(
        !fixture
            .companion
            .link_active(fixture.core.context_mut()?, &mut fixture.base),
        "an unresolved durable witness resumed ordinary companion delivery"
    );
    assert_open_and_silent(&mut queue).await?;
    assert!(
        fixture
            .companion
            .handle_frames(
                fixture.core.context_mut()?,
                &mut fixture.base,
                vec![
                    CompanionFrame::ResumeOk {
                        target_server_id: [2; 16],
                        server_incarnation: [4; 16],
                        delivery_generation: 2,
                        next_delivery_sequence: 7,
                    },
                    CompanionFrame::OriginReady {
                        home_server_id: [2; 16],
                        server_incarnation: [4; 16]
                    },
                ]
            )
            .is_empty()
    );
    assert_open_and_silent(&mut queue).await?;
    assert_eq!(fixture.companion.phase, Phase::Down);
    assert!(!fixture.companion.is_active());
    assert!(fixture.companion.retention_blocked());
    assert_eq!(fixture.companion.delivery.cursor, Some((6, [12; 16])));
    assert_eq!(fixture.companion.delivery.generation, 2);
    assert_eq!(
        fixture
            .companion
            .conversations
            .get(&CONVERSATION)
            .map(|route| route.head.sequence),
        Some(4)
    );
    assert_eq!(
        fixture.base.current_companion_link_id(),
        Some(LinkId::new(link_id))
    );
    Ok(())
}

#[tokio::test]
async fn a_durable_witness_blocks_ordinary_resume_on_a_replacement_link() -> TestResult {
    let mut fixture = durable_fault().await?;
    assert_reconnect_gated(&mut fixture, 2).await?;
    fixture.companion.link_down();
    assert_reconnect_gated(&mut fixture, 3).await
}

#[tokio::test]
async fn sealed_reconstruction_preserves_all_unresolved_historical_witnesses() -> TestResult {
    let mut fixture = durable_fault().await?;
    let historical = WitnessRow {
        event_kind: IrcFederationEventKind::ClosedEvent.value(),
        expected_sequence: 3,
        expected_head_id: [35; 32],
        observed_sequence: 4,
        observed_id: [36; 32],
        observed_predecessor_id: None,
    };
    let write = crate::e2ee::edge::events::state_row(
        WitnessRow::key(&[10; 32])?,
        WITNESS_ROW_KIND,
        historical.encode()?,
    )
    .map_err(|refusal| refusal.code.to_string())?;
    stage_witness_rows(&mut fixture, vec![write])?;
    fixture.core.commit_staged_batch().await?;
    for id in [2, 3] {
        fixture.base = base_edge();
        fixture.companion = edge();
        fixture
            .core
            .restore_edge_state(&mut fixture.base, Some(&mut fixture.companion))?;
        assert_reconnect_gated(&mut fixture, id).await?;
        for conversation in [CONVERSATION, [10; 32]] {
            assert!(
                fixture
                    .core
                    .stored_row_exists(TableId::E2eeState, WitnessRow::key(&conversation)?)?
            );
        }
    }
    Ok(())
}

fn negotiated_capabilities() -> TestResult<CapabilityState> {
    let names = [
        "message-tags",
        "echo-message",
        "batch",
        "labeled-response",
        "standard-replies",
        "account-tag",
    ];
    let mut specs = names
        .iter()
        .map(|name| CapabilitySpec::new(name, None))
        .collect::<Result<Vec<_>, _>>()?;
    specs.push(CapabilitySpec::new(
        "agenc.ag/e2ee-mls",
        Some(agenc_ircd_e2ee::limits::CAPABILITY_VALUE),
    )?);
    let profile = CapabilityProfile::new(specs)?;
    let mut capabilities = CapabilityState::default();
    let requested = format!("{} agenc.ag/e2ee-mls", names.join(" "));
    let _reply = capabilities.request(&requested, &profile)?;
    assert!(capabilities.enabled("agenc.ag/e2ee-mls"));
    Ok(capabilities)
}

#[tokio::test]
async fn a_durable_witness_refuses_client_work_even_if_the_phase_is_active() -> TestResult {
    let mut fixture = durable_fault().await?;
    fixture.companion.phase = Phase::Active;
    let capabilities = negotiated_capabilities()?;
    let facts = SessionFacts {
        user_id: agenc_ircd_types::UserId::from_bytes([18; 16]),
        account: Some([b'a'; 24]),
        capabilities: &capabilities,
        nickname: "WitnessUser",
    };
    let message =
        parse_message(FramedLine::new("EGROUP QUERY CHANNEL #room")?)?.ok_or("message")?;
    let replies = fixture.companion.client_line(
        fixture.core.context_mut()?,
        &mut fixture.base,
        ConnectionGeneration::new(1),
        &message,
        &facts,
    );
    assert_eq!(replies.len(), 1);
    let frames = &replies.first().ok_or("client refusal")?.frames;
    assert_eq!(frames.len(), 1);
    let frame = frames.first().ok_or("FAIL")?;
    assert_eq!(frame.command(), "FAIL");
    assert!(frame.middle().iter().any(|value| value == "E2EE_SYNCING"));
    assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
    assert!(fixture.companion.pending.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_clean_reconstructed_cursor_still_sends_the_exact_resume() -> TestResult {
    let mut fixture = WitnessFixture::new().await?;
    persist_original_cut(&mut fixture).await?;
    fixture.base = base_edge();
    fixture.companion = edge();
    fixture
        .core
        .restore_edge_state(&mut fixture.base, Some(&mut fixture.companion))?;
    let (replacement, mut queue) = link_queue(1 << 20);
    establish(&mut fixture.core, &mut fixture.base, &replacement, 2)?;
    while let Ok(line) = tokio::time::timeout(Duration::from_millis(5), queue.recv()).await {
        drop(line.ok_or("clean base link closed")?);
    }
    assert!(
        fixture
            .companion
            .link_active(fixture.core.context_mut()?, &mut fixture.base)
    );
    let line = tokio::time::timeout(Duration::from_secs(1), queue.recv())
        .await?
        .ok_or("missing clean resume")?;
    let expected = fixture
        .companion
        .line(&CompanionFrame::Resume {
            coordinator_server_id: [3; 16],
            server_incarnation: [4; 16],
            delivery_generation: 2,
            last: Some((6, [12; 16])),
        })
        .map_err(|refusal| refusal.code.to_string())?;
    assert_eq!(line.as_str(), expected.as_str());
    assert_eq!(fixture.companion.phase, Phase::Resuming);
    assert!(!fixture.companion.witness_recovery_pending());
    Ok(())
}
