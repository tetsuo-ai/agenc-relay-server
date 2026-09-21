#![forbid(unsafe_code)]

//! Refused durable admission restores every speculative route projection.

use super::*;

fn ordinary() -> TestResult<OpenEvent> {
    let mut open = part(ArcFederationEventKind::ClosedEvent, 5)?;
    open.event.cross_profile_mutation_id = Opaque::new(Vec::new())?;
    open.event.cross_profile_part_index = 0;
    open.event.cross_profile_part_count = 0;
    Ok(open)
}

fn submit(
    companion: &mut E2eeEdge,
    fixture: &mut StateCoreFixture,
    open: &OpenEvent,
) -> TestResult<bool> {
    let bytes =
        ArcWireObject::new(ArcWireObjectKind::FederationEvent, open.event.encode()?)?.encode()?;
    let id = *agenc_relay_e2ee::ObjectId::compute(&bytes).as_bytes();
    let mut accepted = true;
    for fragment in agenc_relay_e2ee::wire::fragment::fragment_object(&bytes)? {
        accepted &= companion
            .on_event_frame(
                fixture.context_mut()?,
                &mut base_edge(),
                open.position,
                id,
                fragment,
                false,
            )
            .is_ok();
    }
    Ok(accepted)
}

fn quiesce(fixture: &mut StateCoreFixture) -> TestResult {
    fixture
        .state_mut()?
        .step_message(crate::state_core::inbox::StateCoreMessage::Signal(
            crate::state_core::inbox::SignalEvent::Terminate,
        ));
    Ok(())
}

#[tokio::test]
async fn refused_event_admission_restores_the_witness_head() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let mut companion = edge();
    install_route(&mut companion)?;
    companion.delivery.generation = 2;
    companion.delivery.cursor = Some((6, [12; 16]));
    let before = companion.conversations.clone();
    quiesce(&mut fixture)?;
    assert!(!submit(&mut companion, &mut fixture, &ordinary()?)?);
    assert_eq!(companion.conversations, before);
    assert!(companion.commit.is_none());
    Ok(())
}

#[tokio::test]
async fn rejected_event_batch_restores_the_witness_head() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let mut companion = edge();
    install_route(&mut companion)?;
    companion.delivery.generation = 2;
    companion.delivery.cursor = Some((6, [12; 16]));
    let before = companion.conversations.clone();
    assert!(submit(&mut companion, &mut fixture, &ordinary()?)?);
    assert!(companion.commit.is_some());
    companion.batch_rejected();
    assert_eq!(companion.conversations, before);
    Ok(())
}

#[tokio::test]
async fn refused_snapshot_admission_restores_the_removed_route() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let mut companion = edge();
    install_route(&mut companion)?;
    let before = companion.conversations.clone();
    let objects = companion.route_objects.clone();
    let mut base = base_edge();
    companion.link_active(fixture.context_mut()?, &mut base);
    let digest = agenc_relay_e2ee::ids::federation_snapshot_digest(5, 2, &[])?;
    companion
        .state_begin(
            fixture.context_mut()?,
            &base,
            [6; 32],
            5,
            2,
            0,
            0,
            0,
            digest,
        )
        .map_err(|e| e.code.to_string())?;
    quiesce(&mut fixture)?;
    assert!(
        companion
            .state_end(fixture.context_mut()?, [6; 32], 0, None)
            .is_err()
    );
    assert_eq!(companion.conversations, before);
    assert_eq!(companion.route_objects, objects);
    assert_eq!(
        companion
            .routes
            .channel_route(&CHANNEL)
            .map(|r| r.conversation_id),
        Some(ConversationId(CONVERSATION))
    );
    Ok(())
}

#[tokio::test]
async fn failed_barrier_preparation_restores_prior_parts_and_keeps_violation_evidence() -> TestResult
{
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let mut companion = edge();
    install_route(&mut companion)?;
    let before = companion.conversations.clone();
    companion.barrier_parts.insert(
        MUTATION,
        BTreeMap::from([
            (1, (part(ArcFederationEventKind::ClosedEvent, 5)?, None)),
            (2, (part(ArcFederationEventKind::ClosedEvent, 7)?, None)),
        ]),
    );
    assert!(
        companion
            .prepare_barrier(fixture.context_mut()?, &base_edge(), MUTATION)
            .is_err()
    );
    assert_eq!(companion.conversations, before);
    assert!(companion.witnessed.is_some());
    Ok(())
}

#[tokio::test]
async fn ready_commit_after_link_loss_keeps_the_generation_pending_until_active() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let mut companion = edge();
    companion.delivery.generation = 1;
    let mut base = base_edge();
    base.note_companion_delivery(1, None);
    companion.link_active(fixture.context_mut()?, &mut base);
    let digest = agenc_relay_e2ee::ids::federation_snapshot_digest(5, 2, &[])?;
    companion
        .state_begin(
            fixture.context_mut()?,
            &base,
            [6; 32],
            5,
            2,
            0,
            0,
            0,
            digest,
        )
        .map_err(|e| e.code.to_string())?;
    companion
        .state_end(fixture.context_mut()?, [6; 32], 0, None)
        .map_err(|e| e.code.to_string())?;
    companion.link_down();
    fixture.context_mut()?.discard_pending_for_test();
    companion.batch_applied(fixture.context_mut()?, &mut base);
    // READY is durable, but the generation is not in use: the delivery
    // position stays in the previous generation until ACTIVE, and the
    // durable READY survives the link loss.
    assert_eq!(companion.delivery.generation, 1);
    assert_eq!(base.companion_cursor(), (1, None));
    assert!(companion.snapshot_ready_pending());
    assert_eq!(companion.phase(), crate::e2ee::edge::Phase::Down);
    // A later link announces the identical READY instead of ERESUME.
    companion.link_active(fixture.context_mut()?, &mut base);
    assert_eq!(companion.phase(), crate::e2ee::edge::Phase::AwaitingActive);
    Ok(())
}
