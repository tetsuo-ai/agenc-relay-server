#![forbid(unsafe_code)]

use super::*;

fn enable_companion(fixture: &mut PrefixFixture) -> TestResult {
    use agenc_relay_e2ee::profile::EcapTuple;
    use agenc_relay_e2ee::wire::tokens::base64url_encode;
    fixture
        .edge
        .set_companion_profile(Some(crate::e2ee::link::CompanionProfile {
            local: EcapTuple::local(
                &base64url_encode(NETWORK.as_bytes()),
                &base64url_encode(COORDINATOR.as_bytes()),
                1,
                &base64url_encode(&[1; 32]),
            )?,
        }));
    Ok(())
}

#[tokio::test]
async fn replacement_profile_and_resume_wait_for_the_owned_ordinary_receipt() -> TestResult {
    let mut fixture = queued_prefix().await?;
    enable_companion(&mut fixture)?;
    fixture.edge.installed_epoch = Some(COORDINATOR_EPOCH);
    fixture.edge.installed_incarnation = Some(HUB_INCARNATION);
    let (replacement, mut queue) = link_queue(1 << 20);
    fixture.edge.link_established(
        fixture.core.context_mut()?,
        LinkSession {
            link: LinkId::new(2),
            peer: COORDINATOR,
            peer_incarnation: ServerIncarnation::from_bytes([99; 16]),
            peer_recovery_epoch: COORDINATOR_EPOCH,
            transition: agenc_relay_federation_wire::EpochTransition::Initial,
        },
        replacement.clone(),
    );
    assert_no_ack(&mut queue).await?;
    assert_eq!(fixture.handle.queued_bytes(), 0);
    assert_eq!(fixture.edge.cursor, Some((0, event_identity(0)?)));
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_outputs(&fixture.sink, 3);
    assert_eq!(fixture.edge.cursor, Some((2, event_identity(2)?)));
    let offer = tokio::time::timeout(std::time::Duration::from_secs(1), queue.recv())
        .await?
        .ok_or("delayed companion offer")?;
    assert!(matches!(
        crate::federation::link::parse_line(offer.as_str().trim_end_matches("\r\n"), EDGE_NAME),
        Ok(crate::federation::link::ParsedLine::Companion(
            agenc_relay_e2ee::federation::frames::CompanionFrame::EcapOffer(_)
        ))
    ));
    let resume = tokio::time::timeout(std::time::Duration::from_secs(1), queue.recv())
        .await?
        .ok_or("delayed base resume")?;
    let frame = parse_frame(resume.as_str().trim_end_matches("\r\n"), EDGE_NAME)
        .map_err(|error| format!("resume grammar: {error:?}"))?;
    assert!(matches!(frame, FederationFrame::Resume {
        projection_generation: 1,
        cursor: agenc_relay_federation_wire::DeliveryCursor::At { delivery_sequence: 2, event_id },
        ..
    } if event_id == event_identity(2)?));
    assert_no_ack(&mut fixture.queue).await?;
    assert_no_ack(&mut queue).await?;
    assert_eq!(replacement.queued_bytes(), 0);
    Ok(())
}

#[tokio::test]
async fn an_old_rejection_callback_cannot_abort_a_new_exclusive_prefix() -> TestResult {
    let mut fixture = queued_prefix().await?;
    for _ in 0..3 {
        fixture.edge.batch_rejected_with_error(
            fixture.core.context_mut()?,
            agenc_relay_storage::StorageError::FilesystemRejected(
                agenc_relay_storage::FilesystemCause::IoFailure,
            ),
        );
    }
    assert!(matches!(
        fixture.edge.commit,
        Some(PendingCommit::OrdinaryBatch(_))
    ));
    assert_eq!(fixture.edge.phase, Phase::Active);
    assert_no_ack(&mut fixture.queue).await?;
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_next_ack(&mut fixture.queue, 1).await?;
    assert_next_ack(&mut fixture.queue, 2).await?;
    assert_outputs(&fixture.sink, 3);
    Ok(())
}
