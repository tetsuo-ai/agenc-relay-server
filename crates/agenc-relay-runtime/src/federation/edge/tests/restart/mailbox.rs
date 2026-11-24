#![forbid(unsafe_code)]

//! SC-011: a staged reply belongs to the joint durable receipt across link loss.

use super::*;
use agenc_relay_e2ee::tls::{DecodeBudget, TlsDecode};

fn correlated_mailbox() -> TestResult<(Vec<InitialStorageRecord>, ArcFederationEvent)> {
    let (mut parts, _) = parts()?;
    let companion = parts.last_mut().ok_or("companion part")?;
    let mut budget = DecodeBudget::new(1 << 16, 4096);
    let object = ArcWireObject::decode_kind(
        &companion.encoded_event_object,
        Some(ArcWireObjectKind::FederationEvent),
        &mut budget,
    )?;
    let mut event = ArcFederationEvent::decode_exact(object.body(), &mut budget)?;
    event.request_home_server_id = Opaque::new(EDGE.as_bytes().to_vec())?;
    event.request_server_incarnation = Opaque::new(EDGE_INCARNATION.as_bytes().to_vec())?;
    event.request_id = Opaque::new(vec![55; 16])?;
    event.request_origin_id = Opaque::new(vec![56; 16])?;
    event.request_origin_generation = 2;
    event.request_operation_sequence = 3;
    event.payload_object_id = Opaque::new(Vec::new())?;
    event.encoded_event_result =
        Opaque::new(event.coordinator_state_generation.to_be_bytes().to_vec())?;
    let bytes =
        ArcWireObject::new(ArcWireObjectKind::FederationEvent, event.encode()?)?.encode()?;
    companion.event_object_id = *agenc_relay_e2ee::ObjectId::compute(&bytes).as_bytes();
    companion.encoded_event_object = bytes;
    companion.payload_object_id = None;
    companion.payload_object_bytes = 0;
    Ok((staged_rows(parts, Vec::new(), 2, true)?, event))
}

#[tokio::test]
async fn a_staged_mailbox_stream_survives_federation_disconnect_only_if_the_joint_receipt_commits()
-> TestResult {
    for commit in [false, true] {
        let (rows, event) = correlated_mailbox()?;
        let mut fixture =
            StateCoreFixture::with_registration_router_and_records(entropy_script(), rows)?;
        let (mut base, mut companion) = edges();
        fixture.restore_edge_state(&mut base, Some(&mut companion))?;
        base.phase = Phase::Active;
        let (link, _queue) = link_queue(1 << 20);
        let link_id = LinkId::new(99);
        base.live = Some(LiveLink {
            link: link_id,
            handle: link,
            coordinator_epoch: COORDINATOR_EPOCH,
            coordinator_incarnation: HUB_INCARNATION,
        });
        companion.waiting_barrier_mailbox_for_test(&mut fixture, &event)?;
        let context = fixture.context_mut()?;
        let (writes, eager) = companion
            .prepare_barrier(context, &base, MUTATION)
            .map_err(|e| e.to_string())?;
        assert!(eager.is_empty());
        assert!(base.apply_barrier(context, writes, eager));
        companion.barrier_staged(MUTATION, Vec::new());
        assert!(companion.barrier_outputs(context, &base).is_empty());
        base.link_closed(context, link_id);
        companion.link_down();
        assert!(companion.barrier_outputs(context, &base).is_empty());
        if commit {
            fixture.commit_staged_batch().await?;
            let context = fixture.context_mut()?;
            assert!(base.batch_applied(context).is_empty());
            assert!(base.barrier_applied(&MUTATION));
            let mut outputs = companion.barrier_outputs(context, &base);
            assert_eq!(outputs.len(), 1);
            let output = outputs.pop().ok_or("missing committed output")?;
            assert!(output.frames.is_empty());
            let mut batch = output.batch.ok_or("streamed mailbox")?;
            let opener = batch
                .next_line()
                .map_err(|e| e.to_string())?
                .ok_or("opener")?;
            assert!(std::str::from_utf8(opener.as_bytes())?.starts_with("@label=joint "));
        } else {
            base.batch_rejected(context);
            companion.batch_rejected(context, &mut base);
            assert!(!base.barrier_applied(&MUTATION));
            assert!(companion.barrier_outputs(context, &base).is_empty());
        }
        assert!(
            companion
                .barrier_outputs(fixture.context_mut()?, &base)
                .is_empty()
        );
    }
    Ok(())
}
