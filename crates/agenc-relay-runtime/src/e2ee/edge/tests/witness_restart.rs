#![forbid(unsafe_code)]

//! A resumed delivery cursor must restore the record head that it witnessed.

use super::*;
use agenc_relay_e2ee::objects::sequencing::{ArcCandidateReceipt, ArcCandidateReceiptTbs};
use agenc_relay_storage::e2ee_records::{ROUTE_ROW_KIND, RouteRow};

fn candidate() -> TestResult<OpenEvent> {
    let receipt = ArcCandidateReceipt {
        tbs: ArcCandidateReceiptTbs {
            profile_version: 1,
            network_id: [1; 32],
            conversation_id: CONVERSATION,
            route_sequence: 5,
            prior_epoch: 1,
            resulting_epoch: 2,
            candidate_sequence: 0,
            commit_object_id: [31; 32],
            prior_state_id: [58; 32],
            predecessor_record_id: [59; 32],
            sequenced_at: 1000,
            sequencer_key_id: [32; 32],
        },
        sequencer_signature: [33; 64],
    };
    let mut open = part(ArcFederationEventKind::CandidateEvent, 5)?;
    open.event.cross_profile_mutation_id = Opaque::new(Vec::new())?;
    open.event.cross_profile_part_index = 0;
    open.event.cross_profile_part_count = 0;
    open.event.encoded_event_result = Opaque::new(receipt.encode()?)?;
    Ok(open)
}

#[tokio::test]
async fn sealed_reload_keeps_the_candidate_witness_ahead_of_the_original_route_cut() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4096])?;
    let mut original = edge();
    install_route(&mut original)?;
    original.delivery.generation = 2;
    original.delivery.cursor = Some((6, [12; 16]));
    let retained_cut = original
        .route_objects
        .get(&CONVERSATION)
        .ok_or("route cut")?
        .clone();
    let open = candidate()?;
    let bytes =
        ArcWireObject::new(ArcWireObjectKind::FederationEvent, open.event.encode()?)?.encode()?;
    let id = *agenc_relay_e2ee::ObjectId::compute(&bytes).as_bytes();
    for fragment in agenc_relay_e2ee::wire::fragment::fragment_object(&bytes)? {
        original
            .on_event_frame(
                fixture.context_mut()?,
                &mut base_edge(),
                open.position,
                id,
                fragment,
                false,
            )
            .map_err(|e| e.code.to_string())?;
    }
    let writes = fixture.context_mut()?.staged_rows_for_test()?;
    let mut reloaded = edge();
    fixture.commit_and_restore_edge(writes, &mut base_edge(), Some(&mut reloaded))?;
    assert_eq!(reloaded.delivery.cursor, Some((7, [11; 16])));
    assert_eq!(
        reloaded
            .conversations
            .get(&CONVERSATION)
            .map(|route| route.head.sequence),
        Some(5)
    );
    assert_eq!(
        reloaded.route_objects.get(&CONVERSATION),
        Some(&retained_cut)
    );
    // The next terminal extends the committed candidate even though its
    // retained coordinator cut predates that candidate.
    reloaded
        .witness(&part(ArcFederationEventKind::ClosedEvent, 6)?.event)
        .map_err(|e| e.code.to_string())?;
    assert_eq!(
        reloaded
            .conversations
            .get(&CONVERSATION)
            .map(|route| route.head.sequence),
        Some(6)
    );
    Ok(())
}

#[test]
fn a_persisted_witness_cannot_regress_or_fork_the_retained_route_cut() -> TestResult {
    let mut original = edge();
    install_route(&mut original)?;
    let mut writes = Vec::new();
    original
        .checkpoint_witnesses([CONVERSATION], &mut writes)
        .map_err(|e| e.code.to_string())?;
    let AccountServiceDurableWrite::Put { key, plaintext, .. } =
        writes.pop().ok_or("route checkpoint")?
    else {
        return Err("route checkpoint write".into());
    };
    let value = PersistentRecordValue::decode(TableId::E2eeState, &plaintext)?;
    assert_eq!(value.record_kind(), ROUTE_ROW_KIND);
    let mut row = RouteRow::decode(value.body())?;
    row.route_sequence = 3;
    assert!(edge().restore_route(&key, &row).is_err());
    row.route_sequence = 4;
    row.sequencer_head_id = [99; 32];
    assert!(edge().restore_route(&key, &row).is_err());
    Ok(())
}

#[test]
fn new_edge_requires_snapshot_and_committed_checkpoint_resumes() -> TestResult {
    let marked = DeliveryRow::WitnessedCursor {
        generation: 2,
        next_sequence: 8,
        acked_sequence: 7,
        acked_event_id: [11; 16],
        barrier_open: false,
    };
    let mut restored = edge();
    assert!(restored.needs_witness_snapshot());
    assert_eq!(restored.resume_delivery().generation, 0);
    assert_eq!(restored.resume_delivery().cursor, None);
    restored.restore_delivery(&marked)?;
    assert!(!restored.needs_witness_snapshot());
    assert_eq!(restored.resume_delivery().generation, 2);
    assert_eq!(restored.resume_delivery().cursor, Some((7, [11; 16])));
    Ok(())
}
