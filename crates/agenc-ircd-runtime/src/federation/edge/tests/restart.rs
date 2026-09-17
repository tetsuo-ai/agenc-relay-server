#![forbid(unsafe_code)]

//! Crash images retain exact cross-profile rows and resume only committed cursors.

use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::federation::{IrcFederationEvent, IrcFederationEventKind};
use agenc_ircd_e2ee::tls::{Opaque, TlsEncode};
use agenc_ircd_storage::e2ee_records::barrier::{
    BarrierHead, BarrierIdentity, BarrierPart, CrossProfileStream,
};
use agenc_ircd_storage::e2ee_records::{
    BARRIER_ROW_KIND, DELIVERY_ROW_KIND, DeliveryRow, OBJECT_RECORD_KIND, ObjectRow,
};
use agenc_ircd_storage::{InitialStorageRecord, PersistentRecordValue, StoredKey, TableId};

use super::*;
use crate::e2ee::barrier::BarrierAssembly;
use crate::e2ee::edge::{E2eeEdge, E2eeEdgeConfig};
use crate::state_core::durable::AccountServiceDurableWrite;

const MUTATION: [u8; 16] = [77; 16];

mod completion;
mod revisions;
mod rollback;
mod upgrade;

fn edges() -> (EdgeFederation, E2eeEdge) {
    let mut base = EdgeFederation::new(EdgeConfig {
        network_id: NETWORK,
        server_id: EDGE,
        server_name: EDGE_NAME.to_owned(),
        incarnation: EDGE_INCARNATION,
        coordinator: coordinator_identity(),
    });
    base.installed_epoch = Some(COORDINATOR_EPOCH);
    base.installed_incarnation = Some(HUB_INCARNATION);
    let companion = E2eeEdge::new(E2eeEdgeConfig {
        network_id: *NETWORK.as_bytes(),
        server_id: EDGE,
        server_name: EDGE_NAME.to_owned(),
        coordinator_server_id: COORDINATOR,
        sequencer_key_set: None,
        incarnation: *EDGE_INCARNATION.as_bytes(),
        global_disk_bytes: 1 << 30,
    });
    (base, companion)
}

fn identity(count: u16) -> BarrierIdentity {
    BarrierIdentity {
        network_id: *NETWORK.as_bytes(),
        coordinator_server_id: *COORDINATOR.as_bytes(),
        coordinator_server_incarnation: *HUB_INCARNATION.as_bytes(),
        coordinator_recovery_epoch: *COORDINATOR_EPOCH.as_bytes(),
        target_server_id: *EDGE.as_bytes(),
        target_server_incarnation: *EDGE_INCARNATION.as_bytes(),
        mutation_id: MUTATION,
        coordinator_state_generation: 10,
        part_count: count,
    }
}

fn parts() -> TestResult<(Vec<BarrierPart>, Vec<u8>)> {
    let event = ProjectedEvent::NetworkNotice {
        code: "TEST".to_owned(),
        text: "barrier".to_owned(),
    };
    let header = EventHeader {
        network_id: NETWORK,
        target_server_id: EDGE,
        projection_generation: 1,
        coordinator_state_generation: 10,
        delivery_sequence: 0,
        event_id: EventId::from_bytes([78; 16]),
        event_kind: event.kind(),
        correlation: None,
        cross_profile: Some(agenc_ircd_federation_wire::CrossProfilePart {
            mutation_id: MUTATION,
            part_index: 0,
            part_count: 2,
        }),
    };
    let bytes = header
        .build(&event_arm_object(&event).map_err(|e| format!("{e:?}"))?)?
        .encode_canonical()?
        .as_slice()
        .to_vec();
    let base = BarrierPart {
        identity: identity(2),
        stream: CrossProfileStream::Base,
        part_index: 0,
        delivery_generation: 1,
        delivery_sequence: 0,
        event_id: *header.event_id.as_bytes(),
        event_object_id: *federation_object_id(&bytes).as_bytes(),
        encoded_event_object: bytes,
        payload_object_id: None,
        payload_object_bytes: 0,
    };
    let payload = IrcWireObject::new(IrcWireObjectKind::ApplicationMls, vec![12; 32])?.encode()?;
    let payload_id = *agenc_ircd_e2ee::ObjectId::compute(&payload).as_bytes();
    let companion_event = IrcFederationEvent {
        profile_version: 1,
        network_id: *NETWORK.as_bytes(),
        target_server_id: *EDGE.as_bytes(),
        delivery_generation: 1,
        coordinator_state_generation: 10,
        delivery_sequence: 0,
        event_id: [79; 16],
        event_kind: IrcFederationEventKind::RequestCompleted,
        cross_profile_mutation_id: Opaque::new(MUTATION.to_vec())?,
        cross_profile_part_index: 1,
        cross_profile_part_count: 2,
        conversation_id: Opaque::new(Vec::new())?,
        route_sequence: 0,
        origin_id: Opaque::new(Vec::new())?,
        origin_generation: 0,
        source_view: Opaque::new(Vec::new())?,
        request_home_server_id: Opaque::new(Vec::new())?,
        request_server_incarnation: Opaque::new(Vec::new())?,
        request_origin_id: Opaque::new(Vec::new())?,
        request_origin_generation: 0,
        request_operation_sequence: 0,
        request_id: Opaque::new(Vec::new())?,
        payload_object_id: Opaque::new(payload_id.to_vec())?,
        encoded_event_result: Opaque::new(Vec::new())?,
    };
    let bytes = IrcWireObject::new(
        IrcWireObjectKind::FederationEvent,
        companion_event.encode()?,
    )?
    .encode()?;
    let companion = BarrierPart {
        identity: identity(2),
        stream: CrossProfileStream::Companion,
        part_index: 1,
        delivery_generation: 1,
        delivery_sequence: 0,
        event_id: [79; 16],
        event_object_id: *agenc_ircd_e2ee::ObjectId::compute(&bytes).as_bytes(),
        encoded_event_object: bytes,
        payload_object_id: Some(payload_id),
        payload_object_bytes: u32::try_from(payload.len())?,
    };
    Ok((vec![base, companion], payload))
}

fn record(
    table: TableId,
    kind: u16,
    key: StoredKey,
    body: Vec<u8>,
) -> TestResult<InitialStorageRecord> {
    let value = PersistentRecordValue::new(table, kind, 1, 0, None, Vec::new(), body)?.encode()?;
    Ok(InitialStorageRecord::new(table, key, 1, value)?)
}

fn crash_rows(received: usize, omit_payload: bool) -> TestResult<Vec<InitialStorageRecord>> {
    let (base, _) = edges();
    let (parts, payload) = parts()?;
    let mut assembly = BarrierAssembly::open(identity(2))?;
    let mut rows = Vec::new();
    let AccountServiceDurableWrite::Put {
        table,
        key,
        plaintext,
    } = base.peer_row(None, 1).map_err(|e| format!("{e:?}"))?
    else {
        return Err("peer row".into());
    };
    rows.push(InitialStorageRecord::new(
        table,
        key,
        1,
        plaintext.to_vec(),
    )?);
    let cursor = DeliveryRow::WitnessedCursor {
        generation: 1,
        next_sequence: 0,
        acked_sequence: 0,
        acked_event_id: [0; 16],
        barrier_open: false,
    };
    rows.push(record(
        TableId::E2eeState,
        DELIVERY_ROW_KIND,
        DeliveryRow::cursor_key(COORDINATOR.as_bytes())?,
        cursor.encode()?,
    )?);
    for part in parts.into_iter().take(received) {
        rows.push(record(
            TableId::E2eeState,
            BARRIER_ROW_KIND,
            part.identity.part_key(part.part_index)?,
            part.encode()?,
        )?);
        assembly.stage(part)?;
    }
    rows.push(record(
        TableId::E2eeState,
        BARRIER_ROW_KIND,
        identity(2).head_key()?,
        BarrierHead::Stage(assembly.head().clone()).encode()?,
    )?);
    if received == 2 && !omit_payload {
        let row = ObjectRow::new(payload)?;
        rows.push(record(
            TableId::E2eeObject,
            OBJECT_RECORD_KIND,
            row.key()?,
            row.encode()?,
        )?);
    }
    Ok(rows)
}

#[tokio::test]
async fn restart_restores_collecting_parts_without_advancing_either_cursor() -> TestResult {
    let fixture = StateCoreFixture::with_registration_router_and_records(
        entropy_script(),
        crash_rows(1, false)?,
    )?;
    let (mut base, mut companion) = edges();
    fixture.restore_edge_state(&mut base, Some(&mut companion))?;
    assert_eq!(base.cursor, None);
    assert_eq!(base.companion_cursor(), (1, None));
    assert!(!base.barrier.ready);
    assert_eq!(
        base.barrier
            .open
            .as_ref()
            .map(|open| open.assembly.head().received_count()),
        Some(1)
    );
    Ok(())
}

#[tokio::test]
async fn restart_restores_complete_barrier_and_payload_before_link_admission() -> TestResult {
    let fixture = StateCoreFixture::with_registration_router_and_records(
        entropy_script(),
        crash_rows(2, false)?,
    )?;
    let (mut base, mut companion) = edges();
    fixture.restore_edge_state(&mut base, Some(&mut companion))?;
    assert!(base.barrier.ready);
    assert_eq!(base.barrier_ready(), None); // The authenticated link must resume first.
    assert_eq!(base.cursor, None);
    assert_eq!(base.companion_cursor(), (1, None));
    Ok(())
}

#[tokio::test]
async fn restart_refuses_a_collecting_barrier_with_missing_payload() -> TestResult {
    let fixture = StateCoreFixture::with_registration_router_and_records(
        entropy_script(),
        crash_rows(2, true)?,
    )?;
    let (mut base, mut companion) = edges();
    assert!(
        fixture
            .restore_edge_state(&mut base, Some(&mut companion))
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn restart_refuses_a_barrier_for_another_edge_incarnation() -> TestResult {
    let fixture = StateCoreFixture::with_registration_router_and_records(
        entropy_script(),
        crash_rows(1, false)?,
    )?;
    let (mut base, mut companion) = edges();
    base.config.incarnation = ServerIncarnation::from_bytes([99; 16]);
    assert!(
        fixture
            .restore_edge_state(&mut base, Some(&mut companion))
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn barrier_apply_retains_immutable_rows_and_restarts_both_committed_cursors() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router_and_records(
        entropy_script(),
        crash_rows(2, false)?,
    )?;
    let (mut base, mut companion) = edges();
    fixture.restore_edge_state(&mut base, Some(&mut companion))?;
    base.phase = Phase::Active;
    let (writes, outputs) = companion
        .prepare_barrier(fixture.context_mut()?, &base, MUTATION)
        .map_err(|e| e.to_string())?;
    assert!(base.apply_barrier(fixture.context_mut()?, writes, outputs));
    assert_eq!(base.cursor, None);
    let writes = fixture.context_mut()?.staged_rows_for_test()?;
    let (mut restarted, mut restarted_companion) = edges();
    fixture.commit_and_restore_edge(writes, &mut restarted, Some(&mut restarted_companion))?;
    for index in 0..2 {
        assert!(fixture.stored_row_exists(TableId::E2eeState, identity(2).part_key(index)?)?);
    }
    assert_eq!(restarted.cursor, Some((0, EventId::from_bytes([78; 16]))));
    assert_eq!(restarted.companion_cursor(), (1, Some((0, [79; 16]))));
    assert!(restarted.barrier_applied(&MUTATION));
    assert!(restarted.barrier.open.is_none());
    let receipt = restarted.barrier.applied.get(&MUTATION).ok_or("receipt")?;
    assert_eq!(receipt.applied_storage_commit_sequence, 1);
    assert_eq!(receipt.applied_local_state_generation, 1);
    Ok(())
}

#[tokio::test]
async fn companion_part_commits_its_payload_with_the_collecting_head() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router_and_records(
        entropy_script(),
        crash_rows(1, false)?,
    )?;
    let (mut base, mut companion) = edges();
    fixture.restore_edge_state(&mut base, Some(&mut companion))?;
    let (handle, _queue) = link_queue(1 << 20);
    base.live = Some(LiveLink {
        link: LinkId::new(99),
        handle,
        coordinator_epoch: COORDINATOR_EPOCH,
        coordinator_incarnation: HUB_INCARNATION,
    });
    let (mut parts, payload) = parts()?;
    let companion_part = parts.pop().ok_or("part")?;
    let payload_key = ObjectRow::new(payload.clone())?.key()?;
    assert!(base.companion_barrier_part(fixture.context_mut()?, companion_part, Some(payload)));
    assert!(!base.barrier.ready);
    let writes = fixture.context_mut()?.staged_rows_for_test()?;
    let (mut restarted, mut restarted_companion) = edges();
    fixture.commit_and_restore_edge(writes, &mut restarted, Some(&mut restarted_companion))?;
    assert!(fixture.stored_row_exists(TableId::E2eeObject, payload_key)?);
    assert!(restarted.barrier.ready);
    assert_eq!(restarted.cursor, None);
    Ok(())
}

#[tokio::test]
async fn refused_part_storage_does_not_create_a_duplicate_that_cannot_be_retried() -> TestResult {
    use crate::state_core::inbox::SignalEvent;
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let (mut base, _) = edges();
    let (handle, _queue) = link_queue(1 << 20);
    base.live = Some(LiveLink {
        link: LinkId::new(99),
        handle,
        coordinator_epoch: COORDINATOR_EPOCH,
        coordinator_incarnation: HUB_INCARNATION,
    });
    fixture
        .state_mut()?
        .step_message(StateCoreMessage::Signal(SignalEvent::Terminate));
    let (mut parts, payload) = parts()?;
    assert!(!base.companion_barrier_part(
        fixture.context_mut()?,
        parts.pop().ok_or("part")?,
        Some(payload)
    ));
    assert!(base.barrier.open.is_none());
    Ok(())
}

fn retained_image(count: u16) -> TestResult<(EdgeFederation, Vec<InitialStorageRecord>)> {
    let (mut base, _) = edges();
    let mut assembly = BarrierAssembly::open(identity(count))?;
    let mut rows = Vec::new();
    for index in 0..count {
        let stream = if index == 0 {
            CrossProfileStream::Base
        } else {
            CrossProfileStream::Companion
        };
        let bytes = index.to_be_bytes().to_vec();
        let object = match stream {
            CrossProfileStream::Base => *federation_object_id(&bytes).as_bytes(),
            CrossProfileStream::Companion => *agenc_ircd_e2ee::ObjectId::compute(&bytes).as_bytes(),
        };
        // Receipt cleanup uses opaque immutable objects; live event decoding
        // is covered by the complete-barrier crash tests above.
        let part = BarrierPart {
            identity: identity(count),
            stream,
            part_index: index,
            delivery_generation: 1,
            delivery_sequence: u64::from(index.saturating_sub(1)),
            event_id: [u8::try_from(index % 255)?; 16],
            event_object_id: object,
            encoded_event_object: bytes,
            payload_object_id: None,
            payload_object_bytes: 0,
        };
        rows.push(record(
            TableId::E2eeState,
            BARRIER_ROW_KIND,
            part.identity.part_key(index)?,
            part.encode()?,
        )?);
        assembly.stage(part)?;
    }
    let receipt = assembly.receipt(1, 1, 0, 604_800);
    let ((sequence, event), (generation, companion_sequence, companion_event)) =
        crate::federation::edge::barrier::last_entries(&receipt).ok_or("receipt streams")?;
    base.cursor = Some((sequence, EventId::from_bytes(event)));
    base.note_companion_delivery(generation, Some((companion_sequence, companion_event)));
    let AccountServiceDurableWrite::Put {
        table,
        key,
        plaintext,
    } = base
        .peer_row(base.cursor, 1)
        .map_err(|e| format!("{e:?}"))?
    else {
        return Err("peer".into());
    };
    rows.push(InitialStorageRecord::new(
        table,
        key,
        1,
        plaintext.to_vec(),
    )?);
    let cursor = DeliveryRow::WitnessedCursor {
        generation,
        next_sequence: companion_sequence + 1,
        acked_sequence: companion_sequence,
        acked_event_id: companion_event,
        barrier_open: false,
    };
    rows.push(record(
        TableId::E2eeState,
        DELIVERY_ROW_KIND,
        DeliveryRow::cursor_key(COORDINATOR.as_bytes())?,
        cursor.encode()?,
    )?);
    rows.push(record(
        TableId::E2eeState,
        BARRIER_ROW_KIND,
        receipt.identity.head_key()?,
        receipt.encode()?,
    )?);
    base.barrier.applied.insert(MUTATION, receipt);
    Ok((base, rows))
}

#[tokio::test]
async fn retention_waits_for_the_deadline_and_bounds_a_resumable_cleanup() -> TestResult {
    let (mut base, rows) = retained_image(2048)?;
    let mut fixture =
        StateCoreFixture::with_registration_router_and_records(entropy_script(), rows)?;
    fixture.context_mut()?.set_wall_for_test(604_799);
    base.retain_barriers(fixture.context_mut()?, false);
    assert_eq!(fixture.context_mut()?.pending_len(), 0);
    fixture.context_mut()?.set_wall_for_test(604_800);
    base.retain_barriers(fixture.context_mut()?, false);
    let writes = fixture.context_mut()?.staged_rows_for_test()?;
    assert_eq!(writes.len(), 1000); // 999 deletions plus the peer cursor row.
    assert!(!writes.iter().any(
        |write| matches!(write, AccountServiceDurableWrite::Delete { key, .. }
        if identity(2048).head_key().is_ok_and(|head| *key == head))
    ));
    let (mut restarted, mut companion) = edges();
    fixture.commit_and_restore_edge(writes, &mut restarted, Some(&mut companion))?;
    assert!(restarted.barrier_applied(&MUTATION));
    assert!(fixture.stored_row_exists(TableId::E2eeState, identity(2048).head_key()?)?);
    assert!(!fixture.stored_row_exists(TableId::E2eeState, identity(2048).part_key(998)?)?);
    assert!(fixture.stored_row_exists(TableId::E2eeState, identity(2048).part_key(999)?)?);
    assert_eq!(restarted.cursor, base.cursor);
    assert_eq!(restarted.companion_cursor(), base.companion_cursor());
    Ok(())
}

#[tokio::test]
async fn retention_deletes_the_head_only_with_its_last_parts() -> TestResult {
    let (mut base, rows) = retained_image(2)?;
    let mut fixture =
        StateCoreFixture::with_registration_router_and_records(entropy_script(), rows)?;
    fixture.context_mut()?.set_wall_for_test(604_800);
    base.retain_barriers(fixture.context_mut()?, false);
    let writes = fixture.context_mut()?.staged_rows_for_test()?;
    let deleted: Vec<_> = writes
        .iter()
        .filter_map(|write| match write {
            AccountServiceDurableWrite::Delete { key, .. } => Some(key.clone()),
            _ => None,
        })
        .collect();
    assert!(deleted.last() == Some(&identity(2).head_key()?));
    let (mut restarted, mut companion) = edges();
    fixture.commit_and_restore_edge(writes, &mut restarted, Some(&mut companion))?;
    assert!(!restarted.barrier_applied(&MUTATION));
    assert_eq!(restarted.cursor, base.cursor);
    assert_eq!(restarted.companion_cursor(), base.companion_cursor());
    Ok(())
}

#[tokio::test]
async fn a_replacement_coordinator_fences_the_old_stage_before_resuming() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router_and_records(
        entropy_script(),
        crash_rows(1, false)?,
    )?;
    let (mut base, mut companion) = edges();
    fixture.restore_edge_state(&mut base, Some(&mut companion))?;
    let (handle, _queue) = link_queue(1 << 20);
    base.link_established(
        fixture.context_mut()?,
        LinkSession {
            link: LinkId::new(99),
            peer: COORDINATOR,
            peer_incarnation: ServerIncarnation::from_bytes([98; 16]),
            peer_recovery_epoch: COORDINATOR_EPOCH,
            transition: agenc_ircd_federation_wire::EpochTransition::Initial,
        },
        handle,
    );
    assert!(matches!(base.commit, Some(PendingCommit::BarrierFence)));
    assert!(base.barrier.open.is_some());
    let writes = fixture.context_mut()?.staged_rows_for_test()?;
    let (mut restarted, mut restarted_companion) = edges();
    fixture.commit_and_restore_edge(writes, &mut restarted, Some(&mut restarted_companion))?;
    assert!(restarted.barrier.open.is_none());
    assert_eq!(restarted.barrier.fenced.len(), 1);
    assert_eq!(restarted.installed_epoch, None);
    assert_eq!(restarted.cursor, None);
    Ok(())
}
