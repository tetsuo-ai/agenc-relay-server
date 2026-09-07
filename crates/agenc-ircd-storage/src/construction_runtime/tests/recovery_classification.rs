//! Declared recovery preserves semantic state and discards obsolete delivery scope.
#![forbid(unsafe_code)]

use super::*;
use crate::e2ee_records::barrier::{
    BARRIER_RETENTION_SECONDS, BarrierHead, BarrierIdentity, BarrierPart, BarrierReceipt,
    BarrierStage, CrossProfileStream,
};
use crate::e2ee_records::origin::{OriginSequenceKey, OriginSequenceRow};
use crate::e2ee_records::{
    BARRIER_ROW_KIND, DELIVERY_ROW_KIND, DeliveryRow, REPLAY_ROW_KIND, ROUTE_ROW_KIND, ReplayKey,
    ReplayRow, RouteLifecycle, RouteRow,
};

struct RecoveryRow {
    label: &'static str,
    kind: u16,
    key: StoredKey,
    body: Vec<u8>,
}

pub(super) fn route_row(
    conversation_id: [u8; 32],
    lifecycle: RouteLifecycle,
) -> Result<RouteRow, StorageError> {
    use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
    use agenc_ircd_e2ee::objects::conversation::IrcConversationKind;
    use agenc_ircd_e2ee::objects::federation::{IrcFederationRouteState, IrcRouteStateKind};
    use agenc_ircd_e2ee::tls::{Opaque, TlsEncode};

    let mut row = RouteRow::decode(&crate::e2ee_records::fixtures::state_body(
        ROUTE_ROW_KIND,
        19,
    )?)?;
    let state = IrcFederationRouteState {
        profile_version: 1,
        network_id: [18; 32],
        state_generation: 4,
        conversation_id,
        conversation_kind: IrcConversationKind::Channel,
        route_binding: [19; 32],
        semantic_route_lock_id: row.lock_id,
        channel_instance_id: Opaque::new(vec![24; 16])
            .map_err(|_| StorageError::InvalidEncoding)?,
        canonical_channel_name_hash: [25; 32],
        direct_account_a: Opaque::new(Vec::new()).map_err(|_| StorageError::InvalidEncoding)?,
        direct_account_b: Opaque::new(Vec::new()).map_err(|_| StorageError::InvalidEncoding)?,
        binding_id: row.binding_id,
        finalized_epoch: 1,
        accepted_state_id: row.accepted_state_id,
        sequencer_record_head_sequence: row.route_sequence,
        sequencer_record_head_id: row.sequencer_head_id,
        state: if lifecycle == RouteLifecycle::Tombstone {
            IrcRouteStateKind::EncryptedTombstone
        } else {
            IrcRouteStateKind::ActiveRoute
        },
    };
    row.route_state = IrcWireObject::new(
        IrcWireObjectKind::FederationState,
        state.encode().map_err(|_| StorageError::InvalidEncoding)?,
    )
    .and_then(|object| object.encode())
    .map_err(|_| StorageError::InvalidEncoding)?;
    row.lifecycle = lifecycle;
    row.close_id = (lifecycle != RouteLifecycle::Active).then_some([20; 32]);
    Ok(row)
}

fn recovery_record(row: &RecoveryRow) -> Result<ConstructionSourceRecord, StorageError> {
    let plaintext = PersistentRecordValue::new(
        TableId::E2eeState,
        row.kind,
        17,
        4,
        None,
        Vec::new(),
        row.body.clone(),
    )?
    .encode()?;
    Ok(record(TableId::E2eeState, row.key.clone(), plaintext))
}

// Call the real selector, and remove the scratch database before any expected
// red assertion so an assertion failure leaves no in-worktree test artifact.
fn recovery_selection(row: &RecoveryRow) -> Result<RestoreSelection, StorageError> {
    let (file, path) = scratch_file(row.label)?;
    let mut builder = ConstructionPlanBuilder::start_streaming(
        StorageConstructionKind::Restore,
        file,
        maximum_limits(),
    )?;
    let source = backup_source(TableId::E2eeState, &row.key, 1)?;
    let result = select_restore_record(&mut builder, &source, &recovery_record(row)?);
    drop(builder);
    std::fs::remove_file(path).map_err(|_| StorageError::FilesystemRejected)?;
    result
}

fn recover_selected(row: &RecoveryRow) -> Result<PersistentRecordValue, StorageError> {
    let RestoreSelection::Direct(action) = recovery_selection(row)? else {
        return Err(StorageError::StaleState);
    };
    let entry = restore_entry(TableId::E2eeState, row.key.clone(), action)?;
    let mut transformer = RecoveryTransformV1::new(
        RecoveryEpoch::from_bytes([231; 16]),
        StorageDigest::from_bytes([232; 32]),
    );
    let bytes = transformer.transform(
        StorageConstructionKind::Restore,
        &entry,
        &[recovery_record(row)?],
    )?;
    PersistentRecordValue::decode(TableId::E2eeState, &bytes)
}

#[test]
fn declared_recovery_marks_typed_live_routes_pending_without_rewriting_their_heads()
-> Result<(), StorageError> {
    for (lifecycle, pending) in [
        (RouteLifecycle::Active, true),
        (RouteLifecycle::Closing, true),
        (RouteLifecycle::Tombstone, false),
    ] {
        let mut original = route_row([21; 32], lifecycle)?;
        let row = RecoveryRow {
            label: "cap72-route",
            kind: ROUTE_ROW_KIND,
            key: RouteRow::key(&[21; 32])?,
            body: original.encode()?,
        };
        let restored = recover_selected(&row)?;
        assert_eq!((restored.revision(), restored.generation()), (17, 4));
        let actual = RouteRow::decode(restored.body())?;
        original.recovery_gate = pending;
        assert_eq!(actual, original, "typed route lifecycle {lifecycle:?}");
    }
    Ok(())
}

fn assert_recovery_binding_refused(row: &RecoveryRow) -> Result<(), StorageError> {
    assert!(
        recovery_selection(row).is_err(),
        "selector accepted {}",
        row.label
    );
    let entry = restore_entry(
        TableId::E2eeState,
        row.key.clone(),
        StorageConstructionAction::RestoreE2eeState,
    )?;
    let result = RecoveryTransformV1::new(
        RecoveryEpoch::from_bytes([231; 16]),
        StorageDigest::from_bytes([232; 32]),
    )
    .transform(
        StorageConstructionKind::Restore,
        &entry,
        &[recovery_record(row)?],
    );
    assert!(result.is_err(), "stale plan accepted {}", row.label);
    Ok(())
}

#[test]
fn declared_recovery_rejects_a_route_key_that_does_not_bind_its_wire_state()
-> Result<(), StorageError> {
    let route = route_row([21; 32], RouteLifecycle::Active)?;
    let mut row = RecoveryRow {
        label: "cap72-route-identity",
        kind: ROUTE_ROW_KIND,
        key: RouteRow::key(&[22; 32])?,
        body: route.encode()?,
    };
    assert_recovery_binding_refused(&row)?;
    row.key = StoredKey::new(crate::e2ee_records::prefix::ROUTE.to_vec())?;
    assert_recovery_binding_refused(&row)?;
    row.key = RouteRow::key(&[21; 32])?;
    let mut invalid = route;
    invalid.route_state.pop();
    row.body = invalid.encode()?;
    assert_recovery_binding_refused(&row)
}

#[test]
fn declared_recovery_rejects_a_legacy_gate_under_another_conversation() -> Result<(), StorageError>
{
    let gate = crate::E2eeRecoveryGate::new(
        StorageDigest::from_bytes([227; 32]),
        crate::E2eeRecoveryKind::Normal,
        RecoveryEpoch::from_bytes([225; 16]),
        StorageDigest::from_bytes([228; 32]),
        StorageDigest::from_bytes([229; 32]),
        StorageDigest::from_bytes([230; 32]),
        StorageDigest::from_bytes([226; 32]),
    );
    let mut row = RecoveryRow {
        label: "cap72-gate-identity",
        kind: crate::e2ee_records::RECOVERY_GATE_KIND,
        key: crate::e2ee_records::recovery_gate_key(&[224; 32])?,
        body: gate.encode()?,
    };
    assert_recovery_binding_refused(&row)?;
    row.key = StoredKey::new(crate::e2ee_records::prefix::RECOVERY.to_vec())?;
    assert_recovery_binding_refused(&row)
}

fn delivery_rows() -> Result<Vec<RecoveryRow>, StorageError> {
    let cursor = DeliveryRow::Cursor {
        generation: 9,
        next_sequence: 2,
        acked_sequence: 0,
        acked_event_id: [31; 16],
        barrier_open: false,
    };
    let witnessed = DeliveryRow::WitnessedCursor {
        generation: 9,
        next_sequence: 2,
        acked_sequence: 1,
        acked_event_id: [32; 16],
        barrier_open: false,
    };
    let outbox = DeliveryRow::Outbox {
        event_id: [32; 16],
        event_object_id: [33; 32],
        payload_object_id: None,
        payload_bytes: 0,
        acked: false,
        cross_profile: None,
    };
    let snapshot = DeliveryRow::Snapshot {
        generation: 9,
        token: [34; 32],
        entry_count: 0,
        digest: [35; 32],
        ready: true,
        expires_at: 123_456,
    };
    let cases = [
        ("cap72-cursor", DeliveryRow::cursor_key(&[36; 16])?, cursor),
        (
            "cap72-witnessed",
            DeliveryRow::cursor_key(&[37; 16])?,
            witnessed,
        ),
        (
            "cap72-outbox",
            DeliveryRow::outbox_key(&[36; 16], 9, 1)?,
            outbox,
        ),
        (
            "cap72-estate",
            DeliveryRow::snapshot_key(&[36; 16])?,
            snapshot,
        ),
    ];
    cases
        .into_iter()
        .map(|(label, key, value)| {
            Ok(RecoveryRow {
                label,
                kind: DELIVERY_ROW_KIND,
                key,
                body: value.encode()?,
            })
        })
        .collect()
}

fn assert_recovery_omits(rows: Vec<RecoveryRow>) -> Result<(), StorageError> {
    let mut copied = Vec::new();
    for row in rows {
        if !matches!(recovery_selection(&row)?, RestoreSelection::Omit) {
            // Demonstrate that current admitted rows really survive the fixed
            // recovery transform, rather than only checking a classification.
            let restored = recover_selected(&row)?;
            assert_eq!(restored.record_kind(), row.kind);
            assert_eq!(restored.body(), row.body.as_slice());
            copied.push(row.label);
        }
    }
    assert!(
        copied.is_empty(),
        "old transport scope selected and copied: {copied:?}"
    );
    Ok(())
}

#[test]
fn declared_recovery_discards_all_typed_delivery_arms() -> Result<(), StorageError> {
    assert_recovery_omits(delivery_rows()?)
}

#[test]
fn declared_recovery_discards_replay_roots_and_origin_sequence_floors() -> Result<(), StorageError>
{
    let parts = ReplayKey {
        home_server_id: [41; 16],
        server_incarnation: [42; 16],
        origin_id: [43; 16],
        origin_generation: 4,
        operation_sequence: 5,
    };
    let sequence_key = OriginSequenceKey {
        home_server_id: parts.home_server_id,
        server_incarnation: parts.server_incarnation,
        origin_id: parts.origin_id,
    };
    assert_recovery_omits(vec![
        RecoveryRow {
            label: "cap72-replay",
            kind: REPLAY_ROW_KIND,
            key: ReplayRow::key(&parts)?,
            body: crate::e2ee_records::fixtures::state_body(REPLAY_ROW_KIND, 44)?,
        },
        RecoveryRow {
            label: "cap72-origin-floor",
            kind: REPLAY_ROW_KIND,
            key: OriginSequenceRow::key(&sequence_key)?,
            body: OriginSequenceRow {
                origin_generation: 4,
                next_sequence: 6,
            }
            .encode()?,
        },
    ])
}

fn recovery_barrier_part(index: u16, stream: CrossProfileStream) -> BarrierPart {
    BarrierPart {
        identity: BarrierIdentity {
            network_id: [51; 32],
            coordinator_server_id: [52; 16],
            coordinator_server_incarnation: [53; 16],
            coordinator_recovery_epoch: [54; 16],
            target_server_id: [55; 16],
            target_server_incarnation: [56; 16],
            mutation_id: [57; 16],
            coordinator_state_generation: 20,
            part_count: 2,
        },
        stream,
        part_index: index,
        delivery_generation: 9,
        delivery_sequence: 1,
        event_id: [58; 16],
        event_object_id: [59; 32],
        encoded_event_object: vec![60],
        payload_object_id: None,
        payload_object_bytes: 0,
    }
}

#[test]
fn declared_recovery_discards_collecting_applied_and_part_barrier_rows() -> Result<(), StorageError>
{
    let base = recovery_barrier_part(0, CrossProfileStream::Base);
    let companion = recovery_barrier_part(1, CrossProfileStream::Companion);
    let stage = BarrierHead::Stage(BarrierStage::empty(base.identity));
    let receipt = BarrierHead::Receipt(BarrierReceipt {
        identity: base.identity,
        applied_storage_commit_sequence: 21,
        applied_local_state_generation: 20,
        applied_at: 1_000,
        retain_until: 1_000 + BARRIER_RETENTION_SECONDS,
        aggregate_event_payload_bytes: 2,
        entries: vec![base.receipt_entry(), companion.receipt_entry()],
    });
    assert_recovery_omits(vec![
        RecoveryRow {
            label: "cap72-stage",
            kind: BARRIER_ROW_KIND,
            key: base.identity.head_key()?,
            body: stage.encode()?,
        },
        RecoveryRow {
            label: "cap72-receipt",
            kind: BARRIER_ROW_KIND,
            key: base.identity.head_key()?,
            body: receipt.encode()?,
        },
        RecoveryRow {
            label: "cap72-part",
            kind: BARRIER_ROW_KIND,
            key: base.identity.part_key(0)?,
            body: base.encode()?,
        },
    ])
}

#[test]
fn declared_recovery_rejects_delivery_kind_key_and_arm_mismatches() -> Result<(), StorageError> {
    for mut row in delivery_rows()? {
        row.key = RouteRow::key(&[71; 32])?;
        assert!(
            recovery_selection(&row).is_err(),
            "wrong kind: {}",
            row.label
        );
    }
    let mut row = delivery_rows()?
        .into_iter()
        .nth(2)
        .ok_or(StorageError::InvalidEncoding)?;
    row.key = DeliveryRow::cursor_key(&[36; 16])?;
    assert!(recovery_selection(&row).is_err(), "outbox under cursor key");
    row.key = StoredKey::new(crate::e2ee_records::prefix::OUTBOX.to_vec())?;
    assert!(recovery_selection(&row).is_err(), "truncated outbox key");
    Ok(())
}

#[test]
fn declared_recovery_rejects_replay_body_under_an_origin_floor_key() -> Result<(), StorageError> {
    let key = OriginSequenceRow::key(&OriginSequenceKey {
        home_server_id: [72; 16],
        server_incarnation: [73; 16],
        origin_id: [74; 16],
    })?;
    let row = RecoveryRow {
        label: "cap72-replay-key-mismatch",
        kind: REPLAY_ROW_KIND,
        key,
        body: crate::e2ee_records::fixtures::state_body(REPLAY_ROW_KIND, 75)?,
    };
    assert!(recovery_selection(&row).is_err());
    Ok(())
}

#[test]
fn declared_recovery_rejects_a_barrier_part_under_another_identity() -> Result<(), StorageError> {
    let mut part = recovery_barrier_part(0, CrossProfileStream::Base);
    let key = part.identity.part_key(part.part_index)?;
    part.identity.mutation_id = [76; 16];
    let row = RecoveryRow {
        label: "cap72-barrier-key-mismatch",
        kind: BARRIER_ROW_KIND,
        key,
        body: part.encode()?,
    };
    assert!(recovery_selection(&row).is_err());
    Ok(())
}

#[test]
fn declared_recovery_rejects_a_stale_plan_that_copies_old_delivery() -> Result<(), StorageError> {
    let mut transformer = RecoveryTransformV1::new(
        RecoveryEpoch::from_bytes([231; 16]),
        StorageDigest::from_bytes([232; 32]),
    );
    for row in delivery_rows()? {
        let entry = restore_entry(
            TableId::E2eeState,
            row.key.clone(),
            StorageConstructionAction::RestoreE2eeState,
        )?;
        assert_eq!(
            transformer.transform(
                StorageConstructionKind::Restore,
                &entry,
                &[recovery_record(&row)?],
            ),
            Err(StorageError::StaleState),
        );
    }
    Ok(())
}

#[test]
fn declared_recovery_keeps_sequencer_and_mailbox_proof_bytes_and_counters()
-> Result<(), StorageError> {
    use crate::e2ee_records::{
        KEYSET_ROW_KIND, KeySetRow, MAILBOX_ROW_KIND, MailboxRow, ProofRole, SEQUENCER_ROW_KIND,
        SequencerRow,
    };
    let cases = [
        (
            SEQUENCER_ROW_KIND,
            SequencerRow::proof_key(ProofRole::Ack, &[77; 32], &[78; 32], &[79; 32], &[80; 16])?,
        ),
        (
            MAILBOX_ROW_KIND,
            MailboxRow::ack_key(&[81; 32], &[82; 16], &[83; 32])?,
        ),
        (KEYSET_ROW_KIND, KeySetRow::key()?),
    ];
    for (kind, key) in cases {
        let row = RecoveryRow {
            label: "cap72-preserved-proof",
            kind,
            key,
            body: crate::e2ee_records::fixtures::state_body(kind, 84)?,
        };
        let restored = recover_selected(&row)?;
        assert_eq!(restored.body(), row.body.as_slice());
        assert_eq!(restored.record_kind(), kind);
        assert_eq!((restored.revision(), restored.generation()), (17, 4));
        assert!(restored.references().is_empty());
        assert_eq!(restored.expires_at(), None);
    }
    Ok(())
}
