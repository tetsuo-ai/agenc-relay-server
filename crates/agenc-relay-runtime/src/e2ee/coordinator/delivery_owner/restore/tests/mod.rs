//! Delivery restore collects a bounded inventory, and an incomplete or
//! already failed collection can neither continue nor be applied.
#![forbid(unsafe_code)]

use super::*;
use crate::budget::{BackingReservationPort, MemoryBudget};
use crate::e2ee::coordinator::events::SharedBytes;
use crate::test_support::TestResult;
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::tls::TlsEncode;
use agenc_relay_storage::e2ee_records::delivery_recovery::{
    Acknowledgement, BarrierEndpoint, DeliveryBarrierFields, fixture_body,
};
use agenc_relay_storage::e2ee_records::{
    DELIVERY_RECOVERY_ROW_KIND, SEQUENCER_ROW_KIND, SequencerRow,
};
use agenc_relay_storage::{PersistentRecordValue, TableId};
use std::sync::Arc;

fn backing() -> BackingReservationPort {
    BackingReservationPort::new(Arc::new(MemoryBudget::new(64 * 1_048_576)))
}

fn stored(body: Vec<u8>) -> TestResult<PersistentRecordValue> {
    Ok(PersistentRecordValue::new(
        TableId::E2eeState,
        DELIVERY_RECOVERY_ROW_KIND,
        1,
        0,
        None,
        Vec::new(),
        body,
    )?)
}

fn owner_row(seed: u8) -> TestResult<(StoredKey, PersistentRecordValue)> {
    let body = fixture_body(seed)?;
    let key = DeliveryRecoveryRow::decode(&body)?.key()?;
    Ok((key, stored(body)?))
}

fn barrier_row(seed: u8) -> TestResult<(StoredKey, PersistentRecordValue)> {
    let DeliveryRecoveryRow::Owner(owner) = DeliveryRecoveryRow::decode(&fixture_body(seed)?)?
    else {
        return Err("owner fixture".into());
    };
    let gate = DeliveryBarrier::new(DeliveryBarrierFields {
        scope: *owner.scope(),
        mutation_id: [9; 16],
        state_generation: 1,
        part_count: 3,
        base: BarrierEndpoint::new(0, 0, 0, [7; 16])?,
        companion: BarrierEndpoint::new(0, 0, 1, [8; 16])?,
        base_acked: false,
        companion_acked: true,
    })?;
    let row = DeliveryRecoveryRow::Barrier(gate);
    let key = row.key()?;
    Ok((key, stored(row.encode()?)?))
}

fn coordinator() -> CompanionCoordinator {
    CompanionCoordinator::new(
        [7; 32],
        ServerId::from_bytes([7; 16]),
        "coordinator.example".to_owned(),
    )
}

#[test]
fn an_owner_row_collected_after_the_replay_started_fails_the_restore() -> TestResult {
    let mut restore = Restore {
        replay_started: true,
        ..Restore::default()
    };
    let (key, value) = owner_row(7)?;
    restore.admit_owner(&key, &value);
    assert!(restore.validate_scopes(|_| Ok(())).is_err());
    assert!(restore.next_page(&backing()).is_err());
    Ok(())
}

#[test]
fn owner_and_barrier_inventories_stop_at_the_federation_peer_ceiling() -> TestResult {
    let mut owners = Restore::default();
    for seed in 0..crate::federation::MAX_FEDERATION_PEERS {
        let (key, value) = owner_row(u8::try_from(seed)?)?;
        owners.admit_owner(&key, &value);
    }
    owners.validate_scopes(|_| Ok(()))?;
    let (key, value) = owner_row(u8::try_from(crate::federation::MAX_FEDERATION_PEERS)?)?;
    owners.admit_owner(&key, &value);
    assert!(owners.validate_scopes(|_| Ok(())).is_err());

    let mut barriers = Restore::default();
    for seed in 0..crate::federation::MAX_FEDERATION_PEERS {
        let (key, value) = barrier_row(u8::try_from(seed)?)?;
        barriers.admit_owner(&key, &value);
    }
    barriers.validate_scopes(|_| Ok(()))?;
    let (key, value) = barrier_row(u8::try_from(crate::federation::MAX_FEDERATION_PEERS)?)?;
    barriers.admit_owner(&key, &value);
    assert!(barriers.validate_scopes(|_| Ok(())).is_err());
    Ok(())
}

#[test]
fn a_failed_or_incomplete_collection_is_never_applied() -> TestResult {
    let failed = Restore {
        failed: true,
        ..Restore::default()
    };
    assert_eq!(
        failed.apply(&mut coordinator()).err(),
        Some(CompanionFault::Storage)
    );

    let mut short = Restore::default();
    let (key, value) = owner_row(7)?;
    short.admit_owner(&key, &value);
    assert_eq!(
        short.apply(&mut coordinator()).err(),
        Some(CompanionFault::Storage),
        "an owner without its restored stream"
    );
    Ok(())
}

#[test]
fn a_restored_page_of_another_record_kind_is_refused() -> TestResult {
    let mut coordinator = coordinator();
    let body = SequencerRow::Record {
        record_object_id: [1; 32],
        record_id: [2; 32],
        record_kind: 1,
        terminal: false,
        security_proof: false,
        predecessor_record_id: [3; 32],
    }
    .encode()?;
    let value = PersistentRecordValue::new(
        TableId::E2eeState,
        SEQUENCER_ROW_KIND,
        1,
        0,
        None,
        Vec::new(),
        body,
    )?;
    let (key, _) = owner_row(7)?;
    assert_eq!(
        coordinator.admit_restored_delivery_page(&key, &value).err(),
        Some(CompanionFault::Storage)
    );
    assert_eq!(
        coordinator
            .inventory_restored_delivery_page(&key, &value)
            .err(),
        Some(CompanionFault::Storage)
    );
    Ok(())
}

#[test]
fn a_complete_stream_keeps_no_more_than_the_acknowledged_replay_ceiling() -> TestResult {
    let backing = backing();
    let row = |sequence: u64| -> TestResult<StreamRow> {
        Ok(StreamRow {
            sequence,
            event_id: [1; 16],
            event: SharedBytes::copy_from(&[7], &backing).map_err(|_| "row bytes")?,
            payload: None,
            acknowledgement: Acknowledgement::received_at(Some(100)),
        })
    };
    let ceiling = u64::try_from(MAX_ACKED_REPLAY_ROWS)?;
    let mut stream = DeliveryStream {
        next_sequence: ceiling,
        acked: Some((ceiling.saturating_sub(1), [1; 16])),
        ..DeliveryStream::default()
    };
    for sequence in 0..ceiling {
        stream.rows.push_back(row(sequence)?);
    }
    validate_complete(&stream)?;
    stream.rows.push_back(row(ceiling)?);
    assert_eq!(
        validate_complete(&stream).err(),
        Some(CompanionFault::Storage)
    );
    Ok(())
}

#[test]
fn a_restored_object_that_is_not_a_federation_event_does_not_decode() -> TestResult {
    let bytes = ArcWireObject::new(ArcWireObjectKind::CommitMls, vec![1, 2, 3])?.encode()?;
    assert_eq!(decode_event(&bytes).err(), Some(CompanionFault::Storage));
    Ok(())
}
