//! Full-scope binding, closed ACK metadata, and exact outbox codec limits.
#![forbid(unsafe_code)]

use super::*;
use crate::e2ee_records::delivery_recovery::{DeliveryRecoveryRow, DeliveryScopeFields};
use crate::{ProtocolRecordBody, TableId};

type TestResult = Result<(), StorageError>;

#[test]
fn scoped_outbox_rejects_oversize_before_decoding_its_envelope() -> TestResult {
    let mut bytes = vec![0; MAX_OUTBOX_BODY_BYTES + 13];
    bytes
        .get_mut(14..16)
        .ok_or(StorageError::InvalidEncoding)?
        .copy_from_slice(&4_u16.to_be_bytes());
    assert_eq!(
        DeliveryRecoveryRow::decode(&bytes),
        Err(StorageError::LimitExceeded)
    );
    Ok(())
}

fn fields() -> Result<ScopedOutboxFields, StorageError> {
    Ok(ScopedOutboxFields {
        scope: DeliveryScope::new(DeliveryScopeFields {
            network_id: [1; 32],
            coordinator_server_id: [2; 16],
            coordinator_incarnation: [3; 16],
            coordinator_recovery_epoch: [4; 16],
            target_server_id: [5; 16],
            target_incarnation: [6; 16],
            covered_base_client_resync_epoch: 7,
        })?,
        generation: 0,
        sequence: 0,
        event_id: [0; 16],
        event_object_id: [8; 32],
        event_bytes: 1,
        payload_object_id: None,
        payload_bytes: 0,
        acknowledgement: Acknowledgement::Unacknowledged,
        cross_profile: None,
    })
}

fn roundtrip(fields: ScopedOutboxFields) -> Result<DeliveryRecoveryRow, StorageError> {
    let row = DeliveryRecoveryRow::Outbox(ScopedOutbox::new(fields)?);
    let bytes = row.encode()?;
    assert_eq!(DeliveryRecoveryRow::decode_at(&row.key()?, &bytes)?, row);
    assert_eq!(crate::e2ee_records::record_kind_for_key(&row.key()?)?, 14);
    Ok(row)
}

#[test]
fn scoped_outbox_pins_complete_key_and_all_acknowledgement_arms() -> TestResult {
    let fields = fields()?;
    let row = roundtrip(fields)?;
    assert_eq!(row.key()?.as_bytes().len(), 155);
    assert_eq!(row.encode()?.len(), 214);
    assert_eq!(parse_outbox_key(&row.key()?)?, (fields.scope, 0, 0));
    let mut key = OUTBOX_PREFIX.to_vec();
    key.extend_from_slice(&[1; 32]);
    for byte in 2..=6 {
        key.extend_from_slice(&[byte; 16]);
    }
    key.extend_from_slice(&7_u64.to_be_bytes());
    key.extend_from_slice(&[0; 16]);
    assert_eq!(row.key()?.as_bytes(), key);
    for acknowledgement in [
        Acknowledgement::Unacknowledged,
        Acknowledgement::AcknowledgedTimeUnknown,
        Acknowledgement::received_at(Some(0)),
        Acknowledgement::received_at(Some(100)),
    ] {
        roundtrip(ScopedOutboxFields {
            acknowledgement,
            ..fields
        })?;
    }
    assert_eq!(
        Acknowledgement::received_at(None),
        Acknowledgement::AcknowledgedTimeUnknown
    );
    assert_eq!(
        Acknowledgement::received_at(Some(u64::MAX)),
        Acknowledgement::AcknowledgedTimeUnknown
    );
    Ok(())
}

#[test]
fn scoped_outbox_rejects_each_key_field_and_preserves_maximum_shape() -> TestResult {
    let fields = ScopedOutboxFields {
        event_bytes: MAX_EVENT_BYTES,
        payload_object_id: Some([9; 32]),
        payload_bytes: MAX_PAYLOAD_BYTES,
        acknowledgement: Acknowledgement::received_at(Some(100)),
        cross_profile: Some(CrossProfileTuple {
            mutation_id: [10; 16],
            part_index: 2047,
            part_count: 2048,
        }),
        ..fields()?
    };
    let row = roundtrip(fields)?;
    assert_eq!(row.encode()?.len(), 282);
    for offset in [0, 19, 51, 67, 83, 99, 115, 131, 139, 147] {
        let mut key = row.key()?.as_bytes().to_vec();
        *key.get_mut(offset).ok_or(StorageError::InvalidEncoding)? ^= 1;
        assert!(DeliveryRecoveryRow::decode_at(&StoredKey::new(key)?, &row.encode()?).is_err());
    }
    let scoped = ScopedOutbox::new(fields)?;
    let ack = scoped.with_acknowledgement(Acknowledgement::AcknowledgedTimeUnknown)?;
    assert!(ack.key()? == scoped.key()?);
    assert_eq!(ack.cross_profile(), scoped.cross_profile());
    assert_eq!(ack.event_object_id(), scoped.event_object_id());
    assert_eq!(ack.payload_object_id(), scoped.payload_object_id());
    Ok(())
}

#[test]
fn scoped_outbox_rejects_length_tuple_and_retention_fact_conflicts() -> TestResult {
    let fields = fields()?;
    let bad_ack = Acknowledgement::AcknowledgedAt {
        received_unix_seconds: 1,
        retain_until_unix_seconds: 86_400,
    };
    for invalid in [
        ScopedOutboxFields {
            event_bytes: 0,
            ..fields
        },
        ScopedOutboxFields {
            event_bytes: MAX_EVENT_BYTES + 1,
            ..fields
        },
        ScopedOutboxFields {
            payload_bytes: 1,
            ..fields
        },
        ScopedOutboxFields {
            payload_object_id: Some([1; 32]),
            ..fields
        },
        ScopedOutboxFields {
            payload_object_id: Some([1; 32]),
            payload_bytes: MAX_PAYLOAD_BYTES + 1,
            ..fields
        },
        ScopedOutboxFields {
            acknowledgement: bad_ack,
            ..fields
        },
        ScopedOutboxFields {
            cross_profile: Some(CrossProfileTuple {
                mutation_id: [0; 16],
                part_index: 0,
                part_count: 1,
            }),
            ..fields
        },
        ScopedOutboxFields {
            cross_profile: Some(CrossProfileTuple {
                mutation_id: [0; 16],
                part_index: 2,
                part_count: 2,
            }),
            ..fields
        },
    ] {
        assert!(ScopedOutbox::new(invalid).is_err());
    }
    Ok(())
}

#[test]
fn scoped_outbox_wire_rejects_unknown_tags_trailing_bytes_and_oversize() -> TestResult {
    let row = DeliveryRecoveryRow::Outbox(ScopedOutbox::new(fields()?)?);
    let bytes = row.encode()?;
    let envelope = ProtocolRecordBody::decode(TableId::E2eeState, 14, &bytes)?;
    let inner = envelope.canonical_object();
    for offset in [192, 198, 200] {
        let mut altered = inner.to_vec();
        altered
            .get_mut(offset..offset + 2)
            .ok_or(StorageError::InvalidEncoding)?
            .copy_from_slice(&3_u16.to_be_bytes());
        let wrapped = ProtocolRecordBody::new(TableId::E2eeState, 14, 1, altered)?.encode()?;
        assert!(DeliveryRecoveryRow::decode(&wrapped).is_err());
    }
    for extra in [1, 69] {
        let mut altered = inner.to_vec();
        altered.resize(inner.len() + extra, 0);
        let wrapped = ProtocolRecordBody::new(TableId::E2eeState, 14, 1, altered)?.encode()?;
        assert!(DeliveryRecoveryRow::decode(&wrapped).is_err());
    }
    Ok(())
}
