#![forbid(unsafe_code)]

use agenc_ircd_storage::e2ee_records::{DELIVERY_ROW_KIND, DeliveryRow};
use agenc_ircd_storage::{ProtocolRecordBody, StoredKey, TableId};

#[test]
fn witnessed_cursor_rejects_obsolete_arms_and_inconsistent_positions()
-> Result<(), Box<dyn std::error::Error>> {
    let marked = DeliveryRow::WitnessedCursor {
        generation: 2,
        next_sequence: 8,
        acked_sequence: 7,
        acked_event_id: [11; 16],
        barrier_open: false,
    };
    let bytes = marked.encode()?;
    assert_eq!(DeliveryRow::decode(&bytes)?, marked);
    for end in 0..bytes.len() {
        assert!(DeliveryRow::decode(bytes.get(..end).ok_or("truncated body")?).is_err());
    }
    for obsolete in [1_u16, 2, 3] {
        let mut inner = ProtocolRecordBody::decode(TableId::E2eeState, DELIVERY_ROW_KIND, &bytes)?
            .canonical_object()
            .to_vec();
        inner
            .get_mut(2..4)
            .ok_or("body arm")?
            .copy_from_slice(&obsolete.to_be_bytes());
        let unsupported =
            ProtocolRecordBody::new(TableId::E2eeState, DELIVERY_ROW_KIND, 1, inner)?.encode()?;
        assert!(DeliveryRow::decode(&unsupported).is_err());
    }
    for (next_sequence, acked_sequence, acked_event_id) in [
        (7, 8, [11; 16]),
        (8, 6, [11; 16]),
        (0, 0, [11; 16]),
        (0, 1, [0; 16]),
        (u64::MAX, u64::MAX, [11; 16]),
    ] {
        let invalid = DeliveryRow::WitnessedCursor {
            generation: 2,
            next_sequence,
            acked_sequence,
            acked_event_id,
            barrier_open: false,
        };
        assert!(DeliveryRow::decode(&invalid.encode()?).is_err());
    }
    let empty = DeliveryRow::WitnessedCursor {
        generation: 0,
        next_sequence: 0,
        acked_sequence: 0,
        acked_event_id: [0; 16],
        barrier_open: false,
    };
    assert_eq!(DeliveryRow::decode(&empty.encode()?)?, empty);
    assert!(marked.matches_key(&DeliveryRow::cursor_key(&[1; 16])?));
    assert!(!marked.matches_key(&StoredKey::new(b"delivery/v1/".to_vec())?));
    let mut extended = DeliveryRow::cursor_key(&[1; 16])?.as_bytes().to_vec();
    extended.push(0);
    assert!(!marked.matches_key(&StoredKey::new(extended)?));
    for prefix in [b"outbox/v1/".as_slice(), b"estate/v1/".as_slice()] {
        let mut key = prefix.to_vec();
        key.extend_from_slice(&[1; 16]);
        assert!(
            agenc_ircd_storage::e2ee_records::record_kind_for_key(&StoredKey::new(key)?).is_err()
        );
    }
    Ok(())
}
