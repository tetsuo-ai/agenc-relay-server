#![forbid(unsafe_code)]

use agenc_ircd_storage::e2ee_records::DeliveryRow;

#[test]
fn witnessed_cursor_round_trips_without_changing_the_legacy_cursor_encoding()
-> Result<(), Box<dyn std::error::Error>> {
    let legacy = DeliveryRow::Cursor {
        generation: 2,
        next_sequence: 8,
        acked_sequence: 7,
        acked_event_id: [11; 16],
        barrier_open: false,
    };
    let marked = DeliveryRow::WitnessedCursor {
        generation: 2,
        next_sequence: 8,
        acked_sequence: 7,
        acked_event_id: [11; 16],
        barrier_open: false,
    };
    let old_bytes = legacy.encode()?;
    let bytes = marked.encode()?;
    assert_eq!(DeliveryRow::decode(&old_bytes)?, legacy);
    assert_eq!(DeliveryRow::decode(&bytes)?, marked);
    assert_ne!(old_bytes, bytes);
    assert_eq!(old_bytes.len(), bytes.len());
    let end = bytes.len().checked_sub(1).ok_or("cursor body")?;
    assert!(DeliveryRow::decode(bytes.get(..end).ok_or("truncated body")?).is_err());
    let invalid = DeliveryRow::WitnessedCursor {
        generation: 2,
        next_sequence: 7,
        acked_sequence: 8,
        acked_event_id: [11; 16],
        barrier_open: false,
    };
    assert!(DeliveryRow::decode(&invalid.encode()?).is_err());
    Ok(())
}
