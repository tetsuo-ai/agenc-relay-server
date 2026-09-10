//! Hot cache eviction releases acknowledged body leases and preserves the unacknowledged tail.
#![forbid(unsafe_code)]

use super::*;
use crate::budget::{BackingReservationPort, MemoryBudget};
use crate::test_support::TestResult;
use std::sync::Arc;

#[test]
fn acknowledging_large_rows_limits_hot_bytes_and_keeps_the_unacknowledged_tail() -> TestResult {
    let budget = Arc::new(MemoryBudget::new(64 * 1024 * 1024));
    let backing = BackingReservationPort::new(Arc::clone(&budget));
    let mut stream = DeliveryStream {
        acked: Some((3, [3; 16])),
        next_sequence: 6,
        ..DeliveryStream::with_row_capacity(6, &backing)?
    };
    for sequence in 0..6 {
        let seed = u8::try_from(sequence)?;
        stream.rows.push_back(StreamRow {
            sequence,
            event_id: [seed; 16],
            event: SharedBytes::copy_from(&[seed], &backing)?,
            payload: Some((
                [seed; 32],
                SharedBytes::from_owned(vec![seed; 4 * 1024 * 1024], &backing)?,
            )),
            acknowledgement: if sequence < 4 {
                Acknowledgement::received_at(Some(100))
            } else {
                Acknowledgement::Unacknowledged
            },
        });
    }
    let before = budget.charged();
    stream.acknowledge(4, [4; 16], Acknowledgement::received_at(Some(200)))?;
    assert_eq!(stream.rows.iter().filter(|row| row.acked()).count(), 3);
    assert_eq!(stream.rows.front().ok_or("cache head")?.sequence, 2);
    let tail = stream.rows.back().ok_or("tail")?;
    assert_eq!(tail.sequence, 5);
    assert!(!tail.acked());
    assert_eq!(
        tail.payload.as_ref().ok_or("payload")?.1.len(),
        4 * 1024 * 1024
    );
    assert!(budget.charged() < before);
    drop(stream);
    assert_eq!(budget.charged(), 0);
    Ok(())
}
