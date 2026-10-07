//! An ERESUME cursor past the committed acknowledgement names the last row
//! the edge acknowledged (companion 12.5): a retained delivered row at the
//! end of a contiguous unacknowledged prefix, with its exact event ID. Its
//! acknowledgement is cumulative; any other cursor is refused.
#![forbid(unsafe_code)]

use super::*;
use crate::test_support::TestResult;

/// The event identity of the row at `sequence`.
fn id(sequence: u64) -> [u8; 16] {
    [u8::try_from(sequence).unwrap_or(u8::MAX).wrapping_add(40); 16]
}

fn row(sequence: u64) -> TestResult<StreamRow> {
    Ok(StreamRow {
        sequence,
        event_id: id(sequence),
        event: SharedBytes::for_fixture(vec![1, 2, 3])?,
        payload: None,
        acknowledgement: Acknowledgement::Unacknowledged,
    })
}

/// Rows `0..count` delivered, none acknowledged, and no barrier.
fn delivered(count: u64) -> TestResult<DeliveryStream> {
    let mut stream = DeliveryStream {
        generation: 0,
        next_sequence: count,
        ..DeliveryStream::default()
    };
    for sequence in 0..count {
        stream.rows.push_back(row(sequence)?);
    }
    Ok(stream)
}

fn refused(stream: &DeliveryStream, sequence: u64, event_id: [u8; 16]) -> bool {
    matches!(
        stream.validate_resume(sequence, event_id),
        Err(CompanionFault::Protocol)
    )
}

#[test]
fn a_cursor_naming_a_delivered_row_past_the_committed_ack_is_admitted() -> TestResult {
    let mut stream = delivered(4)?;
    // Before any acknowledgement, every delivered row may be the edge's last.
    for sequence in 0..4 {
        stream.validate_resume(sequence, id(sequence))?;
    }
    stream.acknowledge(0, id(0), Acknowledgement::received_at(Some(100)))?;
    // One lost EACK, or several in flight when the link was cut.
    stream.validate_resume(1, id(1))?;
    stream.validate_resume(3, id(3))?;
    Ok(())
}

#[test]
fn a_cursor_naming_no_retained_delivered_row_is_refused() -> TestResult {
    let mut stream = delivered(4)?;
    stream.acknowledge(0, id(0), Acknowledgement::received_at(Some(100)))?;
    assert!(refused(&stream, 2, id(1)), "another row's event ID");
    assert!(refused(&stream, 2, [99; 16]), "an unknown event ID");
    assert!(refused(&stream, 4, id(4)), "a row never delivered");
    assert!(
        refused(&stream, 0, [99; 16]),
        "the committed row under another ID"
    );
    // A cursor behind the committed acknowledgement names an acknowledged row.
    stream.acknowledge(1, id(1), Acknowledgement::received_at(Some(100)))?;
    assert!(
        refused(&stream, 0, id(0)),
        "a cursor behind the committed ack"
    );
    // A gap in the retained prefix.
    let mut gapped = delivered(4)?;
    gapped.rows.remove(1).ok_or("row one")?;
    assert!(refused(&gapped, 2, id(2)), "a gap before the named row");
    // A committed acknowledgement at the highest sequence names no successor.
    let mut saturated = delivered(2)?;
    saturated.acked = Some((u64::MAX, [1; 16]));
    assert!(refused(&saturated, 1, id(1)), "no successor to resume");
    Ok(())
}

#[test]
fn inside_an_open_barrier_only_its_end_and_never_a_held_row() -> TestResult {
    // Rows zero and one are ordinary; the barrier covers two and three.
    let mut stream = delivered(5)?;
    stream.barrier = Some((2, 3));
    stream.hold_after = Some(3);
    stream.validate_resume(1, id(1))?;
    stream.validate_resume(3, id(3))?;
    assert!(refused(&stream, 2, id(2)), "a barrier part before its end");
    assert!(refused(&stream, 4, id(4)), "a row the barrier holds back");
    // Once this profile acknowledged the barrier, later rows are still held
    // until the base profile does.
    stream.acknowledge_resume(3, id(3), Acknowledgement::received_at(Some(100)))?;
    assert_eq!(stream.barrier, None);
    assert!(refused(&stream, 4, id(4)), "a row held after the barrier");
    Ok(())
}

#[test]
fn a_resume_acknowledges_the_prefix_cumulatively() -> TestResult {
    let mut stream = delivered(4)?;
    stream.barrier = Some((3, 3));
    assert!(matches!(
        stream.acknowledge_resume(2, id(2), Acknowledgement::Unacknowledged),
        Err(CompanionFault::Protocol)
    ));
    assert_eq!(stream.acked, None, "the refusal committed nothing");
    stream.acknowledge_resume(2, id(2), Acknowledgement::received_at(Some(100)))?;
    assert_eq!(stream.acked, Some((2, id(2))));
    assert!(
        stream
            .rows
            .iter()
            .all(|row| row.acked() == (row.sequence <= 2))
    );
    assert_eq!(
        stream.barrier,
        Some((3, 3)),
        "an ordinary prefix leaves the barrier open"
    );
    // The barrier end is then acknowledged by its own EACK.
    stream.acknowledge(3, id(3), Acknowledgement::received_at(Some(100)))?;
    assert_eq!(stream.barrier, None);
    Ok(())
}
