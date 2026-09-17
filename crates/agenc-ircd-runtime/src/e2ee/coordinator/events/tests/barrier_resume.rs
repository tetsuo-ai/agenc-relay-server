//! A barrier resume recovers a lost ordinary prefix only through the exact
//! gate end, and only under an acknowledgement that is really one.
#![forbid(unsafe_code)]

use super::*;
use crate::test_support::TestResult;

const FIRST: [u8; 16] = [7; 16];
const LAST: [u8; 16] = [8; 16];

fn row(
    sequence: u64,
    event_id: [u8; 16],
    acknowledgement: Acknowledgement,
) -> TestResult<StreamRow> {
    Ok(StreamRow {
        sequence,
        event_id,
        event: SharedBytes::for_fixture(vec![1, 2, 3])?,
        payload: None,
        acknowledgement,
    })
}

/// Two gated rows, neither acknowledged, with the gate closing at one.
fn open_prefix() -> TestResult<DeliveryStream> {
    let mut stream = DeliveryStream {
        generation: 0,
        next_sequence: 2,
        barrier: Some((0, 1)),
        ..DeliveryStream::default()
    };
    stream
        .rows
        .push_back(row(0, FIRST, Acknowledgement::Unacknowledged)?);
    stream
        .rows
        .push_back(row(1, LAST, Acknowledgement::Unacknowledged)?);
    Ok(stream)
}

#[test]
fn a_resume_names_the_gate_end_and_nothing_else() -> TestResult {
    let stream = open_prefix()?;
    stream.validate_barrier_resume(1, LAST)?;

    // The first gated sequence is not the gate end.
    assert!(matches!(
        stream.validate_barrier_resume(0, FIRST),
        Err(CompanionFault::Protocol)
    ));
    // The gate end under another event identity.
    assert!(matches!(
        stream.validate_barrier_resume(1, FIRST),
        Err(CompanionFault::Protocol)
    ));
    // A stream carrying no open gate at all.
    let mut ungated = open_prefix()?;
    ungated.barrier = None;
    assert!(matches!(
        ungated.validate_barrier_resume(1, LAST),
        Err(CompanionFault::Protocol)
    ));
    // A committed acknowledgement at the highest representable sequence
    // cannot name a successor, so the resume is refused rather than wrapped.
    let mut saturated = open_prefix()?;
    saturated.acked = Some((u64::MAX, FIRST));
    assert!(matches!(
        saturated.validate_barrier_resume(1, LAST),
        Err(CompanionFault::Protocol)
    ));
    Ok(())
}

#[test]
fn an_already_acknowledged_row_is_not_part_of_the_recovered_prefix() -> TestResult {
    let mut stream = open_prefix()?;
    stream.acked = Some((0, FIRST));
    stream.barrier = Some((1, 1));
    let acknowledged = stream.rows.front_mut().ok_or("first row")?;
    acknowledged.acknowledgement = Acknowledgement::received_at(Some(100));
    // The prefix starts after the committed acknowledgement, so the single
    // remaining row is contiguous and the resume is admitted.
    stream.validate_barrier_resume(1, LAST)?;
    Ok(())
}

#[test]
fn an_unacknowledged_resume_records_nothing() -> TestResult {
    let mut stream = open_prefix()?;
    assert!(matches!(
        stream.acknowledge_barrier_resume(1, LAST, Acknowledgement::Unacknowledged),
        Err(CompanionFault::Protocol)
    ));
    assert_eq!(stream.acked, None, "the refusal committed no coverage");
    assert!(
        stream.rows.iter().all(|row| !row.acked()),
        "the refusal acknowledged no row"
    );
    assert_eq!(stream.barrier, Some((0, 1)), "the gate stays open");

    stream.acknowledge_barrier_resume(1, LAST, Acknowledgement::received_at(Some(100)))?;
    assert_eq!(stream.acked, Some((1, LAST)));
    Ok(())
}
