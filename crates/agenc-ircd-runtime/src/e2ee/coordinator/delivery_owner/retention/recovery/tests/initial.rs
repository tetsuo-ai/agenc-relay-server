//! Unacknowledged streams need no ACK journal and cannot inherit ACKs from rows.
#![forbid(unsafe_code)]

use super::*;
use agenc_ircd_e2ee::limits::MAX_UNACKED_E2EE_EVENTS_PER_EDGE;

fn fixture(count: u64) -> TestResult<Fixture> {
    let mut f = Fixture::new()?;
    f.current = DeliveryOwner::new(
        *f.current.scope(),
        DeliveryCursor::new(0, count, LastAcknowledged::BeforeFirst)?,
        *f.current.cut(),
        f.current.phase(),
    )?;
    f.owner = None;
    f.ranges.clear();
    f.rows.truncate(usize::try_from(count)?);
    Ok(f)
}

fn drive(reader: &mut Reader, f: &Fixture) -> TestResult<u64> {
    let mut count = 0;
    loop {
        match reader.next()? {
            Next::Read(request) => {
                let (truncated, records) = f.page(&request)?;
                reader.admit(&request, 7, truncated, records)?;
            }
            Next::Row(row) => {
                assert_eq!(row.sequence(), count);
                assert_eq!(row.acknowledgement(), Acknowledgement::Unacknowledged);
                count += 1;
            }
            Next::Done => return Ok(count),
        }
    }
}

#[test]
fn empty_and_paged_unacknowledged_streams_recover_without_a_journal() -> TestResult {
    for count in [0, 1, 258] {
        let f = fixture(count)?;
        let mut reader = f.reader()?;
        assert_eq!(drive(&mut reader, &f)?, count);
        let restored = reader.finish()?;
        assert!(restored.owner.is_none());
        assert!(restored.head.is_none());
    }
    Ok(())
}

#[test]
fn an_acknowledged_cursor_requires_its_journal_before_any_row_is_returned() -> TestResult {
    let mut f = Fixture::new()?;
    f.owner = None;
    f.ranges.clear();
    let mut reader = f.reader()?;
    let request = query(&mut reader)?;
    assert!(reader.admit(&request, 7, false, Vec::new()).is_err());
    assert!(reader.next().is_err());
    assert!(reader.finish().is_err());
    Ok(())
}

#[test]
fn an_orphan_ack_range_cannot_acknowledge_a_new_stream() -> TestResult {
    let mut f = fixture(2)?;
    f.ranges = Fixture::new()?.ranges;
    let mut reader = start(&f)?;
    assert!(drive(&mut reader, &f).is_err());
    assert!(reader.next().is_err());
    assert!(reader.finish().is_err());
    Ok(())
}

#[test]
fn gaps_missing_tails_and_per_row_acknowledgements_permanently_refuse_recovery() -> TestResult {
    for case in 0..5 {
        let mut f = fixture(2)?;
        match case {
            0 => {
                f.rows.remove(0);
            }
            1 => {
                f.rows.pop();
            }
            _ => {
                let row = ScopedOutbox::new(ScopedOutboxFields {
                    scope: *f.current.scope(),
                    generation: u64::from(case == 4),
                    sequence: 0,
                    event_id: event_id(0),
                    event_object_id: [18; 32],
                    event_bytes: 1024,
                    payload_object_id: None,
                    payload_bytes: 0,
                    acknowledgement: if case == 2 {
                        Acknowledgement::received_at(Some(100))
                    } else if case == 3 {
                        Acknowledgement::AcknowledgedTimeUnknown
                    } else {
                        Acknowledgement::Unacknowledged
                    },
                    cross_profile: None,
                })?;
                *f.rows.first_mut().ok_or("first row")? = (
                    row.key()?,
                    value(DeliveryRecoveryRow::Outbox(row).encode()?)?,
                );
            }
        }
        let mut reader = start(&f)?;
        assert!(drive(&mut reader, &f).is_err(), "case {case}");
        assert!(reader.next().is_err());
        assert!(reader.finish().is_err());
    }
    Ok(())
}

#[test]
fn an_unacknowledged_cursor_cannot_exceed_the_delivery_row_limit() -> TestResult {
    let f = fixture(MAX_UNACKED_E2EE_EVENTS_PER_EDGE + 1)?;
    assert!(start(&f).is_err());
    Ok(())
}

#[test]
fn unacknowledged_payloads_cannot_exceed_the_stream_byte_limit() -> TestResult {
    let mut f = fixture(258)?;
    for (sequence, record) in f.rows.iter_mut().enumerate() {
        let sequence = u64::try_from(sequence)?;
        let row = ScopedOutbox::new(ScopedOutboxFields {
            scope: *f.current.scope(),
            generation: 0,
            sequence,
            event_id: event_id(sequence),
            event_object_id: [18; 32],
            event_bytes: 65_536,
            payload_object_id: Some([19; 32]),
            payload_bytes: 4_194_304,
            acknowledgement: Acknowledgement::Unacknowledged,
            cross_profile: None,
        })?;
        *record = (
            row.key()?,
            value(DeliveryRecoveryRow::Outbox(row).encode()?)?,
        );
    }
    let mut reader = start(&f)?;
    assert!(drive(&mut reader, &f).is_err());
    assert!(reader.next().is_err());
    assert!(reader.finish().is_err());
    Ok(())
}
