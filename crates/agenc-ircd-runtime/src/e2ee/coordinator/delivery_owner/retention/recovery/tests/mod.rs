//! Pages cross interval boundaries; no test here substitutes metadata for object validation.
#![forbid(unsafe_code)]

mod sealed;

use super::*;
use crate::budget::MemoryBudget;
use crate::test_support::TestResult;
use agenc_ircd_storage::TableId;
use agenc_ircd_storage::e2ee_records::DELIVERY_RECOVERY_ROW_KIND;
use agenc_ircd_storage::e2ee_records::delivery_recovery::outbox::replay::{
    AckRangeFields, ReplayLedgerRow, ReplayOwnerFields,
};
use agenc_ircd_storage::e2ee_records::delivery_recovery::{
    Acknowledgement, DeliveryCursor, DeliveryRecoveryRow, LastAcknowledged, ScopedOutboxFields,
    fixture_body,
};
use std::sync::Arc;

type Record = (StoredKey, PersistentRecordValue);

fn copy_record(record: &Record) -> TestResult<Record> {
    Ok((
        record.0.clone(),
        PersistentRecordValue::decode(TableId::E2eeState, &record.1.encode()?)?,
    ))
}

struct Fixture {
    current: DeliveryOwner,
    owner: Option<Record>,
    ranges: Vec<Record>,
    rows: Vec<Record>,
    backing: BackingReservationPort,
}

fn event_id(sequence: u64) -> [u8; 16] {
    let mut result = [0; 16];
    for (byte, value) in result.iter_mut().zip(sequence.to_be_bytes()) {
        *byte = value;
    }
    result
}

fn value(body: Vec<u8>) -> TestResult<PersistentRecordValue> {
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

fn ledger(row: ReplayLedgerRow) -> TestResult<Record> {
    Ok((row.key()?, value(row.encode()?)?))
}

impl Fixture {
    fn new(legacy: bool) -> TestResult<Self> {
        let DeliveryRecoveryRow::Owner(original) = DeliveryRecoveryRow::decode(&fixture_body(7)?)?
        else {
            return Err("owner fixture".into());
        };
        let current = DeliveryOwner::new(
            *original.scope(),
            DeliveryCursor::new(
                0,
                258,
                LastAcknowledged::At {
                    sequence: 256,
                    event_id: event_id(256),
                },
            )?,
            *original.cut(),
            original.phase(),
        )?;
        let replay = ReplayOwner::new(ReplayOwnerFields {
            scope: *current.scope(),
            generation: 0,
            baseline: LastAcknowledged::BeforeFirst,
            through: 256,
            event_id: event_id(256),
            first_retained: 0,
            retained_rows: 257,
            retained_bytes: 257 * 1024,
            trusted_unix_seconds: Some(100),
        })?;
        let mut f = Self {
            current,
            owner: if legacy {
                None
            } else {
                Some(ledger(ReplayLedgerRow::Owner(replay))?)
            },
            ranges: Vec::new(),
            rows: Vec::new(),
            backing: BackingReservationPort::new(Arc::new(MemoryBudget::new(1_048_576))),
        };
        for sequence in 0..258 {
            let ack = if legacy && sequence <= 256 {
                Acknowledgement::received_at(Some(100))
            } else {
                Acknowledgement::Unacknowledged
            };
            let row = ScopedOutbox::new(ScopedOutboxFields {
                scope: *f.current.scope(),
                generation: 0,
                sequence,
                event_id: event_id(sequence),
                event_object_id: [18; 32],
                event_bytes: 1024,
                payload_object_id: None,
                payload_bytes: 0,
                acknowledgement: ack,
                cross_profile: None,
            })?;
            f.rows.push((
                row.key()?,
                value(DeliveryRecoveryRow::Outbox(row).encode()?)?,
            ));
            if !legacy && sequence <= 256 {
                f.ranges.push(ledger(ReplayLedgerRow::Range(AckRange::new(
                    AckRangeFields {
                        scope: *f.current.scope(),
                        generation: 0,
                        first: sequence,
                        last: sequence,
                        event_id: event_id(sequence),
                        acknowledgement: Acknowledgement::received_at(Some(100)),
                    },
                )?))?);
            }
        }
        Ok(f)
    }

    fn reader(&self) -> TestResult<Reader> {
        Ok(Reader::new(self.current.clone(), Some(7), &self.backing)?)
    }

    fn page(&self, query: &Query) -> TestResult<(bool, Vec<Record>)> {
        let (records, start) = match query.kind {
            Kind::Owner => {
                return Ok((
                    false,
                    self.owner
                        .iter()
                        .map(copy_record)
                        .collect::<TestResult<Vec<_>>>()?,
                ));
            }
            Kind::Rows(start) => (&self.rows, usize::try_from(start)?),
            Kind::Ranges(start) => (&self.ranges, usize::try_from(start)?),
        };
        let selected: Vec<_> = records
            .iter()
            .skip(start)
            .take(PAGE_ROWS as usize)
            .map(copy_record)
            .collect::<TestResult<Vec<_>>>()?;
        Ok((start + selected.len() < records.len(), selected))
    }
}

fn query(reader: &mut Reader) -> TestResult<Query> {
    match reader.next()? {
        Next::Read(query) => Ok(query),
        _ => Err("expected read".into()),
    }
}

fn start(f: &Fixture) -> TestResult<Reader> {
    let mut reader = f.reader()?;
    let request = query(&mut reader)?;
    let (truncated, records) = f.page(&request)?;
    reader.admit(&request, 7, truncated, records)?;
    Ok(reader)
}

#[test]
fn independently_paged_journals_reconstruct_every_effective_ack() -> TestResult {
    for legacy in [false, true] {
        let f = Fixture::new(legacy)?;
        let mut reader = f.reader()?;
        let mut sequence = 0;
        let mut reads = 0;
        loop {
            match reader.next()? {
                Next::Read(request) => {
                    let (truncated, records) = f.page(&request)?;
                    reader.admit(&request, 7, truncated, records)?;
                    reads += 1;
                }
                Next::Row(row) => {
                    assert_eq!(row.sequence(), sequence);
                    assert_eq!(row.acknowledgement().is_acknowledged(), sequence < 257);
                    sequence += 1;
                }
                Next::Done => break,
            }
        }
        assert_eq!(sequence, 258);
        assert_eq!(reads, if legacy { 5 } else { 7 });
        let restored = reader.finish()?;
        assert_eq!(
            restored.owner.ok_or("replay owner")?.fields().retained_rows,
            257
        );
        assert_eq!(restored.head.ok_or("head")?.sequence, 0);
    }
    Ok(())
}

#[test]
fn a_commit_change_or_wrong_request_permanently_refuses_the_reader() -> TestResult {
    let f = Fixture::new(false)?;
    for drift in [false, true] {
        let mut reader = f.reader()?;
        let request = query(&mut reader)?;
        let (truncated, records) = f.page(&request)?;
        let wrong = Query::new(&f.current, Kind::Rows(0));
        assert!(
            reader
                .admit(
                    if drift { &request } else { &wrong },
                    if drift { 8 } else { 7 },
                    truncated,
                    records
                )
                .is_err()
        );
        assert!(reader.next().is_err());
        assert!(reader.finish().is_err());
    }
    Ok(())
}

#[test]
fn orphan_ranges_and_missing_ledger_coverage_are_refused() -> TestResult {
    let mut f = Fixture::new(false)?;
    f.owner = None;
    let mut reader = start(&f)?;
    let request = query(&mut reader)?;
    let (truncated, records) = f.page(&request)?;
    assert!(reader.admit(&request, 7, truncated, records).is_err());
    let f = Fixture::new(false)?;
    let mut reader = start(&f)?;
    let request = query(&mut reader)?;
    reader.admit(&request, 7, false, Vec::new())?;
    let request = query(&mut reader)?;
    let (truncated, records) = f.page(&request)?;
    reader.admit(&request, 7, truncated, records)?;
    assert!(reader.next().is_err());
    Ok(())
}

#[test]
fn oversized_empty_truncated_and_unsorted_pages_are_refused_before_use() -> TestResult {
    let f = Fixture::new(false)?;
    for case in 0..3 {
        let mut reader = start(&f)?;
        let request = query(&mut reader)?;
        let mut records = f
            .ranges
            .iter()
            .take(PAGE_ROWS as usize + 1)
            .map(copy_record)
            .collect::<TestResult<Vec<_>>>()?;
        match case {
            0 => {}
            1 => records.clear(),
            _ => {
                records.truncate(2);
                records.reverse();
            }
        }
        assert!(reader.admit(&request, 7, true, records).is_err());
        assert!(reader.next().is_err());
    }
    Ok(())
}

#[test]
fn queued_metadata_stays_charged_until_the_reader_is_dropped() -> TestResult {
    let f = Fixture::new(false)?;
    let capacity = crate::budget::MemoryCharge::allocation(u64::try_from(METADATA_BYTES)?)?.bytes();
    let backing = BackingReservationPort::new(Arc::new(MemoryBudget::new(capacity)));
    let reader = Reader::new(f.current.clone(), None, &backing)?;
    assert!(backing.reserve(1).is_err());
    drop(reader);
    assert!(backing.reserve(METADATA_BYTES).is_ok());
    Ok(())
}
