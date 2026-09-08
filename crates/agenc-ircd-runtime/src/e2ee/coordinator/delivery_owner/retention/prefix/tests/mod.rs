//! These metadata tests model a prior complete inventory; they do not validate object bodies.
#![forbid(unsafe_code)]

use super::*;
use crate::budget::{BackingReservationPort, MemoryBudget};
use crate::test_support::TestResult;
use agenc_ircd_storage::TableId;
use agenc_ircd_storage::e2ee_records::DELIVERY_RECOVERY_ROW_KIND;
use agenc_ircd_storage::e2ee_records::delivery_recovery::outbox::replay::{
    AckRange, AckRangeFields, ReplayLedgerRow, ReplayOwner, ReplayOwnerFields,
};
use agenc_ircd_storage::e2ee_records::delivery_recovery::{
    Acknowledgement, DeliveryCursor, DeliveryRecoveryRow, LastAcknowledged, ScopedOutboxFields,
    fixture_body,
};
use std::sync::Arc;

type Record = (StoredKey, PersistentRecordValue);

struct Fixture {
    current: DeliveryOwner,
    prior: State,
    legacy: bool,
    count: u64,
    backing: BackingReservationPort,
}

fn id(sequence: u64) -> [u8; 16] {
    let mut result = [0; 16];
    for (byte, value) in result.iter_mut().zip(sequence.to_be_bytes()) {
        *byte = value;
    }
    result
}

fn value(bytes: Vec<u8>) -> TestResult<PersistentRecordValue> {
    Ok(PersistentRecordValue::new(
        TableId::E2eeState,
        DELIVERY_RECOVERY_ROW_KIND,
        1,
        0,
        None,
        Vec::new(),
        bytes,
    )?)
}

fn ledger(row: ReplayLedgerRow) -> TestResult<Record> {
    Ok((row.key()?, value(row.encode()?)?))
}

impl Fixture {
    fn new(count: u64, legacy: bool) -> TestResult<Self> {
        let DeliveryRecoveryRow::Owner(template) = DeliveryRecoveryRow::decode(&fixture_body(7)?)?
        else {
            return Err("owner fixture".into());
        };
        let through = count.checked_sub(1).ok_or("nonempty prior inventory")?;
        let last = LastAcknowledged::At {
            sequence: through,
            event_id: id(through),
        };
        let current = DeliveryOwner::new(
            *template.scope(),
            DeliveryCursor::new(0, count + 1, last)?,
            *template.cut(),
            template.phase(),
        )?;
        let owner = ReplayOwner::new(ReplayOwnerFields {
            scope: *current.scope(),
            generation: 0,
            baseline: if legacy {
                last
            } else {
                LastAcknowledged::BeforeFirst
            },
            through,
            event_id: id(through),
            first_retained: 0,
            retained_rows: count,
            retained_bytes: count * 1024,
            trusted_unix_seconds: Some(100),
        })?;
        Ok(Self {
            current,
            legacy,
            count,
            prior: State {
                owner,
                head: Some(Row::new(
                    0,
                    id(0),
                    1024,
                    0,
                    Acknowledgement::received_at(Some(100)),
                )?),
                persisted: !legacy,
            },
            backing: BackingReservationPort::new(Arc::new(MemoryBudget::new(1_048_576))),
        })
    }

    fn prefix(&self, now: u64, protected: Option<u64>) -> TestResult<Prefix> {
        let draft = Draft::append_checked(
            &self.current,
            Some(self.prior.owner),
            self.count,
            id(self.count),
            [Row::new(
                self.count,
                id(self.count),
                1024,
                0,
                Acknowledgement::Unacknowledged,
            )],
            Some(now),
        )?;
        Ok(Prefix::new(
            self.current.clone(),
            self.prior,
            draft,
            protected,
            Some(7),
            &self.backing,
        )?)
    }

    fn rows(&self, count: u64) -> TestResult<Vec<Record>> {
        (0..count)
            .map(|sequence| {
                let ack = if self.legacy && sequence < self.count {
                    Acknowledgement::received_at(Some(100))
                } else {
                    Acknowledgement::Unacknowledged
                };
                let row = ScopedOutbox::new(ScopedOutboxFields {
                    scope: *self.current.scope(),
                    generation: 0,
                    sequence,
                    event_id: id(sequence),
                    event_object_id: [18; 32],
                    event_bytes: 1024,
                    payload_object_id: None,
                    payload_bytes: 0,
                    acknowledgement: ack,
                    cross_profile: None,
                })?;
                Ok((
                    row.key()?,
                    value(DeliveryRecoveryRow::Outbox(row).encode()?)?,
                ))
            })
            .collect()
    }

    fn ranges(&self, count: u64) -> TestResult<Vec<Record>> {
        if self.legacy {
            return Ok(Vec::new());
        }
        (0..count)
            .map(|sequence| {
                ledger(ReplayLedgerRow::Range(AckRange::new(AckRangeFields {
                    scope: *self.current.scope(),
                    generation: 0,
                    first: sequence,
                    last: sequence,
                    event_id: id(sequence),
                    acknowledgement: Acknowledgement::received_at(Some(100)),
                })?))
            })
            .collect()
    }

    fn owner(&self) -> TestResult<Vec<Record>> {
        if self.legacy {
            return Ok(Vec::new());
        }
        Ok(vec![ledger(ReplayLedgerRow::Owner(self.prior.owner))?])
    }
}

fn query(prefix: &mut Prefix) -> TestResult<recovery::Query> {
    match prefix.next()? {
        Next::Read(query) => Ok(query),
        Next::Done => Err("expected read".into()),
    }
}

fn admit(prefix: &mut Prefix, truncated: bool, records: Vec<Record>) -> TestResult {
    let request = query(prefix)?;
    prefix.admit(&request, 7, truncated, records)?;
    Ok(())
}

#[test]
fn a_million_row_bound_needs_only_the_removed_head_and_its_successor() -> TestResult {
    let fixture = Fixture::new(1_000_000, false)?;
    let mut prefix = fixture.prefix(200, None)?;
    admit(&mut prefix, false, fixture.owner()?)?;
    // Both pages explicitly have unread tails. Finishing must not request them.
    admit(&mut prefix, true, fixture.ranges(2)?)?;
    admit(&mut prefix, true, fixture.rows(2)?)?;
    assert!(matches!(prefix.next()?, Next::Done));
    let proposal = prefix.finish()?;
    assert_eq!(proposal.owner.fields().retained_rows, 1_000_000);
    assert_eq!(proposal.owner.fields().retained_bytes, 1_000_000 * 1024);
    assert_eq!(proposal.owner.fields().first_retained, 1);
    assert_eq!(proposal.head.ok_or("retained head")?.sequence, 1);
    Ok(())
}

#[test]
fn age_trims_old_rows_but_keeps_the_new_ack_for_legacy_and_journal_sources() -> TestResult {
    for legacy in [false, true] {
        let fixture = Fixture::new(3, legacy)?;
        let mut prefix = fixture.prefix(86_500, None)?;
        admit(&mut prefix, false, fixture.owner()?)?;
        admit(&mut prefix, false, fixture.ranges(3)?)?;
        admit(&mut prefix, false, fixture.rows(4)?)?;
        assert!(matches!(prefix.next()?, Next::Done));
        let proposal = prefix.finish()?;
        assert_eq!(proposal.owner.fields().retained_rows, 1);
        assert_eq!(proposal.owner.fields().first_retained, 3);
        assert_eq!(
            proposal.owner.fields().baseline,
            fixture.prior.owner.fields().baseline
        );
        assert_eq!(
            proposal.head.ok_or("new ACK head")?.acknowledgement,
            Acknowledgement::received_at(Some(86_500))
        );
    }
    Ok(())
}

#[test]
fn a_changed_or_missing_owner_and_an_unexpected_journal_refuse_the_scan() -> TestResult {
    for case in 0..3 {
        let fixture = Fixture::new(3, case == 2)?;
        let mut prefix = fixture.prefix(200, None)?;
        let records = if case == 0 {
            Vec::new()
        } else {
            let mut fields = *fixture.prior.owner.fields();
            if case == 1 {
                fields.retained_bytes += 1;
            }
            vec![ledger(ReplayLedgerRow::Owner(ReplayOwner::new(fields)?))?]
        };
        let request = query(&mut prefix)?;
        assert!(prefix.admit(&request, 7, false, records).is_err());
        assert!(prefix.next().is_err());
        assert!(prefix.finish().is_err());
    }
    Ok(())
}

#[test]
fn a_changed_commit_or_head_cannot_authorize_a_retention_cutoff() -> TestResult {
    for changed_commit in [false, true] {
        let fixture = Fixture::new(3, false)?;
        let mut prefix = fixture.prefix(86_500, None)?;
        admit(&mut prefix, false, fixture.owner()?)?;
        let request = query(&mut prefix)?;
        if changed_commit {
            assert!(
                prefix
                    .admit(&request, 8, false, fixture.ranges(3)?)
                    .is_err()
            );
        } else {
            prefix.prior.head = Some(Row::new(
                0,
                id(0),
                1025,
                0,
                Acknowledgement::received_at(Some(100)),
            )?);
            prefix.admit(&request, 7, false, fixture.ranges(3)?)?;
            admit(&mut prefix, false, fixture.rows(4)?)?;
        }
        assert!(prefix.next().is_err());
        assert!(prefix.finish().is_err());
    }
    Ok(())
}

#[test]
fn retention_cannot_remove_a_protected_barrier_prefix() -> TestResult {
    let fixture = Fixture::new(3, false)?;
    let mut prefix = fixture.prefix(86_500, Some(1))?;
    admit(&mut prefix, false, fixture.owner()?)?;
    admit(&mut prefix, false, fixture.ranges(3)?)?;
    admit(&mut prefix, false, fixture.rows(4)?)?;
    assert!(matches!(prefix.next(), Err(CompanionFault::Ceiling)));
    assert!(prefix.finish().is_err());
    Ok(())
}
