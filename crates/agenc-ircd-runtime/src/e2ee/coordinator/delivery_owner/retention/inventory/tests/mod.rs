//! Streaming validation uses original rows plus complete, scoped ACK intervals.
#![forbid(unsafe_code)]

mod scope_time;

use super::*;
use crate::test_support::TestResult;
use agenc_ircd_storage::e2ee_records::delivery_recovery::outbox::replay::{
    AckRangeFields, ReplayOwnerFields,
};
use agenc_ircd_storage::e2ee_records::delivery_recovery::{
    DeliveryCursor, DeliveryRecoveryRow, ScopedOutboxFields, fixture_body,
};

fn id(sequence: u64) -> [u8; 16] {
    let mut id = [0; 16];
    for (byte, value) in id.iter_mut().zip(sequence.to_be_bytes()) {
        *byte = value;
    }
    id
}

struct Fixture {
    current: DeliveryOwner,
    replay: ReplayOwner,
}

impl Fixture {
    fn new(first: u64, baseline: LastAcknowledged, through: u64, next: u64) -> TestResult<Self> {
        let DeliveryRecoveryRow::Owner(owner) = DeliveryRecoveryRow::decode(&fixture_body(7)?)?
        else {
            return Err("owner fixture".into());
        };
        let current = DeliveryOwner::new(
            *owner.scope(),
            DeliveryCursor::new(
                0,
                next,
                LastAcknowledged::At {
                    sequence: through,
                    event_id: id(through),
                },
            )?,
            *owner.cut(),
            owner.phase(),
        )?;
        let replay = ReplayOwner::new(ReplayOwnerFields {
            scope: *current.scope(),
            generation: 0,
            baseline,
            through,
            event_id: id(through),
            first_retained: first,
            retained_rows: through + 1 - first,
            retained_bytes: (through + 1 - first) * 1024,
            trusted_unix_seconds: Some(200),
        })?;
        Ok(Self { current, replay })
    }

    fn inventory(&self) -> TestResult<Inventory> {
        Ok(Inventory::new(self.current.clone(), self.replay)?)
    }

    fn row(&self, sequence: u64, ack: Acknowledgement) -> TestResult<ScopedOutbox> {
        Ok(ScopedOutbox::new(ScopedOutboxFields {
            scope: *self.current.scope(),
            generation: 0,
            sequence,
            event_id: id(sequence),
            event_object_id: [31; 32],
            event_bytes: 1024,
            payload_object_id: None,
            payload_bytes: 0,
            acknowledgement: ack,
            cross_profile: None,
        })?)
    }

    fn range(&self, first: u64, last: u64) -> TestResult<AckRange> {
        Ok(AckRange::new(AckRangeFields {
            scope: *self.current.scope(),
            generation: 0,
            first,
            last,
            event_id: id(last),
            acknowledgement: Acknowledgement::received_at(Some(200)),
        })?)
    }
}

#[test]
fn mixed_legacy_and_range_acknowledgements_preserve_original_times() -> TestResult {
    let f = Fixture::new(
        0,
        LastAcknowledged::At {
            sequence: 1,
            event_id: id(1),
        },
        4,
        6,
    )?;
    let mut scan = f.inventory()?;
    let original = Acknowledgement::received_at(Some(100));
    for sequence in 0..2 {
        assert_eq!(scan.needs_range(), None);
        assert_eq!(
            scan.observe(f.row(sequence, original)?)?.acknowledgement(),
            original
        );
    }
    assert_eq!(scan.needs_range(), Some(2));
    scan.admit_range(f.range(2, 3)?)?;
    for sequence in 2..4 {
        assert_eq!(
            scan.observe(f.row(sequence, Acknowledgement::Unacknowledged)?)?
                .acknowledgement(),
            Acknowledgement::received_at(Some(200))
        );
    }
    assert_eq!(scan.needs_range(), Some(4));
    scan.admit_range(f.range(4, 4)?)?;
    scan.observe(f.row(4, Acknowledgement::Unacknowledged)?)?;
    assert_eq!(scan.needs_range(), None);
    assert!(
        !scan
            .observe(f.row(5, Acknowledgement::Unacknowledged)?)?
            .acknowledgement()
            .is_acknowledged()
    );
    let head = scan.finish()?.ok_or("retained head")?;
    assert_eq!((head.sequence, head.acknowledgement), (0, original));
    Ok(())
}

#[test]
fn the_retained_floor_may_start_inside_one_ack_range() -> TestResult {
    let f = Fixture::new(3, LastAcknowledged::BeforeFirst, 4, 5)?;
    let mut scan = f.inventory()?;
    scan.admit_range(f.range(0, 4)?)?;
    for sequence in 3..5 {
        scan.observe(f.row(sequence, Acknowledgement::Unacknowledged)?)?;
    }
    assert_eq!(scan.finish()?.ok_or("head")?.sequence, 3);
    Ok(())
}

#[test]
fn missing_ranges_gaps_and_overlaps_cannot_cover_a_row() -> TestResult {
    let f = Fixture::new(0, LastAcknowledged::BeforeFirst, 4, 5)?;
    let mut missing = f.inventory()?;
    assert!(
        missing
            .observe(f.row(0, Acknowledgement::Unacknowledged)?)
            .is_err()
    );
    assert!(missing.admit_range(f.range(0, 4)?).is_err());
    assert!(missing.finish().is_err());
    for (first, last) in [(0, 2), (2, 2), (1, 5)] {
        let mut scan = f.inventory()?;
        scan.admit_range(f.range(0, 0)?)?;
        scan.observe(f.row(0, Acknowledgement::Unacknowledged)?)?;
        assert!(scan.admit_range(f.range(first, last)?).is_err());
        assert!(scan.finish().is_err());
    }
    Ok(())
}

#[test]
fn range_scope_generation_and_final_identity_are_bound_to_the_rows() -> TestResult {
    let f = Fixture::new(0, LastAcknowledged::BeforeFirst, 1, 2)?;
    let range = f.range(0, 1)?;
    let wrong_generation = AckRange::new(AckRangeFields {
        generation: 1,
        ..*range.fields()
    })?;
    assert!(f.inventory()?.admit_range(wrong_generation).is_err());
    let wrong_final = AckRange::new(AckRangeFields {
        event_id: [71; 16],
        ..*range.fields()
    })?;
    let mut scan = f.inventory()?;
    scan.admit_range(wrong_final)?;
    scan.observe(f.row(0, Acknowledgement::Unacknowledged)?)?;
    assert!(
        scan.observe(f.row(1, Acknowledgement::Unacknowledged)?)
            .is_err()
    );
    assert!(scan.finish().is_err());
    Ok(())
}

#[test]
fn mixed_ack_encodings_cannot_rewrite_legacy_or_range_history() -> TestResult {
    let legacy = Fixture::new(
        0,
        LastAcknowledged::At {
            sequence: 0,
            event_id: id(0),
        },
        0,
        1,
    )?;
    assert!(
        legacy
            .inventory()?
            .observe(legacy.row(0, Acknowledgement::Unacknowledged)?)
            .is_err()
    );
    let f = Fixture::new(0, LastAcknowledged::BeforeFirst, 0, 2)?;
    let mut scan = f.inventory()?;
    scan.admit_range(f.range(0, 0)?)?;
    assert!(
        scan.observe(f.row(0, Acknowledgement::AcknowledgedTimeUnknown)?)
            .is_err()
    );
    let mut scan = f.inventory()?;
    scan.admit_range(f.range(0, 0)?)?;
    scan.observe(f.row(0, Acknowledgement::Unacknowledged)?)?;
    assert!(
        scan.observe(f.row(1, Acknowledgement::AcknowledgedTimeUnknown)?)
            .is_err()
    );
    Ok(())
}

#[test]
fn missing_tail_surplus_rows_and_incorrect_byte_totals_refuse_completion() -> TestResult {
    let f = Fixture::new(0, LastAcknowledged::BeforeFirst, 0, 2)?;
    let mut scan = f.inventory()?;
    scan.admit_range(f.range(0, 0)?)?;
    scan.observe(f.row(0, Acknowledgement::Unacknowledged)?)?;
    assert!(scan.finish().is_err());
    let f = Fixture::new(0, LastAcknowledged::BeforeFirst, 0, 1)?;
    let mut scan = f.inventory()?;
    scan.admit_range(f.range(0, 0)?)?;
    scan.observe(f.row(0, Acknowledgement::Unacknowledged)?)?;
    assert!(
        scan.observe(f.row(1, Acknowledgement::Unacknowledged)?)
            .is_err()
    );
    for expected in [1023, 1025] {
        let replay = ReplayOwner::new(ReplayOwnerFields {
            retained_bytes: expected,
            ..*f.replay.fields()
        })?;
        let mut scan = Inventory::new(f.current.clone(), replay)?;
        scan.admit_range(f.range(0, 0)?)?;
        let observed = scan.observe(f.row(0, Acknowledgement::Unacknowledged)?);
        assert!(observed.is_err() || scan.finish().is_err());
    }
    Ok(())
}

#[test]
fn an_empty_replay_suffix_still_requires_the_entire_unacknowledged_tail() -> TestResult {
    let f = Fixture::new(1, LastAcknowledged::BeforeFirst, 0, 2)?;
    assert!(f.inventory()?.finish().is_err());
    let mut scan = f.inventory()?;
    assert_eq!(scan.needs_range(), None);
    scan.observe(f.row(1, Acknowledgement::Unacknowledged)?)?;
    assert!(scan.finish()?.is_none());
    Ok(())
}
