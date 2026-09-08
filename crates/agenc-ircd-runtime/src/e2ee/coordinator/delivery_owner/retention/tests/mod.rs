//! Metadata-only decisions exercise the published bounds without allocating bodies.
#![forbid(unsafe_code)]

use super::*;
use agenc_ircd_storage::e2ee_records::delivery_recovery::{
    DeliveryCursor, DeliveryRecoveryRow, fixture_body,
};

type TestResult<T = ()> = crate::test_support::TestResult<T>;

#[test]
fn a_refused_legacy_row_poisons_the_inventory() -> TestResult {
    let mut inventory = LegacyInventory::new(current(Some(1), 2)?);
    assert!(
        inventory
            .observe(row(0, Acknowledgement::Unacknowledged)?)
            .is_err()
    );
    assert!(
        inventory
            .observe(row(0, Acknowledgement::AcknowledgedTimeUnknown)?)
            .is_err()
    );
    assert!(inventory.finish().is_err());
    Ok(())
}

fn id(sequence: u64) -> [u8; 16] {
    let mut result = [0; 16];
    for (target, source) in result.iter_mut().zip(sequence.to_be_bytes()) {
        *target = source;
    }
    result
}

fn current(through: Option<u64>, next: u64) -> TestResult<DeliveryOwner> {
    let DeliveryRecoveryRow::Owner(owner) = DeliveryRecoveryRow::decode(&fixture_body(7)?)? else {
        return Err("delivery fixture is not an owner".into());
    };
    Ok(DeliveryOwner::new(
        *owner.scope(),
        DeliveryCursor::new(
            0,
            next,
            through.map_or(LastAcknowledged::BeforeFirst, |sequence| {
                LastAcknowledged::At {
                    sequence,
                    event_id: id(sequence),
                }
            }),
        )?,
        *owner.cut(),
        owner.phase(),
    )?)
}

fn row(sequence: u64, acknowledgement: Acknowledgement) -> TestResult<Row> {
    Ok(Row::new(sequence, id(sequence), 1024, 0, acknowledgement)?)
}

fn baseline(current: &DeliveryOwner, first: u64, bytes: u64) -> TestResult<ReplayOwner> {
    let LastAcknowledged::At { sequence, event_id } = current.cursor().last_ack() else {
        return Err("baseline needs an ACK".into());
    };
    Ok(ReplayOwner::new(ReplayOwnerFields {
        scope: *current.scope(),
        generation: current.cursor().generation(),
        baseline: current.cursor().last_ack(),
        through: sequence,
        event_id,
        first_retained: first,
        retained_rows: sequence + 1 - first,
        retained_bytes: bytes,
        trusted_unix_seconds: None,
    })?)
}

#[test]
fn one_more_ack_preserves_4097_rows_under_the_published_limits() -> TestResult {
    let current = current(Some(4095), 4097)?;
    let ack = Acknowledgement::received_at(Some(100));
    let mut inventory = LegacyInventory::new(current.clone());
    for sequence in 0..4096 {
        inventory.observe(row(sequence, ack)?)?;
    }
    let previous = inventory.finish()?.ok_or("legacy baseline")?;
    let draft = Draft::append(
        &current,
        Some(previous),
        4096,
        id(4096),
        [row(4096, Acknowledgement::Unacknowledged)?],
        Some(200),
    )?;
    let proposal = draft.finish(Some(row(0, ack)?))?;
    assert_eq!(proposal.owner.fields().retained_rows, 4097);
    assert_eq!(proposal.owner.fields().retained_bytes, 4097 * 1024);
    assert_eq!(proposal.owner.fields().first_retained, 0);
    assert_eq!(
        proposal.owner.fields().baseline,
        current.cursor().last_ack()
    );
    assert_eq!(proposal.head, Some(row(0, ack)?));
    let range = proposal.range.ok_or("new ACK range")?;
    assert_eq!((range.fields().first, range.fields().last), (4096, 4096));
    Ok(())
}

#[test]
fn the_first_ack_keeps_before_first_distinct_from_zero_event_identity() -> TestResult {
    let current = current(None, 1)?;
    assert!(LegacyInventory::new(current.clone()).finish()?.is_none());
    let proposal = Draft::append(
        &current,
        None,
        0,
        id(0),
        [row(0, Acknowledgement::Unacknowledged)?],
        Some(0),
    )?
    .finish(Some(row(0, Acknowledgement::received_at(Some(0)))?))?;
    assert_eq!(
        proposal.owner.fields().baseline,
        LastAcknowledged::BeforeFirst
    );
    assert_eq!(proposal.owner.fields().event_id, [0; 16]);
    assert_eq!(proposal.owner.fields().retained_rows, 1);
    Ok(())
}

#[test]
fn the_million_row_limit_trims_only_the_oldest_acknowledged_copy() -> TestResult {
    let current = current(Some(MAX_ROWS - 1), MAX_ROWS + 1)?;
    let previous = baseline(&current, 0, MAX_ROWS * 1024)?;
    let mut draft = Draft::append(
        &current,
        Some(previous),
        MAX_ROWS,
        id(MAX_ROWS),
        [row(MAX_ROWS, Acknowledgement::Unacknowledged)?],
        None,
    )?;
    assert!(draft.consider(row(0, Acknowledgement::AcknowledgedTimeUnknown)?)?);
    assert!(!draft.consider(row(1, Acknowledgement::AcknowledgedTimeUnknown)?)?);
    let proposal = draft.finish(Some(row(1, Acknowledgement::AcknowledgedTimeUnknown)?))?;
    assert_eq!(
        (
            proposal.owner.fields().first_retained,
            proposal.owner.fields().retained_rows
        ),
        (1, MAX_ROWS)
    );
    assert_eq!(proposal.owner.fields().through, MAX_ROWS);
    Ok(())
}

#[test]
fn payload_bytes_trigger_retention_even_below_the_row_ceiling() -> TestResult {
    let current = current(Some(255), 257)?;
    let previous = baseline(&current, 0, MAX_BYTES)?;
    let mut draft = Draft::append(
        &current,
        Some(previous),
        256,
        id(256),
        [row(256, Acknowledgement::Unacknowledged)?],
        None,
    )?;
    let large = |sequence| {
        Row::new(
            sequence,
            id(sequence),
            1024,
            4_194_304 - 1024,
            Acknowledgement::AcknowledgedTimeUnknown,
        )
    };
    assert!(draft.consider(large(0)?)?);
    let proposal = draft.finish(Some(large(1)?))?;
    assert_eq!(
        proposal.owner.fields().retained_bytes,
        MAX_BYTES - 4_194_304 + 1024
    );
    assert_eq!(proposal.owner.fields().retained_rows, 256);
    Ok(())
}

#[test]
fn age_maintenance_preserves_the_exact_last_ack_after_emptying_the_suffix() -> TestResult {
    let current = current(Some(0), 1)?;
    let previous = baseline(&current, 0, 1024)?;
    let head = row(0, Acknowledgement::received_at(Some(100)))?;
    let before = Draft::maintenance(&current, previous, Some(86_499))?;
    assert!(before.finish(Some(head))?.range.is_none());
    let mut at = Draft::maintenance(&current, previous, Some(86_500))?;
    assert!(at.consider(head)?);
    let proposal = at.finish(None)?;
    assert_eq!(proposal.owner.fields().retained_rows, 0);
    assert_eq!(proposal.owner.fields().retained_bytes, 0);
    assert_eq!(proposal.owner.fields().first_retained, 1);
    assert_eq!(proposal.owner.fields().event_id, id(0));
    assert_eq!(proposal.owner.fields().through, 0);
    assert!(proposal.range.is_none());
    Ok(())
}

#[test]
fn unknown_or_overflowed_time_cannot_expire_a_retained_head() -> TestResult {
    let current = current(Some(0), 1)?;
    let previous = baseline(&current, 0, 1024)?;
    for (ack, now) in [
        (Acknowledgement::AcknowledgedTimeUnknown, Some(100_000)),
        (Acknowledgement::received_at(Some(0)), None),
        (Acknowledgement::received_at(Some(0)), Some(u64::MAX)),
        (Acknowledgement::received_at(Some(200)), Some(100)),
    ] {
        let mut draft = Draft::maintenance(&current, previous, now)?;
        let head = row(0, ack)?;
        assert!(!draft.consider(head)?);
        assert_eq!(draft.finish(Some(head))?.owner.fields().retained_rows, 1);
    }
    Ok(())
}

#[test]
fn missing_or_unacknowledged_heads_cannot_authorize_retention_completion() -> TestResult {
    let current = current(Some(0), 1)?;
    let previous = baseline(&current, 0, 1024)?;
    assert!(
        Draft::maintenance(&current, previous, None)?
            .finish(None)
            .is_err()
    );
    for head in [
        row(0, Acknowledgement::Unacknowledged)?,
        row(1, Acknowledgement::AcknowledgedTimeUnknown)?,
    ] {
        assert!(
            Draft::maintenance(&current, previous, None)?
                .finish(Some(head))
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn incomplete_or_conflicting_new_ack_prefixes_are_refused() -> TestResult {
    let current = current(None, 3)?;
    for rows in [
        vec![],
        vec![row(1, Acknowledgement::Unacknowledged)?],
        vec![
            row(0, Acknowledgement::Unacknowledged)?,
            row(2, Acknowledgement::Unacknowledged)?,
        ],
        vec![row(0, Acknowledgement::AcknowledgedTimeUnknown)?],
    ] {
        assert!(Draft::append(&current, None, 2, id(2), rows, None).is_err());
    }
    let wrong = Row::new(0, [91; 16], 1024, 0, Acknowledgement::Unacknowledged)?;
    assert!(Draft::append(&current, None, 0, id(0), [wrong], None).is_err());
    Ok(())
}

#[test]
fn legacy_inventory_cannot_guess_a_missing_tail_or_accept_a_gap() -> TestResult {
    let current = current(Some(2), 3)?;
    let mut missing = LegacyInventory::new(current.clone());
    missing.observe(row(0, Acknowledgement::AcknowledgedTimeUnknown)?)?;
    assert!(missing.finish().is_err());
    let mut gap = LegacyInventory::new(current.clone());
    gap.observe(row(0, Acknowledgement::AcknowledgedTimeUnknown)?)?;
    assert!(
        gap.observe(row(2, Acknowledgement::AcknowledgedTimeUnknown)?)
            .is_err()
    );
    let empty = LegacyInventory::new(current)
        .finish()?
        .ok_or("empty legacy suffix")?;
    assert_eq!(
        (empty.fields().first_retained, empty.fields().retained_rows),
        (3, 0)
    );
    Ok(())
}

#[test]
fn a_replay_owner_must_match_the_current_cursor_and_full_scope() -> TestResult {
    let current = current(Some(0), 2)?;
    let previous = baseline(&current, 0, 1024)?;
    assert!(
        Draft::append(
            &current,
            None,
            1,
            id(1),
            [row(1, Acknowledgement::Unacknowledged)?],
            None
        )
        .is_err()
    );
    let changed = ReplayOwner::new(ReplayOwnerFields {
        generation: 1,
        ..*previous.fields()
    })?;
    assert!(Draft::maintenance(&current, changed, None).is_err());
    let changed = ReplayOwner::new(ReplayOwnerFields {
        baseline: LastAcknowledged::At {
            sequence: 0,
            event_id: [8; 16],
        },
        event_id: [8; 16],
        ..*previous.fields()
    })?;
    assert!(Draft::maintenance(&current, changed, None).is_err());
    Ok(())
}
