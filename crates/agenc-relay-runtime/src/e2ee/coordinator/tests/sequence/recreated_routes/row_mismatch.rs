//! A restart takes an ordinary route's semantics from its retained binding,
//! never from its route row (companion 9.4): a row that names another
//! semantic lock than its binding's semantic route, or another close than
//! the one that route follows, restores nothing, so startup refuses the
//! store, at incarnation zero and at a recreated route's later incarnation
//! alike.

#![forbid(unsafe_code)]

use super::*;
use crate::state_core::durable::AccountServiceDurableWrite as Write;
use agenc_relay_storage::e2ee_records::RouteRow;
use agenc_relay_storage::{PersistentRecordValue, TableId};

/// Rewrites every stored copy of the route row of `conversation` with
/// `edit`, keeping its record envelope.
fn rewrite(harness: &mut Harness, conversation: [u8; 32], edit: fn(&mut RouteRow)) -> TestResult {
    let key = RouteRow::key(&conversation)?;
    let mut rewritten = 0_usize;
    for write in &mut harness.writes {
        if let Write::Put {
            table: TableId::E2eeState,
            key: stored,
            plaintext,
        } = write
            && *stored == key
        {
            let value = PersistentRecordValue::decode(TableId::E2eeState, plaintext)?;
            let mut row = RouteRow::decode(value.body())?;
            edit(&mut row);
            let replacement = PersistentRecordValue::new(
                TableId::E2eeState,
                value.record_kind(),
                value.revision(),
                value.generation(),
                value.expires_at(),
                value.references().to_vec(),
                row.encode()?,
            )?
            .encode()?;
            *plaintext = zeroize::Zeroizing::new(replacement);
            rewritten = rewritten.saturating_add(1);
        }
    }
    if rewritten == 0 {
        return Err("no stored route row".into());
    }
    Ok(())
}

/// The harness channel closed, and its route's incarnation one bound on a
/// fresh instance naming that close: the closed conversation and the next.
fn recreated_channel() -> TestResult<(Harness, [u8; 32], [u8; 32])> {
    let (mut harness, first, close_id) = closed_channel()?;
    let reservation = ok_reservation(reserve_channel(&mut harness, SECOND_INSTANCE)?)?;
    let next = next_channel(&harness, 1, close_id)?;
    bind_and_publish(&mut harness, reservation, &next)?;
    Ok((harness, first, next.conversation))
}

#[test]
fn a_route_row_naming_another_lock_or_close_than_its_binding_refuses_startup() -> TestResult {
    let (harness, first, next) = recreated_channel()?;
    let restarted = harness.reloaded()?;
    assert_eq!(route_of(&restarted, next)?.incarnation, 1);
    assert_eq!(route_of(&restarted, first)?.incarnation, 0);
    type RowEdit = fn(&mut RouteRow);
    let edits: [(&str, bool, RowEdit); 5] = [
        ("incarnation one under another lock", true, |row| {
            row.lock_id[0] ^= 1;
        }),
        ("incarnation one naming another close", true, |row| {
            row.predecessor_close_id = Some([7; 32]);
        }),
        ("incarnation one naming no close", true, |row| {
            row.predecessor_close_id = None;
        }),
        ("incarnation zero under another lock", false, |row| {
            row.lock_id[0] ^= 1;
        }),
        ("incarnation zero naming a close", false, |row| {
            row.predecessor_close_id = Some([7; 32]);
        }),
    ];
    for (name, later, edit) in edits {
        let (mut harness, first, next) = recreated_channel()?;
        rewrite(&mut harness, if later { next } else { first }, edit)?;
        assert!(harness.reloaded().is_err(), "{name}");
    }
    Ok(())
}
