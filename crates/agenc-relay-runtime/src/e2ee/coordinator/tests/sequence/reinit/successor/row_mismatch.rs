//! A reload cross-checks every retained reinit record against the route row
//! that recorded it: a changed accepted state, head, sequence or predecessor
//! cannot restore the conversation.

#![forbid(unsafe_code)]

use super::*;
use crate::state_core::durable::AccountServiceDurableWrite as Write;
use agenc_relay_storage::e2ee_records::{RouteRow, SequencerRow};
use agenc_relay_storage::{PersistentRecordValue, StoredKey, TableId};

/// Rewrites the row stored under `key`, keeping its record envelope intact.
fn rewrite(
    harness: &mut Harness,
    key: &StoredKey,
    edit: impl Fn(Vec<u8>) -> TestResult<Vec<u8>>,
) -> TestResult {
    let current = harness
        .writes
        .iter()
        .rev()
        .find_map(|write| match write {
            Write::Put {
                table: TableId::E2eeState,
                key: stored,
                plaintext,
            } if stored == key => Some(plaintext.to_vec()),
            _ => None,
        })
        .ok_or("stored row")?;
    let value = PersistentRecordValue::decode(TableId::E2eeState, &current)?;
    let replacement = PersistentRecordValue::new(
        TableId::E2eeState,
        value.record_kind(),
        value.revision(),
        value.generation(),
        value.expires_at(),
        value.references().to_vec(),
        edit(value.body().to_vec())?,
    )?
    .encode()?;
    for write in &mut harness.writes {
        if let Write::Put {
            table: TableId::E2eeState,
            key: stored,
            plaintext,
        } = write
            && stored == key
        {
            *plaintext = zeroize::Zeroizing::new(replacement.clone());
        }
    }
    Ok(())
}

/// The route sequence of the last retained record of the old conversation.
fn last_record_sequence(fixture: &Fixture) -> TestResult<u64> {
    fixture
        .harness
        .coordinator
        .state
        .conversations
        .get(&fixture.old)
        .and_then(|state| state.records.keys().copied().next_back())
        .ok_or_else(|| "a retained reinit record".into())
}

#[test]
fn a_reload_refuses_a_route_row_that_no_longer_matches_its_activation_record() -> TestResult {
    type RowEdit = fn(&mut RouteRow);
    let edits: [(&str, RowEdit); 3] = [
        ("another accepted state", |row| {
            row.accepted_state_id[0] ^= 1;
        }),
        ("another sequencer head", |row| {
            row.sequencer_head_id[0] ^= 1;
        }),
        ("another route sequence", |row| {
            row.route_sequence = row.route_sequence.saturating_add(1);
        }),
    ];
    for (name, edit) in edits {
        let mut fixture = Fixture::prepare()?;
        fixture.activate()?;
        let package = fixture.package.clone();
        ok(fixture.bind(&package, fixture.context)?)?;
        let key = RouteRow::key(&fixture.old)?;
        rewrite(&mut fixture.harness, &key, |body| {
            let mut row = RouteRow::decode(&body)?;
            edit(&mut row);
            Ok(row.encode()?)
        })?;
        assert!(fixture.harness.reloaded().is_err(), "{name}");
    }
    Ok(())
}

#[test]
fn a_reload_refuses_an_activation_record_row_under_another_predecessor() -> TestResult {
    let mut fixture = Fixture::prepare()?;
    fixture.activate()?;
    let package = fixture.package.clone();
    ok(fixture.bind(&package, fixture.context)?)?;
    let sequence = last_record_sequence(&fixture)?;
    let key = SequencerRow::record_key(&fixture.old, sequence)?;
    rewrite(&mut fixture.harness, &key, |body| {
        let mut row = SequencerRow::decode(&body)?;
        if let SequencerRow::Record {
            predecessor_record_id,
            ..
        } = &mut row
        {
            predecessor_record_id[0] ^= 1;
        } else {
            return Err("a sequencer record row".into());
        }
        Ok(row.encode()?)
    })?;
    assert!(fixture.harness.reloaded().is_err());
    Ok(())
}
