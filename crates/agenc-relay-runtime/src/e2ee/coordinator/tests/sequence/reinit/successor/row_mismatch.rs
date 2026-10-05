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

#[test]
fn a_reload_refuses_a_successor_whose_stored_binding_is_not_the_installed_one() -> TestResult {
    // The successor's route row names the old conversation's binding,
    // whose package is retained: the successor would restore under it, but
    // it is not the binding the activated target installs.
    let mut fixture = Fixture::prepare()?;
    fixture.activate()?;
    let old_binding = fixture
        .harness
        .coordinator
        .state
        .conversations
        .get(&fixture.old)
        .ok_or("old state")?
        .binding;
    let key = RouteRow::key(&fixture.new)?;
    rewrite(&mut fixture.harness, &key, |body| {
        let mut row = RouteRow::decode(&body)?;
        row.binding_id = old_binding;
        Ok(row.encode()?)
    })?;
    assert!(fixture.harness.reloaded().is_err());
    Ok(())
}

#[test]
fn a_reload_refuses_a_successor_row_that_leaves_its_activation_anchor() -> TestResult {
    type RowEdit = fn(&mut RouteRow) -> TestResult;
    let edits: [(&str, RowEdit); 4] = [
        ("another accepted state", |row| {
            row.accepted_state_id[0] ^= 1;
            Ok(())
        }),
        ("another sequencer head", |row| {
            row.sequencer_head_id[0] ^= 1;
            Ok(())
        }),
        ("no epoch", |row| finalized_epoch(row, 0)),
        ("a later epoch", |row| finalized_epoch(row, 2)),
    ];
    for (name, edit) in edits {
        let mut fixture = Fixture::prepare()?;
        fixture.activate()?;
        let key = RouteRow::key(&fixture.new)?;
        rewrite(&mut fixture.harness, &key, |body| {
            let mut row = RouteRow::decode(&body)?;
            edit(&mut row)?;
            Ok(row.encode()?)
        })?;
        assert!(fixture.harness.reloaded().is_err(), "{name}");
    }
    Ok(())
}

/// Rewrites the finalized epoch the route state object of `row` carries.
fn finalized_epoch(row: &mut RouteRow, epoch: u64) -> TestResult {
    use agenc_relay_e2ee::objects::federation::ArcFederationRouteState;
    use agenc_relay_e2ee::tls::{TlsDecode, TlsEncode};
    let mut budget = agenc_relay_e2ee::tls::DecodeBudget::new(1 << 16, 1 << 10);
    let object = agenc_relay_e2ee::object::ArcWireObject::decode_kind(
        &row.route_state,
        Some(ArcWireObjectKind::FederationState),
        &mut budget,
    )?;
    let mut state = ArcFederationRouteState::decode_exact(object.body(), &mut budget)?;
    state.finalized_epoch = epoch;
    row.route_state = agenc_relay_e2ee::object::ArcWireObject::new(
        ArcWireObjectKind::FederationState,
        state.encode()?,
    )?
    .encode()?;
    Ok(())
}

#[test]
fn a_reload_refuses_a_successor_under_another_binding_of_its_lineage() -> TestResult {
    // Another binding of the same lineage, which the activation did not
    // install, is retained and named by the successor's row: the successor
    // would restore under it on the same route, lock and generation.
    let mut fixture = Fixture::prepare()?;
    fixture.activate()?;
    let mut package = fixture.successor.package()?;
    package.binding.tbs.required_operational_policy_id = [9; 32];
    let binding_id = semantic_id_of(SemanticHashDomain::BindingId, &package.binding.tbs)?;
    let bytes = wire(ArcWireObjectKind::ConversationBinding, &package)?;
    fixture.harness.writes.push(
        crate::e2ee::coordinator::CompanionCoordinator::object_write(&bytes)
            .map_err(|code| format!("object write: {code:?}"))?,
    );
    let key = RouteRow::key(&fixture.new)?;
    rewrite(&mut fixture.harness, &key, |body| {
        let mut row = RouteRow::decode(&body)?;
        row.binding_id = binding_id;
        Ok(row.encode()?)
    })?;
    assert!(fixture.harness.reloaded().is_err());
    Ok(())
}

#[test]
fn a_reload_refuses_a_successor_with_a_later_head_and_no_epoch() -> TestResult {
    // The successor's own candidate is its recorded head: its route state
    // must still name an epoch after the activation's.
    let mut fixture = Fixture::prepare()?;
    fixture.activate()?;
    let commit = fixture.successor_commit(70)?;
    ok(fixture
        .harness
        .run(Op::SubmitCandidate, &fixture.new, Some(&commit))?)?;
    let key = RouteRow::key(&fixture.new)?;
    rewrite(&mut fixture.harness, &key, |body| {
        let mut row = RouteRow::decode(&body)?;
        finalized_epoch(&mut row, 0)?;
        Ok(row.encode()?)
    })?;
    assert!(fixture.harness.reloaded().is_err());
    Ok(())
}
