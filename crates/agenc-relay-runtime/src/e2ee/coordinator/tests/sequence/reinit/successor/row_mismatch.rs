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

/// Aborts the staged attempt of `fixture` with its single device's vote.
fn abort(fixture: &mut Fixture) -> TestResult {
    let old_state = *fixture
        .harness
        .coordinator
        .state
        .logs
        .get(&fixture.old)
        .ok_or("old log")?
        .accepted_state_id();
    let receipt = staged_receipt(&fixture.harness, fixture.old)?;
    let mut budget = DecodeBudget::new(1 << 20, 1 << 16);
    let attempt_object = fixture
        .harness
        .coordinator
        .state
        .objects
        .get(&receipt.tbs.attempt_object_id)
        .ok_or("attempt object")?
        .clone();
    let object = ArcWireObject::decode_kind(
        &attempt_object,
        Some(ArcWireObjectKind::ReinitAttempt),
        &mut budget,
    )?;
    let attempt = ArcReInitAttempt::decode_exact(object.body(), &mut budget)?;
    let core = ArcReInitAbortCoreTbs {
        profile_version: 1,
        network_id: NETWORK,
        old_conversation_id: fixture.old,
        old_reinit_state_id: old_state,
        attempt_sequence: 0,
        slot_predecessor_record_id: receipt.tbs.predecessor_record_id,
        reinit_attempt_id: receipt.tbs.reinit_attempt_id,
        reason_code: 1,
        evidence_digest: [0; 32],
    };
    let abort_id = semantic_id_of(SemanticHashDomain::ReinitAbortId, &core)?;
    let vote = reinit_vote(
        &fixture.harness,
        DEVICE,
        &receipt,
        old_state,
        receipt.tbs.reinit_attempt_id,
        Terminal::abort(abort_id, 1)?,
    )?;
    let request = ArcReInitAbortRequest {
        core,
        receipt,
        attempt,
        votes: TlsVec::new(vec![vote])?,
    };
    let bytes = wire(ArcWireObjectKind::ReinitAbortRequest, &request)?;
    let outcome = ok(fixture
        .harness
        .run(Op::SubmitReinitAbort, &fixture.old, Some(&bytes))?)?;
    assert!(matches!(outcome.result, ResultBody::ReinitAborted(..)));
    Ok(())
}

#[test]
fn a_reload_refuses_a_route_row_that_no_longer_matches_its_abort_record() -> TestResult {
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
    let mut unedited = Fixture::prepare()?;
    abort(&mut unedited)?;
    let restored = unedited.harness.reloaded()?;
    assert!(matches!(
        restored
            .coordinator
            .state
            .logs
            .get(&unedited.old)
            .map(SequencerLog::phase),
        Some(Phase::Reinit { .. })
    ));
    for (name, edit) in edits {
        let mut fixture = Fixture::prepare()?;
        abort(&mut fixture)?;
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
fn a_reload_refuses_a_route_row_rolled_back_before_its_reinit_finalization() -> TestResult {
    // A route row whose head is not its last record restores nothing: here
    // it names the bootstrap activation, the record before the ReInit Commit.
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    harness.activate_bootstrap(conversation)?;
    let earlier = harness
        .coordinator
        .state
        .logs
        .get(&conversation)
        .ok_or("log")?
        .head();
    harness.finalize_reinit(conversation)?;
    assert!(matches!(
        harness
            .reloaded()?
            .coordinator
            .state
            .logs
            .get(&conversation)
            .map(SequencerLog::phase),
        Some(Phase::Reinit { .. })
    ));
    let key = RouteRow::key(&conversation)?;
    rewrite(&mut harness, &key, |body| {
        let mut row = RouteRow::decode(&body)?;
        row.route_sequence = earlier.sequence;
        row.sequencer_head_id = earlier.record_id;
        row.accepted_state_id = earlier.record_id;
        Ok(row.encode()?)
    })?;
    assert!(harness.reloaded().is_err());
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
