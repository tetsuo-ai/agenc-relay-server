//! Restore of the rows a coordinator of release candidate 3 (`70c832c`)
//! stored for each kind of ReInit state of the previous profile (P-04 with
//! G-08). The rows are `test-data/stage-ten/previous-profile-reinit/`: that
//! coordinator's own durable records, written by its test harness, which
//! this tree seals into a storage fixture and restores through the storage
//! reads a restart uses, and through the harness's reload for the requests
//! that follow.
//!
//! Every store restores, and no group of the previous profile takes a
//! candidate, a terminal, an application object or an attempt: a route
//! whose head is a ReInit activation or abort this profile does not read is
//! retired, and so is the successor such an activation's group bound; a
//! group whose finalized ReInit Commit was followed by ordinary records is
//! retired, with no candidate left open, and one closed after it stays
//! closed; an attempt left open stays open in the closed ReInit phase it
//! cannot leave, and a finalized ReInit Commit keeps the group closed for an
//! attempt no target of this profile can match. Plaintext stays refused on
//! every route.

#![forbid(unsafe_code)]

use super::reconstruction::reconstruct;
use super::*;
use crate::e2ee::coordinator::recovery_lineage::resume;
use crate::state_core::durable::AccountServiceDurableWrite as Write;
use agenc_relay_storage::e2ee_records::{ObjectRow, RouteRow, SequencerRow};
use agenc_relay_storage::{PersistentRecordValue, StoredKey, TableId};
use agenc_relay_types::ChannelInstanceId;

fn unhex(text: &str) -> TestResult<Vec<u8>> {
    let pair = |at: usize| -> TestResult<u8> {
        Ok(u8::from_str_radix(text.get(at..at + 2).ok_or("hex")?, 16)?)
    };
    if !text.len().is_multiple_of(2) {
        return Err("odd hex".into());
    }
    (0..text.len()).step_by(2).map(pair).collect()
}

/// The text of the fixture file `file`.
fn fixture(file: &str) -> TestResult<String> {
    Ok(std::fs::read_to_string(format!(
        "{}/../../test-data/stage-ten/previous-profile-reinit/{file}",
        env!("CARGO_MANIFEST_DIR")
    ))?)
}

/// The rows of one store, one `<table> <key hex> <value hex>` per line.
fn rows(name: &str) -> TestResult<Vec<Write>> {
    let mut rows = Vec::new();
    for line in fixture(&format!("{name}.rows"))?.lines() {
        let mut fields = line.split(' ');
        let (Some(table), Some(key), Some(value), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err("a row has three fields".into());
        };
        rows.push(Write::put(
            TableId::from_u16(table.parse()?)?,
            StoredKey::new(unhex(key)?)?,
            unhex(value)?,
        )?);
    }
    Ok(rows)
}

/// The harness reloaded from the rows of `name`, its device attached again.
fn reloaded(name: &str) -> TestResult<Harness> {
    let mut source = Harness::new()?;
    source.writes = rows(name)?;
    let mut harness = source.reloaded()?;
    harness.attach()?;
    Ok(harness)
}

/// The conversation that owns the bound `#room` route.
fn room(harness: &Harness) -> TestResult<[u8; 32]> {
    Ok(harness
        .coordinator
        .state
        .routes
        .channel_route(&ChannelInstanceId::from_bytes(INSTANCE))
        .ok_or("the #room route")?
        .conversation_id
        .0)
}

/// The conversation the bound `#room` route held before any successor.
fn original() -> TestResult<[u8; 32]> {
    Ok(agenc_relay_e2ee::ids::conversation_id(
        &NETWORK,
        &crate::e2ee::coordinator::tests::GROUP,
    )?)
}

fn phase(harness: &Harness, conversation: &[u8; 32]) -> TestResult<Phase> {
    Ok(harness
        .coordinator
        .state
        .logs
        .get(conversation)
        .ok_or("a restored log")?
        .phase())
}

/// What no group of the previous profile takes: a candidate, an application
/// object on its route, an attempt (refused with `attempt_refusal`), and a
/// resumed recovery lineage. Plaintext stays refused on the route.
fn takes_nothing(
    harness: &mut Harness,
    conversation: [u8; 32],
    attempt_refusal: E2eeReplyCode,
) -> TestResult {
    assert!(matches!(
        resume(&harness.coordinator, &conversation),
        Err(E2eeReplyCode::RouteInvalid)
    ));
    refuses_traffic(harness, conversation, attempt_refusal)
}

/// A candidate, an application object on the route, an attempt (refused
/// with `attempt_refusal`) and a new reservation of the channel are refused,
/// and plaintext stays refused on the route.
fn refuses_traffic(
    harness: &mut Harness,
    conversation: [u8; 32],
    attempt_refusal: E2eeReplyCode,
) -> TestResult {
    let mut reserve = INSTANCE.to_vec();
    reserve.push(5);
    reserve.extend_from_slice(b"#room");
    assert_eq!(
        code(harness.run(Op::ReserveChannel, &reserve, None)?),
        Some(E2eeReplyCode::GroupConflict)
    );
    let state = &harness.coordinator.state;
    assert!(
        !state
            .routes
            .channel_plaintext_allowed(&ChannelInstanceId::from_bytes(INSTANCE))
    );
    let log = state.logs.get(&conversation).ok_or("log")?;
    let (epoch, accepted) = (log.accepted_epoch(), *log.accepted_state_id());
    let commit = super::super::super::commit_bytes(harness, conversation, epoch, 90)?;
    assert_eq!(
        code(harness.run(Op::SubmitCandidate, &conversation, Some(&commit))?),
        Some(E2eeReplyCode::RouteInvalid)
    );
    let aad = agenc_relay_e2ee::objects::aad::ArcApplicationAad {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        route_binding: agenc_relay_e2ee::route::channel_route_binding(&NETWORK, &INSTANCE)?,
        latest_state_id: accepted,
    }
    .encode()?;
    let group = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("state")?
        .group_id
        .clone();
    let message = super::super::super::super::wire_raw(
        ArcWireObjectKind::ApplicationMls,
        super::super::super::super::support::private_message_bytes(&group, 1, &aad)?,
    )?;
    let mut send = conversation.to_vec();
    send.extend_from_slice(&INSTANCE);
    assert_eq!(
        code(harness.run(Op::ApplicationChannel, &send, Some(&message))?),
        Some(E2eeReplyCode::RouteInvalid)
    );
    let (_, bytes) = attempt(harness, conversation, accepted, 0)?;
    assert_eq!(
        code(harness.run(Op::SubmitReinitAttempt, &conversation, Some(&bytes))?),
        Some(attempt_refusal)
    );
    Ok(())
}

#[tokio::test]
async fn every_store_of_the_previous_profile_restores() -> TestResult {
    for name in [
        "open-attempt-at-genesis",
        "open-attempt-after-finalization",
        "aborted-attempt",
        "activated",
        "activated-and-bound",
        "reinit-finalization",
        "reinit-finalization-then-attempt",
        "reinit-finalization-then-candidate",
        "reinit-finalization-then-close",
        "reinit-finalization-then-ordinary",
    ] {
        let (_, result) = Box::pin(reconstruct(&rows(name)?)).await?;
        assert!(result.is_ok(), "{name}: {result:?}");
    }
    Ok(())
}

#[test]
fn a_reinit_terminal_of_the_previous_profile_retires_its_route() -> TestResult {
    for name in ["aborted-attempt", "activated"] {
        let mut harness = reloaded(name)?;
        let old = original()?;
        assert_eq!(room(&harness)?, old, "{name}");
        assert_eq!(phase(&harness, &old)?, Phase::Retired, "{name}");
        takes_nothing(&mut harness, old, E2eeReplyCode::FinalityRequired)?;
    }
    Ok(())
}

#[test]
fn a_successor_bound_under_the_previous_profile_is_retired_with_its_predecessor() -> TestResult {
    let mut harness = reloaded("activated-and-bound")?;
    let old = original()?;
    let successor = room(&harness)?;
    assert_ne!(successor, old);
    assert_eq!(phase(&harness, &old)?, Phase::Retired);
    assert_eq!(phase(&harness, &successor)?, Phase::Retired);
    // The attached device holds no leaf of the successor, which the
    // requester checks refuse before the phase is read.
    takes_nothing(&mut harness, successor, E2eeReplyCode::BindingAuthInvalid)?;
    takes_nothing(&mut harness, old, E2eeReplyCode::FinalityRequired)
}

#[test]
fn an_attempt_admitted_before_this_enforcement_keeps_the_group_closed() -> TestResult {
    for (name, authorized) in [
        ("open-attempt-at-genesis", false),
        ("open-attempt-after-finalization", false),
        ("reinit-finalization-then-attempt", true),
    ] {
        let mut harness = reloaded(name)?;
        let old = original()?;
        let log = harness
            .coordinator
            .state
            .logs
            .get(&old)
            .ok_or("log")?
            .clone();
        assert!(matches!(log.phase(), Phase::Reinit { .. }), "{name}");
        assert!(log.reinit_attempt().is_some(), "{name}");
        let state = harness
            .coordinator
            .state
            .conversations
            .get(&old)
            .ok_or("state")?;
        assert_eq!(state.reinit.is_some(), authorized, "{name}");
        // Without a finalized ReInit Commit no attempt follows the one left
        // open; after one, the target it authorized is a target of the
        // previous layout, which no attempt of this profile carries.
        let refusal = if authorized {
            E2eeReplyCode::BindingAuthInvalid
        } else {
            E2eeReplyCode::FinalityRequired
        };
        takes_nothing(&mut harness, old, refusal)?;
    }
    Ok(())
}

#[test]
fn a_reinit_commit_finalized_under_the_previous_profile_keeps_the_group_closed() -> TestResult {
    // The finalized ReInit Commit closes the group in this profile; the
    // target its authorization committed is a target of the previous
    // layout, which no attempt of this profile carries.
    let mut harness = reloaded("reinit-finalization")?;
    let old = original()?;
    assert!(matches!(phase(&harness, &old)?, Phase::Reinit { .. }));
    takes_nothing(&mut harness, old, E2eeReplyCode::BindingAuthInvalid)?;
    // Ordinary records that followed such a finalization retire the group.
    let mut harness = reloaded("reinit-finalization-then-ordinary")?;
    assert_eq!(phase(&harness, &old)?, Phase::Retired);
    takes_nothing(&mut harness, old, E2eeReplyCode::FinalityRequired)
}

#[test]
fn an_ordinary_candidate_left_open_after_a_reinit_finalization_is_never_finalized() -> TestResult {
    // The previous profile sequenced an ordinary candidate after the
    // finalized ReInit Commit; the group is retired without it, and the
    // finalization request that would have completed it is refused.
    let mut harness = reloaded("reinit-finalization-then-candidate")?;
    let old = original()?;
    let log = harness.coordinator.state.logs.get(&old).ok_or("log")?;
    assert_eq!(log.phase(), Phase::Retired);
    assert_eq!(log.candidate(), None);
    let request = unhex(fixture("reinit-finalization-then-candidate.finalization")?.trim())?;
    assert_eq!(
        code(harness.run(Op::SubmitFinalization, &old, Some(&request))?),
        Some(E2eeReplyCode::FinalityRequired)
    );
    takes_nothing(&mut harness, old, E2eeReplyCode::FinalityRequired)
}

#[test]
fn a_group_closed_after_a_reinit_finalization_stays_closed() -> TestResult {
    // A close is read as it was: the group is closed, not retired.
    let mut harness = reloaded("reinit-finalization-then-close")?;
    let old = original()?;
    assert!(matches!(phase(&harness, &old)?, Phase::Closed { .. }));
    refuses_traffic(&mut harness, old, E2eeReplyCode::FinalityRequired)
}

/// The body of the `table` row at `key`.
fn row_body(rows: &[Write], table: TableId, key: &StoredKey) -> TestResult<Vec<u8>> {
    for write in rows {
        if let Write::Put {
            table: stored_table,
            key: stored,
            plaintext,
        } = write
            && *stored_table == table
            && stored == key
        {
            return Ok(PersistentRecordValue::decode(table, plaintext)?
                .body()
                .to_vec());
        }
    }
    Err("no such row".into())
}

/// Replaces the body of the `table` row at `key`.
fn set_row_body(rows: &mut [Write], table: TableId, key: &StoredKey, body: Vec<u8>) -> TestResult {
    for write in rows {
        if let Write::Put {
            table: stored_table,
            key: stored,
            plaintext,
        } = write
            && *stored_table == table
            && stored == key
        {
            let value = PersistentRecordValue::decode(table, plaintext)?;
            *plaintext = zeroize::Zeroizing::new(
                PersistentRecordValue::new(
                    table,
                    value.record_kind(),
                    value.revision(),
                    value.generation(),
                    value.expires_at(),
                    value.references().to_vec(),
                    body,
                )?
                .encode()?,
            );
            return Ok(());
        }
    }
    Err("no such row".into())
}

/// One change to the stored head of the original route.
#[derive(Clone, Copy, Debug)]
enum HeadEdit {
    /// The rows as stored.
    Unchanged,
    /// The route row names another head.
    RouteHead,
    /// The head's record row names another record.
    RecordId,
    /// The head's record row says it is an attempt receipt.
    RecordKind,
    /// The head's record row is not a terminal.
    NotTerminal,
    /// The head's record row names another predecessor.
    Predecessor,
    /// The record before the head is an ordinary abort.
    PredecessorKind,
    /// The head's record row names a retained object of another kind.
    ObjectKind,
    /// The head's record row names an object that is not retained.
    MissingObject,
}

/// Rewrites the record row of the original route at `sequence`.
fn edit_record(
    rows: &mut [Write],
    sequence: u64,
    change: impl FnOnce(&mut SequencerRow),
) -> TestResult {
    let key = SequencerRow::record_key(&original()?, sequence)?;
    let mut record = SequencerRow::decode(&row_body(rows, TableId::E2eeState, &key)?)?;
    change(&mut record);
    set_row_body(rows, TableId::E2eeState, &key, record.encode()?)
}

/// The identifier of a retained object that is not a sequencer record.
fn other_object(rows: &[Write]) -> TestResult<[u8; 32]> {
    for write in rows {
        if let Write::Put {
            table: TableId::E2eeObject,
            key,
            plaintext,
        } = write
        {
            let value = PersistentRecordValue::decode(TableId::E2eeObject, plaintext)?;
            if ObjectRow::decode(value.body())?.kind()? != ArcWireObjectKind::SequencerRecord {
                return Ok(<[u8; 32]>::try_from(key.as_bytes())?);
            }
        }
    }
    Err("no other object".into())
}

/// The rows of `name` with `edit` applied to the head of the original route.
fn edited_head(name: &str, edit: HeadEdit) -> TestResult<Vec<Write>> {
    let mut rows = rows(name)?;
    let route_key = RouteRow::key(&original()?)?;
    let mut route = RouteRow::decode(&row_body(&rows, TableId::E2eeState, &route_key)?)?;
    let head = route.route_sequence;
    let before = head.checked_sub(1).ok_or("a head after its receipt")?;
    let other = other_object(&rows)?;
    match edit {
        HeadEdit::Unchanged => {}
        HeadEdit::RouteHead => {
            route.sequencer_head_id[0] ^= 1;
            set_row_body(&mut rows, TableId::E2eeState, &route_key, route.encode()?)?;
        }
        HeadEdit::RecordId => edit_record(&mut rows, head, |row| {
            if let SequencerRow::Record { record_id, .. } = row {
                record_id[0] ^= 1;
            }
        })?,
        HeadEdit::RecordKind => edit_record(&mut rows, head, |row| {
            if let SequencerRow::Record { record_kind, .. } = row {
                *record_kind = 4;
            }
        })?,
        HeadEdit::NotTerminal => edit_record(&mut rows, head, |row| {
            if let SequencerRow::Record { terminal, .. } = row {
                *terminal = false;
            }
        })?,
        HeadEdit::Predecessor => edit_record(&mut rows, head, |row| {
            if let SequencerRow::Record {
                predecessor_record_id,
                ..
            } = row
            {
                predecessor_record_id[0] ^= 1;
            }
        })?,
        HeadEdit::PredecessorKind => edit_record(&mut rows, before, |row| {
            if let SequencerRow::Record { record_kind, .. } = row {
                *record_kind = 3;
            }
        })?,
        HeadEdit::ObjectKind => edit_record(&mut rows, head, |row| {
            if let SequencerRow::Record {
                record_object_id, ..
            } = row
            {
                *record_object_id = other;
            }
        })?,
        HeadEdit::MissingObject => edit_record(&mut rows, head, |row| {
            if let SequencerRow::Record {
                record_object_id, ..
            } = row
            {
                record_object_id[0] ^= 1;
            }
        })?,
    }
    Ok(rows)
}

#[test]
fn a_previous_profile_terminal_that_disagrees_with_its_rows_refuses_startup() -> TestResult {
    // This profile does not parse the terminal (companion 2.3), so the rows
    // must agree on it: the route row's head is the record row's ID, the
    // record row is a ReInit activation or abort terminal whose predecessor
    // is the attempt receipt before it, and its retained object is a
    // sequencer record.
    for name in ["aborted-attempt", "activated"] {
        let mut source = Harness::new()?;
        source.writes = edited_head(name, HeadEdit::Unchanged)?;
        let harness = source.reloaded()?;
        assert_eq!(phase(&harness, &original()?)?, Phase::Retired, "{name}");
        for edit in [
            HeadEdit::RouteHead,
            HeadEdit::RecordId,
            HeadEdit::RecordKind,
            HeadEdit::NotTerminal,
            HeadEdit::Predecessor,
            HeadEdit::PredecessorKind,
            HeadEdit::ObjectKind,
            HeadEdit::MissingObject,
        ] {
            let mut source = Harness::new()?;
            source.writes = edited_head(name, edit)?;
            assert!(source.reloaded().is_err(), "{name}: {edit:?}");
        }
    }
    Ok(())
}

#[test]
fn a_head_record_row_that_names_another_kind_refuses_startup() -> TestResult {
    // The open candidate's record row says it is an attempt receipt, while
    // its record is a candidate receipt: the head names no phase.
    let mut source = Harness::new()?;
    source.writes = edited_head("reinit-finalization-then-candidate", HeadEdit::RecordKind)?;
    assert!(source.reloaded().is_err());
    Ok(())
}
