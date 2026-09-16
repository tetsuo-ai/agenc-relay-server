#![forbid(unsafe_code)]

//! Durable object ownership (companion 15, 16): every owner class seals and
//! reopens with the same account, shared objects stay protected until their
//! last owner retires, the conversation and global quotas refuse before any
//! row is staged, and reconstruction never invents an age.

use super::super::{
    COORDINATOR, DEVICE_ID, Harness, NETWORK, NOW, STATE_GENERATION, TestResult, account_param,
    object_id, ok, wire_raw,
};
use super::leaf_membership::{finalization::finalize_both, two_member_channel};
use crate::e2ee::coordinator::owners::{Account, Ledger, Rebuild, owned_by};
use crate::e2ee::coordinator::{CompanionCoordinator, request};
use crate::state_core::durable::AccountServiceDurableWrite as Write;
use agenc_ircd_domain::e2ee::projection::StoreKind;
use agenc_ircd_e2ee::limits::{MAX_STORED_BYTES_PER_CONVERSATION, RECOVERY_HEADROOM_BYTES};
use agenc_ircd_e2ee::object::IrcWireObjectKind as Kind;
use agenc_ircd_e2ee::objects::federation::IrcFederationOpcode as Op;
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;
use agenc_ircd_storage::e2ee_records::BARRIER_ROW_KIND;
use agenc_ircd_storage::e2ee_records::barrier::{BarrierIdentity, BarrierPart, CrossProfileStream};
use agenc_ircd_storage::e2ee_records::{
    DIRECTORY_ROW_KIND, DirectoryRow, MAILBOX_ROW_KIND, MailboxRow, OWNER_ROW_KIND, ObjectOwnerRow,
    REPLAY_ROW_KIND, ReplayKey, ReplayRow, RetentionClass, SEQUENCER_ROW_KIND, SequencerRow,
    prefix,
};
use agenc_ircd_storage::{
    MAX_RECORD_REFERENCES, PersistentRecordValue, RecordReference, StoredKey, TableId,
};
use agenc_ircd_types::ServerId;
use std::collections::{BTreeMap, BTreeSet};

use crate::e2ee::coordinator::request::ResultBody;

const CONVERSATION: [u8; 32] = [61; 32];
const DIGEST: [u8; 32] = [62; 32];
const DEVICE: [u8; 16] = [63; 16];
const TOKEN: [u8; 32] = [64; 32];

fn coordinator() -> CompanionCoordinator {
    CompanionCoordinator::new(
        NETWORK,
        ServerId::from_bytes(COORDINATOR),
        "coordinator.example".into(),
    )
}

fn object(kind: Kind, seed: u8, len: usize) -> TestResult<Vec<u8>> {
    wire_raw(kind, vec![seed; len])
}

fn code(code: E2eeReplyCode) -> Box<dyn std::error::Error> {
    format!("refused with {code:?}").into()
}

fn retain(coordinator: &mut CompanionCoordinator, bytes: &[u8]) -> TestResult<[u8; 32]> {
    CompanionCoordinator::retain_object(&mut coordinator.state, bytes.to_vec()).map_err(code)
}

fn row(kind: u16, key: StoredKey, body: Vec<u8>) -> TestResult<Write> {
    request::state_row(TableId::E2eeState, kind, key, body).map_err(code)
}

fn object_write(bytes: &[u8]) -> TestResult<Write> {
    CompanionCoordinator::object_write(bytes).map_err(code)
}

fn record_key(sequence: u64) -> TestResult<StoredKey> {
    Ok(SequencerRow::record_key(&CONVERSATION, sequence)?)
}

fn record_row(object: [u8; 32], sequence: u64, security_proof: bool) -> TestResult<Write> {
    row(
        SEQUENCER_ROW_KIND,
        record_key(sequence)?,
        SequencerRow::Record {
            record_object_id: object,
            record_id: [1; 32],
            record_kind: 1,
            terminal: false,
            security_proof,
            predecessor_record_id: [0; 32],
        }
        .encode()?,
    )
}

fn ack_key() -> TestResult<StoredKey> {
    Ok(MailboxRow::ack_key(&DIGEST, &DEVICE, &TOKEN)?)
}

fn ack_row(object: [u8; 32]) -> TestResult<Write> {
    row(
        MAILBOX_ROW_KIND,
        ack_key()?,
        MailboxRow::Ack {
            object_id: object,
            acknowledged_at: 1,
            retain_until: 2,
        }
        .encode()?,
    )
}

fn replay_key() -> TestResult<StoredKey> {
    Ok(ReplayRow::key(&ReplayKey {
        home_server_id: [2; 16],
        server_incarnation: [3; 16],
        origin_id: [4; 16],
        origin_generation: 0,
        operation_sequence: 1,
    })?)
}

fn replay_row(request: [u8; 32], result: [u8; 32]) -> TestResult<Write> {
    row(
        REPLAY_ROW_KIND,
        replay_key()?,
        ReplayRow {
            request_id: [1; 16],
            request_object_id: request,
            result_object_id: Some(result),
            response_object_ids: Vec::new(),
            security_mutation: false,
            retain_until: 0,
        }
        .encode()?,
    )
}

fn capability_key() -> TestResult<StoredKey> {
    Ok(DirectoryRow::capability_key(&DIGEST, &DEVICE)?)
}

fn capability_row(object: [u8; 32]) -> TestResult<Write> {
    row(
        DIRECTORY_ROW_KIND,
        capability_key()?,
        DirectoryRow::Capability {
            generation: 1,
            capability_id: [2; 32],
            roster_id: [3; 32],
            object_id: object,
        }
        .encode()?,
    )
}

/// Stages and installs one batch as the coordinator does at commit; the
/// owner rows the batch produced are returned for reconstruction tests.
fn commit(
    coordinator: &mut CompanionCoordinator,
    mut writes: Vec<Write>,
    security_mutation: bool,
) -> TestResult<Vec<Write>> {
    let before = writes.len();
    let staged = coordinator
        .stage_owners(&mut writes, NOW, security_mutation, STATE_GENERATION)
        .map_err(code)?;
    staged.apply(&mut coordinator.state);
    Ok(writes.split_off(before))
}

fn delete(key: StoredKey) -> TestResult<Write> {
    Ok(Write::delete(TableId::E2eeState, key)?)
}

fn owner_kind(write: &Write) -> Option<u16> {
    let (table, _, encoded) = write.encoded_record()?;
    PersistentRecordValue::decode(table, encoded)
        .ok()
        .map(|value| value.record_kind())
}

fn is_owner_row(write: &Write) -> bool {
    owner_kind(write) == Some(OWNER_ROW_KIND)
}

fn shared_bytes() -> TestResult<Vec<u8>> {
    object(Kind::CommitMls, 7, 64)
}

fn request_bytes() -> TestResult<Vec<u8>> {
    object(Kind::FederationRequest, 8, 40)
}

/// The encoded sizes of the shared object and its request.
fn shared_sizes() -> TestResult<(u64, u64)> {
    Ok((
        u64::try_from(shared_bytes()?.len())?,
        u64::try_from(request_bytes()?.len())?,
    ))
}

/// A shared object held by a security proof, an ordinary directory row, a
/// mailbox acknowledgement and a replay row.
fn shared_fixture() -> TestResult<(CompanionCoordinator, [u8; 32], Vec<Write>)> {
    let mut coordinator = coordinator();
    let bytes = shared_bytes()?;
    let id = retain(&mut coordinator, &bytes)?;
    let request = request_bytes()?;
    let request_id = retain(&mut coordinator, &request)?;
    let owners = commit(
        &mut coordinator,
        vec![
            record_row(id, 1, true)?,
            capability_row(id)?,
            ack_row(id)?,
            replay_row(request_id, id)?,
        ],
        false,
    )?;
    Ok((coordinator, id, owners))
}

#[test]
fn a_shared_object_stays_protected_until_its_last_owner_retires_in_every_order() -> TestResult {
    let keys = [record_key(1)?, capability_key()?, ack_key()?, replay_key()?];
    let mut orders = Vec::new();
    for a in 0..4 {
        for b in 0..4 {
            for c in 0..4 {
                for d in 0..4 {
                    let order = [a, b, c, d];
                    if BTreeSet::from(order).len() == 4 {
                        orders.push(order);
                    }
                }
            }
        }
    }
    assert_eq!(orders.len(), 24);
    let (size, request_size) = shared_sizes()?;
    for order in orders {
        let (mut coordinator, id, _) = shared_fixture()?;
        let expected: BTreeSet<Vec<u8>> = keys.iter().map(|key| key.as_bytes().to_vec()).collect();
        let account = coordinator
            .state
            .owners
            .account(&id)
            .ok_or("account")?
            .clone();
        assert_eq!(
            account.owners.keys().cloned().collect::<BTreeSet<_>>(),
            expected
        );
        assert_eq!(account.retention, RetentionClass::SecurityProof);
        assert_eq!((account.accepted_at, account.retired_at), (NOW, None));
        assert!(!account.reconstructed);
        assert_eq!(
            coordinator.state.owners.conversation_bytes(&CONVERSATION),
            size
        );
        for (step, index) in order.iter().enumerate() {
            let key = keys.get(*index).ok_or("key")?.clone();
            commit(&mut coordinator, vec![delete(key)?], false)?;
            let account = coordinator.state.owners.account(&id).ok_or("account")?;
            assert_eq!(account.owners.len(), 3 - step);
            assert_eq!(account.retention, RetentionClass::SecurityProof);
            assert_eq!(account.retired_at, (step == 3).then_some(NOW));
            let charged = coordinator.state.owners.conversation_bytes(&CONVERSATION);
            assert_eq!(
                charged != 0,
                !order.get(..=step).unwrap_or(&[]).contains(&0)
            );
        }
        assert_eq!(coordinator.state.owners.total_bytes(), size + request_size);
        // The bytes stay accounted after retirement: nothing here deletes.
        assert!(coordinator.state.owners.account(&id).is_some());
    }
    Ok(())
}

#[test]
fn owner_rows_are_written_only_by_the_ledger() -> TestResult {
    let (coordinator, id, owners) = shared_fixture()?;
    assert_eq!(owners.len(), 2);
    assert!(owners.iter().all(is_owner_row));
    let forged = owners.into_iter().next().ok_or("owner row")?;
    let mut writes = vec![forged];
    assert_eq!(
        coordinator
            .stage_owners(&mut writes, NOW, false, STATE_GENERATION)
            .err(),
        Some(E2eeReplyCode::InvalidFragment)
    );
    assert_eq!(writes.len(), 1);
    assert!(coordinator.state.owners.account(&id).is_some());
    Ok(())
}

#[test]
fn a_batch_that_changes_accounts_needs_a_trusted_time() -> TestResult {
    let mut coordinator = coordinator();
    let bytes = object(Kind::CommitMls, 9, 32)?;
    let id = retain(&mut coordinator, &bytes)?;
    let mut writes = vec![record_row(id, 1, false)?];
    assert_eq!(
        coordinator
            .stage_owners(&mut writes, 0, false, STATE_GENERATION)
            .err(),
        Some(E2eeReplyCode::RateLimited)
    );
    assert!(coordinator.state.owners.account(&id).is_none());
    let mut none = Vec::new();
    let staged = coordinator
        .stage_owners(&mut none, 0, false, STATE_GENERATION)
        .map_err(code)?;
    staged.apply(&mut coordinator.state);
    assert!(none.is_empty());
    Ok(())
}

/// A conversation already charged `charged` bytes, with the record row of
/// sequence 1 as the owner of a synthetic account.
fn charged_conversation(charged: u64) -> TestResult<CompanionCoordinator> {
    let mut coordinator = coordinator();
    let mut owners = BTreeMap::new();
    owners.insert(record_key(1)?.as_bytes().to_vec(), Some(CONVERSATION));
    coordinator.state.owners.install(
        [99; 32],
        Account {
            kind: Kind::CommitMls.value(),
            size: charged,
            retention: RetentionClass::Ordinary,
            accepted_at: 1,
            reconstructed: false,
            retired_at: None,
            owners,
        },
    );
    assert_eq!(
        coordinator.state.owners.conversation_bytes(&CONVERSATION),
        charged
    );
    Ok(coordinator)
}

fn admit(
    coordinator: &mut CompanionCoordinator,
    writes: Vec<Write>,
    security_mutation: bool,
) -> TestResult<Result<u64, E2eeReplyCode>> {
    let before = coordinator.state.owners.clone();
    let count = writes.len();
    let mut writes = writes;
    match coordinator.stage_owners(&mut writes, NOW, security_mutation, STATE_GENERATION) {
        Ok(staged) => {
            staged.apply(&mut coordinator.state);
            Ok(Ok(coordinator
                .state
                .owners
                .conversation_bytes(&CONVERSATION)))
        }
        Err(code) => {
            // A refusal stages nothing and changes nothing.
            assert_eq!(writes.len(), count);
            assert!(coordinator.state.owners == before);
            Ok(Err(code))
        }
    }
}

#[test]
fn the_conversation_quota_admits_up_to_and_refuses_beyond_256_mib() -> TestResult {
    let quota = MAX_STORED_BYTES_PER_CONVERSATION;
    let bytes = object(Kind::CommitMls, 10, 100)?;
    let size = u64::try_from(bytes.len())?;
    for (charged, expected) in [
        (quota - size - 1, Ok(quota - 1)),
        (quota - size, Ok(quota)),
        (quota - size + 1, Err(E2eeReplyCode::RateLimited)),
    ] {
        let mut coordinator = charged_conversation(charged)?;
        let id = retain(&mut coordinator, &bytes)?;
        assert_eq!(
            admit(&mut coordinator, vec![record_row(id, 2, false)?], false)?,
            expected
        );
    }
    Ok(())
}

#[test]
fn a_proof_producing_transition_keeps_the_recovery_headroom_free() -> TestResult {
    let quota = MAX_STORED_BYTES_PER_CONVERSATION;
    let bytes = object(Kind::CommitMls, 11, 100)?;
    let size = u64::try_from(bytes.len())?;
    let boundary = quota - RECOVERY_HEADROOM_BYTES - size;
    for (charged, security, expected) in [
        (boundary, true, Ok(quota - RECOVERY_HEADROOM_BYTES)),
        (boundary + 1, true, Err(E2eeReplyCode::RateLimited)),
        (boundary + 1, false, Ok(quota - RECOVERY_HEADROOM_BYTES + 1)),
    ] {
        let mut coordinator = charged_conversation(charged)?;
        let id = retain(&mut coordinator, &bytes)?;
        assert_eq!(
            admit(&mut coordinator, vec![record_row(id, 2, true)?], security)?,
            expected
        );
    }
    // Retiring an owner never needs headroom, even in a proof-producing batch.
    let mut coordinator = charged_conversation(quota - size)?;
    let id = retain(&mut coordinator, &bytes)?;
    assert_eq!(
        admit(&mut coordinator, vec![record_row(id, 2, false)?], false)?,
        Ok(quota)
    );
    assert_eq!(
        admit(&mut coordinator, vec![delete(record_key(2)?)?], true)?,
        Ok(quota - size)
    );
    Ok(())
}

#[test]
fn an_object_named_by_several_rows_of_one_conversation_is_charged_once() -> TestResult {
    let quota = MAX_STORED_BYTES_PER_CONVERSATION;
    let bytes = object(Kind::CommitMls, 12, 100)?;
    let size = u64::try_from(bytes.len())?;
    let mut coordinator = charged_conversation(quota - size)?;
    let id = retain(&mut coordinator, &bytes)?;
    assert_eq!(
        admit(
            &mut coordinator,
            vec![record_row(id, 2, false)?, record_row(id, 3, true)?],
            false
        )?,
        Ok(quota)
    );
    let account = coordinator.state.owners.account(&id).ok_or("account")?;
    assert_eq!(account.owners.len(), 2);
    assert_eq!(account.retention, RetentionClass::SecurityProof);
    // The same object in another conversation is charged there as well.
    let other = SequencerRow::record_key(&[77; 32], 1)?;
    let write = row(
        SEQUENCER_ROW_KIND,
        other,
        SequencerRow::Record {
            record_object_id: id,
            record_id: [1; 32],
            record_kind: 1,
            terminal: false,
            security_proof: false,
            predecessor_record_id: [0; 32],
        }
        .encode()?,
    )?;
    assert_eq!(admit(&mut coordinator, vec![write], false)?, Ok(quota));
    assert_eq!(coordinator.state.owners.conversation_bytes(&[77; 32]), size);
    assert_eq!(coordinator.state.owners.total_bytes(), quota);
    Ok(())
}

#[test]
fn the_global_ceiling_refuses_atomically_and_zero_means_unlimited() -> TestResult {
    let bytes = object(Kind::CommitMls, 13, 100)?;
    let size = u64::try_from(bytes.len())?;
    for (ceiling, expected) in [
        (0, Ok(size)),
        (1_000 + size, Ok(size)),
        (1_000 + size - 1, Err(E2eeReplyCode::RateLimited)),
    ] {
        let mut coordinator = coordinator();
        coordinator.state.owners.install(
            [98; 32],
            Account {
                kind: Kind::CommitMls.value(),
                size: 1_000,
                retention: RetentionClass::Ordinary,
                accepted_at: 1,
                reconstructed: false,
                retired_at: None,
                owners: BTreeMap::new(),
            },
        );
        coordinator.set_global_disk_bytes(ceiling);
        let id = retain(&mut coordinator, &bytes)?;
        assert_eq!(
            admit(&mut coordinator, vec![record_row(id, 2, false)?], false)?,
            expected
        );
    }
    Ok(())
}

/// Feeds every write of a batch to a rebuild as startup reads them back.
fn rebuild_from(writes: &[&Write]) -> TestResult<Rebuild> {
    let mut rebuild = Rebuild::default();
    for write in writes {
        let Some((table, key, encoded)) = write.encoded_record() else {
            continue;
        };
        let value = PersistentRecordValue::decode(table, encoded)?;
        match table {
            TableId::E2eeObject => rebuild.admit_object(key, &value),
            TableId::E2eeState => rebuild.admit_row(key, &value),
            _ => {}
        }
    }
    Ok(rebuild)
}

fn reencode_owner(
    write: &Write,
    edit: impl FnOnce(&mut ObjectOwnerRow, &mut Vec<RecordReference>),
) -> TestResult<Write> {
    let (table, key, encoded) = write.encoded_record().ok_or("owner put")?;
    let value = PersistentRecordValue::decode(table, encoded)?;
    let mut row = ObjectOwnerRow::decode(value.body())?;
    let mut references = value.references().to_vec();
    edit(&mut row, &mut references);
    let encoded =
        PersistentRecordValue::new(table, OWNER_ROW_KIND, 1, 0, None, references, row.encode()?)?
            .encode()?;
    Ok(Write::put(table, key.clone(), encoded)?)
}

#[test]
fn reconstruction_trusts_only_a_complete_consistent_account() -> TestResult {
    let (source, id, owners) = shared_fixture()?;
    let object_bytes = source.state.objects.get(&id).ok_or("object")?.clone();
    let request_id = *source
        .state
        .objects
        .keys()
        .find(|key| **key != id)
        .ok_or("request object")?;
    let request_bytes = source
        .state
        .objects
        .get(&request_id)
        .ok_or("request")?
        .clone();
    let objects = [object_write(&object_bytes)?, object_write(&request_bytes)?];
    let rows = [
        record_row(id, 1, true)?,
        capability_row(id)?,
        ack_row(id)?,
        replay_row(request_id, id)?,
    ];
    let owner_of = |target: [u8; 32]| -> TestResult<&Write> {
        let key = ObjectOwnerRow::key(&target)?;
        owners
            .iter()
            .find(|write| write.encoded_record().is_some_and(|(_, k, _)| *k == key))
            .ok_or_else(|| "owner row".into())
    };
    let expected = source.state.owners.account(&id).ok_or("account")?.clone();

    // Complete: the same ledger, nothing reconstructed.
    let mut all: Vec<&Write> = objects.iter().chain(&rows).chain(&owners).collect();
    let mut state = coordinator().state;
    let diagnostics = rebuild_from(&all)?.finish(&mut state);
    assert!(diagnostics.is_clean(), "{diagnostics:?}");
    assert!(state.owners == source.state.owners);

    // Traversal order does not matter.
    all.reverse();
    let mut reversed = coordinator().state;
    assert!(rebuild_from(&all)?.finish(&mut reversed).is_clean());
    assert!(reversed.owners == source.state.owners);

    // Crash before the owner rows: the rows rebuild the owners, the age is unknown.
    let without: Vec<&Write> = objects.iter().chain(&rows).collect();
    let mut state = coordinator().state;
    let diagnostics = rebuild_from(&without)?.finish(&mut state);
    // The request object is owned by the replay row; nothing is unowned.
    assert_eq!((diagnostics.reconstructed, diagnostics.unowned), (2, 0));
    let account = state.owners.account(&id).ok_or("account")?;
    assert_eq!(account.owners, expected.owners);
    assert_eq!(account.retention, RetentionClass::SecurityProof);
    assert_eq!((account.accepted_at, account.reconstructed), (0, true));
    assert_eq!(
        state.owners.conversation_bytes(&CONVERSATION),
        shared_sizes()?.0
    );

    // An orphan account is ignored; the object it names is not invented.
    let orphan: Vec<&Write> = objects.iter().take(1).chain(&rows).chain(&owners).collect();
    let mut state = coordinator().state;
    let diagnostics = rebuild_from(&orphan)?.finish(&mut state);
    assert_eq!(diagnostics.orphaned, 1);
    assert!(state.owners.account(&request_id).is_none());

    // A reference set that disagrees with the rows: the rows win, the trusted
    // age of the same object is kept.
    let short = reencode_owner(owner_of(id)?, |_, references| {
        references.pop();
    })?;
    let mismatched: Vec<&Write> = objects
        .iter()
        .chain(&rows)
        .chain(std::iter::once(&short))
        .chain(std::iter::once(owner_of(request_id)?))
        .collect();
    let mut state = coordinator().state;
    let diagnostics = rebuild_from(&mismatched)?.finish(&mut state);
    assert_eq!(diagnostics.mismatched, 1);
    let account = state.owners.account(&id).ok_or("account")?;
    assert_eq!(account.owners, expected.owners);
    assert_eq!((account.accepted_at, account.reconstructed), (NOW, true));

    // An account for another object under this identity is not trusted at all.
    let wrong = reencode_owner(owner_of(id)?, |row, _| row.size += 1)?;
    let wrong_size: Vec<&Write> = objects
        .iter()
        .chain(&rows)
        .chain(std::iter::once(&wrong))
        .chain(std::iter::once(owner_of(request_id)?))
        .collect();
    let mut state = coordinator().state;
    let diagnostics = rebuild_from(&wrong_size)?.finish(&mut state);
    assert_eq!(diagnostics.mismatched, 1);
    let account = state.owners.account(&id).ok_or("account")?;
    assert_eq!((account.accepted_at, account.size), (0, shared_sizes()?.0));

    // A retired account whose object a row names again is live, not aged.
    let retired = reencode_owner(owner_of(id)?, |row, _| row.retired_at = Some(NOW + 5))?;
    let revived: Vec<&Write> = objects
        .iter()
        .chain(&rows)
        .chain(std::iter::once(&retired))
        .chain(std::iter::once(owner_of(request_id)?))
        .collect();
    let mut state = coordinator().state;
    assert_eq!(rebuild_from(&revived)?.finish(&mut state).mismatched, 1);
    assert_eq!(state.owners.account(&id).and_then(|a| a.retired_at), None);

    Ok(())
}

#[test]
fn a_reconstructed_account_takes_its_first_trusted_batch_as_the_floor() -> TestResult {
    let (source, id, _) = shared_fixture()?;
    let mut coordinator = coordinator();
    let bytes = source.state.objects.get(&id).ok_or("object")?.clone();
    let request_bytes = source
        .state
        .objects
        .iter()
        .find(|(key, _)| **key != id)
        .map(|(_, bytes)| bytes.clone())
        .ok_or("request")?;
    let request_id = retain(&mut coordinator, &request_bytes)?;
    retain(&mut coordinator, &bytes)?;
    let rows = [
        record_row(id, 1, true)?,
        capability_row(id)?,
        ack_row(id)?,
        replay_row(request_id, id)?,
        object_write(&bytes)?,
        object_write(&request_bytes)?,
    ];
    let all: Vec<&Write> = rows.iter().collect();
    let diagnostics = rebuild_from(&all)?.finish(&mut coordinator.state);
    assert_eq!(diagnostics.reconstructed, 2);
    assert_eq!(
        coordinator.state.owners.account(&id).map(|a| a.accepted_at),
        Some(0)
    );
    let owners = commit(&mut coordinator, vec![delete(ack_key()?)?], false)?;
    assert_eq!(owners.len(), 1);
    let account = coordinator.state.owners.account(&id).ok_or("account")?;
    assert_eq!((account.accepted_at, account.reconstructed), (NOW, true));
    assert_eq!(account.owners.len(), 3);
    let (_, _, encoded) = owners
        .first()
        .and_then(Write::encoded_record)
        .ok_or("row")?;
    let value = PersistentRecordValue::decode(TableId::E2eeState, encoded)?;
    let row = ObjectOwnerRow::decode(value.body())?;
    assert_eq!(
        (row.accepted_at, row.reconstructed, row.size),
        (NOW, true, shared_sizes()?.0)
    );
    assert_eq!(value.references().len(), 3);
    Ok(())
}

/// Every owner class the coordinator writes, in one sealed store.
fn every_owner_class() -> TestResult<(Harness, [u8; 32])> {
    let (mut harness, conversation) = two_member_channel()?;
    finalize_both(&mut harness, conversation)?;
    let binding = harness.binding_bytes()?;
    let mut parameters = account_param(&harness.account);
    parameters.extend_from_slice(&DEVICE_ID);
    let outcome = ok(harness.run(Op::DeliverBinding, &parameters, Some(&binding))?)?;
    assert!(matches!(
        outcome.result,
        ResultBody::Stored(StoreKind::Binding, ..)
    ));
    let page = ok(harness.run(Op::FetchMailbox, &[2, 0], None)?)?;
    let token = page
        .responses
        .first()
        .and_then(|response| response.delivery_token)
        .ok_or("delivery token")?;
    let mut ack = token.to_vec();
    ack.extend_from_slice(&object_id(&binding));
    ok(harness.run(Op::AcknowledgeMailbox, &ack, None)?)?;
    Ok((harness, conversation))
}

fn prefixes(ledger: &Ledger) -> BTreeSet<&'static [u8]> {
    let known: [&'static [u8]; 14] = [
        prefix::ROUTE,
        prefix::RECORD,
        prefix::CANDIDATE,
        prefix::APPROVAL,
        prefix::ACK,
        prefix::VOTE,
        prefix::POLICY,
        prefix::MEMBERSHIP,
        prefix::IDENTITY,
        prefix::ROSTER,
        prefix::BINDING_LOCK,
        prefix::MAILBOX,
        prefix::ACK_MAILBOX,
        prefix::REPLAY,
    ];
    ledger
        .accounts()
        .flat_map(|(_, account)| account.owners.keys())
        .filter_map(|owner| known.iter().copied().find(|p| owner.starts_with(p)))
        .collect()
}

#[test]
fn every_owner_class_seals_and_reopens_with_the_same_accounts() -> TestResult {
    let (harness, conversation) = every_owner_class()?;
    let ledger = &harness.coordinator.state.owners;
    let seen = prefixes(ledger);
    for expected in [
        prefix::ROUTE,
        prefix::RECORD,
        prefix::CANDIDATE,
        prefix::POLICY,
        prefix::MEMBERSHIP,
        prefix::IDENTITY,
        prefix::ROSTER,
        prefix::ACK_MAILBOX,
    ] {
        assert!(seen.contains(expected), "{expected:?} owns nothing");
    }
    assert!(
        [prefix::APPROVAL, prefix::ACK, prefix::VOTE]
            .iter()
            .any(|proof| seen.contains(proof)),
        "no retained proof row owns an object"
    );
    // Every retained object has an account dated by the trusted clock.
    for (id, bytes) in &harness.coordinator.state.objects {
        let account = ledger.account(id).ok_or("account for every object")?;
        assert_eq!(account.size, u64::try_from(bytes.len())?);
        assert_eq!((account.accepted_at, account.reconstructed), (NOW, false));
    }
    let classes: BTreeSet<RetentionClass> = ledger
        .accounts()
        .map(|(_, account)| account.retention)
        .collect();
    assert!(classes.contains(&RetentionClass::SecurityProof));
    assert!(classes.contains(&RetentionClass::Ordinary));
    assert!(classes.contains(&RetentionClass::Mailbox));
    assert!(classes.contains(&RetentionClass::Replay));
    // The conversation's quota is the deduplicated sum of what its rows own.
    let charged: u64 = ledger
        .accounts()
        .filter(|(_, account)| account.conversations().contains(&conversation))
        .map(|(_, account)| account.size)
        .sum();
    assert_eq!(ledger.conversation_bytes(&conversation), charged);
    assert_eq!(
        harness
            .coordinator
            .state
            .conversations
            .get(&conversation)
            .map(|state| state.stored_bytes),
        Some(charged)
    );
    assert!(charged > 0 && charged < MAX_STORED_BYTES_PER_CONVERSATION);

    // Sealed and reopened: the same accounts, in either traversal order,
    // whatever the memory cache retained.
    let reopened = harness.reloaded()?;
    assert!(reopened.coordinator.owner_reconstruction.is_clean());
    assert!(reopened.coordinator.state.owners == harness.coordinator.state.owners);
    assert_eq!(
        reopened
            .coordinator
            .state
            .conversations
            .get(&conversation)
            .map(|state| state.stored_bytes),
        Some(charged)
    );
    let mut reversed = Harness::with_devices(&harness.devices)?;
    for write in harness.writes.iter().rev() {
        let Write::Put {
            table,
            key,
            plaintext,
        } = write
        else {
            continue;
        };
        let value = PersistentRecordValue::decode(*table, plaintext)?;
        reversed
            .coordinator
            .admit_restored_with_backing(*table, key, &value, &reversed.backing);
    }
    reversed
        .coordinator
        .finish_restore_with_backing(reversed.backing.clone())?;
    assert!(reversed.coordinator.owner_reconstruction.is_clean());
    assert!(reversed.coordinator.state.owners == harness.coordinator.state.owners);
    Ok(())
}

#[test]
fn a_store_without_owner_rows_reopens_with_reconstruction_diagnostics() -> TestResult {
    let (harness, _) = every_owner_class()?;
    let mut stripped = Harness::with_devices(&harness.devices)?;
    let mut objects = 0;
    for write in &harness.writes {
        if is_owner_row(write) {
            continue;
        }
        let Write::Put {
            table,
            key,
            plaintext,
        } = write
        else {
            continue;
        };
        if *table == TableId::E2eeObject {
            objects += 1;
        }
        let value = PersistentRecordValue::decode(*table, plaintext)?;
        stripped
            .coordinator
            .admit_restored_with_backing(*table, key, &value, &stripped.backing);
    }
    stripped
        .coordinator
        .finish_restore_with_backing(stripped.backing.clone())?;
    let diagnostics = stripped.coordinator.owner_reconstruction;
    assert_eq!(diagnostics.reconstructed, objects);
    assert_eq!(
        (
            diagnostics.mismatched,
            diagnostics.orphaned,
            diagnostics.undecodable
        ),
        (0, 0, 0)
    );
    let strength = |class: RetentionClass| match class {
        RetentionClass::SecurityProof => 3,
        RetentionClass::Ordinary => 2,
        RetentionClass::Mailbox => 1,
        RetentionClass::Replay => 0,
    };
    for (id, account) in harness.coordinator.state.owners.accounts() {
        let rebuilt = stripped
            .coordinator
            .state
            .owners
            .account(id)
            .ok_or("account")?;
        assert_eq!(rebuilt.owners, account.owners);
        // Without its account an object keeps the retention its present
        // owners imply; the sealed account may remember a stronger one.
        assert!(
            strength(rebuilt.retention) <= strength(account.retention),
            "kind {} sealed {:?} rebuilt {:?} owners {:?}",
            account.kind,
            account.retention,
            rebuilt.retention,
            account
                .owners
                .keys()
                .map(
                    |k| String::from_utf8_lossy(k.get(..k.len().min(16)).unwrap_or(k)).into_owned()
                )
                .collect::<Vec<_>>()
        );
        assert_eq!((rebuilt.accepted_at, rebuilt.reconstructed), (0, true));
    }
    Ok(())
}

#[test]
fn a_barrier_part_owns_its_event_and_payload_objects() -> TestResult {
    let identity = BarrierIdentity {
        network_id: NETWORK,
        coordinator_server_id: COORDINATOR,
        coordinator_server_incarnation: [1; 16],
        coordinator_recovery_epoch: [2; 16],
        target_server_id: [3; 16],
        target_server_incarnation: [4; 16],
        mutation_id: [5; 16],
        coordinator_state_generation: 9,
        part_count: 2,
    };
    let part = BarrierPart {
        identity,
        stream: CrossProfileStream::Companion,
        part_index: 1,
        delivery_generation: 1,
        delivery_sequence: 7,
        event_id: [6; 16],
        event_object_id: [7; 32],
        encoded_event_object: vec![1, 2, 3],
        payload_object_id: Some([8; 32]),
        payload_object_bytes: 40,
    };
    let key = identity.part_key(1)?;
    let owned = owned_by(&key, BARRIER_ROW_KIND, &part.encode()?).map_err(code)?;
    assert_eq!(
        owned
            .iter()
            .map(|item| (item.object_id, item.retention, item.conversation))
            .collect::<Vec<_>>(),
        vec![
            ([7; 32], RetentionClass::Replay, None),
            ([8; 32], RetentionClass::Replay, None),
        ]
    );
    // A barrier head row of the same kind owns nothing.
    assert!(
        owned_by(&identity.head_key()?, BARRIER_ROW_KIND, &part.encode()?)
            .map_err(code)?
            .is_empty()
    );
    Ok(())
}

#[test]
fn re_putting_an_accounted_object_without_owners_changes_nothing() -> TestResult {
    let (mut coordinator, id, _) = shared_fixture()?;
    let before = coordinator.state.owners.clone();
    let bytes = shared_bytes()?;
    let owners = commit(&mut coordinator, vec![object_write(&bytes)?], false)?;
    assert!(owners.is_empty());
    assert!(coordinator.state.owners == before);
    assert!(coordinator.state.owners.account(&id).is_some());
    Ok(())
}

#[test]
fn an_object_may_have_at_most_the_reference_limit_of_owners() -> TestResult {
    let mut coordinator = coordinator();
    let bytes = object(Kind::CommitMls, 14, 32)?;
    let id = retain(&mut coordinator, &bytes)?;
    let ack_rows = |count: usize| -> TestResult<Vec<Write>> {
        (0..count)
            .map(|index| {
                let mut token = [0_u8; 32];
                token[..8].copy_from_slice(&(index as u64).to_be_bytes());
                row(
                    MAILBOX_ROW_KIND,
                    MailboxRow::ack_key(&DIGEST, &DEVICE, &token)?,
                    MailboxRow::Ack {
                        object_id: id,
                        acknowledged_at: 1,
                        retain_until: 2,
                    }
                    .encode()?,
                )
            })
            .collect()
    };
    let mut over = ack_rows(MAX_RECORD_REFERENCES + 1)?;
    assert_eq!(
        coordinator
            .stage_owners(&mut over, NOW, false, STATE_GENERATION)
            .err(),
        Some(E2eeReplyCode::RateLimited)
    );
    assert!(coordinator.state.owners.account(&id).is_none());
    let owners = commit(&mut coordinator, ack_rows(MAX_RECORD_REFERENCES)?, false)?;
    assert_eq!(owners.len(), 1);
    assert_eq!(
        coordinator
            .state
            .owners
            .account(&id)
            .map(|account| account.owners.len()),
        Some(MAX_RECORD_REFERENCES)
    );
    Ok(())
}

#[test]
fn a_foreign_reference_or_another_kind_discredits_a_stored_account() -> TestResult {
    let (source, id, owners) = shared_fixture()?;
    let object_bytes = source.state.objects.get(&id).ok_or("object")?.clone();
    let request_id = *source
        .state
        .objects
        .keys()
        .find(|key| **key != id)
        .ok_or("request object")?;
    let request_bytes = source
        .state
        .objects
        .get(&request_id)
        .ok_or("request")?
        .clone();
    let objects = [object_write(&object_bytes)?, object_write(&request_bytes)?];
    let rows = [
        record_row(id, 1, true)?,
        capability_row(id)?,
        ack_row(id)?,
        replay_row(request_id, id)?,
    ];
    let key = ObjectOwnerRow::key(&id)?;
    let (mine, other): (Vec<&Write>, Vec<&Write>) = owners
        .iter()
        .partition(|write| write.encoded_record().is_some_and(|(_, k, _)| *k == key));
    let mine = *mine.first().ok_or("owner row")?;
    let foreign_reference = RecordReference::new(
        TableId::E2eeObject,
        agenc_ircd_storage::e2ee_records::object_key(&id)?,
    )?;
    let foreign = reencode_owner(mine, |_, references| references.push(foreign_reference))?;
    let all: Vec<&Write> = objects
        .iter()
        .chain(&rows)
        .chain(std::iter::once(&foreign))
        .chain(other.iter().copied())
        .collect();
    let mut state = coordinator().state;
    let diagnostics = rebuild_from(&all)?.finish(&mut state);
    assert_eq!((diagnostics.undecodable, diagnostics.reconstructed), (1, 1));
    let account = state.owners.account(&id).ok_or("account")?;
    assert_eq!((account.accepted_at, account.owners.len()), (0, 4));

    let other_kind = reencode_owner(mine, |row, _| row.kind = Kind::DeviceRoster.value())?;
    let all: Vec<&Write> = objects
        .iter()
        .chain(&rows)
        .chain(std::iter::once(&other_kind))
        .chain(other.iter().copied())
        .collect();
    let mut state = coordinator().state;
    let diagnostics = rebuild_from(&all)?.finish(&mut state);
    assert_eq!(diagnostics.mismatched, 1);
    let account = state.owners.account(&id).ok_or("account")?;
    assert_eq!(
        (account.accepted_at, account.kind),
        (0, Kind::CommitMls.value())
    );
    Ok(())
}
