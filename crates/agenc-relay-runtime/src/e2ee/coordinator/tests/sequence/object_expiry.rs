#![forbid(unsafe_code)]

//! Bounded physical deletion of expired unowned objects (ENC-09, companion
//! 15 and 16): the trusted retention state alone chooses a body, a page is
//! bounded by rows and bytes, the continuation is durable, and a reference
//! accepted after the capture keeps its object.

use super::super::{COORDINATOR, Harness, NETWORK, NOW, STATE_GENERATION, TestResult, wire_raw};
use crate::budget::{BackingReservationPort, MemoryBudget};
use crate::e2ee::coordinator::object_expiry::{
    MAX_EXPIRY_ACCOUNTS, MAX_EXPIRY_BYTES, Prepared, Progress,
};
use crate::e2ee::coordinator::{CompanionCoordinator, CompanionFault, request};
use crate::state_core::durable::AccountServiceDurableWrite as Write;
use agenc_relay_e2ee::limits::{
    ACKED_E2EE_EVENT_REPLAY_TARGET_SECONDS, SEQUENCER_RECORD_RETENTION_SECONDS,
    WELCOME_RETENTION_SECONDS,
};
use agenc_relay_e2ee::object::ArcWireObjectKind as Kind;
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;
use agenc_relay_storage::e2ee_records::{
    EXPIRY_PROGRESS_ROW_KIND, MAILBOX_ROW_KIND, MailboxRow, OBJECT_RECORD_KIND,
    ObjectExpiryProgressRow, ObjectOwnerRow, REPLAY_ROW_KIND, ReplayKey, ReplayRow, RetentionClass,
    SEQUENCER_ROW_KIND, SequencerRow, UNDATED_SECOND,
};
use agenc_relay_storage::{PersistentRecordValue, StoredKey, TableId};
use agenc_relay_types::ServerId;

const CONVERSATION: [u8; 32] = [71; 32];
const DIGEST: [u8; 32] = [72; 32];
const DEVICE: [u8; 16] = [73; 16];
const TOKEN: [u8; 32] = [74; 32];

/// The trusted second every fixture batch is admitted with, and the first
/// second at which an ordinary unowned object may be collected.
const ORDINARY_DUE: u64 = NOW + SEQUENCER_RECORD_RETENTION_SECONDS;

fn code(code: E2eeReplyCode) -> Box<dyn std::error::Error> {
    format!("refused with {code:?}").into()
}

fn coordinator() -> CompanionCoordinator {
    CompanionCoordinator::new(
        NETWORK,
        ServerId::from_bytes(COORDINATOR),
        "coordinator.example".into(),
    )
}

fn backing() -> BackingReservationPort {
    BackingReservationPort::new(crate::sync::Arc::new(MemoryBudget::new(64 * 1024 * 1024)))
}

fn object(seed: u8, len: usize) -> TestResult<Vec<u8>> {
    wire_raw(Kind::CommitMls, vec![seed; len])
}

fn retain(coordinator: &mut CompanionCoordinator, bytes: &[u8]) -> TestResult<[u8; 32]> {
    CompanionCoordinator::retain_object(&mut coordinator.state, bytes.to_vec()).map_err(code)
}

fn row(kind: u16, key: StoredKey, body: Vec<u8>) -> TestResult<Write> {
    request::state_row(TableId::E2eeState, kind, key, body).map_err(code)
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

/// A mailbox acknowledgement whose own `retain_until` is already in the
/// past: nothing the uploader supplies may accelerate collection.
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

fn replay_row(request_object: [u8; 32]) -> TestResult<Write> {
    row(
        REPLAY_ROW_KIND,
        replay_key()?,
        ReplayRow {
            request_id: [1; 16],
            request_object_id: request_object,
            result_object_id: None,
            response_object_ids: Vec::new(),
            security_mutation: false,
            retain_until: 0,
        }
        .encode()?,
    )
}

fn delete(key: StoredKey) -> TestResult<Write> {
    Ok(Write::delete(TableId::E2eeState, key)?)
}

/// Stages and installs one batch at the trusted second `now`, as the
/// coordinator does at commit.
fn commit_at(
    coordinator: &mut CompanionCoordinator,
    mut writes: Vec<Write>,
    now: u64,
) -> TestResult {
    let staged = coordinator
        .stage_owners(&mut writes, now, false, STATE_GENERATION)
        .map_err(code)?;
    staged.apply(&mut coordinator.state);
    Ok(())
}

/// Retains `bytes`, names it from the record row of `sequence`, then
/// deletes that row, so the account is unowned and retired at `NOW`.
fn retired_object(
    coordinator: &mut CompanionCoordinator,
    bytes: &[u8],
    sequence: u64,
) -> TestResult<[u8; 32]> {
    let id = retain(coordinator, bytes)?;
    commit_at(coordinator, vec![record_row(id, sequence, false)?], NOW)?;
    commit_at(coordinator, vec![delete(record_key(sequence)?)?], NOW)?;
    Ok(id)
}

fn capture(
    coordinator: &CompanionCoordinator,
    progress: Progress,
    now: u64,
) -> Result<Prepared, CompanionFault> {
    Prepared::capture(coordinator, progress, now, &backing())
}

/// [`sweep`], returning the durable writes the pass staged instead.
pub(super) fn sweep_writes(
    coordinator: &mut CompanionCoordinator,
    now: u64,
) -> TestResult<Vec<Write>> {
    let progress = coordinator.expiry_progress();
    let prepared = capture(coordinator, progress, now).map_err(|fault| format!("{fault}"))?;
    let mut writes = prepared.writes(STATE_GENERATION)?;
    let staged = coordinator
        .stage_owners(&mut writes, now, false, STATE_GENERATION)
        .map_err(code)?;
    prepared
        .apply(coordinator)
        .map_err(|fault| format!("{fault}"))?;
    staged.apply(&mut coordinator.state);
    Ok(writes)
}

/// Captures one pass at `now`, stages it as the worker does, and publishes
/// its receipt. Returns the objects the pass deleted.
pub(super) fn sweep(coordinator: &mut CompanionCoordinator, now: u64) -> TestResult<usize> {
    let progress = coordinator.expiry_progress();
    let prepared = capture(coordinator, progress, now).map_err(|fault| format!("{fault}"))?;
    let mut writes = prepared.writes(STATE_GENERATION)?;
    let before = writes.len();
    let staged = coordinator
        .stage_owners(&mut writes, now, false, STATE_GENERATION)
        .map_err(code)?;
    // A collection batch names no new owner, so the ledger writes no row.
    assert_eq!(writes.len(), before);
    let deleted = (writes.len() - 1) / 2;
    prepared
        .apply(coordinator)
        .map_err(|fault| format!("{fault}"))?;
    staged.apply(&mut coordinator.state);
    Ok(deleted)
}

#[test]
fn an_expired_unowned_object_is_deleted_only_at_its_trusted_retention_boundary() -> TestResult {
    let bytes = object(11, 64)?;
    for (now, expected) in [
        (ORDINARY_DUE - 1, 0),
        (ORDINARY_DUE, 1),
        (ORDINARY_DUE + 1, 1),
    ] {
        let mut coordinator = coordinator();
        let id = retired_object(&mut coordinator, &bytes, 1)?;
        assert_eq!(
            coordinator.state.owners.account(&id).map(|a| a.retired_at),
            Some(Some(NOW))
        );
        assert_eq!(sweep(&mut coordinator, now)?, expected, "at {now}");
        assert_eq!(
            coordinator.state.owners.account(&id).is_none(),
            expected == 1
        );
        assert_eq!(coordinator.state.objects.contains_key(&id), expected == 0);
    }
    Ok(())
}

#[test]
fn a_still_owned_object_is_never_chosen_and_stays_byte_identical() -> TestResult {
    let mut coordinator = coordinator();
    let owned = object(12, 96)?;
    let owned_id = retain(&mut coordinator, &owned)?;
    commit_at(&mut coordinator, vec![record_row(owned_id, 1, true)?], NOW)?;
    let retired = retired_object(&mut coordinator, &object(13, 48)?, 2)?;
    assert_eq!(sweep(&mut coordinator, ORDINARY_DUE)?, 1);
    assert!(coordinator.state.owners.account(&retired).is_none());
    assert_eq!(coordinator.state.objects.get(&owned_id), Some(&owned));
    assert!(coordinator.state.owners.account(&owned_id).is_some());
    Ok(())
}

#[test]
fn each_retention_class_waits_exactly_its_published_window() -> TestResult {
    let cases = [
        (RetentionClass::Mailbox, WELCOME_RETENTION_SECONDS),
        (
            RetentionClass::Replay,
            ACKED_E2EE_EVENT_REPLAY_TARGET_SECONDS,
        ),
        (
            RetentionClass::SecurityProof,
            SEQUENCER_RECORD_RETENTION_SECONDS,
        ),
    ];
    for (class, window) in cases {
        let mut coordinator = coordinator();
        let bytes = object(14, 80)?;
        let id = retain(&mut coordinator, &bytes)?;
        let (owner, key) = match class {
            RetentionClass::Mailbox => (ack_row(id)?, ack_key()?),
            RetentionClass::Replay => (replay_row(id)?, replay_key()?),
            _ => (record_row(id, 1, true)?, record_key(1)?),
        };
        commit_at(&mut coordinator, vec![owner], NOW)?;
        assert_eq!(
            coordinator.state.owners.account(&id).map(|a| a.retention),
            Some(class)
        );
        commit_at(&mut coordinator, vec![delete(key)?], NOW)?;
        assert_eq!(sweep(&mut coordinator, NOW + window - 1)?, 0, "{class:?}");
        assert_eq!(sweep(&mut coordinator, NOW + window)?, 1, "{class:?}");
    }
    Ok(())
}

#[test]
fn an_undated_or_unaged_account_is_retained_rather_than_collected() -> TestResult {
    // A batch admitted without a trusted clock retires at UNDATED_SECOND;
    // an account rebuilt without evidence carries no acceptance second.
    let mut coordinator = coordinator();
    let id = retain(&mut coordinator, &object(15, 64)?)?;
    commit_at(&mut coordinator, vec![record_row(id, 1, false)?], NOW)?;
    commit_at(&mut coordinator, vec![delete(record_key(1)?)?], 0)?;
    assert_eq!(
        coordinator.state.owners.account(&id).map(|a| a.retired_at),
        Some(Some(UNDATED_SECOND))
    );
    assert_eq!(sweep(&mut coordinator, u64::MAX)?, 0);
    assert!(coordinator.state.objects.contains_key(&id));

    let mut rebuilt = coordinator;
    let account = rebuilt.state.owners.account(&id).ok_or("account")?.clone();
    let mut unaged = account.clone();
    unaged.accepted_at = 0;
    unaged.retired_at = Some(NOW);
    rebuilt.state.owners.install(id, unaged);
    assert_eq!(sweep(&mut rebuilt, u64::MAX)?, 0);
    assert!(rebuilt.state.objects.contains_key(&id));
    Ok(())
}

#[test]
fn no_uploaded_or_row_supplied_time_can_accelerate_collection() -> TestResult {
    // The acknowledgement row's own `retain_until` is 2 seconds; only the
    // trusted mailbox window measured from the ledger retirement counts.
    let mut coordinator = coordinator();
    let id = retain(&mut coordinator, &object(16, 32)?)?;
    commit_at(&mut coordinator, vec![ack_row(id)?], NOW)?;
    commit_at(&mut coordinator, vec![delete(ack_key()?)?], NOW)?;
    assert_eq!(sweep(&mut coordinator, NOW + 3)?, 0);
    assert_eq!(sweep(&mut coordinator, NOW + WELCOME_RETENTION_SECONDS)?, 1);
    Ok(())
}

#[test]
fn a_reference_accepted_after_the_capture_keeps_its_object() -> TestResult {
    let mut coordinator = coordinator();
    let bytes = object(17, 64)?;
    let id = retired_object(&mut coordinator, &bytes, 1)?;
    let prepared = capture(&coordinator, Progress::default(), ORDINARY_DUE)
        .map_err(|fault| format!("{fault}"))?;
    assert!(!prepared.is_empty());
    // The concurrent acquisition wins: it reinstates an owner and clears
    // the retirement, so the pass refuses its own receipt.
    commit_at(
        &mut coordinator,
        vec![record_row(id, 9, false)?],
        ORDINARY_DUE,
    )?;
    assert_eq!(
        prepared.apply(&mut coordinator),
        Err(CompanionFault::Storage)
    );
    assert_eq!(coordinator.state.objects.get(&id), Some(&bytes));
    assert!(coordinator.state.owners.account(&id).is_some());
    // A capture taken now sees the new owner and chooses nothing.
    assert_eq!(sweep(&mut coordinator, ORDINARY_DUE)?, 0);
    Ok(())
}

#[test]
fn a_replaced_body_under_the_same_account_refuses_the_receipt() -> TestResult {
    let mut coordinator = coordinator();
    let bytes = object(18, 64)?;
    let id = retired_object(&mut coordinator, &bytes, 1)?;
    let prepared = capture(&coordinator, Progress::default(), ORDINARY_DUE)
        .map_err(|fault| format!("{fault}"))?;
    // A resident body that is no longer the exact accounted object breaks
    // the identity revalidation, whatever the account still says.
    coordinator.state.objects.insert(id, object(19, 64)?);
    assert_eq!(
        prepared.apply(&mut coordinator),
        Err(CompanionFault::Storage)
    );
    Ok(())
}

#[test]
fn one_pass_is_bounded_by_rows_and_two_passes_finish_without_skipping() -> TestResult {
    let mut coordinator = coordinator();
    let total = MAX_EXPIRY_ACCOUNTS + 5;
    let mut ids = Vec::new();
    for index in 0..total {
        let seed = u8::try_from(index)?;
        let bytes = wire_raw(Kind::CommitMls, vec![seed; 32 + index])?;
        ids.push(retired_object(
            &mut coordinator,
            &bytes,
            u64::try_from(index)?,
        )?);
    }
    assert_eq!(sweep(&mut coordinator, ORDINARY_DUE)?, MAX_EXPIRY_ACCOUNTS);
    let progress = coordinator.expiry_progress();
    assert!(progress.cursor.is_some());
    assert_eq!(progress.passes, 0);
    assert_eq!(
        progress.deleted_objects,
        u64::try_from(MAX_EXPIRY_ACCOUNTS)?
    );
    assert_eq!(sweep(&mut coordinator, ORDINARY_DUE)?, 5);
    let finished = coordinator.expiry_progress();
    assert_eq!(finished.cursor, None);
    assert_eq!(finished.passes, 1);
    assert_eq!(finished.deleted_objects, u64::try_from(total)?);
    // Nothing is deleted twice and nothing is left behind.
    assert!(
        ids.iter()
            .all(|id| !coordinator.state.objects.contains_key(id))
    );
    assert_eq!(coordinator.state.owners.total_bytes(), 0);
    assert_eq!(coordinator.state.object_bytes, 0);
    assert_eq!(sweep(&mut coordinator, ORDINARY_DUE)?, 0);
    assert_eq!(
        coordinator.expiry_progress().deleted_objects,
        u64::try_from(total)?
    );
    Ok(())
}

#[test]
fn the_byte_budget_stops_a_pass_before_its_cursor_names_the_account() -> TestResult {
    let mut coordinator = coordinator();
    let body = 1_000_000;
    let encoded = u64::try_from(wire_raw(Kind::RootIdentityChain, vec![0; body])?.len())?;
    let per_pass = usize::try_from(MAX_EXPIRY_BYTES / encoded)?;
    assert!((2..MAX_EXPIRY_ACCOUNTS).contains(&per_pass));
    let mut ids = Vec::new();
    for index in 0..=per_pass {
        let seed = u8::try_from(index)?;
        ids.push(retired_object(
            &mut coordinator,
            &wire_raw(Kind::RootIdentityChain, vec![seed; body])?,
            u64::try_from(index)?,
        )?);
    }
    assert_eq!(sweep(&mut coordinator, ORDINARY_DUE)?, per_pass);
    let progress = coordinator.expiry_progress();
    assert!(progress.deleted_bytes <= MAX_EXPIRY_BYTES);
    // The halted pass never advanced its cursor past the account it
    // refused, so the next pass sees exactly that account again.
    assert_eq!(progress.passes, 0);
    assert!(progress.cursor.is_some());
    assert_eq!(sweep(&mut coordinator, ORDINARY_DUE)?, 1);
    assert!(
        ids.iter()
            .all(|id| !coordinator.state.objects.contains_key(id))
    );
    Ok(())
}

#[test]
fn a_pass_stages_the_body_its_account_and_the_continuation_as_one_batch() -> TestResult {
    let mut coordinator = coordinator();
    let id = retired_object(&mut coordinator, &object(21, 64)?, 1)?;
    let prepared = capture(&coordinator, Progress::default(), ORDINARY_DUE)
        .map_err(|fault| format!("{fault}"))?;
    let writes = prepared.writes(STATE_GENERATION)?;
    assert_eq!(writes.len(), 3);
    let deletes: Vec<(TableId, Vec<u8>)> = writes
        .iter()
        .filter_map(|write| match write {
            Write::Delete { table, key } => Some((*table, key.as_bytes().to_vec())),
            Write::Put { .. } => None,
        })
        .collect();
    assert!(deletes.contains(&(TableId::E2eeObject, id.to_vec())));
    assert!(deletes.contains(&(
        TableId::E2eeState,
        ObjectOwnerRow::key(&id)?.as_bytes().to_vec()
    )));
    let progress = writes.last().ok_or("progress row")?;
    let (table, key, encoded) = progress.encoded_record().ok_or("progress put")?;
    assert_eq!(table, TableId::E2eeState);
    assert_eq!(key.as_bytes(), ObjectExpiryProgressRow::key()?.as_bytes());
    let value = PersistentRecordValue::decode(TableId::E2eeState, encoded)?;
    assert_eq!(value.record_kind(), EXPIRY_PROGRESS_ROW_KIND);
    let row = ObjectExpiryProgressRow::decode(value.body())?;
    assert_eq!((row.cursor, row.passes, row.deleted_objects), (None, 1, 1));
    Ok(())
}

#[test]
fn the_resident_body_is_released_only_by_the_receipt() -> TestResult {
    let mut coordinator = coordinator();
    let bytes = object(22, 128)?;
    let id = retired_object(&mut coordinator, &bytes, 1)?;
    let charged = coordinator.state.object_bytes;
    let accounted = coordinator.state.owners.total_bytes();
    let prepared = capture(&coordinator, Progress::default(), ORDINARY_DUE)
        .map_err(|fault| format!("{fault}"))?;
    let _writes = prepared.writes(STATE_GENERATION)?;
    // Staging alone publishes nothing.
    assert_eq!(coordinator.state.objects.get(&id), Some(&bytes));
    assert_eq!(coordinator.state.object_bytes, charged);
    assert_eq!(coordinator.state.owners.total_bytes(), accounted);
    assert_eq!(coordinator.expiry_progress(), Progress::default());
    prepared
        .apply(&mut coordinator)
        .map_err(|fault| format!("{fault}"))?;
    assert!(!coordinator.state.objects.contains_key(&id));
    assert_eq!(coordinator.state.object_bytes, charged - bytes.len());
    assert_eq!(coordinator.state.owners.total_bytes(), 0);
    assert_eq!(coordinator.expiry_progress().deleted_bytes, accounted);
    Ok(())
}

#[test]
fn a_restart_resumes_at_the_continuation_the_last_committed_pass_wrote() -> TestResult {
    // The row a real pass staged, replayed through a startup reload.
    let mut source = coordinator();
    for index in 0..3 {
        let seed = u8::try_from(index)?;
        retired_object(
            &mut source,
            &wire_raw(Kind::CommitMls, vec![seed; 48 + index])?,
            u64::try_from(index)?,
        )?;
    }
    let prepared =
        capture(&source, Progress::default(), ORDINARY_DUE).map_err(|fault| format!("{fault}"))?;
    let staged = prepared.writes(STATE_GENERATION)?;
    let expected = prepared.next_progress();
    prepared
        .apply(&mut source)
        .map_err(|fault| format!("{fault}"))?;
    assert_eq!(source.expiry_progress(), expected);

    let mut harness = Harness::new()?;
    let progress_row = staged.last().ok_or("progress row")?;
    harness.apply_logical_write(progress_row)?;
    let reopened = harness.reloaded()?;
    assert_eq!(reopened.coordinator.expiry_progress(), expected);
    assert!(reopened.coordinator.owner_reconstruction.is_clean());
    Ok(())
}

#[test]
fn a_resumed_continuation_skips_the_accounts_the_committed_pass_examined() -> TestResult {
    let mut coordinator = coordinator();
    let mut ids = Vec::new();
    for index in 0..4 {
        let seed = u8::try_from(index)?;
        ids.push(retired_object(
            &mut coordinator,
            &wire_raw(Kind::CommitMls, vec![seed; 40 + index])?,
            u64::try_from(index)?,
        )?);
    }
    // A continuation naming the second account resumes after it.
    let mut ordered: Vec<[u8; 32]> = ids.clone();
    ordered.sort_unstable();
    let resumed = Progress {
        cursor: ordered.get(1).copied(),
        passes: 7,
        deleted_objects: 2,
        deleted_bytes: 64,
    };
    let prepared =
        capture(&coordinator, resumed, ORDINARY_DUE).map_err(|fault| format!("{fault}"))?;
    prepared
        .apply(&mut coordinator)
        .map_err(|fault| format!("{fault}"))?;
    let remaining: Vec<[u8; 32]> = ordered
        .iter()
        .copied()
        .filter(|id| coordinator.state.objects.contains_key(id))
        .collect();
    assert_eq!(remaining, ordered.get(..2).ok_or("prefix")?.to_vec());
    let progress = coordinator.expiry_progress();
    assert_eq!((progress.passes, progress.deleted_objects), (8, 4));
    Ok(())
}

#[test]
fn an_object_record_write_is_never_produced_by_a_collection_pass() -> TestResult {
    let mut coordinator = coordinator();
    let _id = retired_object(&mut coordinator, &object(23, 64)?, 1)?;
    let prepared = capture(&coordinator, Progress::default(), ORDINARY_DUE)
        .map_err(|fault| format!("{fault}"))?;
    let writes = prepared.writes(STATE_GENERATION)?;
    for write in &writes {
        let Some((table, _, encoded)) = write.encoded_record() else {
            continue;
        };
        let value = PersistentRecordValue::decode(table, encoded)?;
        assert_ne!(value.record_kind(), OBJECT_RECORD_KIND);
    }
    Ok(())
}
