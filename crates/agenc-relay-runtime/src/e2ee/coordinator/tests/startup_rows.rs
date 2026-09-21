//! Startup row admission collects only rows whose key matches their body, and
//! the retained-object index ignores objects it cannot decode.
#![forbid(unsafe_code)]

use super::*;
use agenc_relay_e2ee::tls::TlsEncode;
use agenc_relay_storage::e2ee_records::origin::OriginSequenceKey;
use agenc_relay_storage::e2ee_records::{
    CandidateState, RECOVERY_RECORD_ROW_KIND, RECOVERY_SUBMISSION_ROW_KIND, RecoveryOutcome,
    RecoveryRecordRow, RecoverySubmissionRow, ReplayKey,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CONVERSATION: [u8; 32] = [9; 32];

fn state_value(kind: u16, body: Vec<u8>) -> TestResult<PersistentRecordValue> {
    Ok(PersistentRecordValue::new(
        TableId::E2eeState,
        kind,
        1,
        0,
        None,
        Vec::new(),
        body,
    )?)
}

/// A well-formed key of another row family: no parser of the family under
/// test accepts it.
fn foreign_key() -> TestResult<StoredKey> {
    Ok(AttachRow::key(&[7; 32], &[8; 16])?)
}

fn route_row() -> RouteRow {
    RouteRow {
        route_state: vec![1, 2, 3],
        lifecycle: RowLifecycle::Active,
        binding_id: [1; 32],
        lock_id: [2; 32],
        accepted_state_id: [3; 32],
        sequencer_head_id: [4; 32],
        route_sequence: 0,
        close_id: None,
        predecessor_close_id: None,
        recovery_gate: false,
        stored_bytes: 0,
        sequencer_credential_id: None,
        blocked_credential_id: None,
    }
}

fn admit_state(restore: &mut Restore, key: &StoredKey, kind: u16, body: Vec<u8>) -> TestResult {
    restore.admit(TableId::E2eeState, key, &state_value(kind, body)?);
    Ok(())
}

#[test]
fn route_row_is_collected_only_under_a_route_key() -> TestResult {
    let mut restore = Restore::default();
    let body = route_row().encode()?;
    admit_state(&mut restore, &foreign_key()?, ROUTE_ROW_KIND, body.clone())?;
    assert!(restore.routes.is_empty());
    admit_state(
        &mut restore,
        &RouteRow::key(&CONVERSATION)?,
        ROUTE_ROW_KIND,
        body,
    )?;
    assert_eq!(restore.routes.get(&CONVERSATION), Some(&route_row()));
    Ok(())
}

#[test]
fn rows_of_other_tables_are_not_collected() -> TestResult {
    let mut restore = Restore::default();
    let value = state_value(ROUTE_ROW_KIND, route_row().encode()?)?;
    restore.admit(TableId::Account, &RouteRow::key(&CONVERSATION)?, &value);
    assert!(restore.routes.is_empty());
    Ok(())
}

fn record_row() -> SequencerRow {
    SequencerRow::Record {
        record_object_id: [1; 32],
        record_id: [2; 32],
        record_kind: CANDIDATE_RECORD,
        terminal: false,
        security_proof: false,
        predecessor_record_id: [3; 32],
    }
}

#[test]
fn sequencer_record_is_collected_only_under_a_record_key() -> TestResult {
    let mut restore = Restore::default();
    let body = record_row().encode()?;
    admit_state(
        &mut restore,
        &foreign_key()?,
        SEQUENCER_ROW_KIND,
        body.clone(),
    )?;
    assert!(restore.records.is_empty());
    let key = SequencerRow::record_key(&CONVERSATION, 5)?;
    admit_state(&mut restore, &key, SEQUENCER_ROW_KIND, body)?;
    let row = restore.records.get(&(CONVERSATION, 5)).ok_or("record")?;
    assert_eq!(row.record_id, [2; 32]);
    assert_eq!(row.predecessor_record_id, [3; 32]);
    assert!(!row.terminal);
    Ok(())
}

#[test]
fn sequencer_candidate_is_collected_only_under_a_candidate_key() -> TestResult {
    let mut restore = Restore::default();
    let body = SequencerRow::Candidate {
        candidate_id: [1; 32],
        commit_object_id: [2; 32],
        route_sequence: 4,
        candidate_sequence: 6,
        attempts: 1,
        state: CandidateState::Active,
        terminal_id: None,
    }
    .encode()?;
    admit_state(
        &mut restore,
        &foreign_key()?,
        SEQUENCER_ROW_KIND,
        body.clone(),
    )?;
    assert!(restore.candidates.is_empty());
    let key = SequencerRow::candidate_key(&CONVERSATION, 3)?;
    admit_state(&mut restore, &key, SEQUENCER_ROW_KIND, body)?;
    let row = restore
        .candidates
        .get(&(CONVERSATION, 3))
        .ok_or("candidate")?;
    assert_eq!(
        (row.route_sequence, row.candidate_sequence),
        (4, 6),
        "the slot position comes from the row body"
    );
    Ok(())
}

#[test]
fn sequencer_proof_is_collected_only_under_a_proof_key() -> TestResult {
    let mut restore = Restore::default();
    let body = SequencerRow::Proof {
        role: ProofRole::Ack,
        object_id: [5; 32],
        slot: 0,
    }
    .encode()?;
    admit_state(
        &mut restore,
        &foreign_key()?,
        SEQUENCER_ROW_KIND,
        body.clone(),
    )?;
    assert!(restore.proofs.is_empty());
    let key = SequencerRow::proof_key(ProofRole::Ack, &CONVERSATION, &[6; 32], &[7; 32], &[8; 16])?;
    admit_state(&mut restore, &key, SEQUENCER_ROW_KIND, body)?;
    let (parts, object_id) = restore.proofs.first().ok_or("proof")?;
    assert_eq!(parts.subject_id, [6; 32]);
    assert_eq!(*object_id, [5; 32]);
    Ok(())
}

#[test]
fn sequencer_policy_is_collected_only_under_a_policy_key() -> TestResult {
    let mut restore = Restore::default();
    let body = SequencerRow::Policy {
        object_id: [5; 32],
        generation: 2,
        previous_policy_id: [4; 32],
    }
    .encode()?;
    admit_state(
        &mut restore,
        &foreign_key()?,
        SEQUENCER_ROW_KIND,
        body.clone(),
    )?;
    assert!(restore.policies.is_empty());
    let key = SequencerRow::policy_key(&CONVERSATION, &[6; 32])?;
    admit_state(&mut restore, &key, SEQUENCER_ROW_KIND, body)?;
    let row = restore
        .policies
        .get(&(CONVERSATION, [6; 32]))
        .ok_or("policy")?;
    assert_eq!((row.object_id, row.generation), ([5; 32], 2));
    Ok(())
}

fn submission_row() -> RecoverySubmissionRow {
    RecoverySubmissionRow {
        account_id: [1; 24],
        device_id: [2; 16],
        element_kind: 1,
        element_object_kind: 1,
        element_object_id: [3; 32],
        route_sequence: 1,
        predecessor_record_id: [4; 32],
        accepted_at: 10,
        submission_object_id: [5; 32],
        element_retained: false,
        outcome: RecoveryOutcome::Open,
    }
}

#[test]
fn recovery_submission_is_collected_only_under_a_submission_key() -> TestResult {
    let mut restore = Restore::default();
    let body = submission_row().encode()?;
    admit_state(
        &mut restore,
        &foreign_key()?,
        RECOVERY_SUBMISSION_ROW_KIND,
        body.clone(),
    )?;
    assert!(restore.recovery.submissions.is_empty());
    let key = RecoverySubmissionRow::key(&CONVERSATION, &[6; 32])?;
    admit_state(&mut restore, &key, RECOVERY_SUBMISSION_ROW_KIND, body)?;
    let rows = restore
        .recovery
        .submissions
        .get(&CONVERSATION)
        .ok_or("conversation")?;
    assert_eq!(rows.get(&[6; 32]), Some(&submission_row()));
    Ok(())
}

#[test]
fn recovery_record_is_collected_only_under_a_recovery_record_key() -> TestResult {
    let mut restore = Restore::default();
    let row = RecoveryRecordRow {
        record_id: [1; 32],
        record_object_id: [2; 32],
        predecessor_record_id: [3; 32],
        record_kind: 1,
        submission_id: [4; 32],
    };
    let body = row.encode()?;
    admit_state(
        &mut restore,
        &foreign_key()?,
        RECOVERY_RECORD_ROW_KIND,
        body.clone(),
    )?;
    assert!(restore.recovery.records.is_empty());
    let key = RecoveryRecordRow::key(&CONVERSATION, 8)?;
    admit_state(&mut restore, &key, RECOVERY_RECORD_ROW_KIND, body)?;
    let rows = restore
        .recovery
        .records
        .get(&CONVERSATION)
        .ok_or("conversation")?;
    assert_eq!(rows.get(&8), Some(&row));
    Ok(())
}

#[test]
fn mailbox_row_under_a_foreign_key_fails_the_mailbox_restore() -> TestResult {
    let mut restore = Restore::default();
    let body = MailboxRow::Ack {
        object_id: [1; 32],
        acknowledged_at: 5,
        retain_until: 9,
    }
    .encode()?;
    admit_state(&mut restore, &foreign_key()?, MAILBOX_ROW_KIND, body)?;
    assert!(restore.mailbox.is_empty());
    let mut mailboxes = agenc_relay_domain::e2ee::mailbox::Mailboxes::default();
    assert_eq!(
        restore.mailbox_sequences.apply(&mut mailboxes),
        Err(super::super::CompanionFault::Storage)
    );
    Ok(())
}

#[test]
fn origin_sequence_rows_are_kept_apart_from_replay_rows() -> TestResult {
    let mut restore = Restore::default();
    let parts = OriginSequenceKey {
        home_server_id: [1; 16],
        server_incarnation: [2; 16],
        origin_id: [3; 16],
    };
    let row = OriginSequenceRow {
        origin_generation: 4,
        next_sequence: 5,
    };
    admit_state(
        &mut restore,
        &OriginSequenceRow::key(&parts)?,
        REPLAY_ROW_KIND,
        row.encode()?,
    )?;
    assert_eq!(restore.origin_sequences.len(), 1);
    assert!(restore.replays.is_empty());
    Ok(())
}

// ---------------------------------------------------------------------------
// Replays and origin sequences.

fn replay_row(result: Option<[u8; 32]>) -> ReplayRow {
    ReplayRow {
        request_id: [1; 16],
        request_object_id: [2; 32],
        result_object_id: result,
        response_object_ids: Vec::new(),
        security_mutation: false,
        retain_until: 900,
    }
}

fn replay_key() -> ReplayKey {
    ReplayKey {
        home_server_id: [1; 16],
        server_incarnation: [2; 16],
        origin_id: [3; 16],
        origin_generation: 0,
        operation_sequence: 7,
    }
}

#[test]
fn replay_row_under_a_foreign_key_is_not_restored() -> TestResult {
    let mut state = CompanionState::default();
    let rows = vec![
        (foreign_key()?, replay_row(None)),
        (ReplayRow::key(&replay_key())?, replay_row(None)),
    ];
    restore_replays(&mut state, rows, None)?;
    assert_eq!(state.replays.len(), 1);
    assert_eq!(state.replays.get(&replay_key()), Some(&replay_row(None)));
    Ok(())
}

#[test]
fn replay_row_whose_result_object_is_absent_restores_without_a_result() -> TestResult {
    let mut state = CompanionState::default();
    let rows = vec![(ReplayRow::key(&replay_key())?, replay_row(Some([9; 32])))];
    // No backing port is needed: nothing is captured for an absent result.
    restore_replays(&mut state, rows, None)?;
    assert_eq!(state.replays.len(), 1);
    Ok(())
}

#[test]
fn replay_row_with_a_retained_result_needs_a_backing_port() -> TestResult {
    let mut state = CompanionState::default();
    state.objects.insert([9; 32], vec![1, 2, 3]);
    let rows = vec![(ReplayRow::key(&replay_key())?, replay_row(Some([9; 32])))];
    assert_eq!(
        restore_replays(&mut state, rows, None),
        Err(super::super::CompanionFault::Ceiling)
    );
    assert!(state.replays.is_empty());
    Ok(())
}

#[test]
fn origin_sequence_row_under_a_foreign_key_is_not_restored() -> TestResult {
    let mut state = CompanionState::default();
    let parts = OriginSequenceKey {
        home_server_id: [1; 16],
        server_incarnation: [2; 16],
        origin_id: [3; 16],
    };
    let row = OriginSequenceRow {
        origin_generation: 4,
        next_sequence: 5,
    };
    let rows = vec![
        (foreign_key()?, row),
        (OriginSequenceRow::key(&parts)?, row),
    ];
    restore_origin_sequences(&mut state, rows);
    assert_eq!(state.origin_sequences.len(), 1);
    let key = CompanionOriginKey {
        home_server_id: [1; 16],
        server_incarnation: [2; 16],
        origin_id: [3; 16],
    };
    assert_eq!(state.origin_sequences.get(&key), Some(&row));
    Ok(())
}

// ---------------------------------------------------------------------------
// Retained-object index.

fn raw_object(kind: ArcWireObjectKind, body: Vec<u8>) -> TestResult<Vec<u8>> {
    Ok(ArcWireObject::new(kind, body)?.encode()?)
}

#[test]
fn decode_body_refuses_an_object_of_another_kind() -> TestResult {
    let bytes = raw_object(ArcWireObjectKind::WelcomeMls, vec![0; 8])?;
    let decoded: Option<ArcPolicy> = decode_body(&bytes, ArcWireObjectKind::Policy, 1 << 16);
    assert!(decoded.is_none());
    Ok(())
}

#[test]
fn index_skips_retained_bytes_that_are_not_a_wire_object() {
    let mut state = CompanionState::default();
    state.objects.insert([1; 32], vec![0xff]);
    let index = ObjectIndex::build(&state);
    assert!(index.bindings.is_empty());
    assert!(index.policies.is_empty());
    assert!(index.terminal_requests.is_empty());
}

#[test]
fn index_skips_indexed_kinds_whose_body_does_not_decode() -> TestResult {
    let mut state = CompanionState::default();
    let kinds = [
        ArcWireObjectKind::ConversationBinding,
        ArcWireObjectKind::FinalizationRequest,
        ArcWireObjectKind::AbortRequest,
        ArcWireObjectKind::ReinitActivationRequest,
        ArcWireObjectKind::ReinitAbortRequest,
        ArcWireObjectKind::Policy,
        ArcWireObjectKind::DeviceRoster,
    ];
    for (marker, kind) in (1_u8..).zip(kinds) {
        state
            .objects
            .insert([marker; 32], raw_object(kind, vec![marker; 3])?);
    }
    let index = ObjectIndex::build(&state);
    assert!(index.bindings.is_empty());
    assert!(index.policies.is_empty());
    assert!(index.rosters.is_empty());
    assert!(index.proofs.is_empty());
    assert!(index.terminal_requests.is_empty());
    Ok(())
}

#[test]
fn certified_proofs_are_empty_for_a_conversation_without_retained_requests() {
    let index = ObjectIndex::default();
    let row = RecordRow {
        record_object_id: [1; 32],
        record_id: [2; 32],
        record_kind: FINALIZATION_RECORD,
        terminal: true,
        predecessor_record_id: [3; 32],
    };
    let records = BTreeMap::from([(1_u64, &row)]);
    assert!(index.certified_proofs(&CONVERSATION, &records).is_empty());
}

#[test]
fn certified_proofs_keep_only_requests_a_terminal_record_names() {
    let mut index = ObjectIndex::default();
    index.index_proof(CONVERSATION, [2; 32], [20; 32]);
    index.index_proof(CONVERSATION, [4; 32], [40; 32]);
    index.index_proof(CONVERSATION, [5; 32], [50; 32]);
    let certified = RecordRow {
        record_object_id: [1; 32],
        record_id: [2; 32],
        record_kind: FINALIZATION_RECORD,
        terminal: true,
        predecessor_record_id: [0; 32],
    };
    let receipt = RecordRow {
        record_object_id: [3; 32],
        record_id: [4; 32],
        record_kind: CANDIDATE_RECORD,
        terminal: false,
        predecessor_record_id: [0; 32],
    };
    let unretained = RecordRow {
        record_object_id: [6; 32],
        record_id: [7; 32],
        record_kind: FINALIZATION_RECORD,
        terminal: true,
        predecessor_record_id: [0; 32],
    };
    let records = BTreeMap::from([(1_u64, &receipt), (2, &certified), (3, &unretained)]);
    assert_eq!(
        index.certified_proofs(&CONVERSATION, &records),
        BTreeMap::from([([2; 32], [20; 32])])
    );
}

#[test]
fn decode_body_refuses_a_body_that_does_not_decode() -> TestResult {
    let bytes = raw_object(ArcWireObjectKind::FederationState, vec![0xff])?;
    let decoded: Option<ArcFederationRouteState> = decode_body(
        &bytes,
        ArcWireObjectKind::FederationState,
        MAX_FEDERATION_CONTROL_OBJECT,
    );
    assert!(decoded.is_none());
    Ok(())
}
