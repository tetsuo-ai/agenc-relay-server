//! A restored ReInit attempt head must be the exact record its route row names: the right
//! record kind, this conversation, the row's predecessor, accepted state, head id and
//! route sequence. Any disagreement leaves the log phase unrestorable.
#![forbid(unsafe_code)]

use super::*;
use agenc_relay_e2ee::ObjectId;
use agenc_relay_e2ee::objects::reinit::{ArcReInitAttemptReceipt, ArcReInitAttemptReceiptTbs};
use agenc_relay_e2ee::objects::sequencing::ArcSequencerRecord;
use agenc_relay_e2ee::tls::TlsEncode;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// One edit of the retained attempt receipt.
type ReceiptEdit = (&'static str, fn(&mut ArcReInitAttemptReceiptTbs));

const OLD: [u8; 32] = [0x10; 32];
const PREDECESSOR: [u8; 32] = [0x21; 32];
const ACCEPTED: [u8; 32] = [0x22; 32];
const ATTEMPT: [u8; 32] = [0x23; 32];
const SEQUENCE: u64 = 4;

fn attempt_receipt() -> ArcReInitAttemptReceipt {
    ArcReInitAttemptReceipt {
        tbs: ArcReInitAttemptReceiptTbs {
            profile_version: 1,
            network_id: [1; 32],
            old_conversation_id: OLD,
            old_reinit_state_id: ACCEPTED,
            route_sequence: SEQUENCE,
            attempt_sequence: 2,
            predecessor_record_id: PREDECESSOR,
            reinit_attempt_id: ATTEMPT,
            attempt_object_id: [0x24; 32],
            sequenced_at: 5,
            sequencer_key_id: [0x25; 32],
        },
        sequencer_signature: [0; 64],
    }
}

fn route_row() -> RouteRow {
    RouteRow {
        route_state: Vec::new(),
        lifecycle: RowLifecycle::Active,
        binding_id: [1; 32],
        lock_id: [2; 32],
        accepted_state_id: ACCEPTED,
        sequencer_head_id: ATTEMPT,
        route_sequence: SEQUENCE,
        close_id: None,
        predecessor_close_id: None,
        recovery_gate: false,
        stored_bytes: 0,
        sequencer_credential_id: None,
        blocked_credential_id: None,
    }
}

/// Retains `record` and restores the phase of a route whose head row names it under `kind`.
fn restored(record: &ArcSequencerRecord, kind: u16, row: &RouteRow) -> TestResult<Option<Phase>> {
    let bytes =
        ArcWireObject::new(ArcWireObjectKind::SequencerRecord, record.encode()?)?.encode()?;
    let object_id = *ObjectId::compute(&bytes).as_bytes();
    let mut state = CompanionState::default();
    state.objects.insert(object_id, bytes);
    let head = RecordRow {
        record_object_id: object_id,
        record_id: ATTEMPT,
        record_kind: kind,
        terminal: false,
        predecessor_record_id: PREDECESSOR,
    };
    let records = BTreeMap::from([(SEQUENCE, &head)]);
    Ok(restore_log_phase(&state, OLD, row, &records).map(|restored| restored.phase))
}

#[test]
fn an_attempt_head_that_matches_its_row_restores_the_reinit_phase() -> TestResult {
    let record = ArcSequencerRecord::ReinitAttempt(attempt_receipt());
    assert_eq!(
        restored(&record, REINIT_ATTEMPT_RECORD, &route_row())?,
        Some(Phase::Reinit {
            old_reinit_state_id: ACCEPTED
        })
    );
    Ok(())
}

#[test]
fn an_attempt_head_stored_under_another_record_kind_is_refused() -> TestResult {
    let record = ArcSequencerRecord::ReinitAttempt(attempt_receipt());
    assert_eq!(restored(&record, REINIT_ABORT_RECORD, &route_row())?, None);
    Ok(())
}

#[test]
fn an_attempt_head_that_disagrees_with_its_row_is_refused() -> TestResult {
    let edits: [ReceiptEdit; 5] = [
        ("conversation", |tbs| tbs.old_conversation_id = [9; 32]),
        ("predecessor", |tbs| tbs.predecessor_record_id = [9; 32]),
        ("accepted state", |tbs| tbs.old_reinit_state_id = [9; 32]),
        ("attempt id", |tbs| tbs.reinit_attempt_id = [9; 32]),
        ("route sequence", |tbs| tbs.route_sequence = SEQUENCE + 1),
    ];
    for (name, edit) in edits {
        let mut receipt = attempt_receipt();
        edit(&mut receipt.tbs);
        let record = ArcSequencerRecord::ReinitAttempt(receipt);
        assert_eq!(
            restored(&record, REINIT_ATTEMPT_RECORD, &route_row())?,
            None,
            "{name}"
        );
    }
    Ok(())
}
