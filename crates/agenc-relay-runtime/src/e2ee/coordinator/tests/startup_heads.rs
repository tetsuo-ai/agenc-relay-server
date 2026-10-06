//! A restored ReInit attempt head must be the exact record its route row names: the right
//! record kind, this conversation, the row's predecessor, accepted state, head id and
//! route sequence. Any disagreement leaves the log phase unrestorable. A finalization head
//! whose authorization carries the ReInit bit restores the ReInit phase at that
//! finalization under the same identity checks; any other finalization head leaves the
//! group open. A restored ReInit phase takes its authorized target only from the retained
//! finalization record of its own state. Whatever its kind, the head a route row names
//! must be its last retained record.
#![forbid(unsafe_code)]

use super::*;
use agenc_relay_e2ee::ObjectId;
use agenc_relay_e2ee::ids::semantic_id_of;
use agenc_relay_e2ee::objects::conversation::{
    ArcCommitAuthorization, ArcCommitAuthorizationTbs, action_bits,
};
use agenc_relay_e2ee::objects::reinit::{ArcReInitAttemptReceipt, ArcReInitAttemptReceiptTbs};
use agenc_relay_e2ee::objects::sequencing::{
    ArcCandidateReceipt, ArcCandidateReceiptTbs, ArcCommitAck, ArcCommitAckTbs,
    ArcCommitFinalizationCertificate, ArcCommitFinalizationTbs, ArcFinalizationCoreTbs,
    ArcFinalizationProof, ArcFinalizationRequest, ArcSequencerRecord,
};
use agenc_relay_e2ee::tls::{Opaque, TlsEncode, TlsVec};

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

/// A finalization certificate at `SEQUENCE` whose identifier is `ACCEPTED` and whose
/// authorization carries `bits`.
fn finalization(bits: u32) -> TestResult<ArcCommitFinalizationCertificate> {
    let authorization = ArcCommitAuthorizationTbs {
        profile_version: 1,
        network_id: [1; 32],
        conversation_id: OLD,
        prior_epoch: 1,
        prior_state_id: [0x30; 32],
        candidate_id: PREDECESSOR,
        commit_object_id: [0x31; 32],
        canonical_validation_time: 7,
        old_policy_id: [0x32; 32],
        authorization_rule: ArcCommitAuthorizationRule::ControlledTransition,
        action_bits: bits,
        resulting_policy_id: [0x32; 32],
        resulting_group_context_digest: [0x33; 32],
        resulting_ratchet_tree_digest: [0x34; 32],
        transition_target_digest: [0x35; 32],
    };
    let ack = ArcCommitAck {
        tbs: ArcCommitAckTbs {
            profile_version: 1,
            network_id: [1; 32],
            conversation_id: OLD,
            prior_epoch: 1,
            candidate_id: PREDECESSOR,
            commit_object_id: [0x31; 32],
            old_leaf_index: 0,
            old_credential_hash: [0x36; 32],
            resulting_epoch: 2,
            resulting_group_context_digest: [0x33; 32],
            resulting_ratchet_tree_digest: [0x34; 32],
            finalization_authenticator: [0x37; 32],
        },
        old_leaf_signature: Opaque::new(vec![0; 64])?,
    };
    let receipt = ArcCandidateReceipt {
        tbs: ArcCandidateReceiptTbs {
            profile_version: 1,
            network_id: [1; 32],
            conversation_id: OLD,
            route_sequence: SEQUENCE - 1,
            prior_epoch: 1,
            resulting_epoch: 2,
            candidate_sequence: 0,
            commit_object_id: [0x31; 32],
            prior_state_id: [0x30; 32],
            predecessor_record_id: [0x38; 32],
            sequenced_at: 5,
            sequencer_key_id: [0x25; 32],
        },
        sequencer_signature: [0; 64],
    };
    Ok(ArcCommitFinalizationCertificate {
        tbs: ArcCommitFinalizationTbs {
            profile_version: 1,
            network_id: [1; 32],
            conversation_id: OLD,
            route_sequence: SEQUENCE,
            predecessor_record_id: PREDECESSOR,
            finalization_id: ACCEPTED,
            sequencer_key_id: [0x25; 32],
            request: ArcFinalizationRequest {
                proof: ArcFinalizationProof {
                    core: ArcFinalizationCoreTbs {
                        profile_version: 1,
                        network_id: [1; 32],
                        conversation_id: OLD,
                        prior_epoch: 1,
                        prior_state_id: [0x30; 32],
                        candidate_id: PREDECESSOR,
                        commit_object_id: [0x31; 32],
                        resulting_epoch: 2,
                        old_policy_id: [0x32; 32],
                        commit_authorization_id: [0x39; 32],
                        acknowledgement_set_digest: [0x3a; 32],
                        resulting_group_context_digest: [0x33; 32],
                        resulting_ratchet_tree_digest: [0x34; 32],
                        finalization_authenticator: [0x37; 32],
                    },
                    receipt,
                    authorization: ArcCommitAuthorization {
                        tbs: authorization,
                        approvals: TlsVec::new(Vec::new())?,
                    },
                    acknowledgements: TlsVec::new(vec![ack])?,
                },
                votes: TlsVec::new(Vec::new())?,
            },
        },
        sequencer_signature: [0; 64],
    })
}

/// The route row of a finalization head: the finalization is both the accepted
/// state and the head record.
fn finalization_row() -> RouteRow {
    RouteRow {
        sequencer_head_id: ACCEPTED,
        ..route_row()
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
        record_id: row.sequencer_head_id,
        record_kind: kind,
        terminal: false,
        predecessor_record_id: PREDECESSOR,
    };
    let records = BTreeMap::from([(SEQUENCE, &head)]);
    Ok(restore_log_phase(&state, OLD, row, &records).map(|restored| restored.phase))
}

/// A candidate record row named `id`; a candidate head restores no phase, so
/// its object is not read.
fn candidate_row(id: [u8; 32]) -> RecordRow {
    RecordRow {
        record_object_id: [0x30; 32],
        record_id: id,
        record_kind: CANDIDATE_RECORD,
        terminal: false,
        predecessor_record_id: PREDECESSOR,
    }
}

#[test]
fn a_route_row_whose_head_is_not_its_last_record_is_refused() {
    let state = CompanionState::default();
    let earlier = candidate_row([0x31; 32]);
    let last = candidate_row(ATTEMPT);
    let records = BTreeMap::from([(SEQUENCE - 1, &earlier), (SEQUENCE, &last)]);
    let phase = |row: &RouteRow| {
        restore_log_phase(&state, OLD, row, &records).map(|restored| restored.phase)
    };
    assert_eq!(phase(&route_row()), Some(Phase::Open));
    for (name, row) in [
        (
            "a later position",
            RouteRow {
                route_sequence: SEQUENCE + 1,
                ..route_row()
            },
        ),
        (
            "an earlier record",
            RouteRow {
                route_sequence: SEQUENCE - 1,
                sequencer_head_id: earlier.record_id,
                ..route_row()
            },
        ),
        (
            "another identifier",
            RouteRow {
                sequencer_head_id: [0x32; 32],
                ..route_row()
            },
        ),
    ] {
        assert_eq!(phase(&row), None, "{name}");
    }
    // A closed route's head is its close, which follows the last record.
    let closed = RouteRow {
        lifecycle: RowLifecycle::Tombstone,
        sequencer_head_id: [0x33; 32],
        route_sequence: SEQUENCE + 1,
        close_id: Some([0x33; 32]),
        ..route_row()
    };
    assert_eq!(
        phase(&closed),
        Some(Phase::Closed {
            close_id: [0x33; 32]
        })
    );
    // A route without a retained record has no recorded head.
    let empty = BTreeMap::new();
    assert_eq!(
        restore_log_phase(&state, OLD, &route_row(), &empty).map(|restored| restored.phase),
        Some(Phase::Open)
    );
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

#[test]
fn a_reinit_finalization_head_restores_the_reinit_phase_at_that_finalization() -> TestResult {
    let record = ArcSequencerRecord::Finalization(finalization(action_bits::REINIT)?);
    assert_eq!(
        restored(&record, FINALIZATION_RECORD, &finalization_row())?,
        Some(Phase::Reinit {
            old_reinit_state_id: ACCEPTED
        })
    );
    // The ReInit bit decides, whatever else the authorization carries.
    let combined = action_bits::REINIT | action_bits::ROSTER;
    let record = ArcSequencerRecord::Finalization(finalization(combined)?);
    assert_eq!(
        restored(&record, FINALIZATION_RECORD, &finalization_row())?,
        Some(Phase::Reinit {
            old_reinit_state_id: ACCEPTED
        })
    );
    Ok(())
}

#[test]
fn an_ordinary_finalization_head_leaves_the_group_open() -> TestResult {
    let record = ArcSequencerRecord::Finalization(finalization(action_bits::ROSTER)?);
    assert_eq!(
        restored(&record, FINALIZATION_RECORD, &finalization_row())?,
        Some(Phase::Open)
    );
    Ok(())
}

/// One edit of the retained finalization certificate.
type FinalizationEdit = (&'static str, fn(&mut ArcCommitFinalizationTbs));

#[test]
fn a_reinit_finalization_head_that_disagrees_with_its_row_is_refused() -> TestResult {
    let edits: [FinalizationEdit; 4] = [
        ("conversation", |tbs| tbs.conversation_id = [9; 32]),
        ("predecessor", |tbs| tbs.predecessor_record_id = [9; 32]),
        ("finalization id", |tbs| tbs.finalization_id = [9; 32]),
        ("route sequence", |tbs| tbs.route_sequence = SEQUENCE + 1),
    ];
    for (name, edit) in edits {
        let mut certificate = finalization(action_bits::REINIT)?;
        edit(&mut certificate.tbs);
        let record = ArcSequencerRecord::Finalization(certificate);
        assert_eq!(
            restored(&record, FINALIZATION_RECORD, &finalization_row())?,
            None,
            "{name}"
        );
    }
    // The row's head and accepted state must both be the finalization.
    let record = ArcSequencerRecord::Finalization(finalization(action_bits::REINIT)?);
    let mut stale = finalization_row();
    stale.accepted_state_id = [9; 32];
    assert_eq!(restored(&record, FINALIZATION_RECORD, &stale)?, None);
    let mut moved = finalization_row();
    moved.sequencer_head_id = [9; 32];
    assert_eq!(restored(&record, FINALIZATION_RECORD, &moved)?, None);
    // A finalization stored under another record kind is refused.
    assert_eq!(
        restored(&record, REINIT_ATTEMPT_RECORD, &finalization_row())?,
        None
    );
    Ok(())
}

/// A ReInit finalization certificate whose proof `AuthorizedReinit::from_proof` admits:
/// the receipt, the authorization and the core name one candidate, and the core commits
/// the authorization's identifier. Returns it with its finalization identifier.
fn authorized_finalization() -> TestResult<(ArcCommitFinalizationCertificate, [u8; 32])> {
    let mut certificate = finalization(action_bits::REINIT)?;
    let proof = &mut certificate.tbs.request.proof;
    let candidate_id = semantic_id_of(SemanticHashDomain::CandidateId, &proof.receipt.tbs)?;
    proof.authorization.tbs.candidate_id = candidate_id;
    proof.core.candidate_id = candidate_id;
    proof.core.commit_authorization_id = semantic_id_of(
        SemanticHashDomain::CommitAuthorizationId,
        &proof.authorization.tbs,
    )?;
    let finalization_id = semantic_id_of(SemanticHashDomain::FinalizationId, &proof.core)?;
    certificate.tbs.finalization_id = finalization_id;
    Ok((certificate, finalization_id))
}

/// One retained record row for [`authority`]: the record, the row's kind and identifier,
/// and whether its object is retained.
type Retained<'a> = (&'a ArcSequencerRecord, u16, [u8; 32], bool);

/// The authority a ReInit phase at `finalization_id` restores from the retained `rows`.
fn authority(
    rows: &[Retained<'_>],
    finalization_id: &[u8; 32],
) -> TestResult<Option<AuthorizedReinit>> {
    let mut state = CompanionState::default();
    let mut heads = Vec::new();
    for (record, kind, record_id, retained) in rows {
        let bytes =
            ArcWireObject::new(ArcWireObjectKind::SequencerRecord, record.encode()?)?.encode()?;
        let object_id = *ObjectId::compute(&bytes).as_bytes();
        if *retained {
            state.objects.insert(object_id, bytes);
        }
        heads.push(RecordRow {
            record_object_id: object_id,
            record_id: *record_id,
            record_kind: *kind,
            terminal: false,
            predecessor_record_id: PREDECESSOR,
        });
    }
    let records: BTreeMap<u64, &RecordRow> = (SEQUENCE..).zip(heads.iter()).collect();
    Ok(restored_authority(&state, &records, finalization_id))
}

#[test]
fn a_restored_reinit_phase_takes_its_authority_only_from_its_finalization_record() -> TestResult {
    let (certificate, id) = authorized_finalization()?;
    let digest = certificate
        .tbs
        .request
        .proof
        .authorization
        .tbs
        .transition_target_digest;
    let record = ArcSequencerRecord::Finalization(certificate.clone());
    let restored = authority(&[(&record, FINALIZATION_RECORD, id, true)], &id)?
        .ok_or("the authorized ReInit")?;
    assert_eq!(restored.finalization_id(), &id);
    assert_eq!(restored.target_context_digest(), &digest);
    // Another record before it changes nothing.
    let receipt = ArcSequencerRecord::ReinitAttempt(attempt_receipt());
    let earlier = (&receipt, REINIT_ATTEMPT_RECORD, ATTEMPT, true);
    assert_eq!(
        authority(&[earlier, (&record, FINALIZATION_RECORD, id, true)], &id)?,
        Some(restored)
    );
    // No retained finalization record of that state: none at all, one of another
    // identifier, one under another record kind, or one whose object is not retained.
    assert_eq!(authority(&[], &id)?, None);
    assert_eq!(
        authority(&[(&record, FINALIZATION_RECORD, [9; 32], true)], &id)?,
        None
    );
    assert_eq!(
        authority(&[(&record, REINIT_ATTEMPT_RECORD, id, true)], &id)?,
        None
    );
    assert_eq!(
        authority(&[(&record, FINALIZATION_RECORD, id, false)], &id)?,
        None
    );
    // A finalization row whose object is another record.
    assert_eq!(
        authority(&[(&receipt, FINALIZATION_RECORD, id, true)], &id)?,
        None
    );
    // A finalization whose proof binds no authorized target: the ReInit bit beside
    // another bit, re-committed by the core.
    let mut combined = certificate;
    let proof = &mut combined.tbs.request.proof;
    proof.authorization.tbs.action_bits |= action_bits::ROSTER;
    proof.core.commit_authorization_id = semantic_id_of(
        SemanticHashDomain::CommitAuthorizationId,
        &proof.authorization.tbs,
    )?;
    let combined = ArcSequencerRecord::Finalization(combined);
    assert_eq!(
        authority(&[(&combined, FINALIZATION_RECORD, id, true)], &id)?,
        None
    );
    Ok(())
}
