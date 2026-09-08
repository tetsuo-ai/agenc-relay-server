//! Existing public ReInit fixtures retain their synthetic MLS and leaf signatures.
#![forbid(unsafe_code)]
use super::*;
use crate::e2ee::coordinator::tests::sequence::reinit;
use agenc_ircd_e2ee::objects::reinit::{
    IrcReInitAbortCoreTbs, IrcReInitAbortRequest, IrcReInitActivationCoreTbs,
    IrcReInitActivationRequest, IrcReInitAttempt, IrcReInitAttemptReceipt,
};

pub(super) fn prepare(activate: bool) -> TestResult<Prepared> {
    let (mut harness, conversation) = bound()?;
    let old = *harness
        .coordinator
        .state
        .logs
        .get(&conversation)
        .ok_or("log")?
        .accepted_state_id();
    let (attempt, bytes) = reinit::attempt(&harness, conversation, old, 0)?;
    ok(harness.run(Op::SubmitReinitAttempt, &conversation, Some(&bytes))?)?;
    let receipt = reinit::staged_receipt(&harness, conversation)?;
    let request = if activate {
        activation(&harness, attempt, receipt)?
    } else {
        abort(&harness, attempt, receipt)?
    };
    Ok((harness, conversation, request))
}

fn abort(
    harness: &Harness,
    attempt: IrcReInitAttempt,
    receipt: IrcReInitAttemptReceipt,
) -> TestResult<Vec<u8>> {
    let core = IrcReInitAbortCoreTbs {
        profile_version: 1,
        network_id: NETWORK,
        old_conversation_id: receipt.tbs.old_conversation_id,
        old_reinit_state_id: receipt.tbs.old_reinit_state_id,
        attempt_sequence: receipt.tbs.attempt_sequence,
        slot_predecessor_record_id: receipt.tbs.predecessor_record_id,
        reinit_attempt_id: receipt.tbs.reinit_attempt_id,
        reason_code: 1,
        evidence_digest: [0; 32],
    };
    let id = semantic_id_of(SemanticHashDomain::ReinitAbortId, &core)?;
    let vote = reinit_vote(
        harness,
        DEVICE,
        &receipt,
        core.old_reinit_state_id,
        core.reinit_attempt_id,
        Terminal::abort(id, 1)?,
    )?;
    wire(
        IrcWireObjectKind::ReinitAbortRequest,
        &IrcReInitAbortRequest {
            core,
            receipt,
            attempt,
            votes: TlsVec::new(vec![vote])?,
        },
    )
}

fn activation(
    harness: &Harness,
    attempt: IrcReInitAttempt,
    receipt: IrcReInitAttemptReceipt,
) -> TestResult<Vec<u8>> {
    let tbs = &attempt.tbs;
    let (ack, _) = reinit::ack(
        tbs.old_conversation_id,
        tbs.old_reinit_state_id,
        receipt.tbs.reinit_attempt_id,
    )?;
    let core = IrcReInitActivationCoreTbs {
        profile_version: 1,
        network_id: NETWORK,
        old_conversation_id: tbs.old_conversation_id,
        new_conversation_id: tbs.new_conversation_id,
        old_reinit_state_id: tbs.old_reinit_state_id,
        attempt_sequence: tbs.attempt_sequence,
        reinit_attempt_id: receipt.tbs.reinit_attempt_id,
        new_group_info_digest: tbs.new_group_info_digest,
        new_group_context_digest: tbs.new_group_context_digest,
        new_ratchet_tree_digest: tbs.new_ratchet_tree_digest,
        new_exporter_authenticator: tbs.new_exporter_authenticator,
        acknowledgement_set_digest: agenc_ircd_e2ee::ids::proof_set_digest(
            SemanticHashDomain::ReinitAcknowledgementSet,
            std::slice::from_ref(&ack.tbs),
        )?,
    };
    let id = semantic_id_of(SemanticHashDomain::ReinitActivationId, &core)?;
    let vote = reinit_vote(
        harness,
        DEVICE,
        &receipt,
        core.old_reinit_state_id,
        core.reinit_attempt_id,
        Terminal::finalize(id),
    )?;
    wire(
        IrcWireObjectKind::ReinitActivationRequest,
        &IrcReInitActivationRequest {
            core,
            receipt,
            attempt,
            acknowledgements: TlsVec::new(vec![ack])?,
            votes: TlsVec::new(vec![vote])?,
        },
    )
}
