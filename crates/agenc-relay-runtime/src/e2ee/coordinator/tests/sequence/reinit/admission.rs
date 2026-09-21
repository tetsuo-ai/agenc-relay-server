//! A healthy attachment outside the old binding cannot submit ReInit authority.

#![forbid(unsafe_code)]

use super::super::super::{account_bytes, origin_key, support};
use super::*;

fn prepare(opcode: Op) -> TestResult<(Harness, [u8; 32], Vec<u8>)> {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let old_state = *harness
        .coordinator
        .state
        .logs
        .get(&conversation)
        .ok_or("old log")?
        .accepted_state_id();
    let (mut attempt, _) = attempt(&harness, conversation, old_state, 0)?;
    attempt.authorization.approvals = TlsVec::new(vec![commit_approval(
        &harness.principal,
        DEVICE,
        &attempt.authorization.tbs,
        SignatureDomain::ReinitAttemptAuthorization,
    )?])?;
    attempt.tbs.attempt_authorization_id = semantic_id_of(
        SemanticHashDomain::ReinitAttemptAuthorizationId,
        &attempt.authorization.tbs,
    )?;
    let bytes = wire(ArcWireObjectKind::ReinitAttempt, &attempt)?;
    if opcode == Op::SubmitReinitAttempt {
        return Ok((harness, conversation, bytes));
    }
    ok(harness.run(Op::SubmitReinitAttempt, &conversation, Some(&bytes))?)?;
    let receipt = staged_receipt(&harness, conversation)?;
    let attempt_id = receipt.tbs.reinit_attempt_id;
    let bytes = if opcode == Op::SubmitReinitAbort {
        let core = ArcReInitAbortCoreTbs {
            profile_version: 1,
            network_id: NETWORK,
            old_conversation_id: conversation,
            old_reinit_state_id: old_state,
            attempt_sequence: 0,
            slot_predecessor_record_id: receipt.tbs.predecessor_record_id,
            reinit_attempt_id: attempt_id,
            reason_code: 1,
            evidence_digest: [0; 32],
        };
        let terminal =
            Terminal::abort(semantic_id_of(SemanticHashDomain::ReinitAbortId, &core)?, 1)?;
        let vote = reinit_vote(&harness, DEVICE, &receipt, old_state, attempt_id, terminal)?;
        wire(
            ArcWireObjectKind::ReinitAbortRequest,
            &ArcReInitAbortRequest {
                core,
                receipt,
                attempt,
                votes: TlsVec::new(vec![vote])?,
            },
        )?
    } else {
        let (ack, _) = ack(conversation, old_state, attempt_id)?;
        let core = ArcReInitActivationCoreTbs {
            profile_version: 1,
            network_id: NETWORK,
            old_conversation_id: conversation,
            new_conversation_id: NEW_CONVERSATION,
            old_reinit_state_id: old_state,
            attempt_sequence: 0,
            reinit_attempt_id: attempt_id,
            new_group_info_digest: [7; 32],
            new_group_context_digest: [8; 32],
            new_ratchet_tree_digest: [9; 32],
            new_exporter_authenticator: [10; 32],
            acknowledgement_set_digest: agenc_relay_e2ee::ids::proof_set_digest(
                SemanticHashDomain::ReinitAcknowledgementSet,
                std::slice::from_ref(&ack.tbs),
            )?,
        };
        let terminal = Terminal::finalize(semantic_id_of(
            SemanticHashDomain::ReinitActivationId,
            &core,
        )?);
        let vote = reinit_vote(&harness, DEVICE, &receipt, old_state, attempt_id, terminal)?;
        wire(
            ArcWireObjectKind::ReinitActivationRequest,
            &ArcReInitActivationRequest {
                core,
                receipt,
                attempt,
                acknowledgements: TlsVec::new(vec![ack])?,
                votes: TlsVec::new(vec![vote])?,
            },
        )?
    };
    Ok((harness, conversation, bytes))
}

fn attach_outsider(harness: &mut Harness) -> TestResult {
    let account = account_bytes(19)?;
    let principal = support::principal(29, &account, &[DEVICE])?;
    let digest = agenc_relay_e2ee::ids::account_id_digest(&NETWORK, &account)?;
    let origin = harness
        .coordinator
        .state
        .origins
        .get_mut(&origin_key())
        .ok_or("origin")?;
    origin.account_id = Some(account);
    origin.account_digest = Some(digest);
    origin.device = None;
    let root = wire(ArcWireObjectKind::RootIdentity, &principal.root)?;
    ok(harness.run(Op::PublishIdentity, &[], Some(&root))?)?;
    let roster = wire(ArcWireObjectKind::DeviceRoster, &principal.roster)?;
    ok(harness.run(Op::PublishRoster, &[], Some(&roster))?)?;
    harness.attach()?;
    assert!(
        harness
            .coordinator
            .state
            .directory
            .account(&digest)
            .is_some_and(|entry| entry.device_active(&DEVICE_ID))
    );
    Ok(())
}

fn rejects_outsider(opcode: Op) -> TestResult {
    let (mut control, conversation, bytes) = prepare(opcode)?;
    let accepted = ok(control.run(opcode, &conversation, Some(&bytes))?)?;
    assert!(accepted.security_mutation);
    assert!(!accepted.writes.is_empty());
    assert!(!accepted.events.is_empty());
    for with_signer in [true, false] {
        let (mut harness, named, identical) = prepare(opcode)?;
        assert_eq!(named, conversation);
        assert_eq!(identical, bytes);
        attach_outsider(&mut harness)?;
        if !with_signer {
            harness.coordinator.signer = None;
        }
        let logs = harness.coordinator.state.logs.clone();
        let conversations = harness.coordinator.state.conversations.clone();
        let objects = harness.coordinator.state.objects.clone();
        let writes = harness.writes.len();
        assert_eq!(
            code(harness.run(opcode, &conversation, Some(&bytes))?),
            Some(E2eeReplyCode::BindingAuthInvalid),
            "outside account must fail before signer access: {opcode:?}, signer={with_signer}"
        );
        assert_eq!(harness.coordinator.state.logs, logs);
        assert_eq!(harness.coordinator.state.conversations, conversations);
        assert_eq!(harness.coordinator.state.objects, objects);
        assert_eq!(harness.writes.len(), writes);
    }
    Ok(())
}

#[test]
fn an_attached_outside_account_cannot_stage_a_reinit_attempt() -> TestResult {
    rejects_outsider(Op::SubmitReinitAttempt)
}

#[test]
fn an_attached_outside_account_cannot_activate_a_reinit_attempt() -> TestResult {
    rejects_outsider(Op::SubmitReinitActivate)
}

#[test]
fn an_attached_outside_account_cannot_abort_a_reinit_attempt() -> TestResult {
    rejects_outsider(Op::SubmitReinitAbort)
}
