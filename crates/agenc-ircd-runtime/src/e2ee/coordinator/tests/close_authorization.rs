//! Public close authority, with signed controller/council proofs and synthetic MLS ciphertext.
#![forbid(unsafe_code)]
use super::*;
use crate::e2ee::coordinator::tests::support::commit_approval;

#[path = "close_authority_cases.rs"]
mod cases;
use agenc_ircd_e2ee::authorization::{CandidateBinding, verify_commit_authorization};
use agenc_ircd_e2ee::objects::conversation::{
    IrcCloseAuthorization, IrcCloseAuthorizationTbs, IrcCloseIntent, action_bits,
};

struct Fixture {
    source: Harness,
    conversation: [u8; 32],
    close: IrcCloseAuthorization,
}

impl Fixture {
    fn ready(closing: bool) -> TestResult<Self> {
        let mut source = Harness::new()?;
        let conversation = source.bind_channel()?;
        let intent = IrcCloseIntent {
            reason_code: 1,
            validation_time: 30,
        };
        let intent_id = semantic_id_of(SemanticHashDomain::CloseIntentId, &intent)?;
        finish(&mut source, conversation, 0, None)?;
        assert!(
            !source
                .coordinator
                .state
                .lifecycles
                .get(&conversation)
                .ok_or("lifecycle")?
                .bootstrap_pending()
        );
        let terminal = finish(&mut source, conversation, 1, closing.then_some(intent_id))?;
        let binding = source
            .coordinator
            .state
            .conversations
            .get(&conversation)
            .ok_or("conversation")?
            .binding;
        let tbs = IrcCloseAuthorizationTbs {
            profile_version: 1,
            network_id: NETWORK,
            conversation_id: conversation,
            binding_id: binding,
            authorizing_terminal_id: terminal,
            close_intent: intent,
            close_intent_id: intent_id,
        };
        let close = IrcCloseAuthorization {
            approvals: TlsVec::new(vec![commit_approval(
                &source.principal,
                DEVICE,
                &tbs,
                SignatureDomain::CloseAuthorization,
            )?])?,
            tbs,
        };
        Ok(Self {
            source,
            conversation,
            close,
        })
    }

    fn sign_close(&mut self) -> TestResult {
        self.close.approvals = TlsVec::new(vec![commit_approval(
            &self.source.principal,
            DEVICE,
            &self.close.tbs,
            SignatureDomain::CloseAuthorization,
        )?])?;
        Ok(())
    }

    fn evaluate(&mut self) -> TestResult<Result<Outcome, Fail>> {
        let bytes = wire(IrcWireObjectKind::CloseAuthorization, &self.close)?;
        let mut parameters = self.conversation.to_vec();
        parameters.extend_from_slice(&self.close.tbs.close_intent.reason_code.to_be_bytes());
        evaluate_request(&mut self.source, Op::CloseGroup, &parameters, Some(&bytes))
    }
}

fn finish(
    source: &mut Harness,
    conversation: [u8; 32],
    epoch: u64,
    closing: Option<[u8; 32]>,
) -> TestResult<[u8; 32]> {
    let validation_time = if epoch == 0 { 20 } else { 30 };
    let state = source
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("conversation")?;
    let old_policy = state.current_policy_id;
    let resulting_policy = if epoch == 0 {
        state.required_operational_policy_id
    } else {
        old_policy
    };
    let (receipt, object, candidate) =
        submit_candidate(source, conversation, epoch, validation_time)?;
    let ack_bytes = ack(conversation, epoch, candidate, object)?;
    ok(source.run(Op::SubmitCommitAck, &conversation, Some(&ack_bytes))?)?;
    let bytes = finalization_request_under(
        source,
        conversation,
        &receipt,
        object,
        candidate,
        &ack_bytes,
        &[DEVICE],
        (old_policy, resulting_policy),
    )?;
    let mut budget = DecodeBudget::new(1 << 20, 1 << 16);
    let object = agenc_ircd_e2ee::object::IrcWireObject::decode_kind(
        &bytes,
        Some(IrcWireObjectKind::FinalizationRequest),
        &mut budget,
    )?;
    let mut request = IrcFinalizationRequest::decode_exact(object.body(), &mut budget)?;
    let core = &request.proof.core;
    let mut authorization = request.proof.authorization.tbs.clone();
    authorization.prior_epoch = core.prior_epoch;
    authorization.prior_state_id = core.prior_state_id;
    authorization.candidate_id = core.candidate_id;
    authorization.commit_object_id = core.commit_object_id;
    authorization.canonical_validation_time = validation_time;
    authorization.resulting_group_context_digest = core.resulting_group_context_digest;
    authorization.resulting_ratchet_tree_digest = core.resulting_ratchet_tree_digest;
    if epoch == 0 {
        authorization.authorization_rule = IrcCommitAuthorizationRule::BootstrapActivation;
        authorization.action_bits = action_bits::POLICY | action_bits::BOOTSTRAP;
    } else if let Some(intent) = closing {
        authorization.authorization_rule = IrcCommitAuthorizationRule::ControlledTransition;
        authorization.action_bits = action_bits::CLOSE_INTENT;
        authorization.transition_target_digest = intent;
    }
    request.proof.authorization =
        commit_authorization(authorization, &[(&source.principal, DEVICE)])?;
    validate_public_authorization(source, &request)?;
    request.proof.core.commit_authorization_id = semantic_id_of(
        SemanticHashDomain::CommitAuthorizationId,
        &request.proof.authorization.tbs,
    )?;
    let terminal = semantic_id_of(SemanticHashDomain::FinalizationId, &request.proof.core)?;
    request.votes = TlsVec::new(vec![vote(
        source,
        DEVICE,
        &receipt,
        candidate,
        Terminal::finalize(terminal),
    )?])?;
    let bytes = wire(IrcWireObjectKind::FinalizationRequest, &request)?;
    let outcome = ok(source.run(Op::SubmitFinalization, &conversation, Some(&bytes))?)?;
    assert!(matches!(outcome.result, ResultBody::Finalized(_, _, id, _) if id == terminal));
    Ok(terminal)
}

fn validate_public_authorization(source: &Harness, request: &IrcFinalizationRequest) -> TestResult {
    let core = &request.proof.core;
    let state = source
        .coordinator
        .state
        .conversations
        .get(&core.conversation_id)
        .ok_or("conversation")?;
    let policy = &state
        .policies
        .get(&core.old_policy_id)
        .ok_or("policy")?
        .policy;
    let rosters = source
        .coordinator
        .state
        .principals
        .values()
        .map(|(root, roster)| (root.account_id, (*root, roster.clone())))
        .collect();
    verify_commit_authorization(
        &request.proof.authorization,
        &CandidateBinding {
            network_id: core.network_id,
            conversation_id: core.conversation_id,
            prior_epoch: core.prior_epoch,
            prior_state_id: core.prior_state_id,
            candidate_id: core.candidate_id,
            commit_object_id: core.commit_object_id,
        },
        policy,
        &rosters,
    )?;
    // Bootstrap uses the same one-device council under both published policies.
    let next = &state
        .policies
        .get(&request.proof.authorization.tbs.resulting_policy_id)
        .ok_or("resulting policy")?
        .policy;
    assert_eq!(policy.quorum, 1);
    assert_eq!(next.quorum, 1);
    assert_eq!(policy.council, next.council);
    Ok(())
}

#[test]
fn an_exact_finalized_closing_intent_and_controller_approval_produce_a_close() -> TestResult {
    let mut fixture = Fixture::ready(true)?;
    let outcome = ok(fixture.evaluate()?)?;
    assert!(matches!(outcome.result, ResultBody::Closed { .. }));
    assert!(!outcome.writes.is_empty());
    Ok(())
}

#[test]
fn close_without_controller_approvals_is_refused() -> TestResult {
    let mut fixture = Fixture::ready(true)?;
    let mut body = fixture.close.tbs.encode()?;
    body.extend_from_slice(&0_u32.to_be_bytes());
    let bytes = wire_raw(IrcWireObjectKind::CloseAuthorization, body)?;
    let mut parameters = fixture.conversation.to_vec();
    parameters.extend_from_slice(&fixture.close.tbs.close_intent.reason_code.to_be_bytes());
    assert!(
        evaluate_request(
            &mut fixture.source,
            Op::CloseGroup,
            &parameters,
            Some(&bytes)
        )?
        .is_err(),
        "close accepted without controller authority"
    );
    Ok(())
}

#[test]
fn close_with_a_valid_signature_from_another_root_is_refused() -> TestResult {
    let mut fixture = Fixture::ready(true)?;
    let account = crate::e2ee::coordinator::tests::account_bytes(88)?;
    let outsider = crate::e2ee::coordinator::tests::support::principal(88, &account, &[9])?;
    fixture.close.approvals = TlsVec::new(vec![commit_approval(
        &outsider,
        9,
        &fixture.close.tbs,
        SignatureDomain::CloseAuthorization,
    )?])?;
    assert!(
        fixture.evaluate()?.is_err(),
        "close accepted an unrelated controller root"
    );
    Ok(())
}

#[test]
fn close_with_a_corrupted_controller_signature_is_refused() -> TestResult {
    let mut fixture = Fixture::ready(true)?;
    let mut approvals = fixture.close.approvals.as_slice().to_vec();
    approvals.first_mut().ok_or("approval")?.device_signature[0] ^= 1;
    fixture.close.approvals = TlsVec::new(approvals)?;
    assert!(
        fixture.evaluate()?.is_err(),
        "close accepted a corrupt controller signature"
    );
    Ok(())
}

#[test]
fn a_correctly_signed_close_cannot_reuse_an_ordinary_finalization() -> TestResult {
    let mut fixture = Fixture::ready(false)?;
    assert!(
        fixture.evaluate()?.is_err(),
        "ordinary finalization authorized a close"
    );
    Ok(())
}

#[test]
fn a_correctly_signed_close_cannot_change_the_finalized_intent() -> TestResult {
    let mut fixture = Fixture::ready(true)?;
    fixture.close.tbs.close_intent.reason_code = 2;
    fixture.close.tbs.close_intent_id = semantic_id_of(
        SemanticHashDomain::CloseIntentId,
        &fixture.close.tbs.close_intent,
    )?;
    fixture.sign_close()?;
    assert!(
        fixture.evaluate()?.is_err(),
        "close replaced its finalized intent"
    );
    Ok(())
}
