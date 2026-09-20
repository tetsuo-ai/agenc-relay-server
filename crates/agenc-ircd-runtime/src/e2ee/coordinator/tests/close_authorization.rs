//! Public close authority, with signed controller/council proofs and synthetic MLS ciphertext.
#![forbid(unsafe_code)]
use super::*;
use crate::e2ee::coordinator::tests::support::commit_approval;

#[path = "close_authority_cases.rs"]
mod cases;
use agenc_ircd_e2ee::authorization::{CandidateBinding, verify_commit_authorization};
use agenc_ircd_e2ee::objects::conversation::{
    IrcCloseAuthorization, IrcCloseAuthorizationTbs, IrcCloseIntent, IrcCommitAuthorizationTbs,
    action_bits,
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

pub(in crate::e2ee::coordinator::tests) fn finish(
    source: &mut Harness,
    conversation: [u8; 32],
    epoch: u64,
    closing: Option<[u8; 32]>,
) -> TestResult<[u8; 32]> {
    assert_single_device_councils(source, conversation)?;
    let opened = open_finalization(source, conversation, epoch)?;
    let (bytes, terminal) = finalization_bytes(source, &opened, closing, &[DEVICE])?;
    let outcome = ok(source.run(Op::SubmitFinalization, &conversation, Some(&bytes))?)?;
    assert!(matches!(outcome.result, ResultBody::Finalized(_, _, id, _) if id == terminal));
    Ok(terminal)
}

/// A candidate submitted and acknowledged at `epoch`, ready for its
/// finalization requests.
pub(in crate::e2ee::coordinator::tests) struct Opened {
    conversation: [u8; 32],
    epoch: u64,
    validation_time: u64,
    policies: ([u8; 32], [u8; 32]),
    receipt: IrcCandidateReceipt,
    object: [u8; 32],
    candidate: [u8; 32],
    ack_bytes: Vec<u8>,
}

pub(in crate::e2ee::coordinator::tests) fn open_finalization(
    source: &mut Harness,
    conversation: [u8; 32],
    epoch: u64,
) -> TestResult<Opened> {
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
    Ok(Opened {
        conversation,
        epoch,
        validation_time,
        policies: (old_policy, resulting_policy),
        receipt,
        object,
        candidate,
        ack_bytes,
    })
}

/// The finalization request of `opened` with the finality votes of
/// `voters`: a bootstrap activation at epoch zero, a controlled close
/// transition for `closing`, and a routine self-update otherwise.
pub(in crate::e2ee::coordinator::tests) fn finalization_bytes(
    source: &Harness,
    opened: &Opened,
    closing: Option<[u8; 32]>,
    voters: &[u8],
) -> TestResult<(Vec<u8>, [u8; 32])> {
    let epoch = opened.epoch;
    finalization_with(source, opened, voters, |authorization| {
        if epoch == 0 {
            authorization.authorization_rule = IrcCommitAuthorizationRule::BootstrapActivation;
            authorization.action_bits = action_bits::POLICY | action_bits::BOOTSTRAP;
        } else if let Some(intent) = closing {
            authorization.authorization_rule = IrcCommitAuthorizationRule::ControlledTransition;
            authorization.action_bits = action_bits::CLOSE_INTENT;
            authorization.transition_target_digest = intent;
        }
    })
}

/// The finalization request of `opened` as the controlled `SEQUENCER`
/// transition whose resulting context names the advertised successor
/// credential (companion 9.2.1).
pub(in crate::e2ee::coordinator::tests) fn transition_bytes(
    source: &Harness,
    opened: &Opened,
    voters: &[u8],
) -> TestResult<(Vec<u8>, [u8; 32])> {
    finalization_with(source, opened, voters, |authorization| {
        authorization.authorization_rule = IrcCommitAuthorizationRule::ControlledTransition;
        authorization.action_bits = action_bits::SEQUENCER;
    })
}

/// The finalization request of `opened` with the finality votes of
/// `voters`, after `patch` set the authorization's rule and action bits.
fn finalization_with(
    source: &Harness,
    opened: &Opened,
    voters: &[u8],
    patch: impl FnOnce(&mut IrcCommitAuthorizationTbs),
) -> TestResult<(Vec<u8>, [u8; 32])> {
    let bytes = finalization_request_under(
        source,
        opened.conversation,
        &opened.receipt,
        opened.object,
        opened.candidate,
        &opened.ack_bytes,
        &[DEVICE],
        opened.policies,
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
    authorization.canonical_validation_time = opened.validation_time;
    authorization.resulting_group_context_digest = core.resulting_group_context_digest;
    authorization.resulting_ratchet_tree_digest = core.resulting_ratchet_tree_digest;
    patch(&mut authorization);
    request.proof.authorization =
        commit_authorization(authorization, &[(&source.principal, DEVICE)])?;
    validate_public_authorization(source, &request)?;
    request.proof.core.commit_authorization_id = semantic_id_of(
        SemanticHashDomain::CommitAuthorizationId,
        &request.proof.authorization.tbs,
    )?;
    let terminal = semantic_id_of(SemanticHashDomain::FinalizationId, &request.proof.core)?;
    let mut votes = voters
        .iter()
        .map(|device| {
            vote(
                source,
                *device,
                &opened.receipt,
                opened.candidate,
                Terminal::finalize(terminal),
            )
        })
        .collect::<TestResult<Vec<_>>>()?;
    votes.sort_by_key(|vote| (vote.signer_root_fingerprint, vote.signer_device_id));
    request.votes = TlsVec::new(votes)?;
    let bytes = wire(IrcWireObjectKind::FinalizationRequest, &request)?;
    Ok((bytes, terminal))
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
    Ok(())
}

/// The close fixtures assume the same one-device council under both
/// published policies of `conversation`.
fn assert_single_device_councils(source: &Harness, conversation: [u8; 32]) -> TestResult {
    let state = source
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("conversation")?;
    let policy = &state
        .policies
        .get(&state.current_policy_id)
        .ok_or("current policy")?
        .policy;
    let next = &state
        .policies
        .get(&state.required_operational_policy_id)
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

/// Replaces the retained finalization object the close names with an edited copy, keeping
/// the proof index pointed at the new bytes, so only the terminal's own content disagrees.
fn retain_edited_terminal(
    fixture: &mut Fixture,
    edit: fn(&mut agenc_ircd_e2ee::objects::sequencing::IrcFinalizationRequest),
) -> TestResult {
    let terminal = fixture.close.tbs.authorizing_terminal_id;
    let state = fixture
        .source
        .coordinator
        .state
        .conversations
        .get_mut(&fixture.conversation)
        .ok_or("conversation")?;
    let proof_id = *state.proofs.get(&terminal).ok_or("retained proof")?;
    let bytes = fixture
        .source
        .coordinator
        .state
        .objects
        .get(&proof_id)
        .ok_or("retained terminal object")?
        .clone();
    let mut budget = DecodeBudget::new(1 << 20, 1 << 16);
    let object = agenc_ircd_e2ee::object::IrcWireObject::decode_kind(
        &bytes,
        Some(IrcWireObjectKind::FinalizationRequest),
        &mut budget,
    )?;
    let mut request = agenc_ircd_e2ee::objects::sequencing::IrcFinalizationRequest::decode_exact(
        object.body(),
        &mut budget,
    )?;
    edit(&mut request);
    let edited = wire(IrcWireObjectKind::FinalizationRequest, &request)?;
    let edited_id = object_id(&edited);
    fixture
        .source
        .coordinator
        .state
        .objects
        .insert(edited_id, edited);
    fixture
        .source
        .coordinator
        .state
        .conversations
        .get_mut(&fixture.conversation)
        .ok_or("conversation")?
        .proofs
        .insert(terminal, edited_id);
    Ok(())
}

type TerminalEdit = (
    &'static str,
    fn(&mut agenc_ircd_e2ee::objects::sequencing::IrcFinalizationRequest),
);

#[test]
fn a_close_needs_a_retained_terminal_that_agrees_with_itself_and_the_intent() -> TestResult {
    let edits: [TerminalEdit; 10] = [
        ("core profile version", |request| {
            request.proof.core.profile_version = 2
        }),
        ("core network", |request| {
            request.proof.core.network_id = [9; 32]
        }),
        ("core conversation", |request| {
            request.proof.core.conversation_id = [9; 32]
        }),
        ("core resulting epoch", |request| {
            request.proof.core.resulting_epoch += 1
        }),
        ("core old policy", |request| {
            request.proof.core.old_policy_id = [9; 32]
        }),
        ("authorization resulting policy", |request| {
            request.proof.authorization.tbs.resulting_policy_id = [9; 32];
        }),
        ("authorization prior epoch", |request| {
            request.proof.authorization.tbs.prior_epoch += 1;
        }),
        ("authorization ratchet digest", |request| {
            request
                .proof
                .authorization
                .tbs
                .resulting_ratchet_tree_digest = [9; 32];
        }),
        ("core authenticator", |request| {
            request.proof.core.finalization_authenticator = [9; 32];
        }),
        ("authorization validation time", |request| {
            request.proof.authorization.tbs.canonical_validation_time += 1;
        }),
    ];
    for (name, edit) in edits {
        let mut fixture = Fixture::ready(true)?;
        retain_edited_terminal(&mut fixture, edit)?;
        assert!(fixture.evaluate()?.is_err(), "{name}");
    }
    let mut fixture = Fixture::ready(true)?;
    retain_edited_terminal(&mut fixture, |_| {})?;
    assert!(matches!(
        ok(fixture.evaluate()?)?.result,
        ResultBody::Closed { .. }
    ));
    Ok(())
}
