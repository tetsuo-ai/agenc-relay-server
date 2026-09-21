//! Daemon checks for public close authority. MLS bodies and leaf ACKs are
//! synthetic; controller signatures, council votes and transport are real.
#![forbid(unsafe_code)]
use super::*;

pub(super) enum CertificationTransition {
    Bootstrap,
    Add,
    Remove,
    Sequencer,
    Reinit([u8; 32]),
    Close([u8; 32]),
}

impl CertificationTransition {
    pub(super) fn fields(self) -> (ArcCommitAuthorizationRule, u32, [u8; 32]) {
        match self {
            Self::Bootstrap => (
                ArcCommitAuthorizationRule::BootstrapActivation,
                action_bits::POLICY | action_bits::BOOTSTRAP,
                [0; 32],
            ),
            Self::Add => (
                ArcCommitAuthorizationRule::ControlledTransition,
                action_bits::ADD_LEAF,
                [0; 32],
            ),
            Self::Remove => (
                ArcCommitAuthorizationRule::ControlledTransition,
                action_bits::REMOVE_LEAF,
                [0; 32],
            ),
            Self::Sequencer => (
                ArcCommitAuthorizationRule::ControlledTransition,
                action_bits::SEQUENCER,
                [0; 32],
            ),
            Self::Reinit(target) => (
                ArcCommitAuthorizationRule::ControlledTransition,
                action_bits::REINIT,
                target,
            ),
            Self::Close(id) => (
                ArcCommitAuthorizationRule::ControlledTransition,
                action_bits::CLOSE_INTENT,
                id,
            ),
        }
    }
}

fn intent(validation_time: u64) -> ArcCloseIntent {
    ArcCloseIntent {
        reason_code: 1,
        validation_time,
    }
}

pub(super) fn authorization(
    principal: &Principal,
    bound: &BoundConversation,
    terminal: [u8; 32],
) -> TestResult<ArcCloseAuthorization> {
    authorization_at(principal, bound, terminal, VALIDATION_TIME + 1)
}

/// The close authorization whose intent names `validation_time`, so a
/// lineage the historical chain re-verifies at its own canonical times
/// carries a close of the same era (companion 9.2 and 9.3).
pub(super) fn authorization_at(
    principal: &Principal,
    bound: &BoundConversation,
    terminal: [u8; 32],
    validation_time: u64,
) -> TestResult<ArcCloseAuthorization> {
    let intent = intent(validation_time);
    let tbs = ArcCloseAuthorizationTbs {
        profile_version: 1,
        network_id: *NETWORK_ID.as_bytes(),
        conversation_id: bound.conversation,
        binding_id: bound.binding_id,
        authorizing_terminal_id: terminal,
        close_intent_id: semantic_id_of(SemanticHashDomain::CloseIntentId, &intent)?,
        close_intent: intent,
    };
    let approval = builders::commit_approval(
        &principal.keys,
        principal.device,
        &tbs,
        SignatureDomain::CloseAuthorization,
    )?;
    Ok(ArcCloseAuthorization {
        tbs,
        approvals: TlsVec::new(vec![approval])?,
    })
}

pub(super) fn close_after_public_transition(
    client: &mut ArcClient,
    binder: &mut Principal,
    peer: &Principal,
    bound: &BoundConversation,
    prior: (u64, [u8; 32]),
) -> TestResult<[u8; 32]> {
    // A valid close signature cannot authorize an unrelated finalization.
    let close = authorization(binder, bound, prior.1)?;
    require_refusal(client, binder, bound, &close)?;
    let aad = ArcCommitAad {
        profile_version: 1,
        network_id: *NETWORK_ID.as_bytes(),
        conversation_id: bound.conversation,
        route_binding: bound.route_binding,
        validation_time: VALIDATION_TIME + 1,
        prior_state_id: prior.1,
    }
    .encode()?;
    let commit = builders::private_message_at_epoch(&bound.group_id, prior.0, MLS_COMMIT, &aad)?;
    let policy = builders::policy_id_of(&bound.policies[1])?;
    let terminal = super::real_clients::certify_commit(
        client,
        binder,
        &[peer],
        bound,
        &commit,
        prior,
        (policy, policy),
        CertificationTransition::Close(close.tbs.close_intent_id),
    )?;
    // The exact closing finalization still requires a valid close signature.
    let mut close = authorization(binder, bound, terminal.finalization_id)?;
    close.approvals = TlsVec::new(vec![builders::commit_approval(
        &binder.keys,
        binder.device,
        &close.tbs,
        SignatureDomain::CommitAuthorization,
    )?])?;
    require_refusal(client, binder, bound, &close)?;
    close_conversation(client, binder, bound, terminal.finalization_id)
}

pub(super) fn candidate_validation_time(
    bound: &BoundConversation,
    prior: &[u8; 32],
    commit: &[u8],
) -> TestResult<u64> {
    let object = ArcWireObject::new(ArcWireObjectKind::CommitMls, commit.to_vec())?;
    let expectation = e2ee::envelope::RouteExpectation {
        network_id: *NETWORK_ID.as_bytes(),
        conversation_id: bound.conversation,
        route_binding: bound.route_binding,
        group_id: bound.group_id,
    };
    let mut budget = DecodeBudget::new(1 << 20, 1 << 10);
    Ok(
        e2ee::envelope::verify_commit_object(&object, &expectation, prior, 0, &mut budget)?
            .aad
            .validation_time,
    )
}

fn require_refusal(
    client: &mut ArcClient,
    principal: &mut Principal,
    bound: &BoundConversation,
    close: &ArcCloseAuthorization,
) -> TestResult {
    let object = wire_object(ArcWireObjectKind::CloseAuthorization, close)?;
    let label = principal.label();
    send_object(
        client,
        &label,
        &format!("EGROUP CLOSE {} 1", base64url_encode(&bound.conversation)),
        &object,
    )?;
    let reply = labeled_reply(client, &label)?;
    assert_contains(&reply, "FAIL EGROUP E2EE_BINDING_AUTH_INVALID")?;
    assert!(!reply.iter().any(|line| line.contains(" EGROUP CLOSED ")));
    Ok(())
}
