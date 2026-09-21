//! Public ReInit controller authorization is checked before receipt signing.
#![forbid(unsafe_code)]
mod controllers;
use super::*;

pub(super) fn sign_authorization(harness: &Harness, attempt: &mut ArcReInitAttempt) -> TestResult {
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
    Ok(())
}

pub(super) fn authorize_attempt(harness: &Harness, attempt: &mut ArcReInitAttempt) -> TestResult {
    attempt.tbs.key_package_plan_id = semantic_id_of(
        SemanticHashDomain::KeyPackagePlanId,
        &attempt.key_package_plan,
    )?;
    attempt.tbs.initial_commit_digest =
        agenc_relay_e2ee::ids::initial_commit_digest(attempt.initial_commit_bytes.as_slice())?;
    let tbs = &attempt.tbs;
    attempt.authorization.tbs = ArcReInitAttemptAuthorizationTbs {
        profile_version: tbs.profile_version,
        network_id: tbs.network_id,
        old_conversation_id: tbs.old_conversation_id,
        old_reinit_state_id: tbs.old_reinit_state_id,
        attempt_sequence: tbs.attempt_sequence,
        creator_old_leaf_index: tbs.creator_old_leaf_index,
        creator_old_credential_hash: tbs.creator_old_credential_hash,
        new_conversation_id: tbs.new_conversation_id,
        target_context_digest: tbs.target_context_digest,
        target_binding_id: tbs.target_binding_id,
        initial_member_plan_id: tbs.initial_member_plan_id,
        key_package_plan_id: tbs.key_package_plan_id,
        initial_commit_digest: tbs.initial_commit_digest,
        new_group_info_digest: tbs.new_group_info_digest,
        new_group_context_digest: tbs.new_group_context_digest,
        new_ratchet_tree_digest: tbs.new_ratchet_tree_digest,
        new_exporter_authenticator: tbs.new_exporter_authenticator,
    };
    sign_authorization(harness, attempt)
}

fn prepared() -> TestResult<(Harness, [u8; 32], ArcReInitAttempt)> {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let old_state = *harness
        .coordinator
        .state
        .logs
        .get(&conversation)
        .ok_or("log")?
        .accepted_state_id();
    let (mut attempt, _) = attempt(&harness, conversation, old_state, 0)?;
    authorize_attempt(&harness, &mut attempt)?;
    Ok((harness, conversation, attempt))
}

fn refuses(change: impl Fn(&Harness, &mut ArcReInitAttempt) -> TestResult) -> TestResult {
    let (mut control, conversation, attempt) = prepared()?;
    let bytes = wire(ArcWireObjectKind::ReinitAttempt, &attempt)?;
    let accepted = ok(control.run(Op::SubmitReinitAttempt, &conversation, Some(&bytes))?)?;
    assert!(accepted.security_mutation && !accepted.events.is_empty());
    for with_signer in [true, false] {
        let (mut harness, conversation, mut attempt) = prepared()?;
        change(&harness, &mut attempt)?;
        if !with_signer {
            harness.coordinator.signer = None;
        }
        let bytes = wire(ArcWireObjectKind::ReinitAttempt, &attempt)?;
        let logs = harness.coordinator.state.logs.clone();
        let states = harness.coordinator.state.conversations.clone();
        let writes = harness.writes.len();
        assert_eq!(
            code(harness.run(Op::SubmitReinitAttempt, &conversation, Some(&bytes))?),
            Some(E2eeReplyCode::BindingAuthInvalid)
        );
        assert_eq!(harness.coordinator.state.logs, logs);
        assert_eq!(harness.coordinator.state.conversations, states);
        assert_eq!(harness.writes.len(), writes);
    }
    Ok(())
}

#[test]
fn reinit_authorization_refuses_substituted_profile_version() -> TestResult {
    refuses(|harness, attempt| {
        attempt.authorization.tbs.profile_version = 2;
        sign_authorization(harness, attempt)
    })
}

#[test]
fn reinit_authorization_refuses_substituted_network_id() -> TestResult {
    refuses(|harness, attempt| {
        attempt.authorization.tbs.network_id = [99; 32];
        sign_authorization(harness, attempt)
    })
}

#[test]
fn reinit_authorization_refuses_substituted_old_conversation_id() -> TestResult {
    refuses(|harness, attempt| {
        attempt.authorization.tbs.old_conversation_id = [99; 32];
        sign_authorization(harness, attempt)
    })
}

#[test]
fn reinit_authorization_refuses_substituted_old_reinit_state_id() -> TestResult {
    refuses(|harness, attempt| {
        attempt.authorization.tbs.old_reinit_state_id = [99; 32];
        sign_authorization(harness, attempt)
    })
}

#[test]
fn reinit_authorization_refuses_substituted_attempt_sequence() -> TestResult {
    refuses(|harness, attempt| {
        attempt.authorization.tbs.attempt_sequence = 8;
        sign_authorization(harness, attempt)
    })
}

#[test]
fn reinit_authorization_refuses_substituted_creator_old_leaf_index() -> TestResult {
    refuses(|harness, attempt| {
        attempt.authorization.tbs.creator_old_leaf_index = 8;
        sign_authorization(harness, attempt)
    })
}

#[test]
fn reinit_authorization_refuses_substituted_creator_old_credential_hash() -> TestResult {
    refuses(|harness, attempt| {
        attempt.authorization.tbs.creator_old_credential_hash = [99; 32];
        sign_authorization(harness, attempt)
    })
}

#[test]
fn reinit_authorization_refuses_substituted_new_conversation_id() -> TestResult {
    refuses(|harness, attempt| {
        attempt.authorization.tbs.new_conversation_id = [99; 32];
        sign_authorization(harness, attempt)
    })
}

#[test]
fn reinit_authorization_refuses_substituted_target_context_digest() -> TestResult {
    refuses(|harness, attempt| {
        attempt.authorization.tbs.target_context_digest = [99; 32];
        sign_authorization(harness, attempt)
    })
}

#[test]
fn reinit_authorization_refuses_substituted_target_binding_id() -> TestResult {
    refuses(|harness, attempt| {
        attempt.authorization.tbs.target_binding_id = [99; 32];
        sign_authorization(harness, attempt)
    })
}

#[test]
fn reinit_authorization_refuses_substituted_initial_member_plan_id() -> TestResult {
    refuses(|harness, attempt| {
        attempt.authorization.tbs.initial_member_plan_id = [99; 32];
        sign_authorization(harness, attempt)
    })
}

#[test]
fn reinit_authorization_refuses_substituted_key_package_plan_id() -> TestResult {
    refuses(|harness, attempt| {
        attempt.authorization.tbs.key_package_plan_id = [99; 32];
        sign_authorization(harness, attempt)
    })
}

#[test]
fn reinit_authorization_refuses_substituted_initial_commit_digest() -> TestResult {
    refuses(|harness, attempt| {
        attempt.authorization.tbs.initial_commit_digest = [99; 32];
        sign_authorization(harness, attempt)
    })
}

#[test]
fn reinit_authorization_refuses_substituted_new_group_info_digest() -> TestResult {
    refuses(|harness, attempt| {
        attempt.authorization.tbs.new_group_info_digest = [99; 32];
        sign_authorization(harness, attempt)
    })
}

#[test]
fn reinit_authorization_refuses_substituted_new_group_context_digest() -> TestResult {
    refuses(|harness, attempt| {
        attempt.authorization.tbs.new_group_context_digest = [99; 32];
        sign_authorization(harness, attempt)
    })
}

#[test]
fn reinit_authorization_refuses_substituted_new_ratchet_tree_digest() -> TestResult {
    refuses(|harness, attempt| {
        attempt.authorization.tbs.new_ratchet_tree_digest = [99; 32];
        sign_authorization(harness, attempt)
    })
}

#[test]
fn reinit_authorization_refuses_substituted_new_exporter_authenticator() -> TestResult {
    refuses(|harness, attempt| {
        attempt.authorization.tbs.new_exporter_authenticator = [99; 32];
        sign_authorization(harness, attempt)
    })
}

#[test]
fn reinit_authorization_refuses_a_false_authorization_id() -> TestResult {
    refuses(|_, attempt| {
        attempt.tbs.attempt_authorization_id = [99; 32];
        Ok(())
    })
}

#[test]
fn reinit_authorization_refuses_another_attempt_profile() -> TestResult {
    refuses(|harness, attempt| {
        attempt.tbs.profile_version = 2;
        authorize_attempt(harness, attempt)
    })
}

#[test]
fn reinit_authorization_refuses_another_signature_domain() -> TestResult {
    refuses(|harness, attempt| {
        attempt.authorization.approvals = TlsVec::new(vec![commit_approval(
            &harness.principal,
            DEVICE,
            &attempt.authorization.tbs,
            SignatureDomain::CommitAuthorization,
        )?])?;
        Ok(())
    })
}

#[test]
fn reinit_authorization_refuses_a_modified_signature() -> TestResult {
    refuses(|_, attempt| {
        let mut approvals = attempt.authorization.approvals.as_slice().to_vec();
        approvals.first_mut().ok_or("approval")?.device_signature = [0; 64];
        attempt.authorization.approvals = TlsVec::new(approvals)?;
        Ok(())
    })
}

#[test]
fn reinit_authorization_refuses_a_noncontroller_root() -> TestResult {
    refuses(|_, attempt| {
        let mut approvals = attempt.authorization.approvals.as_slice().to_vec();
        approvals
            .first_mut()
            .ok_or("approval")?
            .signer_root_fingerprint = [99; 32];
        attempt.authorization.approvals = TlsVec::new(approvals)?;
        Ok(())
    })
}

#[test]
fn reinit_authorization_refuses_a_substituted_certificate() -> TestResult {
    refuses(|_, attempt| {
        let mut approvals = attempt.authorization.approvals.as_slice().to_vec();
        approvals
            .first_mut()
            .ok_or("approval")?
            .signer_device_certificate_id = [99; 32];
        attempt.authorization.approvals = TlsVec::new(approvals)?;
        Ok(())
    })
}

#[test]
fn reinit_authorization_refuses_duplicate_controller_approvals() -> TestResult {
    refuses(|_, attempt| {
        let approval = attempt
            .authorization
            .approvals
            .as_slice()
            .first()
            .ok_or("approval")?
            .clone();
        attempt.authorization.approvals = TlsVec::new(vec![approval.clone(), approval])?;
        Ok(())
    })
}

#[test]
fn reinit_authorization_refuses_a_different_initial_commit_body() -> TestResult {
    refuses(|_, attempt| {
        attempt.initial_commit_bytes = Opaque::new(vec![99; 40])?;
        Ok(())
    })
}

#[test]
fn reinit_authorization_refuses_a_different_key_package_plan() -> TestResult {
    refuses(|_, attempt| {
        let mut entries = attempt.key_package_plan.entries.as_slice().to_vec();
        entries.first_mut().ok_or("entry")?.key_package_ref = Opaque::new(vec![99; 32])?;
        attempt.key_package_plan.entries = TlsVec::new(entries)?;
        Ok(())
    })
}

#[test]
fn reinit_authorization_refuses_exhausted_work_memory_before_signing() -> TestResult {
    let (mut harness, conversation, attempt) = prepared()?;
    let bytes = wire(ArcWireObjectKind::ReinitAttempt, &attempt)?;
    let budget = std::sync::Arc::new(crate::budget::MemoryBudget::new(0));
    harness.backing = crate::budget::BackingReservationPort::new(budget.clone());
    let states = harness.coordinator.state.conversations.clone();
    let writes = harness.writes.len();
    assert_eq!(
        code(harness.run(Op::SubmitReinitAttempt, &conversation, Some(&bytes))?),
        Some(E2eeReplyCode::RateLimited)
    );
    assert_eq!(harness.coordinator.state.conversations, states);
    assert_eq!(harness.writes.len(), writes);
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn reinit_authorization_requires_the_original_old_state_on_later_attempts() -> TestResult {
    for substitute in [false, true] {
        let (mut harness, conversation, mut attempt) = prepared()?;
        let old_state = attempt.tbs.old_reinit_state_id;
        harness
            .coordinator
            .state
            .logs
            .get_mut(&conversation)
            .ok_or("log")?
            .enter_reinit(old_state)?;
        if substitute {
            attempt.tbs.old_reinit_state_id = [99; 32];
        }
        authorize_attempt(&harness, &mut attempt)?;
        let bytes = wire(ArcWireObjectKind::ReinitAttempt, &attempt)?;
        let logs = harness.coordinator.state.logs.clone();
        let writes = harness.writes.len();
        let result = harness.run(Op::SubmitReinitAttempt, &conversation, Some(&bytes))?;
        if substitute {
            assert_eq!(code(result), Some(E2eeReplyCode::BindingAuthInvalid));
            assert_eq!(harness.coordinator.state.logs, logs);
            assert_eq!(harness.writes.len(), writes);
        } else {
            ok(result)?;
        }
    }
    Ok(())
}
