//! Public ReInit ACK fields must match the current retained attempt.
#![forbid(unsafe_code)]
use super::*;
use crate::e2ee::coordinator::tests::support::{key, sign};

fn refuses(change: impl FnOnce(&mut IrcReInitAckTbs), expected: E2eeReplyCode) -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let old_state = *harness
        .coordinator
        .state
        .logs
        .get(&conversation)
        .ok_or("log")?
        .accepted_state_id();
    let (_, bytes) = attempt(&harness, conversation, old_state, 0)?;
    ok(harness.run(Op::SubmitReinitAttempt, &conversation, Some(&bytes))?)?;
    let receipt = staged_receipt(&harness, conversation)?;
    let (mut ack, _) = ack(conversation, old_state, receipt.tbs.reinit_attempt_id)?;
    // The key signs each TBS correctly; binding it to an authenticated old leaf
    // is CAP-86's separate obligation and is not established by this fixture.
    let secret = key(113);
    ack.old_leaf_signature =
        Opaque::from_slice(&sign(&secret, SignatureDomain::ReinitProcessed, &ack.tbs)?)?;
    let valid = wire(IrcWireObjectKind::ReinitAck, &ack)?;
    ok(harness.run(Op::SubmitReinitAck, &conversation, Some(&valid))?)?;
    let before = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("state")?
        .acks
        .clone();
    let writes = harness.writes.len();
    change(&mut ack.tbs);
    ack.old_leaf_signature =
        Opaque::from_slice(&sign(&secret, SignatureDomain::ReinitProcessed, &ack.tbs)?)?;
    let wrong = wire(IrcWireObjectKind::ReinitAck, &ack)?;
    assert_eq!(
        code(harness.run(Op::SubmitReinitAck, &conversation, Some(&wrong))?),
        Some(expected)
    );
    assert_eq!(
        harness
            .coordinator
            .state
            .conversations
            .get(&conversation)
            .ok_or("state")?
            .acks,
        before
    );
    assert_eq!(harness.writes.len(), writes);
    Ok(())
}

#[test]
fn reinit_ack_refuses_another_inner_profile() -> TestResult {
    refuses(
        |tbs| tbs.profile_version = 2,
        E2eeReplyCode::InvalidFragment,
    )
}

#[test]
fn reinit_ack_refuses_another_inner_network() -> TestResult {
    refuses(|tbs| tbs.network_id = [99; 32], E2eeReplyCode::RouteInvalid)
}

#[test]
fn reinit_ack_refuses_another_old_reinit_state() -> TestResult {
    refuses(
        |tbs| tbs.old_reinit_state_id = [99; 32],
        E2eeReplyCode::EpochStale,
    )
}

fn activation_case(
    change: Option<fn(&mut IrcReInitAckTbs)>,
) -> TestResult<(Harness, [u8; 32], Vec<u8>)> {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let old_state = *harness
        .coordinator
        .state
        .logs
        .get(&conversation)
        .ok_or("log")?
        .accepted_state_id();
    let (attempt, bytes) = attempt(&harness, conversation, old_state, 0)?;
    ok(harness.run(Op::SubmitReinitAttempt, &conversation, Some(&bytes))?)?;
    let receipt = staged_receipt(&harness, conversation)?;
    let attempt_id = receipt.tbs.reinit_attempt_id;
    let (mut ack, _) = ack(conversation, old_state, attempt_id)?;
    if let Some(change) = change {
        change(&mut ack.tbs);
    }
    ack.old_leaf_signature = Opaque::from_slice(&sign(
        &key(113),
        SignatureDomain::ReinitProcessed,
        &ack.tbs,
    )?)?;
    let core = IrcReInitActivationCoreTbs {
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
        acknowledgement_set_digest: agenc_ircd_e2ee::ids::proof_set_digest(
            SemanticHashDomain::ReinitAcknowledgementSet,
            std::slice::from_ref(&ack.tbs),
        )?,
    };
    let terminal = Terminal::finalize(semantic_id_of(
        SemanticHashDomain::ReinitActivationId,
        &core,
    )?);
    // Each substituted ACK has a new set digest and a valid old-policy council vote.
    let vote = reinit_vote(&harness, DEVICE, &receipt, old_state, attempt_id, terminal)?;
    let bytes = wire(
        IrcWireObjectKind::ReinitActivationRequest,
        &IrcReInitActivationRequest {
            core,
            receipt,
            attempt,
            acknowledgements: TlsVec::new(vec![ack])?,
            votes: TlsVec::new(vec![vote])?,
        },
    )?;
    Ok((harness, conversation, bytes))
}

fn activation_refuses(change: fn(&mut IrcReInitAckTbs)) -> TestResult {
    let (mut control, conversation, bytes) = activation_case(None)?;
    ok(control.run(Op::SubmitReinitActivate, &conversation, Some(&bytes))?)?;
    let (mut harness, conversation, bytes) = activation_case(Some(change))?;
    let logs = harness.coordinator.state.logs.clone();
    let states = harness.coordinator.state.conversations.clone();
    let writes = harness.writes.len();
    assert_eq!(
        code(harness.run(Op::SubmitReinitActivate, &conversation, Some(&bytes))?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    assert_eq!(harness.coordinator.state.logs, logs);
    assert_eq!(harness.coordinator.state.conversations, states);
    assert_eq!(harness.writes.len(), writes);
    Ok(())
}

#[test]
fn activation_refuses_ack_profile_version_substitution() -> TestResult {
    activation_refuses(|tbs| tbs.profile_version = 2)
}

#[test]
fn activation_refuses_ack_network_id_substitution() -> TestResult {
    activation_refuses(|tbs| tbs.network_id = [99; 32])
}

#[test]
fn activation_refuses_ack_old_conversation_id_substitution() -> TestResult {
    activation_refuses(|tbs| tbs.old_conversation_id = [99; 32])
}

#[test]
fn activation_refuses_ack_old_reinit_state_id_substitution() -> TestResult {
    activation_refuses(|tbs| tbs.old_reinit_state_id = [99; 32])
}

#[test]
fn activation_refuses_ack_reinit_attempt_id_substitution() -> TestResult {
    activation_refuses(|tbs| tbs.reinit_attempt_id = [99; 32])
}

#[test]
fn activation_refuses_ack_new_conversation_id_substitution() -> TestResult {
    activation_refuses(|tbs| tbs.new_conversation_id = [99; 32])
}

#[test]
fn activation_refuses_ack_new_group_info_digest_substitution() -> TestResult {
    activation_refuses(|tbs| tbs.new_group_info_digest = [99; 32])
}

#[test]
fn activation_refuses_ack_new_group_context_digest_substitution() -> TestResult {
    activation_refuses(|tbs| tbs.new_group_context_digest = [99; 32])
}

#[test]
fn activation_refuses_ack_new_ratchet_tree_digest_substitution() -> TestResult {
    activation_refuses(|tbs| tbs.new_ratchet_tree_digest = [99; 32])
}

#[test]
fn activation_refuses_ack_new_exporter_authenticator_substitution() -> TestResult {
    activation_refuses(|tbs| tbs.new_exporter_authenticator = [99; 32])
}

#[test]
fn activation_refuses_ack_old_leaf_index_substitution() -> TestResult {
    activation_refuses(|tbs| tbs.old_leaf_index = 8)
}

#[test]
fn activation_refuses_ack_old_credential_hash_substitution() -> TestResult {
    activation_refuses(|tbs| tbs.old_credential_hash = [99; 32])
}

#[test]
fn activation_refuses_ack_ack_kind_substitution() -> TestResult {
    activation_refuses(|tbs| tbs.ack_kind = IrcReInitAckKind::WelcomeJoin)
}

#[test]
fn reinit_ack_refuses_new_conversation_id_substitution() -> TestResult {
    refuses(
        |tbs| tbs.new_conversation_id = [99; 32],
        E2eeReplyCode::BindingAuthInvalid,
    )
}

#[test]
fn reinit_ack_refuses_new_group_info_digest_substitution() -> TestResult {
    refuses(
        |tbs| tbs.new_group_info_digest = [99; 32],
        E2eeReplyCode::BindingAuthInvalid,
    )
}

#[test]
fn reinit_ack_refuses_new_group_context_digest_substitution() -> TestResult {
    refuses(
        |tbs| tbs.new_group_context_digest = [99; 32],
        E2eeReplyCode::BindingAuthInvalid,
    )
}

#[test]
fn reinit_ack_refuses_new_ratchet_tree_digest_substitution() -> TestResult {
    refuses(
        |tbs| tbs.new_ratchet_tree_digest = [99; 32],
        E2eeReplyCode::BindingAuthInvalid,
    )
}

#[test]
fn reinit_ack_refuses_new_exporter_authenticator_substitution() -> TestResult {
    refuses(
        |tbs| tbs.new_exporter_authenticator = [99; 32],
        E2eeReplyCode::BindingAuthInvalid,
    )
}

#[test]
fn reinit_ack_refuses_old_leaf_index_substitution() -> TestResult {
    refuses(
        |tbs| tbs.old_leaf_index = 8,
        E2eeReplyCode::BindingAuthInvalid,
    )
}

#[test]
fn reinit_ack_refuses_old_credential_hash_substitution() -> TestResult {
    refuses(
        |tbs| tbs.old_credential_hash = [99; 32],
        E2eeReplyCode::BindingAuthInvalid,
    )
}

#[test]
fn reinit_ack_refuses_ack_kind_substitution() -> TestResult {
    refuses(
        |tbs| tbs.ack_kind = IrcReInitAckKind::WelcomeJoin,
        E2eeReplyCode::BindingAuthInvalid,
    )
}

fn retained_attempt_case(initial_bytes: usize) -> TestResult<(Harness, [u8; 32], Vec<u8>)> {
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
    // This is a public-object allocation case; the MLS body remains synthetic.
    attempt.initial_commit_bytes = Opaque::new(vec![15; initial_bytes])?;
    super::attempt_authority::authorize_attempt(&harness, &mut attempt)?;
    let bytes = wire(IrcWireObjectKind::ReinitAttempt, &attempt)?;
    ok(harness.run(Op::SubmitReinitAttempt, &conversation, Some(&bytes))?)?;
    let receipt = staged_receipt(&harness, conversation)?;
    let (_, bytes) = ack(conversation, old_state, receipt.tbs.reinit_attempt_id)?;
    Ok((harness, conversation, bytes))
}

#[test]
fn reinit_ack_charges_the_maximum_retained_initial_commit_and_releases_work() -> TestResult {
    let (mut harness, conversation, bytes) =
        retained_attempt_case(agenc_ircd_e2ee::limits::MAX_REINIT_INITIAL_COMMIT_BYTES)?;
    for available in [0, 16_384, 1 << 20] {
        let budget = std::sync::Arc::new(crate::budget::MemoryBudget::new(available));
        harness.backing = crate::budget::BackingReservationPort::new(budget.clone());
        let logs = harness.coordinator.state.logs.clone();
        let states = harness.coordinator.state.conversations.clone();
        let writes = harness.writes.len();
        assert_eq!(
            code(harness.run(Op::SubmitReinitAck, &conversation, Some(&bytes))?),
            Some(E2eeReplyCode::RateLimited)
        );
        assert_eq!(harness.coordinator.state.logs, logs);
        assert_eq!(harness.coordinator.state.conversations, states);
        assert_eq!(harness.writes.len(), writes);
        assert_eq!(budget.charged(), 0);
    }
    let budget = std::sync::Arc::new(crate::budget::MemoryBudget::new(32 << 20));
    harness.backing = crate::budget::BackingReservationPort::new(budget.clone());
    ok(harness.run(Op::SubmitReinitAck, &conversation, Some(&bytes))?)?;
    // Only the small new ACK object remains resident in this replacement budget.
    assert!(budget.charged() > 0 && budget.charged() <= 16_384);
    drop(harness);
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn reinit_ack_refuses_a_missing_retained_attempt_before_writing() -> TestResult {
    let (mut harness, conversation, bytes) = retained_attempt_case(40)?;
    let receipt = staged_receipt(&harness, conversation)?;
    harness
        .coordinator
        .state
        .objects
        .remove(&receipt.tbs.attempt_object_id);
    let writes = harness.writes.len();
    assert_eq!(
        code(harness.run(Op::SubmitReinitAck, &conversation, Some(&bytes))?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    assert_eq!(harness.writes.len(), writes);
    Ok(())
}

#[test]
fn reinit_ack_accepts_a_reserved_welcome_ref_and_refuses_an_unknown_ref() -> TestResult {
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
    let creator = attempt
        .key_package_plan
        .entries
        .as_slice()
        .first()
        .ok_or("creator")?
        .clone();
    let mut joiner = creator.clone();
    joiner.creator = 0;
    joiner.device_id = [88; 16];
    joiner.key_package_ref = Opaque::new(vec![88; 32])?;
    attempt.key_package_plan.entries = TlsVec::new(vec![creator, joiner])?;
    super::attempt_authority::authorize_attempt(&harness, &mut attempt)?;
    let bytes = wire(IrcWireObjectKind::ReinitAttempt, &attempt)?;
    ok(harness.run(Op::SubmitReinitAttempt, &conversation, Some(&bytes))?)?;
    let receipt = staged_receipt(&harness, conversation)?;
    let (mut ack, _) = ack(conversation, old_state, receipt.tbs.reinit_attempt_id)?;
    // Public plan membership is tested here; the new entry is not an authenticated old leaf.
    ack.tbs.ack_kind = IrcReInitAckKind::WelcomeJoin;
    ack.tbs.old_leaf_index = 1;
    ack.tbs.old_credential_hash = [88; 32];
    ack.tbs.new_leaf_index = 1;
    ack.tbs.key_package_ref = Opaque::new(vec![88; 32])?;
    ack.old_leaf_signature = Opaque::from_slice(&sign(
        &key(113),
        SignatureDomain::ReinitProcessed,
        &ack.tbs,
    )?)?;
    let bytes = wire(IrcWireObjectKind::ReinitAck, &ack)?;
    ok(harness.run(Op::SubmitReinitAck, &conversation, Some(&bytes))?)?;
    for reference in [Vec::new(), vec![99; 32], vec![14; 32]] {
        ack.tbs.key_package_ref = Opaque::new(reference)?;
        ack.old_leaf_signature = Opaque::from_slice(&sign(
            &key(113),
            SignatureDomain::ReinitProcessed,
            &ack.tbs,
        )?)?;
        let bytes = wire(IrcWireObjectKind::ReinitAck, &ack)?;
        let writes = harness.writes.len();
        assert_eq!(
            code(harness.run(Op::SubmitReinitAck, &conversation, Some(&bytes))?),
            Some(E2eeReplyCode::BindingAuthInvalid)
        );
        assert_eq!(harness.writes.len(), writes);
    }
    Ok(())
}

#[test]
fn creator_ack_cannot_name_a_key_package_ref() -> TestResult {
    let (mut harness, conversation, _) = retained_attempt_case(40)?;
    let receipt = staged_receipt(&harness, conversation)?;
    let (mut ack, _) = ack(
        conversation,
        receipt.tbs.old_reinit_state_id,
        receipt.tbs.reinit_attempt_id,
    )?;
    ack.tbs.key_package_ref = Opaque::new(vec![14; 32])?;
    ack.old_leaf_signature = Opaque::from_slice(&sign(
        &key(113),
        SignatureDomain::ReinitProcessed,
        &ack.tbs,
    )?)?;
    let bytes = wire(IrcWireObjectKind::ReinitAck, &ack)?;
    let writes = harness.writes.len();
    assert_eq!(
        code(harness.run(Op::SubmitReinitAck, &conversation, Some(&bytes))?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    assert_eq!(harness.writes.len(), writes);
    Ok(())
}
