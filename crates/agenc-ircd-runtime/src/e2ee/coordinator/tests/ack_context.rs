//! ACK context checks are independent of the still-open old-leaf admission contract.
#![forbid(unsafe_code)]
use super::*;

fn refuses(change: impl FnOnce(&mut IrcCommitAckTbs), expected: E2eeReplyCode) -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let (_, commit, candidate) = submit_candidate(&mut harness, conversation, 0, 20)?;
    let bytes = ack(conversation, 0, candidate, commit)?;
    let mut budget = DecodeBudget::new(1 << 20, 1 << 12);
    let object = agenc_ircd_e2ee::object::IrcWireObject::decode_kind(
        &bytes,
        Some(IrcWireObjectKind::CommitAck),
        &mut budget,
    )?;
    let mut ack = IrcCommitAck::decode_exact(object.body(), &mut budget)?;
    // This proves the signature primitive over each changed TBS, without claiming
    // that this fixture key is authenticated as an MLS member by the server.
    let secret = key(113);
    ack.old_leaf_signature =
        Opaque::from_slice(&sign(&secret, SignatureDomain::CommitProcessed, &ack.tbs)?)?;
    let valid = wire(IrcWireObjectKind::CommitAck, &ack)?;
    ok(harness.run(Op::SubmitCommitAck, &conversation, Some(&valid))?)?;
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
        Opaque::from_slice(&sign(&secret, SignatureDomain::CommitProcessed, &ack.tbs)?)?;
    let wrong = wire(IrcWireObjectKind::CommitAck, &ack)?;
    assert_eq!(
        code(harness.run(Op::SubmitCommitAck, &conversation, Some(&wrong))?),
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
fn commit_ack_refuses_another_inner_profile() -> TestResult {
    refuses(
        |tbs| tbs.profile_version = 2,
        E2eeReplyCode::InvalidFragment,
    )
}

#[test]
fn commit_ack_refuses_another_inner_network() -> TestResult {
    refuses(|tbs| tbs.network_id = [99; 32], E2eeReplyCode::RouteInvalid)
}

#[test]
fn commit_ack_refuses_a_resulting_epoch_that_skips_a_commit() -> TestResult {
    refuses(|tbs| tbs.resulting_epoch = 2, E2eeReplyCode::EpochStale)
}

fn finalization_case(
    change: Option<fn(&mut IrcCommitAckTbs)>,
) -> TestResult<(Harness, [u8; 32], Vec<u8>)> {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let (receipt, commit, candidate) = submit_candidate(&mut harness, conversation, 0, 20)?;
    let bytes = ack(conversation, 0, candidate, commit)?;
    let mut budget = DecodeBudget::new(1 << 20, 1 << 12);
    let object = agenc_ircd_e2ee::object::IrcWireObject::decode_kind(
        &bytes,
        Some(IrcWireObjectKind::CommitAck),
        &mut budget,
    )?;
    let mut acknowledgement = IrcCommitAck::decode_exact(object.body(), &mut budget)?;
    if let Some(change) = change {
        change(&mut acknowledgement.tbs);
    }
    acknowledgement.old_leaf_signature = Opaque::from_slice(&sign(
        &key(113),
        SignatureDomain::CommitProcessed,
        &acknowledgement.tbs,
    )?)?;
    let bytes = wire(IrcWireObjectKind::CommitAck, &acknowledgement)?;
    // The helper recomputes the ACK-set digest and signs the resulting core's vote.
    let request = finalization_request(
        &harness,
        conversation,
        &receipt,
        commit,
        candidate,
        &bytes,
        &[DEVICE],
    )?;
    Ok((harness, conversation, request))
}

fn finalization_refuses(change: fn(&mut IrcCommitAckTbs)) -> TestResult {
    let (mut control, conversation, bytes) = finalization_case(None)?;
    ok(control.run(Op::SubmitFinalization, &conversation, Some(&bytes))?)?;
    let (mut harness, conversation, bytes) = finalization_case(Some(change))?;
    let logs = harness.coordinator.state.logs.clone();
    let states = harness.coordinator.state.conversations.clone();
    let writes = harness.writes.len();
    assert_eq!(
        code(harness.run(Op::SubmitFinalization, &conversation, Some(&bytes))?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    assert_eq!(harness.coordinator.state.logs, logs);
    assert_eq!(harness.coordinator.state.conversations, states);
    assert_eq!(harness.writes.len(), writes);
    Ok(())
}

#[test]
fn finalization_refuses_ack_profile_version_substitution() -> TestResult {
    finalization_refuses(|tbs| tbs.profile_version = 2)
}

#[test]
fn finalization_refuses_ack_network_id_substitution() -> TestResult {
    finalization_refuses(|tbs| tbs.network_id = [99; 32])
}

#[test]
fn finalization_refuses_ack_conversation_id_substitution() -> TestResult {
    finalization_refuses(|tbs| tbs.conversation_id = [99; 32])
}

#[test]
fn finalization_refuses_ack_prior_epoch_substitution() -> TestResult {
    finalization_refuses(|tbs| tbs.prior_epoch = 4)
}

#[test]
fn finalization_refuses_ack_candidate_id_substitution() -> TestResult {
    finalization_refuses(|tbs| tbs.candidate_id = [99; 32])
}

#[test]
fn finalization_refuses_ack_commit_object_id_substitution() -> TestResult {
    finalization_refuses(|tbs| tbs.commit_object_id = [99; 32])
}

#[test]
fn finalization_refuses_ack_resulting_epoch_substitution() -> TestResult {
    finalization_refuses(|tbs| tbs.resulting_epoch = 2)
}

#[test]
fn finalization_refuses_ack_resulting_group_context_digest_substitution() -> TestResult {
    finalization_refuses(|tbs| tbs.resulting_group_context_digest = [99; 32])
}

#[test]
fn finalization_refuses_ack_resulting_ratchet_tree_digest_substitution() -> TestResult {
    finalization_refuses(|tbs| tbs.resulting_ratchet_tree_digest = [99; 32])
}

#[test]
fn finalization_refuses_ack_finalization_authenticator_substitution() -> TestResult {
    finalization_refuses(|tbs| tbs.finalization_authenticator = [99; 32])
}
