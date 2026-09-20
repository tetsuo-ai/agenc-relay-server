//! Welcome and staged ReInit mailbox delivery checks the target device,
//! the wrapper kind, the authorizing terminal and the entropy a page needs.

#![forbid(unsafe_code)]

use agenc_ircd_e2ee::ids::account_id_digest;
use agenc_ircd_e2ee::objects::conversation::{
    IrcJoinTransitionProofBundle, IrcJoinTransitionProofReference, IrcJoinTransitionProofRole,
    IrcJoinTransitionSubject,
};
use agenc_ircd_e2ee::objects::reinit::{
    IrcReInitAttemptReceipt, IrcReInitAttemptReceiptTbs, IrcStagedReInit,
};
use agenc_ircd_e2ee::objects::sequencing::{IrcDeliveredWelcome, IrcNormalJoinAuthorizationProof};
use agenc_ircd_types::{EntropyError, EntropySource};

use super::*;
use crate::e2ee::coordinator::tests::support::opaque_v;

const KEY_PACKAGE_REF: [u8; 32] = [4; 32];
const NEW_CONVERSATION: [u8; 32] = [21; 32];
const ATTEMPT: [u8; 32] = [72; 32];

/// A finalized `#room` conversation and the finalization identifier that
/// authorized its first epoch.
fn finalized() -> TestResult<(Harness, [u8; 32], [u8; 32])> {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let (receipt, commit_id, candidate_id) = submit_candidate(&mut harness, conversation, 0, 20)?;
    let ack = acknowledge(&mut harness, conversation, candidate_id, commit_id)?;
    let request = finalization_request(
        &harness,
        conversation,
        &receipt,
        commit_id,
        candidate_id,
        &ack,
        &[DEVICE],
    )?;
    let outcome = ok(harness.run(Op::SubmitFinalization, &conversation, Some(&request))?)?;
    let ResultBody::Finalized(_, _, finalization_id, _) = outcome.result else {
        return Err("expected a finalized result".into());
    };
    Ok((harness, conversation, finalization_id))
}

/// An MLS `Welcome` message addressing `refs`, shaped like the e2ee crate's
/// own fixture.
fn welcome_message(refs: &[&[u8]]) -> TestResult<Vec<u8>> {
    let mut out = vec![0, 1, 0, 3, 0, 1];
    let mut secrets = Vec::new();
    for reference in refs {
        opaque_v(&mut secrets, reference)?;
        opaque_v(&mut secrets, &[5; 32])?;
        opaque_v(&mut secrets, &[6; 64])?;
    }
    opaque_v(&mut out, &secrets)?;
    opaque_v(&mut out, &[8; 100])?;
    Ok(out)
}

fn bundle() -> TestResult<IrcJoinTransitionProofBundle> {
    Ok(IrcJoinTransitionProofBundle {
        references: TlsVec::new(vec![IrcJoinTransitionProofReference {
            subject_kind: IrcJoinTransitionSubject::BindingSubject,
            subject_id: [1; 32],
            proof_role: IrcJoinTransitionProofRole::FinalizedGroupTransition,
            record_conversation_id: [20; 32],
            authorizing_record_id: [50; 32],
            authorizing_object_id: [51; 32],
        }])?,
    })
}

fn welcome_bytes(
    harness: &Harness,
    conversation: [u8; 32],
    finalization_id: [u8; 32],
) -> TestResult<Vec<u8>> {
    let welcome = IrcDeliveredWelcome {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        target_account_id_digest: account_id_digest(&NETWORK, &harness.account)?,
        target_device_id: DEVICE_ID,
        authorization: IrcNormalJoinAuthorizationProof {
            finalization_id,
            finalization_object_id: [61; 32],
            added_key_package_ref: Opaque::new(KEY_PACKAGE_REF.to_vec())?,
            resulting_leaf_index: 5,
            resulting_leaf_credential_hash: [62; 32],
        },
        transition_proofs: bundle()?,
        welcome_bytes: Opaque::new(welcome_message(&[&[9; 32], &KEY_PACKAGE_REF])?)?,
    };
    wire(IrcWireObjectKind::WelcomeMls, &welcome)
}

fn staged_bytes(
    harness: &Harness,
    old_conversation: [u8; 32],
    new_conversation: [u8; 32],
) -> TestResult<Vec<u8>> {
    let tbs = IrcReInitAttemptReceiptTbs {
        profile_version: 1,
        network_id: NETWORK,
        old_conversation_id: old_conversation,
        old_reinit_state_id: [70; 32],
        route_sequence: 8,
        attempt_sequence: 1,
        predecessor_record_id: [71; 32],
        reinit_attempt_id: ATTEMPT,
        attempt_object_id: [73; 32],
        sequenced_at: 1_000,
        sequencer_key_id: [74; 32],
    };
    let staged = IrcStagedReInit {
        old_reinit_state_id: [70; 32],
        old_reinit_finalization_object_id: [75; 32],
        receipt: IrcReInitAttemptReceipt {
            tbs,
            sequencer_signature: [0; 64],
        },
        new_conversation_id: new_conversation,
        target_account_id_digest: account_id_digest(&NETWORK, &harness.account)?,
        target_device_id: DEVICE_ID,
        transition_proofs: bundle()?,
        welcome_bytes: Opaque::new(welcome_message(&[&KEY_PACKAGE_REF])?)?,
    };
    wire(IrcWireObjectKind::StagedReinit, &staged)
}

fn welcome_params(
    harness: &Harness,
    device_id: [u8; 16],
    conversation: [u8; 32],
    authorization_id: [u8; 32],
) -> Vec<u8> {
    let mut parameters = account_param(&harness.account);
    parameters.extend_from_slice(&device_id);
    parameters.extend_from_slice(&conversation);
    parameters.extend_from_slice(&authorization_id);
    parameters
}

#[test]
fn a_welcome_is_stored_only_under_the_finalization_that_authorized_it() -> TestResult {
    let (mut harness, conversation, finalization_id) = finalized()?;
    let welcome = welcome_bytes(&harness, conversation, finalization_id)?;
    // The named authorization must be the wrapper's finalization.
    let other = welcome_params(&harness, DEVICE_ID, conversation, [60; 32]);
    assert_eq!(
        code(harness.run(Op::DeliverWelcome, &other, Some(&welcome))?),
        Some(E2eeReplyCode::FinalityRequired)
    );
    // A wrapper naming a finalization the conversation never retained.
    let unknown = welcome_bytes(&harness, conversation, [60; 32])?;
    let unknown_params = welcome_params(&harness, DEVICE_ID, conversation, [60; 32]);
    assert_eq!(
        code(harness.run(Op::DeliverWelcome, &unknown_params, Some(&unknown))?),
        Some(E2eeReplyCode::FinalityRequired)
    );
    // A device the roster does not list.
    let inactive = welcome_params(&harness, [9; 16], conversation, finalization_id);
    assert_eq!(
        code(harness.run(Op::DeliverWelcome, &inactive, Some(&welcome))?),
        Some(E2eeReplyCode::DeviceRequired)
    );
    // A wrapper of another kind is not a welcome.
    let binding = harness.binding_bytes()?;
    let params = welcome_params(&harness, DEVICE_ID, conversation, finalization_id);
    assert_eq!(
        code(harness.run(Op::DeliverWelcome, &params, Some(&binding))?),
        Some(E2eeReplyCode::InvalidFragment)
    );
    let count = harness.coordinator.state.mailboxes.item_count();
    let outcome = ok(harness.run(Op::DeliverWelcome, &params, Some(&welcome))?)?;
    assert_eq!(
        outcome.result,
        ResultBody::Stored(StoreKind::Welcome, object_id(&welcome))
    );
    assert_eq!(
        harness.coordinator.state.mailboxes.item_count(),
        count.saturating_add(1)
    );
    Ok(())
}

#[test]
fn a_binding_delivery_refuses_a_welcome_wrapper() -> TestResult {
    let (mut harness, conversation, finalization_id) = finalized()?;
    let welcome = welcome_bytes(&harness, conversation, finalization_id)?;
    let mut parameters = account_param(&harness.account);
    parameters.extend_from_slice(&DEVICE_ID);
    assert_eq!(
        code(harness.run(Op::DeliverBinding, &parameters, Some(&welcome))?),
        Some(E2eeReplyCode::InvalidFragment)
    );
    Ok(())
}

#[test]
fn a_staged_reinit_must_name_the_conversation_and_attempt_it_is_delivered_under() -> TestResult {
    let (mut harness, conversation, _) = finalized()?;
    let staged = staged_bytes(&harness, conversation, NEW_CONVERSATION)?;
    // The request names a different new conversation than the wrapper.
    let other = welcome_params(&harness, DEVICE_ID, [22; 32], ATTEMPT);
    assert_eq!(
        code(harness.run(Op::DeliverWelcome, &other, Some(&staged))?),
        Some(E2eeReplyCode::FinalityRequired)
    );
    // The request names a different attempt than the receipt.
    let attempt = welcome_params(&harness, DEVICE_ID, NEW_CONVERSATION, [1; 32]);
    assert_eq!(
        code(harness.run(Op::DeliverWelcome, &attempt, Some(&staged))?),
        Some(E2eeReplyCode::FinalityRequired)
    );
    // A wrapper whose target is not the named device fails verification.
    let elsewhere = welcome_params(&harness, [9; 16], NEW_CONVERSATION, ATTEMPT);
    assert_eq!(
        code(harness.run(Op::DeliverWelcome, &elsewhere, Some(&staged))?),
        Some(E2eeReplyCode::DeviceRequired)
    );
    let params = welcome_params(&harness, DEVICE_ID, NEW_CONVERSATION, ATTEMPT);
    let outcome = ok(harness.run(Op::DeliverWelcome, &params, Some(&staged))?)?;
    assert_eq!(
        outcome.result,
        ResultBody::Stored(StoreKind::StagedReinit, object_id(&staged))
    );
    // The staged mailbox pages the wrapper back once its old conversation is
    // admitted.
    let page = ok(harness.run(Op::FetchMailbox, &[4, 0], None)?)?;
    assert_eq!(page.result, ResultBody::MailboxPage);
    assert_eq!(
        page.responses
            .first()
            .map(|response| response.bytes.clone()),
        Some(staged)
    );
    Ok(())
}

/// Entropy that is exhausted.
struct Exhausted;

impl EntropySource for Exhausted {
    fn fill_exact(&mut self, _: &mut [u8]) -> Result<(), EntropyError> {
        Err(EntropyError::Unavailable)
    }
}

#[test]
fn a_mailbox_page_without_entropy_for_its_tokens_is_refused() -> TestResult {
    let (mut harness, _, _) = finalized()?;
    let binding = harness.binding_bytes()?;
    deliver_binding(&mut harness, &binding)?;
    let count = harness.coordinator.state.mailboxes.item_count();
    let outcome =
        evaluate_request_with_entropy(&harness, Op::FetchMailbox, &[2, 0], None, &mut Exhausted)?;
    assert_eq!(code(outcome), Some(E2eeReplyCode::RateLimited));
    assert_eq!(harness.coordinator.state.mailboxes.item_count(), count);
    let page = ok(harness.run(Op::FetchMailbox, &[2, 0], None)?)?;
    assert!(
        page.responses
            .first()
            .and_then(|response| response.delivery_token)
            .is_some()
    );
    Ok(())
}
