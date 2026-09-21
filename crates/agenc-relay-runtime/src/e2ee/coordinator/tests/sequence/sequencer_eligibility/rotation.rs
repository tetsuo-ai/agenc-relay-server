//! Per-conversation signer pins across a sequencer key rotation (companion
//! 9.2.1): a new receipt follows the conversation's pin, a terminal follows
//! its receipt, a finalized `SEQUENCER` transition moves the pin, and a
//! blocked route keeps only opaque delivery.
#![forbid(unsafe_code)]
use super::*;
use crate::e2ee::coordinator::CompanionCoordinator;
use crate::e2ee::coordinator::tests::sequence::recovery_pending::close_authorization::{
    finalization_bytes, open_finalization, transition_bytes,
};
use crate::e2ee::coordinator::tests::sequence::reinit;
use crate::e2ee::coordinator::tests::support::private_message_bytes;
use agenc_relay_crypto::{Ed25519Signature, verify_canonical};
use agenc_relay_e2ee::objects::aad::ArcApplicationAad;
use agenc_relay_e2ee::objects::conversation::ArcSequencerCredential;
use agenc_relay_e2ee::objects::sequencing::{ArcCandidateReceipt, ArcSequencerRecord};
use agenc_relay_storage::e2ee_records::RouteRow;
use agenc_relay_storage::{PersistentRecordValue, TableId};

mod restart;

/// A bootstrapped harness with its conversation, old and successor credential ids.
pub(super) type Pinned = (Harness, [u8; 32], [u8; 32], [u8; 32]);
/// The pinned and blocked credentials a route row carries.
pub(super) type StoredPin = (Option<[u8; 32]>, Option<[u8; 32]>);

/// The seed of the old (generation-0) sequencer key.
pub(super) const OLD: u8 = 90;
/// The seed of the successor (generation-1) sequencer key.
pub(super) const NEXT: u8 = 91;

fn credential_id(credential: &ArcSequencerCredential) -> TestResult<[u8; 32]> {
    Ok(semantic_id_of(
        SemanticHashDomain::SequencerKey,
        &credential.tbs,
    )?)
}

/// The old and successor credentials and the generation-1 set naming both.
pub(super) fn overlap() -> TestResult<(
    ArcSequencerCredential,
    ArcSequencerCredential,
    SequencerKeySet,
)> {
    let old = sequencer_credential(&key(OLD), 0, (0, 2_000_000), None)?;
    let next = sequencer_credential(&key(NEXT), 1, (100, 3_000_000), Some((&key(OLD), &old)))?;
    let set = SequencerKeySet::verify(&NETWORK, &[old.clone(), next.clone()], 1, None)?;
    Ok((old, next, set))
}

/// Installs the old key as the active signer with the successor key beside
/// it, and returns both credential identifiers.
pub(super) fn install_overlap(
    coordinator: &mut CompanionCoordinator,
) -> TestResult<([u8; 32], [u8; 32])> {
    let (old, next, set) = overlap()?;
    let ids = (credential_id(&old)?, credential_id(&next)?);
    coordinator.install_signers(key(OLD), set, old, Some(key(NEXT)), None)?;
    Ok(ids)
}

/// Installs the generation-2 set naming the successor alone, with the old
/// key retired-retained when `retain`.
pub(super) fn install_retired(
    coordinator: &mut CompanionCoordinator,
    retain: bool,
) -> TestResult<([u8; 32], [u8; 32])> {
    let (old, next, overlap) = overlap()?;
    let ids = (credential_id(&old)?, credential_id(&next)?);
    let head = *overlap.credential(&ids.0).ok_or("old credential")?;
    let set = SequencerKeySet::verify(&NETWORK, std::slice::from_ref(&next), 2, Some(&head))?;
    let retired = retain.then_some((key(OLD), head));
    coordinator.install_signers(key(NEXT), set, next, None, retired)?;
    Ok(ids)
}

/// Binds the channel pinned to `credential` and publishes its policies and
/// the attached device's leaf proof.
pub(super) fn bound_pinned(harness: &mut Harness, credential: [u8; 32]) -> TestResult<[u8; 32]> {
    let conversation = bind_pinned(harness, credential)?;
    let initial = harness.initial_policy.clone();
    let operational = harness.operational_policy.clone();
    harness.publish_policy(conversation, &initial)?;
    harness.publish_policy(conversation, &operational)?;
    harness.publish_leaf_zero(conversation)?;
    Ok(conversation)
}

/// Binds the channel pinned to `credential` and returns the reply code.
fn bind_code(harness: &mut Harness, credential: [u8; 32]) -> TestResult<Option<E2eeReplyCode>> {
    harness.publish_identity_and_roster()?;
    harness.attach()?;
    let mut reserve = INSTANCE.to_vec();
    reserve.push(5);
    reserve.extend_from_slice(b"#room");
    let result = ok(harness.run(Op::ReserveChannel, &reserve, None)?)?;
    let ResultBody::Reserved(reservation, _) = result.result else {
        return Err("reservation".into());
    };
    let conversation = agenc_relay_e2ee::ids::conversation_id(&NETWORK, &GROUP)?;
    let binding = signed_binding(harness, credential)?;
    let mut params = reservation.to_vec();
    params.extend_from_slice(&conversation);
    params.extend_from_slice(&[44; 32]);
    Ok(code(harness.run(Op::BindGroup, &params, Some(&binding))?))
}

/// Bootstraps a channel pinned to the old credential under the overlap set.
pub(super) fn bootstrapped_old_pinned() -> TestResult<Pinned> {
    let mut harness = Harness::new()?;
    let (old, next) = install_overlap(&mut harness.coordinator)?;
    let conversation = bound_pinned(&mut harness, old)?;
    let opened = open_finalization(&mut harness, conversation, 0)?;
    let (bytes, _) = finalization_bytes(&harness, &opened, None, &[DEVICE])?;
    ok(harness.run(Op::SubmitFinalization, &conversation, Some(&bytes))?)?;
    Ok((harness, conversation, old, next))
}

/// Whether the receipt's signature verifies under the key of `seed`.
fn signed_by(receipt: &ArcCandidateReceipt, seed: u8) -> TestResult<bool> {
    Ok(verify_canonical(
        key(seed).public_key(),
        SignatureDomain::CandidateReceipt,
        &receipt.tbs.encode()?,
        Ed25519Signature::from_bytes(receipt.sequencer_signature),
    )
    .is_ok())
}

/// The pinned and blocked credentials the route row of `conversation`
/// carries.
pub(super) fn stored_pin(harness: &Harness, conversation: [u8; 32]) -> TestResult<StoredPin> {
    let key = RouteRow::key(&conversation)?;
    let mut row = None;
    for write in &harness.writes {
        if let Some((table, stored_key, bytes)) = write.encoded_record()
            && table == TableId::E2eeState
            && stored_key == &key
        {
            row = Some(RouteRow::decode(
                PersistentRecordValue::decode(table, bytes)?.body(),
            )?);
        }
    }
    let row = row.ok_or("route row")?;
    Ok((row.sequencer_credential_id, row.blocked_credential_id))
}

/// The credential the terminal record of `result` names.
pub(super) fn record_signer(harness: &Harness, result: &ResultBody) -> TestResult<[u8; 32]> {
    let (ResultBody::Finalized(_, _, _, id)
    | ResultBody::Aborted(_, _, _, id)
    | ResultBody::ReinitActivated(_, _, _, id)
    | ResultBody::ReinitAborted(_, _, _, id)) = result
    else {
        return Err("terminal result".into());
    };
    let bytes = harness
        .coordinator
        .state
        .objects
        .get(id)
        .ok_or("record object")?;
    let mut budget = DecodeBudget::new(1 << 22, 1 << 16);
    let object = agenc_relay_e2ee::object::ArcWireObject::decode_kind(
        bytes,
        Some(ArcWireObjectKind::SequencerRecord),
        &mut budget,
    )?;
    Ok(
        match ArcSequencerRecord::decode_exact(object.body(), &mut budget)? {
            ArcSequencerRecord::Finalization(value) => value.tbs.sequencer_key_id,
            ArcSequencerRecord::Abort(value) => value.tbs.sequencer_key_id,
            ArcSequencerRecord::ReinitActivation(value) => value.tbs.sequencer_key_id,
            ArcSequencerRecord::ReinitAbort(value) => value.tbs.sequencer_key_id,
            _ => return Err("terminal record".into()),
        },
    )
}

/// The conversation's pin and blocked marker in memory.
pub(super) fn pin_of(
    harness: &Harness,
    conversation: [u8; 32],
) -> TestResult<([u8; 32], Option<[u8; 32]>)> {
    let state = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("conversation")?;
    Ok((state.sequencer_credential_id, state.blocked_credential_id))
}

#[test]
fn bindings_pin_a_credential_and_receipts_follow_the_pin() -> TestResult {
    // Conversation A pins the old credential: its receipts are issued by
    // the active signer under that credential.
    let mut old_pinned = Harness::new()?;
    let (old, next) = install_overlap(&mut old_pinned.coordinator)?;
    let a = bound_pinned(&mut old_pinned, old)?;
    assert_eq!(pin_of(&old_pinned, a)?, (old, None));
    let (receipt, ..) = submit_candidate(&mut old_pinned, a, 0, 500)?;
    assert_eq!(receipt.tbs.sequencer_key_id, old);
    assert!(signed_by(&receipt, OLD)?);
    assert_eq!(stored_pin(&old_pinned, a)?, (Some(old), None));
    // Conversation B pins the successor: its receipts are issued by the
    // successor signer, and only once the successor's interval covers the
    // Commit's canonical validation time.
    let mut next_pinned = Harness::new()?;
    install_overlap(&mut next_pinned.coordinator)?;
    let b = bound_pinned(&mut next_pinned, next)?;
    assert_eq!(pin_of(&next_pinned, b)?, (next, None));
    let early = commit_bytes(&next_pinned, b, 0, 99)?;
    let logs = next_pinned.coordinator.state.logs.clone();
    assert_eq!(
        code(next_pinned.run(Op::SubmitCandidate, &b, Some(&early))?),
        Some(E2eeReplyCode::Syncing)
    );
    assert_eq!(next_pinned.coordinator.state.logs, logs);
    let (receipt, ..) = submit_candidate(&mut next_pinned, b, 0, 100)?;
    assert_eq!(receipt.tbs.sequencer_key_id, next);
    assert!(signed_by(&receipt, NEXT)?);
    assert_eq!(stored_pin(&next_pinned, b)?, (Some(next), None));
    // A binding pinning a credential no configured signer issues is refused.
    let mut unrelated = Harness::new()?;
    install_overlap(&mut unrelated.coordinator)?;
    assert_eq!(
        bind_code(&mut unrelated, [7; 32])?,
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    Ok(())
}

#[test]
fn a_finalized_sequencer_transition_moves_the_pin_to_the_successor() -> TestResult {
    let (mut harness, conversation, old, next) = bootstrapped_old_pinned()?;
    let opened = open_finalization(&mut harness, conversation, 1)?;
    let (bytes, terminal) = transition_bytes(&harness, &opened, &[DEVICE])?;
    let outcome = ok(harness.run(Op::SubmitFinalization, &conversation, Some(&bytes))?)?;
    assert!(matches!(outcome.result, ResultBody::Finalized(_, _, id, _) if id == terminal));
    // The transition's own finalization signs under the old credential;
    // the pin moves durably to the successor.
    assert_eq!(record_signer(&harness, &outcome.result)?, old);
    assert_eq!(pin_of(&harness, conversation)?, (next, None));
    assert_eq!(stored_pin(&harness, conversation)?, (Some(next), None));
    // Every later record signs under the successor.
    let (receipt, ..) = submit_candidate(&mut harness, conversation, 2, 500)?;
    assert_eq!(receipt.tbs.sequencer_key_id, next);
    assert!(signed_by(&receipt, NEXT)?);
    // The pin is what the daemon restores.
    let restored = harness.reloaded_with(|coordinator| install_overlap(coordinator).map(|_| ()))?;
    assert_eq!(pin_of(&restored, conversation)?, (next, None));
    Ok(())
}

#[test]
fn a_sequencer_transition_without_an_advertised_successor_is_refused() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let old = harness.pinned_credential();
    let opened = open_finalization(&mut harness, conversation, 0)?;
    let (bytes, _) = finalization_bytes(&harness, &opened, None, &[DEVICE])?;
    ok(harness.run(Op::SubmitFinalization, &conversation, Some(&bytes))?)?;
    let opened = open_finalization(&mut harness, conversation, 1)?;
    let (bytes, _) = transition_bytes(&harness, &opened, &[DEVICE])?;
    let logs = harness.coordinator.state.logs.clone();
    let writes = harness.writes.len();
    assert_eq!(
        code(harness.run(Op::SubmitFinalization, &conversation, Some(&bytes))?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    assert_eq!(harness.coordinator.state.logs, logs);
    assert_eq!(harness.writes.len(), writes);
    assert_eq!(pin_of(&harness, conversation)?, (old, None));
    Ok(())
}

#[test]
fn terminals_complete_under_the_receipt_credential_after_retirement() -> TestResult {
    let mut harness = Harness::new()?;
    let (old, _) = install_overlap(&mut harness.coordinator)?;
    let conversation = bound_pinned(&mut harness, old)?;
    let opened = open_finalization(&mut harness, conversation, 0)?;
    let (bytes, terminal) = finalization_bytes(&harness, &opened, None, &[DEVICE])?;
    // The set now omits the old credential: the open receipt is completed
    // only by the retired-retained signer, never by a replacement.
    install_retired(&mut harness.coordinator, false)?;
    assert_eq!(
        code(harness.run(Op::SubmitFinalization, &conversation, Some(&bytes))?),
        Some(E2eeReplyCode::Syncing)
    );
    install_retired(&mut harness.coordinator, true)?;
    let outcome = ok(harness.run(Op::SubmitFinalization, &conversation, Some(&bytes))?)?;
    assert!(matches!(outcome.result, ResultBody::Finalized(_, _, id, _) if id == terminal));
    assert_eq!(record_signer(&harness, &outcome.result)?, old);
    // A retired-retained signer issues no new receipt while the route
    // still pins the old credential.
    let commit = commit_bytes(&harness, conversation, 1, 500)?;
    let logs = harness.coordinator.state.logs.clone();
    assert_eq!(
        code(harness.run(Op::SubmitCandidate, &conversation, Some(&commit))?),
        Some(E2eeReplyCode::Syncing)
    );
    assert_eq!(harness.coordinator.state.logs, logs);
    Ok(())
}

#[test]
fn a_reinit_attempt_is_signed_only_under_the_old_conversation_pin() -> TestResult {
    let mut harness = Harness::new()?;
    let (old, _) = install_overlap(&mut harness.coordinator)?;
    let conversation = bound_pinned(&mut harness, old)?;
    let accepted = *harness
        .coordinator
        .state
        .logs
        .get(&conversation)
        .ok_or("log")?
        .accepted_state_id();
    let (_, attempt) = reinit::attempt(&harness, conversation, accepted, 0)?;
    // With the old key retired-retained the pin has no issuing owner.
    install_retired(&mut harness.coordinator, true)?;
    let logs = harness.coordinator.state.logs.clone();
    assert_eq!(
        code(harness.run(Op::SubmitReinitAttempt, &conversation, Some(&attempt))?),
        Some(E2eeReplyCode::Syncing)
    );
    assert_eq!(harness.coordinator.state.logs, logs);
    // Under the overlap set the active signer issues the attempt receipt.
    install_overlap(&mut harness.coordinator)?;
    let outcome = ok(harness.run(Op::SubmitReinitAttempt, &conversation, Some(&attempt))?)?;
    assert!(matches!(outcome.result, ResultBody::ReinitStaged(..)));
    assert_eq!(
        reinit::staged_receipt(&harness, conversation)?
            .tbs
            .sequencer_key_id,
        old
    );
    // The open attempt receipt is an unfinished receipt naming the old
    // credential at the next startup, which the reconciliation counts.
    let mut restored =
        harness.reloaded_with(|coordinator| install_overlap(coordinator).map(|_| ()))?;
    let write = restored
        .coordinator
        .next_restored_write(harness.now)?
        .ok_or("the reconciliation")?;
    write.apply(&mut restored.coordinator)?;
    assert_eq!(
        reinit::staged_receipt(&restored, conversation)?
            .tbs
            .sequencer_key_id,
        old
    );
    Ok(())
}

#[test]
fn a_blocked_route_refuses_candidates_attempts_and_policies_but_keeps_delivery() -> TestResult {
    let (mut harness, conversation, old, _) = bootstrapped_old_pinned()?;
    // The overlap deadline passed at a restart (`restart` covers the
    // reconciliation): the route is blocked on the old credential.
    harness
        .coordinator
        .state
        .conversations
        .get_mut(&conversation)
        .ok_or("conversation")?
        .blocked_credential_id = Some(old);
    assert_eq!(harness.coordinator.blocked_routes(), 1);
    let logs = harness.coordinator.state.logs.clone();
    let writes = harness.writes.len();
    let commit = commit_bytes(&harness, conversation, 1, 500)?;
    assert_eq!(
        code(harness.run(Op::SubmitCandidate, &conversation, Some(&commit))?),
        Some(E2eeReplyCode::Syncing)
    );
    let policy = wire(ArcWireObjectKind::Policy, &harness.operational_policy)?;
    assert_eq!(
        code(harness.run(Op::SubmitPolicy, &conversation, Some(&policy))?),
        Some(E2eeReplyCode::Syncing)
    );
    let accepted = *harness
        .coordinator
        .state
        .logs
        .get(&conversation)
        .ok_or("log")?
        .accepted_state_id();
    let (_, attempt) = reinit::attempt(&harness, conversation, accepted, 0)?;
    assert_eq!(
        code(harness.run(Op::SubmitReinitAttempt, &conversation, Some(&attempt))?),
        Some(E2eeReplyCode::Syncing)
    );
    assert_eq!(harness.coordinator.state.logs, logs);
    assert_eq!(harness.writes.len(), writes);
    // Opaque application delivery continues on the last accepted epoch.
    let aad = ArcApplicationAad {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        route_binding: channel_route_binding(&NETWORK, &INSTANCE)?,
        latest_state_id: [22; 32],
    }
    .encode()?;
    let message = wire_raw(
        ArcWireObjectKind::ApplicationMls,
        private_message_bytes(&GROUP, 1, &aad)?,
    )?;
    let mut send = conversation.to_vec();
    send.extend_from_slice(&INSTANCE);
    let outcome = ok(harness.run(Op::ApplicationChannel, &send, Some(&message))?)?;
    assert_eq!(outcome.result, ResultBody::AcceptedEvent);
    Ok(())
}

#[test]
fn signer_installation_refuses_keys_outside_their_role() -> TestResult {
    let (old, next, overlap_set) = overlap()?;
    let old_id = credential_id(&old)?;
    let head = *overlap_set.credential(&old_id).ok_or("old credential")?;
    let next_verified = *overlap_set
        .credential(&credential_id(&next)?)
        .ok_or("successor credential")?;
    let retired_set =
        SequencerKeySet::verify(&NETWORK, std::slice::from_ref(&next), 2, Some(&head))?;
    let mut harness = Harness::new()?;
    let before = harness
        .coordinator
        .signers()
        .map(|signers| signers.active.credential_id);
    // A successor key that is not the key of the set's other credential.
    assert!(
        harness
            .coordinator
            .install_signers(
                key(OLD),
                overlap_set.clone(),
                old.clone(),
                Some(key(70)),
                None
            )
            .is_err()
    );
    // A retired key that is not the key of the credential it claims.
    assert!(
        harness
            .coordinator
            .install_signers(
                key(NEXT),
                retired_set.clone(),
                next.clone(),
                None,
                Some((key(70), head))
            )
            .is_err()
    );
    // A retired credential the advertised set still carries.
    assert!(
        harness
            .coordinator
            .install_signers(
                key(OLD),
                overlap_set.clone(),
                old.clone(),
                Some(key(NEXT)),
                Some((key(NEXT), next_verified))
            )
            .is_err()
    );
    // Two roles sharing one public key, each matching its own credential.
    let reused = sequencer_credential(&key(OLD), 1, (100, 3_000_000), Some((&key(OLD), &old)))?;
    let reused_set = SequencerKeySet::verify(&NETWORK, &[old.clone(), reused], 1, None)?;
    assert!(
        harness
            .coordinator
            .install_signers(key(OLD), reused_set, old.clone(), Some(key(OLD)), None)
            .is_err()
    );
    // A failed installation changes nothing.
    assert_eq!(
        harness
            .coordinator
            .signers()
            .map(|signers| signers.active.credential_id),
        before
    );
    assert!(
        harness
            .coordinator
            .install_signers(key(NEXT), retired_set, next, None, Some((key(OLD), head)))
            .is_ok()
    );
    Ok(())
}
