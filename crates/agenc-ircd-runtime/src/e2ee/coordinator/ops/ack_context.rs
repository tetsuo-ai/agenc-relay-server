//! Public ACK bindings. An ACK signer is identified through the
//! conversation's stored `continuing` leaf-membership proofs (companion
//! 13.7.3); copath coverage and removal outcomes remain endpoint checks.
#![forbid(unsafe_code)]
use super::{Exec, Fail};
use agenc_ircd_crypto::SignatureDomain;
use agenc_ircd_domain::e2ee::sequencer_log::{AttemptSlot, CandidateSlot};
use agenc_ircd_e2ee::limits::{MAX_REINIT_OBJECT, MAX_SEQUENCER_RECORD_OBJECT};
use agenc_ircd_e2ee::membership::{LeafMembershipSet, RetainedLeafMembership};
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::conversation::IrcKeyPackagePlanEntry;
use agenc_ircd_e2ee::objects::reinit::{
    IrcReInitAck, IrcReInitAckKind, IrcReInitAckTbs, IrcReInitActivationRequest, IrcReInitAttempt,
};
use agenc_ircd_e2ee::objects::sequencing::{
    IrcCommitAck, IrcCommitAckTbs, IrcFinalizationCoreTbs, IrcSequencerRecord,
};
use agenc_ircd_e2ee::tls::{DecodeBudget, TlsDecode, TlsEncode};
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;
use std::collections::BTreeSet;

/// The old leaf an ACK claims and the signature it carries.
pub(super) struct AckSigner<'a> {
    /// `old_leaf_index`.
    pub(super) leaf_index: u32,
    /// `old_credential_hash`.
    pub(super) old_credential_hash: [u8; 32],
    /// The prior epoch the proof must not postdate.
    pub(super) prior_epoch: u64,
    /// The registered ACK label.
    pub(super) domain: SignatureDomain,
    /// The suite-encoded `old_leaf_signature`.
    pub(super) signature: &'a [u8],
}

impl<'a> AckSigner<'a> {
    /// The claimed signer of a Commit ACK.
    pub(super) fn commit(ack: &'a IrcCommitAck) -> Self {
        Self {
            leaf_index: ack.tbs.old_leaf_index,
            old_credential_hash: ack.tbs.old_credential_hash,
            prior_epoch: ack.tbs.prior_epoch,
            domain: SignatureDomain::CommitProcessed,
            signature: ack.old_leaf_signature.as_slice(),
        }
    }

    /// The claimed signer of a ReInit ACK against the old group's accepted
    /// epoch, the last epoch whose leaves the ReInit closes.
    pub(super) fn reinit(ack: &'a IrcReInitAck, accepted_epoch: u64) -> Self {
        Self {
            leaf_index: ack.tbs.old_leaf_index,
            old_credential_hash: ack.tbs.old_credential_hash,
            prior_epoch: accepted_epoch,
            domain: SignatureDomain::ReinitProcessed,
            signature: ack.old_leaf_signature.as_slice(),
        }
    }
}

fn memberships<'a>(
    exec: &Exec<'a>,
    conversation: &[u8; 32],
) -> Result<&'a LeafMembershipSet, Fail> {
    exec.coordinator
        .state
        .conversations
        .get(conversation)
        .map(|state| &state.memberships)
        .ok_or_else(|| Fail::with(E2eeReplyCode::BindingAuthInvalid, conversation))
}

/// Whether the proof's device is roster-active in the directory now.
fn device_active(exec: &Exec<'_>, account: &[u8; 24], device: &[u8; 16]) -> bool {
    agenc_ircd_e2ee::ids::account_id_digest(&exec.coordinator.network_id, account)
        .ok()
        .and_then(|digest| exec.coordinator.state.directory.account(&digest))
        .is_some_and(|entry| entry.device_active(device))
}

/// Identifies the signer of an ACK through the stored `continuing` proof
/// whose leaf equals the ACK's and whose epoch is not later than the ACK's
/// prior epoch, requires that device to be roster-active now, and verifies
/// the ACK signature under the proof's public key with the registered
/// label. An ACK with no such proof, from a revoked device, or with a
/// signature that does not verify is refused with `E2EE_BINDING_AUTH_INVALID`
/// and consumes no state (companion 13.7.3).
pub(super) fn identify<'a>(
    exec: &Exec<'a>,
    conversation: &[u8; 32],
    signer: &AckSigner<'_>,
    tbs: &impl TlsEncode,
) -> Result<&'a RetainedLeafMembership, Fail> {
    let invalid = || Fail::with(E2eeReplyCode::BindingAuthInvalid, conversation);
    let entry = memberships(exec, conversation)?
        .identify(
            signer.leaf_index,
            &signer.old_credential_hash,
            signer.prior_epoch,
            signer.domain,
            tbs,
            signer.signature,
        )
        .map_err(|_| invalid())?;
    if !device_active(exec, &entry.proof.account_id, &entry.proof.device_id) {
        return Err(invalid());
    }
    Ok(entry)
}

/// A standalone ACK is admitted only from the attached device its proof
/// names (companion 11.4: "attached device matching signer").
pub(super) fn identify_submitter<'a>(
    exec: &Exec<'a>,
    conversation: &[u8; 32],
    signer: &AckSigner<'_>,
    tbs: &impl TlsEncode,
) -> Result<&'a RetainedLeafMembership, Fail> {
    let entry = identify(exec, conversation, signer, tbs)?;
    let (device, _) = exec.attached_device()?;
    if (exec.account_id()?, device) != (entry.proof.account_id, entry.proof.device_id) {
        return Err(Fail::with(E2eeReplyCode::BindingAuthInvalid, conversation));
    }
    Ok(entry)
}

/// Identifies every ACK a terminal request embeds, in order, refusing a
/// second ACK by one signing device and any signer whose device is no
/// longer roster-active.
pub(super) fn identify_set<'a, 'b, T: TlsEncode + 'b>(
    exec: &Exec<'a>,
    conversation: &[u8; 32],
    acks: impl Iterator<Item = (AckSigner<'b>, &'b T)>,
) -> Result<Vec<&'a RetainedLeafMembership>, Fail> {
    let invalid = || Fail::with(E2eeReplyCode::BindingAuthInvalid, conversation);
    let set = memberships(exec, conversation)?;
    let mut devices = std::collections::BTreeSet::new();
    let mut signers = Vec::new();
    for (signer, tbs) in acks {
        let entry = set
            .identify_distinct(
                &mut devices,
                signer.leaf_index,
                &signer.old_credential_hash,
                signer.prior_epoch,
                signer.domain,
                tbs,
                signer.signature,
            )
            .map_err(|_| invalid())?;
        if !device_active(exec, &entry.proof.account_id, &entry.proof.device_id) {
            return Err(invalid());
        }
        signers.push(entry);
    }
    Ok(signers)
}

/// The account and device that sign through a proof.
pub(super) fn signer_key(entry: &RetainedLeafMembership) -> ([u8; 24], [u8; 16]) {
    agenc_ircd_e2ee::membership::signing_device(entry)
}

/// A standalone ACK names one leaf once per candidate or attempt: a
/// byte-identical resubmission repeats the same result, while a different
/// ACK for an acknowledged leaf, or a second leaf's ACK by the same device,
/// is refused with `E2EE_OPERATION_CONFLICT`.
pub(super) fn admit_standalone(
    exec: &Exec<'_>,
    conversation: &[u8; 32],
    subject: &[u8; 32],
    leaf: u32,
    object_id: &[u8; 32],
    signer: &RetainedLeafMembership,
) -> Result<(), Fail> {
    let conflict = || Fail::with(E2eeReplyCode::OperationConflict, conversation);
    let state = exec
        .coordinator
        .state
        .conversations
        .get(conversation)
        .ok_or_else(conflict)?;
    let acknowledged = state.acks.get(subject).and_then(|acks| acks.get(&leaf));
    if acknowledged.is_some_and(|existing| existing != object_id) {
        return Err(conflict());
    }
    let signed = state
        .ack_signers
        .get(subject)
        .and_then(|signers| signers.get(&signer_key(signer)));
    if signed.is_some_and(|other| *other != leaf) {
        return Err(conflict());
    }
    Ok(())
}

/// The ReInit attempt and abort submitter is an old-group device: the
/// attached device states a continuing claim (companion 11.4 and 13.7.3).
/// No plan exists before an attempt, so that is the whole check and the
/// claim set stays unbounded here. Checked before any signer access.
pub(super) fn old_group_device<'a>(
    exec: &Exec<'a>,
    conversation: &[u8; 32],
) -> Result<&'a RetainedLeafMembership, Fail> {
    let (device, _) = exec.attached_device()?;
    let key = (exec.account_id()?, device);
    memberships(exec, conversation)?
        .expected_continuing(|account, device| device_active(exec, account, device))
        .into_iter()
        .find(|entry| signer_key(entry) == key)
        .ok_or_else(|| Fail::with(E2eeReplyCode::BindingAuthInvalid, conversation))
}

/// The ReInit activation submitter is a continuing old-group device: an
/// old-group device that the attempt's KeyPackage plan carries into the
/// new group, as the creator or a Welcome joiner.
pub(super) fn continuing_device(
    exec: &Exec<'_>,
    conversation: &[u8; 32],
    attempt: &IrcReInitAttempt,
) -> Result<(), Fail> {
    let entry = old_group_device(exec, conversation)?;
    let planned = attempt
        .key_package_plan
        .entries
        .as_slice()
        .iter()
        .any(|planned| plan_device(planned) == signer_key(entry));
    if !planned {
        return Err(Fail::with(E2eeReplyCode::BindingAuthInvalid, conversation));
    }
    Ok(())
}

fn plan_device(entry: &IrcKeyPackagePlanEntry) -> ([u8; 24], [u8; 16]) {
    let account = entry.account_id.exactly::<24>().unwrap_or([0; 24]);
    (account, entry.device_id)
}

/// An activation's embedded ACKs cover the attempt exactly (companion
/// 13.7.3 and 13.8): every ACK is proof-identified by a distinct device,
/// names that device's own plan entry for its role, exactly one ACK exists
/// per plan entry, and no expected continuing leaf lacks a proof-backed
/// ACK. A missing continuing leaf is `E2EE_BINDING_AUTH_INVALID`.
///
/// The expected continuing set is the conversation's continuing claims
/// bounded by the attempt's approved `IrcKeyPackagePlan`: a claim the plan
/// does not carry has already been answered by the old controller threshold
/// that signed `key_package_plan_id`, so it never blocks an activation and
/// no one device can hold the migration open with a leaf key no server can
/// place in the ratchet tree.
pub(super) fn activation_coverage(
    exec: &Exec<'_>,
    conversation: &[u8; 32],
    accepted_epoch: u64,
    request: &IrcReInitActivationRequest,
) -> Result<(), Fail> {
    let invalid = || Fail::with(E2eeReplyCode::BindingAuthInvalid, conversation);
    let acks = request.acknowledgements.as_slice();
    let signers = identify_set(
        exec,
        conversation,
        acks.iter()
            .map(|ack| (AckSigner::reinit(ack, accepted_epoch), &ack.tbs)),
    )?;
    let roles = acks
        .iter()
        .zip(&signers)
        .all(|(ack, signer)| reinit_role_device(&ack.tbs, &request.attempt, signer));
    let planned: BTreeSet<([u8; 24], [u8; 16])> = request
        .attempt
        .key_package_plan
        .entries
        .as_slice()
        .iter()
        .map(plan_device)
        .collect();
    if !roles || acks.len() != request.attempt.key_package_plan.entries.as_slice().len() {
        return Err(invalid());
    }
    let covered = |expected: &RetainedLeafMembership| {
        signers
            .iter()
            .any(|signer| signer.object_id == expected.object_id)
    };
    let missing = memberships(exec, conversation)?
        .expected_continuing(|account, device| device_active(exec, account, device))
        .into_iter()
        .filter(|expected| planned.contains(&signer_key(expected)))
        .any(|expected| !covered(expected));
    if missing {
        return Err(invalid());
    }
    Ok(())
}

/// Whether the ReInit plan entry an ACK's role names belongs to the
/// identified signer's device: the creator entry for `creator_state`, the
/// entry holding the reserved ref for `welcome_join`.
pub(super) fn reinit_role_device(
    ack: &IrcReInitAckTbs,
    attempt: &IrcReInitAttempt,
    signer: &RetainedLeafMembership,
) -> bool {
    agenc_ircd_e2ee::membership::planned_ack_device(ack, attempt) == Some(signer_key(signer))
}

pub(super) fn commit_submission(
    exec: &Exec<'_>,
    conversation: &[u8; 32],
    ack: &IrcCommitAckTbs,
    slot: &CandidateSlot,
) -> Result<(), Fail> {
    if ack.profile_version != 1 {
        return Err(Fail::with(E2eeReplyCode::InvalidFragment, conversation));
    }
    if ack.network_id != exec.coordinator.network_id {
        return Err(Fail::with(E2eeReplyCode::RouteInvalid, conversation));
    }
    if ack.conversation_id != *conversation
        || ack.prior_epoch != slot.position.prior_epoch
        || Some(ack.resulting_epoch) != slot.position.prior_epoch.checked_add(1)
    {
        return Err(Fail::with(E2eeReplyCode::EpochStale, conversation));
    }
    Ok(())
}

pub(super) fn commit_finalization(ack: &IrcCommitAckTbs, core: &IrcFinalizationCoreTbs) -> bool {
    let named = (
        ack.profile_version,
        ack.network_id,
        ack.conversation_id,
        ack.prior_epoch,
        ack.candidate_id,
        ack.commit_object_id,
        ack.resulting_epoch,
    );
    let expected = (
        core.profile_version,
        core.network_id,
        core.conversation_id,
        core.prior_epoch,
        core.candidate_id,
        core.commit_object_id,
        core.resulting_epoch,
    );
    let result = (
        ack.resulting_group_context_digest,
        ack.resulting_ratchet_tree_digest,
        ack.finalization_authenticator,
    );
    let certified = (
        core.resulting_group_context_digest,
        core.resulting_ratchet_tree_digest,
        core.finalization_authenticator,
    );
    named == expected && result == certified
}

/// The public context of a ReInit ACK: profile, network, old conversation,
/// and the log's accepted old ReInit state.
pub(super) fn reinit_submission(
    exec: &Exec<'_>,
    conversation: &[u8; 32],
    ack: &IrcReInitAckTbs,
) -> Result<(), Fail> {
    if ack.profile_version != 1 {
        return Err(Fail::with(E2eeReplyCode::InvalidFragment, conversation));
    }
    if ack.network_id != exec.coordinator.network_id || ack.old_conversation_id != *conversation {
        return Err(Fail::with(E2eeReplyCode::RouteInvalid, conversation));
    }
    let log = exec
        .coordinator
        .state
        .logs
        .get(conversation)
        .ok_or_else(|| Fail::with(E2eeReplyCode::BindingAuthInvalid, conversation))?;
    if ack.old_reinit_state_id != *log.accepted_state_id() {
        return Err(Fail::with(E2eeReplyCode::EpochStale, conversation));
    }
    Ok(())
}

/// A ReInit ACK names the exact retained attempt receipt and object, and
/// its role names the identified signer's own plan entry.
pub(super) fn reinit_retained(
    exec: &Exec<'_>,
    conversation: &[u8; 32],
    ack: &IrcReInitAckTbs,
    slot: &AttemptSlot,
    signer: &RetainedLeafMembership,
) -> Result<(), Fail> {
    let invalid = || Fail::with(E2eeReplyCode::BindingAuthInvalid, conversation);
    let log = exec
        .coordinator
        .state
        .logs
        .get(conversation)
        .ok_or_else(invalid)?;
    let record_id = exec
        .coordinator
        .state
        .conversations
        .get(conversation)
        .and_then(|state| state.records.get(&slot.route_sequence))
        .ok_or_else(invalid)?;
    with_retained(
        exec,
        record_id,
        IrcWireObjectKind::SequencerRecord,
        MAX_SEQUENCER_RECORD_OBJECT,
        |record: IrcSequencerRecord| {
            let IrcSequencerRecord::ReinitAttempt(receipt) = record else {
                return Err(invalid());
            };
            let tbs = &receipt.tbs;
            let named = (
                tbs.profile_version,
                tbs.network_id,
                tbs.old_conversation_id,
                tbs.old_reinit_state_id,
                tbs.route_sequence,
                tbs.attempt_sequence,
                tbs.predecessor_record_id,
                tbs.reinit_attempt_id,
            );
            let expected = (
                1,
                exec.coordinator.network_id,
                *conversation,
                *log.accepted_state_id(),
                slot.route_sequence,
                slot.attempt_sequence,
                slot.predecessor_record_id,
                slot.attempt_id,
            );
            if named != expected {
                return Err(invalid());
            }
            with_retained(
                exec,
                &tbs.attempt_object_id,
                IrcWireObjectKind::ReinitAttempt,
                MAX_REINIT_OBJECT,
                |attempt: IrcReInitAttempt| {
                    if attempt.tbs.attempt_sequence != slot.attempt_sequence
                        || !reinit_attempt(ack, &attempt, &slot.attempt_id)
                        || !reinit_role_device(ack, &attempt, signer)
                    {
                        return Err(invalid());
                    }
                    Ok(())
                },
            )
        },
    )
}

/// Both decoded wire and typed body remain inside the reservation's lifetime.
fn with_retained<T: TlsDecode>(
    exec: &Exec<'_>,
    id: &[u8; 32],
    kind: IrcWireObjectKind,
    limit: usize,
    verify: impl FnOnce(T) -> Result<(), Fail>,
) -> Result<(), Fail> {
    let invalid = || Fail::from(E2eeReplyCode::BindingAuthInvalid);
    let bytes = exec.coordinator.state.objects.get(id).ok_or_else(invalid)?;
    if bytes.len() > limit {
        return Err(invalid());
    }
    let capacity = bytes
        .len()
        .checked_mul(4)
        .and_then(|n| n.checked_add(8192))
        .ok_or_else(invalid)?;
    let _memory = exec
        .backing
        .reserve(capacity)
        .map_err(|_| Fail::from(E2eeReplyCode::RateLimited))?;
    if agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes() != id {
        return Err(invalid());
    }
    let mut budget = DecodeBudget::new(capacity, 1 << 16);
    let object =
        IrcWireObject::decode_kind(bytes, Some(kind), &mut budget).map_err(|_| invalid())?;
    let value = T::decode_exact(object.body(), &mut budget).map_err(|_| invalid())?;
    verify(value)
}

pub(super) fn reinit_attempt(
    ack: &IrcReInitAckTbs,
    attempt: &IrcReInitAttempt,
    id: &[u8; 32],
) -> bool {
    let tbs = &attempt.tbs;
    let named = (
        ack.network_id,
        ack.old_conversation_id,
        ack.new_conversation_id,
        ack.old_reinit_state_id,
        ack.reinit_attempt_id,
    );
    let expected = (
        tbs.network_id,
        tbs.old_conversation_id,
        tbs.new_conversation_id,
        tbs.old_reinit_state_id,
        *id,
    );
    let result = (
        ack.new_group_info_digest,
        ack.new_group_context_digest,
        ack.new_ratchet_tree_digest,
        ack.new_exporter_authenticator,
    );
    let expected_result = (
        tbs.new_group_info_digest,
        tbs.new_group_context_digest,
        tbs.new_ratchet_tree_digest,
        tbs.new_exporter_authenticator,
    );
    ack.profile_version == 1
        && tbs.profile_version == 1
        && named == expected
        && result == expected_result
        && reinit_role(ack, attempt)
}

fn reinit_role(ack: &IrcReInitAckTbs, attempt: &IrcReInitAttempt) -> bool {
    let creator = &attempt.tbs;
    match ack.ack_kind {
        IrcReInitAckKind::CreatorState => {
            ack.key_package_ref.as_slice().is_empty()
                && ack.old_leaf_index == creator.creator_old_leaf_index
                && ack.old_credential_hash == creator.creator_old_credential_hash
        }
        IrcReInitAckKind::WelcomeJoin => {
            !ack.key_package_ref.as_slice().is_empty()
                && ack.old_leaf_index != creator.creator_old_leaf_index
                && attempt
                    .key_package_plan
                    .entries
                    .as_slice()
                    .iter()
                    .any(|entry| entry.creator == 0 && entry.key_package_ref == ack.key_package_ref)
        }
    }
}
