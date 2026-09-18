//! Leaf-membership proof publication (companion Section 13.7.3): the
//! server retains each conversation's device-attested old-leaf proofs so
//! Commit and ReInit ACK signers can be identified, ReInit submitter roles
//! can be checked, and the expected ReInit continuing set can be bounded
//! without any private MLS state.

use agenc_ircd_domain::e2ee::projection::StoreKind;
use agenc_ircd_e2ee::limits::MAX_LEAF_MEMBERSHIP_OBJECT;
use agenc_ircd_e2ee::membership::{
    Admission, AdmissionRefusal, MembershipRefusal, VerifiedLeafMembership,
    verify_leaf_membership_proof,
};
use agenc_ircd_e2ee::object::IrcWireObjectKind;
use agenc_ircd_e2ee::objects::membership::{IrcLeafDispositionKind, IrcLeafMembershipProof};
use agenc_ircd_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;
use agenc_ircd_storage::TableId;
use agenc_ircd_storage::e2ee_records::{SEQUENCER_ROW_KIND, SequencerRow};

use super::super::CompanionCoordinator;
use super::super::request::{Outcome, ResultBody, state_row};
use super::super::roster_snapshots::{Named, RESOLUTION_WORK_BYTES, resolve};
use super::{Exec, Fail};

/// `submit_membership`: the attached device whose Device ID equals the
/// proof's, on an account that is a principal of the current binding,
/// publishes one proof. The proof is verified against the account's
/// retained root and the retained roster snapshot it names, admitted under
/// the 13.7.3 replacement and conflict rules, and retained durably before
/// any ACK it authenticates.
pub fn submit_membership(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let conversation_id = exec.params().read(|reader| reader.fixed::<32>())?;
    let (device, _) = exec.attached_device()?;
    super::route_successor::owner(exec, &conversation_id)?;
    let (object, bytes) = exec.payload()?;
    let proof = decode_proof(object, &conversation_id)?;
    let verified = verify(exec, &conversation_id, &proof, &device)?;
    let object_id = *agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes();
    if admit(exec, &conversation_id, &verified, &object_id)? == Admission::Unchanged {
        return Ok(Outcome::scalar(ResultBody::Stored(
            StoreKind::Membership,
            object_id,
        )));
    }
    stored(bytes, conversation_id, object_id, verified)
}

/// Exactly one `leaf_membership_proof` body naming a leaf the group can hold.
fn decode_proof(
    object: &agenc_ircd_e2ee::object::IrcWireObject,
    conversation_id: &[u8; 32],
) -> Result<IrcLeafMembershipProof, Fail> {
    let malformed = || Fail::with(E2eeReplyCode::InvalidFragment, conversation_id);
    if object.kind() != IrcWireObjectKind::LeafMembershipProof {
        return Err(malformed());
    }
    let mut budget = DecodeBudget::new(MAX_LEAF_MEMBERSHIP_OBJECT, 1 << 12);
    let proof = IrcLeafMembershipProof::decode_exact(object.body(), &mut budget)
        .map_err(|_| malformed())?;
    if proof.tbs.leaf_index >= agenc_ircd_e2ee::limits::MAX_GROUP_LEAVES {
        return Err(malformed());
    }
    Ok(proof)
}

/// The attached device's own proof on its own account, verified against
/// the retained root and roster snapshot the proof names (companion
/// 13.7.3). A continuing leaf keeps the credential it was authorized
/// under, so after a roster or root rotation its proof still names the
/// predecessor; the snapshot is resolved from the same retained objects
/// startup reconstruction re-verifies, and a roster that was never
/// retained is a roster mismatch. The device must have been active in that
/// named roster, which the verifier checks, and must be roster-active now,
/// which `attached_device` has already checked against the directory for
/// this same device, as ACK identification does. Both dispositions take
/// this one path: a `removed` proof comes from a device that is still
/// roster-active, and a revoked device states nothing because revocation
/// already took its claim out of the expected set.
fn verify(
    exec: &Exec<'_>,
    conversation_id: &[u8; 32],
    proof: &IrcLeafMembershipProof,
    device: &[u8; 16],
) -> Result<VerifiedLeafMembership, Fail> {
    let invalid = || Fail::with(E2eeReplyCode::BindingAuthInvalid, conversation_id);
    if proof.tbs.device_id != *device {
        return Err(Fail::with(E2eeReplyCode::DeviceRequired, conversation_id));
    }
    let account = exec.account_id()?;
    if proof.tbs.account_id.as_slice() != account {
        return Err(invalid());
    }
    let named = Named {
        root_fingerprint: proof.tbs.root_fingerprint,
        root_generation: proof.tbs.root_generation,
        roster_id: proof.tbs.roster_id,
    };
    let _memory = exec
        .backing
        .reserve(RESOLUTION_WORK_BYTES)
        .map_err(|_| Fail::from(E2eeReplyCode::RateLimited))?;
    let network_id = &exec.coordinator.network_id;
    let (root, roster) =
        resolve(&exec.coordinator.state, network_id, &account, &named).ok_or_else(invalid)?;
    verify_leaf_membership_proof(network_id, conversation_id, proof, &root, &roster).map_err(
        |refusal| match refusal {
            MembershipRefusal::DeviceInactive => {
                Fail::with(E2eeReplyCode::DeviceRequired, conversation_id)
            }
            MembershipRefusal::Invalid | MembershipRefusal::SignatureInvalid => invalid(),
        },
    )
}

/// The conversation's rules: a removed proof names a retained finalized
/// record, the proof's epoch has been reached (a later epoch names an old
/// state that does not exist yet), and the retained set admits it.
fn admit(
    exec: &Exec<'_>,
    conversation_id: &[u8; 32],
    verified: &VerifiedLeafMembership,
    object_id: &[u8; 32],
) -> Result<Admission, Fail> {
    let state = exec
        .coordinator
        .state
        .conversations
        .get(conversation_id)
        .ok_or_else(|| Fail::with(E2eeReplyCode::RouteInvalid, conversation_id))?;
    let removal = &verified.removal_finalization_id;
    let objects = &exec.coordinator.state.objects;
    if !verified.is_continuing() && !retained_finalization(objects, state, removal) {
        return Err(Fail::with(
            E2eeReplyCode::BindingAuthInvalid,
            conversation_id,
        ));
    }
    let accepted_epoch = exec
        .coordinator
        .state
        .logs
        .get(conversation_id)
        .map(agenc_ircd_domain::e2ee::sequencer_log::SequencerLog::accepted_epoch)
        .ok_or_else(|| Fail::with(E2eeReplyCode::RouteInvalid, conversation_id))?;
    if verified.epoch > accepted_epoch {
        return Err(Fail::with(E2eeReplyCode::EpochStale, conversation_id));
    }
    state
        .memberships
        .admit(object_id, verified)
        .map_err(|refusal| match refusal {
            AdmissionRefusal::Conflict => {
                Fail::with(E2eeReplyCode::OperationConflict, conversation_id)
            }
            AdmissionRefusal::QuotaExceeded => {
                Fail::with(E2eeReplyCode::RateLimited, conversation_id)
            }
        })
}

/// Stages the proof object and its `membership/v1/` row; the retained set
/// changes only when the batch commits.
fn stored(
    bytes: &[u8],
    conversation_id: [u8; 32],
    object_id: [u8; 32],
    verified: VerifiedLeafMembership,
) -> Result<Outcome, Fail> {
    let encoding = || Fail::from(E2eeReplyCode::InvalidFragment);
    let disposition = match verified.disposition {
        IrcLeafDispositionKind::Continuing => 1,
        IrcLeafDispositionKind::Removed => 2,
    };
    let key = SequencerRow::membership_key(
        &conversation_id,
        verified.leaf_index,
        &verified.old_credential_hash,
    )
    .map_err(|_| encoding())?;
    let row = SequencerRow::Membership {
        object_id,
        epoch: verified.epoch,
        device_id: verified.device_id,
        disposition,
    }
    .encode()
    .map_err(|_| encoding())?;
    let mut outcome = Outcome::scalar(ResultBody::Stored(StoreKind::Membership, object_id));
    outcome.security_mutation = true;
    outcome
        .writes
        .push(CompanionCoordinator::object_write(bytes)?);
    outcome
        .writes
        .push(state_row(TableId::E2eeState, SEQUENCER_ROW_KIND, key, row).map_err(Fail::from)?);
    outcome.effects.push(Box::new(move |companion| {
        if let Some(state) = companion.conversations.get_mut(&conversation_id) {
            state.memberships.insert(object_id, verified);
        }
    }));
    Ok(outcome)
}

/// A retained leaf-membership proof is readable through `fetch_object` only
/// under the conversation it names and only by an account that is a
/// principal of that conversation's binding (companion 13.7.3). Every
/// other object kind is unaffected.
pub(super) fn readable(exec: &Exec<'_>, requested: &[u8; 32], bytes: &[u8]) -> bool {
    let mut budget = DecodeBudget::new(MAX_LEAF_MEMBERSHIP_OBJECT, 1 << 12);
    // Any other kind (or an unparsable object, which the recovery read
    // filter already refuses) is not a proof and is unaffected here.
    let Ok(object) = agenc_ircd_e2ee::object::IrcWireObject::decode_kind(
        bytes,
        Some(IrcWireObjectKind::LeafMembershipProof),
        &mut budget,
    ) else {
        return true;
    };
    let named = IrcLeafMembershipProof::decode_exact(object.body(), &mut budget)
        .map(|proof| proof.tbs.conversation_id);
    let principal = exec.account_id().is_ok_and(|account| {
        exec.coordinator
            .state
            .conversations
            .get(requested)
            .is_some_and(|state| state.principal_accounts.contains(&account))
    });
    named.as_ref() == Ok(requested) && principal
}

/// Whether `finalization_id` names a finalization this conversation retains:
/// its terminal request is a retained `finalization_request` object.
pub(in crate::e2ee::coordinator) fn retained_finalization(
    objects: &std::collections::BTreeMap<[u8; 32], Vec<u8>>,
    state: &super::super::ConversationState,
    finalization_id: &[u8; 32],
) -> bool {
    state
        .proofs
        .get(finalization_id)
        .and_then(|object_id| objects.get(object_id))
        .and_then(|bytes| agenc_ircd_e2ee::object::IrcWireObject::peek(bytes).ok())
        .is_some_and(|(kind, _)| kind == IrcWireObjectKind::FinalizationRequest)
}
