//! A normal recipient independently verifies the public epoch-zero Add before touching its
//! one-use MLS key. The signed binding commits the missing context. Complete that same
//! origin with the recipient's authenticated GroupContext before publishing the private group.

use super::{
    ExpectedInitialAuthority, GenesisObjects, InitialAuthority, PublicGenesisEvidence,
    authenticated_objects, decode_object,
};
use crate::history::{ChainLimits, ChainStep, HistoricalChain, RecordReferences};
use crate::identity::{ClientIdentity, ValidationTime};
use crate::membership::{LeafMembershipSet, verify_leaf_membership_proof};
use crate::object::{ArcWireObject, ArcWireObjectKind, ObjectId};
use crate::objects::account_id_bytes;
use crate::objects::conversation::{ArcCommitAuthorizationRule, ArcInitialMemberPlan, action_bits};
use crate::objects::membership::ArcLeafMembershipProof;
use crate::objects::sequencing::{ArcCommitFinalizationCertificate, ArcSequencerRecord};
use crate::{DecodeBudget, E2eeError, TlsEncode};

/// Public inputs at the first planned recipient. Obtain the delivery's addresses, selected local
/// client, locked registered binding and complete signed objects from independently scoped reads.
pub struct FirstAddEvidence<'a> {
    /// The independently enrolled recipient whose published package the Welcome addresses.
    pub recipient: &'a ClientIdentity,
    /// The single roster carried or reaffirmed for that recipient.
    pub recipient_roster: &'a [u8],
    /// Original dual-signed continuing-leaf proof for the epoch-zero creator.
    pub creator_membership: &'a [u8],
    /// Complete standalone finalization object quoted by the selected Welcome.
    pub certificate: &'a [u8],
    /// Complete object address and semantic finalization ID quoted by that delivery.
    pub expected_certificate: (ObjectId, [u8; 32]),
}

/// Original public quorum and signed candidate verified before MLS. The missing initial clock
/// and RequiredCapabilities must be recovered from authenticated MLS to obtain initial authority.
pub struct PublicFirstAdd {
    genesis: GenesisObjects,
    candidate: [u8; 32],
    commit: ObjectId,
    finalization: [u8; 32],
    validation_time: ValidationTime,
}

impl PublicFirstAdd {
    /// The signed candidate ID, complete Commit object address and semantic finalization ID.
    #[must_use]
    pub fn identifiers(&self) -> ([u8; 32], ObjectId, [u8; 32]) {
        (self.candidate, self.commit, self.finalization)
    }

    /// Complete the original genesis using the initial context reconstructed inside the
    /// recipient's authenticated, still-unpublished epoch-one MLS group. The resulting
    /// authority is subject to the same digest, time and cross-field checks as the single-step
    /// constructor. The first Add cannot move its validation time backwards.
    pub fn complete_context(
        self,
        core: &[u8],
        budget: &mut DecodeBudget,
    ) -> Result<InitialAuthority, E2eeError> {
        let initial = self.genesis.complete(core, budget)?;
        if initial.validation_time() > self.validation_time {
            return Err(E2eeError::InvalidValue);
        }
        Ok(initial)
    }
}

/// Authenticate the original, incarnation-zero root locks and signed bootstrap under an
/// independent binding pin. Validate the first candidate and finalization at positions 0 and 1,
/// the controller approvals, creator's original MLS ACK and old-council quorum. The caller owns
/// the memory reservation for bounded original objects and the returned public proof.
pub fn authenticate_first_add(
    pin: &ExpectedInitialAuthority,
    evidence: &PublicGenesisEvidence<'_>,
    add: &FirstAddEvidence<'_>,
    budget: &mut DecodeBudget,
) -> Result<PublicFirstAdd, E2eeError> {
    let (genesis, plan) = authenticated_objects(pin, None, evidence, budget)?;
    require_recipient(&genesis, &plan, add.recipient)?;
    let memberships = creator_membership(&genesis, add.creator_membership, budget)?;
    if ObjectId::compute(add.certificate) != add.expected_certificate.0 {
        return Err(E2eeError::InvalidValue);
    }
    let certificate: ArcCommitFinalizationCertificate = decode_object(
        add.certificate,
        ArcWireObjectKind::FinalizationCertificate,
        budget,
    )?;
    let proof = &certificate.tbs.request.proof;
    let authorization = &proof.authorization.tbs;
    if authorization.authorization_rule != ArcCommitAuthorizationRule::ControlledTransition
        || authorization.action_bits
            != action_bits::ADD_LEAF | action_bits::ROSTER | action_bits::PENDING_JOIN
        || proof.acknowledgements.as_slice().len() != 1
    {
        return Err(E2eeError::InvalidValue);
    }
    let validation_time = ValidationTime(authorization.canonical_validation_time);
    possible_initial_time(&genesis, validation_time)?;
    let mut chain = HistoricalChain::from_genesis(
        &pin.network_id,
        &pin.conversation_id,
        &genesis,
        ChainLimits { max_records: 2 },
    )?;
    let commit = ObjectId::from_bytes(proof.receipt.tbs.commit_object_id);
    let candidate = ArcSequencerRecord::Candidate(proof.receipt.clone());
    advance(&mut chain, candidate, &RecordReferences::default(), budget)?;
    let candidate = chain.head().record_id;
    let finalization = check_terminal(&mut chain, certificate, add, &memberships, budget)?;
    Ok(PublicFirstAdd {
        genesis,
        candidate,
        commit,
        finalization,
        validation_time,
    })
}

fn possible_initial_time(
    genesis: &GenesisObjects,
    add_time: ValidationTime,
) -> Result<(), E2eeError> {
    // All original intervals must share at least one possible initial second at or before
    // this Add. The exact initial second stays committed by the signed context digest.
    let earliest = genesis.principals.values().fold(
        genesis.sequencer.interval.not_before,
        |start, (root, roster)| {
            start
                .max(root.interval.not_before)
                .max(roster.interval.not_before)
        },
    );
    super::anchors::require_initial_time(
        &genesis.principals,
        &genesis.sequencer,
        ValidationTime(earliest),
    )?;
    if earliest > add_time.0 {
        return Err(E2eeError::InvalidValue);
    }
    Ok(())
}

fn check_terminal(
    chain: &mut HistoricalChain,
    certificate: ArcCommitFinalizationCertificate,
    add: &FirstAddEvidence<'_>,
    memberships: &LeafMembershipSet,
    budget: &mut DecodeBudget,
) -> Result<[u8; 32], E2eeError> {
    let terminal = ArcSequencerRecord::Finalization(certificate);
    let references = RecordReferences {
        roster_objects: &[add.recipient_roster],
        memberships: Some(memberships),
        ..Default::default()
    };
    let ChainStep::Finalized {
        finalization_id,
        resulting_epoch: 1,
        transitions,
        ..
    } = advance(chain, terminal, &references, budget)?
    else {
        return Err(E2eeError::InvalidValue);
    };
    let Some((root, roster)) = chain.principals().get(&add.recipient.account_id) else {
        return Err(E2eeError::InvalidValue);
    };
    if finalization_id != add.expected_certificate.1
        || root.fingerprint != add.recipient.root_fingerprint
        || roster.device(&add.recipient.device_id).is_none()
        || transitions.roster_heads.as_slice() != [(add.recipient.account_id, roster.roster_id)]
    {
        return Err(E2eeError::InvalidValue);
    }
    Ok(finalization_id)
}

fn advance(
    chain: &mut HistoricalChain,
    record: ArcSequencerRecord,
    references: &RecordReferences<'_>,
    budget: &mut DecodeBudget,
) -> Result<ChainStep, E2eeError> {
    let bytes =
        ArcWireObject::new(ArcWireObjectKind::SequencerRecord, record.encode()?)?.encode()?;
    drop(record);
    chain.advance(&bytes, references, budget)
}

fn require_recipient(
    genesis: &GenesisObjects,
    plan: &ArcInitialMemberPlan,
    recipient: &ClientIdentity,
) -> Result<(), E2eeError> {
    let [creator] = genesis.policy.council.as_slice() else {
        return Err(E2eeError::InvalidValue);
    };
    let planned = plan.entries.as_slice().iter().find(|entry| {
        (entry.root_fingerprint, entry.device_id) != (creator.root_fingerprint, creator.device_id)
    });
    if recipient.network_id != genesis.network
        || !planned.is_some_and(|entry| {
            entry.account_id.as_slice() == recipient.account_id
                && entry.root_fingerprint == recipient.root_fingerprint
                && entry.device_id == recipient.device_id
        })
    {
        return Err(E2eeError::InvalidValue);
    }
    Ok(())
}

fn creator_membership(
    genesis: &GenesisObjects,
    bytes: &[u8],
    budget: &mut DecodeBudget,
) -> Result<LeafMembershipSet, E2eeError> {
    let proof: ArcLeafMembershipProof =
        decode_object(bytes, ArcWireObjectKind::LeafMembershipProof, budget)?;
    let account = account_id_bytes(&proof.tbs.account_id)?;
    let (root, roster) = genesis
        .principals
        .get(&account)
        .ok_or(E2eeError::InvalidValue)?;
    let member = verify_leaf_membership_proof(
        &genesis.network,
        &genesis.binding.conversation_id,
        &proof,
        root,
        roster,
    )?;
    if member.epoch != 0
        || member.leaf_index != 0
        || !member.is_continuing()
        || genesis
            .policy
            .council_member(&member.root_fingerprint, &member.device_id)
            .is_none()
    {
        return Err(E2eeError::InvalidValue);
    }
    let mut members = LeafMembershipSet::default();
    members.insert(*ObjectId::compute(bytes).as_bytes(), member);
    Ok(members)
}
