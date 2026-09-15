//! Leaf-membership admission (companion Section 13.7.3).
//!
//! A leaf-membership proof binds an attached device to one old MLS leaf:
//! the device signs the statement and, for a continuing leaf, the old leaf
//! key proves possession. The server verifies both signatures against the
//! retained root and roster, then keeps the accepted proofs in a
//! [`LeafMembershipSet`] that identifies Commit and ReInit ACK signers and
//! bounds the expected ReInit continuing set. The exact continuing set,
//! copath coverage, and removal outcomes remain endpoint-only MLS checks;
//! this is a filter, never authority.

use std::collections::{BTreeMap, BTreeSet};

use agenc_ircd_crypto::{SemanticHashDomain, SignatureDomain};

use crate::error::E2eeError;
use crate::identity::{VerifiedRoot, VerifiedRoster};
use crate::ids::{SemanticId, semantic_id_of};
use crate::limits::MAX_GROUP_LEAVES;
use crate::objects::account_id_bytes;
use crate::objects::membership::{IrcLeafDispositionKind, IrcLeafMembershipProof};
use crate::objects::reinit::{IrcReInitAckKind, IrcReInitAckTbs, IrcReInitAttempt};
use crate::signature::RoleKey;
use crate::tls::TlsEncode;

/// The only leaf signature scheme of the enabled suites: Ed25519.
pub const ED25519_LEAF_SIGNATURE_SCHEME: u16 = 0x0807;

/// The authenticated per-conversation quota of retained proofs: two per
/// possible leaf, so every current leaf and one predecessor credential per
/// leaf fit. A replacement does not count; a new proof beyond the quota is
/// refused as an exceeded authenticated quota (companion 13.7.3).
pub const MAX_RETAINED_LEAF_MEMBERSHIPS: usize = 2 * MAX_GROUP_LEAVES as usize;

/// One verified leaf-membership proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedLeafMembership {
    /// `leaf_membership_id`, the Section 2.2 hash of the TBS.
    pub leaf_membership_id: SemanticId,
    /// The conversation the proof names.
    pub conversation_id: [u8; 32],
    /// The MLS epoch in which the leaf holds the credential.
    pub epoch: u64,
    /// The old leaf index.
    pub leaf_index: u32,
    /// The old credential hash the ACK repeats.
    pub old_credential_hash: [u8; 32],
    /// The raw public leaf signature key.
    pub leaf_key: [u8; 32],
    /// The attesting account.
    pub account_id: [u8; 24],
    /// The attesting root.
    pub root_fingerprint: [u8; 32],
    /// The attesting device.
    pub device_id: [u8; 16],
    /// The roster generation the proof named.
    pub roster_generation: u64,
    /// The roster the proof named.
    pub roster_id: [u8; 32],
    /// Whether the leaf continues or is removed.
    pub disposition: IrcLeafDispositionKind,
    /// The finalized record after which a removed leaf is gone.
    pub removal_finalization_id: [u8; 32],
}

impl VerifiedLeafMembership {
    /// Whether the proof states a continuing leaf.
    #[must_use]
    pub fn is_continuing(&self) -> bool {
        self.disposition == IrcLeafDispositionKind::Continuing
    }

    /// Verifies a suite-encoded old-leaf signature over `tbs` under the
    /// proof's public leaf key and the registered `domain`.
    pub fn verify_leaf_signature(
        &self,
        domain: SignatureDomain,
        tbs: &impl TlsEncode,
        signature: &[u8],
    ) -> Result<(), E2eeError> {
        RoleKey::leaf(&self.leaf_key)?.verify_suite_encoded(domain, &tbs.encode()?, signature)
    }
}

/// Why a proof is not admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MembershipRefusal {
    /// The object is malformed or names another network, conversation,
    /// account, root, or roster.
    Invalid,
    /// The attesting device is not active in the named roster.
    DeviceInactive,
    /// A device or possession signature does not verify.
    SignatureInvalid,
}

impl From<MembershipRefusal> for E2eeError {
    fn from(refusal: MembershipRefusal) -> Self {
        match refusal {
            MembershipRefusal::Invalid => Self::InvalidValue,
            MembershipRefusal::DeviceInactive => Self::KeyInvalid,
            MembershipRefusal::SignatureInvalid => Self::SignatureInvalid,
        }
    }
}

/// Verifies one proof against the root and roster it names. The caller
/// supplies the retained roster whose identifier equals the proof's; a
/// revoked device is refused because it is absent from that roster's
/// active set.
pub fn verify_leaf_membership_proof(
    network_id: &[u8; 32],
    conversation_id: &[u8; 32],
    proof: &IrcLeafMembershipProof,
    root: &VerifiedRoot,
    roster: &VerifiedRoster,
) -> Result<VerifiedLeafMembership, MembershipRefusal> {
    let tbs = &proof.tbs;
    let account_id = account_id_bytes(&tbs.account_id).map_err(|_| MembershipRefusal::Invalid)?;
    let named = (
        (tbs.profile_version, tbs.network_id, tbs.conversation_id),
        (account_id, tbs.root_generation, tbs.root_fingerprint),
        (
            tbs.roster_generation,
            tbs.roster_id,
            roster.root_fingerprint,
        ),
        (tbs.credential_generation, tbs.leaf_signature_scheme),
    );
    let expected = (
        (1, *network_id, *conversation_id),
        (root.account_id, root.generation, root.fingerprint),
        (roster.generation, roster.roster_id, root.fingerprint),
        (0, ED25519_LEAF_SIGNATURE_SCHEME),
    );
    if named != expected || tbs.leaf_index >= MAX_GROUP_LEAVES {
        return Err(MembershipRefusal::Invalid);
    }
    let leaf_key: [u8; 32] = tbs
        .leaf_signature_key
        .as_slice()
        .try_into()
        .map_err(|_| MembershipRefusal::Invalid)?;
    let leaf = RoleKey::leaf(&leaf_key).map_err(|_| MembershipRefusal::Invalid)?;
    let possession = proof.possession_signature.as_slice();
    let zero = tbs.removal_finalization_id == [0; 32];
    match tbs.disposition {
        IrcLeafDispositionKind::Continuing if possession.len() != 64 || !zero => {
            return Err(MembershipRefusal::Invalid);
        }
        IrcLeafDispositionKind::Removed if !possession.is_empty() || zero => {
            return Err(MembershipRefusal::Invalid);
        }
        IrcLeafDispositionKind::Continuing | IrcLeafDispositionKind::Removed => {}
    }
    let certificate = roster
        .device(&tbs.device_id)
        .ok_or(MembershipRefusal::DeviceInactive)?;
    let encoded = tbs.encode().map_err(|_| MembershipRefusal::Invalid)?;
    certificate
        .key
        .verify(
            SignatureDomain::LeafMembership,
            &encoded,
            &proof.device_signature,
        )
        .map_err(|_| MembershipRefusal::SignatureInvalid)?;
    if tbs.disposition == IrcLeafDispositionKind::Continuing {
        leaf.verify_suite_encoded(
            SignatureDomain::LeafMembershipPossession,
            &encoded,
            possession,
        )
        .map_err(|_| MembershipRefusal::SignatureInvalid)?;
    }
    let leaf_membership_id = semantic_id_of(SemanticHashDomain::LeafMembershipId, tbs)
        .map_err(|_| MembershipRefusal::Invalid)?;
    Ok(VerifiedLeafMembership {
        leaf_membership_id,
        conversation_id: tbs.conversation_id,
        epoch: tbs.epoch,
        leaf_index: tbs.leaf_index,
        old_credential_hash: tbs.old_credential_hash,
        leaf_key,
        account_id,
        root_fingerprint: tbs.root_fingerprint,
        device_id: tbs.device_id,
        roster_generation: tbs.roster_generation,
        roster_id: tbs.roster_id,
        disposition: tbs.disposition,
        removal_finalization_id: tbs.removal_finalization_id,
    })
}

/// One retained proof: the object that carried it and the verified facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedLeafMembership {
    /// The retained `leaf_membership_proof` object identifier.
    pub object_id: [u8; 32],
    /// The verified proof.
    pub proof: VerifiedLeafMembership,
}

/// The key of one old leaf: its index and credential hash.
pub type LeafKey = (u32, [u8; 32]);

/// What admitting a proof would do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission {
    /// A new or replacing proof is stored.
    Stored,
    /// A byte-identical resubmission changes nothing.
    Unchanged,
}

/// Why a verified proof cannot be stored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionRefusal {
    /// A duplicate or conflicting continuing leaf, or a differing proof at
    /// the same or an earlier epoch.
    Conflict,
    /// The conversation already retains its quota of proofs.
    QuotaExceeded,
}

/// The accepted proofs of one conversation, keyed by old leaf. At most one
/// proof is retained per `(leaf_index, old_credential_hash)`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LeafMembershipSet {
    entries: BTreeMap<LeafKey, RetainedLeafMembership>,
}

impl LeafMembershipSet {
    /// Decides whether `proof`, carried by `object_id`, may be stored
    /// (companion 13.7.3):
    ///
    /// - a byte-identical resubmission is unchanged;
    /// - a proof for a retained leaf from another device is a conflict;
    /// - the same device replaces its proof for a leaf only with a higher
    ///   epoch; a differing proof at the same epoch is a conflict;
    /// - one device holding `continuing` proofs for two leaf indexes at one
    ///   epoch is a duplicate continuing leaf.
    pub fn admit(
        &self,
        object_id: &[u8; 32],
        proof: &VerifiedLeafMembership,
    ) -> Result<Admission, AdmissionRefusal> {
        let key = (proof.leaf_index, proof.old_credential_hash);
        let existing = self.entries.get(&key);
        if let Some(existing) = existing {
            if existing.object_id == *object_id {
                return Ok(Admission::Unchanged);
            }
            if !same_device(&existing.proof, proof) || proof.epoch <= existing.proof.epoch {
                return Err(AdmissionRefusal::Conflict);
            }
        }
        let duplicate = proof.is_continuing()
            && self.entries.values().any(|entry| {
                entry.proof.leaf_index != proof.leaf_index
                    && entry.proof.is_continuing()
                    && entry.proof.epoch == proof.epoch
                    && same_device(&entry.proof, proof)
            });
        if duplicate {
            return Err(AdmissionRefusal::Conflict);
        }
        if existing.is_none() && self.entries.len() >= MAX_RETAINED_LEAF_MEMBERSHIPS {
            return Err(AdmissionRefusal::QuotaExceeded);
        }
        Ok(Admission::Stored)
    }

    /// Stores `proof`, replacing any proof of the same leaf.
    pub fn insert(&mut self, object_id: [u8; 32], proof: VerifiedLeafMembership) {
        self.entries.insert(
            (proof.leaf_index, proof.old_credential_hash),
            RetainedLeafMembership { object_id, proof },
        );
    }

    /// The stored `continuing` proof that identifies the signer of an ACK
    /// naming `leaf_index` and `old_credential_hash` at `prior_epoch`: its
    /// epoch is not later than the ACK's prior epoch.
    #[must_use]
    pub fn signer(
        &self,
        leaf_index: u32,
        old_credential_hash: &[u8; 32],
        prior_epoch: u64,
    ) -> Option<&RetainedLeafMembership> {
        self.entries
            .get(&(leaf_index, *old_credential_hash))
            .filter(|entry| entry.proof.is_continuing() && entry.proof.epoch <= prior_epoch)
    }

    /// The server's expected ReInit continuing set, in leaf order: every
    /// stored `continuing` proof whose device `is_active` still admits
    /// (companion 13.7.3). A `removed` proof supersedes a leaf by replacing
    /// its proof, and a revoked device's proof no longer counts; the exact
    /// continuing set remains an endpoint check.
    pub fn expected_continuing(
        &self,
        is_active: impl Fn(&[u8; 24], &[u8; 16]) -> bool,
    ) -> Vec<&RetainedLeafMembership> {
        self.entries
            .values()
            .filter(|entry| {
                entry.proof.is_continuing()
                    && is_active(&entry.proof.account_id, &entry.proof.device_id)
            })
            .collect()
    }

    /// Identifies the signer of one ACK: the stored `continuing` proof of
    /// `leaf_index` and `old_credential_hash` at or before `prior_epoch`,
    /// under whose public key the suite-encoded `signature` over `tbs`
    /// verifies with the registered `domain`. Whether that device is still
    /// roster-active is the caller's separate check.
    pub fn identify(
        &self,
        leaf_index: u32,
        old_credential_hash: &[u8; 32],
        prior_epoch: u64,
        domain: SignatureDomain,
        tbs: &impl TlsEncode,
        signature: &[u8],
    ) -> Result<&RetainedLeafMembership, E2eeError> {
        let entry = self
            .signer(leaf_index, old_credential_hash, prior_epoch)
            .ok_or(E2eeError::InvalidValue)?;
        entry.proof.verify_leaf_signature(domain, tbs, signature)?;
        Ok(entry)
    }

    /// Identifies one ACK of a set as [`Self::identify`] does and records
    /// its signing device in `signers`, refusing a device that already
    /// signed another ACK of the same set.
    // agenc-review: allow owner=e2ee reviewed=2026-09-15 reason=one ACK claim names its leaf, credential, epoch, label, content, and signature, plus the set's signer record
    #[allow(clippy::too_many_arguments)]
    pub fn identify_distinct(
        &self,
        signers: &mut BTreeSet<([u8; 24], [u8; 16])>,
        leaf_index: u32,
        old_credential_hash: &[u8; 32],
        prior_epoch: u64,
        domain: SignatureDomain,
        tbs: &impl TlsEncode,
        signature: &[u8],
    ) -> Result<&RetainedLeafMembership, E2eeError> {
        let entry = self.identify(
            leaf_index,
            old_credential_hash,
            prior_epoch,
            domain,
            tbs,
            signature,
        )?;
        if !signers.insert(signing_device(entry)) {
            return Err(E2eeError::InvalidValue);
        }
        Ok(entry)
    }

    /// Every stored proof, in leaf order.
    pub fn iter(&self) -> impl Iterator<Item = &RetainedLeafMembership> {
        self.entries.values()
    }

    /// The number of retained proofs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no proof is retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The account and device of the KeyPackage plan entry a ReInit ACK's role
/// names (companion 13.8): the creator entry for `creator_state`, the
/// non-creator entry holding the ACK's reserved ref for `welcome_join`.
#[must_use]
pub fn planned_ack_device(
    ack: &IrcReInitAckTbs,
    attempt: &IrcReInitAttempt,
) -> Option<([u8; 24], [u8; 16])> {
    let entries = attempt.key_package_plan.entries.as_slice();
    let entry = match ack.ack_kind {
        IrcReInitAckKind::CreatorState => entries.iter().find(|entry| entry.creator != 0),
        IrcReInitAckKind::WelcomeJoin => entries
            .iter()
            .find(|entry| entry.creator == 0 && entry.key_package_ref == ack.key_package_ref),
    }?;
    Some((entry.account_id.exactly::<24>().ok()?, entry.device_id))
}

/// The account and device that sign through a retained proof.
#[must_use]
pub fn signing_device(entry: &RetainedLeafMembership) -> ([u8; 24], [u8; 16]) {
    (entry.proof.account_id, entry.proof.device_id)
}

fn same_device(left: &VerifiedLeafMembership, right: &VerifiedLeafMembership) -> bool {
    (left.account_id, left.device_id) == (right.account_id, right.device_id)
}

#[cfg(test)]
#[path = "tests/membership.rs"]
mod tests;
