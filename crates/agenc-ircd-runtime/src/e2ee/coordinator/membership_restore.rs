//! Leaf-membership proofs and ACK signers survive storage reconstruction
//! (companion 13.7.3). Every retained proof row is re-verified against the
//! retained root and the exact roster snapshot the proof named, so a later
//! roster or root rotation does not erase a proof the server accepted; the
//! device's current activity is checked again whenever the proof is used.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use agenc_ircd_e2ee::identity::{VerifiedRoot, VerifiedRoster};
use agenc_ircd_e2ee::limits::{
    MAX_COMMIT_ACK_OBJECT, MAX_LEAF_MEMBERSHIP_OBJECT, MAX_REINIT_ACK_OBJECT,
};
use agenc_ircd_e2ee::membership::{Admission, verify_leaf_membership_proof};
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::membership::{IrcLeafDispositionKind, IrcLeafMembershipProof};
use agenc_ircd_e2ee::objects::reinit::IrcReInitAck;
use agenc_ircd_e2ee::objects::sequencing::IrcCommitAck;
use agenc_ircd_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_ircd_storage::StoredKey;
use agenc_ircd_storage::e2ee_records::SequencerRow;

use super::ConversationState;

/// One durable proof row: the retained object and the facts it was
/// accepted with.
struct Row {
    object_id: [u8; 32],
    epoch: u64,
    device_id: [u8; 16],
    disposition: u8,
}

/// The durable proof rows collected during the reload, by conversation,
/// leaf index, and old credential hash.
#[derive(Default)]
pub(super) struct Rows {
    rows: BTreeMap<([u8; 32], u32, [u8; 32]), Row>,
}

impl Rows {
    /// Records one `membership/v1/` row; an unparsable key is ignored and
    /// therefore restores nothing.
    pub(super) fn admit(
        &mut self,
        key: &StoredKey,
        object_id: [u8; 32],
        epoch: u64,
        device_id: [u8; 16],
        disposition: u8,
    ) {
        if let Ok(parts) = SequencerRow::parse_membership_key(key) {
            self.rows.insert(
                parts,
                Row {
                    object_id,
                    epoch,
                    device_id,
                    disposition,
                },
            );
        }
    }
}

fn decode_body<T: TlsDecode>(bytes: &[u8], kind: IrcWireObjectKind, limit: usize) -> Option<T> {
    let mut budget = DecodeBudget::new(limit, 1 << 12);
    let object = IrcWireObject::decode_kind(bytes, Some(kind), &mut budget).ok()?;
    T::decode_exact(object.body(), &mut budget).ok()
}

/// Restores the conversation's proofs from their rows. A row whose object
/// is missing, does not re-verify under the named retained roster, or
/// disagrees with its key or recorded facts restores nothing, so no ACK can
/// be identified through it.
pub(super) fn restore(
    historical: &[(VerifiedRoot, VerifiedRoster)],
    network_id: &[u8; 32],
    objects: &BTreeMap<[u8; 32], Vec<u8>>,
    rows: &Rows,
    conversation: &mut ConversationState,
    conversation_id: [u8; 32],
) {
    let first = (conversation_id, 0, [0; 32]);
    let last = (conversation_id, u32::MAX, [u8::MAX; 32]);
    let mut ordered: Vec<(&[u8; 32], &Row)> = rows
        .rows
        .range(first..=last)
        .map(|((_, _, credential), row)| (credential, row))
        .collect();
    // Admission replays the accepted order: lower epochs first.
    ordered.sort_by_key(|(_, row)| row.epoch);
    for (credential, row) in ordered {
        let Some(bytes) = objects.get(&row.object_id) else {
            continue;
        };
        let Some(proof) = decode_body::<IrcLeafMembershipProof>(
            bytes,
            IrcWireObjectKind::LeafMembershipProof,
            MAX_LEAF_MEMBERSHIP_OBJECT,
        ) else {
            continue;
        };
        let tbs = &proof.tbs;
        let named = (tbs.root_fingerprint, tbs.root_generation, tbs.roster_id);
        let Some((root, roster)) = historical
            .iter()
            .find(|(root, roster)| (root.fingerprint, root.generation, roster.roster_id) == named)
        else {
            continue;
        };
        let Ok(verified) =
            verify_leaf_membership_proof(network_id, &conversation_id, &proof, root, roster)
        else {
            continue;
        };
        let disposition = match verified.disposition {
            IrcLeafDispositionKind::Continuing => 1,
            IrcLeafDispositionKind::Removed => 2,
        };
        let recorded = (
            verified.old_credential_hash,
            verified.epoch,
            verified.device_id,
            disposition,
        );
        if recorded != (*credential, row.epoch, row.device_id, row.disposition) {
            continue;
        }
        if !verified.is_continuing()
            && !super::ops::membership::retained_finalization(
                objects,
                conversation,
                &verified.removal_finalization_id,
            )
        {
            continue;
        }
        if conversation.memberships.admit(&row.object_id, &verified) == Ok(Admission::Stored) {
            conversation.memberships.insert(row.object_id, verified);
        }
    }
}

/// The old leaf and credential hash an ACK object names.
fn ack_leaf(bytes: &[u8]) -> Option<(u32, [u8; 32])> {
    if let Some(ack) =
        decode_body::<IrcCommitAck>(bytes, IrcWireObjectKind::CommitAck, MAX_COMMIT_ACK_OBJECT)
    {
        return Some((ack.tbs.old_leaf_index, ack.tbs.old_credential_hash));
    }
    decode_body::<IrcReInitAck>(bytes, IrcWireObjectKind::ReinitAck, MAX_REINIT_ACK_OBJECT)
        .map(|ack| (ack.tbs.old_leaf_index, ack.tbs.old_credential_hash))
}

/// Rebuilds which device signed each retained ACK. A proof's leaf key is
/// bound to one device for the life of the conversation, so the restored
/// proof for the ACK's leaf names the same signer the handler identified.
pub(super) fn restore_signers(
    objects: &BTreeMap<[u8; 32], Vec<u8>>,
    conversation: &mut ConversationState,
) {
    let mut signers: BTreeMap<[u8; 32], super::AckSigners> = BTreeMap::new();
    for (subject, acks) in &conversation.acks {
        for object_id in acks.values() {
            let Some((leaf, credential)) = objects.get(object_id).and_then(|bytes| ack_leaf(bytes))
            else {
                continue;
            };
            let Some(entry) = conversation.memberships.iter().find(|entry| {
                (entry.proof.leaf_index, entry.proof.old_credential_hash) == (leaf, credential)
            }) else {
                continue;
            };
            signers
                .entry(*subject)
                .or_default()
                .insert((entry.proof.account_id, entry.proof.device_id), leaf);
        }
    }
    conversation.ack_signers = signers;
}
