#![forbid(unsafe_code)]

use agenc_ircd_crypto::{Ed25519SecretKey, SemanticHashDomain};
use agenc_ircd_e2ee::E2eeError;
use agenc_ircd_e2ee::identity::{Interval, ValidationTime};
use agenc_ircd_e2ee::ids::semantic_id_of;
use agenc_ircd_e2ee::objects::conversation::IrcSequencerCredential;
use agenc_ircd_e2ee::sequencer::{SequencerKeySet, VerifiedSequencerCredential};
use agenc_ircd_e2ee::signature::SignerRole;

use super::{CompanionCoordinator, SequencerSigner, SequencerSigners};

pub(super) fn selected_credential(
    network: &[u8; 32],
    key: &Ed25519SecretKey,
    set: &SequencerKeySet,
    current: &IrcSequencerCredential,
) -> Result<[u8; 32], E2eeError> {
    let tbs = &current.tbs;
    let id = semantic_id_of(SemanticHashDomain::SequencerKey, tbs)?;
    let verified = set.credential(&id).ok_or(E2eeError::KeyInvalid)?;
    let interval = Interval {
        not_before: tbs.not_before,
        not_after: tbs.not_after,
    };
    if tbs.profile_version != 1
        || tbs.network_id != *network
        || tbs.not_before >= tbs.not_after
        || tbs.sequencer_public_key != *key.public_key().as_bytes()
        || verified.key.as_bytes() != &tbs.sequencer_public_key
        || verified.key.role() != SignerRole::Sequencer
        || verified.interval != interval
        || verified.generation != tbs.key_generation
        || verified.previous_key_id != tbs.previous_key_id
    {
        return Err(E2eeError::KeyInvalid);
    }
    Ok(id)
}

/// Verifies every configured private key against the exact credential it
/// serves and returns the owners, or refuses the whole set: the successor
/// key must be the key of the set's other credential, the retired key must
/// be the key of a credential the set no longer carries, and no two owners
/// may share a public key (companion 9.2.1).
pub(super) fn verify_owners(
    network: &[u8; 32],
    key: Ed25519SecretKey,
    set: &SequencerKeySet,
    current: &IrcSequencerCredential,
    successor: Option<Ed25519SecretKey>,
    retired: Option<(Ed25519SecretKey, VerifiedSequencerCredential)>,
) -> Result<SequencerSigners, E2eeError> {
    let credential_id = selected_credential(network, &key, set, current)?;
    let active = SequencerSigner { key, credential_id };
    let successor = successor
        .map(|key| {
            let credential = set
                .credentials
                .iter()
                .find(|credential| credential.credential_id != active.credential_id)
                .ok_or(E2eeError::KeyInvalid)?;
            let matches = credential.key.as_bytes() == key.public_key().as_bytes()
                && credential.key.role() == SignerRole::Sequencer;
            matches
                .then_some(SequencerSigner {
                    key,
                    credential_id: credential.credential_id,
                })
                .ok_or(E2eeError::KeyInvalid)
        })
        .transpose()?;
    let retired = retired
        .map(|(key, credential)| {
            let absent = set.credential(&credential.credential_id).is_none();
            let matches = credential.key.as_bytes() == key.public_key().as_bytes()
                && credential.key.role() == SignerRole::Sequencer;
            (absent && matches)
                .then_some((
                    SequencerSigner {
                        key,
                        credential_id: credential.credential_id,
                    },
                    credential,
                ))
                .ok_or(E2eeError::KeyInvalid)
        })
        .transpose()?;
    let signers = SequencerSigners {
        active,
        successor,
        retired,
    };
    let mut public: Vec<[u8; 32]> = std::iter::once(&signers.active)
        .chain(signers.successor.as_ref())
        .chain(signers.retired.as_ref().map(|(signer, _)| signer))
        .map(|signer| *signer.key.public_key().as_bytes())
        .collect();
    public.sort_unstable();
    public.dedup();
    let distinct = public.len()
        == 1 + usize::from(signers.successor.is_some()) + usize::from(signers.retired.is_some());
    distinct.then_some(signers).ok_or(E2eeError::KeyInvalid)
}

/// The signer for a new receipt of a conversation pinned to `credential_id`:
/// the active or successor owner of that credential, only while the
/// credential covers `time`; a retired-retained signer never issues one.
pub(super) fn at_time<'a>(
    coordinator: &'a CompanionCoordinator,
    credential_id: &[u8; 32],
    time: u64,
) -> Option<&'a SequencerSigner> {
    let signer = coordinator.signers()?.issuing_owner(credential_id)?;
    let credential = coordinator.key_set()?.credential(&signer.credential_id)?;
    credential.covers(ValidationTime(time)).then_some(signer)
}

/// The signer that completes a retained receipt: exactly the owner of the
/// credential the receipt names, in any role.
pub(super) fn for_receipt(
    coordinator: &CompanionCoordinator,
    credential_id: [u8; 32],
) -> Option<&SequencerSigner> {
    coordinator.signers()?.owner(&credential_id)
}
