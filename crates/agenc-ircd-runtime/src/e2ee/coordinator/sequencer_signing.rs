//! The installed secret, advertised credential and receipt validation time must agree.
#![forbid(unsafe_code)]

use agenc_ircd_crypto::{Ed25519SecretKey, SemanticHashDomain};
use agenc_ircd_e2ee::E2eeError;
use agenc_ircd_e2ee::identity::{Interval, ValidationTime};
use agenc_ircd_e2ee::ids::semantic_id_of;
use agenc_ircd_e2ee::objects::conversation::IrcSequencerCredential;
use agenc_ircd_e2ee::sequencer::SequencerKeySet;
use agenc_ircd_e2ee::signature::SignerRole;

use super::{CompanionCoordinator, SequencerSigner};

/// Selects the exact credential from a previously verified key set before changing state.
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

/// Receipt eligibility uses Commit consensus time, independently of the signing clock.
pub(super) fn at_time(coordinator: &CompanionCoordinator, time: u64) -> Option<&SequencerSigner> {
    let signer = coordinator.signer()?;
    let credential = coordinator.key_set()?.credential(&signer.credential_id)?;
    credential.covers(ValidationTime(time)).then_some(signer)
}

/// A terminal stays with the credential on its previously authenticated receipt.
pub(super) fn for_receipt(
    coordinator: &CompanionCoordinator,
    credential_id: [u8; 32],
) -> Option<&SequencerSigner> {
    coordinator
        .signer()
        .filter(|signer| signer.credential_id == credential_id)
}
