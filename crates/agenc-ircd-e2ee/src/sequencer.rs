//! Sequencer credential chains and the federation key set (companion
//! Section 9.2).

use agenc_ircd_crypto::{SemanticHashDomain, SignatureDomain};

use crate::error::E2eeError;
use crate::identity::{Interval, ValidationTime};
use crate::ids::{SemanticId, semantic_id_of, sequencer_key_set_digest};
use crate::limits::{MAX_SEQUENCER_KEY_OVERLAP_SECONDS, PROFILE_VERSION};
use crate::objects::conversation::IrcSequencerCredential;
use crate::signature::{RoleKey, SignerRole};
use crate::tls::TlsEncode;

/// A verified sequencer credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedSequencerCredential {
    /// The credential identifier, the wire key ID.
    pub credential_id: SemanticId,
    /// Key generation.
    pub generation: u64,
    /// The sequencer public key.
    pub key: RoleKey,
    /// Validity.
    pub interval: Interval,
    /// Previous key identifier.
    pub previous_key_id: SemanticId,
}

impl VerifiedSequencerCredential {
    /// Whether the key may sign a record at `time`.
    #[must_use]
    pub const fn covers(&self, time: ValidationTime) -> bool {
        self.interval.covers(time)
    }
}

/// Verifies one credential, optionally continuing from its predecessor.
pub fn verify_sequencer_credential(
    network_id: &[u8; 32],
    credential: &IrcSequencerCredential,
    predecessor: Option<&VerifiedSequencerCredential>,
) -> Result<VerifiedSequencerCredential, E2eeError> {
    let tbs = &credential.tbs;
    if tbs.profile_version != PROFILE_VERSION || tbs.network_id != *network_id {
        return Err(E2eeError::ProfileMismatch);
    }
    if tbs.not_before >= tbs.not_after {
        return Err(E2eeError::InvalidValue);
    }
    let key = RoleKey::new(SignerRole::Sequencer, tbs.sequencer_public_key)?;
    match predecessor {
        None => {
            if tbs.key_generation != 0
                || tbs.previous_key_id != [0; 32]
                || !credential.continuity_signature.is_empty()
            {
                return Err(E2eeError::InvalidValue);
            }
        }
        Some(previous) => {
            if previous.generation.checked_add(1) != Some(tbs.key_generation)
                || tbs.previous_key_id != previous.credential_id
                || !previous.interval.covers(ValidationTime(tbs.not_before))
            {
                return Err(E2eeError::InvalidValue);
            }
            let signature = credential.continuity_signature.exactly::<64>()?;
            previous.key.verify(
                SignatureDomain::SequencerContinuity,
                &tbs.encode()?,
                &signature,
            )?;
        }
    }
    Ok(VerifiedSequencerCredential {
        credential_id: semantic_id_of(SemanticHashDomain::SequencerKey, tbs)?,
        generation: tbs.key_generation,
        key,
        interval: Interval {
            not_before: tbs.not_before,
            not_after: tbs.not_after,
        },
        previous_key_id: tbs.previous_key_id,
    })
}

/// The network's active sequencer key set: the current credential and at
/// most its direct successor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SequencerKeySet {
    /// Credentials in ascending generation.
    pub credentials: Vec<VerifiedSequencerCredential>,
    /// Monotonic set generation.
    pub set_generation: u64,
    /// The set digest advertised on ECAP.
    pub digest: SemanticId,
}

impl SequencerKeySet {
    /// Verifies one or two credentials as a key set. When the set opens at
    /// a generation above zero, `head` supplies the already accepted
    /// predecessor of its first credential.
    pub fn verify(
        network_id: &[u8; 32],
        credentials: &[IrcSequencerCredential],
        set_generation: u64,
        head: Option<&VerifiedSequencerCredential>,
    ) -> Result<Self, E2eeError> {
        if credentials.is_empty() || credentials.len() > 2 {
            return Err(E2eeError::InvalidValue);
        }
        let mut verified = Vec::new();
        let mut previous = head.copied();
        for credential in credentials {
            let current = verify_sequencer_credential(network_id, credential, previous.as_ref())?;
            verified.push(current);
            previous = Some(current);
        }
        let ids: Vec<SemanticId> = verified
            .iter()
            .map(|credential| credential.credential_id)
            .collect();
        Ok(Self {
            credentials: verified,
            set_generation,
            digest: sequencer_key_set_digest(&ids)?,
        })
    }

    /// The credential with `credential_id`, if the set holds it.
    #[must_use]
    pub fn credential(&self, credential_id: &SemanticId) -> Option<&VerifiedSequencerCredential> {
        self.credentials
            .iter()
            .find(|credential| credential.credential_id == *credential_id)
    }

    /// The current credential.
    #[must_use]
    pub fn current(&self) -> Option<&VerifiedSequencerCredential> {
        self.credentials.first()
    }

    /// Whether an overlapping successor is still inside its overlap window
    /// at `time`.
    #[must_use]
    pub fn overlap_open(&self, time: ValidationTime) -> bool {
        match self.credentials.as_slice() {
            [_, successor] => {
                time.0.saturating_sub(successor.interval.not_before)
                    <= MAX_SEQUENCER_KEY_OVERLAP_SECONDS
            }
            _ => false,
        }
    }

    /// Checks that `next` is the accepted successor set of `self`: the set
    /// generation advances by one and the next set's first credential is one
    /// this set already holds, so continuity was proven when it entered.
    pub fn succession(&self, next: &Self) -> Result<(), E2eeError> {
        let advances = self.set_generation.checked_add(1) == Some(next.set_generation);
        let continuous = next
            .current()
            .is_some_and(|current| self.credential(&current.credential_id).is_some());
        if advances && continuous {
            Ok(())
        } else {
            Err(E2eeError::InvalidValue)
        }
    }
}

#[cfg(test)]
#[path = "tests/sequencer.rs"]
mod tests;
