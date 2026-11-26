//! Signed read of the registered account's current directory head under the
//! optional terminal-root-head profile. Only the installation can supply the
//! independent credential set, reviewed predecessor and actual login.

use agenc_relay_crypto::SignatureDomain;

use crate::error::E2eeError;
use crate::identity::ValidationTime;
use crate::sequencer::SequencerKeySet;
use crate::tls::{TlsEncode, tls_struct};

/// Maximum lifetime in UTC and on the initiating client's monotonic clock.
pub const MAX_LIFETIME_SECONDS: u64 = 30;
/// TBS, Ed25519 signature and the six-byte complete wire envelope.
pub const OBJECT_BYTES: usize = 290 + 64 + 6;

tls_struct! {
    /// The original registered OPAQUE success as observed independently by both peers.
    pub struct TerminalRootLogin {
        /// Network from the pinned descriptor.
        pub network_id: [u8; 32],
        /// Current recovery epoch.
        pub recovery_epoch: [u8; 16],
        /// Immutable registered account.
        pub account_id: [u8; 24],
        /// Generation from the successfully consumed account grant.
        pub account_session_generation: u64,
        /// SHA-256 of the raw, sealed and committed login FINISH response.
        pub login_completion_sha256: [u8; 32],
    }
}

tls_struct! {
    /// The terminal standalone identity at the serialized directory read.
    pub struct TerminalRootIdentity {
        /// Current root generation.
        pub generation: u64,
        /// Semantic fingerprint of the signed root.
        pub fingerprint: [u8; 32],
        /// Content address of the complete standalone RootIdentity wire object.
        pub object_id: [u8; 32],
    }
}

tls_struct! {
    /// Canonical 290-byte signature input.
    pub struct TerminalRootHeadTbs {
        /// Receipt format, currently one.
        pub version: u16,
        /// Login that owns the request.
        pub login: TerminalRootLogin,
        /// Original client's independent request challenge.
        pub challenge: [u8; 16],
        /// Exact current identity.
        pub root: TerminalRootIdentity,
        /// Current sequencer set generation.
        pub sequencer_set_generation: u64,
        /// Semantic digest of that complete set.
        pub sequencer_set_digest: [u8; 32],
        /// Credential of the set's active signing key.
        pub sequencer_credential_id: [u8; 32],
        /// Earliest valid UTC second, inclusive.
        pub issued_at: u64,
        /// Last valid UTC second, inclusive.
        pub expires_at: u64,
    }
}

tls_struct! {
    /// The sequencer's challenge-bound attestation. Its signer is never carried in-band.
    pub struct TerminalRootHead {
        /// All scoped and signed fields.
        pub tbs: TerminalRootHeadTbs,
        /// Ed25519 under the dedicated terminal-head label.
        pub signature: [u8; 64],
    }
}

impl TerminalRootHead {
    /// Verify the proof against the independently accepted, complete set,
    /// physical login, client challenge and reviewed identity. The caller
    /// separately owns the original socket and its monotonic deadline.
    pub fn verify(
        &self,
        login: &TerminalRootLogin,
        root: &TerminalRootIdentity,
        challenge: &[u8; 16],
        set: &SequencerKeySet,
        now: ValidationTime,
    ) -> Result<(), E2eeError> {
        let tbs = &self.tbs;
        if tbs.version != 1
            || tbs.login != *login
            || tbs.root != *root
            || tbs.challenge != *challenge
            || tbs.sequencer_set_generation != set.set_generation
            || tbs.sequencer_set_digest != set.digest
        {
            return Err(E2eeError::ProfileMismatch);
        }
        let current = set.current().ok_or(E2eeError::KeyInvalid)?;
        let last = tbs
            .issued_at
            .checked_add(MAX_LIFETIME_SECONDS)
            .ok_or(E2eeError::Overflow)?;
        if tbs.sequencer_credential_id != current.credential_id
            || !current.interval.covers(ValidationTime(tbs.issued_at))
            || !current.interval.covers(now)
            || !(tbs.issued_at..=tbs.expires_at).contains(&now.0)
            || tbs.expires_at > last.min(current.interval.not_after)
        {
            return Err(E2eeError::InvalidValue);
        }
        current.key.verify(
            SignatureDomain::TerminalRootHead,
            &tbs.encode()?,
            &self.signature,
        )
    }
}

#[cfg(test)]
#[path = "tests/terminal_root.rs"]
mod tests;
