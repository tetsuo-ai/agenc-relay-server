//! Private commitment to the prospective creator of one account's initial root.

use agenc_relay_types::{AccountId, NetworkId, RecoveryEpoch, RequestId};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::{CryptoError, OsEntropy};

const PRECOMMIT: &[u8] = b"agenc-chat initial root precommit v1";
const OWNER: &[u8] = b"agenc-chat initial root owner v1";

/// A bootstrap preimage for one prospective creation. This never signs an ARC root.
///
/// ```compile_fail
/// use agenc_relay_crypto::InitialRootSecret;
/// fn leak<T: std::fmt::Debug + Clone>() {}
/// leak::<InitialRootSecret>();
/// ```
pub struct InitialRootSecret(Zeroizing<[u8; 32]>);

impl InitialRootSecret {
    /// Generates the prospective creator's secret directly into a zeroizing buffer.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = Zeroizing::new([0; 32]);
        OsEntropy::fill(bytes.as_mut())?;
        Ok(Self(bytes))
    }

    /// Takes a cleartext secret from the HPKE parser or protected installation owner.
    #[must_use]
    pub fn from_protected_bytes(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    /// Borrows this secret while encoding an HPKE request or its protected installation row.
    #[must_use]
    pub fn expose_for_protection(&self) -> &[u8; 32] {
        &self.0
    }

    /// Commits to the exact start request before the coordinator allocates an account.
    #[must_use]
    pub fn precommit(
        &self,
        network: NetworkId,
        epoch: RecoveryEpoch,
        start: RequestId,
    ) -> InitialRootPrecommit {
        let mut digest = Sha256::new();
        digest.update(PRECOMMIT);
        digest.update(network.as_bytes());
        digest.update(epoch.as_bytes());
        digest.update(start.as_bytes());
        digest.update(self.0.as_ref());
        InitialRootPrecommit(Zeroizing::new(digest.finalize().into()))
    }
}

/// Private commitment carried inside the sealed creation request and transaction journal.
pub struct InitialRootPrecommit(Zeroizing<[u8; 32]>);

impl InitialRootPrecommit {
    /// Takes the exact authenticated field of a guarded creation or its private journal.
    #[must_use]
    pub fn from_protected_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrows the commitment for protected transport or journal storage.
    #[must_use]
    pub fn expose_for_protection(&self) -> &[u8; 32] {
        &self.0
    }

    /// Binds the private creation commitment to the allocated canonical Account ID.
    #[must_use]
    pub fn bind(
        &self,
        network: NetworkId,
        epoch: RecoveryEpoch,
        account: AccountId,
        start: RequestId,
    ) -> InitialRootClaimOwner {
        let mut digest = Sha256::new();
        digest.update(OWNER);
        digest.update(network.as_bytes());
        digest.update(epoch.as_bytes());
        digest.update(account.to_text().as_bytes());
        digest.update(start.as_bytes());
        digest.update(self.0.as_ref());
        InitialRootClaimOwner(Zeroizing::new(digest.finalize().into()))
    }
}

/// The private account-bound verifier stored by the coordinator.
pub struct InitialRootClaimOwner(Zeroizing<[u8; 32]>);

impl InitialRootClaimOwner {
    /// Restores the complete verifier from authenticated authority storage.
    #[must_use]
    pub fn from_protected_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrows the verifier for its protected coordinator row.
    #[must_use]
    pub fn expose_for_storage(&self) -> &[u8; 32] {
        &self.0
    }

    /// Checks the recomputed verifier without a data-dependent comparison.
    #[must_use]
    pub fn matches(&self, candidate: &Self) -> bool {
        bool::from(self.0.as_ref().ct_eq(candidate.0.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use agenc_relay_types::AccountRandomId;

    use super::*;

    #[test]
    fn creation_vectors_and_independent_identity_dependencies() {
        let network = NetworkId::from_bytes([1; 32]);
        let epoch = RecoveryEpoch::from_bytes([2; 16]);
        let start = RequestId::from_bytes([3; 16]);
        let secret = InitialRootSecret::from_protected_bytes(Zeroizing::new([4; 32]));
        let account = AccountId::from_random(AccountRandomId::from_bytes([5; 16]));
        let expected_precommit = [
            0x66, 0x29, 0x4a, 0xe2, 0x22, 0x07, 0x0b, 0x29, 0xe6, 0x47, 0xd6, 0xcc, 0x13, 0x4b,
            0xbb, 0x59, 0x16, 0x6a, 0x21, 0x1f, 0x01, 0x41, 0xbc, 0xb0, 0xb9, 0xc1, 0x4d, 0xcf,
            0x1f, 0x39, 0x2a, 0xd4,
        ];
        let expected_owner = [
            0x97, 0x99, 0x8f, 0x05, 0x00, 0xfb, 0x16, 0x24, 0x66, 0xc3, 0x61, 0x7e, 0x91, 0x76,
            0xb3, 0xee, 0x6f, 0x04, 0x40, 0xd3, 0xbe, 0xf6, 0x98, 0xfb, 0x98, 0xb5, 0x14, 0x36,
            0xcf, 0x6f, 0xf5, 0x18,
        ];
        let expected = InitialRootClaimOwner::from_protected_bytes(expected_owner);
        let precommit = secret.precommit(network, epoch, start);
        assert_eq!(precommit.expose_for_protection(), &expected_precommit);
        assert!(expected.matches(&precommit.bind(network, epoch, account, start)));
        let other_network = NetworkId::from_bytes([9; 32]);
        let other_epoch = RecoveryEpoch::from_bytes([9; 16]);
        let other_account = AccountId::from_random(AccountRandomId::from_bytes([9; 16]));
        let other_start = RequestId::from_bytes([9; 16]);
        for (n, e, a, i) in [
            (other_network, epoch, account, start),
            (network, other_epoch, account, start),
            (network, epoch, other_account, start),
            (network, epoch, account, other_start),
        ] {
            assert!(!expected.matches(&precommit.bind(n, e, a, i)));
            assert!(!expected.matches(&secret.precommit(n, e, i).bind(n, e, a, i)));
        }
        let other = InitialRootSecret::from_protected_bytes(Zeroizing::new([9; 32]));
        assert!(
            !expected.matches(
                &other
                    .precommit(network, epoch, start)
                    .bind(network, epoch, account, start,)
            )
        );
    }
}
