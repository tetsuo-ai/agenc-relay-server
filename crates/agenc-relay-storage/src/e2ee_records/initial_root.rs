//! Bounded, private initial-root ownership and the irreversible format fence.
#![forbid(unsafe_code)]

use agenc_relay_crypto::InitialRootClaimOwner;
use agenc_relay_types::{AccountId, AccountRandomId, NetworkId, RecoveryEpoch, RequestId};

use crate::codec::{Decoder, Encoder};
use crate::{StorageError, StoredKey};

/// Account-private ownership row and feature-format discriminator.
pub const KIND: u16 = 26;
/// Prefix of immutable account-private ownership rows.
pub const PREFIX: &[u8] = b"initial-root-owner/v1/";
/// A singleton retained after deletion of the last guarded account.
pub const FORMAT_KEY: &[u8] = b"initial-root-format/v1";
const VERSION: u16 = 1;
const OWNER_BYTES: usize = 2 + 1 + 32 + 16 + 16 + 16 + 32 + 1 + 32 + 32;
const WRAPPER_BYTES: usize = 12;

/// The private, monotone choice and original publication receipt.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RootClaimState {
    /// Authenticated creation reserved the only first-root choice.
    Reserved,
    /// The claimant chose this specific root fingerprint.
    Chosen([u8; 32]),
    /// The original first root was published with this exact object ID.
    Published {
        /// Verified root fingerprint.
        fingerprint: [u8; 32],
        /// Original signed object ID.
        object_id: [u8; 32],
    },
}

/// Exact private authority from the accepted original guarded account creation.
/// Only the account-bound verifier enters this record.
pub struct RootClaimOwner {
    /// Network authenticated at original account creation.
    pub network: NetworkId,
    /// Newly allocated immutable account.
    pub account: AccountId,
    /// Recovery epoch at creation, retained through declared recovery.
    pub epoch: RecoveryEpoch,
    /// The immutable original guarded START.
    pub start: RequestId,
    /// Account-bound private verifier, released only to account-service code.
    pub owner: InitialRootClaimOwner,
    /// State serialized in the private row only.
    pub state: RootClaimState,
}

impl PartialEq for RootClaimOwner {
    fn eq(&self, other: &Self) -> bool {
        self.network == other.network
            && self.account == other.account
            && self.epoch == other.epoch
            && self.start == other.start
            && self.owner.matches(&other.owner)
            && self.state == other.state
    }
}

impl Eq for RootClaimOwner {}

/// Both tagged arms have a fixed length and an independently checked storage key.
pub enum InitialRootRow {
    /// A durable fence understood by every enabled writer and refused by older writers.
    Format,
    /// One private immutable creation authority for a guarded account.
    Owner(RootClaimOwner),
}

impl RootClaimOwner {
    /// Scoped key of this private creation authority.
    pub fn key(network: NetworkId, account: AccountId) -> Result<StoredKey, StorageError> {
        super::key_of(&[PREFIX, network.as_bytes(), account.random().as_bytes()])
    }

    /// Constructs the only legal next state with the same immutable creation authority.
    pub fn transition(&self, next: RootClaimState) -> Result<Self, StorageError> {
        let allowed = match (self.state, next) {
            (RootClaimState::Reserved, RootClaimState::Chosen(_)) => true,
            (RootClaimState::Chosen(old), RootClaimState::Published { fingerprint, .. }) => {
                old == fingerprint
            }
            _ => false,
        };
        if !allowed {
            return Err(StorageError::StaleState);
        }
        Ok(Self {
            network: self.network,
            account: self.account,
            epoch: self.epoch,
            start: self.start,
            owner: InitialRootClaimOwner::from_protected_bytes(*self.owner.expose_for_storage()),
            state: next,
        })
    }

    /// Encodes the original fixed fields without a public projection.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let mut out = Encoder::with_capacity(OWNER_BYTES, OWNER_BYTES)?;
        out.put_u16(VERSION)?;
        out.put_fixed(&[1])?;
        out.put_fixed(self.network.as_bytes())?;
        out.put_fixed(self.account.random().as_bytes())?;
        out.put_fixed(self.epoch.as_bytes())?;
        out.put_fixed(self.start.as_bytes())?;
        out.put_fixed(self.owner.expose_for_storage())?;
        let empty = [0; 32];
        let (tag, fingerprint, object) = match &self.state {
            RootClaimState::Reserved => (0, &empty, &empty),
            RootClaimState::Chosen(fingerprint) => (1, fingerprint, &empty),
            RootClaimState::Published {
                fingerprint,
                object_id,
            } => (2, fingerprint, object_id),
        };
        out.put_fixed(&[tag])?;
        out.put_fixed(fingerprint)?;
        out.put_fixed(object)?;
        super::wrap(KIND, out.finish())
    }
}

impl InitialRootRow {
    /// Exact stable format marker, authenticated like every private owner row.
    pub fn format() -> Result<Vec<u8>, StorageError> {
        super::wrap(KIND, vec![0, 1, 0])
    }

    /// Decodes only the two supported fixed-width arms.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        if ![3 + WRAPPER_BYTES, OWNER_BYTES + WRAPPER_BYTES].contains(&body.len()) {
            return Err(StorageError::InvalidEncoding);
        }
        let inner = zeroize::Zeroizing::new(super::unwrap(KIND, body)?);
        let mut input = Decoder::new(&inner);
        if input.u16()? != VERSION {
            return Err(StorageError::UnsupportedVersion);
        }
        let row = match input.array()? {
            [0] => Self::Format,
            [1] => Self::Owner(RootClaimOwner {
                network: NetworkId::from_bytes(input.array()?),
                account: AccountRandomId::from_bytes(input.array()?).to_account_id(),
                epoch: RecoveryEpoch::from_bytes(input.array()?),
                start: RequestId::from_bytes(input.array()?),
                owner: InitialRootClaimOwner::from_protected_bytes(input.array()?),
                state: decode_state(&mut input)?,
            }),
            _ => return Err(StorageError::InvalidEncoding),
        };
        input.finish()?;
        Ok(row)
    }

    /// Matches exact key plus identity even when the row is otherwise well formed.
    pub fn decode_keyed(key: &StoredKey, body: &[u8]) -> Result<Self, StorageError> {
        let row = Self::decode(body)?;
        let matches = match &row {
            Self::Format => key.as_bytes() == FORMAT_KEY,
            Self::Owner(owner) => RootClaimOwner::key(owner.network, owner.account)? == *key,
        };
        if !matches {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(row)
    }
}

fn decode_state(input: &mut Decoder<'_>) -> Result<RootClaimState, StorageError> {
    let tag = input.array()?;
    let fingerprint = input.array()?;
    let object_id = input.array()?;
    match tag {
        [0] if fingerprint == [0; 32] && object_id == [0; 32] => Ok(RootClaimState::Reserved),
        [1] if object_id == [0; 32] => Ok(RootClaimState::Chosen(fingerprint)),
        [2] => Ok(RootClaimState::Published {
            fingerprint,
            object_id,
        }),
        _ => Err(StorageError::InvalidEncoding),
    }
}

/// Private key space, including malformed suffixes that must never be accepted under another kind.
#[must_use]
pub fn is_reserved_key(key: &StoredKey) -> bool {
    key.as_bytes().starts_with(PREFIX) || key.as_bytes().starts_with(FORMAT_KEY)
}

#[cfg(test)]
mod tests;
