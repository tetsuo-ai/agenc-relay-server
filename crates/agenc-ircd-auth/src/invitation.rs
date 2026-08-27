//! Signed account-creation invitation validation.

use agenc_ircd_crypto::{Ed25519PublicKey, Ed25519Signature, SignatureDomain, verify_canonical};
use agenc_ircd_types::{InviteId, NetworkId, UtcSecond};
use zeroize::Zeroizing;

use crate::AuthError;

const PROFILE_VERSION: u16 = 1;
const INVITATION_TBS_BYTES: usize = 68;
const MAX_INVITATION_LIFETIME_SECONDS: u64 = 2_592_000;

/// Exact decoded account-creation invitation length.
pub const ACCOUNT_CREATION_INVITE_BYTES: usize = 132;

/// One signed, network-scoped, single-use account-creation invitation.
///
/// The complete bearer credential remains in zeroizing storage until this
/// owner is dropped.
///
/// ```compile_fail
/// use agenc_ircd_auth::AccountCreationInvite;
/// fn require_clone<T: Clone>() {}
/// require_clone::<AccountCreationInvite>();
/// ```
///
/// ```compile_fail
/// use agenc_ircd_auth::AccountCreationInvite;
/// fn require_debug<T: core::fmt::Debug>() {}
/// require_debug::<AccountCreationInvite>();
/// ```
pub struct AccountCreationInvite {
    encoded: Zeroizing<[u8; ACCOUNT_CREATION_INVITE_BYTES]>,
    network_id: NetworkId,
    invite_id: InviteId,
    not_before: u64,
    expires_at: u64,
}

impl AccountCreationInvite {
    /// Parses the exact fixed-width version-one encoding.
    pub fn parse(bytes: &[u8; ACCOUNT_CREATION_INVITE_BYTES]) -> Result<Self, AuthError> {
        let encoded = Zeroizing::new(*bytes);
        let mut cursor = Cursor::new(encoded.as_ref());
        if cursor.read_u16()? != PROFILE_VERSION {
            return Err(AuthError::InvalidEncoding);
        }
        let network_id = NetworkId::from_bytes(cursor.read_array()?);
        let invite_id = InviteId::from_bytes(cursor.read_array()?);
        let not_before = cursor.read_u64()?;
        let expires_at = cursor.read_u64()?;
        if cursor.read_u16()? != 1 {
            return Err(AuthError::InvalidEncoding);
        }
        cursor.skip(64)?;
        if !cursor.is_finished() {
            return Err(AuthError::InvalidEncoding);
        }
        Ok(Self {
            encoded,
            network_id,
            invite_id,
            not_before,
            expires_at,
        })
    }

    /// Verifies the offline authority, exact network, and exclusive time bounds.
    pub fn verify(
        &self,
        authority: Ed25519PublicKey,
        expected_network: NetworkId,
        now: UtcSecond,
    ) -> Result<(), AuthError> {
        if self.network_id != expected_network {
            return Err(AuthError::InvitationRejected);
        }
        let lifetime = self
            .expires_at
            .checked_sub(self.not_before)
            .ok_or(AuthError::InvitationRejected)?;
        if !(1..=MAX_INVITATION_LIFETIME_SECONDS).contains(&lifetime)
            || now.get() < self.not_before
            || now.get() >= self.expires_at
        {
            return Err(AuthError::InvitationRejected);
        }
        let tbs = self
            .encoded
            .get(..INVITATION_TBS_BYTES)
            .ok_or(AuthError::InvalidEncoding)?;
        let signature = self
            .encoded
            .get(INVITATION_TBS_BYTES..)
            .ok_or(AuthError::InvalidEncoding)?
            .try_into()
            .map(Ed25519Signature::from_bytes)
            .map_err(|_| AuthError::InvalidEncoding)?;
        verify_canonical(
            authority,
            SignatureDomain::AccountCreationInvite,
            tbs,
            signature,
        )
        .map_err(|_| AuthError::InvitationRejected)
    }

    /// Returns the permanent one-use invitation identity.
    #[must_use]
    pub const fn invite_id(&self) -> InviteId {
        self.invite_id
    }

    /// Returns the exclusive expiry used by the durable reservation.
    #[must_use]
    pub const fn expires_at(&self) -> UtcSecond {
        UtcSecond::from_unix_seconds(self.expires_at)
    }

    /// Borrows the byte-identical bearer only for the encrypted request codec.
    #[must_use]
    pub fn expose_for_account_request(&self) -> &[u8; ACCOUNT_CREATION_INVITE_BYTES] {
        &self.encoded
    }
}

struct Cursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn read_array<const SIZE: usize>(&mut self) -> Result<[u8; SIZE], AuthError> {
        let end = self
            .position
            .checked_add(SIZE)
            .ok_or(AuthError::InvalidEncoding)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(AuthError::InvalidEncoding)?;
        self.position = end;
        bytes.try_into().map_err(|_| AuthError::InvalidEncoding)
    }

    fn read_u16(&mut self) -> Result<u16, AuthError> {
        self.read_array().map(u16::from_be_bytes)
    }

    fn read_u64(&mut self) -> Result<u64, AuthError> {
        self.read_array().map(u64::from_be_bytes)
    }

    fn skip(&mut self, length: usize) -> Result<(), AuthError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(AuthError::InvalidEncoding)?;
        if self.input.get(self.position..end).is_none() {
            return Err(AuthError::InvalidEncoding);
        }
        self.position = end;
        Ok(())
    }

    const fn is_finished(&self) -> bool {
        self.position == self.input.len()
    }
}

#[cfg(test)]
mod tests {
    use core::mem::needs_drop;

    use super::{ACCOUNT_CREATION_INVITE_BYTES, AccountCreationInvite, AuthError, Cursor};

    #[test]
    fn cursor_skip_rejects_truncation_and_position_overflow() {
        let mut truncated = Cursor::new(&[0]);
        assert_eq!(truncated.skip(2), Err(AuthError::InvalidEncoding));

        let mut overflowing = Cursor::new(&[]);
        overflowing.position = usize::MAX;
        assert_eq!(overflowing.skip(1), Err(AuthError::InvalidEncoding));
    }

    #[test]
    fn bearer_owner_uses_drop_zeroization_and_round_trips_exact_bytes()
    -> Result<(), Box<dyn core::error::Error>> {
        let mut encoded = [0_u8; ACCOUNT_CREATION_INVITE_BYTES];
        encoded
            .get_mut(..2)
            .ok_or("profile slot is absent")?
            .copy_from_slice(&1_u16.to_be_bytes());
        encoded
            .get_mut(58..66)
            .ok_or("expiry slot is absent")?
            .copy_from_slice(&1_u64.to_be_bytes());
        encoded
            .get_mut(66..68)
            .ok_or("use-limit slot is absent")?
            .copy_from_slice(&1_u16.to_be_bytes());

        let invitation = AccountCreationInvite::parse(&encoded)?;
        assert!(needs_drop::<AccountCreationInvite>());
        assert_eq!(invitation.expose_for_account_request(), &encoded);
        Ok(())
    }
}
