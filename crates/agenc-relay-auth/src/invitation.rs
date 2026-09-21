//! Signed account-creation invitation validation.

use agenc_relay_crypto::{
    Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature, SignatureDomain, sign_canonical,
    verify_canonical,
};
use agenc_relay_types::{InviteId, NetworkId, UtcSecond};
use zeroize::Zeroizing;

use crate::AuthError;

const PROFILE_VERSION: u16 = 1;
const INVITATION_TBS_BYTES: usize = 68;
const MAX_INVITATION_LIFETIME_SECONDS: u64 = 2_592_000;
/// Every version-one invitation is single-use; any other limit is malformed.
const INVITATION_USE_LIMIT: u16 = 1;

/// Exact decoded account-creation invitation length.
pub const ACCOUNT_CREATION_INVITE_BYTES: usize = 132;

/// Reports whether `now` lies inside the exclusive invitation interval.
///
/// This is the single implementation of the architecture §11.3 lifetime rule
/// `not_before <= now < expires_at`. START verification and the FINISH-time
/// recheck both evaluate exactly this predicate, so an invitation admitted at
/// START cannot FINISH at or after `expires_at`, or before `not_before` after
/// a UTC rollback, no matter how much monotonic transaction lifetime remains.
///
/// The runtime re-evaluates this same function with a fresh trusted UTC read
/// at durable admission, immediately before the creation FINISH durable set
/// is staged, so crypto or queue latency that crosses `expires_at` after the
/// worker's check cannot publish an account.
#[must_use]
pub fn invitation_interval_admits(
    not_before: UtcSecond,
    expires_at: UtcSecond,
    now: UtcSecond,
) -> bool {
    not_before <= now && now < expires_at
}

/// One signed, network-scoped, single-use account-creation invitation.
///
/// The complete bearer credential remains in zeroizing storage until this
/// owner is dropped.
///
/// ```compile_fail
/// use agenc_relay_auth::AccountCreationInvite;
/// fn require_clone<T: Clone>() {}
/// require_clone::<AccountCreationInvite>();
/// ```
///
/// ```compile_fail
/// use agenc_relay_auth::AccountCreationInvite;
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
    /// Issues one signed invitation with exclusive time bounds.
    ///
    /// The lifetime `expires_at - not_before` must be within `1..=2_592_000`
    /// seconds, the same rule `verify` applies, so an issued invitation always
    /// verifies under its authority inside that window.
    pub fn issue(
        network_id: NetworkId,
        invite_id: InviteId,
        not_before: UtcSecond,
        expires_at: UtcSecond,
        authority: &Ed25519SecretKey,
    ) -> Result<Self, AuthError> {
        let lifetime = expires_at
            .get()
            .checked_sub(not_before.get())
            .ok_or(AuthError::InvitationRejected)?;
        if !(1..=MAX_INVITATION_LIFETIME_SECONDS).contains(&lifetime) {
            return Err(AuthError::InvitationRejected);
        }
        let mut encoded = Zeroizing::new([0_u8; ACCOUNT_CREATION_INVITE_BYTES]);
        let mut writer = Writer::new(encoded.as_mut());
        writer.put(&PROFILE_VERSION.to_be_bytes())?;
        writer.put(network_id.as_bytes())?;
        writer.put(invite_id.as_bytes())?;
        writer.put(&not_before.get().to_be_bytes())?;
        writer.put(&expires_at.get().to_be_bytes())?;
        writer.put(&INVITATION_USE_LIMIT.to_be_bytes())?;
        let tbs = encoded
            .get(..INVITATION_TBS_BYTES)
            .ok_or(AuthError::InvalidEncoding)?;
        let signature = sign_canonical(authority, SignatureDomain::AccountCreationInvite, tbs)?;
        let mut writer = Writer::at(encoded.as_mut(), INVITATION_TBS_BYTES);
        writer.put(signature.as_bytes())?;
        Self::parse(&encoded)
    }

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
        if cursor.read_u16()? != INVITATION_USE_LIMIT {
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
            || !invitation_interval_admits(self.not_before(), self.expires_at(), now)
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

    /// Returns the inclusive start of the invitation interval.
    #[must_use]
    pub const fn not_before(&self) -> UtcSecond {
        UtcSecond::from_unix_seconds(self.not_before)
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

struct Writer<'a> {
    output: &'a mut [u8],
    position: usize,
}

impl<'a> Writer<'a> {
    const fn new(output: &'a mut [u8]) -> Self {
        Self::at(output, 0)
    }

    const fn at(output: &'a mut [u8], position: usize) -> Self {
        Self { output, position }
    }

    fn put(&mut self, bytes: &[u8]) -> Result<(), AuthError> {
        let end = self
            .position
            .checked_add(bytes.len())
            .ok_or(AuthError::InvalidEncoding)?;
        let slot = self
            .output
            .get_mut(self.position..end)
            .ok_or(AuthError::InvalidEncoding)?;
        slot.copy_from_slice(bytes);
        self.position = end;
        Ok(())
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

    use agenc_relay_crypto::{Ed25519SecretKey, SignatureDomain, sign_canonical};
    use agenc_relay_types::{InviteId, NetworkId, UtcSecond};

    use super::{
        ACCOUNT_CREATION_INVITE_BYTES, AccountCreationInvite, AuthError, Cursor, Writer,
        invitation_interval_admits,
    };

    #[test]
    fn interval_predicate_is_inclusive_at_not_before_and_exclusive_at_expiry() {
        let not_before = UtcSecond::from_unix_seconds(10);
        let expires_at = UtcSecond::from_unix_seconds(20);
        let admits = |now: u64| {
            invitation_interval_admits(not_before, expires_at, UtcSecond::from_unix_seconds(now))
        };
        assert!(admits(10), "now == not_before is admitted");
        assert!(admits(19), "now == expires_at - 1 is admitted");
        assert!(!admits(20), "now == expires_at is refused");
        assert!(!admits(9), "now == not_before - 1 is refused");
        assert!(!invitation_interval_admits(
            expires_at, expires_at, expires_at
        ));
    }

    #[test]
    fn verify_and_not_before_share_the_interval_predicate()
    -> Result<(), Box<dyn core::error::Error>> {
        let network = NetworkId::from_bytes([37_u8; 32]);
        let invite = InviteId::from_bytes([93_u8; 16]);
        let authority = Ed25519SecretKey::from_bytes([94_u8; 32]);
        let not_before = UtcSecond::from_unix_seconds(10);
        let expires_at = UtcSecond::from_unix_seconds(20);
        let issued =
            AccountCreationInvite::issue(network, invite, not_before, expires_at, &authority)?;
        assert_eq!(issued.not_before(), not_before);
        assert_eq!(issued.expires_at(), expires_at);
        for now in [9_u64, 10, 19, 20, 21] {
            let now = UtcSecond::from_unix_seconds(now);
            assert_eq!(
                issued.verify(authority.public_key(), network, now).is_ok(),
                invitation_interval_admits(not_before, expires_at, now)
            );
        }
        Ok(())
    }

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

    #[test]
    fn issued_invitations_match_the_reference_encoding_and_verify()
    -> Result<(), Box<dyn core::error::Error>> {
        let network = NetworkId::from_bytes([37_u8; 32]);
        let invite = InviteId::from_bytes([93_u8; 16]);
        let authority = Ed25519SecretKey::from_bytes([94_u8; 32]);
        let not_before = UtcSecond::from_unix_seconds(1_700_000_000);
        let expires_at = UtcSecond::from_unix_seconds(1_700_000_000 + 2_592_000);
        let issued =
            AccountCreationInvite::issue(network, invite, not_before, expires_at, &authority)?;

        let mut reference = Vec::new();
        reference.extend_from_slice(&1_u16.to_be_bytes());
        reference.extend_from_slice(network.as_bytes());
        reference.extend_from_slice(invite.as_bytes());
        reference.extend_from_slice(&not_before.get().to_be_bytes());
        reference.extend_from_slice(&expires_at.get().to_be_bytes());
        reference.extend_from_slice(&1_u16.to_be_bytes());
        let signature = sign_canonical(
            &authority,
            SignatureDomain::AccountCreationInvite,
            &reference,
        )?;
        reference.extend_from_slice(signature.as_bytes());
        assert_eq!(
            issued.expose_for_account_request().as_slice(),
            reference.as_slice()
        );
        assert_eq!(issued.invite_id(), invite);
        assert_eq!(issued.expires_at(), expires_at);

        issued.verify(authority.public_key(), network, not_before)?;
        assert_eq!(
            issued
                .verify(authority.public_key(), network, expires_at)
                .err(),
            Some(AuthError::InvitationRejected)
        );
        let other = Ed25519SecretKey::from_bytes([95_u8; 32]);
        assert_eq!(
            issued.verify(other.public_key(), network, not_before).err(),
            Some(AuthError::InvitationRejected)
        );
        Ok(())
    }

    #[test]
    fn issue_rejects_empty_reversed_and_oversized_lifetimes() {
        let network = NetworkId::from_bytes([1_u8; 32]);
        let invite = InviteId::from_bytes([2_u8; 16]);
        let authority = Ed25519SecretKey::from_bytes([3_u8; 32]);
        let start = UtcSecond::from_unix_seconds(1_000);
        for expires in [999_u64, 1_000, 1_000 + 2_592_001] {
            assert_eq!(
                AccountCreationInvite::issue(
                    network,
                    invite,
                    start,
                    UtcSecond::from_unix_seconds(expires),
                    &authority,
                )
                .err(),
                Some(AuthError::InvitationRejected)
            );
        }
        assert!(
            AccountCreationInvite::issue(
                network,
                invite,
                start,
                UtcSecond::from_unix_seconds(1_001),
                &authority,
            )
            .is_ok()
        );
    }

    #[test]
    fn writer_rejects_overflowing_slots() {
        let mut output = [0_u8; 4];
        let mut writer = Writer::new(&mut output);
        assert_eq!(
            writer.put(&[1, 2, 3, 4, 5]),
            Err(AuthError::InvalidEncoding)
        );
        assert_eq!(writer.put(&[1, 2]), Ok(()));
        assert_eq!(writer.put(&[3, 4, 5]), Err(AuthError::InvalidEncoding));
        let mut overflowing = Writer::at(&mut output, usize::MAX);
        assert_eq!(overflowing.put(&[1]), Err(AuthError::InvalidEncoding));
    }
}
