//! Two-step confirmation tokens (spec 4575-4581).

use agenc_ircd_crypto::admin_confirmation_token_hash;
use agenc_ircd_types::{AdminPermissionSet, MonotonicTick, Revision};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroize;

use crate::base64::{decode_fixed_base64url, encode_base64url};
use crate::{AdminError, MAX_ADMIN_COMMAND_BYTES};

/// Random token width (spec 4578).
pub const CONFIRMATION_TOKEN_BYTES: usize = 16;
/// Token lifetime in monotonic seconds (spec 4578).
pub const CONFIRMATION_TTL_SECONDS: u64 = 60;
/// Token lifetime in the millisecond `MonotonicTick` unit.
pub const CONFIRMATION_TTL_MILLIS: u64 = CONFIRMATION_TTL_SECONDS * 1_000;

/// A bearer confirmation token; never `Debug`, zeroized on drop.
///
/// ```compile_fail
/// use agenc_ircd_admin::ConfirmationToken;
/// fn require_debug<T: core::fmt::Debug>() {}
/// require_debug::<ConfirmationToken>();
/// ```
pub struct ConfirmationToken([u8; CONFIRMATION_TOKEN_BYTES]);

impl ConfirmationToken {
    /// Wraps fresh random bytes drawn by the runtime.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; CONFIRMATION_TOKEN_BYTES]) -> Self {
        Self(bytes)
    }

    /// Parses the 22-character canonical tag value.
    pub fn parse(text: &[u8]) -> Result<Self, AdminError> {
        decode_fixed_base64url::<CONFIRMATION_TOKEN_BYTES>(text).map(Self)
    }

    /// Encodes the canonical tag value for the CONFIRM note.
    #[must_use]
    pub fn to_base64url(&self) -> String {
        encode_base64url(&self.0)
    }

    /// Returns the `SHA256("agenc-chat admin confirmation token v1" || token)`
    /// carried in `AdminCommandTBS` (spec 4419-4424).
    pub fn hash(&self) -> Result<[u8; 32], AdminError> {
        admin_confirmation_token_hash(&self.0)
            .map(|digest| *digest.as_bytes())
            .map_err(|_| AdminError::Overflow)
    }

    /// Constant-time equality.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl Drop for ConfirmationToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The one pending confirmation an admin session may hold.
///
/// The binding stores the exact canonical command bytes so the repeat must
/// be byte-identical; this is the property the spec's SHA-256 binding
/// provides, and the operator signature separately covers the token hash.
pub struct PendingConfirmation {
    token: ConfirmationToken,
    issued_at: MonotonicTick,
    canonical_command: Vec<u8>,
    target_revision: Revision,
    permissions: AdminPermissionSet,
}

/// Outcome of matching a presented token against the pending one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfirmationCheck {
    /// Every binding matched inside the lifetime.
    Satisfied,
    /// The token lifetime elapsed.
    Expired,
    /// The token, command, or permission set differed.
    Mismatch,
}

impl PendingConfirmation {
    /// Records a freshly issued token bound to its session facts.
    pub fn issue(
        token: ConfirmationToken,
        issued_at: MonotonicTick,
        canonical_command: &[u8],
        target_revision: Revision,
        permissions: AdminPermissionSet,
    ) -> Result<Self, AdminError> {
        if canonical_command.is_empty() || canonical_command.len() > MAX_ADMIN_COMMAND_BYTES {
            return Err(AdminError::Framing);
        }
        Ok(Self {
            token,
            issued_at,
            canonical_command: canonical_command.to_vec(),
            target_revision,
            permissions,
        })
    }

    /// Returns the token for rendering the CONFIRM note.
    #[must_use]
    pub const fn token(&self) -> &ConfirmationToken {
        &self.token
    }

    /// Returns the target revision the runtime must still observe.
    #[must_use]
    pub const fn target_revision(&self) -> Revision {
        self.target_revision
    }

    /// The instant after which the token is expired (inclusive).
    pub fn expires_at(&self) -> Result<MonotonicTick, AdminError> {
        self.issued_at
            .checked_add(CONFIRMATION_TTL_MILLIS)
            .map_err(|_| AdminError::Overflow)
    }

    /// Checks one presented token; any outcome consumes the pending value
    /// at the caller (spec 4580: "any attempt ... consumes it").
    pub fn check(
        &self,
        now: MonotonicTick,
        presented: &ConfirmationToken,
        canonical_command: &[u8],
        permissions: AdminPermissionSet,
    ) -> Result<ConfirmationCheck, AdminError> {
        if now >= self.expires_at()? {
            return Ok(ConfirmationCheck::Expired);
        }
        let token_matches = self.token.matches(presented);
        let command_matches = self.canonical_command == canonical_command;
        let permissions_match = self.permissions == permissions;
        if token_matches && command_matches && permissions_match {
            Ok(ConfirmationCheck::Satisfied)
        } else {
            Ok(ConfirmationCheck::Mismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use agenc_ircd_types::{AdminPermission, AdminPermissionSet, MonotonicTick, Revision};

    use super::{
        CONFIRMATION_TTL_MILLIS, ConfirmationCheck, ConfirmationToken, PendingConfirmation,
    };
    use crate::AdminError;

    fn permissions() -> AdminPermissionSet {
        let mut set = AdminPermissionSet::EMPTY;
        set.insert(AdminPermission::Process);
        set
    }

    fn pending() -> Result<PendingConfirmation, AdminError> {
        PendingConfirmation::issue(
            ConfirmationToken::from_bytes([1; 16]),
            MonotonicTick::new(1_000).map_err(|_| AdminError::Overflow)?,
            b"DIE :maintenance",
            Revision::new(3).map_err(|_| AdminError::Overflow)?,
            permissions(),
        )
    }

    fn tick(value: u64) -> Result<MonotonicTick, AdminError> {
        MonotonicTick::new(value).map_err(|_| AdminError::Overflow)
    }

    #[test]
    fn tokens_render_parse_hash_and_compare_in_constant_time() -> Result<(), AdminError> {
        let token = ConfirmationToken::from_bytes([9; 16]);
        let text = token.to_base64url();
        assert_eq!(text.len(), 22);
        assert!(ConfirmationToken::parse(text.as_bytes())?.matches(&token));
        assert!(!ConfirmationToken::from_bytes([8; 16]).matches(&token));
        assert_eq!(
            ConfirmationToken::parse(b"x").err(),
            Some(AdminError::Token)
        );
        assert_ne!(token.hash()?, [0; 32]);
        Ok(())
    }

    #[test]
    fn lifetime_boundaries_and_bindings_are_exact() -> Result<(), AdminError> {
        let pending = pending()?;
        assert_eq!(pending.target_revision().get(), 3);
        assert_eq!(pending.expires_at()?.get(), 1_000 + CONFIRMATION_TTL_MILLIS);
        let same = ConfirmationToken::from_bytes([1; 16]);
        let at = |seconds: u64| tick(1_000 + seconds * 1_000);
        assert_eq!(
            pending.check(at(59)?, &same, b"DIE :maintenance", permissions())?,
            ConfirmationCheck::Satisfied
        );
        assert_eq!(
            pending.check(at(60)?, &same, b"DIE :maintenance", permissions())?,
            ConfirmationCheck::Expired
        );
        assert_eq!(
            pending.check(at(61)?, &same, b"DIE :maintenance", permissions())?,
            ConfirmationCheck::Expired
        );
        let other = ConfirmationToken::from_bytes([2; 16]);
        assert_eq!(
            pending.check(at(1)?, &other, b"DIE :maintenance", permissions())?,
            ConfirmationCheck::Mismatch
        );
        assert_eq!(
            pending.check(at(1)?, &same, b"DIE :other", permissions())?,
            ConfirmationCheck::Mismatch
        );
        assert_eq!(
            pending.check(
                at(1)?,
                &same,
                b"DIE :maintenance",
                AdminPermissionSet::EMPTY
            )?,
            ConfirmationCheck::Mismatch
        );
        assert!(pending.token().matches(&same));
        let zero = Revision::new(0).map_err(|_| AdminError::Overflow)?;
        assert_eq!(
            PendingConfirmation::issue(same, tick(0)?, &[], zero, permissions()).err(),
            Some(AdminError::Framing)
        );
        Ok(())
    }
}
