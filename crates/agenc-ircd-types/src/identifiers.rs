//! Domain-separated fixed-size identifiers and canonical text forms.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroize;

use crate::{EntropyError, EntropySource, ValidationError};

const MAX_IDENTIFIER_TEXT_BYTES: usize = 43;

const fn unpadded_base64_len(bytes: usize) -> usize {
    (bytes * 4).div_ceil(3)
}

fn parse_fixed<const SIZE: usize>(text: &str) -> Result<[u8; SIZE], ValidationError> {
    if text.len() != unpadded_base64_len(SIZE) {
        return Err(ValidationError::IdentifierLength);
    }
    let mut bytes = [0_u8; SIZE];
    let decoded = URL_SAFE_NO_PAD
        .decode_slice(text, &mut bytes)
        .map_err(|_| ValidationError::NonCanonical)?;
    if decoded != SIZE {
        return Err(ValidationError::IdentifierLength);
    }
    let mut canonical = [0_u8; MAX_IDENTIFIER_TEXT_BYTES];
    let written = URL_SAFE_NO_PAD
        .encode_slice(bytes, &mut canonical)
        .map_err(|_| ValidationError::Overflow)?;
    let Some(encoded) = canonical.get(..written) else {
        return Err(ValidationError::Overflow);
    };
    if encoded != text.as_bytes() {
        return Err(ValidationError::NonCanonical);
    }
    Ok(bytes)
}

fn encode_fixed(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

macro_rules! identifier {
    ($name:ident, $bytes:expr, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; $bytes]);

        impl $name {
            /// Constructs the identifier from its complete binary representation.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; $bytes]) -> Self {
                Self(bytes)
            }

            /// Generates a fresh identifier through an injected entropy authority.
            pub fn generate(entropy: &mut impl EntropySource) -> Result<Self, EntropyError> {
                let mut bytes = [0_u8; $bytes];
                entropy.fill_exact(&mut bytes)?;
                Ok(Self(bytes))
            }

            /// Parses the one canonical unpadded URL-safe base64 form.
            pub fn parse(text: &str) -> Result<Self, ValidationError> {
                parse_fixed(text).map(Self)
            }

            /// Returns the complete binary representation.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $bytes] {
                &self.0
            }

            /// Encodes the canonical unpadded URL-safe base64 form.
            #[must_use]
            pub fn to_base64url(&self) -> String {
                encode_fixed(&self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

identifier!(NetworkId, 32, "A permanent 32-byte network identity.");
identifier!(ServerId, 16, "A permanent 16-byte server identity.");
identifier!(
    ServerIncarnation,
    16,
    "A 16-byte server-incarnation identity for durable replay state."
);
identifier!(
    RecoveryEpoch,
    16,
    "A 16-byte continuous-state lineage identity."
);
identifier!(SessionId, 16, "A 16-byte accepted client-session identity.");
identifier!(UserId, 16, "A 16-byte registered user-session identity.");
identifier!(
    ChannelInstanceId,
    16,
    "A 16-byte identity for one channel creation."
);
identifier!(
    MessageId,
    16,
    "A permanent 16-byte network message identity."
);
identifier!(RequestId, 16, "A 16-byte idempotent request identity.");
identifier!(EventId, 16, "A 16-byte federation event identity.");
identifier!(OriginId, 16, "A 16-byte federation origin identity.");
identifier!(
    TransactionId,
    16,
    "A 16-byte account-service transaction identity."
);
identifier!(DatabaseId, 16, "A 16-byte durable database identity.");
identifier!(ConnectionId, 16, "A 16-byte accepted transport identity.");
identifier!(InviteId, 16, "A 16-byte invitation identity.");
identifier!(EntryId, 16, "A 16-byte list-mode entry identity.");

/// A one-use account-deletion confirmation token.
///
/// The token is move-only, redacted from formatting, and zeroized on drop.
/// Its only public byte exposure is the exact deletion reply/confirmation
/// boundary.
pub struct AccountDeletionToken([u8; 16]);

impl AccountDeletionToken {
    /// Constructs a token from explicitly supplied entropy bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Borrows the bytes for the deletion reply or confirmation boundary.
    #[must_use]
    pub const fn expose_for_deletion(&self) -> &[u8; 16] {
        &self.0
    }

    /// Compares a supplied token without data-dependent early exit.
    #[must_use]
    pub fn matches(&self, candidate: &[u8; 16]) -> bool {
        bool::from(self.0.ct_eq(candidate))
    }
}

impl Drop for AccountDeletionToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A one-use 32-byte authentication bearer grant.
///
/// The grant deliberately has no text form and does not implement `Clone`,
/// `Copy`, `Debug`, or `Display`.
///
/// ```compile_fail
/// use agenc_ircd_types::AuthGrantId;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<AuthGrantId>();
/// ```
///
/// ```compile_fail
/// use std::fmt::Debug;
///
/// use agenc_ircd_types::AuthGrantId;
///
/// fn require_debug<T: Debug>() {}
/// require_debug::<AuthGrantId>();
/// ```
pub struct AuthGrantId([u8; 32]);

impl AuthGrantId {
    /// Constructs a grant from its complete private binary representation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Generates a fresh grant through an injected entropy authority.
    pub fn generate(entropy: &mut impl EntropySource) -> Result<Self, EntropyError> {
        let mut grant = Self([0_u8; 32]);
        entropy.fill_exact(&mut grant.0)?;
        Ok(grant)
    }

    /// Borrows the private bytes for the one matching session-open operation.
    #[must_use]
    pub const fn expose_for_session_open(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for AuthGrantId {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The immutable 16-byte random component of a public account identity.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AccountRandomId([u8; 16]);

impl AccountRandomId {
    /// Constructs an account identity from its complete random component.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Generates a fresh account identity through an injected entropy authority.
    pub fn generate(entropy: &mut impl EntropySource) -> Result<Self, EntropyError> {
        let mut bytes = [0_u8; 16];
        entropy.fill_exact(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// Parses the exact `a_` plus 22-character canonical representation.
    pub fn parse(text: &str) -> Result<Self, ValidationError> {
        let Some(encoded) = text.strip_prefix("a_") else {
            return Err(ValidationError::InvalidPrefix);
        };
        parse_fixed(encoded).map(Self)
    }

    /// Returns the complete random component.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Returns the exact public account identity text.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut text = String::with_capacity(24);
        text.push_str("a_");
        text.push_str(&encode_fixed(&self.0));
        text
    }

    /// Converts the random component into its domain-separated Account ID.
    #[must_use]
    pub const fn to_account_id(self) -> AccountId {
        AccountId(self)
    }
}

impl fmt::Debug for AccountRandomId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccountRandomId([redacted])")
    }
}

/// The exact textual 24-byte `a_` account authority identifier.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AccountId(AccountRandomId);

impl AccountId {
    /// Constructs an Account ID from its permanent random component.
    #[must_use]
    pub const fn from_random(random: AccountRandomId) -> Self {
        Self(random)
    }

    /// Parses the exact `a_` plus canonical 22-character Base64url form.
    pub fn parse(text: &str) -> Result<Self, ValidationError> {
        AccountRandomId::parse(text).map(Self)
    }

    /// Parses the exact 24 ASCII bytes carried by federation and E2EE fields.
    pub fn parse_wire_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        let text = std::str::from_utf8(bytes).map_err(|_| ValidationError::InvalidUtf8)?;
        Self::parse(text)
    }

    /// Returns the permanent 16-byte random component.
    #[must_use]
    pub const fn random(self) -> AccountRandomId {
        self.0
    }

    /// Produces the exact 24-byte textual identity.
    #[must_use]
    pub fn to_text(self) -> String {
        self.0.to_text()
    }
}

impl fmt::Debug for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccountId([redacted])")
    }
}

/// A private 32-byte account-service credential lookup identity.
pub struct OpaqueCredentialId([u8; 32]);

impl OpaqueCredentialId {
    /// Constructs the private identity from account-service bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the private binary value for an account-service operation.
    #[must_use]
    pub const fn expose_for_account_service(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for OpaqueCredentialId {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::{AccountRandomId, NetworkId};
    use crate::ValidationError;

    #[test]
    fn identifier_text_rejects_each_length_and_prefix_boundary() {
        assert_eq!(
            NetworkId::parse("short"),
            Err(ValidationError::IdentifierLength)
        );
        assert_eq!(
            NetworkId::parse(&"!".repeat(43)),
            Err(ValidationError::NonCanonical)
        );
        assert_eq!(
            AccountRandomId::parse("AAAAAAAAAAAAAAAAAAAAAA"),
            Err(ValidationError::InvalidPrefix)
        );

        let network = NetworkId::from_bytes([0_u8; 32]);
        assert_eq!(NetworkId::parse(&network.to_base64url()), Ok(network));
    }
}
