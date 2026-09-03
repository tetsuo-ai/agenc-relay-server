//! The closed failure set of every public-object check in this crate.

use std::error::Error;
use std::fmt;

/// Why a companion object, chain, or check was refused.
///
/// The variants are deliberately coarse: a rejected object never reports
/// which secret-bearing field differed, and no variant carries object bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum E2eeError {
    /// The input ended before the structure did.
    Truncated,
    /// Bytes remained after the complete structure.
    TrailingBytes,
    /// A length prefix was outside its declared bound.
    LengthOutOfRange,
    /// A vector was not canonical: unsorted, duplicated, or not exactly filled.
    NonCanonical,
    /// A closed enumeration carried an unregistered value.
    UnknownDiscriminant,
    /// A field violated a fixed semantic rule of the profile.
    InvalidValue,
    /// A profile ceiling would be exceeded.
    LimitExceeded,
    /// The caller's decode budget was exhausted.
    BudgetExceeded,
    /// Checked arithmetic overflowed.
    Overflow,
    /// A signature did not verify under its registered label.
    SignatureInvalid,
    /// A public key was not a canonical Ed25519 point.
    KeyInvalid,
    /// The recomputed object identifier differs from the asserted one.
    ObjectIdMismatch,
    /// The object kind does not match the carrier or expected body.
    WrongKind,
    /// A version, profile hash, network, or suite is not the one supported.
    ProfileMismatch,
}

impl fmt::Display for E2eeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Truncated => "truncated object",
            Self::TrailingBytes => "trailing bytes after object",
            Self::LengthOutOfRange => "length prefix outside its bound",
            Self::NonCanonical => "non-canonical vector",
            Self::UnknownDiscriminant => "unknown enumeration value",
            Self::InvalidValue => "field violates the profile",
            Self::LimitExceeded => "profile limit exceeded",
            Self::BudgetExceeded => "decode budget exhausted",
            Self::Overflow => "arithmetic overflow",
            Self::SignatureInvalid => "signature verification failed",
            Self::KeyInvalid => "invalid public key",
            Self::ObjectIdMismatch => "object identifier mismatch",
            Self::WrongKind => "object kind mismatch",
            Self::ProfileMismatch => "profile mismatch",
        })
    }
}

impl Error for E2eeError {}
