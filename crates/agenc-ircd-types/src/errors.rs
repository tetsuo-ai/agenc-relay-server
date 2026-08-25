//! Stable validation and public-safe error values.

use std::error::Error;
use std::fmt;

/// Closed failures raised while constructing foundational values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    /// A required value was empty.
    Empty,
    /// A value was shorter than its domain minimum.
    TooShort,
    /// A value exceeded its domain maximum.
    TooLong,
    /// Input was not valid UTF-8.
    InvalidUtf8,
    /// Input contained a forbidden NUL byte.
    Nul,
    /// Input contained a forbidden control character.
    Control,
    /// Input contained a character outside its closed grammar.
    InvalidCharacter,
    /// Input used a valid but noncanonical representation.
    NonCanonical,
    /// A checked calculation overflowed.
    Overflow,
    /// A checked calculation underflowed.
    Underflow,
    /// A value was outside a numeric domain.
    OutOfRange,
    /// Allocation admission failed before construction completed.
    AllocationFailed,
    /// A name did not satisfy its pinned PRECIS profile.
    PrecisRejected,
    /// A typed name or mask used the wrong prefix.
    InvalidPrefix,
    /// A typed mask had an invalid or recursive shape.
    InvalidMask,
    /// A fixed-size identifier had the wrong decoded length.
    IdentifierLength,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Empty => "value is empty",
            Self::TooShort => "value is too short",
            Self::TooLong => "value is too long",
            Self::InvalidUtf8 => "value is not valid UTF-8",
            Self::Nul => "value contains NUL",
            Self::Control => "value contains a forbidden control character",
            Self::InvalidCharacter => "value contains an invalid character",
            Self::NonCanonical => "value is not canonical",
            Self::Overflow => "checked calculation overflowed",
            Self::Underflow => "checked calculation underflowed",
            Self::OutOfRange => "value is outside its domain",
            Self::AllocationFailed => "bounded allocation failed",
            Self::PrecisRejected => "value is rejected by its PRECIS profile",
            Self::InvalidPrefix => "value has an invalid type prefix",
            Self::InvalidMask => "typed mask is invalid",
            Self::IdentifierLength => "identifier has an invalid decoded length",
        };
        formatter.write_str(message)
    }
}

impl Error for ValidationError {}

/// Public-safe context carried beside a closed reply code.
///
/// The context is selected from server-owned values. It never stores raw input
/// or an internal error source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SafeContext {
    /// No context is safe or needed.
    None,
    /// A zero-based bounded target index.
    TargetIndex(u16),
    /// A server-owned retry delay in whole seconds.
    RetryAfterSeconds(u32),
    /// A server-owned maximum expressed as an unsigned count.
    Maximum(u64),
}
