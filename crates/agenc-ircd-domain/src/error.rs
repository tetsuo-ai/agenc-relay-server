//! Closed, public-safe domain failures.

use std::error::Error;
use std::fmt;

use agenc_ircd_types::ValidationError;

/// A closed domain rejection that carries no peer-controlled text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainError {
    /// A bounded value failed construction.
    InvalidArgument,
    /// A command included duplicate canonical targets.
    DuplicateTarget,
    /// One command mixed local and global authority.
    MixedAuthority,
    /// The referenced session, user, account, or channel does not exist.
    NotFound,
    /// A secret target is unavailable to this principal.
    SecretUnavailable,
    /// The current principal is not allowed to perform the operation.
    Forbidden,
    /// The operation requires an authenticated account.
    RegistrationRequired,
    /// The caller no longer matches the current session generation.
    StaleGeneration,
    /// The caller or plan no longer matches the current revision.
    StaleRevision,
    /// A resource or protocol collection reached its fixed limit.
    LimitExceeded,
    /// Required rate or resource credit is unavailable.
    ServerBusy,
    /// Current protocol state does not admit this transition.
    BadState,
    /// The selected route accepts encrypted content only.
    EncryptedRoute,
    /// The selected route accepts plaintext content only.
    PlaintextRoute,
    /// A plaintext message attempted to carry an unsafe CTCP DCC command.
    UnsafeCtcp,
    /// A required UTC input was unavailable or untrusted.
    WallClockUnavailable,
    /// Explicit external inputs did not match the plan request.
    ExternalInputMismatch,
    /// Checked revision, sequence, or accounting arithmetic overflowed.
    Overflow,
    /// A bounded allocation could not be admitted.
    AllocationFailed,
    /// An internal state invariant is inconsistent.
    InvariantViolation,
}

impl From<ValidationError> for DomainError {
    fn from(error: ValidationError) -> Self {
        match error {
            ValidationError::AllocationFailed => Self::AllocationFailed,
            ValidationError::Overflow | ValidationError::Underflow => Self::Overflow,
            _ => Self::InvalidArgument,
        }
    }
}

impl fmt::Display for DomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidArgument => "invalid argument",
            Self::DuplicateTarget => "duplicate target",
            Self::MixedAuthority => "mixed authority",
            Self::NotFound => "target not found",
            Self::SecretUnavailable => "channel is unavailable",
            Self::Forbidden => "operation is not authorized",
            Self::RegistrationRequired => "account registration is required",
            Self::StaleGeneration => "session generation is stale",
            Self::StaleRevision => "state revision is stale",
            Self::LimitExceeded => "protocol limit exceeded",
            Self::ServerBusy => "resource admission failed",
            Self::BadState => "operation is not valid in the current state",
            Self::EncryptedRoute => "encrypted route rejects plaintext",
            Self::PlaintextRoute => "plaintext route rejects encrypted content",
            Self::UnsafeCtcp => "unsafe CTCP command refused",
            Self::WallClockUnavailable => "wall clock is unavailable",
            Self::ExternalInputMismatch => "external input does not match the request",
            Self::Overflow => "checked domain arithmetic overflowed",
            Self::AllocationFailed => "bounded allocation failed",
            Self::InvariantViolation => "domain invariant violation",
        };
        formatter.write_str(message)
    }
}

impl Error for DomainError {}
