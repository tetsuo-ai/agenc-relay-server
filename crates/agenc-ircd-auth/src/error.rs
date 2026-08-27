//! Closed, non-secret authentication failures.

use std::error::Error;
use std::fmt;

use agenc_ircd_crypto::{CryptoError, CryptoWorkerError};

/// Stable failures at account-service trust boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthError {
    /// A canonical protocol encoding was malformed.
    InvalidEncoding,
    /// An authenticated field did not match its expected context.
    ContextMismatch,
    /// A one-use state was already consumed.
    Consumed,
    /// A one-use state reached its exclusive deadline.
    Expired,
    /// The request came from a different connection.
    WrongConnection,
    /// The request came through a different federation origin.
    WrongOrigin,
    /// OPAQUE authentication or strict signature verification failed.
    AuthenticationFailed,
    /// The invitation was invalid for the current account policy.
    InvitationRejected,
    /// The operating-system entropy authority was unavailable.
    EntropyUnavailable,
    /// A bounded allocation was refused.
    AllocationFailed,
    /// A checked counter or deadline calculation overflowed.
    Overflow,
    /// The blocking cryptographic worker could not accept or complete work.
    WorkerUnavailable,
    /// The operation was not legal in the current state.
    WrongState,
}

impl fmt::Display for AuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidEncoding => "account-service encoding is invalid",
            Self::ContextMismatch => "account-service context does not match",
            Self::Consumed => "account-service state was already consumed",
            Self::Expired => "account-service state expired",
            Self::WrongConnection => "account-service connection does not match",
            Self::WrongOrigin => "account-service origin does not match",
            Self::AuthenticationFailed => "account authentication failed",
            Self::InvitationRejected => "account-creation invitation was rejected",
            Self::EntropyUnavailable => "account-service entropy is unavailable",
            Self::AllocationFailed => "account-service allocation was refused",
            Self::Overflow => "account-service calculation overflowed",
            Self::WorkerUnavailable => "account-service crypto worker is unavailable",
            Self::WrongState => "account-service operation is not valid in this state",
        };
        formatter.write_str(message)
    }
}

impl Error for AuthError {}

impl From<CryptoError> for AuthError {
    fn from(error: CryptoError) -> Self {
        match error {
            CryptoError::EntropyUnavailable => Self::EntropyUnavailable,
            CryptoError::InvalidEncoding | CryptoError::LimitExceeded => Self::InvalidEncoding,
            CryptoError::AuthenticationFailed
            | CryptoError::ExporterConsumed
            | CryptoError::KindMismatch => Self::AuthenticationFailed,
            CryptoError::Overflow => Self::Overflow,
            CryptoError::AllocationFailed => Self::AllocationFailed,
        }
    }
}

impl From<CryptoWorkerError> for AuthError {
    fn from(_error: CryptoWorkerError) -> Self {
        Self::WorkerUnavailable
    }
}
