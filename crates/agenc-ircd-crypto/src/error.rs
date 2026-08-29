//! Closed, non-secret cryptographic failures.

use std::error::Error;
use std::fmt;

/// Public-safe failures from a cryptographic adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    /// The operating-system entropy authority was unavailable.
    EntropyUnavailable,
    /// A supplied encoding had the wrong fixed length or shape.
    InvalidEncoding,
    /// Authenticated opening or strict signature verification failed.
    AuthenticationFailed,
    /// A value exceeded a protocol limit.
    LimitExceeded,
    /// A checked calculation overflowed.
    Overflow,
    /// A fallible bounded allocation was refused.
    AllocationFailed,
    /// A request kind and response kind were not a registered pair.
    KindMismatch,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EntropyUnavailable => "operating-system entropy is unavailable",
            Self::InvalidEncoding => "cryptographic encoding is invalid",
            Self::AuthenticationFailed => "cryptographic authentication failed",
            Self::LimitExceeded => "cryptographic input exceeds its protocol limit",
            Self::Overflow => "cryptographic length calculation overflowed",
            Self::AllocationFailed => "bounded cryptographic allocation failed",
            Self::KindMismatch => "account request and response kinds do not match",
        };
        formatter.write_str(message)
    }
}

impl Error for CryptoError {}

/// Public-safe failures from the bounded cryptographic worker pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoWorkerError {
    /// The selected bounded queue had no remaining admission capacity.
    QueueFull,
    /// Work was cancelled before a worker started it.
    CancelledBeforeStart,
    /// A worker panicked and the pool entered a permanent failed state.
    WorkerPanicked,
    /// The worker pool is shutting down or already stopped.
    ShuttingDown,
    /// Worker configuration was outside its closed limits.
    InvalidConfiguration,
    /// The operating system refused to create a worker thread.
    WorkerSpawnFailed,
}

impl fmt::Display for CryptoWorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::QueueFull => "cryptographic worker queue is full",
            Self::CancelledBeforeStart => "cryptographic job was cancelled before execution",
            Self::WorkerPanicked => "cryptographic worker failed",
            Self::ShuttingDown => "cryptographic worker pool is shutting down",
            Self::InvalidConfiguration => "cryptographic worker configuration is invalid",
            Self::WorkerSpawnFailed => "cryptographic worker thread could not be created",
        };
        formatter.write_str(message)
    }
}

impl Error for CryptoWorkerError {}
