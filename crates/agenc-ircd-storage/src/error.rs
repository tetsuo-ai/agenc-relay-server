//! Closed failures at the durable storage boundary.

use std::error::Error;
use std::fmt;

/// Failures returned before a storage outcome becomes uncertain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageError {
    /// A canonical encoding was malformed, non-canonical, or incomplete.
    InvalidEncoding,
    /// An object named an unsupported format, table, schema, or generation.
    UnsupportedVersion,
    /// A configured or protocol limit would be exceeded.
    LimitExceeded,
    /// Checked size, sequence, or accounting arithmetic overflowed.
    Overflow,
    /// A bounded allocation could not be reserved.
    AllocationFailed,
    /// Authenticated bytes or their independently computed commitment differed.
    AuthenticationFailed,
    /// A revision, sequence, identity, or cross-reference was stale or inconsistent.
    StaleState,
    /// The fixed storage handoff queue had no free slot.
    QueueFull,
    /// The storage owner is closing, entered indeterminate state, or lost a required
    /// operating-system facility such as entropy.
    Unavailable,
    /// The filesystem identity, permissions, capacity, or qualification was invalid.
    FilesystemRejected,
    /// Another process owns the fixed writer lock.
    WriterLocked,
    /// A database operation failed before irreversible commit began.
    DatabaseRejected,
    /// The requested migration profile is not compiled into this schema generation.
    UnsupportedMigration,
    /// A maintenance operation could not safely resume the named construction.
    ResumeMismatch,
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEncoding => "storage encoding is invalid",
            Self::UnsupportedVersion => "storage version is unsupported",
            Self::LimitExceeded => "storage input exceeds its limit",
            Self::Overflow => "storage arithmetic overflowed",
            Self::AllocationFailed => "bounded storage allocation failed",
            Self::AuthenticationFailed => "storage authentication failed",
            Self::StaleState => "storage state is stale or inconsistent",
            Self::QueueFull => "storage queue is full",
            Self::Unavailable => "storage owner is unavailable",
            Self::FilesystemRejected => "filesystem policy rejected storage",
            Self::WriterLocked => "storage writer is already locked",
            Self::DatabaseRejected => "database rejected the operation",
            Self::UnsupportedMigration => "storage migration profile is unsupported",
            Self::ResumeMismatch => "storage construction cannot be resumed",
        })
    }
}

impl Error for StorageError {}

impl From<agenc_ircd_crypto::CryptoError> for StorageError {
    fn from(error: agenc_ircd_crypto::CryptoError) -> Self {
        use agenc_ircd_crypto::CryptoError;
        match error {
            CryptoError::AuthenticationFailed => Self::AuthenticationFailed,
            CryptoError::LimitExceeded => Self::LimitExceeded,
            CryptoError::Overflow => Self::Overflow,
            CryptoError::AllocationFailed => Self::AllocationFailed,
            CryptoError::EntropyUnavailable => Self::Unavailable,
            CryptoError::InvalidEncoding | CryptoError::KindMismatch => Self::InvalidEncoding,
        }
    }
}
