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
    /// The filesystem identity, permissions, capacity, or qualification was invalid;
    /// the closed cause says which, for operator diagnosis only. The outer
    /// determinate/committed/indeterminate outcome never depends on the cause.
    FilesystemRejected(FilesystemCause),
    /// Another process owns the fixed writer lock.
    WriterLocked,
    /// A database operation failed before irreversible commit began.
    DatabaseRejected,
    /// A maintenance operation could not safely resume the named construction.
    ResumeMismatch,
    /// One durable operation's Section 19.3 physical growth allowance could not admit an
    /// allocation. The refusal is determinate: nothing of the refused transaction was written,
    /// an already burned nonce reservation stays durable and is never reused, and the next
    /// operation starts unaffected. It is never an I/O failure, never stale state, and never
    /// the indeterminate outcome; the closed phase says where the allowance ran out, for
    /// operator diagnosis only.
    AllowanceRefused(AllowancePhase),
    /// The database was laid out with regions of the named size in bytes, larger than the
    /// bounded allowance can ever extend the file by, so no bounded transaction could grow it.
    /// The daemon refuses to open it rather than run it unbounded or let it fill up silently;
    /// it must be recreated (initialized or restored) with bounded regions.
    UnboundedRegion(u64),
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
            Self::FilesystemRejected(cause) => {
                return write!(formatter, "filesystem policy rejected storage: {cause}");
            }
            Self::WriterLocked => "storage writer is already locked",
            Self::DatabaseRejected => "database rejected the operation",
            Self::ResumeMismatch => "storage construction cannot be resumed",
            Self::AllowanceRefused(phase) => {
                return write!(
                    formatter,
                    "storage growth allowance refused the operation during {phase}"
                );
            }
            Self::UnboundedRegion(bytes) => {
                return write!(
                    formatter,
                    "database region size {bytes} bytes cannot grow under the bounded allowance; recreate the database with {}-byte regions",
                    crate::bounded::LIVE_DATABASE_REGION_BYTES
                );
            }
        })
    }
}

impl Error for StorageError {}

/// Closed phase of one durable operation in which its physical growth allowance refused.
///
/// The phase is diagnostic only: every refusal is the same determinate, side-effect-free
/// `AllowanceRefused` outcome whatever the phase, and no phase makes a refusal retryable in
/// place. `Mutation` and `Preparation` name the two abortable halves of one bounded redb
/// transaction, `Cleanup` names the deferred freed-page reclamation that follows a committed
/// operation, and `Close` names the allocator-state persistence that precedes a database close.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllowancePhase {
    /// A table write of the transaction requested a page or a file extension.
    Mutation,
    /// The abortable commit preparation requested a page or a file extension.
    Preparation,
    /// The deferred reclamation of pages earlier transactions freed requested an allocation.
    Cleanup,
    /// The allocator-state persistence before a database close requested an allocation.
    Close,
}

impl AllowancePhase {
    /// Every phase, in operation order.
    pub const ALL: [Self; 4] = [
        Self::Mutation,
        Self::Preparation,
        Self::Cleanup,
        Self::Close,
    ];

    /// Fixed lowercase label for logs and metrics.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Mutation => "mutation",
            Self::Preparation => "preparation",
            Self::Cleanup => "cleanup",
            Self::Close => "close",
        }
    }
}

impl fmt::Display for AllowancePhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// Closed, bounded cause of a filesystem rejection (spec 25.2: fixed labels,
/// never a path, an errno string, or content). It is diagnostic only: the
/// public storage outcome is the same `FilesystemRejected` whatever the cause,
/// and no cause makes an uncertain write retryable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilesystemCause {
    /// A required entry (guard, database, lock, directory, plan) was absent.
    MissingState,
    /// Ownership, mode, or an access check refused the entry.
    PermissionRejected,
    /// The free-space reserve, quota, or configured size ceiling was exhausted.
    InsufficientCapacity,
    /// The filesystem, mount, target, or measured tuple is not the qualified one.
    Unqualified,
    /// The kernel reported an input/output failure.
    IoFailure,
    /// The path, name, link count, type, or filesystem boundary is unsafe.
    UnsafePath,
    /// An operating-system error outside the classified set.
    Unknown,
}

impl FilesystemCause {
    /// Every cause, in label order.
    pub const ALL: [Self; 7] = [
        Self::MissingState,
        Self::PermissionRejected,
        Self::InsufficientCapacity,
        Self::Unqualified,
        Self::IoFailure,
        Self::UnsafePath,
        Self::Unknown,
    ];

    /// Fixed lowercase label for logs and metrics.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MissingState => "missing_state",
            Self::PermissionRejected => "permission_rejected",
            Self::InsufficientCapacity => "insufficient_capacity",
            Self::Unqualified => "unqualified",
            Self::IoFailure => "io_failure",
            Self::UnsafePath => "unsafe_path",
            Self::Unknown => "unknown",
        }
    }

    /// Classifies a raw operating-system errno into the closed set.
    #[must_use]
    pub fn from_errno(errno: rustix::io::Errno) -> Self {
        use rustix::io::Errno;
        match errno {
            Errno::NOENT => Self::MissingState,
            Errno::ACCESS | Errno::PERM | Errno::ROFS => Self::PermissionRejected,
            Errno::NOSPC | Errno::DQUOT | Errno::FBIG => Self::InsufficientCapacity,
            Errno::IO | Errno::STALE => Self::IoFailure,
            Errno::LOOP
            | Errno::NOTDIR
            | Errno::ISDIR
            | Errno::XDEV
            | Errno::EXIST
            | Errno::NAMETOOLONG
            | Errno::INVAL
            | Errno::TXTBSY => Self::UnsafePath,
            _ => Self::Unknown,
        }
    }

    /// Classifies a `std::io::Error` through its raw errno when it has one.
    #[must_use]
    pub fn from_io(error: &std::io::Error) -> Self {
        match error.raw_os_error() {
            Some(raw) => Self::from_errno(rustix::io::Errno::from_raw_os_error(raw)),
            None => match error.kind() {
                std::io::ErrorKind::NotFound => Self::MissingState,
                std::io::ErrorKind::PermissionDenied => Self::PermissionRejected,
                std::io::ErrorKind::UnexpectedEof => Self::IoFailure,
                _ => Self::Unknown,
            },
        }
    }
}

impl fmt::Display for FilesystemCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// A raw operating-system failure that classifies into a [`FilesystemCause`].
pub trait FilesystemFailure {
    /// The closed cause this failure maps to.
    fn cause(&self) -> FilesystemCause;
}

impl FilesystemFailure for std::io::Error {
    fn cause(&self) -> FilesystemCause {
        FilesystemCause::from_io(self)
    }
}

impl FilesystemFailure for rustix::io::Errno {
    fn cause(&self) -> FilesystemCause {
        FilesystemCause::from_errno(*self)
    }
}

/// Maps a raw operating-system failure to the closed rejection, retaining
/// only its classified cause; the raw error, its text, and any path are
/// dropped here at the adapter boundary.
pub fn filesystem_rejected<E: FilesystemFailure>(error: E) -> StorageError {
    StorageError::FilesystemRejected(error.cause())
}

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
