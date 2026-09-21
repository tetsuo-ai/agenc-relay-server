//! Closed runtime failures with fixed, secret-free descriptions.

use std::error::Error;
use std::fmt;

use agenc_relay_storage::StorageError;

/// Public-safe failures from the Stage 06 runtime.
///
/// Every variant renders a fixed string: no address, identifier, input byte,
/// or secret can reach a log or operator message through this type (spec
/// 25.2, lines 6685-6692).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeError {
    /// The configured memory budget cannot fund the fixed pools (spec 19.2).
    BudgetArithmetic,
    /// The live permit pool is below the largest enabled listener working set.
    BudgetBelowWorkingSet,
    /// A checked size, count, or time calculation overflowed.
    Overflow,
    /// A bounded collection, ceiling, or registry would be exceeded.
    LimitExceeded,
    /// A value violated an invariant that its constructor must enforce.
    InvalidValue,
    /// A valid client command was refused before its state-dependent conversion.
    CommandRefused(agenc_relay_domain::DomainError),
    /// The process-wide memory budget refused a permit batch.
    MemoryExhausted,
    /// The owning token was cancelled before the operation completed.
    Cancelled,
    /// The storage owner reported a closed failure.
    Storage(StorageError),
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BudgetArithmetic => {
                formatter.write_str("memory budget cannot fund the fixed runtime pools")
            }
            Self::BudgetBelowWorkingSet => {
                formatter.write_str("memory budget is below the enabled listener working set")
            }
            Self::Overflow => formatter.write_str("runtime size calculation overflowed"),
            Self::LimitExceeded => formatter.write_str("runtime ceiling exceeded"),
            Self::InvalidValue => formatter.write_str("runtime value violates its invariant"),
            Self::CommandRefused(_) => formatter.write_str("client command refused"),
            Self::MemoryExhausted => formatter.write_str("memory budget exhausted"),
            Self::Cancelled => formatter.write_str("runtime operation cancelled"),
            Self::Storage(error) => write!(formatter, "storage owner failed: {error}"),
        }
    }
}

impl Error for RuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Storage(error) => Some(error),
            _ => None,
        }
    }
}

impl From<StorageError> for RuntimeError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [RuntimeError; 9] = [
        RuntimeError::BudgetArithmetic,
        RuntimeError::BudgetBelowWorkingSet,
        RuntimeError::Overflow,
        RuntimeError::LimitExceeded,
        RuntimeError::InvalidValue,
        RuntimeError::CommandRefused(agenc_relay_domain::DomainError::Forbidden),
        RuntimeError::MemoryExhausted,
        RuntimeError::Cancelled,
        RuntimeError::Storage(StorageError::Unavailable),
    ];

    #[test]
    fn every_variant_renders_a_fixed_ascii_message_and_only_storage_has_a_source() {
        for error in ALL {
            let text = error.to_string();
            assert!(!text.is_empty());
            assert!(text.is_ascii());
            assert_eq!(
                error.source().is_some(),
                matches!(error, RuntimeError::Storage(_))
            );
        }
        assert_eq!(
            RuntimeError::from(StorageError::QueueFull),
            RuntimeError::Storage(StorageError::QueueFull)
        );
    }
}
