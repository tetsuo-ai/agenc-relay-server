//! A valid unsupported export profile is distinct from invalid source evidence.
#![forbid(unsafe_code)]

use crate::RuntimeError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuditExportFailure {
    UnsupportedProfile,
    Source(RuntimeError),
}

impl From<RuntimeError> for AuditExportFailure {
    fn from(error: RuntimeError) -> Self {
        Self::Source(error)
    }
}

impl std::fmt::Display for AuditExportFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedProfile => formatter.write_str("audit export profile is unavailable"),
            Self::Source(error) => std::fmt::Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for AuditExportFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnsupportedProfile => None,
            Self::Source(error) => Some(error),
        }
    }
}
