//! Pure client-facing endpoint and onboarding descriptor grammar.
#![forbid(unsafe_code)]

pub mod endpoint;
pub mod onboarding;
pub mod socks;

use std::fmt;

/// Closed failures for client configuration and descriptor input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ClientSupportError {
    /// The document does not match the descriptor grammar.
    InvalidDocument,
    /// The descriptor omits a required value.
    MissingValue,
    /// A value is outside its canonical grammar or bound.
    InvalidValue,
}

impl fmt::Display for ClientSupportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidDocument => "onboarding document rejected",
            Self::MissingValue => "required onboarding value missing",
            Self::InvalidValue => "client configuration value rejected",
        })
    }
}

impl std::error::Error for ClientSupportError {}
