//! Closed, payload-free administrative failures.

use std::error::Error;
use std::fmt;

/// A bounded parsing or verification failure inside the admin boundary.
///
/// Every variant is payload-free so an error can never carry operator input,
/// a token, or a signature into a log line (Architecture 25.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminError {
    /// A line, tag section, or command exceeded a Section 22.4 bound.
    Framing,
    /// The tag section was absent, malformed, misordered, or duplicated.
    Tag,
    /// A counter was noncanonical, out of order, or exhausted.
    Counter,
    /// A base64url token had the wrong length or a noncanonical form.
    Token,
    /// The command bytes were not in canonical form.
    Canonical,
    /// The command was outside the closed 22.5 registry or malformed.
    Command,
    /// A typed target, count, or reason was out of its domain.
    Argument,
    /// An Ed25519 proof failed strict verification.
    Signature,
    /// The operator identity, credentials, and key did not select one record.
    Operator,
    /// A confirmation token was missing, stale, or bound to something else.
    Confirmation,
    /// An audit record was malformed, out of sequence, or broke the chain.
    Audit,
    /// A checked calculation overflowed.
    Overflow,
    /// A collection exceeded its closed ceiling.
    Limit,
}

impl fmt::Display for AdminError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Framing => "administrative line exceeds its framing bound",
            Self::Tag => "administrative tag section is invalid",
            Self::Counter => "administrative command counter is invalid",
            Self::Token => "administrative token encoding is invalid",
            Self::Canonical => "administrative command is not canonical",
            Self::Command => "administrative command is not registered",
            Self::Argument => "administrative command argument is invalid",
            Self::Signature => "administrative signature verification failed",
            Self::Operator => "administrative operator selection failed",
            Self::Confirmation => "administrative confirmation binding failed",
            Self::Audit => "administrative audit record is invalid",
            Self::Overflow => "administrative arithmetic overflowed",
            Self::Limit => "administrative collection exceeds its limit",
        };
        formatter.write_str(message)
    }
}

impl Error for AdminError {}

/// Why an administrative session was closed by this boundary.
///
/// Section 22.4 requires every malformed, mismatched, replayed, or failed
/// proof to close the connection with a safe local alert; the reason is a
/// closed identifier the runtime can log without any operator input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminCloseReason {
    /// The client sent QUIT.
    Quit,
    /// A line broke the framing, tag, canonical-form, or command rules.
    MalformedLine,
    /// The pre-authentication PING budget was exhausted.
    PingBudget,
    /// The operator proof failed, or a second OPER arrived.
    ProofFailed,
    /// The operator id, key, and peer credentials did not select one record.
    OperatorMismatch,
    /// The command counter was not the expected contiguous value.
    BadCounter,
    /// The command signature failed strict verification.
    BadSignature,
    /// A confirmation tag did not bind to the pending confirmation.
    ConfirmationBinding,
    /// The runtime terminated the session (shutdown, reload, or disconnect).
    Terminated,
}

impl AdminCloseReason {
    /// Returns the closed identifier used in local alerts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Quit => "quit",
            Self::MalformedLine => "malformed-line",
            Self::PingBudget => "ping-budget",
            Self::ProofFailed => "proof-failed",
            Self::OperatorMismatch => "operator-mismatch",
            Self::BadCounter => "bad-counter",
            Self::BadSignature => "bad-signature",
            Self::ConfirmationBinding => "confirmation-binding",
            Self::Terminated => "terminated",
        }
    }
}

impl fmt::Display for AdminCloseReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::{AdminCloseReason, AdminError};

    #[test]
    fn every_error_and_reason_renders_a_fixed_string() {
        let errors = [
            AdminError::Framing,
            AdminError::Tag,
            AdminError::Counter,
            AdminError::Token,
            AdminError::Canonical,
            AdminError::Command,
            AdminError::Argument,
            AdminError::Signature,
            AdminError::Operator,
            AdminError::Confirmation,
            AdminError::Audit,
            AdminError::Overflow,
            AdminError::Limit,
        ];
        for error in errors {
            assert!(error.to_string().starts_with("administrative "));
        }
        let reasons = [
            AdminCloseReason::Quit,
            AdminCloseReason::MalformedLine,
            AdminCloseReason::PingBudget,
            AdminCloseReason::ProofFailed,
            AdminCloseReason::OperatorMismatch,
            AdminCloseReason::BadCounter,
            AdminCloseReason::BadSignature,
            AdminCloseReason::ConfirmationBinding,
            AdminCloseReason::Terminated,
        ];
        for reason in reasons {
            assert_eq!(reason.to_string(), reason.as_str());
            assert!(!reason.as_str().contains(' '));
        }
    }
}
