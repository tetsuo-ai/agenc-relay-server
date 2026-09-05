//! Test-client trust presentation and inert rendering for companion Sections 5.1 and 14.

use std::fmt::{self, Write as _};

/// Maximum accepted decrypted text, before display escaping.
pub const MAX_DISPLAY_TEXT_BYTES: usize = 16_384;

/// Separate assurance states shown by the test client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustState {
    /// A first-contact identity has no out-of-band authentication.
    UnverifiedEncrypted,
    /// Every required account, network, and root binding was authenticated out of band.
    VerifiedEncrypted,
    /// Experimental proofs were observed without granting out-of-band verification.
    TransparencyObserved,
    /// An unexpected security change blocks sending until explicit review.
    SecurityChanged,
}

impl TrustState {
    /// Returns the companion's distinct user-visible label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::UnverifiedEncrypted => "Unverified encrypted",
            Self::VerifiedEncrypted => "Verified encrypted",
            Self::TransparencyObserved => "Transparency observed",
            Self::SecurityChanged => "Security changed",
        }
    }

    /// Returns whether policy allows sending in the current state.
    #[must_use]
    pub const fn permits_sending(self) -> bool {
        !matches!(self, Self::SecurityChanged)
    }
}

/// Display policy for one currently accepted set of security bindings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientTrust {
    state: TrustState,
    authenticated_out_of_band: bool,
}

impl ClientTrust {
    /// Starts with first-contact uncertainty.
    #[must_use]
    pub const fn first_contact() -> Self {
        Self {
            state: TrustState::UnverifiedEncrypted,
            authenticated_out_of_band: false,
        }
    }

    /// Reads the assurance state without changing authority.
    #[must_use]
    pub const fn state(self) -> TrustState {
        self.state
    }

    /// Records accepted experimental proofs. Proofs cannot clear an unexpected
    /// change or replace the out-of-band verification requirement.
    pub fn observe_transparency(&mut self) {
        if self.state == TrustState::UnverifiedEncrypted {
            self.state = TrustState::TransparencyObserved;
        }
    }

    /// Records successful authentication of every required binding. An existing
    /// security-change alarm still requires explicit review of the new context.
    pub fn authenticate_out_of_band(&mut self) {
        self.authenticated_out_of_band = true;
        if self.state != TrustState::SecurityChanged {
            self.state = TrustState::VerifiedEncrypted;
        }
    }

    /// Blocks sending when a root, device, binding, capability, suite, policy,
    /// or Commit chain changes unexpectedly. Previous verification is revoked.
    pub fn unexpected_security_change(&mut self) {
        self.state = TrustState::SecurityChanged;
        self.authenticated_out_of_band = false;
    }

    /// Finishes explicit review after the caller has authenticated the changed
    /// account, network, and root bindings. A server message cannot call this.
    pub fn accept_reviewed_change(&mut self) -> Result<(), DisplayError> {
        if self.state != TrustState::SecurityChanged || !self.authenticated_out_of_band {
            return Err(DisplayError::ReviewRequired);
        }
        self.state = TrustState::VerifiedEncrypted;
        Ok(())
    }
}

/// Rendering or trust-policy refusal in the test-only client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisplayError {
    /// The body is malformed UTF-8, includes NUL, or exceeds the text limit.
    InvalidText,
    /// The bounded display allocation failed.
    Allocation,
    /// An unexpected security change has not been authenticated and reviewed.
    ReviewRequired,
}

impl fmt::Display for DisplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidText => "invalid decrypted display text",
            Self::Allocation => "display allocation failed",
            Self::ReviewRequired => "security change requires review",
        })
    }
}

impl std::error::Error for DisplayError {}

/// Inert display output. It is never passed to an IRC or local command parser.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayText(String);

impl DisplayText {
    /// Borrows the already escaped display text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Renders decrypted text with visible controls and HTML metacharacters escaped.
/// CTCP markers, terminal escapes, bidi controls, and leading command prefixes
/// remain text and never gain protocol authority.
pub fn render_decrypted_text(bytes: &[u8]) -> Result<DisplayText, DisplayError> {
    if bytes.len() > MAX_DISPLAY_TEXT_BYTES || bytes.contains(&0) {
        return Err(DisplayError::InvalidText);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| DisplayError::InvalidText)?;
    let mut output = String::new();
    output
        .try_reserve_exact(bytes.len().saturating_mul(10))
        .map_err(|_| DisplayError::Allocation)?;
    for character in text.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            value
                if value.is_control()
                    || matches!(value, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') =>
            {
                write!(output, "\\u{{{:04x}}}", u32::from(value))
                    .map_err(|_| DisplayError::Allocation)?;
            }
            value => output.push(value),
        }
    }
    Ok(DisplayText(output))
}
