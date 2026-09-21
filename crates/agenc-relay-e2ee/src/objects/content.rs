//! The encrypted application content (companion Section 10) and its
//! Section 7.5 bucket padding.
//!
//! No daemon code path receives or decodes this structure: it exists only
//! inside MLS application data. It is declared here so clients, the test
//! kit, and the padding vectors share one encoder, and so the padding rule
//! is checked against the exact bytes a receiver decodes.

use crate::envelope::{check_padding, padding_bytes};
use crate::error::E2eeError;
use crate::limits::PROFILE_VERSION;
use crate::tls::{DecodeBudget, Opaque, TlsDecode, TlsEncode, tls_enum, tls_struct};

/// The largest `body` (Section 10).
pub const MAX_CONTENT_BODY_BYTES: usize = 32_768;

tls_enum! {
    /// `ArcEncryptedContentType` (10).
    pub enum ArcEncryptedContentType: u8 {
        /// Text.
        Text = 1,
        /// Notice.
        Notice = 2,
        /// Action.
        Action = 3,
        /// Explanatory policy notice without authority.
        PolicyNotice = 4,
        /// Member-attributed security event without authority.
        SecurityEvent = 5,
    }
}

tls_struct! {
    /// `ArcEncryptedContent` (10): the application plaintext structure
    /// carried in MLS `application_data`, ending in its bucket padding.
    pub struct ArcEncryptedContent {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Conversation identifier.
        pub conversation_id: [u8; 32],
        /// Route binding.
        pub route_binding: [u8; 32],
        /// Sender device identity.
        pub sender_device_id: [u8; 16],
        /// Leaf credential generation, zero in version 1.
        pub leaf_credential_generation: u64,
        /// Per-leaf application counter.
        pub sender_sequence: u64,
        /// Fresh random message identifier.
        pub message_id: [u8; 16],
        /// The newest sequencer record head the sender observed.
        pub sequencer_record_chain_head: [u8; 32],
        /// Content type.
        pub content_type: ArcEncryptedContentType,
        /// Body, UTF-8 without NUL for every version-1 type.
        pub body: Opaque<0, 32_768>,
        /// Section 7.5 zero padding.
        pub zero_padding: Opaque<0, 65_535>,
    }
}

impl ArcEncryptedContent {
    /// The encoded length with an empty padding vector: the `L` of
    /// Section 7.5.
    pub fn unpadded_length(&self) -> Result<usize, E2eeError> {
        let total = self.encode()?.len();
        total
            .checked_sub(self.zero_padding.as_slice().len())
            .ok_or(E2eeError::Overflow)
    }

    /// Fills `zero_padding` so the complete encoding is exactly the
    /// Section 7.5 bucket target; checked arithmetic precedes allocation.
    pub fn pad(&mut self) -> Result<(), E2eeError> {
        self.zero_padding = Opaque::new(Vec::new())?;
        let padding = padding_bytes(self.encode()?.len())?;
        let mut zeros = Vec::new();
        zeros
            .try_reserve_exact(padding)
            .map_err(|_| E2eeError::BudgetExceeded)?;
        zeros.resize(padding, 0);
        self.zero_padding = Opaque::new(zeros)?;
        Ok(())
    }

    /// Rejects a padding length other than the bucket rule requires or any
    /// nonzero padding octet.
    pub fn check_padding(&self) -> Result<(), E2eeError> {
        check_padding(self.unpadded_length()?, self.zero_padding.as_slice())
    }

    /// Checks the fields a receiver validates before interpreting the body:
    /// profile, version-1 generation, UTF-8 without NUL, and padding.
    pub fn check_shape(&self) -> Result<(), E2eeError> {
        if self.profile_version != PROFILE_VERSION || self.leaf_credential_generation != 0 {
            return Err(E2eeError::ProfileMismatch);
        }
        let body = self.body.as_slice();
        if std::str::from_utf8(body).is_err() || body.contains(&0) {
            return Err(E2eeError::InvalidValue);
        }
        self.check_padding()
    }

    /// Decodes exactly one content and runs [`Self::check_shape`].
    pub fn decode_checked(bytes: &[u8], budget: &mut DecodeBudget) -> Result<Self, E2eeError> {
        let content = Self::decode_exact(bytes, budget)?;
        content.check_shape()?;
        Ok(content)
    }
}

#[cfg(test)]
#[path = "../tests/content.rs"]
mod tests;
