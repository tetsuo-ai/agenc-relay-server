//! The exact negotiated profile: `(version, profile-hash)` on the client
//! capability (Section 11.1) and the ECAP tuple (Section 12.5).

use agenc_ircd_federation_wire::E2EE_PROFILE_TOKEN;

use crate::error::E2eeError;
use crate::limits::{
    CAPABILITY_VALUE, MAX_CLIENT_TAG_DATA, MAX_COMBINED_TAG_SECTION, MAX_FRAGMENT_RAW,
    MAX_LIVE_OBJECT, MAX_SERVER_TAG_DATA, MAX_WELCOME_MAILBOX_OBJECT, PROFILE_VERSION,
};

/// Fails unless `value` is byte-for-byte the compiled Section 11.1
/// capability value.
pub fn check_capability_value(value: &str) -> Result<(), E2eeError> {
    if value == CAPABILITY_VALUE {
        Ok(())
    } else {
        Err(E2eeError::ProfileMismatch)
    }
}

/// The twelve-parameter ECAP tuple after the `IRCMLS OFFER` or `ACK`
/// subcommand (fourteen parameters after `ECAP` including those two).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcapTuple {
    /// `1`.
    pub version: u64,
    /// The 43-character profile token.
    pub profile_hash: String,
    /// The 43-character network token.
    pub network_id: String,
    /// The 22-character coordinator token.
    pub coordinator_server_id: String,
    /// The six fixed limits in order.
    pub limits: [u64; 6],
    /// The key-set generation.
    pub key_set_generation: u64,
    /// The 43-character key-set hash token.
    pub key_set_hash: String,
}

impl EcapTuple {
    /// The six fixed decimal limits every OFFER and ACK must carry.
    pub const FIXED_LIMITS: [u64; 6] = [
        MAX_FRAGMENT_RAW as u64,
        MAX_LIVE_OBJECT as u64,
        MAX_WELCOME_MAILBOX_OBJECT as u64,
        MAX_CLIENT_TAG_DATA as u64,
        MAX_SERVER_TAG_DATA as u64,
        MAX_COMBINED_TAG_SECTION as u64,
    ];

    /// Builds the local tuple from the compiled profile and the accepted
    /// network sequencer key set.
    pub fn local(
        network_id: &str,
        coordinator_server_id: &str,
        key_set_generation: u64,
        key_set_hash: &str,
    ) -> Result<Self, E2eeError> {
        let tuple = Self {
            version: u64::from(PROFILE_VERSION),
            profile_hash: E2EE_PROFILE_TOKEN.to_owned(),
            network_id: network_id.to_owned(),
            coordinator_server_id: coordinator_server_id.to_owned(),
            limits: Self::FIXED_LIMITS,
            key_set_generation,
            key_set_hash: key_set_hash.to_owned(),
        };
        tuple.check_shape()?;
        Ok(tuple)
    }

    /// Parses the twelve parameters after the subcommand.
    pub fn parse(parameters: &[&str]) -> Result<Self, E2eeError> {
        let [
            version,
            profile,
            network,
            coordinator,
            limits @ ..,
            generation,
            hash,
        ] = parameters
        else {
            return Err(E2eeError::InvalidValue);
        };
        if limits.len() != 6 {
            return Err(E2eeError::InvalidValue);
        }
        let mut fixed = [0_u64; 6];
        for (slot, text) in fixed.iter_mut().zip(limits) {
            *slot = canonical_decimal(text)?;
        }
        let tuple = Self {
            version: canonical_decimal(version)?,
            profile_hash: (*profile).to_owned(),
            network_id: (*network).to_owned(),
            coordinator_server_id: (*coordinator).to_owned(),
            limits: fixed,
            key_set_generation: canonical_decimal(generation)?,
            key_set_hash: (*hash).to_owned(),
        };
        tuple.check_shape()?;
        Ok(tuple)
    }

    /// Renders the twelve parameters in wire order.
    #[must_use]
    pub fn render(&self) -> Vec<String> {
        let mut parameters = vec![
            self.version.to_string(),
            self.profile_hash.clone(),
            self.network_id.clone(),
            self.coordinator_server_id.clone(),
        ];
        parameters.extend(self.limits.iter().map(u64::to_string));
        parameters.push(self.key_set_generation.to_string());
        parameters.push(self.key_set_hash.clone());
        parameters
    }

    fn check_shape(&self) -> Result<(), E2eeError> {
        if self.version != u64::from(PROFILE_VERSION)
            || self.profile_hash != E2EE_PROFILE_TOKEN
            || self.limits != Self::FIXED_LIMITS
            || !is_hash_token(&self.network_id)
            || !is_id16_token(&self.coordinator_server_id)
            || !is_hash_token(&self.key_set_hash)
        {
            return Err(E2eeError::ProfileMismatch);
        }
        Ok(())
    }
}

/// Parses a canonical unsigned decimal: no sign, no leading zero except `0`.
pub fn canonical_decimal(text: &str) -> Result<u64, E2eeError> {
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(E2eeError::InvalidValue);
    }
    if text.len() > 1 && text.starts_with('0') {
        return Err(E2eeError::InvalidValue);
    }
    text.parse().map_err(|_| E2eeError::InvalidValue)
}

fn is_base64url(text: &str) -> bool {
    text.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// Whether `text` has the shape of a 43-character `hash-token`.
#[must_use]
pub fn is_hash_token(text: &str) -> bool {
    text.len() == 43 && is_base64url(text)
}

/// Whether `text` has the shape of a 22-character `id16-token`.
#[must_use]
pub fn is_id16_token(text: &str) -> bool {
    text.len() == 22 && is_base64url(text)
}

#[cfg(test)]
#[path = "tests/profile.rs"]
mod tests;
