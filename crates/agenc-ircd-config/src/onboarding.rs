//! The canonical onboarding descriptor (spec C.8 9294-9321).

use agenc_ircd_types::RecoveryEpoch;

use crate::config::Config;
use crate::error::ConfigError;
use crate::scalar::encode_base64url_32;

/// Base federation profile hash token (spec 9305).
pub const BASE_PROFILE_SHA256_TOKEN: &str = "g3AiB-HhFTyHItXMZop9G6uFulGPzd4DCjaBG0G9zEA";
/// E2EE profile name token (spec 9308).
pub const E2EE_PROFILE_TOKEN: &str = "IRC-MLS/1";
/// E2EE profile hash token (spec 9309).
pub const E2EE_PROFILE_SHA256_TOKEN: &str = "lk0p96oG1QiE3t2W0fUBHPAVUls5iUpFNX-6k9Xou3M";

/// Public facts the composition layer supplies from storage and key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnboardingFacts {
    /// Current recovery epoch from the database header.
    pub recovery_epoch: RecoveryEpoch,
    /// Derived account-service HPKE key identifier.
    pub account_service_hpke_key_id: [u8; 32],
    /// Sequencer key-set generation.
    pub sequencer_key_set_generation: u64,
    /// Sequencer key-set hash.
    pub sequencer_key_set_hash: [u8; 32],
}

/// Renders the LF-terminated descriptor with lines in the fixed order, omitting
/// the DNS line and the onion pair as units; at least one endpoint must remain.
pub fn render_onboarding(config: &Config, facts: &OnboardingFacts) -> Result<String, ConfigError> {
    let network = &config.network;
    if network.dns.is_none() && network.onion.is_none() {
        return Err(ConfigError::MissingValue);
    }
    let mut lines: Vec<String> = Vec::new();
    lines.push("AGENC-CHAT-CONNECT/1".to_owned());
    lines.push(format!("network-id={}", network.network_id.to_base64url()));
    lines.push(format!("server-name={}", config.server.name.as_str()));
    if let Some(dns) = &network.dns {
        lines.push(format!("dns-endpoint={}:{}", dns.name.as_str(), dns.port));
    }
    if let Some(onion) = &network.onion {
        lines.push(format!(
            "onion-endpoint={}:{}",
            onion.address.as_str(),
            onion.port
        ));
        lines.push(format!(
            "onion-tls-spki-sha256={}",
            encode_base64url_32(&onion.tls_spki_sha256)
        ));
    }
    lines.push(format!(
        "recovery-epoch={}",
        facts.recovery_epoch.to_base64url()
    ));
    lines.push(format!("base-profile-sha256={BASE_PROFILE_SHA256_TOKEN}"));
    lines.push(format!(
        "account-service-hpke-key-id={}",
        encode_base64url_32(&facts.account_service_hpke_key_id)
    ));
    lines.push(format!(
        "account-service-hpke-public-key={}",
        encode_base64url_32(&config.accounts.account_service_hpke_public_key)
    ));
    lines.push(format!("e2ee-profile={E2EE_PROFILE_TOKEN}"));
    lines.push(format!("e2ee-profile-sha256={E2EE_PROFILE_SHA256_TOKEN}"));
    lines.push(format!(
        "sequencer-key-set-generation={}",
        facts.sequencer_key_set_generation
    ));
    lines.push(format!(
        "sequencer-key-set-hash={}",
        encode_base64url_32(&facts.sequencer_key_set_hash)
    ));
    let mut descriptor = lines.join("\n");
    descriptor.push('\n');
    if !descriptor
        .bytes()
        .all(|byte| byte == b'\n' || (byte.is_ascii_graphic()))
    {
        return Err(ConfigError::InvalidValue);
    }
    Ok(descriptor)
}
