//! Configuration adapters for the canonical onboarding descriptor.

use agenc_relay_client_support::onboarding as client;
use agenc_relay_types::{NetworkId, RecoveryEpoch};

use crate::config::Config;
use crate::error::ConfigError;
use crate::network::{DnsEndpoint, OnionEndpoint};
use crate::scalar::{DnsName, OnionAddress, encode_base64url_32};

pub use client::{
    BASE_PROFILE_SHA256_TOKEN, E2EE_PROFILE_SHA256_TOKEN, E2EE_PROFILE_TOKEN,
    MAX_ONBOARDING_DESCRIPTOR_BYTES, SequencerKeySetFacts,
};

/// One fully parsed canonical onboarding descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnboardingDescriptor {
    /// Permanent network identity imported by an edge.
    pub network_id: NetworkId,
    /// Coordinator server name displayed before enrollment.
    pub server_name: DnsName,
    /// Optional public DNS endpoint.
    pub dns: Option<DnsEndpoint>,
    /// Optional onion endpoint and exact TLS SPKI pin.
    pub onion: Option<OnionEndpoint>,
    /// Coordinator recovery lineage pin.
    pub recovery_epoch: RecoveryEpoch,
    /// Derived account-service HPKE public-key identifier.
    pub account_service_hpke_key_id: [u8; 32],
    /// Pinned account-service HPKE public key.
    pub account_service_hpke_public_key: [u8; 32],
    /// The published sequencer key set, absent when the coordinator offers
    /// no E2EE (spec C.8): an importer then never enables E2EE.
    pub sequencer_key_set: Option<SequencerKeySetFacts>,
}

/// Parses the exact LF-terminated descriptor grammar and fixed profile pins.
pub fn parse_onboarding_descriptor(text: &str) -> Result<OnboardingDescriptor, ConfigError> {
    let descriptor = client::parse_onboarding_descriptor(text)?;
    Ok(OnboardingDescriptor {
        network_id: descriptor.network_id,
        server_name: DnsName(descriptor.server_name),
        dns: descriptor.dns.map(|endpoint| DnsEndpoint {
            name: DnsName(endpoint.name),
            port: endpoint.port,
        }),
        onion: descriptor.onion.map(|endpoint| OnionEndpoint {
            address: OnionAddress(endpoint.address),
            port: endpoint.port,
            tls_spki_sha256: endpoint.tls_spki_sha256,
        }),
        recovery_epoch: descriptor.recovery_epoch,
        account_service_hpke_key_id: descriptor.account_service_hpke_key_id,
        account_service_hpke_public_key: descriptor.account_service_hpke_public_key,
        sequencer_key_set: descriptor.sequencer_key_set,
    })
}

/// Public facts the composition layer supplies from storage and key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnboardingFacts {
    /// Current recovery epoch from the database header.
    pub recovery_epoch: RecoveryEpoch,
    /// Derived account-service HPKE key identifier.
    pub account_service_hpke_key_id: [u8; 32],
    /// The verified sequencer key set, or `None` when `e2ee.enabled` is
    /// false: the four E2EE lines are then omitted as one unit (spec C.8).
    pub sequencer_key_set: Option<SequencerKeySetFacts>,
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
    if let Some(key_set) = &facts.sequencer_key_set {
        lines.push(format!("e2ee-profile={E2EE_PROFILE_TOKEN}"));
        lines.push(format!("e2ee-profile-sha256={E2EE_PROFILE_SHA256_TOKEN}"));
        lines.push(format!(
            "sequencer-key-set-generation={}",
            key_set.generation
        ));
        lines.push(format!(
            "sequencer-key-set-hash={}",
            encode_base64url_32(&key_set.hash)
        ));
    }
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
