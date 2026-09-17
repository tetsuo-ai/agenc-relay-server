//! The canonical onboarding descriptor (spec C.8 9294-9321).

use agenc_ircd_types::{NetworkId, RecoveryEpoch};

use crate::config::Config;
use crate::error::ConfigError;
use crate::network::{DnsEndpoint, OnionEndpoint};
use crate::scalar::{DnsName, OnionAddress, base64url_32, encode_base64url_32, port};

/// Maximum accepted bytes in one canonical onboarding descriptor.
pub const MAX_ONBOARDING_DESCRIPTOR_BYTES: usize = 4_096;

/// Base federation profile hash token (spec 9305). The runtime crate binds this
/// literal to the compiled registry hash, so a profile revision that forgets
/// the descriptor fails a test instead of shipping a stale token.
pub const BASE_PROFILE_SHA256_TOKEN: &str = "ewDg0IRCcGJkEdOY8V91ICJOqQYRdzjj2pdBphHcZ7M";
/// E2EE profile name token (spec 9308).
pub const E2EE_PROFILE_TOKEN: &str = "IRC-MLS/1";
/// E2EE profile hash token (spec 9309).
pub const E2EE_PROFILE_SHA256_TOKEN: &str = "N3G6svCQJGRNBGjQBK8w-6PQBAPk3G8CBa6iCnUmXkU";

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

/// The advertised sequencer key set an onboarding descriptor pins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SequencerKeySetFacts {
    /// Published sequencer key-set generation.
    pub generation: u64,
    /// Published sequencer key-set hash.
    pub hash: [u8; 32],
}

struct DescriptorProfile {
    account_service_hpke_key_id: [u8; 32],
    account_service_hpke_public_key: [u8; 32],
    sequencer_key_set: Option<SequencerKeySetFacts>,
}

/// Parses the exact LF-terminated descriptor grammar and fixed profile pins.
pub fn parse_onboarding_descriptor(text: &str) -> Result<OnboardingDescriptor, ConfigError> {
    let body = descriptor_body(text)?;
    let mut lines = body.split('\n').peekable();
    if lines.next() != Some("AGENC-CHAT-CONNECT/1") {
        return Err(ConfigError::InvalidDocument);
    }
    let network_id = NetworkId::parse(required_value(&mut lines, "network-id=")?)
        .map_err(|_| ConfigError::InvalidValue)?;
    let server_name = DnsName::parse(required_value(&mut lines, "server-name=")?)?;
    let dns = optional_dns_endpoint(&mut lines)?;
    let onion = optional_onion_endpoint(&mut lines)?;
    if dns.is_none() && onion.is_none() {
        return Err(ConfigError::MissingValue);
    }
    let recovery_epoch = RecoveryEpoch::parse(required_value(&mut lines, "recovery-epoch=")?)
        .map_err(|_| ConfigError::InvalidValue)?;
    let profile = parse_profile(&mut lines)?;
    if lines.next().is_some() {
        return Err(ConfigError::InvalidDocument);
    }
    Ok(OnboardingDescriptor {
        network_id,
        server_name,
        dns,
        onion,
        recovery_epoch,
        account_service_hpke_key_id: profile.account_service_hpke_key_id,
        account_service_hpke_public_key: profile.account_service_hpke_public_key,
        sequencer_key_set: profile.sequencer_key_set,
    })
}

fn descriptor_body(text: &str) -> Result<&str, ConfigError> {
    if text.is_empty()
        || text.len() > MAX_ONBOARDING_DESCRIPTOR_BYTES
        || !text.ends_with('\n')
        || !text
            .bytes()
            .all(|byte| byte == b'\n' || byte.is_ascii_graphic())
    {
        return Err(ConfigError::InvalidDocument);
    }
    text.strip_suffix('\n').ok_or(ConfigError::InvalidDocument)
}

fn parse_profile<'a>(
    lines: &mut std::iter::Peekable<impl Iterator<Item = &'a str>>,
) -> Result<DescriptorProfile, ConfigError> {
    if required_value(lines, "base-profile-sha256=")? != BASE_PROFILE_SHA256_TOKEN {
        return Err(ConfigError::InvalidValue);
    }
    let account_service_hpke_key_id =
        base64url_32(required_value(lines, "account-service-hpke-key-id=")?)?;
    let account_service_hpke_public_key =
        base64url_32(required_value(lines, "account-service-hpke-public-key=")?)?;
    // The four E2EE lines are present or absent as one unit; a present
    // block must still carry the build's exact profile.
    let sequencer_key_set = if lines
        .peek()
        .is_some_and(|line| line.starts_with("e2ee-profile="))
    {
        if required_value(lines, "e2ee-profile=")? != E2EE_PROFILE_TOKEN
            || required_value(lines, "e2ee-profile-sha256=")? != E2EE_PROFILE_SHA256_TOKEN
        {
            return Err(ConfigError::InvalidValue);
        }
        Some(SequencerKeySetFacts {
            generation: canonical_u64(required_value(lines, "sequencer-key-set-generation=")?)?,
            hash: base64url_32(required_value(lines, "sequencer-key-set-hash=")?)?,
        })
    } else {
        None
    };
    Ok(DescriptorProfile {
        account_service_hpke_key_id,
        account_service_hpke_public_key,
        sequencer_key_set,
    })
}

fn required_value<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    prefix: &str,
) -> Result<&'a str, ConfigError> {
    let line = lines.next().ok_or(ConfigError::MissingValue)?;
    let value = line
        .strip_prefix(prefix)
        .ok_or(ConfigError::InvalidDocument)?;
    if value.is_empty() {
        return Err(ConfigError::InvalidValue);
    }
    Ok(value)
}

fn optional_dns_endpoint<'a>(
    lines: &mut std::iter::Peekable<impl Iterator<Item = &'a str>>,
) -> Result<Option<DnsEndpoint>, ConfigError> {
    let Some(value) = lines
        .peek()
        .and_then(|line| line.strip_prefix("dns-endpoint="))
    else {
        return Ok(None);
    };
    let endpoint = parse_dns_endpoint(value)?;
    let _consumed = lines.next();
    Ok(Some(endpoint))
}

fn optional_onion_endpoint<'a>(
    lines: &mut std::iter::Peekable<impl Iterator<Item = &'a str>>,
) -> Result<Option<OnionEndpoint>, ConfigError> {
    let Some(value) = lines
        .peek()
        .and_then(|line| line.strip_prefix("onion-endpoint="))
    else {
        return Ok(None);
    };
    let (address, onion_port) = parse_endpoint(value)?;
    let address = OnionAddress::parse(address)?;
    let _consumed = lines.next();
    let tls_spki_sha256 = base64url_32(required_value(lines, "onion-tls-spki-sha256=")?)?;
    Ok(Some(OnionEndpoint {
        address,
        port: onion_port,
        tls_spki_sha256,
    }))
}

fn parse_dns_endpoint(text: &str) -> Result<DnsEndpoint, ConfigError> {
    let (name, dns_port) = parse_endpoint(text)?;
    Ok(DnsEndpoint {
        name: DnsName::parse(name)?,
        port: dns_port,
    })
}

fn parse_endpoint(text: &str) -> Result<(&str, u16), ConfigError> {
    let (name, port_text) = text.rsplit_once(':').ok_or(ConfigError::InvalidValue)?;
    if name.is_empty() {
        return Err(ConfigError::InvalidValue);
    }
    Ok((name, port(canonical_u64(port_text)?)?))
}

fn canonical_u64(text: &str) -> Result<u64, ConfigError> {
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ConfigError::InvalidValue);
    }
    text.parse().map_err(|_| ConfigError::InvalidValue)
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
