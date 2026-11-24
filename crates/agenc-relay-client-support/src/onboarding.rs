//! The canonical onboarding descriptor from Architecture Appendix C.8.

use agenc_relay_types::{NetworkId, RecoveryEpoch};

use crate::ClientSupportError;
use crate::endpoint::{DnsEndpoint, DnsName, OnionAddress, OnionEndpoint, base64url_32, port};

pub use agenc_relay_federation_wire::{
    BASE_FEDERATION_PROFILE_TOKEN as BASE_PROFILE_SHA256_TOKEN,
    E2EE_PROFILE_TOKEN as E2EE_PROFILE_SHA256_TOKEN,
};

/// Maximum accepted bytes in one canonical onboarding descriptor.
pub const MAX_ONBOARDING_DESCRIPTOR_BYTES: usize = 4_096;
/// E2EE profile name token.
pub const E2EE_PROFILE_TOKEN: &str = "ARC-MLS/1";

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
pub fn parse_onboarding_descriptor(text: &str) -> Result<OnboardingDescriptor, ClientSupportError> {
    let body = descriptor_body(text)?;
    let mut lines = body.split('\n').peekable();
    if lines.next() != Some("AGENC-CHAT-CONNECT/1") {
        return Err(ClientSupportError::InvalidDocument);
    }
    let network_id = NetworkId::parse(required_value(&mut lines, "network-id=")?)
        .map_err(|_| ClientSupportError::InvalidValue)?;
    let server_name = DnsName::parse(required_value(&mut lines, "server-name=")?)?;
    let dns = optional_dns_endpoint(&mut lines)?;
    let onion = optional_onion_endpoint(&mut lines)?;
    if dns.is_none() && onion.is_none() {
        return Err(ClientSupportError::MissingValue);
    }
    let recovery_epoch = RecoveryEpoch::parse(required_value(&mut lines, "recovery-epoch=")?)
        .map_err(|_| ClientSupportError::InvalidValue)?;
    let profile = parse_profile(&mut lines)?;
    if lines.next().is_some() {
        return Err(ClientSupportError::InvalidDocument);
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

fn descriptor_body(text: &str) -> Result<&str, ClientSupportError> {
    if text.is_empty()
        || text.len() > MAX_ONBOARDING_DESCRIPTOR_BYTES
        || !text.ends_with('\n')
        || !text
            .bytes()
            .all(|byte| byte == b'\n' || byte.is_ascii_graphic())
    {
        return Err(ClientSupportError::InvalidDocument);
    }
    text.strip_suffix('\n')
        .ok_or(ClientSupportError::InvalidDocument)
}

fn parse_profile<'a>(
    lines: &mut std::iter::Peekable<impl Iterator<Item = &'a str>>,
) -> Result<DescriptorProfile, ClientSupportError> {
    if required_value(lines, "base-profile-sha256=")? != BASE_PROFILE_SHA256_TOKEN {
        return Err(ClientSupportError::InvalidValue);
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
            return Err(ClientSupportError::InvalidValue);
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
) -> Result<&'a str, ClientSupportError> {
    let line = lines.next().ok_or(ClientSupportError::MissingValue)?;
    let value = line
        .strip_prefix(prefix)
        .ok_or(ClientSupportError::InvalidDocument)?;
    if value.is_empty() {
        return Err(ClientSupportError::InvalidValue);
    }
    Ok(value)
}

fn optional_dns_endpoint<'a>(
    lines: &mut std::iter::Peekable<impl Iterator<Item = &'a str>>,
) -> Result<Option<DnsEndpoint>, ClientSupportError> {
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
) -> Result<Option<OnionEndpoint>, ClientSupportError> {
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

fn parse_dns_endpoint(text: &str) -> Result<DnsEndpoint, ClientSupportError> {
    let (name, dns_port) = parse_endpoint(text)?;
    Ok(DnsEndpoint {
        name: DnsName::parse(name)?,
        port: dns_port,
    })
}

fn parse_endpoint(text: &str) -> Result<(&str, u16), ClientSupportError> {
    let (name, port_text) = text
        .rsplit_once(':')
        .ok_or(ClientSupportError::InvalidValue)?;
    if name.is_empty() {
        return Err(ClientSupportError::InvalidValue);
    }
    Ok((name, port(canonical_u64(port_text)?)?))
}

fn canonical_u64(text: &str) -> Result<u64, ClientSupportError> {
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ClientSupportError::InvalidValue);
    }
    text.parse().map_err(|_| ClientSupportError::InvalidValue)
}

#[cfg(test)]
mod grammar_tests {
    use super::*;

    #[test]
    fn a_canonical_number_is_non_empty_unpadded_and_all_digits() {
        for text in ["", "007", "12a", "0x10"] {
            assert_eq!(
                canonical_u64(text).err(),
                Some(ClientSupportError::InvalidValue),
                "{text:?}"
            );
        }
        assert_eq!(canonical_u64("0").ok(), Some(0));
        assert_eq!(canonical_u64("6697").ok(), Some(6_697));
    }

    #[test]
    fn an_endpoint_needs_a_name_before_its_port() {
        assert_eq!(
            parse_endpoint(":6697").err(),
            Some(ClientSupportError::InvalidValue)
        );
        assert_eq!(
            parse_endpoint("hub.example").err(),
            Some(ClientSupportError::InvalidValue)
        );
        assert_eq!(
            parse_endpoint("hub.example:6697").ok(),
            Some(("hub.example", 6_697))
        );
    }

    #[test]
    fn a_required_value_must_follow_its_prefix_and_be_non_empty() {
        let mut lines = ["network-id=", "network-id=abc"].into_iter();
        assert_eq!(
            required_value(&mut lines, "network-id=").err(),
            Some(ClientSupportError::InvalidValue)
        );
        assert_eq!(required_value(&mut lines, "network-id=").ok(), Some("abc"));
        assert_eq!(
            required_value(&mut lines, "network-id=").err(),
            Some(ClientSupportError::MissingValue)
        );
        let mut other = ["server-id=abc"].into_iter();
        assert_eq!(
            required_value(&mut other, "network-id=").err(),
            Some(ClientSupportError::InvalidDocument)
        );
    }

    #[test]
    fn a_descriptor_body_is_non_empty_graphic_text_ending_in_a_newline() {
        for text in ["", "no newline", "tab\there\n", "bad byte \u{e9}\n"] {
            assert_eq!(
                descriptor_body(text).err(),
                Some(ClientSupportError::InvalidDocument),
                "{text:?}"
            );
        }
        let long = format!("{}\n", "x".repeat(MAX_ONBOARDING_DESCRIPTOR_BYTES));
        assert_eq!(
            descriptor_body(&long).err(),
            Some(ClientSupportError::InvalidDocument)
        );
    }
}
