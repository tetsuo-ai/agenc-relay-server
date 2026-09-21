//! The `[network]` table (spec C.2 8891-8899).

use agenc_relay_types::{NetworkId, ServerId};
use toml::Table;

use crate::bounds::{DISPLAY_NAME_BYTES, ENDPOINT_PORT};
use crate::document::{check_keys, optional_string, optional_unsigned, string};
use crate::error::{ConfigError, IssueSink, SchemaKey};
use crate::scalar::{
    DnsName, OnionAddress, ascii_identifier, base64url_32, closed_enum, dns_name, port,
};

pub(crate) const NETWORK_KEYS: &[&str] = &[
    "coordinator_server_id",
    "display_name",
    "dns_name",
    "dns_port",
    "network_id",
    "onion_address",
    "onion_port",
    "onion_tls_spki_sha256",
    "role",
];

/// The local node's federation role (spec 8893).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum NodeRole {
    /// The single logical coordinator.
    Coordinator,
    /// An edge that projects coordinator state.
    Edge,
}

impl NodeRole {
    /// Returns the configuration spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Coordinator => "coordinator",
            Self::Edge => "edge",
        }
    }
}

/// A network display name: 1..32 ASCII `[A-Za-z0-9._-]` (spec 8892).
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DisplayLabel(String);

impl DisplayLabel {
    /// Parses the closed grammar.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        ascii_identifier(text, DISPLAY_NAME_BYTES.0, DISPLAY_NAME_BYTES.1)?;
        Ok(Self(text.to_owned()))
    }

    /// Borrows the label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The public DNS onboarding endpoint (spec 8895-8896).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsEndpoint {
    /// Lowercase RFC 9525 reference name.
    pub name: DnsName,
    /// TCP port, default 6697.
    pub port: u16,
}

/// The onion onboarding endpoint with its pinned SPKI hash (spec 8897-8899).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionEndpoint {
    /// Version-3 onion address.
    pub address: OnionAddress,
    /// Virtual port, default 6697.
    pub port: u16,
    /// Pinned certificate SPKI SHA-256.
    pub tls_spki_sha256: [u8; 32],
}

/// The validated `[network]` table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkConfig {
    /// Permanent network identity.
    pub network_id: NetworkId,
    /// Reloadable display name.
    pub display_name: DisplayLabel,
    /// Local role.
    pub role: NodeRole,
    /// Coordinator identity; equals the local server identity on a coordinator.
    pub coordinator_server_id: ServerId,
    /// Optional DNS onboarding endpoint.
    pub dns: Option<DnsEndpoint>,
    /// Optional onion onboarding endpoint.
    pub onion: Option<OnionEndpoint>,
}

impl NetworkConfig {
    /// Returns whether the only onboarding endpoint is an onion endpoint (spec 9025).
    #[must_use]
    pub const fn is_onion_only(&self) -> bool {
        self.dns.is_none() && self.onion.is_some()
    }
}

const TABLE: &str = "network";

pub(crate) fn parse(table: &Table, sink: &mut IssueSink) -> Option<NetworkConfig> {
    let key = |field| SchemaKey::new(TABLE, field);
    sink.field(key(""), check_keys(table, NETWORK_KEYS))?;
    let network_id = sink.field(key("network_id"), parse_network_id(table));
    let display_name = sink.field(
        key("display_name"),
        string(table, "display_name").and_then(DisplayLabel::parse),
    );
    let role = sink.field(key("role"), parse_role(table));
    let coordinator_server_id = sink.field(
        key("coordinator_server_id"),
        string(table, "coordinator_server_id")
            .and_then(|text| ServerId::parse(text).map_err(|_| ConfigError::InvalidValue)),
    );
    let dns_port = sink.field(
        key("dns_port"),
        optional_unsigned(table, "dns_port")
            .and_then(|value| ENDPOINT_PORT.resolve(value))
            .and_then(port),
    );
    let dns = sink.field(key("dns_name"), parse_dns(table, dns_port));
    let onion = parse_onion(table, sink);
    Some(NetworkConfig {
        network_id: network_id?,
        display_name: display_name?,
        role: role?,
        coordinator_server_id: coordinator_server_id?,
        dns: dns?,
        onion: onion?,
    })
}

fn parse_network_id(table: &Table) -> Result<NetworkId, ConfigError> {
    NetworkId::parse(string(table, "network_id")?).map_err(|_| ConfigError::InvalidValue)
}

fn parse_role(table: &Table) -> Result<NodeRole, ConfigError> {
    closed_enum(
        string(table, "role")?,
        &[
            ("coordinator", NodeRole::Coordinator),
            ("edge", NodeRole::Edge),
        ],
    )
}

fn parse_dns(table: &Table, port: Option<u16>) -> Result<Option<DnsEndpoint>, ConfigError> {
    let Some(name) = optional_string(table, "dns_name")? else {
        return Ok(None);
    };
    // A rejected port has already been recorded under its own key.
    let port = port.ok_or(ConfigError::InvalidValue)?;
    Ok(Some(DnsEndpoint {
        name: dns_name(name)?,
        port,
    }))
}

fn parse_onion(table: &Table, sink: &mut IssueSink) -> Option<Option<OnionEndpoint>> {
    let port_key = SchemaKey::new(TABLE, "onion_port");
    let port_value = sink.field(
        port_key,
        optional_unsigned(table, "onion_port")
            .and_then(|value| ENDPOINT_PORT.resolve(value))
            .and_then(port),
    );
    let address = sink.field(
        SchemaKey::new(TABLE, "onion_address"),
        optional_string(table, "onion_address")
            .and_then(|text| text.map(OnionAddress::parse).transpose()),
    );
    let pin = sink.field(
        SchemaKey::new(TABLE, "onion_tls_spki_sha256"),
        optional_string(table, "onion_tls_spki_sha256")
            .and_then(|text| text.map(base64url_32).transpose()),
    );
    // The pin is required exactly when the address is present (spec 8899).
    let endpoint = match (address?, pin?) {
        (None, None) => None,
        (Some(address), Some(tls_spki_sha256)) => Some(OnionEndpoint {
            address,
            port: port_value?,
            tls_spki_sha256,
        }),
        _ => {
            return sink.field(
                SchemaKey::new(TABLE, "onion_tls_spki_sha256"),
                Err(ConfigError::MissingValue),
            );
        }
    };
    Some(endpoint)
}
