//! The `[federation]` table and its `[[federation.peer]]` records (spec C.4 8973-9004).

use std::path::PathBuf;

use agenc_relay_types::{RecoveryEpoch, ServerId};
use toml::Table;

use crate::bounds::{
    CONNECT_TIMEOUT_SECONDS, MAX_PEER_ENDPOINTS, MAX_PEER_RECORDS, MAX_PEERS, RECONNECT_MAX_SECONDS,
};
use crate::document::{
    boolean, check_keys, optional_boolean, optional_string, optional_unsigned, string,
    string_array, table_array,
};
use crate::error::{ConfigError, IssueSink, SchemaKey};
use crate::network::NodeRole;
use crate::paths::{PathResolver, index_u16};
use crate::scalar::{DnsName, PeerEndpoint, SocksEndpoint, base64url_32, closed_enum, dns_name};

pub(crate) const FEDERATION_KEYS: &[&str] = &[
    "connect_timeout_seconds",
    "enabled",
    "max_peers",
    "peer",
    "private_ca_file",
    "reconnect_max_seconds",
    "signing_private_key_file",
    "tor_socks_endpoint",
];
pub(crate) const FEDERATION_PEER_KEYS: &[&str] = &[
    "certificate_spki_sha256",
    "enabled",
    "endpoints",
    "recovery_epoch",
    "role",
    "server_id",
    "server_name",
    "signing_public_key",
];

/// One static federation peer record (spec 8987-8997).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerConfig {
    /// Unique peer identity, never the local identity.
    pub server_id: ServerId,
    /// Unique exact Section 7.4 name.
    pub server_name: DnsName,
    /// The peer's role, the inverse of the local role.
    pub role: NodeRole,
    /// Exact recovery epoch pin expected in FHELLO.
    pub recovery_epoch: RecoveryEpoch,
    /// Dial endpoints: 1..8 on an edge's coordinator record, empty otherwise.
    pub endpoints: Vec<PeerEndpoint>,
    /// Exact certificate SPKI pin.
    pub certificate_spki_sha256: [u8; 32],
    /// Exact Ed25519 public key.
    pub signing_public_key: [u8; 32],
    /// Explicit enable flag.
    pub enabled: bool,
}

/// The validated `[federation]` table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationConfig {
    /// Whether federation is active; false is core-only.
    pub enabled: bool,
    /// Separate private CA bundle, required when enabled.
    pub private_ca_file: Option<PathBuf>,
    /// Ed25519 signing key file, required when enabled.
    pub signing_private_key_file: Option<PathBuf>,
    /// Local Tor SOCKS proxy, required when any peer endpoint is an onion endpoint.
    pub tor_socks_endpoint: Option<SocksEndpoint>,
    /// Connect timeout, 1..30 seconds.
    pub connect_timeout_seconds: u64,
    /// Reconnect ceiling, fixed at 60 seconds.
    pub reconnect_max_seconds: u64,
    /// Peer ceiling, fixed at 64.
    pub max_peers: u64,
    /// Static peer records.
    pub peers: Vec<PeerConfig>,
}

const TABLE: &str = "federation";
const PEER_TABLE: &str = "federation.peer";

pub(crate) fn parse(
    table: &Table,
    resolver: &PathResolver,
    sink: &mut IssueSink,
) -> Option<FederationConfig> {
    let key = |field| SchemaKey::new(TABLE, field);
    sink.field(key(""), check_keys(table, FEDERATION_KEYS))?;
    let enabled = sink.field(
        key("enabled"),
        optional_boolean(table, "enabled").map(|value| value.unwrap_or(true)),
    );
    let private_ca_file = sink.field(
        key("private_ca_file"),
        optional_path(table, "private_ca_file", resolver),
    );
    let signing_private_key_file = sink.field(
        key("signing_private_key_file"),
        optional_path(table, "signing_private_key_file", resolver),
    );
    let tor_socks_endpoint = sink.field(
        key("tor_socks_endpoint"),
        optional_string(table, "tor_socks_endpoint")
            .and_then(|text| text.map(SocksEndpoint::parse).transpose()),
    );
    let connect_timeout_seconds = sink.field(
        key("connect_timeout_seconds"),
        optional_unsigned(table, "connect_timeout_seconds")
            .and_then(|value| CONNECT_TIMEOUT_SECONDS.resolve(value)),
    );
    let reconnect_max_seconds = sink.field(
        key("reconnect_max_seconds"),
        optional_unsigned(table, "reconnect_max_seconds")
            .and_then(|value| RECONNECT_MAX_SECONDS.fixed(value)),
    );
    let max_peers = sink.field(
        key("max_peers"),
        optional_unsigned(table, "max_peers").and_then(|value| MAX_PEERS.fixed(value)),
    );
    let peers = parse_peers(table, sink);
    Some(FederationConfig {
        enabled: enabled?,
        private_ca_file: private_ca_file?,
        signing_private_key_file: signing_private_key_file?,
        tor_socks_endpoint: tor_socks_endpoint?,
        connect_timeout_seconds: connect_timeout_seconds?,
        reconnect_max_seconds: reconnect_max_seconds?,
        max_peers: max_peers?,
        peers: peers?,
    })
}

pub(crate) fn optional_path(
    table: &Table,
    name: &str,
    resolver: &PathResolver,
) -> Result<Option<PathBuf>, ConfigError> {
    optional_string(table, name)?
        .map(|text| resolver.resolve(text))
        .transpose()
}

fn parse_peers(table: &Table, sink: &mut IssueSink) -> Option<Vec<PeerConfig>> {
    let rows = sink.field(
        SchemaKey::new(TABLE, "peer"),
        table_array(table, "peer", 0, MAX_PEER_RECORDS),
    )?;
    let mut peers = Vec::new();
    let mut complete = true;
    for (index, row) in rows.iter().enumerate() {
        match parse_peer(row, index_u16(index), sink) {
            Some(peer) => peers.push(peer),
            None => complete = false,
        }
    }
    complete.then_some(peers)
}

fn parse_peer(row: &Table, index: u16, sink: &mut IssueSink) -> Option<PeerConfig> {
    let key = |field| SchemaKey::indexed(PEER_TABLE, index, field);
    sink.field(key(""), check_keys(row, FEDERATION_PEER_KEYS))?;
    let server_id = sink.field(
        key("server_id"),
        string(row, "server_id")
            .and_then(|text| ServerId::parse(text).map_err(|_| ConfigError::InvalidValue)),
    );
    let server_name = sink.field(
        key("server_name"),
        string(row, "server_name").and_then(dns_name),
    );
    let role = sink.field(
        key("role"),
        string(row, "role").and_then(|text| {
            closed_enum(
                text,
                &[
                    ("coordinator", NodeRole::Coordinator),
                    ("edge", NodeRole::Edge),
                ],
            )
        }),
    );
    let recovery_epoch = sink.field(
        key("recovery_epoch"),
        string(row, "recovery_epoch")
            .and_then(|text| RecoveryEpoch::parse(text).map_err(|_| ConfigError::InvalidValue)),
    );
    let endpoints = sink.field(key("endpoints"), parse_endpoints(row));
    let certificate_spki_sha256 = sink.field(
        key("certificate_spki_sha256"),
        string(row, "certificate_spki_sha256").and_then(base64url_32),
    );
    let signing_public_key = sink.field(
        key("signing_public_key"),
        string(row, "signing_public_key").and_then(base64url_32),
    );
    let enabled = sink.field(key("enabled"), boolean(row, "enabled"));
    Some(PeerConfig {
        server_id: server_id?,
        server_name: server_name?,
        role: role?,
        recovery_epoch: recovery_epoch?,
        endpoints: endpoints?,
        certificate_spki_sha256: certificate_spki_sha256?,
        signing_public_key: signing_public_key?,
        enabled: enabled?,
    })
}

fn parse_endpoints(row: &Table) -> Result<Vec<PeerEndpoint>, ConfigError> {
    let texts = string_array(row, "endpoints", MAX_PEER_ENDPOINTS)?;
    let mut endpoints = Vec::new();
    endpoints
        .try_reserve_exact(texts.len())
        .map_err(|_| ConfigError::InvalidValue)?;
    for text in texts {
        let endpoint = PeerEndpoint::parse(text)?;
        if endpoints.contains(&endpoint) {
            return Err(ConfigError::InvalidValue);
        }
        endpoints.push(endpoint);
    }
    Ok(endpoints)
}
