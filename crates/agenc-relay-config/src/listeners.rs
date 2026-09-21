//! The `[listeners]` table and its `[[listeners.endpoint]]` union (spec C.3 8920-8961).

use std::net::SocketAddr;
use std::path::PathBuf;

use toml::Table;

use crate::bounds::{
    ALLOWED_UIDS, LISTENER_COUNT, LISTENER_NAME_BYTES, MAX_ALLOWED_GIDS, MAX_ALLOWED_ORIGINS,
};
use crate::document::{
    boolean, check_keys, optional_boolean, optional_string, string, string_array, table_array,
    unsigned, unsigned_array,
};
use crate::error::{ConfigError, IssueSink, SchemaKey};
use crate::paths::{PathResolver, index_u16};
use crate::scalar::{
    HttpsOrigin, as_u32, ascii_identifier, closed_enum, socket_bind, unique_unsigned,
};

pub(crate) const LISTENERS_KEYS: &[&str] = &["endpoint"];
pub(crate) const LISTENER_KEYS: &[&str] = &[
    "allow_missing_origin",
    "allowed_gids",
    "allowed_origins",
    "allowed_uids",
    "bind",
    "client_ca_file",
    "enabled",
    "max_connections",
    "name",
    "purpose",
    "tls_certificate_file",
    "tls_ocsp_staple_file",
    "tls_private_key_file",
];

/// The closed listener purpose set (spec 8927).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum ListenerPurpose {
    /// Direct TLS client listener.
    ClientTls,
    /// WebSocket-over-TLS client listener, enabled by the optional `wss` feature.
    ClientWss,
    /// Onion client listener behind a Unix socket.
    ClientOnion,
    /// Federation link listener.
    Federation,
    /// Local Unix-socket administration.
    AdminLocal,
    /// Remote mutual-TLS administration.
    AdminTls,
}

impl ListenerPurpose {
    /// Every purpose in registry order.
    pub const ALL: [Self; 6] = [
        Self::ClientTls,
        Self::ClientWss,
        Self::ClientOnion,
        Self::Federation,
        Self::AdminLocal,
        Self::AdminTls,
    ];

    /// Returns the configuration spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientTls => "client_tls",
            Self::ClientWss => "client_wss",
            Self::ClientOnion => "client_onion",
            Self::Federation => "federation",
            Self::AdminLocal => "admin_local",
            Self::AdminTls => "admin_tls",
        }
    }

    /// Returns whether the purpose serves clients and shares the global client permit.
    #[must_use]
    pub const fn is_client(self) -> bool {
        matches!(self, Self::ClientTls | Self::ClientWss | Self::ClientOnion)
    }

    /// Returns whether the purpose is administrative.
    #[must_use]
    pub const fn is_admin(self) -> bool {
        matches!(self, Self::AdminLocal | Self::AdminTls)
    }

    /// Returns whether the purpose binds a TCP socket rather than a Unix path.
    #[must_use]
    pub const fn uses_tcp(self) -> bool {
        matches!(
            self,
            Self::ClientTls | Self::ClientWss | Self::Federation | Self::AdminTls
        )
    }

    /// Returns the key-reuse class: client, federation, or admin (spec 8954).
    #[must_use]
    pub const fn key_class(self) -> u8 {
        match self {
            Self::ClientTls | Self::ClientWss | Self::ClientOnion => 0,
            Self::Federation => 1,
            Self::AdminLocal | Self::AdminTls => 2,
        }
    }
}

/// A unique 1..32 ASCII listener name (spec 8925).
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct ListenerName(String);

impl ListenerName {
    /// Parses the closed grammar.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        ascii_identifier(text, LISTENER_NAME_BYTES.0, LISTENER_NAME_BYTES.1)?;
        Ok(Self(text.to_owned()))
    }

    /// Borrows the name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A listener bind address by purpose (spec 8928, 8951-8953).
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum ListenerBind {
    /// Literal unicast IP and port.
    Socket(SocketAddr),
    /// Absolute Unix socket path.
    Unix(PathBuf),
}

/// Certificate and private key files for a TLS purpose (spec 8930-8931).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsFiles {
    /// Certificate chain file.
    pub certificate_file: PathBuf,
    /// Private key file under Section 22.2 rules.
    pub private_key_file: PathBuf,
    /// Optional bounded DER OCSP response for a public DNS certificate.
    pub ocsp_staple_file: Option<PathBuf>,
}

/// WebSocket origin policy (spec 8934-8935).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WssPolicy {
    /// Exact HTTPS origins, 0..64.
    pub allowed_origins: Vec<HttpsOrigin>,
    /// Whether a missing Origin header is accepted (non-browser listener).
    pub allow_missing_origin: bool,
}

/// Local admin peer-credential policy (spec 8937-8938).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalAdminPolicy {
    /// Allowed OS user IDs, 1..64.
    pub allowed_uids: Vec<u32>,
    /// Allowed OS group IDs, 0..64.
    pub allowed_gids: Vec<u32>,
}

/// One validated `[[listeners.endpoint]]` element.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenerConfig {
    /// Unique listener name.
    pub name: ListenerName,
    /// Explicit enable flag.
    pub enabled: bool,
    /// Listener purpose.
    pub purpose: ListenerPurpose,
    /// Bind address or path.
    pub bind: ListenerBind,
    /// Per-listener connection ceiling (checked against limits in the union stage).
    pub max_connections: u64,
    /// TLS files for every purpose except `admin_local`.
    pub tls: Option<TlsFiles>,
    /// Client CA bundle for `federation` and `admin_tls`.
    pub client_ca_file: Option<PathBuf>,
    /// WebSocket policy for `client_wss`.
    pub wss: Option<WssPolicy>,
    /// Peer-credential policy for `admin_local`.
    pub local_admin: Option<LocalAdminPolicy>,
}

const TABLE: &str = "listeners.endpoint";

pub(crate) fn parse(
    table: &Table,
    resolver: &PathResolver,
    sink: &mut IssueSink,
) -> Option<Vec<ListenerConfig>> {
    sink.field(
        SchemaKey::new("listeners", ""),
        check_keys(table, LISTENERS_KEYS),
    )?;
    let rows = sink.field(
        SchemaKey::new("listeners", "endpoint"),
        table_array(table, "endpoint", LISTENER_COUNT.0, LISTENER_COUNT.1),
    )?;
    let mut listeners = Vec::new();
    let mut complete = true;
    for (index, row) in rows.iter().enumerate() {
        match parse_endpoint(row, index_u16(index), resolver, sink) {
            Some(listener) => listeners.push(listener),
            None => complete = false,
        }
    }
    complete.then_some(listeners)
}

struct RawEndpoint {
    name: ListenerName,
    enabled: bool,
    purpose: ListenerPurpose,
    max_connections: u64,
}

fn parse_endpoint(
    row: &Table,
    index: u16,
    resolver: &PathResolver,
    sink: &mut IssueSink,
) -> Option<ListenerConfig> {
    let key = |field| SchemaKey::indexed(TABLE, index, field);
    sink.field(key(""), check_keys(row, LISTENER_KEYS))?;
    let raw = parse_raw(row, index, sink);
    let purpose = raw.as_ref().map(|raw| raw.purpose);
    let bind = sink.field(key("bind"), parse_bind(row, purpose, resolver));
    let tls = sink.field(
        key("tls_certificate_file"),
        parse_tls(row, purpose, resolver),
    );
    let ocsp_staple_file = sink.field(
        key("tls_ocsp_staple_file"),
        parse_ocsp_staple(row, purpose, resolver),
    );
    let client_ca_file = sink.field(
        key("client_ca_file"),
        parse_client_ca(row, purpose, resolver),
    );
    let wss = sink.field(key("allowed_origins"), parse_wss(row, purpose));
    let local_admin = sink.field(key("allowed_uids"), parse_local_admin(row, purpose));
    let raw = raw?;
    let mut tls = tls?;
    if let Some(files) = tls.as_mut() {
        files.ocsp_staple_file = ocsp_staple_file?;
    } else if ocsp_staple_file?.is_some() {
        return None;
    }
    Some(ListenerConfig {
        name: raw.name,
        enabled: raw.enabled,
        purpose: raw.purpose,
        bind: bind?,
        max_connections: raw.max_connections,
        tls,
        client_ca_file: client_ca_file?,
        wss: wss?,
        local_admin: local_admin?,
    })
}

fn parse_raw(row: &Table, index: u16, sink: &mut IssueSink) -> Option<RawEndpoint> {
    let key = |field| SchemaKey::indexed(TABLE, index, field);
    let name = sink.field(
        key("name"),
        string(row, "name").and_then(ListenerName::parse),
    );
    let enabled = sink.field(key("enabled"), boolean(row, "enabled"));
    let purpose = sink.field(key("purpose"), parse_purpose(row));
    let max_connections = sink.field(
        key("max_connections"),
        unsigned(row, "max_connections").and_then(|value| {
            if value == 0 {
                Err(ConfigError::InvalidValue)
            } else {
                Ok(value)
            }
        }),
    );
    Some(RawEndpoint {
        name: name?,
        enabled: enabled?,
        purpose: purpose?,
        max_connections: max_connections?,
    })
}

fn parse_purpose(row: &Table) -> Result<ListenerPurpose, ConfigError> {
    let choices: Vec<(&str, ListenerPurpose)> = ListenerPurpose::ALL
        .iter()
        .map(|purpose| (purpose.as_str(), *purpose))
        .collect();
    closed_enum(string(row, "purpose")?, &choices)
}

fn parse_bind(
    row: &Table,
    purpose: Option<ListenerPurpose>,
    resolver: &PathResolver,
) -> Result<ListenerBind, ConfigError> {
    let text = string(row, "bind")?;
    match purpose {
        Some(purpose) if purpose.uses_tcp() => socket_bind(text).map(ListenerBind::Socket),
        Some(_) => resolver.resolve(text).map(ListenerBind::Unix),
        None => Err(ConfigError::MissingValue),
    }
}

fn parse_tls(
    row: &Table,
    purpose: Option<ListenerPurpose>,
    resolver: &PathResolver,
) -> Result<Option<TlsFiles>, ConfigError> {
    let certificate = optional_string(row, "tls_certificate_file")?;
    let private_key = optional_string(row, "tls_private_key_file")?;
    // Every purpose except admin_local requires both files; admin_local forbids them
    // (spec 8930-8931).
    let required = purpose.is_some_and(|purpose| purpose != ListenerPurpose::AdminLocal);
    match (certificate, private_key) {
        (None, None) if !required => Ok(None),
        (Some(certificate), Some(private_key)) if required => Ok(Some(TlsFiles {
            certificate_file: resolver.resolve(certificate)?,
            private_key_file: resolver.resolve(private_key)?,
            ocsp_staple_file: None,
        })),
        (None, None) => Err(ConfigError::MissingValue),
        _ => Err(ConfigError::InvalidValue),
    }
}

fn parse_ocsp_staple(
    row: &Table,
    purpose: Option<ListenerPurpose>,
    resolver: &PathResolver,
) -> Result<Option<PathBuf>, ConfigError> {
    let path = optional_string(row, "tls_ocsp_staple_file")?;
    match (purpose, path) {
        (Some(ListenerPurpose::ClientTls | ListenerPurpose::ClientWss), Some(path)) => {
            resolver.resolve(path).map(Some)
        }
        (_, None) => Ok(None),
        _ => Err(ConfigError::InvalidValue),
    }
}

fn parse_client_ca(
    row: &Table,
    purpose: Option<ListenerPurpose>,
    resolver: &PathResolver,
) -> Result<Option<PathBuf>, ConfigError> {
    let text = optional_string(row, "client_ca_file")?;
    let required = matches!(
        purpose,
        Some(ListenerPurpose::Federation | ListenerPurpose::AdminTls)
    );
    match (text, required) {
        (Some(text), true) => resolver.resolve(text).map(Some),
        (None, false) => Ok(None),
        (None, true) => Err(ConfigError::MissingValue),
        (Some(_), false) => Err(ConfigError::InvalidValue),
    }
}

fn parse_wss(
    row: &Table,
    purpose: Option<ListenerPurpose>,
) -> Result<Option<WssPolicy>, ConfigError> {
    let origins = string_array(row, "allowed_origins", MAX_ALLOWED_ORIGINS)?;
    let allow_missing = optional_boolean(row, "allow_missing_origin")?;
    if purpose != Some(ListenerPurpose::ClientWss) {
        return if origins.is_empty() && allow_missing.is_none() {
            Ok(None)
        } else {
            Err(ConfigError::InvalidValue)
        };
    }
    let mut allowed_origins = Vec::new();
    allowed_origins
        .try_reserve_exact(origins.len())
        .map_err(|_| ConfigError::InvalidValue)?;
    for origin in origins {
        let parsed = HttpsOrigin::parse(origin)?;
        if allowed_origins.contains(&parsed) {
            return Err(ConfigError::InvalidValue);
        }
        allowed_origins.push(parsed);
    }
    Ok(Some(WssPolicy {
        allowed_origins,
        allow_missing_origin: allow_missing.unwrap_or(false),
    }))
}

fn parse_local_admin(
    row: &Table,
    purpose: Option<ListenerPurpose>,
) -> Result<Option<LocalAdminPolicy>, ConfigError> {
    let uids = unsigned_array(row, "allowed_uids", ALLOWED_UIDS.1)?;
    let gids = unsigned_array(row, "allowed_gids", MAX_ALLOWED_GIDS)?;
    if purpose != Some(ListenerPurpose::AdminLocal) {
        return if uids.is_empty() && gids.is_empty() {
            Ok(None)
        } else {
            Err(ConfigError::InvalidValue)
        };
    }
    if uids.len() < ALLOWED_UIDS.0 {
        return Err(ConfigError::MissingValue);
    }
    unique_unsigned(&uids)?;
    unique_unsigned(&gids)?;
    let allowed_uids = uids
        .into_iter()
        .map(as_u32)
        .collect::<Result<Vec<_>, _>>()?;
    let allowed_gids = gids
        .into_iter()
        .map(as_u32)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(LocalAdminPolicy {
        allowed_uids,
        allowed_gids,
    }))
}
