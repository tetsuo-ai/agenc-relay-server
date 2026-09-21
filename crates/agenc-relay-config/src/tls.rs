//! The `[tls]` table (spec C.4 8965-8972).

use toml::Table;

use crate::bounds::{TICKET_LIFETIME_SECONDS, TICKET_ROTATION_SECONDS};
use crate::document::{check_keys, optional_boolean, optional_string, optional_unsigned};
use crate::error::{ConfigError, IssueSink, SchemaKey};
use crate::scalar::closed_enum;

/// `tls.key_log_file` is deliberately absent from this list so its presence is an
/// unknown-key error (spec 8972).
pub(crate) const TLS_KEYS: &[&str] = &[
    "group_policy",
    "require_ocsp_staple",
    "session_tickets",
    "ticket_lifetime_seconds",
    "ticket_rotation_seconds",
];

/// The TLS key-exchange group policy (spec 8967).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum GroupPolicy {
    /// Offer the hybrid group first and allow the X25519 fallback.
    HybridPreferred,
    /// Require the hybrid group.
    HybridRequired,
}

impl GroupPolicy {
    /// Returns the configuration spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HybridPreferred => "hybrid_preferred",
            Self::HybridRequired => "hybrid_required",
        }
    }
}

/// The validated `[tls]` table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsConfig {
    /// Key-exchange group policy.
    pub group_policy: GroupPolicy,
    /// Whether session tickets are issued.
    pub session_tickets: bool,
    /// Ticket key rotation interval, fixed at 21,600 seconds.
    pub ticket_rotation_seconds: u64,
    /// Ticket lifetime, fixed at 86,400 seconds.
    pub ticket_lifetime_seconds: u64,
    /// Whether public DNS certificates require an OCSP staple.
    pub require_ocsp_staple: bool,
}

const TABLE: &str = "tls";

pub(crate) fn parse(table: &Table, sink: &mut IssueSink) -> Option<TlsConfig> {
    let key = |field| SchemaKey::new(TABLE, field);
    sink.field(key(""), check_keys(table, TLS_KEYS))?;
    let group_policy = sink.field(key("group_policy"), parse_group_policy(table));
    let session_tickets = sink.field(
        key("session_tickets"),
        optional_boolean(table, "session_tickets").map(|value| value.unwrap_or(true)),
    );
    let ticket_rotation_seconds = sink.field(
        key("ticket_rotation_seconds"),
        optional_unsigned(table, "ticket_rotation_seconds")
            .and_then(|value| TICKET_ROTATION_SECONDS.fixed(value)),
    );
    let ticket_lifetime_seconds = sink.field(
        key("ticket_lifetime_seconds"),
        optional_unsigned(table, "ticket_lifetime_seconds")
            .and_then(|value| TICKET_LIFETIME_SECONDS.fixed(value)),
    );
    let require_ocsp_staple = sink.field(
        key("require_ocsp_staple"),
        optional_boolean(table, "require_ocsp_staple").map(|value| value.unwrap_or(false)),
    );
    Some(TlsConfig {
        group_policy: group_policy?,
        session_tickets: session_tickets?,
        ticket_rotation_seconds: ticket_rotation_seconds?,
        ticket_lifetime_seconds: ticket_lifetime_seconds?,
        require_ocsp_staple: require_ocsp_staple?,
    })
}

fn parse_group_policy(table: &Table) -> Result<GroupPolicy, ConfigError> {
    match optional_string(table, "group_policy")? {
        None => Ok(GroupPolicy::HybridPreferred),
        Some(text) => closed_enum(
            text,
            &[
                ("hybrid_preferred", GroupPolicy::HybridPreferred),
                ("hybrid_required", GroupPolicy::HybridRequired),
            ],
        ),
    }
}
