//! The `[moderation]` table and its `[[moderation.operator]]` records (spec C.7 9189-9276).

use std::path::PathBuf;

use agenc_relay_types::{AdminPermissionSet, OperatorId};
use toml::Table;

use crate::bounds::{
    ACCOUNT_SANCTION_DAYS, AUDIT_RETENTION_DAYS, FREE_REASON_BYTES, MAX_OPERATOR_IDS,
    OPERATOR_COUNT, OPERATOR_LABEL_BYTES, SESSION_SANCTION_HOURS,
};
use crate::document::{
    boolean, check_keys, optional_string, optional_unsigned, string, string_array, table_array,
    unsigned_array,
};
use crate::error::{ConfigError, IssueSink, SchemaKey};
use crate::paths::{PathResolver, index_u16};
use crate::scalar::{as_u32, ascii_identifier, base64url_32, unique_unsigned};

pub(crate) const MODERATION_KEYS: &[&str] = &[
    "account_sanction_days",
    "audit_retention_days",
    "audit_signing_private_key_file",
    "audit_trust_manifest_file",
    "free_reason_bytes",
    "operator",
    "session_sanction_hours",
];
pub(crate) const OPERATOR_KEYS: &[&str] = &[
    "certificate_spki_sha256",
    "display_label",
    "enabled",
    "local_gids",
    "local_uids",
    "operator_id",
    "permissions",
    "signing_public_key",
];

/// One operator record (spec 9260-9269).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorConfig {
    /// Immutable unique operator identity.
    pub operator_id: OperatorId,
    /// Safe ASCII label without authority.
    pub display_label: String,
    /// Unique Ed25519 verification key.
    pub signing_public_key: [u8; 32],
    /// Unique certificate pin, required for remote administration.
    pub certificate_spki_sha256: Option<[u8; 32]>,
    /// Local admin UID mappings, 0..16 unique.
    pub local_uids: Vec<u32>,
    /// Local admin GID mappings, 0..16 unique.
    pub local_gids: Vec<u32>,
    /// Nonempty permission subset.
    pub permissions: AdminPermissionSet,
    /// Reloadable enable flag.
    pub enabled: bool,
}

/// The validated `[moderation]` table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModerationConfig {
    /// Dedicated Ed25519 audit-signing key file.
    pub audit_signing_private_key_file: PathBuf,
    /// Authorized audit-signing public keys.
    pub audit_trust_manifest_file: PathBuf,
    /// Audit retention, 30..365 days.
    pub audit_retention_days: u64,
    /// Default session sanction, 1..720 hours.
    pub session_sanction_hours: u64,
    /// Default account sanction, 1..365 days.
    pub account_sanction_days: u64,
    /// Free-form reason ceiling, fixed at 512 bytes.
    pub free_reason_bytes: u64,
    /// Operator records, 1..64.
    pub operators: Vec<OperatorConfig>,
}

const TABLE: &str = "moderation";
const OPERATOR_TABLE: &str = "moderation.operator";

pub(crate) fn parse(
    table: &Table,
    resolver: &PathResolver,
    sink: &mut IssueSink,
) -> Option<ModerationConfig> {
    let key = |field| SchemaKey::new(TABLE, field);
    sink.field(key(""), check_keys(table, MODERATION_KEYS))?;
    let audit_signing_private_key_file = sink.field(
        key("audit_signing_private_key_file"),
        string(table, "audit_signing_private_key_file").and_then(|text| resolver.resolve(text)),
    );
    let audit_trust_manifest_file = sink.field(
        key("audit_trust_manifest_file"),
        string(table, "audit_trust_manifest_file").and_then(|text| resolver.resolve(text)),
    );
    let mut bounded = |field: &'static str, bound: crate::scalar::Bound, fixed: bool| {
        sink.field(
            SchemaKey::new(TABLE, field),
            optional_unsigned(table, field).and_then(|value| {
                if fixed {
                    bound.fixed(value)
                } else {
                    bound.resolve(value)
                }
            }),
        )
    };
    let audit_retention_days = bounded("audit_retention_days", AUDIT_RETENTION_DAYS, false);
    let session_sanction_hours = bounded("session_sanction_hours", SESSION_SANCTION_HOURS, false);
    let account_sanction_days = bounded("account_sanction_days", ACCOUNT_SANCTION_DAYS, false);
    let free_reason_bytes = bounded("free_reason_bytes", FREE_REASON_BYTES, true);
    let operators = parse_operators(table, sink);
    Some(ModerationConfig {
        audit_signing_private_key_file: audit_signing_private_key_file?,
        audit_trust_manifest_file: audit_trust_manifest_file?,
        audit_retention_days: audit_retention_days?,
        session_sanction_hours: session_sanction_hours?,
        account_sanction_days: account_sanction_days?,
        free_reason_bytes: free_reason_bytes?,
        operators: operators?,
    })
}

fn parse_operators(table: &Table, sink: &mut IssueSink) -> Option<Vec<OperatorConfig>> {
    let rows = sink.field(
        SchemaKey::new(TABLE, "operator"),
        table_array(table, "operator", OPERATOR_COUNT.0, OPERATOR_COUNT.1),
    )?;
    let mut operators = Vec::new();
    let mut complete = true;
    for (index, row) in rows.iter().enumerate() {
        match parse_operator(row, index_u16(index), sink) {
            Some(operator) => operators.push(operator),
            None => complete = false,
        }
    }
    complete.then_some(operators)
}

fn parse_operator(row: &Table, index: u16, sink: &mut IssueSink) -> Option<OperatorConfig> {
    let key = |field| SchemaKey::indexed(OPERATOR_TABLE, index, field);
    sink.field(key(""), check_keys(row, OPERATOR_KEYS))?;
    let operator_id = sink.field(
        key("operator_id"),
        string(row, "operator_id")
            .and_then(|text| OperatorId::parse(text).map_err(|_| ConfigError::InvalidValue)),
    );
    let display_label = sink.field(key("display_label"), parse_label(row));
    let signing_public_key = sink.field(
        key("signing_public_key"),
        string(row, "signing_public_key").and_then(base64url_32),
    );
    let certificate_spki_sha256 = sink.field(
        key("certificate_spki_sha256"),
        optional_string(row, "certificate_spki_sha256")
            .and_then(|text| text.map(base64url_32).transpose()),
    );
    let local_uids = sink.field(key("local_uids"), parse_ids(row, "local_uids"));
    let local_gids = sink.field(key("local_gids"), parse_ids(row, "local_gids"));
    let permissions = sink.field(key("permissions"), parse_permissions(row));
    let enabled = sink.field(key("enabled"), boolean(row, "enabled"));
    Some(OperatorConfig {
        operator_id: operator_id?,
        display_label: display_label?,
        signing_public_key: signing_public_key?,
        certificate_spki_sha256: certificate_spki_sha256?,
        local_uids: local_uids?,
        local_gids: local_gids?,
        permissions: permissions?,
        enabled: enabled?,
    })
}

fn parse_label(row: &Table) -> Result<String, ConfigError> {
    let text = string(row, "display_label")?;
    ascii_identifier(text, OPERATOR_LABEL_BYTES.0, OPERATOR_LABEL_BYTES.1)?;
    Ok(text.to_owned())
}

fn parse_ids(row: &Table, name: &str) -> Result<Vec<u32>, ConfigError> {
    let values = unsigned_array(row, name, MAX_OPERATOR_IDS)?;
    unique_unsigned(&values)?;
    values.into_iter().map(as_u32).collect()
}

fn parse_permissions(row: &Table) -> Result<AdminPermissionSet, ConfigError> {
    let names = string_array(
        row,
        "permissions",
        agenc_relay_types::AdminPermission::ALL.len(),
    )?;
    AdminPermissionSet::from_names(names.iter().copied()).map_err(|_| ConfigError::InvalidValue)
}
