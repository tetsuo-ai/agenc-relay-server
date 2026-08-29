//! Backup and audit trust manifests (spec 9071-9082, 9244-9251).

use std::collections::BTreeSet;
use std::path::Path;

use toml::{Table, Value};

use crate::bounds::{MAX_CONFIG_BYTES, MAX_TRUST_MANIFEST_KEYS};
use crate::document::{parse_document, require_exact_keys, string, unsigned};
use crate::error::ConfigError;
use crate::paths::read_protected_text;
use crate::scalar::base64url_32;

/// One validated row from the offline backup trust manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupTrustManifestEntry {
    /// Claimed derived key identifier.
    pub key_id: [u8; 32],
    /// Canonical Ed25519 public key.
    pub ed25519_public_key: [u8; 32],
    /// Inclusive first accepted backup creation second.
    pub not_before: u64,
    /// Exclusive last accepted backup creation second.
    pub not_after: u64,
}

/// One validated row from the audit trust manifest (spec 9244-9251).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditTrustManifestEntry {
    /// Claimed Section 16.4 key identifier.
    pub key_id: [u8; 32],
    /// Canonical Ed25519 public key.
    pub ed25519_public_key: [u8; 32],
    /// Inclusive first accepted event second.
    pub not_before: u64,
    /// Exclusive last accepted event second.
    pub not_after: u64,
}

/// Parses a protected canonical backup trust manifest.
pub fn load_backup_trust_manifest(
    path: &Path,
) -> Result<Vec<BackupTrustManifestEntry>, ConfigError> {
    let text = read_protected_text(path, MAX_CONFIG_BYTES)?;
    parse_backup_trust_manifest(&text)
}

/// Parses backup trust manifest text.
pub fn parse_backup_trust_manifest(
    text: &str,
) -> Result<Vec<BackupTrustManifestEntry>, ConfigError> {
    parse_rows(text, "backup_trust_version")?
        .into_iter()
        .map(|row| {
            Ok(BackupTrustManifestEntry {
                key_id: row.key_id,
                ed25519_public_key: row.ed25519_public_key,
                not_before: row.not_before,
                not_after: row.not_after,
            })
        })
        .collect()
}

/// Parses a protected canonical audit trust manifest.
pub fn load_audit_trust_manifest(path: &Path) -> Result<Vec<AuditTrustManifestEntry>, ConfigError> {
    let text = read_protected_text(path, MAX_CONFIG_BYTES)?;
    parse_audit_trust_manifest(&text)
}

/// Parses audit trust manifest text.
pub fn parse_audit_trust_manifest(text: &str) -> Result<Vec<AuditTrustManifestEntry>, ConfigError> {
    parse_rows(text, "audit_trust_version")?
        .into_iter()
        .map(|row| {
            Ok(AuditTrustManifestEntry {
                key_id: row.key_id,
                ed25519_public_key: row.ed25519_public_key,
                not_before: row.not_before,
                not_after: row.not_after,
            })
        })
        .collect()
}

struct TrustRow {
    key_id: [u8; 32],
    ed25519_public_key: [u8; 32],
    not_before: u64,
    not_after: u64,
}

fn parse_rows(text: &str, version_key: &str) -> Result<Vec<TrustRow>, ConfigError> {
    let root = parse_document(text)?;
    require_exact_keys(&root, &[version_key, "key"])?;
    if unsigned(&root, version_key)? != 1 {
        return Err(ConfigError::InvalidValue);
    }
    let rows = root
        .get("key")
        .and_then(Value::as_array)
        .ok_or(ConfigError::MissingValue)?;
    if rows.is_empty() || rows.len() > MAX_TRUST_MANIFEST_KEYS {
        return Err(ConfigError::InvalidValue);
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(rows.len())
        .map_err(|_| ConfigError::InvalidValue)?;
    let mut key_ids = BTreeSet::new();
    for row in rows {
        let table = row.as_table().ok_or(ConfigError::InvalidDocument)?;
        let entry = parse_row(table)?;
        if !key_ids.insert(entry.key_id) {
            return Err(ConfigError::InvalidValue);
        }
        entries.push(entry);
    }
    Ok(entries)
}

fn parse_row(table: &Table) -> Result<TrustRow, ConfigError> {
    require_exact_keys(
        table,
        &["ed25519_public_key", "key_id", "not_after", "not_before"],
    )?;
    let key_id = base64url_32(string(table, "key_id")?)?;
    let ed25519_public_key = base64url_32(string(table, "ed25519_public_key")?)?;
    let not_before = unsigned(table, "not_before")?;
    let not_after = unsigned(table, "not_after")?;
    if not_before >= not_after {
        return Err(ConfigError::InvalidValue);
    }
    Ok(TrustRow {
        key_id,
        ed25519_public_key,
        not_before,
        not_after,
    })
}
