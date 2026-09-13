//! The complete typed configuration tree and its ordered validation entry points.

use std::path::{Path, PathBuf};

use toml::Table;

use crate::accounts::{self, AccountsConfig};
use crate::bounds::MAX_CONFIG_BYTES;
use crate::cross;
use crate::document::{check_keys, parse_document, table, unsigned};
use crate::e2ee::{self, E2eeConfig};
use crate::error::{ConfigError, ConfigReport, IssueSink, SchemaKey};
use crate::federation::{self, FederationConfig};
use crate::limits::{self, LimitsConfig};
use crate::listeners::{self, ListenerConfig, ListenerPurpose};
use crate::moderation::{self, ModerationConfig};
use crate::network::{self, NetworkConfig};
use crate::paths::{self, PathResolver, read_protected_text};
use crate::privacy::{self, PrivacyConfig};
use crate::server::{self, ServerConfig};
use crate::storage::{self, StorageConfig};
use crate::tls::{self, TlsConfig};

/// Required root keys: `config_version` and the eleven tables (spec 8873-8876).
pub(crate) const ROOT_KEYS: &[&str] = &[
    "accounts",
    "config_version",
    "e2ee",
    "federation",
    "limits",
    "listeners",
    "moderation",
    "network",
    "privacy",
    "server",
    "storage",
    "tls",
];

/// The only supported document version (spec 4274).
pub const CONFIG_VERSION: u64 = 1;

/// How deep one validation run goes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationDepth {
    /// Stages 1, 2, and 5 through 8: no host filesystem access beyond path syntax.
    Document,
    /// Adds stage 3 (directory and file-type checks). Stage 4 secret opening is
    /// performed separately by [`crate::SecretSet::load`].
    Host,
}

/// The validated configuration document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    /// `[network]`.
    pub network: NetworkConfig,
    /// `[server]`.
    pub server: ServerConfig,
    /// `[[listeners.endpoint]]`.
    pub listeners: Vec<ListenerConfig>,
    /// `[tls]`.
    pub tls: TlsConfig,
    /// `[federation]`.
    pub federation: FederationConfig,
    /// `[storage]`.
    pub storage: StorageConfig,
    /// `[accounts]`.
    pub accounts: AccountsConfig,
    /// `[limits]`.
    pub limits: LimitsConfig,
    /// `[privacy]`.
    pub privacy: PrivacyConfig,
    /// `[moderation]`.
    pub moderation: ModerationConfig,
    /// `[e2ee]`.
    pub e2ee: E2eeConfig,
}

impl Config {
    /// Whether this identity is used by a listener or an outbound federation link.
    /// Edge federation listeners stay disabled while supplying the dialer's TLS identity.
    #[must_use]
    pub fn listener_material_required(&self, listener: &ListenerConfig) -> bool {
        listener.enabled
            || (self.federation.enabled
                && self.network.role == crate::NodeRole::Edge
                && listener.purpose == ListenerPurpose::Federation)
    }

    /// Parses and validates one document in the C.8 stage order.
    ///
    /// Structural failure (stages 1 and 2) returns before any later stage runs;
    /// otherwise every stage runs and all issues are returned together.
    pub fn parse_text(
        text: &str,
        resolver: &PathResolver,
        depth: ValidationDepth,
    ) -> Result<Self, ConfigReport> {
        let mut sink = IssueSink::default();
        let root = match parse_document(text) {
            Ok(root) => root,
            Err(error) => {
                sink.push(
                    crate::error::ValidationStage::RootSchema,
                    SchemaKey::new("", ""),
                    error,
                );
                return Err(sink.into_report());
            }
        };
        let config = parse_tables(&root, resolver, &mut sink);
        let Some(config) = config else {
            return Err(sink.into_report());
        };
        if sink.has_structural_issue() {
            return Err(sink.into_report());
        }
        if depth == ValidationDepth::Host {
            paths::verify_host_paths(&config, &mut sink);
        }
        cross::validate(&config, &mut sink);
        sink.into_result(config)
    }

    /// Returns the enabled listener purposes in registry order without duplicates.
    #[must_use]
    pub fn enabled_purposes(&self) -> Vec<ListenerPurpose> {
        ListenerPurpose::ALL
            .iter()
            .copied()
            .filter(|purpose| {
                self.listeners
                    .iter()
                    .any(|listener| listener.enabled && listener.purpose == *purpose)
            })
            .collect()
    }

    /// Every secret file path with its schema key (spec 4311-4333).
    pub(crate) fn secret_paths(&self) -> Vec<(SchemaKey, PathBuf)> {
        let mut paths = vec![
            (
                SchemaKey::new("storage", "master_key_file"),
                self.storage.master_key_file.clone(),
            ),
            (
                SchemaKey::new("storage", "rollback_guard_key_file"),
                self.storage.rollback_guard_key_file.clone(),
            ),
            (
                SchemaKey::new("storage", "login_index_key_file"),
                self.storage.login_index_key_file.clone(),
            ),
            (
                SchemaKey::new("storage", "backup_signing_private_key_file"),
                self.storage.backup_signing_private_key_file.clone(),
            ),
            (
                SchemaKey::new("moderation", "audit_signing_private_key_file"),
                self.moderation.audit_signing_private_key_file.clone(),
            ),
        ];
        push_optional(
            &mut paths,
            SchemaKey::new("storage", "login_index_previous_key_file"),
            self.storage.login_index_previous_key_file.as_ref(),
        );
        push_optional(
            &mut paths,
            SchemaKey::new("federation", "signing_private_key_file"),
            self.federation.signing_private_key_file.as_ref(),
        );
        for (field, path) in self.account_secret_paths() {
            push_optional(&mut paths, SchemaKey::new("accounts", field), path);
        }
        push_optional(
            &mut paths,
            SchemaKey::new("e2ee", "sequencer_private_key_file"),
            self.e2ee.sequencer_private_key_file.as_ref(),
        );
        for (index, listener) in self.listeners.iter().enumerate() {
            if !self.listener_material_required(listener) {
                continue;
            }
            let key = SchemaKey::indexed(
                "listeners.endpoint",
                paths::index_u16(index),
                "tls_private_key_file",
            );
            push_optional(
                &mut paths,
                key,
                listener.tls.as_ref().map(|tls| &tls.private_key_file),
            );
        }
        paths
    }

    fn account_secret_paths(&self) -> [(&'static str, Option<&PathBuf>); 4] {
        [
            (
                "access_token_key_file",
                self.accounts.access_token_key_file.as_ref(),
            ),
            (
                "account_service_hpke_private_key_file",
                self.accounts.account_service_hpke_private_key_file.as_ref(),
            ),
            (
                "opaque_server_setup_file",
                self.accounts.opaque_server_setup_file.as_ref(),
            ),
            (
                "opaque_fake_credential_key_file",
                self.accounts.opaque_fake_credential_key_file.as_ref(),
            ),
        ]
    }

    /// Public text files: MOTD and public info (spec 9185-9186).
    pub(crate) fn public_text_paths(&self) -> Vec<(SchemaKey, PathBuf)> {
        let mut paths = Vec::new();
        push_optional(
            &mut paths,
            SchemaKey::new("privacy", "motd_file"),
            self.privacy.motd_file.as_ref(),
        );
        push_optional(
            &mut paths,
            SchemaKey::new("privacy", "public_info_file"),
            self.privacy.public_info_file.as_ref(),
        );
        paths
    }

    /// The two trust manifests.
    pub(crate) fn trust_manifest_paths(&self) -> Vec<(SchemaKey, PathBuf)> {
        vec![
            (
                SchemaKey::new("storage", "backup_trust_manifest_file"),
                self.storage.backup_trust_manifest_file.clone(),
            ),
            (
                SchemaKey::new("moderation", "audit_trust_manifest_file"),
                self.moderation.audit_trust_manifest_file.clone(),
            ),
        ]
    }

    /// Public listener certificate, private client-CA, and OCSP inputs.
    pub(crate) fn listener_material_paths(&self) -> Vec<(SchemaKey, PathBuf)> {
        let mut paths = Vec::new();
        for (index, listener) in self.listeners.iter().enumerate() {
            if !self.listener_material_required(listener) {
                continue;
            }
            let key =
                |field| SchemaKey::indexed("listeners.endpoint", paths::index_u16(index), field);
            if let Some(tls) = &listener.tls {
                paths.push((key("tls_certificate_file"), tls.certificate_file.clone()));
                push_optional(
                    &mut paths,
                    key("tls_ocsp_staple_file"),
                    tls.ocsp_staple_file.as_ref(),
                );
            }
            push_optional(
                &mut paths,
                key("client_ca_file"),
                listener.client_ca_file.as_ref(),
            );
        }
        paths
    }
}

fn push_optional(paths: &mut Vec<(SchemaKey, PathBuf)>, key: SchemaKey, path: Option<&PathBuf>) {
    if let Some(path) = path {
        paths.push((key, path.clone()));
    }
}

/// Loads one protected configuration file and validates it to the given depth.
pub fn load_config(path: &Path, depth: ValidationDepth) -> Result<Config, ConfigReport> {
    let mut sink = IssueSink::default();
    let text = sink.field(
        SchemaKey::new("", ""),
        read_protected_text(path, MAX_CONFIG_BYTES),
    );
    let resolver = sink.field(SchemaKey::new("", ""), PathResolver::for_config_file(path));
    match (text, resolver) {
        (Some(text), Some(resolver)) => Config::parse_text(&text, &resolver, depth),
        _ => Err(sink.into_report()),
    }
}

fn parse_tables(root: &Table, resolver: &PathResolver, sink: &mut IssueSink) -> Option<Config> {
    let root_key = |field| SchemaKey::new("", field);
    sink.field(root_key(""), check_keys(root, ROOT_KEYS))?;
    sink.field(root_key("config_version"), parse_version(root))?;
    let mut sub = |name: &'static str| sink.field(SchemaKey::new(name, ""), table(root, name));
    let tables = [
        sub("network"),
        sub("server"),
        sub("listeners"),
        sub("tls"),
        sub("federation"),
        sub("storage"),
        sub("accounts"),
        sub("limits"),
        sub("privacy"),
        sub("moderation"),
        sub("e2ee"),
    ];
    let [
        network_t,
        server_t,
        listeners_t,
        tls_t,
        federation_t,
        storage_t,
        accounts_t,
        limits_t,
        privacy_t,
        moderation_t,
        e2ee_t,
    ] = tables;
    let network = network_t.and_then(|t| network::parse(t, sink));
    let onion_only = network.as_ref().is_some_and(NetworkConfig::is_onion_only);
    let server = server_t.and_then(|t| server::parse(t, resolver, sink));
    let listeners = listeners_t.and_then(|t| listeners::parse(t, resolver, sink));
    let tls = tls_t.and_then(|t| tls::parse(t, sink));
    let federation = federation_t.and_then(|t| federation::parse(t, resolver, sink));
    let storage = storage_t.and_then(|t| storage::parse(t, resolver, sink));
    let accounts = accounts_t.and_then(|t| accounts::parse(t, resolver, onion_only, sink));
    let limits = limits_t.and_then(|t| limits::parse(t, sink));
    let privacy = privacy_t.and_then(|t| privacy::parse(t, resolver, sink));
    let moderation = moderation_t.and_then(|t| moderation::parse(t, resolver, sink));
    let e2ee = e2ee_t.and_then(|t| e2ee::parse(t, resolver, sink));
    Some(Config {
        network: network?,
        server: server?,
        listeners: listeners?,
        tls: tls?,
        federation: federation?,
        storage: storage?,
        accounts: accounts?,
        limits: limits?,
        privacy: privacy?,
        moderation: moderation?,
        e2ee: e2ee?,
    })
}

fn parse_version(root: &Table) -> Result<(), ConfigError> {
    if unsigned(root, "config_version")? != CONFIG_VERSION {
        return Err(ConfigError::InvalidValue);
    }
    Ok(())
}
