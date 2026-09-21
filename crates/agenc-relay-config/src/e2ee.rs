//! The `[e2ee]` table (spec C.7 9196-9208, 9230-9236).

use std::path::PathBuf;

use agenc_relay_types::ServerId;
use toml::Table;

use crate::bounds::{
    DIRECTORY_BYTES_PER_ACCOUNT, E2EE_GLOBAL_DISK_BYTES, E2EE_PROFILE_VERSION,
    FEDERATION_PEER_BURST_BYTES, FEDERATION_PEER_BYTES_PER_SECOND, MAILBOX_BYTES_PER_ACCOUNT,
    MAX_DEVICES_PER_ACCOUNT, MAX_GROUP_LEAVES, STORED_BYTES_PER_CONVERSATION,
};
use crate::document::{check_keys, optional_boolean, optional_string, optional_unsigned};
use crate::error::{ConfigError, IssueSink, SchemaKey};
use crate::federation::optional_path;
use crate::paths::PathResolver;

pub(crate) const E2EE_KEYS: &[&str] = &[
    "coordinator_server_id",
    "directory_bytes_per_account",
    "enabled",
    "federation_peer_burst_bytes",
    "federation_peer_bytes_per_second",
    "global_disk_bytes",
    "mailbox_bytes_per_account",
    "max_devices_per_account",
    "max_group_leaves",
    "profile_version",
    "sequencer_credentials_file",
    "sequencer_private_key_file",
    "sequencer_retired_private_key_file",
    "sequencer_successor_private_key_file",
    "stored_bytes_per_conversation",
];

/// The validated `[e2ee]` table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct E2eeConfig {
    /// Whether the companion profile is enabled.
    pub enabled: bool,
    /// Profile version, fixed at 1.
    pub profile_version: u64,
    /// The E2EE coordinator, required when enabled.
    pub coordinator_server_id: Option<ServerId>,
    /// Sequencer private key file, only on the logical E2EE coordinator.
    pub sequencer_private_key_file: Option<PathBuf>,
    /// The successor credential's private key, present exactly while the
    /// credentials file holds a successor.
    pub sequencer_successor_private_key_file: Option<PathBuf>,
    /// The retired-retained private key of one credential absent from the
    /// advertised set that a normal route or an unfinished receipt still
    /// names.
    pub sequencer_retired_private_key_file: Option<PathBuf>,
    /// Public sequencer credentials, required when enabled.
    pub sequencer_credentials_file: Option<PathBuf>,
    /// Group leaf ceiling.
    pub max_group_leaves: u64,
    /// Device ceiling per account.
    pub max_devices_per_account: u64,
    /// Mailbox byte ceiling per account.
    pub mailbox_bytes_per_account: u64,
    /// Directory byte ceiling per account.
    pub directory_bytes_per_account: u64,
    /// Stored byte ceiling per conversation.
    pub stored_bytes_per_conversation: u64,
    /// Global logical E2EE disk ceiling.
    pub global_disk_bytes: u64,
    /// Per-peer decoded byte rate.
    pub federation_peer_bytes_per_second: u64,
    /// Per-peer burst bytes.
    pub federation_peer_burst_bytes: u64,
}

const TABLE: &str = "e2ee";

pub(crate) fn parse(
    table: &Table,
    resolver: &PathResolver,
    sink: &mut IssueSink,
) -> Option<E2eeConfig> {
    let key = |field| SchemaKey::new(TABLE, field);
    sink.field(key(""), check_keys(table, E2EE_KEYS))?;
    let enabled = sink.field(
        key("enabled"),
        optional_boolean(table, "enabled").map(|value| value.unwrap_or(true)),
    );
    let profile_version = sink.field(
        key("profile_version"),
        optional_unsigned(table, "profile_version")
            .and_then(|value| E2EE_PROFILE_VERSION.fixed(value)),
    );
    let coordinator_server_id = sink.field(
        key("coordinator_server_id"),
        parse_coordinator(table, enabled.unwrap_or(true)),
    );
    let sequencer_private_key_file = sink.field(
        key("sequencer_private_key_file"),
        optional_path(table, "sequencer_private_key_file", resolver),
    );
    let sequencer_successor_private_key_file = sink.field(
        key("sequencer_successor_private_key_file"),
        optional_path(table, "sequencer_successor_private_key_file", resolver),
    );
    let sequencer_retired_private_key_file = sink.field(
        key("sequencer_retired_private_key_file"),
        optional_path(table, "sequencer_retired_private_key_file", resolver),
    );
    let sequencer_credentials_file = sink.field(
        key("sequencer_credentials_file"),
        parse_credentials(table, resolver, enabled.unwrap_or(true)),
    );
    let ceilings = parse_ceilings(table, sink);
    let ceilings = ceilings?;
    Some(E2eeConfig {
        enabled: enabled?,
        profile_version: profile_version?,
        coordinator_server_id: coordinator_server_id?,
        sequencer_private_key_file: sequencer_private_key_file?,
        sequencer_successor_private_key_file: sequencer_successor_private_key_file?,
        sequencer_retired_private_key_file: sequencer_retired_private_key_file?,
        sequencer_credentials_file: sequencer_credentials_file?,
        max_group_leaves: ceilings.max_group_leaves,
        max_devices_per_account: ceilings.max_devices_per_account,
        mailbox_bytes_per_account: ceilings.mailbox_bytes_per_account,
        directory_bytes_per_account: ceilings.directory_bytes_per_account,
        stored_bytes_per_conversation: ceilings.stored_bytes_per_conversation,
        global_disk_bytes: ceilings.global_disk_bytes,
        federation_peer_bytes_per_second: ceilings.federation_peer_bytes_per_second,
        federation_peer_burst_bytes: ceilings.federation_peer_burst_bytes,
    })
}

fn parse_coordinator(table: &Table, enabled: bool) -> Result<Option<ServerId>, ConfigError> {
    // Required exactly when the profile is enabled (spec 9198).
    match optional_string(table, "coordinator_server_id")? {
        None if enabled => Err(ConfigError::MissingValue),
        None => Ok(None),
        Some(text) => ServerId::parse(text)
            .map(Some)
            .map_err(|_| ConfigError::InvalidValue),
    }
}

fn parse_credentials(
    table: &Table,
    resolver: &PathResolver,
    enabled: bool,
) -> Result<Option<PathBuf>, ConfigError> {
    // Required when enabled (spec 9200).
    match optional_path(table, "sequencer_credentials_file", resolver)? {
        None if enabled => Err(ConfigError::MissingValue),
        value => Ok(value),
    }
}

struct Ceilings {
    max_group_leaves: u64,
    max_devices_per_account: u64,
    mailbox_bytes_per_account: u64,
    directory_bytes_per_account: u64,
    stored_bytes_per_conversation: u64,
    global_disk_bytes: u64,
    federation_peer_bytes_per_second: u64,
    federation_peer_burst_bytes: u64,
}

fn parse_ceilings(table: &Table, sink: &mut IssueSink) -> Option<Ceilings> {
    let mut bounded = |field: &'static str, bound: crate::scalar::Bound| {
        sink.field(
            SchemaKey::new(TABLE, field),
            optional_unsigned(table, field).and_then(|value| bound.resolve(value)),
        )
    };
    let max_group_leaves = bounded("max_group_leaves", MAX_GROUP_LEAVES);
    let max_devices_per_account = bounded("max_devices_per_account", MAX_DEVICES_PER_ACCOUNT);
    let mailbox_bytes_per_account = bounded("mailbox_bytes_per_account", MAILBOX_BYTES_PER_ACCOUNT);
    let directory_bytes_per_account =
        bounded("directory_bytes_per_account", DIRECTORY_BYTES_PER_ACCOUNT);
    let stored_bytes_per_conversation = bounded(
        "stored_bytes_per_conversation",
        STORED_BYTES_PER_CONVERSATION,
    );
    let global_disk_bytes = bounded("global_disk_bytes", E2EE_GLOBAL_DISK_BYTES);
    let federation_peer_bytes_per_second = bounded(
        "federation_peer_bytes_per_second",
        FEDERATION_PEER_BYTES_PER_SECOND,
    );
    let federation_peer_burst_bytes =
        bounded("federation_peer_burst_bytes", FEDERATION_PEER_BURST_BYTES);
    Some(Ceilings {
        max_group_leaves: max_group_leaves?,
        max_devices_per_account: max_devices_per_account?,
        mailbox_bytes_per_account: mailbox_bytes_per_account?,
        directory_bytes_per_account: directory_bytes_per_account?,
        stored_bytes_per_conversation: stored_bytes_per_conversation?,
        global_disk_bytes: global_disk_bytes?,
        federation_peer_bytes_per_second: federation_peer_bytes_per_second?,
        federation_peer_burst_bytes: federation_peer_burst_bytes?,
    })
}
