//! The `[server]` table (spec C.2 8900-8915).

use std::path::PathBuf;

use agenc_ircd_types::ServerId;
use toml::Table;

use crate::bounds::{
    CRYPTO_WORKER_THREADS, DRAIN_SECONDS, FLUSH_SECONDS, MAX_SHUTDOWN_SECONDS, MEMORY_BUDGET_BYTES,
    QUIESCE_SECONDS, STOP_SECONDS, TOKIO_WORKER_THREADS,
};
use crate::document::{check_keys, optional_boolean, optional_unsigned, string};
use crate::error::{ConfigError, IssueSink, SchemaKey};
use crate::paths::PathResolver;
use crate::scalar::{DnsName, dns_name};

pub(crate) const SERVER_KEYS: &[&str] = &[
    "crypto_worker_threads",
    "data_dir",
    "drain_seconds",
    "flush_seconds",
    "memory_budget_bytes",
    "name",
    "quiesce_seconds",
    "require_locked_secrets",
    "runtime_dir",
    "server_id",
    "stop_seconds",
    "tokio_worker_threads",
];

/// The four bounded shutdown phases (spec 8907-8913, 4254-4267).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShutdownPhases {
    /// Close listeners and reject new mutations.
    pub quiesce_seconds: u64,
    /// Finish accepted durable batches.
    pub drain_seconds: u64,
    /// Persist cursors and flush writer queues.
    pub flush_seconds: u64,
    /// Cancel tasks and join threads.
    pub stop_seconds: u64,
}

impl ShutdownPhases {
    /// Returns the checked sum of the four phases.
    pub fn total_seconds(self) -> Result<u64, ConfigError> {
        self.quiesce_seconds
            .checked_add(self.drain_seconds)
            .and_then(|sum| sum.checked_add(self.flush_seconds))
            .and_then(|sum| sum.checked_add(self.stop_seconds))
            .ok_or(ConfigError::Overflow)
    }
}

/// The validated `[server]` table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerConfig {
    /// Permanent local server identity.
    pub server_id: ServerId,
    /// Section 7.4 server name.
    pub name: DnsName,
    /// Dedicated data directory.
    pub data_dir: PathBuf,
    /// Dedicated runtime directory.
    pub runtime_dir: PathBuf,
    /// Process memory budget `B`.
    pub memory_budget_bytes: u64,
    /// Tokio worker threads.
    pub tokio_worker_threads: u64,
    /// Crypto worker threads.
    pub crypto_worker_threads: u64,
    /// Shutdown phase budgets.
    pub shutdown: ShutdownPhases,
    /// Whether a failed secret memory lock is fatal.
    pub require_locked_secrets: bool,
}

const TABLE: &str = "server";

pub(crate) fn parse(
    table: &Table,
    resolver: &PathResolver,
    sink: &mut IssueSink,
) -> Option<ServerConfig> {
    let key = |field| SchemaKey::new(TABLE, field);
    sink.field(key(""), check_keys(table, SERVER_KEYS))?;
    let server_id = sink.field(
        key("server_id"),
        string(table, "server_id")
            .and_then(|text| ServerId::parse(text).map_err(|_| ConfigError::InvalidValue)),
    );
    let name = sink.field(key("name"), string(table, "name").and_then(dns_name));
    let data_dir = sink.field(
        key("data_dir"),
        string(table, "data_dir").and_then(|text| resolver.resolve(text)),
    );
    let runtime_dir = sink.field(
        key("runtime_dir"),
        string(table, "runtime_dir").and_then(|text| resolver.resolve(text)),
    );
    let memory_budget_bytes = bounded(table, "memory_budget_bytes", MEMORY_BUDGET_BYTES, sink);
    let tokio_worker_threads = bounded(table, "tokio_worker_threads", TOKIO_WORKER_THREADS, sink);
    let crypto_worker_threads =
        bounded(table, "crypto_worker_threads", CRYPTO_WORKER_THREADS, sink);
    let shutdown = parse_shutdown(table, sink);
    let require_locked_secrets = sink.field(
        key("require_locked_secrets"),
        optional_boolean(table, "require_locked_secrets").map(|value| value.unwrap_or(false)),
    );
    Some(ServerConfig {
        server_id: server_id?,
        name: name?,
        data_dir: data_dir?,
        runtime_dir: runtime_dir?,
        memory_budget_bytes: memory_budget_bytes?,
        tokio_worker_threads: tokio_worker_threads?,
        crypto_worker_threads: crypto_worker_threads?,
        shutdown: shutdown?,
        require_locked_secrets: require_locked_secrets?,
    })
}

fn bounded(
    table: &Table,
    field: &'static str,
    bound: crate::scalar::Bound,
    sink: &mut IssueSink,
) -> Option<u64> {
    sink.field(
        SchemaKey::new(TABLE, field),
        optional_unsigned(table, field).and_then(|value| bound.resolve(value)),
    )
}

fn parse_shutdown(table: &Table, sink: &mut IssueSink) -> Option<ShutdownPhases> {
    let quiesce_seconds = bounded(table, "quiesce_seconds", QUIESCE_SECONDS, sink);
    let drain_seconds = bounded(table, "drain_seconds", DRAIN_SECONDS, sink);
    let flush_seconds = bounded(table, "flush_seconds", FLUSH_SECONDS, sink);
    let stop_seconds = bounded(table, "stop_seconds", STOP_SECONDS, sink);
    let phases = ShutdownPhases {
        quiesce_seconds: quiesce_seconds?,
        drain_seconds: drain_seconds?,
        flush_seconds: flush_seconds?,
        stop_seconds: stop_seconds?,
    };
    // The four values sum to no more than 120 seconds (spec 8913).
    let total = sink.field(
        SchemaKey::new(TABLE, "stop_seconds"),
        phases.total_seconds(),
    )?;
    if total > MAX_SHUTDOWN_SECONDS {
        return sink.field(
            SchemaKey::new(TABLE, "stop_seconds"),
            Err(ConfigError::InvalidValue),
        );
    }
    Some(phases)
}
