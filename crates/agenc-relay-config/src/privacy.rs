//! The `[privacy]` table (spec C.7 9181-9188).

use std::path::PathBuf;

use toml::Table;

use crate::bounds::{
    LOG_RETENTION_HOURS, SECRET_LOOKUP_FLOOR_MILLISECONDS, WHOWAS_RECORDS, WHOWAS_RETENTION_SECONDS,
};
use crate::document::{check_keys, optional_boolean, optional_string, optional_unsigned};
use crate::error::{ConfigError, IssueSink, SchemaKey};
use crate::federation::optional_path;
use crate::paths::PathResolver;
use crate::scalar::closed_enum;

pub(crate) const PRIVACY_KEYS: &[&str] = &[
    "history_default",
    "history_enabled",
    "log_retention_hours",
    "motd_file",
    "public_info_file",
    "secret_lookup_floor_milliseconds",
    "whowas_records",
    "whowas_retention_seconds",
];

/// The default history retention copied on explicit owner enable (spec 9184).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum HistoryDefault {
    /// One hour.
    OneHour,
    /// One day.
    OneDay,
    /// Seven days.
    SevenDays,
}

impl HistoryDefault {
    /// Returns the configuration spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OneHour => "1h",
            Self::OneDay => "24h",
            Self::SevenDays => "7d",
        }
    }
}

/// The validated `[privacy]` table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyConfig {
    /// Operational log retention, 1..720 hours.
    pub log_retention_hours: u64,
    /// Whether the history capability is enabled at all.
    pub history_enabled: bool,
    /// Default retention copied on explicit enable.
    pub history_default: HistoryDefault,
    /// Secret-channel lookup timing floor, 1..50 milliseconds.
    pub secret_lookup_floor_milliseconds: u64,
    /// WHOWAS retention, fixed at 900 seconds.
    pub whowas_retention_seconds: u64,
    /// WHOWAS record ceiling.
    pub whowas_records: u64,
    /// Optional public MOTD text file.
    pub motd_file: Option<PathBuf>,
    /// Optional public ADMIN/INFO text file.
    pub public_info_file: Option<PathBuf>,
}

const TABLE: &str = "privacy";

pub(crate) fn parse(
    table: &Table,
    resolver: &PathResolver,
    sink: &mut IssueSink,
) -> Option<PrivacyConfig> {
    let key = |field| SchemaKey::new(TABLE, field);
    sink.field(key(""), check_keys(table, PRIVACY_KEYS))?;
    let log_retention_hours = sink.field(
        key("log_retention_hours"),
        optional_unsigned(table, "log_retention_hours")
            .and_then(|value| LOG_RETENTION_HOURS.resolve(value)),
    );
    let history_enabled = sink.field(
        key("history_enabled"),
        optional_boolean(table, "history_enabled").and_then(|value| {
            let enabled = value.unwrap_or(false);
            if enabled && !cfg!(feature = "history") {
                return Err(ConfigError::InvalidValue);
            }
            Ok(enabled)
        }),
    );
    let history_default = sink.field(key("history_default"), parse_history_default(table));
    let secret_lookup_floor_milliseconds = sink.field(
        key("secret_lookup_floor_milliseconds"),
        optional_unsigned(table, "secret_lookup_floor_milliseconds")
            .and_then(|value| SECRET_LOOKUP_FLOOR_MILLISECONDS.resolve(value)),
    );
    let whowas_retention_seconds = sink.field(
        key("whowas_retention_seconds"),
        optional_unsigned(table, "whowas_retention_seconds")
            .and_then(|value| WHOWAS_RETENTION_SECONDS.fixed(value)),
    );
    let whowas_records = sink.field(
        key("whowas_records"),
        optional_unsigned(table, "whowas_records").and_then(|value| WHOWAS_RECORDS.resolve(value)),
    );
    let motd_file = sink.field(
        key("motd_file"),
        optional_path(table, "motd_file", resolver),
    );
    let public_info_file = sink.field(
        key("public_info_file"),
        optional_path(table, "public_info_file", resolver),
    );
    Some(PrivacyConfig {
        log_retention_hours: log_retention_hours?,
        history_enabled: history_enabled?,
        history_default: history_default?,
        secret_lookup_floor_milliseconds: secret_lookup_floor_milliseconds?,
        whowas_retention_seconds: whowas_retention_seconds?,
        whowas_records: whowas_records?,
        motd_file: motd_file?,
        public_info_file: public_info_file?,
    })
}

fn parse_history_default(table: &Table) -> Result<HistoryDefault, ConfigError> {
    match optional_string(table, "history_default")? {
        None => Ok(HistoryDefault::OneDay),
        Some(text) => closed_enum(
            text,
            &[
                ("1h", HistoryDefault::OneHour),
                ("24h", HistoryDefault::OneDay),
                ("7d", HistoryDefault::SevenDays),
            ],
        ),
    }
}
