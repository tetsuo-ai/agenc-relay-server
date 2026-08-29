#![forbid(unsafe_code)]

//! Strict configuration parsing, host-policy validation, reload diffs, and the
//! closed observability vocabulary (Architecture 22, 25, and Appendix C).

mod accounts;
mod bounds;
mod config;
mod cross;
mod diff;
mod document;
mod e2ee;
mod error;
mod federation;
mod host;
mod limits;
mod listeners;
mod maintenance;
mod moderation;
mod network;
mod observability;
mod onboarding;
mod paths;
mod privacy;
mod scalar;
mod secrets;
mod server;
mod storage;
mod template;
mod tls;
mod trust;

pub use accounts::{AccountsConfig, DirectMessageDefault, RegistrationPolicy};
pub use bounds::*;
pub use config::{CONFIG_VERSION, Config, ValidationDepth, load_config};
pub use cross::{protocol_pool, working_set};
pub use diff::{ConfigDiff, ReloadPlan, ReloadRejected, ReloadableChange, RestartOnlyField};
pub use e2ee::E2eeConfig;
pub use error::{
    ConfigError, ConfigIssue, ConfigReport, MAX_REPORTED_ISSUES, SchemaKey, ValidationStage,
};
pub use federation::{FederationConfig, PeerConfig};
pub use host::{
    ControlState, HardeningOutcome, HostControl, HostControlReport, HostLimit, HostReader,
    HostSource, SystemHostReader, apply_process_hardening, probe_host_controls,
};
pub use limits::{
    LIMIT_COUNT, LIMIT_ROWS, LimitKey, LimitRow, LimitValues, LimitsConfig, RATE_COUNT, RATE_ROWS,
    RateKey, RateRow, RateSpec, RateTable,
};
pub use listeners::{
    ListenerBind, ListenerConfig, ListenerName, ListenerPurpose, LocalAdminPolicy, TlsFiles,
    WssPolicy,
};
pub use maintenance::{MaintenanceStorageConfig, load_maintenance_config};
pub use moderation::{ModerationConfig, OperatorConfig};
pub use network::{DisplayLabel, DnsEndpoint, NetworkConfig, NodeRole, OnionEndpoint};
pub use observability::{
    CommandClass, CorrelationNumber, CorrelationSource, CountBucket, DURATION_BUCKET_MILLIS,
    DurationBucket, Liveness, LogEvent, LogEventCode, LogEventFields, MetricLabel, PublicErrorCode,
    QueueName, ReadinessGate, ResultClass, SIZE_BUCKET_BYTES, Severity, TransportFamily,
};
pub use onboarding::{
    BASE_PROFILE_SHA256_TOKEN, E2EE_PROFILE_SHA256_TOKEN, E2EE_PROFILE_TOKEN, OnboardingFacts,
    render_onboarding,
};
pub use paths::PathResolver;
pub use privacy::{HistoryDefault, PrivacyConfig};
pub use scalar::{
    Bound, DnsName, HttpsOrigin, ONION_LABEL_BYTES, OnionAddress, PeerEndpoint, SocksEndpoint,
    encode_base64url_32,
};
pub use secrets::{
    FileIdentity, MAX_SECRET_BLOB_BYTES, SECRET_FILE_MODE, SecretBlob, SecretBytes32, SecretLength,
    SecretSet, open_secret_file, open_secret_file_with_hook, secret_paths,
};
pub use server::{ServerConfig, ShutdownPhases};
pub use storage::StorageConfig;
pub use template::{InitProfile, InitValues, OperatorTemplate, render_template};
pub use tls::{GroupPolicy, TlsConfig};
pub use trust::{
    AuditTrustManifestEntry, BackupTrustManifestEntry, load_audit_trust_manifest,
    load_backup_trust_manifest, parse_audit_trust_manifest, parse_backup_trust_manifest,
};
