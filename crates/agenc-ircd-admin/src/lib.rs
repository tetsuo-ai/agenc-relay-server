#![forbid(unsafe_code)]

//! Administrative command parsing, challenge verification, permission mapping,
//! and audit record types for the Stage 06 administration surface.
//!
//! The crate is a pure boundary: it never opens a socket, reads a key file, or
//! touches storage. The runtime admin owner supplies the transport binding,
//! the monotonic clock, the confirmation token bytes, and the operator
//! registry, and consumes the closed `AdminEvent` values this crate returns.
//! Every parser is total and bounded by the Architecture 22.4 framing limits.

mod audit;
mod audit_event;
mod base64;
mod canonical;
mod challenge;
mod codec;
mod command;
mod confirm;
mod error;
mod framing;
mod maintenance;
mod operator;
mod session;
mod stats;
mod tag;
mod tbs;

pub use audit::{
    AdminAuditCheckpoint, AdminAuditCheckpointTbs, AdminAuditEvent, AdminAuditEventTbs,
    AdminAuditPhase, AuditChainCursor, AuditExportProfile, MAX_AUDIT_EVENT_BYTES,
    render_export_batch, render_export_batch_with_profile,
};
pub use audit_event::AuditEvent;
pub use base64::{decode_fixed_base64url, encode_base64url};
pub use canonical::{CanonicalCommand, MAX_COMMAND_PARAMETERS, parse_canonical_u64};
pub use challenge::{
    ADMIN_CHALLENGE_BYTES, ADMIN_SESSION_ID_BYTES, ADMIN_TRANSPORT_BINDING_BYTES, AdminChallenge,
    AdminSessionId, Challenge, TransportBinding, TransportKind,
};
pub use command::{
    AdminCommand, AuditRange, MAX_ADMIN_REASON_BYTES, MAX_PING_TOKEN_BYTES, MAX_SUSPENSION_SECONDS,
    MIN_ADMIN_REASON_BYTES, PingToken, Reason, SuspensionSeconds,
    UNCONFIRMED_SUSPENSION_MAX_SECONDS,
};
pub use confirm::{
    CONFIRMATION_TOKEN_BYTES, CONFIRMATION_TTL_MILLIS, CONFIRMATION_TTL_SECONDS, ConfirmationCheck,
    ConfirmationToken, PendingConfirmation,
};
pub use error::{AdminCloseReason, AdminError};
pub use framing::{
    MAX_ADMIN_COMMAND_BYTES, MAX_ADMIN_LINE_BYTES, MAX_ADMIN_OUTPUT_LINE_BYTES,
    MAX_ADMIN_TAG_PREFIX_BYTES, MAX_AUDIT_EXPORT_BYTES, MAX_AUDIT_EXPORT_RECORDS,
    MAX_PRE_AUTH_PINGS,
};
pub use maintenance::{
    MAINTENANCE_AUDIT_EVENT_BYTES, MAINTENANCE_AUDIT_TBS_BYTES, MaintenanceAuditEvent,
    MaintenanceAuditEventTbs, MaintenanceAuditPosition, MaintenanceAuditScope, MaintenanceKeyState,
    MaintenanceOperation, MaintenanceTransition,
};
pub use operator::{
    MAX_OPERATOR_GIDS, MAX_OPERATOR_RECORDS, MAX_OPERATOR_UIDS, OperatorRecord, OperatorRegistry,
    PeerIdentity,
};
pub use session::{
    AdminCommandEvent, AdminEvent, AdminSession, AdminSessionBinding, AdminSessionState,
    ConfirmationState,
};
pub use stats::{
    STATS_SIXTY_SECOND_BUCKETS, StatsSelector, StatsValues, checked_window_sum, render_stats_batch,
    render_stats_storage_unavailable, render_stats_unavailable,
};
pub use tag::{AdminLine, parse_admin_line, render_admin_tag};
pub use tbs::AdminCommandTbs;
