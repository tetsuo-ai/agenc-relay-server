//! The few companion limits the pure domain models need. The e2ee crate
//! owns the complete Section 16 table and asserts these copies equal it.

/// `MAX_CANDIDATE_ATTEMPTS_PER_EPOCH`.
pub const MAX_CANDIDATE_ATTEMPTS_PER_EPOCH: u32 = 8;
/// `MIN_KEY_PACKAGE_CLAIM_VALIDITY` in seconds.
pub const MIN_KEY_PACKAGE_CLAIM_VALIDITY_SECONDS: u64 = 60 * 60;
/// `MAX_KEY_PACKAGE_LIFETIME` in seconds.
pub const MAX_KEY_PACKAGE_LIFETIME_SECONDS: u64 = 7 * 24 * 60 * 60;
/// `KEY_PACKAGE_CLAIM_TIMEOUT` in seconds.
pub const KEY_PACKAGE_CLAIM_TIMEOUT_SECONDS: u64 = 7 * 24 * 60 * 60;
/// `JOIN_CONFIRMATION_TIMEOUT` in seconds.
pub const JOIN_CONFIRMATION_TIMEOUT_SECONDS: u64 = 60 * 60;
/// `ATTACH_CHALLENGE_TIMEOUT` in seconds.
pub const ATTACH_CHALLENGE_TIMEOUT_SECONDS: u64 = 60;
/// `MAILBOX_DELIVERY_TOKEN_TIMEOUT` in seconds.
pub const MAILBOX_DELIVERY_TOKEN_TIMEOUT_SECONDS: u64 = 10 * 60;
/// `MAILBOX_ACK_RETENTION` in seconds.
pub const MAILBOX_ACK_RETENTION_SECONDS: u64 = 30 * 60;
/// `WELCOME_RETENTION` in seconds.
pub const WELCOME_RETENTION_SECONDS: u64 = 7 * 24 * 60 * 60;
/// `MAX_BATCH_OBJECTS`.
pub const MAX_BATCH_OBJECTS: usize = 32;
/// `MAX_ACTIVE_DEVICES_PER_ACCOUNT`.
pub const MAX_ACTIVE_DEVICES_PER_ACCOUNT: usize = 64;
/// `MAX_UNACKED_E2EE_EVENTS_PER_EDGE`.
pub const MAX_UNACKED_E2EE_EVENTS_PER_EDGE: u64 = 262_144;
/// `MAX_UNACKED_E2EE_EVENT_BYTES_PER_EDGE`.
pub const MAX_UNACKED_E2EE_EVENT_BYTES_PER_EDGE: u64 = 1_073_741_824;
/// The cross-profile aggregate ceiling per target mutation.
pub const MAX_CROSS_PROFILE_AGGREGATE_BYTES: u64 = 16_777_216;
/// The cross-profile part count bounds.
pub const MAX_CROSS_PROFILE_PARTS: usize = 2_048;
