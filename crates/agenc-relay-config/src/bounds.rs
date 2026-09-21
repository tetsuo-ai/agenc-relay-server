//! Named bounds, defaults, and fixed values from Appendix C.2 through C.7.
//!
//! Every constant cites the spec line that fixes it so a reviewer can compare
//! the table and the code without searching.

use crate::scalar::Bound;

/// Largest configuration or manifest document accepted (1 MiB).
pub const MAX_CONFIG_BYTES: u64 = 1_048_576;
/// Largest MOTD or public-info file (spec 9185-9186).
pub const MAX_PUBLIC_TEXT_BYTES: u64 = 65_536;
/// Most lines in a MOTD or public-info file (spec 9185-9186).
pub const MAX_PUBLIC_TEXT_LINES: usize = 256;

/// `network.display_name` byte range (spec 8892).
pub const DISPLAY_NAME_BYTES: (usize, usize) = (1, 32);
/// `network.dns_port` and `network.onion_port` (spec 8896, 8898).
pub const ENDPOINT_PORT: Bound = Bound::new(1, 6_697, 65_535);
/// `server.name` ceiling when federation is enabled (spec 8901, 2950).
pub const MAX_FEDERATED_SERVER_NAME_BYTES: usize = 127;
/// `server.memory_budget_bytes` (spec 8904).
pub const MEMORY_BUDGET_BYTES: Bound = Bound::new(536_870_912, 6_442_450_944, 1_099_511_627_776);
/// `server.tokio_worker_threads` (spec 8905).
pub const TOKIO_WORKER_THREADS: Bound = Bound::new(2, 4, 128);
/// `server.crypto_worker_threads` (spec 8906).
pub const CRYPTO_WORKER_THREADS: Bound = Bound::new(1, 4, 128);
/// `server.quiesce_seconds` (spec 8907).
pub const QUIESCE_SECONDS: Bound = Bound::new(1, 5, 30);
/// `server.drain_seconds` (spec 8908).
pub const DRAIN_SECONDS: Bound = Bound::new(1, 20, 60);
/// `server.flush_seconds` (spec 8909).
pub const FLUSH_SECONDS: Bound = Bound::new(1, 10, 30);
/// `server.stop_seconds` (spec 8910).
pub const STOP_SECONDS: Bound = Bound::new(1, 5, 30);
/// Sum ceiling of the four shutdown phases (spec 8913).
pub const MAX_SHUTDOWN_SECONDS: u64 = 120;

/// `[[listeners.endpoint]]` element count (spec 8920).
pub const LISTENER_COUNT: (usize, usize) = (1, 16);
/// Listener `name` byte range (spec 8925).
pub const LISTENER_NAME_BYTES: (usize, usize) = (1, 32);
/// `allowed_origins` element ceiling (spec 8935).
pub const MAX_ALLOWED_ORIGINS: usize = 64;
/// `allowed_uids` element range (spec 8937).
pub const ALLOWED_UIDS: (usize, usize) = (1, 64);
/// `allowed_gids` element ceiling (spec 8938).
pub const MAX_ALLOWED_GIDS: usize = 64;
/// Federation and admin listener `max_connections` ceiling (spec 8941-8942).
pub const MAX_FEDERATION_OR_ADMIN_CONNECTIONS: u64 = 64;

/// `tls.ticket_rotation_seconds`, fixed in v1 (spec 8969).
pub const TICKET_ROTATION_SECONDS: Bound = Bound::new(21_600, 21_600, 21_600);
/// `tls.ticket_lifetime_seconds`, fixed in v1 (spec 8970).
pub const TICKET_LIFETIME_SECONDS: Bound = Bound::new(86_400, 86_400, 86_400);
/// `federation.connect_timeout_seconds` (spec 8978).
pub const CONNECT_TIMEOUT_SECONDS: Bound = Bound::new(1, 10, 30);
/// `federation.reconnect_max_seconds`, fixed in v1 (spec 8979).
pub const RECONNECT_MAX_SECONDS: Bound = Bound::new(60, 60, 60);
/// `federation.max_peers`, fixed in v1 (spec 8980).
pub const MAX_PEERS: Bound = Bound::new(64, 64, 64);
/// `[[federation.peer]]` element ceiling (spec 8985).
pub const MAX_PEER_RECORDS: usize = 64;
/// Peer `endpoints` element ceiling (spec 8993).
pub const MAX_PEER_ENDPOINTS: usize = 8;

/// `storage.database_max_bytes` (spec 9016).
pub const DATABASE_MAX_BYTES: Bound = Bound::new(1_073_741_824, 85_899_345_920, 1_099_511_627_776);
/// `storage.backup_max_bytes` (spec 9017).
pub const BACKUP_MAX_BYTES: Bound = Bound::new(1_073_741_824, 107_374_182_400, 1_099_511_627_776);
/// `storage.disk_reserve_bytes` (spec 9018).
pub const DISK_RESERVE_BYTES: Bound = Bound::new(67_108_864, 1_073_741_824, 1_099_511_627_776);
/// `storage.disk_reserve_percent` (spec 9019).
pub const DISK_RESERVE_PERCENT: Bound = Bound::new(1, 5, 25);
/// `storage.integrity_checkpoint_manifests` (spec 9020).
pub const INTEGRITY_CHECKPOINT_MANIFESTS: Bound = Bound::new(10_000, 100_000, 1_000_000);
/// Cache bytes handed to the offline redb owner by maintenance commands.
pub const DEFAULT_REDB_CACHE_BYTES: usize = 67_108_864;
/// Trust manifest key rows, mirroring `agenc_relay_storage::MAX_BACKUP_TRUST_KEYS`.
pub const MAX_TRUST_MANIFEST_KEYS: usize = 1_024;

/// `accounts.max_contacts` (spec 9033).
pub const MAX_CONTACTS: Bound = Bound::new(1, 1_000, 10_000);
/// `accounts.max_reserved_nicknames`, fixed in v1 (spec 9034).
pub const MAX_RESERVED_NICKNAMES: Bound = Bound::new(5, 5, 5);
/// `accounts.auth_transaction_seconds`, fixed in v1 (spec 9035).
pub const AUTH_TRANSACTION_SECONDS: Bound = Bound::new(30, 30, 30);
/// `accounts.create_transaction_seconds`, fixed in v1 (spec 9036).
pub const CREATE_TRANSACTION_SECONDS: Bound = Bound::new(60, 60, 60);
/// `accounts.credential_change_transaction_seconds`, fixed in v1 (spec 9037).
pub const CREDENTIAL_CHANGE_TRANSACTION_SECONDS: Bound = Bound::new(60, 60, 60);

/// `privacy.log_retention_hours` (spec 9182).
pub const LOG_RETENTION_HOURS: Bound = Bound::new(1, 24, 720);
/// `privacy.secret_lookup_floor_milliseconds` (spec 9185).
pub const SECRET_LOOKUP_FLOOR_MILLISECONDS: Bound = Bound::new(1, 5, 50);
/// `privacy.whowas_retention_seconds`, fixed in v1 (spec 9186).
pub const WHOWAS_RETENTION_SECONDS: Bound = Bound::new(900, 900, 900);
/// `privacy.whowas_records` (spec 9187).
pub const WHOWAS_RECORDS: Bound = Bound::new(1, 10_000, 10_000);
/// `moderation.audit_retention_days` (spec 9192).
pub const AUDIT_RETENTION_DAYS: Bound = Bound::new(30, 30, 365);
/// `moderation.session_sanction_hours` (spec 9193).
pub const SESSION_SANCTION_HOURS: Bound = Bound::new(1, 24, 720);
/// `moderation.account_sanction_days` (spec 9194).
pub const ACCOUNT_SANCTION_DAYS: Bound = Bound::new(1, 30, 365);
/// `moderation.free_reason_bytes`, fixed in v1 (spec 9195).
pub const FREE_REASON_BYTES: Bound = Bound::new(512, 512, 512);
/// `[[moderation.operator]]` element count (spec 9258).
pub const OPERATOR_COUNT: (usize, usize) = (1, 64);
/// Operator `display_label` byte range (spec 9263).
pub const OPERATOR_LABEL_BYTES: (usize, usize) = (1, 32);
/// Operator `local_uids` and `local_gids` element ceiling (spec 9266-9267).
pub const MAX_OPERATOR_IDS: usize = 16;

/// `e2ee.profile_version`, fixed (spec 9197).
pub const E2EE_PROFILE_VERSION: Bound = Bound::new(1, 1, 1);
/// `e2ee.max_group_leaves`; companion `MAX_GROUP_LEAVES` is 512 (spec 9201).
pub const MAX_GROUP_LEAVES: Bound = Bound::new(1, 512, 512);
/// `e2ee.max_devices_per_account`; companion `MAX_ACTIVE_DEVICES_PER_ACCOUNT` is 64 (spec 9202).
pub const MAX_DEVICES_PER_ACCOUNT: Bound = Bound::new(1, 64, 64);
/// `e2ee.mailbox_bytes_per_account`; companion maximum 67,108,864 (spec 9203).
pub const MAILBOX_BYTES_PER_ACCOUNT: Bound = Bound::new(1_048_576, 67_108_864, 67_108_864);
/// `e2ee.directory_bytes_per_account`; companion maximum 8,388,608 (spec 9204).
pub const DIRECTORY_BYTES_PER_ACCOUNT: Bound = Bound::new(1_048_576, 8_388_608, 8_388_608);
/// `e2ee.stored_bytes_per_conversation`; companion maximum 268,435,456 (spec 9205).
pub const STORED_BYTES_PER_CONVERSATION: Bound = Bound::new(1_048_576, 268_435_456, 268_435_456);
/// `e2ee.global_disk_bytes` (spec 9206).
pub const E2EE_GLOBAL_DISK_BYTES: Bound =
    Bound::new(1_073_741_824, 107_374_182_400, 17_592_186_044_416);
/// `e2ee.federation_peer_bytes_per_second` (spec 9207).
pub const FEDERATION_PEER_BYTES_PER_SECOND: Bound = Bound::new(65_536, 16_777_216, 1_073_741_824);
/// `e2ee.federation_peer_burst_bytes` (spec 9208).
pub const FEDERATION_PEER_BURST_BYTES: Bound = Bound::new(4_194_304, 33_554_432, 4_294_967_296);
/// Burst may not exceed this many seconds of the peer rate (spec 9235).
pub const MAX_BURST_SECONDS_OF_RATE: u64 = 10;

/// Rate table field ranges (spec 9160).
pub const RATE_REFILL_TOKENS: Bound = Bound::new(1, 1, 1_000);
/// `refill_seconds` range (spec 9160).
pub const RATE_REFILL_SECONDS: Bound = Bound::new(1, 1, 3_600);
/// `burst` range (spec 9160).
pub const RATE_BURST: Bound = Bound::new(1, 1, 1_000);

/// Fixed overload thresholds in percent (spec 9174-9177, 2816-2829).
pub const OVERLOAD_GUEST_STOP_PERCENT: u8 = 80;
/// Threshold at which every new connection and channel creation stops.
pub const OVERLOAD_CONNECTION_STOP_PERCENT: u8 = 90;
/// Threshold at which whole connections are evicted.
pub const OVERLOAD_EVICT_PERCENT: u8 = 95;
/// Recovery threshold below which eviction stops.
pub const OVERLOAD_RECOVER_PERCENT: u8 = 85;

/// Fixed runtime and allocator headroom floor (spec 2762).
pub const HEADROOM_FLOOR_BYTES: u64 = 268_435_456;
/// One storage handoff slot reservation (spec 2763, 2793).
pub const STORAGE_SLOT_BYTES: u64 = 58_720_240;
/// Number of storage handoff slots backed by `D` (spec 2763).
pub const STORAGE_SLOTS: u64 = 2;
/// One crypto worker reservation (spec 2764, 2801).
pub const CRYPTO_WORKER_BYTES: u64 = 75_497_472;
/// Allocation charge quantum and pad (spec 2720-2723).
pub const ALLOCATION_QUANTUM: u64 = 4_096;
/// Fixed pad added to every nonzero allocation before rounding.
pub const ALLOCATION_PAD: u64 = 256;
/// Client base charge (spec 2741).
pub const CLIENT_BASE_CHARGE: u64 = 65_536;
/// Federation base charge (spec 2742).
pub const FEDERATION_BASE_CHARGE: u64 = 262_144;
/// Admin base charge (spec 2743).
pub const ADMIN_BASE_CHARGE: u64 = 65_536;
/// Client physical line ceiling used by the working-set rows (spec 2777-2783, 574).
pub const CLIENT_PHYSICAL_LINE_BYTES: u64 = 8_703;
/// Client command ceiling used by the WSS working-set row (spec 2779).
pub const CLIENT_COMMAND_BYTES: u64 = 8_701;
/// Federation frame ceiling used by the working-set row (spec 2780).
pub const FEDERATION_FRAME_BYTES: u64 = 16_777_216;
/// Minimum TLS client working set beyond the arena (spec 2777).
pub const CLIENT_TLS_WORKING_SET_FLOOR: u64 = 262_144;
/// Minimum WSS client working set beyond the arena (spec 2779).
pub const CLIENT_WSS_WORKING_SET_FLOOR: u64 = 327_680;
/// Minimum federation working set (spec 2780).
pub const FEDERATION_WORKING_SET_FLOOR: u64 = 262_144;
/// Minimum admin TLS working set (spec 2782).
pub const ADMIN_TLS_WORKING_SET_FLOOR: u64 = 262_144;

/// Returns `4096 * ceil((n + 256) / 4096)` for nonzero `n` and zero for zero (spec 2720-2723).
pub fn allocation_charge(bytes: u64) -> Option<u64> {
    if bytes == 0 {
        return Some(0);
    }
    let padded = bytes.checked_add(ALLOCATION_PAD)?;
    let quanta = padded.div_ceil(ALLOCATION_QUANTUM);
    quanta.checked_mul(ALLOCATION_QUANTUM)
}
