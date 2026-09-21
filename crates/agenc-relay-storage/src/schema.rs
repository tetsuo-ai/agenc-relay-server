//! Closed version-one table and record schema registry.

use crate::StorageError;

/// Database format implemented by this crate.
pub const DATABASE_FORMAT: u16 = 1;
/// Schema generation accepted by ordinary service startup.
pub const SCHEMA_GENERATION: u64 = 5;
/// Maximum stored key length.
pub const MAX_STORED_KEY_BYTES: usize = 4_096;
/// Maximum integrity-tracked mutations in one manifest.
pub const MAX_TRACKED_MUTATIONS: usize = 65_535;
/// Maximum transaction plans batched by the state owner.
pub const MAX_TRANSACTION_PLANS: usize = 256;
/// Maximum number of nonce draws under one storage key generation.
pub const MAX_NONCE_DRAWS: u64 = 1_u64 << 40;
/// Maximum combined growth admitted for one transaction and guard replacement.
pub const MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH: u64 = 268_435_456;
/// Fixed byte reservation backing each storage handoff slot.
pub const STORAGE_HANDOFF_SLOT_BYTES: u64 = 58_720_240;

/// Closed numeric registry of every encrypted database table.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum TableId {
    /// Database key-check object.
    KeyCheck = 0,
    /// Account authority and policy.
    Account = 1,
    /// Private keyed login lookup.
    LoginIndex = 2,
    /// OPAQUE registration records.
    OpaqueRecord = 3,
    /// Bounded authentication transactions.
    AuthTransaction = 4,
    /// Private nickname reservations.
    NicknameReservation = 5,
    /// Account-creation invitation state.
    RegistrationInvite = 6,
    /// Durable session and tombstone state.
    Session = 7,
    /// Channel instance state.
    Channel = 8,
    /// Private keyed channel-name lookup.
    ChannelName = 9,
    /// Typed sanctions.
    Sanction = 10,
    /// Federation peer state.
    FederationPeer = 11,
    /// Federation origin state.
    FederationOrigin = 12,
    /// Idempotent request results.
    RequestResult = 13,
    /// Authenticated global storage counters.
    StateMeta = 14,
    /// Mutation integrity ledger.
    IntegrityManifest = 15,
    /// Compact record-set checkpoints.
    IntegrityCheckpoint = 16,
    /// Durable edge delivery outbox.
    EdgeOutbox = 17,
    /// Edge projection generations.
    EdgeProjection = 18,
    /// Optional plaintext-history records.
    History = 19,
    /// Signed security audit events.
    Audit = 20,
    /// Signed audit deletion checkpoints.
    AuditCheckpoint = 21,
    /// Opaque E2EE companion objects.
    E2eeObject = 22,
    /// E2EE route and replay state.
    E2eeState = 23,
    /// Current and previous login-index key state.
    LoginIndexKeyState = 24,
    /// In-progress offline construction ledger.
    StorageConstruction = 25,
    /// Completed storage operation provenance.
    StorageOperation = 26,
}

impl TableId {
    /// Parses the closed version-one numeric registry.
    pub const fn from_u16(value: u16) -> Result<Self, StorageError> {
        match value {
            0 => Ok(Self::KeyCheck),
            1 => Ok(Self::Account),
            2 => Ok(Self::LoginIndex),
            3 => Ok(Self::OpaqueRecord),
            4 => Ok(Self::AuthTransaction),
            5 => Ok(Self::NicknameReservation),
            6 => Ok(Self::RegistrationInvite),
            7 => Ok(Self::Session),
            8 => Ok(Self::Channel),
            9 => Ok(Self::ChannelName),
            10 => Ok(Self::Sanction),
            11 => Ok(Self::FederationPeer),
            12 => Ok(Self::FederationOrigin),
            13 => Ok(Self::RequestResult),
            14 => Ok(Self::StateMeta),
            15 => Ok(Self::IntegrityManifest),
            16 => Ok(Self::IntegrityCheckpoint),
            17 => Ok(Self::EdgeOutbox),
            18 => Ok(Self::EdgeProjection),
            19 => Ok(Self::History),
            20 => Ok(Self::Audit),
            21 => Ok(Self::AuditCheckpoint),
            22 => Ok(Self::E2eeObject),
            23 => Ok(Self::E2eeState),
            24 => Ok(Self::LoginIndexKeyState),
            25 => Ok(Self::StorageConstruction),
            26 => Ok(Self::StorageOperation),
            _ => Err(StorageError::UnsupportedVersion),
        }
    }

    /// Returns the stable numeric table identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Reports whether the table participates in record-set integrity.
    #[must_use]
    pub const fn is_integrity_tracked(self) -> bool {
        matches!(self.as_u16(), 1..=13 | 17..=26)
    }

    /// Returns the fixed redb table name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::KeyCheck => "key_check",
            Self::Account => "account",
            Self::LoginIndex => "login_index",
            Self::OpaqueRecord => "opaque_record",
            Self::AuthTransaction => "auth_transaction",
            Self::NicknameReservation => "nickname_reservation",
            Self::RegistrationInvite => "registration_invite",
            Self::Session => "session",
            Self::Channel => "channel",
            Self::ChannelName => "channel_name",
            Self::Sanction => "sanction",
            Self::FederationPeer => "federation_peer",
            Self::FederationOrigin => "federation_origin",
            Self::RequestResult => "request_result",
            Self::StateMeta => "state_meta",
            Self::IntegrityManifest => "integrity_manifest",
            Self::IntegrityCheckpoint => "integrity_checkpoint",
            Self::EdgeOutbox => "edge_outbox",
            Self::EdgeProjection => "edge_projection",
            Self::History => "history",
            Self::Audit => "audit",
            Self::AuditCheckpoint => "audit_checkpoint",
            Self::E2eeObject => "e2ee_object",
            Self::E2eeState => "e2ee_state",
            Self::LoginIndexKeyState => "login_index_key_state",
            Self::StorageConstruction => "storage_construction",
            Self::StorageOperation => "storage_operation",
        }
    }
}

/// A nonempty bounded canonical redb key.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct StoredKey(Vec<u8>);

impl StoredKey {
    /// Validates and owns one complete stored key.
    pub fn new(bytes: Vec<u8>) -> Result<Self, StorageError> {
        if bytes.is_empty() || bytes.len() > MAX_STORED_KEY_BYTES {
            return Err(StorageError::LimitExceeded);
        }
        Ok(Self(bytes))
    }

    /// Borrows the canonical key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
