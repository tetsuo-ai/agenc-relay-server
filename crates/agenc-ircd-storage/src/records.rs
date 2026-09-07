//! Closed table schemas and the canonical schema-one domain-record envelope.

use std::cmp::Ordering;

use agenc_ircd_crypto::StorageDigest;
use agenc_ircd_types::{AccountId, Nickname, RecoveryEpoch};
use zeroize::Zeroizing;

use crate::codec::{Decoder, Encoder};
use crate::domain_records::{
    AccountRecordBody, ChannelNameRecordBody, ChannelRecordBody, LIVE_RECORD_KIND,
    SanctionRecordBody, SessionRecordBody,
};
use crate::{
    IntegrityCheckpoint, IntegrityManifest, LoginIndexKeyState, LoginIndexStoredKey,
    LoginIndexValue, SealedRecord, StorageConstruction, StorageError, StorageOperationCompletion,
    StoredKey, TableId,
};

/// Greatest number of authenticated cross-record references in one value.
pub const MAX_RECORD_REFERENCES: usize = 4_096;
/// Greatest domain-record body accepted by the schema-one envelope.
pub const MAX_DOMAIN_RECORD_BODY_BYTES: usize = 16_760_000;
/// Fixed key of the key-check record.
pub const KEY_CHECK_STORED_KEY: &[u8] = b"agenc-chat/key-check/v1";
/// Fixed key of the StateMeta record.
pub const STATE_META_STORED_KEY: &[u8] = b"agenc-chat/state-meta/v1";

/// Fixed key of the stable fake OPAQUE record used for unknown-login work.
pub const OPAQUE_FAKE_RECORD_KEY: &[u8] = b"agenc-chat/opaque-fake-record/v1";
const DOMAIN_RECORD_VERSION: u16 = 1;
/// Encoded bytes of a schema-one domain record ahead of its references and body: version,
/// kind, revision, generation, the expiry tag and value, the reference count, and the body length.
const DOMAIN_RECORD_FIXED_BYTES: usize = 38;
/// Encoded bytes of one reference ahead of its key: the table and the key length.
const RECORD_REFERENCE_FIXED_BYTES: usize = 6;
const PROTOCOL_BODY_VERSION: u16 = 1;
const PROTOCOL_BODY_PREFIX_BYTES: usize = 12;

/// Greatest canonical later-profile object carried in one persistent body.
pub const MAX_PROTOCOL_BODY_BYTES: usize =
    MAX_DOMAIN_RECORD_BODY_BYTES - PROTOCOL_BODY_PREFIX_BYTES;

/// Closed server-side recovery state embedded in an E2EE recovery-gate row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum E2eeRecoveryKind {
    /// Ordinary live route before a restore.
    Normal = 1,
    /// Restored route that cannot resume the old lineage.
    Pending = 2,
    /// Permanent conflicting-successor tombstone.
    Conflict = 3,
    /// Permanently closed encrypted lineage.
    Closed = 4,
}

impl E2eeRecoveryKind {
    fn decode(value: u16) -> Result<Self, StorageError> {
        match value {
            1 => Ok(Self::Normal),
            2 => Ok(Self::Pending),
            3 => Ok(Self::Conflict),
            4 => Ok(Self::Closed),
            _ => Err(StorageError::UnsupportedVersion),
        }
    }
}

/// Exact Section-18.4 recovery-gate body stored by the E2EE-state gate arm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct E2eeRecoveryGate {
    conversation_id: StorageDigest,
    state: E2eeRecoveryKind,
    recovery_epoch: RecoveryEpoch,
    restored_binding_id: StorageDigest,
    restored_accepted_state_id: StorageDigest,
    restored_sequencer_head_id: StorageDigest,
    source_rollback_guard_hash: StorageDigest,
}

impl E2eeRecoveryGate {
    /// Creates one complete version-one recovery gate.
    pub const fn new(
        conversation_id: StorageDigest,
        state: E2eeRecoveryKind,
        recovery_epoch: RecoveryEpoch,
        restored_binding_id: StorageDigest,
        restored_accepted_state_id: StorageDigest,
        restored_sequencer_head_id: StorageDigest,
        source_rollback_guard_hash: StorageDigest,
    ) -> Self {
        Self {
            conversation_id,
            state,
            recovery_epoch,
            restored_binding_id,
            restored_accepted_state_id,
            restored_sequencer_head_id,
            source_rollback_guard_hash,
        }
    }

    /// Parses one full-consumption recovery-gate body.
    pub fn decode(encoded: &[u8]) -> Result<Self, StorageError> {
        let mut decoder = Decoder::new(encoded);
        if decoder.u16()? != 1 {
            return Err(StorageError::UnsupportedVersion);
        }
        let value = Self {
            conversation_id: StorageDigest::from_bytes(decoder.array()?),
            state: E2eeRecoveryKind::decode(decoder.u16()?)?,
            recovery_epoch: RecoveryEpoch::from_bytes(decoder.array()?),
            restored_binding_id: StorageDigest::from_bytes(decoder.array()?),
            restored_accepted_state_id: StorageDigest::from_bytes(decoder.array()?),
            restored_sequencer_head_id: StorageDigest::from_bytes(decoder.array()?),
            source_rollback_guard_hash: StorageDigest::from_bytes(decoder.array()?),
        };
        decoder.finish()?;
        Ok(value)
    }

    /// Encodes the fixed version-one recovery-gate body.
    pub fn encode(self) -> Result<Vec<u8>, StorageError> {
        let mut encoder = Encoder::with_capacity(180, 180)?;
        encoder.put_u16(1)?;
        encoder.put_fixed(self.conversation_id.as_bytes())?;
        encoder.put_u16(self.state as u16)?;
        encoder.put_fixed(self.recovery_epoch.as_bytes())?;
        encoder.put_fixed(self.restored_binding_id.as_bytes())?;
        encoder.put_fixed(self.restored_accepted_state_id.as_bytes())?;
        encoder.put_fixed(self.restored_sequencer_head_id.as_bytes())?;
        encoder.put_fixed(self.source_rollback_guard_hash.as_bytes())?;
        Ok(encoder.finish())
    }

    /// Returns the closed recovery state.
    #[must_use]
    pub const fn state(self) -> E2eeRecoveryKind {
        self.state
    }

    pub(crate) const fn conversation_id(self) -> StorageDigest {
        self.conversation_id
    }

    /// Returns the lineage epoch bound by this gate.
    #[must_use]
    pub const fn recovery_epoch(self) -> RecoveryEpoch {
        self.recovery_epoch
    }

    /// Returns the signed source guard whose heads were restored.
    #[must_use]
    pub const fn source_rollback_guard_hash(self) -> StorageDigest {
        self.source_rollback_guard_hash
    }

    /// Rebinds only nonterminal routes to a fresh recovery epoch and source guard.
    #[must_use]
    pub const fn recover(
        mut self,
        target_recovery_epoch: RecoveryEpoch,
        source_rollback_guard_hash: StorageDigest,
    ) -> Self {
        if matches!(
            self.state,
            E2eeRecoveryKind::Normal | E2eeRecoveryKind::Pending
        ) {
            self.state = E2eeRecoveryKind::Pending;
            self.recovery_epoch = target_recovery_epoch;
            self.source_rollback_guard_hash = source_rollback_guard_hash;
        }
        self
    }
}

/// Exact persistence wrapper for one already validated federation or E2EE object.
///
/// The wrapper binds the canonical object bytes to their table, closed record
/// arm, and protocol profile. It prevents a value accepted for one later-stage
/// type from being replayed as another while leaving protocol semantic
/// validation with the owning federation or E2EE crate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolRecordBody {
    table: TableId,
    record_kind: u16,
    profile_version: u16,
    canonical_object: Vec<u8>,
}

impl ProtocolRecordBody {
    /// Creates one complete version-one protocol body.
    pub fn new(
        table: TableId,
        record_kind: u16,
        profile_version: u16,
        canonical_object: Vec<u8>,
    ) -> Result<Self, StorageError> {
        if !uses_protocol_body(table, record_kind)
            || profile_version != 1
            || canonical_object.is_empty()
            || canonical_object.len() > protocol_body_limit(table)
        {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self {
            table,
            record_kind,
            profile_version,
            canonical_object,
        })
    }

    /// Parses one full-consumption protocol body for an expected table and arm.
    pub fn decode(
        expected_table: TableId,
        expected_kind: u16,
        encoded: &[u8],
    ) -> Result<Self, StorageError> {
        let mut decoder = Decoder::new(encoded);
        if decoder.u16()? != PROTOCOL_BODY_VERSION {
            return Err(StorageError::UnsupportedVersion);
        }
        let table = TableId::from_u16(decoder.u16()?)?;
        let record_kind = decoder.u16()?;
        let profile_version = decoder.u16()?;
        let maximum = protocol_body_limit(expected_table);
        let canonical_object = decoder.vector_u32(maximum)?.to_vec();
        decoder.finish()?;
        if table != expected_table || record_kind != expected_kind {
            return Err(StorageError::InvalidEncoding);
        }
        Self::new(table, record_kind, profile_version, canonical_object)
    }

    /// Encodes the exact table- and arm-bound wrapper.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let capacity = PROTOCOL_BODY_PREFIX_BYTES
            .checked_add(self.canonical_object.len())
            .ok_or(StorageError::Overflow)?;
        let mut encoder = Encoder::with_capacity(capacity, MAX_DOMAIN_RECORD_BODY_BYTES)?;
        encoder.put_u16(PROTOCOL_BODY_VERSION)?;
        encoder.put_u16(self.table.as_u16())?;
        encoder.put_u16(self.record_kind)?;
        encoder.put_u16(self.profile_version)?;
        encoder.put_vector_u32(&self.canonical_object)?;
        Ok(encoder.finish())
    }

    /// Returns the owning persistent table.
    #[must_use]
    pub const fn table(&self) -> TableId {
        self.table
    }

    /// Returns the closed record arm within the table.
    #[must_use]
    pub const fn record_kind(&self) -> u16 {
        self.record_kind
    }

    /// Returns the protocol profile version of the canonical object.
    #[must_use]
    pub const fn profile_version(&self) -> u16 {
        self.profile_version
    }

    /// Borrows the complete canonical protocol object.
    #[must_use]
    pub fn canonical_object(&self) -> &[u8] {
        &self.canonical_object
    }
}

/// Canonical redb-key grammar for one table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoredKeyShape {
    /// One exact protocol byte string.
    Fixed(&'static [u8]),
    /// One exact byte length.
    Exact(usize),
    /// An inclusive bounded byte-length range.
    Range {
        /// Smallest accepted key length.
        minimum: usize,
        /// Greatest accepted key length.
        maximum: usize,
    },
    /// Either an Account-ID key or the fixed fake OPAQUE key.
    AccountOrOpaqueFake,
}

impl StoredKeyShape {
    fn accepts(self, key: &[u8]) -> bool {
        match self {
            Self::Fixed(expected) => key == expected,
            Self::Exact(length) => key.len() == length,
            Self::Range { minimum, maximum } => (minimum..=maximum).contains(&key.len()),
            Self::AccountOrOpaqueFake => key.len() == 24 || key == OPAQUE_FAKE_RECORD_KEY,
        }
    }
}

/// Codec selected for a table's schema-one plaintext.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordCodecKind {
    /// A table-specific control codec implemented in this crate.
    Control,
    /// The private login-index union.
    LoginIndex,
    /// The canonical schema-one domain envelope below.
    Domain,
}

/// One entry in the complete database-format-one schema inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableSchema {
    table: TableId,
    key_shape: StoredKeyShape,
    codec: RecordCodecKind,
    integrity_tracked: bool,
}

impl TableSchema {
    /// Returns the table governed by this entry.
    #[must_use]
    pub const fn table(self) -> TableId {
        self.table
    }

    /// Returns the table's exact stored-key grammar.
    #[must_use]
    pub const fn key_shape(self) -> StoredKeyShape {
        self.key_shape
    }

    /// Returns the schema-one plaintext codec family.
    #[must_use]
    pub const fn codec(self) -> RecordCodecKind {
        self.codec
    }

    /// Reports whether the table is included in record-set integrity.
    #[must_use]
    pub const fn is_integrity_tracked(self) -> bool {
        self.integrity_tracked
    }

    /// Validates one complete stored key for this table.
    pub fn validate_key(self, key: &[u8]) -> Result<(), StorageError> {
        if !self.key_shape.accepts(key) {
            return Err(StorageError::InvalidEncoding);
        }
        if self.table == TableId::Account
            || (self.table == TableId::OpaqueRecord && key != OPAQUE_FAKE_RECORD_KEY)
        {
            let account =
                AccountId::parse_wire_bytes(key).map_err(|_| StorageError::InvalidEncoding)?;
            if account.to_text().as_bytes() != key {
                return Err(StorageError::InvalidEncoding);
            }
        }
        Ok(())
    }
}

/// Returns the closed database-format-one schema for one table.
#[must_use]
// agenc-review: focus owner=storage reviewed=2026-08-28 reason=closed twenty-seven-table registry is reviewed against the normative schema inventory
pub const fn table_schema(table: TableId) -> TableSchema {
    let (key_shape, codec) = match table {
        TableId::KeyCheck => (
            StoredKeyShape::Fixed(KEY_CHECK_STORED_KEY),
            RecordCodecKind::Control,
        ),
        TableId::Account => (StoredKeyShape::Exact(24), RecordCodecKind::Domain),
        TableId::LoginIndex => (StoredKeyShape::Exact(36), RecordCodecKind::LoginIndex),
        TableId::OpaqueRecord => (StoredKeyShape::AccountOrOpaqueFake, RecordCodecKind::Domain),
        TableId::AuthTransaction => (StoredKeyShape::Exact(16), RecordCodecKind::Domain),
        TableId::NicknameReservation => (StoredKeyShape::Exact(32), RecordCodecKind::Domain),
        TableId::RegistrationInvite => (StoredKeyShape::Exact(16), RecordCodecKind::Domain),
        TableId::Session => (StoredKeyShape::Exact(16), RecordCodecKind::Domain),
        TableId::Channel => (StoredKeyShape::Exact(16), RecordCodecKind::Domain),
        TableId::ChannelName => (StoredKeyShape::Exact(32), RecordCodecKind::Domain),
        TableId::Sanction => (
            StoredKeyShape::Range {
                minimum: 18,
                maximum: 4_096,
            },
            RecordCodecKind::Domain,
        ),
        TableId::FederationPeer => (StoredKeyShape::Exact(16), RecordCodecKind::Domain),
        TableId::FederationOrigin => (
            StoredKeyShape::Range {
                minimum: 56,
                maximum: 4_096,
            },
            RecordCodecKind::Domain,
        ),
        TableId::RequestResult => (
            StoredKeyShape::Range {
                minimum: 16,
                maximum: 4_096,
            },
            RecordCodecKind::Domain,
        ),
        TableId::StateMeta => (
            StoredKeyShape::Fixed(STATE_META_STORED_KEY),
            RecordCodecKind::Control,
        ),
        TableId::IntegrityManifest | TableId::IntegrityCheckpoint => {
            (StoredKeyShape::Exact(8), RecordCodecKind::Control)
        }
        TableId::EdgeOutbox | TableId::EdgeProjection => (
            StoredKeyShape::Range {
                minimum: 10,
                maximum: 4_096,
            },
            RecordCodecKind::Domain,
        ),
        TableId::History => (StoredKeyShape::Exact(24), RecordCodecKind::Domain),
        TableId::Audit | TableId::AuditCheckpoint => {
            (StoredKeyShape::Exact(8), RecordCodecKind::Domain)
        }
        TableId::E2eeObject => (StoredKeyShape::Exact(32), RecordCodecKind::Domain),
        TableId::E2eeState => (
            StoredKeyShape::Range {
                minimum: 3,
                maximum: 4_096,
            },
            RecordCodecKind::Domain,
        ),
        TableId::LoginIndexKeyState => (
            StoredKeyShape::Fixed(crate::LOGIN_INDEX_KEY_STATE_KEY),
            RecordCodecKind::Control,
        ),
        TableId::StorageConstruction => (
            StoredKeyShape::Fixed(crate::STORAGE_CONSTRUCTION_KEY),
            RecordCodecKind::Control,
        ),
        TableId::StorageOperation => (StoredKeyShape::Exact(32), RecordCodecKind::Control),
    };
    TableSchema {
        table,
        key_shape,
        codec,
        integrity_tracked: table.is_integrity_tracked(),
    }
}

/// Returns every database-format-one schema entry in numeric table order.
pub fn table_schemas() -> Result<[TableSchema; 27], StorageError> {
    let mut schemas = [table_schema(TableId::KeyCheck); 27];
    for (number, slot) in (0_u16..=26).zip(&mut schemas) {
        *slot = table_schema(TableId::from_u16(number)?);
    }
    Ok(schemas)
}

/// An authenticated logical reference used for bounded reconstruction.
#[derive(Clone, Eq, PartialEq)]
pub struct RecordReference {
    table: TableId,
    key: StoredKey,
}

impl RecordReference {
    /// Validates one reference to an integrity-tracked row.
    pub fn new(table: TableId, key: StoredKey) -> Result<Self, StorageError> {
        if !table.is_integrity_tracked() {
            return Err(StorageError::InvalidEncoding);
        }
        table_schema(table).validate_key(key.as_bytes())?;
        Ok(Self { table, key })
    }

    /// Returns the referenced table.
    #[must_use]
    pub const fn table(&self) -> TableId {
        self.table
    }

    /// Borrows the referenced stored key.
    #[must_use]
    pub const fn key(&self) -> &StoredKey {
        &self.key
    }

    fn encode(&self, encoder: &mut Encoder) -> Result<(), StorageError> {
        encoder.put_u16(self.table.as_u16())?;
        encoder.put_vector_u32(self.key.as_bytes())
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        Self::new(
            TableId::from_u16(decoder.u16()?)?,
            StoredKey::new(decoder.vector_u32(crate::MAX_STORED_KEY_BYTES)?.to_vec())?,
        )
    }
}

/// Canonical schema-one plaintext for non-control durable tables.
///
/// Table-specific union arms are identified by `record_kind`; this envelope
/// keeps revisions, generations, expirations, and cross-record references in
/// a common prefix so startup can validate them without retaining secret body
/// bytes. The body remains table-owned canonical bytes.
pub struct PersistentRecordValue {
    table: TableId,
    record_kind: u16,
    revision: u64,
    generation: u64,
    expires_at: Option<u64>,
    references: Vec<RecordReference>,
    body: Zeroizing<Vec<u8>>,
}

impl PersistentRecordValue {
    /// Validates and owns one complete schema-one domain record.
    pub fn new(
        table: TableId,
        record_kind: u16,
        revision: u64,
        generation: u64,
        expires_at: Option<u64>,
        mut references: Vec<RecordReference>,
        body: Vec<u8>,
    ) -> Result<Self, StorageError> {
        if table_schema(table).codec != RecordCodecKind::Domain
            || !record_kind_is_valid(table, record_kind)
            || expires_at == Some(0)
            || references.len() > MAX_RECORD_REFERENCES
            || body.len() > MAX_DOMAIN_RECORD_BODY_BYTES
        {
            return Err(StorageError::InvalidEncoding);
        }
        validate_domain_body(table, record_kind, &body)?;
        references.sort_by(compare_references);
        if references
            .windows(2)
            .any(|pair| matches!(pair, [first, second] if first == second))
        {
            return Err(StorageError::InvalidEncoding);
        }
        validate_record_counters(table, record_kind, revision, generation)?;
        // The reference and body ceilings are independent, so their sum can exceed the sealed
        // plaintext ceiling; admit only what `encode` can seal.
        if domain_record_encoded_bytes(&references, body.len())?
            > agenc_ircd_crypto::MAX_STORAGE_PLAINTEXT_BYTES
        {
            return Err(StorageError::LimitExceeded);
        }
        Ok(Self {
            table,
            record_kind,
            revision,
            generation,
            expires_at,
            references,
            body: Zeroizing::new(body),
        })
    }

    /// Parses one full-consumption schema-one domain record.
    pub fn decode(table: TableId, encoded: &[u8]) -> Result<Self, StorageError> {
        let mut decoder = Decoder::new(encoded);
        if decoder.u16()? != DOMAIN_RECORD_VERSION {
            return Err(StorageError::UnsupportedVersion);
        }
        let record_kind = decoder.u16()?;
        let revision = decoder.u64()?;
        let generation = decoder.u64()?;
        let expires_at = match decoder.u16()? {
            0 => {
                if decoder.u64()? != 0 {
                    return Err(StorageError::InvalidEncoding);
                }
                None
            }
            1 => Some(decoder.u64()?),
            _ => return Err(StorageError::UnsupportedVersion),
        };
        let reference_count =
            usize::try_from(decoder.u32()?).map_err(|_| StorageError::Overflow)?;
        if reference_count > MAX_RECORD_REFERENCES {
            return Err(StorageError::LimitExceeded);
        }
        let mut references = Vec::new();
        references
            .try_reserve_exact(reference_count)
            .map_err(|_| StorageError::AllocationFailed)?;
        for _ in 0..reference_count {
            references.push(RecordReference::decode(&mut decoder)?);
        }
        let body = decoder.vector_u32(MAX_DOMAIN_RECORD_BODY_BYTES)?.to_vec();
        decoder.finish()?;
        Self::new(
            table,
            record_kind,
            revision,
            generation,
            expires_at,
            references,
            body,
        )
    }

    /// Encodes one complete canonical domain record.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let capacity = domain_record_encoded_bytes(&self.references, self.body.len())?;
        let mut encoder =
            Encoder::with_capacity(capacity, agenc_ircd_crypto::MAX_STORAGE_PLAINTEXT_BYTES)?;
        encoder.put_u16(DOMAIN_RECORD_VERSION)?;
        encoder.put_u16(self.record_kind)?;
        encoder.put_u64(self.revision)?;
        encoder.put_u64(self.generation)?;
        match self.expires_at {
            None => {
                encoder.put_u16(0)?;
                encoder.put_u64(0)?;
            }
            Some(expires_at) => {
                encoder.put_u16(1)?;
                encoder.put_u64(expires_at)?;
            }
        }
        encoder.put_u32(
            u32::try_from(self.references.len()).map_err(|_| StorageError::LimitExceeded)?,
        )?;
        for reference in &self.references {
            reference.encode(&mut encoder)?;
        }
        encoder.put_vector_u32(&self.body)?;
        Ok(encoder.finish())
    }

    /// Returns the owning table.
    #[must_use]
    pub const fn table(&self) -> TableId {
        self.table
    }

    /// Returns the table-specific closed union arm.
    #[must_use]
    pub const fn record_kind(&self) -> u16 {
        self.record_kind
    }

    /// Returns the authenticated logical revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the authenticated generation or zero when not applicable.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the optional exclusive expiration second.
    #[must_use]
    pub const fn expires_at(&self) -> Option<u64> {
        self.expires_at
    }

    /// Borrows references in canonical table/key order.
    #[must_use]
    pub fn references(&self) -> &[RecordReference] {
        &self.references
    }

    /// Borrows the table-owned canonical body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Validates one schema-one plaintext and its exact stored-key binding.
pub fn validate_record_plaintext(
    table: TableId,
    stored_key: &StoredKey,
    record_schema: u32,
    plaintext: &[u8],
) -> Result<(), StorageError> {
    if record_schema != 1 {
        return Err(StorageError::UnsupportedVersion);
    }
    table_schema(table).validate_key(stored_key.as_bytes())?;
    match table {
        TableId::KeyCheck => validate_key_check(plaintext),
        TableId::LoginIndex => {
            let key = LoginIndexStoredKey::decode(stored_key.as_bytes())?;
            LoginIndexValue::decode(plaintext, &key).map(|_| ())
        }
        TableId::StateMeta => validate_fixed_length(plaintext, crate::STATE_META_BYTES),
        TableId::IntegrityManifest => {
            let manifest = IntegrityManifest::decode(plaintext)?;
            if stored_key.as_bytes() == manifest.tbs().manifest_sequence.to_be_bytes() {
                Ok(())
            } else {
                Err(StorageError::StaleState)
            }
        }
        TableId::IntegrityCheckpoint => {
            let checkpoint = IntegrityCheckpoint::decode(plaintext)?;
            if stored_key.as_bytes() == checkpoint.tbs().cut_manifest_sequence.to_be_bytes() {
                Ok(())
            } else {
                Err(StorageError::StaleState)
            }
        }
        TableId::LoginIndexKeyState => LoginIndexKeyState::decode(plaintext).map(|_| ()),
        TableId::StorageConstruction => StorageConstruction::decode(plaintext).map(|_| ()),
        TableId::StorageOperation => {
            let completion = StorageOperationCompletion::decode(plaintext)?;
            if stored_key.as_bytes() == completion.storage_operation_id.as_bytes() {
                Ok(())
            } else {
                Err(StorageError::StaleState)
            }
        }
        TableId::RequestResult => {
            let value = PersistentRecordValue::decode(table, plaintext)?;
            if matches!(value.record_kind(), 5 | 6) {
                crate::history_records::validate_result_binding(stored_key, &value)?;
            }
            Ok(())
        }
        TableId::History => {
            let value = PersistentRecordValue::decode(table, plaintext)?;
            crate::history_records::validate_binding(stored_key, &value)
        }
        _ => PersistentRecordValue::decode(table, plaintext).map(|_| ()),
    }
}

/// Validates an encoded sealed record against the closed table/key/schema inventory.
pub fn validate_sealed_record(
    table: TableId,
    stored_key: &StoredKey,
    encoded: &[u8],
) -> Result<SealedRecord, StorageError> {
    table_schema(table).validate_key(stored_key.as_bytes())?;
    let sealed = SealedRecord::decode(encoded)?;
    if sealed.table() != table || sealed.record_schema() != 1 {
        return Err(StorageError::AuthenticationFailed);
    }
    Ok(sealed)
}

/// Computes the exact encoded length of a schema-one domain record.
fn domain_record_encoded_bytes(
    references: &[RecordReference],
    body_bytes: usize,
) -> Result<usize, StorageError> {
    let reference_bytes = references.iter().try_fold(0_usize, |total, reference| {
        total
            .checked_add(RECORD_REFERENCE_FIXED_BYTES)
            .and_then(|value| value.checked_add(reference.key.as_bytes().len()))
            .ok_or(StorageError::Overflow)
    })?;
    DOMAIN_RECORD_FIXED_BYTES
        .checked_add(reference_bytes)
        .and_then(|value| value.checked_add(body_bytes))
        .ok_or(StorageError::Overflow)
}

fn validate_key_check(plaintext: &[u8]) -> Result<(), StorageError> {
    validate_fixed_length(plaintext, 32)
}

fn validate_fixed_length(plaintext: &[u8], expected: usize) -> Result<(), StorageError> {
    if plaintext.len() == expected {
        Ok(())
    } else {
        Err(StorageError::InvalidEncoding)
    }
}

fn compare_references(left: &RecordReference, right: &RecordReference) -> Ordering {
    (left.table, left.key.as_bytes()).cmp(&(right.table, right.key.as_bytes()))
}

fn validate_record_counters(
    table: TableId,
    record_kind: u16,
    revision: u64,
    generation: u64,
) -> Result<(), StorageError> {
    let tombstone = matches!(
        (table, record_kind),
        (TableId::Account, 2)
            | (TableId::Session, 2)
            | (TableId::Channel, 2)
            | (TableId::RegistrationInvite, 2)
    );
    if revision == 0 && !tombstone {
        return Err(StorageError::InvalidEncoding);
    }
    if matches!(
        table,
        TableId::Account | TableId::Session | TableId::EdgeProjection
    ) && generation == 0
        && !tombstone
    {
        return Err(StorageError::InvalidEncoding);
    }
    Ok(())
}

fn validate_domain_body(table: TableId, record_kind: u16, body: &[u8]) -> Result<(), StorageError> {
    match (table, record_kind) {
        (TableId::History, kind) => crate::history_records::validate_body(kind, body),
        (TableId::RequestResult, 5) => {
            crate::history_records::HistoryCoordinatorResultRecord::decode(body).map(|_| ())
        }
        (TableId::RequestResult, 6) => {
            crate::history_records::HistoryEdgeRequestRecord::decode(body).map(|_| ())
        }
        (TableId::NicknameReservation, 1) => std::str::from_utf8(body)
            .map_err(|_| StorageError::InvalidEncoding)
            .and_then(|name| Nickname::parse(name).map_err(|_| StorageError::InvalidEncoding))
            .map(|_| ()),
        (TableId::ChannelName, 1) => ChannelNameRecordBody::decode(body).map(|_| ()),
        (TableId::E2eeState, 1) => E2eeRecoveryGate::decode(body).map(|_| ()),
        (TableId::E2eeState, kind) => crate::e2ee_records::validate_state_body(kind, body),
        (TableId::E2eeObject, 1) => crate::e2ee_records::validate_object_body(body),
        (TableId::Account, LIVE_RECORD_KIND) => AccountRecordBody::decode(body).map(|_| ()),
        (TableId::Session, LIVE_RECORD_KIND) => SessionRecordBody::decode(body).map(|_| ()),
        (TableId::Channel, LIVE_RECORD_KIND) => ChannelRecordBody::decode(body).map(|_| ()),
        (TableId::Sanction, LIVE_RECORD_KIND) => SanctionRecordBody::decode(body).map(|_| ()),
        _ if uses_protocol_body(table, record_kind) => {
            ProtocolRecordBody::decode(table, record_kind, body).map(|_| ())
        }
        // Every other kind, including the kind-2 tombstones, carries an opaque
        // body here; runtime reconstruction is where a tombstone must be bare.
        _ => Ok(()),
    }
}

const fn uses_protocol_body(table: TableId, record_kind: u16) -> bool {
    matches!(
        table,
        TableId::FederationPeer
            | TableId::FederationOrigin
            | TableId::RequestResult
            | TableId::EdgeOutbox
            | TableId::EdgeProjection
            | TableId::E2eeObject
    ) || (matches!(table, TableId::E2eeState) && record_kind != 1)
}

const fn protocol_body_limit(table: TableId) -> usize {
    if matches!(table, TableId::E2eeObject) {
        4_194_304
    } else {
        MAX_PROTOCOL_BODY_BYTES
    }
}

const fn record_kind_is_valid(table: TableId, kind: u16) -> bool {
    let maximum = match table {
        TableId::Account => 2,
        TableId::OpaqueRecord => 2,
        TableId::AuthTransaction => 4,
        TableId::NicknameReservation => 2,
        TableId::RegistrationInvite => 2,
        TableId::Session => 2,
        TableId::Channel => 3,
        TableId::ChannelName => 2,
        TableId::Sanction => 4,
        TableId::FederationPeer => 2,
        TableId::FederationOrigin => 2,
        TableId::RequestResult => 6,
        TableId::EdgeOutbox => 3,
        TableId::EdgeProjection => 3,
        TableId::History => 2,
        TableId::Audit => 1,
        TableId::AuditCheckpoint => 1,
        TableId::E2eeObject => 1,
        TableId::E2eeState => 12,
        _ => 0,
    };
    kind != 0 && kind <= maximum
}

#[cfg(test)]
mod tests {
    use agenc_ircd_crypto::{DatabaseBinding, StorageMasterKey};
    use agenc_ircd_types::{AccountRandomId, DatabaseId, NetworkId, ServerId, ServerIncarnation};

    use super::*;
    use crate::{
        IntegrityCheckpoint, IntegrityCheckpointTbs, IntegrityManifest, IntegrityManifestTbs,
        IntegrityRecordMutation, IntegrityRecordVersion, StorageSealContext,
    };

    #[test]
    fn domain_record_admission_stops_at_the_exact_sealed_plaintext_ceiling()
    -> Result<(), StorageError> {
        let plaintext_ceiling = agenc_ircd_crypto::MAX_STORAGE_PLAINTEXT_BYTES;
        let body = vec![7_u8; MAX_DOMAIN_RECORD_BODY_BYTES];
        let full_key_bytes = crate::MAX_STORED_KEY_BYTES;
        let remaining = plaintext_ceiling
            - DOMAIN_RECORD_FIXED_BYTES
            - MAX_DOMAIN_RECORD_BODY_BYTES
            - 4 * (RECORD_REFERENCE_FIXED_BYTES + full_key_bytes)
            - RECORD_REFERENCE_FIXED_BYTES;
        let references = |last_key_bytes: usize| -> Result<Vec<RecordReference>, StorageError> {
            let mut references = Vec::new();
            for index in 0_u8..4 {
                let mut key = vec![index; full_key_bytes];
                key.push(index);
                key.truncate(full_key_bytes);
                references.push(RecordReference::new(
                    TableId::Sanction,
                    StoredKey::new(key)?,
                )?);
            }
            references.push(RecordReference::new(
                TableId::Sanction,
                StoredKey::new(vec![9; last_key_bytes])?,
            )?);
            Ok(references)
        };

        let exact = PersistentRecordValue::new(
            TableId::AuthTransaction,
            1,
            1,
            0,
            None,
            references(remaining)?,
            body.clone(),
        )?;
        let encoded = exact.encode()?;
        assert_eq!(encoded.len(), plaintext_ceiling);
        assert_eq!(
            domain_record_encoded_bytes(&references(remaining)?, body.len())?,
            plaintext_ceiling
        );
        assert_eq!(
            PersistentRecordValue::new(
                TableId::AuthTransaction,
                1,
                1,
                0,
                None,
                references(remaining + 1)?,
                body,
            )
            .map(|_| ()),
            Err(StorageError::LimitExceeded)
        );
        Ok(())
    }

    #[test]
    fn domain_envelope_and_sealed_inventory_reject_each_outer_binding() -> Result<(), StorageError>
    {
        assert_eq!(
            PersistentRecordValue::new(TableId::KeyCheck, 1, 1, 0, None, Vec::new(), Vec::new())
                .map(|_| ()),
            Err(StorageError::InvalidEncoding)
        );

        let valid = PersistentRecordValue::new(
            TableId::Account,
            1,
            1,
            1,
            None,
            Vec::new(),
            crate::domain_records::fixtures::live_body(TableId::Account, 1)?,
        )?
        .encode()?;
        let mut wrong_version = valid.clone();
        wrong_version
            .get_mut(..2)
            .ok_or(StorageError::InvalidEncoding)?
            .copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            PersistentRecordValue::decode(TableId::Account, &wrong_version).map(|_| ()),
            Err(StorageError::UnsupportedVersion)
        );

        let key = StoredKey::new(AccountRandomId::from_bytes([1; 16]).to_text().into_bytes())?;
        let binding = DatabaseBinding::new(
            NetworkId::from_bytes([2; 32]),
            ServerId::from_bytes([3; 16]),
            ServerIncarnation::from_bytes([4; 16]),
            DatabaseId::from_bytes([5; 16]),
        );
        let master_key = StorageMasterKey::from_bytes([6; 32]);
        let context = StorageSealContext::new(&master_key, binding, 1)?;
        let sealed = context
            .seal(TableId::Account, 1, [7; 24], &key, &valid)?
            .encode()?;
        assert!(validate_sealed_record(TableId::Account, &key, &sealed).is_ok());
        assert_eq!(
            validate_sealed_record(TableId::OpaqueRecord, &key, &sealed).map(|_| ()),
            Err(StorageError::AuthenticationFailed)
        );
        let wrong_schema = context
            .seal(TableId::Account, 2, [8; 24], &key, &valid)?
            .encode()?;
        assert_eq!(
            validate_sealed_record(TableId::Account, &key, &wrong_schema).map(|_| ()),
            Err(StorageError::AuthenticationFailed)
        );
        Ok(())
    }

    #[test]
    fn control_plaintext_validation_rejects_mismatched_integrity_keys() -> Result<(), StorageError>
    {
        let mutation = IntegrityRecordMutation::new(
            TableId::Account,
            StoredKey::new(AccountRandomId::from_bytes([11; 16]).to_text().into_bytes())?,
            IntegrityRecordVersion::Absent,
            IntegrityRecordVersion::Present {
                record_schema: 1,
                sealed_record_id: StorageDigest::from_bytes([12; 32]),
            },
        )?;
        let manifest = IntegrityManifest::new(IntegrityManifestTbs::new(
            DatabaseId::from_bytes([13; 16]),
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            3,
            3,
            StorageDigest::from_bytes([0; 32]),
            vec![mutation],
        )?)?;
        assert_eq!(
            validate_record_plaintext(
                TableId::IntegrityManifest,
                &StoredKey::new(2_u64.to_be_bytes().to_vec())?,
                1,
                &manifest.encode()?,
            ),
            Err(StorageError::StaleState),
        );

        let checkpoint = IntegrityCheckpoint::new(IntegrityCheckpointTbs {
            database_instance_id: DatabaseId::from_bytes([13; 16]),
            cut_storage_commit_sequence: 0,
            cut_manifest_sequence: 0,
            cut_state_generation: 0,
            cut_account_service_response_count: 0,
            cut_nonce_draw_high_water: 3,
            cut_manifest_hash: StorageDigest::from_bytes([0; 32]),
            tracked_record_count: 0,
            tracked_state_digest: StorageDigest::from_bytes([0; 32]),
            previous_checkpoint_hash: StorageDigest::from_bytes([0; 32]),
            installation_storage_commit_sequence: 0,
            installation_manifest_sequence: 0,
            installation_nonce_reservation_start: 3,
            installation_nonce_draw_high_water: 5,
        })?;
        assert_eq!(
            validate_record_plaintext(
                TableId::IntegrityCheckpoint,
                &StoredKey::new(1_u64.to_be_bytes().to_vec())?,
                1,
                &checkpoint.encode()?,
            ),
            Err(StorageError::StaleState),
        );
        Ok(())
    }
}
