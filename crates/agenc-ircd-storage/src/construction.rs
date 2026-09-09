//! Authenticated restore and rekey construction plans and cursors.

use agenc_ircd_crypto::{
    ConstructionPlanHasher, StorageDigest, rekey_transform_profile_hash,
    restore_transform_profile_hash, storage_operation_id,
};
use agenc_ircd_types::DatabaseId;

use crate::codec::{Decoder, Encoder};
use crate::{StorageError, StoredKey, TableId};

/// Fixed key of the sole in-progress construction marker.
pub const STORAGE_CONSTRUCTION_KEY: &[u8] = b"agenc-chat/storage-construction/v1";
/// Hard version-one ceiling for canonical plan-entry bytes.
pub const MAX_CONSTRUCTION_PLAN_BYTES: u64 = 2_199_023_255_552;
const MAX_PLAN_ENTRY_BYTES: usize = 12_403;

/// Closed offline construction operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum StorageConstructionKind {
    /// Verified signed-backup restore into a new recovery epoch.
    Restore = 1,
    /// Copy-on-write storage master-key rotation.
    Rekey = 2,
}

impl StorageConstructionKind {
    fn decode(value: u16) -> Result<Self, StorageError> {
        match value {
            1 => Ok(Self::Restore),
            2 => Ok(Self::Rekey),
            _ => Err(StorageError::UnsupportedVersion),
        }
    }
}

/// Closed resumable target cursor.
#[derive(Clone, Eq, PartialEq)]
pub enum StorageConstructionCursor {
    /// No plan entry has committed.
    BeforeFirst,
    /// Exact next target in canonical plan order.
    AtTarget {
        /// Target table.
        table: TableId,
        /// Target stored key.
        key: StoredKey,
    },
    /// Every planned target has committed.
    Complete,
}

impl StorageConstructionCursor {
    /// Validates a cursor against its committed and planned counts.
    pub fn validate(&self, committed: u64, planned: u64) -> Result<(), StorageError> {
        match self {
            Self::BeforeFirst if committed == 0 && planned != 0 => Ok(()),
            Self::AtTarget { table, .. }
                if committed < planned && is_construction_target(*table) =>
            {
                Ok(())
            }
            Self::Complete if committed == planned => Ok(()),
            _ => Err(StorageError::StaleState),
        }
    }

    fn encode(&self, encoder: &mut Encoder) -> Result<(), StorageError> {
        match self {
            Self::BeforeFirst => {
                encoder.put_u16(0)?;
                encoder.put_u16(0)?;
                encoder.put_vector_u32(&[])
            }
            Self::AtTarget { table, key } => {
                if !is_construction_target(*table) {
                    return Err(StorageError::InvalidEncoding);
                }
                encoder.put_u16(1)?;
                encoder.put_u16(table.as_u16())?;
                encoder.put_vector_u32(key.as_bytes())
            }
            Self::Complete => {
                encoder.put_u16(2)?;
                encoder.put_u16(0)?;
                encoder.put_vector_u32(&[])
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        let kind = decoder.u16()?;
        let table = decoder.u16()?;
        let key = decoder.vector_u32(crate::MAX_STORED_KEY_BYTES)?;
        match (kind, table, key.is_empty()) {
            (0, 0, true) => Ok(Self::BeforeFirst),
            (1, table, false) => {
                let table = TableId::from_u16(table)?;
                if !is_construction_target(table) {
                    return Err(StorageError::InvalidEncoding);
                }
                Ok(Self::AtTarget {
                    table,
                    key: StoredKey::new(key.to_vec())?,
                })
            }
            (2, 0, true) => Ok(Self::Complete),
            _ => Err(StorageError::InvalidEncoding),
        }
    }
}

/// Where one construction source record is authenticated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum StorageConstructionSourceKind {
    /// Continuously locked source database.
    DatabaseRecord = 1,
    /// Already verified signed backup offset.
    BackupRecord = 2,
}

/// Exact source-envelope reference retained by the public plan.
pub struct StorageConstructionSource {
    kind: StorageConstructionSourceKind,
    table: TableId,
    key: StoredKey,
    record_schema: u32,
    sealed_record_id: StorageDigest,
    backup_byte_offset: u64,
}

impl StorageConstructionSource {
    /// Validates one database or backup record reference.
    pub fn new(
        kind: StorageConstructionSourceKind,
        table: TableId,
        key: StoredKey,
        record_schema: u32,
        sealed_record_id: StorageDigest,
        backup_byte_offset: u64,
    ) -> Result<Self, StorageError> {
        if record_schema == 0
            || (kind == StorageConstructionSourceKind::DatabaseRecord && backup_byte_offset != 0)
        {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self {
            kind,
            table,
            key,
            record_schema,
            sealed_record_id,
            backup_byte_offset,
        })
    }

    fn encode(&self, encoder: &mut Encoder) -> Result<(), StorageError> {
        encoder.put_u16(self.kind as u16)?;
        encoder.put_u16(self.table.as_u16())?;
        encoder.put_vector_u32(self.key.as_bytes())?;
        encoder.put_u32(self.record_schema)?;
        encoder.put_fixed(self.sealed_record_id.as_bytes())?;
        encoder.put_u64(self.backup_byte_offset)
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        let kind = match decoder.u16()? {
            1 => StorageConstructionSourceKind::DatabaseRecord,
            2 => StorageConstructionSourceKind::BackupRecord,
            _ => return Err(StorageError::UnsupportedVersion),
        };
        Self::new(
            kind,
            TableId::from_u16(decoder.u16()?)?,
            StoredKey::new(decoder.vector_u32(crate::MAX_STORED_KEY_BYTES)?.to_vec())?,
            decoder.u32()?,
            StorageDigest::from_bytes(decoder.array()?),
            decoder.u64()?,
        )
    }

    fn identity(&self) -> (TableId, &[u8]) {
        (self.table, self.key.as_bytes())
    }

    /// Returns the source medium.
    #[must_use]
    pub const fn kind(&self) -> StorageConstructionSourceKind {
        self.kind
    }

    /// Returns the exact source table.
    #[must_use]
    pub const fn table(&self) -> TableId {
        self.table
    }

    /// Borrows the exact source stored key.
    #[must_use]
    pub const fn key(&self) -> &StoredKey {
        &self.key
    }

    /// Returns the nonzero source record schema.
    #[must_use]
    pub const fn record_schema(&self) -> u32 {
        self.record_schema
    }

    /// Returns the complete expected source envelope identifier.
    #[must_use]
    pub const fn sealed_record_id(&self) -> StorageDigest {
        self.sealed_record_id
    }

    /// Returns the signed-stream record offset, or zero for a database source.
    #[must_use]
    pub const fn backup_byte_offset(&self) -> u64 {
        self.backup_byte_offset
    }
}

/// Closed construction transformation action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum StorageConstructionAction {
    /// Same-table rekey copy.
    RekeyCopy = 1,
    /// Restore one admitted unchanged record.
    RestoreCopy = 2,
    /// Restore one account with its generation increment.
    RestoreAccount = 3,
    /// Restore one registered channel with revision increment.
    RestoreChannel = 4,
    /// Regenerate one restored channel-name index from two sources.
    RestoreChannelName = 5,
    /// Retain only peer recovery tombstones.
    RestorePeerTombstones = 6,
    /// Apply the fixed E2EE recovery-pending transform.
    RestoreE2eeState = 7,
}

impl StorageConstructionAction {
    fn decode(value: u16) -> Result<Self, StorageError> {
        match value {
            1 => Ok(Self::RekeyCopy),
            2 => Ok(Self::RestoreCopy),
            3 => Ok(Self::RestoreAccount),
            4 => Ok(Self::RestoreChannel),
            5 => Ok(Self::RestoreChannelName),
            6 => Ok(Self::RestorePeerTombstones),
            7 => Ok(Self::RestoreE2eeState),
            _ => Err(StorageError::UnsupportedVersion),
        }
    }
}

/// One deterministic, secret-free target plan entry.
pub struct StorageConstructionPlanEntry {
    sources: Vec<StorageConstructionSource>,
    target_table: TableId,
    target_key: StoredKey,
    target_record_schema: u32,
    action: StorageConstructionAction,
    transform_rule_id: u16,
}

impl StorageConstructionPlanEntry {
    /// Validates source order and the closed kind/action/table matrix.
    pub fn new(
        kind: StorageConstructionKind,
        mut sources: Vec<StorageConstructionSource>,
        target_table: TableId,
        target_key: StoredKey,
        target_record_schema: u32,
        action: StorageConstructionAction,
        transform_rule_id: u16,
    ) -> Result<Self, StorageError> {
        if sources.len() > 2 || target_record_schema == 0 || !is_construction_target(target_table) {
            return Err(StorageError::InvalidEncoding);
        }
        sources.sort_by(|left, right| left.identity().cmp(&right.identity()));
        if sources
            .iter()
            .zip(sources.iter().skip(1))
            .any(|(left, right)| left.identity() == right.identity())
        {
            return Err(StorageError::InvalidEncoding);
        }
        validate_action(kind, &sources, target_table, action, transform_rule_id)?;
        Ok(Self {
            sources,
            target_table,
            target_key,
            target_record_schema,
            action,
            transform_rule_id,
        })
    }

    /// Encodes one canonical plan entry.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let mut encoder = Encoder::with_capacity(128, MAX_PLAN_ENTRY_BYTES)?;
        encoder.put_u16(1)?;
        encoder.put_u32(u32::try_from(self.sources.len()).map_err(|_| StorageError::Overflow)?)?;
        for source in &self.sources {
            source.encode(&mut encoder)?;
        }
        encoder.put_u16(self.target_table.as_u16())?;
        encoder.put_vector_u32(self.target_key.as_bytes())?;
        encoder.put_u32(self.target_record_schema)?;
        encoder.put_u16(self.action as u16)?;
        encoder.put_u16(self.transform_rule_id)?;
        Ok(encoder.finish())
    }

    /// Parses and revalidates one full-consumption plan entry.
    pub fn decode(kind: StorageConstructionKind, encoded: &[u8]) -> Result<Self, StorageError> {
        let mut decoder = Decoder::new(encoded);
        if decoder.u16()? != 1 {
            return Err(StorageError::UnsupportedVersion);
        }
        let source_count = usize::try_from(decoder.u32()?).map_err(|_| StorageError::Overflow)?;
        if source_count > 2 {
            return Err(StorageError::LimitExceeded);
        }
        let mut sources = Vec::new();
        sources
            .try_reserve_exact(source_count)
            .map_err(|_| StorageError::AllocationFailed)?;
        for _ in 0..source_count {
            sources.push(StorageConstructionSource::decode(&mut decoder)?);
        }
        let target_table = TableId::from_u16(decoder.u16()?)?;
        let target_key = StoredKey::new(decoder.vector_u32(crate::MAX_STORED_KEY_BYTES)?.to_vec())?;
        let target_record_schema = decoder.u32()?;
        let action = StorageConstructionAction::decode(decoder.u16()?)?;
        let transform_rule_id = decoder.u16()?;
        decoder.finish()?;
        Self::new(
            kind,
            sources,
            target_table,
            target_key,
            target_record_schema,
            action,
            transform_rule_id,
        )
    }

    fn target_identity(&self) -> (TableId, &[u8]) {
        (self.target_table, self.target_key.as_bytes())
    }

    /// Borrows the zero-to-two source references in canonical order.
    #[must_use]
    pub fn sources(&self) -> &[StorageConstructionSource] {
        &self.sources
    }

    /// Returns the target table.
    #[must_use]
    pub const fn target_table(&self) -> TableId {
        self.target_table
    }

    /// Borrows the target stored key.
    #[must_use]
    pub const fn target_key(&self) -> &StoredKey {
        &self.target_key
    }

    /// Returns the target record schema.
    #[must_use]
    pub const fn target_record_schema(&self) -> u32 {
        self.target_record_schema
    }

    /// Returns the closed transform action.
    #[must_use]
    pub const fn action(&self) -> StorageConstructionAction {
        self.action
    }

    /// Returns the reserved transform rule ID, which must be zero.
    #[must_use]
    pub const fn transform_rule_id(&self) -> u16 {
        self.transform_rule_id
    }
}

/// Hashes a complete sorted plan and rejects duplicate/out-of-order targets.
pub fn construction_plan_hash(
    kind: StorageConstructionKind,
    entries: &[StorageConstructionPlanEntry],
    maximum_bytes: u64,
) -> Result<StorageDigest, StorageError> {
    let count = u64::try_from(entries.len()).map_err(|_| StorageError::Overflow)?;
    let mut hasher =
        ConstructionPlanHasher::new(count, maximum_bytes.min(MAX_CONSTRUCTION_PLAN_BYTES))?;
    let mut previous: Option<(TableId, &[u8])> = None;
    for entry in entries {
        validate_action(
            kind,
            &entry.sources,
            entry.target_table,
            entry.action,
            entry.transform_rule_id,
        )?;
        let identity = entry.target_identity();
        if previous.is_some_and(|value| value >= identity) {
            return Err(StorageError::InvalidEncoding);
        }
        hasher.update_entry(&entry.encode()?)?;
        previous = Some(identity);
    }
    hasher.finalize().map_err(StorageError::from)
}

/// Fields shared by the resumable marker and permanent completion identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageOperationIdentity {
    /// Operation kind.
    pub kind: StorageConstructionKind,
    /// Exact command protocol version.
    pub command_version: u32,
    /// Complete source header hash.
    pub source_database_header_hash: StorageDigest,
    /// Complete target header hash.
    pub target_database_header_hash: StorageDigest,
    /// Verified source guard hash.
    pub source_rollback_guard_hash: StorageDigest,
    /// Signed restore stream digest, absent otherwise.
    pub source_stream_digest: Option<StorageDigest>,
    /// Source schema generation.
    pub source_schema_generation: u64,
    /// Target schema generation.
    pub target_schema_generation: u64,
    /// Fixed restore or rekey profile hash.
    pub transform_profile_hash: StorageDigest,
    /// Fresh target database instance.
    pub target_database_instance_id: DatabaseId,
    /// Purpose-separated source master-key ID.
    pub source_master_key_id: StorageDigest,
    /// Purpose-separated source guard-root ID.
    pub source_guard_root_key_id: StorageDigest,
    /// Purpose-separated target master-key ID.
    pub target_master_key_id: StorageDigest,
    /// Purpose-separated target guard-root ID.
    pub target_guard_root_key_id: StorageDigest,
    /// Exact target-plan entry count.
    pub planned_entry_count: u64,
    /// Complete canonical plan hash.
    pub construction_plan_hash: StorageDigest,
}

impl StorageOperationIdentity {
    /// Validates version, schema relation, stream presence, and fixed profiles.
    // agenc-review: focus owner=storage reviewed=2026-08-27 reason=closed construction-kind matrix mirrors the normative identity union
    pub fn validate(&self) -> Result<(), StorageError> {
        if self.command_version != 1 || self.source_schema_generation != crate::SCHEMA_GENERATION {
            return Err(StorageError::UnsupportedVersion);
        }
        match self.kind {
            StorageConstructionKind::Restore
                if self.source_stream_digest.is_some()
                    && self.target_schema_generation == self.source_schema_generation
                    && self.transform_profile_hash == restore_transform_profile_hash()? =>
            {
                Ok(())
            }
            StorageConstructionKind::Rekey
                if self.source_stream_digest.is_none()
                    && self.target_schema_generation == self.source_schema_generation
                    && self.transform_profile_hash == rekey_transform_profile_hash()? =>
            {
                Ok(())
            }
            _ => Err(StorageError::InvalidEncoding),
        }
    }

    fn encode_tbs(&self) -> Result<Vec<u8>, StorageError> {
        let mut encoder = Encoder::with_capacity(384, 416)?;
        encoder.put_u16(1)?;
        self.encode_fields(&mut encoder, None)?;
        Ok(encoder.finish())
    }

    fn encode_fields(
        &self,
        encoder: &mut Encoder,
        output_path_hash: Option<StorageDigest>,
    ) -> Result<(), StorageError> {
        self.validate()?;
        encoder.put_u16(self.kind as u16)?;
        encoder.put_u32(self.command_version)?;
        encoder.put_fixed(self.source_database_header_hash.as_bytes())?;
        encoder.put_fixed(self.target_database_header_hash.as_bytes())?;
        encoder.put_fixed(self.source_rollback_guard_hash.as_bytes())?;
        encoder.put_vector_u32(
            self.source_stream_digest
                .as_ref()
                .map_or(&[][..], |digest| digest.as_bytes().as_slice()),
        )?;
        encoder.put_u64(self.source_schema_generation)?;
        encoder.put_u64(self.target_schema_generation)?;
        encoder.put_fixed(self.transform_profile_hash.as_bytes())?;
        encoder.put_fixed(self.target_database_instance_id.as_bytes())?;
        if let Some(output_path_hash) = output_path_hash {
            encoder.put_fixed(output_path_hash.as_bytes())?;
        }
        encoder.put_fixed(self.source_master_key_id.as_bytes())?;
        encoder.put_fixed(self.source_guard_root_key_id.as_bytes())?;
        encoder.put_fixed(self.target_master_key_id.as_bytes())?;
        encoder.put_fixed(self.target_guard_root_key_id.as_bytes())?;
        encoder.put_u64(self.planned_entry_count)?;
        encoder.put_fixed(self.construction_plan_hash.as_bytes())
    }

    fn decode_tbs(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        if decoder.u16()? != 1 {
            return Err(StorageError::UnsupportedVersion);
        }
        let (identity, _output_path_hash) = Self::decode_fields(decoder, false)?;
        Ok(identity)
    }

    fn decode_fields(
        decoder: &mut Decoder<'_>,
        includes_output_path_hash: bool,
    ) -> Result<(Self, Option<StorageDigest>), StorageError> {
        let kind = StorageConstructionKind::decode(decoder.u16()?)?;
        let command_version = decoder.u32()?;
        let source_database_header_hash = StorageDigest::from_bytes(decoder.array()?);
        let target_database_header_hash = StorageDigest::from_bytes(decoder.array()?);
        let source_rollback_guard_hash = StorageDigest::from_bytes(decoder.array()?);
        let stream = decoder.vector_u32(32)?;
        let source_stream_digest = match stream.len() {
            0 => None,
            32 => Some(StorageDigest::from_bytes(
                stream
                    .try_into()
                    .map_err(|_| StorageError::InvalidEncoding)?,
            )),
            _ => return Err(StorageError::InvalidEncoding),
        };
        let source_schema_generation = decoder.u64()?;
        let target_schema_generation = decoder.u64()?;
        let transform_profile_hash = StorageDigest::from_bytes(decoder.array()?);
        let target_database_instance_id = DatabaseId::from_bytes(decoder.array()?);
        let output_path_hash = if includes_output_path_hash {
            Some(StorageDigest::from_bytes(decoder.array()?))
        } else {
            None
        };
        let value = Self {
            kind,
            command_version,
            source_database_header_hash,
            target_database_header_hash,
            source_rollback_guard_hash,
            source_stream_digest,
            source_schema_generation,
            target_schema_generation,
            transform_profile_hash,
            target_database_instance_id,
            source_master_key_id: StorageDigest::from_bytes(decoder.array()?),
            source_guard_root_key_id: StorageDigest::from_bytes(decoder.array()?),
            target_master_key_id: StorageDigest::from_bytes(decoder.array()?),
            target_guard_root_key_id: StorageDigest::from_bytes(decoder.array()?),
            planned_entry_count: decoder.u64()?,
            construction_plan_hash: StorageDigest::from_bytes(decoder.array()?),
        };
        value.validate()?;
        Ok((value, output_path_hash))
    }

    /// Computes the permanent completed-operation identifier.
    pub fn operation_id(&self) -> Result<StorageDigest, StorageError> {
        storage_operation_id(&self.encode_tbs()?).map_err(StorageError::from)
    }
}

/// Authenticated resumable marker stored only in a staging target.
pub struct StorageConstruction {
    /// Stable construction identity.
    pub identity: StorageOperationIdentity,
    /// Hash of the path-local output directory.
    pub output_path_hash: StorageDigest,
    /// Exact next target cursor.
    pub next_target: StorageConstructionCursor,
    /// Number of plan entries committed before the cursor.
    pub target_records_committed: u64,
}

impl StorageConstruction {
    /// Validates identity and cursor/count agreement.
    pub fn validate(&self) -> Result<(), StorageError> {
        self.identity.validate()?;
        self.next_target.validate(
            self.target_records_committed,
            self.identity.planned_entry_count,
        )
    }

    /// Encodes the complete construction marker plaintext.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        self.validate()?;
        let mut encoder = Encoder::with_capacity(448, 4_096)?;
        encoder.put_u16(1)?;
        self.identity
            .encode_fields(&mut encoder, Some(self.output_path_hash))?;
        self.next_target.encode(&mut encoder)?;
        encoder.put_u64(self.target_records_committed)?;
        Ok(encoder.finish())
    }

    /// Parses and revalidates one full-consumption construction marker.
    pub fn decode(encoded: &[u8]) -> Result<Self, StorageError> {
        let mut decoder = Decoder::new(encoded);
        if decoder.u16()? != 1 {
            return Err(StorageError::UnsupportedVersion);
        }
        let (identity, output_path_hash) =
            StorageOperationIdentity::decode_fields(&mut decoder, true)?;
        let output_path_hash = output_path_hash.ok_or(StorageError::InvalidEncoding)?;
        let next_target = StorageConstructionCursor::decode(&mut decoder)?;
        let target_records_committed = decoder.u64()?;
        decoder.finish()?;
        let value = Self {
            identity,
            output_path_hash,
            next_target,
            target_records_committed,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Permanent exact completion replacing the staging marker.
pub struct StorageOperationCompletion {
    /// Stable operation identity.
    pub identity: StorageOperationIdentity,
    /// Recomputed permanent operation ID.
    pub storage_operation_id: StorageDigest,
    /// Exact finalized plan count.
    pub target_records_committed: u64,
    /// Final storage commit sequence.
    pub finalization_storage_commit_sequence: u64,
    /// Final manifest sequence.
    pub finalization_manifest_sequence: u64,
    /// Final state generation.
    pub finalization_state_generation: u64,
    /// Final account-service response count.
    pub finalization_account_service_response_count: u64,
    /// Final nonce high-water mark.
    pub finalization_nonce_draw_high_water: u64,
}

impl StorageOperationCompletion {
    /// Validates the permanent ID, count, and nonzero finalization commit.
    pub fn validate(&self) -> Result<(), StorageError> {
        self.identity.validate()?;
        if self.storage_operation_id != self.identity.operation_id()?
            || self.target_records_committed != self.identity.planned_entry_count
            || self.finalization_storage_commit_sequence == 0
        {
            return Err(StorageError::StaleState);
        }
        Ok(())
    }

    /// Encodes the canonical permanent completion plaintext.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        self.validate()?;
        let mut encoder = Encoder::with_capacity(480, 512)?;
        encoder.put_u16(1)?;
        encoder.put_fixed(&self.identity.encode_tbs()?)?;
        encoder.put_fixed(self.storage_operation_id.as_bytes())?;
        encoder.put_u64(self.target_records_committed)?;
        encoder.put_u64(self.finalization_storage_commit_sequence)?;
        encoder.put_u64(self.finalization_manifest_sequence)?;
        encoder.put_u64(self.finalization_state_generation)?;
        encoder.put_u64(self.finalization_account_service_response_count)?;
        encoder.put_u64(self.finalization_nonce_draw_high_water)?;
        Ok(encoder.finish())
    }

    /// Parses and revalidates one full-consumption permanent completion.
    pub fn decode(encoded: &[u8]) -> Result<Self, StorageError> {
        let mut decoder = Decoder::new(encoded);
        if decoder.u16()? != 1 {
            return Err(StorageError::UnsupportedVersion);
        }
        let value = Self {
            identity: StorageOperationIdentity::decode_tbs(&mut decoder)?,
            storage_operation_id: StorageDigest::from_bytes(decoder.array()?),
            target_records_committed: decoder.u64()?,
            finalization_storage_commit_sequence: decoder.u64()?,
            finalization_manifest_sequence: decoder.u64()?,
            finalization_state_generation: decoder.u64()?,
            finalization_account_service_response_count: decoder.u64()?,
            finalization_nonce_draw_high_water: decoder.u64()?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }
}

fn is_construction_target(table: TableId) -> bool {
    matches!(table.as_u16(), 1..=13 | 17..=24 | 26)
}

// agenc-review: focus owner=storage reviewed=2026-08-27 reason=closed action-kind-source matrix is reviewed as one exhaustive protocol table
fn validate_action(
    kind: StorageConstructionKind,
    sources: &[StorageConstructionSource],
    target: TableId,
    action: StorageConstructionAction,
    rule_id: u16,
) -> Result<(), StorageError> {
    let one_same_table = sources
        .first()
        .is_some_and(|source| sources.len() == 1 && source.table == target);
    match (kind, action) {
        (StorageConstructionKind::Rekey, StorageConstructionAction::RekeyCopy)
            if rule_id == 0 && one_same_table =>
        {
            Ok(())
        }
        (StorageConstructionKind::Restore, StorageConstructionAction::RestoreCopy)
            if rule_id == 0
                && one_same_table
                && matches!(target.as_u16(), 2 | 3 | 5 | 6 | 10 | 19..=22 | 24 | 26) =>
        {
            Ok(())
        }
        (StorageConstructionKind::Restore, StorageConstructionAction::RestoreAccount)
            if rule_id == 0 && one_same_table && target == TableId::Account =>
        {
            Ok(())
        }
        (StorageConstructionKind::Restore, StorageConstructionAction::RestoreChannel)
            if rule_id == 0 && one_same_table && target == TableId::Channel =>
        {
            Ok(())
        }
        (StorageConstructionKind::Restore, StorageConstructionAction::RestoreChannelName)
            if rule_id == 0 && sources.len() == 2 && target == TableId::ChannelName =>
        {
            Ok(())
        }
        (StorageConstructionKind::Restore, StorageConstructionAction::RestorePeerTombstones)
            if rule_id == 0 && one_same_table && target == TableId::FederationPeer =>
        {
            Ok(())
        }
        (StorageConstructionKind::Restore, StorageConstructionAction::RestoreE2eeState)
            if rule_id == 0
                && target == TableId::E2eeState
                && (one_same_table
                    || (sources.len() == 2
                        && sources
                            .iter()
                            .all(|source| source.table == TableId::E2eeState))) =>
        {
            Ok(())
        }
        _ => Err(StorageError::InvalidEncoding),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO: StorageDigest = StorageDigest::from_bytes([0; 32]);

    #[test]
    fn cursor_and_operation_decoders_reject_invalid_profiles() -> Result<(), StorageError> {
        let invalid_cursor = StorageConstructionCursor::AtTarget {
            table: TableId::KeyCheck,
            key: StoredKey::new(vec![1])?,
        };
        let mut encoder = Encoder::with_capacity(16, 32)?;
        assert_eq!(
            invalid_cursor.encode(&mut encoder),
            Err(StorageError::InvalidEncoding),
        );

        let mut encoder = Encoder::with_capacity(16, 32)?;
        encoder.put_u16(1)?;
        encoder.put_u16(TableId::KeyCheck.as_u16())?;
        encoder.put_vector_u32(&[1])?;
        let encoded = encoder.finish();
        assert!(matches!(
            StorageConstructionCursor::decode(&mut Decoder::new(&encoded)),
            Err(StorageError::InvalidEncoding),
        ));

        let identity = StorageOperationIdentity {
            kind: StorageConstructionKind::Rekey,
            command_version: 1,
            source_database_header_hash: ZERO,
            target_database_header_hash: ZERO,
            source_rollback_guard_hash: ZERO,
            source_stream_digest: None,
            source_schema_generation: 1,
            target_schema_generation: 1,
            transform_profile_hash: ZERO,
            target_database_instance_id: DatabaseId::from_bytes([0; 16]),
            source_master_key_id: ZERO,
            source_guard_root_key_id: ZERO,
            target_master_key_id: ZERO,
            target_guard_root_key_id: ZERO,
            planned_entry_count: 0,
            construction_plan_hash: ZERO,
        };
        assert_eq!(identity.validate(), Err(StorageError::UnsupportedVersion),);
        Ok(())
    }
}
