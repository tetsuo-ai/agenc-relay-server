//! Authenticated mutation manifests, checkpoints, and exact logical accounting.

use std::collections::BTreeSet;

use agenc_ircd_crypto::{
    StorageDigest, integrity_checkpoint_hash, integrity_manifest_hash, tracked_record_commitment,
    tracked_state_digest,
};
use agenc_ircd_types::DatabaseId;

use crate::codec::{Decoder, Encoder};
use crate::{
    MAX_NONCE_DRAWS, MAX_SEALED_RECORD_BYTES, MAX_STORED_KEY_BYTES, MAX_TRACKED_MUTATIONS,
    StorageError, StoredKey, TableId,
};

/// Greatest canonical manifest or checkpoint plaintext accepted for sealing.
pub const MAX_INTEGRITY_PLAINTEXT_BYTES: usize = 16_777_200;
const CHECKPOINT_TBS_BYTES: usize = 194;
/// Commitment input: table id (2), key length prefix (4), the longest key, record
/// schema (4), and the 32-byte sealed-record identity.
const TRACKED_RECORD_COMMITMENT_INPUT_BYTES: usize = 2 + 4 + MAX_STORED_KEY_BYTES + 4 + 32;
/// Exact plaintext size of an integrity checkpoint.
pub const INTEGRITY_CHECKPOINT_BYTES: usize = 226;

/// Before/after commitment for one tracked database row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegrityRecordVersion {
    /// No row exists.
    Absent,
    /// A row exists with this schema and complete SealedRecord ID.
    Present {
        /// Nonzero persistent record schema.
        record_schema: u32,
        /// Commitment to the complete sealed envelope.
        sealed_record_id: StorageDigest,
    },
}

impl IntegrityRecordVersion {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), StorageError> {
        match self {
            Self::Absent => {
                encoder.put_u16(0)?;
                encoder.put_u32(0)?;
                encoder.put_vector_u32(&[])
            }
            Self::Present {
                record_schema,
                sealed_record_id,
            } => {
                if *record_schema == 0 {
                    return Err(StorageError::InvalidEncoding);
                }
                encoder.put_u16(1)?;
                encoder.put_u32(*record_schema)?;
                encoder.put_vector_u32(sealed_record_id.as_bytes())
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        let presence = decoder.u16()?;
        let record_schema = decoder.u32()?;
        let identifier = decoder.vector_u32(32)?;
        match (presence, record_schema, identifier.len()) {
            (0, 0, 0) => Ok(Self::Absent),
            (1, schema, 32) if schema != 0 => Ok(Self::Present {
                record_schema: schema,
                sealed_record_id: StorageDigest::from_bytes(
                    identifier
                        .try_into()
                        .map_err(|_| StorageError::InvalidEncoding)?,
                ),
            }),
            _ => Err(StorageError::InvalidEncoding),
        }
    }
}

/// One unique integrity-tracked row transition.
#[derive(Clone, Eq, PartialEq)]
pub struct IntegrityRecordMutation {
    table: TableId,
    stored_key: StoredKey,
    before: IntegrityRecordVersion,
    after: IntegrityRecordVersion,
}

impl IntegrityRecordMutation {
    /// Validates one actual before/after record change.
    pub fn new(
        table: TableId,
        stored_key: StoredKey,
        before: IntegrityRecordVersion,
        after: IntegrityRecordVersion,
    ) -> Result<Self, StorageError> {
        if !table.is_integrity_tracked() || before == after {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self {
            table,
            stored_key,
            before,
            after,
        })
    }

    fn encode(&self, encoder: &mut Encoder) -> Result<(), StorageError> {
        encoder.put_u16(self.table.as_u16())?;
        encoder.put_vector_u32(self.stored_key.as_bytes())?;
        self.before.encode(encoder)?;
        self.after.encode(encoder)
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        Self::new(
            TableId::from_u16(decoder.u16()?)?,
            StoredKey::new(decoder.vector_u32(MAX_STORED_KEY_BYTES)?.to_vec())?,
            IntegrityRecordVersion::decode(decoder)?,
            IntegrityRecordVersion::decode(decoder)?,
        )
    }

    /// Returns the tracked table.
    #[must_use]
    pub const fn table(&self) -> TableId {
        self.table
    }

    /// Borrows the exact stored database key.
    #[must_use]
    pub const fn stored_key(&self) -> &StoredKey {
        &self.stored_key
    }

    /// Returns the before version.
    #[must_use]
    pub const fn before(&self) -> IntegrityRecordVersion {
        self.before
    }

    /// Returns the after version.
    #[must_use]
    pub const fn after(&self) -> IntegrityRecordVersion {
        self.after
    }
}

/// Canonical fields hashed by one integrity manifest.
pub struct IntegrityManifestTbs {
    /// Database instance being mutated.
    pub database_instance_id: DatabaseId,
    /// Successive manifest sequence.
    pub manifest_sequence: u64,
    /// Successive StateMeta commit sequence.
    pub storage_commit_sequence: u64,
    /// Prior logical generation.
    pub previous_state_generation: u64,
    /// Resulting logical generation.
    pub resulting_state_generation: u64,
    /// Prior account-service response count.
    pub previous_account_service_response_count: u64,
    /// Resulting account-service response count.
    pub resulting_account_service_response_count: u64,
    /// Prior committed nonce high-water mark.
    pub previous_nonce_draw_high_water: u64,
    /// Start of the one-use transaction reservation.
    pub transaction_nonce_reservation_start: u64,
    /// Resulting committed nonce high-water mark.
    pub resulting_nonce_draw_high_water: u64,
    /// Exact number of envelopes sealed by the transaction.
    pub transaction_seal_count: u32,
    /// Immediate predecessor manifest or checkpoint cut hash.
    pub previous_manifest_hash: StorageDigest,
    mutations: Vec<IntegrityRecordMutation>,
}

impl IntegrityManifestTbs {
    /// Validates ordering, counters, seal count, and nonce arithmetic.
    #[expect(
        clippy::too_many_arguments,
        reason = "the arguments mirror the fixed canonical manifest TBS fields"
    )]
    pub fn new(
        database_instance_id: DatabaseId,
        manifest_sequence: u64,
        storage_commit_sequence: u64,
        previous_state_generation: u64,
        resulting_state_generation: u64,
        previous_account_service_response_count: u64,
        resulting_account_service_response_count: u64,
        previous_nonce_draw_high_water: u64,
        transaction_nonce_reservation_start: u64,
        resulting_nonce_draw_high_water: u64,
        transaction_seal_count: u32,
        previous_manifest_hash: StorageDigest,
        mut mutations: Vec<IntegrityRecordMutation>,
    ) -> Result<Self, StorageError> {
        if manifest_sequence == 0
            || mutations.is_empty()
            || mutations.len() > MAX_TRACKED_MUTATIONS
            || transaction_nonce_reservation_start < previous_nonce_draw_high_water
            || resulting_nonce_draw_high_water > MAX_NONCE_DRAWS
        {
            return Err(StorageError::LimitExceeded);
        }
        mutations.sort_by(|left, right| {
            (left.table, left.stored_key.as_bytes())
                .cmp(&(right.table, right.stored_key.as_bytes()))
        });
        let mut unique = BTreeSet::new();
        for mutation in &mutations {
            if !unique.insert((mutation.table, mutation.stored_key.as_bytes())) {
                return Err(StorageError::InvalidEncoding);
            }
        }
        let present = mutations
            .iter()
            .filter(|mutation| matches!(mutation.after, IntegrityRecordVersion::Present { .. }))
            .count();
        let expected_seals = present.checked_add(2).ok_or(StorageError::Overflow)?;
        if usize::try_from(transaction_seal_count).map_err(|_| StorageError::Overflow)?
            != expected_seals
        {
            return Err(StorageError::InvalidEncoding);
        }
        let expected_high_water = transaction_nonce_reservation_start
            .checked_add(u64::from(transaction_seal_count))
            .ok_or(StorageError::Overflow)?;
        if resulting_nonce_draw_high_water != expected_high_water {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self {
            database_instance_id,
            manifest_sequence,
            storage_commit_sequence,
            previous_state_generation,
            resulting_state_generation,
            previous_account_service_response_count,
            resulting_account_service_response_count,
            previous_nonce_draw_high_water,
            transaction_nonce_reservation_start,
            resulting_nonce_draw_high_water,
            transaction_seal_count,
            previous_manifest_hash,
            mutations,
        })
    }

    fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let mut encoder = Encoder::with_capacity(256, MAX_INTEGRITY_PLAINTEXT_BYTES)?;
        encoder.put_u16(1)?;
        encoder.put_fixed(self.database_instance_id.as_bytes())?;
        encoder.put_u64(self.manifest_sequence)?;
        encoder.put_u64(self.storage_commit_sequence)?;
        encoder.put_u64(self.previous_state_generation)?;
        encoder.put_u64(self.resulting_state_generation)?;
        encoder.put_u64(self.previous_account_service_response_count)?;
        encoder.put_u64(self.resulting_account_service_response_count)?;
        encoder.put_u64(self.previous_nonce_draw_high_water)?;
        encoder.put_u64(self.transaction_nonce_reservation_start)?;
        encoder.put_u64(self.resulting_nonce_draw_high_water)?;
        encoder.put_u32(self.transaction_seal_count)?;
        encoder.put_fixed(self.previous_manifest_hash.as_bytes())?;
        let mutation_count =
            u32::try_from(self.mutations.len()).map_err(|_| StorageError::LimitExceeded)?;
        encoder.put_u32(mutation_count)?;
        for mutation in &self.mutations {
            mutation.encode(&mut encoder)?;
        }
        Ok(encoder.finish())
    }

    fn decode(encoded: &[u8]) -> Result<Self, StorageError> {
        let mut decoder = Decoder::new(encoded);
        if decoder.u16()? != 1 {
            return Err(StorageError::UnsupportedVersion);
        }
        let database_instance_id = DatabaseId::from_bytes(decoder.array()?);
        let manifest_sequence = decoder.u64()?;
        let storage_commit_sequence = decoder.u64()?;
        let previous_state_generation = decoder.u64()?;
        let resulting_state_generation = decoder.u64()?;
        let previous_account_service_response_count = decoder.u64()?;
        let resulting_account_service_response_count = decoder.u64()?;
        let previous_nonce_draw_high_water = decoder.u64()?;
        let transaction_nonce_reservation_start = decoder.u64()?;
        let resulting_nonce_draw_high_water = decoder.u64()?;
        let transaction_seal_count = decoder.u32()?;
        let previous_manifest_hash = StorageDigest::from_bytes(decoder.array()?);
        let count = usize::try_from(decoder.u32()?).map_err(|_| StorageError::Overflow)?;
        if !(1..=MAX_TRACKED_MUTATIONS).contains(&count) {
            return Err(StorageError::LimitExceeded);
        }
        let mut mutations = Vec::new();
        mutations
            .try_reserve_exact(count)
            .map_err(|_| StorageError::AllocationFailed)?;
        for _ in 0..count {
            mutations.push(IntegrityRecordMutation::decode(&mut decoder)?);
        }
        decoder.finish()?;
        Self::new(
            database_instance_id,
            manifest_sequence,
            storage_commit_sequence,
            previous_state_generation,
            resulting_state_generation,
            previous_account_service_response_count,
            resulting_account_service_response_count,
            previous_nonce_draw_high_water,
            transaction_nonce_reservation_start,
            resulting_nonce_draw_high_water,
            transaction_seal_count,
            previous_manifest_hash,
            mutations,
        )
    }

    /// Borrows mutations in canonical table/key order.
    #[must_use]
    pub fn mutations(&self) -> &[IntegrityRecordMutation] {
        &self.mutations
    }
}

/// Complete self-verifying integrity manifest plaintext.
pub struct IntegrityManifest {
    tbs: IntegrityManifestTbs,
    manifest_hash: StorageDigest,
}

impl IntegrityManifest {
    /// Hashes a validated manifest TBS value.
    pub fn new(tbs: IntegrityManifestTbs) -> Result<Self, StorageError> {
        let manifest_hash = integrity_manifest_hash(&tbs.encode()?)?;
        Ok(Self { tbs, manifest_hash })
    }

    /// Parses and verifies a complete manifest plaintext.
    pub fn decode(encoded: &[u8]) -> Result<Self, StorageError> {
        if encoded.len() > MAX_INTEGRITY_PLAINTEXT_BYTES || encoded.len() < 32 {
            return Err(StorageError::LimitExceeded);
        }
        let tbs_length = encoded
            .len()
            .checked_sub(32)
            .ok_or(StorageError::Overflow)?;
        let tbs_bytes = encoded
            .get(..tbs_length)
            .ok_or(StorageError::InvalidEncoding)?;
        let hash_bytes: [u8; 32] = encoded
            .get(tbs_length..)
            .ok_or(StorageError::InvalidEncoding)?
            .try_into()
            .map_err(|_| StorageError::InvalidEncoding)?;
        let tbs = IntegrityManifestTbs::decode(tbs_bytes)?;
        let expected = integrity_manifest_hash(tbs_bytes)?;
        if expected != StorageDigest::from_bytes(hash_bytes) {
            return Err(StorageError::AuthenticationFailed);
        }
        Ok(Self {
            tbs,
            manifest_hash: expected,
        })
    }

    /// Encodes the complete manifest plaintext.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let tbs = self.tbs.encode()?;
        let capacity = tbs.len().checked_add(32).ok_or(StorageError::Overflow)?;
        let mut encoder = Encoder::with_capacity(capacity, MAX_INTEGRITY_PLAINTEXT_BYTES)?;
        encoder.put_fixed(&tbs)?;
        encoder.put_fixed(self.manifest_hash.as_bytes())?;
        Ok(encoder.finish())
    }

    /// Returns the validated transition fields.
    #[must_use]
    pub const fn tbs(&self) -> &IntegrityManifestTbs {
        &self.tbs
    }

    /// Returns the verified manifest hash.
    #[must_use]
    pub const fn manifest_hash(&self) -> StorageDigest {
        self.manifest_hash
    }
}

/// Fixed fields committed by one compact integrity checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntegrityCheckpointTbs {
    /// Database instance being checkpointed.
    pub database_instance_id: DatabaseId,
    /// Commit sequence at the immutable cut.
    pub cut_storage_commit_sequence: u64,
    /// Manifest sequence at the immutable cut.
    pub cut_manifest_sequence: u64,
    /// State generation at the immutable cut.
    pub cut_state_generation: u64,
    /// Response count at the immutable cut.
    pub cut_account_service_response_count: u64,
    /// Nonce high-water mark at the immutable cut.
    pub cut_nonce_draw_high_water: u64,
    /// Manifest hash at the cut.
    pub cut_manifest_hash: StorageDigest,
    /// Exact tracked record count.
    pub tracked_record_count: u64,
    /// Ordered tracked record-set digest.
    pub tracked_state_digest: StorageDigest,
    /// Previous retained checkpoint hash.
    pub previous_checkpoint_hash: StorageDigest,
    /// Commit sequence after checkpoint installation.
    pub installation_storage_commit_sequence: u64,
    /// Manifest sequence observed at installation.
    pub installation_manifest_sequence: u64,
    /// Start of the two-draw installation reservation.
    pub installation_nonce_reservation_start: u64,
    /// End of the two-draw installation reservation.
    pub installation_nonce_draw_high_water: u64,
}

impl IntegrityCheckpointTbs {
    fn validate(&self) -> Result<(), StorageError> {
        // Installation reserves exactly two draws, so the recorded start is always the
        // installation high-water mark minus two. That also holds for the genesis
        // checkpoint written by `initialize_storage`; the specification sentence saying
        // the genesis start equals the high-water mark itself needs a later amendment.
        if self.cut_nonce_draw_high_water > MAX_NONCE_DRAWS
            || self.installation_nonce_draw_high_water > MAX_NONCE_DRAWS
            || self.installation_manifest_sequence < self.cut_manifest_sequence
            || self.installation_nonce_draw_high_water
                != self
                    .installation_nonce_reservation_start
                    .checked_add(2)
                    .ok_or(StorageError::Overflow)?
        {
            return Err(StorageError::StaleState);
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, StorageError> {
        self.validate()?;
        let mut encoder = Encoder::with_capacity(CHECKPOINT_TBS_BYTES, CHECKPOINT_TBS_BYTES)?;
        encoder.put_u16(1)?;
        encoder.put_fixed(self.database_instance_id.as_bytes())?;
        encoder.put_u64(self.cut_storage_commit_sequence)?;
        encoder.put_u64(self.cut_manifest_sequence)?;
        encoder.put_u64(self.cut_state_generation)?;
        encoder.put_u64(self.cut_account_service_response_count)?;
        encoder.put_u64(self.cut_nonce_draw_high_water)?;
        encoder.put_fixed(self.cut_manifest_hash.as_bytes())?;
        encoder.put_u64(self.tracked_record_count)?;
        encoder.put_fixed(self.tracked_state_digest.as_bytes())?;
        encoder.put_fixed(self.previous_checkpoint_hash.as_bytes())?;
        encoder.put_u64(self.installation_storage_commit_sequence)?;
        encoder.put_u64(self.installation_manifest_sequence)?;
        encoder.put_u64(self.installation_nonce_reservation_start)?;
        encoder.put_u64(self.installation_nonce_draw_high_water)?;
        Ok(encoder.finish())
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        if decoder.u16()? != 1 {
            return Err(StorageError::UnsupportedVersion);
        }
        let value = Self {
            database_instance_id: DatabaseId::from_bytes(decoder.array()?),
            cut_storage_commit_sequence: decoder.u64()?,
            cut_manifest_sequence: decoder.u64()?,
            cut_state_generation: decoder.u64()?,
            cut_account_service_response_count: decoder.u64()?,
            cut_nonce_draw_high_water: decoder.u64()?,
            cut_manifest_hash: StorageDigest::from_bytes(decoder.array()?),
            tracked_record_count: decoder.u64()?,
            tracked_state_digest: StorageDigest::from_bytes(decoder.array()?),
            previous_checkpoint_hash: StorageDigest::from_bytes(decoder.array()?),
            installation_storage_commit_sequence: decoder.u64()?,
            installation_manifest_sequence: decoder.u64()?,
            installation_nonce_reservation_start: decoder.u64()?,
            installation_nonce_draw_high_water: decoder.u64()?,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Complete self-verifying checkpoint plaintext.
pub struct IntegrityCheckpoint {
    tbs: IntegrityCheckpointTbs,
    checkpoint_hash: StorageDigest,
}

impl IntegrityCheckpoint {
    /// Hashes one validated checkpoint TBS value.
    pub fn new(tbs: IntegrityCheckpointTbs) -> Result<Self, StorageError> {
        let checkpoint_hash = integrity_checkpoint_hash(&tbs.encode()?)?;
        Ok(Self {
            tbs,
            checkpoint_hash,
        })
    }

    /// Parses and verifies the exact checkpoint plaintext.
    pub fn decode(encoded: &[u8]) -> Result<Self, StorageError> {
        if encoded.len() != INTEGRITY_CHECKPOINT_BYTES {
            return Err(StorageError::InvalidEncoding);
        }
        let mut decoder = Decoder::new(encoded);
        let tbs = IntegrityCheckpointTbs::decode(&mut decoder)?;
        let candidate = StorageDigest::from_bytes(decoder.array()?);
        decoder.finish()?;
        let expected = integrity_checkpoint_hash(&tbs.encode()?)?;
        if expected != candidate {
            return Err(StorageError::AuthenticationFailed);
        }
        Ok(Self {
            tbs,
            checkpoint_hash: candidate,
        })
    }

    /// Encodes the exact checkpoint plaintext.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let mut encoder =
            Encoder::with_capacity(INTEGRITY_CHECKPOINT_BYTES, INTEGRITY_CHECKPOINT_BYTES)?;
        encoder.put_fixed(&self.tbs.encode()?)?;
        encoder.put_fixed(self.checkpoint_hash.as_bytes())?;
        Ok(encoder.finish())
    }

    /// Returns the verified checkpoint hash.
    #[must_use]
    pub const fn checkpoint_hash(&self) -> StorageDigest {
        self.checkpoint_hash
    }

    /// Returns the validated checkpoint fields.
    #[must_use]
    pub const fn tbs(&self) -> &IntegrityCheckpointTbs {
        &self.tbs
    }
}

/// One canonical record tuple used to reconstruct a checkpoint digest.
pub struct TrackedRecord<'a> {
    /// Integrity-tracked table.
    pub table: TableId,
    /// Exact stored key.
    pub stored_key: &'a StoredKey,
    /// Nonzero record schema.
    pub record_schema: u32,
    /// Complete envelope identifier.
    pub sealed_record_id: StorageDigest,
}

/// Recomputes the exact ordered tracked-state digest.
pub fn compute_tracked_state_digest(
    records: &mut [TrackedRecord<'_>],
) -> Result<StorageDigest, StorageError> {
    records.sort_by(|left, right| {
        (left.table, left.stored_key.as_bytes()).cmp(&(right.table, right.stored_key.as_bytes()))
    });
    let mut commitments = Vec::new();
    commitments
        .try_reserve_exact(records.len())
        .map_err(|_| StorageError::AllocationFailed)?;
    let mut previous: Option<(TableId, &[u8])> = None;
    for record in records {
        if !record.table.is_integrity_tracked() || record.record_schema == 0 {
            return Err(StorageError::InvalidEncoding);
        }
        let identity = (record.table, record.stored_key.as_bytes());
        if previous == Some(identity) {
            return Err(StorageError::InvalidEncoding);
        }
        previous = Some(identity);
        let mut encoder = Encoder::with_capacity(64, TRACKED_RECORD_COMMITMENT_INPUT_BYTES)?;
        encoder.put_u16(record.table.as_u16())?;
        encoder.put_vector_u32(record.stored_key.as_bytes())?;
        encoder.put_u32(record.record_schema)?;
        encoder.put_fixed(record.sealed_record_id.as_bytes())?;
        commitments.push(tracked_record_commitment(&encoder.finish())?);
    }
    let count = u64::try_from(commitments.len()).map_err(|_| StorageError::Overflow)?;
    tracked_state_digest(count, &commitments).map_err(StorageError::from)
}

/// Returns the exact logical charge for one numbered-table row.
pub fn logical_record_charge(
    stored_key_bytes: usize,
    sealed_record_bytes: usize,
) -> Result<u64, StorageError> {
    if stored_key_bytes == 0
        || stored_key_bytes > MAX_STORED_KEY_BYTES
        || !(crate::MIN_SEALED_RECORD_BYTES..=MAX_SEALED_RECORD_BYTES)
            .contains(&sealed_record_bytes)
    {
        return Err(StorageError::LimitExceeded);
    }
    // Row layout: table id (2), key length prefix (4), key, sealed-record length prefix
    // (4), sealed record.
    let total = 2_usize
        .checked_add(4)
        .and_then(|value| value.checked_add(stored_key_bytes))
        .and_then(|value| value.checked_add(4))
        .and_then(|value| value.checked_add(sealed_record_bytes))
        .ok_or(StorageError::Overflow)?;
    u64::try_from(total).map_err(|_| StorageError::Overflow)
}

/// Returns the exact logical charge for one fixed meta row.
pub fn logical_meta_charge(key_bytes: usize, value_bytes: usize) -> Result<u64, StorageError> {
    if key_bytes == 0 || value_bytes == 0 {
        return Err(StorageError::InvalidEncoding);
    }
    let total = 4_usize
        .checked_add(key_bytes)
        .and_then(|value| value.checked_add(4))
        .and_then(|value| value.checked_add(value_bytes))
        .ok_or(StorageError::Overflow)?;
    u64::try_from(total).map_err(|_| StorageError::Overflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> StorageDigest {
        StorageDigest::from_bytes([byte; 32])
    }

    fn stored_key(byte: u8) -> Result<StoredKey, StorageError> {
        StoredKey::new(vec![byte])
    }

    fn mutation(byte: u8) -> Result<IntegrityRecordMutation, StorageError> {
        IntegrityRecordMutation::new(
            TableId::Account,
            stored_key(byte)?,
            IntegrityRecordVersion::Absent,
            IntegrityRecordVersion::Present {
                record_schema: 1,
                sealed_record_id: digest(byte),
            },
        )
    }

    fn manifest_tbs(
        mutations: Vec<IntegrityRecordMutation>,
    ) -> Result<IntegrityManifestTbs, StorageError> {
        let seals = u32::try_from(
            mutations
                .iter()
                .filter(|mutation| {
                    matches!(mutation.after(), IntegrityRecordVersion::Present { .. })
                })
                .count()
                + 2,
        )
        .map_err(|_| StorageError::Overflow)?;
        IntegrityManifestTbs::new(
            DatabaseId::from_bytes([1; 16]),
            1,
            1,
            0,
            1,
            0,
            0,
            10,
            10,
            10 + u64::from(seals),
            seals,
            digest(2),
            mutations,
        )
    }

    fn checkpoint_tbs() -> IntegrityCheckpointTbs {
        IntegrityCheckpointTbs {
            database_instance_id: DatabaseId::from_bytes([3; 16]),
            cut_storage_commit_sequence: 2,
            cut_manifest_sequence: 2,
            cut_state_generation: 2,
            cut_account_service_response_count: 1,
            cut_nonce_draw_high_water: 20,
            cut_manifest_hash: digest(4),
            tracked_record_count: 1,
            tracked_state_digest: digest(5),
            previous_checkpoint_hash: digest(6),
            installation_storage_commit_sequence: 3,
            installation_manifest_sequence: 2,
            installation_nonce_reservation_start: 20,
            installation_nonce_draw_high_water: 22,
        }
    }

    #[test]
    fn record_versions_reject_zero_schema_and_noncanonical_encodings() -> Result<(), StorageError> {
        let mut encoder = Encoder::with_capacity(38, 38)?;
        assert_eq!(
            IntegrityRecordVersion::Present {
                record_schema: 0,
                sealed_record_id: digest(1),
            }
            .encode(&mut encoder),
            Err(StorageError::InvalidEncoding)
        );

        for (presence, schema, identifier) in [
            (0_u16, 1_u32, Vec::new()),
            (1, 0, vec![0; 32]),
            (1, 1, vec![0; 31]),
            (2, 1, vec![0; 32]),
        ] {
            let mut encoder = Encoder::with_capacity(42, 42)?;
            encoder.put_u16(presence)?;
            encoder.put_u32(schema)?;
            encoder.put_vector_u32(&identifier)?;
            assert_eq!(
                IntegrityRecordVersion::decode(&mut Decoder::new(&encoder.finish())),
                Err(StorageError::InvalidEncoding)
            );
        }
        Ok(())
    }

    #[test]
    fn manifest_validation_rejects_each_independent_limit() -> Result<(), StorageError> {
        let valid = mutation(1)?;
        assert!(matches!(
            IntegrityManifestTbs::new(
                DatabaseId::from_bytes([1; 16]),
                0,
                1,
                0,
                1,
                0,
                0,
                10,
                10,
                13,
                3,
                digest(2),
                vec![valid.clone()],
            ),
            Err(StorageError::LimitExceeded)
        ));
        assert!(matches!(
            manifest_tbs(Vec::new()),
            Err(StorageError::LimitExceeded)
        ));
        assert!(matches!(
            manifest_tbs(vec![valid.clone(); MAX_TRACKED_MUTATIONS + 1]),
            Err(StorageError::LimitExceeded)
        ));
        assert!(matches!(
            IntegrityManifestTbs::new(
                DatabaseId::from_bytes([1; 16]),
                1,
                1,
                0,
                1,
                0,
                0,
                11,
                10,
                13,
                3,
                digest(2),
                vec![valid.clone()],
            ),
            Err(StorageError::LimitExceeded)
        ));
        assert!(matches!(
            IntegrityManifestTbs::new(
                DatabaseId::from_bytes([1; 16]),
                1,
                1,
                0,
                1,
                0,
                0,
                10,
                10,
                MAX_NONCE_DRAWS + 1,
                3,
                digest(2),
                vec![valid],
            ),
            Err(StorageError::LimitExceeded)
        ));
        Ok(())
    }

    #[test]
    fn manifest_validation_rejects_duplicates_seal_mismatch_and_nonce_errors()
    -> Result<(), StorageError> {
        let duplicate = mutation(1)?;
        assert!(matches!(
            manifest_tbs(vec![duplicate.clone(), duplicate]),
            Err(StorageError::InvalidEncoding)
        ));
        assert!(matches!(
            IntegrityManifestTbs::new(
                DatabaseId::from_bytes([1; 16]),
                1,
                1,
                0,
                1,
                0,
                0,
                10,
                10,
                12,
                2,
                digest(2),
                vec![mutation(2)?],
            ),
            Err(StorageError::InvalidEncoding)
        ));
        assert!(matches!(
            IntegrityManifestTbs::new(
                DatabaseId::from_bytes([1; 16]),
                1,
                1,
                0,
                1,
                0,
                0,
                10,
                10,
                14,
                3,
                digest(2),
                vec![mutation(3)?],
            ),
            Err(StorageError::InvalidEncoding)
        ));
        assert!(matches!(
            IntegrityManifestTbs::new(
                DatabaseId::from_bytes([1; 16]),
                1,
                1,
                0,
                1,
                0,
                0,
                10,
                u64::MAX,
                10,
                3,
                digest(2),
                vec![mutation(4)?],
            ),
            Err(StorageError::Overflow)
        ));
        Ok(())
    }

    #[test]
    fn manifest_decoding_rejects_invalid_counts_versions_and_hashes() -> Result<(), StorageError> {
        let manifest = IntegrityManifest::new(manifest_tbs(vec![mutation(1)?])?)?;
        let encoded = manifest.encode()?;
        let count_offset = 126;

        for count in [0_u32, (MAX_TRACKED_MUTATIONS as u32) + 1] {
            let mut candidate = encoded.clone();
            candidate
                .get_mut(count_offset..count_offset + 4)
                .ok_or(StorageError::InvalidEncoding)?
                .copy_from_slice(&count.to_be_bytes());
            assert!(matches!(
                IntegrityManifest::decode(&candidate),
                Err(StorageError::LimitExceeded)
            ));
        }
        let mut wrong_version = encoded.clone();
        wrong_version
            .get_mut(..2)
            .ok_or(StorageError::InvalidEncoding)?
            .copy_from_slice(&2_u16.to_be_bytes());
        assert!(matches!(
            IntegrityManifest::decode(&wrong_version),
            Err(StorageError::UnsupportedVersion)
        ));
        let mut wrong_hash = encoded;
        let last = wrong_hash.last_mut().ok_or(StorageError::InvalidEncoding)?;
        *last ^= 1;
        assert!(matches!(
            IntegrityManifest::decode(&wrong_hash),
            Err(StorageError::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    fn checkpoint_validation_rejects_each_cut_and_installation_error() {
        let mut candidate = checkpoint_tbs();
        candidate.cut_nonce_draw_high_water = MAX_NONCE_DRAWS + 1;
        assert_eq!(candidate.validate(), Err(StorageError::StaleState));

        let mut candidate = checkpoint_tbs();
        candidate.installation_nonce_draw_high_water = MAX_NONCE_DRAWS + 1;
        assert_eq!(candidate.validate(), Err(StorageError::StaleState));

        let mut candidate = checkpoint_tbs();
        candidate.installation_manifest_sequence = candidate.cut_manifest_sequence - 1;
        assert_eq!(candidate.validate(), Err(StorageError::StaleState));

        let mut candidate = checkpoint_tbs();
        candidate.installation_nonce_draw_high_water += 1;
        assert_eq!(candidate.validate(), Err(StorageError::StaleState));

        let mut candidate = checkpoint_tbs();
        candidate.installation_nonce_reservation_start = u64::MAX;
        assert_eq!(candidate.validate(), Err(StorageError::Overflow));
    }

    #[test]
    fn checkpoint_decoding_rejects_version_length_and_hash_errors() -> Result<(), StorageError> {
        let checkpoint = IntegrityCheckpoint::new(checkpoint_tbs())?;
        let encoded = checkpoint.encode()?;

        let truncated_length = encoded
            .len()
            .checked_sub(1)
            .ok_or(StorageError::InvalidEncoding)?;
        let truncated = encoded
            .get(..truncated_length)
            .ok_or(StorageError::InvalidEncoding)?;
        assert!(matches!(
            IntegrityCheckpoint::decode(truncated),
            Err(StorageError::InvalidEncoding)
        ));
        let mut wrong_version = encoded.clone();
        wrong_version
            .get_mut(..2)
            .ok_or(StorageError::InvalidEncoding)?
            .copy_from_slice(&2_u16.to_be_bytes());
        assert!(matches!(
            IntegrityCheckpoint::decode(&wrong_version),
            Err(StorageError::UnsupportedVersion)
        ));
        let mut wrong_hash = encoded;
        let last = wrong_hash.last_mut().ok_or(StorageError::InvalidEncoding)?;
        *last ^= 1;
        assert!(matches!(
            IntegrityCheckpoint::decode(&wrong_hash),
            Err(StorageError::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    fn tracked_state_digest_rejects_untracked_zero_schema_and_duplicate_rows()
    -> Result<(), StorageError> {
        let key = stored_key(1)?;
        let mut untracked = [TrackedRecord {
            table: TableId::KeyCheck,
            stored_key: &key,
            record_schema: 1,
            sealed_record_id: digest(1),
        }];
        assert_eq!(
            compute_tracked_state_digest(&mut untracked),
            Err(StorageError::InvalidEncoding)
        );

        let mut zero_schema = [TrackedRecord {
            table: TableId::Account,
            stored_key: &key,
            record_schema: 0,
            sealed_record_id: digest(1),
        }];
        assert_eq!(
            compute_tracked_state_digest(&mut zero_schema),
            Err(StorageError::InvalidEncoding)
        );

        let mut duplicate = [
            TrackedRecord {
                table: TableId::Account,
                stored_key: &key,
                record_schema: 1,
                sealed_record_id: digest(1),
            },
            TrackedRecord {
                table: TableId::Account,
                stored_key: &key,
                record_schema: 1,
                sealed_record_id: digest(2),
            },
        ];
        assert_eq!(
            compute_tracked_state_digest(&mut duplicate),
            Err(StorageError::InvalidEncoding)
        );
        Ok(())
    }
}
