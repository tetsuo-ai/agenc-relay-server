//! Canonical database identity, accounting, reservation, and rollback objects.

use agenc_relay_crypto::{
    StorageAuthenticator, StorageDigest, StorageIntegrityKeys, authenticate_nonce_reservation,
    authenticate_rollback_guard, authenticate_state_meta, database_header_hash,
    nonce_reservation_hash, rollback_guard_hash,
};
use agenc_relay_types::{DatabaseId, NetworkId, RecoveryEpoch, ServerId, ServerIncarnation};

use crate::codec::{Decoder, Encoder};
use crate::{
    DATABASE_FORMAT, MAX_NONCE_DRAWS, MAX_TRACKED_MUTATIONS, SCHEMA_GENERATION, StorageError,
};

const DATABASE_MAGIC: &[u8; 16] = b"AGENC-ARCD-DB\0\0\0";
const GUARD_MAGIC: &[u8; 20] = b"AGENC-ARCD-GUARD-V1\0";
const HEADER_TBS_BYTES: usize = 126;
/// Exact encoded size of a complete database header.
pub const DATABASE_HEADER_BYTES: usize = 158;
const NONCE_RESERVATION_TBS_BYTES: usize = 164;
/// Greatest reservation length: one seal per tracked mutation plus the manifest and StateMeta
/// seals every commit adds. Checkpoint (two) and construction (three) reservations stay below it.
const MAX_RESERVATION_LENGTH: u64 = MAX_TRACKED_MUTATIONS as u64 + 2;
/// Exact encoded size of the fixed nonce-reservation object.
pub const NONCE_RESERVATION_BYTES: usize = 196;
const ROLLBACK_GUARD_TBS_BYTES: usize = 292;
/// Exact encoded size of the external rollback guard.
pub const ROLLBACK_GUARD_BYTES: usize = 324;
const STATE_META_TBS_BYTES: usize = 162;
/// Exact plaintext size of StateMeta.
pub const STATE_META_BYTES: usize = 194;

/// Immutable deployment identity plus versioned storage generations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseHeaderTbs {
    /// Permanent network identity.
    pub network_id: NetworkId,
    /// Permanent server identity.
    pub server_id: ServerId,
    /// Durable request-continuity incarnation.
    pub server_incarnation: ServerIncarnation,
    /// Fresh identity of this physical database construction.
    pub database_instance_id: DatabaseId,
    /// Active master-key generation.
    pub storage_key_generation: u32,
    /// Active canonical record schema generation.
    pub schema_generation: u64,
    /// Continuous-state lineage identity.
    pub recovery_epoch: RecoveryEpoch,
}

impl DatabaseHeaderTbs {
    /// Validates a version-one database identity.
    pub fn new(
        network_id: NetworkId,
        server_id: ServerId,
        server_incarnation: ServerIncarnation,
        database_instance_id: DatabaseId,
        storage_key_generation: u32,
        schema_generation: u64,
        recovery_epoch: RecoveryEpoch,
    ) -> Result<Self, StorageError> {
        if storage_key_generation == 0 || schema_generation != SCHEMA_GENERATION {
            return Err(StorageError::UnsupportedVersion);
        }
        Ok(Self {
            network_id,
            server_id,
            server_incarnation,
            database_instance_id,
            storage_key_generation,
            schema_generation,
            recovery_epoch,
        })
    }

    fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let mut encoder = Encoder::with_capacity(HEADER_TBS_BYTES, HEADER_TBS_BYTES)?;
        encoder.put_fixed(DATABASE_MAGIC)?;
        encoder.put_u16(DATABASE_FORMAT)?;
        encoder.put_fixed(self.network_id.as_bytes())?;
        encoder.put_fixed(self.server_id.as_bytes())?;
        encoder.put_fixed(self.server_incarnation.as_bytes())?;
        encoder.put_fixed(self.database_instance_id.as_bytes())?;
        encoder.put_u32(self.storage_key_generation)?;
        encoder.put_u64(self.schema_generation)?;
        encoder.put_fixed(self.recovery_epoch.as_bytes())?;
        Ok(encoder.finish())
    }

    /// Computes the exact key-check plaintext for this header identity.
    pub fn key_check_plaintext(&self) -> Result<StorageDigest, StorageError> {
        agenc_relay_crypto::database_key_check(&self.encode()?).map_err(StorageError::from)
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        if decoder.take(DATABASE_MAGIC.len())? != DATABASE_MAGIC
            || decoder.u16()? != DATABASE_FORMAT
        {
            return Err(StorageError::UnsupportedVersion);
        }
        let value = Self {
            network_id: NetworkId::from_bytes(decoder.array()?),
            server_id: ServerId::from_bytes(decoder.array()?),
            server_incarnation: ServerIncarnation::from_bytes(decoder.array()?),
            database_instance_id: DatabaseId::from_bytes(decoder.array()?),
            storage_key_generation: decoder.u32()?,
            schema_generation: decoder.u64()?,
            recovery_epoch: RecoveryEpoch::from_bytes(decoder.array()?),
        };
        // Control decoding serves authenticated backup readers.
        // The engine separately requires the exact generation for its open mode.
        if value.storage_key_generation == 0 || value.schema_generation != SCHEMA_GENERATION {
            return Err(StorageError::UnsupportedVersion);
        }
        Ok(value)
    }
}

/// Complete canonical database header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseHeader {
    tbs: DatabaseHeaderTbs,
    key_check_object_id: StorageDigest,
}

impl DatabaseHeader {
    /// Binds an identity to its exact key-check envelope.
    #[must_use]
    pub const fn new(tbs: DatabaseHeaderTbs, key_check_object_id: StorageDigest) -> Self {
        Self {
            tbs,
            key_check_object_id,
        }
    }

    /// Parses the complete fixed header.
    pub fn decode(encoded: &[u8]) -> Result<Self, StorageError> {
        if encoded.len() != DATABASE_HEADER_BYTES {
            return Err(StorageError::InvalidEncoding);
        }
        let mut decoder = Decoder::new(encoded);
        let tbs = DatabaseHeaderTbs::decode(&mut decoder)?;
        let key_check_object_id = StorageDigest::from_bytes(decoder.array()?);
        decoder.finish()?;
        Ok(Self::new(tbs, key_check_object_id))
    }

    /// Encodes the complete fixed header.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let mut encoder = Encoder::with_capacity(DATABASE_HEADER_BYTES, DATABASE_HEADER_BYTES)?;
        encoder.put_fixed(&self.tbs.encode()?)?;
        encoder.put_fixed(self.key_check_object_id.as_bytes())?;
        Ok(encoder.finish())
    }

    /// Hashes every header field for guard and StateMeta bindings.
    pub fn complete_hash(&self) -> Result<StorageDigest, StorageError> {
        database_header_hash(&self.encode()?).map_err(StorageError::from)
    }

    /// Returns the immutable and versioned identity fields.
    #[must_use]
    pub const fn tbs(&self) -> &DatabaseHeaderTbs {
        &self.tbs
    }

    /// Returns the required key-check object commitment.
    #[must_use]
    pub const fn key_check_object_id(&self) -> StorageDigest {
        self.key_check_object_id
    }
}

/// External guard phase for a committed or reserved nonce authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum RollbackGuardPhase {
    /// Database and guard identify the same committed StateMeta.
    Committed = 1,
    /// A one-use nonce block is durably reserved ahead of StateMeta.
    NonceReserved = 2,
}

impl RollbackGuardPhase {
    fn decode(value: u16) -> Result<Self, StorageError> {
        match value {
            1 => Ok(Self::Committed),
            2 => Ok(Self::NonceReserved),
            _ => Err(StorageError::UnsupportedVersion),
        }
    }
}

/// Fields shared by the database control record and external guard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonceReservationTbs {
    /// Candidate database instance.
    pub database_instance_id: DatabaseId,
    /// Monotonic reservation transition sequence.
    pub reservation_sequence: u64,
    /// Committed or reserved phase.
    pub phase: RollbackGuardPhase,
    /// First one-use slot in this block.
    pub nonce_reservation_start: u64,
    /// Exclusive end of all reserved/drawn slots.
    pub nonce_draw_high_water: u64,
    /// StateMeta commit sequence named by the guard.
    pub storage_commit_sequence: u64,
    /// Manifest sequence named by the guard.
    pub manifest_sequence: u64,
    /// Logical state generation named by the guard.
    pub state_generation: u64,
    /// Complete database-header hash.
    pub database_header_hash: StorageDigest,
    /// Current StateMeta envelope identifier.
    pub state_meta_record_id: StorageDigest,
    /// Predecessor rollback-guard hash.
    pub previous_guard_hash: StorageDigest,
}

impl NonceReservationTbs {
    /// Validates intrinsic phase and nonce bounds.
    pub fn validate(&self) -> Result<(), StorageError> {
        if self.nonce_draw_high_water > MAX_NONCE_DRAWS
            || self.nonce_reservation_start > self.nonce_draw_high_water
        {
            return Err(StorageError::LimitExceeded);
        }
        if self.phase == RollbackGuardPhase::Committed
            && self.nonce_reservation_start != self.nonce_draw_high_water
        {
            return Err(StorageError::StaleState);
        }
        if self.phase == RollbackGuardPhase::NonceReserved {
            let length = self
                .nonce_draw_high_water
                .checked_sub(self.nonce_reservation_start)
                .ok_or(StorageError::Overflow)?;
            if !(1..=MAX_RESERVATION_LENGTH).contains(&length) {
                return Err(StorageError::LimitExceeded);
            }
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, StorageError> {
        self.validate()?;
        let mut encoder =
            Encoder::with_capacity(NONCE_RESERVATION_TBS_BYTES, NONCE_RESERVATION_TBS_BYTES)?;
        encoder.put_u16(1)?;
        encoder.put_fixed(self.database_instance_id.as_bytes())?;
        encoder.put_u64(self.reservation_sequence)?;
        encoder.put_u16(self.phase as u16)?;
        encoder.put_u64(self.nonce_reservation_start)?;
        encoder.put_u64(self.nonce_draw_high_water)?;
        encoder.put_u64(self.storage_commit_sequence)?;
        encoder.put_u64(self.manifest_sequence)?;
        encoder.put_u64(self.state_generation)?;
        encoder.put_fixed(self.database_header_hash.as_bytes())?;
        encoder.put_fixed(self.state_meta_record_id.as_bytes())?;
        encoder.put_fixed(self.previous_guard_hash.as_bytes())?;
        Ok(encoder.finish())
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        if decoder.u16()? != 1 {
            return Err(StorageError::UnsupportedVersion);
        }
        let value = Self {
            database_instance_id: DatabaseId::from_bytes(decoder.array()?),
            reservation_sequence: decoder.u64()?,
            phase: RollbackGuardPhase::decode(decoder.u16()?)?,
            nonce_reservation_start: decoder.u64()?,
            nonce_draw_high_water: decoder.u64()?,
            storage_commit_sequence: decoder.u64()?,
            manifest_sequence: decoder.u64()?,
            state_generation: decoder.u64()?,
            database_header_hash: StorageDigest::from_bytes(decoder.array()?),
            state_meta_record_id: StorageDigest::from_bytes(decoder.array()?),
            previous_guard_hash: StorageDigest::from_bytes(decoder.array()?),
        };
        value.validate()?;
        Ok(value)
    }
}

/// Authenticated fixed nonce-reservation control record.
pub struct NonceReservationState {
    tbs: NonceReservationTbs,
    authenticator: StorageAuthenticator,
}

impl NonceReservationState {
    /// Authenticates a validated reservation state.
    pub fn authenticate(
        tbs: NonceReservationTbs,
        keys: &StorageIntegrityKeys,
    ) -> Result<Self, StorageError> {
        let authenticator = authenticate_nonce_reservation(keys, &tbs.encode()?)?;
        Ok(Self { tbs, authenticator })
    }

    /// Parses and verifies the exact fixed object.
    pub fn decode_and_verify(
        encoded: &[u8],
        keys: &StorageIntegrityKeys,
    ) -> Result<Self, StorageError> {
        if encoded.len() != NONCE_RESERVATION_BYTES {
            return Err(StorageError::InvalidEncoding);
        }
        let mut decoder = Decoder::new(encoded);
        let tbs = NonceReservationTbs::decode(&mut decoder)?;
        let candidate = StorageAuthenticator::from_bytes(decoder.array()?);
        decoder.finish()?;
        let expected = authenticate_nonce_reservation(keys, &tbs.encode()?)?;
        if !expected.matches(&candidate) {
            return Err(StorageError::AuthenticationFailed);
        }
        Ok(Self {
            tbs,
            authenticator: candidate,
        })
    }

    /// Encodes the authenticated fixed object.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let mut encoder = Encoder::with_capacity(NONCE_RESERVATION_BYTES, NONCE_RESERVATION_BYTES)?;
        encoder.put_fixed(&self.tbs.encode()?)?;
        encoder.put_fixed(self.authenticator.expose_for_storage())?;
        Ok(encoder.finish())
    }

    /// Hashes the complete authenticated record for guard binding.
    pub fn complete_hash(&self) -> Result<StorageDigest, StorageError> {
        nonce_reservation_hash(&self.encode()?).map_err(StorageError::from)
    }

    /// Returns the authenticated reservation fields.
    #[must_use]
    pub const fn tbs(&self) -> &NonceReservationTbs {
        &self.tbs
    }
}

/// Exact fields stored in the independently authenticated guard file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollbackGuardTbs {
    /// Network identity.
    pub network_id: NetworkId,
    /// Server identity.
    pub server_id: ServerId,
    /// Database instance.
    pub database_instance_id: DatabaseId,
    /// Storage-key generation.
    pub storage_key_generation: u32,
    /// Record schema generation.
    pub schema_generation: u64,
    /// Recovery lineage.
    pub recovery_epoch: RecoveryEpoch,
    /// StateMeta commit sequence.
    pub storage_commit_sequence: u64,
    /// Integrity manifest sequence.
    pub manifest_sequence: u64,
    /// Logical state generation.
    pub state_generation: u64,
    /// Guard phase.
    pub phase: RollbackGuardPhase,
    /// Reservation transition sequence.
    pub reservation_sequence: u64,
    /// First slot in the current reservation.
    pub nonce_reservation_start: u64,
    /// Exclusive nonce reservation end.
    pub nonce_draw_high_water: u64,
    /// Complete header hash.
    pub database_header_hash: StorageDigest,
    /// Current StateMeta record ID.
    pub state_meta_record_id: StorageDigest,
    /// Complete reservation-state hash.
    pub nonce_reservation_state_hash: StorageDigest,
    /// Predecessor guard hash.
    pub previous_guard_hash: StorageDigest,
}

impl RollbackGuardTbs {
    fn encode(&self) -> Result<Vec<u8>, StorageError> {
        if self.storage_key_generation == 0
            || self.schema_generation != SCHEMA_GENERATION
            || self.nonce_draw_high_water > MAX_NONCE_DRAWS
            || self.nonce_reservation_start > self.nonce_draw_high_water
        {
            return Err(StorageError::InvalidEncoding);
        }
        let mut encoder =
            Encoder::with_capacity(ROLLBACK_GUARD_TBS_BYTES, ROLLBACK_GUARD_TBS_BYTES)?;
        encoder.put_fixed(GUARD_MAGIC)?;
        encoder.put_u16(1)?;
        encoder.put_fixed(self.network_id.as_bytes())?;
        encoder.put_fixed(self.server_id.as_bytes())?;
        encoder.put_fixed(self.database_instance_id.as_bytes())?;
        encoder.put_u32(self.storage_key_generation)?;
        encoder.put_u64(self.schema_generation)?;
        encoder.put_fixed(self.recovery_epoch.as_bytes())?;
        encoder.put_u64(self.storage_commit_sequence)?;
        encoder.put_u64(self.manifest_sequence)?;
        encoder.put_u64(self.state_generation)?;
        encoder.put_u16(self.phase as u16)?;
        encoder.put_u64(self.reservation_sequence)?;
        encoder.put_u64(self.nonce_reservation_start)?;
        encoder.put_u64(self.nonce_draw_high_water)?;
        encoder.put_fixed(self.database_header_hash.as_bytes())?;
        encoder.put_fixed(self.state_meta_record_id.as_bytes())?;
        encoder.put_fixed(self.nonce_reservation_state_hash.as_bytes())?;
        encoder.put_fixed(self.previous_guard_hash.as_bytes())?;
        Ok(encoder.finish())
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        if decoder.take(GUARD_MAGIC.len())? != GUARD_MAGIC || decoder.u16()? != 1 {
            return Err(StorageError::UnsupportedVersion);
        }
        let value = Self {
            network_id: NetworkId::from_bytes(decoder.array()?),
            server_id: ServerId::from_bytes(decoder.array()?),
            database_instance_id: DatabaseId::from_bytes(decoder.array()?),
            storage_key_generation: decoder.u32()?,
            schema_generation: decoder.u64()?,
            recovery_epoch: RecoveryEpoch::from_bytes(decoder.array()?),
            storage_commit_sequence: decoder.u64()?,
            manifest_sequence: decoder.u64()?,
            state_generation: decoder.u64()?,
            phase: RollbackGuardPhase::decode(decoder.u16()?)?,
            reservation_sequence: decoder.u64()?,
            nonce_reservation_start: decoder.u64()?,
            nonce_draw_high_water: decoder.u64()?,
            database_header_hash: StorageDigest::from_bytes(decoder.array()?),
            state_meta_record_id: StorageDigest::from_bytes(decoder.array()?),
            nonce_reservation_state_hash: StorageDigest::from_bytes(decoder.array()?),
            previous_guard_hash: StorageDigest::from_bytes(decoder.array()?),
        };
        let _ = value.encode()?;
        Ok(value)
    }
}

/// Complete independently authenticated rollback guard.
pub struct RollbackGuard {
    tbs: RollbackGuardTbs,
    authenticator: StorageAuthenticator,
}

impl RollbackGuard {
    /// Authenticates the guard's immutable identity before a database is opened writable.
    pub(crate) fn decode_with_root(
        encoded: &[u8],
        root: &agenc_relay_crypto::RollbackGuardRootKey,
    ) -> Result<Self, StorageError> {
        if encoded.len() != ROLLBACK_GUARD_BYTES {
            return Err(StorageError::InvalidEncoding);
        }
        let tbs = RollbackGuardTbs::decode(&mut Decoder::new(encoded))?;
        let context = agenc_relay_crypto::StorageIntegrityContext::new(
            tbs.network_id,
            tbs.server_id,
            tbs.database_instance_id,
        );
        let keys = agenc_relay_crypto::derive_storage_integrity_keys(root, context)?;
        Self::decode_and_verify(encoded, &keys)
    }

    /// Authenticates one complete guard state.
    pub fn authenticate(
        tbs: RollbackGuardTbs,
        keys: &StorageIntegrityKeys,
    ) -> Result<Self, StorageError> {
        let authenticator = authenticate_rollback_guard(keys, &tbs.encode()?)?;
        Ok(Self { tbs, authenticator })
    }

    /// Parses and verifies one exact guard file.
    pub fn decode_and_verify(
        encoded: &[u8],
        keys: &StorageIntegrityKeys,
    ) -> Result<Self, StorageError> {
        if encoded.len() != ROLLBACK_GUARD_BYTES {
            return Err(StorageError::InvalidEncoding);
        }
        let mut decoder = Decoder::new(encoded);
        let tbs = RollbackGuardTbs::decode(&mut decoder)?;
        let candidate = StorageAuthenticator::from_bytes(decoder.array()?);
        decoder.finish()?;
        let expected = authenticate_rollback_guard(keys, &tbs.encode()?)?;
        if !expected.matches(&candidate) {
            return Err(StorageError::AuthenticationFailed);
        }
        Ok(Self {
            tbs,
            authenticator: candidate,
        })
    }

    /// Encodes the exact fixed guard.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let mut encoder = Encoder::with_capacity(ROLLBACK_GUARD_BYTES, ROLLBACK_GUARD_BYTES)?;
        encoder.put_fixed(&self.tbs.encode()?)?;
        encoder.put_fixed(self.authenticator.expose_for_storage())?;
        Ok(encoder.finish())
    }

    /// Hashes the complete authenticated guard.
    pub fn complete_hash(&self) -> Result<StorageDigest, StorageError> {
        rollback_guard_hash(&self.encode()?).map_err(StorageError::from)
    }

    /// Returns the authenticated guard fields.
    #[must_use]
    pub const fn tbs(&self) -> &RollbackGuardTbs {
        &self.tbs
    }
}

/// Authenticated global counters and integrity anchors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateMetaTbs {
    /// Immediate application/checkpoint commit sequence.
    pub storage_commit_sequence: u64,
    /// Latest integrity manifest sequence.
    pub manifest_sequence: u64,
    /// Global logical state generation.
    pub state_generation: u64,
    /// Epoch-scoped coordinator response counter.
    pub account_service_response_count: u64,
    /// Exclusive high-water mark of reserved nonce slots.
    pub nonce_draw_high_water: u64,
    /// Exact canonical logical database charge.
    pub logical_database_bytes: u64,
    /// Exact canonical backup stream length.
    pub backup_stream_bytes: u64,
    /// Active checkpoint cut manifest sequence.
    pub checkpoint_manifest_sequence: u64,
    /// Latest manifest hash.
    pub latest_manifest_hash: StorageDigest,
    /// Active checkpoint hash.
    pub checkpoint_hash: StorageDigest,
    /// Guard preceding the transaction that wrote this StateMeta.
    pub previous_rollback_guard_hash: StorageDigest,
}

impl StateMetaTbs {
    fn encode(&self) -> Result<Vec<u8>, StorageError> {
        if self.nonce_draw_high_water > MAX_NONCE_DRAWS
            || self.checkpoint_manifest_sequence > self.manifest_sequence
        {
            return Err(StorageError::StaleState);
        }
        let mut encoder = Encoder::with_capacity(STATE_META_TBS_BYTES, STATE_META_TBS_BYTES)?;
        encoder.put_u16(1)?;
        encoder.put_u64(self.storage_commit_sequence)?;
        encoder.put_u64(self.manifest_sequence)?;
        encoder.put_u64(self.state_generation)?;
        encoder.put_u64(self.account_service_response_count)?;
        encoder.put_u64(self.nonce_draw_high_water)?;
        encoder.put_u64(self.logical_database_bytes)?;
        encoder.put_u64(self.backup_stream_bytes)?;
        encoder.put_u64(self.checkpoint_manifest_sequence)?;
        encoder.put_fixed(self.latest_manifest_hash.as_bytes())?;
        encoder.put_fixed(self.checkpoint_hash.as_bytes())?;
        encoder.put_fixed(self.previous_rollback_guard_hash.as_bytes())?;
        Ok(encoder.finish())
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        if decoder.u16()? != 1 {
            return Err(StorageError::UnsupportedVersion);
        }
        let value = Self {
            storage_commit_sequence: decoder.u64()?,
            manifest_sequence: decoder.u64()?,
            state_generation: decoder.u64()?,
            account_service_response_count: decoder.u64()?,
            nonce_draw_high_water: decoder.u64()?,
            logical_database_bytes: decoder.u64()?,
            backup_stream_bytes: decoder.u64()?,
            checkpoint_manifest_sequence: decoder.u64()?,
            latest_manifest_hash: StorageDigest::from_bytes(decoder.array()?),
            checkpoint_hash: StorageDigest::from_bytes(decoder.array()?),
            previous_rollback_guard_hash: StorageDigest::from_bytes(decoder.array()?),
        };
        let _ = value.encode()?;
        Ok(value)
    }
}

/// Complete StateMeta plaintext with independent commit authorization.
pub struct StateMeta {
    tbs: StateMetaTbs,
    authenticator: StorageAuthenticator,
}

impl StateMeta {
    /// Authorizes a complete successor before its database transaction begins.
    pub fn authenticate(
        tbs: StateMetaTbs,
        database_header_hash: StorageDigest,
        keys: &StorageIntegrityKeys,
    ) -> Result<Self, StorageError> {
        let authenticator = authenticate_state_meta(keys, database_header_hash, &tbs.encode()?)?;
        Ok(Self { tbs, authenticator })
    }

    /// Parses and verifies a complete StateMeta plaintext.
    pub fn decode_and_verify(
        encoded: &[u8],
        database_header_hash: StorageDigest,
        keys: &StorageIntegrityKeys,
    ) -> Result<Self, StorageError> {
        if encoded.len() != STATE_META_BYTES {
            return Err(StorageError::InvalidEncoding);
        }
        let mut decoder = Decoder::new(encoded);
        let tbs = StateMetaTbs::decode(&mut decoder)?;
        let candidate = StorageAuthenticator::from_bytes(decoder.array()?);
        decoder.finish()?;
        let expected = authenticate_state_meta(keys, database_header_hash, &tbs.encode()?)?;
        if !expected.matches(&candidate) {
            return Err(StorageError::AuthenticationFailed);
        }
        Ok(Self {
            tbs,
            authenticator: candidate,
        })
    }

    /// Encodes the complete fixed plaintext.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let mut encoder = Encoder::with_capacity(STATE_META_BYTES, STATE_META_BYTES)?;
        encoder.put_fixed(&self.tbs.encode()?)?;
        encoder.put_fixed(self.authenticator.expose_for_storage())?;
        Ok(encoder.finish())
    }

    /// Returns the authenticated counters and anchors.
    #[must_use]
    pub const fn tbs(&self) -> &StateMetaTbs {
        &self.tbs
    }
}

/// Requires exact repetition between the database reservation record and guard.
///
/// The fence is an exact equality and reconciles nothing. Both publication steps of every
/// durable operation make the in-database reservation record durable before they replace the
/// guard file, so a guard can only ever lag its record and only ever by one step. Naming and
/// repairing those two lags is `classify_recovery_state`'s work, against the authenticated
/// StateMeta; a disagreement this function reports is one the publication order cannot reach, so
/// it is refused rather than guessed and a reopen never trusts a guard it cannot prove.
// agenc-review: focus owner=storage reviewed=2026-08-27 reason=one exhaustive equality fence prevents omitted control-field bindings
pub fn verify_guard_pair(
    header: &DatabaseHeader,
    reservation: &NonceReservationState,
    guard: &RollbackGuard,
) -> Result<(), StorageError> {
    let header_hash = header.complete_hash()?;
    let reservation_tbs = reservation.tbs();
    let guard_tbs = guard.tbs();
    if reservation_tbs.database_instance_id != guard_tbs.database_instance_id
        || guard_tbs.database_instance_id != header.tbs().database_instance_id
        || guard_tbs.network_id != header.tbs().network_id
        || guard_tbs.server_id != header.tbs().server_id
        || guard_tbs.storage_key_generation != header.tbs().storage_key_generation
        || guard_tbs.schema_generation != header.tbs().schema_generation
        || guard_tbs.recovery_epoch != header.tbs().recovery_epoch
        || reservation_tbs.phase != guard_tbs.phase
        || reservation_tbs.reservation_sequence != guard_tbs.reservation_sequence
        || reservation_tbs.nonce_reservation_start != guard_tbs.nonce_reservation_start
        || reservation_tbs.nonce_draw_high_water != guard_tbs.nonce_draw_high_water
        || reservation_tbs.storage_commit_sequence != guard_tbs.storage_commit_sequence
        || reservation_tbs.manifest_sequence != guard_tbs.manifest_sequence
        || reservation_tbs.state_generation != guard_tbs.state_generation
        || reservation_tbs.database_header_hash != header_hash
        || guard_tbs.database_header_hash != header_hash
        || reservation_tbs.state_meta_record_id != guard_tbs.state_meta_record_id
        || reservation_tbs.previous_guard_hash != guard_tbs.previous_guard_hash
        || reservation.complete_hash()? != guard_tbs.nonce_reservation_state_hash
    {
        return Err(StorageError::StaleState);
    }
    Ok(())
}
