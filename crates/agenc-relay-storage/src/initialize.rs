//! Sequence-zero initialization for fresh live and staging databases.

use std::collections::BTreeSet;

use agenc_relay_crypto::{
    DatabaseBinding, RollbackGuardRootKey, StorageDigest, StorageIntegrityContext,
    StorageMasterKey, derive_storage_integrity_keys,
};
use zeroize::Zeroizing;

use crate::bounded::OperationAllowance;
use crate::engine::{StorageEngineLimits, draw_nonces_with_faults};
use crate::integrity::TrackedRecord;
use crate::redb_store::{RedbCommitFailure, RedbStore, RedbWrite};
use crate::{
    BACKUP_FIXED_STREAM_BYTES, DatabaseHeader, DatabaseHeaderTbs, IntegrityCheckpoint,
    IntegrityCheckpointTbs, NonceReservationState, NonceReservationTbs, RollbackGuard,
    RollbackGuardPhase, RollbackGuardTbs, SealedRecord, StateDirectory, StateMeta, StateMetaTbs,
    StorageConstruction, StorageConstructionCursor, StorageError, StorageSealContext, StoredKey,
    TableId, compute_tracked_state_digest, logical_meta_charge, logical_record_charge,
};

const KEY_CHECK_KEY: &[u8] = b"agenc-chat/key-check/v1";
const STATE_META_KEY: &[u8] = b"agenc-chat/state-meta/v1";

/// Whether sequence zero is immediately live or contains a construction marker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageInitializationMode {
    /// Fresh live database; key state must already exist and no marker may exist.
    Live,
    /// Restore or rekey staging target; one construction marker must exist.
    Construction,
}

/// One small integrity-tracked record included at sequence zero.
pub struct InitialStorageRecord {
    table: TableId,
    key: StoredKey,
    record_schema: u32,
    plaintext: Zeroizing<Vec<u8>>,
}

impl InitialStorageRecord {
    /// Validates one initial tracked record and owns its plaintext.
    pub fn new(
        table: TableId,
        key: StoredKey,
        record_schema: u32,
        plaintext: Vec<u8>,
    ) -> Result<Self, StorageError> {
        if !table.is_integrity_tracked()
            || record_schema == 0
            || plaintext.len() > agenc_relay_crypto::MAX_STORAGE_PLAINTEXT_BYTES
        {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self {
            table,
            key,
            record_schema,
            plaintext: Zeroizing::new(plaintext),
        })
    }
}

/// Complete secret-bearing inputs for one empty-file initialization.
pub struct StorageInitializationConfig {
    /// Empty validated state directory and lifetime writer lock.
    pub state_directory: StateDirectory,
    /// Complete target header identity before its key-check ID is known.
    pub header_tbs: DatabaseHeaderTbs,
    /// Target storage master key.
    pub storage_master_key: StorageMasterKey,
    /// Independently provisioned target rollback-guard root.
    pub rollback_guard_root_key: RollbackGuardRootKey,
    /// Live or staging singleton requirements.
    pub mode: StorageInitializationMode,
    /// Small initial tracked record set.
    pub initial_records: Vec<InitialStorageRecord>,
    /// Restore resets this to zero; rekey preserves the source value.
    pub account_service_response_count: u64,
    /// Initial logical state generation.
    pub state_generation: u64,
    /// Source guard hash for a construction, or all-zero for first run.
    pub predecessor_guard_hash: StorageDigest,
    /// Storage and filesystem limits.
    pub limits: StorageEngineLimits,
}

/// Certain completion or an outcome requiring staging-directory reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageInitializationOutcome {
    /// Database and first committed guard are durable.
    Complete {
        /// Hash of the installed initial guard.
        rollback_guard_hash: StorageDigest,
        /// Exact initial logical database charge.
        logical_database_bytes: u64,
        /// Exact initial signed-backup stream length.
        backup_stream_bytes: u64,
        /// Exact sequence-zero nonce high-water mark.
        nonce_draw_high_water: u64,
    },
    /// A durable boundary may have been crossed; do not reuse this directory blindly.
    Indeterminate,
}

/// Initializes one empty database transaction and then installs its first guard.
pub fn initialize_storage(
    config: StorageInitializationConfig,
) -> Result<StorageInitializationOutcome, StorageError> {
    if config.header_tbs.schema_generation != crate::SCHEMA_GENERATION {
        return Err(StorageError::UnsupportedVersion);
    }
    initialize_storage_inner(config)
}

pub(crate) fn initialize_stopped_construction(
    config: StorageInitializationConfig,
) -> Result<StorageInitializationOutcome, StorageError> {
    let schema = crate::construction_schema::ConstructionSchema::from_generation(
        config.header_tbs.schema_generation,
    )?;
    if config.mode != StorageInitializationMode::Construction {
        return Err(StorageError::UnsupportedVersion);
    }
    let record = config
        .initial_records
        .iter()
        .find(|record| record.table == TableId::StorageConstruction)
        .ok_or(StorageError::InvalidEncoding)?;
    let marker = crate::StorageConstruction::decode(&record.plaintext)?;
    marker.identity.validate()?;
    if marker.identity.target_schema_generation != schema.generation()
        || marker.identity.target_database_instance_id != config.header_tbs.database_instance_id
    {
        return Err(StorageError::StaleState);
    }
    initialize_storage_inner(config)
}

// agenc-review: focus owner=storage reviewed=2026-09-18 reason=sequence-zero construction retains the existing linear nonce-charge-commit transcript under one physical allowance after explicit schema admission
fn initialize_storage_inner(
    mut config: StorageInitializationConfig,
) -> Result<StorageInitializationOutcome, StorageError> {
    let limits = config.limits.validate()?;
    validate_initial_records(config.mode, &mut config.initial_records)?;
    config.state_directory.require_absent_guard()?;
    let _capacity = config
        .state_directory
        .admit_transaction(limits.fixed_reserve_bytes, limits.reserve_percent)?;
    // One allowance spans the initializing transaction, the first guard and the close.
    let mut allowance = OperationAllowance::new(config.state_directory.tuple().block_size, 1)?
        .capped(config.state_directory.faults().growth_cap());
    let file = config.state_directory.create_database_file()?;
    if file.metadata().map_err(crate::filesystem_rejected)?.len() != 0 {
        return Err(StorageError::StaleState);
    }
    let store = RedbStore::open_with_faults(
        file,
        limits.redb_cache_bytes,
        config.state_directory.faults(),
    )?;
    let binding = DatabaseBinding::new(
        config.header_tbs.network_id,
        config.header_tbs.server_id,
        config.header_tbs.server_incarnation,
        config.header_tbs.database_instance_id,
    );
    let seal_count = config
        .initial_records
        .len()
        .checked_add(3)
        .ok_or(StorageError::Overflow)?;
    let seal_count_u32 = u32::try_from(seal_count).map_err(|_| StorageError::LimitExceeded)?;
    let nonces = draw_nonces_with_faults(seal_count_u32, &config.state_directory.faults())?;
    let mut nonce_cursor = 0_usize;
    let seal_context = StorageSealContext::new(
        &config.storage_master_key,
        binding,
        config.header_tbs.storage_key_generation,
    )?;
    let key_check_key = StoredKey::new(KEY_CHECK_KEY.to_vec())?;
    let key_check_record = seal_context
        .seal(
            TableId::KeyCheck,
            1,
            take_nonce(&nonces, &mut nonce_cursor)?,
            &key_check_key,
            config.header_tbs.key_check_plaintext()?.as_bytes(),
        )?
        .encode()?;
    let header = DatabaseHeader::new(
        config.header_tbs,
        SealedRecord::decode(&key_check_record)?.record_id()?,
    );
    bind_construction_target_header(config.mode, &mut config.initial_records, &header)?;
    let integrity_keys = derive_storage_integrity_keys(
        &config.rollback_guard_root_key,
        StorageIntegrityContext::new(
            header.tbs().network_id,
            header.tbs().server_id,
            header.tbs().database_instance_id,
        ),
    )?;
    let mut prepared = Vec::new();
    prepared
        .try_reserve_exact(config.initial_records.len())
        .map_err(|_| StorageError::AllocationFailed)?;
    for record in &config.initial_records {
        let sealed = seal_context
            .seal(
                record.table,
                record.record_schema,
                take_nonce(&nonces, &mut nonce_cursor)?,
                &record.key,
                &record.plaintext,
            )?
            .encode()?;
        prepared.push(PreparedInitialRecord {
            table: record.table,
            key: StoredKey::new(record.key.as_bytes().to_vec())?,
            record_schema: record.record_schema,
            sealed_record_id: SealedRecord::decode(&sealed)?.record_id()?,
            sealed,
        });
    }
    let mut tracked = prepared
        .iter()
        .map(|record| TrackedRecord {
            table: record.table,
            stored_key: &record.key,
            record_schema: record.record_schema,
            sealed_record_id: record.sealed_record_id,
        })
        .collect::<Vec<_>>();
    let tracked_state_digest = compute_tracked_state_digest(&mut tracked)?;
    let zero = StorageDigest::from_bytes([0_u8; 32]);
    let high_water = u64::try_from(seal_count).map_err(|_| StorageError::Overflow)?;
    let checkpoint = IntegrityCheckpoint::new(IntegrityCheckpointTbs {
        database_instance_id: header.tbs().database_instance_id,
        cut_storage_commit_sequence: 0,
        cut_manifest_sequence: 0,
        cut_state_generation: config.state_generation,
        cut_account_service_response_count: config.account_service_response_count,
        cut_nonce_draw_high_water: high_water,
        cut_manifest_hash: zero,
        tracked_record_count: u64::try_from(prepared.len()).map_err(|_| StorageError::Overflow)?,
        tracked_state_digest,
        previous_checkpoint_hash: zero,
        installation_storage_commit_sequence: 0,
        installation_manifest_sequence: 0,
        // The genesis installation drew exactly the checkpoint and StateMeta seals, the last two
        // nonces of `high_water`, so its reservation starts two draws below the high-water mark.
        // `IntegrityCheckpointTbs::validate` requires that exact distance.
        installation_nonce_reservation_start: high_water
            .checked_sub(2)
            .ok_or(StorageError::Overflow)?,
        installation_nonce_draw_high_water: high_water,
    })?;
    let checkpoint_key = StoredKey::new(0_u64.to_be_bytes().to_vec())?;
    let checkpoint_record = seal_context
        .seal(
            TableId::IntegrityCheckpoint,
            1,
            take_nonce(&nonces, &mut nonce_cursor)?,
            &checkpoint_key,
            &checkpoint.encode()?,
        )?
        .encode()?;
    let predicted_state_meta_record_bytes = crate::STATE_META_BYTES
        .checked_add(crate::MIN_SEALED_RECORD_BYTES)
        .ok_or(StorageError::Overflow)?;
    let mut logical_bytes =
        logical_meta_charge(HEADER_META_KEY_BYTES, crate::DATABASE_HEADER_BYTES)?
            .checked_add(logical_meta_charge(
                RESERVATION_META_KEY_BYTES,
                crate::NONCE_RESERVATION_BYTES,
            )?)
            .ok_or(StorageError::Overflow)?;
    let mut backup_bytes = BACKUP_FIXED_STREAM_BYTES;
    add_record_charge(
        &mut logical_bytes,
        &mut backup_bytes,
        key_check_key.as_bytes().len(),
        key_check_record.len(),
    )?;
    for record in &prepared {
        add_record_charge(
            &mut logical_bytes,
            &mut backup_bytes,
            record.key.as_bytes().len(),
            record.sealed.len(),
        )?;
    }
    add_record_charge(
        &mut logical_bytes,
        &mut backup_bytes,
        checkpoint_key.as_bytes().len(),
        checkpoint_record.len(),
    )?;
    add_record_charge(
        &mut logical_bytes,
        &mut backup_bytes,
        STATE_META_KEY.len(),
        predicted_state_meta_record_bytes,
    )?;
    if (
        logical_bytes > limits.database_max_bytes,
        backup_bytes > limits.backup_max_bytes,
    ) != (false, false)
    {
        return Err(StorageError::LimitExceeded);
    }
    let state_meta = StateMeta::authenticate(
        StateMetaTbs {
            storage_commit_sequence: 0,
            manifest_sequence: 0,
            state_generation: config.state_generation,
            account_service_response_count: config.account_service_response_count,
            nonce_draw_high_water: high_water,
            logical_database_bytes: logical_bytes,
            backup_stream_bytes: backup_bytes,
            checkpoint_manifest_sequence: 0,
            latest_manifest_hash: zero,
            checkpoint_hash: checkpoint.checkpoint_hash(),
            previous_rollback_guard_hash: config.predecessor_guard_hash,
        },
        header.complete_hash()?,
        &integrity_keys,
    )?;
    let state_meta_key = StoredKey::new(STATE_META_KEY.to_vec())?;
    let state_meta_record = seal_context
        .seal(
            TableId::StateMeta,
            1,
            take_nonce(&nonces, &mut nonce_cursor)?,
            &state_meta_key,
            &state_meta.encode()?,
        )?
        .encode()?;
    if (nonce_cursor, state_meta_record.len()) != (nonces.len(), predicted_state_meta_record_bytes)
    {
        return Err(StorageError::InvalidEncoding);
    }
    let state_meta_record_id = SealedRecord::decode(&state_meta_record)?.record_id()?;
    let reservation = NonceReservationState::authenticate(
        NonceReservationTbs {
            database_instance_id: header.tbs().database_instance_id,
            reservation_sequence: 0,
            phase: RollbackGuardPhase::Committed,
            nonce_reservation_start: high_water,
            nonce_draw_high_water: high_water,
            storage_commit_sequence: 0,
            manifest_sequence: 0,
            state_generation: config.state_generation,
            database_header_hash: header.complete_hash()?,
            state_meta_record_id,
            previous_guard_hash: config.predecessor_guard_hash,
        },
        &integrity_keys,
    )?;
    let guard = RollbackGuard::authenticate(guard_tbs(&header, &reservation)?, &integrity_keys)?;
    let mut writes = prepared
        .iter()
        .map(|record| RedbWrite {
            table: record.table,
            key: record.key.as_bytes(),
            value: Some(record.sealed.as_slice()),
        })
        .collect::<Vec<_>>();
    writes.push(RedbWrite {
        table: TableId::KeyCheck,
        key: key_check_key.as_bytes(),
        value: Some(&key_check_record),
    });
    writes.push(RedbWrite {
        table: TableId::IntegrityCheckpoint,
        key: checkpoint_key.as_bytes(),
        value: Some(&checkpoint_record),
    });
    writes.push(RedbWrite {
        table: TableId::StateMeta,
        key: state_meta_key.as_bytes(),
        value: Some(&state_meta_record),
    });
    let charged = match store.initialize_database(
        &header.encode()?,
        &reservation.encode()?,
        &writes,
        allowance.allowance(),
    ) {
        Ok(charged) => charged,
        Err(RedbCommitFailure::Rejected(error)) => return Err(error),
        Err(RedbCommitFailure::Indeterminate) => {
            return Ok(StorageInitializationOutcome::Indeterminate);
        }
    };
    let guard_bytes = guard.encode()?;
    if config
        .state_directory
        .install_initial_guard(&guard_bytes)
        .is_err()
    {
        return Ok(StorageInitializationOutcome::Indeterminate);
    }
    // The database is complete and its guard published; the close persists the allocator
    // state within what remains of the allowance, and a refusal or failure here leaves that
    // persistence to the next open's repair, which changes nothing the guard names.
    if allowance.charge(charged).is_ok() {
        let _closed = store.persist_for_close(allowance.allowance());
    }
    Ok(StorageInitializationOutcome::Complete {
        rollback_guard_hash: guard.complete_hash()?,
        logical_database_bytes: logical_bytes,
        backup_stream_bytes: backup_bytes,
        nonce_draw_high_water: high_water,
    })
}

const HEADER_META_KEY_BYTES: usize = b"header/v1".len();
const RESERVATION_META_KEY_BYTES: usize = b"nonce-reservation/v1".len();

struct PreparedInitialRecord {
    table: TableId,
    key: StoredKey,
    record_schema: u32,
    sealed_record_id: StorageDigest,
    sealed: Vec<u8>,
}

fn validate_initial_records(
    mode: StorageInitializationMode,
    records: &mut [InitialStorageRecord],
) -> Result<(), StorageError> {
    records.sort_by(|left, right| {
        (left.table, left.key.as_bytes()).cmp(&(right.table, right.key.as_bytes()))
    });
    let mut identities = BTreeSet::new();
    let mut key_state = 0_u8;
    let mut construction = 0_u8;
    for record in records {
        crate::validate_record_plaintext(
            record.table,
            &record.key,
            record.record_schema,
            &record.plaintext,
        )?;
        if !identities.insert((record.table, record.key.as_bytes())) {
            return Err(StorageError::InvalidEncoding);
        }
        if record.table == TableId::LoginIndexKeyState {
            key_state = key_state.checked_add(1).ok_or(StorageError::Overflow)?;
        }
        if record.table == TableId::StorageConstruction {
            construction = construction.checked_add(1).ok_or(StorageError::Overflow)?;
        }
    }
    match mode {
        StorageInitializationMode::Live if key_state == 1 && construction == 0 => Ok(()),
        StorageInitializationMode::Construction if construction == 1 && key_state <= 1 => Ok(()),
        _ => Err(StorageError::InvalidEncoding),
    }
}

fn bind_construction_target_header(
    mode: StorageInitializationMode,
    records: &mut [InitialStorageRecord],
    header: &DatabaseHeader,
) -> Result<(), StorageError> {
    if mode == StorageInitializationMode::Live {
        return Ok(());
    }
    let record = records
        .iter_mut()
        .find(|record| record.table == TableId::StorageConstruction)
        .ok_or(StorageError::InvalidEncoding)?;
    if (record.key.as_bytes(), record.record_schema) != (crate::STORAGE_CONSTRUCTION_KEY, 1) {
        return Err(StorageError::InvalidEncoding);
    }
    let mut marker = StorageConstruction::decode(&record.plaintext)?;
    let zero = StorageDigest::from_bytes([0_u8; 32]);
    if (
        marker.identity.target_database_header_hash,
        marker.identity.target_database_instance_id,
        marker.identity.target_schema_generation,
        &marker.next_target,
        marker.target_records_committed,
    ) != (
        zero,
        header.tbs().database_instance_id,
        header.tbs().schema_generation,
        &StorageConstructionCursor::BeforeFirst,
        0,
    ) {
        return Err(StorageError::ResumeMismatch);
    }
    marker.identity.target_database_header_hash = header.complete_hash()?;
    marker.validate()?;
    record.plaintext = Zeroizing::new(marker.encode()?);
    Ok(())
}

fn take_nonce(nonces: &[[u8; 24]], cursor: &mut usize) -> Result<[u8; 24], StorageError> {
    let nonce = *nonces.get(*cursor).ok_or(StorageError::InvalidEncoding)?;
    *cursor = cursor.checked_add(1).ok_or(StorageError::Overflow)?;
    Ok(nonce)
}

fn add_record_charge(
    logical: &mut u64,
    backup: &mut u64,
    key_bytes: usize,
    value_bytes: usize,
) -> Result<(), StorageError> {
    let charge = logical_record_charge(key_bytes, value_bytes)?;
    *logical = logical.checked_add(charge).ok_or(StorageError::Overflow)?;
    *backup = backup
        .checked_add(charge.checked_add(8).ok_or(StorageError::Overflow)?)
        .ok_or(StorageError::Overflow)?;
    Ok(())
}

fn guard_tbs(
    header: &DatabaseHeader,
    reservation: &NonceReservationState,
) -> Result<RollbackGuardTbs, StorageError> {
    let state = reservation.tbs();
    Ok(RollbackGuardTbs {
        network_id: header.tbs().network_id,
        server_id: header.tbs().server_id,
        database_instance_id: header.tbs().database_instance_id,
        storage_key_generation: header.tbs().storage_key_generation,
        schema_generation: header.tbs().schema_generation,
        recovery_epoch: header.tbs().recovery_epoch,
        storage_commit_sequence: state.storage_commit_sequence,
        manifest_sequence: state.manifest_sequence,
        state_generation: state.state_generation,
        phase: state.phase,
        reservation_sequence: state.reservation_sequence,
        nonce_reservation_start: state.nonce_reservation_start,
        nonce_draw_high_water: state.nonce_draw_high_water,
        database_header_hash: state.database_header_hash,
        state_meta_record_id: state.state_meta_record_id,
        nonce_reservation_state_hash: reservation.complete_hash()?,
        previous_guard_hash: state.previous_guard_hash,
    })
}

#[cfg(test)]
mod tests {
    use agenc_relay_crypto::{LoginIndexKey, rekey_transform_profile_hash};
    use agenc_relay_types::{DatabaseId, NetworkId, RecoveryEpoch, ServerId, ServerIncarnation};

    use super::*;
    use crate::{
        LoginIndexKeyState, StorageConstructionKind, StorageOperationIdentity,
        construction_plan_hash,
    };

    const ZERO: StorageDigest = StorageDigest::from_bytes([0; 32]);

    fn header(database: DatabaseId) -> Result<DatabaseHeader, StorageError> {
        let tbs = DatabaseHeaderTbs::new(
            NetworkId::from_bytes([1; 32]),
            ServerId::from_bytes([2; 16]),
            ServerIncarnation::from_bytes([3; 16]),
            database,
            1,
            crate::SCHEMA_GENERATION,
            RecoveryEpoch::from_bytes([4; 16]),
        )?;
        Ok(DatabaseHeader::new(tbs, StorageDigest::from_bytes([5; 32])))
    }

    fn identity(database: DatabaseId) -> Result<StorageOperationIdentity, StorageError> {
        Ok(StorageOperationIdentity {
            kind: StorageConstructionKind::Rekey,
            command_version: 1,
            source_database_header_hash: ZERO,
            target_database_header_hash: ZERO,
            source_rollback_guard_hash: ZERO,
            source_stream_digest: None,
            source_schema_generation: crate::SCHEMA_GENERATION,
            target_schema_generation: crate::SCHEMA_GENERATION,
            transform_profile_hash: rekey_transform_profile_hash()?,
            target_database_instance_id: database,
            source_master_key_id: ZERO,
            source_guard_root_key_id: ZERO,
            target_master_key_id: ZERO,
            target_guard_root_key_id: ZERO,
            planned_entry_count: 1,
            construction_plan_hash: construction_plan_hash(
                StorageConstructionKind::Rekey,
                &[],
                crate::MAX_CONSTRUCTION_PLAN_BYTES,
            )?,
        })
    }

    fn marker_record(
        marker: StorageConstruction,
        key: Vec<u8>,
        schema: u32,
    ) -> Result<InitialStorageRecord, StorageError> {
        Ok(InitialStorageRecord {
            table: TableId::StorageConstruction,
            key: StoredKey::new(key)?,
            record_schema: schema,
            plaintext: Zeroizing::new(marker.encode()?),
        })
    }

    fn login_key_state_record(byte: u8) -> Result<InitialStorageRecord, StorageError> {
        let network = NetworkId::from_bytes([1; 32]);
        let key = LoginIndexKey::from_bytes([byte; 32]);
        let state = LoginIndexKeyState::stable(1, key.key_id(network))?;
        InitialStorageRecord::new(
            TableId::LoginIndexKeyState,
            StoredKey::new(crate::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
            1,
            state.encode()?,
        )
    }

    #[test]
    fn initial_record_rejects_untracked_zero_schema_and_oversized_plaintext()
    -> Result<(), StorageError> {
        assert!(matches!(
            InitialStorageRecord::new(TableId::KeyCheck, StoredKey::new(vec![1])?, 1, vec![1],),
            Err(StorageError::InvalidEncoding)
        ));
        assert!(matches!(
            InitialStorageRecord::new(TableId::Account, StoredKey::new(vec![1])?, 0, vec![1],),
            Err(StorageError::InvalidEncoding)
        ));
        assert!(matches!(
            InitialStorageRecord::new(
                TableId::Account,
                StoredKey::new(vec![1])?,
                1,
                vec![0; agenc_relay_crypto::MAX_STORAGE_PLAINTEXT_BYTES + 1],
            ),
            Err(StorageError::InvalidEncoding)
        ));
        Ok(())
    }

    #[test]
    fn initial_singleton_validation_enforces_mode_and_unique_identity() -> Result<(), StorageError>
    {
        let mut live = vec![login_key_state_record(1)?];
        assert_eq!(
            validate_initial_records(StorageInitializationMode::Live, &mut live),
            Ok(())
        );

        let mut missing = Vec::new();
        assert_eq!(
            validate_initial_records(StorageInitializationMode::Live, &mut missing),
            Err(StorageError::InvalidEncoding)
        );
        assert_eq!(
            validate_initial_records(StorageInitializationMode::Construction, &mut missing),
            Err(StorageError::InvalidEncoding)
        );

        let mut duplicate = vec![login_key_state_record(2)?, login_key_state_record(2)?];
        assert_eq!(
            validate_initial_records(StorageInitializationMode::Live, &mut duplicate),
            Err(StorageError::InvalidEncoding)
        );
        Ok(())
    }

    #[test]
    fn construction_header_binding_rejects_each_marker_mismatch() -> Result<(), StorageError> {
        let database = DatabaseId::from_bytes([6; 16]);
        let header = header(database)?;
        let valid = StorageConstruction {
            identity: identity(database)?,
            output_path_hash: StorageDigest::from_bytes([7; 32]),
            next_target: StorageConstructionCursor::BeforeFirst,
            target_records_committed: 0,
        };
        let mut live = Vec::new();
        assert_eq!(
            bind_construction_target_header(StorageInitializationMode::Live, &mut live, &header),
            Ok(())
        );
        assert_eq!(
            bind_construction_target_header(
                StorageInitializationMode::Construction,
                &mut live,
                &header,
            ),
            Err(StorageError::InvalidEncoding)
        );

        let mut wrong_key = vec![marker_record(valid, b"wrong-key".to_vec(), 1)?];
        assert_eq!(
            bind_construction_target_header(
                StorageInitializationMode::Construction,
                &mut wrong_key,
                &header,
            ),
            Err(StorageError::InvalidEncoding)
        );

        let valid = StorageConstruction {
            identity: identity(database)?,
            output_path_hash: StorageDigest::from_bytes([7; 32]),
            next_target: StorageConstructionCursor::BeforeFirst,
            target_records_committed: 0,
        };
        let mut wrong_schema = vec![marker_record(
            valid,
            crate::STORAGE_CONSTRUCTION_KEY.to_vec(),
            2,
        )?];
        assert_eq!(
            bind_construction_target_header(
                StorageInitializationMode::Construction,
                &mut wrong_schema,
                &header,
            ),
            Err(StorageError::InvalidEncoding)
        );

        let mut nonzero_hash_identity = identity(database)?;
        nonzero_hash_identity.target_database_header_hash = StorageDigest::from_bytes([8; 32]);
        let mut nonzero_hash = vec![marker_record(
            StorageConstruction {
                identity: nonzero_hash_identity,
                output_path_hash: StorageDigest::from_bytes([7; 32]),
                next_target: StorageConstructionCursor::BeforeFirst,
                target_records_committed: 0,
            },
            crate::STORAGE_CONSTRUCTION_KEY.to_vec(),
            1,
        )?];
        assert_eq!(
            bind_construction_target_header(
                StorageInitializationMode::Construction,
                &mut nonzero_hash,
                &header,
            ),
            Err(StorageError::ResumeMismatch)
        );

        let mut advanced_identity = identity(database)?;
        advanced_identity.planned_entry_count = 2;
        let advanced = StorageConstruction {
            identity: advanced_identity,
            output_path_hash: StorageDigest::from_bytes([7; 32]),
            next_target: StorageConstructionCursor::AtTarget {
                table: TableId::Account,
                key: StoredKey::new(vec![10; 24])?,
            },
            target_records_committed: 1,
        };
        let mut advanced_record = vec![marker_record(
            advanced,
            crate::STORAGE_CONSTRUCTION_KEY.to_vec(),
            1,
        )?];
        assert_eq!(
            bind_construction_target_header(
                StorageInitializationMode::Construction,
                &mut advanced_record,
                &header,
            ),
            Err(StorageError::ResumeMismatch)
        );

        let mut wrong_database = vec![marker_record(
            StorageConstruction {
                identity: identity(DatabaseId::from_bytes([9; 16]))?,
                output_path_hash: StorageDigest::from_bytes([7; 32]),
                next_target: StorageConstructionCursor::BeforeFirst,
                target_records_committed: 0,
            },
            crate::STORAGE_CONSTRUCTION_KEY.to_vec(),
            1,
        )?];
        assert_eq!(
            bind_construction_target_header(
                StorageInitializationMode::Construction,
                &mut wrong_database,
                &header,
            ),
            Err(StorageError::ResumeMismatch)
        );

        let valid = StorageConstruction {
            identity: identity(database)?,
            output_path_hash: StorageDigest::from_bytes([7; 32]),
            next_target: StorageConstructionCursor::BeforeFirst,
            target_records_committed: 0,
        };
        let mut records = vec![marker_record(
            valid,
            crate::STORAGE_CONSTRUCTION_KEY.to_vec(),
            1,
        )?];
        assert_eq!(
            bind_construction_target_header(
                StorageInitializationMode::Construction,
                &mut records,
                &header,
            ),
            Ok(())
        );
        let rebound = StorageConstruction::decode(
            &records.first().ok_or(StorageError::StaleState)?.plaintext,
        )?;
        assert_eq!(
            rebound.identity.target_database_header_hash,
            header.complete_hash()?
        );
        Ok(())
    }

    #[test]
    fn nonce_and_charge_helpers_reject_exhaustion_and_overflow() -> Result<(), StorageError> {
        let nonces = [[1_u8; 24], [2_u8; 24]];
        let mut cursor = 0;
        assert_eq!(take_nonce(&nonces, &mut cursor)?, [1; 24]);
        assert_eq!(take_nonce(&nonces, &mut cursor)?, [2; 24]);
        assert_eq!(
            take_nonce(&nonces, &mut cursor),
            Err(StorageError::InvalidEncoding)
        );

        let mut logical = 0;
        let mut backup = 0;
        add_record_charge(&mut logical, &mut backup, 1, crate::MIN_SEALED_RECORD_BYTES)?;
        assert!(logical > 0 && backup > logical);

        let mut logical = u64::MAX;
        let mut backup = 0;
        assert_eq!(
            add_record_charge(&mut logical, &mut backup, 1, crate::MIN_SEALED_RECORD_BYTES,),
            Err(StorageError::Overflow)
        );
        let mut logical = 0;
        let mut backup = u64::MAX;
        assert_eq!(
            add_record_charge(&mut logical, &mut backup, 1, crate::MIN_SEALED_RECORD_BYTES,),
            Err(StorageError::Overflow)
        );
        Ok(())
    }
}
