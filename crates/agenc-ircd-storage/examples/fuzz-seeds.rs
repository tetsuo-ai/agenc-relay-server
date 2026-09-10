#![forbid(unsafe_code)]

//! Deterministic public seed corpora for the `storage_codecs` and `backup_stream`
//! fuzz targets. Every fixture uses the fixed public test keys those targets
//! hold, so the campaigns start from accepted authenticated inputs as well as
//! rejected variants. Nothing here is a production secret or a release claim.
//! Storage nonces are drawn from OS entropy, so the backup stream is golden
//! data written once; `tests/fuzz_seeds.rs` verifies the committed bytes.

use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use agenc_ircd_crypto::{
    DatabaseBinding, Ed25519SecretKey, LoginIndexKey, RollbackGuardRootKey, StorageDigest,
    StorageIntegrityContext, StorageIntegrityKeys, StorageMasterKey, derive_storage_integrity_keys,
};
use agenc_ircd_storage::{
    BackupDestination, BackupRecord, DatabaseHeader, DatabaseHeaderTbs, InitialStorageRecord,
    IntegrityCheckpoint, IntegrityCheckpointTbs, IntegrityManifest, IntegrityManifestTbs,
    IntegrityRecordMutation, IntegrityRecordVersion, LOGIN_INDEX_KEY_STATE_KEY, LoginIndexKeyState,
    NonceReservationState, NonceReservationTbs, QualificationTarget, REQUIRED_QUALIFICATION_CASES,
    RollbackGuard, RollbackGuardPhase, RollbackGuardTbs, SCHEMA_GENERATION, StateDirectory,
    StateMeta, StateMetaTbs, StorageEngineLimits, StorageError, StorageGrowthCase,
    StorageInitializationConfig, StorageInitializationMode, StorageInitializationOutcome,
    StorageOpenConfig, StorageOwner, StorageQualification, StorageQualificationReport,
    StorageQualificationReportTbs, StorageSealContext, StoredKey, TableId, initialize_storage,
};
use agenc_ircd_types::{DatabaseId, NetworkId, RecoveryEpoch, ServerId, ServerIncarnation};

/// Public keys the `storage_codecs` target derives its integrity keys from.
const CODEC_GUARD_ROOT: [u8; 32] = [0x51; 32];
const CODEC_HEADER_HASH: [u8; 32] = [0x52; 32];
const CODEC_NETWORK: [u8; 32] = [0x53; 32];
const CODEC_SERVER: [u8; 16] = [0x54; 16];
const CODEC_DATABASE: [u8; 16] = [0x55; 16];
/// Public keys the `backup_stream` target verifies under.
const BACKUP_MASTER_KEY: [u8; 32] = [0x61; 32];
const BACKUP_GUARD_ROOT: [u8; 32] = [0x62; 32];
const BACKUP_SIGNING_KEY: [u8; 32] = [0x63; 32];
const BACKUP_LOGIN_KEY: [u8; 32] = [0x64; 32];
const BACKUP_NETWORK: [u8; 32] = [0x66; 32];
const BACKUP_SERVER: [u8; 16] = [0x67; 16];

/// Shared counters of the coherent codec fixture set.
const COMMIT_SEQUENCE: u64 = 2;
const STATE_GENERATION: u64 = 5;
const RESERVATION_START: u64 = 8;
const NONCE_HIGH_WATER: u64 = 11;

const LIMITS: StorageEngineLimits = StorageEngineLimits {
    redb_cache_bytes: 8 * 1_024 * 1_024,
    fixed_reserve_bytes: 64 * 1_024 * 1_024,
    reserve_percent: 1,
    database_max_bytes: 1_073_741_824,
    backup_max_bytes: 2_147_483_648,
    integrity_checkpoint_manifests: 100_000,
};

type SeedResult<T> = Result<T, Box<dyn Error>>;
type Seed = (&'static str, Vec<u8>);

fn main() -> SeedResult<()> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let output = arguments.next().ok_or("missing corpus root")?;
    let scratch = arguments.next().ok_or("missing scratch directory")?;
    if arguments.next().is_some() {
        return Err("usage: fuzz-seeds <corpus-root> <empty-scratch-directory>".into());
    }
    let output = PathBuf::from(output);
    let identity = CodecIdentity::fixed()?;
    let mut codec = control_seeds(&identity)?;
    codec.extend(integrity_seeds(&identity)?);
    codec.extend(row_seeds(&identity)?);
    write_seeds(&output.join("storage_codecs"), codec)?;
    write_seeds(
        &output.join("backup_stream"),
        backup_seeds(Path::new(&scratch))?,
    )?;
    Ok(())
}

fn write_seeds(directory: &Path, seeds: Vec<Seed>) -> SeedResult<()> {
    fs::create_dir_all(directory)?;
    for (name, bytes) in seeds {
        let path = directory.join(name);
        fs::write(&path, bytes)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}

fn seed(arm: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(body.len() + 1);
    bytes.push(arm);
    bytes.extend_from_slice(body);
    bytes
}

fn tampered(mut bytes: Vec<u8>) -> Vec<u8> {
    if let Some(last) = bytes.last_mut() {
        *last ^= 0x01;
    }
    bytes
}

fn shortened(bytes: &[u8], drop: usize) -> SeedResult<&[u8]> {
    let end = bytes
        .len()
        .checked_sub(drop)
        .ok_or("fixture is shorter than the bytes to drop")?;
    Ok(bytes.get(..end).ok_or("fixture slice is out of range")?)
}

/// The one database identity every codec fixture refers to.
struct CodecIdentity {
    network: NetworkId,
    server: ServerId,
    database: DatabaseId,
    incarnation: ServerIncarnation,
    epoch: RecoveryEpoch,
    keys: StorageIntegrityKeys,
    header: DatabaseHeader,
    header_hash: StorageDigest,
    state_meta_record_id: StorageDigest,
}

impl CodecIdentity {
    fn fixed() -> SeedResult<Self> {
        let network = NetworkId::from_bytes(CODEC_NETWORK);
        let server = ServerId::from_bytes(CODEC_SERVER);
        let database = DatabaseId::from_bytes(CODEC_DATABASE);
        let incarnation = ServerIncarnation::from_bytes([0x56; 16]);
        let epoch = RecoveryEpoch::from_bytes([0x57; 16]);
        let header = DatabaseHeader::new(
            DatabaseHeaderTbs::new(
                network,
                server,
                incarnation,
                database,
                1,
                SCHEMA_GENERATION,
                epoch,
            )?,
            StorageDigest::from_bytes([0x58; 32]),
        );
        Ok(Self {
            network,
            server,
            database,
            incarnation,
            epoch,
            keys: derive_storage_integrity_keys(
                &RollbackGuardRootKey::from_bytes(CODEC_GUARD_ROOT),
                StorageIntegrityContext::new(network, server, database),
            )?,
            header_hash: header.complete_hash()?,
            header,
            state_meta_record_id: StorageDigest::from_bytes([0x59; 32]),
        })
    }

    fn reservation(&self) -> Result<NonceReservationState, StorageError> {
        NonceReservationState::authenticate(
            NonceReservationTbs {
                database_instance_id: self.database,
                reservation_sequence: 3,
                phase: RollbackGuardPhase::NonceReserved,
                nonce_reservation_start: RESERVATION_START,
                nonce_draw_high_water: NONCE_HIGH_WATER,
                storage_commit_sequence: COMMIT_SEQUENCE,
                manifest_sequence: COMMIT_SEQUENCE,
                state_generation: STATE_GENERATION,
                database_header_hash: self.header_hash,
                state_meta_record_id: self.state_meta_record_id,
                previous_guard_hash: StorageDigest::from_bytes([0; 32]),
            },
            &self.keys,
        )
    }

    fn guard(&self, reservation: &NonceReservationState) -> Result<RollbackGuard, StorageError> {
        RollbackGuard::authenticate(
            RollbackGuardTbs {
                network_id: self.network,
                server_id: self.server,
                database_instance_id: self.database,
                storage_key_generation: 1,
                schema_generation: SCHEMA_GENERATION,
                recovery_epoch: self.epoch,
                storage_commit_sequence: COMMIT_SEQUENCE,
                manifest_sequence: COMMIT_SEQUENCE,
                state_generation: STATE_GENERATION,
                phase: RollbackGuardPhase::NonceReserved,
                reservation_sequence: 3,
                nonce_reservation_start: RESERVATION_START,
                nonce_draw_high_water: NONCE_HIGH_WATER,
                database_header_hash: self.header_hash,
                state_meta_record_id: self.state_meta_record_id,
                nonce_reservation_state_hash: reservation.complete_hash()?,
                previous_guard_hash: StorageDigest::from_bytes([0; 32]),
            },
            &self.keys,
        )
    }

    fn state_meta(&self) -> Result<StateMeta, StorageError> {
        StateMeta::authenticate(
            StateMetaTbs {
                storage_commit_sequence: COMMIT_SEQUENCE,
                manifest_sequence: COMMIT_SEQUENCE,
                state_generation: STATE_GENERATION,
                account_service_response_count: 1,
                nonce_draw_high_water: NONCE_HIGH_WATER,
                logical_database_bytes: 4_096,
                backup_stream_bytes: 8_192,
                checkpoint_manifest_sequence: 1,
                latest_manifest_hash: StorageDigest::from_bytes([0x5a; 32]),
                checkpoint_hash: StorageDigest::from_bytes([0x5b; 32]),
                previous_rollback_guard_hash: StorageDigest::from_bytes([0; 32]),
            },
            StorageDigest::from_bytes(CODEC_HEADER_HASH),
            &self.keys,
        )
    }

    fn manifest(&self) -> SeedResult<IntegrityManifest> {
        let mutation = IntegrityRecordMutation::new(
            TableId::Account,
            StoredKey::new(vec![0x5c; 4])?,
            IntegrityRecordVersion::Absent,
            IntegrityRecordVersion::Present {
                record_schema: 1,
                sealed_record_id: StorageDigest::from_bytes([0x5d; 32]),
            },
        )?;
        // One present mutation plus the two fixed seals draws three nonces.
        Ok(IntegrityManifest::new(IntegrityManifestTbs::new(
            self.database,
            COMMIT_SEQUENCE,
            COMMIT_SEQUENCE,
            STATE_GENERATION - 1,
            STATE_GENERATION,
            1,
            1,
            RESERVATION_START,
            RESERVATION_START,
            NONCE_HIGH_WATER,
            3,
            StorageDigest::from_bytes([0x5e; 32]),
            vec![mutation],
        )?)?)
    }

    fn checkpoint(
        &self,
        manifest: &IntegrityManifest,
    ) -> Result<IntegrityCheckpoint, StorageError> {
        IntegrityCheckpoint::new(IntegrityCheckpointTbs {
            database_instance_id: self.database,
            cut_storage_commit_sequence: COMMIT_SEQUENCE,
            cut_manifest_sequence: COMMIT_SEQUENCE,
            cut_state_generation: STATE_GENERATION,
            cut_account_service_response_count: 1,
            cut_nonce_draw_high_water: NONCE_HIGH_WATER,
            cut_manifest_hash: manifest.manifest_hash(),
            tracked_record_count: 1,
            tracked_state_digest: StorageDigest::from_bytes([0x5f; 32]),
            previous_checkpoint_hash: StorageDigest::from_bytes([0; 32]),
            installation_storage_commit_sequence: COMMIT_SEQUENCE + 1,
            installation_manifest_sequence: COMMIT_SEQUENCE,
            installation_nonce_reservation_start: NONCE_HIGH_WATER,
            installation_nonce_draw_high_water: NONCE_HIGH_WATER + 2,
        })
    }
}

/// Arms 0 through 3: the authenticated control records and the plain header.
fn control_seeds(identity: &CodecIdentity) -> SeedResult<Vec<Seed>> {
    let header = identity.header.encode()?;
    let reservation = identity.reservation()?;
    let reservation_bytes = reservation.encode()?;
    let guard = identity.guard(&reservation)?.encode()?;
    let state_meta = identity.state_meta()?.encode()?;
    Ok(vec![
        ("header-valid", seed(0, &header)),
        ("header-truncated", seed(0, shortened(&header, 1)?)),
        ("nonce-reservation-valid", seed(1, &reservation_bytes)),
        (
            "nonce-reservation-tampered",
            tampered(seed(1, &reservation_bytes)),
        ),
        ("rollback-guard-valid", seed(2, &guard)),
        ("rollback-guard-tampered", tampered(seed(2, &guard))),
        ("state-meta-valid", seed(3, &state_meta)),
        ("state-meta-tampered", tampered(seed(3, &state_meta))),
    ])
}

/// Arms 4 and 5: the integrity manifest and its checkpoint.
fn integrity_seeds(identity: &CodecIdentity) -> SeedResult<Vec<Seed>> {
    let manifest = identity.manifest()?;
    let checkpoint = identity.checkpoint(&manifest)?;
    Ok(vec![
        ("manifest-valid", seed(4, &manifest.encode()?)),
        ("checkpoint-valid", seed(5, &checkpoint.encode()?)),
    ])
}

/// Arms 6 through 9: sealed rows, backup rows, and login-index keys and state.
fn row_seeds(identity: &CodecIdentity) -> SeedResult<Vec<Seed>> {
    let master = StorageMasterKey::from_bytes([0x60; 32]);
    let seal = StorageSealContext::new(
        &master,
        DatabaseBinding::new(
            identity.network,
            identity.server,
            identity.incarnation,
            identity.database,
        ),
        1,
    )?;
    let stored_key = StoredKey::new(vec![0x5c; 4])?;
    let sealed = seal
        .seal(
            TableId::Account,
            1,
            [0x61; 24],
            &stored_key,
            b"seed-plaintext",
        )?
        .encode()?;
    let backup_record = BackupRecord::new(TableId::Account, stored_key, 1, sealed.clone())?;
    let login_state = LoginIndexKeyState::stable(
        1,
        LoginIndexKey::from_bytes([0x62; 32]).key_id(identity.network),
    )?;
    let mut login_key = 1_u32.to_be_bytes().to_vec();
    login_key.extend_from_slice(&[0x63; 32]);
    Ok(vec![
        ("sealed-record-valid", seed(6, &sealed)),
        // The envelope codec does not open the AEAD, so a flipped ciphertext
        // byte is still an accepted canonical frame for this target.
        (
            "sealed-record-flipped-ciphertext",
            tampered(seed(6, &sealed)),
        ),
        ("backup-record-valid", seed(7, &backup_record.encode()?)),
        ("login-index-key-valid", seed(8, &login_key)),
        ("login-index-key-short", seed(8, shortened(&login_key, 1)?)),
        ("login-key-state-valid", seed(9, &login_state.encode()?)),
    ])
}

fn scratch_qualification(directory: &Path) -> SeedResult<StorageQualification> {
    let tuple = StateDirectory::probe(directory)?;
    let target = match tuple.target {
        "x86_64-unknown-linux-gnu" => QualificationTarget::X86_64UnknownLinuxGnu,
        "aarch64-unknown-linux-gnu" => QualificationTarget::Aarch64UnknownLinuxGnu,
        _ => return Err("unsupported seed-generation host".into()),
    };
    let mut cases = REQUIRED_QUALIFICATION_CASES
        .iter()
        .map(|name| StorageGrowthCase::new((*name).to_owned(), 1, 1))
        .collect::<Result<Vec<_>, _>>()?;
    cases.sort_by(|left, right| left.name().cmp(right.name()));
    // A disposable key admits the scratch tuple for seed generation only; it
    // qualifies nothing and never leaves this process.
    let key = Ed25519SecretKey::from_bytes([0x65; 32]);
    let report = StorageQualificationReport::sign(
        StorageQualificationReportTbs {
            target,
            filesystem_type: tuple.filesystem_type,
            block_size: tuple.block_size,
            mount_flags: tuple.mount_flags,
            kernel_release: "seed-generation".to_owned(),
            redb_features_hash: StorageDigest::from_bytes([1; 32]),
            release_profile_hash: StorageDigest::from_bytes([2; 32]),
            corpus_hash: StorageDigest::from_bytes([3; 32]),
            cases,
            maximum_observed_growth: 0,
            raw_log_hash: StorageDigest::from_bytes([4; 32]),
        },
        &key,
    )?;
    let verified =
        StorageQualificationReport::decode_and_verify(&report.encode()?, key.public_key())?;
    Ok(verified.qualification_for(tuple)?)
}

fn private_directory(path: &Path) -> SeedResult<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Initializes one fresh live database under the backup target's public keys.
fn seed_database(state: &Path, qualification: StorageQualification) -> SeedResult<()> {
    let network = NetworkId::from_bytes(BACKUP_NETWORK);
    let login_key = LoginIndexKey::from_bytes(BACKUP_LOGIN_KEY);
    let key_state = LoginIndexKeyState::stable(1, login_key.key_id(network))?;
    let initial = InitialStorageRecord::new(
        TableId::LoginIndexKeyState,
        StoredKey::new(LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
        1,
        key_state.encode()?,
    )?;
    let outcome = initialize_storage(StorageInitializationConfig {
        state_directory: StateDirectory::open(state, &[qualification])?,
        header_tbs: DatabaseHeaderTbs::new(
            network,
            ServerId::from_bytes(BACKUP_SERVER),
            ServerIncarnation::from_bytes([0x68; 16]),
            DatabaseId::from_bytes([0x69; 16]),
            1,
            SCHEMA_GENERATION,
            RecoveryEpoch::from_bytes([0x6a; 16]),
        )?,
        storage_master_key: StorageMasterKey::from_bytes(BACKUP_MASTER_KEY),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes(BACKUP_GUARD_ROOT),
        mode: StorageInitializationMode::Live,
        initial_records: vec![initial],
        account_service_response_count: 0,
        state_generation: 0,
        predecessor_guard_hash: StorageDigest::from_bytes([0; 32]),
        limits: LIMITS,
    })?;
    if !matches!(outcome, StorageInitializationOutcome::Complete { .. }) {
        return Err("seed database initialization was indeterminate".into());
    }
    Ok(())
}

/// Produces one real signed backup through the production storage owner.
fn write_seed_backup(
    state: &Path,
    backups: &Path,
    qualification: StorageQualification,
) -> SeedResult<Vec<u8>> {
    let owner = StorageOwner::start(StorageOpenConfig {
        expected_network_id: NetworkId::from_bytes(BACKUP_NETWORK),
        expected_server_id: ServerId::from_bytes(BACKUP_SERVER),
        state_directory: StateDirectory::open(state, &[qualification])?,
        storage_master_key: StorageMasterKey::from_bytes(BACKUP_MASTER_KEY),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes(BACKUP_GUARD_ROOT),
        login_index_key: LoginIndexKey::from_bytes(BACKUP_LOGIN_KEY),
        previous_login_index_key: None,
        limits: LIMITS,
    })?;
    let receipt = owner
        .port()
        .try_backup(
            BackupDestination::new(backups, "seed.backup")?,
            Ed25519SecretKey::from_bytes(BACKUP_SIGNING_KEY),
            1_700_000_000,
            [0x6b; 16],
        )?
        .wait()?;
    owner.shutdown()?;
    let stream = fs::read(backups.join("seed.backup"))?;
    if u64::try_from(stream.len())? != receipt.stream_bytes {
        return Err(StorageError::InvalidEncoding.into());
    }
    Ok(stream)
}

fn backup_seeds(scratch: &Path) -> SeedResult<Vec<Seed>> {
    if scratch.exists() {
        return Err("scratch directory must not exist yet".into());
    }
    private_directory(scratch)?;
    let state = scratch.join("state");
    let backups = scratch.join("backups");
    private_directory(&state)?;
    private_directory(&backups)?;
    let qualification = scratch_qualification(&state)?;
    seed_database(&state, qualification)?;
    let stream = write_seed_backup(&state, &backups, qualification)?;
    let public_key = *Ed25519SecretKey::from_bytes(BACKUP_SIGNING_KEY)
        .public_key()
        .as_bytes();
    let mut signed = public_key.to_vec();
    signed.extend_from_slice(&stream);
    let mut wrong_key = vec![0x6c; 32];
    wrong_key.extend_from_slice(&stream);
    let mut trailing = signed.clone();
    trailing.push(0);
    let truncated = shortened(&signed, 8)?.to_vec();
    Ok(vec![
        ("signed-fresh-database", signed.clone()),
        ("signed-wrong-trust-key", wrong_key),
        ("signed-trailing-byte", trailing),
        ("signed-truncated-trailer", truncated),
        ("signed-tampered-record", tampered(signed)),
    ])
}
