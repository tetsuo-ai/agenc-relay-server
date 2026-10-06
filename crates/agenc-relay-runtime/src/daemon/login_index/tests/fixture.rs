//! Private composition uses only authenticated storage and the production audit verifier.
#![forbid(unsafe_code)]
#![cfg(test)]

use super::*;
use agenc_relay_admin::OperatorRecord;
use agenc_relay_auth::OpaqueProfile;
use agenc_relay_storage::{
    DatabaseHeaderTbs, InitialStorageRecord, LIVE_RECORD_KIND, LOGIN_INDEX_KEY_STATE_KEY,
    OPAQUE_FAKE_RECORD_KEY, SCHEMA_GENERATION, StorageInitializationConfig,
    StorageInitializationMode, StorageInitializationOutcome, StorageQualification,
    initialize_storage,
};
use agenc_relay_types::{AdminPermission, AdminPermissionSet, OperatorId};

pub(super) struct FaultFixture {
    pub(super) config: Config,
    qualification: StorageQualification,
    directory: TestDirectory,
}

impl FaultFixture {
    pub(super) fn new() -> TestResult<Self> {
        let mut config = Config::parse_text(
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../agenc-relay-config/tests/golden/public.toml"
            )),
            &PathResolver::none(),
            ValidationDepth::Document,
        )?;
        let directory = TestDirectory::create()?;
        config.storage.state_dir = directory.0.clone();
        config.storage.database_max_bytes = TEST_STORAGE_LIMITS.database_max_bytes;
        config.storage.backup_max_bytes = TEST_STORAGE_LIMITS.backup_max_bytes;
        let qualification = signed_test_qualification(StateDirectory::probe(&directory.0)?)?;
        let fixture = Self {
            config,
            qualification,
            directory,
        };
        fixture.initialize()?;
        Ok(fixture)
    }

    fn initialize(&self) -> TestResult {
        let network = self.config.network.network_id;
        let opaque = OpaqueProfile::generate(network)?;
        let state =
            LoginIndexKeyState::stable(1, LoginIndexKey::from_bytes(OLD_KEY).key_id(network))?;
        let records = vec![
            InitialStorageRecord::new(
                TableId::LoginIndexKeyState,
                StoredKey::new(LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
                1,
                state.encode()?,
            )?,
            InitialStorageRecord::new(
                TableId::OpaqueRecord,
                StoredKey::new(OPAQUE_FAKE_RECORD_KEY.to_vec())?,
                1,
                PersistentRecordValue::new(
                    TableId::OpaqueRecord,
                    LIVE_RECORD_KIND,
                    1,
                    0,
                    None,
                    Vec::new(),
                    opaque.expose_fake_record_for_persistence().to_vec(),
                )?
                .encode()?,
            )?,
        ];
        let result = initialize_storage(StorageInitializationConfig {
            state_directory: StateDirectory::open(
                &self.directory.0,
                core::slice::from_ref(&self.qualification),
            )?,
            header_tbs: DatabaseHeaderTbs::new(
                network,
                self.config.server.server_id,
                ServerIncarnation::from_bytes([33; 16]),
                DatabaseId::from_bytes([38; 16]),
                1,
                SCHEMA_GENERATION,
                RecoveryEpoch::from_bytes([34; 16]),
            )?,
            storage_master_key: StorageMasterKey::from_bytes(MASTER),
            rollback_guard_root_key: RollbackGuardRootKey::from_bytes(GUARD),
            mode: StorageInitializationMode::Live,
            initial_records: records,
            account_service_response_count: 0,
            state_generation: 0,
            predecessor_guard_hash: StorageDigest::from_bytes([0; 32]),
            limits: TEST_STORAGE_LIMITS,
        })?;
        if !matches!(result, StorageInitializationOutcome::Complete { .. }) {
            return Err("indeterminate fixture initialization".into());
        }
        Ok(())
    }

    pub(super) fn start_storage(
        &self,
        state: LoginIndexKeyState,
        faults: StorageFaultInjector,
    ) -> Result<StorageOwner, StorageError> {
        let (current, previous) = match state {
            LoginIndexKeyState::Stable {
                current_generation: 1,
                ..
            } => (OLD_KEY, None),
            LoginIndexKeyState::Stable { .. } => (NEW_KEY, None),
            LoginIndexKeyState::Transition { .. } => (NEW_KEY, Some(OLD_KEY)),
        };
        StorageOwner::start(StorageOpenConfig {
            expected_network_id: self.config.network.network_id,
            expected_server_id: self.config.server.server_id,
            state_directory: StateDirectory::open_with_faults(
                &self.directory.0,
                core::slice::from_ref(&self.qualification),
                faults,
            )?,
            storage_master_key: StorageMasterKey::from_bytes(MASTER),
            rollback_guard_root_key: RollbackGuardRootKey::from_bytes(GUARD),
            login_index_key: LoginIndexKey::from_bytes(current),
            previous_login_index_key: previous.map(LoginIndexKey::from_bytes),
            limits: TEST_STORAGE_LIMITS,
        })
    }

    pub(super) fn open(
        &self,
        state: LoginIndexKeyState,
        faults: StorageFaultInjector,
    ) -> TestResult<LiveStorage> {
        let mut owner = self.start_storage(state, faults)?;
        let limit_writer = owner.take_limit_writer()?;
        let seed = StateCoreSeed::from_storage(&owner)?;
        let recovered = seed.storage();
        let keys = KeyDeriver::new(
            StorageMasterKey::from_bytes(MASTER),
            recovered.database_binding(),
            recovered.storage_key_generation(),
        )?;
        let reconstruction = reconstruct(
            &seed,
            &owner.port(),
            &keys,
            self.config.network.role,
            MonotonicTick::from_ticks(0),
            UtcSecond::from_unix_seconds(60),
        )?;
        assert_eq!(
            reconstruction.account_service.login_index_key_state(),
            state
        );
        let audit = AuditAuthority::reconstruct(
            MaintenanceAuditScope::new(
                self.config.network.network_id,
                self.config.server.server_id,
                recovered.database_binding().database_instance_id(),
                recovered.database_binding().server_incarnation(),
                recovered.recovery_epoch(),
            ),
            Ed25519SecretKey::from_bytes(AUDIT_KEY),
            &[trust()?],
            owner.port(),
            KeyDeriver::new(
                StorageMasterKey::from_bytes(MASTER),
                recovered.database_binding(),
                recovered.storage_key_generation(),
            )?,
            &operators()?,
            60,
        )?;
        Ok(LiveStorage {
            owner,
            limit_writer,
            seed,
            keys,
            reconstruction,
            audit,
            backup_trust: Vec::new(),
        })
    }

    pub(super) fn stable(&self) -> TestResult<LoginIndexKeyState> {
        Ok(LoginIndexKeyState::stable(
            1,
            LoginIndexKey::from_bytes(OLD_KEY).key_id(self.config.network.network_id),
        )?)
    }

    pub(super) fn new_key_id(&self) -> LoginIndexKeyId {
        LoginIndexKey::from_bytes(NEW_KEY).key_id(self.config.network.network_id)
    }
}

fn trust() -> TestResult<AuditTrustManifestEntry> {
    let key = Ed25519SecretKey::from_bytes(AUDIT_KEY).public_key();
    Ok(AuditTrustManifestEntry {
        key_id: *audit_signing_key_id(key.as_bytes())?.as_bytes(),
        ed25519_public_key: *key.as_bytes(),
        not_before: 1,
        not_after: 100,
    })
}

fn operators() -> TestResult<OperatorRegistry> {
    let mut permissions = AdminPermissionSet::EMPTY;
    permissions.insert(AdminPermission::Observe);
    Ok(OperatorRegistry::from_records(vec![OperatorRecord::new(
        OperatorId::from_bytes([6; 16]),
        Ed25519SecretKey::from_bytes([5; 32]).public_key(),
        None,
        vec![1_000],
        Vec::new(),
        permissions,
        true,
    )?])?)
}
