//! Completion coverage for the closed Stage 05 schema and qualification surfaces.

#![forbid(unsafe_code)]

#[path = "stage_five_completion/recovery_provenance.rs"]
mod recovery_provenance;
#[path = "stage_five_completion/source_validation.rs"]
mod source_validation;
#[path = "stage_five_completion/witness_evidence.rs"]
mod witness_evidence;

use std::collections::BTreeMap;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use agenc_ircd_crypto::{
    BackupStreamHasher, ConstructionPlanHasher, CryptoError, DatabaseBinding, Ed25519PublicKey,
    Ed25519SecretKey, LoginIndexKey, RollbackGuardRootKey, SignatureDomain, StorageAuthenticator,
    StorageDigest, StorageIntegrityContext, StorageMasterKey, StorageNonce, StorageTable,
    TrackedStateHasher, authenticate_nonce_reservation, authenticate_rollback_guard,
    authenticate_state_meta, backup_signing_key_id, database_header_hash, database_key_check,
    derive_login_index, derive_storage_index, derive_storage_integrity_keys,
    derive_storage_record_key, integrity_checkpoint_hash, integrity_manifest_hash,
    nonce_reservation_hash, open_storage_record, rekey_transform_profile_hash,
    restore_transform_profile_hash, rollback_guard_hash, seal_storage_record, sealed_record_id,
    sign_canonical, storage_operation_id, storage_operation_key_id, storage_output_path_hash,
    storage_qualification_component_hash, tracked_record_commitment, tracked_state_digest,
};
use agenc_ircd_storage::{
    BackupConstructionSourceReader, BackupDestination, BackupTrustKey, CommitOutcome,
    ConstructionCommitReceipt, ConstructionDirectory, ConstructionDirectoryPhase,
    ConstructionExecutor, ConstructionFinalizationCounters, ConstructionLimits, ConstructionPlan,
    ConstructionPlanBuilder, ConstructionSourceDatabase, ConstructionSourceReader,
    ConstructionSourceRecord, ConstructionTarget, ConstructionTargetBatch,
    ConstructionTargetWriter, ConstructionTransformer, DatabaseConstructionSourceReader,
    E2eeRecoveryGate, E2eeRecoveryKind, ExactCopyTransformer, ExistingRecord, InitialStorageRecord,
    LoginIndexKeyState, LoginIndexLazyMigration, LoginIndexLookupSchedule, LoginIndexStoredKey,
    LoginIndexTransitionBatch, LoginIndexTransitionPreflight, LoginIndexValue, LoginIndexValueKind,
    PersistentRecordValue, ProtocolRecordBody, QualificationTarget, ReadPlan, RecordCodecKind,
    RecordMutation, RecordReference, RecoveryTransformV1, RestoreCommandRequest, RestoreTrustKey,
    SCHEMA_GENERATION, SealedRecord, StateDirectory, StorageAccountingLimits, StorageConstruction,
    StorageConstructionAction, StorageConstructionCursor, StorageConstructionKind,
    StorageConstructionPlanEntry, StorageConstructionSource, StorageConstructionSourceKind,
    StorageEngineLimits, StorageError, StorageFaultBoundary, StorageFaultCase,
    StorageFaultInjector, StorageFaultSchedule, StorageFaultSite, StorageGrowthCase,
    StorageGrowthRecorder, StorageInitializationConfig, StorageInitializationMode,
    StorageInitializationOutcome, StorageMutationBatch, StorageMutationHead, StorageOpenConfig,
    StorageOperationCompletion, StorageOperationIdentity, StorageOwner, StoragePort,
    StorageQualificationReport, StorageQualificationReportTbs, StorageSealContext, StoredKey,
    StoredKeyShape, TableId, construction_plan_hash, execute_restore_command, initialize_storage,
    recovery_transform_prefix, table_schema, table_schemas, validate_record_plaintext,
    verify_backup,
};
use agenc_ircd_types::{
    AccountRandomId, DatabaseId, NetworkId, NormalizedLogin, OpaqueCredentialId, RecoveryEpoch,
    ServerId, ServerIncarnation, TransactionId,
};

static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

const DOMAIN_TABLES: [TableId; 19] = [
    TableId::Account,
    TableId::OpaqueRecord,
    TableId::AuthTransaction,
    TableId::NicknameReservation,
    TableId::RegistrationInvite,
    TableId::Session,
    TableId::Channel,
    TableId::ChannelName,
    TableId::Sanction,
    TableId::FederationPeer,
    TableId::FederationOrigin,
    TableId::RequestResult,
    TableId::EdgeOutbox,
    TableId::EdgeProjection,
    TableId::History,
    TableId::Audit,
    TableId::AuditCheckpoint,
    TableId::E2eeObject,
    TableId::E2eeState,
];

fn domain_body(table: TableId, kind: u16, bytes: Vec<u8>) -> Result<Vec<u8>, StorageError> {
    if table == TableId::History {
        return crate::history_records::body(kind);
    }
    if kind == 1
        && matches!(
            table,
            TableId::Account | TableId::Session | TableId::Channel | TableId::Sanction
        )
    {
        return crate::domain_records::live_body(table, bytes.first().copied().unwrap_or(1));
    }
    if table == TableId::NicknameReservation && kind == 1 {
        return Ok(b"nickname".to_vec());
    }
    if table == TableId::ChannelName && kind == 1 {
        return crate::domain_records::channel_name_body(8, "#channel");
    }
    let seed = bytes.first().copied().unwrap_or(1);
    if table == TableId::E2eeObject {
        return agenc_ircd_storage::e2ee_records::fixtures::object_body(seed);
    }
    if table == TableId::E2eeState && kind != 1 {
        return agenc_ircd_storage::e2ee_records::fixtures::state_body(kind, seed);
    }
    if matches!(
        table,
        TableId::FederationPeer
            | TableId::FederationOrigin
            | TableId::RequestResult
            | TableId::EdgeOutbox
            | TableId::EdgeProjection
    ) {
        ProtocolRecordBody::new(table, kind, 1, bytes)?.encode()
    } else {
        Ok(bytes)
    }
}

fn account_key_bytes(seed: u8) -> Vec<u8> {
    AccountRandomId::from_bytes([seed; 16])
        .to_text()
        .into_bytes()
}

const QUALIFICATION_CASES: [&str; 21] = agenc_ircd_storage::REQUIRED_QUALIFICATION_CASES;

#[test]
fn storage_crypto_adapters_cover_every_public_boundary() -> Result<(), Box<dyn Error>> {
    let binding = DatabaseBinding::new(
        NetworkId::from_bytes([1; 32]),
        ServerId::from_bytes([2; 16]),
        ServerIncarnation::from_bytes([3; 16]),
        DatabaseId::from_bytes([4; 16]),
    );
    assert_eq!(binding.encode()?.len(), 98);
    assert_eq!(StorageTable::new(0)?.value(), 0);
    assert_eq!(StorageTable::new(26)?.value(), 26);
    assert!(StorageTable::new(27).is_err());

    let master = StorageMasterKey::from_bytes([5; 32]);
    assert!(master.matches(&StorageMasterKey::from_bytes([5; 32])));
    assert!(!master.matches(&StorageMasterKey::from_bytes([6; 32])));
    assert_ne!(
        master.source_operation_key_id()?,
        master.target_operation_key_id()?
    );
    let table = StorageTable::new(1)?;
    assert!(derive_storage_record_key(&master, binding, table, 0).is_err());
    let record_key = derive_storage_record_key(&master, binding, table, 1)?;
    assert!(derive_storage_index(&master, binding, table, 0, b"key").is_err());
    assert!(derive_storage_index(&master, binding, table, 1, &vec![0; 4_097]).is_err());
    let first_index = derive_storage_index(&master, binding, table, 1, b"key")?;
    let same_index = derive_storage_index(&master, binding, table, 1, b"key")?;
    let other_index = derive_storage_index(&master, binding, table, 1, b"other")?;
    assert!(first_index.matches(&same_index));
    assert!(first_index == same_index);
    assert!(!first_index.matches(&other_index));
    assert_eq!(first_index.expose_for_storage_key().len(), 32);

    let nonce_bytes = [7; 24];
    let sealed = seal_storage_record(
        &record_key,
        StorageNonce::from_reserved_bytes(nonce_bytes),
        1,
        b"stored-key",
        b"plaintext",
    )?;
    assert_eq!(sealed.as_bytes().len(), b"plaintext".len() + 16);
    let opened = open_storage_record(
        &record_key,
        &StorageNonce::from_reserved_bytes(nonce_bytes),
        1,
        b"stored-key",
        &sealed,
    )?;
    assert_eq!(opened.expose_for_storage_codec(), b"plaintext");
    assert!(
        open_storage_record(
            &record_key,
            &StorageNonce::from_reserved_bytes([8; 24]),
            1,
            b"stored-key",
            &sealed,
        )
        .is_err()
    );
    assert!(
        open_storage_record(
            &record_key,
            &StorageNonce::from_reserved_bytes(nonce_bytes),
            2,
            b"stored-key",
            &sealed,
        )
        .is_err()
    );
    assert!(
        seal_storage_record(
            &record_key,
            StorageNonce::from_reserved_bytes(nonce_bytes),
            0,
            b"stored-key",
            b"plaintext",
        )
        .is_err()
    );
    assert!(
        seal_storage_record(
            &record_key,
            StorageNonce::from_reserved_bytes(nonce_bytes),
            1,
            &vec![0; 4_097],
            b"plaintext",
        )
        .is_err()
    );

    let root = RollbackGuardRootKey::from_bytes([9; 32]);
    assert!(root.matches(&RollbackGuardRootKey::from_bytes([9; 32])));
    assert!(!root.matches(&RollbackGuardRootKey::from_bytes([10; 32])));
    assert_ne!(
        root.source_operation_key_id()?,
        root.target_operation_key_id()?
    );
    let keys = derive_storage_integrity_keys(
        &root,
        StorageIntegrityContext::new(
            NetworkId::from_bytes([1; 32]),
            ServerId::from_bytes([2; 16]),
            DatabaseId::from_bytes([4; 16]),
        ),
    )?;
    let auth = authenticate_state_meta(&keys, digest(11), b"state")?;
    assert!(auth.matches(&StorageAuthenticator::from_bytes(
        *auth.expose_for_storage()
    )));
    assert!(!auth.matches(&StorageAuthenticator::from_bytes([0; 32])));
    assert_ne!(
        authenticate_nonce_reservation(&keys, b"control")?.expose_for_storage(),
        authenticate_rollback_guard(&keys, b"control")?.expose_for_storage()
    );

    let small = b"canonical";
    let hashes = [
        database_header_hash(small)?,
        database_key_check(small)?,
        nonce_reservation_hash(small)?,
        rollback_guard_hash(small)?,
        sealed_record_id(small)?,
        integrity_manifest_hash(small)?,
        integrity_checkpoint_hash(small)?,
        tracked_record_commitment(small)?,
        backup_signing_key_id(&[12; 32])?,
        storage_operation_id(small)?,
        restore_transform_profile_hash()?,
        rekey_transform_profile_hash()?,
    ];
    assert!(hashes.windows(2).all(|pair| {
        let [left, right] = pair else {
            return false;
        };
        left != right
    }));

    assert!(tracked_state_digest(1, &[]).is_err());
    let commitments = [digest(13), digest(14)];
    assert_eq!(tracked_state_digest(2, &commitments)?, {
        let mut hasher = TrackedStateHasher::new(2);
        hasher.update(commitments[0])?;
        hasher.update(commitments[1])?;
        hasher.finalize()?
    });
    assert!(TrackedStateHasher::new(1).finalize().is_err());
    let mut full_state = TrackedStateHasher::new(0);
    assert!(full_state.update(digest(15)).is_err());

    assert!(storage_qualification_component_hash(b"", b"bytes").is_err());
    assert!(storage_qualification_component_hash(&[b'a'; 129], b"bytes").is_err());
    assert!(storage_qualification_component_hash(b"not\nprintable", b"bytes").is_err());
    assert!(storage_qualification_component_hash(b"valid", &vec![0; 16_777_257]).is_err());
    storage_qualification_component_hash(b"valid", b"bytes")?;

    assert!(ConstructionPlanHasher::new(1, 0).is_err());
    let mut too_small = ConstructionPlanHasher::new(1, 1)?;
    assert!(too_small.update_entry(b"two").is_err());
    let mut complete = ConstructionPlanHasher::new(1, 3)?;
    complete.update_entry(b"one")?;
    assert!(complete.update_entry(b"extra").is_err());
    complete.finalize()?;
    assert!(ConstructionPlanHasher::new(1, 3)?.finalize().is_err());

    assert!(storage_operation_key_id(b"", &[16; 32]).is_err());
    assert!(storage_operation_key_id(&[b'x'; 33], &[16; 32]).is_err());
    storage_operation_key_id(b"purpose", &[16; 32])?;
    assert!(storage_output_path_hash("").is_err());
    assert!(storage_output_path_hash(&"x".repeat(4_097)).is_err());
    storage_output_path_hash("/absolute/output")?;

    assert!(BackupStreamHasher::new(0).is_err());
    let mut stream = BackupStreamHasher::new(3)?;
    stream.update(b"abc")?;
    assert_eq!(stream.bytes_seen(), 3);
    assert!(stream.update(b"d").is_err());
    let _ = stream.finalize();
    Ok(())
}

#[test]
fn every_table_has_one_closed_schema_and_domain_codec_consumes_fully() -> Result<(), Box<dyn Error>>
{
    let schemas = table_schemas()?;
    for (number, schema) in (0_u16..=26).zip(schemas) {
        assert_eq!(schema.table().as_u16(), number);
        assert_eq!(
            schema.is_integrity_tracked(),
            schema.table().is_integrity_tracked()
        );
    }
    for table in DOMAIN_TABLES {
        assert_eq!(table_schema(table).codec(), RecordCodecKind::Domain);
        let key = key_for(table)?;
        let reference =
            RecordReference::new(TableId::Account, StoredKey::new(account_key_bytes(1))?)?;
        let kind = if table == TableId::History { 2 } else { 1 };
        let body = if table == TableId::E2eeState {
            E2eeRecoveryGate::new(
                digest(40),
                E2eeRecoveryKind::Normal,
                RecoveryEpoch::from_bytes([41; 16]),
                digest(42),
                digest(43),
                digest(44),
                digest(45),
            )
            .encode()?
        } else {
            domain_body(table, kind, vec![7, 8, 9])?
        };
        let value = PersistentRecordValue::new(table, kind, 1, 1, None, vec![reference], body)?;
        let encoded = value.encode()?;
        validate_record_plaintext(table, &key, 1, &encoded)?;
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(validate_record_plaintext(table, &key, 1, &trailing).is_err());
        for length in 0..encoded.len() {
            let prefix = encoded.get(..length).ok_or("missing record prefix")?;
            assert!(validate_record_plaintext(table, &key, 1, prefix).is_err());
        }
    }
    Ok(())
}

#[test]
fn later_protocol_bodies_are_profile_table_and_arm_bound() -> Result<(), Box<dyn Error>> {
    let body = ProtocolRecordBody::new(TableId::FederationPeer, 1, 1, vec![7, 8, 9])?;
    let encoded = body.encode()?;
    let decoded = ProtocolRecordBody::decode(TableId::FederationPeer, 1, &encoded)?;
    assert_eq!(decoded.table(), TableId::FederationPeer);
    assert_eq!(decoded.record_kind(), 1);
    assert_eq!(decoded.profile_version(), 1);
    assert_eq!(decoded.canonical_object(), [7, 8, 9]);

    assert!(ProtocolRecordBody::new(TableId::Account, 1, 1, vec![1]).is_err());
    assert!(ProtocolRecordBody::new(TableId::FederationPeer, 1, 2, vec![1]).is_err());
    assert!(ProtocolRecordBody::new(TableId::FederationPeer, 1, 1, Vec::new()).is_err());
    assert!(ProtocolRecordBody::decode(TableId::FederationOrigin, 1, &encoded).is_err());
    assert!(ProtocolRecordBody::decode(TableId::FederationPeer, 2, &encoded).is_err());

    let mut unsupported_version = encoded.clone();
    unsupported_version
        .get_mut(..2)
        .ok_or("missing protocol body version")?
        .copy_from_slice(&2_u16.to_be_bytes());
    assert!(ProtocolRecordBody::decode(TableId::FederationPeer, 1, &unsupported_version).is_err());
    let mut trailing = encoded;
    trailing.push(0);
    assert!(ProtocolRecordBody::decode(TableId::FederationPeer, 1, &trailing).is_err());

    let maximum_e2ee = ProtocolRecordBody::new(TableId::E2eeObject, 1, 1, vec![1; 4_194_304])?;
    assert_eq!(maximum_e2ee.canonical_object().len(), 4_194_304);
    assert!(ProtocolRecordBody::new(TableId::E2eeObject, 1, 1, vec![1; 4_194_305]).is_err());
    Ok(())
}

#[test]
fn persistent_record_schema_rejects_every_key_kind_and_counter_mismatch()
-> Result<(), Box<dyn Error>> {
    for schema in table_schemas()? {
        match schema.key_shape() {
            StoredKeyShape::Fixed(expected) => {
                schema.validate_key(expected)?;
                let mut changed = expected.to_vec();
                changed.push(0);
                assert!(schema.validate_key(&changed).is_err());
            }
            StoredKeyShape::Exact(length) => {
                let valid = if schema.table() == TableId::Account {
                    account_key_bytes(1)
                } else {
                    vec![1; length]
                };
                schema.validate_key(&valid)?;
                assert!(
                    schema
                        .validate_key(&vec![1; length.saturating_sub(1)])
                        .is_err()
                );
                assert!(schema.validate_key(&vec![1; length + 1]).is_err());
            }
            StoredKeyShape::Range { minimum, maximum } => {
                schema.validate_key(&vec![1; minimum])?;
                schema.validate_key(&vec![1; maximum])?;
                assert!(schema.validate_key(&vec![1; minimum - 1]).is_err());
                if maximum < agenc_ircd_storage::MAX_STORED_KEY_BYTES {
                    assert!(schema.validate_key(&vec![1; maximum + 1]).is_err());
                }
            }
            StoredKeyShape::AccountOrOpaqueFake => {
                schema.validate_key(&account_key_bytes(1))?;
                schema.validate_key(b"agenc-chat/opaque-fake-record/v1")?;
                assert!(schema.validate_key(&[1; 23]).is_err());
                assert!(schema.validate_key(&[1; 25]).is_err());
            }
        }
    }

    assert!(
        RecordReference::new(
            TableId::IntegrityManifest,
            StoredKey::new(1_u64.to_be_bytes().to_vec())?,
        )
        .is_err()
    );
    let account_reference =
        RecordReference::new(TableId::Account, StoredKey::new(account_key_bytes(1))?)?;
    assert!(
        PersistentRecordValue::new(
            TableId::Account,
            1,
            1,
            1,
            None,
            vec![account_reference.clone(), account_reference],
            crate::domain_records::live_body(TableId::Account, 1)?
        )
        .is_err()
    );

    for table in DOMAIN_TABLES {
        let generation = if matches!(
            table,
            TableId::Account | TableId::Session | TableId::EdgeProjection
        ) {
            1
        } else {
            0
        };
        let body = if table == TableId::E2eeState {
            E2eeRecoveryGate::new(
                digest(130),
                E2eeRecoveryKind::Normal,
                RecoveryEpoch::from_bytes([131; 16]),
                digest(132),
                digest(133),
                digest(134),
                digest(135),
            )
            .encode()?
        } else {
            domain_body(table, 1, vec![1])?
        };
        assert!(
            PersistentRecordValue::new(table, 0, 1, generation, None, Vec::new(), body.clone())
                .is_err()
        );
        assert!(
            PersistentRecordValue::new(
                table,
                u16::MAX,
                1,
                generation,
                None,
                Vec::new(),
                body.clone(),
            )
            .is_err()
        );
        assert!(
            PersistentRecordValue::new(table, 1, 1, generation, Some(0), Vec::new(), body.clone(),)
                .is_err()
        );
        assert!(
            PersistentRecordValue::new(table, 1, 0, generation, None, Vec::new(), body.clone())
                .is_err()
        );
        if matches!(
            table,
            TableId::Account | TableId::Session | TableId::EdgeProjection
        ) {
            assert!(
                PersistentRecordValue::new(table, 1, 1, 0, None, Vec::new(), body.clone()).is_err()
            );
        }
        assert!(
            validate_record_plaintext(table, &key_for(table)?, 2, &body).is_err(),
            "table {table:?} accepted schema two"
        );
    }

    for table in [
        TableId::Account,
        TableId::RegistrationInvite,
        TableId::Session,
        TableId::Channel,
    ] {
        let tombstone = PersistentRecordValue::new(table, 2, 0, 0, None, Vec::new(), vec![1])?;
        assert_eq!(
            PersistentRecordValue::decode(table, &tombstone.encode()?)?.revision(),
            0
        );
    }

    for state in [
        E2eeRecoveryKind::Normal,
        E2eeRecoveryKind::Pending,
        E2eeRecoveryKind::Conflict,
        E2eeRecoveryKind::Closed,
    ] {
        let gate = E2eeRecoveryGate::new(
            digest(140),
            state,
            RecoveryEpoch::from_bytes([141; 16]),
            digest(142),
            digest(143),
            digest(144),
            digest(145),
        );
        let encoded = gate.encode()?;
        assert_eq!(E2eeRecoveryGate::decode(&encoded)?.state(), state);
        let recovered = gate.recover(RecoveryEpoch::from_bytes([146; 16]), digest(147));
        if matches!(state, E2eeRecoveryKind::Normal | E2eeRecoveryKind::Pending) {
            assert_eq!(recovered.state(), E2eeRecoveryKind::Pending);
            assert_eq!(
                recovered.recovery_epoch(),
                RecoveryEpoch::from_bytes([146; 16])
            );
        } else {
            assert_eq!(recovered, gate);
        }
    }
    let mut bad_version = E2eeRecoveryGate::new(
        digest(150),
        E2eeRecoveryKind::Normal,
        RecoveryEpoch::from_bytes([151; 16]),
        digest(152),
        digest(153),
        digest(154),
        digest(155),
    )
    .encode()?;
    *bad_version.get_mut(1).ok_or("missing gate version byte")? = 2;
    assert!(E2eeRecoveryGate::decode(&bad_version).is_err());
    *bad_version.get_mut(1).ok_or("missing gate version byte")? = 1;
    bad_version
        .get_mut(34..36)
        .ok_or("missing gate state bytes")?
        .fill(0);
    assert!(E2eeRecoveryGate::decode(&bad_version).is_err());
    Ok(())
}

#[test]
fn signed_growth_report_is_exact_tuple_authority() -> Result<(), Box<dyn Error>> {
    let mut recorder = StorageGrowthRecorder::new();
    let measurement_directory = TestDirectory::create()?;
    let file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(measurement_directory.path().join("growth.bin"))?;
    let database = redb::Builder::new().create_file(file.try_clone()?)?;
    recorder.measure_required_corpus(&file, |name| {
        let mut transaction = database
            .begin_write()
            .map_err(|_| StorageError::DatabaseRejected)?;
        transaction
            .set_durability(redb::Durability::Immediate)
            .map_err(|_| StorageError::DatabaseRejected)?;
        transaction.set_two_phase_commit(true);
        {
            let definition: redb::TableDefinition<'static, &'static [u8], &'static [u8]> =
                redb::TableDefinition::new("qualification");
            let mut table = transaction
                .open_table(definition)
                .map_err(|_| StorageError::DatabaseRejected)?;
            let value_bytes = if name.contains("max") || name == "fragmented" {
                65_536
            } else {
                4_096
            };
            let value = vec![name.as_bytes().first().copied().unwrap_or(1); value_bytes];
            table
                .insert(name.as_bytes(), value.as_slice())
                .map_err(|_| StorageError::DatabaseRejected)?;
            if name.starts_with("delete") {
                table
                    .remove(name.as_bytes())
                    .map_err(|_| StorageError::DatabaseRejected)?;
            }
        }
        transaction
            .commit()
            .map_err(|_| StorageError::DatabaseRejected)
    })?;
    let (cases, maximum) = recorder.finish()?;
    assert_eq!(cases.len(), QUALIFICATION_CASES.len());
    let key = Ed25519SecretKey::from_bytes([61; 32]);
    let report = StorageQualificationReport::sign(
        StorageQualificationReportTbs {
            target: QualificationTarget::X86_64UnknownLinuxGnu,
            filesystem_type: 0xef53,
            block_size: 4_096,
            mount_flags: 1,
            kernel_release: "6.16.0-agenc".to_owned(),
            redb_features_hash: digest(1),
            release_profile_hash: digest(2),
            corpus_hash: digest(3),
            cases,
            maximum_observed_growth: maximum,
            raw_log_hash: digest(4),
        },
        &key,
    )?;
    let encoded = report.encode()?;
    let verified = StorageQualificationReport::decode_and_verify(&encoded, key.public_key())?;
    let tuple = agenc_ircd_storage::FilesystemTuple {
        target: "x86_64-unknown-linux-gnu",
        filesystem_type: 0xef53,
        block_size: 4_096,
        mount_flags: 1,
    };
    let qualification = verified.qualification_for(tuple)?;
    assert_eq!(qualification.tuple(), tuple);
    assert_eq!(qualification.maximum_observed_growth(), maximum);

    let mut tampered = encoded;
    let last = tampered.len().checked_sub(1).ok_or("empty report")?;
    *tampered.get_mut(last).ok_or("missing signature")? ^= 1;
    assert!(StorageQualificationReport::decode_and_verify(&tampered, key.public_key()).is_err());
    Ok(())
}

#[test]
fn checked_in_native_qualification_reports_are_signed_and_complete() -> Result<(), Box<dyn Error>> {
    const PUBLIC_KEY_BYTES: &[u8; 32] = include_bytes!(
        "../../../conformance/evidence/storage-qualification/release-public-key.bin"
    );
    const ARTIFACTS: [(&str, &[u8], &[u8], QualificationTarget); 2] = [
        (
            "aarch64",
            include_bytes!(
                "../../../conformance/evidence/storage-qualification/aarch64-unknown-linux-gnu-ext4.report"
            ),
            include_bytes!(
                "../../../conformance/evidence/storage-qualification/aarch64-unknown-linux-gnu-ext4.log"
            ),
            QualificationTarget::Aarch64UnknownLinuxGnu,
        ),
        (
            "x86_64",
            include_bytes!(
                "../../../conformance/evidence/storage-qualification/x86_64-unknown-linux-gnu-ext4.report"
            ),
            include_bytes!(
                "../../../conformance/evidence/storage-qualification/x86_64-unknown-linux-gnu-ext4.log"
            ),
            QualificationTarget::X86_64UnknownLinuxGnu,
        ),
    ];
    let public_key = Ed25519PublicKey::from_bytes(*PUBLIC_KEY_BYTES)?;
    for (label, encoded, raw_log, expected_target) in ARTIFACTS {
        let report = StorageQualificationReport::decode_and_verify(encoded, public_key)
            .map_err(|error| format!("{label} report verification failed: {error}"))?;
        assert_eq!(report.tbs().target, expected_target);
        assert_eq!(report.tbs().cases.len(), QUALIFICATION_CASES.len());
        assert_eq!(
            report.tbs().raw_log_hash,
            storage_qualification_component_hash(b"raw-log", raw_log)?
        );
        assert!(
            report.tbs().maximum_observed_growth
                <= agenc_ircd_storage::MAX_QUALIFIED_OBSERVED_GROWTH
        );
    }
    Ok(())
}

#[test]
fn startup_reconstructs_every_domain_table_and_reference_kind() -> Result<(), Box<dyn Error>> {
    let initial = comprehensive_initial_state()?;
    let expected_rows = initial.rows.clone();
    let fixture = initialized_live_fixture_from(initial.records)?;
    let owner = StorageOwner::start(live_open_config(StateDirectory::open(
        fixture.directory.path(),
        &[fixture.qualification],
    )?))?;
    let recovered = owner.recovered_state();
    for table in DOMAIN_TABLES {
        assert_eq!(recovered.table_record_count(table), 1, "{table:?}");
    }
    assert_eq!(recovered.table_record_count(TableId::LoginIndex), 1);
    assert_eq!(recovered.maximum_record_revision(), 23);

    let port = owner.port();
    for (table, key) in &expected_rows {
        let exact = port
            .try_read(ReadPlan::exact(
                *table,
                StoredKey::new(key.as_bytes().to_vec())?,
            ))?
            .wait()?;
        assert_eq!(exact.records.len(), 1, "exact {table:?}");
        let range = port
            .try_read(ReadPlan::range(
                *table,
                StoredKey::new(vec![0])?,
                StoredKey::new(vec![u8::MAX; agenc_ircd_storage::MAX_STORED_KEY_BYTES])?,
                2,
            )?)?
            .wait()?;
        assert_eq!(range.records.len(), 1, "range {table:?}");
    }

    let backup_directory = TestDirectory::create()?;
    let backup_name = "complete-domain-state.agenc";
    let signing_key = Ed25519SecretKey::from_bytes([210; 32]);
    let public_key = signing_key.public_key();
    let receipt = port
        .try_backup(
            BackupDestination::new(backup_directory.path(), backup_name)?,
            signing_key,
            1_000,
            [211; 16],
        )?
        .wait()?;
    assert_eq!(receipt.record_count, 24);
    owner.shutdown()?;

    let backup_file = fs::File::open(backup_directory.path().join(backup_name))?;
    let verified = verify_backup(
        backup_file,
        &StorageMasterKey::from_bytes([207; 32]),
        &RollbackGuardRootKey::from_bytes([208; 32]),
        &[BackupTrustKey::new(public_key)?],
        test_limits().backup_max_bytes,
    )
    .map_err(|error| format!("complete-domain backup verification failed: {error}"))?;
    assert_eq!(verified.trailer.record_count, receipt.record_count);
    assert_eq!(verified.stream_bytes, receipt.stream_bytes);

    let source = ConstructionSourceDatabase::open(live_open_config(StateDirectory::open(
        fixture.directory.path(),
        &[fixture.qualification],
    )?))
    .map_err(|error| format!("complete-domain construction source failed: {error}"))?;
    assert_eq!(source.rekey_entry_count()?, 21);
    let plan_directory = TestDirectory::create()?;
    let plan_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(plan_directory.path().join("complete-rekey-plan.redb"))?;
    let plan = source
        .rebuild_rekey_plan(
            plan_file,
            &StorageMasterKey::from_bytes([212; 32]),
            DatabaseBinding::new(
                NetworkId::from_bytes([201; 32]),
                ServerId::from_bytes([202; 16]),
                ServerIncarnation::from_bytes([213; 16]),
                DatabaseId::from_bytes([214; 16]),
            ),
            1,
            construction_limits(),
        )
        .map_err(|error| format!("complete-domain rekey plan failed: {error}"))?;
    assert_eq!(plan.entry_count(), 21);
    Ok(())
}

#[test]
fn platform_adapter_rejects_each_path_lock_guard_and_capacity_boundary()
-> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create()?;
    let tuple = StateDirectory::probe(directory.path())?;
    let qualification = signed_qualification(tuple)?;

    for name in ["", ".", "..", "/absolute", "nested/name"] {
        assert_eq!(
            agenc_ircd_storage::BackupDestination::new(directory.path(), name).err(),
            Some(StorageError::FilesystemRejected),
            "unsafe backup name {name:?} was not rejected as a filesystem policy violation"
        );
    }
    let safe_destination =
        agenc_ircd_storage::BackupDestination::new(directory.path(), "backup.agenc")?;
    drop(safe_destination);

    assert!(StateDirectory::open(directory.path(), &[]).is_err());
    let state = StateDirectory::open(directory.path(), &[qualification])?;
    assert_eq!(state.tuple(), tuple);
    let capacity = state.capacity(0, 0)?;
    assert!(capacity.available_bytes > 0);
    assert_eq!(capacity.reserve_bytes, 0);
    assert_eq!(state.capacity(0, 101), Err(StorageError::LimitExceeded));
    assert_eq!(
        state.admit_transaction(u64::MAX, 0),
        Err(StorageError::Overflow)
    );
    assert_eq!(
        StateDirectory::open(directory.path(), &[qualification]).err(),
        Some(StorageError::WriterLocked)
    );

    assert!(state.open_database_file().is_err());
    let database = state.create_database_file()?;
    assert_eq!(database.metadata()?.permissions().mode() & 0o777, 0o600);
    assert!(state.create_database_file().is_err());
    drop(database);
    drop(state.open_database_file()?);

    assert!(state.read_guard(1).is_err());
    state.replace_guard(b"authenticated-guard")?;
    assert_eq!(state.read_guard(19)?, b"authenticated-guard");
    assert_eq!(state.read_guard(18), Err(StorageError::InvalidEncoding));
    drop(state);

    let invalid_temporary = directory
        .path()
        .join(".agenc-recovery-scratch-v1-not-a-random-name");
    fs::write(&invalid_temporary, [])?;
    fs::set_permissions(&invalid_temporary, fs::Permissions::from_mode(0o600))?;
    assert_eq!(
        StateDirectory::open(directory.path(), &[qualification]).err(),
        Some(StorageError::FilesystemRejected)
    );
    fs::remove_file(invalid_temporary)?;

    let valid_temporary = directory
        .path()
        .join(".agenc-recovery-scratch-v1-0123456789abcdef0123456789abcdef");
    fs::write(&valid_temporary, [])?;
    fs::set_permissions(&valid_temporary, fs::Permissions::from_mode(0o600))?;
    let reopened = StateDirectory::open(directory.path(), &[qualification])?;
    assert!(!valid_temporary.exists());
    drop(reopened);

    let wrong_mode = TestDirectory::create()?;
    fs::set_permissions(wrong_mode.path(), fs::Permissions::from_mode(0o755))?;
    assert_eq!(
        StateDirectory::probe(wrong_mode.path()),
        Err(StorageError::FilesystemRejected)
    );

    let symlink_parent = TestDirectory::create()?;
    let symlink_path = symlink_parent.path().join("state-link");
    std::os::unix::fs::symlink(directory.path(), &symlink_path)?;
    assert!(StateDirectory::probe(&symlink_path).is_err());
    Ok(())
}

#[test]
fn transaction_capacity_admission_observes_minus_equal_and_plus_one_boundaries()
-> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create()?;
    let tuple = StateDirectory::probe(directory.path())?;
    let qualification = signed_qualification(tuple)?;
    let state = StateDirectory::open(directory.path(), &[qualification])?;
    let growth = agenc_ircd_storage::MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH;
    observe_capacity_boundary(&state, growth, 1, false)?;
    observe_capacity_boundary(&state, growth, 0, true)?;
    observe_capacity_boundary(&state, growth, -1, true)?;
    Ok(())
}

fn observe_capacity_boundary(
    state: &StateDirectory,
    growth: u64,
    reserve_delta: i8,
    expected_admitted: bool,
) -> Result<(), Box<dyn Error>> {
    // Other tests share this filesystem, so free space can move between the two
    // probes below. Retry with a bounded backoff instead of spinning on yield_now.
    let mut backoff = CAPACITY_RETRY_INITIAL_BACKOFF;
    for _ in 0..CAPACITY_RETRY_ATTEMPTS {
        let before = state.capacity(0, 0)?.available_bytes;
        let exact_reserve = before
            .checked_sub(growth)
            .ok_or("qualification filesystem is smaller than the fixed growth allowance")?;
        let reserve = match reserve_delta {
            -1 => exact_reserve
                .checked_sub(1)
                .ok_or("plus-one reserve underflow")?,
            0 => exact_reserve,
            1 => exact_reserve
                .checked_add(1)
                .ok_or("minus-one reserve overflow")?,
            _ => return Err("unsupported capacity boundary delta".into()),
        };
        let result = state.admit_transaction(reserve, 0);
        let after = state.capacity(0, 0)?.available_bytes;
        if before != after {
            std::thread::sleep(backoff);
            backoff = (backoff * 2).min(CAPACITY_RETRY_MAX_BACKOFF);
            continue;
        }
        assert_eq!(result.is_ok(), expected_admitted);
        return Ok(());
    }
    Err("filesystem capacity did not stabilize for a boundary observation".into())
}

/// Capacity observations retry for roughly five seconds at most: 10 ms doubling to a
/// 100 ms ceiling over 48 attempts.
const CAPACITY_RETRY_ATTEMPTS: usize = 48;
const CAPACITY_RETRY_INITIAL_BACKOFF: std::time::Duration = std::time::Duration::from_millis(10);
const CAPACITY_RETRY_MAX_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

#[test]
fn qualification_rejects_every_report_and_measurement_boundary() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        QualificationTarget::Aarch64UnknownLinuxGnu.as_str(),
        "aarch64-unknown-linux-gnu"
    );
    for name in ["", "UPPER", "has space", "has_underscore"] {
        assert!(StorageGrowthCase::new(name.to_owned(), 0, 0).is_err());
    }
    assert!(StorageGrowthCase::new("a".repeat(65), 0, 0).is_err());
    let reclaimed = StorageGrowthCase::new("reclaimed".to_owned(), 2, 1)?;
    assert_eq!(reclaimed.allocated_before(), 2);
    assert_eq!(reclaimed.allocated_after(), 1);
    assert_eq!(reclaimed.positive_delta(), 0);

    let valid_cases = || {
        let mut cases = QUALIFICATION_CASES
            .iter()
            .map(|name| StorageGrowthCase::new((*name).to_owned(), 10, 11))
            .collect::<Result<Vec<_>, StorageError>>()?;
        cases.sort_by(|left, right| left.name().cmp(right.name()));
        Ok::<_, StorageError>(cases)
    };
    let valid_tbs = || -> Result<StorageQualificationReportTbs, StorageError> {
        Ok(StorageQualificationReportTbs {
            target: QualificationTarget::X86_64UnknownLinuxGnu,
            filesystem_type: 0xef53,
            block_size: 4_096,
            mount_flags: 1,
            kernel_release: "6.16.0-agenc".to_owned(),
            redb_features_hash: digest(1),
            release_profile_hash: digest(2),
            corpus_hash: digest(3),
            cases: valid_cases()?,
            maximum_observed_growth: 1,
            raw_log_hash: digest(4),
        })
    };
    for invalid in [
        StorageQualificationReportTbs {
            filesystem_type: 0,
            ..valid_tbs()?
        },
        StorageQualificationReportTbs {
            block_size: 0,
            ..valid_tbs()?
        },
        StorageQualificationReportTbs {
            block_size: 3,
            ..valid_tbs()?
        },
        StorageQualificationReportTbs {
            kernel_release: String::new(),
            ..valid_tbs()?
        },
        StorageQualificationReportTbs {
            kernel_release: "not graphic".to_owned(),
            ..valid_tbs()?
        },
        StorageQualificationReportTbs {
            kernel_release: "k".repeat(257),
            ..valid_tbs()?
        },
        StorageQualificationReportTbs {
            cases: Vec::new(),
            ..valid_tbs()?
        },
        StorageQualificationReportTbs {
            maximum_observed_growth: agenc_ircd_storage::MAX_QUALIFIED_OBSERVED_GROWTH + 1,
            ..valid_tbs()?
        },
        StorageQualificationReportTbs {
            maximum_observed_growth: 0,
            ..valid_tbs()?
        },
    ] {
        assert!(invalid.validate().is_err());
    }
    let mut missing = valid_cases()?;
    missing.pop();
    assert!(
        StorageQualificationReportTbs {
            cases: missing,
            ..valid_tbs()?
        }
        .validate()
        .is_err()
    );
    let mut out_of_order = valid_cases()?;
    out_of_order.swap(0, 1);
    assert!(
        StorageQualificationReportTbs {
            cases: out_of_order,
            ..valid_tbs()?
        }
        .validate()
        .is_err()
    );
    let mut duplicate = valid_cases()?;
    duplicate.push(StorageGrowthCase::new("btree-merge".to_owned(), 10, 11)?);
    assert!(
        StorageQualificationReportTbs {
            cases: duplicate,
            ..valid_tbs()?
        }
        .validate()
        .is_err()
    );

    assert!(StorageGrowthRecorder::new().finish().is_err());
    let mut recorder = StorageGrowthRecorder::new();
    let duplicate_case = StorageGrowthCase::new("duplicate".to_owned(), 0, 1)?;
    recorder.record(duplicate_case.clone())?;
    assert!(recorder.record(duplicate_case).is_err());
    assert!(
        StorageGrowthRecorder::new()
            .record(StorageGrowthCase::new(
                "too-large".to_owned(),
                0,
                agenc_ircd_storage::MAX_QUALIFIED_OBSERVED_GROWTH + 1,
            )?)
            .is_err()
    );
    let measurement_directory = TestDirectory::create()?;
    let first = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(measurement_directory.path().join("first-allocation.bin"))?;
    let second = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(measurement_directory.path().join("second-allocation.bin"))?;
    let mut set_recorder = StorageGrowthRecorder::new();
    assert!(
        set_recorder
            .measure_file_set("empty-set", &[], || Ok(()))
            .is_err()
    );
    set_recorder.measure_file_set("file-set", &[&first, &second], || {
        first
            .set_len(8_192)
            .map_err(|_| StorageError::FilesystemRejected)?;
        second
            .set_len(4_096)
            .map_err(|_| StorageError::FilesystemRejected)?;
        first
            .sync_all()
            .map_err(|_| StorageError::FilesystemRejected)?;
        second
            .sync_all()
            .map_err(|_| StorageError::FilesystemRejected)
    })?;
    let (measured_set, _) = set_recorder.finish()?;
    assert_eq!(
        measured_set
            .first()
            .ok_or("missing file-set measurement")?
            .name(),
        "file-set"
    );

    let release_key = Ed25519SecretKey::from_bytes([221; 32]);
    let report = StorageQualificationReport::sign(valid_tbs()?, &release_key)?;
    let encoded = report.encode()?;
    assert!(
        StorageQualificationReport::decode_and_verify(
            &encoded,
            Ed25519SecretKey::from_bytes([222; 32]).public_key(),
        )
        .is_err()
    );
    let verified =
        StorageQualificationReport::decode_and_verify(&encoded, release_key.public_key())?;
    for tuple in [
        agenc_ircd_storage::FilesystemTuple {
            target: "aarch64-unknown-linux-gnu",
            filesystem_type: 0xef53,
            block_size: 4_096,
            mount_flags: 1,
        },
        agenc_ircd_storage::FilesystemTuple {
            target: "x86_64-unknown-linux-gnu",
            filesystem_type: 1,
            block_size: 4_096,
            mount_flags: 1,
        },
        agenc_ircd_storage::FilesystemTuple {
            target: "x86_64-unknown-linux-gnu",
            filesystem_type: 0xef53,
            block_size: 8_192,
            mount_flags: 1,
        },
        agenc_ircd_storage::FilesystemTuple {
            target: "x86_64-unknown-linux-gnu",
            filesystem_type: 0xef53,
            block_size: 4_096,
            mount_flags: 2,
        },
    ] {
        assert!(verified.qualification_for(tuple).is_err());
    }

    for (offset, replacement) in [(4_usize, 0_u16), (6, 0), (6, 3)] {
        let mut changed = encoded.clone();
        changed
            .get_mut(offset..offset + 2)
            .ok_or("missing qualification discriminator")?
            .copy_from_slice(&replacement.to_be_bytes());
        resign_qualification_frame(&mut changed, &release_key)?;
        assert!(
            StorageQualificationReport::decode_and_verify(&changed, release_key.public_key())
                .is_err()
        );
    }
    let oversized = vec![0_u8; agenc_ircd_storage::MAX_QUALIFICATION_REPORT_BYTES + 1];
    assert!(
        StorageQualificationReport::decode_and_verify(&oversized, release_key.public_key())
            .is_err()
    );
    Ok(())
}

#[test]
fn qualification_rejects_oversized_case_sets_and_unsigned_frames() -> Result<(), Box<dyn Error>> {
    let case = StorageGrowthCase::new("case".to_owned(), 0, 1)?;
    let too_many_cases = vec![case.clone(); agenc_ircd_storage::MAX_QUALIFICATION_CASES + 1];
    let oversized_tbs = StorageQualificationReportTbs {
        target: QualificationTarget::X86_64UnknownLinuxGnu,
        filesystem_type: 0xef53,
        block_size: 4_096,
        mount_flags: 1,
        kernel_release: "6.16.0-agenc".to_owned(),
        redb_features_hash: digest(1),
        release_profile_hash: digest(2),
        corpus_hash: digest(3),
        cases: too_many_cases,
        maximum_observed_growth: 1,
        raw_log_hash: digest(4),
    };
    assert_eq!(oversized_tbs.validate(), Err(StorageError::InvalidEncoding));

    let mut cases = QUALIFICATION_CASES
        .iter()
        .map(|name| StorageGrowthCase::new((*name).to_owned(), 0, 1))
        .collect::<Result<Vec<_>, _>>()?;
    cases.sort_by(|left, right| left.name().cmp(right.name()));
    let valid = StorageQualificationReportTbs {
        target: QualificationTarget::X86_64UnknownLinuxGnu,
        filesystem_type: 0xef53,
        block_size: 4_096,
        mount_flags: 1,
        kernel_release: "6.16.0-agenc".to_owned(),
        redb_features_hash: digest(1),
        release_profile_hash: digest(2),
        corpus_hash: digest(3),
        cases,
        maximum_observed_growth: 1,
        raw_log_hash: digest(4),
    };
    let unsigned = valid.encode_unsigned()?;
    let count_offset = 128 + valid.kernel_release.len();
    for count in [
        0_u32,
        (agenc_ircd_storage::MAX_QUALIFICATION_CASES as u32) + 1,
    ] {
        let mut changed = unsigned.clone();
        changed
            .get_mut(count_offset..count_offset + 4)
            .ok_or("missing qualification case count")?
            .copy_from_slice(&count.to_be_bytes());
        assert!(StorageQualificationReportTbs::decode_unsigned(&changed).is_err());
    }
    assert!(
        StorageQualificationReportTbs::decode_unsigned(&vec![
            0;
            agenc_ircd_storage::MAX_QUALIFICATION_REPORT_BYTES
                + 1
        ])
        .is_err()
    );
    Ok(())
}

#[test]
fn qualification_required_file_set_measures_every_named_durable_case() -> Result<(), Box<dyn Error>>
{
    let directory = TestDirectory::create()?;
    let database = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(directory.path().join("qualification-database.bin"))?;
    let guard = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(directory.path().join("qualification-guard.bin"))?;
    let directory_file = OpenOptions::new().read(true).open(directory.path())?;
    let mut operation_database = database.try_clone()?;
    let operation_guard = guard.try_clone()?;
    let operation_directory = directory_file.try_clone()?;
    let mut recorder = StorageGrowthRecorder::new();
    recorder.measure_required_file_set(&[&database, &guard, &directory_file], |name| {
        operation_database
            .write_all(name.as_bytes())
            .map_err(|_| StorageError::FilesystemRejected)?;
        operation_database
            .sync_all()
            .map_err(|_| StorageError::FilesystemRejected)?;
        operation_guard
            .sync_all()
            .map_err(|_| StorageError::FilesystemRejected)?;
        operation_directory
            .sync_all()
            .map_err(|_| StorageError::FilesystemRejected)
    })?;
    let (cases, maximum) = recorder.finish()?;
    let mut expected = QUALIFICATION_CASES;
    expected.sort_unstable();
    assert_eq!(
        cases
            .iter()
            .map(StorageGrowthCase::name)
            .collect::<Vec<_>>(),
        expected
    );
    assert!(maximum <= agenc_ircd_storage::MAX_QUALIFIED_OBSERVED_GROWTH);
    Ok(())
}

fn resign_qualification_frame(
    encoded: &mut [u8],
    release_key: &Ed25519SecretKey,
) -> Result<(), Box<dyn Error>> {
    let length_bytes: [u8; 4] = encoded
        .get(..4)
        .ok_or("qualification frame is missing its length")?
        .try_into()?;
    let tbs_length = usize::try_from(u32::from_be_bytes(length_bytes))?;
    let tbs_end = 4_usize
        .checked_add(tbs_length)
        .ok_or("qualification length overflow")?;
    let tbs = encoded
        .get(4..tbs_end)
        .ok_or("qualification frame is truncated")?;
    let signature = sign_canonical(
        release_key,
        SignatureDomain::StorageQualificationReport,
        tbs,
    )?;
    encoded
        .get_mut(tbs_end..)
        .ok_or("qualification signature is missing")?
        .copy_from_slice(signature.as_bytes());
    Ok(())
}

#[test]
fn fault_campaign_covers_before_and_after_of_every_site() -> Result<(), Box<dyn Error>> {
    let cases = StorageFaultCase::all()?;
    assert_eq!(cases.len(), StorageFaultSite::all().len() * 2);
    for case in cases {
        let mut schedule = StorageFaultSchedule::new(case, 2)?;
        schedule.check(case.site, case.boundary)?;
        assert!(schedule.check(case.site, case.boundary).is_err());
        schedule.finish()?;
    }
    let mut schedule = StorageFaultSchedule::new(
        StorageFaultCase {
            site: StorageFaultSite::GuardRename,
            boundary: StorageFaultBoundary::After,
        },
        1,
    )?;
    schedule.check(StorageFaultSite::RecordRead, StorageFaultBoundary::After)?;
    assert!(schedule.finish().is_err());
    let before_effect = std::cell::Cell::new(false);
    let mut before = StorageFaultSchedule::new(
        StorageFaultCase {
            site: StorageFaultSite::RecordWrite,
            boundary: StorageFaultBoundary::Before,
        },
        1,
    )?;
    assert!(
        before
            .run(StorageFaultSite::RecordWrite, || {
                before_effect.set(true);
                Ok(())
            })
            .is_err()
    );
    assert!(!before_effect.get());
    before.finish()?;
    let after_effect = std::cell::Cell::new(false);
    let mut after = StorageFaultSchedule::new(
        StorageFaultCase {
            site: StorageFaultSite::RecordWrite,
            boundary: StorageFaultBoundary::After,
        },
        1,
    )?;
    assert!(
        after
            .run(StorageFaultSite::RecordWrite, || {
                after_effect.set(true);
                Ok(())
            })
            .is_err()
    );
    assert!(after_effect.get());
    after.finish()?;
    Ok(())
}

#[test]
fn storage_errors_and_fault_controllers_cover_the_closed_failure_surface()
-> Result<(), Box<dyn Error>> {
    let errors = [
        (StorageError::InvalidEncoding, "storage encoding is invalid"),
        (
            StorageError::UnsupportedVersion,
            "storage version is unsupported",
        ),
        (
            StorageError::LimitExceeded,
            "storage input exceeds its limit",
        ),
        (StorageError::Overflow, "storage arithmetic overflowed"),
        (
            StorageError::AllocationFailed,
            "bounded storage allocation failed",
        ),
        (
            StorageError::AuthenticationFailed,
            "storage authentication failed",
        ),
        (
            StorageError::StaleState,
            "storage state is stale or inconsistent",
        ),
        (StorageError::QueueFull, "storage queue is full"),
        (StorageError::Unavailable, "storage owner is unavailable"),
        (
            StorageError::FilesystemRejected,
            "filesystem policy rejected storage",
        ),
        (
            StorageError::WriterLocked,
            "storage writer is already locked",
        ),
        (
            StorageError::DatabaseRejected,
            "database rejected the operation",
        ),
        (
            StorageError::ResumeMismatch,
            "storage construction cannot be resumed",
        ),
    ];
    for (error, expected) in errors {
        assert_eq!(error.to_string(), expected);
    }

    let crypto_conversions = [
        (
            CryptoError::AuthenticationFailed,
            StorageError::AuthenticationFailed,
        ),
        (CryptoError::LimitExceeded, StorageError::LimitExceeded),
        (CryptoError::Overflow, StorageError::Overflow),
        (
            CryptoError::AllocationFailed,
            StorageError::AllocationFailed,
        ),
        (CryptoError::EntropyUnavailable, StorageError::Unavailable),
        (CryptoError::InvalidEncoding, StorageError::InvalidEncoding),
        (CryptoError::KindMismatch, StorageError::InvalidEncoding),
    ];
    for (source, expected) in crypto_conversions {
        assert_eq!(StorageError::from(source), expected);
    }

    let case = StorageFaultCase {
        site: StorageFaultSite::Manifest,
        boundary: StorageFaultBoundary::After,
    };
    assert!(StorageFaultSchedule::new(case, 0).is_err());
    let mut operation_error = StorageFaultSchedule::new(case, 1)?;
    assert_eq!(
        operation_error.run(StorageFaultSite::Manifest, || Err::<(), _>(
            StorageError::Overflow
        )),
        Err(StorageError::Overflow)
    );
    assert_eq!(operation_error.finish(), Err(StorageError::StaleState));

    let disabled = StorageFaultInjector::disabled();
    assert!(!disabled.is_enabled());
    disabled.check(StorageFaultSite::Manifest, StorageFaultBoundary::Before)?;
    assert_eq!(
        disabled.run(StorageFaultSite::Manifest, || Ok::<_, StorageError>(17))?,
        17
    );
    disabled.verify_fired()?;
    assert_eq!(
        disabled.arm_after_current(1),
        Err(StorageError::InvalidEncoding)
    );

    let armed = StorageFaultInjector::new(case, u64::MAX)?;
    assert!(armed.is_enabled());
    assert_eq!(
        armed.arm_after_current(0),
        Err(StorageError::InvalidEncoding)
    );
    armed.arm_after_current(1)?;
    assert_eq!(
        armed.check(StorageFaultSite::Manifest, StorageFaultBoundary::After),
        Err(StorageError::DatabaseRejected)
    );
    armed.verify_fired()?;
    assert_eq!(armed.arm_after_current(1), Err(StorageError::StaleState));
    assert_eq!(
        armed.check(StorageFaultSite::Manifest, StorageFaultBoundary::After),
        Ok(())
    );
    Ok(())
}

#[test]
fn fault_campaign_classifies_real_durable_file_effects() -> Result<(), Box<dyn Error>> {
    for case in StorageFaultCase::all()? {
        let directory = TestDirectory::create()?;
        let path = directory.path().join("fault-boundary.bin");
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)?;
        let mut schedule = StorageFaultSchedule::new(case, 1)?;
        let result = schedule.run(case.site, || {
            file.write_all(&(case.site as u16).to_be_bytes())
                .map_err(|_| StorageError::FilesystemRejected)?;
            file.sync_all()
                .map_err(|_| StorageError::FilesystemRejected)?;
            Ok(())
        });
        assert!(result.is_err());
        schedule.finish()?;
        drop(file);
        let bytes = fs::read(path)?;
        match case.boundary {
            StorageFaultBoundary::Before => assert!(bytes.is_empty()),
            StorageFaultBoundary::After => {
                assert_eq!(bytes, (case.site as u16).to_be_bytes())
            }
        }
    }
    Ok(())
}

#[test]
fn real_storage_initialization_injects_every_durable_boundary() -> Result<(), Box<dyn Error>> {
    for boundary in [StorageFaultBoundary::Before, StorageFaultBoundary::After] {
        let directory = TestDirectory::create()?;
        let tuple = StateDirectory::probe(directory.path())?;
        let qualification = signed_qualification(tuple)?;
        let faults = StorageFaultInjector::new(
            StorageFaultCase {
                site: StorageFaultSite::WriterLock,
                boundary,
            },
            1,
        )?;
        assert!(
            StateDirectory::open_with_faults(directory.path(), &[qualification], faults.clone(),)
                .is_err()
        );
        faults.verify_fired()?;
    }

    for site in [
        StorageFaultSite::CapacityAdmission,
        StorageFaultSite::Allocation,
        StorageFaultSite::RecordWrite,
        StorageFaultSite::TransactionBegin,
        StorageFaultSite::TransactionPhaseOne,
        StorageFaultSite::TransactionPhaseTwo,
        StorageFaultSite::DatabaseSync,
        StorageFaultSite::NonceDraw,
        StorageFaultSite::GuardTemporaryCreate,
        StorageFaultSite::GuardWrite,
        StorageFaultSite::GuardFileSync,
        StorageFaultSite::GuardRename,
        StorageFaultSite::GuardDirectorySync,
    ] {
        for boundary in [StorageFaultBoundary::Before, StorageFaultBoundary::After] {
            let faults = StorageFaultInjector::new(StorageFaultCase { site, boundary }, 1)?;
            let outcome = initialize_with_faults(faults.clone())?;
            assert!(
                !matches!(outcome, Ok(StorageInitializationOutcome::Complete { .. })),
                "fault {site:?} {boundary:?} reported certain completion"
            );
            faults.verify_fired()?;
        }
    }
    Ok(())
}

#[test]
fn every_commit_fault_reopens_to_exact_prior_or_successor_state() -> Result<(), Box<dyn Error>> {
    for site in [
        StorageFaultSite::CapacityAdmission,
        StorageFaultSite::Allocation,
        StorageFaultSite::RecordWrite,
        StorageFaultSite::TransactionBegin,
        StorageFaultSite::TransactionPhaseOne,
        StorageFaultSite::TransactionPhaseTwo,
        StorageFaultSite::DatabaseSync,
        StorageFaultSite::NonceDraw,
        StorageFaultSite::GuardTemporaryCreate,
        StorageFaultSite::GuardWrite,
        StorageFaultSite::GuardFileSync,
        StorageFaultSite::GuardRename,
        StorageFaultSite::GuardDirectorySync,
        StorageFaultSite::Manifest,
    ] {
        for boundary in [StorageFaultBoundary::Before, StorageFaultBoundary::After] {
            let fixture = initialized_live_fixture()?;
            let faults = StorageFaultInjector::new(StorageFaultCase { site, boundary }, u64::MAX)?;
            let state_directory = StateDirectory::open_with_faults(
                fixture.directory.path(),
                &[fixture.qualification],
                faults.clone(),
            )?;
            let owner = StorageOwner::start(live_open_config(state_directory))?;
            faults.arm_after_current(1)?;
            let outcome = owner
                .port()
                .try_commit(first_account_batch(
                    &fixture,
                    site == StorageFaultSite::Allocation,
                )?)?
                .wait()?;
            assert!(
                !matches!(outcome, CommitOutcome::Committed(_)),
                "fault {site:?} {boundary:?} reported certain success"
            );
            faults.verify_fired()?;
            owner.shutdown()?;

            let reopened = StorageOwner::start(live_open_config(StateDirectory::open(
                fixture.directory.path(),
                &[fixture.qualification],
            )?))?;
            let result = reopened
                .port()
                .try_read(ReadPlan::exact(
                    TableId::Account,
                    StoredKey::new(account_key_bytes(2))?,
                ))?
                .wait()?;
            match result.storage_commit_sequence {
                0 => assert!(result.records.is_empty()),
                1 => assert_eq!(result.records.len(), 1),
                sequence => return Err(format!("unexpected recovered commit {sequence}").into()),
            }
            reopened.shutdown()?;
        }
    }
    Ok(())
}

#[test]
fn every_checkpoint_fault_reopens_to_a_verified_commit_or_checkpoint() -> Result<(), Box<dyn Error>>
{
    for site in [
        StorageFaultSite::CheckpointScan,
        StorageFaultSite::CheckpointInstall,
        StorageFaultSite::CheckpointPrune,
    ] {
        for boundary in [StorageFaultBoundary::Before, StorageFaultBoundary::After] {
            let fixture = initialized_live_fixture()?;
            let faults = StorageFaultInjector::new(StorageFaultCase { site, boundary }, 1)?;
            let state_directory = StateDirectory::open_with_faults(
                fixture.directory.path(),
                &[fixture.qualification],
                faults.clone(),
            )?;
            let owner = StorageOwner::start(live_open_config(state_directory))?;
            let outcome = owner
                .port()
                .try_commit(first_account_batch(&fixture, false)?)?
                .wait()?;
            assert!(matches!(outcome, CommitOutcome::Committed(_)));
            assert!(owner.shutdown().is_err());
            faults.verify_fired()?;

            let reopened = StorageOwner::start(live_open_config(StateDirectory::open(
                fixture.directory.path(),
                &[fixture.qualification],
            )?))?;
            let result = reopened
                .port()
                .try_read(ReadPlan::exact(
                    TableId::Account,
                    StoredKey::new(account_key_bytes(2))?,
                ))?
                .wait()?;
            assert!(matches!(result.storage_commit_sequence, 1 | 2));
            assert_eq!(result.records.len(), 1);
            reopened.shutdown()?;
        }
    }
    Ok(())
}

fn first_account_batch(
    fixture: &InitializedLiveFixture,
    force_allocation: bool,
) -> Result<agenc_ircd_storage::StorageMutationBatch, StorageError> {
    // A live account body is bounded; the allocation probe uses an opaque authentication transaction.
    let (table, body) = if force_allocation {
        (TableId::AuthTransaction, vec![0; 8 * 1_024 * 1_024])
    } else {
        (
            TableId::Account,
            crate::domain_records::live_body(TableId::Account, 1)?,
        )
    };
    StorageMutationBatch::new(
        StorageMutationHead {
            transaction_id: TransactionId::from_bytes([239; 16]),
            expected_storage_commit_sequence: 0,
            expected_state_generation: 0,
            resulting_state_generation: 1,
            state_advancing_plan_count: 1,
            expected_account_service_response_count: 0,
            resulting_account_service_response_count: 0,
        },
        1,
        fixture.accounting(),
        vec![RecordMutation::put(
            table,
            StoredKey::new(if force_allocation {
                vec![2; 16]
            } else {
                account_key_bytes(2)
            })?,
            1,
            None,
            PersistentRecordValue::new(table, 1, 1, 1, None, Vec::new(), body)?.encode()?,
        )?],
    )
}

#[test]
fn real_startup_and_backup_inject_read_and_publication_boundaries() -> Result<(), Box<dyn Error>> {
    let fixture = initialized_live_fixture()?;
    for boundary in [StorageFaultBoundary::Before, StorageFaultBoundary::After] {
        let faults = StorageFaultInjector::new(
            StorageFaultCase {
                site: StorageFaultSite::RecordRead,
                boundary,
            },
            1,
        )?;
        let state_directory = StateDirectory::open_with_faults(
            fixture.directory.path(),
            &[fixture.qualification],
            faults.clone(),
        )?;
        assert!(StorageOwner::start(live_open_config(state_directory)).is_err());
        faults.verify_fired()?;
    }

    for site in [
        StorageFaultSite::BackupRecord,
        StorageFaultSite::BackupFileSync,
        StorageFaultSite::BackupRename,
        StorageFaultSite::BackupDirectorySync,
    ] {
        for boundary in [StorageFaultBoundary::Before, StorageFaultBoundary::After] {
            let faults = StorageFaultInjector::new(StorageFaultCase { site, boundary }, 1)?;
            let state_directory = StateDirectory::open_with_faults(
                fixture.directory.path(),
                &[fixture.qualification],
                faults.clone(),
            )?;
            let owner = StorageOwner::start(live_open_config(state_directory))?;
            let backup_directory = TestDirectory::create()?;
            let backup_name = format!("backup-{}-{boundary:?}.agenc", site as u16);
            let completion = owner.port().try_backup(
                agenc_ircd_storage::BackupDestination::new(backup_directory.path(), &backup_name)?,
                Ed25519SecretKey::from_bytes([209; 32]),
                1,
                [210; 16],
            )?;
            assert!(completion.wait().is_err());
            faults.verify_fired()?;
            // Whatever side of whichever boundary failed, the backup
            // directory holds neither the final name nor a temporary.
            assert_eq!(
                directory_names(backup_directory.path())?,
                Vec::<String>::new(),
                "{site:?} {boundary:?}"
            );
            // The same name publishes on the retry with the same producer,
            // and the artifact is the exact verified stream for that cut.
            let receipt = owner
                .port()
                .try_backup(
                    agenc_ircd_storage::BackupDestination::new(
                        backup_directory.path(),
                        &backup_name,
                    )?,
                    Ed25519SecretKey::from_bytes([209; 32]),
                    1,
                    [211; 16],
                )?
                .wait()?;
            assert_eq!(
                directory_names(backup_directory.path())?,
                vec![backup_name.clone()],
                "{site:?} {boundary:?}"
            );
            let bytes = fs::read(backup_directory.path().join(&backup_name))?;
            assert_eq!(u64::try_from(bytes.len())?, receipt.stream_bytes);
            let verified = agenc_ircd_storage::verify_backup(
                bytes.as_slice(),
                &StorageMasterKey::from_bytes([207; 32]),
                &RollbackGuardRootKey::from_bytes([208; 32]),
                &[agenc_ircd_storage::BackupTrustKey::new(
                    Ed25519SecretKey::from_bytes([209; 32]).public_key(),
                )?],
                receipt.stream_bytes,
            )?;
            assert_eq!(verified.trailer.stream_digest, receipt.stream_digest);
            assert_eq!(verified.trailer.record_count, receipt.record_count);
            owner.shutdown()?;
        }
    }
    Ok(())
}

fn directory_names(directory: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut names = fs::read_dir(directory)?
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    names.sort();
    Ok(names)
}

/// Audit regression (issue #48): a failure immediately after the no-replace
/// rename must not leave the final name occupied by an unverified artifact,
/// and the same-name retry must succeed. Before the repair this failed with
/// `final_exists=true` and a `FilesystemRejected` retry.
#[test]
fn audit_backup_rename_error_leaves_final_name_and_blocks_retry() -> Result<(), Box<dyn Error>> {
    let fixture = initialized_live_fixture()?;
    let faults = StorageFaultInjector::new(
        StorageFaultCase {
            site: StorageFaultSite::BackupRename,
            boundary: StorageFaultBoundary::After,
        },
        1,
    )?;
    let state = StateDirectory::open_with_faults(
        fixture.directory.path(),
        &[fixture.qualification],
        faults.clone(),
    )?;
    let owner = StorageOwner::start(live_open_config(state))?;
    let backups = TestDirectory::create()?;
    let name = "audit-backup.agenc";
    let result = owner
        .port()
        .try_backup(
            agenc_ircd_storage::BackupDestination::new(backups.path(), name)?,
            Ed25519SecretKey::from_bytes([209; 32]),
            1,
            [210; 16],
        )?
        .wait();
    assert!(result.is_err());
    faults.verify_fired()?;
    let final_exists = backups.path().join(name).exists();
    let retry = owner
        .port()
        .try_backup(
            agenc_ircd_storage::BackupDestination::new(backups.path(), name)?,
            Ed25519SecretKey::from_bytes([209; 32]),
            1,
            [211; 16],
        )?
        .wait();
    eprintln!("result={result:?} final_exists={final_exists} retry={retry:?}");
    owner.shutdown()?;
    assert!(
        !final_exists,
        "undifferentiated failure occupied the final name"
    );
    assert!(retry.is_ok(), "failed publication blocked same-name retry");
    Ok(())
}

#[test]
fn login_index_codecs_reject_each_short_circuit_boundary() -> Result<(), Box<dyn Error>> {
    let network_id = NetworkId::from_bytes([31; 32]);
    let previous_key = LoginIndexKey::from_bytes([32; 32]);
    let current_key = LoginIndexKey::from_bytes([33; 32]);
    let unrelated_key = LoginIndexKey::from_bytes([34; 32]);
    let login = NormalizedLogin::prepare("coverage-login")?;
    let stored =
        LoginIndexStoredKey::new(2, derive_login_index(&current_key, network_id, &login)?)?;

    let mut zero_generation_key = stored.encode()?.as_bytes().to_vec();
    zero_generation_key
        .get_mut(..4)
        .ok_or("missing login-index generation")?
        .fill(0);
    assert_eq!(
        LoginIndexStoredKey::decode(&zero_generation_key).map(|_| ()),
        Err(StorageError::InvalidEncoding)
    );

    let account_id = AccountRandomId::from_bytes([35; 16]).to_account_id();
    let live = LoginIndexValue::new(
        &stored,
        LoginIndexValueKind::Live {
            account_id,
            opaque_credential_id: OpaqueCredentialId::from_bytes([36; 32]),
        },
    )?;
    let live_bytes = live.encode()?;
    let mut unsupported_value = live_bytes.clone();
    unsupported_value
        .get_mut(..2)
        .ok_or("missing login-index value version")?
        .copy_from_slice(&2_u16.to_be_bytes());
    assert_eq!(
        LoginIndexValue::decode(&unsupported_value, &stored).map(|_| ()),
        Err(StorageError::UnsupportedVersion)
    );
    let mut wrong_digest = live_bytes;
    *wrong_digest
        .get_mut(6)
        .ok_or("missing login-index digest")? ^= 1;
    assert_eq!(
        LoginIndexValue::decode(&wrong_digest, &stored).map(|_| ()),
        Err(StorageError::AuthenticationFailed)
    );

    for kind in [
        LoginIndexValueKind::CreationReservation {
            transaction_id: TransactionId::from_bytes([37; 16]),
            expires_at: 1,
        },
        LoginIndexValueKind::DeletionTombstone {
            deleted_account_id: account_id,
            expires_at: 1,
        },
    ] {
        let mut encoded = LoginIndexValue::new(&stored, kind)?.encode()?;
        let expiry_offset = encoded.len().checked_sub(8).ok_or("missing expiry")?;
        encoded
            .get_mut(expiry_offset..)
            .ok_or("missing login-index expiry")?
            .fill(0);
        assert_eq!(
            LoginIndexValue::decode(&encoded, &stored).map(|_| ()),
            Err(StorageError::InvalidEncoding)
        );
    }

    let stable = LoginIndexKeyState::stable(1, previous_key.key_id(network_id))?;
    let stable_bytes = stable.encode()?;
    let mut unsupported_state = stable_bytes.clone();
    unsupported_state
        .get_mut(..2)
        .ok_or("missing login-index state version")?
        .copy_from_slice(&2_u16.to_be_bytes());
    assert_eq!(
        LoginIndexKeyState::decode(&unsupported_state),
        Err(StorageError::UnsupportedVersion)
    );

    let mut previous_generation_in_stable = stable_bytes.clone();
    previous_generation_in_stable
        .get_mut(40..44)
        .ok_or("missing previous generation")?
        .copy_from_slice(&1_u32.to_be_bytes());
    assert_eq!(
        LoginIndexKeyState::decode(&previous_generation_in_stable),
        Err(StorageError::InvalidEncoding)
    );
    let mut previous_key_in_stable = stable_bytes.clone();
    previous_key_in_stable
        .get_mut(44..48)
        .ok_or("missing previous key length")?
        .copy_from_slice(&1_u32.to_be_bytes());
    previous_key_in_stable.insert(48, 1);
    assert_eq!(
        LoginIndexKeyState::decode(&previous_key_in_stable),
        Err(StorageError::InvalidEncoding)
    );
    let mut previous_count_in_stable = stable_bytes;
    previous_count_in_stable
        .get_mut(48..56)
        .ok_or("missing previous record count")?
        .copy_from_slice(&1_u64.to_be_bytes());
    assert_eq!(
        LoginIndexKeyState::decode(&previous_count_in_stable),
        Err(StorageError::InvalidEncoding)
    );

    assert_eq!(
        LoginIndexKeyState::transition(
            0,
            previous_key.key_id(network_id),
            current_key.key_id(network_id),
            1,
        ),
        Err(StorageError::InvalidEncoding)
    );
    let transition = LoginIndexKeyState::transition(
        1,
        previous_key.key_id(network_id),
        current_key.key_id(network_id),
        1,
    )?;
    let mut short_previous_key = transition.encode()?;
    short_previous_key
        .get_mut(44..48)
        .ok_or("missing previous key length")?
        .copy_from_slice(&31_u32.to_be_bytes());
    short_previous_key.remove(79);
    assert_eq!(
        LoginIndexKeyState::decode(&short_previous_key),
        Err(StorageError::InvalidEncoding)
    );
    let mut wrong_current_generation = transition.encode()?;
    wrong_current_generation
        .get_mut(4..8)
        .ok_or("missing current generation")?
        .copy_from_slice(&3_u32.to_be_bytes());
    assert_eq!(
        LoginIndexKeyState::decode(&wrong_current_generation),
        Err(StorageError::InvalidEncoding)
    );
    assert_eq!(
        transition.validate_configured_keys(network_id, &current_key, Some(&unrelated_key)),
        Err(StorageError::AuthenticationFailed)
    );
    assert_eq!(
        transition.start_rotation(unrelated_key.key_id(network_id), 1),
        Err(StorageError::StaleState)
    );
    Ok(())
}

#[test]
fn real_login_transition_commits_inject_start_and_finish_boundaries() -> Result<(), Box<dyn Error>>
{
    for boundary in [StorageFaultBoundary::Before, StorageFaultBoundary::After] {
        let fixture = initialized_live_fixture()?;
        let faults = StorageFaultInjector::new(
            StorageFaultCase {
                site: StorageFaultSite::LoginIndexRotationStart,
                boundary,
            },
            1,
        )?;
        let state_directory = StateDirectory::open_with_faults(
            fixture.directory.path(),
            &[fixture.qualification],
            faults.clone(),
        )?;
        let owner = StorageOwner::start(live_open_config(state_directory))?;
        let port = owner.port();
        let key_state_record = read_key_state_record(&port)?;
        let stable = LoginIndexKeyState::stable(
            1,
            LoginIndexKey::from_bytes([203; 32]).key_id(NetworkId::from_bytes([201; 32])),
        )?;
        let batch = LoginIndexTransitionBatch::start(
            transition_head(0)?,
            fixture.accounting(),
            stable,
            LoginIndexKey::from_bytes([221; 32]).key_id(NetworkId::from_bytes([201; 32])),
            0,
            key_state_record,
            transition_audit(1)?,
        )?;
        let outcome = port.try_commit(batch)?.wait().map_err(|error| {
            std::io::Error::other(format!("start completion failed at {boundary:?}: {error}"))
        })?;
        assert!(!matches!(outcome, CommitOutcome::Committed(_)));
        faults.verify_fired()?;
        owner.shutdown().map_err(|error| {
            std::io::Error::other(format!("start shutdown failed at {boundary:?}: {error}"))
        })?;
    }

    for boundary in [StorageFaultBoundary::Before, StorageFaultBoundary::After] {
        let fixture = initialized_live_fixture()?;
        let faults = StorageFaultInjector::new(
            StorageFaultCase {
                site: StorageFaultSite::LoginIndexRotationFinish,
                boundary,
            },
            1,
        )?;
        let state_directory = StateDirectory::open_with_faults(
            fixture.directory.path(),
            &[fixture.qualification],
            faults.clone(),
        )?;
        let owner = StorageOwner::start(live_open_config(state_directory))?;
        let port = owner.port();
        let network = NetworkId::from_bytes([201; 32]);
        let previous_key = LoginIndexKey::from_bytes([203; 32]);
        let current_key = LoginIndexKey::from_bytes([221; 32]);
        let stable = LoginIndexKeyState::stable(1, previous_key.key_id(network))?;
        let start = LoginIndexTransitionBatch::start(
            transition_head(0)?,
            fixture.accounting(),
            stable,
            current_key.key_id(network),
            0,
            read_key_state_record(&port)?,
            transition_audit(1)?,
        )?;
        let start_logical_database_bytes = start.resulting_logical_database_bytes();
        let start_backup_stream_bytes = start.resulting_backup_stream_bytes();
        let start_outcome = port.try_commit(start)?.wait().map_err(|error| {
            std::io::Error::other(format!(
                "finish setup completion failed at {boundary:?}: {error}"
            ))
        })?;
        assert!(matches!(start_outcome, CommitOutcome::Committed(_)));
        let transition = stable.start_rotation(current_key.key_id(network), 0)?;
        let finish = LoginIndexTransitionBatch::finalize(
            transition_head(1)?,
            StorageAccountingLimits {
                current_logical_database_bytes: start_logical_database_bytes,
                current_backup_stream_bytes: start_backup_stream_bytes,
                database_max_bytes: test_limits().database_max_bytes,
                backup_max_bytes: test_limits().backup_max_bytes,
            },
            transition,
            read_key_state_record(&port)?,
            transition_audit(2)?,
        )?;
        let outcome = port.try_commit(finish)?.wait().map_err(|error| {
            std::io::Error::other(format!("finish completion failed at {boundary:?}: {error}"))
        })?;
        assert!(!matches!(outcome, CommitOutcome::Committed(_)));
        faults.verify_fired()?;
        owner.shutdown().map_err(|error| {
            std::io::Error::other(format!("finish shutdown failed at {boundary:?}: {error}"))
        })?;
    }
    Ok(())
}

#[test]
fn real_successful_login_batch_injects_lazy_migration_boundaries() -> Result<(), Box<dyn Error>> {
    for boundary in [StorageFaultBoundary::Before, StorageFaultBoundary::After] {
        let setup = initialized_lazy_login_fixture()?;
        let faults = StorageFaultInjector::new(
            StorageFaultCase {
                site: StorageFaultSite::LoginIndexLazyMigration,
                boundary,
            },
            1,
        )?;
        let state_directory = StateDirectory::open_with_faults(
            setup.fixture.directory.path(),
            &[setup.fixture.qualification],
            faults.clone(),
        )?;
        let owner = StorageOwner::start(live_open_config(state_directory))?;
        let port = owner.port();
        let network = NetworkId::from_bytes([201; 32]);
        let previous_key = LoginIndexKey::from_bytes([203; 32]);
        let current_key = LoginIndexKey::from_bytes([221; 32]);
        let stable = LoginIndexKeyState::stable(1, previous_key.key_id(network))?;
        let start = LoginIndexTransitionBatch::start(
            transition_head(0)?,
            setup.fixture.accounting(),
            stable,
            current_key.key_id(network),
            1,
            read_key_state_record(&port)?,
            transition_audit(1)?,
        )?;
        let start_logical_database_bytes = start.resulting_logical_database_bytes();
        let start_backup_stream_bytes = start.resulting_backup_stream_bytes();
        assert!(matches!(
            port.try_commit(start)?.wait()?,
            CommitOutcome::Committed(_)
        ));
        let transition = stable.start_rotation(current_key.key_id(network), 1)?;
        let migration = LoginIndexLazyMigration::new(
            network,
            &setup.login,
            transition,
            &current_key,
            &previous_key,
            setup.account_id,
            setup.credential_id,
            &setup.previous_value,
        )?;
        let previous_record = read_existing_record(
            &port,
            TableId::LoginIndex,
            StoredKey::new(setup.previous_key.as_bytes().to_vec())?,
        )?;
        let mutations = migration.into_mutations(previous_record, read_key_state_record(&port)?)?;
        let batch = agenc_ircd_storage::StorageMutationBatch::new_login_index_lazy(
            transition_head(1)?,
            1,
            StorageAccountingLimits {
                current_logical_database_bytes: start_logical_database_bytes,
                current_backup_stream_bytes: start_backup_stream_bytes,
                database_max_bytes: test_limits().database_max_bytes,
                backup_max_bytes: test_limits().backup_max_bytes,
            },
            Vec::from(mutations),
        )?;
        let outcome = port.try_commit(batch)?.wait()?;
        assert!(!matches!(outcome, CommitOutcome::Committed(_)));
        faults.verify_fired()?;
        owner.shutdown()?;
    }
    Ok(())
}

#[test]
fn login_lookup_and_lazy_migration_are_exactly_two_generation() -> Result<(), Box<dyn Error>> {
    let network = NetworkId::from_bytes([1; 32]);
    let login = NormalizedLogin::prepare("example-login")?;
    let old_key = LoginIndexKey::from_bytes([2; 32]);
    let new_key = LoginIndexKey::from_bytes([3; 32]);
    let stable = LoginIndexKeyState::stable(7, old_key.key_id(network))?;
    let stable_schedule = LoginIndexLookupSchedule::new(network, &login, stable, &old_key, None)?;
    assert!(!stable_schedule.is_transition());
    assert_ne!(
        stable_schedule.current().encode()?.as_bytes(),
        stable_schedule.previous_or_dummy().encode()?.as_bytes()
    );
    let stable_lookup =
        LoginIndexStoredKey::decode(stable_schedule.current().encode()?.as_bytes())?;
    let account = AccountRandomId::from_bytes([4; 16]).to_account_id();
    let credential = OpaqueCredentialId::from_bytes([5; 32]);
    let stable_value = LoginIndexValue::new(
        &stable_lookup,
        LoginIndexValueKind::Live {
            account_id: account,
            opaque_credential_id: OpaqueCredentialId::from_bytes([5; 32]),
        },
    )?;
    let mut preflight = LoginIndexTransitionPreflight::new(stable, new_key.key_id(network))?;
    preflight.observe(&stable_lookup, &stable_value)?;
    assert_eq!(preflight.finish()?.previous(), Some((7, 1)));
    let reservation = LoginIndexValue::new(
        &stable_lookup,
        LoginIndexValueKind::CreationReservation {
            transaction_id: agenc_ircd_types::TransactionId::from_bytes([6; 16]),
            expires_at: 1,
        },
    )?;
    let mut reservation_scan = LoginIndexTransitionPreflight::new(stable, new_key.key_id(network))?;
    assert!(
        reservation_scan
            .observe(&stable_lookup, &reservation)
            .is_err()
    );

    let transition = stable.start_rotation(new_key.key_id(network), 1)?;
    let transition_schedule =
        LoginIndexLookupSchedule::new(network, &login, transition, &new_key, Some(&old_key))?;
    assert!(transition_schedule.is_transition());
    let previous_lookup =
        LoginIndexStoredKey::decode(transition_schedule.previous_or_dummy().encode()?.as_bytes())?;
    let previous_value = LoginIndexValue::new(
        &previous_lookup,
        LoginIndexValueKind::Live {
            account_id: account,
            opaque_credential_id: OpaqueCredentialId::from_bytes([5; 32]),
        },
    )?;
    let migration = LoginIndexLazyMigration::new(
        network,
        &login,
        transition,
        &new_key,
        &old_key,
        account,
        credential,
        &previous_value,
    )?;
    assert_eq!(migration.resulting_key_state().previous(), Some((7, 0)));
    assert_eq!(migration.resulting_key_state().finish()?.previous(), None);
    Ok(())
}

#[test]
fn login_transition_start_and_finish_are_atomic_audited_batches() -> Result<(), Box<dyn Error>> {
    let network = NetworkId::from_bytes([101; 32]);
    let previous_key = LoginIndexKey::from_bytes([102; 32]);
    let current_key = LoginIndexKey::from_bytes([103; 32]);
    let stable = LoginIndexKeyState::stable(1, previous_key.key_id(network))?;
    let accounting = StorageAccountingLimits {
        current_logical_database_bytes: 10_000,
        current_backup_stream_bytes: 10_000,
        database_max_bytes: 1_073_741_824,
        backup_max_bytes: 1_073_741_824,
    };
    let start = LoginIndexTransitionBatch::start(
        transition_head(1)?,
        accounting,
        stable,
        current_key.key_id(network),
        0,
        ExistingRecord::new(1, digest(104), 100)?,
        transition_audit(1)?,
    )?;
    assert_eq!(start.plan_count(), 1);
    assert_eq!(start.state_advancing_plan_count(), 1);
    assert_eq!(start.mutations().len(), 2);

    let transition = stable.start_rotation(current_key.key_id(network), 0)?;
    let finish = LoginIndexTransitionBatch::finalize(
        transition_head(2)?,
        StorageAccountingLimits {
            current_logical_database_bytes: start.resulting_logical_database_bytes(),
            current_backup_stream_bytes: start.resulting_backup_stream_bytes(),
            ..accounting
        },
        transition,
        ExistingRecord::new(1, digest(105), 144)?,
        transition_audit(2)?,
    )?;
    assert_eq!(finish.plan_count(), 1);
    assert_eq!(finish.state_advancing_plan_count(), 1);
    assert_eq!(finish.mutations().len(), 2);
    Ok(())
}

fn transition_head(generation: u64) -> Result<StorageMutationHead, StorageError> {
    let transaction_byte = u8::try_from(generation).map_err(|_| StorageError::Overflow)?;
    Ok(StorageMutationHead {
        transaction_id: TransactionId::from_bytes([transaction_byte; 16]),
        expected_storage_commit_sequence: generation,
        expected_state_generation: generation,
        resulting_state_generation: generation + 1,
        state_advancing_plan_count: 1,
        expected_account_service_response_count: 0,
        resulting_account_service_response_count: 0,
    })
}

fn transition_audit(sequence: u64) -> Result<RecordMutation, StorageError> {
    RecordMutation::put(
        TableId::Audit,
        StoredKey::new(sequence.to_be_bytes().to_vec())?,
        1,
        None,
        PersistentRecordValue::new(
            TableId::Audit,
            1,
            sequence,
            0,
            None,
            Vec::new(),
            b"login-index-transition".to_vec(),
        )?
        .encode()?,
    )
}

#[test]
fn restore_transform_preserves_deleted_accounts_and_rejects_creation_reservations()
-> Result<(), Box<dyn Error>> {
    let tombstone =
        PersistentRecordValue::new(TableId::Account, 2, 0, 0, None, Vec::new(), vec![1, 2, 3])?;
    assert_eq!(
        recovery_transform_prefix(TableId::Account, &tombstone.encode()?)?,
        tombstone.encode()?
    );
    let channel = PersistentRecordValue::new(
        TableId::Channel,
        1,
        4,
        0,
        None,
        vec![
            RecordReference::new(TableId::Account, StoredKey::new(account_key_bytes(1))?)?,
            RecordReference::new(TableId::Session, StoredKey::new(vec![b's'; 16])?)?,
            RecordReference::new(TableId::RegistrationInvite, StoredKey::new(vec![b'i'; 16])?)?,
        ],
        crate::domain_records::live_body(TableId::Channel, 4)?,
    )?;
    let transformed_channel = PersistentRecordValue::decode(
        TableId::Channel,
        &recovery_transform_prefix(TableId::Channel, &channel.encode()?)?,
    )?;
    assert_eq!(transformed_channel.revision(), 5);
    assert_eq!(transformed_channel.references().len(), 1);
    assert_eq!(
        transformed_channel
            .references()
            .first()
            .ok_or("retained account role reference is missing")?
            .table(),
        TableId::Account
    );

    let network = NetworkId::from_bytes([70; 32]);
    let login_key = LoginIndexKey::from_bytes([71; 32]);
    let normalized = NormalizedLogin::prepare("restore-reservation")?;
    let index_key =
        LoginIndexStoredKey::new(1, derive_login_index(&login_key, network, &normalized)?)?;
    let stored_key = index_key.encode()?;
    let plaintext = LoginIndexValue::new(
        &index_key,
        LoginIndexValueKind::CreationReservation {
            transaction_id: agenc_ircd_types::TransactionId::from_bytes([72; 16]),
            expires_at: 73,
        },
    )?
    .encode()?;
    let master = StorageMasterKey::from_bytes([74; 32]);
    let binding = DatabaseBinding::new(
        network,
        ServerId::from_bytes([75; 16]),
        ServerIncarnation::from_bytes([76; 16]),
        DatabaseId::from_bytes([77; 16]),
    );
    let sealed = StorageSealContext::new(&master, binding, 1)?
        .seal(TableId::LoginIndex, 1, [78; 24], &stored_key, &plaintext)?
        .encode()?;
    let record_id = agenc_ircd_storage::SealedRecord::decode(&sealed)?.record_id()?;
    let source_reference = StorageConstructionSource::new(
        StorageConstructionSourceKind::BackupRecord,
        TableId::LoginIndex,
        StoredKey::new(stored_key.as_bytes().to_vec())?,
        1,
        record_id,
        1,
    )?;
    let entry = StorageConstructionPlanEntry::new(
        StorageConstructionKind::Restore,
        vec![source_reference],
        TableId::LoginIndex,
        StoredKey::new(stored_key.as_bytes().to_vec())?,
        1,
        StorageConstructionAction::RestoreCopy,
        0,
    )?;
    let source = ConstructionSourceRecord::open(
        entry.sources().first().ok_or("missing source")?,
        &sealed,
        &master,
        binding,
        1,
    )?;
    assert_eq!(
        ExactCopyTransformer.transform(StorageConstructionKind::Restore, &entry, &[source]),
        Err(StorageError::StaleState)
    );

    let live_account = PersistentRecordValue::new(
        TableId::Account,
        1,
        9,
        4,
        None,
        Vec::new(),
        crate::domain_records::live_body(TableId::Account, 4)?,
    )?;
    let transformed_account = PersistentRecordValue::decode(
        TableId::Account,
        &recovery_transform_prefix(TableId::Account, &live_account.encode()?)?,
    )?;
    assert_eq!(transformed_account.revision(), 10);
    assert_eq!(transformed_account.generation(), 5);

    recovery_provenance::verify_sealed_gate_pair(&master, binding)?;
    Ok(())
}

#[test]
fn restore_transform_covers_every_closed_action_and_source_mismatch() -> Result<(), Box<dyn Error>>
{
    let account_key = StoredKey::new(account_key_bytes(1))?;
    let live_account = PersistentRecordValue::new(
        TableId::Account,
        1,
        7,
        9,
        None,
        Vec::new(),
        crate::domain_records::live_body(TableId::Account, 1)?,
    )?
    .encode()?;
    let (account_reference, account_source) =
        opened_domain_source(TableId::Account, account_key, live_account, 230)?;
    let account_entry = StorageConstructionPlanEntry::new(
        StorageConstructionKind::Restore,
        vec![account_reference],
        TableId::Account,
        StoredKey::new(account_key_bytes(1))?,
        1,
        StorageConstructionAction::RestoreAccount,
        0,
    )?;
    let mut recovery = RecoveryTransformV1::new(RecoveryEpoch::from_bytes([231; 16]), digest(232));
    assert!(
        recovery
            .transform(
                StorageConstructionKind::Restore,
                &account_entry,
                &[account_source],
            )
            .is_ok()
    );
    assert_eq!(
        recovery.transform(StorageConstructionKind::Rekey, &account_entry, &[]),
        Err(StorageError::InvalidEncoding)
    );
    assert_eq!(
        recovery.transform(StorageConstructionKind::Restore, &account_entry, &[]),
        Err(StorageError::StaleState)
    );

    let invitation_key = StoredKey::new(vec![1; 16])?;
    let redeemed_invitation = PersistentRecordValue::new(
        TableId::RegistrationInvite,
        2,
        0,
        0,
        None,
        Vec::new(),
        vec![2],
    )?
    .encode()?;
    let (invitation_reference, invitation_source) = opened_domain_source(
        TableId::RegistrationInvite,
        invitation_key,
        redeemed_invitation,
        233,
    )?;
    let invitation_entry = StorageConstructionPlanEntry::new(
        StorageConstructionKind::Restore,
        vec![invitation_reference],
        TableId::RegistrationInvite,
        StoredKey::new(vec![1; 16])?,
        1,
        StorageConstructionAction::RestoreCopy,
        0,
    )?;
    assert!(
        ExactCopyTransformer
            .transform(
                StorageConstructionKind::Restore,
                &invitation_entry,
                &[invitation_source],
            )
            .is_ok()
    );
    assert_eq!(
        ExactCopyTransformer.transform(StorageConstructionKind::Restore, &invitation_entry, &[]),
        Err(StorageError::StaleState)
    );

    let active_invitation = PersistentRecordValue::new(
        TableId::RegistrationInvite,
        1,
        1,
        0,
        None,
        Vec::new(),
        vec![3],
    )?
    .encode()?;
    let (_, active_invitation_source) = opened_domain_source(
        TableId::RegistrationInvite,
        StoredKey::new(vec![2; 16])?,
        active_invitation,
        234,
    )?;
    assert_eq!(
        ExactCopyTransformer.transform(
            StorageConstructionKind::Restore,
            &invitation_entry,
            &[active_invitation_source],
        ),
        Err(StorageError::StaleState)
    );

    let channel_key = StoredKey::new(vec![4; 16])?;
    let channel_plaintext = PersistentRecordValue::new(
        TableId::Channel,
        1,
        10,
        0,
        None,
        Vec::new(),
        crate::domain_records::live_body(TableId::Channel, 4)?,
    )?
    .encode()?;
    let (channel_reference, channel_source) =
        opened_domain_source(TableId::Channel, channel_key, channel_plaintext, 235)?;
    let name_plaintext = PersistentRecordValue::new(
        TableId::ChannelName,
        1,
        8,
        0,
        None,
        vec![RecordReference::new(
            TableId::Channel,
            StoredKey::new(vec![4; 16])?,
        )?],
        crate::domain_records::channel_name_body(4, "#fixture")?,
    )?
    .encode()?;
    let (name_reference, name_source) = opened_domain_source(
        TableId::ChannelName,
        StoredKey::new(vec![5; 32])?,
        name_plaintext,
        236,
    )?;
    let name_entry = StorageConstructionPlanEntry::new(
        StorageConstructionKind::Restore,
        vec![name_reference, channel_reference],
        TableId::ChannelName,
        StoredKey::new(vec![5; 32])?,
        1,
        StorageConstructionAction::RestoreChannelName,
        0,
    )?;
    let transformed_name = recovery.transform(
        StorageConstructionKind::Restore,
        &name_entry,
        &[name_source, channel_source],
    )?;
    assert_eq!(
        PersistentRecordValue::decode(TableId::ChannelName, &transformed_name)?.revision(),
        11
    );
    assert_eq!(
        recovery.transform(StorageConstructionKind::Restore, &name_entry, &[]),
        Err(StorageError::StaleState)
    );

    let peer_plaintext = PersistentRecordValue::new(
        TableId::FederationPeer,
        2,
        12,
        0,
        None,
        Vec::new(),
        domain_body(TableId::FederationPeer, 2, vec![6])?,
    )?
    .encode()?;
    let (peer_reference, peer_source) = opened_domain_source(
        TableId::FederationPeer,
        StoredKey::new(vec![6; 16])?,
        peer_plaintext,
        237,
    )?;
    let peer_entry = StorageConstructionPlanEntry::new(
        StorageConstructionKind::Restore,
        vec![peer_reference],
        TableId::FederationPeer,
        StoredKey::new(vec![6; 16])?,
        1,
        StorageConstructionAction::RestorePeerTombstones,
        0,
    )?;
    assert!(
        recovery
            .transform(
                StorageConstructionKind::Restore,
                &peer_entry,
                &[peer_source]
            )
            .is_ok()
    );

    let other_e2ee_key = agenc_ircd_storage::e2ee_records::KeySetRow::key()?;
    let other_e2ee_body = domain_body(TableId::E2eeState, 11, vec![7])?;
    let other_e2ee_plaintext = PersistentRecordValue::new(
        TableId::E2eeState,
        11,
        13,
        0,
        None,
        Vec::new(),
        other_e2ee_body.clone(),
    )?
    .encode()?;
    let (other_e2ee_reference, other_e2ee_source) = opened_domain_source(
        TableId::E2eeState,
        other_e2ee_key.clone(),
        other_e2ee_plaintext,
        238,
    )?;
    let other_e2ee_entry = StorageConstructionPlanEntry::new(
        StorageConstructionKind::Restore,
        vec![other_e2ee_reference],
        TableId::E2eeState,
        other_e2ee_key,
        1,
        StorageConstructionAction::RestoreE2eeState,
        0,
    )?;
    let restored_e2ee = recovery.transform(
        StorageConstructionKind::Restore,
        &other_e2ee_entry,
        &[other_e2ee_source],
    )?;
    assert_eq!(
        PersistentRecordValue::decode(TableId::E2eeState, &restored_e2ee)?.body(),
        other_e2ee_body.as_slice(),
    );

    let maximum_account_revision = PersistentRecordValue::new(
        TableId::Account,
        1,
        u64::MAX,
        1,
        None,
        Vec::new(),
        crate::domain_records::live_body(TableId::Account, 8)?,
    )?
    .encode()?;
    assert!(recovery_transform_prefix(TableId::Account, &maximum_account_revision).is_err());
    let maximum_account_generation = PersistentRecordValue::new(
        TableId::Account,
        1,
        1,
        u64::MAX,
        None,
        Vec::new(),
        crate::domain_records::live_body(TableId::Account, 9)?,
    )?
    .encode()?;
    assert!(recovery_transform_prefix(TableId::Account, &maximum_account_generation).is_err());
    let audit = PersistentRecordValue::new(TableId::Audit, 1, 1, 0, None, Vec::new(), vec![10])?
        .encode()?;
    assert!(recovery_transform_prefix(TableId::Audit, &audit).is_err());
    Ok(())
}

fn opened_domain_source(
    table: TableId,
    key: StoredKey,
    plaintext: Vec<u8>,
    nonce_byte: u8,
) -> Result<(StorageConstructionSource, ConstructionSourceRecord), StorageError> {
    let master = StorageMasterKey::from_bytes([240; 32]);
    let binding = DatabaseBinding::new(
        NetworkId::from_bytes([241; 32]),
        ServerId::from_bytes([242; 16]),
        ServerIncarnation::from_bytes([243; 16]),
        DatabaseId::from_bytes([244; 16]),
    );
    let sealed = StorageSealContext::new(&master, binding, 1)?
        .seal(table, 1, [nonce_byte; 24], &key, &plaintext)?
        .encode()?;
    let reference = StorageConstructionSource::new(
        StorageConstructionSourceKind::BackupRecord,
        table,
        key,
        1,
        SealedRecord::decode(&sealed)?.record_id()?,
        u64::from(nonce_byte),
    )?;
    let record = ConstructionSourceRecord::open(&reference, &sealed, &master, binding, 1)?;
    Ok((reference, record))
}

#[test]
fn disk_plan_orders_variable_keys_by_raw_bytes() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create()?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(directory.path().join("ordered-plan.redb"))?;
    let raw_first = StoredKey::new(
        std::iter::once(1_u8)
            .chain(std::iter::repeat_n(9_u8, 18))
            .collect(),
    )?;
    let length_first = StoredKey::new(
        std::iter::once(2_u8)
            .chain(std::iter::repeat_n(8_u8, 17))
            .collect(),
    )?;
    let login_state_key = StoredKey::new(agenc_ircd_storage::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?;
    let expected = vec![
        rekey_entry(TableId::Sanction, &raw_first, digest(1))?,
        rekey_entry(TableId::Sanction, &length_first, digest(2))?,
        rekey_login_state_entry(&login_state_key, digest(3))?,
    ];
    let expected_hash = construction_plan_hash(
        StorageConstructionKind::Rekey,
        &expected,
        agenc_ircd_storage::MAX_CONSTRUCTION_PLAN_BYTES,
    )?;
    let mut builder = ConstructionPlanBuilder::start_streaming(
        StorageConstructionKind::Rekey,
        file,
        construction_limits(),
    )?;
    builder.push(rekey_entry(TableId::Sanction, &length_first, digest(2))?)?;
    builder.push(rekey_login_state_entry(&login_state_key, digest(3))?)?;
    builder.push(rekey_entry(TableId::Sanction, &raw_first, digest(1))?)?;
    let plan = builder.finish()?;
    assert_eq!(plan.entry_count(), 3);
    assert_eq!(plan.hash(), expected_hash);
    Ok(())
}

#[test]
fn construction_directory_rejects_every_phase_and_plan_rebuild_mismatch()
-> Result<(), Box<dyn Error>> {
    assert!(ConstructionDirectory::open(Path::new("relative-output"), false).is_err());

    let missing_root = TestDirectory::create()?;
    let missing_output = missing_root.path().join("missing-output");
    assert!(ConstructionDirectory::open(&missing_output, true).is_err());

    let installed_root = TestDirectory::create()?;
    let installed_output = installed_root.path().join("installed-output");
    fs::create_dir(&installed_output)?;
    fs::set_permissions(&installed_output, fs::Permissions::from_mode(0o700))?;
    assert!(ConstructionDirectory::open(&installed_output, false).is_err());
    let installed = ConstructionDirectory::open(&installed_output, true)?;
    assert_eq!(installed.phase(), ConstructionDirectoryPhase::Installed);
    assert_eq!(installed.selected_path(), installed_output);
    assert_eq!(installed.output_path(), installed_output);
    assert!(installed.rebuild_plan_file().is_err());
    assert!(installed.remove_plan_file().is_err());

    let ambiguous_root = TestDirectory::create()?;
    let ambiguous_output = ambiguous_root.path().join("ambiguous-output");
    fs::create_dir(&ambiguous_output)?;
    fs::set_permissions(&ambiguous_output, fs::Permissions::from_mode(0o700))?;
    let ambiguous_staging = ambiguous_root
        .path()
        .join(".ambiguous-output.agenc-construction-v1");
    fs::create_dir(&ambiguous_staging)?;
    fs::set_permissions(&ambiguous_staging, fs::Permissions::from_mode(0o700))?;
    assert!(ConstructionDirectory::open(&ambiguous_output, true).is_err());

    let rebuild_root = TestDirectory::create()?;
    let rebuild_output = rebuild_root.path().join("rebuild-output");
    let rebuild = ConstructionDirectory::open(&rebuild_output, false)?;
    drop(rebuild.rebuild_plan_file()?);
    drop(rebuild.rebuild_plan_file()?);
    rebuild.remove_plan_file()?;
    assert!(rebuild.remove_plan_file().is_err());

    for boundary in [StorageFaultBoundary::Before, StorageFaultBoundary::After] {
        let root = TestDirectory::create()?;
        let output = root.path().join(format!("fault-{boundary:?}"));
        let faults = StorageFaultInjector::new(
            StorageFaultCase {
                site: StorageFaultSite::ConstructionPlanRebuild,
                boundary,
            },
            1,
        )?;
        let directory = ConstructionDirectory::open_with_faults(&output, false, faults.clone())?;
        assert!(directory.rebuild_plan_file().is_err());
        faults.verify_fired()?;
    }
    Ok(())
}

#[test]
fn reconstructed_source_rebuilds_rekey_plan_and_enforces_key_generation()
-> Result<(), Box<dyn Error>> {
    let root = TestDirectory::create()?;
    let source_path = root.path().join("source-state");
    fs::create_dir(&source_path)?;
    fs::set_permissions(&source_path, fs::Permissions::from_mode(0o700))?;
    let network = NetworkId::from_bytes([70; 32]);
    let server = ServerId::from_bytes([71; 16]);
    let incarnation = ServerIncarnation::from_bytes([72; 16]);
    let source_database = DatabaseId::from_bytes([73; 16]);
    let source_master_bytes = [74; 32];
    let source_guard_bytes = [75; 32];
    let login_key_bytes = [76; 32];
    let source_binding = DatabaseBinding::new(network, server, incarnation, source_database);
    let nickname_index = derive_storage_index(
        &StorageMasterKey::from_bytes(source_master_bytes),
        source_binding,
        StorageTable::new(TableId::NicknameReservation.as_u16())?,
        1,
        b"nick-one",
    )?;
    let account_key = StoredKey::new(account_key_bytes(1))?;
    let nickname_key = StoredKey::new(nickname_index.expose_for_storage_key().to_vec())?;
    let login_key = LoginIndexKey::from_bytes(login_key_bytes);
    let login_state = LoginIndexKeyState::stable(1, login_key.key_id(network))?;
    let initial_records = vec![
        InitialStorageRecord::new(
            TableId::Account,
            StoredKey::new(account_key.as_bytes().to_vec())?,
            1,
            PersistentRecordValue::new(
                TableId::Account,
                1,
                1,
                1,
                None,
                Vec::new(),
                crate::domain_records::live_body(TableId::Account, 1)?,
            )?
            .encode()?,
        )?,
        InitialStorageRecord::new(
            TableId::NicknameReservation,
            nickname_key,
            1,
            PersistentRecordValue::new(
                TableId::NicknameReservation,
                1,
                1,
                0,
                None,
                vec![RecordReference::new(
                    TableId::Account,
                    StoredKey::new(account_key.as_bytes().to_vec())?,
                )?],
                b"Nick-One".to_vec(),
            )?
            .encode()?,
        )?,
        InitialStorageRecord::new(
            TableId::LoginIndexKeyState,
            StoredKey::new(agenc_ircd_storage::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
            1,
            login_state.encode()?,
        )?,
    ];
    let limits = test_limits();
    let tuple = StateDirectory::probe(&source_path)?;
    let qualification = signed_qualification(tuple)?;
    let initialized = initialize_storage(StorageInitializationConfig {
        state_directory: StateDirectory::open(&source_path, &[qualification])?,
        header_tbs: agenc_ircd_storage::DatabaseHeaderTbs::new(
            network,
            server,
            incarnation,
            source_database,
            1,
            SCHEMA_GENERATION,
            RecoveryEpoch::from_bytes([77; 16]),
        )?,
        storage_master_key: StorageMasterKey::from_bytes(source_master_bytes),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes(source_guard_bytes),
        mode: StorageInitializationMode::Live,
        initial_records,
        account_service_response_count: 0,
        state_generation: 1,
        predecessor_guard_hash: digest(0),
        limits,
    })?;
    assert!(matches!(
        initialized,
        StorageInitializationOutcome::Complete { .. }
    ));
    let source = ConstructionSourceDatabase::open(StorageOpenConfig {
        expected_network_id: network,
        expected_server_id: server,
        state_directory: StateDirectory::open(&source_path, &[qualification])?,
        storage_master_key: StorageMasterKey::from_bytes(source_master_bytes),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes(source_guard_bytes),
        login_index_key: LoginIndexKey::from_bytes(login_key_bytes),
        previous_login_index_key: None,
        limits,
    })?;
    assert_eq!(source.rekey_entry_count()?, 3);
    let transition = source
        .login_index_transition_preflight(LoginIndexKey::from_bytes([99; 32]).key_id(network))?;
    assert_eq!(transition.current_generation(), 2);
    assert_eq!(transition.previous(), Some((1, 0)));

    let target_binding = DatabaseBinding::new(
        network,
        server,
        incarnation,
        DatabaseId::from_bytes([78; 16]),
    );
    let invalid_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(root.path().join("invalid-plan.redb"))?;
    assert!(matches!(
        source.rebuild_rekey_plan(
            invalid_file,
            &StorageMasterKey::from_bytes([79; 32]),
            target_binding,
            2,
            construction_limits(),
        ),
        Err(StorageError::InvalidEncoding)
    ));
    let new_key_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(root.path().join("new-key-plan.redb"))?;
    let new_key_plan = source.rebuild_rekey_plan(
        new_key_file,
        &StorageMasterKey::from_bytes([79; 32]),
        target_binding,
        1,
        construction_limits(),
    )?;
    assert_eq!(new_key_plan.entry_count(), 3);
    let same_key_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(root.path().join("same-key-plan.redb"))?;
    let same_key_plan = source.rebuild_rekey_plan(
        same_key_file,
        &StorageMasterKey::from_bytes(source_master_bytes),
        target_binding,
        2,
        construction_limits(),
    )?;
    assert_eq!(same_key_plan.entry_count(), 3);
    Ok(())
}

#[test]
fn rekey_construction_commits_finalizes_installs_and_reopens() -> Result<(), Box<dyn Error>> {
    let root = TestDirectory::create()?;
    let output = root.path().join("rekeyed-state");
    let directory = ConstructionDirectory::open(&output, false)?;
    let network = NetworkId::from_bytes([21; 32]);
    let server = ServerId::from_bytes([22; 16]);
    let target_database = DatabaseId::from_bytes([23; 16]);
    let login_key = LoginIndexKey::from_bytes([24; 32]);
    let login_state = LoginIndexKeyState::stable(1, login_key.key_id(network))?;
    let stored_key = StoredKey::new(agenc_ircd_storage::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?;
    let source_master_bytes = [25; 32];
    let target_master_bytes = [26; 32];
    let source_guard_bytes = [27; 32];
    let target_guard_bytes = [28; 32];
    assert!(
        !StorageMasterKey::from_bytes(source_master_bytes)
            .matches(&StorageMasterKey::from_bytes(target_master_bytes))
    );
    assert!(
        !RollbackGuardRootKey::from_bytes(source_guard_bytes)
            .matches(&RollbackGuardRootKey::from_bytes(target_guard_bytes))
    );
    let source_binding = DatabaseBinding::new(
        network,
        server,
        ServerIncarnation::from_bytes([29; 16]),
        DatabaseId::from_bytes([30; 16]),
    );
    let source_sealed = StorageSealContext::new(
        &StorageMasterKey::from_bytes(source_master_bytes),
        source_binding,
        1,
    )?
    .seal(
        TableId::LoginIndexKeyState,
        1,
        [31; 24],
        &stored_key,
        &login_state.encode()?,
    )?
    .encode()?;
    let source_record_id = agenc_ircd_storage::SealedRecord::decode(&source_sealed)?.record_id()?;
    let account_key = StoredKey::new(account_key_bytes(1))?;
    let account_plaintext = PersistentRecordValue::new(
        TableId::Account,
        1,
        7,
        9,
        None,
        Vec::new(),
        crate::domain_records::live_body(TableId::Account, 41)?,
    )?
    .encode()?;
    let source_account_sealed = StorageSealContext::new(
        &StorageMasterKey::from_bytes(source_master_bytes),
        source_binding,
        1,
    )?
    .seal(
        TableId::Account,
        1,
        [32; 24],
        &account_key,
        &account_plaintext,
    )?
    .encode()?;
    let source_account_id =
        agenc_ircd_storage::SealedRecord::decode(&source_account_sealed)?.record_id()?;
    let account_entry_for_hash = rekey_entry(TableId::Account, &account_key, source_account_id)?;
    let login_entry_for_hash = rekey_login_state_entry(&stored_key, source_record_id)?;
    let plan_hash = construction_plan_hash(
        StorageConstructionKind::Rekey,
        &[account_entry_for_hash, login_entry_for_hash],
        agenc_ircd_storage::MAX_CONSTRUCTION_PLAN_BYTES,
    )?;
    let identity_template = StorageOperationIdentity {
        kind: StorageConstructionKind::Rekey,
        command_version: 1,
        source_database_header_hash: digest(32),
        target_database_header_hash: digest(0),
        source_rollback_guard_hash: digest(33),
        source_stream_digest: None,
        source_schema_generation: SCHEMA_GENERATION,
        target_schema_generation: SCHEMA_GENERATION,
        transform_profile_hash: rekey_transform_profile_hash()?,
        target_database_instance_id: target_database,
        source_master_key_id: StorageMasterKey::from_bytes(source_master_bytes)
            .source_operation_key_id()?,
        source_guard_root_key_id: RollbackGuardRootKey::from_bytes(source_guard_bytes)
            .source_operation_key_id()?,
        target_master_key_id: StorageMasterKey::from_bytes(target_master_bytes)
            .target_operation_key_id()?,
        target_guard_root_key_id: RollbackGuardRootKey::from_bytes(target_guard_bytes)
            .target_operation_key_id()?,
        planned_entry_count: 2,
        construction_plan_hash: plan_hash,
    };
    let marker = StorageConstruction {
        identity: identity_template,
        output_path_hash: directory.output_path_hash(),
        next_target: StorageConstructionCursor::BeforeFirst,
        target_records_committed: 0,
    };
    let limits = test_limits();
    let tuple = StateDirectory::probe(&directory.selected_path())?;
    let qualification = signed_qualification(tuple)?;
    let outcome = initialize_storage(StorageInitializationConfig {
        state_directory: StateDirectory::open(&directory.selected_path(), &[qualification])?,
        header_tbs: agenc_ircd_storage::DatabaseHeaderTbs::new(
            network,
            server,
            ServerIncarnation::from_bytes([34; 16]),
            target_database,
            1,
            SCHEMA_GENERATION,
            RecoveryEpoch::from_bytes([35; 16]),
        )?,
        storage_master_key: StorageMasterKey::from_bytes(target_master_bytes),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes(target_guard_bytes),
        mode: StorageInitializationMode::Construction,
        initial_records: vec![InitialStorageRecord::new(
            TableId::StorageConstruction,
            StoredKey::new(agenc_ircd_storage::STORAGE_CONSTRUCTION_KEY.to_vec())?,
            1,
            marker.encode()?,
        )?],
        account_service_response_count: 0,
        state_generation: 7,
        predecessor_guard_hash: identity_template.source_rollback_guard_hash,
        limits,
    })?;
    if !matches!(outcome, StorageInitializationOutcome::Complete { .. }) {
        return Err("construction initialization did not complete".into());
    }
    let mut target = ConstructionTarget::open(StorageOpenConfig {
        expected_network_id: network,
        expected_server_id: server,
        state_directory: StateDirectory::open(&directory.selected_path(), &[qualification])?,
        storage_master_key: StorageMasterKey::from_bytes(target_master_bytes),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes(target_guard_bytes),
        login_index_key: LoginIndexKey::from_bytes([24; 32]),
        previous_login_index_key: None,
        limits,
    })?;
    let final_marker = target.marker()?;
    let expected_identity = final_marker.identity;
    assert_ne!(final_marker.identity.target_database_header_hash, digest(0));
    let plan_file = directory.rebuild_plan_file()?;
    let plan = ConstructionPlan::rebuild_disk(
        &final_marker.identity,
        plan_file,
        [
            Ok(rekey_entry(
                TableId::Account,
                &account_key,
                source_account_id,
            )?),
            Ok(rekey_login_state_entry(&stored_key, source_record_id)?),
        ],
        construction_limits(),
    )?;
    let mut source = TestConstructionSource {
        records: vec![
            (TableId::Account, account_key, source_account_sealed),
            (TableId::LoginIndexKeyState, stored_key, source_sealed),
        ],
        master_key: StorageMasterKey::from_bytes(source_master_bytes),
        binding: source_binding,
    };
    let preflight = plan.preflight(
        &final_marker,
        7,
        0,
        &mut source,
        &mut ExactCopyTransformer,
        construction_limits(),
    )?;
    assert_eq!(preflight.target_batch_count, 1);
    assert_eq!(preflight.finalization_storage_commit_sequence, 2);
    assert_eq!(preflight.finalization_manifest_sequence, 2);
    assert_eq!(preflight.checkpoint_storage_commit_sequence, 3);
    let mut executor = ConstructionExecutor::resume(final_marker, plan, construction_limits())?;
    assert_eq!(
        executor.service_batch(&mut source, &mut ExactCopyTransformer, &mut target)?,
        2
    );
    let receipt = executor
        .last_receipt()
        .ok_or("construction batch did not retain its receipt")?;
    assert_eq!(receipt.target_records_committed, 2);
    assert_eq!(receipt.storage_commit_sequence, 1);
    assert_eq!(receipt.manifest_sequence, 1);
    assert_eq!(receipt.state_generation, 7);
    assert_eq!(receipt.account_service_response_count, 0);
    assert_eq!(receipt.nonce_draw_high_water, 9);
    let operation_id = executor.finalize(&mut target)?;
    assert_ne!(operation_id, digest(0));
    drop(executor);
    drop(target);
    directory.remove_plan_file()?;
    let verification = ConstructionTarget::verify_completed(
        StorageOpenConfig {
            expected_network_id: network,
            expected_server_id: server,
            state_directory: StateDirectory::open(&directory.selected_path(), &[qualification])?,
            storage_master_key: StorageMasterKey::from_bytes(target_master_bytes),
            rollback_guard_root_key: RollbackGuardRootKey::from_bytes(target_guard_bytes),
            login_index_key: LoginIndexKey::from_bytes([24; 32]),
            previous_login_index_key: None,
            limits,
        },
        expected_identity,
        directory.output_path_hash(),
    )?;
    assert_eq!(verification.completion().storage_operation_id, operation_id);
    assert_eq!(
        verification.logical_database_bytes(),
        preflight.final_logical_database_bytes
    );
    assert_eq!(
        verification.backup_stream_bytes(),
        preflight.final_backup_stream_bytes
    );
    assert_eq!(
        verification
            .completion()
            .finalization_storage_commit_sequence,
        preflight.finalization_storage_commit_sequence
    );
    assert_eq!(
        verification.completion().finalization_manifest_sequence,
        preflight.finalization_manifest_sequence
    );
    assert_eq!(
        verification.completion().finalization_nonce_draw_high_water,
        preflight
            .checkpoint_nonce_draw_high_water
            .checked_sub(2)
            .ok_or("checkpoint nonce high-water underflow")?
    );
    let installed = directory.install(verification)?;
    assert_eq!(installed, output);
    let installed_directory = ConstructionDirectory::open(&installed, true)?;
    assert_eq!(
        installed_directory.phase(),
        ConstructionDirectoryPhase::Installed
    );
    let resumed_verification = ConstructionTarget::verify_completed(
        StorageOpenConfig {
            expected_network_id: network,
            expected_server_id: server,
            state_directory: StateDirectory::open(
                &installed_directory.selected_path(),
                &[qualification],
            )?,
            storage_master_key: StorageMasterKey::from_bytes(target_master_bytes),
            rollback_guard_root_key: RollbackGuardRootKey::from_bytes(target_guard_bytes),
            login_index_key: LoginIndexKey::from_bytes([24; 32]),
            previous_login_index_key: None,
            limits,
        },
        expected_identity,
        installed_directory.output_path_hash(),
    )?;
    assert_eq!(
        resumed_verification.completion().storage_operation_id,
        operation_id
    );
    let owner = StorageOwner::start(StorageOpenConfig {
        expected_network_id: network,
        expected_server_id: server,
        state_directory: StateDirectory::open(&installed, &[qualification])?,
        storage_master_key: StorageMasterKey::from_bytes(target_master_bytes),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes(target_guard_bytes),
        login_index_key: LoginIndexKey::from_bytes([24; 32]),
        previous_login_index_key: None,
        limits,
    })?;
    owner.shutdown()?;
    Ok(())
}

#[test]
fn stopped_daemon_restore_installs_and_reverifies_a_signed_backup() -> Result<(), Box<dyn Error>> {
    let source = initialized_live_fixture()?;
    let owner = StorageOwner::start(live_open_config(StateDirectory::open(
        source.directory.path(),
        &[source.qualification],
    )?))?;
    let backup_directory = TestDirectory::create()?;
    let signing_key = Ed25519SecretKey::from_bytes([151; 32]);
    let public_key = signing_key.public_key();
    let backup_name = "restore-source.agenc";
    let backup_path = backup_directory.path().join(backup_name);
    owner
        .port()
        .try_backup(
            agenc_ircd_storage::BackupDestination::new(backup_directory.path(), backup_name)?,
            signing_key,
            1_000,
            [152; 16],
        )?
        .wait()?;
    owner.shutdown()?;

    let command_directory = TestDirectory::create()?;
    let source_master =
        protected_key_file(command_directory.path(), "source-master.key", [207; 32])?;
    let source_guard = protected_key_file(command_directory.path(), "source-guard.key", [208; 32])?;
    let login_key = protected_key_file(command_directory.path(), "login.key", [203; 32])?;
    let target_guard = protected_key_file(command_directory.path(), "target-guard.key", [153; 32])?;
    let output = command_directory.path().join("restored-state");
    let trusted = agenc_ircd_storage::BackupTrustKey::new(public_key)?.key_id;
    let request = || RestoreCommandRequest {
        network_id: NetworkId::from_bytes([201; 32]),
        server_id: ServerId::from_bytes([202; 16]),
        current_state_directory: source.directory.path().to_path_buf(),
        current_master_key_file: source_master.clone(),
        current_rollback_guard_key_file: source_guard.clone(),
        backup_path: backup_path.clone(),
        source_master_key_file: source_master.clone(),
        source_rollback_guard_key_file: source_guard.clone(),
        login_index_key_file: login_key.clone(),
        login_index_previous_key_file: None,
        output_state_directory: output.clone(),
        target_rollback_guard_key_file: target_guard.clone(),
        target_master_key_file: None,
        resume: false,
        declare_recovery_epoch: true,
        trusted_backup_keys: vec![RestoreTrustKey::new(
            *trusted.as_bytes(),
            *public_key.as_bytes(),
            900,
            1_100,
        )],
        limits: test_limits(),
    };
    let locked_owner = StorageOwner::start(live_open_config(StateDirectory::open(
        source.directory.path(),
        &[source.qualification],
    )?))?;
    let mut locked_current = request();
    locked_current.output_state_directory = command_directory.path().join("locked-current");
    assert_eq!(
        execute_restore_command(locked_current, &[source.qualification]),
        Err(StorageError::WriterLocked)
    );
    locked_owner.shutdown()?;

    let divergent = initialized_live_fixture()?;
    let mut mismatched_current = request();
    mismatched_current.current_state_directory = divergent.directory.path().to_path_buf();
    mismatched_current.output_state_directory = command_directory.path().join("mismatched-current");
    assert_eq!(
        execute_restore_command(mismatched_current, &[source.qualification]),
        Err(StorageError::StaleState)
    );

    let receipt = execute_restore_command(request(), &[source.qualification])?;
    assert_eq!(receipt.output_state_directory, output);
    assert_eq!(receipt.current_state_generation, Some(0));
    assert_eq!(receipt.source_state_generation, 0);
    assert_eq!(receipt.target_state_generation, 0);
    assert_ne!(receipt.source_recovery_epoch, receipt.target_recovery_epoch);
    assert_ne!(
        receipt.source_server_incarnation,
        receipt.target_server_incarnation
    );
    assert!(
        receipt
            .output_state_directory
            .join("database.redb")
            .is_file()
    );

    let mut resumed = request();
    resumed.resume = true;
    assert_eq!(
        execute_restore_command(resumed, &[source.qualification])?,
        receipt
    );

    // A process that died after finalizing the construction but before the
    // rename leaves a finalized staging directory with no marker row. Recreate
    // that state from the installed output and prove resume still installs it.
    let staging = command_directory
        .path()
        .join(".restored-state.agenc-construction-v1");
    std::fs::rename(&output, &staging)?;
    let mut finalized = request();
    finalized.resume = true;
    assert_eq!(
        execute_restore_command(finalized, &[source.qualification])?,
        receipt
    );
    assert!(output.join("database.redb").is_file());
    assert!(!staging.exists());

    let mut undeclared = request();
    undeclared.output_state_directory = command_directory.path().join("undeclared");
    undeclared.declare_recovery_epoch = false;
    assert_eq!(
        execute_restore_command(undeclared, &[source.qualification]),
        Err(StorageError::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn every_construction_commit_fault_resumes_from_the_authenticated_cursor()
-> Result<(), Box<dyn Error>> {
    for site in [
        StorageFaultSite::ConstructionBatch,
        StorageFaultSite::ConstructionCursor,
        StorageFaultSite::ConstructionCompletion,
    ] {
        for boundary in [StorageFaultBoundary::Before, StorageFaultBoundary::After] {
            let fixture = RekeyConstructionFixture::create()?;
            let faults = StorageFaultInjector::new(StorageFaultCase { site, boundary }, 1)?;
            let (mut target, mut executor, mut source) = fixture.execution(faults.clone())?;
            if site == StorageFaultSite::ConstructionCompletion {
                assert_eq!(
                    executor.service_batch(&mut source, &mut ExactCopyTransformer, &mut target,)?,
                    2,
                );
                assert!(executor.finalize(&mut target).is_err());
            } else {
                assert!(
                    executor
                        .service_batch(&mut source, &mut ExactCopyTransformer, &mut target,)
                        .is_err()
                );
            }
            faults.verify_fired()?;
            let expected_identity = executor.marker().identity;
            drop(executor);
            drop(target);

            let operation_id = fixture.finish(expected_identity)?;
            let verification = fixture.verify_completed(expected_identity)?;
            assert_eq!(verification.completion().storage_operation_id, operation_id,);
        }
    }
    Ok(())
}

#[test]
fn every_construction_checkpoint_fault_resumes_the_committed_completion()
-> Result<(), Box<dyn Error>> {
    for site in [
        StorageFaultSite::CheckpointScan,
        StorageFaultSite::CheckpointInstall,
        StorageFaultSite::CheckpointPrune,
    ] {
        for boundary in [StorageFaultBoundary::Before, StorageFaultBoundary::After] {
            let fixture = RekeyConstructionFixture::create()?;
            let faults = StorageFaultInjector::new(StorageFaultCase { site, boundary }, 1)?;
            let (mut target, mut executor, mut source) = fixture.execution(faults.clone())?;
            assert_eq!(
                executor.service_batch(&mut source, &mut ExactCopyTransformer, &mut target,)?,
                2,
            );
            let expected_identity = executor.marker().identity;
            assert!(executor.finalize(&mut target).is_err());
            faults.verify_fired()?;
            drop(executor);
            drop(target);

            let operation_id = fixture.finish(expected_identity)?;
            let verification = fixture.verify_completed(expected_identity)?;
            assert_eq!(verification.completion().storage_operation_id, operation_id,);
        }
    }
    Ok(())
}

#[test]
fn construction_directory_rename_fault_resumes_before_or_after_install()
-> Result<(), Box<dyn Error>> {
    for boundary in [StorageFaultBoundary::Before, StorageFaultBoundary::After] {
        let fixture = RekeyConstructionFixture::create()?;
        let (target, executor, source) = fixture.execution(StorageFaultInjector::disabled())?;
        let expected_identity = executor.marker().identity;
        drop(target);
        drop(executor);
        drop(source);
        fixture.finish(expected_identity)?;
        let verification = fixture.verify_completed(expected_identity)?;
        let faults = StorageFaultInjector::new(
            StorageFaultCase {
                site: StorageFaultSite::ConstructionDirectoryRename,
                boundary,
            },
            1,
        )?;
        let directory =
            ConstructionDirectory::open_with_faults(&fixture.output, true, faults.clone())?;
        assert!(directory.install(verification).is_err());
        faults.verify_fired()?;

        let resumed = ConstructionDirectory::open(&fixture.output, true)?;
        let resumed_verification = fixture.verify_completed_at(
            &resumed.selected_path(),
            expected_identity,
            resumed.output_path_hash(),
        )?;
        match resumed.phase() {
            ConstructionDirectoryPhase::Staging => {
                assert_eq!(resumed.install(resumed_verification)?, fixture.output);
            }
            ConstructionDirectoryPhase::Installed => {
                assert_eq!(resumed.selected_path(), fixture.output);
            }
        }
        let installed = ConstructionDirectory::open(&fixture.output, true)?;
        assert_eq!(installed.phase(), ConstructionDirectoryPhase::Installed);
        let final_verification = fixture.verify_completed_at(
            &installed.selected_path(),
            expected_identity,
            installed.output_path_hash(),
        )?;
        assert_eq!(
            final_verification.completion().storage_operation_id,
            expected_identity.operation_id()?,
        );
    }
    Ok(())
}

struct RekeyConstructionFixture {
    _root: TestDirectory,
    output: PathBuf,
    staging: PathBuf,
    output_path_hash: StorageDigest,
    qualification: agenc_ircd_storage::StorageQualification,
    network: NetworkId,
    server: ServerId,
    target_master_bytes: [u8; 32],
    target_guard_bytes: [u8; 32],
    login_key_bytes: [u8; 32],
    source_master_bytes: [u8; 32],
    source_binding: DatabaseBinding,
    account_sealed: Vec<u8>,
    account_record_id: StorageDigest,
    login_state_sealed: Vec<u8>,
    login_state_record_id: StorageDigest,
}

impl RekeyConstructionFixture {
    fn create() -> Result<Self, Box<dyn Error>> {
        let root = TestDirectory::create()?;
        let output = root.path().join("fault-rekeyed-state");
        let directory = ConstructionDirectory::open(&output, false)?;
        let staging = directory.selected_path();
        let output_path_hash = directory.output_path_hash();
        let network = NetworkId::from_bytes([121; 32]);
        let server = ServerId::from_bytes([122; 16]);
        let target_database = DatabaseId::from_bytes([123; 16]);
        let login_key_bytes = [124; 32];
        let login_key = LoginIndexKey::from_bytes(login_key_bytes);
        let login_state = LoginIndexKeyState::stable(1, login_key.key_id(network))?;
        let login_state_key =
            StoredKey::new(agenc_ircd_storage::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?;
        let source_master_bytes = [125; 32];
        let target_master_bytes = [126; 32];
        let source_guard_bytes = [127; 32];
        let target_guard_bytes = [128; 32];
        let source_binding = DatabaseBinding::new(
            network,
            server,
            ServerIncarnation::from_bytes([129; 16]),
            DatabaseId::from_bytes([130; 16]),
        );
        let login_state_sealed = StorageSealContext::new(
            &StorageMasterKey::from_bytes(source_master_bytes),
            source_binding,
            1,
        )?
        .seal(
            TableId::LoginIndexKeyState,
            1,
            [131; 24],
            &login_state_key,
            &login_state.encode()?,
        )?
        .encode()?;
        let login_state_record_id = SealedRecord::decode(&login_state_sealed)?.record_id()?;
        let account_key = StoredKey::new(account_key_bytes(3))?;
        let account_plaintext = PersistentRecordValue::new(
            TableId::Account,
            1,
            7,
            9,
            None,
            Vec::new(),
            crate::domain_records::live_body(TableId::Account, 132)?,
        )?
        .encode()?;
        let account_sealed = StorageSealContext::new(
            &StorageMasterKey::from_bytes(source_master_bytes),
            source_binding,
            1,
        )?
        .seal(
            TableId::Account,
            1,
            [133; 24],
            &account_key,
            &account_plaintext,
        )?
        .encode()?;
        let account_record_id = SealedRecord::decode(&account_sealed)?.record_id()?;
        let plan_hash = construction_plan_hash(
            StorageConstructionKind::Rekey,
            &[
                rekey_entry(TableId::Account, &account_key, account_record_id)?,
                rekey_login_state_entry(&login_state_key, login_state_record_id)?,
            ],
            agenc_ircd_storage::MAX_CONSTRUCTION_PLAN_BYTES,
        )?;
        let identity = StorageOperationIdentity {
            kind: StorageConstructionKind::Rekey,
            command_version: 1,
            source_database_header_hash: digest(134),
            target_database_header_hash: digest(0),
            source_rollback_guard_hash: digest(135),
            source_stream_digest: None,
            source_schema_generation: SCHEMA_GENERATION,
            target_schema_generation: SCHEMA_GENERATION,
            transform_profile_hash: rekey_transform_profile_hash()?,
            target_database_instance_id: target_database,
            source_master_key_id: StorageMasterKey::from_bytes(source_master_bytes)
                .source_operation_key_id()?,
            source_guard_root_key_id: RollbackGuardRootKey::from_bytes(source_guard_bytes)
                .source_operation_key_id()?,
            target_master_key_id: StorageMasterKey::from_bytes(target_master_bytes)
                .target_operation_key_id()?,
            target_guard_root_key_id: RollbackGuardRootKey::from_bytes(target_guard_bytes)
                .target_operation_key_id()?,
            planned_entry_count: 2,
            construction_plan_hash: plan_hash,
        };
        let marker = StorageConstruction {
            identity,
            output_path_hash,
            next_target: StorageConstructionCursor::BeforeFirst,
            target_records_committed: 0,
        };
        let tuple = StateDirectory::probe(&staging)?;
        let qualification = signed_qualification(tuple)?;
        let outcome = initialize_storage(StorageInitializationConfig {
            state_directory: StateDirectory::open(&staging, &[qualification])?,
            header_tbs: agenc_ircd_storage::DatabaseHeaderTbs::new(
                network,
                server,
                ServerIncarnation::from_bytes([136; 16]),
                target_database,
                1,
                SCHEMA_GENERATION,
                RecoveryEpoch::from_bytes([137; 16]),
            )?,
            storage_master_key: StorageMasterKey::from_bytes(target_master_bytes),
            rollback_guard_root_key: RollbackGuardRootKey::from_bytes(target_guard_bytes),
            mode: StorageInitializationMode::Construction,
            initial_records: vec![InitialStorageRecord::new(
                TableId::StorageConstruction,
                StoredKey::new(agenc_ircd_storage::STORAGE_CONSTRUCTION_KEY.to_vec())?,
                1,
                marker.encode()?,
            )?],
            account_service_response_count: 0,
            state_generation: 7,
            predecessor_guard_hash: identity.source_rollback_guard_hash,
            limits: test_limits(),
        })?;
        if !matches!(outcome, StorageInitializationOutcome::Complete { .. }) {
            return Err("fault construction initialization did not complete".into());
        }
        Ok(Self {
            _root: root,
            output,
            staging,
            output_path_hash,
            qualification,
            network,
            server,
            target_master_bytes,
            target_guard_bytes,
            login_key_bytes,
            source_master_bytes,
            source_binding,
            account_sealed,
            account_record_id,
            login_state_sealed,
            login_state_record_id,
        })
    }

    fn open_config_at(
        &self,
        path: &Path,
        faults: StorageFaultInjector,
    ) -> Result<StorageOpenConfig, StorageError> {
        Ok(StorageOpenConfig {
            expected_network_id: self.network,
            expected_server_id: self.server,
            state_directory: StateDirectory::open_with_faults(path, &[self.qualification], faults)?,
            storage_master_key: StorageMasterKey::from_bytes(self.target_master_bytes),
            rollback_guard_root_key: RollbackGuardRootKey::from_bytes(self.target_guard_bytes),
            login_index_key: LoginIndexKey::from_bytes(self.login_key_bytes),
            previous_login_index_key: None,
            limits: test_limits(),
        })
    }

    fn source(&self) -> Result<TestConstructionSource, StorageError> {
        Ok(TestConstructionSource {
            records: vec![
                (
                    TableId::Account,
                    StoredKey::new(account_key_bytes(3))?,
                    self.account_sealed.clone(),
                ),
                (
                    TableId::LoginIndexKeyState,
                    StoredKey::new(agenc_ircd_storage::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
                    self.login_state_sealed.clone(),
                ),
            ],
            master_key: StorageMasterKey::from_bytes(self.source_master_bytes),
            binding: self.source_binding,
        })
    }

    fn plan(&self, identity: &StorageOperationIdentity) -> Result<ConstructionPlan, StorageError> {
        let account_key = StoredKey::new(account_key_bytes(3))?;
        let login_state_key =
            StoredKey::new(agenc_ircd_storage::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?;
        ConstructionPlan::new(
            identity,
            vec![
                rekey_entry(TableId::Account, &account_key, self.account_record_id)?,
                rekey_login_state_entry(&login_state_key, self.login_state_record_id)?,
            ],
            construction_limits(),
        )
    }

    fn execution(
        &self,
        faults: StorageFaultInjector,
    ) -> Result<
        (
            ConstructionTarget,
            ConstructionExecutor,
            TestConstructionSource,
        ),
        StorageError,
    > {
        let target = ConstructionTarget::open(self.open_config_at(&self.staging, faults)?)?;
        let marker = target.marker()?;
        let plan = self.plan(&marker.identity)?;
        let source = self.source()?;
        let executor = ConstructionExecutor::resume(marker, plan, construction_limits())?;
        Ok((target, executor, source))
    }

    fn finish(
        &self,
        expected_identity: StorageOperationIdentity,
    ) -> Result<StorageDigest, StorageError> {
        match self.execution(StorageFaultInjector::disabled()) {
            Ok((mut target, mut executor, mut source)) => {
                while executor.service_batch(&mut source, &mut ExactCopyTransformer, &mut target)?
                    != 0
                {}
                executor.finalize(&mut target)
            }
            Err(_) => Ok(self
                .verify_completed(expected_identity)?
                .completion()
                .storage_operation_id),
        }
    }

    fn verify_completed(
        &self,
        expected_identity: StorageOperationIdentity,
    ) -> Result<agenc_ircd_storage::VerifiedConstructionOutput, StorageError> {
        self.verify_completed_at(&self.staging, expected_identity, self.output_path_hash)
    }

    fn verify_completed_at(
        &self,
        path: &Path,
        expected_identity: StorageOperationIdentity,
        output_path_hash: StorageDigest,
    ) -> Result<agenc_ircd_storage::VerifiedConstructionOutput, StorageError> {
        ConstructionTarget::verify_completed(
            self.open_config_at(path, StorageFaultInjector::disabled())?,
            expected_identity,
            output_path_hash,
        )
    }
}

struct TestConstructionSource {
    records: Vec<(TableId, StoredKey, Vec<u8>)>,
    master_key: StorageMasterKey,
    binding: DatabaseBinding,
}

impl ConstructionSourceReader for TestConstructionSource {
    fn read_source(
        &mut self,
        reference: &StorageConstructionSource,
    ) -> Result<ConstructionSourceRecord, StorageError> {
        let sealed = self
            .records
            .iter()
            .find(|(table, key, _)| {
                *table == reference.table() && key.as_bytes() == reference.key().as_bytes()
            })
            .map(|(_, _, sealed)| sealed)
            .ok_or(StorageError::StaleState)?;
        ConstructionSourceRecord::open(reference, sealed, &self.master_key, self.binding, 1)
    }
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn create() -> Result<Self, Box<dyn Error>> {
        let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "agenc-ircd-stage-five-completion-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn construction_limits_reject_each_independent_zero_order_and_maximum_boundary() {
    let maximum = ConstructionLimits {
        source_database_bytes: agenc_ircd_storage::MAX_CONSTRUCTION_SOURCE_BYTES,
        source_backup_bytes: agenc_ircd_storage::MAX_CONSTRUCTION_SOURCE_BYTES,
        target_database_bytes: agenc_ircd_storage::MAX_CONSTRUCTION_TARGET_BYTES,
        target_backup_bytes: agenc_ircd_storage::MAX_CONSTRUCTION_TARGET_BYTES,
        plan_bytes: agenc_ircd_storage::MAX_CONSTRUCTION_PLAN_BYTES,
        batch_records: agenc_ircd_storage::MAX_CONSTRUCTION_BATCH_RECORDS,
        batch_bytes: agenc_ircd_storage::MAX_CONSTRUCTION_BATCH_BYTES,
    };
    assert_eq!(maximum.validate(), Ok(maximum));
    for invalid in [
        ConstructionLimits {
            source_database_bytes: 0,
            ..maximum
        },
        ConstructionLimits {
            source_database_bytes: agenc_ircd_storage::MAX_CONSTRUCTION_SOURCE_BYTES + 1,
            ..maximum
        },
        ConstructionLimits {
            source_backup_bytes: 0,
            ..maximum
        },
        ConstructionLimits {
            source_backup_bytes: agenc_ircd_storage::MAX_CONSTRUCTION_SOURCE_BYTES + 1,
            ..maximum
        },
        ConstructionLimits {
            target_database_bytes: 0,
            ..maximum
        },
        ConstructionLimits {
            target_database_bytes: agenc_ircd_storage::MAX_CONSTRUCTION_TARGET_BYTES + 1,
            ..maximum
        },
        ConstructionLimits {
            target_backup_bytes: 0,
            ..maximum
        },
        ConstructionLimits {
            target_backup_bytes: agenc_ircd_storage::MAX_CONSTRUCTION_TARGET_BYTES + 1,
            ..maximum
        },
        ConstructionLimits {
            target_database_bytes: 2,
            target_backup_bytes: 1,
            ..maximum
        },
        ConstructionLimits {
            plan_bytes: 0,
            ..maximum
        },
        ConstructionLimits {
            plan_bytes: agenc_ircd_storage::MAX_CONSTRUCTION_PLAN_BYTES + 1,
            ..maximum
        },
        ConstructionLimits {
            batch_records: 0,
            ..maximum
        },
        ConstructionLimits {
            batch_records: agenc_ircd_storage::MAX_CONSTRUCTION_BATCH_RECORDS + 1,
            ..maximum
        },
        ConstructionLimits {
            batch_bytes: 0,
            ..maximum
        },
        ConstructionLimits {
            batch_bytes: agenc_ircd_storage::MAX_CONSTRUCTION_BATCH_BYTES + 1,
            ..maximum
        },
    ] {
        assert_eq!(invalid.validate(), Err(StorageError::LimitExceeded));
    }
}

#[test]
fn storage_engine_limits_reject_each_independent_profile_boundary() {
    let valid = test_limits();
    assert_eq!(valid.validate(), Ok(valid));
    let invalid = [
        StorageEngineLimits {
            redb_cache_bytes: 0,
            ..valid
        },
        StorageEngineLimits {
            database_max_bytes: 1_073_741_823,
            ..valid
        },
        StorageEngineLimits {
            database_max_bytes: 1_099_511_627_777,
            backup_max_bytes: 1_099_511_627_777,
            ..valid
        },
        StorageEngineLimits {
            backup_max_bytes: 1_073_741_823,
            ..valid
        },
        StorageEngineLimits {
            database_max_bytes: 1_073_741_825,
            backup_max_bytes: 1_073_741_824,
            ..valid
        },
        StorageEngineLimits {
            fixed_reserve_bytes: 67_108_863,
            ..valid
        },
        StorageEngineLimits {
            fixed_reserve_bytes: 1_099_511_627_777,
            ..valid
        },
        StorageEngineLimits {
            reserve_percent: 0,
            ..valid
        },
        StorageEngineLimits {
            reserve_percent: 26,
            ..valid
        },
        StorageEngineLimits {
            integrity_checkpoint_manifests: 9_999,
            ..valid
        },
        StorageEngineLimits {
            integrity_checkpoint_manifests: 1_000_001,
            ..valid
        },
    ];
    for limits in invalid {
        assert_eq!(limits.validate(), Err(StorageError::LimitExceeded));
    }
}

#[test]
fn disk_plan_builder_rejects_count_size_duplicate_and_missing_key_state()
-> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create()?;
    let login_key = StoredKey::new(agenc_ircd_storage::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?;

    let count_file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(directory.path().join("count.redb"))?;
    let mut count_builder = ConstructionPlanBuilder::start(
        StorageConstructionKind::Rekey,
        1,
        count_file,
        construction_limits(),
    )?;
    count_builder.push(rekey_login_state_entry(&login_key, digest(1))?)?;
    assert_eq!(
        count_builder.push(rekey_entry(
            TableId::Account,
            &StoredKey::new(account_key_bytes(1))?,
            digest(2),
        )?),
        Err(StorageError::LimitExceeded)
    );

    let size_file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(directory.path().join("size.redb"))?;
    let mut size_builder = ConstructionPlanBuilder::start_streaming(
        StorageConstructionKind::Rekey,
        size_file,
        ConstructionLimits {
            plan_bytes: 1,
            ..construction_limits()
        },
    )?;
    assert_eq!(
        size_builder.push(rekey_login_state_entry(&login_key, digest(1))?),
        Err(StorageError::LimitExceeded)
    );

    let duplicate_file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(directory.path().join("duplicate.redb"))?;
    let mut duplicate_builder = ConstructionPlanBuilder::start_streaming(
        StorageConstructionKind::Rekey,
        duplicate_file,
        construction_limits(),
    )?;
    duplicate_builder.push(rekey_login_state_entry(&login_key, digest(1))?)?;
    assert_eq!(
        duplicate_builder.push(rekey_login_state_entry(&login_key, digest(2))?),
        Err(StorageError::InvalidEncoding)
    );

    let short_file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(directory.path().join("short.redb"))?;
    let short_builder = ConstructionPlanBuilder::start(
        StorageConstructionKind::Rekey,
        1,
        short_file,
        construction_limits(),
    )?;
    assert!(matches!(
        short_builder.finish(),
        Err(StorageError::StaleState)
    ));

    let missing_file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(directory.path().join("missing.redb"))?;
    let mut missing_builder = ConstructionPlanBuilder::start_streaming(
        StorageConstructionKind::Rekey,
        missing_file,
        construction_limits(),
    )?;
    missing_builder.push(rekey_entry(
        TableId::Account,
        &StoredKey::new(account_key_bytes(1))?,
        digest(1),
    )?)?;
    assert!(matches!(
        missing_builder.finish(),
        Err(StorageError::StaleState)
    ));
    Ok(())
}

#[test]
fn backup_construction_reader_rejects_invalid_generation_stream_and_source_kind()
-> Result<(), Box<dyn Error>> {
    let binding = DatabaseBinding::new(
        NetworkId::from_bytes([31; 32]),
        ServerId::from_bytes([32; 16]),
        ServerIncarnation::from_bytes([33; 16]),
        DatabaseId::from_bytes([34; 16]),
    );
    assert_eq!(
        BackupConstructionSourceReader::new(
            Cursor::new(Vec::<u8>::new()),
            StorageMasterKey::from_bytes([35; 32]),
            binding,
            0,
            agenc_ircd_storage::BACKUP_FIXED_STREAM_BYTES,
        )
        .map(|_| ()),
        Err(StorageError::InvalidEncoding)
    );
    assert_eq!(
        BackupConstructionSourceReader::new(
            Cursor::new(Vec::<u8>::new()),
            StorageMasterKey::from_bytes([35; 32]),
            binding,
            1,
            agenc_ircd_storage::BACKUP_FIXED_STREAM_BYTES - 1,
        )
        .map(|_| ()),
        Err(StorageError::InvalidEncoding)
    );
    let stream_bytes = agenc_ircd_storage::BACKUP_FIXED_STREAM_BYTES;
    let mut reader = BackupConstructionSourceReader::new(
        Cursor::new(vec![0; usize::try_from(stream_bytes)?]),
        StorageMasterKey::from_bytes([35; 32]),
        binding,
        1,
        stream_bytes,
    )?;
    let database_reference = StorageConstructionSource::new(
        StorageConstructionSourceKind::DatabaseRecord,
        TableId::Account,
        StoredKey::new(account_key_bytes(1))?,
        1,
        digest(1),
        0,
    )?;
    assert_eq!(
        reader.read_source(&database_reference).map(|_| ()),
        Err(StorageError::InvalidEncoding)
    );
    let end_reference = StorageConstructionSource::new(
        StorageConstructionSourceKind::BackupRecord,
        TableId::Account,
        StoredKey::new(account_key_bytes(1))?,
        1,
        digest(1),
        stream_bytes,
    )?;
    assert_eq!(
        reader.read_source(&end_reference).map(|_| ()),
        Err(StorageError::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn construction_source_readers_reject_missing_rows_and_every_backup_frame_mismatch()
-> Result<(), Box<dyn Error>> {
    let live = initialized_live_fixture()?;
    let owner = StorageOwner::start(live_open_config(StateDirectory::open(
        live.directory.path(),
        &[live.qualification],
    )?))?;
    let port = owner.port();
    let binding = DatabaseBinding::new(
        NetworkId::from_bytes([201; 32]),
        ServerId::from_bytes([202; 16]),
        ServerIncarnation::from_bytes([204; 16]),
        DatabaseId::from_bytes([205; 16]),
    );
    assert_eq!(
        DatabaseConstructionSourceReader::new(
            port.clone(),
            StorageMasterKey::from_bytes([207; 32]),
            binding,
            0,
        )
        .map(|_| ()),
        Err(StorageError::InvalidEncoding)
    );
    let mut database_reader = DatabaseConstructionSourceReader::new(
        port.clone(),
        StorageMasterKey::from_bytes([207; 32]),
        binding,
        1,
    )?;
    let missing_key = StoredKey::new(account_key_bytes(254))?;
    let missing = StorageConstructionSource::new(
        StorageConstructionSourceKind::DatabaseRecord,
        TableId::Account,
        missing_key,
        1,
        digest(1),
        0,
    )?;
    assert_eq!(
        database_reader.read_source(&missing).map(|_| ()),
        Err(StorageError::StaleState)
    );
    let backup_kind = StorageConstructionSource::new(
        StorageConstructionSourceKind::BackupRecord,
        TableId::Account,
        StoredKey::new(account_key_bytes(1))?,
        1,
        digest(1),
        1,
    )?;
    assert_eq!(
        database_reader.read_source(&backup_kind).map(|_| ()),
        Err(StorageError::InvalidEncoding)
    );
    drop(database_reader);
    drop(port);
    owner.shutdown()?;

    let backup_binding = DatabaseBinding::new(
        NetworkId::from_bytes([31; 32]),
        ServerId::from_bytes([32; 16]),
        ServerIncarnation::from_bytes([33; 16]),
        DatabaseId::from_bytes([34; 16]),
    );
    let stream_bytes = agenc_ircd_storage::BACKUP_FIXED_STREAM_BYTES;
    let frame_reference = |table, key, schema, offset| {
        StorageConstructionSource::new(
            StorageConstructionSourceKind::BackupRecord,
            table,
            key,
            schema,
            digest(2),
            offset,
        )
    };
    for length in [0_u32, u32::MAX] {
        let mut stream = vec![0; usize::try_from(stream_bytes)?];
        stream
            .get_mut(1..5)
            .ok_or("missing backup frame length")?
            .copy_from_slice(&length.to_be_bytes());
        let mut reader = BackupConstructionSourceReader::new(
            Cursor::new(stream),
            StorageMasterKey::from_bytes([35; 32]),
            backup_binding,
            1,
            stream_bytes,
        )?;
        let reference = frame_reference(
            TableId::Account,
            StoredKey::new(account_key_bytes(1))?,
            1,
            1,
        )?;
        assert_eq!(
            reader.read_source(&reference).map(|_| ()),
            Err(StorageError::LimitExceeded)
        );
    }
    let offset = stream_bytes - 8;
    let mut stream = vec![0; usize::try_from(stream_bytes)?];
    let offset_index = usize::try_from(offset)?;
    let offset_end = offset_index
        .checked_add(4)
        .ok_or("backup frame offset overflow")?;
    stream
        .get_mut(offset_index..offset_end)
        .ok_or("missing backup frame length")?
        .copy_from_slice(&16_u32.to_be_bytes());
    let mut reader = BackupConstructionSourceReader::new(
        Cursor::new(stream),
        StorageMasterKey::from_bytes([35; 32]),
        backup_binding,
        1,
        stream_bytes,
    )?;
    let reference = frame_reference(
        TableId::Account,
        StoredKey::new(account_key_bytes(1))?,
        1,
        offset,
    )?;
    assert_eq!(
        reader.read_source(&reference).map(|_| ()),
        Err(StorageError::LimitExceeded)
    );

    let account_key = StoredKey::new(account_key_bytes(1))?;
    let plaintext = PersistentRecordValue::new(
        TableId::Account,
        1,
        1,
        1,
        None,
        Vec::new(),
        crate::domain_records::live_body(TableId::Account, 1)?,
    )?
    .encode()?;
    let sealed =
        StorageSealContext::new(&StorageMasterKey::from_bytes([35; 32]), backup_binding, 1)?
            .seal(TableId::Account, 1, [36; 24], &account_key, &plaintext)?
            .encode()?;
    let encoded = agenc_ircd_storage::BackupRecord::new(
        TableId::Account,
        StoredKey::new(account_key.as_bytes().to_vec())?,
        1,
        sealed,
    )?
    .encode()?;
    let mut frame = vec![0; usize::try_from(stream_bytes)?];
    frame
        .get_mut(1..5)
        .ok_or("missing backup frame length")?
        .copy_from_slice(&u32::try_from(encoded.len())?.to_be_bytes());
    let record_end = 5_usize
        .checked_add(encoded.len())
        .ok_or("backup record length overflow")?;
    frame
        .get_mut(5..record_end)
        .ok_or("missing backup record bytes")?
        .copy_from_slice(&encoded);
    for reference in [
        frame_reference(TableId::Channel, StoredKey::new(vec![1; 16])?, 1, 1)?,
        frame_reference(
            TableId::Account,
            StoredKey::new(account_key_bytes(2))?,
            1,
            1,
        )?,
        frame_reference(
            TableId::Account,
            StoredKey::new(account_key.as_bytes().to_vec())?,
            2,
            1,
        )?,
    ] {
        let mut reader = BackupConstructionSourceReader::new(
            Cursor::new(frame.clone()),
            StorageMasterKey::from_bytes([35; 32]),
            backup_binding,
            1,
            stream_bytes,
        )?;
        assert_eq!(
            reader.read_source(&reference).map(|_| ()),
            Err(StorageError::StaleState)
        );
    }
    Ok(())
}

#[derive(Default)]
struct RecordingConstructionTarget {
    commit_error: Option<StorageError>,
    stale_receipt: bool,
    finalization_error: Option<StorageError>,
    finalize_error: Option<StorageError>,
    committed_batches: Vec<usize>,
    finalized_operation: Option<StorageDigest>,
}

impl ConstructionTargetWriter for RecordingConstructionTarget {
    fn commit_batch(
        &mut self,
        batch: ConstructionTargetBatch<'_>,
    ) -> Result<ConstructionCommitReceipt, StorageError> {
        if let Some(error) = self.commit_error {
            return Err(error);
        }
        self.committed_batches.push(batch.records.len());
        let committed = if self.stale_receipt {
            batch.successor.target_records_committed.saturating_sub(1)
        } else {
            batch.successor.target_records_committed
        };
        Ok(ConstructionCommitReceipt {
            target_records_committed: committed,
            storage_commit_sequence: 1,
            manifest_sequence: 1,
            state_generation: 1,
            account_service_response_count: 0,
            nonce_draw_high_water: 1,
        })
    }

    fn finalization_counters(
        &mut self,
        _marker: &StorageConstruction,
    ) -> Result<ConstructionFinalizationCounters, StorageError> {
        if let Some(error) = self.finalization_error {
            return Err(error);
        }
        Ok(ConstructionFinalizationCounters {
            storage_commit_sequence: 2,
            manifest_sequence: 2,
            state_generation: 1,
            account_service_response_count: 0,
            nonce_draw_high_water: 2,
        })
    }

    fn finalize(
        &mut self,
        _marker: &StorageConstruction,
        completion: &StorageOperationCompletion,
    ) -> Result<(), StorageError> {
        if let Some(error) = self.finalize_error {
            return Err(error);
        }
        self.finalized_operation = Some(completion.storage_operation_id);
        Ok(())
    }
}

#[test]
fn construction_executor_rejects_source_receipt_and_finalization_failures()
-> Result<(), Box<dyn Error>> {
    let fixture = RekeyConstructionFixture::create()?;

    let (real_target, mut missing_source_executor, mut missing_source) =
        fixture.execution(StorageFaultInjector::disabled())?;
    drop(real_target);
    missing_source.records.clear();
    assert_eq!(
        missing_source_executor.service_batch(
            &mut missing_source,
            &mut ExactCopyTransformer,
            &mut RecordingConstructionTarget::default(),
        ),
        Err(StorageError::StaleState)
    );

    let (real_target, mut failed_commit_executor, mut failed_commit_source) =
        fixture.execution(StorageFaultInjector::disabled())?;
    drop(real_target);
    let mut failed_commit_target = RecordingConstructionTarget {
        commit_error: Some(StorageError::DatabaseRejected),
        ..RecordingConstructionTarget::default()
    };
    assert_eq!(
        failed_commit_executor.service_batch(
            &mut failed_commit_source,
            &mut ExactCopyTransformer,
            &mut failed_commit_target,
        ),
        Err(StorageError::DatabaseRejected)
    );

    let (real_target, mut stale_executor, mut stale_source) =
        fixture.execution(StorageFaultInjector::disabled())?;
    drop(real_target);
    let mut stale_target = RecordingConstructionTarget {
        stale_receipt: true,
        ..RecordingConstructionTarget::default()
    };
    assert_eq!(
        stale_executor.service_batch(
            &mut stale_source,
            &mut ExactCopyTransformer,
            &mut stale_target,
        ),
        Err(StorageError::StaleState)
    );
    assert_eq!(stale_executor.last_receipt(), None);

    let (real_target, mut incomplete_executor, _incomplete_source) =
        fixture.execution(StorageFaultInjector::disabled())?;
    drop(real_target);
    assert_eq!(
        incomplete_executor.finalize(&mut RecordingConstructionTarget::default()),
        Err(StorageError::StaleState)
    );

    for (finalization_error, finalize_error, expected) in [
        (
            Some(StorageError::DatabaseRejected),
            None,
            StorageError::DatabaseRejected,
        ),
        (
            None,
            Some(StorageError::AuthenticationFailed),
            StorageError::AuthenticationFailed,
        ),
    ] {
        let (real_target, mut executor, mut source) =
            fixture.execution(StorageFaultInjector::disabled())?;
        drop(real_target);
        let mut target = RecordingConstructionTarget {
            finalization_error,
            finalize_error,
            ..RecordingConstructionTarget::default()
        };
        assert_eq!(
            executor.service_batch(&mut source, &mut ExactCopyTransformer, &mut target)?,
            2
        );
        assert_eq!(executor.finalize(&mut target), Err(expected));
    }

    let (real_target, mut executor, mut source) =
        fixture.execution(StorageFaultInjector::disabled())?;
    drop(real_target);
    let mut target = RecordingConstructionTarget::default();
    assert_eq!(
        executor.service_batch(&mut source, &mut ExactCopyTransformer, &mut target)?,
        2
    );
    assert_eq!(
        executor.service_batch(&mut source, &mut ExactCopyTransformer, &mut target)?,
        0
    );
    let operation_id = executor.finalize(&mut target)?;
    assert_eq!(target.committed_batches, [2]);
    assert_eq!(target.finalized_operation, Some(operation_id));
    Ok(())
}

#[test]
fn construction_executor_enforces_first_and_accumulated_plaintext_limits()
-> Result<(), Box<dyn Error>> {
    let fixture = RekeyConstructionFixture::create()?;
    let account_bytes = PersistentRecordValue::new(
        TableId::Account,
        1,
        7,
        9,
        None,
        Vec::new(),
        crate::domain_records::live_body(TableId::Account, 132)?,
    )?
    .encode()?
    .len();

    for (batch_bytes, expected) in [
        (account_bytes - 1, Err(StorageError::LimitExceeded)),
        (account_bytes, Ok(1)),
    ] {
        let target = ConstructionTarget::open(
            fixture.open_config_at(&fixture.staging, StorageFaultInjector::disabled())?,
        )?;
        let marker = target.marker()?;
        let plan = fixture.plan(&marker.identity)?;
        drop(target);
        let limits = ConstructionLimits {
            batch_bytes,
            ..construction_limits()
        };
        let mut executor = ConstructionExecutor::resume(marker, plan, limits)?;
        let mut source = fixture.source()?;
        let mut recording_target = RecordingConstructionTarget::default();
        assert_eq!(
            executor.service_batch(
                &mut source,
                &mut ExactCopyTransformer,
                &mut recording_target,
            ),
            expected
        );
    }
    Ok(())
}

#[test]
fn construction_preflight_rejects_an_oversized_first_record() -> Result<(), Box<dyn Error>> {
    let fixture = RekeyConstructionFixture::create()?;
    let target = ConstructionTarget::open(
        fixture.open_config_at(&fixture.staging, StorageFaultInjector::disabled())?,
    )?;
    let marker = target.marker()?;
    let plan = fixture.plan(&marker.identity)?;
    let mut source = fixture.source()?;
    let account_bytes = PersistentRecordValue::new(
        TableId::Account,
        1,
        7,
        9,
        None,
        Vec::new(),
        crate::domain_records::live_body(TableId::Account, 132)?,
    )?
    .encode()?
    .len();
    let limits = ConstructionLimits {
        batch_bytes: account_bytes - 1,
        ..construction_limits()
    };
    assert_eq!(
        plan.preflight(
            &marker,
            7,
            0,
            &mut source,
            &mut ExactCopyTransformer,
            limits,
        )
        .map(|_| ()),
        Err(StorageError::LimitExceeded)
    );
    Ok(())
}

#[test]
fn construction_target_validates_an_at_target_successor_between_batches()
-> Result<(), Box<dyn Error>> {
    let fixture = RekeyConstructionFixture::create()?;
    let mut target = ConstructionTarget::open(
        fixture.open_config_at(&fixture.staging, StorageFaultInjector::disabled())?,
    )?;
    let marker = target.marker()?;
    let plan = fixture.plan(&marker.identity)?;
    let limits = ConstructionLimits {
        batch_records: 1,
        ..construction_limits()
    };
    let mut executor = ConstructionExecutor::resume(marker, plan, limits)?;
    let mut source = fixture.source()?;
    assert_eq!(
        executor.service_batch(&mut source, &mut ExactCopyTransformer, &mut target)?,
        1
    );
    assert_eq!(
        executor.service_batch(&mut source, &mut ExactCopyTransformer, &mut target)?,
        1
    );
    assert_eq!(
        executor.service_batch(&mut source, &mut ExactCopyTransformer, &mut target)?,
        0
    );
    executor.finalize(&mut target)?;
    Ok(())
}

fn protected_key_file(
    directory: &Path,
    name: &str,
    bytes: [u8; 32],
) -> Result<PathBuf, Box<dyn Error>> {
    let path = directory.join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(path)
}

fn rekey_login_state_entry(
    key: &StoredKey,
    source_record_id: StorageDigest,
) -> Result<StorageConstructionPlanEntry, StorageError> {
    rekey_entry(TableId::LoginIndexKeyState, key, source_record_id)
}

fn rekey_entry(
    table: TableId,
    key: &StoredKey,
    source_record_id: StorageDigest,
) -> Result<StorageConstructionPlanEntry, StorageError> {
    StorageConstructionPlanEntry::new(
        StorageConstructionKind::Rekey,
        vec![StorageConstructionSource::new(
            StorageConstructionSourceKind::DatabaseRecord,
            table,
            StoredKey::new(key.as_bytes().to_vec())?,
            1,
            source_record_id,
            0,
        )?],
        table,
        StoredKey::new(key.as_bytes().to_vec())?,
        1,
        StorageConstructionAction::RekeyCopy,
        0,
    )
}

fn test_limits() -> StorageEngineLimits {
    StorageEngineLimits {
        redb_cache_bytes: 8 * 1_024 * 1_024,
        fixed_reserve_bytes: 64 * 1_024 * 1_024,
        reserve_percent: 1,
        database_max_bytes: 1_073_741_824,
        backup_max_bytes: 1_073_741_824,
        integrity_checkpoint_manifests: 10_000,
    }
}

fn construction_limits() -> ConstructionLimits {
    ConstructionLimits {
        source_database_bytes: 1_073_741_824,
        source_backup_bytes: 1_073_741_824,
        target_database_bytes: 1_073_741_824,
        target_backup_bytes: 1_073_741_824,
        plan_bytes: 1_048_576,
        batch_records: 1_000,
        batch_bytes: 16_777_216,
    }
}

fn initialize_with_faults(
    faults: StorageFaultInjector,
) -> Result<Result<StorageInitializationOutcome, StorageError>, Box<dyn Error>> {
    let directory = TestDirectory::create()?;
    let tuple = StateDirectory::probe(directory.path())?;
    let qualification = signed_qualification(tuple)?;
    let network = NetworkId::from_bytes([201; 32]);
    let server = ServerId::from_bytes([202; 16]);
    let login_key = LoginIndexKey::from_bytes([203; 32]);
    let key_state = LoginIndexKeyState::stable(1, login_key.key_id(network))?;
    let initial = InitialStorageRecord::new(
        TableId::LoginIndexKeyState,
        StoredKey::new(agenc_ircd_storage::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
        1,
        key_state.encode()?,
    )?;
    let state_directory =
        StateDirectory::open_with_faults(directory.path(), &[qualification], faults)?;
    Ok(initialize_storage(StorageInitializationConfig {
        state_directory,
        header_tbs: agenc_ircd_storage::DatabaseHeaderTbs::new(
            network,
            server,
            ServerIncarnation::from_bytes([204; 16]),
            DatabaseId::from_bytes([205; 16]),
            1,
            SCHEMA_GENERATION,
            RecoveryEpoch::from_bytes([206; 16]),
        )?,
        storage_master_key: StorageMasterKey::from_bytes([207; 32]),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes([208; 32]),
        mode: StorageInitializationMode::Live,
        initial_records: vec![initial],
        account_service_response_count: 0,
        state_generation: 0,
        predecessor_guard_hash: StorageDigest::from_bytes([0; 32]),
        limits: test_limits(),
    }))
}

struct ComprehensiveInitialState {
    records: Vec<InitialStorageRecord>,
    rows: Vec<(TableId, StoredKey)>,
}

fn comprehensive_initial_state() -> Result<ComprehensiveInitialState, Box<dyn Error>> {
    let network = NetworkId::from_bytes([201; 32]);
    let login_key = LoginIndexKey::from_bytes([203; 32]);
    let master_key = StorageMasterKey::from_bytes([207; 32]);
    let binding = DatabaseBinding::new(
        network,
        ServerId::from_bytes([202; 16]),
        ServerIncarnation::from_bytes([204; 16]),
        DatabaseId::from_bytes([205; 16]),
    );
    let mut keys = BTreeMap::new();
    for table in DOMAIN_TABLES {
        keys.insert(table, key_for(table)?);
    }
    let account_key = StoredKey::new(account_key_bytes(1))?;
    keys.insert(
        TableId::Account,
        StoredKey::new(account_key.as_bytes().to_vec())?,
    );
    keys.insert(
        TableId::OpaqueRecord,
        StoredKey::new(account_key.as_bytes().to_vec())?,
    );
    for (table, semantic_key) in [
        (TableId::NicknameReservation, b"nickname".as_slice()),
        (TableId::ChannelName, b"#channel".as_slice()),
    ] {
        let index = derive_storage_index(
            &master_key,
            binding,
            StorageTable::new(table.as_u16())?,
            1,
            semantic_key,
        )?;
        keys.insert(
            table,
            StoredKey::new(index.expose_for_storage_key().to_vec())?,
        );
    }

    let key_state = LoginIndexKeyState::stable(1, login_key.key_id(network))?;
    let mut records = vec![InitialStorageRecord::new(
        TableId::LoginIndexKeyState,
        StoredKey::new(agenc_ircd_storage::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
        1,
        key_state.encode()?,
    )?];
    let mut rows = Vec::with_capacity(DOMAIN_TABLES.len() + 1);
    for table in DOMAIN_TABLES {
        let key = cloned_domain_key(&keys, table)?;
        let references = comprehensive_references(&keys, table)?;
        let kind = if table == TableId::History { 2 } else { 1 };
        let body = if table == TableId::E2eeState {
            E2eeRecoveryGate::new(
                digest(215),
                E2eeRecoveryKind::Normal,
                RecoveryEpoch::from_bytes([206; 16]),
                digest(216),
                digest(217),
                digest(218),
                digest(219),
            )
            .encode()?
        } else {
            domain_body(table, kind, vec![table.as_u16() as u8, 1])?
        };
        let plaintext = PersistentRecordValue::new(
            table,
            kind,
            u64::from(table.as_u16()),
            1,
            if table == TableId::History {
                None
            } else {
                Some(4_000_000_000)
            },
            references,
            body,
        )?
        .encode()?;
        records.push(InitialStorageRecord::new(
            table,
            StoredKey::new(key.as_bytes().to_vec())?,
            1,
            plaintext,
        )?);
        rows.push((table, key));
    }

    let login = NormalizedLogin::prepare("complete-storage-reconstruction")?;
    let login_stored_key =
        LoginIndexStoredKey::new(1, derive_login_index(&login_key, network, &login)?)?;
    let login_key_bytes = login_stored_key.encode()?;
    let login_value = LoginIndexValue::new(
        &login_stored_key,
        LoginIndexValueKind::Live {
            account_id: AccountRandomId::from_bytes([1; 16]).to_account_id(),
            opaque_credential_id: OpaqueCredentialId::from_bytes([220; 32]),
        },
    )?;
    records.push(InitialStorageRecord::new(
        TableId::LoginIndex,
        StoredKey::new(login_key_bytes.as_bytes().to_vec())?,
        1,
        login_value.encode()?,
    )?);
    rows.push((TableId::LoginIndex, login_key_bytes));
    Ok(ComprehensiveInitialState { records, rows })
}

fn comprehensive_references(
    keys: &BTreeMap<TableId, StoredKey>,
    source: TableId,
) -> Result<Vec<RecordReference>, StorageError> {
    let targets: &[TableId] = match source {
        TableId::Account => &[TableId::OpaqueRecord],
        TableId::OpaqueRecord | TableId::NicknameReservation => &[TableId::Account],
        TableId::AuthTransaction => &[
            TableId::Account,
            TableId::OpaqueRecord,
            TableId::RegistrationInvite,
        ],
        TableId::RegistrationInvite => &[TableId::Account, TableId::AuthTransaction],
        TableId::Session => &[TableId::Account, TableId::Channel],
        TableId::Channel => &[
            TableId::Account,
            TableId::Session,
            TableId::RegistrationInvite,
        ],
        TableId::ChannelName | TableId::History => &[TableId::Channel],
        TableId::Sanction => &[TableId::Account, TableId::Session, TableId::Channel],
        TableId::FederationPeer => &[TableId::E2eeState],
        TableId::FederationOrigin => &[TableId::FederationPeer],
        TableId::RequestResult => &[
            TableId::FederationPeer,
            TableId::FederationOrigin,
            TableId::EdgeOutbox,
            TableId::E2eeState,
        ],
        TableId::EdgeOutbox => &[
            TableId::FederationPeer,
            TableId::RequestResult,
            TableId::E2eeObject,
            TableId::E2eeState,
        ],
        TableId::EdgeProjection => &[
            TableId::FederationPeer,
            TableId::Account,
            TableId::Session,
            TableId::Channel,
            TableId::E2eeState,
        ],
        TableId::Audit => &[
            TableId::Account,
            TableId::Session,
            TableId::Channel,
            TableId::Sanction,
            TableId::FederationPeer,
            TableId::E2eeState,
        ],
        TableId::AuditCheckpoint => &[TableId::Audit],
        TableId::E2eeObject => &[TableId::Account, TableId::Channel, TableId::E2eeState],
        TableId::E2eeState => &[
            TableId::Account,
            TableId::Channel,
            TableId::FederationPeer,
            TableId::E2eeObject,
            TableId::E2eeState,
        ],
        _ => return Err(StorageError::InvalidEncoding),
    };
    targets
        .iter()
        .map(|target| {
            let key = cloned_domain_key(keys, *target)?;
            RecordReference::new(*target, key)
        })
        .collect()
}

fn cloned_domain_key(
    keys: &BTreeMap<TableId, StoredKey>,
    table: TableId,
) -> Result<StoredKey, StorageError> {
    let key = keys.get(&table).ok_or(StorageError::InvalidEncoding)?;
    StoredKey::new(key.as_bytes().to_vec())
}

struct InitializedLiveFixture {
    directory: TestDirectory,
    qualification: agenc_ircd_storage::StorageQualification,
    logical_database_bytes: u64,
    backup_stream_bytes: u64,
}

impl InitializedLiveFixture {
    fn accounting(&self) -> StorageAccountingLimits {
        StorageAccountingLimits {
            current_logical_database_bytes: self.logical_database_bytes,
            current_backup_stream_bytes: self.backup_stream_bytes,
            database_max_bytes: test_limits().database_max_bytes,
            backup_max_bytes: test_limits().backup_max_bytes,
        }
    }
}

fn initialized_live_fixture() -> Result<InitializedLiveFixture, Box<dyn Error>> {
    let network = NetworkId::from_bytes([201; 32]);
    let login_key = LoginIndexKey::from_bytes([203; 32]);
    let key_state = LoginIndexKeyState::stable(1, login_key.key_id(network))?;
    initialized_live_fixture_from(vec![InitialStorageRecord::new(
        TableId::LoginIndexKeyState,
        StoredKey::new(agenc_ircd_storage::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
        1,
        key_state.encode()?,
    )?])
}

struct LazyLoginFixture {
    fixture: InitializedLiveFixture,
    login: NormalizedLogin,
    previous_key: StoredKey,
    previous_value: LoginIndexValue,
    account_id: agenc_ircd_types::AccountId,
    credential_id: OpaqueCredentialId,
}

fn initialized_lazy_login_fixture() -> Result<LazyLoginFixture, Box<dyn Error>> {
    let network = NetworkId::from_bytes([201; 32]);
    let previous_login_key = LoginIndexKey::from_bytes([203; 32]);
    let key_state = LoginIndexKeyState::stable(1, previous_login_key.key_id(network))?;
    let login = NormalizedLogin::prepare("lazy-fault-login")?;
    let previous_lookup =
        LoginIndexStoredKey::new(1, derive_login_index(&previous_login_key, network, &login)?)?;
    let previous_key = previous_lookup.encode()?;
    let account_id = AccountRandomId::from_bytes([222; 16]).to_account_id();
    let credential_id = OpaqueCredentialId::from_bytes([223; 32]);
    let previous_value = LoginIndexValue::new(
        &previous_lookup,
        LoginIndexValueKind::Live {
            account_id,
            opaque_credential_id: OpaqueCredentialId::from_bytes([223; 32]),
        },
    )?;
    let account_key = StoredKey::new(account_id.to_text().as_bytes().to_vec())?;
    let fixture = initialized_live_fixture_from(vec![
        InitialStorageRecord::new(
            TableId::LoginIndexKeyState,
            StoredKey::new(agenc_ircd_storage::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
            1,
            key_state.encode()?,
        )?,
        InitialStorageRecord::new(
            TableId::Account,
            StoredKey::new(account_key.as_bytes().to_vec())?,
            1,
            PersistentRecordValue::new(
                TableId::Account,
                1,
                1,
                1,
                None,
                Vec::new(),
                crate::domain_records::live_body(TableId::Account, 1)?,
            )?
            .encode()?,
        )?,
        InitialStorageRecord::new(
            TableId::OpaqueRecord,
            account_key,
            1,
            PersistentRecordValue::new(TableId::OpaqueRecord, 1, 1, 0, None, Vec::new(), vec![2])?
                .encode()?,
        )?,
        InitialStorageRecord::new(
            TableId::LoginIndex,
            StoredKey::new(previous_key.as_bytes().to_vec())?,
            1,
            previous_value.encode()?,
        )?,
    ])?;
    Ok(LazyLoginFixture {
        fixture,
        login,
        previous_key,
        previous_value,
        account_id,
        credential_id,
    })
}

fn initialized_live_fixture_from(
    initial_records: Vec<InitialStorageRecord>,
) -> Result<InitializedLiveFixture, Box<dyn Error>> {
    let directory = TestDirectory::create()?;
    let tuple = StateDirectory::probe(directory.path())?;
    let qualification = signed_qualification(tuple)?;
    let network = NetworkId::from_bytes([201; 32]);
    let outcome = initialize_storage(StorageInitializationConfig {
        state_directory: StateDirectory::open(directory.path(), &[qualification])?,
        header_tbs: agenc_ircd_storage::DatabaseHeaderTbs::new(
            network,
            ServerId::from_bytes([202; 16]),
            ServerIncarnation::from_bytes([204; 16]),
            DatabaseId::from_bytes([205; 16]),
            1,
            SCHEMA_GENERATION,
            RecoveryEpoch::from_bytes([206; 16]),
        )?,
        storage_master_key: StorageMasterKey::from_bytes([207; 32]),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes([208; 32]),
        mode: StorageInitializationMode::Live,
        initial_records,
        account_service_response_count: 0,
        state_generation: 0,
        predecessor_guard_hash: StorageDigest::from_bytes([0; 32]),
        limits: test_limits(),
    })?;
    let StorageInitializationOutcome::Complete {
        logical_database_bytes,
        backup_stream_bytes,
        ..
    } = outcome
    else {
        return Err("live fixture initialization was indeterminate".into());
    };
    Ok(InitializedLiveFixture {
        directory,
        qualification,
        logical_database_bytes,
        backup_stream_bytes,
    })
}

fn live_open_config(state_directory: StateDirectory) -> StorageOpenConfig {
    StorageOpenConfig {
        expected_network_id: NetworkId::from_bytes([201; 32]),
        expected_server_id: ServerId::from_bytes([202; 16]),
        state_directory,
        storage_master_key: StorageMasterKey::from_bytes([207; 32]),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes([208; 32]),
        login_index_key: LoginIndexKey::from_bytes([203; 32]),
        previous_login_index_key: None,
        limits: test_limits(),
    }
}

fn read_key_state_record(port: &StoragePort) -> Result<ExistingRecord, Box<dyn Error>> {
    let key = StoredKey::new(agenc_ircd_storage::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?;
    let mut result = port
        .try_read(ReadPlan::exact(TableId::LoginIndexKeyState, key))?
        .wait()?;
    if result.records.len() != 1 {
        return Err("login-index key-state singleton is missing".into());
    }
    let record = result
        .records
        .pop()
        .ok_or("login-index key-state singleton is missing")?;
    let sealed = SealedRecord::decode(&record.sealed_record)?;
    Ok(ExistingRecord::new(
        sealed.record_schema(),
        sealed.record_id()?,
        record.sealed_record.len(),
    )?)
}

fn read_existing_record(
    port: &StoragePort,
    table: TableId,
    key: StoredKey,
) -> Result<ExistingRecord, Box<dyn Error>> {
    let mut result = port.try_read(ReadPlan::exact(table, key))?.wait()?;
    if result.records.len() != 1 {
        return Err("expected storage record is missing".into());
    }
    let record = result
        .records
        .pop()
        .ok_or("expected storage record is missing")?;
    let sealed = SealedRecord::decode(&record.sealed_record)?;
    Ok(ExistingRecord::new(
        sealed.record_schema(),
        sealed.record_id()?,
        record.sealed_record.len(),
    )?)
}

fn signed_qualification(
    tuple: agenc_ircd_storage::FilesystemTuple,
) -> Result<agenc_ircd_storage::StorageQualification, Box<dyn Error>> {
    let target = match tuple.target {
        "x86_64-unknown-linux-gnu" => QualificationTarget::X86_64UnknownLinuxGnu,
        "aarch64-unknown-linux-gnu" => QualificationTarget::Aarch64UnknownLinuxGnu,
        _ => return Err("unsupported test target".into()),
    };
    let mut cases = QUALIFICATION_CASES
        .iter()
        .map(|name| StorageGrowthCase::new((*name).to_owned(), 1_000, 1_001))
        .collect::<Result<Vec<_>, _>>()?;
    cases.sort_by(|left, right| left.name().cmp(right.name()));
    let key = Ed25519SecretKey::from_bytes([62; 32]);
    let report = StorageQualificationReport::sign(
        StorageQualificationReportTbs {
            target,
            filesystem_type: tuple.filesystem_type,
            block_size: tuple.block_size,
            mount_flags: tuple.mount_flags,
            kernel_release: "test-kernel".to_owned(),
            redb_features_hash: digest(1),
            release_profile_hash: digest(2),
            corpus_hash: digest(3),
            cases,
            maximum_observed_growth: 1,
            raw_log_hash: digest(4),
        },
        &key,
    )?;
    let verified =
        StorageQualificationReport::decode_and_verify(&report.encode()?, key.public_key())?;
    Ok(verified.qualification_for(tuple)?)
}

fn key_for(table: TableId) -> Result<StoredKey, Box<dyn Error>> {
    let bytes = match table {
        TableId::Account => account_key_bytes(1),
        TableId::OpaqueRecord => account_key_bytes(2),
        TableId::AuthTransaction
        | TableId::RegistrationInvite
        | TableId::Session
        | TableId::Channel => vec![1; 16],
        TableId::NicknameReservation | TableId::ChannelName | TableId::E2eeObject => vec![2; 32],
        TableId::Sanction => vec![3; 18],
        TableId::FederationPeer => vec![4; 16],
        TableId::FederationOrigin => vec![5; 56],
        TableId::RequestResult => vec![6; 16],
        TableId::EdgeOutbox | TableId::EdgeProjection => vec![7; 10],
        TableId::History => agenc_ircd_storage::history_records::history_control_key(
            agenc_ircd_types::ChannelInstanceId::from_bytes([1; 16]),
        )?
        .as_bytes()
        .to_vec(),
        TableId::Audit | TableId::AuditCheckpoint => vec![9; 8],
        TableId::E2eeState => vec![10; 3],
        _ => return Err("not a domain table".into()),
    };
    Ok(StoredKey::new(bytes)?)
}

fn digest(byte: u8) -> StorageDigest {
    StorageDigest::from_bytes([byte; 32])
}
