//! Exhaustive closed-union and hostile-input coverage for Stage 05 codecs.

#![forbid(unsafe_code)]

use std::error::Error;

use agenc_ircd_crypto::{
    DatabaseBinding, Ed25519SecretKey, LoginIndexKey, RollbackGuardRootKey, StorageDigest,
    StorageIntegrityContext, StorageMasterKey, derive_login_index, derive_storage_integrity_keys,
    rekey_transform_profile_hash, restore_transform_profile_hash,
};
use agenc_ircd_storage::{
    BACKUP_FIXED_STREAM_BYTES, BackupHeader, BackupRecord, BackupStreamWriter, BackupTrustKey,
    DatabaseHeader, DatabaseHeaderTbs, ExistingRecord, INTEGRITY_CHECKPOINT_BYTES,
    IntegrityCheckpoint, IntegrityCheckpointTbs, IntegrityManifest, IntegrityManifestTbs,
    IntegrityRecordMutation, IntegrityRecordVersion, LoginIndexKeyState, LoginIndexStoredKey,
    LoginIndexValue, LoginIndexValueKind, MAX_NONCE_DRAWS, MAX_SEALED_RECORD_BYTES,
    MIN_SEALED_RECORD_BYTES, NonceReservationState, NonceReservationTbs, ProtocolRecordBody,
    ReadPlan, RecordMutation, RecordReference, RollbackGuard, RollbackGuardPhase, RollbackGuardTbs,
    SCHEMA_GENERATION, SealedRecord, StateMeta, StateMetaTbs, StorageAccountingLimits,
    StorageConstruction, StorageConstructionAction, StorageConstructionCursor,
    StorageConstructionKind, StorageConstructionPlanEntry, StorageConstructionSource,
    StorageConstructionSourceKind, StorageError, StorageMutationBatch, StorageMutationHead,
    StorageOperationCompletion, StorageOperationIdentity, StorageSealContext, StoredKey, TableId,
    backup_stream_bytes, construction_plan_hash, logical_meta_charge, logical_record_charge,
    validate_record_plaintext, verify_backup, verify_guard_pair,
};
use agenc_ircd_types::{
    AccountRandomId, DatabaseId, NetworkId, NormalizedLogin, OpaqueCredentialId, RecoveryEpoch,
    ServerId, ServerIncarnation, TransactionId,
};

fn digest(byte: u8) -> StorageDigest {
    StorageDigest::from_bytes([byte; 32])
}

fn stored_key(text: &[u8]) -> Result<StoredKey, StorageError> {
    StoredKey::new(text.to_vec())
}

fn account_key(seed: u8) -> Vec<u8> {
    AccountRandomId::from_bytes([seed; 16])
        .to_text()
        .into_bytes()
}

fn domain_body(table: TableId, kind: u16, byte: u8) -> Result<Vec<u8>, StorageError> {
    if kind == 1
        && matches!(
            table,
            TableId::Account | TableId::Session | TableId::Channel | TableId::Sanction
        )
    {
        return crate::domain_records::live_body(table, byte);
    }
    if table == TableId::NicknameReservation && kind == 1 {
        return Ok(b"nickname".to_vec());
    }
    if table == TableId::ChannelName && kind == 1 {
        return Ok(b"#channel".to_vec());
    }
    if table == TableId::E2eeObject {
        return agenc_ircd_storage::e2ee_records::fixtures::object_body(byte);
    }
    if table == TableId::E2eeState && kind != 1 {
        return agenc_ircd_storage::e2ee_records::fixtures::state_body(kind, byte);
    }
    if matches!(
        table,
        TableId::FederationPeer
            | TableId::FederationOrigin
            | TableId::RequestResult
            | TableId::EdgeOutbox
            | TableId::EdgeProjection
    ) {
        ProtocolRecordBody::new(table, kind, 1, vec![byte])?.encode()
    } else {
        Ok(vec![byte])
    }
}

fn source(
    kind: StorageConstructionSourceKind,
    table: TableId,
    key: &[u8],
    byte: u8,
) -> Result<StorageConstructionSource, StorageError> {
    StorageConstructionSource::new(
        kind,
        table,
        stored_key(key)?,
        1,
        digest(byte),
        if kind == StorageConstructionSourceKind::BackupRecord {
            100
        } else {
            0
        },
    )
}

fn assert_all_truncations_fail(
    bytes: &[u8],
    mut decode: impl FnMut(&[u8]) -> Result<(), StorageError>,
) {
    let mut prefix = Vec::with_capacity(bytes.len());
    for (length, byte) in bytes.iter().copied().enumerate() {
        assert!(decode(&prefix).is_err(), "accepted length {length}");
        prefix.push(byte);
    }
}

fn exercise_single_byte_corruptions(
    bytes: &[u8],
    mut reencode: impl FnMut(&[u8]) -> Result<Vec<u8>, StorageError>,
) {
    for index in 0..bytes.len() {
        let mut corrupted = bytes.to_vec();
        if let Some(byte) = corrupted.get_mut(index) {
            *byte ^= 0xff;
        }
        // An unauthenticated codec may accept the corrupted frame as a different
        // valid value, but only when the frame is that value's canonical encoding.
        if let Ok(reencoded) = reencode(&corrupted) {
            assert_eq!(reencoded, corrupted, "byte {index} decoded non-canonically");
        }
    }
}

fn backup_boundary() -> Result<
    (
        BackupHeader,
        StorageMasterKey,
        RollbackGuardRootKey,
        Ed25519SecretKey,
        DatabaseBinding,
    ),
    StorageError,
> {
    let network = NetworkId::from_bytes([201; 32]);
    let server = ServerId::from_bytes([202; 16]);
    let database = DatabaseId::from_bytes([203; 16]);
    let header = DatabaseHeader::new(
        DatabaseHeaderTbs::new(
            network,
            server,
            ServerIncarnation::from_bytes([204; 16]),
            database,
            1,
            SCHEMA_GENERATION,
            RecoveryEpoch::from_bytes([205; 16]),
        )?,
        digest(206),
    );
    let guard_root = RollbackGuardRootKey::from_bytes([207; 32]);
    let integrity_keys = derive_storage_integrity_keys(
        &guard_root,
        StorageIntegrityContext::new(network, server, database),
    )?;
    let state_meta_record_id = digest(208);
    let reservation_tbs = NonceReservationTbs {
        database_instance_id: database,
        reservation_sequence: 0,
        phase: RollbackGuardPhase::Committed,
        nonce_reservation_start: 0,
        nonce_draw_high_water: 0,
        storage_commit_sequence: 0,
        manifest_sequence: 0,
        state_generation: 0,
        database_header_hash: header.complete_hash()?,
        state_meta_record_id,
        previous_guard_hash: digest(0),
    };
    let reservation = NonceReservationState::authenticate(reservation_tbs, &integrity_keys)?;
    let guard = RollbackGuard::authenticate(
        RollbackGuardTbs {
            network_id: network,
            server_id: server,
            database_instance_id: database,
            storage_key_generation: 1,
            schema_generation: SCHEMA_GENERATION,
            recovery_epoch: header.tbs().recovery_epoch,
            storage_commit_sequence: 0,
            manifest_sequence: 0,
            state_generation: 0,
            phase: RollbackGuardPhase::Committed,
            reservation_sequence: 0,
            nonce_reservation_start: 0,
            nonce_draw_high_water: 0,
            database_header_hash: header.complete_hash()?,
            state_meta_record_id,
            nonce_reservation_state_hash: reservation.complete_hash()?,
            previous_guard_hash: digest(0),
        },
        &integrity_keys,
    )?;
    let signing_key = Ed25519SecretKey::from_bytes([209; 32]);
    let backup_header = BackupHeader::new(
        header,
        reservation,
        guard,
        123,
        [210; 16],
        signing_key.public_key(),
    )?;
    let binding = DatabaseBinding::new(
        network,
        server,
        ServerIncarnation::from_bytes([204; 16]),
        database,
    );
    Ok((
        backup_header,
        StorageMasterKey::from_bytes([211; 32]),
        guard_root,
        signing_key,
        binding,
    ))
}

#[test]
fn backup_components_reject_each_envelope_order_trust_and_size_boundary()
-> Result<(), Box<dyn Error>> {
    let (header, master_key, guard_root, signing_key, binding) = backup_boundary()?;
    assert_eq!(
        header.source_header().tbs().database_instance_id,
        DatabaseId::from_bytes([203; 16])
    );
    assert_eq!(
        header.source_nonce_reservation().tbs().reservation_sequence,
        0
    );
    assert_eq!(header.source_rollback_guard().tbs().reservation_sequence, 0);
    assert_eq!(
        header.signing_key_id(),
        BackupTrustKey::new(signing_key.public_key())?.key_id
    );

    let stored_key = StoredKey::new(account_key(1))?;
    let sealed = StorageSealContext::new(&master_key, binding, 1)?.seal(
        TableId::Account,
        1,
        [212; 24],
        &stored_key,
        b"backup-record",
    )?;
    let sealed_bytes = sealed.encode()?;
    assert!(
        BackupRecord::new(
            TableId::Account,
            StoredKey::new(stored_key.as_bytes().to_vec())?,
            0,
            sealed_bytes.clone(),
        )
        .is_err()
    );
    assert!(
        BackupRecord::new(
            TableId::Channel,
            StoredKey::new(stored_key.as_bytes().to_vec())?,
            1,
            sealed_bytes.clone(),
        )
        .is_err()
    );
    assert!(
        BackupRecord::new(
            TableId::Account,
            StoredKey::new(stored_key.as_bytes().to_vec())?,
            2,
            sealed_bytes.clone(),
        )
        .is_err()
    );
    let record = BackupRecord::new(
        TableId::Account,
        StoredKey::new(stored_key.as_bytes().to_vec())?,
        1,
        sealed_bytes,
    )?;
    assert_eq!(record.table(), TableId::Account);
    assert_eq!(record.stored_key().as_bytes(), stored_key.as_bytes());
    assert_eq!(record.record_schema(), 1);
    assert_eq!(
        SealedRecord::decode(record.sealed_record())?.encode()?,
        sealed.encode()?
    );
    let encoded_record = record.encode()?;
    let decoded_record = BackupRecord::decode(&encoded_record)?;
    assert_eq!(decoded_record.encode()?, encoded_record);
    let mut trailing = encoded_record.clone();
    trailing.push(0);
    assert!(BackupRecord::decode(&trailing).is_err());

    assert!(BackupStreamWriter::start(Vec::new(), &header, BACKUP_FIXED_STREAM_BYTES - 1).is_err());
    let mut ordered = BackupStreamWriter::start(Vec::new(), &header, 1_073_741_824)?;
    ordered.write_record(&record)?;
    assert!(ordered.write_record(&record).is_err());

    let wrong_signing_key = Ed25519SecretKey::from_bytes([213; 32]);
    assert!(
        BackupStreamWriter::start(Vec::new(), &header, 1_073_741_824)?
            .finish(&wrong_signing_key)
            .is_err()
    );
    let mut too_small = BackupStreamWriter::start(Vec::new(), &header, BACKUP_FIXED_STREAM_BYTES)?;
    assert!(too_small.write_record(&record).is_err());

    let (stream, trailer) =
        BackupStreamWriter::start(Vec::new(), &header, 1_073_741_824)?.finish(&signing_key)?;
    assert_eq!(trailer.record_count, 0);
    let trust = BackupTrustKey::new(signing_key.public_key())?;
    assert!(BackupTrustKey::with_validity(trust.key_id, signing_key.public_key(), 5, 5).is_err());
    assert!(verify_backup(stream.as_slice(), &master_key, &guard_root, &[], u64::MAX).is_err());
    assert!(
        verify_backup(
            stream.as_slice(),
            &master_key,
            &guard_root,
            &[trust, trust],
            u64::MAX,
        )
        .is_err()
    );
    let excessive_trust = vec![trust; 1_025];
    assert!(
        verify_backup(
            stream.as_slice(),
            &master_key,
            &guard_root,
            &excessive_trust,
            u64::MAX,
        )
        .is_err()
    );
    assert!(
        verify_backup(
            [0_u8; 21].as_slice(),
            &master_key,
            &guard_root,
            &[trust],
            u64::MAX
        )
        .is_err()
    );
    assert!(
        verify_backup(
            stream.as_slice(),
            &master_key,
            &guard_root,
            &[BackupTrustKey::new(wrong_signing_key.public_key())?],
            u64::MAX,
        )
        .is_err()
    );

    assert!(backup_stream_bytes([(&stored_key, MIN_SEALED_RECORD_BYTES - 1)]).is_err());
    assert!(backup_stream_bytes([(&stored_key, MAX_SEALED_RECORD_BYTES)]).is_ok());
    Ok(())
}

#[test]
fn schema_registry_and_charge_boundaries_are_closed() -> Result<(), Box<dyn Error>> {
    for number in 0_u16..=26 {
        let table = TableId::from_u16(number)?;
        assert_eq!(table.as_u16(), number);
        assert_eq!(
            table.is_integrity_tracked(),
            matches!(number, 1..=13 | 17..=26)
        );
    }
    assert_eq!(TableId::from_u16(27), Err(StorageError::UnsupportedVersion));
    assert!(StoredKey::new(Vec::new()).is_err());
    assert!(StoredKey::new(vec![0; 4_097]).is_err());
    assert!(StoredKey::new(vec![0; 4_096]).is_ok());

    assert!(logical_record_charge(0, MIN_SEALED_RECORD_BYTES).is_err());
    assert!(logical_record_charge(4_097, MIN_SEALED_RECORD_BYTES).is_err());
    assert!(logical_record_charge(1, MIN_SEALED_RECORD_BYTES - 1).is_err());
    assert!(logical_record_charge(1, MAX_SEALED_RECORD_BYTES + 1).is_err());
    assert!(logical_record_charge(4_096, MAX_SEALED_RECORD_BYTES).is_ok());
    assert!(logical_meta_charge(0, 1).is_err());
    assert!(logical_meta_charge(1, 0).is_err());
    assert_eq!(logical_meta_charge(1, 1)?, 10);
    Ok(())
}

#[test]
fn sealed_record_codec_rejects_every_binding_and_envelope_mismatch() -> Result<(), Box<dyn Error>> {
    let network = NetworkId::from_bytes([1; 32]);
    let binding = DatabaseBinding::new(
        network,
        agenc_ircd_types::ServerId::from_bytes([2; 16]),
        agenc_ircd_types::ServerIncarnation::from_bytes([3; 16]),
        DatabaseId::from_bytes([4; 16]),
    );
    let master = StorageMasterKey::from_bytes([5; 32]);
    let context = StorageSealContext::new(&master, binding, 1)?;
    let key = stored_key(b"account")?;
    let sealed = context.seal(TableId::Account, 1, [6; 24], &key, b"logical-value")?;
    let encoded = sealed.encode()?;
    assert_all_truncations_fail(&encoded, |candidate| {
        SealedRecord::decode(candidate).map(|_| ())
    });
    assert_eq!(SealedRecord::decode(&encoded)?.encode()?, encoded);

    assert!(
        sealed
            .open(&master, binding, TableId::Channel, 1, 1, &key)
            .is_err()
    );
    assert!(
        sealed
            .open(&master, binding, TableId::Account, 2, 1, &key)
            .is_err()
    );
    assert!(
        sealed
            .open(&master, binding, TableId::Account, 1, 2, &key)
            .is_err()
    );
    assert!(
        sealed
            .open(
                &StorageMasterKey::from_bytes([9; 32]),
                binding,
                TableId::Account,
                1,
                1,
                &key,
            )
            .is_err()
    );
    assert!(
        sealed
            .open(
                &master,
                DatabaseBinding::new(
                    network,
                    agenc_ircd_types::ServerId::from_bytes([2; 16]),
                    agenc_ircd_types::ServerIncarnation::from_bytes([3; 16]),
                    DatabaseId::from_bytes([99; 16]),
                ),
                TableId::Account,
                1,
                1,
                &key,
            )
            .is_err()
    );
    assert!(
        sealed
            .open(
                &master,
                binding,
                TableId::Account,
                1,
                1,
                &stored_key(b"other")?,
            )
            .is_err()
    );

    for offset in [0, 2, 4, 8, 31, encoded.len() - 1] {
        let mut corrupted = encoded.clone();
        let byte = corrupted
            .get_mut(offset)
            .ok_or(StorageError::InvalidEncoding)?;
        *byte ^= 0x80;
        if let Ok(candidate) = SealedRecord::decode(&corrupted) {
            assert!(
                candidate
                    .open(&master, binding, TableId::Account, 1, 1, &key)
                    .is_err()
            );
        }
    }
    Ok(())
}

#[test]
fn login_index_codecs_cover_all_arms_and_transition_failures() -> Result<(), Box<dyn Error>> {
    let network = NetworkId::from_bytes([10; 32]);
    let previous_key = LoginIndexKey::from_bytes([11; 32]);
    let current_key = LoginIndexKey::from_bytes([12; 32]);
    let login = NormalizedLogin::prepare("stage-five-user")?;
    let digest = derive_login_index(&current_key, network, &login)?;
    let stored = LoginIndexStoredKey::new(2, digest)?;
    let encoded_key = stored.encode()?;
    assert_eq!(
        LoginIndexStoredKey::decode(encoded_key.as_bytes())?.generation(),
        2
    );
    let short_key = encoded_key
        .as_bytes()
        .get(..35)
        .ok_or(StorageError::InvalidEncoding)?;
    assert!(LoginIndexStoredKey::decode(short_key).is_err());
    assert!(
        LoginIndexStoredKey::new(0, derive_login_index(&current_key, network, &login)?).is_err()
    );

    let account = AccountRandomId::from_bytes([13; 16]).to_account_id();
    let values = [
        LoginIndexValue::new(
            &stored,
            LoginIndexValueKind::Live {
                account_id: account,
                opaque_credential_id: OpaqueCredentialId::from_bytes([14; 32]),
            },
        )?,
        LoginIndexValue::new(
            &stored,
            LoginIndexValueKind::CreationReservation {
                transaction_id: TransactionId::from_bytes([15; 16]),
                expires_at: 1,
            },
        )?,
        LoginIndexValue::new(
            &stored,
            LoginIndexValueKind::DeletionTombstone {
                deleted_account_id: account,
                expires_at: u64::MAX,
            },
        )?,
    ];
    for value in values {
        let encoded = value.encode()?;
        assert_eq!(LoginIndexValue::decode(&encoded, &stored)?.generation(), 2);
        assert_all_truncations_fail(&encoded, |candidate| {
            LoginIndexValue::decode(candidate, &stored).map(|_| ())
        });
        let wrong =
            LoginIndexStoredKey::new(1, derive_login_index(&previous_key, network, &login)?)?;
        assert!(LoginIndexValue::decode(&encoded, &wrong).is_err());
    }
    assert!(
        LoginIndexValue::new(
            &stored,
            LoginIndexValueKind::CreationReservation {
                transaction_id: TransactionId::from_bytes([0; 16]),
                expires_at: 0,
            },
        )
        .is_err()
    );
    assert!(
        LoginIndexValue::new(
            &stored,
            LoginIndexValueKind::DeletionTombstone {
                deleted_account_id: account,
                expires_at: 0,
            },
        )
        .is_err()
    );

    let stable = LoginIndexKeyState::stable(1, previous_key.key_id(network))?;
    assert_eq!(stable.previous(), None);
    assert!(stable.decrement_previous().is_err());
    assert!(stable.finish().is_err());
    assert!(
        stable
            .validate_configured_keys(network, &previous_key, None)
            .is_ok()
    );
    assert!(
        stable
            .validate_configured_keys(network, &current_key, None)
            .is_err()
    );
    let stable_bytes = stable.encode()?;
    assert_all_truncations_fail(&stable_bytes, |candidate| {
        LoginIndexKeyState::decode(candidate).map(|_| ())
    });

    let transition = LoginIndexKeyState::transition(
        1,
        previous_key.key_id(network),
        current_key.key_id(network),
        1,
    )?;
    assert_eq!(transition.previous(), Some((1, 1)));
    assert!(
        transition
            .validate_configured_keys(network, &current_key, Some(&previous_key))
            .is_ok()
    );
    assert!(
        transition
            .validate_configured_keys(network, &current_key, None)
            .is_err()
    );
    assert!(transition.finish().is_err());
    assert!(transition.decrement_previous()?.finish().is_ok());
    assert!(LoginIndexKeyState::stable(0, previous_key.key_id(network)).is_err());
    assert!(
        LoginIndexKeyState::transition(
            1,
            previous_key.key_id(network),
            previous_key.key_id(network),
            1,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn integrity_codecs_cover_insert_delete_replace_and_checkpoint_failures()
-> Result<(), Box<dyn Error>> {
    let key_a = stored_key(b"a")?;
    let key_b = stored_key(b"b")?;
    let insert = IntegrityRecordMutation::new(
        TableId::Account,
        stored_key(key_a.as_bytes())?,
        IntegrityRecordVersion::Absent,
        IntegrityRecordVersion::Present {
            record_schema: 1,
            sealed_record_id: digest(20),
        },
    )?;
    let delete = IntegrityRecordMutation::new(
        TableId::Channel,
        stored_key(key_b.as_bytes())?,
        IntegrityRecordVersion::Present {
            record_schema: 1,
            sealed_record_id: digest(21),
        },
        IntegrityRecordVersion::Absent,
    )?;
    assert!(
        IntegrityRecordMutation::new(
            TableId::StateMeta,
            stored_key(b"control")?,
            IntegrityRecordVersion::Absent,
            IntegrityRecordVersion::Present {
                record_schema: 1,
                sealed_record_id: digest(22),
            },
        )
        .is_err()
    );
    assert!(
        IntegrityRecordMutation::new(
            TableId::Account,
            stored_key(b"same")?,
            IntegrityRecordVersion::Absent,
            IntegrityRecordVersion::Absent,
        )
        .is_err()
    );
    let manifest = IntegrityManifest::new(IntegrityManifestTbs::new(
        DatabaseId::from_bytes([23; 16]),
        1,
        1,
        0,
        1,
        0,
        0,
        10,
        12,
        15,
        3,
        digest(24),
        vec![delete, insert],
    )?)?;
    let encoded = manifest.encode()?;
    assert_eq!(
        IntegrityManifest::decode(&encoded)?.manifest_hash(),
        manifest.manifest_hash()
    );
    assert_all_truncations_fail(&encoded, |candidate| {
        IntegrityManifest::decode(candidate).map(|_| ())
    });
    for offset in [0, 2, 20, encoded.len() - 1] {
        let mut corrupted = encoded.clone();
        let byte = corrupted
            .get_mut(offset)
            .ok_or(StorageError::InvalidEncoding)?;
        *byte ^= 1;
        assert!(IntegrityManifest::decode(&corrupted).is_err());
    }
    assert!(
        IntegrityManifestTbs::new(
            DatabaseId::from_bytes([23; 16]),
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            2,
            2,
            digest(0),
            vec![IntegrityRecordMutation::new(
                TableId::Account,
                stored_key(b"x")?,
                IntegrityRecordVersion::Absent,
                IntegrityRecordVersion::Present {
                    record_schema: 1,
                    sealed_record_id: digest(1),
                },
            )?],
        )
        .is_err()
    );

    let checkpoint = IntegrityCheckpoint::new(IntegrityCheckpointTbs {
        database_instance_id: DatabaseId::from_bytes([25; 16]),
        cut_storage_commit_sequence: 2,
        cut_manifest_sequence: 2,
        cut_state_generation: 2,
        cut_account_service_response_count: 0,
        cut_nonce_draw_high_water: 20,
        cut_manifest_hash: digest(26),
        tracked_record_count: 2,
        tracked_state_digest: digest(27),
        previous_checkpoint_hash: digest(28),
        installation_storage_commit_sequence: 3,
        installation_manifest_sequence: 2,
        installation_nonce_reservation_start: 20,
        installation_nonce_draw_high_water: 22,
    })?;
    let checkpoint_bytes = checkpoint.encode()?;
    assert_eq!(checkpoint_bytes.len(), INTEGRITY_CHECKPOINT_BYTES);
    assert_eq!(
        IntegrityCheckpoint::decode(&checkpoint_bytes)?.checkpoint_hash(),
        checkpoint.checkpoint_hash()
    );
    assert_all_truncations_fail(&checkpoint_bytes, |candidate| {
        IntegrityCheckpoint::decode(candidate).map(|_| ())
    });
    let mut corrupted = checkpoint_bytes;
    let last = corrupted.len() - 1;
    let byte = corrupted
        .get_mut(last)
        .ok_or(StorageError::InvalidEncoding)?;
    *byte ^= 1;
    assert!(IntegrityCheckpoint::decode(&corrupted).is_err());

    Ok(())
}

#[test]
fn construction_codecs_cover_every_closed_action_and_cursor() -> Result<(), Box<dyn Error>> {
    let entries = vec![
        StorageConstructionPlanEntry::new(
            StorageConstructionKind::Restore,
            vec![source(
                StorageConstructionSourceKind::BackupRecord,
                TableId::Account,
                b"a",
                1,
            )?],
            TableId::Account,
            stored_key(b"a")?,
            1,
            StorageConstructionAction::RestoreAccount,
            0,
        )?,
        StorageConstructionPlanEntry::new(
            StorageConstructionKind::Restore,
            vec![source(
                StorageConstructionSourceKind::BackupRecord,
                TableId::LoginIndex,
                b"b",
                2,
            )?],
            TableId::LoginIndex,
            stored_key(b"b")?,
            1,
            StorageConstructionAction::RestoreCopy,
            0,
        )?,
        StorageConstructionPlanEntry::new(
            StorageConstructionKind::Restore,
            vec![source(
                StorageConstructionSourceKind::BackupRecord,
                TableId::Channel,
                b"c",
                3,
            )?],
            TableId::Channel,
            stored_key(b"c")?,
            1,
            StorageConstructionAction::RestoreChannel,
            0,
        )?,
        StorageConstructionPlanEntry::new(
            StorageConstructionKind::Restore,
            vec![
                source(
                    StorageConstructionSourceKind::BackupRecord,
                    TableId::Channel,
                    b"c",
                    3,
                )?,
                source(
                    StorageConstructionSourceKind::BackupRecord,
                    TableId::ChannelName,
                    b"d",
                    4,
                )?,
            ],
            TableId::ChannelName,
            stored_key(b"d")?,
            1,
            StorageConstructionAction::RestoreChannelName,
            0,
        )?,
        StorageConstructionPlanEntry::new(
            StorageConstructionKind::Restore,
            vec![source(
                StorageConstructionSourceKind::BackupRecord,
                TableId::FederationPeer,
                b"e",
                5,
            )?],
            TableId::FederationPeer,
            stored_key(b"e")?,
            1,
            StorageConstructionAction::RestorePeerTombstones,
            0,
        )?,
        StorageConstructionPlanEntry::new(
            StorageConstructionKind::Restore,
            vec![source(
                StorageConstructionSourceKind::BackupRecord,
                TableId::E2eeState,
                b"f",
                6,
            )?],
            TableId::E2eeState,
            stored_key(b"f")?,
            1,
            StorageConstructionAction::RestoreE2eeState,
            0,
        )?,
    ];
    for entry in &entries {
        let encoded = entry.encode()?;
        let _ = StorageConstructionPlanEntry::decode(StorageConstructionKind::Restore, &encoded)?;
        assert_all_truncations_fail(&encoded, |candidate| {
            StorageConstructionPlanEntry::decode(StorageConstructionKind::Restore, candidate)
                .map(|_| ())
        });
        exercise_single_byte_corruptions(&encoded, |candidate| {
            StorageConstructionPlanEntry::decode(StorageConstructionKind::Restore, candidate)?
                .encode()
        });
    }
    let _ = construction_plan_hash(StorageConstructionKind::Restore, &entries, 100_000)?;

    let rekey = StorageConstructionPlanEntry::new(
        StorageConstructionKind::Rekey,
        vec![source(
            StorageConstructionSourceKind::DatabaseRecord,
            TableId::Account,
            b"r",
            7,
        )?],
        TableId::Account,
        stored_key(b"r")?,
        1,
        StorageConstructionAction::RekeyCopy,
        0,
    )?;
    let migrate = StorageConstructionPlanEntry::new(
        StorageConstructionKind::Migrate,
        Vec::new(),
        TableId::Account,
        stored_key(b"m")?,
        2,
        StorageConstructionAction::MigrateTransform,
        1,
    )?;
    assert!(
        StorageConstructionPlanEntry::decode(StorageConstructionKind::Rekey, &rekey.encode()?)
            .is_ok()
    );
    assert!(
        StorageConstructionPlanEntry::decode(StorageConstructionKind::Migrate, &migrate.encode()?)
            .is_ok()
    );
    exercise_single_byte_corruptions(&rekey.encode()?, |candidate| {
        StorageConstructionPlanEntry::decode(StorageConstructionKind::Rekey, candidate)?.encode()
    });
    exercise_single_byte_corruptions(&migrate.encode()?, |candidate| {
        StorageConstructionPlanEntry::decode(StorageConstructionKind::Migrate, candidate)?.encode()
    });
    assert!(
        StorageConstructionSource::new(
            StorageConstructionSourceKind::DatabaseRecord,
            TableId::Account,
            stored_key(b"bad")?,
            0,
            digest(1),
            1,
        )
        .is_err()
    );
    assert!(
        StorageConstructionSource::new(
            StorageConstructionSourceKind::DatabaseRecord,
            TableId::Account,
            stored_key(b"bad")?,
            1,
            digest(1),
            1,
        )
        .is_err()
    );
    let duplicate_source = || {
        source(
            StorageConstructionSourceKind::BackupRecord,
            TableId::Channel,
            b"duplicate",
            9,
        )
    };
    assert!(
        StorageConstructionPlanEntry::new(
            StorageConstructionKind::Restore,
            vec![duplicate_source()?, duplicate_source()?],
            TableId::ChannelName,
            stored_key(b"bad")?,
            1,
            StorageConstructionAction::RestoreChannelName,
            0,
        )
        .is_err()
    );
    assert!(
        StorageConstructionPlanEntry::new(
            StorageConstructionKind::Restore,
            vec![
                source(
                    StorageConstructionSourceKind::BackupRecord,
                    TableId::Account,
                    b"one",
                    10,
                )?,
                source(
                    StorageConstructionSourceKind::BackupRecord,
                    TableId::Channel,
                    b"two",
                    11,
                )?,
                source(
                    StorageConstructionSourceKind::BackupRecord,
                    TableId::Session,
                    b"three",
                    12,
                )?,
            ],
            TableId::ChannelName,
            stored_key(b"bad")?,
            1,
            StorageConstructionAction::RestoreChannelName,
            0,
        )
        .is_err()
    );
    assert!(
        StorageConstructionPlanEntry::new(
            StorageConstructionKind::Restore,
            Vec::new(),
            TableId::Account,
            stored_key(b"bad")?,
            0,
            StorageConstructionAction::RestoreAccount,
            0,
        )
        .is_err()
    );
    assert!(
        StorageConstructionPlanEntry::new(
            StorageConstructionKind::Restore,
            Vec::new(),
            TableId::StateMeta,
            stored_key(b"bad")?,
            1,
            StorageConstructionAction::RestoreCopy,
            0,
        )
        .is_err()
    );
    for table in [
        TableId::LoginIndex,
        TableId::OpaqueRecord,
        TableId::NicknameReservation,
        TableId::RegistrationInvite,
        TableId::Sanction,
        TableId::History,
        TableId::Audit,
        TableId::AuditCheckpoint,
        TableId::E2eeObject,
        TableId::LoginIndexKeyState,
        TableId::StorageOperation,
    ] {
        assert!(
            StorageConstructionPlanEntry::new(
                StorageConstructionKind::Restore,
                vec![source(
                    StorageConstructionSourceKind::BackupRecord,
                    table,
                    table.name().as_bytes(),
                    13,
                )?],
                table,
                stored_key(table.name().as_bytes())?,
                1,
                StorageConstructionAction::RestoreCopy,
                0,
            )
            .is_ok()
        );
    }
    for (kind, action, rule_id) in [
        (
            StorageConstructionKind::Restore,
            StorageConstructionAction::RekeyCopy,
            0,
        ),
        (
            StorageConstructionKind::Rekey,
            StorageConstructionAction::RekeyCopy,
            1,
        ),
        (
            StorageConstructionKind::Migrate,
            StorageConstructionAction::MigrateTransform,
            0,
        ),
    ] {
        assert!(
            StorageConstructionPlanEntry::new(
                kind,
                vec![source(
                    StorageConstructionSourceKind::DatabaseRecord,
                    TableId::Account,
                    b"matrix",
                    14,
                )?],
                TableId::Account,
                stored_key(b"matrix")?,
                1,
                action,
                rule_id,
            )
            .is_err()
        );
    }

    for (kind, action, target) in [
        (
            StorageConstructionKind::Rekey,
            StorageConstructionAction::RekeyCopy,
            TableId::Account,
        ),
        (
            StorageConstructionKind::Restore,
            StorageConstructionAction::RestoreCopy,
            TableId::LoginIndex,
        ),
        (
            StorageConstructionKind::Restore,
            StorageConstructionAction::RestoreAccount,
            TableId::Account,
        ),
        (
            StorageConstructionKind::Restore,
            StorageConstructionAction::RestoreChannel,
            TableId::Channel,
        ),
        (
            StorageConstructionKind::Restore,
            StorageConstructionAction::RestorePeerTombstones,
            TableId::FederationPeer,
        ),
        (
            StorageConstructionKind::Restore,
            StorageConstructionAction::RestoreE2eeState,
            TableId::E2eeState,
        ),
    ] {
        assert!(
            StorageConstructionPlanEntry::new(
                kind,
                Vec::new(),
                target,
                stored_key(b"no-source")?,
                1,
                action,
                0,
            )
            .is_err()
        );
        assert!(
            StorageConstructionPlanEntry::new(
                kind,
                vec![source(
                    StorageConstructionSourceKind::DatabaseRecord,
                    target,
                    b"wrong-rule",
                    17,
                )?],
                target,
                stored_key(b"wrong-rule")?,
                1,
                action,
                1,
            )
            .is_err()
        );
    }
    for (action, valid_target) in [
        (StorageConstructionAction::RestoreCopy, TableId::LoginIndex),
        (StorageConstructionAction::RestoreAccount, TableId::Account),
        (StorageConstructionAction::RestoreChannel, TableId::Channel),
        (
            StorageConstructionAction::RestorePeerTombstones,
            TableId::FederationPeer,
        ),
        (
            StorageConstructionAction::RestoreE2eeState,
            TableId::E2eeState,
        ),
    ] {
        assert!(
            StorageConstructionPlanEntry::new(
                StorageConstructionKind::Restore,
                vec![source(
                    StorageConstructionSourceKind::BackupRecord,
                    valid_target,
                    b"wrong-target",
                    18,
                )?],
                TableId::Audit,
                stored_key(b"wrong-target")?,
                1,
                action,
                0,
            )
            .is_err()
        );
    }
    assert!(
        StorageConstructionPlanEntry::new(
            StorageConstructionKind::Restore,
            vec![source(
                StorageConstructionSourceKind::BackupRecord,
                TableId::ChannelName,
                b"one-name-source",
                19,
            )?],
            TableId::ChannelName,
            stored_key(b"one-name-source")?,
            1,
            StorageConstructionAction::RestoreChannelName,
            0,
        )
        .is_err()
    );
    assert!(
        StorageConstructionPlanEntry::new(
            StorageConstructionKind::Restore,
            vec![
                source(
                    StorageConstructionSourceKind::BackupRecord,
                    TableId::Channel,
                    b"channel-source",
                    20,
                )?,
                source(
                    StorageConstructionSourceKind::BackupRecord,
                    TableId::ChannelName,
                    b"name-source",
                    21,
                )?,
            ],
            TableId::Audit,
            stored_key(b"wrong-name-target")?,
            1,
            StorageConstructionAction::RestoreChannelName,
            0,
        )
        .is_err()
    );
    assert!(
        StorageConstructionPlanEntry::new(
            StorageConstructionKind::Migrate,
            Vec::new(),
            TableId::Account,
            stored_key(b"migration-wrong-action")?,
            1,
            StorageConstructionAction::RestoreAccount,
            1,
        )
        .is_err()
    );

    let restore_identity = StorageOperationIdentity {
        kind: StorageConstructionKind::Restore,
        command_version: 1,
        source_database_header_hash: digest(40),
        target_database_header_hash: digest(41),
        source_rollback_guard_hash: digest(42),
        source_stream_digest: Some(digest(43)),
        source_schema_generation: SCHEMA_GENERATION,
        target_schema_generation: SCHEMA_GENERATION,
        transform_profile_hash: restore_transform_profile_hash()?,
        target_database_instance_id: DatabaseId::from_bytes([44; 16]),
        source_master_key_id: digest(45),
        source_guard_root_key_id: digest(46),
        target_master_key_id: digest(47),
        target_guard_root_key_id: digest(48),
        planned_entry_count: 1,
        construction_plan_hash: digest(49),
    };
    restore_identity.validate()?;
    let marker = StorageConstruction {
        identity: restore_identity,
        output_path_hash: digest(50),
        next_target: StorageConstructionCursor::BeforeFirst,
        target_records_committed: 0,
    };
    let marker_bytes = marker.encode()?;
    assert!(StorageConstruction::decode(&marker_bytes).is_ok());
    assert_all_truncations_fail(&marker_bytes, |candidate| {
        StorageConstruction::decode(candidate).map(|_| ())
    });
    exercise_single_byte_corruptions(&marker_bytes, |candidate| {
        StorageConstruction::decode(candidate)?.encode()
    });

    let complete_identity = restore_identity;
    let completion = StorageOperationCompletion {
        identity: complete_identity,
        storage_operation_id: complete_identity.operation_id()?,
        target_records_committed: 1,
        finalization_storage_commit_sequence: 3,
        finalization_manifest_sequence: 2,
        finalization_state_generation: 0,
        finalization_account_service_response_count: 0,
        finalization_nonce_draw_high_water: 20,
    };
    let completion_bytes = completion.encode()?;
    assert!(StorageOperationCompletion::decode(&completion_bytes).is_ok());
    assert_all_truncations_fail(&completion_bytes, |candidate| {
        StorageOperationCompletion::decode(candidate).map(|_| ())
    });
    exercise_single_byte_corruptions(&completion_bytes, |candidate| {
        StorageOperationCompletion::decode(candidate)?.encode()
    });

    let rekey_identity = StorageOperationIdentity {
        kind: StorageConstructionKind::Rekey,
        source_stream_digest: None,
        transform_profile_hash: rekey_transform_profile_hash()?,
        ..restore_identity
    };
    rekey_identity.validate()?;
    assert!(
        StorageOperationIdentity {
            source_stream_digest: Some(digest(90)),
            ..rekey_identity
        }
        .validate()
        .is_err()
    );
    assert!(
        StorageOperationIdentity {
            target_schema_generation: SCHEMA_GENERATION + 1,
            ..rekey_identity
        }
        .validate()
        .is_err()
    );
    assert!(
        StorageOperationIdentity {
            transform_profile_hash: digest(91),
            ..rekey_identity
        }
        .validate()
        .is_err()
    );
    assert!(
        StorageOperationIdentity {
            command_version: 2,
            ..restore_identity
        }
        .validate()
        .is_err()
    );
    assert!(
        StorageOperationIdentity {
            source_schema_generation: 0,
            ..restore_identity
        }
        .validate()
        .is_err()
    );
    assert!(
        StorageOperationIdentity {
            target_schema_generation: SCHEMA_GENERATION + 1,
            ..restore_identity
        }
        .validate()
        .is_err()
    );
    assert!(
        StorageOperationIdentity {
            transform_profile_hash: digest(200),
            ..restore_identity
        }
        .validate()
        .is_err()
    );
    assert!(
        StorageOperationIdentity {
            source_stream_digest: None,
            ..restore_identity
        }
        .validate()
        .is_err()
    );
    assert!(matches!(
        StorageOperationIdentity {
            kind: StorageConstructionKind::Migrate,
            source_stream_digest: None,
            ..restore_identity
        }
        .validate(),
        Err(StorageError::UnsupportedMigration)
    ));
    assert!(
        StorageConstructionCursor::BeforeFirst
            .validate(0, 1)
            .is_ok()
    );
    assert!(
        StorageConstructionCursor::BeforeFirst
            .validate(0, 0)
            .is_err()
    );
    assert!(StorageConstructionCursor::Complete.validate(1, 1).is_ok());
    assert!(StorageConstructionCursor::Complete.validate(0, 1).is_err());
    assert!(
        StorageConstructionCursor::AtTarget {
            table: TableId::Account,
            key: stored_key(b"next")?,
        }
        .validate(0, 1)
        .is_ok()
    );
    assert!(
        StorageConstructionCursor::AtTarget {
            table: TableId::StateMeta,
            key: stored_key(b"next")?,
        }
        .validate(0, 1)
        .is_err()
    );
    assert!(
        StorageConstructionCursor::AtTarget {
            table: TableId::Account,
            key: stored_key(b"next")?,
        }
        .validate(1, 1)
        .is_err()
    );
    assert!(construction_plan_hash(StorageConstructionKind::Restore, &entries, 1).is_err());
    let duplicate_entries = [
        StorageConstructionPlanEntry::new(
            StorageConstructionKind::Restore,
            vec![source(
                StorageConstructionSourceKind::BackupRecord,
                TableId::Account,
                b"same",
                15,
            )?],
            TableId::Account,
            stored_key(b"same")?,
            1,
            StorageConstructionAction::RestoreAccount,
            0,
        )?,
        StorageConstructionPlanEntry::new(
            StorageConstructionKind::Restore,
            vec![source(
                StorageConstructionSourceKind::BackupRecord,
                TableId::Account,
                b"same",
                16,
            )?],
            TableId::Account,
            stored_key(b"same")?,
            1,
            StorageConstructionAction::RestoreAccount,
            0,
        )?,
    ];
    assert!(
        construction_plan_hash(StorageConstructionKind::Restore, &duplicate_entries, 10_000)
            .is_err()
    );
    let invalid_marker = StorageConstruction {
        identity: restore_identity,
        output_path_hash: digest(50),
        next_target: StorageConstructionCursor::Complete,
        target_records_committed: 0,
    };
    assert!(invalid_marker.encode().is_err());
    for invalid_completion in [
        StorageOperationCompletion {
            storage_operation_id: digest(201),
            ..completion
        },
        StorageOperationCompletion {
            target_records_committed: 0,
            ..completion
        },
        StorageOperationCompletion {
            finalization_storage_commit_sequence: 0,
            ..completion
        },
    ] {
        assert!(invalid_completion.encode().is_err());
    }
    Ok(())
}

#[test]
fn state_meta_rejects_counter_and_authenticator_corruption() -> Result<(), Box<dyn Error>> {
    let network = NetworkId::from_bytes([60; 32]);
    let database = DatabaseId::from_bytes([61; 16]);
    let keys = derive_storage_integrity_keys(
        &RollbackGuardRootKey::from_bytes([62; 32]),
        StorageIntegrityContext::new(
            network,
            agenc_ircd_types::ServerId::from_bytes([63; 16]),
            database,
        ),
    )?;
    let header_hash = digest(64);
    let state = StateMeta::authenticate(
        StateMetaTbs {
            storage_commit_sequence: 1,
            manifest_sequence: 1,
            state_generation: 1,
            account_service_response_count: 0,
            nonce_draw_high_water: 10,
            logical_database_bytes: 1_024,
            backup_stream_bytes: 2_048,
            checkpoint_manifest_sequence: 0,
            latest_manifest_hash: digest(65),
            checkpoint_hash: digest(66),
            previous_rollback_guard_hash: digest(67),
        },
        header_hash,
        &keys,
    )?;
    let encoded = state.encode()?;
    assert!(StateMeta::decode_and_verify(&encoded, header_hash, &keys).is_ok());
    assert_all_truncations_fail(&encoded, |candidate| {
        StateMeta::decode_and_verify(candidate, header_hash, &keys).map(|_| ())
    });
    let mut wrong_version = encoded.clone();
    wrong_version
        .get_mut(..2)
        .ok_or(StorageError::InvalidEncoding)?
        .copy_from_slice(&2_u16.to_be_bytes());
    assert_eq!(
        StateMeta::decode_and_verify(&wrong_version, header_hash, &keys).map(|_| ()),
        Err(StorageError::UnsupportedVersion),
    );
    let mut corrupted = encoded;
    let last = corrupted.len() - 1;
    let byte = corrupted
        .get_mut(last)
        .ok_or(StorageError::InvalidEncoding)?;
    *byte ^= 1;
    assert!(StateMeta::decode_and_verify(&corrupted, header_hash, &keys).is_err());
    assert!(
        StateMeta::authenticate(
            StateMetaTbs {
                nonce_draw_high_water: MAX_NONCE_DRAWS + 1,
                ..*state.tbs()
            },
            header_hash,
            &keys,
        )
        .is_err()
    );
    assert!(
        StateMeta::authenticate(
            StateMetaTbs {
                checkpoint_manifest_sequence: 2,
                ..*state.tbs()
            },
            header_hash,
            &keys,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn database_and_guard_controls_bind_every_identity_and_phase() -> Result<(), Box<dyn Error>> {
    let network = NetworkId::from_bytes([80; 32]);
    let server = ServerId::from_bytes([81; 16]);
    let database = DatabaseId::from_bytes([82; 16]);
    let header_tbs = DatabaseHeaderTbs::new(
        network,
        server,
        ServerIncarnation::from_bytes([83; 16]),
        database,
        1,
        SCHEMA_GENERATION,
        RecoveryEpoch::from_bytes([84; 16]),
    )?;
    assert!(
        DatabaseHeaderTbs::new(
            network,
            server,
            ServerIncarnation::from_bytes([83; 16]),
            database,
            0,
            SCHEMA_GENERATION,
            RecoveryEpoch::from_bytes([84; 16]),
        )
        .is_err()
    );
    assert!(
        DatabaseHeaderTbs::new(
            network,
            server,
            ServerIncarnation::from_bytes([83; 16]),
            database,
            1,
            SCHEMA_GENERATION + 1,
            RecoveryEpoch::from_bytes([84; 16]),
        )
        .is_err()
    );
    let header = DatabaseHeader::new(header_tbs, digest(85));
    let header_bytes = header.encode()?;
    assert_eq!(DatabaseHeader::decode(&header_bytes)?, header);
    assert_all_truncations_fail(&header_bytes, |candidate| {
        DatabaseHeader::decode(candidate).map(|_| ())
    });
    for offset in [0, 15, 16, 17] {
        let mut corrupted = header_bytes.clone();
        let byte = corrupted
            .get_mut(offset)
            .ok_or(StorageError::InvalidEncoding)?;
        *byte ^= 1;
        assert!(DatabaseHeader::decode(&corrupted).is_err());
    }

    let root = RollbackGuardRootKey::from_bytes([86; 32]);
    let keys = derive_storage_integrity_keys(
        &root,
        StorageIntegrityContext::new(network, server, database),
    )?;
    let state_record_id = digest(87);
    let reservation_tbs = NonceReservationTbs {
        database_instance_id: database,
        reservation_sequence: 0,
        phase: RollbackGuardPhase::Committed,
        nonce_reservation_start: 10,
        nonce_draw_high_water: 10,
        storage_commit_sequence: 0,
        manifest_sequence: 0,
        state_generation: 0,
        database_header_hash: header.complete_hash()?,
        state_meta_record_id: state_record_id,
        previous_guard_hash: digest(0),
    };
    assert!(
        NonceReservationTbs {
            nonce_draw_high_water: MAX_NONCE_DRAWS + 1,
            ..reservation_tbs
        }
        .validate()
        .is_err()
    );
    assert!(
        NonceReservationTbs {
            nonce_reservation_start: 11,
            ..reservation_tbs
        }
        .validate()
        .is_err()
    );
    assert!(
        NonceReservationTbs {
            nonce_reservation_start: 9,
            ..reservation_tbs
        }
        .validate()
        .is_err()
    );
    assert!(
        NonceReservationTbs {
            phase: RollbackGuardPhase::NonceReserved,
            ..reservation_tbs
        }
        .validate()
        .is_err()
    );
    assert!(
        NonceReservationTbs {
            phase: RollbackGuardPhase::NonceReserved,
            nonce_draw_high_water: 65_548,
            ..reservation_tbs
        }
        .validate()
        .is_err()
    );
    let reservation = NonceReservationState::authenticate(reservation_tbs, &keys)?;
    let reservation_bytes = reservation.encode()?;
    assert!(NonceReservationState::decode_and_verify(&reservation_bytes, &keys).is_ok());
    assert_all_truncations_fail(&reservation_bytes, |candidate| {
        NonceReservationState::decode_and_verify(candidate, &keys).map(|_| ())
    });
    let mut bad_reservation = reservation_bytes;
    let last = bad_reservation.len() - 1;
    let byte = bad_reservation
        .get_mut(last)
        .ok_or(StorageError::InvalidEncoding)?;
    *byte ^= 1;
    assert!(NonceReservationState::decode_and_verify(&bad_reservation, &keys).is_err());

    let guard_tbs = RollbackGuardTbs {
        network_id: network,
        server_id: server,
        database_instance_id: database,
        storage_key_generation: 1,
        schema_generation: SCHEMA_GENERATION,
        recovery_epoch: header.tbs().recovery_epoch,
        storage_commit_sequence: 0,
        manifest_sequence: 0,
        state_generation: 0,
        phase: RollbackGuardPhase::Committed,
        reservation_sequence: 0,
        nonce_reservation_start: 10,
        nonce_draw_high_water: 10,
        database_header_hash: header.complete_hash()?,
        state_meta_record_id: state_record_id,
        nonce_reservation_state_hash: reservation.complete_hash()?,
        previous_guard_hash: digest(0),
    };
    let guard = RollbackGuard::authenticate(guard_tbs, &keys)?;
    let guard_bytes = guard.encode()?;
    assert!(RollbackGuard::decode_and_verify(&guard_bytes, &keys).is_ok());
    assert_all_truncations_fail(&guard_bytes, |candidate| {
        RollbackGuard::decode_and_verify(candidate, &keys).map(|_| ())
    });
    let mut bad_guard = guard_bytes;
    let last = bad_guard.len() - 1;
    let byte = bad_guard
        .get_mut(last)
        .ok_or(StorageError::InvalidEncoding)?;
    *byte ^= 1;
    assert!(RollbackGuard::decode_and_verify(&bad_guard, &keys).is_err());
    verify_guard_pair(&header, &reservation, &guard)?;

    let mut guard_mismatches = Vec::new();
    let mut value = guard_tbs;
    value.network_id = NetworkId::from_bytes([90; 32]);
    guard_mismatches.push(value);
    let mut value = guard_tbs;
    value.server_id = ServerId::from_bytes([91; 16]);
    guard_mismatches.push(value);
    let mut value = guard_tbs;
    value.database_instance_id = DatabaseId::from_bytes([92; 16]);
    guard_mismatches.push(value);
    let mut value = guard_tbs;
    value.storage_key_generation = 2;
    guard_mismatches.push(value);
    let mut value = guard_tbs;
    value.recovery_epoch = RecoveryEpoch::from_bytes([93; 16]);
    guard_mismatches.push(value);
    let mut value = guard_tbs;
    value.storage_commit_sequence = 1;
    guard_mismatches.push(value);
    let mut value = guard_tbs;
    value.manifest_sequence = 1;
    guard_mismatches.push(value);
    let mut value = guard_tbs;
    value.state_generation = 1;
    guard_mismatches.push(value);
    let mut value = guard_tbs;
    value.reservation_sequence = 1;
    guard_mismatches.push(value);
    let mut value = guard_tbs;
    value.state_meta_record_id = digest(94);
    guard_mismatches.push(value);
    let mut value = guard_tbs;
    value.nonce_reservation_state_hash = digest(95);
    guard_mismatches.push(value);
    let mut value = guard_tbs;
    value.previous_guard_hash = digest(96);
    guard_mismatches.push(value);
    let mut value = guard_tbs;
    value.database_header_hash = digest(97);
    guard_mismatches.push(value);
    for tbs in guard_mismatches {
        let candidate = RollbackGuard::authenticate(tbs, &keys)?;
        assert_eq!(
            verify_guard_pair(&header, &reservation, &candidate),
            Err(StorageError::StaleState),
        );
    }

    let reserved_tbs = NonceReservationTbs {
        phase: RollbackGuardPhase::NonceReserved,
        reservation_sequence: 1,
        nonce_reservation_start: 10,
        nonce_draw_high_water: 11,
        ..reservation_tbs
    };
    let reserved = NonceReservationState::authenticate(reserved_tbs, &keys)?;
    let reserved_guard = RollbackGuard::authenticate(
        RollbackGuardTbs {
            phase: RollbackGuardPhase::NonceReserved,
            reservation_sequence: 1,
            nonce_reservation_start: 10,
            nonce_draw_high_water: 12,
            nonce_reservation_state_hash: reserved.complete_hash()?,
            ..guard_tbs
        },
        &keys,
    )?;
    assert_eq!(
        verify_guard_pair(&header, &reserved, &reserved_guard),
        Err(StorageError::StaleState),
    );
    Ok(())
}

#[test]
fn mutation_batches_recompute_every_bound_and_read_range() -> Result<(), Box<dyn Error>> {
    let existing = ExistingRecord::new(1, digest(70), MIN_SEALED_RECORD_BYTES)?;
    assert!(ExistingRecord::new(0, digest(70), MIN_SEALED_RECORD_BYTES).is_err());
    assert!(ExistingRecord::new(1, digest(70), MIN_SEALED_RECORD_BYTES - 1).is_err());
    let head = StorageMutationHead {
        transaction_id: TransactionId::from_bytes([71; 16]),
        expected_storage_commit_sequence: 3,
        expected_state_generation: 4,
        resulting_state_generation: 5,
        state_advancing_plan_count: 1,
        expected_account_service_response_count: 6,
        resulting_account_service_response_count: 7,
    };
    let accounting = StorageAccountingLimits {
        current_logical_database_bytes: 1_000_000,
        current_backup_stream_bytes: 2_000_000,
        database_max_bytes: 10_000_000,
        backup_max_bytes: 20_000_000,
    };
    let insert = || {
        RecordMutation::put(
            TableId::Account,
            stored_key(b"insert")?,
            1,
            None,
            b"value".to_vec(),
        )
    };
    let replacement = || {
        RecordMutation::put(
            TableId::Channel,
            stored_key(b"replace")?,
            1,
            Some(existing),
            b"replacement".to_vec(),
        )
    };
    let deletion = || -> Result<RecordMutation, StorageError> {
        Ok(RecordMutation::delete(
            TableId::History,
            stored_key(b"delete")?,
            existing,
        ))
    };
    let accepted = StorageMutationBatch::new(
        head,
        1,
        accounting,
        vec![deletion()?, replacement()?, insert()?],
    )?;
    assert_eq!(accepted.plan_count(), 1);
    assert_eq!(accepted.seal_count(), 4);
    assert_eq!(accepted.mutations().len(), 3);
    assert_eq!(accepted.state_advancing_plan_count(), 1);
    assert_eq!(accepted.resulting_account_service_response_count(), 7);

    assert!(StorageMutationBatch::new(head, 0, accounting, vec![insert()?]).is_err());
    assert!(StorageMutationBatch::new(head, 1, accounting, Vec::new()).is_err());
    assert!(
        StorageMutationBatch::new(
            StorageMutationHead {
                resulting_account_service_response_count: 5,
                ..head
            },
            1,
            accounting,
            vec![insert()?],
        )
        .is_err()
    );
    assert!(
        StorageMutationBatch::new(
            StorageMutationHead {
                resulting_state_generation: 3,
                ..head
            },
            1,
            accounting,
            vec![insert()?],
        )
        .is_err()
    );
    assert!(
        StorageMutationBatch::new(
            StorageMutationHead {
                state_advancing_plan_count: 2,
                resulting_state_generation: 6,
                ..head
            },
            1,
            accounting,
            vec![insert()?],
        )
        .is_err()
    );
    assert!(
        StorageMutationBatch::new(
            StorageMutationHead {
                state_advancing_plan_count: 0,
                ..head
            },
            1,
            accounting,
            vec![insert()?],
        )
        .is_err()
    );
    assert!(
        StorageMutationBatch::new(
            StorageMutationHead {
                resulting_account_service_response_count: 8,
                ..head
            },
            1,
            accounting,
            vec![insert()?],
        )
        .is_err()
    );
    assert!(StorageMutationBatch::new(head, 1, accounting, vec![insert()?, insert()?],).is_err());
    assert!(
        StorageMutationBatch::new(
            head,
            1,
            accounting,
            vec![RecordMutation::put(
                TableId::StateMeta,
                stored_key(b"control")?,
                1,
                None,
                vec![1],
            )?],
        )
        .is_err()
    );
    assert!(
        StorageMutationBatch::new(
            head,
            1,
            accounting,
            vec![RecordMutation::put(
                TableId::StorageConstruction,
                stored_key(b"construction")?,
                1,
                None,
                vec![1],
            )?],
        )
        .is_err()
    );
    assert!(
        StorageMutationBatch::new(
            head,
            1,
            StorageAccountingLimits {
                current_logical_database_bytes: 0,
                current_backup_stream_bytes: 0,
                ..accounting
            },
            vec![deletion()?],
        )
        .is_err()
    );
    assert!(
        StorageMutationBatch::new(
            head,
            1,
            StorageAccountingLimits {
                database_max_bytes: 1,
                ..accounting
            },
            vec![insert()?],
        )
        .is_err()
    );
    assert!(RecordMutation::put(TableId::Account, stored_key(b"zero")?, 0, None, vec![]).is_err());
    assert!(
        RecordMutation::put(
            TableId::Account,
            stored_key(b"schema")?,
            2,
            Some(existing),
            vec![],
        )
        .is_err()
    );

    assert!(ReadPlan::range(TableId::Account, stored_key(b"a")?, stored_key(b"b")?, 1).is_ok());
    assert!(ReadPlan::range(TableId::Account, stored_key(b"b")?, stored_key(b"a")?, 1).is_err());
    assert!(ReadPlan::range(TableId::Account, stored_key(b"a")?, stored_key(b"b")?, 0).is_err());
    assert!(
        ReadPlan::range(
            TableId::Account,
            stored_key(b"a")?,
            stored_key(b"b")?,
            4_097
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn mutation_batches_reject_each_independent_admission_boundary() -> Result<(), Box<dyn Error>> {
    let existing = ExistingRecord::new(1, digest(80), MIN_SEALED_RECORD_BYTES)?;
    assert_eq!(existing.record_schema(), 1);
    assert_eq!(existing.sealed_record_id(), digest(80));
    assert_eq!(
        usize::try_from(existing.sealed_record_bytes())?,
        MIN_SEALED_RECORD_BYTES
    );
    assert!(ExistingRecord::new(1, digest(80), MAX_SEALED_RECORD_BYTES + 1).is_err());

    let head = StorageMutationHead {
        transaction_id: TransactionId::from_bytes([81; 16]),
        expected_storage_commit_sequence: 3,
        expected_state_generation: 4,
        resulting_state_generation: 5,
        state_advancing_plan_count: 1,
        expected_account_service_response_count: 6,
        resulting_account_service_response_count: 6,
    };
    let accounting = StorageAccountingLimits {
        current_logical_database_bytes: 100_000_000,
        current_backup_stream_bytes: 100_000_000,
        database_max_bytes: 1_000_000_000,
        backup_max_bytes: 1_000_000_000,
    };
    let insert = |table: TableId, key: Vec<u8>| {
        RecordMutation::put(table, StoredKey::new(key)?, 1, None, vec![1])
    };
    let delete = |table: TableId, key: Vec<u8>| -> Result<RecordMutation, StorageError> {
        Ok(RecordMutation::delete(
            table,
            StoredKey::new(key)?,
            existing,
        ))
    };

    assert!(
        StorageMutationBatch::new(
            head,
            agenc_ircd_storage::MAX_TRANSACTION_PLANS + 1,
            accounting,
            vec![insert(TableId::Account, b"plan-overflow".to_vec())?],
        )
        .is_err()
    );
    let excessive_mutations = (0..=agenc_ircd_storage::MAX_TRACKED_MUTATIONS)
        .map(|index| insert(TableId::Account, index.to_be_bytes().to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(StorageMutationBatch::new(head, 1, accounting, excessive_mutations).is_err());
    assert!(
        StorageMutationBatch::new(
            StorageMutationHead {
                state_advancing_plan_count: 2,
                resulting_state_generation: 6,
                ..head
            },
            1,
            accounting,
            vec![insert(TableId::Account, b"too-many-advancing".to_vec())?],
        )
        .is_err()
    );
    assert!(
        StorageMutationBatch::new(
            StorageMutationHead {
                resulting_state_generation: 6,
                ..head
            },
            2,
            accounting,
            vec![insert(
                TableId::Account,
                b"wrong-generation-delta".to_vec()
            )?],
        )
        .is_err()
    );
    assert!(
        StorageMutationBatch::new(
            StorageMutationHead {
                resulting_account_service_response_count: 9,
                ..head
            },
            2,
            accounting,
            vec![insert(TableId::Account, b"response-delta".to_vec())?],
        )
        .is_err()
    );
    assert!(
        StorageMutationBatch::new(
            head,
            1,
            accounting,
            vec![insert(TableId::KeyCheck, b"untracked".to_vec())?],
        )
        .is_err()
    );
    assert!(
        StorageMutationBatch::new(
            head,
            1,
            StorageAccountingLimits {
                backup_max_bytes: 1,
                ..accounting
            },
            vec![insert(TableId::Account, b"backup-limit".to_vec())?],
        )
        .is_err()
    );
    let maximum_plaintext = vec![0_u8; agenc_ircd_crypto::MAX_STORAGE_PLAINTEXT_BYTES];
    assert!(
        StorageMutationBatch::new(
            head,
            1,
            accounting,
            vec![RecordMutation::put(
                TableId::Account,
                stored_key(b"tracked-byte-limit")?,
                1,
                None,
                maximum_plaintext,
            )?],
        )
        .is_err()
    );
    assert!(
        RecordMutation::put(
            TableId::Account,
            stored_key(b"plaintext-overflow")?,
            1,
            None,
            vec![0; agenc_ircd_crypto::MAX_STORAGE_PLAINTEXT_BYTES + 1],
        )
        .is_err()
    );

    let stable_head = StorageMutationHead {
        resulting_state_generation: head.expected_state_generation,
        state_advancing_plan_count: 0,
        ..head
    };
    let cursor = || insert(TableId::Audit, b"cursor".to_vec());
    assert!(
        StorageMutationBatch::retention_deletion(stable_head, accounting, cursor()?, Vec::new())
            .is_err()
    );
    assert!(
        StorageMutationBatch::retention_deletion(
            stable_head,
            accounting,
            cursor()?,
            vec![insert(TableId::Audit, b"not-a-deletion".to_vec())?],
        )
        .is_err()
    );
    assert!(
        StorageMutationBatch::retention_deletion(
            stable_head,
            accounting,
            delete(TableId::Audit, b"deleting-cursor".to_vec())?,
            vec![delete(TableId::Audit, b"deletion".to_vec())?],
        )
        .is_err()
    );
    for invalid_head in [
        StorageMutationHead {
            resulting_state_generation: stable_head.expected_state_generation + 1,
            ..stable_head
        },
        StorageMutationHead {
            resulting_account_service_response_count: stable_head
                .expected_account_service_response_count
                + 1,
            ..stable_head
        },
        StorageMutationHead {
            state_advancing_plan_count: 1,
            ..stable_head
        },
    ] {
        assert!(
            StorageMutationBatch::retention_deletion(
                invalid_head,
                accounting,
                cursor()?,
                vec![delete(TableId::Audit, b"deletion".to_vec())?],
            )
            .is_err()
        );
    }
    let too_many_deletions = (0..=agenc_ircd_storage::MAX_RETENTION_DELETIONS)
        .map(|index| delete(TableId::Audit, index.to_be_bytes().to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(
        StorageMutationBatch::retention_deletion(
            stable_head,
            accounting,
            cursor()?,
            too_many_deletions,
        )
        .is_err()
    );
    let retention = StorageMutationBatch::retention_deletion(
        stable_head,
        accounting,
        cursor()?,
        vec![delete(TableId::Audit, b"deletion".to_vec())?],
    )?;
    assert_eq!(retention.transaction_id(), stable_head.transaction_id);
    assert_eq!(
        retention.expected_storage_commit_sequence(),
        stable_head.expected_storage_commit_sequence
    );
    assert_eq!(
        retention.expected_state_generation(),
        stable_head.expected_state_generation
    );
    assert_eq!(
        retention.resulting_state_generation(),
        stable_head.resulting_state_generation
    );
    assert_eq!(
        retention.expected_account_service_response_count(),
        stable_head.expected_account_service_response_count
    );
    assert_eq!(
        retention.expected_logical_database_bytes(),
        accounting.current_logical_database_bytes
    );
    assert_eq!(
        retention.expected_backup_stream_bytes(),
        accounting.current_backup_stream_bytes
    );
    assert_ne!(
        retention.resulting_logical_database_bytes(),
        retention.expected_logical_database_bytes()
    );
    assert_ne!(
        retention.resulting_backup_stream_bytes(),
        retention.expected_backup_stream_bytes()
    );

    for mutations in [
        vec![insert(TableId::LoginIndex, b"only-insert".to_vec())?],
        vec![delete(TableId::LoginIndex, b"only-delete".to_vec())?],
        vec![
            delete(TableId::LoginIndex, b"old".to_vec())?,
            insert(TableId::LoginIndex, b"new".to_vec())?,
        ],
    ] {
        assert!(
            StorageMutationBatch::new_login_index_lazy(stable_head, 1, accounting, mutations,)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn domain_record_envelope_covers_every_union_and_length_boundary() -> Result<(), Box<dyn Error>> {
    let kinds = [
        (TableId::Account, 2),
        (TableId::OpaqueRecord, 2),
        (TableId::AuthTransaction, 4),
        (TableId::NicknameReservation, 2),
        (TableId::RegistrationInvite, 2),
        (TableId::Session, 2),
        (TableId::Channel, 3),
        (TableId::ChannelName, 2),
        (TableId::Sanction, 4),
        (TableId::FederationPeer, 2),
        (TableId::FederationOrigin, 2),
        (TableId::RequestResult, 4),
        (TableId::EdgeOutbox, 3),
        (TableId::EdgeProjection, 3),
        (TableId::History, 1),
        (TableId::Audit, 1),
        (TableId::AuditCheckpoint, 1),
        (TableId::E2eeObject, 1),
        (TableId::E2eeState, 12),
    ];
    for (table, maximum_kind) in kinds {
        for kind in 1..=maximum_kind {
            let body = if table == TableId::E2eeState && kind == 1 {
                agenc_ircd_storage::E2eeRecoveryGate::new(
                    digest(90),
                    agenc_ircd_storage::E2eeRecoveryKind::Normal,
                    RecoveryEpoch::from_bytes([91; 16]),
                    digest(92),
                    digest(93),
                    digest(94),
                    digest(95),
                )
                .encode()?
            } else {
                domain_body(table, kind, u8::try_from(kind)?)?
            };
            let value = agenc_ircd_storage::PersistentRecordValue::new(
                table,
                kind,
                1,
                1,
                Some(100),
                Vec::new(),
                body,
            )?;
            let encoded = value.encode()?;
            let decoded = agenc_ircd_storage::PersistentRecordValue::decode(table, &encoded)?;
            assert_eq!(decoded.table(), table);
            assert_eq!(decoded.record_kind(), kind);
            assert_eq!(decoded.revision(), 1);
            assert_eq!(decoded.generation(), 1);
            assert_eq!(decoded.expires_at(), Some(100));
            assert!(!decoded.body().is_empty());
        }
    }

    let canonical_account_key = account_key(1);
    let account = RecordReference::new(TableId::Account, stored_key(&canonical_account_key)?)?;
    let session = RecordReference::new(TableId::Session, stored_key(&[b's'; 16])?)?;
    assert_eq!(account.table(), TableId::Account);
    assert_eq!(account.key().as_bytes(), canonical_account_key);
    let ordered = agenc_ircd_storage::PersistentRecordValue::new(
        TableId::Channel,
        1,
        1,
        0,
        None,
        vec![session, account],
        crate::domain_records::live_body(TableId::Channel, 1)?,
    )?;
    let ordered =
        agenc_ircd_storage::PersistentRecordValue::decode(TableId::Channel, &ordered.encode()?)?;
    assert_eq!(
        ordered.references().first().map(RecordReference::table),
        Some(TableId::Account)
    );

    let base = agenc_ircd_storage::PersistentRecordValue::new(
        TableId::Audit,
        1,
        1,
        0,
        None,
        Vec::new(),
        vec![1],
    )?
    .encode()?;
    let mut noncanonical_absent_expiry = base.clone();
    noncanonical_absent_expiry
        .get_mut(22..30)
        .ok_or("missing expiry bytes")?
        .copy_from_slice(&1_u64.to_be_bytes());
    assert!(
        agenc_ircd_storage::PersistentRecordValue::decode(
            TableId::Audit,
            &noncanonical_absent_expiry,
        )
        .is_err()
    );
    let mut unknown_expiry_arm = base.clone();
    unknown_expiry_arm
        .get_mut(20..22)
        .ok_or("missing expiry discriminator")?
        .copy_from_slice(&2_u16.to_be_bytes());
    assert!(
        agenc_ircd_storage::PersistentRecordValue::decode(TableId::Audit, &unknown_expiry_arm,)
            .is_err()
    );
    let mut excessive_reference_count = base;
    excessive_reference_count
        .get_mut(30..34)
        .ok_or("missing reference count")?
        .copy_from_slice(
            &u32::try_from(agenc_ircd_storage::MAX_RECORD_REFERENCES + 1)?.to_be_bytes(),
        );
    assert!(
        agenc_ircd_storage::PersistentRecordValue::decode(
            TableId::Audit,
            &excessive_reference_count,
        )
        .is_err()
    );
    let too_many_references = (0..=agenc_ircd_storage::MAX_RECORD_REFERENCES)
        .map(|_| {
            let key = account_key(1);
            RecordReference::new(TableId::Account, stored_key(&key)?)
        })
        .collect::<Result<Vec<_>, StorageError>>()?;
    assert!(
        agenc_ircd_storage::PersistentRecordValue::new(
            TableId::Audit,
            1,
            1,
            0,
            None,
            too_many_references,
            vec![1],
        )
        .is_err()
    );
    assert!(
        agenc_ircd_storage::PersistentRecordValue::new(
            TableId::Audit,
            1,
            1,
            0,
            None,
            Vec::new(),
            vec![0; agenc_ircd_storage::MAX_DOMAIN_RECORD_BODY_BYTES + 1],
        )
        .is_err()
    );
    assert!(
        agenc_ircd_storage::PersistentRecordValue::new(
            TableId::E2eeState,
            1,
            1,
            0,
            None,
            Vec::new(),
            vec![1],
        )
        .is_err()
    );
    assert_eq!(
        validate_record_plaintext(
            TableId::KeyCheck,
            &stored_key(agenc_ircd_storage::KEY_CHECK_STORED_KEY)?,
            1,
            &[0; 32],
        ),
        Ok(())
    );
    assert!(
        validate_record_plaintext(
            TableId::KeyCheck,
            &stored_key(agenc_ircd_storage::KEY_CHECK_STORED_KEY)?,
            1,
            &[0; 31],
        )
        .is_err()
    );
    assert!(
        validate_record_plaintext(
            TableId::StateMeta,
            &stored_key(agenc_ircd_storage::STATE_META_STORED_KEY)?,
            1,
            &[0; agenc_ircd_storage::STATE_META_BYTES - 1],
        )
        .is_err()
    );
    Ok(())
}
