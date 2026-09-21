//! Sealed source pairing and complete signed-backup restore of recovery provenance.
//! Route objects are public typed fixtures; these tests do not validate MLS endpoints.
#![forbid(unsafe_code)]
use super::*;
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::conversation::ArcConversationKind;
use agenc_relay_e2ee::objects::federation::{ArcFederationRouteState, ArcRouteStateKind};
use agenc_relay_e2ee::tls::{Opaque, TlsEncode};
use agenc_relay_storage::e2ee_records::{
    RECOVERY_GATE_KIND, ROUTE_ROW_KIND, RouteLifecycle, RouteRow, recovery_gate_key,
};
use agenc_relay_storage::{
    AuthenticatedSourceRecord, ConstructionSourceFacts, SourceRecordValidator,
};

const CONVERSATION: [u8; 32] = [80; 32];

fn route(network: [u8; 32], closed: bool) -> Result<RouteRow, Box<dyn Error>> {
    let mut row = RouteRow::decode(&agenc_relay_storage::e2ee_records::fixtures::state_body(
        ROUTE_ROW_KIND,
        19,
    )?)?;
    row.binding_id = [81; 32];
    row.accepted_state_id = [82; 32];
    row.sequencer_head_id = [83; 32];
    row.recovery_gate = false;
    row.lifecycle = if closed {
        RouteLifecycle::Tombstone
    } else {
        RouteLifecycle::Active
    };
    row.close_id = closed.then_some([84; 32]);
    let state = ArcFederationRouteState {
        profile_version: 1,
        network_id: network,
        state_generation: 0,
        conversation_id: CONVERSATION,
        conversation_kind: ArcConversationKind::Channel,
        route_binding: [19; 32],
        semantic_route_lock_id: row.lock_id,
        channel_instance_id: Opaque::new(vec![24; 16])?,
        canonical_channel_name_hash: [25; 32],
        direct_account_a: Opaque::new(Vec::new())?,
        direct_account_b: Opaque::new(Vec::new())?,
        binding_id: row.binding_id,
        finalized_epoch: 1,
        accepted_state_id: row.accepted_state_id,
        sequencer_record_head_sequence: row.route_sequence,
        sequencer_record_head_id: row.sequencer_head_id,
        state: if closed {
            ArcRouteStateKind::EncryptedTombstone
        } else {
            ArcRouteStateKind::ActiveRoute
        },
    };
    row.route_state =
        ArcWireObject::new(ArcWireObjectKind::FederationState, state.encode()?)?.encode()?;
    Ok(row)
}

fn persistent(kind: u16, body: Vec<u8>) -> Result<Vec<u8>, StorageError> {
    PersistentRecordValue::new(TableId::E2eeState, kind, 3, 0, None, Vec::new(), body)?.encode()
}

pub(super) fn verify_sealed_gate_pair(
    master: &StorageMasterKey,
    binding: DatabaseBinding,
) -> Result<(), Box<dyn Error>> {
    let route = route([70; 32], false)?;
    let gate = E2eeRecoveryGate::new(
        digest(80),
        E2eeRecoveryKind::Normal,
        RecoveryEpoch::from_bytes([80; 16]),
        digest(91),
        digest(92),
        digest(93),
        digest(84),
    );
    let mut references = Vec::new();
    let mut sources = Vec::new();
    for (kind, key, body, nonce) in [
        (
            RECOVERY_GATE_KIND,
            recovery_gate_key(&CONVERSATION)?,
            gate.encode()?,
            81,
        ),
        (
            ROUTE_ROW_KIND,
            RouteRow::key(&CONVERSATION)?,
            route.encode()?,
            82,
        ),
    ] {
        let sealed = StorageSealContext::new(master, binding, 1)?
            .seal(
                TableId::E2eeState,
                1,
                [nonce; 24],
                &key,
                &persistent(kind, body)?,
            )?
            .encode()?;
        let reference = StorageConstructionSource::new(
            StorageConstructionSourceKind::BackupRecord,
            TableId::E2eeState,
            key,
            1,
            SealedRecord::decode(&sealed)?.record_id()?,
            u64::from(nonce),
        )?;
        sources.push(ConstructionSourceRecord::open(
            &reference, &sealed, master, binding, 1,
        )?);
        references.push(reference);
    }
    let entry = StorageConstructionPlanEntry::new(
        StorageConstructionKind::Restore,
        references,
        TableId::E2eeState,
        recovery_gate_key(&CONVERSATION)?,
        1,
        StorageConstructionAction::RestoreE2eeState,
        0,
    )?;
    let target_epoch = RecoveryEpoch::from_bytes([82; 16]);
    let source_guard = digest(85);
    let encoded = RecoveryTransformV1::new(target_epoch, source_guard).transform(
        StorageConstructionKind::Restore,
        &entry,
        &sources,
    )?;
    let value = PersistentRecordValue::decode(TableId::E2eeState, &encoded)?;
    let restored = E2eeRecoveryGate::decode(value.body())?;
    assert_eq!(restored.state(), E2eeRecoveryKind::Pending);
    assert_eq!(restored.recovery_epoch(), target_epoch);
    assert_eq!(restored.source_rollback_guard_hash(), source_guard);
    assert_heads(restored, &route);
    Ok(())
}

#[derive(Clone, Copy)]
enum Case {
    NormalMissing,
    NormalOlder,
    PendingMatching,
    PendingMissing,
    Closed,
    Conflict,
    TerminalMissing,
}

struct Initial {
    records: Vec<InitialStorageRecord>,
    route: RouteRow,
    gate: Option<E2eeRecoveryGate>,
}

fn initial(case: Case) -> Result<Initial, Box<dyn Error>> {
    let mut route = route(
        [201; 32],
        matches!(case, Case::Closed | Case::TerminalMissing),
    )?;
    route.recovery_gate = matches!(
        case,
        Case::PendingMatching | Case::PendingMissing | Case::Conflict
    );
    let gate = match case {
        Case::NormalMissing | Case::PendingMissing | Case::TerminalMissing => None,
        _ => Some(E2eeRecoveryGate::new(
            digest(80),
            match case {
                Case::NormalOlder => E2eeRecoveryKind::Normal,
                Case::Closed => E2eeRecoveryKind::Closed,
                Case::Conflict => E2eeRecoveryKind::Conflict,
                _ => E2eeRecoveryKind::Pending,
            },
            RecoveryEpoch::from_bytes([206; 16]),
            StorageDigest::from_bytes(route.binding_id),
            if matches!(case, Case::NormalOlder) {
                digest(92)
            } else {
                StorageDigest::from_bytes(route.accepted_state_id)
            },
            if matches!(case, Case::NormalOlder) {
                digest(93)
            } else {
                StorageDigest::from_bytes(route.sequencer_head_id)
            },
            digest(219),
        )),
    };
    let key = LoginIndexKey::from_bytes([203; 32]);
    let state = LoginIndexKeyState::stable(1, key.key_id(NetworkId::from_bytes([201; 32])))?;
    let mut records = vec![
        InitialStorageRecord::new(
            TableId::LoginIndexKeyState,
            StoredKey::new(agenc_relay_storage::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
            1,
            state.encode()?,
        )?,
        InitialStorageRecord::new(
            TableId::E2eeState,
            RouteRow::key(&CONVERSATION)?,
            1,
            persistent(ROUTE_ROW_KIND, route.encode()?)?,
        )?,
    ];
    if let Some(gate) = gate {
        records.push(InitialStorageRecord::new(
            TableId::E2eeState,
            recovery_gate_key(&CONVERSATION)?,
            1,
            persistent(RECOVERY_GATE_KIND, gate.encode()?)?,
        )?);
    }
    Ok(Initial {
        records,
        route,
        gate,
    })
}

#[derive(Default)]
struct Restored {
    gate: Option<E2eeRecoveryGate>,
    route: Option<RouteRow>,
}

impl SourceRecordValidator for Restored {
    fn begin_source(&mut self, _: &ConstructionSourceFacts) -> Result<(), StorageError> {
        Ok(())
    }
    fn validate_record(
        &mut self,
        record: AuthenticatedSourceRecord<'_>,
    ) -> Result<(), StorageError> {
        if record.table() != TableId::E2eeState {
            return Ok(());
        }
        let value = PersistentRecordValue::decode(record.table(), record.plaintext())?;
        match value.record_kind() {
            RECOVERY_GATE_KIND => {
                assert!(
                    self.gate
                        .replace(E2eeRecoveryGate::decode(value.body())?)
                        .is_none()
                );
            }
            ROUTE_ROW_KIND => {
                assert!(
                    self.route
                        .replace(RouteRow::decode(value.body())?)
                        .is_none()
                );
            }
            _ => return Err(StorageError::StaleState),
        }
        Ok(())
    }
    fn finish_source(&mut self) -> Result<(), StorageError> {
        Ok(())
    }
}

fn assert_heads(gate: E2eeRecoveryGate, route: &RouteRow) {
    assert_eq!(gate.restored_binding_id().as_bytes(), &route.binding_id);
    assert_eq!(
        gate.restored_accepted_state_id().as_bytes(),
        &route.accepted_state_id
    );
    assert_eq!(
        gate.restored_sequencer_head_id().as_bytes(),
        &route.sequencer_head_id
    );
}

#[test]
fn signed_backup_restore_installs_exact_route_provenance_and_preserves_blocked_lineages()
-> Result<(), Box<dyn Error>> {
    for case in [
        Case::NormalMissing,
        Case::NormalOlder,
        Case::PendingMatching,
        Case::PendingMissing,
        Case::Closed,
        Case::Conflict,
        Case::TerminalMissing,
    ] {
        restore_case(case)?;
    }
    Ok(())
}

fn restore_case(case: Case) -> Result<(), Box<dyn Error>> {
    let Initial {
        records,
        route: mut expected_route,
        gate: original_gate,
    } = initial(case)?;
    let source = initialized_live_fixture_from(records)?;
    let owner = StorageOwner::start(live_open_config(StateDirectory::open(
        source.directory.path(),
        &[source.qualification],
    )?))?;
    let directory = TestDirectory::create()?;
    let signer = Ed25519SecretKey::from_bytes([151; 32]);
    let public = signer.public_key();
    let backup_path = directory.path().join("source.agenc");
    owner
        .port()
        .try_backup(
            BackupDestination::new(directory.path(), "source.agenc")?,
            signer,
            1_000,
            [152; 16],
        )?
        .wait()?;
    owner.shutdown()?;
    let verified = verify_backup(
        fs::File::open(&backup_path)?,
        &StorageMasterKey::from_bytes([207; 32]),
        &RollbackGuardRootKey::from_bytes([208; 32]),
        &[BackupTrustKey::new(public)?],
        test_limits().backup_max_bytes,
    )?;
    let source_guard_hash = verified.header.source_rollback_guard().complete_hash()?;
    let master = protected_key_file(directory.path(), "master.key", [207; 32])?;
    let guard = protected_key_file(directory.path(), "source-guard.key", [208; 32])?;
    let login = protected_key_file(directory.path(), "login.key", [203; 32])?;
    let target_guard = protected_key_file(directory.path(), "target-guard.key", [153; 32])?;
    let output = directory.path().join("restored");
    let trusted_key_id = BackupTrustKey::new(public)?.key_id;
    let request = |resume| RestoreCommandRequest {
        network_id: NetworkId::from_bytes([201; 32]),
        server_id: ServerId::from_bytes([202; 16]),
        current_state_directory: source.directory.path().to_path_buf(),
        current_master_key_file: master.clone(),
        current_rollback_guard_key_file: guard.clone(),
        backup_path: backup_path.clone(),
        source_master_key_file: master.clone(),
        source_rollback_guard_key_file: guard.clone(),
        login_index_key_file: login.clone(),
        login_index_previous_key_file: None,
        output_state_directory: output.clone(),
        target_rollback_guard_key_file: target_guard.clone(),
        target_master_key_file: None,
        resume,
        declare_recovery_epoch: true,
        trusted_backup_keys: vec![RestoreTrustKey::new(
            *trusted_key_id.as_bytes(),
            *public.as_bytes(),
            900,
            1_100,
        )],
        limits: test_limits(),
    };
    if original_gate.is_none() {
        assert!(execute_restore_command(request(false), &[source.qualification]).is_err());
        assert!(
            !output.exists(),
            "a restore without a declaration cannot install a database"
        );
        return Ok(());
    }
    let receipt = execute_restore_command(request(false), &[source.qualification])?;
    assert_eq!(
        execute_restore_command(request(true), &[source.qualification])?,
        receipt
    );
    let mut config = live_open_config(StateDirectory::open(&output, &[source.qualification])?);
    config.rollback_guard_root_key = RollbackGuardRootKey::from_bytes([153; 32]);
    let restored = ConstructionSourceDatabase::open(config)?;
    assert_eq!(
        restored.facts()?.header.tbs().recovery_epoch,
        receipt.target_recovery_epoch
    );
    let mut captured = Restored::default();
    restored.validate_source_records(&mut captured)?;
    if expected_route.lifecycle != RouteLifecycle::Tombstone {
        expected_route.recovery_gate = true;
    }
    assert_eq!(captured.route.as_ref(), Some(&expected_route));
    if matches!(case, Case::Closed | Case::Conflict) {
        assert_eq!(captured.gate, original_gate);
    } else {
        let gate = captured.gate.ok_or("restored gate")?;
        assert_eq!(gate.state(), E2eeRecoveryKind::Pending);
        assert_eq!(gate.recovery_epoch(), receipt.target_recovery_epoch);
        assert_eq!(gate.source_rollback_guard_hash(), source_guard_hash);
        assert_heads(gate, &expected_route);
    }
    Ok(())
}
