#![forbid(unsafe_code)]

use agenc_ircd_crypto::{
    RollbackGuardRootKey, StorageDigest, StorageIntegrityContext, StorageIntegrityKeys,
    derive_storage_integrity_keys,
};
use agenc_ircd_storage::{
    DatabaseHeader, DatabaseHeaderTbs, NonceReservationState, NonceReservationTbs,
    RecoveryDisposition, RollbackGuard, RollbackGuardPhase, RollbackGuardTbs, SCHEMA_GENERATION,
    StateMeta, StateMetaTbs, StorageError, classify_recovery_state,
};
use agenc_ircd_types::{DatabaseId, NetworkId, RecoveryEpoch, ServerId, ServerIncarnation};

const ZERO: StorageDigest = StorageDigest::from_bytes([0; 32]);
const STATE_RECORD_ID: StorageDigest = StorageDigest::from_bytes([7; 32]);

struct RecoveryFixture {
    header: DatabaseHeader,
    keys: StorageIntegrityKeys,
}

#[derive(Clone, Copy)]
struct ReservationFields {
    sequence: u64,
    phase: RollbackGuardPhase,
    start: u64,
    end: u64,
    commit: u64,
    manifest: u64,
    generation: u64,
    previous_guard_hash: StorageDigest,
}

impl RecoveryFixture {
    fn new() -> Result<Self, StorageError> {
        let tbs = DatabaseHeaderTbs::new(
            NetworkId::from_bytes([1; 32]),
            ServerId::from_bytes([2; 16]),
            ServerIncarnation::from_bytes([3; 16]),
            DatabaseId::from_bytes([4; 16]),
            1,
            SCHEMA_GENERATION,
            RecoveryEpoch::from_bytes([5; 16]),
        )?;
        let header = DatabaseHeader::new(tbs, StorageDigest::from_bytes([6; 32]));
        let keys = derive_storage_integrity_keys(
            &RollbackGuardRootKey::from_bytes([8; 32]),
            StorageIntegrityContext::new(tbs.network_id, tbs.server_id, tbs.database_instance_id),
        )?;
        Ok(Self { header, keys })
    }

    fn state(
        &self,
        storage_commit_sequence: u64,
        manifest_sequence: u64,
        state_generation: u64,
        nonce_draw_high_water: u64,
        previous_guard_hash: StorageDigest,
    ) -> Result<StateMeta, StorageError> {
        StateMeta::authenticate(
            StateMetaTbs {
                storage_commit_sequence,
                manifest_sequence,
                state_generation,
                account_service_response_count: 0,
                nonce_draw_high_water,
                logical_database_bytes: 1_024,
                backup_stream_bytes: 2_048,
                checkpoint_manifest_sequence: 0,
                latest_manifest_hash: ZERO,
                checkpoint_hash: ZERO,
                previous_rollback_guard_hash: previous_guard_hash,
            },
            self.header.complete_hash()?,
            &self.keys,
        )
    }

    fn reservation_tbs(
        &self,
        fields: ReservationFields,
    ) -> Result<NonceReservationTbs, StorageError> {
        Ok(NonceReservationTbs {
            database_instance_id: self.header.tbs().database_instance_id,
            reservation_sequence: fields.sequence,
            phase: fields.phase,
            nonce_reservation_start: fields.start,
            nonce_draw_high_water: fields.end,
            storage_commit_sequence: fields.commit,
            manifest_sequence: fields.manifest,
            state_generation: fields.generation,
            database_header_hash: self.header.complete_hash()?,
            state_meta_record_id: STATE_RECORD_ID,
            previous_guard_hash: fields.previous_guard_hash,
        })
    }

    fn reservation(
        &self,
        fields: ReservationFields,
    ) -> Result<NonceReservationState, StorageError> {
        NonceReservationState::authenticate(self.reservation_tbs(fields)?, &self.keys)
    }

    fn guard(&self, reservation: &NonceReservationState) -> Result<RollbackGuard, StorageError> {
        let source = reservation.tbs();
        self.authenticate_guard(RollbackGuardTbs {
            network_id: self.header.tbs().network_id,
            server_id: self.header.tbs().server_id,
            database_instance_id: source.database_instance_id,
            storage_key_generation: self.header.tbs().storage_key_generation,
            schema_generation: self.header.tbs().schema_generation,
            recovery_epoch: self.header.tbs().recovery_epoch,
            storage_commit_sequence: source.storage_commit_sequence,
            manifest_sequence: source.manifest_sequence,
            state_generation: source.state_generation,
            phase: source.phase,
            reservation_sequence: source.reservation_sequence,
            nonce_reservation_start: source.nonce_reservation_start,
            nonce_draw_high_water: source.nonce_draw_high_water,
            database_header_hash: source.database_header_hash,
            state_meta_record_id: source.state_meta_record_id,
            nonce_reservation_state_hash: reservation.complete_hash()?,
            previous_guard_hash: source.previous_guard_hash,
        })
    }

    fn authenticate_guard(&self, tbs: RollbackGuardTbs) -> Result<RollbackGuard, StorageError> {
        RollbackGuard::authenticate(tbs, &self.keys)
    }
}

fn committed_fields() -> ReservationFields {
    ReservationFields {
        sequence: 0,
        phase: RollbackGuardPhase::Committed,
        start: 10,
        end: 10,
        commit: 0,
        manifest: 0,
        generation: 0,
        previous_guard_hash: ZERO,
    }
}

fn assert_stale(
    fixture: &RecoveryFixture,
    state: &StateMeta,
    reservation: &NonceReservationState,
    guard: &RollbackGuard,
) {
    assert_eq!(
        classify_recovery_state(&fixture.header, state, STATE_RECORD_ID, reservation, guard,),
        Err(StorageError::StaleState),
    );
}

#[test]
fn public_recovery_classifier_covers_the_complete_authenticated_matrix() -> Result<(), StorageError>
{
    let fixture = RecoveryFixture::new()?;
    let old_state = fixture.state(0, 0, 0, 10, ZERO)?;
    let committed = fixture.reservation(committed_fields())?;
    let committed_guard = fixture.guard(&committed)?;
    assert_eq!(
        classify_recovery_state(
            &fixture.header,
            &old_state,
            STATE_RECORD_ID,
            &committed,
            &committed_guard,
        )?,
        RecoveryDisposition::ExactCommitted,
    );

    let committed_guard_hash = committed_guard.complete_hash()?;
    let reserved_fields = ReservationFields {
        sequence: 1,
        phase: RollbackGuardPhase::NonceReserved,
        start: 10,
        end: 13,
        commit: 0,
        manifest: 0,
        generation: 0,
        previous_guard_hash: committed_guard_hash,
    };
    let reserved = fixture.reservation(reserved_fields)?;
    assert_eq!(
        classify_recovery_state(
            &fixture.header,
            &old_state,
            STATE_RECORD_ID,
            &reserved,
            &committed_guard,
        )?,
        RecoveryDisposition::InstallReservedGuard,
    );
    let reserved_guard = fixture.guard(&reserved)?;
    assert_eq!(
        classify_recovery_state(
            &fixture.header,
            &old_state,
            STATE_RECORD_ID,
            &reserved,
            &reserved_guard,
        )?,
        RecoveryDisposition::ExactReserved,
    );

    for mismatched_state in [
        fixture.state(1, 0, 0, 10, ZERO)?,
        fixture.state(0, 1, 0, 10, ZERO)?,
        fixture.state(0, 0, 1, 10, ZERO)?,
        fixture.state(0, 0, 0, 11, ZERO)?,
    ] {
        assert_stale(&fixture, &mismatched_state, &reserved, &committed_guard);
    }
    assert_eq!(
        classify_recovery_state(
            &fixture.header,
            &old_state,
            StorageDigest::from_bytes([77; 32]),
            &reserved,
            &committed_guard,
        ),
        Err(StorageError::StaleState),
    );

    let mut invalid_successors = Vec::new();
    let mut wrong_instance = fixture.reservation_tbs(reserved_fields)?;
    wrong_instance.database_instance_id = DatabaseId::from_bytes([91; 16]);
    invalid_successors.push(wrong_instance);
    let mut wrong_header = fixture.reservation_tbs(reserved_fields)?;
    wrong_header.database_header_hash = StorageDigest::from_bytes([92; 32]);
    invalid_successors.push(wrong_header);
    let mut wrong_record = fixture.reservation_tbs(reserved_fields)?;
    wrong_record.state_meta_record_id = StorageDigest::from_bytes([93; 32]);
    invalid_successors.push(wrong_record);
    for mutate in [
        |fields: &mut NonceReservationTbs| fields.reservation_sequence = 2,
        |fields: &mut NonceReservationTbs| {
            fields.phase = RollbackGuardPhase::Committed;
            fields.nonce_draw_high_water = fields.nonce_reservation_start;
        },
        |fields: &mut NonceReservationTbs| fields.nonce_reservation_start = 11,
        |fields: &mut NonceReservationTbs| fields.storage_commit_sequence = 1,
        |fields: &mut NonceReservationTbs| fields.manifest_sequence = 1,
        |fields: &mut NonceReservationTbs| fields.state_generation = 1,
        |fields: &mut NonceReservationTbs| fields.previous_guard_hash = ZERO,
    ] {
        let mut candidate = fixture.reservation_tbs(reserved_fields)?;
        mutate(&mut candidate);
        invalid_successors.push(candidate);
    }
    for candidate in invalid_successors {
        assert_stale(
            &fixture,
            &old_state,
            &NonceReservationState::authenticate(candidate, &fixture.keys)?,
            &committed_guard,
        );
    }

    let mut wrong_external_instance = *committed_guard.tbs();
    wrong_external_instance.database_instance_id = DatabaseId::from_bytes([94; 16]);
    assert_stale(
        &fixture,
        &old_state,
        &reserved,
        &fixture.authenticate_guard(wrong_external_instance)?,
    );
    let mut wrong_external_header = *committed_guard.tbs();
    wrong_external_header.database_header_hash = StorageDigest::from_bytes([95; 32]);
    assert_stale(
        &fixture,
        &old_state,
        &reserved,
        &fixture.authenticate_guard(wrong_external_header)?,
    );
    let mut exhausted_sequence = *committed_guard.tbs();
    exhausted_sequence.reservation_sequence = u64::MAX;
    assert_eq!(
        classify_recovery_state(
            &fixture.header,
            &old_state,
            STATE_RECORD_ID,
            &reserved,
            &fixture.authenticate_guard(exhausted_sequence)?,
        ),
        Err(StorageError::Overflow),
    );

    let reserved_guard_hash = reserved_guard.complete_hash()?;
    let application_fields = ReservationFields {
        sequence: 1,
        phase: RollbackGuardPhase::Committed,
        start: 13,
        end: 13,
        commit: 1,
        manifest: 1,
        generation: 1,
        previous_guard_hash: reserved_guard_hash,
    };
    let application = fixture.reservation(application_fields)?;
    let application_state = fixture.state(1, 1, 1, 13, reserved_guard_hash)?;
    assert_eq!(
        classify_recovery_state(
            &fixture.header,
            &application_state,
            STATE_RECORD_ID,
            &application,
            &reserved_guard,
        )?,
        RecoveryDisposition::InstallCommittedGuard,
    );
    let checkpoint = fixture.reservation(ReservationFields {
        manifest: 0,
        generation: 0,
        ..application_fields
    })?;
    let checkpoint_state = fixture.state(1, 0, 0, 13, reserved_guard_hash)?;
    assert_eq!(
        classify_recovery_state(
            &fixture.header,
            &checkpoint_state,
            STATE_RECORD_ID,
            &checkpoint,
            &reserved_guard,
        )?,
        RecoveryDisposition::InstallCommittedGuard,
    );

    let mut invalid_applications = Vec::new();
    for mutate in [
        |fields: &mut NonceReservationTbs| {
            fields.phase = RollbackGuardPhase::NonceReserved;
            fields.nonce_reservation_start = 12;
        },
        |fields: &mut NonceReservationTbs| fields.reservation_sequence = 2,
        |fields: &mut NonceReservationTbs| {
            fields.nonce_reservation_start = 12;
            fields.nonce_draw_high_water = 12;
        },
        |fields: &mut NonceReservationTbs| fields.storage_commit_sequence = 2,
        |fields: &mut NonceReservationTbs| fields.manifest_sequence = 2,
        |fields: &mut NonceReservationTbs| fields.previous_guard_hash = ZERO,
    ] {
        let mut candidate = fixture.reservation_tbs(application_fields)?;
        mutate(&mut candidate);
        invalid_applications.push(candidate);
    }
    for candidate in invalid_applications {
        assert_stale(
            &fixture,
            &old_state,
            &NonceReservationState::authenticate(candidate, &fixture.keys)?,
            &reserved_guard,
        );
    }

    for mismatched_state in [
        fixture.state(0, 1, 1, 13, reserved_guard_hash)?,
        fixture.state(1, 0, 1, 13, reserved_guard_hash)?,
        fixture.state(1, 1, 0, 13, reserved_guard_hash)?,
        fixture.state(1, 1, 1, 12, reserved_guard_hash)?,
        fixture.state(1, 1, 1, 13, ZERO)?,
    ] {
        assert_stale(&fixture, &mismatched_state, &application, &reserved_guard);
    }
    assert_eq!(
        classify_recovery_state(
            &fixture.header,
            &application_state,
            StorageDigest::from_bytes([96; 32]),
            &application,
            &reserved_guard,
        ),
        Err(StorageError::StaleState),
    );

    let mut exhausted_commit = *reserved_guard.tbs();
    exhausted_commit.storage_commit_sequence = u64::MAX;
    assert_eq!(
        classify_recovery_state(
            &fixture.header,
            &old_state,
            STATE_RECORD_ID,
            &application,
            &fixture.authenticate_guard(exhausted_commit)?,
        ),
        Err(StorageError::Overflow),
    );
    let mut exhausted_manifest = *reserved_guard.tbs();
    exhausted_manifest.manifest_sequence = u64::MAX;
    assert_eq!(
        classify_recovery_state(
            &fixture.header,
            &old_state,
            STATE_RECORD_ID,
            &application,
            &fixture.authenticate_guard(exhausted_manifest)?,
        ),
        Err(StorageError::Overflow),
    );

    let reserved_before_state = fixture.reservation(ReservationFields {
        sequence: 2,
        phase: RollbackGuardPhase::NonceReserved,
        start: 12,
        end: 14,
        commit: 0,
        manifest: 0,
        generation: 0,
        previous_guard_hash: reserved_guard_hash,
    })?;
    let advanced_state = fixture.state(0, 0, 0, 13, ZERO)?;
    assert_stale(
        &fixture,
        &advanced_state,
        &reserved_before_state,
        &reserved_guard,
    );
    Ok(())
}
