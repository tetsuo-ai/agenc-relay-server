//! Closed classification of the four admissible database/guard crash states.

use crate::{
    DatabaseHeader, NonceReservationState, RollbackGuard, RollbackGuardPhase, StateMeta,
    StorageError, verify_guard_pair,
};
use agenc_ircd_crypto::StorageDigest;

/// Exact recovery action permitted before any listener opens.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryDisposition {
    /// Database and committed guard already match.
    ExactCommitted,
    /// Database and same-state reserved guard match; its block stays burned.
    ExactReserved,
    /// The reservation-record commit succeeded but its reserved guard is missing.
    InstallReservedGuard,
    /// The application commit succeeded but its committed guard is missing.
    InstallCommittedGuard,
}

/// Accepts only an exact pair or one authenticated direct successor.
///
/// The database record is the authority and the guard is never allowed to lead it. A durable
/// operation writes the reserved record, publishes the reserved guard, commits the transaction
/// that carries both the data and the committed record, and only then publishes the committed
/// guard; each write is durable before the next begins. A kill therefore stops the sequence
/// after one of four durable prefixes, and each one is named above: the two exact pairs, the
/// reserved record whose guard was never published, and the committed record whose guard was
/// never published. A guard two or more steps behind its record would need the database to have
/// advanced twice across one unpublished guard, which the ordering makes unreachable, so it is
/// refused here rather than reconciled. Each successor is admitted only when its predecessor's
/// own guard hash, header hash, instance, sequences and StateMeta binding all repeat exactly, so
/// a stale, gapped or foreign guard is refused even when its distance happens to be one.
// agenc-review: focus owner=storage reviewed=2026-08-27 reason=four-state recovery classifier is reviewed as one closed crash-state matrix
pub fn classify_recovery_state(
    header: &DatabaseHeader,
    state_meta: &StateMeta,
    state_meta_record_id: StorageDigest,
    reservation: &NonceReservationState,
    guard: &RollbackGuard,
) -> Result<RecoveryDisposition, StorageError> {
    if verify_guard_pair(header, reservation, guard).is_ok() {
        verify_state_against_reservation(state_meta, state_meta_record_id, reservation)?;
        return match reservation.tbs().phase {
            RollbackGuardPhase::Committed => Ok(RecoveryDisposition::ExactCommitted),
            RollbackGuardPhase::NonceReserved => Ok(RecoveryDisposition::ExactReserved),
        };
    }
    let database = reservation.tbs();
    let external = guard.tbs();
    let guard_hash = guard.complete_hash()?;
    let header_hash = header.complete_hash()?;
    if database.database_instance_id != header.tbs().database_instance_id
        || external.database_instance_id != header.tbs().database_instance_id
        || database.database_header_hash != header_hash
        || external.database_header_hash != header_hash
    {
        return Err(StorageError::StaleState);
    }
    let reservation_successor = database.phase == RollbackGuardPhase::NonceReserved
        && database.reservation_sequence
            == external
                .reservation_sequence
                .checked_add(1)
                .ok_or(StorageError::Overflow)?
        && database.nonce_reservation_start == external.nonce_draw_high_water
        && database.storage_commit_sequence == external.storage_commit_sequence
        && database.manifest_sequence == external.manifest_sequence
        && database.state_generation == external.state_generation
        && database.state_meta_record_id == external.state_meta_record_id
        && database.previous_guard_hash == guard_hash;
    if reservation_successor {
        verify_state_against_guard(state_meta, state_meta_record_id, guard)?;
        return Ok(RecoveryDisposition::InstallReservedGuard);
    }
    let common_application_successor = external.phase == RollbackGuardPhase::NonceReserved
        && database.phase == RollbackGuardPhase::Committed
        && database.reservation_sequence == external.reservation_sequence
        && database.nonce_reservation_start == external.nonce_draw_high_water
        && database.storage_commit_sequence
            == external
                .storage_commit_sequence
                .checked_add(1)
                .ok_or(StorageError::Overflow)?
        && database.previous_guard_hash == guard_hash;
    let tracked_successor = database.manifest_sequence
        == external
            .manifest_sequence
            .checked_add(1)
            .ok_or(StorageError::Overflow)?
        && database.state_generation >= external.state_generation;
    let checkpoint_successor = database.manifest_sequence == external.manifest_sequence
        && database.state_generation == external.state_generation;
    let application_successor =
        common_application_successor && (tracked_successor || checkpoint_successor);
    if application_successor {
        verify_state_against_reservation(state_meta, state_meta_record_id, reservation)?;
        if state_meta.tbs().previous_rollback_guard_hash != guard_hash {
            return Err(StorageError::StaleState);
        }
        return Ok(RecoveryDisposition::InstallCommittedGuard);
    }
    Err(StorageError::StaleState)
}

fn verify_state_against_reservation(
    state: &StateMeta,
    record_id: StorageDigest,
    reservation: &NonceReservationState,
) -> Result<(), StorageError> {
    let state = state.tbs();
    let reservation = reservation.tbs();
    if reservation.state_meta_record_id != record_id
        || reservation.storage_commit_sequence != state.storage_commit_sequence
        || reservation.manifest_sequence != state.manifest_sequence
        || reservation.state_generation != state.state_generation
        || (reservation.phase == RollbackGuardPhase::Committed
            && reservation.nonce_draw_high_water != state.nonce_draw_high_water)
        || (reservation.phase == RollbackGuardPhase::NonceReserved
            && reservation.nonce_reservation_start < state.nonce_draw_high_water)
    {
        return Err(StorageError::StaleState);
    }
    Ok(())
}

fn verify_state_against_guard(
    state: &StateMeta,
    record_id: StorageDigest,
    guard: &RollbackGuard,
) -> Result<(), StorageError> {
    let state = state.tbs();
    let guard = guard.tbs();
    if guard.state_meta_record_id != record_id
        || guard.storage_commit_sequence != state.storage_commit_sequence
        || guard.manifest_sequence != state.manifest_sequence
        || guard.state_generation != state.state_generation
        || (guard.phase == RollbackGuardPhase::Committed
            && guard.nonce_draw_high_water != state.nonce_draw_high_water)
        || (guard.phase == RollbackGuardPhase::NonceReserved
            && guard.nonce_reservation_start < state.nonce_draw_high_water)
    {
        return Err(StorageError::StaleState);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use agenc_ircd_crypto::{
        RollbackGuardRootKey, StorageIntegrityContext, StorageIntegrityKeys,
        derive_storage_integrity_keys,
    };
    use agenc_ircd_types::{DatabaseId, NetworkId, RecoveryEpoch, ServerId, ServerIncarnation};

    use super::*;
    use crate::{DatabaseHeaderTbs, NonceReservationTbs, RollbackGuardTbs, StateMetaTbs};

    const ZERO: StorageDigest = StorageDigest::from_bytes([0; 32]);
    const STATE_RECORD_ID: StorageDigest = StorageDigest::from_bytes([7; 32]);

    struct Fixture {
        header: DatabaseHeader,
        keys: StorageIntegrityKeys,
    }

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

    impl Fixture {
        fn new() -> Result<Self, StorageError> {
            let tbs = DatabaseHeaderTbs::new(
                NetworkId::from_bytes([1; 32]),
                ServerId::from_bytes([2; 16]),
                ServerIncarnation::from_bytes([3; 16]),
                DatabaseId::from_bytes([4; 16]),
                1,
                crate::SCHEMA_GENERATION,
                RecoveryEpoch::from_bytes([5; 16]),
            )?;
            let header = DatabaseHeader::new(tbs, StorageDigest::from_bytes([6; 32]));
            let keys = derive_storage_integrity_keys(
                &RollbackGuardRootKey::from_bytes([8; 32]),
                StorageIntegrityContext::new(
                    tbs.network_id,
                    tbs.server_id,
                    tbs.database_instance_id,
                ),
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

        fn reservation(
            &self,
            tbs: NonceReservationTbs,
        ) -> Result<NonceReservationState, StorageError> {
            NonceReservationState::authenticate(tbs, &self.keys)
        }

        fn guard(
            &self,
            reservation: &NonceReservationState,
        ) -> Result<RollbackGuard, StorageError> {
            let source = reservation.tbs();
            RollbackGuard::authenticate(
                RollbackGuardTbs {
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
                },
                &self.keys,
            )
        }

        fn authenticate_guard(&self, tbs: RollbackGuardTbs) -> Result<RollbackGuard, StorageError> {
            RollbackGuard::authenticate(tbs, &self.keys)
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
    }

    #[test]
    fn accepts_exact_committed_and_reserved_pairs() -> Result<(), StorageError> {
        let fixture = Fixture::new()?;
        let state = fixture.state(0, 0, 0, 10, ZERO)?;
        let committed = fixture.reservation(fixture.reservation_tbs(ReservationFields {
            sequence: 0,
            phase: RollbackGuardPhase::Committed,
            start: 10,
            end: 10,
            commit: 0,
            manifest: 0,
            generation: 0,
            previous_guard_hash: ZERO,
        })?)?;
        let committed_guard = fixture.guard(&committed)?;
        assert_eq!(
            classify_recovery_state(
                &fixture.header,
                &state,
                STATE_RECORD_ID,
                &committed,
                &committed_guard,
            )?,
            RecoveryDisposition::ExactCommitted,
        );

        let reserved = fixture.reservation(fixture.reservation_tbs(ReservationFields {
            sequence: 1,
            phase: RollbackGuardPhase::NonceReserved,
            start: 10,
            end: 12,
            commit: 0,
            manifest: 0,
            generation: 0,
            previous_guard_hash: committed_guard.complete_hash()?,
        })?)?;
        let reserved_guard = fixture.guard(&reserved)?;
        assert_eq!(
            classify_recovery_state(
                &fixture.header,
                &state,
                STATE_RECORD_ID,
                &reserved,
                &reserved_guard,
            )?,
            RecoveryDisposition::ExactReserved,
        );
        Ok(())
    }

    #[test]
    fn accepts_only_the_two_direct_successor_states() -> Result<(), StorageError> {
        let fixture = Fixture::new()?;
        let old_state = fixture.state(0, 0, 0, 10, ZERO)?;
        let committed = fixture.reservation(fixture.reservation_tbs(ReservationFields {
            sequence: 0,
            phase: RollbackGuardPhase::Committed,
            start: 10,
            end: 10,
            commit: 0,
            manifest: 0,
            generation: 0,
            previous_guard_hash: ZERO,
        })?)?;
        let committed_guard = fixture.guard(&committed)?;
        let committed_guard_hash = committed_guard.complete_hash()?;
        let reserved = fixture.reservation(fixture.reservation_tbs(ReservationFields {
            sequence: 1,
            phase: RollbackGuardPhase::NonceReserved,
            start: 10,
            end: 13,
            commit: 0,
            manifest: 0,
            generation: 0,
            previous_guard_hash: committed_guard_hash,
        })?)?;
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
        let reserved_guard_hash = reserved_guard.complete_hash()?;
        let application = fixture.reservation(fixture.reservation_tbs(ReservationFields {
            sequence: 1,
            phase: RollbackGuardPhase::Committed,
            start: 13,
            end: 13,
            commit: 1,
            manifest: 1,
            generation: 1,
            previous_guard_hash: reserved_guard_hash,
        })?)?;
        let new_state = fixture.state(1, 1, 1, 13, reserved_guard_hash)?;
        assert_eq!(
            classify_recovery_state(
                &fixture.header,
                &new_state,
                STATE_RECORD_ID,
                &application,
                &reserved_guard,
            )?,
            RecoveryDisposition::InstallCommittedGuard,
        );
        let checkpoint = fixture.reservation(fixture.reservation_tbs(ReservationFields {
            sequence: 1,
            phase: RollbackGuardPhase::Committed,
            start: 13,
            end: 13,
            commit: 1,
            manifest: 0,
            generation: 0,
            previous_guard_hash: reserved_guard_hash,
        })?)?;
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
        Ok(())
    }

    #[test]
    fn rejects_gaps_mismatches_and_non_successors() -> Result<(), StorageError> {
        let fixture = Fixture::new()?;
        let state = fixture.state(0, 0, 0, 10, ZERO)?;
        let base = fixture.reservation(fixture.reservation_tbs(ReservationFields {
            sequence: 0,
            phase: RollbackGuardPhase::Committed,
            start: 10,
            end: 10,
            commit: 0,
            manifest: 0,
            generation: 0,
            previous_guard_hash: ZERO,
        })?)?;
        let guard = fixture.guard(&base)?;
        let guard_hash = guard.complete_hash()?;

        let mut cases = Vec::new();
        let successor_fields = || ReservationFields {
            sequence: 1,
            phase: RollbackGuardPhase::NonceReserved,
            start: 10,
            end: 12,
            commit: 0,
            manifest: 0,
            generation: 0,
            previous_guard_hash: guard_hash,
        };
        let mut wrong_instance = fixture.reservation_tbs(successor_fields())?;
        wrong_instance.database_instance_id = DatabaseId::from_bytes([99; 16]);
        cases.push(wrong_instance);
        let mut wrong_header = fixture.reservation_tbs(successor_fields())?;
        wrong_header.database_header_hash = StorageDigest::from_bytes([98; 32]);
        cases.push(wrong_header);
        let mut gap = successor_fields();
        gap.sequence = 2;
        cases.push(fixture.reservation_tbs(gap)?);
        let mut wrong_start = successor_fields();
        wrong_start.start = 11;
        cases.push(fixture.reservation_tbs(wrong_start)?);
        let mut wrong_commit = successor_fields();
        wrong_commit.commit = 1;
        cases.push(fixture.reservation_tbs(wrong_commit)?);
        let mut wrong_manifest = successor_fields();
        wrong_manifest.manifest = 1;
        cases.push(fixture.reservation_tbs(wrong_manifest)?);
        let mut wrong_generation = successor_fields();
        wrong_generation.generation = 1;
        cases.push(fixture.reservation_tbs(wrong_generation)?);
        for tbs in cases {
            let reservation = fixture.reservation(tbs)?;
            assert_eq!(
                classify_recovery_state(
                    &fixture.header,
                    &state,
                    STATE_RECORD_ID,
                    &reservation,
                    &guard,
                ),
                Err(StorageError::StaleState),
            );
        }

        let wrong_record_id = StorageDigest::from_bytes([42; 32]);
        assert_eq!(
            classify_recovery_state(&fixture.header, &state, wrong_record_id, &base, &guard),
            Err(StorageError::StaleState),
        );
        let wrong_state = fixture.state(1, 0, 0, 10, ZERO)?;
        assert_eq!(
            classify_recovery_state(
                &fixture.header,
                &wrong_state,
                STATE_RECORD_ID,
                &base,
                &guard,
            ),
            Err(StorageError::StaleState),
        );
        Ok(())
    }

    #[test]
    fn rejects_every_guard_and_state_successor_mismatch() -> Result<(), StorageError> {
        let fixture = Fixture::new()?;
        let old_state = fixture.state(0, 0, 0, 10, ZERO)?;
        let committed = fixture.reservation(fixture.reservation_tbs(ReservationFields {
            sequence: 0,
            phase: RollbackGuardPhase::Committed,
            start: 10,
            end: 10,
            commit: 0,
            manifest: 0,
            generation: 0,
            previous_guard_hash: ZERO,
        })?)?;
        let committed_guard = fixture.guard(&committed)?;
        let committed_guard_hash = committed_guard.complete_hash()?;
        let successor_fields = || ReservationFields {
            sequence: 1,
            phase: RollbackGuardPhase::NonceReserved,
            start: 10,
            end: 13,
            commit: 0,
            manifest: 0,
            generation: 0,
            previous_guard_hash: committed_guard_hash,
        };
        let successor = fixture.reservation(fixture.reservation_tbs(successor_fields())?)?;

        for mismatched_state in [
            fixture.state(1, 0, 0, 10, ZERO)?,
            fixture.state(0, 1, 0, 10, ZERO)?,
            fixture.state(0, 0, 1, 10, ZERO)?,
            fixture.state(0, 0, 0, 11, ZERO)?,
        ] {
            assert_eq!(
                classify_recovery_state(
                    &fixture.header,
                    &mismatched_state,
                    STATE_RECORD_ID,
                    &successor,
                    &committed_guard,
                ),
                Err(StorageError::StaleState),
            );
        }
        assert_eq!(
            classify_recovery_state(
                &fixture.header,
                &old_state,
                StorageDigest::from_bytes([77; 32]),
                &successor,
                &committed_guard,
            ),
            Err(StorageError::StaleState),
        );

        let mut wrong_external = *committed_guard.tbs();
        wrong_external.database_instance_id = DatabaseId::from_bytes([71; 16]);
        let wrong_external = fixture.authenticate_guard(wrong_external)?;
        assert_eq!(
            classify_recovery_state(
                &fixture.header,
                &old_state,
                STATE_RECORD_ID,
                &successor,
                &wrong_external,
            ),
            Err(StorageError::StaleState),
        );
        let mut wrong_header = *committed_guard.tbs();
        wrong_header.database_header_hash = StorageDigest::from_bytes([72; 32]);
        let wrong_header = fixture.authenticate_guard(wrong_header)?;
        assert_eq!(
            classify_recovery_state(
                &fixture.header,
                &old_state,
                STATE_RECORD_ID,
                &successor,
                &wrong_header,
            ),
            Err(StorageError::StaleState),
        );

        let mut exhausted_guard = *committed_guard.tbs();
        exhausted_guard.reservation_sequence = u64::MAX;
        let exhausted_guard = fixture.authenticate_guard(exhausted_guard)?;
        assert_eq!(
            classify_recovery_state(
                &fixture.header,
                &old_state,
                STATE_RECORD_ID,
                &successor,
                &exhausted_guard,
            ),
            Err(StorageError::Overflow),
        );

        let reserved_guard_source =
            fixture.reservation(fixture.reservation_tbs(ReservationFields {
                sequence: 1,
                phase: RollbackGuardPhase::NonceReserved,
                start: 10,
                end: 13,
                commit: 0,
                manifest: 0,
                generation: 0,
                previous_guard_hash: committed_guard_hash,
            })?)?;
        let reserved_guard = fixture.guard(&reserved_guard_source)?;
        let reserved_guard_hash = reserved_guard.complete_hash()?;
        let application_fields = || ReservationFields {
            sequence: 1,
            phase: RollbackGuardPhase::Committed,
            start: 13,
            end: 13,
            commit: 1,
            manifest: 1,
            generation: 1,
            previous_guard_hash: reserved_guard_hash,
        };
        let application = fixture.reservation(fixture.reservation_tbs(application_fields())?)?;

        let mut bad_applications = Vec::new();
        let mut wrong_phase = application_fields();
        wrong_phase.phase = RollbackGuardPhase::NonceReserved;
        wrong_phase.start = 12;
        bad_applications.push(wrong_phase);
        let mut wrong_sequence = application_fields();
        wrong_sequence.sequence = 2;
        bad_applications.push(wrong_sequence);
        let mut wrong_start = application_fields();
        wrong_start.start = 12;
        wrong_start.end = 12;
        bad_applications.push(wrong_start);
        let mut wrong_commit = application_fields();
        wrong_commit.commit = 2;
        bad_applications.push(wrong_commit);
        let mut wrong_manifest = application_fields();
        wrong_manifest.manifest = 2;
        bad_applications.push(wrong_manifest);
        let mut wrong_generation = application_fields();
        wrong_generation.generation = 0;
        bad_applications.push(wrong_generation);
        let mut wrong_predecessor = application_fields();
        wrong_predecessor.previous_guard_hash = ZERO;
        bad_applications.push(wrong_predecessor);
        for fields in bad_applications {
            let candidate = fixture.reservation(fixture.reservation_tbs(fields)?)?;
            assert_eq!(
                classify_recovery_state(
                    &fixture.header,
                    &old_state,
                    STATE_RECORD_ID,
                    &candidate,
                    &reserved_guard,
                ),
                Err(StorageError::StaleState),
            );
        }

        for state in [
            fixture.state(1, 1, 1, 13, ZERO)?,
            fixture.state(1, 1, 1, 12, reserved_guard_hash)?,
        ] {
            assert_eq!(
                classify_recovery_state(
                    &fixture.header,
                    &state,
                    STATE_RECORD_ID,
                    &application,
                    &reserved_guard,
                ),
                Err(StorageError::StaleState),
            );
        }

        let mut max_commit_guard = *reserved_guard.tbs();
        max_commit_guard.storage_commit_sequence = u64::MAX;
        let max_commit_guard = fixture.authenticate_guard(max_commit_guard)?;
        assert_eq!(
            classify_recovery_state(
                &fixture.header,
                &old_state,
                STATE_RECORD_ID,
                &application,
                &max_commit_guard,
            ),
            Err(StorageError::Overflow),
        );
        let mut max_manifest_guard = *reserved_guard.tbs();
        max_manifest_guard.manifest_sequence = u64::MAX;
        let max_manifest_guard = fixture.authenticate_guard(max_manifest_guard)?;
        let max_manifest_application =
            fixture.reservation(fixture.reservation_tbs(ReservationFields {
                commit: 1,
                ..application_fields()
            })?)?;
        assert_eq!(
            classify_recovery_state(
                &fixture.header,
                &old_state,
                STATE_RECORD_ID,
                &max_manifest_application,
                &max_manifest_guard,
            ),
            Err(StorageError::Overflow),
        );

        let prior_reserved =
            fixture.reservation(fixture.reservation_tbs(ReservationFields {
                sequence: 1,
                phase: RollbackGuardPhase::NonceReserved,
                start: 10,
                end: 12,
                commit: 0,
                manifest: 0,
                generation: 0,
                previous_guard_hash: committed_guard_hash,
            })?)?;
        let prior_reserved_guard = fixture.guard(&prior_reserved)?;
        let next_reserved = fixture.reservation(fixture.reservation_tbs(ReservationFields {
            sequence: 2,
            phase: RollbackGuardPhase::NonceReserved,
            start: 12,
            end: 14,
            commit: 0,
            manifest: 0,
            generation: 0,
            previous_guard_hash: prior_reserved_guard.complete_hash()?,
        })?)?;
        let advanced_state = fixture.state(0, 0, 0, 11, ZERO)?;
        assert_eq!(
            classify_recovery_state(
                &fixture.header,
                &advanced_state,
                STATE_RECORD_ID,
                &next_reserved,
                &prior_reserved_guard,
            ),
            Err(StorageError::StaleState),
        );
        Ok(())
    }

    #[test]
    fn rejects_each_remaining_authenticated_state_mismatch() -> Result<(), StorageError> {
        let fixture = Fixture::new()?;
        let committed = fixture.reservation(fixture.reservation_tbs(ReservationFields {
            sequence: 0,
            phase: RollbackGuardPhase::Committed,
            start: 10,
            end: 10,
            commit: 0,
            manifest: 0,
            generation: 0,
            previous_guard_hash: ZERO,
        })?)?;
        let committed_guard = fixture.guard(&committed)?;
        let committed_guard_hash = committed_guard.complete_hash()?;
        let state = fixture.state(0, 0, 0, 10, ZERO)?;

        let mut mismatched_record = fixture.reservation_tbs(ReservationFields {
            sequence: 1,
            phase: RollbackGuardPhase::NonceReserved,
            start: 10,
            end: 12,
            commit: 0,
            manifest: 0,
            generation: 0,
            previous_guard_hash: committed_guard_hash,
        })?;
        mismatched_record.state_meta_record_id = StorageDigest::from_bytes([44; 32]);
        assert_eq!(
            classify_recovery_state(
                &fixture.header,
                &state,
                STATE_RECORD_ID,
                &fixture.reservation(mismatched_record)?,
                &committed_guard,
            ),
            Err(StorageError::StaleState),
        );

        let reserved = fixture.reservation(fixture.reservation_tbs(ReservationFields {
            sequence: 1,
            phase: RollbackGuardPhase::NonceReserved,
            start: 10,
            end: 13,
            commit: 0,
            manifest: 0,
            generation: 0,
            previous_guard_hash: committed_guard_hash,
        })?)?;
        let reserved_guard = fixture.guard(&reserved)?;
        let reserved_guard_hash = reserved_guard.complete_hash()?;
        let application = fixture.reservation(fixture.reservation_tbs(ReservationFields {
            sequence: 1,
            phase: RollbackGuardPhase::Committed,
            start: 13,
            end: 13,
            commit: 1,
            manifest: 1,
            generation: 1,
            previous_guard_hash: reserved_guard_hash,
        })?)?;
        assert_eq!(
            classify_recovery_state(
                &fixture.header,
                &fixture.state(1, 1, 1, 12, reserved_guard_hash)?,
                STATE_RECORD_ID,
                &application,
                &reserved_guard,
            ),
            Err(StorageError::StaleState),
        );

        let wrong_manifest =
            fixture.reservation(fixture.reservation_tbs(ReservationFields {
                sequence: 0,
                phase: RollbackGuardPhase::Committed,
                start: 10,
                end: 10,
                commit: 0,
                manifest: 1,
                generation: 0,
                previous_guard_hash: ZERO,
            })?)?;
        assert_eq!(
            verify_state_against_reservation(&state, STATE_RECORD_ID, &wrong_manifest),
            Err(StorageError::StaleState),
        );
        let wrong_generation =
            fixture.reservation(fixture.reservation_tbs(ReservationFields {
                sequence: 0,
                phase: RollbackGuardPhase::Committed,
                start: 10,
                end: 10,
                commit: 0,
                manifest: 0,
                generation: 1,
                previous_guard_hash: ZERO,
            })?)?;
        assert_eq!(
            verify_state_against_reservation(&state, STATE_RECORD_ID, &wrong_generation),
            Err(StorageError::StaleState),
        );
        let reserved_before_state =
            fixture.reservation(fixture.reservation_tbs(ReservationFields {
                sequence: 1,
                phase: RollbackGuardPhase::NonceReserved,
                start: 9,
                end: 11,
                commit: 0,
                manifest: 0,
                generation: 0,
                previous_guard_hash: committed_guard_hash,
            })?)?;
        assert_eq!(
            verify_state_against_reservation(&state, STATE_RECORD_ID, &reserved_before_state),
            Err(StorageError::StaleState),
        );
        verify_state_against_guard(&state, STATE_RECORD_ID, &reserved_guard)?;
        Ok(())
    }
}
