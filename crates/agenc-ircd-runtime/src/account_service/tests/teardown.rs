//! What a closed connection, an expired reservation timer and a full cleanup
//! queue leave behind: every server-owned transaction row is queued for
//! deletion exactly once and no continuation outlives its transport.
#![forbid(unsafe_code)]

use super::harness::{
    Live, WALL, authentication_finish, commit_authentication_start, exhaust_transaction_capacity,
    fire_transaction_timer, rejected_authentication_finish, sasl_request,
    sealed_unknown_authentication, unsealed_unknown_authentication,
};
use super::invitation_window::{commit_start, open_connection};
use super::*;
use crate::account_service::{ReadySeal, ReadyStage, TransactionCleanupReservation};
use crate::state_core::timers::{TimedId, TimerKind};
use crate::test_support::TestResult;
use agenc_ircd_auth::OpenedAccountServiceRequest;

fn transaction_key(transaction_id: TransactionId) -> TestResult<StoredKey> {
    Ok(StoredKey::new(transaction_id.as_bytes().to_vec())?)
}

fn close(live: &mut Live) -> TestResult {
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    coordinator.connection_closed(context, generation);
    assert!(!coordinator.connections.contains_key(&generation));
    Ok(())
}

/// Commits the cleanup batch a teardown staged and applies its receipt.
async fn settle_cleanup(live: &mut Live) -> TestResult {
    assert_eq!(live.fixture.core.context_mut()?.pending_len(), 1);
    live.fixture.core.commit_staged_batch().await?;
    let (coordinator, context) = live.fixture.parts()?;
    assert!(coordinator.batch_applied(context).is_empty());
    assert!(coordinator.pending_cleanups.is_empty());
    Ok(())
}

#[tokio::test]
async fn closing_mid_creation_deletes_the_transaction_and_its_login_reservation() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = commit_start(
        &mut live.fixture,
        live.generation,
        live.route,
        1,
        "abandoned",
        None,
        WALL,
    )
    .await?;
    let login_key = live
        .fixture
        .coordinator
        .connections
        .get(&live.generation)
        .and_then(|connection| connection.creation_transaction.as_ref())
        .and_then(|creation| creation.reservation.as_ref())
        .map(|reservation| reservation.login_key.clone())
        .ok_or("login reservation")?;
    assert!(
        live.fixture
            .core
            .stored_row_exists(TableId::LoginIndex, login_key.clone())?
    );
    close(&mut live)?;
    let owners = &live.fixture.coordinator.transaction_owners;
    assert!(!owners.contains_key(&transaction_id));
    settle_cleanup(&mut live).await?;
    let core = &live.fixture.core;
    assert!(!core.stored_row_exists(TableId::LoginIndex, login_key)?);
    assert!(!core.stored_row_exists(TableId::AuthTransaction, transaction_key(transaction_id)?)?);
    Ok(())
}

#[tokio::test]
async fn closing_mid_authentication_deletes_the_transaction_row() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = commit_authentication_start(&mut live, 1, "abandoned").await?;
    let key = transaction_key(transaction_id)?;
    assert!(
        live.fixture
            .core
            .stored_row_exists(TableId::AuthTransaction, key.clone())?
    );
    close(&mut live)?;
    settle_cleanup(&mut live).await?;
    assert!(
        !live
            .fixture
            .core
            .stored_row_exists(TableId::AuthTransaction, key)?
    );
    Ok(())
}

#[tokio::test]
async fn an_expired_authentication_is_cleaned_up_without_closing_its_connection() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = commit_authentication_start(&mut live, 1, "sleeper").await?;
    let (consumed, completions) = fire_transaction_timer(&mut live.fixture, transaction_id)?;
    assert!(consumed);
    assert!(completions.is_empty());
    let coordinator = &live.fixture.coordinator;
    assert!(!coordinator.transaction_owners.contains_key(&transaction_id));
    let connection = coordinator.connections.get(&live.generation);
    assert!(connection.is_some_and(|connection| connection.transaction.is_none()));
    settle_cleanup(&mut live).await?;
    let key = transaction_key(transaction_id)?;
    assert!(
        !live
            .fixture
            .core
            .stored_row_exists(TableId::AuthTransaction, key)?
    );
    Ok(())
}

#[tokio::test]
async fn an_expired_creation_releases_its_reservation_with_the_transaction() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = commit_start(
        &mut live.fixture,
        live.generation,
        live.route,
        1,
        "sleeper",
        None,
        WALL,
    )
    .await?;
    let (consumed, completions) = fire_transaction_timer(&mut live.fixture, transaction_id)?;
    assert!(consumed && completions.is_empty());
    let cleanup = live.fixture.coordinator.pending_cleanups.first();
    assert!(cleanup.is_some_and(|cleanup| {
        cleanup.transaction_id == transaction_id
            && matches!(
                cleanup.reservation,
                TransactionCleanupReservation::Creation(_)
            )
    }));
    Ok(())
}

#[tokio::test]
async fn a_timer_for_a_transaction_the_connection_no_longer_holds_is_consumed() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = commit_authentication_start(&mut live, 1, "finisher").await?;
    let _finish = rejected_authentication_finish(&mut live, 2, transaction_id)?;
    let (consumed, completions) = fire_transaction_timer(&mut live.fixture, transaction_id)?;
    assert!(consumed && completions.is_empty());
    // The finish continuation still owns the row; the timer queued nothing.
    let coordinator = &live.fixture.coordinator;
    assert!(coordinator.transaction_owners.contains_key(&transaction_id));
    assert!(coordinator.cleanup_queue.is_empty() && coordinator.pending_cleanups.is_empty());
    Ok(())
}

#[test]
fn a_global_reservation_timer_without_a_scheduled_tombstone_is_not_consumed() -> TestResult {
    let mut live = Live::open()?;
    let (coordinator, context) = live.fixture.parts()?;
    let due = MonotonicTick::from_ticks(0);
    context
        .timers_mut()
        .schedule(due, TimerKind::Reservation, TimedId::Global)?;
    let entry = context.timers_mut().pop_due(due).ok_or("due timer")?;
    let (consumed, completions) = coordinator.timer_fired(context, entry);
    assert!(!consumed && completions.is_empty());
    Ok(())
}

#[tokio::test]
async fn closing_during_finish_crypto_cancels_the_job_and_queues_the_transaction() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = commit_authentication_start(&mut live, 1, "finisher").await?;
    let (opened, envelope) = authentication_finish(&live.fixture.core.identity, 2, transaction_id)?;
    let request = live.sasl(AccountCarrierPhase::Finish, envelope);
    let (coordinator, context) = live.fixture.parts()?;
    let opened = OpenedAccountServiceRequest::AuthenticationFinish(opened);
    assert!(
        coordinator
            .open_completed(context, request, Ok(opened))?
            .is_empty()
    );
    assert_eq!(coordinator.crypto.len(), 1);
    close(&mut live)?;
    let coordinator = &live.fixture.coordinator;
    assert!(coordinator.crypto.is_empty());
    assert!(!coordinator.transaction_owners.contains_key(&transaction_id));
    let cleanup = coordinator.pending_cleanups.first();
    assert!(cleanup.is_some_and(|cleanup| cleanup.transaction_id == transaction_id));
    Ok(())
}

#[tokio::test]
async fn closing_discards_only_the_closed_connections_ready_seals() -> TestResult {
    let mut live = Live::open()?;
    let other = ConnectionGeneration::new(2);
    let (_sink, other_route) = open_connection(&mut live.fixture, other)?;
    let transaction_id = commit_authentication_start(&mut live, 1, "sealer").await?;
    let (outcome, envelope) = rejected_authentication_finish(&mut live, 2, transaction_id)?;
    let finish = ReadySeal::Finish {
        request: live.sasl(AccountCarrierPhase::Finish, envelope),
        transaction_id,
        outcome,
        account_id: None,
        login: NormalizedLogin::prepare("sealer")?,
        previous_value: None,
        authenticated_at: MonotonicTick::from_ticks(0),
    };
    let (bystander, other_envelope) = unsealed_unknown_authentication(&mut live, 3, "bystander")?;
    let retained = ReadySeal::Start {
        request: sasl_request(
            other,
            1,
            other_route,
            AccountCarrierPhase::Start,
            other_envelope,
        ),
        outcome: bystander,
        account_id: None,
        login: NormalizedLogin::prepare("bystander")?,
        previous_value: None,
    };
    live.fixture.coordinator.ready_seals.push_back(retained);
    live.fixture.coordinator.ready_seals.push_back(finish);
    close(&mut live)?;
    let coordinator = &live.fixture.coordinator;
    assert!(!coordinator.transaction_owners.contains_key(&transaction_id));
    assert!(
        coordinator
            .ready_seals
            .iter()
            .all(|ready| ready.generation() == other)
    );
    Ok(())
}

#[tokio::test]
async fn closing_discards_a_ready_finish_stage_and_queues_its_transaction() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = commit_authentication_start(&mut live, 1, "stager").await?;
    let (outcome, envelope) = rejected_authentication_finish(&mut live, 2, transaction_id)?;
    let count = live
        .fixture
        .core
        .context_mut()?
        .head()
        .account_service_response_count;
    live.fixture.coordinator.ready_stage = Some(ReadyStage::Finish {
        request: live.sasl(AccountCarrierPhase::Finish, envelope),
        transaction_id,
        sealed: outcome.seal(count)?,
        account_id: None,
        login: NormalizedLogin::prepare("stager")?,
        previous_value: None,
        authenticated_at: MonotonicTick::from_ticks(0),
    });
    close(&mut live)?;
    let coordinator = &live.fixture.coordinator;
    assert!(coordinator.ready_stage.is_none());
    assert!(!coordinator.transaction_owners.contains_key(&transaction_id));
    Ok(())
}

#[test]
fn closing_discards_a_ready_start_stage_that_owns_no_transaction() -> TestResult {
    let mut live = Live::open()?;
    let (sealed, envelope) = sealed_unknown_authentication(&mut live, 1, "stager")?;
    live.fixture.coordinator.ready_stage = Some(ReadyStage::Start {
        request: live.sasl(AccountCarrierPhase::Start, envelope),
        sealed,
        account_id: None,
        login: NormalizedLogin::prepare("stager")?,
        previous_value: None,
    });
    close(&mut live)?;
    let coordinator = &live.fixture.coordinator;
    assert!(coordinator.ready_stage.is_none());
    assert!(coordinator.cleanup_queue.is_empty() && coordinator.pending_cleanups.is_empty());
    Ok(())
}

#[test]
fn closing_keeps_a_ready_stage_that_belongs_to_another_connection() -> TestResult {
    let mut live = Live::open()?;
    let other = ConnectionGeneration::new(2);
    let (_sink, other_route) = open_connection(&mut live.fixture, other)?;
    let (sealed, envelope) = sealed_unknown_authentication(&mut live, 1, "stager")?;
    live.fixture.coordinator.ready_stage = Some(ReadyStage::Start {
        request: sasl_request(other, 1, other_route, AccountCarrierPhase::Start, envelope),
        sealed,
        account_id: None,
        login: NormalizedLogin::prepare("stager")?,
        previous_value: None,
    });
    close(&mut live)?;
    assert!(live.fixture.coordinator.ready_stage.is_some());
    Ok(())
}

#[test]
fn closing_releases_the_connections_unqueued_credential_reservation() -> TestResult {
    let mut live = Live::open()?;
    let reservations = &mut live.fixture.coordinator.credential_reservations;
    reservations.insert(account(1), live.generation);
    reservations.insert(account(2), ConnectionGeneration::new(2));
    close(&mut live)?;
    let reservations = &live.fixture.coordinator.credential_reservations;
    assert!(!reservations.contains_key(&account(1)));
    assert!(reservations.contains_key(&account(2)));
    Ok(())
}

#[test]
fn closing_keeps_a_credential_reservation_whose_cleanup_is_still_queued() -> TestResult {
    let mut live = Live::open()?;
    let coordinator = &mut live.fixture.coordinator;
    coordinator
        .credential_reservations
        .insert(account(1), live.generation);
    coordinator
        .credential_cleanup_owners
        .insert(live.generation);
    close(&mut live)?;
    let reservations = &live.fixture.coordinator.credential_reservations;
    assert_eq!(reservations.get(&account(1)), Some(&live.generation));
    Ok(())
}

#[test]
fn closing_keeps_a_credential_reservation_owned_by_a_live_transaction() -> TestResult {
    let mut live = Live::open()?;
    let coordinator = &mut live.fixture.coordinator;
    coordinator
        .credential_reservations
        .insert(account(1), live.generation);
    coordinator.transaction_owners.insert(
        TransactionId::from_bytes([8; 16]),
        (live.generation, LiveTransactionClass::CredentialChange),
    );
    close(&mut live)?;
    let reservations = &live.fixture.coordinator.credential_reservations;
    assert_eq!(reservations.get(&account(1)), Some(&live.generation));
    Ok(())
}

#[test]
fn a_credential_cleanup_releases_the_reservation_only_after_its_batch_applies() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = TransactionId::from_bytes([8; 16]);
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    coordinator
        .credential_reservations
        .insert(account(1), generation);
    coordinator.transaction_owners.insert(
        transaction_id,
        (generation, LiveTransactionClass::CredentialChange),
    );
    let cleanup = TransactionCleanup::credential(transaction_id, Some(account(1)), generation);
    coordinator.queue_transaction_cleanup(
        context,
        generation,
        LiveTransactionClass::CredentialChange,
        cleanup,
    )?;
    assert!(coordinator.credential_cleanup_owners.contains(&generation));
    coordinator.connection_closed(context, generation);
    assert!(
        coordinator
            .credential_reservations
            .contains_key(&account(1))
    );
    assert_eq!(coordinator.pending_cleanups.len(), 1);
    assert!(coordinator.batch_applied(context).is_empty());
    assert!(coordinator.credential_reservations.is_empty());
    assert!(coordinator.credential_cleanup_owners.is_empty());
    Ok(())
}

#[test]
fn a_cleanup_for_a_transaction_another_owner_holds_is_refused() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = TransactionId::from_bytes([8; 16]);
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    coordinator.transaction_owners.insert(
        transaction_id,
        (generation, LiveTransactionClass::Authentication),
    );
    let queued = coordinator.queue_transaction_cleanup(
        context,
        generation,
        LiveTransactionClass::Creation,
        TransactionCleanup::authentication(transaction_id),
    );
    assert_eq!(queued.err(), Some(RuntimeError::InvalidValue));
    assert!(coordinator.transaction_owners.contains_key(&transaction_id));
    assert!(coordinator.cleanup_queue.is_empty());
    Ok(())
}

#[test]
fn a_full_cleanup_queue_refuses_another_cleanup_and_keeps_its_owner() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = TransactionId::from_bytes([8; 16]);
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    exhaust_transaction_capacity(coordinator);
    coordinator.transaction_owners.insert(
        transaction_id,
        (generation, LiveTransactionClass::Authentication),
    );
    let queued = coordinator.queue_transaction_cleanup(
        context,
        generation,
        LiveTransactionClass::Authentication,
        TransactionCleanup::authentication(transaction_id),
    );
    assert_eq!(queued.err(), Some(RuntimeError::LimitExceeded));
    assert!(coordinator.transaction_owners.contains_key(&transaction_id));
    assert_eq!(
        coordinator.cleanup_queue.len(),
        MAX_PENDING_TRANSACTION_CLEANUPS
    );
    Ok(())
}

#[test]
fn queued_cleanups_wait_while_an_account_authority_is_staged() -> TestResult {
    let mut live = Live::open()?;
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    coordinator
        .cleanup_queue
        .push_back(TransactionCleanup::authentication(
            TransactionId::from_bytes([8; 16]),
        ));
    coordinator.pending_authority = Some(PendingAuthority::Logout {
        generation,
        carrier_generation: 1,
    });
    coordinator.try_stage_transaction_cleanup(context)?;
    assert_eq!(context.pending_len(), 0);
    assert_eq!(coordinator.cleanup_queue.len(), 1);
    coordinator.pending_authority = None;
    coordinator.try_stage_transaction_cleanup(context)?;
    assert_eq!(context.pending_len(), 1);
    assert!(coordinator.cleanup_queue.is_empty());
    Ok(())
}

#[test]
fn a_new_connection_is_refused_until_recovered_cleanups_commit() -> TestResult {
    let mut fixture = CoordinatorFixture::new(vec![7; 512])?;
    let generation = ConnectionGeneration::new(1);
    let (coordinator, context) = fixture.parts()?;
    coordinator.startup_cleanup_remaining = 1;
    coordinator.cleanup_queue.push_back(TransactionCleanup {
        transaction_id: TransactionId::from_bytes([8; 16]),
        reservation: TransactionCleanupReservation::None,
        recovered: true,
    });
    let refused = coordinator.connection_opened(context, generation);
    assert!(matches!(
        refused,
        Err(RuntimeError::Storage(
            agenc_ircd_storage::StorageError::Unavailable
        ))
    ));
    assert!(!coordinator.connections.contains_key(&generation));
    assert_eq!(context.pending_len(), 1);
    assert!(coordinator.batch_applied(context).is_empty());
    assert_eq!(coordinator.startup_cleanup_remaining, 0);
    coordinator.connection_opened(context, generation)?;
    Ok(())
}

#[test]
fn a_recovered_cleanup_beyond_the_startup_count_is_reported_as_invalid() -> TestResult {
    let mut fixture = CoordinatorFixture::new(vec![7; 512])?;
    let cleanup = TransactionCleanup {
        transaction_id: TransactionId::from_bytes([8; 16]),
        reservation: TransactionCleanupReservation::None,
        recovered: true,
    };
    let completed = fixture.coordinator.complete_transaction_cleanup(cleanup);
    assert_eq!(completed.err(), Some(RuntimeError::InvalidValue));
    Ok(())
}
