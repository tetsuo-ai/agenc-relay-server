//! Account deletion barriers, the login-tombstone sweep they schedule, and
//! the registration-grant bookkeeping that survives without a live grant.
#![forbid(unsafe_code)]

use super::harness::{Live, WALL, commit_authentication_start};
use super::*;
use crate::account_service::{
    AccountTransactionCleanup, LOGIN_DELETION_TOMBSTONE_SECONDS, login_tombstone_deadline,
};
use crate::state_core::inbox::{MaintenanceEvent, StateCoreMessage};
use crate::state_core::timers::{DRIFT_CHECK_INTERVAL_MILLIS, TimedId, TimerKind};
use crate::test_support::TestResult;

const DELETER: ConnectionGeneration = ConnectionGeneration::new(30);

fn login_key(live: &Live, digest: u8) -> TestResult<StoredKey> {
    let generation = live.fixture.core.key_state.current_generation();
    let digest = LoginIndexDigest::from_storage_key([digest; 32]);
    Ok(LoginIndexStoredKey::new(generation, digest)?.encode()?)
}

fn with_login(live: &mut Live, account_id: AccountId) -> TestResult {
    let key = login_key(live, 61)?;
    let keys = &mut live.fixture.coordinator.config.live_login_keys;
    keys.insert(account_id, key);
    Ok(())
}

/// Withdraws wall-clock trust the way the periodic drift check does after a
/// jump larger than five minutes.
fn distrust_wall(live: &mut Live) -> TestResult {
    let jumped = WALL.saturating_add(100_000);
    let context = live.fixture.core.context_mut()?;
    context.set_untrusted_wall_for_test(Some(jumped));
    let check = StateCoreMessage::Maintenance(MaintenanceEvent::ClockDriftCheck);
    let _exit = live.fixture.core.state_mut()?.step_message(check);
    assert!(!live.fixture.core.context_mut()?.drift().wall_trusted());
    Ok(())
}

fn fire_sweep(live: &mut Live) -> TestResult<Vec<CarrierCompletion>> {
    let (coordinator, context) = live.fixture.parts()?;
    let due = MonotonicTick::from_ticks(0);
    context
        .timers_mut()
        .schedule(due, TimerKind::Reservation, TimedId::Global)?;
    let entry = context.timers_mut().pop_due(due).ok_or("due timer")?;
    let (consumed, completions) = coordinator.timer_fired(context, entry);
    assert!(consumed);
    Ok(completions)
}

/// Records one tombstone as the scheduled head of the sweep.
fn retain_tombstone(live: &mut Live, expires_at: u64, seed: u8) -> TestResult<(u64, AccountId)> {
    let key = login_key(live, seed)?;
    let id = (expires_at, account(seed));
    let coordinator = &mut live.fixture.coordinator;
    coordinator.config.login_deletion_tombstones.insert(id, key);
    let head = coordinator.config.login_deletion_tombstones.keys().next();
    coordinator.scheduled_login_tombstone = head.copied();
    Ok(id)
}

#[test]
fn deleting_an_account_with_a_reserved_credential_change_is_refused() -> TestResult {
    let mut live = Live::open()?;
    with_login(&mut live, account(3))?;
    let (coordinator, context) = live.fixture.parts()?;
    coordinator
        .credential_reservations
        .insert(account(3), ConnectionGeneration::new(1));
    let refused = coordinator.begin_account_deletion(context, DELETER, account(3));
    assert_eq!(refused.err(), Some(RuntimeError::LimitExceeded));
    assert!(coordinator.config.login_deletion_tombstones.is_empty());
    Ok(())
}

#[test]
fn deleting_an_account_while_the_wall_clock_is_distrusted_is_refused() -> TestResult {
    let mut live = Live::open()?;
    with_login(&mut live, account(3))?;
    distrust_wall(&mut live)?;
    let (coordinator, context) = live.fixture.parts()?;
    let refused = coordinator.begin_account_deletion(context, DELETER, account(3));
    assert_eq!(refused.err(), Some(RuntimeError::InvalidValue));
    assert!(coordinator.pending_account_deletions.is_empty());
    Ok(())
}

#[test]
fn deleting_an_account_whose_tombstone_already_exists_is_refused() -> TestResult {
    let mut live = Live::open()?;
    with_login(&mut live, account(3))?;
    let expires_at = WALL.saturating_add(LOGIN_DELETION_TOMBSTONE_SECONDS);
    let key = login_key(&live, 62)?;
    let (coordinator, context) = live.fixture.parts()?;
    let tombstones = &mut coordinator.config.login_deletion_tombstones;
    tombstones.insert((expires_at, account(3)), key);
    let refused = coordinator.begin_account_deletion(context, DELETER, account(3));
    assert_eq!(refused.err(), Some(RuntimeError::InvalidValue));
    assert_eq!(coordinator.config.login_deletion_tombstones.len(), 1);
    assert!(coordinator.pending_account_deletions.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_committed_deletion_invalidates_the_accounts_live_authentication() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = commit_authentication_start(&mut live, 1, "doomed").await?;
    with_login(&mut live, account(3))?;
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    let connection = coordinator.connections.get_mut(&generation);
    let exchange = connection.and_then(|connection| connection.transaction.as_mut());
    exchange.ok_or("live authentication")?.account_id = Some(account(3));
    let writes = coordinator.begin_account_deletion(context, DELETER, account(3))?;
    assert_eq!(writes.len(), 3);
    assert!(coordinator.registered_authority_fenced(context, generation));
    assert!(coordinator.registered_authority_fenced(context, DELETER));
    let completions = coordinator.batch_applied(context);
    let closed: Vec<_> = completions.iter().map(|done| done.generation).collect();
    assert_eq!(closed, vec![DELETER, generation]);
    assert!(!coordinator.transaction_owners.contains_key(&transaction_id));
    assert!(coordinator.config.live_login_keys.is_empty());
    let connection = coordinator.connections.get(&generation);
    assert!(connection.is_some_and(|connection| connection.transaction.is_none()));
    Ok(())
}

#[tokio::test]
async fn a_committed_deletion_skips_an_authentication_that_already_finished() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = commit_authentication_start(&mut live, 1, "doomed").await?;
    with_login(&mut live, account(3))?;
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    let connection = coordinator.connections.get_mut(&generation);
    let exchange = connection.and_then(|connection| connection.transaction.as_mut());
    exchange.ok_or("live authentication")?.account_id = Some(account(3));
    let _writes = coordinator.begin_account_deletion(context, DELETER, account(3))?;
    if let Some(connection) = coordinator.connections.get_mut(&generation) {
        connection.transaction = None;
    }
    let _completions = coordinator.batch_applied(context);
    // The finish continuation that took the transaction still owns its row.
    assert!(coordinator.transaction_owners.contains_key(&transaction_id));
    Ok(())
}

#[test]
fn a_rejected_deletion_drops_its_tombstone_and_a_second_rejection_finds_nothing() -> TestResult {
    let mut live = Live::open()?;
    with_login(&mut live, account(3))?;
    let (coordinator, context) = live.fixture.parts()?;
    let _writes = coordinator.begin_account_deletion(context, DELETER, account(3))?;
    assert_eq!(coordinator.config.login_deletion_tombstones.len(), 1);
    assert!(coordinator.account_deletion_rejected(context, DELETER));
    assert!(coordinator.config.login_deletion_tombstones.is_empty());
    assert!(coordinator.scheduled_login_tombstone.is_none());
    assert!(!coordinator.account_deletion_rejected(context, DELETER));
    assert!(coordinator.config.live_login_keys.contains_key(&account(3)));
    Ok(())
}

#[test]
fn a_cancelled_deletion_drops_its_tombstone_exactly_once() -> TestResult {
    let mut live = Live::open()?;
    with_login(&mut live, account(3))?;
    let (coordinator, context) = live.fixture.parts()?;
    let _writes = coordinator.begin_account_deletion(context, DELETER, account(3))?;
    coordinator.cancel_account_deletion(context, DELETER)?;
    assert!(coordinator.config.login_deletion_tombstones.is_empty());
    let again = coordinator.cancel_account_deletion(context, DELETER);
    assert_eq!(again.err(), Some(RuntimeError::InvalidValue));
    Ok(())
}

#[test]
fn an_expired_tombstone_is_swept_and_the_next_one_is_scheduled() -> TestResult {
    let mut live = Live::open()?;
    let expired = retain_tombstone(&mut live, WALL.saturating_sub(1), 71)?;
    let later = retain_tombstone(&mut live, WALL.saturating_add(500), 72)?;
    assert!(fire_sweep(&mut live)?.is_empty());
    let (coordinator, context) = live.fixture.parts()?;
    assert_eq!(context.pending_len(), 1);
    assert_eq!(coordinator.scheduled_login_tombstone, Some(later));
    assert!(coordinator.pending_login_tombstone_expiry.is_some());
    let _completions = coordinator.batch_applied(context);
    let tombstones = &coordinator.config.login_deletion_tombstones;
    assert!(!tombstones.contains_key(&expired) && tombstones.contains_key(&later));
    Ok(())
}

#[test]
fn a_sweep_with_nothing_expired_reschedules_the_earliest_tombstone() -> TestResult {
    let mut live = Live::open()?;
    let later = retain_tombstone(&mut live, WALL.saturating_add(500), 72)?;
    assert!(fire_sweep(&mut live)?.is_empty());
    let (coordinator, context) = live.fixture.parts()?;
    assert_eq!(context.pending_len(), 0);
    assert_eq!(coordinator.scheduled_login_tombstone, Some(later));
    assert!(
        context
            .timers_mut()
            .cancel(TimerKind::Reservation, TimedId::Global)
    );
    Ok(())
}

#[test]
fn a_sweep_waits_while_another_account_transition_is_in_flight() -> TestResult {
    let mut live = Live::open()?;
    let expired = retain_tombstone(&mut live, WALL.saturating_sub(1), 71)?;
    live.fixture.coordinator.pending_authority = Some(PendingAuthority::Logout {
        generation: live.generation,
        carrier_generation: 1,
    });
    let _completions = fire_sweep(&mut live)?;
    let (coordinator, context) = live.fixture.parts()?;
    assert_eq!(context.pending_len(), 0);
    assert!(coordinator.pending_login_tombstone_expiry.is_none());
    assert_eq!(coordinator.scheduled_login_tombstone, Some(expired));
    Ok(())
}

#[test]
fn a_sweep_waits_behind_a_batch_another_owner_staged() -> TestResult {
    let mut live = Live::open()?;
    let expired = retain_tombstone(&mut live, WALL.saturating_sub(1), 71)?;
    let writes =
        TransactionCleanup::authentication(TransactionId::from_bytes([1; 16])).durable_writes()?;
    let context = live.fixture.core.context_mut()?;
    assert!(
        context
            .stage_account_transaction_cleanup(AccountTransactionCleanup { writes })
            .is_ok()
    );
    let _completions = fire_sweep(&mut live)?;
    let coordinator = &live.fixture.coordinator;
    assert!(coordinator.pending_login_tombstone_expiry.is_none());
    assert_eq!(coordinator.scheduled_login_tombstone, Some(expired));
    Ok(())
}

#[test]
fn a_sweep_waits_while_the_wall_clock_is_distrusted() -> TestResult {
    let mut live = Live::open()?;
    let expired = retain_tombstone(&mut live, WALL.saturating_sub(1), 71)?;
    distrust_wall(&mut live)?;
    let _completions = fire_sweep(&mut live)?;
    let (coordinator, context) = live.fixture.parts()?;
    assert_eq!(context.pending_len(), 0);
    assert_eq!(coordinator.scheduled_login_tombstone, Some(expired));
    Ok(())
}

#[test]
fn a_sweep_waits_while_the_wall_clock_cannot_be_read() -> TestResult {
    let mut live = Live::open()?;
    let expired = retain_tombstone(&mut live, WALL.saturating_sub(1), 71)?;
    live.fixture
        .core
        .context_mut()?
        .set_untrusted_wall_for_test(None);
    let _completions = fire_sweep(&mut live)?;
    let (coordinator, context) = live.fixture.parts()?;
    assert_eq!(context.pending_len(), 0);
    assert_eq!(coordinator.scheduled_login_tombstone, Some(expired));
    Ok(())
}

#[test]
fn a_committed_sweep_whose_tombstone_key_changed_removes_nothing() -> TestResult {
    let mut live = Live::open()?;
    let expired = retain_tombstone(&mut live, WALL.saturating_sub(1), 71)?;
    let other_key = login_key(&live, 99)?;
    let (coordinator, context) = live.fixture.parts()?;
    coordinator.pending_login_tombstone_expiry = Some(PendingLoginTombstoneExpiry {
        tombstones: vec![(expired, other_key)],
        resulting_key_state: None,
    });
    let _completions = coordinator.batch_applied(context);
    assert!(coordinator.pending_login_tombstone_expiry.is_none());
    assert!(
        coordinator
            .config
            .login_deletion_tombstones
            .contains_key(&expired)
    );
    Ok(())
}

#[test]
fn a_committed_sweep_installs_the_key_state_its_batch_wrote() -> TestResult {
    let mut live = Live::open()?;
    let network = live.fixture.core.identity.network_id;
    let key_id = LoginIndexKey::from_bytes([77; 32]).key_id(network);
    let (coordinator, context) = live.fixture.parts()?;
    coordinator.pending_login_tombstone_expiry = Some(PendingLoginTombstoneExpiry {
        tombstones: Vec::new(),
        resulting_key_state: Some(LoginIndexKeyState::stable(9, key_id)?),
    });
    let _completions = coordinator.batch_applied(context);
    let installed = coordinator.config.login_index_key_state;
    assert_eq!(installed.current_generation(), 9);
    Ok(())
}

#[test]
fn a_tombstone_under_an_unknown_key_generation_stops_the_sweep_as_stale() -> TestResult {
    let network = NetworkId::from_bytes([19; 32]);
    let key_state =
        LoginIndexKeyState::stable(3, LoginIndexKey::from_bytes([20; 32]).key_id(network))?;
    let stale = LoginIndexStoredKey::new(1, LoginIndexDigest::from_storage_key([4; 32]))?;
    let mut tombstones = BTreeMap::new();
    tombstones.insert((100, account(4)), stale.encode()?);
    let batch =
        login_tombstone_expiry_batch(&tombstones, key_state, UtcSecond::from_unix_seconds(100));
    assert!(matches!(
        batch.err(),
        Some(RuntimeError::Storage(
            agenc_ircd_storage::StorageError::StaleState
        ))
    ));
    Ok(())
}

#[test]
fn scheduling_the_already_scheduled_tombstone_does_not_touch_the_timer() -> TestResult {
    let mut live = Live::open()?;
    let id = (WALL.saturating_add(500), account(4));
    let (coordinator, context) = live.fixture.parts()?;
    coordinator.schedule_login_tombstone(context, id)?;
    assert!(
        context
            .timers_mut()
            .cancel(TimerKind::Reservation, TimedId::Global)
    );
    coordinator.schedule_login_tombstone(context, id)?;
    assert!(
        !context
            .timers_mut()
            .cancel(TimerKind::Reservation, TimedId::Global)
    );
    Ok(())
}

#[test]
fn a_distrusted_wall_clock_defers_a_tombstone_by_one_drift_interval() -> TestResult {
    let mut live = Live::open()?;
    distrust_wall(&mut live)?;
    let context = live.fixture.core.context_mut()?;
    let deadline = login_tombstone_deadline(context, WALL.saturating_add(9_000))?;
    assert_eq!(
        deadline,
        context.now().checked_add(DRIFT_CHECK_INTERVAL_MILLIS)?
    );
    Ok(())
}

#[test]
fn an_unreadable_wall_clock_defers_a_tombstone_by_one_drift_interval() -> TestResult {
    let mut live = Live::open()?;
    let context = live.fixture.core.context_mut()?;
    context.set_untrusted_wall_for_test(None);
    let deadline = login_tombstone_deadline(context, WALL.saturating_add(9_000))?;
    assert_eq!(
        deadline,
        context.now().checked_add(DRIFT_CHECK_INTERVAL_MILLIS)?
    );
    Ok(())
}

#[test]
fn a_registration_cannot_consume_a_grant_twice_or_without_one() -> TestResult {
    let mut live = Live::open()?;
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    let absent = coordinator.begin_registration_grant_consumption(context, generation);
    assert_eq!(absent.err(), Some(RuntimeError::InvalidValue));
    coordinator
        .grant_consumptions
        .insert(generation, TransactionId::from_bytes([2; 16]));
    let twice = coordinator.begin_registration_grant_consumption(context, generation);
    assert_eq!(twice.err(), Some(RuntimeError::InvalidValue));
    assert_eq!(coordinator.grant_consumptions.len(), 1);
    Ok(())
}

#[test]
fn a_committed_registration_whose_grant_was_invalidated_installs_no_proof() -> TestResult {
    let mut live = Live::open()?;
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    coordinator
        .grant_consumptions
        .insert(generation, TransactionId::from_bytes([2; 16]));
    let user_id = agenc_ircd_types::UserId::from_bytes([9; 16]);
    coordinator.registration_committed(
        context,
        generation,
        user_id,
        super::super::SessionHome::Local,
    )?;
    assert!(coordinator.grant_consumptions.is_empty());
    let connection = coordinator.connections.get(&generation);
    assert!(connection.is_some_and(|connection| connection.fresh_authentication.is_none()));
    Ok(())
}

#[test]
fn a_rejected_registration_queues_the_grant_row_it_could_not_consume() -> TestResult {
    let mut live = Live::open()?;
    let generation = live.generation;
    let transaction_id = TransactionId::from_bytes([2; 16]);
    let (coordinator, context) = live.fixture.parts()?;
    let unknown = coordinator.registration_rejected(context, generation);
    assert_eq!(unknown.err(), Some(RuntimeError::InvalidValue));
    coordinator
        .grant_consumptions
        .insert(generation, transaction_id);
    coordinator.registration_rejected(context, generation)?;
    assert!(coordinator.grant_consumptions.is_empty());
    let cleanup = coordinator.pending_cleanups.first();
    assert!(cleanup.is_some_and(|cleanup| cleanup.transaction_id == transaction_id));
    assert_eq!(context.pending_len(), 1);
    Ok(())
}

#[test]
fn only_one_account_deletion_is_pending_at_a_time() -> TestResult {
    let mut live = Live::open()?;
    with_login(&mut live, account(3))?;
    with_login(&mut live, account(4))?;
    let (coordinator, context) = live.fixture.parts()?;
    let writes = coordinator.begin_account_deletion(context, DELETER, account(3))?;
    assert!(!writes.is_empty());
    assert_eq!(coordinator.pending_account_deletions.len(), 1);
    let refused = coordinator.begin_account_deletion(context, DELETER, account(4));
    assert_eq!(refused.err(), Some(RuntimeError::LimitExceeded));
    assert_eq!(coordinator.pending_account_deletions.len(), 1);
    assert_eq!(coordinator.config.login_deletion_tombstones.len(), 1);
    Ok(())
}
