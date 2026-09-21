//! What the coordinator does once a staged account batch is visible or was
//! rejected: a sealed authority is released only against the exact committed
//! response count and its recorded owner, and every failure closes exactly
//! the originating carrier.
#![forbid(unsafe_code)]

use super::harness::{
    Live, begin_creation, begin_unavailable_credential_change, commit_authentication_start,
    commit_credential_start, rejected_authentication_finish, rejected_credential_finish,
    sealed_unknown_authentication,
};
use super::*;
use crate::account_service::CommittedLoginIndexMigration;
use crate::state_core::timers::{TimedId, TimerKind};
use crate::test_support::TestResult;
use agenc_relay_auth::{AuthenticationGrant, SealedAccountFinishOutcome};

const OTHER: ConnectionGeneration = ConnectionGeneration::new(55);

fn assert_closed(completion: Option<CarrierCompletion>, generation: ConnectionGeneration) {
    assert!(completion.is_some_and(|completion| {
        completion.close
            && completion.generation == generation
            && completion.result == ResultClass::Error
    }));
}

fn commit_authentication(
    live: &mut Live,
    lag: u64,
    owner: Option<ConnectionGeneration>,
) -> TestResult<(Option<CarrierCompletion>, TransactionId)> {
    let (sealed, _) = sealed_unknown_authentication(live, 1, "committer")?;
    let transaction_id = sealed.transaction_id();
    let committed = live.response_count()?.saturating_add(1).saturating_sub(lag);
    let login = NormalizedLogin::prepare("committer")?;
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    if let Some(owner) = owner {
        let class = LiveTransactionClass::Authentication;
        coordinator
            .transaction_owners
            .insert(transaction_id, (owner, class));
    }
    let completion =
        coordinator.commit_start(context, committed, generation, 1, sealed, None, login, None);
    Ok((completion, transaction_id))
}

fn commit_creation(
    live: &mut Live,
    lag: u64,
    owner: Option<ConnectionGeneration>,
) -> TestResult<(Option<CarrierCompletion>, TransactionId)> {
    let (start, _) = begin_creation(live, 1, "committer", true)?;
    let transaction_id = start.transaction_id();
    let count = live.response_count()?;
    let sealed = start.seal(count)?;
    let committed = count.saturating_add(1).saturating_sub(lag);
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    let reservation = coordinator.creation_reservation(&sealed)?;
    if let Some(owner) = owner {
        let class = LiveTransactionClass::Creation;
        coordinator
            .transaction_owners
            .insert(transaction_id, (owner, class));
    }
    let completion =
        coordinator.commit_creation_start(context, committed, generation, 1, sealed, reservation);
    Ok((completion, transaction_id))
}

fn commit_credential(
    live: &mut Live,
    account_id: AccountId,
    lag: u64,
    owner: Option<ConnectionGeneration>,
) -> TestResult<(Option<CarrierCompletion>, TransactionId)> {
    let (start, _) = begin_unavailable_credential_change(live, 1, account_id)?;
    let transaction_id = start.transaction_id();
    let count = live.response_count()?;
    let sealed = start.seal(count)?;
    let committed = count.saturating_add(1).saturating_sub(lag);
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    if let Some(owner) = owner {
        let class = LiveTransactionClass::CredentialChange;
        coordinator
            .transaction_owners
            .insert(transaction_id, (owner, class));
    }
    let completion =
        coordinator.commit_credential_start(context, committed, generation, 1, sealed, None);
    Ok((completion, transaction_id))
}

#[test]
fn an_authentication_start_applied_before_its_response_count_is_visible_closes() -> TestResult {
    let mut live = Live::open()?;
    let (completion, transaction_id) = commit_authentication(&mut live, 1, None)?;
    assert_closed(completion, live.generation);
    let owners = &live.fixture.coordinator.transaction_owners;
    assert!(!owners.contains_key(&transaction_id));
    Ok(())
}

#[test]
fn a_creation_start_applied_before_its_response_count_is_visible_closes() -> TestResult {
    let mut live = Live::open()?;
    let (completion, transaction_id) = commit_creation(&mut live, 1, None)?;
    assert_closed(completion, live.generation);
    let owners = &live.fixture.coordinator.transaction_owners;
    assert!(!owners.contains_key(&transaction_id));
    Ok(())
}

#[test]
fn a_credential_start_applied_before_its_response_count_is_visible_closes() -> TestResult {
    let (mut live, account_id) = Live::open_registered()?;
    let (completion, transaction_id) = commit_credential(&mut live, account_id, 1, None)?;
    assert_closed(completion, live.generation);
    let owners = &live.fixture.coordinator.transaction_owners;
    assert!(!owners.contains_key(&transaction_id));
    Ok(())
}

#[test]
fn an_authentication_start_whose_transaction_is_already_owned_closes() -> TestResult {
    let mut live = Live::open()?;
    let (completion, transaction_id) = commit_authentication(&mut live, 0, Some(OTHER))?;
    assert_closed(completion, live.generation);
    let coordinator = &live.fixture.coordinator;
    let connection = coordinator.connections.get(&live.generation);
    assert!(connection.is_some_and(|connection| connection.transaction.is_none()));
    // The earlier owner keeps the transaction; nothing was queued on its behalf.
    assert!(coordinator.transaction_owners.contains_key(&transaction_id));
    assert!(coordinator.cleanup_queue.is_empty());
    Ok(())
}

#[test]
fn a_creation_start_whose_transaction_is_already_owned_closes() -> TestResult {
    let mut live = Live::open()?;
    let (completion, transaction_id) = commit_creation(&mut live, 0, Some(OTHER))?;
    assert_closed(completion, live.generation);
    let coordinator = &live.fixture.coordinator;
    let connection = coordinator.connections.get(&live.generation);
    assert!(connection.is_some_and(|connection| connection.creation_transaction.is_none()));
    assert!(coordinator.transaction_owners.contains_key(&transaction_id));
    Ok(())
}

#[test]
fn a_credential_start_whose_transaction_is_already_owned_closes() -> TestResult {
    let (mut live, account_id) = Live::open_registered()?;
    let (completion, transaction_id) = commit_credential(&mut live, account_id, 0, Some(OTHER))?;
    assert_closed(completion, live.generation);
    let coordinator = &live.fixture.coordinator;
    let connection = coordinator.connections.get(&live.generation);
    assert!(connection.is_some_and(|connection| connection.credential_transaction.is_none()));
    assert!(coordinator.transaction_owners.contains_key(&transaction_id));
    Ok(())
}

fn assert_orphan_queued(live: &mut Live, transaction_id: TransactionId) -> TestResult {
    let (coordinator, context) = live.fixture.parts()?;
    assert!(!coordinator.transaction_owners.contains_key(&transaction_id));
    let queued = coordinator
        .cleanup_queue
        .iter()
        .any(|cleanup| cleanup.transaction_id == transaction_id);
    assert!(queued);
    let id = TimedId::Transaction(transaction_id);
    assert!(!context.timers_mut().cancel(TimerKind::Reservation, id));
    Ok(())
}

#[test]
fn an_authentication_start_committed_after_its_connection_closed_is_cleaned_up() -> TestResult {
    let mut live = Live::open()?;
    live.fixture.coordinator.connections.clear();
    let (completion, transaction_id) = commit_authentication(&mut live, 0, None)?;
    assert!(completion.is_none());
    assert_orphan_queued(&mut live, transaction_id)
}

#[test]
fn a_creation_start_committed_after_its_connection_closed_is_cleaned_up() -> TestResult {
    let mut live = Live::open()?;
    live.fixture.coordinator.connections.clear();
    let (completion, transaction_id) = commit_creation(&mut live, 0, None)?;
    assert!(completion.is_none());
    assert_orphan_queued(&mut live, transaction_id)
}

#[test]
fn a_credential_start_committed_after_its_connection_closed_is_cleaned_up() -> TestResult {
    let (mut live, account_id) = Live::open_registered()?;
    live.fixture.coordinator.connections.clear();
    let (completion, transaction_id) = commit_credential(&mut live, account_id, 0, None)?;
    assert!(completion.is_none());
    assert_orphan_queued(&mut live, transaction_id)
}

async fn sealed_rejected_finish(
    live: &mut Live,
) -> TestResult<(
    TransactionId,
    SealedAccountFinishOutcome<AuthenticationGrant>,
)> {
    let transaction_id = commit_authentication_start(live, 1, "finisher").await?;
    let (outcome, _) = rejected_authentication_finish(live, 2, transaction_id)?;
    Ok((transaction_id, outcome.seal(live.response_count()?)?))
}

struct FinishCommit {
    lag: u64,
    key_state: Option<LoginIndexKeyState>,
    migration: Option<CommittedLoginIndexMigration>,
}

fn commit_finish(
    live: &mut Live,
    transaction_id: TransactionId,
    sealed: SealedAccountFinishOutcome<AuthenticationGrant>,
    commit: FinishCommit,
) -> TestResult<CarrierCompletion> {
    let committed = live
        .response_count()?
        .saturating_add(1)
        .saturating_sub(commit.lag);
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    let at = context.now();
    Ok(coordinator.commit_finish(
        context,
        committed,
        generation,
        1,
        transaction_id,
        sealed,
        at,
        false,
        None,
        commit.key_state,
        commit.migration,
    ))
}

#[tokio::test]
async fn a_finish_whose_transaction_owner_vanished_closes_its_carrier() -> TestResult {
    let mut live = Live::open()?;
    let (transaction_id, sealed) = sealed_rejected_finish(&mut live).await?;
    live.fixture.coordinator.transaction_owners.clear();
    let commit = FinishCommit {
        lag: 0,
        key_state: None,
        migration: None,
    };
    let completion = commit_finish(&mut live, transaction_id, sealed, commit)?;
    assert_closed(Some(completion), live.generation);
    Ok(())
}

#[tokio::test]
async fn a_finish_applied_before_its_response_count_is_visible_closes() -> TestResult {
    let mut live = Live::open()?;
    let (transaction_id, sealed) = sealed_rejected_finish(&mut live).await?;
    let commit = FinishCommit {
        lag: 1,
        key_state: None,
        migration: None,
    };
    let completion = commit_finish(&mut live, transaction_id, sealed, commit)?;
    assert_closed(Some(completion), live.generation);
    Ok(())
}

#[tokio::test]
async fn a_committed_finish_installs_the_key_state_its_batch_wrote() -> TestResult {
    let mut live = Live::open()?;
    let (transaction_id, sealed) = sealed_rejected_finish(&mut live).await?;
    let network = live.fixture.core.identity.network_id;
    let key_id = LoginIndexKey::from_bytes([77; 32]).key_id(network);
    let key_state = LoginIndexKeyState::stable(9, key_id)?;
    let commit = FinishCommit {
        lag: 0,
        key_state: Some(key_state),
        migration: None,
    };
    let completion = commit_finish(&mut live, transaction_id, sealed, commit)?;
    assert!(!completion.close);
    assert_eq!(completion.result, ResultClass::Rejected);
    let installed = live.fixture.coordinator.config.login_index_key_state;
    assert_eq!(installed.current_generation(), 9);
    Ok(())
}

#[tokio::test]
async fn a_login_index_migration_without_an_accepted_grant_closes_its_carrier() -> TestResult {
    let mut live = Live::open()?;
    let (transaction_id, sealed) = sealed_rejected_finish(&mut live).await?;
    let migration = CommittedLoginIndexMigration {
        account_id: account(3),
        previous_key: StoredKey::new(vec![1; 40])?,
        current_key: StoredKey::new(vec![2; 40])?,
    };
    let commit = FinishCommit {
        lag: 0,
        key_state: None,
        migration: Some(migration),
    };
    let completion = commit_finish(&mut live, transaction_id, sealed, commit)?;
    assert_closed(Some(completion), live.generation);
    assert!(live.fixture.coordinator.config.live_login_keys.is_empty());
    Ok(())
}

struct CredentialCommit {
    lag: u64,
    reservation: Option<AccountId>,
}

async fn commit_rejected_credential_finish(
    live: &mut Live,
    account_id: AccountId,
    commit: CredentialCommit,
    forget_owner: bool,
) -> TestResult<Vec<CarrierCompletion>> {
    let transaction_id = commit_credential_start(live, 1, account_id).await?;
    let (outcome, _) = rejected_credential_finish(live, 2, transaction_id)?;
    let count = live.response_count()?;
    let sealed = outcome.seal(count)?;
    let committed = count.saturating_add(1).saturating_sub(commit.lag);
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    if forget_owner {
        coordinator.transaction_owners.clear();
    }
    Ok(coordinator.commit_credential_finish(
        context,
        committed,
        generation,
        1,
        transaction_id,
        sealed,
        commit.reservation,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    ))
}

#[tokio::test]
async fn a_credential_finish_whose_transaction_owner_vanished_closes() -> TestResult {
    let (mut live, account_id) = Live::open_registered()?;
    let commit = CredentialCommit {
        lag: 0,
        reservation: None,
    };
    let completions =
        commit_rejected_credential_finish(&mut live, account_id, commit, true).await?;
    assert_closed(completions.first().copied(), live.generation);
    Ok(())
}

#[tokio::test]
async fn a_credential_finish_whose_reservation_is_not_its_own_closes() -> TestResult {
    let (mut live, account_id) = Live::open_registered()?;
    let commit = CredentialCommit {
        lag: 0,
        reservation: Some(account_id),
    };
    let completions =
        commit_rejected_credential_finish(&mut live, account_id, commit, false).await?;
    assert_closed(completions.first().copied(), live.generation);
    Ok(())
}

#[tokio::test]
async fn a_credential_finish_applied_before_its_response_count_is_visible_closes() -> TestResult {
    let (mut live, account_id) = Live::open_registered()?;
    let commit = CredentialCommit {
        lag: 1,
        reservation: None,
    };
    let completions =
        commit_rejected_credential_finish(&mut live, account_id, commit, false).await?;
    assert_closed(completions.first().copied(), live.generation);
    Ok(())
}

#[tokio::test]
async fn a_rejected_credential_finish_completes_without_closing_any_connection() -> TestResult {
    let (mut live, account_id) = Live::open_registered()?;
    let commit = CredentialCommit {
        lag: 0,
        reservation: None,
    };
    let completions =
        commit_rejected_credential_finish(&mut live, account_id, commit, false).await?;
    let [completion] = completions.as_slice() else {
        return Err("one completion".into());
    };
    assert!(!completion.close);
    assert_eq!(completion.result, ResultClass::Rejected);
    Ok(())
}

fn rejected_credential_start_authority(
    live: &mut Live,
    account_id: AccountId,
) -> TestResult<PendingAuthority> {
    let (start, _) = begin_unavailable_credential_change(live, 1, account_id)?;
    Ok(PendingAuthority::CredentialStart {
        generation: live.generation,
        carrier_generation: 4,
        sealed: start.seal(live.response_count()?)?,
        reservation: Some(account_id),
    })
}

#[test]
fn a_rejected_credential_start_batch_releases_the_origins_reservation() -> TestResult {
    let (mut live, account_id) = Live::open_registered()?;
    let authority = rejected_credential_start_authority(&mut live, account_id)?;
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    coordinator.pending_authority = Some(authority);
    coordinator
        .credential_reservations
        .insert(account_id, generation);
    let completions = coordinator.batch_rejected(context, Some(generation));
    assert!(matches!(
        completions.as_slice(),
        [completion] if completion.close && completion.carrier_generation == 4
    ));
    assert!(coordinator.credential_reservations.is_empty());
    Ok(())
}

#[test]
fn a_rejected_credential_start_batch_keeps_a_reservation_another_connection_owns() -> TestResult {
    let (mut live, account_id) = Live::open_registered()?;
    let authority = rejected_credential_start_authority(&mut live, account_id)?;
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    coordinator.pending_authority = Some(authority);
    coordinator
        .credential_reservations
        .insert(account_id, OTHER);
    let completions = coordinator.batch_rejected(context, Some(generation));
    assert_eq!(completions.len(), 1);
    assert_eq!(
        coordinator.credential_reservations.get(&account_id),
        Some(&OTHER)
    );
    Ok(())
}

#[tokio::test]
async fn a_rejected_finish_batch_queues_the_transaction_it_consumed() -> TestResult {
    let mut live = Live::open()?;
    let (transaction_id, sealed) = sealed_rejected_finish(&mut live).await?;
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    coordinator.pending_authority = Some(PendingAuthority::Finish {
        generation,
        carrier_generation: 2,
        transaction_id,
        sealed,
        account_id: None,
        authenticated_at: MonotonicTick::from_ticks(0),
        sasl_accepted: false,
        fresh_auth_session: None,
        resulting_key_state: None,
        login_index_migration: None,
    });
    let completions = coordinator.batch_rejected(context, Some(generation));
    assert!(matches!(completions.as_slice(), [completion] if completion.close));
    assert!(!coordinator.transaction_owners.contains_key(&transaction_id));
    let cleanup = coordinator.pending_cleanups.first();
    assert!(cleanup.is_some_and(|cleanup| cleanup.transaction_id == transaction_id));
    Ok(())
}

#[test]
fn a_rejected_client_batch_leaves_unrelated_pending_cleanups_in_flight() -> TestResult {
    let mut live = Live::open()?;
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    let cleanup = TransactionCleanup::authentication(TransactionId::from_bytes([8; 16]));
    coordinator.pending_cleanups.push(cleanup);
    coordinator.pending_authority = Some(PendingAuthority::Logout {
        generation,
        carrier_generation: 3,
    });
    let completions = coordinator.batch_rejected(context, Some(generation));
    assert!(matches!(completions.as_slice(), [completion] if completion.close));
    assert_eq!(coordinator.pending_cleanups.len(), 1);
    assert!(coordinator.cleanup_queue.is_empty());
    Ok(())
}
