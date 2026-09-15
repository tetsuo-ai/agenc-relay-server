//! ZDH-A1 (issue #38): the invitation interval is re-evaluated at durable admission.
//!
//! These tests drive the coordinator with real auth-crate START and FINISH
//! transactions, deterministic clocks and the fixture's actual storage. They
//! use the profile's fixed OPAQUE registration vectors rather than an OPAQUE
//! client, so they exercise the runtime admission boundary, not OPAQUE itself.
#![forbid(unsafe_code)]

use super::*;
use crate::account_service::{LiveCreation, ReadyStage, request_result_key};
use crate::connection::ClientSink;
use crate::purpose::ListenerPurpose;
use crate::state_core::inbox::SourceAddressKey;
use crate::state_core::timers::{TimedId, TimerKind};
use crate::test_support::{FixtureIdentity, FrameSink, TestResult};
use agenc_ircd_auth::{
    AccountCreationInvite, AccountCreationStartParameters, AccountRequestPayload,
    AccountServiceEnvelope, CreateAccountIntent, CreationAdmission, CreationFinish, CreationStart,
    OpaqueRegistrationRecord, OpaqueRegistrationRequest, OpenedAccountServiceRequest,
    SealedAccountFinishOutcome, begin_account_creation, encode_request_plaintext,
    finish_account_creation, open_and_parse_request,
};
use agenc_ircd_client_wire::{ACCOUNT_RESPONSE_BYTES, AccountTransfer};
use agenc_ircd_crypto::{
    AccountHpkePrivateKey, AccountRequestBinding, Ed25519SecretKey, LoginIndexKey,
    seal_account_request,
};
use agenc_ircd_storage::ReadPlan;
use agenc_ircd_types::RequestId;

const OPAQUE_VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-data/vectors/stage-four-opaque-v1.vectors"
));
const NOT_BEFORE: u64 = 10;
const EXPIRES_AT: u64 = 20;
const CREATION_AUTHORITY: [u8; 32] = [94; 32];
const FIXTURE_HPKE_KEY: [u8; 32] = [40; 32];

fn hex_nibble(byte: u8) -> TestResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("OPAQUE vector is not lowercase hexadecimal".into()),
    }
}

fn vector<const N: usize>(name: &str) -> TestResult<[u8; N]> {
    let record = OPAQUE_VECTORS
        .lines()
        .find(|line| line.starts_with("VEC-S04-007-OPAQUE|"))
        .ok_or("OPAQUE vector record is absent")?;
    let encoded = record
        .split('|')
        .skip(3)
        .find_map(|item| {
            item.split_once('=')
                .filter(|(candidate, _)| *candidate == name)
                .map(|(_, value)| value)
        })
        .ok_or("OPAQUE vector field is absent")?;
    let (pairs, remainder) = encoded.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() || pairs.len() != N {
        return Err("OPAQUE vector length does not match the requested size".into());
    }
    let mut decoded = [0_u8; N];
    for (slot, [high, low]) in decoded.iter_mut().zip(pairs) {
        *slot = (hex_nibble(*high)? << 4) | hex_nibble(*low)?;
    }
    Ok(decoded)
}

fn base64url(bytes: &[u8]) -> TestResult<String> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut encoded = String::new();
    for chunk in bytes.chunks(3) {
        let mut value = 0_u32;
        for byte in chunk {
            value = (value << 8) | u32::from(*byte);
        }
        let missing = 3 - chunk.len();
        value <<= 8 * missing;
        for index in 0..=chunk.len() {
            let shift = 18 - 6 * index;
            let sextet = usize::try_from((value >> shift) & 0x3f)?;
            let symbol = *ALPHABET.get(sextet).ok_or("base64 alphabet index")?;
            encoded.push(char::from(symbol));
        }
    }
    Ok(encoded)
}

fn opened_request(
    identity: &FixtureIdentity,
    request_seed: u8,
    payload: AccountRequestPayload,
) -> TestResult<(OpenedAccountServiceRequest, AccountServiceEnvelope)> {
    let private_key = AccountHpkePrivateKey::from_bytes(FIXTURE_HPKE_KEY)?;
    let public_key = private_key.public_key()?;
    let kind = payload.message_kind();
    let binding = AccountRequestBinding::new(
        identity.network_id,
        identity.recovery_epoch,
        public_key.key_id(),
        RequestId::from_bytes([request_seed; 16]),
        kind,
    );
    let plaintext = encode_request_plaintext(&payload)?;
    let (sealed, _token) = seal_account_request(public_key, binding, plaintext.expose_for_hpke())?;
    let envelope = AccountServiceEnvelope::from_sealed(sealed)?;
    let opened = open_and_parse_request(
        &private_key,
        identity.recovery_epoch,
        identity.network_id,
        kind,
        &envelope,
    )?;
    Ok((opened, envelope))
}

fn issued_invitation(
    identity: &FixtureIdentity,
    invite_byte: u8,
) -> TestResult<(AccountCreationInvite, Ed25519SecretKey)> {
    let authority = Ed25519SecretKey::from_bytes(CREATION_AUTHORITY);
    let invitation = AccountCreationInvite::issue(
        identity.network_id,
        InviteId::from_bytes([invite_byte; 16]),
        UtcSecond::from_unix_seconds(NOT_BEFORE),
        UtcSecond::from_unix_seconds(EXPIRES_AT),
        &authority,
    )?;
    Ok((invitation, authority))
}

fn request(
    generation: ConnectionGeneration,
    carrier_generation: u64,
    route: ConnectionRoute,
    phase: AccountCarrierPhase,
    envelope: AccountServiceEnvelope,
) -> RequestContext {
    RequestContext {
        generation,
        carrier_generation,
        target: "tester".to_owned(),
        route,
        envelope,
        carrier: RequestCarrier::Account(AccountCarrierKind::Create),
        phase,
    }
}

/// Feeds one complete chunked ACCTCREATE request so the carrier waits for
/// the phase response exactly as it would after a real client exchange.
fn feed_transfer(
    transfer: &mut AccountTransfer,
    phase: AccountCarrierPhase,
    envelope: &AccountServiceEnvelope,
    now: u64,
) -> TestResult {
    let subcommand = match phase {
        AccountCarrierPhase::Start => "START",
        AccountCarrierPhase::Finish => "FINISH",
    };
    transfer
        .client(subcommand, Some("4726"), false, now)
        .map_err(|_| "the carrier refused the phase begin")?;
    let encoded = base64url(envelope.as_bytes())?;
    let mut rest = encoded.as_str();
    while !rest.is_empty() {
        let (chunk, tail) = rest.split_at(rest.len().min(400));
        transfer
            .client("DATA", Some(chunk), false, now)
            .map_err(|_| "the carrier refused a request chunk")?;
        rest = tail;
    }
    transfer
        .client("END", None, false, now)
        .map_err(|_| "the carrier refused the request end")?;
    Ok(())
}

fn open_connection(
    fixture: &mut CoordinatorFixture,
    generation: ConnectionGeneration,
) -> TestResult<(Arc<FrameSink>, ConnectionRoute)> {
    let sink = FrameSink::new(generation, true);
    let (coordinator, context) = fixture.parts()?;
    let now = context.now();
    context.sessions_mut().open(
        generation,
        ListenerPurpose::ClientOnion,
        SourceAddressKey::onion_listener(),
        Arc::clone(&sink) as Arc<dyn ClientSink>,
        now,
    )?;
    coordinator
        .connection_opened(context, generation)
        .map_err(|error| format!("open connection {generation:?}: {error:?}"))?;
    let route = coordinator
        .connections
        .get(&generation)
        .ok_or("connection")?
        .route;
    Ok((sink, route))
}

fn transfer(
    coordinator: &mut AccountServiceCoordinator,
    generation: ConnectionGeneration,
) -> TestResult<&mut AccountTransfer> {
    Ok(&mut coordinator
        .connections
        .get_mut(&generation)
        .ok_or("connection")?
        .creation)
}

/// Commits one creation START through the real staging path and installs its
/// live transaction, reservation timer and ownership on the connection.
async fn commit_start(
    fixture: &mut CoordinatorFixture,
    generation: ConnectionGeneration,
    route: ConnectionRoute,
    request_seed: u8,
    login: &str,
    invite_byte: Option<u8>,
    wall: u64,
) -> TestResult<TransactionId> {
    let (invitation, admission) = match invite_byte {
        Some(byte) => {
            let (invitation, authority) = issued_invitation(&fixture.core.identity, byte)?;
            (
                Some(invitation),
                CreationAdmission::Invitation {
                    authority: authority.public_key(),
                    now: UtcSecond::from_unix_seconds(wall),
                },
            )
        }
        None => (None, CreationAdmission::Open),
    };
    let payload = AccountRequestPayload::CreationStart(CreationStart {
        network_id: fixture.core.identity.network_id,
        login: NormalizedLogin::prepare(login)?,
        registration_request: OpaqueRegistrationRequest::from_bytes(vector(
            "registration_request",
        )?)?,
        invitation,
    });
    let (opened, envelope) = opened_request(&fixture.core.identity, request_seed, payload)?;
    let OpenedAccountServiceRequest::CreationStart(start_request) = opened else {
        return Err("opened request kind changed".into());
    };
    let login_key = LoginIndexKey::from_bytes(fixture.core.identity.login_index);
    let opaque = Arc::clone(&fixture.core.opaque);
    let (coordinator, context) = fixture.parts()?;
    context.set_wall_for_test(wall);
    let operation = coordinator
        .operation_context(context, route)
        .map_err(|error| format!("START operation context: {error:?}"))?;
    let start = begin_account_creation(
        &opaque,
        &login_key,
        AccountCreationStartParameters {
            context: operation,
            request: start_request,
            admission,
            login_is_available: true,
            invitation_is_available: true,
        },
    )?;
    let transaction_id = start.transaction_id();
    let sealed = start.seal(context.head().account_service_response_count)?;
    let now = context.now().get();
    feed_transfer(
        transfer(coordinator, generation)?,
        AccountCarrierPhase::Start,
        &envelope,
        now,
    )?;
    coordinator
        .stage_creation_start(
            context,
            request(generation, 1, route, AccountCarrierPhase::Start, envelope),
            sealed,
        )
        .map_err(|error| format!("stage creation START: {error:?}"))?;
    fixture
        .core
        .commit_staged_batch()
        .await
        .map_err(|error| format!("commit creation START: {error}"))?;
    let (coordinator, context) = fixture.parts()?;
    let completions = coordinator.batch_applied(context);
    assert_eq!(completions.len(), 1);
    assert!(
        coordinator
            .connections
            .get(&generation)
            .is_some_and(|connection| connection.creation_transaction.is_some())
    );
    assert!(coordinator.transaction_owners.contains_key(&transaction_id));
    Ok(transaction_id)
}

/// One worker-side FINISH result, boxed so the async helpers that await
/// storage receipts do not carry the sealed outcome in their futures.
struct WorkerOutcome {
    transaction_id: TransactionId,
    sealed: SealedAccountFinishOutcome<CreateAccountIntent>,
    reservation: Option<CreationReservation>,
    envelope: AccountServiceEnvelope,
}

/// The worker-side FINISH: the live transaction leaves the connection, the
/// trusted UTC read taken at open becomes the operation context, and the
/// auth crate produces the sealed outcome the runtime later admits.
fn worker_finish(
    fixture: &mut CoordinatorFixture,
    generation: ConnectionGeneration,
    route: ConnectionRoute,
    request_seed: u8,
    transaction_id: TransactionId,
    worker_wall: u64,
) -> TestResult<Box<WorkerOutcome>> {
    let payload = AccountRequestPayload::CreationFinish(CreationFinish {
        network_id: fixture.core.identity.network_id,
        transaction_id,
        registration_record: OpaqueRegistrationRecord::from_bytes(vector("registration_record")?)?,
    });
    let (opened, envelope) = opened_request(&fixture.core.identity, request_seed, payload)?;
    let OpenedAccountServiceRequest::CreationFinish(finish_request) = opened else {
        return Err("opened request kind changed".into());
    };
    let (coordinator, context) = fixture.parts()?;
    context.set_wall_for_test(worker_wall);
    let LiveCreation {
        mut transaction,
        reservation,
    } = coordinator
        .connections
        .get_mut(&generation)
        .ok_or("connection")?
        .creation_transaction
        .take()
        .ok_or("live creation transaction")?;
    context
        .timers_mut()
        .cancel(TimerKind::Reservation, TimedId::Transaction(transaction_id));
    let operation = coordinator
        .operation_context(context, route)
        .map_err(|error| format!("FINISH operation context: {error:?}"))?;
    let outcome = finish_account_creation(&mut transaction, operation, finish_request)?;
    let sealed = outcome.seal(context.head().account_service_response_count)?;
    let now = context.now().get();
    feed_transfer(
        transfer(coordinator, generation)?,
        AccountCarrierPhase::Finish,
        &envelope,
        now,
    )?;
    Ok(Box::new(WorkerOutcome {
        transaction_id,
        sealed,
        reservation,
        envelope,
    }))
}

fn committed_account(
    sealed: &SealedAccountFinishOutcome<CreateAccountIntent>,
) -> TestResult<AccountId> {
    sealed
        .result()
        .map(CreateAccountIntent::account_id)
        .map_err(|_| "the worker outcome must be committed".into())
}

fn opaque_key(account_id: AccountId) -> TestResult<StoredKey> {
    Ok(StoredKey::new(account_id.to_text().into_bytes())?)
}

fn invite_key(invite_byte: u8) -> TestResult<StoredKey> {
    Ok(StoredKey::new(
        InviteId::from_bytes([invite_byte; 16]).as_bytes().to_vec(),
    )?)
}

fn transaction_key(transaction_id: TransactionId) -> TestResult<StoredKey> {
    Ok(StoredKey::new(transaction_id.as_bytes().to_vec())?)
}

/// Runs the failed durable admission through `stage_ready`, then commits the
/// queued creation cleanup so the reservations are really released.
async fn refuse_and_clean_up(
    fixture: &mut CoordinatorFixture,
    generation: ConnectionGeneration,
    route: ConnectionRoute,
    outcome: Box<WorkerOutcome>,
    stage_wall: Option<u64>,
) -> TestResult<AccountId> {
    let WorkerOutcome {
        transaction_id,
        sealed,
        reservation,
        envelope,
    } = *outcome;
    let account_id = committed_account(&sealed)?;
    let login_key = reservation.as_ref().ok_or("reservation")?.login_key.clone();
    let (coordinator, context) = fixture.parts()?;
    context.set_untrusted_wall_for_test(stage_wall);
    let pending_before = context.pending_len();
    coordinator.ready_stage = Some(ReadyStage::CreationFinish {
        request: request(generation, 2, route, AccountCarrierPhase::Finish, envelope),
        transaction_id,
        sealed,
        reservation,
    });
    let completion = coordinator
        .stage_ready(context)
        .err()
        .ok_or("durable admission must refuse the finish")?;
    assert_eq!(completion.generation, generation);
    assert!(completion.close);
    assert!(coordinator.pending_authority.is_none());
    assert!(coordinator.ready_stage.is_none());
    assert_eq!(context.pending_len(), pending_before);
    assert!(context.domain().account(account_id).is_none());
    assert!(!coordinator.config.live_login_keys.contains_key(&account_id));
    let cleanup = coordinator.cleanup_queue.back().ok_or("queued cleanup")?;
    assert_eq!(cleanup.transaction_id, transaction_id);
    assert_eq!(cleanup.durable_writes()?.len(), 3);
    // The one-use FINISH is spent: the connection holds no live transaction
    // and the coordinator still owns the cleanup until it commits.
    assert!(
        coordinator
            .connections
            .get(&generation)
            .is_some_and(|connection| connection.creation_transaction.is_none())
    );
    context.set_wall_for_test(stage_wall.unwrap_or(EXPIRES_AT));
    let completions = coordinator.progress(context);
    assert!(completions.is_empty());
    assert_eq!(context.pending_len(), 1);
    fixture.core.commit_staged_batch().await?;
    let (coordinator, context) = fixture.parts()?;
    assert!(coordinator.batch_applied(context).is_empty());
    assert!(!coordinator.transaction_owners.contains_key(&transaction_id));
    assert!(
        !fixture
            .core
            .stored_row_exists(TableId::AuthTransaction, transaction_key(transaction_id)?)?
    );
    assert!(
        !fixture
            .core
            .stored_row_exists(TableId::LoginIndex, login_key)?
    );
    assert!(
        !fixture
            .core
            .stored_row_exists(TableId::OpaqueRecord, opaque_key(account_id)?)?
    );
    Ok(account_id)
}

/// Stages one worker outcome at `stage_wall`, commits it and installs the
/// live login key exactly as the state core does after the storage receipt.
async fn commit_finish(
    fixture: &mut CoordinatorFixture,
    generation: ConnectionGeneration,
    route: ConnectionRoute,
    outcome: Box<WorkerOutcome>,
    stage_wall: u64,
) -> TestResult<CarrierCompletion> {
    let WorkerOutcome {
        transaction_id,
        sealed,
        reservation,
        envelope,
    } = *outcome;
    let (coordinator, context) = fixture.parts()?;
    context.set_wall_for_test(stage_wall);
    coordinator
        .stage_creation_finish(
            context,
            request(generation, 2, route, AccountCarrierPhase::Finish, envelope),
            transaction_id,
            sealed,
            reservation,
        )
        .map_err(|error| format!("stage creation FINISH: {error:?}"))?;
    assert!(matches!(
        coordinator.pending_authority,
        Some(PendingAuthority::CreationFinish { .. })
    ));
    fixture
        .core
        .commit_staged_batch()
        .await
        .map_err(|error| format!("commit creation FINISH: {error}"))?;
    let (coordinator, context) = fixture.parts()?;
    let mut completions = coordinator.batch_applied(context);
    assert_eq!(completions.len(), 1);
    assert!(!coordinator.transaction_owners.contains_key(&transaction_id));
    completions.pop().ok_or_else(|| "completion".into())
}

fn assert_account_published(
    fixture: &CoordinatorFixture,
    account_id: AccountId,
    invite_byte: u8,
    transaction_id: TransactionId,
) -> TestResult {
    assert!(
        fixture
            .coordinator
            .config
            .live_login_keys
            .contains_key(&account_id)
    );
    assert!(
        fixture
            .core
            .stored_row_exists(TableId::OpaqueRecord, opaque_key(account_id)?)?
    );
    assert!(
        fixture
            .core
            .stored_row_exists(TableId::RegistrationInvite, invite_key(invite_byte)?)?
    );
    assert!(
        !fixture
            .core
            .stored_row_exists(TableId::AuthTransaction, transaction_key(transaction_id)?)?
    );
    Ok(())
}

#[tokio::test]
async fn durable_admission_refuses_a_valid_worker_finish_whose_wall_clock_passed_expiry()
-> TestResult {
    let mut fixture = CoordinatorFixture::new(vec![7; 512])?;
    let generation = ConnectionGeneration::new(1);
    let (sink, route) = open_connection(&mut fixture, generation)?;
    let transaction_id = commit_start(
        &mut fixture,
        generation,
        route,
        1,
        "invited-user",
        Some(93),
        EXPIRES_AT - 1,
    )
    .await?;
    let outcome = worker_finish(
        &mut fixture,
        generation,
        route,
        2,
        transaction_id,
        EXPIRES_AT - 1,
    )?;
    assert_eq!(
        outcome
            .sealed
            .result()
            .ok()
            .and_then(CreateAccountIntent::invitation_interval),
        Some((
            UtcSecond::from_unix_seconds(NOT_BEFORE),
            UtcSecond::from_unix_seconds(EXPIRES_AT)
        ))
    );
    let lines_before = sink.lines().len();
    let account_id = refuse_and_clean_up(
        &mut fixture,
        generation,
        route,
        outcome,
        Some(EXPIRES_AT + 1),
    )
    .await?;
    assert_eq!(sink.lines().len(), lines_before);
    assert!(
        fixture
            .core
            .context_mut()?
            .domain()
            .account(account_id)
            .is_none()
    );
    assert!(
        !fixture
            .core
            .stored_row_exists(TableId::RegistrationInvite, invite_key(93)?)?
    );

    // Neither an unrelated open-policy creation nor a distinct unexpired
    // invitation is affected by the refusal.
    let second = ConnectionGeneration::new(2);
    let (_sink, second_route) = open_connection(&mut fixture, second)?;
    let second_transaction = commit_start(
        &mut fixture,
        second,
        second_route,
        3,
        "second-invited-user",
        Some(95),
        EXPIRES_AT - 1,
    )
    .await?;
    let outcome = worker_finish(
        &mut fixture,
        second,
        second_route,
        4,
        second_transaction,
        EXPIRES_AT - 1,
    )?;
    let second_account = committed_account(&outcome.sealed)?;
    let completion =
        commit_finish(&mut fixture, second, second_route, outcome, EXPIRES_AT - 1).await?;
    assert!(!completion.close);
    assert_account_published(&fixture, second_account, 95, second_transaction)?;

    let third = ConnectionGeneration::new(3);
    let (_sink, third_route) = open_connection(&mut fixture, third)?;
    let third_transaction = commit_start(
        &mut fixture,
        third,
        third_route,
        5,
        "open-policy-user",
        None,
        EXPIRES_AT + 5,
    )
    .await?;
    let outcome = worker_finish(
        &mut fixture,
        third,
        third_route,
        6,
        third_transaction,
        EXPIRES_AT + 5,
    )?;
    let third_account = committed_account(&outcome.sealed)?;
    assert!(
        outcome
            .sealed
            .result()
            .ok()
            .and_then(CreateAccountIntent::invitation_interval)
            .is_none()
    );
    let completion =
        commit_finish(&mut fixture, third, third_route, outcome, EXPIRES_AT + 40).await?;
    assert!(!completion.close);
    assert!(
        fixture
            .coordinator
            .config
            .live_login_keys
            .contains_key(&third_account)
    );
    assert!(
        fixture
            .core
            .stored_row_exists(TableId::OpaqueRecord, opaque_key(third_account)?)?
    );
    Ok(())
}

#[tokio::test]
async fn durable_admission_refuses_a_wall_clock_before_not_before_or_no_trusted_clock() -> TestResult
{
    for stage_wall in [Some(NOT_BEFORE - 1), None] {
        let mut fixture = CoordinatorFixture::new(vec![9; 512])?;
        let generation = ConnectionGeneration::new(1);
        let (_sink, route) = open_connection(&mut fixture, generation)?;
        let transaction_id = commit_start(
            &mut fixture,
            generation,
            route,
            1,
            "invited-user",
            Some(93),
            NOT_BEFORE,
        )
        .await?;
        let outcome = worker_finish(
            &mut fixture,
            generation,
            route,
            2,
            transaction_id,
            NOT_BEFORE,
        )?;
        let account_id =
            refuse_and_clean_up(&mut fixture, generation, route, outcome, stage_wall).await?;
        assert!(
            !fixture
                .core
                .stored_row_exists(TableId::RegistrationInvite, invite_key(93)?)?
        );
        assert!(
            fixture
                .core
                .context_mut()?
                .domain()
                .account(account_id)
                .is_none()
        );
    }
    Ok(())
}

#[tokio::test]
async fn finish_inside_the_interval_commits_at_both_exact_boundaries() -> TestResult {
    for (invite_byte, wall) in [(93_u8, NOT_BEFORE), (95_u8, EXPIRES_AT - 1)] {
        let mut fixture = CoordinatorFixture::new(vec![11; 512])?;
        let generation = ConnectionGeneration::new(1);
        let (sink, route) = open_connection(&mut fixture, generation)?;
        let login = format!("boundary-user-{invite_byte}");
        let transaction_id = commit_start(
            &mut fixture,
            generation,
            route,
            1,
            &login,
            Some(invite_byte),
            wall,
        )
        .await?;
        let outcome = worker_finish(&mut fixture, generation, route, 2, transaction_id, wall)?;
        let account_id = committed_account(&outcome.sealed)?;
        assert_eq!(
            outcome
                .sealed
                .result()
                .ok()
                .map(CreateAccountIntent::invitation_id),
            Some(Some(InviteId::from_bytes([invite_byte; 16])))
        );
        let completion = commit_finish(&mut fixture, generation, route, outcome, wall).await?;
        assert!(!completion.close);
        assert_eq!(completion.result, ResultClass::Ok);
        assert_account_published(&fixture, account_id, invite_byte, transaction_id)?;
        assert!(
            fixture
                .core
                .context_mut()?
                .domain()
                .account(account_id)
                .is_some()
        );
        assert!(
            sink.lines()
                .iter()
                .any(|line| line.contains(&account_id.to_text()))
        );
        // A restart after the committed FINISH reconstructs the exact rows
        // and finds no stale creation authority to clean up.
        fixture.core.restart_registration_storage(vec![11; 64])?;
        assert!(
            fixture
                .core
                .stored_row_exists(TableId::OpaqueRecord, opaque_key(account_id)?)?
        );
        assert!(
            fixture
                .core
                .stored_row_exists(TableId::RegistrationInvite, invite_key(invite_byte)?)?
        );
        assert!(
            !fixture
                .core
                .stored_row_exists(TableId::AuthTransaction, transaction_key(transaction_id)?)?
        );
        assert!(
            fixture
                .core
                .context_mut()?
                .domain()
                .account(account_id)
                .is_some()
        );
        assert_eq!(fixture.core.recovered_startup_cleanup_count()?, 0);
    }
    Ok(())
}

#[tokio::test]
async fn worker_time_expiry_inside_the_transaction_ttl_is_a_rejected_completion() -> TestResult {
    for worker_wall in [EXPIRES_AT, EXPIRES_AT + 1] {
        let mut fixture = CoordinatorFixture::new(vec![13; 512])?;
        let generation = ConnectionGeneration::new(1);
        let (sink, route) = open_connection(&mut fixture, generation)?;
        let transaction_id = commit_start(
            &mut fixture,
            generation,
            route,
            1,
            "late-user",
            Some(93),
            EXPIRES_AT - 1,
        )
        .await?;
        let login_key = fixture
            .coordinator
            .connections
            .get(&generation)
            .and_then(|connection| connection.creation_transaction.as_ref())
            .and_then(|live| live.reservation.as_ref())
            .ok_or("reservation")?
            .login_key
            .clone();
        let outcome = worker_finish(
            &mut fixture,
            generation,
            route,
            2,
            transaction_id,
            worker_wall,
        )?;
        assert_eq!(
            outcome.sealed.result().err(),
            Some(agenc_ircd_auth::AuthError::InvitationRejected)
        );
        assert!(
            fixture
                .coordinator
                .connections
                .get(&generation)
                .is_some_and(|connection| connection.creation_transaction.is_none())
        );
        let completion =
            commit_finish(&mut fixture, generation, route, outcome, worker_wall).await?;
        assert!(!completion.close);
        assert_eq!(completion.result, ResultClass::Rejected);
        assert!(fixture.coordinator.config.live_login_keys.is_empty());
        assert!(
            !fixture
                .core
                .stored_row_exists(TableId::LoginIndex, login_key)?
        );
        assert!(
            !fixture
                .core
                .stored_row_exists(TableId::RegistrationInvite, invite_key(93)?)?
        );
        assert!(
            !fixture
                .core
                .stored_row_exists(TableId::AuthTransaction, transaction_key(transaction_id)?)?
        );
        assert!(
            !fixture
                .core
                .read_rows(ReadPlan::range(
                    TableId::OpaqueRecord,
                    StoredKey::new(vec![b'A'])?,
                    StoredKey::new(vec![b'z'; 24])?,
                    4,
                )?)?
                .records
                .iter()
                .any(|row| row.key.as_bytes() != agenc_ircd_storage::OPAQUE_FAKE_RECORD_KEY)
        );
        // The generic failure frame is the only client-visible outcome.
        assert!(sink.lines().iter().any(|line| line.contains("FAIL")));
    }
    Ok(())
}

#[tokio::test]
async fn refused_batch_after_a_valid_finish_publishes_nothing_and_releases_reservations()
-> TestResult {
    let mut fixture = CoordinatorFixture::new(vec![15; 512])?;
    let generation = ConnectionGeneration::new(1);
    let (_sink, route) = open_connection(&mut fixture, generation)?;
    let transaction_id = commit_start(
        &mut fixture,
        generation,
        route,
        1,
        "refused-user",
        Some(93),
        EXPIRES_AT - 1,
    )
    .await?;
    let outcome = worker_finish(
        &mut fixture,
        generation,
        route,
        2,
        transaction_id,
        EXPIRES_AT - 1,
    )?;
    let account_id = committed_account(&outcome.sealed)?;
    let WorkerOutcome {
        transaction_id,
        sealed,
        reservation,
        envelope,
    } = *outcome;
    let login_key = reservation.as_ref().ok_or("reservation")?.login_key.clone();
    let (coordinator, context) = fixture.parts()?;
    coordinator.stage_creation_finish(
        context,
        request(generation, 2, route, AccountCarrierPhase::Finish, envelope),
        transaction_id,
        sealed,
        reservation,
    )?;
    assert_eq!(context.pending_len(), 1);
    // The state core discards the refused batch before telling the owner.
    context.discard_pending_for_test();
    let completions = coordinator.batch_rejected(context, Some(generation));
    assert!(
        completions
            .first()
            .is_some_and(|completion| completion.close)
    );
    assert!(coordinator.pending_authority.is_none());
    assert!(!coordinator.config.live_login_keys.contains_key(&account_id));
    assert_eq!(context.pending_len(), 1, "the creation cleanup is staged");
    fixture.core.commit_staged_batch().await?;
    let (coordinator, context) = fixture.parts()?;
    assert!(coordinator.batch_applied(context).is_empty());
    assert!(!coordinator.transaction_owners.contains_key(&transaction_id));
    assert!(
        !fixture
            .core
            .stored_row_exists(TableId::OpaqueRecord, opaque_key(account_id)?)?
    );
    assert!(
        !fixture
            .core
            .stored_row_exists(TableId::LoginIndex, login_key)?
    );
    assert!(
        !fixture
            .core
            .stored_row_exists(TableId::RegistrationInvite, invite_key(93)?)?
    );
    assert!(
        !fixture
            .core
            .stored_row_exists(TableId::AuthTransaction, transaction_key(transaction_id)?)?
    );
    Ok(())
}

#[tokio::test]
async fn committed_success_replays_the_exact_stored_result_after_expiry() -> TestResult {
    let mut fixture = CoordinatorFixture::new(vec![17; 512])?;
    let generation = ConnectionGeneration::new(1);
    let (_sink, route) = open_connection(&mut fixture, generation)?;
    let transaction_id = commit_start(
        &mut fixture,
        generation,
        route,
        1,
        "replayed-user",
        Some(93),
        EXPIRES_AT - 1,
    )
    .await?;
    let outcome = worker_finish(
        &mut fixture,
        generation,
        route,
        2,
        transaction_id,
        EXPIRES_AT - 1,
    )?;
    let account_id = committed_account(&outcome.sealed)?;
    let replay_envelope = AccountServiceEnvelope::parse(*outcome.envelope.as_bytes())?;
    let completion =
        commit_finish(&mut fixture, generation, route, outcome, EXPIRES_AT - 1).await?;
    assert_eq!(completion.result, ResultClass::Ok);
    assert_account_published(&fixture, account_id, 93, transaction_id)?;
    let head_after_commit = fixture.core.context_mut()?.head();

    // The same request replayed after expiry on a fresh carrier reproduces the
    // stored accepted result without touching storage or the invitation.
    let replay = ConnectionGeneration::new(2);
    let (replay_sink, _replay_route) = open_connection(&mut fixture, replay)?;
    let result = fixture.core.read_rows(ReadPlan::exact(
        TableId::RequestResult,
        request_result_key(replay_envelope.client_request_id())?,
    ))?;
    assert_eq!(result.records.len(), 1);
    let (coordinator, context) = fixture.parts()?;
    context.set_wall_for_test(EXPIRES_AT + 30);
    let now = context.now().get();
    let carrier = transfer(coordinator, replay)?;
    feed_transfer(carrier, AccountCarrierPhase::Start, &replay_envelope, now)?;
    carrier
        .server_response(
            AccountCarrierPhase::Start,
            &[0; ACCOUNT_RESPONSE_BYTES],
            now,
        )
        .map_err(|_| "the replay carrier refused the start response")?;
    feed_transfer(carrier, AccountCarrierPhase::Finish, &replay_envelope, now)?;
    let completions = coordinator.replay_read(
        context,
        request(
            replay,
            1,
            route,
            AccountCarrierPhase::Finish,
            replay_envelope,
        ),
        result,
    )?;
    assert_eq!(completions.len(), 1);
    assert!(
        completions
            .first()
            .is_some_and(|completion| completion.result == ResultClass::Ok)
    );
    assert_eq!(context.pending_len(), 0);
    assert!(coordinator.pending_authority.is_none());
    assert_eq!(context.head(), head_after_commit);
    assert_eq!(coordinator.config.live_login_keys.len(), 1);
    assert!(
        replay_sink
            .lines()
            .iter()
            .any(|line| line.contains(&account_id.to_text()))
    );
    Ok(())
}

#[tokio::test]
async fn opening_finish_without_a_trusted_clock_fails_closed_and_spends_the_transaction()
-> TestResult {
    let mut fixture = CoordinatorFixture::new(vec![19; 512])?;
    let generation = ConnectionGeneration::new(1);
    let (_sink, route) = open_connection(&mut fixture, generation)?;
    let transaction_id = commit_start(
        &mut fixture,
        generation,
        route,
        1,
        "clockless-user",
        Some(93),
        EXPIRES_AT - 1,
    )
    .await?;
    let payload = AccountRequestPayload::CreationFinish(CreationFinish {
        network_id: fixture.core.identity.network_id,
        transaction_id,
        registration_record: OpaqueRegistrationRecord::from_bytes(vector("registration_record")?)?,
    });
    let (opened, envelope) = opened_request(&fixture.core.identity, 2, payload)?;
    let OpenedAccountServiceRequest::CreationFinish(finish_request) = opened else {
        return Err("opened request kind changed".into());
    };
    let (coordinator, context) = fixture.parts()?;
    context.set_untrusted_wall_for_test(None);
    let pending_before = context.pending_len();
    let result = coordinator.open_creation_finish(
        context,
        request(generation, 2, route, AccountCarrierPhase::Finish, envelope),
        finish_request,
    );
    assert_eq!(result.err(), Some(RuntimeError::InvalidValue));
    assert!(
        coordinator
            .connections
            .get(&generation)
            .is_some_and(|connection| connection.creation_transaction.is_none())
    );
    assert_eq!(context.pending_len(), pending_before);
    let cleanup = coordinator.cleanup_queue.back().ok_or("queued cleanup")?;
    assert_eq!(cleanup.transaction_id, transaction_id);
    assert_eq!(cleanup.durable_writes()?.len(), 3);
    assert!(coordinator.pending_authority.is_none());
    Ok(())
}
