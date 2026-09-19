//! Shared drivers for the account-service refusal, limit and teardown tests.
//!
//! Every request here is a real HPKE-sealed envelope opened with the fixture's
//! account key, and every transaction comes from the auth crate's own START
//! and FINISH operations, so the coordinator is exercised with the values a
//! worker would hand it. No OPAQUE client exists in this crate: authentication
//! and credential exchanges therefore follow the latent-rejection path.
#![forbid(unsafe_code)]

use super::invitation_window::{open_connection, opened_request, vector};
use super::*;
use crate::state_core::timers::{TimedId, TimerKind};
use crate::test_support::{FixtureIdentity, FrameSink, TestResult};
use agenc_ircd_auth::{
    AccountAuthenticationState, AccountFinishOutcome, AccountRequestPayload, AccountStartOutcome,
    AuthenticatedAccountRequest, AuthenticationFinish, AuthenticationGrant, AuthenticationLookup,
    AuthenticationStart, AuthenticationStartParameters, CreationFinish, CreationStart,
    CredentialChangeFinish, CredentialChangeStart, OpaqueKe1, OpaqueKe3, OpaqueRegistrationRecord,
    OpaqueRegistrationRequest, OpenedAccountServiceRequest, SealedAccountStart,
    begin_authentication, finish_account_authentication,
};
use agenc_ircd_client_wire::{ACCOUNT_RESPONSE_BYTES, AUTH_CHUNK_CHARACTERS};
use agenc_ircd_crypto::OpaqueFakeCredentialKey;

/// The wall-clock second every harness fixture trusts.
pub(super) const WALL: u64 = 1_000;

/// A valid Ristretto group element, so the server OPAQUE round accepts KE1.
const BASEPOINT: [u8; 32] = [
    0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51, 0x5f,
    0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76,
];

/// A fixture with one open connection and a trusted wall clock.
pub(super) struct Live {
    pub(super) fixture: CoordinatorFixture,
    pub(super) generation: ConnectionGeneration,
    pub(super) route: ConnectionRoute,
    pub(super) sink: Arc<FrameSink>,
}

impl Live {
    pub(super) fn open() -> TestResult<Self> {
        let mut fixture = CoordinatorFixture::new(vec![7; 4_096])?;
        let generation = ConnectionGeneration::new(1);
        let (sink, route) = open_connection(&mut fixture, generation)?;
        fixture.core.context_mut()?.set_wall_for_test(WALL);
        Ok(Self {
            fixture,
            generation,
            route,
            sink,
        })
    }

    pub(super) fn sasl(
        &self,
        phase: AccountCarrierPhase,
        envelope: AccountServiceEnvelope,
    ) -> RequestContext {
        sasl_request(self.generation, 1, self.route, phase, envelope)
    }

    pub(super) fn account(
        &self,
        kind: AccountCarrierKind,
        phase: AccountCarrierPhase,
        envelope: AccountServiceEnvelope,
    ) -> RequestContext {
        account_request(self.generation, 1, self.route, kind, phase, envelope)
    }
}

pub(super) fn sasl_request(
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
        carrier: RequestCarrier::Sasl,
        phase,
    }
}

pub(super) fn account_request(
    generation: ConnectionGeneration,
    carrier_generation: u64,
    route: ConnectionRoute,
    kind: AccountCarrierKind,
    phase: AccountCarrierPhase,
    envelope: AccountServiceEnvelope,
) -> RequestContext {
    RequestContext {
        generation,
        carrier_generation,
        target: "tester".to_owned(),
        route,
        envelope,
        carrier: RequestCarrier::Account(kind),
        phase,
    }
}

/// The canonical padded Base64 of one fixed-size request whose bytes are not
/// a parsable envelope; it only moves the SASL carrier to its waiting phase.
fn filler_request() -> String {
    let mut request = "A".repeat(SASL_REQUEST_CHARACTERS - 2);
    request.push_str("==");
    request
}

fn feed_sasl(connection: &mut super::super::AccountConnection, now: u64) -> TestResult {
    let request = filler_request();
    for chunk in request.as_bytes().chunks(AUTH_CHUNK_CHARACTERS) {
        let _actions = connection.sasl.client(std::str::from_utf8(chunk)?, now)?;
    }
    Ok(())
}

/// Moves one connection's SASL carrier to the phase in which it waits for the
/// START response, or for the FINISH response when `finish` is set.
pub(super) fn arm_sasl(
    fixture: &mut CoordinatorFixture,
    generation: ConnectionGeneration,
    finish: bool,
) -> TestResult {
    let (coordinator, context) = fixture.parts()?;
    let now = context.now().get();
    let connection = coordinator
        .connections
        .get_mut(&generation)
        .ok_or("connection")?;
    let _selected = connection.sasl.client("AGENC-OPAQUE", now)?;
    feed_sasl(connection, now)?;
    if finish {
        let _start = connection
            .sasl
            .server_response(&[9_u8; ACCOUNT_RESPONSE_BYTES], now)?;
        feed_sasl(connection, now)?;
    }
    Ok(())
}

pub(super) fn authentication_start(
    identity: &FixtureIdentity,
    request_seed: u8,
    login: &str,
) -> TestResult<(
    AuthenticatedAccountRequest<AuthenticationStart>,
    AccountServiceEnvelope,
)> {
    let mut ke1 = [7_u8; 96];
    for range in [0..32, 64..96] {
        ke1.get_mut(range)
            .ok_or("KE1 element range")?
            .copy_from_slice(&BASEPOINT);
    }
    let payload = AccountRequestPayload::AuthenticationStart(AuthenticationStart {
        network_id: identity.network_id,
        login: NormalizedLogin::prepare(login)?,
        ke1: OpaqueKe1::from_bytes(ke1)?,
    });
    match opened_request(identity, request_seed, payload)? {
        (OpenedAccountServiceRequest::AuthenticationStart(opened), envelope) => {
            Ok((opened, envelope))
        }
        _ => Err("opened request kind changed".into()),
    }
}

pub(super) fn authentication_finish(
    identity: &FixtureIdentity,
    request_seed: u8,
    transaction_id: TransactionId,
) -> TestResult<(
    AuthenticatedAccountRequest<AuthenticationFinish>,
    AccountServiceEnvelope,
)> {
    let payload = AccountRequestPayload::AuthenticationFinish(AuthenticationFinish {
        network_id: identity.network_id,
        transaction_id,
        ke3: OpaqueKe3::from_bytes([3; 64])?,
    });
    match opened_request(identity, request_seed, payload)? {
        (OpenedAccountServiceRequest::AuthenticationFinish(opened), envelope) => {
            Ok((opened, envelope))
        }
        _ => Err("opened request kind changed".into()),
    }
}

pub(super) fn creation_start(
    identity: &FixtureIdentity,
    request_seed: u8,
    login: &str,
) -> TestResult<(
    AuthenticatedAccountRequest<CreationStart>,
    AccountServiceEnvelope,
)> {
    let payload = AccountRequestPayload::CreationStart(CreationStart {
        network_id: identity.network_id,
        login: NormalizedLogin::prepare(login)?,
        registration_request: OpaqueRegistrationRequest::from_bytes(vector(
            "registration_request",
        )?)?,
        invitation: None,
    });
    match opened_request(identity, request_seed, payload)? {
        (OpenedAccountServiceRequest::CreationStart(opened), envelope) => Ok((opened, envelope)),
        _ => Err("opened request kind changed".into()),
    }
}

pub(super) fn creation_finish(
    identity: &FixtureIdentity,
    request_seed: u8,
    transaction_id: TransactionId,
) -> TestResult<(
    AuthenticatedAccountRequest<CreationFinish>,
    AccountServiceEnvelope,
)> {
    let payload = AccountRequestPayload::CreationFinish(CreationFinish {
        network_id: identity.network_id,
        transaction_id,
        registration_record: OpaqueRegistrationRecord::from_bytes(vector("registration_record")?)?,
    });
    match opened_request(identity, request_seed, payload)? {
        (OpenedAccountServiceRequest::CreationFinish(opened), envelope) => Ok((opened, envelope)),
        _ => Err("opened request kind changed".into()),
    }
}

pub(super) fn credential_start(
    identity: &FixtureIdentity,
    request_seed: u8,
    account_id: AccountId,
) -> TestResult<(
    AuthenticatedAccountRequest<CredentialChangeStart>,
    AccountServiceEnvelope,
)> {
    let payload = AccountRequestPayload::CredentialChangeStart(CredentialChangeStart {
        network_id: identity.network_id,
        account_id,
        registration_request: OpaqueRegistrationRequest::from_bytes(vector(
            "registration_request",
        )?)?,
    });
    match opened_request(identity, request_seed, payload)? {
        (OpenedAccountServiceRequest::CredentialChangeStart(opened), envelope) => {
            Ok((opened, envelope))
        }
        _ => Err("opened request kind changed".into()),
    }
}

pub(super) fn credential_finish(
    identity: &FixtureIdentity,
    request_seed: u8,
    transaction_id: TransactionId,
) -> TestResult<(
    AuthenticatedAccountRequest<CredentialChangeFinish>,
    AccountServiceEnvelope,
)> {
    let payload = AccountRequestPayload::CredentialChangeFinish(CredentialChangeFinish {
        network_id: identity.network_id,
        transaction_id,
        registration_record: OpaqueRegistrationRecord::from_bytes(vector("registration_record")?)?,
    });
    match opened_request(identity, request_seed, payload)? {
        (OpenedAccountServiceRequest::CredentialChangeFinish(opened), envelope) => {
            Ok((opened, envelope))
        }
        _ => Err("opened request kind changed".into()),
    }
}

/// One authentication START for an unknown login: the auth crate answers it
/// with the fake record and a transaction whose FINISH always rejects.
pub(super) fn unsealed_unknown_authentication(
    live: &mut Live,
    request_seed: u8,
    login: &str,
) -> TestResult<(
    AccountStartOutcome<AccountAuthenticationState>,
    AccountServiceEnvelope,
)> {
    let (opened, envelope) =
        authentication_start(&live.fixture.core.identity, request_seed, login)?;
    let login_key = LoginIndexKey::from_bytes(live.fixture.core.identity.login_index);
    let opaque = Arc::clone(&live.fixture.core.opaque);
    let route = live.route;
    let (coordinator, context) = live.fixture.parts()?;
    let fake_key: &OpaqueFakeCredentialKey = &coordinator.config.fake_credential_key;
    let start = begin_authentication(
        &opaque,
        &login_key,
        fake_key,
        AuthenticationStartParameters {
            context: coordinator.operation_context(context, route)?,
            request: opened,
            lookup: AuthenticationLookup::Unknown,
        },
    )?;
    Ok((start, envelope))
}

/// The same START sealed against the current response count.
pub(super) fn sealed_unknown_authentication(
    live: &mut Live,
    request_seed: u8,
    login: &str,
) -> TestResult<(
    SealedAccountStart<AccountAuthenticationState>,
    AccountServiceEnvelope,
)> {
    let (start, envelope) = unsealed_unknown_authentication(live, request_seed, login)?;
    let count = live
        .fixture
        .core
        .context_mut()?
        .head()
        .account_service_response_count;
    Ok((start.seal(count)?, envelope))
}

/// Commits one unknown-login authentication START through the real staging
/// path and returns the live transaction's identifier.
pub(super) async fn commit_authentication_start(
    live: &mut Live,
    request_seed: u8,
    login: &str,
) -> TestResult<TransactionId> {
    let (sealed, envelope) = sealed_unknown_authentication(live, request_seed, login)?;
    let transaction_id = sealed.transaction_id();
    arm_sasl(&mut live.fixture, live.generation, false)?;
    let request = live.sasl(AccountCarrierPhase::Start, envelope);
    let login = NormalizedLogin::prepare(login)?;
    let (coordinator, context) = live.fixture.parts()?;
    coordinator
        .stage_start(context, request, sealed, None, login, None)
        .map_err(|error| format!("stage authentication START: {error:?}"))?;
    live.fixture.core.commit_staged_batch().await?;
    let (coordinator, context) = live.fixture.parts()?;
    let completions = coordinator.batch_applied(context);
    assert_eq!(completions.len(), 1);
    assert!(coordinator.transaction_owners.contains_key(&transaction_id));
    Ok(transaction_id)
}

/// Takes the live authentication off its connection and runs the worker-side
/// FINISH, which the auth crate rejects for an unknown login.
pub(super) fn rejected_authentication_finish(
    live: &mut Live,
    request_seed: u8,
    transaction_id: TransactionId,
) -> TestResult<(
    AccountFinishOutcome<AuthenticationGrant>,
    AccountServiceEnvelope,
)> {
    let (opened, envelope) =
        authentication_finish(&live.fixture.core.identity, request_seed, transaction_id)?;
    let route = live.route;
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    let mut exchange = coordinator
        .connections
        .get_mut(&generation)
        .ok_or("connection")?
        .transaction
        .take()
        .ok_or("live authentication")?;
    let operation = coordinator.operation_context(context, route)?;
    let outcome = finish_account_authentication(&mut exchange.transaction, operation, opened)?;
    assert!(outcome.result().is_err());
    Ok((outcome, envelope))
}

/// Fires the reservation timer of one transaction as the timer heap would.
pub(super) fn fire_transaction_timer(
    fixture: &mut CoordinatorFixture,
    transaction_id: TransactionId,
) -> TestResult<(bool, Vec<CarrierCompletion>)> {
    let (coordinator, context) = fixture.parts()?;
    let id = TimedId::Transaction(transaction_id);
    let due = MonotonicTick::from_ticks(0);
    context
        .timers_mut()
        .schedule(due, TimerKind::Reservation, id)?;
    let entry = context.timers_mut().pop_due(due).ok_or("due timer")?;
    assert_eq!(entry.id, id);
    Ok(coordinator.timer_fired(context, entry))
}

/// Fills the cleanup queue to the coordinator's retained-transaction limit.
pub(super) fn exhaust_transaction_capacity(coordinator: &mut AccountServiceCoordinator) {
    let filler = TransactionCleanup::authentication(TransactionId::from_bytes([0xee; 16]));
    coordinator
        .cleanup_queue
        .resize(MAX_PENDING_TRANSACTION_CLEANUPS, filler);
}
