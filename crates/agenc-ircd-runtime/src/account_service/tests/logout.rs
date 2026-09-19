//! SASL logout of a registered session: the account switch is one staged
//! durable authority, a busy coordinator refuses it with the SASL failure
//! numeric, and a connection without a live account session is closed.
#![forbid(unsafe_code)]

use super::harness::{Live, arm_sasl};
use super::*;
use crate::test_support::{TestResult, bind_live_session, negotiated_capabilities, seed_session};
use agenc_ircd_client_wire::ACCOUNT_RESPONSE_BYTES;

/// Completes the armed FINISH as accepted, so the carrier is authenticated.
fn authenticate_carrier(live: &mut Live) -> TestResult {
    arm_sasl(&mut live.fixture, live.generation, true)?;
    let connection = live
        .fixture
        .coordinator
        .connections
        .get_mut(&live.generation)
        .ok_or("connection")?;
    let _finish = connection
        .sasl
        .server_response(&[9_u8; ACCOUNT_RESPONSE_BYTES], 0)?;
    let _accepted = connection.sasl.complete(true, 0)?;
    Ok(())
}

fn request_logout(live: &mut Live) -> TestResult<CarrierRoute> {
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    Ok(coordinator.route_sasl(
        context,
        generation,
        6,
        "tester",
        false,
        parsed("AUTHENTICATE *")?,
    ))
}

fn assert_refused_with_904(route: CarrierRoute) -> TestResult {
    let CarrierRoute::Finished { frames, result } = route else {
        return Err("a refused logout finishes its carrier".into());
    };
    assert_eq!(result, ResultClass::Rejected);
    let mut frames = frames.into_iter();
    let (Some(frame), None) = (frames.next(), frames.next()) else {
        return Err("a refused logout sends one numeric".into());
    };
    let line = String::from_utf8(encoded(frame)?)?;
    assert!(line.contains(" 904 tester "), "{line}");
    Ok(())
}

/// A connection bound to a guest session that holds no account.
fn open_guest() -> TestResult<Live> {
    let mut live = Live::open()?;
    let generation = ConnectionGeneration::new(2);
    let (coordinator, context) = live.fixture.parts()?;
    let identity = seed_session(context, 5, "guest", None)?;
    let capabilities = negotiated_capabilities(&[])?;
    live.sink = bind_live_session(context, generation.get(), identity, capabilities, true)?;
    coordinator.connection_opened(context, generation)?;
    live.generation = generation;
    Ok(live)
}

#[tokio::test]
async fn a_registered_logout_detaches_the_account_once_its_batch_commits() -> TestResult {
    let (mut live, account_id) = Live::open_registered()?;
    authenticate_carrier(&mut live)?;
    assert!(matches!(request_logout(&mut live)?, CarrierRoute::Pending));
    assert!(matches!(
        live.fixture.coordinator.pending_authority,
        Some(PendingAuthority::Logout {
            carrier_generation: 6,
            ..
        })
    ));
    live.fixture.core.commit_staged_batch().await?;
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    let completions = coordinator.batch_applied(context);
    assert!(matches!(
        completions.as_slice(),
        [completion] if !completion.close && completion.result == ResultClass::Ok
    ));
    let user_id = context
        .sessions()
        .connection(generation)
        .and_then(|entry| entry.session())
        .map(|bound| bound.user_id)
        .ok_or("bound session")?;
    let session = context.domain().session(user_id).ok_or("session")?;
    assert!(session.account_id().is_none());
    assert!(context.domain().account(account_id).is_some());
    Ok(())
}

#[test]
fn a_logout_while_another_account_authority_is_staged_is_refused() -> TestResult {
    let (mut live, _) = Live::open_registered()?;
    authenticate_carrier(&mut live)?;
    live.fixture.coordinator.pending_authority = Some(PendingAuthority::Logout {
        generation: ConnectionGeneration::new(40),
        carrier_generation: 1,
    });
    assert_refused_with_904(request_logout(&mut live)?)?;
    assert_eq!(live.fixture.core.context_mut()?.pending_len(), 0);
    Ok(())
}

#[test]
fn a_logout_behind_an_unsettled_batch_is_refused() -> TestResult {
    let (mut live, _) = Live::open_registered()?;
    authenticate_carrier(&mut live)?;
    live.occupy_pending_batch()?;
    assert_refused_with_904(request_logout(&mut live)?)?;
    assert!(live.fixture.coordinator.pending_authority.is_none());
    Ok(())
}

#[test]
fn a_refused_logout_leaves_the_carrier_authenticated_for_a_retry() -> TestResult {
    let (mut live, _) = Live::open_registered()?;
    authenticate_carrier(&mut live)?;
    live.occupy_pending_batch()?;
    assert_refused_with_904(request_logout(&mut live)?)?;
    live.fixture.core.context_mut()?.discard_pending_for_test();
    live.fixture.coordinator.pending_cleanups.clear();
    assert!(matches!(request_logout(&mut live)?, CarrierRoute::Pending));
    Ok(())
}

#[test]
fn a_logout_from_a_guest_session_closes_the_connection() -> TestResult {
    let mut live = open_guest()?;
    authenticate_carrier(&mut live)?;
    assert!(matches!(request_logout(&mut live)?, CarrierRoute::Close));
    assert!(live.fixture.coordinator.pending_authority.is_none());
    Ok(())
}

#[test]
fn a_logout_whose_bound_session_left_the_domain_closes_the_connection() -> TestResult {
    let mut live = Live::open()?;
    let generation = ConnectionGeneration::new(2);
    let (coordinator, context) = live.fixture.parts()?;
    let identity = agenc_ircd_testkit::DomainTestIdentity {
        session_id: agenc_ircd_types::SessionId::from_bytes([21; 16]),
        user_id: agenc_ircd_types::UserId::from_bytes([22; 16]),
        generation: Generation::new(1)?,
        account_id: None,
    };
    let capabilities = negotiated_capabilities(&[])?;
    let _sink = bind_live_session(context, generation.get(), identity, capabilities, true)?;
    coordinator.connection_opened(context, generation)?;
    live.generation = generation;
    authenticate_carrier(&mut live)?;
    assert!(matches!(request_logout(&mut live)?, CarrierRoute::Close));
    Ok(())
}

#[test]
fn a_refused_logout_on_a_carrier_that_never_asked_closes_the_connection() -> TestResult {
    let (mut live, _) = Live::open_registered()?;
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    coordinator.pending_authority = Some(PendingAuthority::Logout {
        generation: ConnectionGeneration::new(40),
        carrier_generation: 1,
    });
    let route = coordinator.route_logout(context, generation, 6, "tester");
    assert!(matches!(route, CarrierRoute::Close));
    Ok(())
}

#[test]
fn a_refused_logout_for_a_connection_the_coordinator_forgot_closes_it() -> TestResult {
    let (mut live, _) = Live::open_registered()?;
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    coordinator.connections.clear();
    coordinator.pending_authority = Some(PendingAuthority::Logout {
        generation: ConnectionGeneration::new(40),
        carrier_generation: 1,
    });
    let route = coordinator.route_logout(context, generation, 6, "tester");
    assert!(matches!(route, CarrierRoute::Close));
    Ok(())
}

#[tokio::test]
async fn a_logout_that_commits_after_its_connection_closed_reports_a_close() -> TestResult {
    let (mut live, _) = Live::open_registered()?;
    authenticate_carrier(&mut live)?;
    assert!(matches!(request_logout(&mut live)?, CarrierRoute::Pending));
    live.fixture.core.commit_staged_batch().await?;
    let (coordinator, context) = live.fixture.parts()?;
    coordinator.connections.clear();
    let completions = coordinator.batch_applied(context);
    assert!(matches!(completions.as_slice(), [completion] if completion.close));
    Ok(())
}
