//! A registered initial-root request retains the same origin and authenticated link through its declaration ACK.
#![forbid(unsafe_code)]

use super::*;
use crate::federation::edge::initial_root::{Carrier, OwnedCarrier};
use agenc_relay_federation_wire::{FederationProfile, InitialRootRequest};
use agenc_relay_types::AccountId;

/// Run the actual ACK handler with the canonical hash of its own next declaration.
fn ack_next_claim_update(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    connection: ConnectionGeneration,
) -> TestResult {
    let origin = edge.origins.get(&connection).ok_or("missing connection")?;
    let update = origin
        .pending_updates
        .front()
        .ok_or("missing declaration")?;
    let bytes = update.to_object()?.encode_canonical()?;
    ack(
        edge,
        context,
        update.origin_id,
        update.generation,
        Some(federation_object_id(bytes.as_slice())),
    )
    .map_err(|error| format!("acknowledging the origin: {error:?}"))?;
    Ok(())
}

#[tokio::test]
async fn registered_claim_owns_its_exact_queued_declaration_through_acknowledgements() -> TestResult
{
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let context = fixture.context_mut()?;
    let connection = ConnectionGeneration::new(4);
    let mut edge = bound_edge(context, connection)?;
    let first = agenc_relay_types::AccountId::parse("a_AAAAAAAAAAAAAAAAAAAAAA")?;
    let next = agenc_relay_types::AccountId::parse("a_BBBBBBBBBBBBBBBBBBBBBA")?;
    edge.origins.get_mut(&connection).ok_or("origin")?.account = Some((first, 1));
    edge.session_bound(context, connection);
    let admitted = edge
        .initial_root_principal(connection)
        .ok_or("registered claim's admission")?;
    for _ in 0..2 {
        ack_next_claim_update(&mut edge, context, connection)?;
        assert!(
            edge.initial_root_principal(connection) == Some(admitted),
            "the ACK for the same already-queued registration changed the claim owner"
        );
    }
    let origin = edge.origins.get_mut(&connection).ok_or("settled")?;
    assert_eq!(origin.acked_generation, Some(2));
    origin.account = Some((first, 2));
    edge.session_bound(context, connection);
    assert!(
        edge.initial_root_principal(connection)
            .is_some_and(|value| value != admitted)
    );
    ack_next_claim_update(&mut edge, context, connection)?;
    let rotated = edge
        .initial_root_principal(connection)
        .ok_or("changed account session")?;
    assert!(rotated != admitted);
    edge.origins.get_mut(&connection).ok_or("settled")?.account = Some((next, 1));
    edge.session_bound(context, connection);
    assert!(
        edge.initial_root_principal(connection)
            .is_some_and(|value| value != admitted && value != rotated)
    );
    Ok(())
}

fn sealed_read(account: AccountId) -> TestResult<agenc_relay_auth::InitialRootServiceEnvelope> {
    use agenc_relay_auth::initial_root::{ClaimAction, seal_claim};
    use agenc_relay_crypto::{
        AccountHpkePrivateKey, AccountRequestBinding, InitialRootExchange, InitialRootSecret,
    };
    let public = AccountHpkePrivateKey::generate()?.public_key()?;
    let binding = AccountRequestBinding::new(
        NETWORK,
        COORDINATOR_EPOCH,
        public.key_id(),
        RequestId::from_bytes([105; 16]),
        InitialRootExchange::Claim,
    );
    let (sealed, _) = seal_claim(
        public,
        binding,
        account,
        RequestId::from_bytes([106; 16]),
        &InitialRootSecret::generate()?,
        ClaimAction::Read,
    )?;
    Ok(sealed)
}

#[derive(Clone, Copy)]
enum Change {
    MatchingAck,
    NewAccountSession,
    ReplacedLink,
}

async fn deferred_claim(change: Change) -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let context = fixture.context_mut()?;
    let connection = ConnectionGeneration::new(7);
    let mut edge = bound_edge(context, connection)?;
    let (mut handle, _reader) = link_queue(1 << 20);
    handle.profile = FederationProfile::InitialRoot;
    let link = LinkId::new(11);
    edge.live = Some(LiveLink {
        link,
        handle,
        coordinator_epoch: COORDINATOR_EPOCH,
        coordinator_incarnation: HUB_INCARNATION,
    });
    let first = AccountId::parse("a_AAAAAAAAAAAAAAAAAAAAAA")?;
    edge.origins.get_mut(&connection).ok_or("origin")?.account = Some((first, 1));
    edge.session_bound(context, connection);
    let sealed = sealed_read(first)?;
    let transfer = OwnedCarrier::bind(&edge, connection, Carrier::Claim, link)
        .ok_or("missing eligible owner")?;
    transfer
        .send(&mut edge, context, connection, 31, sealed.as_bytes())
        .map_err(|error| format!("holding claim: {error:?}"))?;
    assert!(edge.pending.is_empty());
    assert!(edge.deferred_carriers.contains_key(&connection));
    match change {
        Change::MatchingAck => {}
        Change::NewAccountSession => {
            edge.origins.get_mut(&connection).ok_or("origin")?.account = Some((first, 2));
            edge.session_bound(context, connection);
        }
        Change::ReplacedLink => {
            edge.live.as_mut().ok_or("active link")?.link = LinkId::new(12);
        }
    }
    let updates = edge
        .origins
        .get(&connection)
        .ok_or("origin")?
        .pending_updates
        .len();
    for _ in 0..updates {
        ack_next_claim_update(&mut edge, context, connection)?;
    }
    assert!(!edge.deferred_carriers.contains_key(&connection));
    if matches!(change, Change::MatchingAck) {
        assert_eq!(edge.pending.len(), 1);
        let sent = edge
            .pending
            .values()
            .next()
            .ok_or("missing ordinary request")?;
        let checked = InitialRootRequest::decode(
            FederationProfile::InitialRoot,
            &sent.bytes,
            &mut DecodeBudget::new(65_536, 256),
        )?;
        assert_eq!(checked.layout.replay_key.origin_generation, 2);
        assert_eq!(checked.session, Some(SessionId::from_bytes([41; 16])));
        assert!(checked.envelope == sealed.as_bytes());
    } else {
        assert!(
            edge.pending.is_empty(),
            "a changed owner or link produced a federated private request"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_deferred_registered_claim_only_advances_on_its_original_principal_and_link() -> TestResult
{
    for change in [
        Change::MatchingAck,
        Change::NewAccountSession,
        Change::ReplacedLink,
    ] {
        deferred_claim(change).await?;
    }
    Ok(())
}
