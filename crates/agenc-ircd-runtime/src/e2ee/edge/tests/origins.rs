#![forbid(unsafe_code)]

//! Reconnecting a companion origin must replay the declaration bytes exactly.

use super::*;
use crate::e2ee::edge::E2eeEdgeConfig;
use crate::federation::edge::EdgeConfig;
use crate::federation::link::{LinkQueue, link_queue};
use crate::federation::{FederationInbound, LinkEvent, LinkId, LinkSession, PeerIdentity};
use crate::test_support::StateCoreFixture;
use agenc_ircd_types::{FederationRole, NetworkId, RecoveryEpoch, ServerId, ServerIncarnation};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn companion() -> E2eeEdge {
    E2eeEdge::new(E2eeEdgeConfig {
        network_id: [1; 32],
        server_id: ServerId::from_bytes([2; 16]),
        server_name: "edge.example".to_owned(),
        coordinator_server_id: ServerId::from_bytes([3; 16]),
        incarnation: [4; 16],
        global_disk_bytes: 1 << 20,
    })
}

fn transport(context: &mut StateCoreContext) -> (EdgeFederation, LinkQueue) {
    let peer = ServerId::from_bytes([3; 16]);
    let epoch = RecoveryEpoch::from_bytes([5; 16]);
    let mut edge = EdgeFederation::new(EdgeConfig {
        network_id: NetworkId::from_bytes([1; 32]),
        server_id: ServerId::from_bytes([2; 16]),
        server_name: "edge.example".to_owned(),
        incarnation: ServerIncarnation::from_bytes([4; 16]),
        coordinator: PeerIdentity::new(
            peer,
            "coordinator.example",
            FederationRole::Coordinator,
            epoch,
            agenc_ircd_crypto::Ed25519SecretKey::from_bytes([6; 32]).public_key(),
            [7; 32],
        ),
    });
    let (handle, queue) = link_queue(1 << 20);
    edge.inbound(
        context,
        FederationInbound {
            link: LinkId::new(1),
            peer,
            event: LinkEvent::Established {
                session: LinkSession {
                    link: LinkId::new(1),
                    peer,
                    peer_incarnation: ServerIncarnation::from_bytes([8; 16]),
                    peer_recovery_epoch: epoch,
                    transition: agenc_ircd_federation_wire::EpochTransition::Initial,
                },
                handle,
            },
            charge: None,
        },
    );
    (edge, queue)
}

fn facts(generation: u64) -> BaseOriginFacts {
    BaseOriginFacts {
        origin_id: [9; 16],
        generation,
        acked_generation: Some(generation),
        connection_id: [10; 16],
        connection_nonce: [11; 32],
        session: None,
        account: None,
    }
}

async fn next_declaration(queue: &mut LinkQueue) -> TestResult<String> {
    for _ in 0..8 {
        let line = tokio::time::timeout(std::time::Duration::from_secs(1), queue.recv())
            .await?
            .ok_or("link ended before declaration")?;
        if line.as_str().contains(" EORIGIN ") {
            return Ok(line.as_str().to_owned());
        }
    }
    Err("origin declaration was not queued".into())
}

#[tokio::test]
async fn reconnect_replays_the_exact_companion_origin_declaration() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let (mut base, mut queue) = transport(fixture.context_mut()?);
    let mut edge = companion();
    let connection = ConnectionGeneration::new(1);
    edge.declare_origin(fixture.context_mut()?, &mut base, connection, &facts(0), 0)
        .map_err(|error| error.code.to_string())?;
    let initial = next_declaration(&mut queue).await?;
    edge.acknowledge_origin([9; 16], 0);
    edge.declare_origin(fixture.context_mut()?, &mut base, connection, &facts(1), 1)
        .map_err(|error| error.code.to_string())?;
    let successor = next_declaration(&mut queue).await?;
    assert_ne!(initial, successor);
    edge.acknowledge_origin([9; 16], 1);
    edge.origins
        .get_mut(&connection)
        .ok_or("origin")?
        .next_sequence = 7;
    for _ in 0..2 {
        edge.link_down();
        edge.declare_origin(fixture.context_mut()?, &mut base, connection, &facts(1), 1)
            .map_err(|error| error.code.to_string())?;
        assert_eq!(
            next_declaration(&mut queue).await?,
            successor,
            "replay must name the original predecessor and object id"
        );
        edge.acknowledge_origin([9; 16], 1);
        assert_eq!(
            edge.origins.get(&connection).ok_or("origin")?.next_sequence,
            7
        );
    }
    edge.declare_origin(fixture.context_mut()?, &mut base, connection, &facts(2), 2)
        .map_err(|error| error.code.to_string())?;
    let unacknowledged = next_declaration(&mut queue).await?;
    assert_ne!(unacknowledged, successor);
    edge.link_down();
    edge.declare_origin(fixture.context_mut()?, &mut base, connection, &facts(2), 2)
        .map_err(|error| error.code.to_string())?;
    assert_eq!(
        next_declaration(&mut queue).await?,
        unacknowledged,
        "a lost declaration acknowledgement also requires exact replay"
    );
    edge.acknowledge_origin([9; 16], 2);
    assert_eq!(
        edge.origins.get(&connection).ok_or("origin")?.next_sequence,
        0
    );
    Ok(())
}

#[tokio::test]
async fn requests_wait_for_the_declaration_that_carries_a_new_attachment() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let (mut base, mut queue) = transport(fixture.context_mut()?);
    let mut edge = companion();
    let connection = ConnectionGeneration::new(1);
    edge.declare_origin(fixture.context_mut()?, &mut base, connection, &facts(0), 0)
        .map_err(|error| error.code.to_string())?;
    let _initial = next_declaration(&mut queue).await?;
    edge.acknowledge_origin([9; 16], 0);
    assert!(super::super::router::settled(
        edge.origins.get(&connection).ok_or("origin")?
    ));
    // The attachment advances the base generation; until that generation's
    // declaration is acknowledged the origin is not settled.
    edge.device_attached(fixture.context_mut()?, &mut base, connection, [12; 16], 1);
    let origin = edge.origins.get(&connection).ok_or("origin")?;
    assert_eq!(origin.device, Some(([12; 16], 1)));
    assert_eq!(origin.predates_device, Some(0));
    assert!(!super::super::router::settled(origin));
    // An acknowledgement of the same generation changes nothing; the next
    // generation's does.
    edge.acknowledge_origin([9; 16], 0);
    assert_eq!(
        edge.origins
            .get(&connection)
            .ok_or("origin")?
            .predates_device,
        Some(0)
    );
    edge.origins.get_mut(&connection).ok_or("origin")?.declared = Some(1);
    edge.acknowledge_origin([9; 16], 1);
    let origin = edge.origins.get(&connection).ok_or("origin")?;
    assert_eq!(origin.predates_device, None);
    assert!(super::super::router::settled(origin));
    // An acknowledgement of an undeclared generation changes nothing, and
    // an attachment on an unknown connection installs no origin.
    edge.acknowledge_origin([9; 16], 5);
    assert_eq!(
        edge.origins.get(&connection).ok_or("origin")?.acked,
        Some(1)
    );
    let unknown = ConnectionGeneration::new(7);
    edge.device_attached(fixture.context_mut()?, &mut base, unknown, [13; 16], 1);
    assert!(!edge.origins.contains_key(&unknown));
    // The gate needs an acknowledged declaration of the declared generation
    // and no attachment awaiting its declaration.
    let candidate = edge.origins.get_mut(&connection).ok_or("origin")?;
    candidate.acked = None;
    assert!(!super::super::router::settled(candidate));
    candidate.acked = Some(0);
    assert!(!super::super::router::settled(candidate));
    candidate.acked = Some(1);
    assert!(super::super::router::settled(candidate));
    candidate.predates_device = Some(1);
    assert!(!super::super::router::settled(candidate));
    Ok(())
}
