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
