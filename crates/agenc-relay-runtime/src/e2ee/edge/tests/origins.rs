#![forbid(unsafe_code)]

//! Reconnecting a companion origin must replay the declaration bytes exactly;
//! its deletion names the generation the coordinator holds and the next
//! sequence the edge has not used under it (12.5), and an ended connection
//! releases its companion state.

use super::*;
use crate::e2ee::coordinator::tests::sync::edge_peer::{EdgePeer, Held};
use crate::e2ee::edge::E2eeEdgeConfig;
use crate::e2ee::edge::SessionFacts;
use crate::federation::edge::EdgeConfig;
use crate::federation::link::{LinkQueue, link_queue};
use crate::federation::{FederationInbound, LinkEvent, LinkId, LinkSession, PeerIdentity};
use crate::test_support::StateCoreFixture;
use agenc_relay_client_wire::{
    CapabilityProfile, CapabilitySpec, CapabilityState, FramedLine, parse_message,
};
use agenc_relay_types::{
    FederationRole, NetworkId, RecoveryEpoch, ServerId, ServerIncarnation, UserId,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn companion() -> E2eeEdge {
    E2eeEdge::new(E2eeEdgeConfig {
        network_id: [1; 32],
        server_id: ServerId::from_bytes([2; 16]),
        server_name: "edge.example".to_owned(),
        coordinator_server_id: ServerId::from_bytes([3; 16]),
        sequencer_key_set: super::super::tests::sequencer_key_set(),
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
            agenc_relay_crypto::Ed25519SecretKey::from_bytes([6; 32]).public_key(),
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
                    transition: agenc_relay_federation_wire::EpochTransition::Initial,
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

/// Delivers every companion origin line the edge queued to the real
/// coordinator and returns its answers; a refusal fails the test with the
/// coordinator's fault.
async fn relay(queue: &mut LinkQueue, peer: &mut EdgePeer) -> TestResult<Vec<CompanionFrame>> {
    let mut answers = Vec::new();
    while let Ok(Some(line)) =
        tokio::time::timeout(std::time::Duration::from_millis(20), queue.recv()).await
    {
        if !line.as_str().contains(" EORIGIN ") {
            continue;
        }
        let answer = peer
            .deliver(line.as_str(), "edge.example")
            .map_err(|fault| format!("the coordinator refused {:?}: {fault:?}", line.as_str()))?;
        answers.extend(answer);
    }
    Ok(answers)
}

/// Applies the coordinator's declaration acknowledgements to the edge.
fn acknowledge(edge: &mut E2eeEdge, answers: &[CompanionFrame]) {
    for answer in answers {
        if let CompanionFrame::OriginAck {
            origin_id,
            origin_generation,
            object_id: Some(_),
            ..
        } = answer
        {
            edge.acknowledge_origin(*origin_id, *origin_generation);
        }
    }
}

fn deletion_acknowledged(answers: &[CompanionFrame], generation: u64) -> bool {
    matches!(
        answers,
        [CompanionFrame::OriginAck {
            origin_generation,
            object_id: None,
            ..
        }] if *origin_generation == generation
    )
}

/// What the coordinator holds after a deletion fenced the origin at
/// `next_sequence` under `generation`.
const fn fenced(generation: u64, next_sequence: u64) -> Held {
    Held {
        generation,
        next_sequence,
        fenced: true,
    }
}

/// Declares generation zero on the live link and applies the coordinator's
/// acknowledgement.
async fn declared(
    fixture: &mut StateCoreFixture,
    base: &mut EdgeFederation,
    queue: &mut LinkQueue,
    edge: &mut E2eeEdge,
    peer: &mut EdgePeer,
    connection: ConnectionGeneration,
) -> TestResult {
    edge.declare_origin(
        fixture.context_mut()?,
        base,
        connection,
        &EdgePeer::facts(0),
        0,
    )
    .map_err(|error| error.code.to_string())?;
    let answers = relay(queue, peer).await?;
    acknowledge(edge, &answers);
    Ok(())
}

/// The edge counted `count` requests under the generation it sequences.
fn counted(edge: &mut E2eeEdge, connection: ConnectionGeneration, count: u64) -> TestResult {
    edge.origins
        .get_mut(&connection)
        .ok_or("origin")?
        .next_sequence = count;
    Ok(())
}

/// Companion 12.5: EORIGIN DEL names the generation the coordinator holds
/// and the next unused companion sequence under it. The coordinator holds
/// the edge's last declaration on the link, which precedes the DEL, whether
/// or not its acknowledgement has reached the edge.
#[tokio::test]
async fn a_deletion_names_the_last_declared_generation() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let (mut base, mut queue) = transport(fixture.context_mut()?);
    let mut edge = companion();
    let mut peer = EdgePeer::reset()?;
    let connection = ConnectionGeneration::new(1);
    declared(
        &mut fixture,
        &mut base,
        &mut queue,
        &mut edge,
        &mut peer,
        connection,
    )
    .await?;
    // The base origin advances and the coordinator accepts the companion
    // declaration of the new generation; the edge has not applied its
    // acknowledgement when the connection ends.
    peer.base_generation(1)?;
    edge.declare_origin(
        fixture.context_mut()?,
        &mut base,
        connection,
        &EdgePeer::facts(1),
        1,
    )
    .map_err(|error| error.code.to_string())?;
    let unacknowledged = relay(&mut queue, &mut peer).await?;
    assert!(matches!(
        unacknowledged.as_slice(),
        [CompanionFrame::OriginAck {
            origin_generation: 1,
            object_id: Some(_),
            ..
        }]
    ));
    edge.delete_origin(fixture.context_mut()?, &mut base, connection);
    let answers = relay(&mut queue, &mut peer).await?;
    assert!(
        deletion_acknowledged(&answers, 1),
        "the deletion is acknowledged at the declared generation: {answers:?}"
    );
    assert_eq!(peer.held()?, fenced(1, 0));
    assert!(!edge.origins.contains_key(&connection));
    Ok(())
}

/// A generation the edge does not sequence yet starts its companion
/// sequence at zero (12.5), whatever the edge counted under the generation
/// before it.
#[tokio::test]
async fn a_deletion_names_zero_under_a_generation_not_sequenced_yet() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let (mut base, mut queue) = transport(fixture.context_mut()?);
    let mut edge = companion();
    let mut peer = EdgePeer::reset()?;
    let connection = ConnectionGeneration::new(1);
    declared(
        &mut fixture,
        &mut base,
        &mut queue,
        &mut edge,
        &mut peer,
        connection,
    )
    .await?;
    // Three requests ran under generation zero.
    counted(&mut edge, connection, 3)?;
    peer.committed_requests(3)?;
    peer.base_generation(1)?;
    edge.declare_origin(
        fixture.context_mut()?,
        &mut base,
        connection,
        &EdgePeer::facts(1),
        1,
    )
    .map_err(|error| error.code.to_string())?;
    let _accepted = relay(&mut queue, &mut peer).await?;
    edge.delete_origin(fixture.context_mut()?, &mut base, connection);
    let answers = relay(&mut queue, &mut peer).await?;
    assert!(
        deletion_acknowledged(&answers, 1),
        "the deletion names the declared generation: {answers:?}"
    );
    assert_eq!(
        peer.held()?,
        fenced(1, 0),
        "the deletion names sequence zero under the new generation"
    );
    Ok(())
}

/// A declaration replayed on a new link continues its generation's
/// sequence, so its DEL names that generation at the sequence the edge
/// counted, also before the replay is acknowledged.
#[tokio::test]
async fn a_replayed_declaration_is_deleted_at_its_counted_sequence() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let (mut base, mut queue) = transport(fixture.context_mut()?);
    let mut edge = companion();
    let mut peer = EdgePeer::reset()?;
    let connection = ConnectionGeneration::new(1);
    declared(
        &mut fixture,
        &mut base,
        &mut queue,
        &mut edge,
        &mut peer,
        connection,
    )
    .await?;
    // Seven requests ran under generation zero on the first link.
    counted(&mut edge, connection, 7)?;
    peer.committed_requests(7)?;
    edge.link_down();
    peer.relink()?;
    edge.declare_origin(
        fixture.context_mut()?,
        &mut base,
        connection,
        &EdgePeer::facts(0),
        0,
    )
    .map_err(|error| error.code.to_string())?;
    let replayed = relay(&mut queue, &mut peer).await?;
    assert!(matches!(
        replayed.as_slice(),
        [CompanionFrame::OriginAck {
            origin_generation: 0,
            object_id: Some(_),
            ..
        }]
    ));
    edge.delete_origin(fixture.context_mut()?, &mut base, connection);
    let answers = relay(&mut queue, &mut peer).await?;
    assert!(
        deletion_acknowledged(&answers, 0),
        "the deletion names the replayed generation: {answers:?}"
    );
    assert_eq!(peer.held()?, fenced(0, 7));
    Ok(())
}

/// Companion 12.5: "`DEL` supplies the next unused sequence". The edge
/// counted a request the coordinator never executed, so its next unused
/// sequence is above the coordinator's; the coordinator fences the origin
/// at the sequence the edge states.
#[tokio::test]
async fn a_deletion_fences_at_the_sequence_the_edge_counted() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let (mut base, mut queue) = transport(fixture.context_mut()?);
    let mut edge = companion();
    let mut peer = EdgePeer::reset()?;
    let connection = ConnectionGeneration::new(1);
    declared(
        &mut fixture,
        &mut base,
        &mut queue,
        &mut edge,
        &mut peer,
        connection,
    )
    .await?;
    // Seven requests executed under generation zero; the edge counted an
    // eighth, which went out on the first link and did not execute.
    counted(&mut edge, connection, 8)?;
    peer.committed_requests(7)?;
    edge.link_down();
    peer.relink()?;
    edge.declare_origin(
        fixture.context_mut()?,
        &mut base,
        connection,
        &EdgePeer::facts(0),
        0,
    )
    .map_err(|error| error.code.to_string())?;
    let replayed = relay(&mut queue, &mut peer).await?;
    acknowledge(&mut edge, &replayed);
    edge.delete_origin(fixture.context_mut()?, &mut base, connection);
    let answers = relay(&mut queue, &mut peer).await?;
    assert!(
        deletion_acknowledged(&answers, 0),
        "the deletion is acknowledged: {answers:?}"
    );
    assert_eq!(
        peer.held()?,
        fenced(0, 8),
        "fenced at the sequence the edge counted"
    );
    Ok(())
}

/// An origin no declaration on the live link names sends no deletion: the
/// companion never declared it, or the link that carried its declaration is
/// gone.
#[tokio::test]
async fn an_origin_undeclared_on_the_live_link_sends_no_deletion() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let (mut base, mut queue) = transport(fixture.context_mut()?);
    let mut edge = companion();
    let mut peer = EdgePeer::reset()?;
    edge.delete_origin(
        fixture.context_mut()?,
        &mut base,
        ConnectionGeneration::new(7),
    );
    assert!(relay(&mut queue, &mut peer).await?.is_empty());
    let connection = ConnectionGeneration::new(1);
    declared(
        &mut fixture,
        &mut base,
        &mut queue,
        &mut edge,
        &mut peer,
        connection,
    )
    .await?;
    edge.link_down();
    edge.delete_origin(fixture.context_mut()?, &mut base, connection);
    assert!(
        relay(&mut queue, &mut peer).await?.is_empty(),
        "nothing is sent for an origin no live declaration names"
    );
    assert!(!edge.origins.contains_key(&connection));
    Ok(())
}

/// Every line the edge queued since the last call.
async fn lines(queue: &mut LinkQueue) -> Vec<String> {
    let mut lines = Vec::new();
    while let Ok(Some(line)) =
        tokio::time::timeout(std::time::Duration::from_millis(20), queue.recv()).await
    {
        lines.push(line.as_str().to_owned());
    }
    lines
}

/// The capabilities of a connection that negotiated the E2EE capability.
fn e2ee_capable() -> TestResult<CapabilityState> {
    let names = [
        "message-tags",
        "echo-message",
        "batch",
        "labeled-response",
        "standard-replies",
        "account-tag",
    ];
    let mut specs = names
        .iter()
        .map(|name| CapabilitySpec::new(name, None))
        .collect::<Result<Vec<_>, _>>()?;
    specs.push(CapabilitySpec::new(
        "agenc.ag/e2ee-mls",
        Some(agenc_relay_e2ee::limits::CAPABILITY_VALUE),
    )?);
    let profile = CapabilityProfile::new(specs)?;
    let mut state = CapabilityState::default();
    let _reply = state.request(&format!("{} agenc.ag/e2ee-mls", names.join(" ")), &profile)?;
    Ok(state)
}

/// The connection sends `EKEY WHOAMI` under its settled origin; returns the
/// lines the edge queued for it.
async fn whoami(
    fixture: &mut StateCoreFixture,
    base: &mut EdgeFederation,
    queue: &mut LinkQueue,
    edge: &mut E2eeEdge,
    connection: ConnectionGeneration,
) -> TestResult<Vec<String>> {
    let capabilities = e2ee_capable()?;
    let facts = SessionFacts {
        user_id: UserId::from_bytes([22; 16]),
        account: Some([b'a'; 24]),
        capabilities: &capabilities,
        nickname: "member",
    };
    let message = parse_message(FramedLine::new("EKEY WHOAMI")?)?.ok_or("message")?;
    let refused = edge.client_line(fixture.context_mut()?, base, connection, &message, &facts);
    assert!(refused.is_empty(), "the request is sent: {refused:?}");
    let sent = lines(queue).await;
    assert!(
        !sent.is_empty() && sent.iter().all(|line| line.contains(" EREQUEST ")),
        "one request: {sent:?}"
    );
    Ok(sent)
}

/// A connection that ends while no declaration on the live link names its
/// origin sends no deletion, and still releases its unanswered requests.
#[tokio::test]
async fn an_ended_connection_releases_its_requests_without_a_live_declaration() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let (mut base, mut queue) = transport(fixture.context_mut()?);
    let mut edge = companion();
    let mut peer = EdgePeer::reset()?;
    let connection = ConnectionGeneration::new(1);
    declared(
        &mut fixture,
        &mut base,
        &mut queue,
        &mut edge,
        &mut peer,
        connection,
    )
    .await?;
    edge.phase = Phase::Active;
    let _sent = whoami(&mut fixture, &mut base, &mut queue, &mut edge, connection).await?;
    assert_eq!(edge.pending.len(), 1, "one request is outstanding");
    edge.link_down();
    edge.delete_origin(fixture.context_mut()?, &mut base, connection);
    assert!(
        relay(&mut queue, &mut peer).await?.is_empty(),
        "nothing is sent for an origin no live declaration names"
    );
    assert!(!edge.origins.contains_key(&connection));
    assert!(
        edge.pending.is_empty(),
        "the ended connection's request is released"
    );
    Ok(())
}
