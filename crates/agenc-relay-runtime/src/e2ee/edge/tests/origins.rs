#![forbid(unsafe_code)]

//! Reconnecting a companion origin must replay the declaration bytes exactly
//! and send its unanswered requests again once the replayed declaration is
//! acknowledged, each only under the generation its origin is acknowledged
//! at; its deletion names the generation the coordinator holds and the next
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

/// The device the origin's last declaration names.
fn declared_device(
    edge: &E2eeEdge,
    connection: ConnectionGeneration,
) -> TestResult<Option<[u8; 16]>> {
    use agenc_relay_e2ee::tls::TlsDecode;
    let (_, bytes) = edge
        .origins
        .get(&connection)
        .ok_or("origin")?
        .declaration
        .clone()
        .ok_or("declaration")?;
    let mut budget = agenc_relay_e2ee::tls::DecodeBudget::new(1 << 16, 256);
    let object = ArcWireObject::decode_kind(
        &bytes,
        Some(ArcWireObjectKind::FederationOrigin),
        &mut budget,
    )?;
    let origin = ArcFederationOrigin::decode_exact(object.body(), &mut budget)?;
    Ok(<[u8; 16]>::try_from(origin.attached_device_id.as_slice()).ok())
}

/// Opens the connection's one in-progress submission under the attachment
/// session `session_generation`.
fn open_submission(
    edge: &mut E2eeEdge,
    connection: ConnectionGeneration,
    session_generation: u64,
) -> TestResult {
    use agenc_relay_e2ee::wire::assembly::{AssemblyKey, Direction, Ingest, QuotaScopes, Sender};
    use agenc_relay_e2ee::wire::carrier::CarrierCommand;
    let fragments = fragment_object(&[7; 4_096])?;
    assert!(fragments.len() > 1);
    let first = fragments.into_iter().next().ok_or("fragment")?;
    let key = AssemblyKey {
        direction: Direction::LocalIngress,
        sender: Sender::Connection {
            connection: connection.get(),
            session_generation,
        },
        command: CarrierCommand::Tagmsg,
        route: [3; 32],
        scope: None,
        object_id: first.object_id,
    };
    let opened = edge.assembler.ingest(
        key.clone(),
        QuotaScopes::default(),
        CarrierCommand::Tagmsg.limit(),
        &first,
        0,
    )?;
    assert_eq!(opened, Ingest::Incomplete);
    edge.ingress.insert(
        connection,
        super::super::Ingress {
            key,
            command: super::super::router::Resolved::Command(
                agenc_relay_e2ee::wire::command::ClientCommand::Edirect([3; 32]),
            ),
        },
    );
    Ok(())
}

/// Logout, an account switch and a replaced session each end a device
/// attachment (companion 11.6: they invalidate it, and submission stops):
/// the declaration of the next base generation names no device, the
/// connection holds none, so its device-requiring lines are refused
/// locally, and its in-progress submission and the retry it answered from
/// its replies end; a later
/// declaration naming the first principal again does not bring the
/// attachment back. A reauthentication to the same account keeps it.
#[tokio::test]
async fn a_principal_change_ends_the_attachment_its_declarations_carried() -> TestResult {
    const ACCOUNT: [u8; 24] = [b'a'; 24];
    const DEVICE: [u8; 16] = [12; 16];
    let session = Some(([21; 16], [22; 16]));
    let principal = |generation, account, session| BaseOriginFacts {
        session,
        account,
        ..facts(generation)
    };
    for (case, changed, keeps, submitting) in [
        (
            "reauthentication",
            principal(3, Some((ACCOUNT, 4)), session),
            true,
            true,
        ),
        ("logout", principal(3, None, session), false, true),
        (
            "logout with no submission in progress",
            principal(3, None, session),
            false,
            false,
        ),
        (
            "account switch",
            principal(3, Some(([b'b'; 24], 1)), session),
            false,
            true,
        ),
        (
            "replaced session",
            principal(3, Some((ACCOUNT, 3)), Some(([23; 16], [24; 16]))),
            false,
            true,
        ),
    ] {
        let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
        let (mut base, mut queue) = transport(fixture.context_mut()?);
        let mut edge = companion();
        let connection = ConnectionGeneration::new(1);
        base.connection_opened(fixture.context_mut()?, connection);
        let authenticated = principal(1, Some((ACCOUNT, 3)), session);
        for declared in [facts(0), authenticated] {
            let generation = declared.generation;
            edge.declare_origin(
                fixture.context_mut()?,
                &mut base,
                connection,
                &declared,
                generation,
            )
            .map_err(|error| error.code.to_string())?;
            let _line = next_declaration(&mut queue).await?;
            edge.acknowledge_origin([9; 16], generation);
        }
        edge.device_attached(fixture.context_mut()?, &mut base, connection, DEVICE, 1);
        let attached = principal(2, Some((ACCOUNT, 3)), session);
        edge.declare_origin(fixture.context_mut()?, &mut base, connection, &attached, 2)
            .map_err(|error| error.code.to_string())?;
        let _line = next_declaration(&mut queue).await?;
        edge.acknowledge_origin([9; 16], 2);
        assert_eq!(declared_device(&edge, connection)?, Some(DEVICE), "{case}");
        if submitting {
            open_submission(&mut edge, connection, 1)?;
        }
        // The connection's last retried object, answered from its replies.
        edge.retried.insert(connection, [5; 32]);
        edge.declare_origin(fixture.context_mut()?, &mut base, connection, &changed, 3)
            .map_err(|error| error.code.to_string())?;
        let _line = next_declaration(&mut queue).await?;
        edge.acknowledge_origin([9; 16], 3);
        let device = edge.origins.get(&connection).ok_or("origin")?.device;
        if keeps {
            assert_eq!(device, Some((DEVICE, 1)), "{case}");
            assert_eq!(declared_device(&edge, connection)?, Some(DEVICE), "{case}");
            assert!(edge.ingress.contains_key(&connection), "{case}");
            assert_eq!(edge.assembler.open_count(), 1, "{case}");
            assert!(edge.retried.contains_key(&connection), "{case}");
            continue;
        }
        assert_eq!(device, None, "{case}");
        assert_eq!(declared_device(&edge, connection)?, None, "{case}");
        assert!(!edge.ingress.contains_key(&connection), "{case}");
        assert_eq!(edge.assembler.open_count(), 0, "{case}");
        assert!(!edge.retried.contains_key(&connection), "{case}");
        let restored = principal(4, Some((ACCOUNT, 3)), session);
        edge.declare_origin(fixture.context_mut()?, &mut base, connection, &restored, 4)
            .map_err(|error| error.code.to_string())?;
        assert_eq!(declared_device(&edge, connection)?, None, "{case}");
    }
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
    assert!(
        edge.closed_requests.is_empty(),
        "no deletion went out, so the request keeps no place"
    );
    Ok(())
}

/// A closed connection's unanswered requests keep their places in the
/// outstanding bounds while the coordinator may still hold them queued
/// (companion 12.5, 16): a request already answered holds none, another
/// connection's requests stay its own, and each unanswered one holds its
/// place until a frame of its result arrives or the origin's deletion is
/// acknowledged; a link loss releases them all.
#[tokio::test]
async fn a_closed_connection_keeps_its_unanswered_requests_until_answered() -> TestResult {
    let mut fixture = StateCoreFixture::new((0..=u8::MAX).cycle().take(4_096).collect())?;
    let (mut base, mut queue) = transport(fixture.context_mut()?);
    let mut edge = companion();
    let mut peer = EdgePeer::reset()?;
    let (connection, other) = (ConnectionGeneration::new(1), ConnectionGeneration::new(2));
    declared(
        &mut fixture,
        &mut base,
        &mut queue,
        &mut edge,
        &mut peer,
        connection,
    )
    .await?;
    edge.declare_origin(
        fixture.context_mut()?,
        &mut base,
        other,
        &EdgePeer::facts_of([0x77; 16], 0),
        0,
    )
    .map_err(|error| error.code.to_string())?;
    let answers = relay(&mut queue, &mut peer).await?;
    acknowledge(&mut edge, &answers);
    edge.phase = Phase::Active;
    for _ in 0..3 {
        let _sent = whoami(&mut fixture, &mut base, &mut queue, &mut edge, connection).await?;
    }
    let _sent = whoami(&mut fixture, &mut base, &mut queue, &mut edge, other).await?;
    let ids: Vec<[u8; 16]> = edge
        .pending
        .iter()
        .filter(|(_, pending)| pending.generation == connection)
        .map(|(id, _)| *id)
        .collect();
    let [answered, first, second] = ids[..] else {
        return Err(format!("three requests: {ids:?}").into());
    };
    edge.pending.get_mut(&answered).ok_or("pending")?.result =
        Some(super::super::result::DecodedResult {
            request_object_id: [7; 32],
            kind: agenc_relay_e2ee::objects::federation::ArcFederationResultKind::Failed,
            value: super::super::result::ResultValue::Failed {
                code: "E2EE_SYNCING".to_owned(),
                context: Vec::new(),
            },
            completion_event_id: None,
            snapshot_token: None,
            next_cursor: None,
            descriptors: Vec::new(),
        });
    edge.delete_origin(fixture.context_mut()?, &mut base, connection);
    assert_eq!(
        edge.pending.len(),
        1,
        "the other connection's request stays"
    );
    let held = |edge: &E2eeEdge| edge.closed_requests.keys().copied().collect::<Vec<_>>();
    assert_eq!(held(&edge), vec![first, second], "the unanswered ones");
    let fragment = fragment_object(&[0; 16])?
        .into_iter()
        .next()
        .ok_or("fragment")?;
    let answer = CompanionFrame::Result {
        correlation: agenc_relay_e2ee::federation::frames::Correlation {
            peer_server_id: [3; 16],
            server_incarnation: [4; 16],
            origin_id: EdgePeer::facts(0).origin_id,
            origin_generation: 0,
            operation_sequence: 0,
            request_id: first,
        },
        object_id: [0; 32],
        fragment,
    };
    let _dropped = edge
        .on_result_frame(fixture.context_mut()?, answer)
        .map_err(|error| error.code.to_string())?;
    assert_eq!(held(&edge), vec![second], "a frame of its result arrived");
    let answers = relay(&mut queue, &mut peer).await?;
    assert!(deletion_acknowledged(&answers, 0), "{answers:?}");
    let _outputs = edge.handle_frames(fixture.context_mut()?, &mut base, answers);
    assert!(held(&edge).is_empty(), "the deletion is acknowledged");
    edge.delete_origin(fixture.context_mut()?, &mut base, other);
    assert_eq!(held(&edge).len(), 1);
    edge.link_down();
    assert!(held(&edge).is_empty(), "the link ended");
    Ok(())
}

/// An active edge whose one request under generation zero went out on a
/// link that then closed before the coordinator received it; the edge has
/// sent EORIGIN RESET on the next link and replayed its declaration, and
/// the coordinator held the base origin set `base_ready` at the RESET.
/// Returns the edge, its link, the coordinator, the coordinator's answers
/// so far and the request's lines.
async fn relinked_with_a_lost_request(
    fixture: &mut StateCoreFixture,
    base_ready: bool,
) -> TestResult<(
    EdgeFederation,
    LinkQueue,
    E2eeEdge,
    EdgePeer,
    Vec<CompanionFrame>,
    Vec<String>,
)> {
    let (mut base, mut queue) = transport(fixture.context_mut()?);
    let mut edge = companion();
    let mut peer = EdgePeer::reset()?;
    let connection = ConnectionGeneration::new(1);
    declared(
        fixture, &mut base, &mut queue, &mut edge, &mut peer, connection,
    )
    .await?;
    edge.phase = Phase::Active;
    let sent = whoami(fixture, &mut base, &mut queue, &mut edge, connection).await?;
    edge.link_down();
    peer.link_lost(base_ready);
    edge.begin_origins(fixture.context_mut()?, &mut base)
        .map_err(|error| error.code.to_string())?;
    edge.declare_origin(
        fixture.context_mut()?,
        &mut base,
        connection,
        &EdgePeer::facts(0),
        0,
    )
    .map_err(|error| error.code.to_string())?;
    let answers = relay(&mut queue, &mut peer).await?;
    Ok((base, queue, edge, peer, answers, sent))
}

/// Companion 12.5: a reconnect replays RESET and origin state before it
/// resumes, and the coordinator answers EORIGIN RESET with READY as soon as
/// the base origin set is ready, so READY can precede the acknowledgement of
/// a replayed declaration. That acknowledgement sends the origin's
/// unanswered requests again, exactly as first sent, and the coordinator
/// runs them under the generation it holds.
#[tokio::test]
async fn requests_resend_when_their_origin_is_acknowledged_after_ready() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let (mut base, mut queue, mut edge, mut peer, answers, sent) =
        relinked_with_a_lost_request(&mut fixture, true).await?;
    let [
        ready @ CompanionFrame::OriginReady { .. },
        acknowledgement @ CompanionFrame::OriginAck {
            origin_generation: 0,
            object_id: Some(_),
            ..
        },
    ] = answers.as_slice()
    else {
        return Err(format!("READY, then the acknowledgement: {answers:?}").into());
    };
    let _outputs = edge.handle_frames(fixture.context_mut()?, &mut base, vec![ready.clone()]);
    assert!(
        lines(&mut queue).await.is_empty(),
        "READY resends no origin it has not seen acknowledged"
    );
    let _outputs = edge.handle_frames(
        fixture.context_mut()?,
        &mut base,
        vec![acknowledgement.clone()],
    );
    let resent = lines(&mut queue).await;
    assert_eq!(resent, sent, "the request goes out again as first sent");
    for line in &resent {
        peer.deliver(line, "edge.example")
            .map_err(|fault| format!("the coordinator refused {line:?}: {fault:?}"))?;
    }
    assert_eq!(
        peer.held()?,
        Held {
            generation: 0,
            next_sequence: 1,
            fenced: false,
        },
        "the coordinator ran the request"
    );
    edge.delete_origin(
        fixture.context_mut()?,
        &mut base,
        ConnectionGeneration::new(1),
    );
    let deleted = relay(&mut queue, &mut peer).await?;
    assert!(deletion_acknowledged(&deleted, 0), "{deleted:?}");
    assert_eq!(peer.held()?, fenced(0, 1));
    Ok(())
}

/// When the base origin set is not ready at the RESET, the acknowledgement
/// of the replayed declaration precedes READY, and READY resends the
/// origin's unanswered requests once. A later acknowledgement on the same
/// link, of a new generation, of another origin or of a generation never
/// declared, sends nothing.
#[tokio::test]
async fn requests_resend_once_when_ready_follows_the_acknowledgement() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let (mut base, mut queue, mut edge, mut peer, answers, sent) =
        relinked_with_a_lost_request(&mut fixture, false).await?;
    assert!(
        matches!(
            answers.as_slice(),
            [CompanionFrame::OriginAck {
                origin_generation: 0,
                object_id: Some(_),
                ..
            }]
        ),
        "the acknowledgement alone: {answers:?}"
    );
    let _outputs = edge.handle_frames(fixture.context_mut()?, &mut base, answers);
    assert!(
        lines(&mut queue).await.is_empty(),
        "an acknowledgement before READY sends nothing"
    );
    let ready = peer.base_ready()?;
    assert!(matches!(
        ready.as_slice(),
        [CompanionFrame::OriginReady { .. }]
    ));
    let _outputs = edge.handle_frames(fixture.context_mut()?, &mut base, ready);
    let resent = lines(&mut queue).await;
    assert_eq!(resent, sent, "READY sends the request again as first sent");
    for line in &resent {
        peer.deliver(line, "edge.example")
            .map_err(|fault| format!("the coordinator refused {line:?}: {fault:?}"))?;
    }
    assert_eq!(peer.held()?.next_sequence, 1, "the coordinator ran it");
    let connection = ConnectionGeneration::new(1);
    peer.base_generation(1)?;
    edge.declare_origin(
        fixture.context_mut()?,
        &mut base,
        connection,
        &EdgePeer::facts(1),
        1,
    )
    .map_err(|error| error.code.to_string())?;
    let advanced = relay(&mut queue, &mut peer).await?;
    let _outputs = edge.handle_frames(fixture.context_mut()?, &mut base, advanced);
    let origin_id = EdgePeer::facts(1).origin_id;
    for (acknowledged, generation) in [([0x99; 16], 1), (origin_id, 7)] {
        edge.origin_acked(
            fixture.context_mut()?,
            &mut base,
            acknowledged,
            generation,
            true,
        )
        .map_err(|error| error.code.to_string())?;
    }
    assert!(
        lines(&mut queue).await.is_empty(),
        "no later acknowledgement on the link sends the request again"
    );
    let origin = edge.origins.get(&connection).ok_or("origin")?;
    assert_eq!((origin.declared, origin.acked), (Some(1), Some(1)));
    Ok(())
}

/// A request went out under generation zero on a link that closed before
/// the coordinator received it; before the companion replays its origins on
/// the next link the shared base origin advances (a login completed), so
/// the edge declares generation one, which the coordinator accepts as the
/// successor of the generation zero it held. The resume names each
/// unanswered request only under the generation its origin is acknowledged
/// at, so the request waits rather than going out under the superseded
/// generation. Returns the coordinator's refusals, if any, of request lines
/// the edge sent; `base_ready` decides whether READY precedes the
/// acknowledgement of the replayed declaration.
async fn relinked_after_the_origin_generation_advanced(
    base_ready: bool,
) -> TestResult<Vec<String>> {
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
    edge.link_down();
    peer.link_lost(base_ready);
    peer.base_generation(1)?;
    edge.begin_origins(fixture.context_mut()?, &mut base)
        .map_err(|error| error.code.to_string())?;
    edge.declare_origin(
        fixture.context_mut()?,
        &mut base,
        connection,
        &EdgePeer::facts(1),
        1,
    )
    .map_err(|error| error.code.to_string())?;
    let mut answers = relay(&mut queue, &mut peer).await?;
    if !base_ready {
        answers.extend(peer.base_ready()?);
    }
    let mut refusals = Vec::new();
    for answer in answers {
        let _outputs = edge.handle_frames(fixture.context_mut()?, &mut base, vec![answer]);
        for line in lines(&mut queue).await {
            if line.contains(" EREQUEST ")
                && let Err(fault) = peer.deliver(&line, "edge.example")
            {
                refusals.push(format!("{fault:?} for {line}"));
            }
        }
    }
    Ok(refusals)
}

/// READY precedes the acknowledgement of the replayed declaration: neither
/// resends the request under the superseded generation.
#[tokio::test]
async fn a_superseded_generation_request_is_held_when_ready_precedes_the_acknowledgement()
-> TestResult {
    let refusals = Box::pin(relinked_after_the_origin_generation_advanced(true)).await?;
    assert!(refusals.is_empty(), "the coordinator refused: {refusals:?}");
    Ok(())
}

/// The acknowledgement of the replayed declaration precedes READY: neither
/// resends the request under the superseded generation.
#[tokio::test]
async fn a_superseded_generation_request_is_held_when_the_acknowledgement_precedes_ready()
-> TestResult {
    let refusals = Box::pin(relinked_after_the_origin_generation_advanced(false)).await?;
    assert!(refusals.is_empty(), "the coordinator refused: {refusals:?}");
    Ok(())
}

/// The payload the requests below carry: a complete wire object.
fn payload_object() -> TestResult<Vec<u8>> {
    Ok(ArcWireObject::new(ArcWireObjectKind::RootIdentity, vec![12; 32])?.encode()?)
}

/// Makes the edge's one unanswered request carry a payload: it is encoded
/// again under the same correlation as a `publish_identity` request that
/// names the payload object, which follows it, as the edge sends a request
/// that carries an object. Returns the request's lines.
fn carry_payload(edge: &mut E2eeEdge) -> TestResult<Vec<String>> {
    use agenc_relay_e2ee::objects::federation::{ArcFederationOpcode, ArcFederationRequest};
    let payload = payload_object()?;
    let payload_object_id = *agenc_relay_e2ee::ObjectId::compute(&payload).as_bytes();
    let (network_id, home_server_id, server_incarnation) = (
        edge.config.network_id,
        *edge.config.server_id.as_bytes(),
        edge.config.incarnation,
    );
    let pending = edge
        .pending
        .values_mut()
        .next()
        .ok_or("one unanswered request")?;
    let Some(CompanionFrame::Request { correlation, .. }) = pending.frames.first().cloned() else {
        return Err("the request's first frame".into());
    };
    let request = ArcFederationRequest {
        profile_version: 1,
        network_id,
        home_server_id,
        server_incarnation,
        origin_id: correlation.origin_id,
        origin_generation: correlation.origin_generation,
        operation_sequence: correlation.operation_sequence,
        request_id: correlation.request_id,
        opcode: ArcFederationOpcode::PublishIdentity,
        encoded_parameters: Opaque::new(Vec::new())?,
        payload_object_id: Opaque::new(payload_object_id.to_vec())?,
    };
    let bytes =
        ArcWireObject::new(ArcWireObjectKind::FederationRequest, request.encode()?)?.encode()?;
    let request_object_id = *agenc_relay_e2ee::ObjectId::compute(&bytes).as_bytes();
    let mut frames: Vec<CompanionFrame> = fragment_object(&bytes)?
        .into_iter()
        .map(|fragment| CompanionFrame::Request {
            correlation,
            object_id: request_object_id,
            fragment,
        })
        .collect();
    frames.extend(
        fragment_object(&payload)?
            .into_iter()
            .map(|fragment| CompanionFrame::Payload {
                correlation,
                object_id: payload_object_id,
                fragment,
            }),
    );
    pending.frames = frames.clone();
    pending.request_object_id = request_object_id;
    frames
        .iter()
        .map(|frame| {
            edge.line(frame)
                .map(|line| line.as_str().to_owned())
                .map_err(|error| error.code.to_string().into())
        })
        .collect()
}

/// How far the request a closed link carried got at the coordinator.
#[derive(Clone, Copy, Debug)]
enum Reached {
    /// Its request object completed and waited for its payload.
    RequestObject,
    /// It completed and waited for the executor.
    Unexecuted,
    /// It ran; its result was lost with the link.
    Executed,
}

/// What a resume sent and the coordinator answered.
struct Resumed {
    /// The request's lines as first sent.
    sent: Vec<String>,
    /// The lines the resume sent again.
    resent: Vec<String>,
    /// The coordinator's refusals of them.
    refusals: Vec<String>,
    /// The results the coordinator answered them with.
    results: usize,
    /// What the coordinator then holds for the origin.
    held: Held,
}

/// An active edge sends one request under generation zero, with or without
/// a payload, which gets as far as `reached` at the coordinator before the
/// link closes. On the next link the edge replays its origin; the
/// coordinator held the base origin set `base_ready` at the RESET, so READY
/// comes before or after the acknowledgement of the replayed declaration.
/// Every line the edge then sends is delivered to the coordinator.
async fn resumed_after(
    reached: Reached,
    carries_payload: bool,
    base_ready: bool,
) -> TestResult<Resumed> {
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
    let mut sent = whoami(&mut fixture, &mut base, &mut queue, &mut edge, connection).await?;
    if carries_payload {
        sent = carry_payload(&mut edge)?;
    }
    for line in &sent {
        let outcome = match reached {
            Reached::RequestObject if !line.contains(" EREQUEST ") => Ok(()),
            Reached::RequestObject | Reached::Unexecuted => {
                peer.deliver_unexecuted(line, "edge.example")
            }
            Reached::Executed => peer.deliver(line, "edge.example").map(|_lost| ()),
        };
        outcome.map_err(|fault| format!("the first copy was refused: {fault:?}"))?;
    }
    edge.link_down();
    peer.link_lost(base_ready);
    edge.begin_origins(fixture.context_mut()?, &mut base)
        .map_err(|error| error.code.to_string())?;
    edge.declare_origin(
        fixture.context_mut()?,
        &mut base,
        connection,
        &EdgePeer::facts(0),
        0,
    )
    .map_err(|error| error.code.to_string())?;
    let mut answers = relay(&mut queue, &mut peer).await?;
    if !base_ready {
        answers.extend(peer.base_ready()?);
    }
    let mut resumed = Resumed {
        sent,
        resent: Vec::new(),
        refusals: Vec::new(),
        results: 0,
        held: peer.held()?,
    };
    for answer in answers {
        let _outputs = edge.handle_frames(fixture.context_mut()?, &mut base, vec![answer]);
        for line in lines(&mut queue).await {
            match peer.deliver(&line, "edge.example") {
                Ok(frames) => {
                    resumed.results += frames
                        .iter()
                        .filter(|frame| matches!(frame, CompanionFrame::Result { .. }))
                        .count();
                }
                Err(fault) => resumed.refusals.push(format!("{fault:?} for {line}")),
            }
            resumed.resent.push(line);
        }
    }
    resumed.held = peer.held()?;
    Ok(resumed)
}

/// The request shapes a closed link can leave unexecuted at the
/// coordinator: complete, with or without a payload, or with its payload
/// still outstanding.
const LEFT_UNEXECUTED: [(Reached, bool); 3] = [
    (Reached::Unexecuted, false),
    (Reached::Unexecuted, true),
    (Reached::RequestObject, true),
];

/// Requires that the resume sent the request again exactly as first sent
/// and that the coordinator ran it once, at sequence zero.
fn assert_ran(resumed: &Resumed, case: &str) {
    assert!(
        resumed.refusals.is_empty(),
        "{case}: the coordinator refused {:?}",
        resumed.refusals
    );
    assert_eq!(
        resumed.resent, resumed.sent,
        "{case}: the request goes out again as first sent"
    );
    assert_eq!(
        resumed.held,
        Held {
            generation: 0,
            next_sequence: 1,
            fenced: false,
        },
        "{case}: the coordinator ran the request once"
    );
}

/// Companion 12.5: a request a closed link left unexecuted is sent again
/// once its origin is replayed, here at the acknowledgement that follows
/// READY, and the coordinator runs it at its sequence. It completed the
/// request's objects on the closed link but keeps no replay row for it, so
/// the copy the next link carries is assembled and classified again.
#[tokio::test]
async fn a_request_left_unexecuted_runs_when_resent_after_ready() -> TestResult {
    for (reached, carries_payload) in LEFT_UNEXECUTED {
        let resumed = Box::pin(resumed_after(reached, carries_payload, true)).await?;
        assert_ran(&resumed, &format!("{reached:?}, payload {carries_payload}"));
        assert_eq!(resumed.results, 0, "nothing is answered from a replay row");
    }
    Ok(())
}

/// The same requests when the acknowledgement of the replayed declaration
/// precedes READY, which then sends them again.
#[tokio::test]
async fn a_request_left_unexecuted_runs_when_ready_follows_the_acknowledgement() -> TestResult {
    for (reached, carries_payload) in LEFT_UNEXECUTED {
        let resumed = Box::pin(resumed_after(reached, carries_payload, false)).await?;
        assert_ran(&resumed, &format!("{reached:?}, payload {carries_payload}"));
        assert_eq!(resumed.results, 0, "nothing is answered from a replay row");
    }
    Ok(())
}

/// Architecture 20.5 and companion 12.5: an exact duplicate returns the
/// stored result. A request that ran before its link closed is sent again
/// with its payload, if any, and the coordinator answers it once from its
/// replay row without running it again, in both orders of READY and the
/// acknowledgement.
#[tokio::test]
async fn an_executed_request_resent_on_the_next_link_returns_its_stored_result() -> TestResult {
    for carries_payload in [false, true] {
        for base_ready in [true, false] {
            let resumed = Box::pin(resumed_after(
                Reached::Executed,
                carries_payload,
                base_ready,
            ))
            .await?;
            let case = format!("payload {carries_payload}, READY first {base_ready}");
            assert_ran(&resumed, &case);
            assert_eq!(resumed.results, 1, "{case}: the stored result answers it");
        }
    }
    Ok(())
}

/// Two origins resume on one link. The first one's replayed declaration is
/// acknowledged before READY, which resends its request; the second one's
/// is acknowledged after READY. That later acknowledgement resends only the
/// requests of the origin it settles, never again those READY resent on
/// the link.
#[tokio::test]
async fn a_later_acknowledgement_resends_only_the_requests_of_the_origin_it_settles() -> TestResult
{
    // Distinct entropy gives the two requests distinct request IDs.
    let entropy = (0..4_096_u16)
        .map(|index| u8::try_from(index % 251))
        .collect::<Result<Vec<_>, _>>()?;
    let mut fixture = StateCoreFixture::new(entropy)?;
    let (mut base, mut queue) = transport(fixture.context_mut()?);
    let mut edge = companion();
    let mut peer = EdgePeer::reset()?;
    let second_origin = [0x55; 16];
    let origins = [
        (ConnectionGeneration::new(1), EdgePeer::facts(0)),
        (
            ConnectionGeneration::new(2),
            EdgePeer::facts_of(second_origin, 0),
        ),
    ];
    for (connection, facts) in &origins {
        edge.declare_origin(fixture.context_mut()?, &mut base, *connection, facts, 0)
            .map_err(|error| error.code.to_string())?;
        let answers = relay(&mut queue, &mut peer).await?;
        acknowledge(&mut edge, &answers);
    }
    edge.phase = Phase::Active;
    let mut sent = Vec::new();
    for (connection, _) in &origins {
        sent.push(whoami(&mut fixture, &mut base, &mut queue, &mut edge, *connection).await?);
    }
    edge.link_down();
    peer.link_lost(false);
    edge.begin_origins(fixture.context_mut()?, &mut base)
        .map_err(|error| error.code.to_string())?;
    // The coordinator acknowledges the first replayed declaration, the base
    // origin set then becomes ready, and the second declaration follows.
    let mut from_coordinator = Vec::new();
    for (index, (connection, facts)) in origins.iter().enumerate() {
        edge.declare_origin(fixture.context_mut()?, &mut base, *connection, facts, 0)
            .map_err(|error| error.code.to_string())?;
        let mut answers = relay(&mut queue, &mut peer).await?;
        if index == 0 {
            answers.extend(peer.base_ready()?);
        }
        from_coordinator.extend(answers);
    }
    let [
        first_acknowledgement @ CompanionFrame::OriginAck { .. },
        ready @ CompanionFrame::OriginReady { .. },
        second_acknowledgement @ CompanionFrame::OriginAck { .. },
    ] = from_coordinator.as_slice()
    else {
        return Err(
            format!("acknowledgement, READY, acknowledgement: {from_coordinator:?}").into(),
        );
    };
    let [first_sent, second_sent] = sent.as_slice() else {
        return Err("two requests".into());
    };
    let expected = [Vec::new(), first_sent.clone(), second_sent.clone()];
    let delivered = [first_acknowledgement, ready, second_acknowledgement];
    for (frame, expected) in delivered.into_iter().zip(expected) {
        let _outputs = edge.handle_frames(fixture.context_mut()?, &mut base, vec![frame.clone()]);
        let resent = lines(&mut queue).await;
        assert_eq!(resent, expected, "after {frame:?}");
        for line in &resent {
            peer.deliver(line, "edge.example")
                .map_err(|fault| format!("the coordinator refused {line:?}: {fault:?}"))?;
        }
    }
    assert_eq!(
        peer.held()?.next_sequence,
        1,
        "the first origin's request ran"
    );
    assert_eq!(
        peer.held_of(second_origin)?.next_sequence,
        1,
        "the second origin's request ran"
    );
    Ok(())
}

/// READY reaches the edge while a newer declaration of the origin, which
/// the link carried before READY arrived, awaits its acknowledgement: the
/// coordinator holds the newer generation, so READY resends nothing named
/// under the acknowledged one, and the newer acknowledgement does not
/// resend a request named under the generation it replaced. That request
/// gets no reply; the connection's end releases it.
#[tokio::test]
async fn ready_resends_nothing_while_a_newer_declaration_awaits_its_acknowledgement() -> TestResult
{
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
    edge.link_down();
    peer.link_lost(false);
    edge.begin_origins(fixture.context_mut()?, &mut base)
        .map_err(|error| error.code.to_string())?;
    edge.declare_origin(
        fixture.context_mut()?,
        &mut base,
        connection,
        &EdgePeer::facts(0),
        0,
    )
    .map_err(|error| error.code.to_string())?;
    let replayed = relay(&mut queue, &mut peer).await?;
    let _outputs = edge.handle_frames(fixture.context_mut()?, &mut base, replayed);
    assert!(
        lines(&mut queue).await.is_empty(),
        "an acknowledgement before READY sends nothing"
    );
    // The base origin advances and the edge declares generation one; the
    // coordinator's READY is on its way, and it reads the declaration after.
    peer.base_generation(1)?;
    edge.declare_origin(
        fixture.context_mut()?,
        &mut base,
        connection,
        &EdgePeer::facts(1),
        1,
    )
    .map_err(|error| error.code.to_string())?;
    let ready = peer.base_ready()?;
    let advanced = relay(&mut queue, &mut peer).await?;
    for (step, frames) in [("READY", ready), ("the acknowledgement", advanced)] {
        let _outputs = edge.handle_frames(fixture.context_mut()?, &mut base, frames);
        let sent = lines(&mut queue).await;
        let refused: Vec<String> = sent
            .iter()
            .filter_map(|line| {
                peer.deliver(line, "edge.example")
                    .err()
                    .map(|fault| format!("{fault:?} for {line}"))
            })
            .collect();
        assert!(
            sent.is_empty(),
            "{step} sends nothing named under generation zero: {sent:?}, refused {refused:?}"
        );
    }
    let origin = edge.origins.get(&connection).ok_or("origin")?;
    assert_eq!((origin.declared, origin.acked), (Some(1), Some(1)));
    assert_eq!(edge.pending.len(), 1, "the request stays unanswered");
    edge.delete_origin(fixture.context_mut()?, &mut base, connection);
    let deleted = relay(&mut queue, &mut peer).await?;
    assert!(deletion_acknowledged(&deleted, 1), "{deleted:?}");
    assert_eq!(peer.held()?, fenced(1, 0));
    assert!(edge.pending.is_empty(), "the connection's end releases it");
    Ok(())
}

/// Only an origin's first acknowledgement on a link past READY resends its
/// unanswered requests: the same acknowledgement repeated on that link
/// resends nothing, since the requests went out on the link already.
#[tokio::test]
async fn a_repeated_acknowledgement_on_the_link_resends_nothing() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let (mut base, mut queue, mut edge, mut peer, answers, sent) =
        relinked_with_a_lost_request(&mut fixture, true).await?;
    let [
        ready @ CompanionFrame::OriginReady { .. },
        acknowledgement @ CompanionFrame::OriginAck { .. },
    ] = answers.as_slice()
    else {
        return Err(format!("READY, then the acknowledgement: {answers:?}").into());
    };
    let _outputs = edge.handle_frames(fixture.context_mut()?, &mut base, vec![ready.clone()]);
    let _outputs = edge.handle_frames(
        fixture.context_mut()?,
        &mut base,
        vec![acknowledgement.clone()],
    );
    let resent = lines(&mut queue).await;
    assert_eq!(resent, sent);
    for line in &resent {
        peer.deliver_unexecuted(line, "edge.example")
            .map_err(|fault| format!("{fault:?}"))?;
    }
    let _outputs = edge.handle_frames(
        fixture.context_mut()?,
        &mut base,
        vec![acknowledgement.clone()],
    );
    let again = lines(&mut queue).await;
    let mut refusals = Vec::new();
    for line in &again {
        if let Err(fault) = peer.deliver(line, "edge.example") {
            refusals.push(format!("{fault:?}"));
        }
    }
    assert!(
        again.is_empty(),
        "a repeated acknowledgement resent {} lines; coordinator: {refusals:?}",
        again.len()
    );
    Ok(())
}
