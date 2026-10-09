#![forbid(unsafe_code)]

//! An origin reset must name the live incarnation of a peer that is neither fenced nor expired,
//! and an origin declaration must agree with the record it carries.

use agenc_relay_storage::federation_records::PeerPhase;
use agenc_relay_types::{ConnectionId, OriginId};

use super::*;

const PEER: ServerId = ServerId::from_bytes([50; 16]);
const INCARNATION: ServerIncarnation = ServerIncarnation::from_bytes([51; 16]);

fn frame(link: u64, frame: FederationFrame) -> FederationInbound {
    FederationInbound {
        link: LinkId::new(link),
        peer: PEER,
        event: LinkEvent::Frame(frame),
        charge: None,
    }
}

fn reset(incarnation: ServerIncarnation) -> FederationFrame {
    FederationFrame::OriginReset {
        coordinator_server_id: COORDINATOR,
        server_incarnation: incarnation,
    }
}

fn live(coordinator: &FederationCoordinator) -> TestResult<bool> {
    Ok(coordinator.peers.get(&PEER).ok_or("peer")?.live.is_some())
}

fn linked() -> TestResult<(StateCoreFixture, FederationCoordinator, LinkQueue)> {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let mut coordinator = standalone_coordinator(PEER);
    let (handle, queue) = link_queue(1 << 20);
    coordinator.inbound(
        fixture.context_mut()?,
        established(1, PEER, INCARNATION, handle),
    );
    Ok((fixture, coordinator, queue))
}

type PeerEdit = fn(&mut FederationCoordinator) -> TestResult;

#[tokio::test]
async fn an_origin_reset_needs_the_live_incarnation_of_an_unfenced_unexpired_peer() -> TestResult {
    let cases: [(ServerIncarnation, PeerEdit); 3] = [
        (ServerIncarnation::from_bytes([99; 16]), |_| Ok(())),
        (INCARNATION, |coordinator| {
            coordinator
                .peers
                .get_mut(&PEER)
                .ok_or("peer")?
                .fence_pending = true;
            Ok(())
        }),
        (INCARNATION, |coordinator| {
            coordinator.peers.get_mut(&PEER).ok_or("peer")?.phase = PeerPhase::Expired;
            Ok(())
        }),
    ];
    for (incarnation, edit) in cases {
        let (mut fixture, mut coordinator, _queue) = linked()?;
        edit(&mut coordinator)?;
        coordinator.inbound(fixture.context_mut()?, frame(1, reset(incarnation)));
        assert_eq!(coordinator.counters().violations, 1);
        assert!(!live(&coordinator)?);
        assert_eq!(fixture.context_mut()?.pending_len(), 0);
    }
    let (mut fixture, mut coordinator, _queue) = linked()?;
    coordinator.inbound(fixture.context_mut()?, frame(1, reset(INCARNATION)));
    assert_eq!(coordinator.counters().violations, 0);
    assert!(live(&coordinator)?);
    Ok(())
}

fn origin_record(network: NetworkId, generation: u64) -> OriginRecord {
    OriginRecord {
        network_id: network,
        home_server_id: PEER,
        server_incarnation: INCARNATION,
        origin_id: OriginId::from_bytes([70; 16]),
        generation,
        previous_origin_object_id: [0; 32],
        connection_id: ConnectionId::from_bytes([71; 16]),
        session: None,
        account: None,
        connection_nonce: [5; 32],
    }
}

fn declaration(
    record: &OriginRecord,
    descriptor_generation: u64,
) -> TestResult<(ObjectCarrier, AssembledObject)> {
    let encoded = record.to_object()?.encode_canonical()?;
    let bytes = encoded.as_slice().to_vec();
    let object_id = federation_object_id(&bytes);
    let descriptor = OriginDescriptor {
        coordinator_server_id: COORDINATOR,
        server_incarnation: INCARNATION,
        origin_id: record.origin_id,
        generation: descriptor_generation,
        object_id,
    };
    let mut assembler = FragmentAssembler::new();
    let mut assembled = None;
    let mut carrier = None;
    for fragment in split_fragments(object_id, &bytes)? {
        let built = FederationFrame::OriginAdd {
            descriptor,
            fragment,
        };
        let (this_carrier, key) = carrier_of(&built).map_err(|error| error.to_string())?;
        let fragment = built.fragment().ok_or("frame without fragment")?;
        carrier = Some(this_carrier);
        if let AssemblyProgress::Complete(object) = assembler.admit(key, fragment, 0)? {
            assembled = Some(object);
        }
    }
    match (assembled, carrier) {
        (Some(object), Some(carrier)) => Ok((carrier, object)),
        _ => Err("the declaration did not assemble".into()),
    }
}

#[tokio::test]
async fn an_origin_declaration_must_agree_with_its_record_and_this_network() -> TestResult {
    let disagreeing = [
        declaration(&origin_record(NETWORK, 0), 1)?,
        declaration(&origin_record(NetworkId::from_bytes([99; 32]), 0), 0)?,
    ];
    for (carrier, object) in disagreeing {
        let (mut fixture, mut coordinator, _queue) = linked()?;
        coordinator.inbound(fixture.context_mut()?, frame(1, reset(INCARNATION)));
        assert_eq!(coordinator.counters().violations, 0);
        // The reset commits before the declaration is looked at.
        if fixture.context_mut()?.pending_len() != 0 {
            fixture.commit_staged_batch().await?;
            coordinator.batch_applied(fixture.context_mut()?);
        }
        assert!(coordinator.pending.is_none());
        coordinator.inbound(
            fixture.context_mut()?,
            FederationInbound {
                link: LinkId::new(1),
                peer: PEER,
                event: LinkEvent::Object { carrier, object },
                charge: None,
            },
        );
        assert_eq!(coordinator.counters().violations, 1);
        assert!(!live(&coordinator)?);
        assert!(coordinator.pending.is_none());
    }
    Ok(())
}

/// A deletion of a fenced origin is acknowledged for that origin alone and
/// changes nothing (Architecture 20.7: the fence already rejects every later
/// request for good), whatever generation and next sequence it names; the
/// link stays up, nothing is staged, and the sessions the origin owns are
/// queued to close, since its connection is gone.
#[tokio::test]
async fn a_deletion_of_a_fenced_origin_is_acknowledged_and_changes_nothing() -> TestResult {
    let (mut fixture, mut coordinator, mut queue) = linked()?;
    coordinator.inbound(fixture.context_mut()?, frame(1, reset(INCARNATION)));
    let (carrier, object) = declaration(&origin_record(NETWORK, 0), 0)?;
    coordinator.inbound(
        fixture.context_mut()?,
        FederationInbound {
            link: LinkId::new(1),
            peer: PEER,
            event: LinkEvent::Object { carrier, object },
            charge: None,
        },
    );
    while fixture.context_mut()?.pending_len() != 0 {
        fixture.commit_staged_batch().await?;
        coordinator.batch_applied(fixture.context_mut()?);
    }
    let key = OriginKey {
        home_server_id: PEER,
        server_incarnation: INCARNATION,
        origin_id: OriginId::from_bytes([70; 16]),
    };
    coordinator.origins.fence(&key)?;
    // A session the origin's connection registered.
    let registered = agenc_relay_types::UserId::from_bytes([72; 16]);
    coordinator
        .registered_sessions
        .insert(key, std::collections::BTreeSet::from([registered]));
    while let Ok(Some(_line)) =
        tokio::time::timeout(std::time::Duration::from_millis(20), queue.recv()).await
    {}
    for (generation, next) in [(0, 0), (1, 0), (0, 5)] {
        coordinator.inbound(
            fixture.context_mut()?,
            frame(
                1,
                FederationFrame::OriginDel {
                    coordinator_server_id: COORDINATOR,
                    server_incarnation: INCARNATION,
                    origin_id: key.origin_id,
                    generation,
                    next_operation_sequence: next,
                },
            ),
        );
        assert_eq!(
            coordinator.counters().violations,
            0,
            "({generation}, {next})"
        );
        assert!(live(&coordinator)?);
        assert!(coordinator.pending.is_none());
        assert_eq!(fixture.context_mut()?.pending_len(), 0);
        let line = tokio::time::timeout(std::time::Duration::from_secs(1), queue.recv())
            .await?
            .ok_or("acknowledgement")?;
        let acknowledged = parse_frame(line.as_str().trim_end_matches("\r\n"), COORDINATOR_NAME)
            .map_err(|error| format!("{error:?}"))?;
        assert!(
            matches!(
                acknowledged,
                FederationFrame::OriginAck {
                    generation: acked,
                    object_id: None,
                    ..
                } if acked == generation
            ),
            "({generation}, {next})"
        );
        let entry = coordinator.origins.origin(&key).ok_or("origin")?;
        assert_eq!(
            (entry.status, entry.generation),
            (agenc_relay_domain::federation::OriginStatus::Fenced, 0)
        );
        // The sessions the origin owns are queued to close.
        assert!(
            coordinator
                .peers
                .get(&PEER)
                .ok_or("peer")?
                .cleanup
                .contains(&registered),
            "({generation}, {next})"
        );
    }
    Ok(())
}
