#![forbid(unsafe_code)]

//! An origin reset must name the live incarnation of a peer that is neither fenced nor expired,
//! and an origin declaration must agree with the record it carries.

use agenc_ircd_storage::federation_records::PeerPhase;
use agenc_ircd_types::{ConnectionId, OriginId};

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
