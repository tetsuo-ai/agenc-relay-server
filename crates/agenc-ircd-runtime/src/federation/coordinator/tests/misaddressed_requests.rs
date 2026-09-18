#![forbid(unsafe_code)]

//! A request whose carrier disagrees with its own header is refused before it consumes anything.

use agenc_ircd_federation_wire::OperationDescriptor;
use agenc_ircd_types::{OriginId, RequestId};

use super::*;

type Forge = fn(&mut RequestHeader, &mut OperationDescriptor);

fn forgeries() -> [Forge; 8] {
    [
        |header, _| header.network_id = NetworkId::from_bytes([99; 32]),
        |header, _| header.replay_key.home_server_id = ServerId::from_bytes([99; 16]),
        |_, descriptor| descriptor.addressed_server_id = ServerId::from_bytes([99; 16]),
        |_, descriptor| descriptor.server_incarnation = ServerIncarnation::from_bytes([99; 16]),
        |_, descriptor| descriptor.origin_id = OriginId::from_bytes([99; 16]),
        |_, descriptor| descriptor.origin_generation = 9,
        |_, descriptor| descriptor.operation_sequence = 9,
        |_, descriptor| descriptor.request_id = RequestId::from_bytes([99; 16]),
    ]
}

async fn send_forged(edge: &mut Edge, origin: &Origin, forge: Forge) -> TestResult {
    let operation = session_open(62, "carol");
    let mut header = RequestHeader {
        network_id: NETWORK,
        replay_key: origin.replay_key(edge),
        request_id: RequestId::from_bytes([61; 16]),
        opcode: operation.opcode(),
    };
    let mut descriptor = OperationDescriptor {
        addressed_server_id: COORDINATOR,
        server_incarnation: header.replay_key.server_incarnation,
        origin_id: header.replay_key.origin_id,
        origin_generation: header.replay_key.origin_generation,
        operation_sequence: header.replay_key.operation_sequence,
        request_id: header.request_id,
        object_id: federation_object_id(&[]),
    };
    forge(&mut header, &mut descriptor);
    let bytes = header
        .build(&operation.to_object()?)?
        .encode_canonical()?
        .as_slice()
        .to_vec();
    descriptor.object_id = federation_object_id(&bytes);
    edge.object(&bytes, |fragment| FederationFrame::Request {
        descriptor,
        fragment,
    })
    .await
}

#[tokio::test]
async fn a_forged_carrier_closes_the_link_and_leaves_the_origin_sequence_unused() -> TestResult {
    for forge in forgeries() {
        let identity = peer_identity(ServerId::from_bytes([42; 16]), "edge.example");
        run_coordinator(&[identity], |inbox| async move {
            let mut edge = Edge::new(inbox, 42);
            let mut origin = Origin::new(62);
            edge.establish().await?;
            synchronize_ok(&mut edge, &mut [&mut origin]).await?;
            send_forged(&mut edge, &origin, forge).await?;
            edge.expect_closed().await?;
            // The honest request still owns sequence zero after the reconnect.
            edge.establish().await?;
            synchronize_ok(&mut edge, &mut [&mut origin]).await?;
            request(&mut edge, &mut origin, &session_open(62, "carol")).await?;
            let mut events = Vec::new();
            let result = answer(&mut edge, &mut events).await?;
            assert_eq!(
                result.header.result_kind,
                FederationResultKind::SessionRegistered
            );
            Ok(())
        })
        .await?;
    }
    Ok(())
}
