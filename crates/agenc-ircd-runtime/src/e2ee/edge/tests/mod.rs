#![forbid(unsafe_code)]

//! Edge router facts that need no live link: the operation sequence across
//! declarations and the resend order after a resume.

use std::collections::BTreeMap;

use agenc_ircd_e2ee::wire::command::ClientCommand;
use agenc_ircd_types::ServerId;

use super::router::Resolved;
use super::{E2eeEdge, E2eeEdgeConfig, LocalOrigin, PendingRequest};
use crate::connection::ConnectionGeneration;

fn edge() -> E2eeEdge {
    E2eeEdge::new(E2eeEdgeConfig {
        network_id: [1; 32],
        server_id: ServerId::from_bytes([2; 16]),
        server_name: "edge.example".to_owned(),
        coordinator_server_id: ServerId::from_bytes([3; 16]),
        incarnation: [4; 16],
        global_disk_bytes: 1 << 20,
    })
}

fn origin(origin_id: [u8; 16], declared: u64, sequence: u64) -> LocalOrigin {
    LocalOrigin {
        origin_id,
        declared: Some(declared),
        acked: None,
        next_sequence: sequence,
        sequenced: Some(declared),
        state_id: [0; 32],
        user_id: None,
        account: None,
        device: None,
    }
}

fn pending(generation: u64, sequence: u64, answered: bool) -> PendingRequest {
    PendingRequest {
        generation: ConnectionGeneration::new(generation),
        label: None,
        command: Resolved::Command(ClientCommand::Edirect([9; 32])),
        request_object_id: [7; 32],
        sequence,
        frames: Vec::new(),
        result: answered.then(|| super::result::DecodedResult {
            request_object_id: [7; 32],
            kind: agenc_ircd_e2ee::objects::federation::IrcFederationResultKind::Failed,
            value: super::result::ResultValue::Failed {
                code: "E2EE_SYNCING".to_owned(),
                context: Vec::new(),
            },
            completion_event_id: None,
            snapshot_token: None,
            next_cursor: None,
            descriptors: Vec::new(),
        }),
        responses: BTreeMap::new(),
        completion_seen: false,
        rendered: false,
    }
}

/// A replayed declaration of the generation already in force keeps the
/// operation sequence the coordinator continues from its replay rows; a
/// new generation restarts it at zero (companion 12.5).
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn a_replayed_declaration_keeps_the_operation_sequence() -> TestResult {
    let mut edge = edge();
    let generation = ConnectionGeneration::new(1);
    edge.origins.insert(generation, origin([5; 16], 2, 9));
    edge.acknowledge_origin([5; 16], 2);
    let replayed = edge.origins.get(&generation).ok_or("origin")?;
    assert_eq!(replayed.acked, Some(2));
    assert_eq!(replayed.next_sequence, 9);
    if let Some(origin) = edge.origins.get_mut(&generation) {
        origin.declared = Some(3);
    }
    edge.acknowledge_origin([5; 16], 3);
    let advanced = edge.origins.get(&generation).ok_or("origin")?;
    assert_eq!(advanced.acked, Some(3));
    assert_eq!(advanced.next_sequence, 0);
    assert_eq!(advanced.sequenced, Some(3));
    // Another origin's acknowledgement leaves this one alone.
    edge.acknowledge_origin([6; 16], 3);
    assert_eq!(
        edge.origins.get(&generation).map(|origin| origin.acked),
        Some(Some(3))
    );
    Ok(())
}

/// After EORIGIN READY the edge resends only the requests that are still
/// unanswered, only for origins whose declaration is acknowledged, in
/// operation sequence order.
#[test]
fn unanswered_requests_are_resent_after_origin_ready() {
    let mut edge = edge();
    let acked = ConnectionGeneration::new(1);
    let silent = ConnectionGeneration::new(2);
    let mut ready = origin([5; 16], 2, 4);
    ready.acked = Some(2);
    edge.origins.insert(acked, ready);
    edge.origins.insert(silent, origin([6; 16], 1, 1));
    edge.pending.insert([3; 16], pending(1, 3, false));
    edge.pending.insert([1; 16], pending(1, 1, false));
    edge.pending.insert([2; 16], pending(1, 2, true));
    edge.pending.insert([4; 16], pending(2, 0, false));
    assert_eq!(edge.resend_order(), vec![[1; 16], [3; 16]]);
    edge.acknowledge_origin([6; 16], 1);
    assert_eq!(edge.resend_order(), vec![[4; 16], [1; 16], [3; 16]]);
}
