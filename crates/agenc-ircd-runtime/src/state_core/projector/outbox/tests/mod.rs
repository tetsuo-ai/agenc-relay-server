//! Overflow cannot replace an already committed combined gate with a snapshot.
#![forbid(unsafe_code)]

use super::*;
use crate::test_support::TestResult;
use agenc_ircd_federation_wire::FederationHash32;
use agenc_ircd_types::{EventId, NetworkId};
use std::collections::BTreeMap;

#[test]
fn overflow_under_an_existing_barrier_refuses_without_a_snapshot_fence() -> TestResult {
    let peer = ServerId::from_bytes([2; 16]);
    for barrier_open in [false, true] {
        let mut projector = FederationProjector::new(
            NetworkId::from_bytes([1; 32]),
            ServerId::from_bytes([1; 16]),
        );
        projector.set_outbox_budget(
            peer,
            OutboxBudget {
                objects: 2,
                bytes: 256,
                max_objects: 2,
                max_bytes: 1024,
                barrier_open,
                peer: FederationPeerRecord {
                    fenced_incarnations: Vec::new(),
                    server_incarnation: [3; 16],
                    recovery_epoch: [4; 16],
                    accepted_epochs: Vec::new(),
                    phase: PeerPhase::Ready,
                    projection_generation: 0,
                    next_delivery_sequence: 2,
                    cursor: None,
                    active_entry_count: 0,
                    active_entry_bytes: 0,
                    pending_generation: None,
                    snapshot_required: false,
                    cleanup_cursor: None,
                    quarantined: false,
                    client_resync_epoch: 0,
                },
            },
        );
        let event = OutboundEvent {
            target: peer,
            projection_generation: 0,
            delivery_sequence: 2,
            event_id: EventId::from_bytes([5; 16]),
            object_id: FederationHash32::from_bytes([6; 32]),
            encoded: vec![0; 128],
            combined_barrier: None,
        };
        let mut output = ProjectedOutput {
            writes: Vec::new(),
            events: Vec::new(),
            advances: BTreeMap::new(),
            revision: 3,
            state_generation: 3,
            fences: Vec::new(),
        };
        let result = projector.fit_outbox(
            peer,
            EdgeDelivery {
                projection_generation: 0,
                next_delivery_sequence: 2,
            },
            &[event],
            None,
            &mut output,
        );
        if barrier_open {
            assert!(matches!(result, Err(RuntimeError::LimitExceeded)));
            assert!(output.writes.is_empty());
            assert!(output.fences.is_empty());
        } else {
            assert!(!result?);
            assert_eq!(output.writes.len(), 1);
            assert_eq!(output.fences, vec![peer]);
        }
    }
    Ok(())
}
