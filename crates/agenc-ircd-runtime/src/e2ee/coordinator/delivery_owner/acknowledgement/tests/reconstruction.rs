//! A reduced ACK candidate reconstructs its Owner before any stream mutation.
#![forbid(unsafe_code)]

use super::*;
use crate::test_support::TestResult;
use agenc_ircd_storage::e2ee_records::delivery_recovery::{SnapshotCut, SnapshotCutFields};
use agenc_ircd_types::{RecoveryEpoch, ServerIncarnation};

#[test]
fn a_mismatched_proposed_generation_fails_before_touching_the_stream() -> TestResult {
    let peer = ServerId::from_bytes([2; 16]);
    let mut coordinator = CompanionCoordinator::new(
        [1; 32],
        ServerId::from_bytes([1; 16]),
        "coordinator.example".into(),
    );
    coordinator.configure_delivery_identity(
        ServerIncarnation::from_bytes([3; 16]),
        RecoveryEpoch::from_bytes([4; 16]),
    )?;
    let scope = coordinator.delivery_scope(peer, [5; 16], 0)?;
    let cursor = DeliveryCursor::new(0, 0, LastAcknowledged::BeforeFirst)?;
    let cut = SnapshotCut::new(SnapshotCutFields {
        token: [6; 32],
        state_generation: 1,
        delivery_generation: 0,
        entry_count: 0,
        digest: [7; 32],
        page_count: 1,
        total_object_bytes: 0,
    })?;
    let expected = DeliveryOwner::new(scope, cursor, cut, CutPhase::Ready)?;
    let before = DeliveryStream {
        owner: Some(expected.clone()),
        ..DeliveryStream::default()
    };
    let backing = crate::budget::BackingReservationPort::new(std::sync::Arc::new(
        crate::budget::MemoryBudget::new(1_024),
    ));
    coordinator
        .state
        .streams
        .insert(peer, before.try_clone(0, &backing)?);
    let proposal = super::super::retention::Proposal {
        owner: agenc_ircd_storage::e2ee_records::delivery_recovery::outbox::replay::ReplayOwner::new(
            agenc_ircd_storage::e2ee_records::delivery_recovery::outbox::replay::ReplayOwnerFields {
                scope, generation: 1,
                through: 0, event_id: [8; 16], first_retained: 1, retained_rows: 0,
                retained_bytes: 0, trusted_unix_seconds: None,
            },
        )?,
        range: None,
        head: None,
    };
    let candidate = PreparedAck {
        replay: Box::new(Update::new(&before, &proposal)),
        resume: false,
        peer,
        link: LinkId::new(1),
        position: DeliveryPosition {
            server_id: [1; 16],
            delivery_generation: 0,
            delivery_sequence: 0,
            event_id: [8; 16],
        },
        expected,
        proposed: DeliveryCursor::new(
            1,
            1,
            LastAcknowledged::At {
                sequence: 0,
                event_id: [8; 16],
            },
        )?,
        acknowledgement: Acknowledgement::AcknowledgedTimeUnknown,
    };
    assert_eq!(
        candidate.apply(&mut coordinator),
        Err(CompanionFault::Storage)
    );
    assert_eq!(coordinator.state.streams.get(&peer), Some(&before));
    Ok(())
}
