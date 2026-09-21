#![forbid(unsafe_code)]

//! Hello tuple verification and recovery-epoch transition classification.

use agenc_relay_types::{FederationRole, NetworkId, RecoveryEpoch, ServerId, ServerIncarnation};

use super::*;

fn expectation() -> HelloExpectation {
    HelloExpectation {
        local_role: FederationRole::Coordinator,
        network_id: NetworkId::from_bytes([1; 32]),
        local_server_id: ServerId::from_bytes([3; 16]),
        peer_server_id: ServerId::from_bytes([2; 16]),
        pinned_recovery_epoch: RecoveryEpoch::from_bytes([5; 16]),
        tls_exporter: [7; 32],
        profile_hash: [8; 32],
    }
}

fn matching_tbs() -> HelloTbs {
    HelloTbs {
        network_id: NetworkId::from_bytes([1; 32]),
        sender_server_id: ServerId::from_bytes([2; 16]),
        expected_peer_server_id: ServerId::from_bytes([3; 16]),
        server_incarnation: ServerIncarnation::from_bytes([4; 16]),
        recovery_epoch: RecoveryEpoch::from_bytes([5; 16]),
        role: FederationRole::Edge,
        hello_nonce: [6; 32],
        profile_hash: [8; 32],
        tls_exporter: [7; 32],
    }
}

#[test]
fn matching_tuple_is_accepted_for_both_roles() {
    assert_eq!(
        verify_hello_tuple(&matching_tbs(), &expectation(), true),
        Ok(())
    );
    let edge_side = HelloExpectation {
        local_role: FederationRole::Edge,
        ..expectation()
    };
    let coordinator_hello = HelloTbs {
        role: FederationRole::Coordinator,
        ..matching_tbs()
    };
    assert_eq!(
        verify_hello_tuple(&coordinator_hello, &edge_side, true),
        Ok(())
    );
}

#[test]
fn every_tuple_field_is_checked_in_order() {
    let cases: [(HelloTbs, bool, HelloRejection); 8] = [
        (
            HelloTbs {
                role: FederationRole::Coordinator,
                ..matching_tbs()
            },
            true,
            HelloRejection::Role,
        ),
        (
            HelloTbs {
                network_id: NetworkId::from_bytes([9; 32]),
                ..matching_tbs()
            },
            true,
            HelloRejection::Network,
        ),
        (
            HelloTbs {
                sender_server_id: ServerId::from_bytes([9; 16]),
                ..matching_tbs()
            },
            true,
            HelloRejection::SenderId,
        ),
        (
            HelloTbs {
                expected_peer_server_id: ServerId::from_bytes([9; 16]),
                ..matching_tbs()
            },
            true,
            HelloRejection::ExpectedPeerId,
        ),
        (
            HelloTbs {
                recovery_epoch: RecoveryEpoch::from_bytes([9; 16]),
                ..matching_tbs()
            },
            true,
            HelloRejection::RecoveryEpochPin,
        ),
        (matching_tbs(), false, HelloRejection::NonceReuse),
        (
            HelloTbs {
                tls_exporter: [9; 32],
                ..matching_tbs()
            },
            true,
            HelloRejection::Exporter,
        ),
        (
            HelloTbs {
                profile_hash: [9; 32],
                ..matching_tbs()
            },
            true,
            HelloRejection::ProfileHash,
        ),
    ];
    for (tbs, fresh, expected) in cases {
        assert_eq!(
            verify_hello_tuple(&tbs, &expectation(), fresh),
            Err(expected)
        );
        assert!(!expected.to_string().is_empty());
    }
}

#[test]
fn epoch_transitions_distinguish_initial_continuing_new_and_fatal() {
    let epoch = RecoveryEpoch::from_bytes([5; 16]);
    let newer = RecoveryEpoch::from_bytes([6; 16]);
    let old_incarnation = ServerIncarnation::from_bytes([4; 16]);
    let new_incarnation = ServerIncarnation::from_bytes([7; 16]);
    let none = PeerContinuity {
        last_accepted: None,
    };
    let continuity = PeerContinuity {
        last_accepted: Some((epoch, old_incarnation)),
    };
    assert_eq!(
        classify_epoch_transition(epoch, old_incarnation, none, &[]),
        Ok(EpochTransition::Initial)
    );
    assert_eq!(
        classify_epoch_transition(epoch, new_incarnation, continuity, &[epoch]),
        Ok(EpochTransition::Continuing)
    );
    assert_eq!(
        classify_epoch_transition(newer, new_incarnation, continuity, &[epoch]),
        Ok(EpochTransition::NewEpoch)
    );
    assert_eq!(
        classify_epoch_transition(newer, old_incarnation, continuity, &[epoch]),
        Err(EpochRejection::SameIncarnationEpochChange)
    );
    assert_eq!(
        classify_epoch_transition(newer, new_incarnation, continuity, &[epoch, newer]),
        Err(EpochRejection::ReusedEpoch)
    );
    assert!(!EpochRejection::ReusedEpoch.to_string().is_empty());
    assert!(
        !EpochRejection::SameIncarnationEpochChange
            .to_string()
            .is_empty()
    );
}
