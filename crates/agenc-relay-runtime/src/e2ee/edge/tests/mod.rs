#![forbid(unsafe_code)]

//! Edge router facts that need no live link: the operation sequence across
//! declarations and the resend order after a resume.

use std::collections::BTreeMap;

use agenc_relay_e2ee::wire::command::ClientCommand;
use agenc_relay_types::ServerId;

use super::events::{ChainHead, Conversation};
use super::router::Resolved;
use super::{E2eeEdge, E2eeEdgeConfig, LocalOrigin, PendingRequest, Phase};
use crate::connection::ConnectionGeneration;

mod event_faults;
mod ingress;
mod projection;
mod responses;
mod retry;
mod scope;
mod snapshot;

/// The private key behind the single credential of the test key set.
pub(super) const SEQUENCER_SEED: [u8; 32] = [60; 32];

/// The verified sequencer key set the test edge negotiated: one credential
/// whose private key signs the records a witness resolution delivers.
pub(super) fn sequencer_key_set() -> Option<agenc_relay_e2ee::sequencer::SequencerKeySet> {
    use agenc_relay_e2ee::objects::conversation::{
        ArcSequencerCredential, ArcSequencerCredentialTbs,
    };
    let secret = agenc_relay_crypto::Ed25519SecretKey::from_bytes(SEQUENCER_SEED);
    let credential = ArcSequencerCredential {
        tbs: ArcSequencerCredentialTbs {
            profile_version: 1,
            network_id: [1; 32],
            key_generation: 0,
            sequencer_public_key: *secret.public_key().as_bytes(),
            not_before: 0,
            not_after: u64::MAX,
            previous_key_id: [0; 32],
        },
        continuity_signature: agenc_relay_e2ee::tls::Opaque::new(Vec::new()).ok()?,
    };
    agenc_relay_e2ee::sequencer::SequencerKeySet::verify(
        &[1; 32],
        std::slice::from_ref(&credential),
        0,
        None,
    )
    .ok()
}

/// The private key behind the overlapping successor of the rotating set.
pub(super) const SUCCESSOR_SEED: [u8; 32] = [61; 32];
/// The second the successor's overlap window opens.
pub(super) const SUCCESSOR_OPENS: u64 = 500_000;

/// The test key set during a rotation: the same active credential and its
/// direct successor, whose overlap window opens at [`SUCCESSOR_OPENS`]
/// (companion 9.2, 12.5.1).
pub(super) fn rotating_key_set() -> Option<agenc_relay_e2ee::sequencer::SequencerKeySet> {
    use agenc_relay_e2ee::objects::conversation::{
        ArcSequencerCredential, ArcSequencerCredentialTbs,
    };
    use agenc_relay_e2ee::tls::{Opaque, TlsEncode};
    let active_secret = agenc_relay_crypto::Ed25519SecretKey::from_bytes(SEQUENCER_SEED);
    let active = ArcSequencerCredential {
        tbs: ArcSequencerCredentialTbs {
            profile_version: 1,
            network_id: [1; 32],
            key_generation: 0,
            sequencer_public_key: *active_secret.public_key().as_bytes(),
            not_before: 0,
            not_after: u64::MAX,
            previous_key_id: [0; 32],
        },
        continuity_signature: Opaque::new(Vec::new()).ok()?,
    };
    let previous_key_id = sequencer_key_set()?.current()?.credential_id;
    let successor_secret = agenc_relay_crypto::Ed25519SecretKey::from_bytes(SUCCESSOR_SEED);
    let tbs = ArcSequencerCredentialTbs {
        profile_version: 1,
        network_id: [1; 32],
        key_generation: 1,
        sequencer_public_key: *successor_secret.public_key().as_bytes(),
        not_before: SUCCESSOR_OPENS,
        not_after: u64::MAX,
        previous_key_id,
    };
    let continuity = agenc_relay_crypto::sign_canonical(
        &active_secret,
        agenc_relay_crypto::SignatureDomain::SequencerContinuity,
        &tbs.encode().ok()?,
    )
    .ok()?;
    let successor = ArcSequencerCredential {
        tbs,
        continuity_signature: Opaque::new(continuity.as_bytes().to_vec()).ok()?,
    };
    agenc_relay_e2ee::sequencer::SequencerKeySet::verify(&[1; 32], &[active, successor], 1, None)
        .ok()
}

fn edge() -> E2eeEdge {
    E2eeEdge::new(E2eeEdgeConfig {
        network_id: [1; 32],
        server_id: ServerId::from_bytes([2; 16]),
        server_name: "edge.example".to_owned(),
        coordinator_server_id: ServerId::from_bytes([3; 16]),
        sequencer_key_set: sequencer_key_set(),
        incarnation: [4; 16],
        global_disk_bytes: 1 << 20,
    })
}

fn origin(origin_id: [u8; 16], declared: u64, sequence: u64) -> LocalOrigin {
    LocalOrigin {
        origin_id,
        declared: Some(declared),
        acked: None,
        predates_device: None,
        next_sequence: sequence,
        sequenced: Some(declared),
        state_id: [0; 32],
        declaration: None,
        user_id: None,
        account: None,
        device: None,
    }
}

fn pending(generation: u64, sequence: u64, answered: bool) -> PendingRequest {
    PendingRequest {
        reply_key: None,
        echo_lines: Vec::new(),
        retry_label: None,
        generation: ConnectionGeneration::new(generation),
        label: None,
        command: Resolved::Command(ClientCommand::Edirect([9; 32])),
        subject: None,
        request_object_id: [7; 32],
        sequence,
        frames: Vec::new(),
        result_object_id: None,
        result: answered.then(|| super::result::DecodedResult {
            request_object_id: [7; 32],
            kind: agenc_relay_e2ee::objects::federation::ArcFederationResultKind::Failed,
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

mod witness {
    //! The record-chain witness (companion 12.5) on synthetic events.

    use agenc_relay_e2ee::objects::federation::{ArcFederationEvent, ArcFederationEventKind};
    use agenc_relay_e2ee::objects::sequencing::{ArcCandidateReceipt, ArcCandidateReceiptTbs};
    use agenc_relay_e2ee::tls::{Opaque, TlsEncode};
    use agenc_relay_storage::e2ee_records::WitnessRow;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const CONVERSATION: [u8; 32] = [9; 32];
    const ANCHOR: [u8; 32] = [10; 32];

    fn event(
        kind: ArcFederationEventKind,
        route_sequence: u64,
        result: Vec<u8>,
    ) -> Result<ArcFederationEvent, agenc_relay_e2ee::E2eeError> {
        Ok(ArcFederationEvent {
            profile_version: 1,
            network_id: [1; 32],
            target_server_id: [2; 16],
            delivery_generation: 1,
            coordinator_state_generation: 1,
            delivery_sequence: 1,
            event_id: [5; 16],
            event_kind: kind,
            cross_profile_mutation_id: Opaque::new(Vec::new())?,
            cross_profile_part_index: 0,
            cross_profile_part_count: 0,
            conversation_id: Opaque::new(CONVERSATION.to_vec())?,
            route_sequence,
            origin_id: Opaque::new(Vec::new())?,
            origin_generation: 0,
            source_view: Opaque::new(Vec::new())?,
            request_home_server_id: Opaque::new(Vec::new())?,
            request_server_incarnation: Opaque::new(Vec::new())?,
            request_origin_id: Opaque::new(Vec::new())?,
            request_origin_generation: 0,
            request_operation_sequence: 0,
            request_id: Opaque::new(Vec::new())?,
            payload_object_id: Opaque::new(Vec::new())?,
            encoded_event_result: Opaque::new(result)?,
        })
    }

    fn receipt(
        route_sequence: u64,
        predecessor: [u8; 32],
    ) -> Result<(Vec<u8>, [u8; 32]), agenc_relay_e2ee::E2eeError> {
        let tbs = ArcCandidateReceiptTbs {
            profile_version: 1,
            network_id: [1; 32],
            conversation_id: CONVERSATION,
            route_sequence,
            prior_epoch: 0,
            resulting_epoch: 1,
            candidate_sequence: 0,
            commit_object_id: [3; 32],
            prior_state_id: ANCHOR,
            predecessor_record_id: predecessor,
            sequenced_at: 0,
            sequencer_key_id: [4; 32],
        };
        let candidate_id = agenc_relay_e2ee::ids::semantic_id_of(
            agenc_relay_crypto::SemanticHashDomain::CandidateId,
            &tbs,
        )?;
        let receipt = ArcCandidateReceipt {
            tbs,
            sequencer_signature: [6; 64],
        };
        Ok((receipt.encode()?, candidate_id))
    }

    fn witnessing_edge(head: ChainHead) -> E2eeEdge {
        let mut edge = edge();
        edge.conversations.insert(
            CONVERSATION,
            Conversation {
                channel: None,
                direct: None,
                head,
            },
        );
        edge
    }

    fn witness_ok(edge: &mut E2eeEdge, event: &ArcFederationEvent) -> TestResult {
        edge.witness(event)
            .map_err(|refusal| refusal.code.to_string().into())
    }

    fn head_of(edge: &E2eeEdge) -> Option<ChainHead> {
        edge.conversations
            .get(&CONVERSATION)
            .map(|known| known.head)
    }

    fn violation(edge: &mut E2eeEdge) -> Option<WitnessRow> {
        edge.witnessed.take().map(|(_, row)| row)
    }

    #[test]
    fn a_chain_that_extends_advances_the_head_from_the_anchor() -> TestResult {
        let mut edge = witnessing_edge(ChainHead {
            sequence: 0,
            record_id: ANCHOR,
            recorded: false,
        });
        // The first candidate takes sequence zero and names the anchor.
        let (encoded, candidate_id) = receipt(0, ANCHOR)?;
        witness_ok(
            &mut edge,
            &event(ArcFederationEventKind::CandidateEvent, 0, encoded)?,
        )?;
        assert_eq!(
            head_of(&edge),
            Some(ChainHead {
                sequence: 0,
                record_id: candidate_id,
                recorded: true,
            })
        );
        // Its finalization follows at one, and becomes the head.
        let finalization = [11; 32];
        let mut finalized = 1_u64.to_be_bytes().to_vec();
        finalized.extend_from_slice(&finalization);
        finalized.extend_from_slice(&[12; 32]);
        witness_ok(
            &mut edge,
            &event(ArcFederationEventKind::FinalizedEvent, 1, finalized)?,
        )?;
        assert_eq!(
            head_of(&edge).map(|head| head.record_id),
            Some(finalization)
        );
        // The next candidate names the finalization at two; a close occupies
        // the next position and becomes the tombstone head.
        let (encoded, candidate_id) = receipt(2, finalization)?;
        witness_ok(
            &mut edge,
            &event(ArcFederationEventKind::CandidateEvent, 2, encoded)?,
        )?;
        // The tombstone cut arrives before the close event; the event then
        // names the installed head again and leaves it.
        edge.conversations
            .get_mut(&CONVERSATION)
            .ok_or("conversation")?
            .head = ChainHead {
            sequence: 3,
            record_id: [13; 32],
            recorded: true,
        };
        witness_ok(
            &mut edge,
            &event(ArcFederationEventKind::ClosedEvent, 3, [13; 32].to_vec())?,
        )?;
        assert_eq!(head_of(&edge).map(|head| head.record_id), Some([13; 32]));
        let _ = candidate_id;
        assert!(violation(&mut edge).is_none());
        Ok(())
    }

    #[test]
    fn a_fork_or_a_skipped_position_is_refused_and_recorded() -> TestResult {
        let recorded = ChainHead {
            sequence: 4,
            record_id: [20; 32],
            recorded: true,
        };
        // A candidate that names another predecessor at the right sequence.
        let mut edge = witnessing_edge(recorded);
        let (forked, candidate_id) = receipt(5, [21; 32])?;
        assert!(
            edge.witness(&event(ArcFederationEventKind::CandidateEvent, 5, forked)?)
                .is_err()
        );
        let row = violation(&mut edge).ok_or("a witness row")?;
        assert_eq!(row.expected_sequence, 5);
        assert_eq!(row.expected_head_id, [20; 32]);
        assert_eq!(row.observed_id, candidate_id);
        assert_eq!(row.observed_predecessor_id, Some([21; 32]));
        assert_eq!(head_of(&edge), Some(recorded));
        // A terminal that skips a position.
        let mut edge = witnessing_edge(recorded);
        let aborted = [[30; 32], [31; 32], [32; 32]].concat();
        assert!(
            edge.witness(&event(ArcFederationEventKind::AbortedEvent, 6, aborted)?)
                .is_err()
        );
        let row = violation(&mut edge).ok_or("a witness row")?;
        assert_eq!((row.expected_sequence, row.observed_sequence), (5, 6));
        assert_eq!(row.observed_id, [31; 32]);
        // Events that never move the head pass through.
        let mut edge = witnessing_edge(recorded);
        witness_ok(
            &mut edge,
            &event(ArcFederationEventKind::CommitAckEvent, 9, [40; 32].to_vec())?,
        )?;
        assert_eq!(head_of(&edge), Some(recorded));
        assert!(violation(&mut edge).is_none());
        Ok(())
    }

    #[test]
    fn a_route_state_cut_may_only_move_the_head_forward() {
        let recorded = ChainHead {
            sequence: 4,
            record_id: [20; 32],
            recorded: true,
        };
        let same = ChainHead {
            sequence: 4,
            record_id: [20; 32],
            recorded: true,
        };
        let forked = ChainHead {
            sequence: 4,
            record_id: [21; 32],
            recorded: true,
        };
        let older = ChainHead {
            sequence: 3,
            record_id: [19; 32],
            recorded: true,
        };
        let newer = ChainHead {
            sequence: 7,
            record_id: [27; 32],
            recorded: true,
        };
        assert!(recorded.accepts_cut(same));
        assert!(recorded.accepts_cut(newer));
        assert!(!recorded.accepts_cut(forked));
        assert!(!recorded.accepts_cut(older));
        let anchor = ChainHead {
            sequence: 0,
            record_id: ANCHOR,
            recorded: false,
        };
        assert!(anchor.accepts_cut(older));
        assert_eq!(anchor.next_sequence(), 0);
        assert_eq!(recorded.next_sequence(), 5);
    }
}
