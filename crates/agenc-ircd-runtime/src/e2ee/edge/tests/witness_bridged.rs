#![forbid(unsafe_code)]

//! The real coordinator publication side answers the real blocked edge
//! (companion 12.5.1): every line crosses the bridge as rendered text.

use agenc_ircd_domain::e2ee::sequencer_log::{Head, Phase as LogPhase, SequencerLog};
use agenc_ircd_types::{EntropyError, EntropySource};

use super::*;
use crate::e2ee::coordinator::sync::Action;
use crate::e2ee::coordinator::tests::sync::FakeHost;
use crate::e2ee::coordinator::{CompanionCoordinator, ConversationState};
use crate::federation::LinkId;
use crate::federation::link::{ParsedLine, parse_line};

const COORDINATOR_NAME: &str = "coordinator.example";
const EDGE_NAME: &str = "edge.example";

/// Deterministic token bytes.
struct Tokens(u8);

impl EntropySource for Tokens {
    fn fill_exact(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        self.0 = self.0.wrapping_add(1);
        destination.fill(self.0);
        Ok(())
    }
}

/// The coordinator whose retained chain for `CONVERSATION` is `records`,
/// with the edge entitled and its link active.
fn coordinator(records: &[Record], first: u64) -> TestResult<CompanionCoordinator> {
    let mut coordinator = CompanionCoordinator::new(
        [1; 32],
        ServerId::from_bytes(COORDINATOR),
        COORDINATOR_NAME.to_owned(),
    );
    let mut conversation = ConversationState::default();
    let mut sequence = first;
    for record in records {
        conversation.records.insert(sequence, record.object_id);
        coordinator
            .state
            .objects
            .insert(record.object_id, record.bytes.clone());
        sequence += 1;
    }
    let last = records.last().ok_or("a retained chain")?;
    coordinator.state.logs.insert(
        CONVERSATION,
        SequencerLog::restore(
            CONVERSATION,
            Head {
                sequence: sequence - 1,
                record_id: last.semantic_id,
                recorded: true,
            },
            [58; 32],
            0,
            LogPhase::Open,
        ),
    );
    coordinator
        .state
        .conversations
        .insert(CONVERSATION, conversation);
    let edge = ServerId::from_bytes(EDGE);
    coordinator
        .state
        .entitlements
        .set_channel(edge, CONVERSATION, true);
    let sync = coordinator.peers.entry(edge).or_default();
    sync.active = true;
    Ok(coordinator)
}

fn parsed(text: &str, sender: &str) -> TestResult<CompanionFrame> {
    match parse_line(text.trim_end_matches("\r\n"), sender).map_err(|error| format!("{error:?}"))? {
        ParsedLine::Companion(frame) => Ok(frame),
        ParsedLine::Base(_) => Err("expected a companion frame".into()),
    }
}

/// Hands one edge line to the coordinator and returns the frames it sends.
fn answered(
    coordinator: &mut CompanionCoordinator,
    tokens: &mut Tokens,
    edge_line: &str,
) -> TestResult<Vec<CompanionFrame>> {
    let actions = coordinator
        .on_frame(
            LinkId::new(1),
            ServerId::from_bytes(EDGE),
            parsed(edge_line, EDGE_NAME)?,
            1_000,
            &FakeHost::default(),
            tokens,
        )
        .map_err(|fault| format!("the coordinator closed the link: {fault:?}"))?;
    let mut frames = Vec::new();
    for action in &actions {
        if let Action::Send(lines) = action {
            for line in lines {
                frames.push(parsed(line.as_str(), COORDINATOR_NAME)?);
            }
        }
    }
    Ok(frames)
}

#[tokio::test]
async fn a_skip_resolves_through_the_coordinator_and_the_link_stays_up() -> TestResult {
    let (mut fixture, mut queue, request) = Box::pin(requesting_line()).await?;
    let records = continuation()?;
    let head = records.last().ok_or("records")?.semantic_id;
    let mut coordinator = coordinator(&records, EXPECTED)?;
    let mut tokens = Tokens(0);
    let frames = answered(&mut coordinator, &mut tokens, &request)?;
    assert!(matches!(
        frames.last(),
        Some(CompanionFrame::WitnessEnd {
            record_count: 2,
            ..
        })
    ));
    feed(&mut fixture, frames)?;
    fixture.core.commit_staged_batch().await?;
    assert!(
        fixture
            .companion
            .batch_applied(fixture.core.context_mut()?, &mut fixture.base)
            .is_empty()
    );
    let resolved = next_line(&mut queue).await?;
    assert!(resolved.contains(" EWITNESS RESOLVED "));
    // The coordinator accepts the installation, a repeat is idempotent, and
    // the origin replay that follows is answered on the same link.
    assert!(answered(&mut coordinator, &mut tokens, &resolved)?.is_empty());
    assert!(answered(&mut coordinator, &mut tokens, &resolved)?.is_empty());
    let reset = next_line(&mut queue).await?;
    assert!(reset.contains(" EORIGIN RESET "));
    answered(&mut coordinator, &mut tokens, &reset)?;
    assert_eq!(fixture.companion.phase, Phase::Origins);
    assert!(!fixture.companion.blocked_conversation(&CONVERSATION));
    assert!(!stored_witness(&mut fixture)?);
    assert_eq!(
        fixture
            .companion
            .conversations
            .get(&CONVERSATION)
            .map(|route| (route.head.sequence, route.head.record_id)),
        Some((EXPECTED + 1, head))
    );
    Ok(())
}

#[tokio::test]
async fn a_fork_becomes_a_conflict_confined_to_its_conversation() -> TestResult {
    let (mut fixture, mut queue, request) = Box::pin(requesting_line()).await?;
    // The coordinator's record at the expected position names another head.
    let forked = record(EXPECTED, [99; 32], credential_id()?)?;
    let later = record(EXPECTED + 1, forked.semantic_id, credential_id()?)?;
    let mut coordinator = coordinator(&[forked, later], EXPECTED)?;
    let mut tokens = Tokens(0);
    let frames = answered(&mut coordinator, &mut tokens, &request)?;
    // Only the forking record is delivered.
    assert!(matches!(
        frames.last(),
        Some(CompanionFrame::WitnessEnd {
            record_count: 1,
            ..
        })
    ));
    feed(&mut fixture, frames)?;
    fixture.core.commit_staged_batch().await?;
    assert!(
        fixture
            .companion
            .batch_applied(fixture.core.context_mut()?, &mut fixture.base)
            .is_empty()
    );
    let reset = next_line(&mut queue).await?;
    assert!(reset.contains(" EORIGIN RESET "));
    answered(&mut coordinator, &mut tokens, &reset)?;
    assert_eq!(fixture.companion.phase, Phase::Origins);
    assert!(stored_witness(&mut fixture)?);
    assert!(fixture.companion.blocked_conversation(&CONVERSATION));
    assert!(!fixture.companion.blocked_conversation(&[10; 32]));
    assert_eq!(
        fixture
            .companion
            .conversations
            .get(&CONVERSATION)
            .map(|route| route.head.sequence),
        Some(EXPECTED - 1)
    );
    // A later request on the same link is still answered, never refused.
    let again = answered(
        &mut coordinator,
        &mut tokens,
        &format!(
            ":{EDGE_NAME} EWITNESS REQUEST {} {} 0 {}",
            agenc_ircd_e2ee::wire::tokens::base64url_encode(&COORDINATOR),
            agenc_ircd_e2ee::wire::tokens::base64url_encode(&[10; 32]),
            agenc_ircd_e2ee::wire::tokens::base64url_encode(&[11; 32]),
        ),
    )?;
    assert!(matches!(
        again.last(),
        Some(CompanionFrame::WitnessEnd {
            record_count: 0,
            ..
        })
    ));
    Ok(())
}

/// A finalized event at `route_sequence` the edge has not acknowledged.
fn unacknowledged_event(
    route_sequence: u64,
) -> TestResult<crate::e2ee::coordinator::events::StreamRow> {
    use agenc_ircd_e2ee::objects::federation::{IrcFederationEvent, IrcFederationEventKind};
    let event = IrcFederationEvent {
        profile_version: 1,
        network_id: [1; 32],
        target_server_id: EDGE,
        delivery_generation: 2,
        coordinator_state_generation: 1,
        delivery_sequence: 7,
        event_id: [8; 16],
        event_kind: IrcFederationEventKind::FinalizedEvent,
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
        encoded_event_result: Opaque::new(vec![0; 72])?,
    };
    let bytes =
        IrcWireObject::new(IrcWireObjectKind::FederationEvent, event.encode()?)?.encode()?;
    Ok(crate::e2ee::coordinator::events::StreamRow {
        sequence: 7,
        event_id: [8; 16],
        event: crate::e2ee::coordinator::events::SharedBytes::for_fixture(bytes)?,
        payload: None,
        acknowledgement:
            agenc_ircd_storage::e2ee_records::delivery_recovery::Acknowledgement::Unacknowledged,
    })
}

#[tokio::test]
async fn the_answer_stops_before_the_event_the_edge_will_receive_again() -> TestResult {
    let (_fixture, _queue, request) = Box::pin(requesting_line()).await?;
    let mut records = continuation()?;
    let second = records.last().ok_or("records")?.semantic_id;
    records.push(record(EXPECTED + 2, second, credential_id()?)?);
    let mut coordinator = coordinator(&records, EXPECTED)?;
    // The edge refused the event of the third record; it is retransmitted
    // after the resolution and must still extend the installed head.
    coordinator
        .state
        .streams
        .entry(ServerId::from_bytes(EDGE))
        .or_default()
        .rows
        .push_back(unacknowledged_event(EXPECTED + 2)?);
    let frames = answered(&mut coordinator, &mut Tokens(0), &request)?;
    assert!(matches!(
        frames.last(),
        Some(CompanionFrame::WitnessEnd {
            record_count: 2,
            ..
        })
    ));
    Ok(())
}
