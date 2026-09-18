#![forbid(unsafe_code)]

//! Edge barriers and snapshots must preserve witness and projection boundaries.

use agenc_ircd_domain::e2ee::ConversationId;
use agenc_ircd_e2ee::federation::frames::DeliveryPosition;
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::conversation::IrcConversationKind;
use agenc_ircd_e2ee::objects::federation::{
    IrcFederationEvent, IrcFederationEventKind, IrcFederationRouteState, IrcRouteStateKind,
};
use agenc_ircd_e2ee::tls::{Opaque, TlsEncode};
use agenc_ircd_storage::e2ee_records::DeliveryRow;
use agenc_ircd_storage::{PersistentRecordValue, TableId};
use agenc_ircd_types::{
    ChannelInstanceId, FederationRole, NetworkId, RecoveryEpoch, ServerIncarnation,
};

use super::*;
use crate::e2ee::edge::events::OpenEvent;
use crate::federation::PeerIdentity;
use crate::federation::edge::{EdgeConfig, EdgeFederation};
use crate::state_core::durable::AccountServiceDurableWrite;
use crate::test_support::StateCoreFixture;

pub(super) const CONVERSATION: [u8; 32] = [9; 32];
pub(super) const CHANNEL: ChannelInstanceId = ChannelInstanceId::from_bytes([8; 16]);
const MUTATION: [u8; 16] = [7; 16];

mod rollback;

#[test]
fn a_result_arriving_during_completion_staging_is_released_at_commit() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let mut edge = edge();
    let mut open = part(IrcFederationEventKind::RequestCompleted, 0)?;
    open.event.request_home_server_id = Opaque::new(vec![2; 16])?;
    open.event.request_server_incarnation = Opaque::new(vec![4; 16])?;
    open.event.request_id = Opaque::new(vec![5; 16])?;
    let mut request = pending(1, 0, false);
    let key = (1, 0, [9; 32], [7; 32]);
    request.reply_key = Some(key);
    let command = request.command.clone();
    edge.pending.insert([5; 16], request);
    let (prepared, before) = edge
        .prepare_completion(fixture.context_mut()?, &open.event)
        .map_err(|e| e.code.to_string())?;
    assert!(before.is_empty());
    assert!(!edge.covered.contains(&open.position.event_id));
    let mut result = pending(1, 0, true).result.ok_or("result")?;
    result.completion_event_id = Some(open.position.event_id);
    edge.pending.get_mut(&[5; 16]).ok_or("pending")?.result = Some(result);
    edge.by_completion.insert(open.position.event_id, [5; 16]);
    assert!(
        edge.render_ready(fixture.context_mut()?, [5; 16])
            .map_err(|e| e.code.to_string())?
            .is_empty()
    );
    let committed = edge.commit_completion(fixture.context_mut()?, prepared);
    assert_eq!(committed.len(), 1);
    assert!(!edge.pending.contains_key(&[5; 16]));
    assert!(
        edge.replies
            .replay(key, &command, None)
            .map_err(|e| e.code.to_string())?
            .is_some()
    );
    Ok(())
}

#[tokio::test]
async fn refused_storage_does_not_complete_or_cache_a_request() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let mut edge = edge();
    edge.delivery.generation = 2;
    edge.delivery.cursor = Some((6, [12; 16]));
    let mut open = part(IrcFederationEventKind::RequestCompleted, 0)?;
    open.event.cross_profile_mutation_id = Opaque::new(Vec::new())?;
    open.event.cross_profile_part_index = 0;
    open.event.cross_profile_part_count = 0;
    open.event.request_home_server_id = Opaque::new(vec![2; 16])?;
    open.event.request_server_incarnation = Opaque::new(vec![4; 16])?;
    open.event.request_id = Opaque::new(vec![5; 16])?;
    let mut request = pending(1, 0, true);
    let key = (1, 0, [9; 32], [7; 32]);
    request.reply_key = Some(key);
    let command = request.command.clone();
    request.result.as_mut().ok_or("result")?.completion_event_id = Some(open.position.event_id);
    edge.pending.insert([5; 16], request);
    edge.by_completion.insert(open.position.event_id, [5; 16]);
    fixture
        .state_mut()?
        .step_message(crate::state_core::inbox::StateCoreMessage::Signal(
            crate::state_core::inbox::SignalEvent::Terminate,
        ));
    let bytes =
        IrcWireObject::new(IrcWireObjectKind::FederationEvent, open.event.encode()?)?.encode()?;
    let object_id = *agenc_ircd_e2ee::ObjectId::compute(&bytes).as_bytes();
    let mut refused = false;
    for fragment in agenc_ircd_e2ee::wire::fragment::fragment_object(&bytes)? {
        refused |= edge
            .on_event_frame(
                fixture.context_mut()?,
                &mut base_edge(),
                open.position,
                object_id,
                fragment,
                false,
            )
            .is_err();
    }
    assert!(refused);
    assert!(
        !edge
            .pending
            .get(&[5; 16])
            .ok_or("request remains pending")?
            .completion_seen
    );
    assert!(!edge.covered.contains(&open.position.event_id));
    assert!(
        edge.replies
            .replay(key, &command, None)
            .map_err(|e| e.code.to_string())?
            .is_none()
    );
    Ok(())
}

pub(super) fn base_edge() -> EdgeFederation {
    EdgeFederation::new(EdgeConfig {
        network_id: NetworkId::from_bytes([1; 32]),
        server_id: ServerId::from_bytes([2; 16]),
        server_name: "edge.example".to_owned(),
        incarnation: ServerIncarnation::from_bytes([4; 16]),
        coordinator: PeerIdentity::new(
            ServerId::from_bytes([3; 16]),
            "coordinator.example",
            FederationRole::Coordinator,
            RecoveryEpoch::from_bytes([5; 16]),
            agenc_ircd_crypto::Ed25519SecretKey::from_bytes([6; 32]).public_key(),
            [7; 32],
        ),
    })
}

pub(super) fn install_route(edge: &mut E2eeEdge) -> TestResult {
    let state = IrcFederationRouteState {
        profile_version: 1,
        network_id: [1; 32],
        state_generation: 4,
        conversation_id: CONVERSATION,
        conversation_kind: IrcConversationKind::Channel,
        route_binding: [26; 32],
        semantic_route_lock_id: [23; 32],
        channel_instance_id: Opaque::new(CHANNEL.as_bytes().to_vec())?,
        canonical_channel_name_hash: [116; 32],
        direct_account_a: Opaque::new(Vec::new())?,
        direct_account_b: Opaque::new(Vec::new())?,
        binding_id: [34; 32],
        finalized_epoch: 1,
        accepted_state_id: [58; 32],
        sequencer_record_head_sequence: 4,
        sequencer_record_head_id: [59; 32],
        state: IrcRouteStateKind::ActiveRoute,
    };
    let bytes =
        IrcWireObject::new(IrcWireObjectKind::FederationState, state.encode()?)?.encode()?;
    edge.route_changed(&bytes)
        .map_err(|refusal| refusal.code.to_string())?;
    Ok(())
}

fn part(kind: IrcFederationEventKind, route_sequence: u64) -> TestResult<OpenEvent> {
    let position = DeliveryPosition {
        server_id: [2; 16],
        delivery_generation: 2,
        delivery_sequence: 7,
        event_id: [11; 16],
    };
    Ok(OpenEvent {
        position,
        event: IrcFederationEvent {
            profile_version: 1,
            network_id: [1; 32],
            target_server_id: [2; 16],
            delivery_generation: position.delivery_generation,
            coordinator_state_generation: 5,
            delivery_sequence: position.delivery_sequence,
            event_id: position.event_id,
            event_kind: kind,
            cross_profile_mutation_id: Opaque::new(MUTATION.to_vec())?,
            cross_profile_part_index: 1,
            cross_profile_part_count: 2,
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
            encoded_event_result: Opaque::new([60; 32].to_vec())?,
        },
        payload_object_id: None,
    })
}

fn stage_part(edge: &mut E2eeEdge, part: OpenEvent) {
    edge.barrier_parts
        .insert(MUTATION, BTreeMap::from([(1, (part, None))]));
}

#[tokio::test]
async fn a_barrier_rejects_a_skipped_sequencer_record() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let mut edge = edge();
    install_route(&mut edge)?;
    let head = edge.conversations.get(&CONVERSATION).ok_or("route")?.head;
    stage_part(&mut edge, part(IrcFederationEventKind::ClosedEvent, 6)?);
    assert!(
        edge.prepare_barrier(fixture.context_mut()?, &base_edge(), MUTATION)
            .is_err()
    );
    assert_eq!(
        edge.conversations
            .get(&CONVERSATION)
            .map(|route| route.head),
        Some(head)
    );
    assert!(edge.witnessed.is_some());
    Ok(())
}

#[tokio::test]
async fn a_barrier_persists_the_final_companion_cursor_without_exposing_it_early() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let mut edge = edge();
    install_route(&mut edge)?;
    let open = part(IrcFederationEventKind::ClosedEvent, 5)?;
    let position = open.position;
    stage_part(&mut edge, open);
    let before = (edge.delivery.generation, edge.delivery.cursor);
    let (writes, _) = edge
        .prepare_barrier(fixture.context_mut()?, &base_edge(), MUTATION)
        .map_err(|code| code.to_string())?;
    let key = DeliveryRow::cursor_key(&[3; 16])?;
    let body = writes
        .iter()
        .find_map(|write| match write {
            AccountServiceDurableWrite::Put {
                table: TableId::E2eeState,
                key: found,
                plaintext,
            } if *found == key => Some(plaintext),
            _ => None,
        })
        .ok_or("barrier omitted its durable companion cursor")?;
    let value = PersistentRecordValue::decode(TableId::E2eeState, body)?;
    assert_eq!(
        DeliveryRow::decode(value.body())?,
        DeliveryRow::WitnessedCursor {
            generation: position.delivery_generation,
            next_sequence: position.delivery_sequence + 1,
            acked_sequence: position.delivery_sequence,
            acked_event_id: position.event_id,
            barrier_open: false,
        }
    );
    assert_eq!((edge.delivery.generation, edge.delivery.cursor), before);
    assert_eq!(
        edge.conversations
            .get(&CONVERSATION)
            .map(|route| route.head.sequence),
        Some(5)
    );
    Ok(())
}

#[tokio::test]
async fn a_hidden_route_is_removed_from_every_projection_index() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let mut edge = edge();
    install_route(&mut edge)?;
    stage_part(
        &mut edge,
        part(IrcFederationEventKind::RouteStateHidden, 4)?,
    );
    edge.prepare_barrier(fixture.context_mut()?, &base_edge(), MUTATION)
        .map_err(|code| code.to_string())?;
    assert!(!edge.conversations.contains_key(&CONVERSATION));
    assert!(!edge.route_objects.contains_key(&CONVERSATION));
    assert!(edge.routes.route(&ConversationId(CONVERSATION)).is_none());
    assert!(edge.routes.channel_route(&CHANNEL).is_none());
    Ok(())
}

#[tokio::test]
async fn an_empty_snapshot_removes_every_prior_route_only_once_active() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let mut edge = edge();
    super::snapshot::install_backing(&mut edge);
    install_route(&mut edge)?;
    edge.link_down();
    let mut base = base_edge();
    edge.link_active(fixture.context_mut()?, &mut base);
    let digest = agenc_ircd_e2ee::ids::federation_snapshot_digest(5, 2, &[])?;
    edge.state_begin(
        fixture.context_mut()?,
        &base,
        [6; 32],
        5,
        2,
        0,
        0,
        0,
        digest,
    )
    .map_err(|refusal| refusal.code.to_string())?;
    edge.state_end(fixture.context_mut()?, [6; 32], 0, None)
        .map_err(|refusal| refusal.code.to_string())?;
    // The prior projection stays live through READY.
    assert_eq!(edge.conversations.len(), 1);
    assert_eq!(edge.routes.routes().count(), 1);
    fixture.context_mut()?.discard_pending_for_test();
    edge.batch_applied(fixture.context_mut()?, &mut base);
    assert_eq!(edge.phase(), Phase::AwaitingActive);
    assert_eq!(edge.conversations.len(), 1);
    edge.state_active(fixture.context_mut()?, [6; 32], 5, 2, digest)
        .map_err(|refusal| refusal.code.to_string())?;
    fixture.context_mut()?.discard_pending_for_test();
    edge.batch_applied(fixture.context_mut()?, &mut base);
    assert!(edge.conversations.is_empty());
    assert!(edge.route_objects.is_empty());
    assert_eq!(edge.routes.routes().count(), 0);
    assert_eq!(edge.delivery.generation, 2);
    Ok(())
}

#[tokio::test]
async fn refused_event_storage_keeps_the_previous_resume_cursor() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let mut edge = edge();
    install_route(&mut edge)?;
    edge.delivery.generation = 2;
    edge.delivery.cursor = Some((6, [12; 16]));
    let before = (edge.delivery.generation, edge.delivery.cursor);
    let mut open = part(IrcFederationEventKind::ClosedEvent, 5)?;
    open.event.cross_profile_mutation_id = Opaque::new(Vec::new())?;
    open.event.cross_profile_part_index = 0;
    open.event.cross_profile_part_count = 0;
    let bytes =
        IrcWireObject::new(IrcWireObjectKind::FederationEvent, open.event.encode()?)?.encode()?;
    let object_id = *agenc_ircd_e2ee::ObjectId::compute(&bytes).as_bytes();
    fixture
        .state_mut()?
        .step_message(crate::state_core::inbox::StateCoreMessage::Signal(
            crate::state_core::inbox::SignalEvent::Terminate,
        ));
    let mut refused = false;
    for fragment in agenc_ircd_e2ee::wire::fragment::fragment_object(&bytes)? {
        refused |= edge
            .on_event_frame(
                fixture.context_mut()?,
                &mut base_edge(),
                open.position,
                object_id,
                fragment,
                false,
            )
            .is_err();
    }
    assert!(refused);
    edge.link_down();
    assert_eq!((edge.delivery.generation, edge.delivery.cursor), before);
    Ok(())
}

#[tokio::test]
async fn refused_snapshot_storage_keeps_the_previous_delivery_generation() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let mut edge = edge();
    super::snapshot::install_backing(&mut edge);
    edge.delivery.generation = 1;
    edge.delivery.cursor = Some((6, [12; 16]));
    let before = (edge.delivery.generation, edge.delivery.cursor);
    let mut base = base_edge();
    base.note_companion_delivery(before.0, before.1);
    edge.link_active(fixture.context_mut()?, &mut base);
    let digest = agenc_ircd_e2ee::ids::federation_snapshot_digest(5, 2, &[])?;
    edge.state_begin(
        fixture.context_mut()?,
        &base,
        [6; 32],
        5,
        2,
        0,
        0,
        0,
        digest,
    )
    .map_err(|refusal| refusal.code.to_string())?;
    fixture
        .state_mut()?
        .step_message(crate::state_core::inbox::StateCoreMessage::Signal(
            crate::state_core::inbox::SignalEvent::Terminate,
        ));
    assert!(
        edge.state_end(fixture.context_mut()?, [6; 32], 0, None)
            .is_err()
    );
    edge.link_down();
    assert_eq!((edge.delivery.generation, edge.delivery.cursor), before);
    assert_eq!(base.companion_cursor(), before);
    Ok(())
}

#[path = "witness_restart.rs"]
mod witness_restart;

#[path = "witness_persistence.rs"]
mod witness_persistence;
