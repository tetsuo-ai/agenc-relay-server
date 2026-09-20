#![forbid(unsafe_code)]

//! Registration restores companion projection when the joint apply is refused.

use crate::state_core::inbox::SignalEvent;
use agenc_ircd_e2ee::federation::frames::CompanionFrame;
use agenc_ircd_e2ee::objects::conversation::IrcConversationKind;
use agenc_ircd_e2ee::objects::federation::{IrcFederationRouteState, IrcRouteStateKind};
use agenc_ircd_types::ChannelInstanceId;

use super::*;

const CONVERSATION: [u8; 32] = [9; 32];
const CHANNEL: ChannelInstanceId = ChannelInstanceId::from_bytes([8; 16]);

fn route_payload() -> TestResult<Vec<u8>> {
    let state = IrcFederationRouteState {
        profile_version: 1,
        network_id: *NETWORK.as_bytes(),
        state_generation: 10,
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
    Ok(IrcWireObject::new(IrcWireObjectKind::FederationState, state.encode()?)?.encode()?)
}

fn projected_parts(payload: &[u8]) -> TestResult<Vec<BarrierPart>> {
    let event = ProjectedEvent::NetworkNotice {
        code: "TEST".to_owned(),
        text: "barrier".to_owned(),
    };
    let header = EventHeader {
        network_id: NETWORK,
        target_server_id: EDGE,
        projection_generation: 1,
        coordinator_state_generation: 10,
        delivery_sequence: 0,
        event_id: EventId::from_bytes([78; 16]),
        event_kind: event.kind(),
        correlation: None,
        cross_profile: Some(agenc_ircd_federation_wire::CrossProfilePart {
            mutation_id: MUTATION,
            part_index: 0,
            part_count: 3,
        }),
    };
    let bytes = header
        .build(&event_arm_object(&event).map_err(|e| format!("{e:?}"))?)?
        .encode_canonical()?
        .as_slice()
        .to_vec();
    let mut parts = vec![BarrierPart {
        identity: identity(3),
        stream: CrossProfileStream::Base,
        part_index: 0,
        delivery_generation: 1,
        delivery_sequence: 0,
        event_id: *header.event_id.as_bytes(),
        event_object_id: *federation_object_id(&bytes).as_bytes(),
        encoded_event_object: bytes,
        payload_object_id: None,
        payload_object_bytes: 0,
    }];
    for index in 1..=2 {
        let id = (index == 1).then(|| *agenc_ircd_e2ee::ObjectId::compute(payload).as_bytes());
        let event = IrcFederationEvent {
            profile_version: 1,
            network_id: *NETWORK.as_bytes(),
            target_server_id: *EDGE.as_bytes(),
            delivery_generation: 1,
            coordinator_state_generation: 10,
            delivery_sequence: u64::from(index - 1),
            event_id: [78 + u8::try_from(index)?; 16],
            event_kind: if index == 1 {
                IrcFederationEventKind::RouteStateChanged
            } else {
                IrcFederationEventKind::ClosedEvent
            },
            cross_profile_mutation_id: Opaque::new(MUTATION.to_vec())?,
            cross_profile_part_index: index,
            cross_profile_part_count: 3,
            conversation_id: Opaque::new(CONVERSATION.to_vec())?,
            route_sequence: u64::from(index + 3),
            origin_id: Opaque::new(Vec::new())?,
            origin_generation: 0,
            source_view: Opaque::new(Vec::new())?,
            request_home_server_id: Opaque::new(Vec::new())?,
            request_server_incarnation: Opaque::new(Vec::new())?,
            request_origin_id: Opaque::new(Vec::new())?,
            request_origin_generation: 0,
            request_operation_sequence: 0,
            request_id: Opaque::new(Vec::new())?,
            payload_object_id: Opaque::new(id.map_or_else(Vec::new, |id| id.to_vec()))?,
            encoded_event_result: Opaque::new(if index == 1 { Vec::new() } else { vec![60; 32] })?,
        };
        let bytes =
            IrcWireObject::new(IrcWireObjectKind::FederationEvent, event.encode()?)?.encode()?;
        parts.push(BarrierPart {
            identity: identity(3),
            stream: CrossProfileStream::Companion,
            part_index: index,
            delivery_generation: 1,
            delivery_sequence: event.delivery_sequence,
            event_id: event.event_id,
            event_object_id: *agenc_ircd_e2ee::ObjectId::compute(&bytes).as_bytes(),
            encoded_event_object: bytes,
            payload_object_id: id,
            payload_object_bytes: if id.is_some() {
                u32::try_from(payload.len())?
            } else {
                0
            },
        });
    }
    Ok(parts)
}

fn projected_rows() -> TestResult<Vec<InitialStorageRecord>> {
    let (base, _) = edges();
    let AccountServiceDurableWrite::Put {
        table,
        key,
        plaintext,
    } = base.peer_row(None, 1).map_err(|e| format!("{e:?}"))?
    else {
        return Err("peer row".into());
    };
    let mut rows = vec![InitialStorageRecord::new(
        table,
        key,
        1,
        plaintext.to_vec(),
    )?];
    let cursor = DeliveryRow::WitnessedCursor {
        generation: 1,
        next_sequence: 0,
        acked_sequence: 0,
        acked_event_id: [0; 16],
        barrier_open: false,
    };
    rows.push(record(
        TableId::E2eeState,
        DELIVERY_ROW_KIND,
        DeliveryRow::cursor_key(COORDINATOR.as_bytes())?,
        cursor.encode()?,
    )?);
    let payload = route_payload()?;
    let mut assembly = BarrierAssembly::open(identity(3))?;
    for part in projected_parts(&payload)? {
        rows.push(record(
            TableId::E2eeState,
            BARRIER_ROW_KIND,
            part.identity.part_key(part.part_index)?,
            part.encode()?,
        )?);
        assembly.stage(part)?;
    }
    rows.push(record(
        TableId::E2eeState,
        BARRIER_ROW_KIND,
        identity(3).head_key()?,
        BarrierHead::Stage(assembly.head().clone()).encode()?,
    )?);
    let row = ObjectRow::new(payload)?;
    rows.push(record(
        TableId::E2eeObject,
        OBJECT_RECORD_KIND,
        row.key()?,
        row.encode()?,
    )?);
    Ok(rows)
}

#[tokio::test]
async fn refused_barrier_apply_restores_projection_and_retries_the_retained_parts() -> TestResult {
    let (_, mut companion) = edges();
    for rejected in [true, false] {
        let mut fixture = StateCoreFixture::with_registration_router_and_records(
            entropy_script(),
            projected_rows()?,
        )
        .map_err(|error| format!("fixture rejected={rejected}: {error}"))?;
        let (mut base, mut disposable_companion) = edges();
        let restore_companion = if rejected {
            &mut companion
        } else {
            &mut disposable_companion
        };
        fixture
            .restore_edge_state(&mut base, Some(restore_companion))
            .map_err(|error| format!("restore rejected={rejected}: {error}"))?;
        base.phase = Phase::Active;
        let (handle, _queue) = link_queue(1 << 20);
        base.live = Some(LiveLink {
            link: LinkId::new(99),
            handle,
            coordinator_epoch: COORDINATOR_EPOCH,
            coordinator_incarnation: HUB_INCARNATION,
        });
        companion.link_down();
        assert!(companion.link_active(fixture.context_mut()?, &mut base));
        companion.handle_frames(
            fixture.context_mut()?,
            &mut base,
            vec![
                CompanionFrame::ResumeOk {
                    target_server_id: *EDGE.as_bytes(),
                    server_incarnation: *EDGE_INCARNATION.as_bytes(),
                    delivery_generation: 1,
                    next_delivery_sequence: 0,
                },
                CompanionFrame::OriginReady {
                    home_server_id: *EDGE.as_bytes(),
                    server_incarnation: *EDGE_INCARNATION.as_bytes(),
                },
            ],
        );
        assert!(companion.is_active());
        assert_eq!(base.barrier_ready(), Some(MUTATION));
        // A busy commit slot holds the complete barrier back.
        base.commit = Some(PendingCommit::BarrierFence);
        assert_eq!(base.barrier_ready(), None);
        base.commit = None;
        assert_eq!(base.barrier_ready(), Some(MUTATION));
        if rejected {
            fixture
                .state_mut()?
                .step_message(StateCoreMessage::Signal(SignalEvent::Terminate));
        }
        crate::registration::apply_ready_barrier(fixture.context_mut()?, &mut companion, &mut base);
        if rejected {
            assert!(!companion.channel_bound(&CHANNEL));
            assert_eq!(fixture.context_mut()?.pending_len(), 0);
        } else {
            assert!(companion.channel_bound(&CHANNEL));
            assert!(base.commit.is_some());
            let writes = fixture.context_mut()?.staged_rows_for_test()?;
            let (mut restored, mut restored_companion) = edges();
            fixture
                .commit_and_restore_edge(writes, &mut restored, Some(&mut restored_companion))
                .map_err(|error| format!("commit retry: {error}"))?;
            assert!(restored.barrier_applied(&MUTATION));
            assert!(restored_companion.channel_bound(&CHANNEL));
        }
    }
    Ok(())
}
