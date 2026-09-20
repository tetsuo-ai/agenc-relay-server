#![forbid(unsafe_code)]

//! An origin acknowledgement must name the exact declaration or deletion the edge is waiting
//! for, and a companion deadline timer is routed only for the edge's own coordinator.

use super::*;
use crate::state_core::timers::{TimedId, TimerKind};

/// An active edge whose one connection has just been bound to a session.
fn bound_edge(
    context: &mut StateCoreContext,
    connection: ConnectionGeneration,
) -> TestResult<EdgeFederation> {
    let mut edge = resync_edge();
    edge.phase = Phase::Active;
    edge.connection_opened(context, connection);
    let origin = edge.origins.get_mut(&connection).ok_or("origin")?;
    origin.acked_generation = Some(0);
    origin.ever_acked = true;
    origin.object_id = [40; 32];
    origin.session = Some((
        SessionId::from_bytes([41; 16]),
        UserId::from_bytes([42; 16]),
    ));
    edge.session_bound(context, connection);
    Ok(edge)
}

fn ack(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    origin_id: OriginId,
    generation: u64,
    object_id: Option<agenc_ircd_federation_wire::FederationHash32>,
) -> Result<Vec<EdgeCompletion>, Violation> {
    edge.handle_frame(
        context,
        FederationFrame::OriginAck {
            edge_server_id: EDGE,
            server_incarnation: EDGE_INCARNATION,
            origin_id,
            generation,
            object_id,
        },
    )
}

#[tokio::test]
async fn an_acknowledgement_that_disagrees_with_the_pending_update_is_refused() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let context = fixture.context_mut()?;
    let connection = ConnectionGeneration::new(1);
    let mut edge = bound_edge(context, connection)?;
    let origin = edge.origins.get(&connection).ok_or("origin")?;
    let origin_id = origin.origin_id;
    let update = origin.pending_updates.front().copied().ok_or("update")?;
    let wrong = agenc_ircd_federation_wire::FederationHash32::from_bytes([99; 32]);
    assert!(matches!(
        ack(
            &mut edge,
            context,
            origin_id,
            update.generation,
            Some(wrong)
        ),
        Err(Violation::Consistency)
    ));
    assert!(matches!(
        ack(&mut edge, context, origin_id, update.generation, None),
        Err(Violation::Consistency)
    ));
    let unknown = ack(
        &mut edge,
        context,
        OriginId::from_bytes([99; 16]),
        update.generation,
        Some(wrong),
    )
    .map_err(|violation| format!("{violation:?}"))?;
    assert!(
        unknown.is_empty(),
        "an acknowledgement for an unknown origin is ignored"
    );
    Ok(())
}

#[tokio::test]
async fn an_acknowledgement_of_a_settled_origin_must_repeat_its_generation_and_object() -> TestResult
{
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let context = fixture.context_mut()?;
    let connection = ConnectionGeneration::new(1);
    let mut edge = bound_edge(context, connection)?;
    let origin = edge.origins.get_mut(&connection).ok_or("origin")?;
    origin.pending_updates.clear();
    let origin_id = origin.origin_id;
    let object = agenc_ircd_federation_wire::FederationHash32::from_bytes(origin.object_id);
    let generation = origin.generation;
    let wrong = agenc_ircd_federation_wire::FederationHash32::from_bytes([99; 32]);
    assert!(matches!(
        ack(&mut edge, context, origin_id, generation, Some(wrong)),
        Err(Violation::Consistency)
    ));
    assert!(matches!(
        ack(&mut edge, context, origin_id, generation + 1, Some(object)),
        Err(Violation::Consistency)
    ));
    assert!(ack(&mut edge, context, origin_id, generation, Some(object)).is_ok());
    assert_eq!(
        edge.origins
            .get(&connection)
            .ok_or("origin")?
            .acked_generation,
        Some(generation)
    );
    Ok(())
}

#[test]
fn a_companion_deadline_is_routed_only_for_the_edges_coordinator() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut edge = resync_edge();
    let deadline = context.now().checked_add(5)?;
    for (peer, routed) in [(HUB, false), (COORDINATOR, true)] {
        context.timers_mut().schedule(
            deadline,
            TimerKind::CompanionProfileDeadline,
            TimedId::Peer(peer),
        )?;
        let entry = context.timers_mut().pop_due(deadline).ok_or("due timer")?;
        assert_eq!(entry.id, TimedId::Peer(peer));
        assert_eq!(
            edge.timer_fired(context, entry),
            routed,
            "a deadline for another peer is not this edge's timer"
        );
    }
    assert!(edge.live.is_none());
    Ok(())
}

#[tokio::test]
async fn an_unchanged_origin_update_is_folded_and_the_deferral_ceiling_holds() -> TestResult {
    use crate::federation::edge::journal::queue_update;
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let context = fixture.context_mut()?;
    let connection = ConnectionGeneration::new(1);
    let mut edge = bound_edge(context, connection)?;
    let pending = |edge: &EdgeFederation| -> TestResult<usize> {
        Ok(edge
            .origins
            .get(&connection)
            .ok_or("origin")?
            .pending_updates
            .len())
    };
    assert_eq!(pending(&edge)?, 1);
    queue_update(&mut edge, connection).map_err(|violation| format!("{violation:?}"))?;
    assert_eq!(
        pending(&edge)?,
        1,
        "the same facts fold into the last update"
    );
    let sessions = [
        Some((
            SessionId::from_bytes([41; 16]),
            UserId::from_bytes([42; 16]),
        )),
        Some((
            SessionId::from_bytes([43; 16]),
            UserId::from_bytes([44; 16]),
        )),
    ];
    for index in 1..crate::federation::edge::MAX_DEFERRED_COMMANDS {
        let origin = edge.origins.get_mut(&connection).ok_or("origin")?;
        origin.session = sessions.get(index % 2).copied().flatten();
        queue_update(&mut edge, connection).map_err(|violation| format!("{violation:?}"))?;
        assert_eq!(pending(&edge)?, index + 1);
    }
    let origin = edge.origins.get_mut(&connection).ok_or("origin")?;
    origin.session = sessions
        .get(crate::federation::edge::MAX_DEFERRED_COMMANDS % 2)
        .copied()
        .flatten();
    assert!(matches!(
        queue_update(&mut edge, connection),
        Err(Violation::Ceiling)
    ));
    assert_eq!(
        pending(&edge)?,
        crate::federation::edge::MAX_DEFERRED_COMMANDS
    );
    Ok(())
}
