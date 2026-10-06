//! A labeled message's own echoes, held until its request completes so that
//! the request gets one labeled logical response (Architecture 9.5).
//!
//! The coordinator answers its own client's labeled `PRIVMSG`, `NOTICE` or
//! `TAGMSG` with one logical response: the requester's echoes under
//! `echo-message` (one labeled line, or one labeled batch when the message
//! named several targets), and otherwise a labeled `ACK`. An edge renders
//! each echo from the coordinator's events, which come before the request's
//! completion, so it holds the requester's copy of a labeled request and
//! sends the copies it held as that one response once the request
//! completes. Every other recipient's copy, and the echo of an unlabeled
//! request, is sent with its event as before.
//!
//! A held echo belongs to its request: a re-rendered event replaces the copy
//! it held, and the request completes only after the event that carries its
//! completion is applied, which follows every event of the request in
//! delivery order.

use agenc_relay_client_wire::{CapabilityState, ParsedMessage, WireMessage};
use agenc_relay_domain::federation::ProjectedEvent;
use agenc_relay_federation_wire::EventHeader;
use agenc_relay_types::{EventId, FederationOpcode, UserId};

use super::request::{PendingKind, PendingRequest};
use super::{EdgeCompletion, EdgeFederation, Violation};
use crate::budget::MemoryPermit;
use crate::connection::ConnectionGeneration;
use crate::federation::codec::results::ResultArm;
use crate::state_core::StateCoreContext;
use crate::state_core::inbox::CloseReason;

/// The memory charged for one held echo: twice the longest encoded line,
/// which covers its owned fields and their allocations.
const ECHO_BACKING_BYTES: usize = 2 * agenc_relay_client_wire::MAX_PHYSICAL_LINE_BYTES;

#[cfg(test)]
#[path = "tests/message_echo.rs"]
mod tests;

/// The requester's copy of one delivered message, held for its response.
pub(super) struct MessageEcho {
    /// The event that delivered it; rendering that event again replaces it.
    event: EventId,
    /// The coordinator state generation of that event.
    state_generation: u64,
    frame: WireMessage,
    permit: MemoryPermit,
}

/// Takes the requester's own copy of a delivered message out of `frames`
/// and holds it on the request it answers, when that request is a labeled
/// message whose label the connection negotiated; any other copy stays in
/// `frames`. A copy that contradicts the request's result, follows its
/// completion, or exceeds its targets is refused.
pub(super) fn capture(
    edge: &mut EdgeFederation,
    context: &StateCoreContext,
    header: &EventHeader,
    event: &ProjectedEvent,
    recipient: (UserId, ConnectionGeneration, Option<&CapabilityState>),
    frames: &mut Vec<WireMessage>,
) -> Result<(), Violation> {
    let (user_id, generation, capabilities) = recipient;
    let ProjectedEvent::MessageDelivered(record) = event else {
        return Ok(());
    };
    if record.sender.user_id != user_id {
        return Ok(());
    }
    // A connection has one command in flight; its later commands wait.
    let Some((pending, targets)) = edge.pending.values_mut().find_map(|pending| {
        let targets = labeled_targets(pending, generation, capabilities)?;
        Some((pending, targets))
    }) else {
        return Ok(());
    };
    let Some(frame) = frames.pop() else {
        return Ok(());
    };
    let state_generation = header.coordinator_state_generation;
    if pending.completion_generation.is_some()
        || pending.completion_coverage.is_some()
        || pending
            .result
            .as_ref()
            .is_some_and(|result| !commits_at(result, state_generation))
        || pending
            .message_echoes
            .iter()
            .any(|echo| echo.state_generation != state_generation)
    {
        return Err(Violation::Consistency);
    }
    if let Some(held) = pending
        .message_echoes
        .iter_mut()
        .find(|echo| echo.event == header.event_id)
    {
        held.frame = frame;
        return Ok(());
    }
    if pending.message_echoes.len() >= targets {
        return Err(Violation::Ceiling);
    }
    let permit = context.reserve_output_backing(ECHO_BACKING_BYTES)?;
    pending
        .message_echoes
        .try_reserve(1)
        .map_err(|_| Violation::Ceiling)?;
    pending.message_echoes.push(MessageEcho {
        event: header.event_id,
        state_generation,
        frame,
        permit,
    });
    Ok(())
}

/// The number of targets of the labeled message `pending` carries for the
/// connection `generation`, each of which echoes at most once, when the
/// connection negotiated `labeled-response` and is still open.
fn labeled_targets(
    pending: &PendingRequest,
    generation: ConnectionGeneration,
    capabilities: Option<&CapabilityState>,
) -> Option<usize> {
    let PendingKind::Command { message } = &pending.kind else {
        return None;
    };
    let labeled = message
        .tags()
        .iter()
        .any(|tag| tag.key() == "label" && tag.value().is_some());
    (pending.generation == generation
        && !pending.sink_gone
        && pending.header.opcode == FederationOpcode::Message
        && labeled
        && capabilities.is_some_and(|state| state.enabled("labeled-response")))
    .then(|| {
        message
            .middle()
            .first()
            .map_or(0, |targets| targets.split(',').count())
    })
}

fn commits_at(result: &ResultArm, generation: u64) -> bool {
    matches!(result, ResultArm::Committed { resulting_state_generation }
        if *resulting_state_generation == generation)
}

/// A result cannot contradict a held echo: the request commits at the
/// generation of the events that carried its echoes.
pub(super) fn validate_result(
    pending: &PendingRequest,
    result: &ResultArm,
) -> Result<(), Violation> {
    if pending
        .message_echoes
        .iter()
        .any(|echo| !commits_at(result, echo.state_generation))
    {
        return Err(Violation::Consistency);
    }
    Ok(())
}

/// The committed message's response: the echoes held for it, in delivery
/// order, then any replies its result carried. The router labels it, or
/// sends a labeled `ACK` when it is empty; an unlabeled request with nothing
/// held gets nothing. Their backing is kept until the response is sent.
pub(super) fn complete(
    context: &StateCoreContext,
    generation: ConnectionGeneration,
    message: Box<ParsedMessage>,
    echoes: Vec<MessageEcho>,
    replies: Vec<WireMessage>,
) -> Vec<EdgeCompletion> {
    let mut frames = Vec::new();
    let mut echo_permits = Vec::new();
    let reserved = echoes
        .len()
        .checked_add(replies.len())
        .is_some_and(|count| frames.try_reserve_exact(count).is_ok())
        && echo_permits.try_reserve_exact(echoes.len()).is_ok();
    if !reserved {
        if let Some(sink) = context.sessions().sink_for_generation(generation) {
            sink.close_after_flush(CloseReason::ProtocolError);
        }
        return Vec::new();
    }
    for echo in echoes {
        frames.push(echo.frame);
        echo_permits.push(echo.permit);
    }
    frames.extend(replies);
    vec![EdgeCompletion::MessageCommitted {
        generation,
        frames,
        echo_permits,
        message,
    }]
}
