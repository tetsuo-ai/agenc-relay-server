//! Commit-dependent requester JOIN echoes, retained until the covered result.

use agenc_relay_client_wire::{ParsedMessage, WireMessage};
use agenc_relay_domain::federation::ProjectedEvent;
use agenc_relay_federation_wire::{EventHeader, ReplayKey};
use agenc_relay_types::{ChannelInstanceId, RequestId, UserId};

use super::request::{PendingKind, PendingRequest};
use super::{EdgeCompletion, EdgeFederation, Violation};
use crate::budget::MemoryPermit;
use crate::connection::ConnectionGeneration;
use crate::federation::codec::results::ResultArm;
use crate::state_core::StateCoreContext;
use crate::state_core::inbox::CloseReason;

pub(super) const MAX_JOIN_ECHOES: usize = 20;
// Covers the bounded source, channel, account label, display name, owned
// frame/string allocations, and one retained-record slot with ample headroom.
const ECHO_BACKING_BYTES: usize = 16_384;

#[cfg(test)]
#[path = "tests/join_echo.rs"]
mod tests;

pub(super) struct JoinEcho {
    request: RequestId,
    replay_key: ReplayKey,
    state_generation: u64,
    channel: ChannelInstanceId,
    frame: WireMessage,
    permit: MemoryPermit,
}

/// Only the requester's matching JOIN response is withheld from normal fanout.
pub(super) fn capture(
    edge: &EdgeFederation,
    context: &StateCoreContext,
    header: &EventHeader,
    event: &ProjectedEvent,
    recipient: UserId,
    frames: &mut Vec<WireMessage>,
) -> Result<Option<JoinEcho>, Violation> {
    let ProjectedEvent::MemberJoined { view, .. } = event else {
        return Ok(None);
    };
    if view.source.user_id != recipient {
        return Ok(None);
    }
    let Some(pending) = pending_join(edge, context, recipient)? else {
        return Ok(None);
    };
    let session = edge
        .origins
        .get(&pending.generation)
        .and_then(|origin| origin.session);
    if session.map(|(_, user)| user) != Some(recipient)
        || header.correlation.is_some()
        || frames.len() != 1
    {
        return Err(Violation::Consistency);
    }
    check_capture_generation(pending, header.coordinator_state_generation)?;
    check_target(pending, &view.membership.channel_id, edge)?;
    let permit = context.reserve_output_backing(ECHO_BACKING_BYTES)?;
    let frame = frames.pop().ok_or(Violation::Consistency)?;
    if frame.measure().map_err(|_| Violation::Codec)?.bytes() > ECHO_BACKING_BYTES / 2 {
        return Err(Violation::Ceiling);
    }
    Ok(Some(JoinEcho {
        request: pending.header.request_id,
        replay_key: pending.header.replay_key,
        state_generation: header.coordinator_state_generation,
        channel: view.membership.channel_id,
        frame,
        permit,
    }))
}

fn is_join(pending: &PendingRequest) -> bool {
    pending.header.opcode == agenc_relay_types::FederationOpcode::Join
        && matches!(&pending.kind, PendingKind::Command { message } if message.command() == "JOIN")
}

// Only RequestCompleted carries a wire correlation. A live origin admits one
// command at a time; membership events are held against that exact JOIN and
// its generation until the correlated durable completion validates the result.
fn pending_join<'a>(
    edge: &'a EdgeFederation,
    context: &StateCoreContext,
    recipient: UserId,
) -> Result<Option<&'a PendingRequest>, Violation> {
    let Some(generation) = context.sessions().generation_for_user(recipient) else {
        return Ok(None);
    };
    let mut requests = edge.pending.values().filter(|pending| {
        pending.generation == generation && !pending.sink_gone && is_join(pending)
    });
    let first = requests.next();
    if requests.next().is_some() {
        return Err(Violation::Consistency);
    }
    Ok(first)
}

fn check_capture_generation(pending: &PendingRequest, generation: u64) -> Result<(), Violation> {
    if pending.completion_generation.is_some() || pending.completion_coverage.is_some() {
        return Err(Violation::Consistency);
    }
    check_generation(pending, generation)
}

fn check_generation(pending: &PendingRequest, generation: u64) -> Result<(), Violation> {
    if let Some(result) = &pending.result {
        check_result_generation(result, generation)?;
    }
    if pending
        .join_echoes
        .iter()
        .any(|echo| echo.state_generation != generation)
    {
        return Err(Violation::Consistency);
    }
    Ok(())
}

/// Even an event still awaiting storage cannot be contradicted by its result.
pub(super) fn validate_result(
    edge: &EdgeFederation,
    request: RequestId,
    result: &ResultArm,
) -> Result<(), Violation> {
    if let Some(pending) = edge.pending.get(&request) {
        for echo in &pending.join_echoes {
            check_result(echo, request, result)?;
        }
    }
    match &edge.commit {
        Some(super::PendingCommit::Event {
            join_echo: Some(echo),
            ..
        }) => {
            check_result(echo, request, result)?;
        }
        Some(super::PendingCommit::OrdinaryBatch(pending)) => {
            for echo in &pending.echoes {
                check_result(echo, request, result)?;
            }
        }
        Some(super::PendingCommit::BarrierApplied { join_echoes, .. }) => {
            for echo in join_echoes {
                check_result(echo, request, result)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn check_result(echo: &JoinEcho, request: RequestId, result: &ResultArm) -> Result<(), Violation> {
    if echo.request == request {
        check_result_generation(result, echo.state_generation)?;
    }
    Ok(())
}

fn check_result_generation(result: &ResultArm, generation: u64) -> Result<(), Violation> {
    if !matches!(result, ResultArm::Committed { resulting_state_generation }
        if *resulting_state_generation == generation)
    {
        return Err(Violation::Consistency);
    }
    Ok(())
}

fn check_target(
    pending: &PendingRequest,
    channel: &ChannelInstanceId,
    edge: &EdgeFederation,
) -> Result<(), Violation> {
    if pending.join_echoes.len() >= MAX_JOIN_ECHOES
        || pending
            .join_echoes
            .iter()
            .any(|echo| echo.channel == *channel)
    {
        return Err(Violation::Ceiling);
    }
    let PendingKind::Command { message } = &pending.kind else {
        return Err(Violation::Consistency);
    };
    let name = edge
        .replica
        .channel(*channel)
        .ok_or(Violation::Consistency)?;
    let requested = message.middle().first().is_some_and(|names| {
        names.split(',').any(|candidate| {
            agenc_relay_domain::ChannelNameValue::parse(candidate)
                .is_ok_and(|candidate| candidate == name.name)
        })
    });
    if !requested {
        return Err(Violation::Consistency);
    }
    Ok(())
}

/// Coalescing durable rows must not hide repeated or excessive tentative JOINs.
pub(super) fn validate_tentative(
    edge: &EdgeFederation,
    tentative: &[JoinEcho],
    echo: &JoinEcho,
    completed: &std::collections::BTreeSet<RequestId>,
) -> Result<(), Violation> {
    let pending = edge
        .pending
        .get(&echo.request)
        .ok_or(Violation::Consistency)?;
    if completed.contains(&echo.request) {
        return Err(Violation::Consistency);
    }
    check_capture_generation(pending, echo.state_generation)?;
    let mut count = pending.join_echoes.len();
    for prior in tentative
        .iter()
        .filter(|prior| prior.request == echo.request)
    {
        if prior.channel == echo.channel
            || prior.state_generation != echo.state_generation
            || prior.replay_key != echo.replay_key
        {
            return Err(Violation::Consistency);
        }
        count = count.checked_add(1).ok_or(Violation::Ceiling)?;
    }
    if count >= MAX_JOIN_ECHOES {
        return Err(Violation::Ceiling);
    }
    Ok(())
}

/// An ordinary prefix validates all requester echoes before any row coalescing
/// or storage admission. Its final marker cannot cover a different mutation.
pub(super) fn validate_completion(
    edge: &EdgeFederation,
    tentative: &[JoinEcho],
    header: &EventHeader,
) -> Result<(), Violation> {
    let correlation = header.correlation.ok_or(Violation::Consistency)?;
    let pending = edge
        .pending
        .get(&correlation.request_id)
        .ok_or(Violation::Consistency)?;
    if pending.header.replay_key != correlation.replay_key {
        return Err(Violation::Consistency);
    }
    for echo in pending
        .join_echoes
        .iter()
        .chain(tentative)
        .filter(|echo| echo.request == correlation.request_id)
    {
        if echo.replay_key != correlation.replay_key
            || echo.state_generation != header.coordinator_state_generation
        {
            return Err(Violation::Consistency);
        }
    }
    Ok(())
}

/// Called only after the event or complete barrier storage receipt succeeds.
pub(super) fn committed(edge: &mut EdgeFederation, echo: JoinEcho) -> Result<(), Violation> {
    let Some(pending) = edge.pending.get_mut(&echo.request) else {
        return Ok(());
    };
    if pending.sink_gone {
        return Ok(());
    }
    if !is_join(pending)
        || pending.header.replay_key != echo.replay_key
        || pending.join_echoes.len() >= MAX_JOIN_ECHOES
        || pending
            .join_echoes
            .iter()
            .any(|prior| prior.channel == echo.channel)
    {
        return Err(Violation::Consistency);
    }
    check_generation(pending, echo.state_generation)?;
    pending
        .join_echoes
        .try_reserve(1)
        .map_err(|_| Violation::Ceiling)?;
    pending.join_echoes.push(echo);
    Ok(())
}

/// Prefixes the exact committed echoes and keeps their backing alive through delivery.
pub(super) fn complete(
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    message: Box<ParsedMessage>,
    state_generation: u64,
    echoes: Vec<JoinEcho>,
    replies: Vec<WireMessage>,
) -> Vec<EdgeCompletion> {
    match into_frames(state_generation, echoes, replies) {
        Ok((frames, echo_permits)) => vec![EdgeCompletion::JoinCommitted {
            generation,
            frames,
            echo_permits,
            message,
        }],
        Err(_) => {
            if let Some(sink) = context.sessions().sink_for_generation(generation) {
                sink.close_after_flush(CloseReason::ProtocolError);
            }
            Vec::new()
        }
    }
}

fn into_frames(
    generation: u64,
    echoes: Vec<JoinEcho>,
    replies: Vec<WireMessage>,
) -> Result<(Vec<WireMessage>, Vec<MemoryPermit>), Violation> {
    let accepted = replies
        .iter()
        .filter(|frame| matches!(frame.command(), "331" | "332"))
        .count();
    if echoes.len() != accepted
        || echoes.len() > MAX_JOIN_ECHOES
        || echoes
            .iter()
            .any(|echo| echo.state_generation != generation)
    {
        return Err(Violation::Consistency);
    }
    validate_channels(&echoes, &replies)?;
    let count = echoes
        .len()
        .checked_add(replies.len())
        .ok_or(Violation::Ceiling)?;
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(count)
        .map_err(|_| Violation::Ceiling)?;
    let mut permits = Vec::new();
    permits
        .try_reserve_exact(echoes.len())
        .map_err(|_| Violation::Ceiling)?;
    for echo in echoes {
        frames.push(echo.frame);
        permits.push(echo.permit);
    }
    frames.extend(replies);
    Ok((frames, permits))
}

fn validate_channels(echoes: &[JoinEcho], replies: &[WireMessage]) -> Result<(), Violation> {
    let mut remaining = Vec::new();
    remaining
        .try_reserve_exact(MAX_JOIN_ECHOES)
        .map_err(|_| Violation::Ceiling)?;
    remaining.extend(
        replies
            .iter()
            .filter(|frame| matches!(frame.command(), "331" | "332")),
    );
    for echo in echoes {
        let channel = frame_channel(&echo.frame, 0)?;
        let index = remaining
            .iter()
            .position(|frame| frame_channel(frame, 1).is_ok_and(|name| name == channel))
            .ok_or(Violation::Consistency)?;
        remaining.swap_remove(index);
    }
    Ok(())
}

fn frame_channel(
    frame: &WireMessage,
    index: usize,
) -> Result<agenc_relay_domain::ChannelNameValue, Violation> {
    let name = frame.middle().get(index).ok_or(Violation::Consistency)?;
    agenc_relay_domain::ChannelNameValue::parse(name).map_err(|_| Violation::Consistency)
}
