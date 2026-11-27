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

//! NICK and SETNAME use the same committed delivery boundary. Their own
//! notifications are independent of echo-message. The requested name and
//! the coordinator's committed generation must match before sending the label.
//! A connection without setname receives its ordinary labeled ACK.
//! A public TOPIC notification must match the instance selected at admission,
//! the original actor and the exact topic bytes (including an explicit clear).
//! An explicit PART may name several channels. Each correlated departure must match
//! one of their original instances, the departing user, and the admitted reason.

use agenc_relay_client_wire::{CapabilityState, ParsedMessage, WireMessage};
use agenc_relay_domain::federation::ProjectedEvent;
use agenc_relay_federation_wire::EventHeader;
use agenc_relay_types::{ChannelInstanceId, EventId, FederationOpcode, UserId};

use super::request::{EchoChannels, PendingKind, PendingRequest};
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

/// The requester's original notification, held until the matching command commits.
pub(super) struct MessageEcho {
    /// The event that delivered it; rendering that event again replaces it.
    event: EventId,
    /// The coordinator state generation of that event.
    state_generation: u64,
    /// One explicit PART can remove the user from each admitted instance only once.
    parted_channel: Option<ChannelInstanceId>,
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
    let actor = match event {
        ProjectedEvent::MessageDelivered(record) => record.sender.user_id,
        ProjectedEvent::TopicChanged { actor, .. } => actor.user_id,
        ProjectedEvent::MemberParted { source, .. } => source.user_id,
        ProjectedEvent::NicknameChanged { view, .. }
        | ProjectedEvent::DisplayNameChanged { view, .. } => view.source.user_id,
        _ => return Ok(()),
    };
    if actor != user_id {
        return Ok(());
    }
    // A connection has one command in flight; its later commands wait.
    let Some((pending, targets)) = edge.pending.values_mut().find_map(|pending| {
        let targets = labeled_targets(pending, generation, capabilities, event)?;
        Some((pending, targets))
    }) else {
        return Ok(());
    };
    if let PendingKind::Command {
        message,
        echo_channels: Some(EchoChannels::Message(_)),
    } = &pending.kind
        && frames
            .last()
            .is_some_and(|frame| !original_message_echo(message, frame))
    {
        return Ok(());
    }
    let Some(frame) = frames.pop() else {
        return Ok(());
    };
    let parted_channel = match event {
        ProjectedEvent::MemberParted { channel_id, .. } => Some(*channel_id),
        _ => None,
    };
    hold_echo(pending, context, header, parted_channel, targets, frame)
}

fn hold_echo(
    pending: &mut PendingRequest,
    context: &StateCoreContext,
    header: &EventHeader,
    parted_channel: Option<ChannelInstanceId>,
    targets: usize,
    frame: WireMessage,
) -> Result<(), Violation> {
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
    check_departure_reply(parted_channel, &frame, &pending.replies)?;
    if let PendingKind::Command {
        message,
        echo_channels: Some(EchoChannels::Message(_)),
    } = &pending.kind
    {
        check_message_replies(
            message,
            pending
                .message_echoes
                .iter()
                .filter(|held| held.event != header.event_id)
                .map(|held| &held.frame)
                .chain(std::iter::once(&frame)),
            &pending.replies,
        )?;
    }
    if let Some(held) = pending
        .message_echoes
        .iter_mut()
        .find(|echo| echo.event == header.event_id)
    {
        if held.parted_channel != parted_channel || held.frame.middle() != frame.middle() {
            return Err(Violation::Consistency);
        }
        held.frame = frame;
        return Ok(());
    }
    if parted_channel.is_some()
        && pending
            .message_echoes
            .iter()
            .any(|echo| echo.parted_channel == parted_channel)
    {
        return Err(Violation::Consistency);
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
        parted_channel,
        frame,
        permit,
    });
    Ok(())
}

/// How many requester notifications this event can contribute to the pending
/// command on this live, labeled connection. A NICK must match its exact new name.
fn labeled_targets(
    pending: &PendingRequest,
    generation: ConnectionGeneration,
    capabilities: Option<&CapabilityState>,
    event: &ProjectedEvent,
) -> Option<usize> {
    let PendingKind::Command {
        message,
        echo_channels,
    } = &pending.kind
    else {
        return None;
    };
    let labeled = message
        .tags()
        .iter()
        .any(|tag| tag.key() == "label" && tag.value().is_some());
    if pending.generation != generation
        || pending.sink_gone
        || !labeled
        || !capabilities.is_some_and(|state| state.enabled("labeled-response"))
    {
        return None;
    }
    match (pending.header.opcode, event) {
        (FederationOpcode::Message, ProjectedEvent::MessageDelivered(_)) => message
            .middle()
            .first()
            .map(|targets| targets.split(',').count()),
        (
            FederationOpcode::Topic,
            ProjectedEvent::TopicChanged {
                channel_id, topic, ..
            },
        ) => {
            let committed = topic.as_ref().map_or("", |(text, _, _)| text.as_str());
            (matches!(echo_channels, Some(EchoChannels::Topic(original)) if original == channel_id)
                && message.trailing() == Some(committed))
            .then_some(1)
        }
        (
            FederationOpcode::Part,
            ProjectedEvent::MemberParted {
                channel_id, reason, ..
            },
        ) => departure_targets(echo_channels.as_ref(), channel_id, reason),
        (FederationOpcode::NickChange, ProjectedEvent::NicknameChanged { view, .. }) => {
            let requested = message
                .middle()
                .first()
                .map(String::as_str)
                .or(message.trailing())?;
            (requested == view.source.nickname.presentation()).then_some(1)
        }
        (FederationOpcode::Setname, ProjectedEvent::DisplayNameChanged { display_name, .. }) => {
            // Compare the value admitted by the shared PRECIS profile, including
            // canonical whitespace and normalization in requests from other clients.
            let requested = agenc_relay_types::DisplayName::prepare(message.trailing()?).ok()?;
            (capabilities.is_some_and(|state| state.enabled("setname"))
                && requested.as_str() == display_name.as_str())
            .then_some(1)
        }
        _ => None,
    }
}

fn departure_targets(
    original: Option<&EchoChannels>,
    channel_id: &ChannelInstanceId,
    reason: &str,
) -> Option<usize> {
    let Some(EchoChannels::Part {
        channels,
        reason: requested,
        ..
    }) = original
    else {
        return None;
    };
    (channels.contains(channel_id) && requested == reason).then_some(channels.len())
}

/// Whether any already held successful PART contradicts a scoped refusal in the result.
pub(super) fn validate_departure_replies(
    pending: &PendingRequest,
    replies: &[WireMessage],
) -> Result<(), Violation> {
    for echo in &pending.message_echoes {
        check_departure_reply(echo.parted_channel, &echo.frame, replies)?;
    }
    Ok(())
}

fn check_departure_reply(
    channel: Option<ChannelInstanceId>,
    frame: &WireMessage,
    replies: &[WireMessage],
) -> Result<(), Violation> {
    if channel.is_none() {
        return Ok(());
    }
    let [parted] = frame.middle() else {
        return Err(Violation::Consistency);
    };
    if replies
        .iter()
        .any(|reply| matches!(reply.middle(), [_, refused] if refused.eq_ignore_ascii_case(parted)))
    {
        return Err(Violation::Consistency);
    }
    Ok(())
}

/// A result or a later echo must agree with the original target dispositions,
/// whichever arrives first. Unqualified user policy errors can only cover users
/// with no named decision or accepted echo.
pub(super) fn validate_message_replies(
    pending: &PendingRequest,
    replies: &[WireMessage],
) -> Result<(), Violation> {
    let PendingKind::Command { message, .. } = &pending.kind else {
        return Err(Violation::Consistency);
    };
    check_message_replies(
        message,
        pending.message_echoes.iter().map(|held| &held.frame),
        replies,
    )
}

fn original_message_echo(message: &ParsedMessage, frame: &WireMessage) -> bool {
    matches!(frame.middle(), [name] if message.middle().first().is_some_and(|names|
        names.split(',').any(|original| original.eq_ignore_ascii_case(name))))
        && message.command() == frame.command()
        && message.trailing() == frame.trailing()
}

fn check_message_replies<'a>(
    message: &ParsedMessage,
    echoes: impl Iterator<Item = &'a WireMessage>,
    replies: &[WireMessage],
) -> Result<(), Violation> {
    let names = message.middle().first().ok_or(Violation::Consistency)?;
    let mut accepted = 0u8;
    for echo in echoes {
        let [name] = echo.middle() else {
            return Err(Violation::Consistency);
        };
        let index = names
            .split(',')
            .position(|target| target.eq_ignore_ascii_case(name))
            .filter(|index| *index < 4)
            .ok_or(Violation::Consistency)?;
        let bit = 1 << index;
        if accepted & bit != 0
            || replies.iter().any(|reply| {
                reply.middle().last().is_some_and(|refused| {
                    reply.command() != "481" && refused.eq_ignore_ascii_case(name)
                })
            })
        {
            return Err(Violation::Consistency);
        }
        accepted |= bit;
    }
    let available_users = names
        .split(',')
        .enumerate()
        .filter(|(index, name)| {
            *index < 4 && !name.starts_with('#') && accepted & (1 << index) == 0
        })
        .count();
    let refused_users = replies
        .iter()
        .filter(|reply| matches!(reply.command(), "401" | "481"))
        .count();
    if refused_users > available_users {
        return Err(Violation::Consistency);
    }
    Ok(())
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
