//! Client-visible lines rendered from projected events on the edge.
//!
//! Every event names its local recipients through the replica; each
//! recipient's own capability set decides the extended forms, exactly as
//! the coordinator's local renderer does for its own clients.

use agenc_relay_client_wire::{CapabilityState, WireMessage};
use agenc_relay_domain::MessageKind;
use agenc_relay_domain::federation::{
    ActorView, ApplyOutcome, DeliveryTarget, ModeDirection, ProjectedEvent, ProjectedModeChange,
    SourceView,
};
use agenc_relay_types::{ChannelInstanceId, UserId};

use super::EdgeFederation;
use crate::RuntimeError;
use crate::connection::ConnectionGeneration;
use crate::state_core::StateCoreContext;
use crate::state_core::fanout::{
    FanoutFrame, FanoutRequest, FanoutTarget, MAX_FANOUT_FRAMES, MAX_FANOUT_TARGETS,
};

#[cfg(test)]
#[path = "tests/fanout.rs"]
mod tests;

/// One bounded fanout shared by every event in a durable apply.
#[derive(Default)]
pub(super) struct EventFanout {
    targets: Vec<FanoutTarget>,
    frames: std::collections::HashMap<(usize, WireMessage), Vec<usize>>,
    indices: std::collections::BTreeMap<ConnectionGeneration, (usize, usize)>,
}

impl EventFanout {
    pub(super) fn append(
        &mut self,
        context: &StateCoreContext,
        generation: ConnectionGeneration,
        frames: Vec<WireMessage>,
    ) -> Result<(), RuntimeError> {
        if frames.is_empty() {
            return Ok(());
        }
        let Some((index, mut position)) = self.target_position(context, generation)? else {
            return Ok(());
        };
        for frame in frames {
            self.append_frame(index, position, frame)?;
            position = position.checked_add(1).ok_or(RuntimeError::Overflow)?;
        }
        self.indices.insert(generation, (index, position));
        Ok(())
    }

    fn target_position(
        &mut self,
        context: &StateCoreContext,
        generation: ConnectionGeneration,
    ) -> Result<Option<(usize, usize)>, RuntimeError> {
        if let Some(position) = self.indices.get(&generation) {
            return Ok(Some(*position));
        }
        let Some(sink) = context.sessions().sink_for_generation(generation) else {
            return Ok(None);
        };
        if self.targets.len() >= MAX_FANOUT_TARGETS {
            return Err(RuntimeError::LimitExceeded);
        }
        self.targets
            .try_reserve(1)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        let index = self.targets.len();
        self.targets.push(FanoutTarget { generation, sink });
        self.indices.insert(generation, (index, 0));
        Ok(Some((index, 0)))
    }

    /// Sharing by position preserves repeated equal frames and every sink's
    /// ordering, even when other sinks have different capability projections.
    fn append_frame(
        &mut self,
        target: usize,
        position: usize,
        frame: WireMessage,
    ) -> Result<(), RuntimeError> {
        let key = (position, frame);
        if !self.frames.contains_key(&key) {
            if self.frames.len() >= MAX_FANOUT_FRAMES {
                return Err(RuntimeError::LimitExceeded);
            }
            self.frames
                .try_reserve(1)
                .map_err(|_| RuntimeError::MemoryExhausted)?;
        }
        let recipients = self.frames.entry(key).or_default();
        if recipients.len() >= MAX_FANOUT_TARGETS {
            return Err(RuntimeError::LimitExceeded);
        }
        recipients
            .try_reserve(1)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        recipients.push(target);
        Ok(())
    }

    pub(super) fn finish(self) -> Result<FanoutRequest, RuntimeError> {
        let mut groups = Vec::new();
        groups
            .try_reserve_exact(self.frames.len())
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        groups.extend(self.frames);
        groups.sort_unstable_by_key(|((position, _), recipients)| {
            (*position, recipients.first().copied())
        });
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(groups.len())
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        for ((_, message), recipients) in groups {
            frames.push(FanoutFrame::new(message, recipients)?);
        }
        FanoutRequest::new(self.targets, frames)
    }
}

/// Keeps the nickname directory of remote users current from events.
pub(super) fn remember_nicknames(edge: &mut EdgeFederation, event: &ProjectedEvent) {
    match event {
        ProjectedEvent::MemberJoined { view, .. } => {
            edge.nicknames
                .insert(view.source.user_id, view.source.nickname.clone());
        }
        ProjectedEvent::NicknameChanged { view, .. } => {
            edge.nicknames
                .insert(view.source.user_id, view.source.nickname.clone());
        }
        ProjectedEvent::MessageDelivered(record) => {
            edge.nicknames
                .insert(record.sender.user_id, record.sender.nickname.clone());
        }
        ProjectedEvent::SessionHidden { source, .. } => {
            edge.nicknames.remove(&source.user_id);
        }
        _ => {}
    }
}

fn line(
    prefix: &str,
    command: &str,
    middle: &[&str],
    trailing: Option<&str>,
) -> Result<WireMessage, RuntimeError> {
    WireMessage::new(prefix, command, middle, trailing).map_err(|_| RuntimeError::InvalidValue)
}

fn numeric(
    prefix: &str,
    code: u16,
    target: &str,
    middle: &[&str],
    trailing: Option<&str>,
) -> Result<WireMessage, RuntimeError> {
    agenc_relay_client_wire::numeric_reply(prefix, code, target, middle, trailing)
        .map_err(|_| RuntimeError::InvalidValue)
}

/// The visible user mask of an event's source, from the shared Architecture
/// 7.4 formatter the coordinator's own renderer uses.
pub(crate) fn prefix(source: &SourceView) -> Result<String, RuntimeError> {
    agenc_relay_client_wire::user_mask(source.nickname.presentation(), &source.public_cloak)
        .map_err(|_| RuntimeError::InvalidValue)
}

fn actor_prefix(edge: &EdgeFederation, actor: &ActorView) -> Result<String, RuntimeError> {
    match &actor.0 {
        Some(source) => prefix(source),
        None => Ok(edge.config.server_name.clone()),
    }
}

fn channel_name(edge: &EdgeFederation, channel_id: ChannelInstanceId) -> Option<String> {
    edge.replica
        .channel(channel_id)
        .map(|channel| channel.name.presentation().to_owned())
}

/// The channel name an event refers to, read before the replica applies
/// it: a removal that unreferences the channel drops the record, and the
/// rendered line still has to name it.
pub(super) fn event_channel_label(edge: &EdgeFederation, event: &ProjectedEvent) -> Option<String> {
    match event {
        ProjectedEvent::ChannelHidden { channel_id, .. }
        | ProjectedEvent::MemberParted { channel_id, .. }
        | ProjectedEvent::ChannelModesChanged { channel_id, .. }
        | ProjectedEvent::TopicChanged { channel_id, .. }
        | ProjectedEvent::Invited { channel_id, .. }
        | ProjectedEvent::InviteRemoved { channel_id, .. }
        | ProjectedEvent::Kicked { channel_id, .. } => channel_name(edge, *channel_id),
        _ => None,
    }
}

/// Collects one event's local frames for the durable apply reservation.
pub(super) enum EventRenderRefused {
    Runtime(RuntimeError),
    Protocol(super::Violation),
}

impl From<RuntimeError> for EventRenderRefused {
    fn from(error: RuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<super::Violation> for EventRenderRefused {
    fn from(error: super::Violation) -> Self {
        Self::Protocol(error)
    }
}

pub(super) fn render_event(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    header: &agenc_relay_federation_wire::EventHeader,
    event: &ProjectedEvent,
    outcome: &ApplyOutcome,
    label: Option<&str>,
    fanout: &mut EventFanout,
) -> Result<Option<super::join_echo::JoinEcho>, super::Violation> {
    render_event_strict(edge, context, header, event, outcome, label, fanout).map_err(|error| {
        match error {
            EventRenderRefused::Runtime(error) => error.into(),
            EventRenderRefused::Protocol(violation) => violation,
        }
    })
}

pub(super) fn render_event_strict(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    header: &agenc_relay_federation_wire::EventHeader,
    event: &ProjectedEvent,
    outcome: &ApplyOutcome,
    label: Option<&str>,
    fanout: &mut EventFanout,
) -> Result<Option<super::join_echo::JoinEcho>, EventRenderRefused> {
    let mut echo = None;
    for user_id in &outcome.local_recipients {
        let Some(generation) = context.sessions().generation_for_user(*user_id) else {
            continue;
        };
        let capabilities = context
            .sessions()
            .capabilities_for_user(*user_id)
            .cloned_state();
        let mut frames = frames_for(edge, event, *user_id, capabilities.as_ref(), label)?;
        if let Some(captured) =
            super::join_echo::capture(edge, context, header, event, *user_id, &mut frames)?
        {
            if echo.is_some() {
                return Err(EventRenderRefused::Protocol(super::Violation::Consistency));
            }
            echo = Some(captured);
        }
        fanout.append(context, generation, frames)?;
    }
    Ok(echo)
}

trait ClonedState {
    fn cloned_state(self) -> Option<CapabilityState>;
}

impl ClonedState for Option<&CapabilityState> {
    fn cloned_state(self) -> Option<CapabilityState> {
        self.and_then(|state| state.try_clone().ok())
    }
}

fn enabled(capabilities: Option<&CapabilityState>, name: &str) -> bool {
    capabilities.is_some_and(|state| state.enabled(name))
}

/// The lines one recipient receives for one event.
// agenc-review: focus owner=runtime reviewed=2026-09-02 reason=one closed match renders every client-visible projected event kind
fn frames_for(
    edge: &EdgeFederation,
    event: &ProjectedEvent,
    recipient: UserId,
    capabilities: Option<&CapabilityState>,
    label: Option<&str>,
) -> Result<Vec<WireMessage>, RuntimeError> {
    let server = edge.config.server_name.as_str();
    let name_of = |channel_id: ChannelInstanceId| {
        channel_name(edge, channel_id).or_else(|| label.map(str::to_owned))
    };
    let frames = match event {
        ProjectedEvent::SessionHidden { source, reason, .. } => {
            if source.user_id == recipient {
                Vec::new()
            } else {
                vec![line(&prefix(source)?, "QUIT", &[], Some(reason))?]
            }
        }
        ProjectedEvent::NicknameChanged { old_nickname, view } => {
            let mut old = view.source.clone();
            old.nickname = old_nickname.clone();
            vec![line(
                &prefix(&old)?,
                "NICK",
                &[],
                Some(view.source.nickname.presentation()),
            )?]
        }
        ProjectedEvent::MemberJoined {
            view, display_name, ..
        } => {
            let Some(name) = channel_name(edge, view.membership.channel_id) else {
                return Ok(Vec::new());
            };
            let source = prefix(&view.source)?;
            if enabled(capabilities, "extended-join") {
                let account = view
                    .source
                    .account_label
                    .as_ref()
                    .map_or("*", |label| label.as_str());
                vec![line(
                    &source,
                    "JOIN",
                    &[&name, account],
                    Some(display_name.as_str()),
                )?]
            } else {
                vec![line(&source, "JOIN", &[&name], None)?]
            }
        }
        ProjectedEvent::MemberParted {
            channel_id,
            source,
            reason,
            ..
        } => {
            let Some(name) = name_of(*channel_id) else {
                return Ok(Vec::new());
            };
            let trailing = (!reason.is_empty()).then_some(reason.as_str());
            vec![line(&prefix(source)?, "PART", &[&name], trailing)?]
        }
        ProjectedEvent::Kicked {
            channel_id,
            actor,
            target,
            reason,
            ..
        } => {
            let Some(name) = name_of(*channel_id) else {
                return Ok(Vec::new());
            };
            vec![line(
                &actor_prefix(edge, actor)?,
                "KICK",
                &[&name, target.nickname.presentation()],
                Some(reason),
            )?]
        }
        ProjectedEvent::TopicChanged {
            channel_id,
            actor,
            topic,
            ..
        } => {
            let Some(name) = name_of(*channel_id) else {
                return Ok(Vec::new());
            };
            let text = topic.as_ref().map_or("", |(text, _, _)| text.as_str());
            vec![line(&prefix(actor)?, "TOPIC", &[&name], Some(text))?]
        }
        ProjectedEvent::ChannelModesChanged {
            channel_id,
            actor,
            changes,
            ..
        } => {
            let Some(name) = name_of(*channel_id) else {
                return Ok(Vec::new());
            };
            let (modes, arguments) = mode_text(changes);
            let mut middle: Vec<&str> = vec![&name, &modes];
            middle.extend(arguments.iter().map(String::as_str));
            vec![line(&actor_prefix(edge, actor)?, "MODE", &middle, None)?]
        }
        ProjectedEvent::Invited {
            channel_id,
            inviter,
            named_target,
            ..
        } => {
            let Some(name) = name_of(*channel_id) else {
                return Ok(Vec::new());
            };
            if recipient == named_target.user_id {
                vec![line(
                    &prefix(inviter)?,
                    "INVITE",
                    &[named_target.nickname.presentation()],
                    Some(&name),
                )?]
            } else if recipient == inviter.user_id {
                vec![numeric(
                    server,
                    341,
                    inviter.nickname.presentation(),
                    &[named_target.nickname.presentation(), &name],
                    None,
                )?]
            } else {
                Vec::new()
            }
        }
        ProjectedEvent::AwayChanged { view, away } => {
            if !enabled(capabilities, "away-notify") {
                Vec::new()
            } else {
                vec![line(&prefix(&view.source)?, "AWAY", &[], away.as_deref())?]
            }
        }
        ProjectedEvent::DisplayNameChanged { view, display_name } => {
            if !enabled(capabilities, "setname") {
                Vec::new()
            } else {
                vec![line(
                    &prefix(&view.source)?,
                    "SETNAME",
                    &[],
                    Some(display_name.as_str()),
                )?]
            }
        }
        ProjectedEvent::AccountLabelChanged(view) => {
            if !enabled(capabilities, "account-notify") {
                Vec::new()
            } else {
                let label = view
                    .source
                    .account_label
                    .as_ref()
                    .map_or("*", |label| label.as_str());
                vec![line(&prefix(&view.source)?, "ACCOUNT", &[label], None)?]
            }
        }
        ProjectedEvent::MessageDelivered(record) => {
            if record.sender.user_id == recipient && !enabled(capabilities, "echo-message") {
                return Ok(Vec::new());
            }
            let target = match record.target {
                DeliveryTarget::Channel(channel_id) => channel_name(edge, channel_id),
                DeliveryTarget::User(user_id) => edge
                    .replica
                    .session(user_id)
                    .map(|session| session.nickname.presentation().to_owned()),
            };
            let Some(target) = target else {
                return Ok(Vec::new());
            };
            let command = match record.kind {
                MessageKind::Privmsg => "PRIVMSG",
                MessageKind::Notice => "NOTICE",
                MessageKind::Tagmsg => "TAGMSG",
            };
            let trailing = (record.kind != MessageKind::Tagmsg).then_some(record.body.as_str());
            let mut frame = line(&prefix(&record.sender)?, command, &[&target], trailing)?;
            if let Some(capabilities) = capabilities.filter(|state| state.enabled("message-tags")) {
                for (key, value) in &record.tags {
                    let _added = frame.add_client_only_tag(
                        capabilities,
                        key,
                        (!value.is_empty()).then_some(value.as_str()),
                    );
                }
            }
            vec![frame]
        }
        ProjectedEvent::NetworkNotice { text, .. } => {
            let nickname = edge
                .replica
                .session(recipient)
                .map(|session| session.nickname.presentation().to_owned())
                .unwrap_or_else(|| "*".to_owned());
            vec![line(server, "NOTICE", &[&nickname], Some(text))?]
        }
        ProjectedEvent::UserModesChanged(record) if recipient == record.user_id => {
            let mode = if record.user_mode_bits & 2 == 0 {
                "-w"
            } else {
                "+w"
            };
            vec![line(
                &prefix(&record.source_view())?,
                "MODE",
                &[record.nickname.presentation(), mode],
                None,
            )?]
        }
        ProjectedEvent::SessionVisible(_)
        | ProjectedEvent::ChannelVisible(_)
        | ProjectedEvent::ChannelHidden { .. }
        | ProjectedEvent::ChannelDestroyed { .. }
        | ProjectedEvent::InviteRemoved { .. }
        | ProjectedEvent::UserModesChanged(_)
        | ProjectedEvent::ChannelPolicyChanged(_)
        | ProjectedEvent::ChannelMembershipsRecomputed { .. }
        | ProjectedEvent::AccountStateChanged(_)
        | ProjectedEvent::RequestCompleted { .. } => Vec::new(),
    };
    Ok(frames)
}

/// Renders projected mode changes as one mode string and its arguments.
fn mode_text(changes: &[ProjectedModeChange]) -> (String, Vec<String>) {
    let mut modes = String::new();
    let mut arguments = Vec::new();
    let mut direction: Option<ModeDirection> = None;
    for change in changes {
        if direction != Some(change.direction()) {
            modes.push(match change.direction() {
                ModeDirection::Add => '+',
                ModeDirection::Remove => '-',
            });
            direction = Some(change.direction());
        }
        let (letter, argument) = match change {
            ProjectedModeChange::List { entry, .. } => {
                (mode_letter(entry.mode_code), Some(entry.mask.clone()))
            }
            ProjectedModeChange::Key { present, .. } => ('k', present.then(|| "*".to_owned())),
            ProjectedModeChange::Limit { limit, direction } => (
                'l',
                (*direction == ModeDirection::Add).then(|| limit.to_string()),
            ),
            ProjectedModeChange::Simple { mode_code, .. } => (mode_letter(*mode_code), None),
            ProjectedModeChange::Prefix {
                mode_code, view, ..
            } => (
                mode_letter(*mode_code),
                Some(view.source.nickname.presentation().to_owned()),
            ),
        };
        modes.push(letter);
        arguments.extend(argument);
    }
    (modes, arguments)
}

const fn mode_letter(code: u16) -> char {
    match code {
        1 => 'b',
        2 => 'e',
        3 => 'I',
        4 => 'k',
        5 => 'l',
        6 => 'i',
        7 => 'm',
        8 => 'n',
        9 => 'p',
        10 => 's',
        11 => 't',
        12 => 'q',
        13 => 'a',
        14 => 'o',
        15 => 'h',
        _ => 'v',
    }
}
