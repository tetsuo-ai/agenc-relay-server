//! Commit-coupled rendering for successful registered mutations.

use std::collections::{BTreeMap, BTreeSet};

use agenc_ircd_client_wire::{
    CapabilityState, ReplyKind, SafeReplyContext, SafeReplyDescription, WireMessage, numeric_reply,
    standard_reply,
};
use agenc_ircd_domain::{
    AccountCommand, CanonicalCommand, CanonicalCommandView, ChannelCommand, ChannelNameValue,
    DomainEvent, DomainState, MaskList, Membership, MessageBatch, MessageKind, ModeChange,
    ModeCommand, ModeOperation, MutationPlan, PresenceCommand, ResolvedMessageTarget, Role,
    VisibilityMode,
};
use agenc_ircd_types::{
    AccountDeletionToken, AccountId, ChannelName, MaskSubject, PublicErrorCode, TypedMask, UserId,
    UtcSecond,
};

use crate::RuntimeError;
use crate::client_render::ReplyInput;
use crate::state_core::StateCoreContext;
use crate::state_core::fanout::{FanoutFrame, FanoutRequest, FanoutTarget};
use crate::state_core::session::BoundSession;

const NAMES_CHUNK_BYTES: usize = 8_000;

pub(crate) fn render_mutation(
    context: &StateCoreContext,
    bound: BoundSession,
    reply: Option<ReplyInput<'_>>,
    command: &CanonicalCommand,
    plan: &MutationPlan,
) -> Result<FanoutRequest, RuntimeError> {
    if plan.expected_revision() != context.domain().revision() {
        return Err(RuntimeError::InvalidValue);
    }
    let mut builder = FanoutBuilder::new(context, plan, reply)?;
    let session = context
        .domain()
        .session(bound.user_id)
        .ok_or(RuntimeError::InvalidValue)?;
    let source = session_prefix(session)?;
    render_command(&mut builder, plan, bound.user_id, &source, command.view())?;
    builder.append_failures(plan)?;
    builder.finish()
}

pub(crate) fn render_account_logout(
    context: &StateCoreContext,
    bound: BoundSession,
    plan: &MutationPlan,
) -> Result<FanoutRequest, RuntimeError> {
    if plan.expected_revision() != context.domain().revision() {
        return Err(RuntimeError::InvalidValue);
    }
    require_event(plan, DomainEvent::SessionAuthorityChanged(bound.user_id))?;
    let session = context
        .domain()
        .session(bound.user_id)
        .ok_or(RuntimeError::InvalidValue)?;
    if session.account_id().is_none() {
        return Err(RuntimeError::InvalidValue);
    }
    let source = session_prefix(session)?;
    let mut builder = FanoutBuilder::new(context, plan, None)?;
    let recipients: Vec<_> = plan.recipients().iter().collect();
    let notified = builder.users_with_capability(&recipients, "account-notify");
    builder.add_simple(&source, "ACCOUNT", &["*".to_owned()], None, &notified)?;
    builder.finish()
}

/// Renders the terminal credential receipt to its requester and the exact
/// public session departures to their pre-mutation audiences.
pub(crate) fn render_account_credential_replacement(
    context: &StateCoreContext,
    account_id: AccountId,
    initiating_user: UserId,
    terminal_frames: Vec<WireMessage>,
    plan: &MutationPlan,
) -> Result<FanoutRequest, RuntimeError> {
    if plan.expected_revision() != context.domain().revision() {
        return Err(RuntimeError::InvalidValue);
    }
    require_event(plan, DomainEvent::AccountCredentialReplaced(account_id))?;
    let hidden: Vec<UserId> = plan
        .events()
        .iter()
        .filter_map(|event| match event {
            DomainEvent::SessionHidden(user_id) => Some(*user_id),
            _ => None,
        })
        .collect();
    if !hidden.contains(&initiating_user) {
        return Err(RuntimeError::InvalidValue);
    }
    let mut builder = FanoutBuilder::new(context, plan, None)?;
    for frame in terminal_frames {
        builder.push_to_user(frame, initiating_user)?;
    }
    for user_id in hidden {
        let session = context
            .domain()
            .session(user_id)
            .filter(|session| session.account_id() == Some(account_id))
            .ok_or(RuntimeError::InvalidValue)?;
        let source = session_prefix(session)?;
        let recipients: Vec<UserId> = context
            .domain()
            .session_fanout_recipients(user_id)
            .map_err(|_| RuntimeError::InvalidValue)?
            .iter()
            .filter(|recipient| *recipient != user_id && *recipient != initiating_user)
            .collect();
        render_credential_quit(
            &mut builder,
            plan,
            user_id,
            &source,
            "connection closed",
            &recipients,
        )?;
    }
    builder.finish()
}

fn render_command(
    builder: &mut FanoutBuilder<'_, '_>,
    plan: &MutationPlan,
    user_id: UserId,
    source: &str,
    command: CanonicalCommandView<'_>,
) -> Result<(), RuntimeError> {
    match command {
        CanonicalCommandView::Nick(nickname) => {
            render_nick(builder, plan, user_id, source, nickname.presentation())
        }
        CanonicalCommandView::Quit(reason) => render_quit(
            builder,
            plan,
            user_id,
            source,
            reason.map_or("connection closed", |value| value.as_str()),
        ),
        CanonicalCommandView::Join(_)
        | CanonicalCommandView::Part(_, _)
        | CanonicalCommandView::PartAll
        | CanonicalCommandView::Mode(_)
        | CanonicalCommandView::TopicSet(_, _)
        | CanonicalCommandView::Invite(_, _)
        | CanonicalCommandView::Kick(_, _, _) => {
            render_channel_command(builder, plan, user_id, source, command)
        }
        CanonicalCommandView::Message(_)
        | CanonicalCommandView::Presence(_)
        | CanonicalCommandView::Setname(_)
        | CanonicalCommandView::Account(_)
        | CanonicalCommandView::Channel(_) => {
            render_user_command(builder, plan, user_id, source, command)
        }
        CanonicalCommandView::TopicQuery(_)
        | CanonicalCommandView::Names(_)
        | CanonicalCommandView::List(_)
        | CanonicalCommandView::Information(_)
        | CanonicalCommandView::UserQuery(_)
        | CanonicalCommandView::Chathistory(_, _) => Err(RuntimeError::InvalidValue),
    }
}

fn render_channel_command(
    builder: &mut FanoutBuilder<'_, '_>,
    plan: &MutationPlan,
    user_id: UserId,
    source: &str,
    command: CanonicalCommandView<'_>,
) -> Result<(), RuntimeError> {
    match command {
        CanonicalCommandView::Join(targets) => render_join(builder, plan, user_id, source, targets),
        CanonicalCommandView::Part(_, reason) => render_parts(
            builder,
            plan,
            user_id,
            source,
            reason.map(|value| value.as_str()),
        ),
        CanonicalCommandView::PartAll => render_parts(builder, plan, user_id, source, None),
        CanonicalCommandView::Mode(mode) => render_mode(builder, plan, user_id, source, mode),
        CanonicalCommandView::TopicSet(channel, topic) => {
            render_topic(builder, plan, user_id, source, channel, topic.as_str())
        }
        CanonicalCommandView::Invite(target, channel) => {
            render_invite(builder, plan, user_id, source, target, channel)
        }
        CanonicalCommandView::Kick(channel, _, reason) => render_kicks(
            builder,
            plan,
            user_id,
            source,
            channel,
            reason.map(|value| value.as_str()),
        ),
        _ => Err(RuntimeError::InvalidValue),
    }
}

fn render_user_command(
    builder: &mut FanoutBuilder<'_, '_>,
    plan: &MutationPlan,
    user_id: UserId,
    source: &str,
    command: CanonicalCommandView<'_>,
) -> Result<(), RuntimeError> {
    match command {
        CanonicalCommandView::Message(_) => render_messages(builder, plan, user_id, source),
        CanonicalCommandView::Presence(presence) => {
            render_presence(builder, plan, user_id, source, presence)
        }
        CanonicalCommandView::Setname(display_name) => {
            render_setname(builder, plan, user_id, source, display_name.as_str())
        }
        CanonicalCommandView::Account(account) => render_account(builder, plan, account),
        CanonicalCommandView::Channel(channel) => render_channel_control(builder, plan, channel),
        _ => Err(RuntimeError::InvalidValue),
    }
}

struct FanoutBuilder<'context, 'reply> {
    context: &'context StateCoreContext,
    reply: Option<ReplyInput<'reply>>,
    indices: BTreeMap<UserId, usize>,
    targets: Vec<FanoutTarget>,
    frames: Vec<FanoutFrame>,
    origin_semantic: Vec<WireMessage>,
}

impl<'context, 'reply> FanoutBuilder<'context, 'reply> {
    fn new(
        context: &'context StateCoreContext,
        plan: &MutationPlan,
        reply: Option<ReplyInput<'reply>>,
    ) -> Result<Self, RuntimeError> {
        let mut users: BTreeSet<UserId> = plan.recipients().iter().collect();
        if let Some(reply) = reply {
            users.insert(reply.requester);
        }
        let mut indices = BTreeMap::new();
        let mut targets = Vec::new();
        targets
            .try_reserve_exact(users.len())
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        for user_id in users {
            let Some((generation, sink)) = context.sessions().sink_for_user(user_id) else {
                continue;
            };
            let index = targets.len();
            targets.push(FanoutTarget { generation, sink });
            indices.insert(user_id, index);
        }
        Ok(Self {
            context,
            reply,
            indices,
            targets,
            frames: Vec::new(),
            origin_semantic: Vec::new(),
        })
    }

    fn add_simple(
        &mut self,
        prefix: &str,
        command: &str,
        middle: &[String],
        trailing: Option<&str>,
        users: &[UserId],
    ) -> Result<(), RuntimeError> {
        let parameters: Vec<&str> = middle.iter().map(String::as_str).collect();
        let common = WireMessage::new(prefix, command, &parameters, trailing)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let origin = WireMessage::new(prefix, command, &parameters, trailing)
            .map_err(|_| RuntimeError::InvalidValue)?;
        self.add_pair(common, origin, users)
    }

    fn add_pair(
        &mut self,
        common: WireMessage,
        origin: WireMessage,
        users: &[UserId],
    ) -> Result<(), RuntimeError> {
        let origin_user = self.reply.map(|reply| reply.requester);
        let mut recipients = BTreeSet::new();
        let mut origin_receives = false;
        for user_id in users {
            if Some(*user_id) == origin_user {
                origin_receives = self.indices.contains_key(user_id);
            } else if let Some(index) = self.indices.get(user_id) {
                recipients.insert(*index);
            }
        }
        if !recipients.is_empty() {
            self.frames
                .try_reserve(1)
                .map_err(|_| RuntimeError::MemoryExhausted)?;
            self.frames
                .push(FanoutFrame::new(common, recipients.into_iter().collect())?);
        }
        if origin_receives {
            self.push_origin(origin)?;
        }
        Ok(())
    }

    fn push_origin(&mut self, message: WireMessage) -> Result<(), RuntimeError> {
        self.origin_semantic
            .try_reserve(1)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        self.origin_semantic.push(message);
        Ok(())
    }

    fn push_to_user(&mut self, message: WireMessage, user_id: UserId) -> Result<(), RuntimeError> {
        let Some(index) = self.indices.get(&user_id).copied() else {
            return Ok(());
        };
        self.frames
            .try_reserve(1)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        self.frames.push(FanoutFrame::new(message, vec![index])?);
        Ok(())
    }

    fn capabilities(&self, user_id: UserId) -> Option<&CapabilityState> {
        self.context.sessions().capabilities_for_user(user_id)
    }

    fn users_with_capability(&self, users: &[UserId], capability: &str) -> Vec<UserId> {
        users
            .iter()
            .copied()
            .filter(|user_id| {
                self.capabilities(*user_id)
                    .is_some_and(|capabilities| capabilities.enabled(capability))
            })
            .collect()
    }

    fn append_failures(&mut self, plan: &MutationPlan) -> Result<(), RuntimeError> {
        let Some(reply) = self.reply else {
            return Ok(());
        };
        if plan
            .message_batch()
            .is_some_and(|batch| batch.kind() == MessageKind::Notice)
        {
            return Ok(());
        }
        let nickname = crate::client_render::requester_nickname(self.context, reply.requester);
        for failure in plan.failures() {
            let frame = crate::client_render::failure_frame(
                reply.capabilities,
                self.context.server_prefix(),
                &nickname,
                reply.request,
                failure.error(),
                Some(failure.target()),
            )?;
            self.push_origin(frame)?;
        }
        Ok(())
    }

    fn finish(mut self) -> Result<FanoutRequest, RuntimeError> {
        if let Some(reply) = self.reply
            && let Some(index) = self.indices.get(&reply.requester).copied()
        {
            let logical = crate::client_render::logical_frames(
                self.context.server_prefix(),
                reply.capabilities,
                reply.request,
                self.origin_semantic,
            )?;
            self.frames
                .try_reserve(logical.len())
                .map_err(|_| RuntimeError::MemoryExhausted)?;
            for message in logical {
                self.frames.push(FanoutFrame::new(message, vec![index])?);
            }
        }
        FanoutRequest::new(self.targets, self.frames)
    }
}

fn render_nick(
    builder: &mut FanoutBuilder<'_, '_>,
    plan: &MutationPlan,
    user_id: UserId,
    source: &str,
    nickname: &str,
) -> Result<(), RuntimeError> {
    require_event(plan, DomainEvent::NicknameChanged(user_id))?;
    let users: Vec<_> = plan.recipients().iter().collect();
    builder.add_simple(source, "NICK", &[], Some(nickname), &users)
}

fn render_quit(
    builder: &mut FanoutBuilder<'_, '_>,
    plan: &MutationPlan,
    user_id: UserId,
    source: &str,
    reason: &str,
) -> Result<(), RuntimeError> {
    require_event(plan, DomainEvent::SessionHidden(user_id))?;
    let users: Vec<_> = plan.recipients().iter().collect();
    builder.add_simple(source, "QUIT", &[], Some(reason), &users)
}

fn render_credential_quit(
    builder: &mut FanoutBuilder<'_, '_>,
    plan: &MutationPlan,
    user_id: UserId,
    source: &str,
    reason: &str,
    users: &[UserId],
) -> Result<(), RuntimeError> {
    require_event(plan, DomainEvent::SessionHidden(user_id))?;
    builder.add_simple(source, "QUIT", &[], Some(reason), users)
}

fn render_join(
    builder: &mut FanoutBuilder<'_, '_>,
    plan: &MutationPlan,
    user_id: UserId,
    source: &str,
    targets: &[agenc_ircd_domain::ChannelTarget],
) -> Result<(), RuntimeError> {
    let failed: BTreeSet<usize> = plan
        .failures()
        .iter()
        .map(|failure| usize::from(failure.target_index()))
        .collect();
    let mut joined = plan.events().iter().filter_map(|event| match event {
        DomainEvent::Joined(channel_id, joined_user) if *joined_user == user_id => {
            Some(*channel_id)
        }
        _ => None,
    });
    for (index, target) in targets.iter().enumerate() {
        if failed.contains(&index) {
            continue;
        }
        let channel_id = joined.next().ok_or(RuntimeError::InvalidValue)?;
        render_join_target(builder, user_id, source, target.name(), channel_id)?;
    }
    if joined.next().is_some() {
        return Err(RuntimeError::InvalidValue);
    }
    Ok(())
}

fn render_join_target(
    builder: &mut FanoutBuilder<'_, '_>,
    user_id: UserId,
    source: &str,
    name: &ChannelNameValue,
    channel_id: agenc_ircd_types::ChannelInstanceId,
) -> Result<(), RuntimeError> {
    let existing = builder.context.domain().channel(channel_id);
    if existing.is_some_and(|channel| channel.name() != name) {
        return Err(RuntimeError::InvalidValue);
    }
    let mut users: Vec<_> = existing
        .map(|channel| channel.members().collect())
        .unwrap_or_default();
    if !users.contains(&user_id) {
        users.push(user_id);
    }
    users.sort_unstable();
    let extended = builder.users_with_capability(&users, "extended-join");
    let base: Vec<_> = users
        .iter()
        .copied()
        .filter(|candidate| !extended.contains(candidate))
        .collect();
    if !base.is_empty() {
        builder.add_simple(
            source,
            "JOIN",
            &[name.presentation().to_owned()],
            None,
            &base,
        )?;
    }
    if !extended.is_empty() {
        let session = builder
            .context
            .domain()
            .session(user_id)
            .ok_or(RuntimeError::InvalidValue)?;
        let account = public_account_label(builder.context.domain(), session).unwrap_or("*");
        builder.add_simple(
            source,
            "JOIN",
            &[name.presentation().to_owned(), account.to_owned()],
            Some(session.display_name().as_str()),
            &extended,
        )?;
    }
    render_join_burst(builder, user_id, name, existing)
}

fn render_join_burst(
    builder: &mut FanoutBuilder<'_, '_>,
    user_id: UserId,
    name: &ChannelNameValue,
    channel: Option<&agenc_ircd_domain::ChannelState>,
) -> Result<(), RuntimeError> {
    let Some(reply) = builder.reply else {
        return Ok(());
    };
    if reply.requester != user_id || !builder.indices.contains_key(&user_id) {
        return Ok(());
    }
    let nickname = builder
        .context
        .domain()
        .session(user_id)
        .ok_or(RuntimeError::InvalidValue)?
        .nickname()
        .presentation();
    render_join_topic(builder, nickname, name, channel)?;
    render_join_names(
        builder,
        reply.capabilities,
        nickname,
        name,
        user_id,
        channel,
    )
}

fn render_join_topic(
    builder: &mut FanoutBuilder<'_, '_>,
    nickname: &str,
    name: &ChannelNameValue,
    channel: Option<&agenc_ircd_domain::ChannelState>,
) -> Result<(), RuntimeError> {
    let prefix = builder.context.server_prefix();
    let Some(topic) = channel.and_then(agenc_ircd_domain::ChannelState::topic) else {
        return builder.push_origin(numeric(
            prefix,
            331,
            nickname,
            &[name.presentation()],
            Some("No topic is set"),
        )?);
    };
    builder.push_origin(numeric(
        prefix,
        332,
        nickname,
        &[name.presentation()],
        Some(topic.text()),
    )?)?;
    let setter = builder
        .context
        .domain()
        .session(topic.setter())
        .map(|session| session.nickname().presentation())
        .unwrap_or(builder.context.server_prefix());
    builder.push_origin(numeric(
        prefix,
        333,
        nickname,
        &[
            name.presentation(),
            setter,
            &topic.set_at().get().to_string(),
        ],
        None,
    )?)
}

fn render_join_names(
    builder: &mut FanoutBuilder<'_, '_>,
    capabilities: &CapabilityState,
    nickname: &str,
    name: &ChannelNameValue,
    user_id: UserId,
    channel: Option<&agenc_ircd_domain::ChannelState>,
) -> Result<(), RuntimeError> {
    let mut members: Vec<_> = channel
        .map(|channel| channel.members().collect())
        .unwrap_or_default();
    if !members.contains(&user_id) {
        members.push(user_id);
    }
    members.sort_unstable();
    let mut chunk = String::new();
    for member in members {
        let session = builder
            .context
            .domain()
            .session(member)
            .ok_or(RuntimeError::InvalidValue)?;
        let role = if member == user_id {
            channel.map_or(Role::Owner, |channel| {
                channel.effective_role(Membership::new(user_id, session.account_id(), Role::Member))
            })
        } else {
            channel
                .and_then(|channel| channel.role_of(member))
                .ok_or(RuntimeError::InvalidValue)?
        };
        let token = names_token(session, role, capabilities.enabled("userhost-in-names"))?;
        if !chunk.is_empty()
            && chunk.len().saturating_add(1).saturating_add(token.len()) > NAMES_CHUNK_BYTES
        {
            push_names_chunk(builder, nickname, name, &chunk)?;
            chunk.clear();
        }
        if !chunk.is_empty() {
            chunk.push(' ');
        }
        chunk.push_str(&token);
    }
    push_names_chunk(builder, nickname, name, &chunk)?;
    builder.push_origin(numeric(
        builder.context.server_prefix(),
        366,
        nickname,
        &[name.presentation()],
        Some("End of /NAMES list"),
    )?)
}

fn push_names_chunk(
    builder: &mut FanoutBuilder<'_, '_>,
    nickname: &str,
    name: &ChannelNameValue,
    chunk: &str,
) -> Result<(), RuntimeError> {
    builder.push_origin(numeric(
        builder.context.server_prefix(),
        353,
        nickname,
        &["=", name.presentation()],
        Some(chunk),
    )?)
}

fn names_token(
    session: &agenc_ircd_domain::SessionState,
    role: Role,
    include_userhost: bool,
) -> Result<String, RuntimeError> {
    let mut token = String::new();
    if let Some(prefix) = role_prefix(role) {
        token.push(prefix);
    }
    token.push_str(session.nickname().presentation());
    if include_userhost {
        let cloak = session.public_cloak();
        token.push('!');
        token.push_str(ascii(cloak.user_component())?);
        token.push('@');
        token.push_str(ascii(cloak.host_component())?);
    }
    Ok(token)
}

fn render_parts(
    builder: &mut FanoutBuilder<'_, '_>,
    plan: &MutationPlan,
    user_id: UserId,
    source: &str,
    reason: Option<&str>,
) -> Result<(), RuntimeError> {
    for event in plan.events() {
        let DomainEvent::Parted(channel_id, parted_user) = event else {
            continue;
        };
        if *parted_user != user_id {
            return Err(RuntimeError::InvalidValue);
        }
        let channel = builder
            .context
            .domain()
            .channel(*channel_id)
            .ok_or(RuntimeError::InvalidValue)?;
        let users: Vec<_> = channel.members().collect();
        builder.add_simple(
            source,
            "PART",
            &[channel.name().presentation().to_owned()],
            reason,
            &users,
        )?;
    }
    Ok(())
}

fn render_mode(
    builder: &mut FanoutBuilder<'_, '_>,
    plan: &MutationPlan,
    user_id: UserId,
    source: &str,
    mode: &ModeCommand,
) -> Result<(), RuntimeError> {
    match mode {
        ModeCommand::UserOperatorNotices(nickname, enabled) => {
            let users = [user_id];
            builder.add_simple(
                source,
                "MODE",
                &[
                    nickname.presentation().to_owned(),
                    if *enabled { "+w" } else { "-w" }.to_owned(),
                ],
                None,
                &users,
            )
        }
        ModeCommand::ChannelChange(name, changes) => {
            let channel_id = builder
                .context
                .domain()
                .resolve_channel(name)
                .ok_or(RuntimeError::InvalidValue)?;
            require_event(plan, DomainEvent::ChannelModesChanged(channel_id))?;
            let channel = builder
                .context
                .domain()
                .channel(channel_id)
                .ok_or(RuntimeError::InvalidValue)?;
            let parameters = mode_parameters(channel, name, changes)?;
            let users: Vec<_> = channel.members().collect();
            builder.add_simple(source, "MODE", &parameters, None, &users)
        }
        ModeCommand::UserQuery(_)
        | ModeCommand::ChannelQuery(_)
        | ModeCommand::ChannelList(_, _) => Err(RuntimeError::InvalidValue),
    }
}

fn mode_parameters(
    channel: &agenc_ircd_domain::ChannelState,
    name: &ChannelNameValue,
    changes: &[ModeChange],
) -> Result<Vec<String>, RuntimeError> {
    let mut modes = String::new();
    let mut arguments = Vec::new();
    let mut direction = None;
    for change in changes {
        let (operation, letter, argument) = mode_change_text(channel, change)?;
        if direction != Some(operation) {
            modes.push(match operation {
                ModeOperation::Add => '+',
                ModeOperation::Remove => '-',
            });
            direction = Some(operation);
        }
        modes.push(letter);
        if let Some(argument) = argument {
            arguments.push(argument);
        }
    }
    let mut parameters = Vec::new();
    parameters.push(name.presentation().to_owned());
    parameters.push(modes);
    parameters.extend(arguments);
    Ok(parameters)
}

fn mode_change_text(
    channel: &agenc_ircd_domain::ChannelState,
    change: &ModeChange,
) -> Result<(ModeOperation, char, Option<String>), RuntimeError> {
    let value = match change {
        ModeChange::Visibility { operation, mode } => (
            *operation,
            match mode {
                VisibilityMode::Unlisted => 'p',
                VisibilityMode::Secret => 's',
            },
            None,
        ),
        ModeChange::InviteOnly(enabled) => (operation(*enabled), 'i', None),
        ModeChange::Moderated(enabled) => (operation(*enabled), 'm', None),
        ModeChange::TopicProtected(enabled) => (operation(*enabled), 't', None),
        ModeChange::JoinKey(enabled) => (operation(*enabled), 'k', None),
        ModeChange::MemberLimit(limit) => (
            operation(limit.is_some()),
            'l',
            limit.map(|limit| limit.to_string()),
        ),
        ModeChange::Role {
            operation,
            target,
            role,
        } => (
            *operation,
            role_letter(*role)?,
            Some(target.presentation().to_owned()),
        ),
        ModeChange::AddMask { list, mask } => (
            ModeOperation::Add,
            list_letter(*list),
            Some(typed_mask_text(mask)),
        ),
        ModeChange::RemoveMask { list, entry_id } => {
            let entry = channel
                .mask_list(*list)
                .iter()
                .find(|entry| entry.entry_id() == *entry_id)
                .ok_or(RuntimeError::InvalidValue)?;
            (
                ModeOperation::Remove,
                list_letter(*list),
                Some(typed_mask_text(entry.mask())),
            )
        }
    };
    Ok(value)
}

fn render_topic(
    builder: &mut FanoutBuilder<'_, '_>,
    plan: &MutationPlan,
    _user_id: UserId,
    source: &str,
    name: &ChannelNameValue,
    topic: &str,
) -> Result<(), RuntimeError> {
    let channel_id = builder
        .context
        .domain()
        .resolve_channel(name)
        .ok_or(RuntimeError::InvalidValue)?;
    if !plan
        .events()
        .iter()
        .any(|event| matches!(event, DomainEvent::TopicChanged(id, _) if *id == channel_id))
    {
        return Err(RuntimeError::InvalidValue);
    }
    let channel = builder
        .context
        .domain()
        .channel(channel_id)
        .ok_or(RuntimeError::InvalidValue)?;
    let users: Vec<_> = channel.members().collect();
    builder.add_simple(
        source,
        "TOPIC",
        &[name.presentation().to_owned()],
        Some(topic),
        &users,
    )
}

fn render_invite(
    builder: &mut FanoutBuilder<'_, '_>,
    plan: &MutationPlan,
    user_id: UserId,
    source: &str,
    target: &agenc_ircd_domain::NicknameValue,
    channel: &ChannelNameValue,
) -> Result<(), RuntimeError> {
    if !plan
        .events()
        .iter()
        .any(|event| matches!(event, DomainEvent::InviteCreated(_, _)))
    {
        return Err(RuntimeError::InvalidValue);
    }
    let target_user = builder
        .context
        .domain()
        .resolve_nickname(target)
        .ok_or(RuntimeError::InvalidValue)?;
    builder.add_simple(
        source,
        "INVITE",
        &[
            target.presentation().to_owned(),
            channel.presentation().to_owned(),
        ],
        None,
        &[target_user],
    )?;
    if builder
        .reply
        .is_some_and(|reply| reply.requester == user_id)
    {
        let nickname = builder
            .context
            .domain()
            .session(user_id)
            .ok_or(RuntimeError::InvalidValue)?
            .nickname()
            .presentation();
        builder.push_origin(numeric(
            builder.context.server_prefix(),
            341,
            nickname,
            &[target.presentation(), channel.presentation()],
            None,
        )?)?;
    }
    Ok(())
}

fn render_kicks(
    builder: &mut FanoutBuilder<'_, '_>,
    plan: &MutationPlan,
    _user_id: UserId,
    source: &str,
    name: &ChannelNameValue,
    reason: Option<&str>,
) -> Result<(), RuntimeError> {
    let channel_id = builder
        .context
        .domain()
        .resolve_channel(name)
        .ok_or(RuntimeError::InvalidValue)?;
    let channel = builder
        .context
        .domain()
        .channel(channel_id)
        .ok_or(RuntimeError::InvalidValue)?;
    let users: Vec<_> = channel.members().collect();
    for event in plan.events() {
        let DomainEvent::Parted(event_channel, target_user) = event else {
            continue;
        };
        if *event_channel != channel_id {
            return Err(RuntimeError::InvalidValue);
        }
        let target = builder
            .context
            .domain()
            .session(*target_user)
            .ok_or(RuntimeError::InvalidValue)?
            .nickname()
            .presentation();
        builder.add_simple(
            source,
            "KICK",
            &[name.presentation().to_owned(), target.to_owned()],
            reason,
            &users,
        )?;
    }
    Ok(())
}

fn render_messages(
    builder: &mut FanoutBuilder<'_, '_>,
    plan: &MutationPlan,
    sender: UserId,
    source: &str,
) -> Result<(), RuntimeError> {
    let batch = plan.message_batch().ok_or(RuntimeError::InvalidValue)?;
    if batch.sender() != sender {
        return Err(RuntimeError::InvalidValue);
    }
    for route in batch.routes() {
        let target = message_target(builder.context.domain(), route.target())?;
        let users: Vec<_> = route
            .recipients()
            .iter()
            .filter(|recipient| {
                *recipient != sender
                    || builder
                        .capabilities(sender)
                        .is_some_and(|capabilities| capabilities.enabled("echo-message"))
            })
            .collect();
        render_message_route(builder, batch, route.message_id(), source, &target, &users)?;
    }
    Ok(())
}

fn render_message_route(
    builder: &mut FanoutBuilder<'_, '_>,
    batch: &MessageBatch,
    message_id: agenc_ircd_types::MessageId,
    source: &str,
    target: &str,
    users: &[UserId],
) -> Result<(), RuntimeError> {
    let mut groups: BTreeMap<u8, Vec<UserId>> = BTreeMap::new();
    for user_id in users {
        let capabilities = builder
            .capabilities(*user_id)
            .ok_or(RuntimeError::InvalidValue)?;
        let key = message_capability_key(capabilities);
        if batch.kind() == MessageKind::Tagmsg && key & 1 == 0 {
            continue;
        }
        groups.entry(key).or_default().push(*user_id);
    }
    for (key, recipients) in groups {
        let capabilities = builder
            .capabilities(*recipients.first().ok_or(RuntimeError::InvalidValue)?)
            .ok_or(RuntimeError::InvalidValue)?;
        let input = MessageWireInput {
            domain: builder.context.domain(),
            batch,
            message_id,
            source,
            target,
            request: builder.reply.map(|reply| reply.request),
        };
        let common = message_wire(&input, capabilities, key)?;
        let origin = message_wire(&input, capabilities, key)?;
        builder.add_pair(common, origin, &recipients)?;
    }
    Ok(())
}

struct MessageWireInput<'a> {
    domain: &'a DomainState,
    batch: &'a MessageBatch,
    message_id: agenc_ircd_types::MessageId,
    source: &'a str,
    target: &'a str,
    request: Option<&'a agenc_ircd_client_wire::ParsedMessage>,
}

fn message_wire(
    input: &MessageWireInput<'_>,
    capabilities: &CapabilityState,
    key: u8,
) -> Result<WireMessage, RuntimeError> {
    let command = match input.batch.kind() {
        MessageKind::Privmsg => "PRIVMSG",
        MessageKind::Notice => "NOTICE",
        MessageKind::Tagmsg => "TAGMSG",
    };
    let mut message = WireMessage::new(input.source, command, &[input.target], input.batch.body())
        .map_err(|_| RuntimeError::InvalidValue)?;
    if key & 2 != 0 {
        message
            .add_server_tag("msgid", Some(&input.message_id.to_base64url()))
            .map_err(|_| RuntimeError::InvalidValue)?;
    }
    if key & 4 != 0 {
        let timestamp = server_time(input.batch.accepted_at())?;
        message
            .add_server_tag("time", Some(&timestamp))
            .map_err(|_| RuntimeError::InvalidValue)?;
    }
    if key & 8 != 0
        && let Some(label) = sender_account_label(input.domain, input.batch.sender())
    {
        message
            .add_server_tag("account", Some(label))
            .map_err(|_| RuntimeError::InvalidValue)?;
    }
    if key & 1 != 0
        && let Some(request) = input.request
    {
        for tag in request.tags().iter().filter(|tag| tag.is_client_only()) {
            message
                .add_client_only_tag(capabilities, tag.key(), tag.value())
                .map_err(|_| RuntimeError::InvalidValue)?;
        }
    }
    Ok(message)
}

fn render_presence(
    builder: &mut FanoutBuilder<'_, '_>,
    plan: &MutationPlan,
    user_id: UserId,
    source: &str,
    presence: &PresenceCommand,
) -> Result<(), RuntimeError> {
    let PresenceCommand::Away(away) = presence else {
        return Ok(());
    };
    require_event(plan, DomainEvent::AwayChanged(user_id))?;
    let users: Vec<_> = plan.recipients().iter().collect();
    let notified = builder.users_with_capability(&users, "away-notify");
    if !notified.is_empty() {
        builder.add_simple(
            source,
            "AWAY",
            &[],
            away.as_ref().map(|value| value.as_str()),
            &notified,
        )?;
    }
    if builder
        .reply
        .is_some_and(|reply| reply.requester == user_id)
    {
        let nickname = builder
            .context
            .domain()
            .session(user_id)
            .ok_or(RuntimeError::InvalidValue)?
            .nickname()
            .presentation();
        let (code, text) = if away.is_some() {
            (306, "You have been marked as being away")
        } else {
            (305, "You are no longer marked as being away")
        };
        builder.push_origin(numeric(
            builder.context.server_prefix(),
            code,
            nickname,
            &[],
            Some(text),
        )?)?;
    }
    Ok(())
}

fn render_setname(
    builder: &mut FanoutBuilder<'_, '_>,
    plan: &MutationPlan,
    user_id: UserId,
    source: &str,
    display_name: &str,
) -> Result<(), RuntimeError> {
    require_event(plan, DomainEvent::DisplayNameChanged(user_id))?;
    let users: Vec<_> = plan.recipients().iter().collect();
    let notified = builder.users_with_capability(&users, "setname");
    if notified.is_empty() {
        return Ok(());
    }
    builder.add_simple(source, "SETNAME", &[], Some(display_name), &notified)
}

fn render_account(
    builder: &mut FanoutBuilder<'_, '_>,
    plan: &MutationPlan,
    command: &AccountCommand,
) -> Result<(), RuntimeError> {
    let Some(reply) = builder.reply else {
        return Err(RuntimeError::InvalidValue);
    };
    if matches!(command, AccountCommand::DeleteConfirm(_))
        && plan.events().iter().any(|event| {
            matches!(
                event,
                DomainEvent::AccountDeletionConfirmationRejected(user_id)
                    if *user_id == reply.requester
            )
        })
    {
        let nickname = crate::client_render::requester_nickname(builder.context, reply.requester);
        let frame = crate::client_render::failure_frame(
            reply.capabilities,
            builder.context.server_prefix(),
            &nickname,
            reply.request,
            agenc_ircd_domain::DomainError::BadState,
            None,
        )?;
        return builder.push_origin(frame);
    }
    if !reply.capabilities.enabled("standard-replies") {
        return Ok(());
    }
    let frame = match command {
        AccountCommand::DeleteStart => {
            let token = plan
                .account_deletion_token()
                .ok_or(RuntimeError::InvalidValue)?;
            let token = AccountDeletionToken::from_bytes(*token);
            standard_reply(
                reply.capabilities,
                builder.context.server_prefix(),
                ReplyKind::Note,
                "ACCT",
                PublicErrorCode::DELETECHALLENGE,
                &[SafeReplyContext::DeletionChallenge(&token)],
                description("Confirm account deletion")?,
            )
        }
        _ => standard_reply(
            reply.capabilities,
            builder.context.server_prefix(),
            ReplyKind::Note,
            "ACCT",
            PublicErrorCode::UPDATED,
            &[],
            description("Account setting updated")?,
        ),
    }
    .map_err(|_| RuntimeError::InvalidValue)?;
    builder.push_origin(frame)
}

fn render_channel_control(
    builder: &mut FanoutBuilder<'_, '_>,
    plan: &MutationPlan,
    command: ChannelCommand,
) -> Result<(), RuntimeError> {
    let channel_id = match command {
        ChannelCommand::Register(channel_id)
        | ChannelCommand::Unregister(channel_id)
        | ChannelCommand::History(channel_id, _) => channel_id,
    };
    require_event(plan, DomainEvent::ChannelPolicyChanged(channel_id))?;
    let Some(reply) = builder.reply else {
        return Err(RuntimeError::InvalidValue);
    };
    if !reply.capabilities.enabled("standard-replies") {
        return Ok(());
    }
    let channel = builder
        .context
        .domain()
        .channel(channel_id)
        .ok_or(RuntimeError::InvalidValue)?;
    let name = ChannelName::parse(channel.name().presentation())
        .map_err(|_| RuntimeError::InvalidValue)?;
    let frame = standard_reply(
        reply.capabilities,
        builder.context.server_prefix(),
        ReplyKind::Note,
        "CHANCTL",
        PublicErrorCode::UPDATED,
        &[SafeReplyContext::Channel(&name)],
        description("Channel setting updated")?,
    )
    .map_err(|_| RuntimeError::InvalidValue)?;
    builder.push_origin(frame)
}

fn require_event(plan: &MutationPlan, event: DomainEvent) -> Result<(), RuntimeError> {
    if plan.events().contains(&event) {
        Ok(())
    } else {
        Err(RuntimeError::InvalidValue)
    }
}

fn public_account_label<'a>(
    domain: &'a DomainState,
    session: &agenc_ircd_domain::SessionState,
) -> Option<&'a str> {
    let account_id = session.account_id()?;
    domain
        .account(account_id)?
        .label()
        .map(agenc_ircd_domain::AccountLabelValue::as_str)
}

fn sender_account_label(domain: &DomainState, sender: UserId) -> Option<&str> {
    public_account_label(domain, domain.session(sender)?)
}

fn message_target(
    domain: &DomainState,
    target: ResolvedMessageTarget,
) -> Result<String, RuntimeError> {
    match target {
        ResolvedMessageTarget::Channel(channel_id) => domain
            .channel(channel_id)
            .map(|channel| channel.name().presentation().to_owned())
            .ok_or(RuntimeError::InvalidValue),
        ResolvedMessageTarget::User(user_id) => domain
            .session(user_id)
            .map(|session| session.nickname().presentation().to_owned())
            .ok_or(RuntimeError::InvalidValue),
    }
}

fn message_capability_key(capabilities: &CapabilityState) -> u8 {
    u8::from(capabilities.enabled("message-tags"))
        | (u8::from(capabilities.enabled("message-ids")) << 1)
        | (u8::from(capabilities.enabled("server-time")) << 2)
        | (u8::from(capabilities.enabled("account-tag")) << 3)
}

fn session_prefix(session: &agenc_ircd_domain::SessionState) -> Result<String, RuntimeError> {
    let cloak = session.public_cloak();
    Ok(format!(
        "{}!{}@{}",
        session.nickname().presentation(),
        ascii(cloak.user_component())?,
        ascii(cloak.host_component())?
    ))
}

fn server_time(timestamp: UtcSecond) -> Result<String, RuntimeError> {
    let seconds = timestamp.get();
    let days = seconds / 86_400;
    let day_seconds = seconds % 86_400;
    let shifted = days.checked_add(719_468).ok_or(RuntimeError::Overflow)?;
    let era = shifted / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    year += u64::from(month <= 2);
    if year > 9_999 {
        return Err(RuntimeError::InvalidValue);
    }
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.000Z"
    ))
}

fn numeric(
    prefix: &str,
    code: u16,
    nickname: &str,
    middle: &[&str],
    trailing: Option<&str>,
) -> Result<WireMessage, RuntimeError> {
    numeric_reply(prefix, code, nickname, middle, trailing).map_err(|_| RuntimeError::InvalidValue)
}

fn description(value: &'static str) -> Result<SafeReplyDescription, RuntimeError> {
    SafeReplyDescription::new(value).map_err(|_| RuntimeError::InvalidValue)
}

const fn operation(enabled: bool) -> ModeOperation {
    if enabled {
        ModeOperation::Add
    } else {
        ModeOperation::Remove
    }
}

const fn role_letter(role: Role) -> Result<char, RuntimeError> {
    match role {
        Role::Owner => Ok('q'),
        Role::Administrator => Ok('a'),
        Role::Operator => Ok('o'),
        Role::HalfOperator => Ok('h'),
        Role::Voice => Ok('v'),
        Role::Member => Err(RuntimeError::InvalidValue),
    }
}

const fn role_prefix(role: Role) -> Option<char> {
    match role {
        Role::Owner => Some('~'),
        Role::Administrator => Some('&'),
        Role::Operator => Some('@'),
        Role::HalfOperator => Some('%'),
        Role::Voice => Some('+'),
        Role::Member => None,
    }
}

const fn list_letter(list: MaskList) -> char {
    match list {
        MaskList::Ban => 'b',
        MaskList::Exception => 'e',
        MaskList::InviteException => 'I',
    }
}

fn typed_mask_text(mask: &TypedMask) -> String {
    let subject = match mask.subject() {
        MaskSubject::Account(account) => format!("$a:{}", account.to_text()),
        MaskSubject::User(user_id) => format!("$u:{}", user_id.to_base64url()),
        MaskSubject::Nickname(glob) => format!("$n:{}", glob.pattern()),
        MaskSubject::Cloak(glob) => format!("$c:{}", glob.pattern()),
    };
    if mask.is_quiet() {
        format!("$q:{subject}")
    } else {
        subject
    }
}

fn ascii(bytes: &[u8]) -> Result<&str, RuntimeError> {
    std::str::from_utf8(bytes).map_err(|_| RuntimeError::InvalidValue)
}

#[cfg(test)]
mod tests {
    use agenc_ircd_client_wire::{CapabilityProfile, CapabilitySpec};
    use agenc_ircd_domain::{ChannelTarget, ExternalInputs};
    use agenc_ircd_testkit::{apply_command, channel_id, open_session, registered_admission};
    use agenc_ircd_types::{AccountRandomId, EntryId};

    use super::*;

    #[test]
    fn server_time_formats_epoch_and_leap_day() -> Result<(), RuntimeError> {
        assert_eq!(
            server_time(UtcSecond::from_unix_seconds(0))?,
            "1970-01-01T00:00:00.000Z"
        );
        assert_eq!(
            server_time(UtcSecond::from_unix_seconds(1_582_934_400))?,
            "2020-02-29T00:00:00.000Z"
        );
        Ok(())
    }

    #[test]
    fn capability_keys_partition_message_renderings() {
        assert_eq!(message_capability_key(&CapabilityState::default()), 0);
    }

    #[test]
    fn member_role_has_no_wire_mode_letter() {
        assert_eq!(role_letter(Role::Member), Err(RuntimeError::InvalidValue));
        assert_eq!(role_letter(Role::Voice), Ok('v'));
    }

    #[test]
    fn capability_key_sets_each_independent_message_bit() -> Result<(), Box<dyn core::error::Error>>
    {
        let profile = CapabilityProfile::new(
            ["message-tags", "message-ids", "server-time", "account-tag"]
                .into_iter()
                .map(|name| CapabilitySpec::new(name, None))
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        let mut capabilities = CapabilityState::default();
        let _listed = capabilities.ls(Some("302"), &profile)?;
        let _reply =
            capabilities.request("message-tags message-ids server-time account-tag", &profile)?;
        assert_eq!(message_capability_key(&capabilities), 0b1111);
        Ok(())
    }

    #[test]
    fn closed_mode_helpers_cover_every_role_list_direction_and_mask_subject()
    -> Result<(), Box<dyn core::error::Error>> {
        assert_eq!(operation(true), ModeOperation::Add);
        assert_eq!(operation(false), ModeOperation::Remove);
        for (role, letter, prefix) in [
            (Role::Owner, Some('q'), Some('~')),
            (Role::Administrator, Some('a'), Some('&')),
            (Role::Operator, Some('o'), Some('@')),
            (Role::HalfOperator, Some('h'), Some('%')),
            (Role::Voice, Some('v'), Some('+')),
            (Role::Member, None, None),
        ] {
            assert_eq!(role_letter(role).ok(), letter);
            assert_eq!(role_prefix(role), prefix);
        }
        assert_eq!(list_letter(MaskList::Ban), 'b');
        assert_eq!(list_letter(MaskList::Exception), 'e');
        assert_eq!(list_letter(MaskList::InviteException), 'I');

        let account = AccountRandomId::from_bytes([1; 16]);
        let user = UserId::from_bytes([2; 16]);
        for (text, expected) in [
            (
                format!("$a:{}", account.to_text()),
                format!("$a:{}", account.to_text()),
            ),
            (
                format!("$u:{}", user.to_base64url()),
                format!("$u:{}", user.to_base64url()),
            ),
            ("$n:Te*t".to_owned(), "$n:te*t".to_owned()),
            ("$c:Host*".to_owned(), "$c:Host*".to_owned()),
            ("$q:$n:quiet*".to_owned(), "$q:$n:quiet*".to_owned()),
        ] {
            assert_eq!(typed_mask_text(&TypedMask::parse(&text)?), expected);
        }
        Ok(())
    }

    #[test]
    fn timestamp_and_ascii_helpers_fail_closed_at_their_outer_bounds() {
        assert_eq!(
            server_time(UtcSecond::from_unix_seconds(253_402_300_799)),
            Ok("9999-12-31T23:59:59.000Z".to_owned())
        );
        assert_eq!(
            server_time(UtcSecond::from_unix_seconds(253_402_300_800)),
            Err(RuntimeError::InvalidValue)
        );
        assert_eq!(
            server_time(UtcSecond::from_unix_seconds(u64::MAX)),
            Err(RuntimeError::InvalidValue)
        );
        assert_eq!(ascii(b"ascii"), Ok("ascii"));
        assert_eq!(ascii(&[0xff]), Err(RuntimeError::InvalidValue));
    }

    #[test]
    fn mode_change_text_covers_every_state_independent_arm()
    -> Result<(), Box<dyn core::error::Error>> {
        let mut state = DomainState::new()?;
        let identity = open_session(&mut state, 1, "actor", None)?;
        let name = ChannelNameValue::parse("#room")?;
        apply_command(
            &mut state,
            identity,
            CanonicalCommand::join(vec![ChannelTarget::new(name.clone(), false)])?,
            &registered_admission(identity.user_id)?,
            Some(ExternalInputs {
                utc_now: Some(UtcSecond::from_unix_seconds(1_700_000_000)),
                channel_ids: vec![channel_id(1)],
                ..ExternalInputs::default()
            }),
        )?;
        let channel = state.channel(channel_id(1)).ok_or("missing channel")?;
        let target = agenc_ircd_domain::NicknameValue::parse("target")?;
        let mask = TypedMask::parse("$n:mask*")?;
        let changes = [
            ModeChange::Visibility {
                operation: ModeOperation::Add,
                mode: VisibilityMode::Unlisted,
            },
            ModeChange::Visibility {
                operation: ModeOperation::Remove,
                mode: VisibilityMode::Secret,
            },
            ModeChange::InviteOnly(true),
            ModeChange::Moderated(false),
            ModeChange::TopicProtected(true),
            ModeChange::JoinKey(false),
            ModeChange::MemberLimit(Some(7)),
            ModeChange::MemberLimit(None),
            ModeChange::Role {
                operation: ModeOperation::Add,
                target,
                role: Role::Operator,
            },
            ModeChange::AddMask {
                list: MaskList::Ban,
                mask,
            },
            ModeChange::RemoveMask {
                list: MaskList::Ban,
                entry_id: EntryId::from_bytes([9; 16]),
            },
        ];
        let expected = [
            (ModeOperation::Add, 'p', None),
            (ModeOperation::Remove, 's', None),
            (ModeOperation::Add, 'i', None),
            (ModeOperation::Remove, 'm', None),
            (ModeOperation::Add, 't', None),
            (ModeOperation::Remove, 'k', None),
            (ModeOperation::Add, 'l', Some("7".to_owned())),
            (ModeOperation::Remove, 'l', None),
            (ModeOperation::Add, 'o', Some("target".to_owned())),
            (ModeOperation::Add, 'b', Some("$n:mask*".to_owned())),
        ];
        for (change, expected) in changes.iter().zip(expected) {
            assert_eq!(mode_change_text(channel, change)?, expected);
        }
        assert_eq!(
            mode_change_text(channel, changes.last().ok_or(RuntimeError::InvalidValue)?),
            Err(RuntimeError::InvalidValue)
        );
        Ok(())
    }
}
