//! Requests an edge sends on behalf of its clients and the results it
//! receives (spec 20.4, 20.5).

use agenc_ircd_client_wire::{ParsedMessage, RegisteredCommandKind};
use agenc_ircd_domain::federation::ModeDirection;
use agenc_ircd_domain::{
    CanonicalCommand, CanonicalCommandView, DomainError, MessageKind, MessageTarget, ModeChange,
    ModeCommand, ModeOperation, PresenceCommand,
};
use agenc_ircd_federation_wire::{
    AssembledObject, CanonicalEncode, DecodeBudget, OperationDescriptor, OriginAccount,
    OriginRecord, OriginSession, ReplayKey, RequestHeader, ResultHeader, SchemaObject,
    decode_result_arm, federation_object_id,
};
use agenc_ircd_types::{FederationResultKind, RequestId, SessionId, UserId};
use std::collections::VecDeque;
use zeroize::Zeroizing;

use super::{DeferredCommand, EdgeFederation, MAX_DEFERRED_COMMANDS, Phase, Violation};
use crate::connection::ConnectionGeneration;
use crate::federation::codec::operations::{
    FederatedOperation, JoinTarget, MessageTargetArg, ModeChangeArg,
};
use crate::federation::codec::results::{ResultArm, failure_error, reply_parts_of};
use crate::state_core::StateCoreContext;

/// What the router does when a request finishes.
pub enum EdgeCompletion {
    /// The coordinator registered the session: bind it and run the welcome.
    SessionRegistered {
        /// The client connection.
        generation: ConnectionGeneration,
        /// The accepted session identity.
        session_id: SessionId,
        /// The per-connection user identity.
        user_id: UserId,
        /// The registration event generation the state machine expects.
        event_generation: u64,
        /// The registered nickname.
        nickname: String,
    },
    /// Registration was refused.
    RegistrationRefused {
        /// The client connection.
        generation: ConnectionGeneration,
        /// The registration event generation the state machine expects.
        event_generation: u64,
    },
    /// A command failed with a client-facing error.
    CommandFailed {
        /// The client connection.
        generation: ConnectionGeneration,
        /// The client's original line.
        message: Box<ParsedMessage>,
        /// The error the edge renders.
        error: DomainError,
    },
    /// A command's mutation is applied on the replica.
    CommandCompleted {
        /// The client connection.
        generation: ConnectionGeneration,
        /// The client's original line.
        message: Box<ParsedMessage>,
    },
    /// A query page rendered by the coordinator.
    Replies {
        /// The client connection.
        generation: ConnectionGeneration,
        /// The reply lines, prefixed by this edge.
        frames: Vec<agenc_ircd_client_wire::WireMessage>,
        /// The cursor of the next page, if any.
        next_cursor: Option<[u8; 32]>,
        /// The client's original line.
        message: Box<ParsedMessage>,
    },
    /// The link lost synchronization; the registered client must reconnect.
    Resync {
        /// The client connection.
        generation: ConnectionGeneration,
    },
}

/// Why a request was sent.
pub(crate) enum PendingKind {
    SessionOpen {
        event_generation: u64,
        nickname: agenc_ircd_domain::NicknameValue,
    },
    Command {
        message: Box<ParsedMessage>,
    },
    Close,
}

/// One request awaiting its result or completion.
pub(super) struct PendingRequest {
    pub(super) generation: ConnectionGeneration,
    pub(super) kind: PendingKind,
    pub(super) header: RequestHeader,
    pub(super) bytes: Vec<u8>,
    pub(super) sent: bool,
    pub(super) result: Option<ResultArm>,
    pub(super) replies: Vec<agenc_ircd_client_wire::WireMessage>,
    pub(super) completion: Option<agenc_ircd_types::EventId>,
}

impl PendingRequest {
    /// The client left before the result: nothing renders.
    pub(super) fn sink_gone(self, edge: &mut EdgeFederation) {
        if let Some(completion) = self.completion {
            edge.by_completion.remove(&completion);
        }
    }
}

/// Declares or updates the connection's origin with the coordinator.
pub(super) fn declare_origin(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    update: bool,
) {
    let Some(origin) = edge.origins.get_mut(&generation) else {
        return;
    };
    if origin.deleted {
        return;
    }
    let record = OriginRecord {
        network_id: edge.config.network_id,
        home_server_id: edge.config.server_id,
        server_incarnation: edge.config.incarnation,
        origin_id: origin.origin_id,
        generation: origin.generation,
        previous_origin_object_id: origin.previous_object_id,
        connection_id: origin.connection_id,
        session: origin.session.map(|(session_id, user_id)| OriginSession {
            session_id,
            user_id,
        }),
        account: None::<OriginAccount>,
        connection_nonce: origin.connection_nonce,
    };
    let Ok(encoded) = record
        .to_object()
        .and_then(|object| object.encode_canonical())
        .map(|bytes| bytes.as_slice().to_vec())
    else {
        return;
    };
    let object_id = federation_object_id(&encoded);
    origin.object_id = *object_id.as_bytes();
    let Some((descriptor, _)) = edge.origin_descriptor(generation) else {
        return;
    };
    let _sent = edge.send_object(context, &encoded, |fragment| {
        if update {
            agenc_ircd_federation_wire::FederationFrame::OriginUpdate {
                descriptor,
                fragment,
            }
        } else {
            agenc_ircd_federation_wire::FederationFrame::OriginAdd {
                descriptor,
                fragment,
            }
        }
    });
}

/// Sends FORIGIN DEL for a closed connection.
pub(super) fn delete_origin(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
) {
    let Some(origin) = edge.origins.get_mut(&generation) else {
        return;
    };
    origin.deleted = true;
    let frame = agenc_ircd_federation_wire::FederationFrame::OriginDel {
        coordinator_server_id: edge.config.coordinator.server_id(),
        server_incarnation: edge.config.incarnation,
        origin_id: origin.origin_id,
        generation: origin.generation,
        next_operation_sequence: origin.sequence,
    };
    edge.send_frame(context, &frame);
    edge.origins.remove(&generation);
}

/// Encodes one request for the connection's origin, consuming the next
/// operation sequence.
fn prepare_request(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    operation: &FederatedOperation,
) -> Result<(RequestId, RequestHeader, Vec<u8>), Violation> {
    let mut random = [0_u8; 16];
    context
        .entropy_mut()
        .fill_exact(&mut random)
        .map_err(|_| Violation::Ceiling)?;
    let origin = edge.origins.get_mut(&generation).ok_or(Violation::Phase)?;
    let request_id = RequestId::from_bytes(random);
    let header = RequestHeader {
        network_id: edge.config.network_id,
        replay_key: ReplayKey {
            home_server_id: edge.config.server_id,
            server_incarnation: edge.config.incarnation,
            origin_id: origin.origin_id,
            origin_generation: origin.generation,
            operation_sequence: origin.sequence,
        },
        request_id,
        opcode: operation.opcode(),
    };
    let bytes = operation
        .to_object()
        .and_then(|arm| header.build(&arm))
        .and_then(|object| object.encode_canonical())
        .map(|bytes| bytes.as_slice().to_vec())
        .map_err(|_| Violation::Codec)?;
    origin.sequence = origin.sequence.checked_add(1).ok_or(Violation::Ceiling)?;
    Ok((request_id, header, bytes))
}

/// Registers a prepared request as pending and transmits it.
fn register_request(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    prepared: (RequestId, RequestHeader, Vec<u8>),
    kind: PendingKind,
) {
    let (request_id, header, bytes) = prepared;
    edge.pending.insert(
        request_id,
        PendingRequest {
            generation,
            kind,
            header,
            bytes,
            sent: false,
            result: None,
            replies: Vec::new(),
            completion: None,
        },
    );
    edge.counters.requests_sent = edge.counters.requests_sent.saturating_add(1);
    transmit(edge, context, request_id);
}

/// Transmits one pending request when the link is active; otherwise it waits
/// for the next resume and is resent byte-identically.
pub(super) fn transmit(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    request_id: RequestId,
) {
    if edge.phase != Phase::Active {
        return;
    }
    let Some(pending) = edge.pending.get(&request_id) else {
        return;
    };
    if pending.sent || pending.result.is_some() {
        return;
    }
    let descriptor = OperationDescriptor {
        addressed_server_id: edge.config.coordinator.server_id(),
        server_incarnation: pending.header.replay_key.server_incarnation,
        origin_id: pending.header.replay_key.origin_id,
        origin_generation: pending.header.replay_key.origin_generation,
        operation_sequence: pending.header.replay_key.operation_sequence,
        request_id,
        object_id: federation_object_id(&pending.bytes),
    };
    let bytes = pending.bytes.clone();
    let sent = edge.send_object(context, &bytes, |fragment| {
        agenc_ircd_federation_wire::FederationFrame::Request {
            descriptor,
            fragment,
        }
    });
    if sent && let Some(pending) = edge.pending.get_mut(&request_id) {
        pending.sent = true;
    }
}

/// Re-sends every unanswered request in origin and sequence order.
pub(super) fn resend_pending(edge: &mut EdgeFederation, context: &mut StateCoreContext) {
    let mut order: Vec<(ReplayKey, RequestId)> = edge
        .pending
        .iter()
        .filter(|(_, pending)| pending.result.is_none())
        .map(|(request_id, pending)| (pending.header.replay_key, *request_id))
        .collect();
    order.sort_by_key(|(key, _)| key.to_bytes());
    for (_, request_id) in order {
        transmit(edge, context, request_id);
    }
}

/// Requests a session for a connection that completed local registration.
pub(super) fn send_session_open(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    event_generation: u64,
    nickname: &str,
    realname: &str,
    capability_hash: [u8; 32],
) -> Result<(), Violation> {
    let origin = edge.origins.get(&generation).ok_or(Violation::Phase)?;
    let parsed = agenc_ircd_domain::NicknameValue::parse(nickname).map_err(|_| Violation::Codec)?;
    let operation = FederatedOperation::SessionOpen {
        connection_id: origin.connection_id,
        auth_grant_id: None,
        nickname: nickname.to_owned(),
        realname: realname.to_owned(),
        capability_hash,
        connection_nonce: origin.connection_nonce,
    };
    let prepared = prepare_request(edge, context, generation, &operation)?;
    register_request(
        edge,
        context,
        generation,
        prepared,
        PendingKind::SessionOpen {
            event_generation,
            nickname: parsed,
        },
    );
    Ok(())
}

/// Closes the session of a connection that ended.
pub(super) fn send_session_close(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    session_id: SessionId,
    reason: &str,
) {
    let reason_code = if reason.is_empty() { 2 } else { 1 };
    let operation = FederatedOperation::SessionClose {
        session_id,
        reason_code,
    };
    if let Ok(prepared) = prepare_request(edge, context, generation, &operation) {
        register_request(edge, context, generation, prepared, PendingKind::Close);
    }
}

/// Converts and sends one registered command; `Err` returns the line with
/// the public error the router renders itself.
pub(super) fn send_command(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    kind: RegisteredCommandKind,
    message: Box<ParsedMessage>,
) -> Result<(), (Box<ParsedMessage>, DomainError)> {
    if edge.phase != Phase::Active {
        return Err((message, DomainError::ServerBusy));
    }
    let Some((session_id, user_id)) = edge
        .origins
        .get(&generation)
        .and_then(|origin| origin.session)
    else {
        return Err((message, DomainError::RegistrationRequired));
    };
    if edge
        .pending
        .values()
        .any(|pending| pending.generation == generation)
    {
        let queue = edge.deferred.entry(generation).or_default();
        if queue.len() >= MAX_DEFERRED_COMMANDS {
            return Err((message, DomainError::ServerBusy));
        }
        queue.push_back(DeferredCommand { kind, message });
        return Ok(());
    }
    let Ok(command) = crate::command_convert::convert(context.domain(), kind, &message) else {
        return Err((message, DomainError::InvalidArgument));
    };
    let operation = match operation_of(edge, session_id, user_id, &message, &command) {
        Ok(operation) => operation,
        Err(error) => return Err((message, error)),
    };
    let Ok(prepared) = prepare_request(edge, context, generation, &operation) else {
        return Err((message, DomainError::ServerBusy));
    };
    register_request(
        edge,
        context,
        generation,
        prepared,
        PendingKind::Command { message },
    );
    Ok(())
}

fn session_revision(edge: &EdgeFederation, user_id: UserId) -> Result<u64, DomainError> {
    edge.replica
        .session(user_id)
        .map(|session| session.session_revision.get())
        .ok_or(DomainError::RegistrationRequired)
}

fn channel_of(
    edge: &EdgeFederation,
    name: &agenc_ircd_domain::ChannelNameValue,
) -> Result<(agenc_ircd_types::ChannelInstanceId, u64), DomainError> {
    edge.replica
        .channel_by_name(name)
        .map(|channel| (channel.channel_id, channel.channel_revision.get()))
        .ok_or(DomainError::NotFound)
}

/// Maps one canonical command onto its operation using the replica for
/// identities and expected revisions.
// agenc-review: focus owner=runtime reviewed=2026-09-02 reason=one closed match maps every federated client command onto its operation arm
fn operation_of(
    edge: &EdgeFederation,
    session_id: SessionId,
    user_id: UserId,
    message: &ParsedMessage,
    command: &CanonicalCommand,
) -> Result<FederatedOperation, DomainError> {
    match command.view() {
        CanonicalCommandView::Nick(nickname) => Ok(FederatedOperation::NickChange {
            session_id,
            expected_session_revision: session_revision(edge, user_id)?,
            nickname: nickname.presentation().to_owned(),
        }),
        CanonicalCommandView::Join(targets) => {
            let keys = message.middle().get(1).map_or("", String::as_str);
            let mut joins = Vec::new();
            for (index, target) in targets.iter().enumerate() {
                let key = keys.split(',').nth(index).unwrap_or("");
                joins.push(JoinTarget {
                    channel_name: target.name().canonical().to_owned(),
                    join_key: Zeroizing::new(if target.key_supplied() {
                        key.as_bytes().to_vec()
                    } else {
                        Vec::new()
                    }),
                });
            }
            joins.sort_by(|left, right| left.channel_name.cmp(&right.channel_name));
            Ok(FederatedOperation::Join {
                session_id,
                expected_session_revision: session_revision(edge, user_id)?,
                targets: joins,
            })
        }
        CanonicalCommandView::Part(channels, reason) => {
            let mut ids = Vec::new();
            for name in channels {
                ids.push(channel_of(edge, name)?.0);
            }
            ids.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
            Ok(FederatedOperation::Part {
                session_id,
                expected_session_revision: session_revision(edge, user_id)?,
                all_channels: false,
                channels: ids,
                reason: reason.map_or(String::new(), |reason| reason.as_str().to_owned()),
            })
        }
        CanonicalCommandView::PartAll => {
            let mut ids: Vec<_> = edge.replica.channels_of(user_id).collect();
            ids.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
            Ok(FederatedOperation::Part {
                session_id,
                expected_session_revision: session_revision(edge, user_id)?,
                all_channels: true,
                channels: ids,
                reason: String::new(),
            })
        }
        CanonicalCommandView::Mode(mode) => {
            mode_operation(edge, session_id, user_id, message, mode)
        }
        CanonicalCommandView::TopicSet(name, topic) => {
            let (channel_id, revision) = channel_of(edge, name)?;
            Ok(FederatedOperation::Topic {
                session_id,
                channel_id,
                expected_channel_revision: revision,
                topic: topic.as_str().to_owned(),
            })
        }
        CanonicalCommandView::Invite(target, name) => {
            let (channel_id, revision) = channel_of(edge, name)?;
            Ok(FederatedOperation::Invite {
                session_id,
                channel_id,
                target_nickname: target.canonical().to_owned(),
                expected_channel_revision: revision,
            })
        }
        CanonicalCommandView::Kick(name, targets, reason) => {
            let (channel_id, revision) = channel_of(edge, name)?;
            let mut ids = Vec::new();
            for nickname in targets {
                ids.push(user_by_nickname(edge, nickname).ok_or(DomainError::NotFound)?);
            }
            Ok(FederatedOperation::Kick {
                session_id,
                channel_id,
                targets: ids,
                expected_channel_revision: revision,
                reason: reason.map_or(String::new(), |reason| reason.as_str().to_owned()),
            })
        }
        CanonicalCommandView::Message(message_command) => {
            message_operation(edge, session_id, message, message_command)
        }
        CanonicalCommandView::Presence(PresenceCommand::Away(away)) => {
            Ok(FederatedOperation::Away {
                session_id,
                expected_session_revision: session_revision(edge, user_id)?,
                away_text: away
                    .as_ref()
                    .map_or(String::new(), |away| away.as_str().to_owned()),
            })
        }
        CanonicalCommandView::Setname(display_name) => Ok(FederatedOperation::Setname {
            session_id,
            expected_session_revision: session_revision(edge, user_id)?,
            display_name: display_name.as_str().to_owned(),
        }),
        _ => Err(DomainError::BadState),
    }
}

/// Finds a user this edge learned about through its replica or events.
fn user_by_nickname(
    edge: &EdgeFederation,
    nickname: &agenc_ircd_domain::NicknameValue,
) -> Option<UserId> {
    edge.replica
        .sessions()
        .find(|session| session.nickname.canonical() == nickname.canonical())
        .map(|session| session.user_id)
        .or_else(|| {
            edge.nicknames
                .iter()
                .find(|(_, known)| known.canonical() == nickname.canonical())
                .map(|(user_id, _)| *user_id)
        })
}

fn mode_operation(
    edge: &EdgeFederation,
    session_id: SessionId,
    user_id: UserId,
    message: &ParsedMessage,
    mode: &ModeCommand,
) -> Result<FederatedOperation, DomainError> {
    match mode {
        ModeCommand::ChannelChange(name, changes) => {
            let (channel_id, revision) = channel_of(edge, name)?;
            let arguments: Vec<&str> = message
                .middle()
                .iter()
                .skip(2)
                .map(String::as_str)
                .collect();
            Ok(FederatedOperation::ChannelMode {
                session_id,
                channel_id,
                expected_channel_revision: revision,
                changes: channel_mode_args(changes, &arguments),
            })
        }
        ModeCommand::UserOperatorNotices(_, enabled) => Ok(FederatedOperation::UserMode {
            session_id,
            expected_session_revision: session_revision(edge, user_id)?,
            changes: vec![ModeChangeArg {
                direction: flag(*enabled),
                mode_code: 2,
                argument: Zeroizing::new(Vec::new()),
            }],
        }),
        ModeCommand::UserQuery(_)
        | ModeCommand::ChannelQuery(_)
        | ModeCommand::ChannelList(_, _) => Err(DomainError::BadState),
    }
}

/// Pairs each change with the client argument it consumes, in order.
fn channel_mode_args(changes: &[ModeChange], arguments: &[&str]) -> Vec<ModeChangeArg> {
    let mut converted = Vec::new();
    let mut argument_index = 0;
    for change in changes {
        let (direction, mode_code, needs_argument) = mode_change_parts(change);
        let argument = if needs_argument {
            let value = arguments.get(argument_index).copied().unwrap_or("");
            argument_index = argument_index.saturating_add(1);
            value.as_bytes().to_vec()
        } else {
            Vec::new()
        };
        converted.push(ModeChangeArg {
            direction,
            mode_code,
            argument: Zeroizing::new(argument),
        });
    }
    converted
}

const fn direction(operation: ModeOperation) -> ModeDirection {
    match operation {
        ModeOperation::Add => ModeDirection::Add,
        ModeOperation::Remove => ModeDirection::Remove,
    }
}

const fn flag(enabled: bool) -> ModeDirection {
    if enabled {
        ModeDirection::Add
    } else {
        ModeDirection::Remove
    }
}

/// The B.4 code, direction, and argument presence of one channel mode change.
const fn mode_change_parts(change: &ModeChange) -> (ModeDirection, u16, bool) {
    match change {
        ModeChange::Visibility { operation, mode } => (
            direction(*operation),
            match mode {
                agenc_ircd_domain::VisibilityMode::Unlisted => 9,
                agenc_ircd_domain::VisibilityMode::Secret => 10,
            },
            false,
        ),
        ModeChange::InviteOnly(enabled) => (flag(*enabled), 6, false),
        ModeChange::Moderated(enabled) => (flag(*enabled), 7, false),
        ModeChange::TopicProtected(enabled) => (flag(*enabled), 11, false),
        ModeChange::JoinKey(enabled) => (flag(*enabled), 4, *enabled),
        ModeChange::MemberLimit(limit) => (flag(limit.is_some()), 5, limit.is_some()),
        ModeChange::Role {
            operation, role, ..
        } => (
            direction(*operation),
            match role {
                agenc_ircd_domain::Role::Owner => 12,
                agenc_ircd_domain::Role::Administrator => 13,
                agenc_ircd_domain::Role::Operator => 14,
                agenc_ircd_domain::Role::HalfOperator => 15,
                agenc_ircd_domain::Role::Member | agenc_ircd_domain::Role::Voice => 16,
            },
            true,
        ),
        ModeChange::AddMask { list, .. } => (ModeDirection::Add, mask_code(*list), true),
        ModeChange::RemoveMask { list, .. } => (ModeDirection::Remove, mask_code(*list), true),
    }
}

const fn mask_code(list: agenc_ircd_domain::MaskList) -> u16 {
    match list {
        agenc_ircd_domain::MaskList::Ban => 1,
        agenc_ircd_domain::MaskList::Exception => 2,
        agenc_ircd_domain::MaskList::InviteException => 3,
    }
}

fn message_operation(
    edge: &EdgeFederation,
    session_id: SessionId,
    message: &ParsedMessage,
    command: &agenc_ircd_domain::MessageCommand,
) -> Result<FederatedOperation, DomainError> {
    let mut targets = Vec::new();
    for target in command.targets() {
        targets.push(message_target_arg(edge, target)?);
    }
    targets.sort_by_key(|target| match target {
        MessageTargetArg::Channel { channel_id, .. } => (1_u16, channel_id.as_bytes().to_vec()),
        MessageTargetArg::User { nickname } => (2_u16, nickname.as_bytes().to_vec()),
    });
    let mut tags: Vec<(String, String)> = message
        .tags()
        .iter()
        .filter(|tag| tag.key().starts_with('+'))
        .map(|tag| (tag.key().to_owned(), tag.value().unwrap_or("").to_owned()))
        .collect();
    tags.sort();
    let kind = command.kind();
    Ok(FederatedOperation::Message {
        session_id,
        kind,
        targets,
        tags,
        body: if kind == MessageKind::Tagmsg {
            String::new()
        } else {
            command.body().map_or(String::new(), str::to_owned)
        },
    })
}

fn message_target_arg(
    edge: &EdgeFederation,
    target: &MessageTarget,
) -> Result<MessageTargetArg, DomainError> {
    Ok(match target {
        MessageTarget::Channel(name) => {
            let (channel_id, revision) = channel_of(edge, name)?;
            MessageTargetArg::Channel {
                channel_id,
                expected_revision: revision,
            }
        }
        MessageTarget::User(nickname) => MessageTargetArg::User {
            nickname: nickname.canonical().to_owned(),
        },
    })
}

/// Receives one result object.
pub(super) fn receive_result(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    descriptor: OperationDescriptor,
    object: &AssembledObject,
) -> Result<Vec<EdgeCompletion>, Violation> {
    let mut budget = DecodeBudget::new(1 << 20, 4_096);
    let result = SchemaObject::decode_exact("FederationResult", object.as_slice(), &mut budget)
        .map_err(|_| Violation::Codec)?;
    let header = ResultHeader::from_object(&result).map_err(|_| Violation::Codec)?;
    if descriptor.request_id != header.request_id || descriptor.object_id != object.object_id() {
        return Err(Violation::Consistency);
    }
    let Some(pending) = edge.pending.get_mut(&header.request_id) else {
        return Ok(Vec::new());
    };
    if pending.header.replay_key != header.replay_key
        || header.request_object_id != federation_object_id(&pending.bytes)
        || pending.result.is_some()
    {
        return Err(Violation::Consistency);
    }
    let arm = ResultArm::from_object(
        header.result_kind,
        &decode_result_arm(&result, &mut budget).map_err(|_| Violation::Codec)?,
    )
    .map_err(|_| Violation::Codec)?;
    let mut replies = Vec::new();
    for reply in agenc_ircd_federation_wire::access::vector(&result, "replies")
        .map_err(|_| Violation::Codec)?
    {
        replies.push(reply_frame(&edge.config.server_name, reply)?);
    }
    pending.replies = replies;
    pending.completion = header.completion_event_id;
    edge.counters.results_applied = edge.counters.results_applied.saturating_add(1);
    match (header.result_kind, header.completion_event_id) {
        (
            FederationResultKind::Committed | FederationResultKind::SessionRegistered,
            Some(event_id),
        ) => {
            pending.result = Some(arm);
            // The completion event may already have been applied and ACKed.
            if edge.applied_completions.remove(&event_id) {
                return Ok(completed(edge, context, header.request_id));
            }
            edge.by_completion.insert(event_id, header.request_id);
            Ok(Vec::new())
        }
        (FederationResultKind::Committed | FederationResultKind::SessionRegistered, None) => {
            Err(Violation::Consistency)
        }
        _ => {
            pending.result = Some(arm);
            Ok(completed(edge, context, header.request_id))
        }
    }
}

/// Rebuilds one relayed reply under this edge's prefix; numerics go through
/// the registry-checked constructor.
fn reply_frame(
    prefix: &str,
    reply: &SchemaObject,
) -> Result<agenc_ircd_client_wire::WireMessage, Violation> {
    let parts = reply_parts_of(reply).map_err(|_| Violation::Codec)?;
    let middle: Vec<&str> = parts.parameters.iter().map(String::as_str).collect();
    let numeric =
        parts.command.len() == 3 && parts.command.bytes().all(|byte| byte.is_ascii_digit());
    let frame = if numeric {
        let code: u16 = parts.command.parse().map_err(|_| Violation::Codec)?;
        let (target, rest) = middle.split_first().ok_or(Violation::Codec)?;
        agenc_ircd_client_wire::numeric_reply(prefix, code, target, rest, parts.trailing.as_deref())
    } else {
        agenc_ircd_client_wire::WireMessage::new(
            prefix,
            &parts.command,
            &middle,
            parts.trailing.as_deref(),
        )
    };
    frame.map_err(|_| Violation::Codec)
}

/// Finishes one request whose result and completion are both known.
pub(super) fn completed(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    request_id: RequestId,
) -> Vec<EdgeCompletion> {
    let generation = edge
        .pending
        .get(&request_id)
        .map(|pending| pending.generation);
    let mut completions = completed_request(edge, request_id);
    if let Some(generation) = generation {
        completions.extend(dispatch_deferred(edge, context, generation));
    }
    completions
}

/// Sends the connection's next deferred commands once nothing of its is
/// in flight; a command that cannot be sent fails to the client in order.
fn dispatch_deferred(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
) -> Vec<EdgeCompletion> {
    let mut completions = Vec::new();
    loop {
        let in_flight = edge
            .pending
            .values()
            .any(|pending| pending.generation == generation);
        if in_flight {
            break;
        }
        let Some(next) = edge
            .deferred
            .get_mut(&generation)
            .and_then(VecDeque::pop_front)
        else {
            edge.deferred.remove(&generation);
            break;
        };
        if let Err((message, error)) =
            send_command(edge, context, generation, next.kind, next.message)
        {
            completions.push(EdgeCompletion::CommandFailed {
                generation,
                message,
                error,
            });
        }
    }
    completions
}

/// Resolves one finished request into its client-facing completion.
fn completed_request(edge: &mut EdgeFederation, request_id: RequestId) -> Vec<EdgeCompletion> {
    let Some(pending) = edge.pending.remove(&request_id) else {
        return Vec::new();
    };
    if let Some(completion) = pending.completion {
        edge.by_completion.remove(&completion);
    }
    let Some(result) = pending.result else {
        return Vec::new();
    };
    let generation = pending.generation;
    match (pending.kind, result) {
        (
            PendingKind::SessionOpen {
                event_generation,
                nickname,
            },
            ResultArm::SessionRegistered(registered),
        ) => {
            if let Some(origin) = edge.origins.get_mut(&generation) {
                origin.session = Some((registered.session_id, registered.user_id));
            }
            let presentation = nickname.presentation().to_owned();
            edge.nicknames.insert(registered.user_id, nickname);
            vec![EdgeCompletion::SessionRegistered {
                generation,
                session_id: registered.session_id,
                user_id: registered.user_id,
                event_generation,
                nickname: presentation,
            }]
        }
        (
            PendingKind::SessionOpen {
                event_generation, ..
            },
            _,
        ) => vec![EdgeCompletion::RegistrationRefused {
            generation,
            event_generation,
        }],
        (PendingKind::Command { message }, ResultArm::Failed { code, .. }) => {
            vec![EdgeCompletion::CommandFailed {
                generation,
                message,
                error: failure_error(&code).unwrap_or(DomainError::ServerBusy),
            }]
        }
        (PendingKind::Command { message }, ResultArm::ReplyPage { next_cursor, .. }) => {
            vec![EdgeCompletion::Replies {
                generation,
                frames: pending.replies,
                next_cursor,
                message,
            }]
        }
        (PendingKind::Command { message }, _) => vec![EdgeCompletion::CommandCompleted {
            generation,
            message,
        }],
        (PendingKind::Close, _) => Vec::new(),
    }
}

/// Builds a `directory.names` query for one channel.
fn names_query(channel: &str, cursor: Option<[u8; 32]>) -> Result<FederatedOperation, Violation> {
    let name = SchemaObject::new(
        "FederationChannelName",
        vec![
            agenc_ircd_federation_wire::access::opaque(channel.as_bytes())
                .map_err(|_| Violation::Codec)?,
        ],
    )
    .map_err(|_| Violation::Codec)?;
    let arm = SchemaObject::new(
        "directory.names",
        vec![agenc_ircd_federation_wire::WireValue::Vector(vec![name])],
    )
    .map_err(|_| Violation::Codec)?;
    directory_query(
        agenc_ircd_types::FederationDirectoryQueryKind::Names,
        &arm,
        cursor,
    )
}

/// Wraps one directory arm into the `DirectoryQuery` operation payload.
fn directory_query(
    kind: agenc_ircd_types::FederationDirectoryQueryKind,
    arm: &SchemaObject,
    cursor: Option<[u8; 32]>,
) -> Result<FederatedOperation, Violation> {
    let cursor_bytes: &[u8] = cursor.as_ref().map_or(&[], |cursor| cursor);
    let query = SchemaObject::new(
        "DirectoryQuery",
        vec![
            agenc_ircd_federation_wire::WireValue::Unsigned(u64::from(kind.wire_value())),
            agenc_ircd_federation_wire::access::opaque(
                arm.encode_canonical()
                    .map_err(|_| Violation::Codec)?
                    .as_slice(),
            )
            .map_err(|_| Violation::Codec)?,
            agenc_ircd_federation_wire::access::opaque(cursor_bytes)
                .map_err(|_| Violation::Codec)?,
        ],
    )
    .map_err(|_| Violation::Codec)?;
    Ok(FederatedOperation::DirectoryQuery {
        session_id: SessionId::from_bytes([0; 16]),
        query,
    })
}

/// Sends the NAMES query of one channel for a connection.
pub(super) fn send_names(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    channel: &str,
    cursor: Option<[u8; 32]>,
) {
    let Some((session_id, _)) = edge
        .origins
        .get(&generation)
        .and_then(|origin| origin.session)
    else {
        return;
    };
    let Ok(FederatedOperation::DirectoryQuery { query, .. }) = names_query(channel, cursor) else {
        return;
    };
    let operation = FederatedOperation::DirectoryQuery { session_id, query };
    let Ok(prepared) = prepare_request(edge, context, generation, &operation) else {
        return;
    };
    let line = format!("NAMES {channel}");
    let Ok(Some(message)) = agenc_ircd_client_wire::FramedLine::new(&line)
        .map_err(|_| ())
        .and_then(|framed| agenc_ircd_client_wire::parse_message(framed).map_err(|_| ()))
    else {
        return;
    };
    register_request(
        edge,
        context,
        generation,
        prepared,
        PendingKind::Command {
            message: Box::new(message),
        },
    );
}

/// Re-issues the client's query with the continuation cursor.
pub(super) fn continue_query(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    message: &ParsedMessage,
    cursor: [u8; 32],
) {
    if message.command() != "NAMES" {
        return;
    }
    let Some(channel) = message.middle().first() else {
        return;
    };
    let channel = channel.clone();
    send_names(edge, context, generation, &channel, Some(cursor));
}
