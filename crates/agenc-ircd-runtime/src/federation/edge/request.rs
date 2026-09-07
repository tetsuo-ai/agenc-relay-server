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
use zeroize::Zeroizing;

use super::{DeferredCommand, EdgeFederation, MAX_DEFERRED_COMMANDS, Phase, Violation};
use crate::connection::ConnectionGeneration;
use crate::federation::codec::operations::{
    FederatedOperation, JoinTarget, MessageTargetArg, ModeChangeArg, USER_MODE_CODE_WALLOPS,
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
    /// A covered JOIN result starts its bounded topic and NAMES response.
    JoinCommitted {
        /// The client connection.
        generation: ConnectionGeneration,
        /// Covered topic numerics and per-target failures.
        frames: Vec<agenc_ircd_client_wire::WireMessage>,
        /// Memory backing retained through publication of the committed echoes.
        echo_permits: Vec<crate::budget::MemoryPermit>,
        /// The original JOIN and its local response label.
        message: Box<ParsedMessage>,
    },
    /// A query page rendered by the coordinator.
    Replies {
        /// The client connection.
        generation: ConnectionGeneration,
        /// The reply lines, prefixed by this edge.
        frames: Vec<agenc_ircd_client_wire::WireMessage>,
        /// The sequence within this one logical directory response.
        page_sequence: u32,
        /// The cursor of the next page, if any.
        next_cursor: Option<[u8; 32]>,
        /// The client's original line.
        message: Box<ParsedMessage>,
    },
    /// A covered account deletion queues its final reply and closes the client.
    AccountDeleted {
        /// The invalidated client connection.
        generation: ConnectionGeneration,
        /// The exact committed final account reply.
        frames: Vec<agenc_ircd_client_wire::WireMessage>,
        /// The original deletion confirmation and its response label.
        message: Box<ParsedMessage>,
    },
    /// The link lost synchronization; the registered client must reconnect.
    Resync {
        /// The client connection.
        generation: ConnectionGeneration,
    },
    /// A forwarded account carrier envelope was answered (spec 22.2).
    AccountCarrier {
        /// The client connection.
        generation: ConnectionGeneration,
        /// The carrier transfer the router observes.
        carrier_generation: u64,
        /// Whether the carrier is SASL rather than account creation.
        sasl: bool,
        /// Whether this was the finish phase.
        finish: bool,
        /// What the coordinator answered.
        outcome: RemoteCarrierOutcome,
    },
}

/// Why a request was sent.
pub(crate) enum PendingKind {
    SessionOpen {
        event_generation: u64,
        nickname: agenc_ircd_domain::NicknameValue,
    },
    /// A forwarded account carrier envelope (spec 22.2).
    AccountCarrier {
        sasl: bool,
        finish: bool,
        carrier_generation: u64,
    },
    Command {
        message: Box<ParsedMessage>,
    },
    Close,
}

/// One request awaiting its result or completion.
pub(super) struct PendingRequest {
    pub(super) generation: ConnectionGeneration,
    pub(super) sink_gone: bool,
    pub(super) kind: PendingKind,
    pub(super) header: RequestHeader,
    pub(super) bytes: Vec<u8>,
    pub(super) sent: bool,
    pub(super) result: Option<ResultArm>,
    pub(super) result_bytes: Vec<u8>,
    pub(super) replies: Vec<agenc_ircd_client_wire::WireMessage>,
    pub(super) join_echoes: Vec<super::join_echo::JoinEcho>,
    pub(super) completion: Option<agenc_ircd_types::EventId>,
    /// Generation of the completion event that durably covered this request.
    pub(super) completion_generation: Option<u64>,
    pub(super) completion_coverage:
        Option<agenc_ircd_storage::federation_records::CompletionCoverageRecord>,
}

impl PendingRequest {
    /// The client left before the result: nothing renders.
    pub(super) fn sink_gone(self, edge: &mut EdgeFederation) {
        if let Some(completion) = self.completion {
            edge.by_completion.remove(&completion);
            edge.applied_completions.remove(&completion);
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
    if edge
        .origins
        .get(&generation)
        .is_some_and(|origin| origin.deleted)
    {
        return;
    }
    send_origin_declaration(edge, context, generation, update);
}

/// Replays one origin after FORIGIN RESET: the exact current declaration
/// of an open connection, or the DEL of one that closed while the link was
/// down, so the coordinator learns of every closure it missed before READY
/// revives the origins it still holds. An absent ACK does not prove the
/// declaration was refused: the coordinator may have committed it before
/// the link failed. Even an unacknowledged origin therefore replays DEL.
pub(super) fn replay_origin(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
) {
    let Some(origin) = edge.origins.get(&generation) else {
        return;
    };
    if origin.deleted
        && origin.del_acked
        && super::journal::is_durable(edge, super::journal::Identity::Origin(generation))
    {
        super::journal::retire_origin(edge, generation);
        return;
    }
    if origin.deleted {
        // An all-zero object identity means no declaration was even encoded.
        // Such a connection has no remote work unless it owns a pending request.
        if origin.object_id == [0; 32]
            && !edge
                .pending
                .values()
                .any(|pending| pending.generation == generation)
        {
            edge.origins.remove(&generation);
            return;
        }
        send_origin_del(edge, context, generation);
        return;
    }
    let update = origin.generation > 0;
    send_origin_declaration(edge, context, generation, update);
}

fn send_origin_declaration(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    update: bool,
) {
    if !super::journal::is_durable(edge, super::journal::Identity::Origin(generation)) {
        super::journal::retain(edge, context, super::journal::Identity::Origin(generation));
        return;
    }
    if edge.phase == Phase::Down {
        return;
    }
    let Some(origin) = edge.origins.get_mut(&generation) else {
        return;
    };
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
        account: origin
            .account
            .map(|(account_id, account_session_generation)| OriginAccount {
                account_id,
                account_session_generation,
            }),
        connection_nonce: origin.connection_nonce,
    };
    let record = origin.pending_updates.front().copied().unwrap_or(record);
    let update = update || record.generation > 0;
    let Ok(encoded) = record
        .to_object()
        .and_then(|object| object.encode_canonical())
        .map(|bytes| bytes.as_slice().to_vec())
    else {
        return;
    };
    let object_id = federation_object_id(&encoded);
    if origin.pending_updates.is_empty() {
        origin.object_id = *object_id.as_bytes();
    }
    let descriptor = agenc_ircd_federation_wire::OriginDescriptor {
        coordinator_server_id: edge.config.coordinator.server_id(),
        server_incarnation: edge.config.incarnation,
        origin_id: record.origin_id,
        generation: record.generation,
        object_id,
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

/// Sends FORIGIN DEL for a closed connection. The origin stays retained,
/// marked deleted, until the coordinator acknowledges the deletion: a DEL
/// lost with the link is replayed after the next reset.
pub(super) fn delete_origin(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
) {
    let Some(origin) = edge.origins.get_mut(&generation) else {
        return;
    };
    origin.deleted = true;
    send_origin_del(edge, context, generation);
}

fn send_origin_del(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
) {
    if !super::journal::is_durable(edge, super::journal::Identity::Origin(generation)) {
        super::journal::retain(edge, context, super::journal::Identity::Origin(generation));
        return;
    }
    let Some(origin) = edge.origins.get(&generation) else {
        return;
    };
    // An update still in flight precedes the DEL on the link, so the
    // coordinator holds that generation, with no operation under it yet,
    // by the time the DEL arrives.
    let (declared_generation, next_operation_sequence) = origin
        .pending_updates
        .front()
        .map_or((origin.generation, origin.sequence), |update| {
            (update.generation, 0)
        });
    let frame = agenc_ircd_federation_wire::FederationFrame::OriginDel {
        coordinator_server_id: edge.config.coordinator.server_id(),
        server_incarnation: edge.config.incarnation,
        origin_id: origin.origin_id,
        generation: declared_generation,
        next_operation_sequence,
    };
    edge.send_frame(context, &frame);
}

/// Encodes one request for the connection's origin, consuming the next
/// operation sequence.
pub(super) fn prepare_request(
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
    if !origin.pending_updates.is_empty() {
        return Err(Violation::Phase);
    }
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
pub(super) fn register_request(
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
            sink_gone: false,
            kind,
            header,
            bytes,
            sent: false,
            result: None,
            result_bytes: Vec::new(),
            replies: Vec::new(),
            join_echoes: Vec::new(),
            completion: None,
            completion_generation: None,
            completion_coverage: None,
        },
    );
    edge.counters.requests_sent = edge.counters.requests_sent.saturating_add(1);
    if header.opcode != agenc_ircd_types::FederationOpcode::HistoryQuery {
        super::journal::retain_request(edge, context, request_id, generation);
    }
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
    // A resync or a client's departure deletes the origin and marks its
    // in-flight requests sink-gone. The coordinator drops that origin on the
    // replayed DEL, so replaying the request would only draw Violation::Origin
    // and loop the link. Such a request is abandoned when the origin retires.
    if edge
        .origins
        .get(&pending.generation)
        .is_none_or(|origin| origin.deleted)
    {
        return;
    }
    if origin_update_pending(edge, pending) {
        return;
    }
    if pending.header.opcode != agenc_ircd_types::FederationOpcode::HistoryQuery
        && !super::journal::is_durable(edge, super::journal::Identity::Request(request_id))
    {
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

fn origin_update_pending(edge: &EdgeFederation, pending: &PendingRequest) -> bool {
    edge.origins.get(&pending.generation).is_some_and(|origin| {
        !origin.deleted
            && (origin.acked_generation != Some(pending.header.replay_key.origin_generation)
                || !origin.pending_updates.is_empty())
    })
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
// agenc-review: allow owner=runtime reviewed=2026-09-03 reason=a session open carries the connection its registration facts capability hash and optional grant in the exact field order of the operation
#[allow(clippy::too_many_arguments)]
pub(super) fn send_session_open(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    event_generation: u64,
    nickname: &str,
    realname: &str,
    capability_hash: [u8; 32],
    auth_grant_id: Option<[u8; 32]>,
) -> Result<(), Violation> {
    let origin = edge.origins.get(&generation).ok_or(Violation::Phase)?;
    let parsed = agenc_ircd_domain::NicknameValue::parse(nickname).map_err(|_| Violation::Codec)?;
    let operation = FederatedOperation::SessionOpen {
        connection_id: origin.connection_id,
        auth_grant_id,
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

/// Forwards one sealed account-service envelope of a pre-registration
/// client to the coordinator's account service (spec 22.2).
pub(super) fn send_account_carrier(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    opcode: agenc_ircd_types::FederationOpcode,
    envelope: &[u8],
    finish: bool,
    carrier_generation: u64,
) -> Result<(), Violation> {
    if edge.phase != Phase::Active {
        return Err(Violation::Phase);
    }
    let mut budget = DecodeBudget::new(8_192, 64);
    let envelope = SchemaObject::decode_exact("AccountServiceEnvelope", envelope, &mut budget)
        .map_err(|_| Violation::Codec)?;
    let sasl = matches!(
        opcode,
        agenc_ircd_types::FederationOpcode::OpaqueAuthStart
            | agenc_ircd_types::FederationOpcode::OpaqueAuthFinish
    );
    let operation = FederatedOperation::AccountService {
        opcode,
        session_id: None,
        envelope,
    };
    let prepared = prepare_request(edge, context, generation, &operation)?;
    register_request(
        edge,
        context,
        generation,
        prepared,
        PendingKind::AccountCarrier {
            sasl,
            finish,
            carrier_generation,
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
    if edge.phase != Phase::Active && !is_local_user_mode_query(&message) {
        return Err((message, DomainError::ServerBusy));
    }
    let Some((session_id, user_id)) = edge
        .origins
        .get(&generation)
        .and_then(|origin| origin.session)
    else {
        return Err((message, DomainError::RegistrationRequired));
    };
    if must_defer_command(edge, generation) {
        return defer_command(edge, context, generation, kind, message);
    }
    let Ok(command) =
        crate::command_convert::convert(context.domain(), &edge.replica, kind, &message)
    else {
        return Err((message, DomainError::InvalidArgument));
    };
    if let CanonicalCommandView::Mode(ModeCommand::UserQuery(target)) = command.view() {
        return local_user_modes(edge, context, generation, user_id, &message, target)
            .map_err(|error| (message, error));
    }
    let operation = match operation_of(edge, session_id, user_id, &message, &command) {
        Ok(operation) => operation,
        Err(error) => return Err((message, error)),
    };
    if matches!(operation, FederatedOperation::HistoryQuery { .. }) {
        return super::history::begin(edge, context, generation, message, operation);
    }
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

fn defer_command(
    edge: &mut EdgeFederation,
    context: &StateCoreContext,
    generation: ConnectionGeneration,
    kind: RegisteredCommandKind,
    message: Box<ParsedMessage>,
) -> Result<(), (Box<ParsedMessage>, DomainError)> {
    let queue = edge.deferred.entry(generation).or_default();
    if queue.len() >= MAX_DEFERRED_COMMANDS {
        return Err((message, DomainError::ServerBusy));
    }
    let Some(backing) = message
        .requested_backing_bytes()
        .checked_add(size_of::<ParsedMessage>())
    else {
        return Err((message, DomainError::ServerBusy));
    };
    let Ok(permit) = context.reserve_output_backing(backing) else {
        return Err((message, DomainError::ServerBusy));
    };
    if queue
        .reserve(MAX_DEFERRED_COMMANDS, |bytes| {
            context.reserve_output_backing(bytes)
        })
        .is_err()
    {
        return Err((message, DomainError::ServerBusy));
    }
    let entry = DeferredCommand {
        kind,
        message,
        _permit: permit,
    };
    if let Err(entry) = queue.push_back(entry) {
        return Err((entry.message, DomainError::ServerBusy));
    }
    Ok(())
}

/// Identifies the own-session read whose authority remains local during a partition.
pub(crate) fn is_local_user_mode_query(message: &ParsedMessage) -> bool {
    message.command() == "MODE"
        && message.trailing().is_none()
        && matches!(message.middle(), [target] if agenc_ircd_domain::NicknameValue::parse(target).is_ok())
}

fn must_defer_command(edge: &EdgeFederation, generation: ConnectionGeneration) -> bool {
    edge.phase == Phase::Active
        && (edge
            .pending
            .values()
            .any(|pending| pending.generation == generation)
            || edge.origins.get(&generation).is_some_and(|origin| {
                origin.join_names_pending || !origin.pending_updates.is_empty()
            }))
}

fn local_user_modes(
    edge: &EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    user_id: UserId,
    message: &ParsedMessage,
    target: &agenc_ircd_domain::NicknameValue,
) -> Result<(), DomainError> {
    let command = CanonicalCommand::user_mode_query(target.clone());
    let charges = context.domain().command_charges(user_id, &command);
    let now = context.now();
    context
        .buckets_mut()
        .apply_domain_charges(now, &charges)
        .map_err(|_| DomainError::ServerBusy)?;
    let session = edge
        .replica
        .session(user_id)
        .ok_or(DomainError::RegistrationRequired)?;
    if session.nickname != *target {
        return Err(DomainError::Forbidden);
    }
    let modes = if session.user_mode_bits & 2 == 0 {
        "+i"
    } else {
        "+iw"
    };
    let frame = agenc_ircd_client_wire::numeric_reply(
        context.server_prefix(),
        221,
        session.nickname.presentation(),
        &[modes],
        None,
    )
    .map_err(|_| DomainError::InvariantViolation)?;
    let capabilities = context
        .sessions()
        .capabilities_for_user(user_id)
        .ok_or(DomainError::RegistrationRequired)?;
    let frames = crate::client_render::logical_frames(
        context.server_prefix(),
        capabilities,
        message,
        vec![frame],
    )
    .map_err(|_| DomainError::InvariantViolation)?;
    context
        .send_to(generation, frames)
        .map_err(|_| DomainError::ServerBusy)?;
    Ok(())
}

fn session_revision(edge: &EdgeFederation, user_id: UserId) -> Result<u64, DomainError> {
    edge.replica
        .session(user_id)
        .map(|session| session.session_revision.get())
        .ok_or(DomainError::RegistrationRequired)
}

/// Owner-controlled channel state changes: registration, unregistration,
/// and the history policy, each pinned to the replica's channel revision.
fn channel_control_operation(
    edge: &EdgeFederation,
    session_id: SessionId,
    command: agenc_ircd_domain::ChannelCommand,
) -> Result<FederatedOperation, DomainError> {
    use agenc_ircd_domain::ChannelCommand;
    let channel_id = match command {
        ChannelCommand::Register(channel_id)
        | ChannelCommand::Unregister(channel_id)
        | ChannelCommand::History(channel_id, _)
        | ChannelCommand::HistoryDefault(channel_id) => channel_id,
    };
    let expected_channel_revision = edge
        .replica
        .channel(channel_id)
        .map(|channel| channel.channel_revision.get())
        .ok_or(DomainError::NotFound)?;
    Ok(match command {
        ChannelCommand::Register(_) => FederatedOperation::ChannelRegister {
            session_id,
            channel_id,
            expected_channel_revision,
        },
        ChannelCommand::Unregister(_) => FederatedOperation::ChannelUnregister {
            session_id,
            channel_id,
            expected_channel_revision,
        },
        ChannelCommand::History(_, policy) => FederatedOperation::ChannelSettings {
            session_id,
            channel_id,
            expected_channel_revision,
            setting_kind: crate::federation::codec::history_setting_kind(policy),
        },
        ChannelCommand::HistoryDefault(_) => FederatedOperation::ChannelSettings {
            session_id,
            channel_id,
            expected_channel_revision,
            setting_kind: 5,
        },
    })
}

impl crate::command_convert::ChannelResolver for agenc_ircd_domain::federation::EdgeReplica {
    fn channel_id_of(
        &self,
        name: &agenc_ircd_domain::ChannelNameValue,
    ) -> Option<agenc_ircd_types::ChannelInstanceId> {
        self.channel_by_name(name).map(|channel| channel.channel_id)
    }
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

fn account_operation(
    edge: &EdgeFederation,
    session_id: SessionId,
    user_id: UserId,
    command: &agenc_ircd_domain::AccountCommand,
) -> Result<FederatedOperation, DomainError> {
    let (account_id, _) = edge
        .replica
        .session(user_id)
        .and_then(|session| session.account)
        .ok_or(DomainError::RegistrationRequired)?;
    let expected_account_revision = edge
        .replica
        .account(account_id)
        .map(|account| account.account_revision.get())
        .ok_or(DomainError::RegistrationRequired)?;
    let (setting_kind, value) = account_change(command)?;
    Ok(FederatedOperation::AccountSettings {
        session_id,
        expected_account_revision,
        setting_kind,
        value,
    })
}

fn account_change(
    command: &agenc_ircd_domain::AccountCommand,
) -> Result<(u16, Vec<u8>), DomainError> {
    use agenc_ircd_domain::AccountCommand;
    Ok(match command {
        AccountCommand::Label(Some(label)) => (1, label.as_str().as_bytes().to_vec()),
        AccountCommand::ContactAdd(account) => (7, account.to_text().into_bytes()),
        AccountCommand::ContactRemove(account) => (8, account.to_text().into_bytes()),
        AccountCommand::NickReserve(nickname) => (9, nickname.presentation().as_bytes().to_vec()),
        AccountCommand::NickRelease(nickname) => (10, nickname.presentation().as_bytes().to_vec()),
        AccountCommand::DeleteConfirm(token) => (12, token.expose_for_deletion().to_vec()),
        other => (account_flag(other)?, Vec::new()),
    })
}

fn account_flag(command: &agenc_ircd_domain::AccountCommand) -> Result<u16, DomainError> {
    use agenc_ircd_domain::{
        AccountCommand, DirectMessagePolicy, GuestDirectMessagePolicy, PresencePolicy,
    };
    Ok(match command {
        AccountCommand::Label(None) => 2,
        AccountCommand::Presence(PresencePolicy::Public) => 3,
        AccountCommand::Presence(PresencePolicy::Private) => 4,
        AccountCommand::GuestDirectMessages(GuestDirectMessagePolicy::Allow) => 5,
        AccountCommand::GuestDirectMessages(GuestDirectMessagePolicy::Deny) => 6,
        AccountCommand::DeleteStart => 11,
        AccountCommand::DirectMessages(DirectMessagePolicy::Allow) => 13,
        AccountCommand::DirectMessages(DirectMessagePolicy::Contacts) => 14,
        AccountCommand::DirectMessages(DirectMessagePolicy::Deny) => 15,
        _ => return Err(DomainError::InvalidArgument),
    })
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
        CanonicalCommandView::Channel(command) => {
            channel_control_operation(edge, session_id, command)
        }
        CanonicalCommandView::Account(command) => {
            account_operation(edge, session_id, user_id, command)
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
        CanonicalCommandView::Mode(
            ModeCommand::ChannelQuery(_) | ModeCommand::ChannelList(_, _),
        ) => super::directory::operation(session_id, command, None),
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
        CanonicalCommandView::Chathistory(channel_id, query) => {
            Ok(FederatedOperation::HistoryQuery {
                session_id,
                channel_id,
                selector: crate::federation::codec::history::selector_object(query.selector())
                    .map_err(|_| DomainError::InvalidArgument)?,
                limit: query.limit(),
                cursor: None,
            })
        }
        _ => super::directory::operation(session_id, command, None),
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
        ModeCommand::UserOperatorNotices(target, enabled) => {
            user_mode_operation(edge, session_id, user_id, target, *enabled)
        }
        ModeCommand::UserQuery(_)
        | ModeCommand::ChannelQuery(_)
        | ModeCommand::ChannelList(_, _) => Err(DomainError::BadState),
    }
}

fn user_mode_operation(
    edge: &EdgeFederation,
    session_id: SessionId,
    user_id: UserId,
    target: &agenc_ircd_domain::NicknameValue,
    enabled: bool,
) -> Result<FederatedOperation, DomainError> {
    let session = edge
        .replica
        .session(user_id)
        .ok_or(DomainError::RegistrationRequired)?;
    if session.nickname != *target {
        return Err(DomainError::Forbidden);
    }
    Ok(FederatedOperation::UserMode {
        session_id,
        expected_session_revision: session.session_revision.get(),
        changes: vec![ModeChangeArg {
            direction: flag(enabled),
            mode_code: USER_MODE_CODE_WALLOPS,
            argument: Zeroizing::new(Vec::new()),
        }],
    })
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
    validate_result_completion(edge, &header)?;
    let Some(pending) = edge.pending.get(&header.request_id) else {
        return Ok(Vec::new());
    };
    if pending.header.replay_key != header.replay_key
        || header.request_object_id != federation_object_id(&pending.bytes)
    {
        return Err(Violation::Consistency);
    }
    if pending.result.is_some() {
        return repeated_result(pending, object);
    }
    let arm = ResultArm::from_object(
        header.result_kind,
        &decode_result_arm(&result, &mut budget).map_err(|_| Violation::Codec)?,
    )
    .map_err(|_| Violation::Codec)?;
    validate_result_generation(edge, header.request_id, &arm)?;
    super::join_echo::validate_result(edge, header.request_id, &arm)?;
    if pending.header.opcode == agenc_ircd_types::FederationOpcode::HistoryQuery {
        return super::history::receive(edge, context, header, object.object_id(), arm);
    }
    let mut replies = Vec::new();
    for reply in agenc_ircd_federation_wire::access::vector(&result, "replies")
        .map_err(|_| Violation::Codec)?
    {
        replies.push(reply_frame(&edge.config.server_name, reply)?);
    }
    let pending = edge
        .pending
        .get_mut(&header.request_id)
        .ok_or(Violation::Consistency)?;
    pending.replies = replies;
    pending.result_bytes = object.as_slice().to_vec();
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
            super::journal::retain(
                edge,
                context,
                super::journal::Identity::Request(header.request_id),
            );
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

/// A result cannot substitute another request's pending or durable completion.
fn validate_result_completion(
    edge: &EdgeFederation,
    header: &ResultHeader,
) -> Result<(), Violation> {
    let Some(pending) = edge.pending.get(&header.request_id) else {
        return Ok(());
    };
    let changed = pending
        .completion
        .is_some_and(|id| Some(id) != header.completion_event_id);
    let wrong_owner = header.completion_event_id.is_some_and(|id| {
        (edge.applied_completions.contains(&id) && pending.completion != Some(id))
            || edge
                .by_completion
                .get(&id)
                .is_some_and(|owner| *owner != header.request_id)
    });
    if changed || wrong_owner {
        return Err(Violation::Consistency);
    }
    Ok(())
}

/// The generation repeated only by results that require a completion event.
pub(super) fn result_generation(result: &ResultArm) -> Option<u64> {
    match result {
        ResultArm::Committed {
            resulting_state_generation,
        } => Some(*resulting_state_generation),
        ResultArm::SessionRegistered(registered) => Some(registered.resulting_state_generation),
        _ => None,
    }
}

fn validate_result_generation(
    edge: &EdgeFederation,
    request_id: RequestId,
    result: &ResultArm,
) -> Result<(), Violation> {
    let expected = edge
        .pending
        .get(&request_id)
        .and_then(|pending| pending.completion_generation)
        .or_else(|| super::events::staged_completion_generation(edge, request_id));
    if expected.is_some_and(|generation| result_generation(result) != Some(generation)) {
        return Err(Violation::Consistency);
    }
    Ok(())
}

fn repeated_result(
    pending: &PendingRequest,
    object: &AssembledObject,
) -> Result<Vec<EdgeCompletion>, Violation> {
    if pending.result_bytes == object.as_slice() {
        Ok(Vec::new())
    } else {
        Err(Violation::Consistency)
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
    if edge.pending.get(&request_id).is_some_and(|pending| {
        pending.header.opcode != agenc_ircd_types::FederationOpcode::HistoryQuery
    }) && !super::journal::is_durable(edge, super::journal::Identity::Request(request_id))
    {
        super::journal::retain(edge, context, super::journal::Identity::Request(request_id));
        return Vec::new();
    }
    super::journal::forget(edge, request_id);
    let generation = edge
        .pending
        .get(&request_id)
        .map(|pending| pending.generation);
    let continues_query = edge.pending.get(&request_id).is_some_and(|pending| {
        matches!(
            pending.result,
            Some(ResultArm::ReplyPage {
                next_cursor: Some(_),
                ..
            })
        )
    });
    let mut completions = completed_request(edge, context, request_id);
    if let Some(generation) = generation {
        super::journal::retire_origin(edge, generation);
        if !continues_query {
            completions.extend(dispatch_deferred(edge, context, generation));
        }
    }
    completions
}

/// Sends the connection's next deferred commands once nothing of its is
/// in flight; a command that cannot be sent fails to the client in order.
pub(super) fn dispatch_deferred(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
) -> Vec<EdgeCompletion> {
    let mut completions = Vec::new();
    loop {
        let in_flight = edge
            .pending
            .values()
            .any(|pending| pending.generation == generation)
            || edge.origins.get(&generation).is_some_and(|origin| {
                origin.join_names_pending || !origin.pending_updates.is_empty()
            });
        if in_flight {
            break;
        }
        let Some(next) = edge
            .deferred
            .get_mut(&generation)
            .and_then(crate::budget::RetainedQueue::pop_front)
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
// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one match pairs every pending request kind with the result kinds the profile permits for it so a forbidden pair is visible in place
fn completed_request(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    request_id: RequestId,
) -> Vec<EdgeCompletion> {
    let Some(pending) = edge.pending.remove(&request_id) else {
        return Vec::new();
    };
    if pending.sink_gone {
        pending.sink_gone(edge);
        return Vec::new();
    }
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
                origin.account = registered
                    .account
                    .map(|(account, generation, _)| (account, generation));
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
        (
            PendingKind::AccountCarrier {
                sasl,
                finish,
                carrier_generation,
            },
            result,
        ) => vec![EdgeCompletion::AccountCarrier {
            generation,
            carrier_generation,
            sasl,
            finish,
            outcome: carrier_outcome(result, &pending.replies, sasl),
        }],
        (PendingKind::Command { message }, ResultArm::Failed { code, .. }) => {
            vec![EdgeCompletion::CommandFailed {
                generation,
                message,
                error: failure_error(&code).unwrap_or(DomainError::ServerBusy),
            }]
        }
        (
            PendingKind::Command { message },
            ResultArm::ReplyPage {
                page_sequence,
                next_cursor,
                ..
            },
        ) => {
            vec![EdgeCompletion::Replies {
                generation,
                frames: pending.replies,
                page_sequence,
                next_cursor,
                message,
            }]
        }
        (
            PendingKind::Command { message },
            ResultArm::Committed {
                resulting_state_generation,
            },
        ) if message.command() == "JOIN" => {
            if let Some(origin) = edge.origins.get_mut(&generation) {
                origin.join_names_pending = true;
            }
            super::join_echo::complete(
                context,
                generation,
                message,
                resulting_state_generation,
                pending.join_echoes,
                pending.replies,
            )
        }
        (PendingKind::Command { message }, ResultArm::Committed { .. })
            if pending.header.opcode == agenc_ircd_types::FederationOpcode::AccountSettings
                && is_committed_account_deletion(&message, &pending.replies) =>
        {
            vec![EdgeCompletion::AccountDeleted {
                generation,
                frames: pending.replies,
                message,
            }]
        }
        (PendingKind::Command { message }, _) if !pending.replies.is_empty() => {
            vec![EdgeCompletion::Replies {
                generation,
                frames: pending.replies,
                next_cursor: None,
                page_sequence: 0,
                message,
            }]
        }
        (PendingKind::Command { message }, ResultArm::NoContent) => vec![EdgeCompletion::Replies {
            generation,
            frames: Vec::new(),
            page_sequence: 0,
            next_cursor: None,
            message,
        }],
        (PendingKind::Command { message }, _) => vec![EdgeCompletion::CommandCompleted {
            generation,
            message,
        }],
        (PendingKind::Close, _) => Vec::new(),
    }
}

fn is_committed_account_deletion(
    message: &ParsedMessage,
    replies: &[agenc_ircd_client_wire::WireMessage],
) -> bool {
    if message.command() != "ACCT" {
        return false;
    }
    let [operation, confirmation, ..] = message.middle() else {
        return false;
    };
    if !operation.eq_ignore_ascii_case("DELETE") || !confirmation.eq_ignore_ascii_case("CONFIRM") {
        return false;
    }
    let [reply] = replies else {
        return false;
    };
    reply.command() == "NOTE"
        && reply.middle() == ["ACCT", "UPDATED"]
        && reply.trailing() == Some("Account setting updated")
}

/// Sends the NAMES query of one channel for a connection.
pub(super) fn send_names(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    channel: &str,
    cursor: Option<[u8; 32]>,
) {
    let line = format!("NAMES {channel}");
    let Ok(Some(message)) = agenc_ircd_client_wire::FramedLine::new(&line)
        .map_err(|_| ())
        .and_then(|framed| agenc_ircd_client_wire::parse_message(framed).map_err(|_| ()))
    else {
        return;
    };
    let _started = send_directory_query(edge, context, generation, Box::new(message), cursor);
}

/// Re-issues the client's query with the continuation cursor.
pub(super) fn continue_query(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    message: Box<ParsedMessage>,
    cursor: [u8; 32],
) -> bool {
    send_directory_query(edge, context, generation, message, Some(cursor))
}

fn send_directory_query(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    message: Box<ParsedMessage>,
    cursor: Option<[u8; 32]>,
) -> bool {
    let Some((session_id, _)) = edge
        .origins
        .get(&generation)
        .and_then(|origin| origin.session)
    else {
        return false;
    };
    let Ok(proof) = agenc_ircd_client_wire::validate_post_registration_command(&message) else {
        return false;
    };
    let kind = RegisteredCommandKind::Public(proof.kind());
    let Ok(command) =
        crate::command_convert::convert(context.domain(), &edge.replica, kind, &message)
    else {
        return false;
    };
    let Ok(operation) = super::directory::operation(session_id, &command, cursor) else {
        return false;
    };
    let Ok(prepared) = prepare_request(edge, context, generation, &operation) else {
        return false;
    };
    register_request(
        edge,
        context,
        generation,
        prepared,
        PendingKind::Command { message },
    );
    true
}

pub(super) fn continue_join_names(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    channels: &[agenc_ircd_domain::ChannelNameValue],
    message: Box<ParsedMessage>,
    cursor: Option<[u8; 32]>,
) -> bool {
    if edge.phase != Phase::Active {
        return false;
    }
    let Some(origin) = edge
        .origins
        .get(&generation)
        .filter(|origin| origin.join_names_pending)
    else {
        return false;
    };
    let Some((session_id, _)) = origin.session else {
        return false;
    };
    let Ok(command) = CanonicalCommand::names(channels.to_vec()) else {
        return false;
    };
    let Ok(operation) = super::directory::operation(session_id, &command, cursor) else {
        return false;
    };
    let Ok(prepared) = prepare_request(edge, context, generation, &operation) else {
        return false;
    };
    register_request(
        edge,
        context,
        generation,
        prepared,
        PendingKind::Command { message },
    );
    true
}

/// What the coordinator's account service answered for one forwarded
/// carrier envelope.
pub enum RemoteCarrierOutcome {
    /// The sealed start challenge, for the edge transport to chunk.
    Challenge(Vec<u8>),
    /// The client authenticated; the reply block carried the sealed
    /// completion chunks and the grant names the account at session open.
    Authenticated {
        /// The account.
        account_id: agenc_ircd_types::AccountId,
        /// The account session generation.
        account_session_generation: u64,
        /// The pre-registration grant to present in `session_open`.
        auth_grant_id: [u8; 32],
        /// The sealed completion, as the relayed payload chunks.
        chunks: Vec<String>,
    },
    /// The account was created; the reply block carried the completion.
    Created {
        /// The account.
        account_id: agenc_ircd_types::AccountId,
        /// The sealed completion, as the relayed payload chunks.
        chunks: Vec<String>,
    },
    /// The account service refused; a sealed rejection may accompany it.
    Failed {
        /// The sealed rejection, as the relayed payload chunks.
        chunks: Vec<String>,
    },
}

/// Maps one result and its relayed replies onto the carrier outcome.
fn carrier_outcome(
    result: ResultArm,
    replies: &[agenc_ircd_client_wire::WireMessage],
    sasl: bool,
) -> RemoteCarrierOutcome {
    let chunks: Vec<String> = replies
        .iter()
        .filter_map(|reply| reply_chunk(reply, sasl))
        .collect();
    match result {
        ResultArm::AuthChallenge(response) => {
            let encoded = agenc_ircd_federation_wire::CanonicalEncode::encode_canonical(&response);
            encoded.map_or(RemoteCarrierOutcome::Failed { chunks }, |bytes| {
                RemoteCarrierOutcome::Challenge(bytes.as_slice().to_vec())
            })
        }
        ResultArm::Authenticated {
            account_id,
            account_session_generation,
            auth_grant_id,
        } => RemoteCarrierOutcome::Authenticated {
            account_id,
            account_session_generation,
            auth_grant_id,
            chunks,
        },
        ResultArm::AccountCreated { account_id, .. } => {
            RemoteCarrierOutcome::Created { account_id, chunks }
        }
        _ => RemoteCarrierOutcome::Failed { chunks },
    }
}

/// The payload chunk one relayed reply carries, for the carrier class.
fn reply_chunk(reply: &agenc_ircd_client_wire::WireMessage, sasl: bool) -> Option<String> {
    let middle = reply.middle();
    if sasl {
        return (reply.command() == "AUTHENTICATE").then(|| middle.first().cloned())?;
    }
    let data =
        reply.command() == "ACCTCREATE" && middle.first().map(String::as_str) == Some("DATA");
    data.then(|| middle.get(1).cloned())?
}
