//! Maps a decoded federated operation onto the domain command the
//! coordinator executes for the remote session (spec 20.5.2).
//!
//! Every conversion re-checks that the named session is hosted by the
//! requesting edge and that the operation's expected revisions match the
//! live entities, so a stale edge view fails closed before authorization.

use agenc_ircd_domain::federation::{MutationContext, SessionHideKind};
use agenc_ircd_domain::{
    AccountCommand, AccountLabelValue, AwayText, CanonicalCommand, ChannelCommand,
    ChannelNameValue, ChannelTarget, DirectMessagePolicy, DisplayNameValue, DomainError,
    DomainState, ExternalInputRequest, GuestDirectMessagePolicy, InformationQuery, MaskList,
    MessageCommand, MessageKind, MessageTarget, MessageText, ModeChange, ModeOperation,
    NicknameValue, PresenceCommand, PresencePolicy, SessionSeed, TopicText, UserQuery, WhoTarget,
};
use agenc_ircd_federation_wire::CanonicalEncode as _;
use agenc_ircd_federation_wire::access::{
    opaque_field, structure, text, unsigned, unsigned_u16, vector,
};
use agenc_ircd_federation_wire::{DecodeBudget, SchemaObject};
use agenc_ircd_types::FederationOpcode;
use agenc_ircd_types::{
    AccountDeletionToken, AccountId, ChannelInstanceId, ControlPolicy,
    FederationDirectoryQueryKind, Generation, Revision, ServerId, SessionId, UserId,
};
use zeroize::Zeroizing;

use crate::RuntimeError;
use crate::federation::codec::operations::{FederatedOperation, MessageTargetArg, ModeChangeArg};
use crate::federation::codec::{channel_name_of, history_of_value, nickname_of};
use crate::state_core::StateCoreContext;
use crate::state_core::session::BoundSession;

/// User-mode code for `w` in the B.4 registry.
const USER_MODE_CODE_WALLOPS: u16 = 2;

/// What one operation converts into.
pub(super) enum ConvertedRequest {
    /// A new session hosted by the requesting edge.
    SessionOpen(Box<SessionSeed>),
    /// A session whose account a pre-registration grant proves.
    SessionOpenWithGrant(Box<SessionSeed>, [u8; 32]),
    /// A sealed account-service envelope a pre-registration client sent
    /// through its edge (spec 22.2).
    AccountService {
        opcode: FederationOpcode,
        envelope: Vec<u8>,
    },
    /// A session close with its hide kind.
    SessionClose {
        user_id: UserId,
        kind: SessionHideKind,
    },
    /// A command for an existing remote session.
    Command(Box<CommandRequest>),
    /// A directory query, fresh or continued.
    Query(Box<QueryRequest>),
    /// A history query, whose selection and storage read the history owner controls.
    History(Box<HistoryRequest>),
    /// An operation this coordinator cannot answer (history has no store).
    Unavailable,
}

/// A converted directory query with its cursor identity.
pub(super) struct QueryRequest {
    pub(super) bound: BoundSession,
    pub(super) command: CanonicalCommand,
    pub(super) identity: super::query::QueryIdentity,
    pub(super) cursor: Option<[u8; 32]>,
}

pub(super) struct HistoryRequest {
    pub(super) bound: BoundSession,
    pub(super) channel_id: ChannelInstanceId,
    pub(super) query: agenc_ircd_domain::HistoryQuery,
    pub(super) cursor: Option<[u8; 32]>,
}

/// A converted command with the session it acts for and its intent.
pub(super) struct CommandRequest {
    pub(super) bound: BoundSession,
    pub(super) command: CanonicalCommand,
    pub(super) mutation: MutationContext,
}

/// Converts one operation, validating session ownership and revisions.
pub(super) fn convert_operation(
    context: &mut StateCoreContext,
    peer: ServerId,
    operation: &FederatedOperation,
) -> Result<ConvertedRequest, DomainError> {
    match operation {
        FederatedOperation::SessionOpen { .. } => convert_open(context, peer, operation),
        FederatedOperation::SessionClose {
            session_id,
            reason_code,
        } => {
            let (user_id, _) = hosted_session(context.domain(), peer, *session_id)?;
            let kind =
                SessionHideKind::from_wire(*reason_code).ok_or(DomainError::InvalidArgument)?;
            Ok(ConvertedRequest::SessionClose { user_id, kind })
        }
        FederatedOperation::DirectoryQuery { session_id, query } => {
            let (user_id, bound) = hosted_session(context.domain(), peer, *session_id)?;
            directory_query(context.domain(), bound, user_id, query)
        }
        FederatedOperation::AccountService {
            opcode,
            session_id: None,
            envelope,
        } => {
            let bytes = envelope
                .encode_canonical()
                .map_err(|_| DomainError::InvalidArgument)?;
            Ok(ConvertedRequest::AccountService {
                opcode: *opcode,
                envelope: bytes.as_slice().to_vec(),
            })
        }
        FederatedOperation::HistoryQuery {
            session_id,
            channel_id,
            selector,
            limit,
            cursor,
        } => {
            if !context.history_enabled() {
                return Ok(ConvertedRequest::Unavailable);
            }
            let (_, bound) = hosted_session(context.domain(), peer, *session_id)?;
            let query = crate::federation::codec::history::query_of(selector, *limit)
                .map_err(|_| DomainError::InvalidArgument)?;
            Ok(ConvertedRequest::History(Box::new(HistoryRequest {
                bound,
                channel_id: *channel_id,
                query,
                cursor: *cursor,
            })))
        }
        FederatedOperation::AccountService { .. } => Ok(ConvertedRequest::Unavailable),
        _ => {
            let session_id = operation.session_id().ok_or(DomainError::InvalidArgument)?;
            let (user_id, bound) = hosted_session(context.domain(), peer, session_id)?;
            check_revisions(context.domain(), user_id, operation)?;
            let command = rebuild_command(context.domain(), operation)
                .map_err(|_| DomainError::InvalidArgument)?
                .resolve_history_default(context.history_default())?;
            let mutation = mutation_context(context, user_id, operation);
            Ok(ConvertedRequest::Command(Box::new(CommandRequest {
                bound,
                command,
                mutation,
            })))
        }
    }
}

fn convert_open(
    context: &mut StateCoreContext,
    peer: ServerId,
    operation: &FederatedOperation,
) -> Result<ConvertedRequest, DomainError> {
    let FederatedOperation::SessionOpen {
        auth_grant_id,
        nickname,
        realname,
        capability_hash,
        connection_nonce,
        ..
    } = operation
    else {
        return Err(DomainError::InvalidArgument);
    };
    let seed = Box::new(session_seed(
        context,
        peer,
        nickname,
        realname,
        *capability_hash,
        *connection_nonce,
    )?);
    Ok(match auth_grant_id {
        Some(grant_id) => ConvertedRequest::SessionOpenWithGrant(seed, *grant_id),
        None => ConvertedRequest::SessionOpen(seed),
    })
}

fn session_seed(
    context: &mut StateCoreContext,
    peer: ServerId,
    nickname: &str,
    realname: &str,
    capability_hash: [u8; 32],
    connection_nonce: [u8; 32],
) -> Result<SessionSeed, DomainError> {
    let mut random = [0_u8; 58];
    context
        .entropy_mut()
        .fill_exact(&mut random)
        .map_err(|_| DomainError::ServerBusy)?;
    let (ids, cloak) = random.split_at(32);
    let (session, user) = ids.split_at(16);
    let session_id = SessionId::from_bytes(session.try_into().map_err(|_| DomainError::Overflow)?);
    let user_id = UserId::from_bytes(user.try_into().map_err(|_| DomainError::Overflow)?);
    let public_cloak =
        crate::registration::cloak_from_random(cloak).map_err(|_| DomainError::ServerBusy)?;
    Ok(SessionSeed {
        session_id,
        user_id,
        home_server_id: peer,
        account_id: None,
        account_session_generation: Generation::new(0).map_err(|_| DomainError::Overflow)?,
        generation: Generation::new(1).map_err(|_| DomainError::Overflow)?,
        nickname: NicknameValue::parse(nickname)?,
        display_name: DisplayNameValue::prepare(realname)?,
        public_cloak,
        connection_nonce,
        negotiated_capability_hash: capability_hash,
        created_at_utc: context
            .utc_now()
            .map_err(|_| DomainError::WallClockUnavailable)?,
        revision: Revision::new(context.domain().revision().get())
            .map_err(|_| DomainError::Overflow)?,
    })
}

/// Resolves a session the requesting edge hosts.
fn hosted_session(
    domain: &DomainState,
    peer: ServerId,
    session_id: SessionId,
) -> Result<(UserId, BoundSession), DomainError> {
    let user_id = domain
        .user_for_session(session_id)
        .ok_or(DomainError::NotFound)?;
    let session = domain.session(user_id).ok_or(DomainError::NotFound)?;
    if session.home_server_id() != peer {
        return Err(DomainError::Forbidden);
    }
    Ok((
        user_id,
        BoundSession {
            session_id,
            user_id,
            capability_hash: *session.negotiated_capability_hash(),
        },
    ))
}

/// Compares every expected revision the operation names with live state.
fn check_revisions(
    domain: &DomainState,
    user_id: UserId,
    operation: &FederatedOperation,
) -> Result<(), DomainError> {
    if let Some(expected) = expected_session_revision(operation) {
        let live = domain
            .session(user_id)
            .map(|session| session.revision().get())
            .ok_or(DomainError::NotFound)?;
        return same_revision(live, expected);
    }
    if let Some((channel_id, expected)) = expected_channel_revision(operation) {
        return check_channel_revision(domain, channel_id, expected);
    }
    match operation {
        FederatedOperation::Message { targets, .. } => targets
            .iter()
            .try_for_each(|target| check_message_target(domain, target)),
        FederatedOperation::AccountSettings {
            expected_account_revision,
            ..
        } => {
            let account = domain
                .session(user_id)
                .and_then(|session| session.account_id())
                .and_then(|account| domain.account(account))
                .ok_or(DomainError::RegistrationRequired)?;
            same_revision(account.revision().get(), *expected_account_revision)
        }
        _ => Ok(()),
    }
}

fn check_message_target(
    domain: &DomainState,
    target: &MessageTargetArg,
) -> Result<(), DomainError> {
    match target {
        MessageTargetArg::Channel {
            channel_id,
            expected_revision,
        } => check_channel_revision(domain, *channel_id, *expected_revision),
        MessageTargetArg::User { .. } => Ok(()),
    }
}

fn same_revision(live: u64, expected: u64) -> Result<(), DomainError> {
    if live == expected {
        Ok(())
    } else {
        Err(DomainError::StaleRevision)
    }
}

fn check_channel_revision(
    domain: &DomainState,
    channel_id: ChannelInstanceId,
    expected: u64,
) -> Result<(), DomainError> {
    let channel = domain.channel(channel_id).ok_or(DomainError::NotFound)?;
    same_revision(channel.revision().get(), expected)
}

const fn expected_session_revision(operation: &FederatedOperation) -> Option<u64> {
    match operation {
        FederatedOperation::NickChange {
            expected_session_revision,
            ..
        }
        | FederatedOperation::Join {
            expected_session_revision,
            ..
        }
        | FederatedOperation::Part {
            expected_session_revision,
            ..
        }
        | FederatedOperation::UserMode {
            expected_session_revision,
            ..
        }
        | FederatedOperation::Away {
            expected_session_revision,
            ..
        }
        | FederatedOperation::Setname {
            expected_session_revision,
            ..
        } => Some(*expected_session_revision),
        _ => None,
    }
}

const fn expected_channel_revision(
    operation: &FederatedOperation,
) -> Option<(ChannelInstanceId, u64)> {
    match operation {
        FederatedOperation::ChannelMode {
            channel_id,
            expected_channel_revision,
            ..
        }
        | FederatedOperation::Topic {
            channel_id,
            expected_channel_revision,
            ..
        }
        | FederatedOperation::Invite {
            channel_id,
            expected_channel_revision,
            ..
        }
        | FederatedOperation::Kick {
            channel_id,
            expected_channel_revision,
            ..
        }
        | FederatedOperation::ChannelRegister {
            channel_id,
            expected_channel_revision,
            ..
        }
        | FederatedOperation::ChannelUnregister {
            channel_id,
            expected_channel_revision,
            ..
        }
        | FederatedOperation::ChannelSettings {
            channel_id,
            expected_channel_revision,
            ..
        } => Some((*channel_id, *expected_channel_revision)),
        _ => None,
    }
}

fn channel_name(
    domain: &DomainState,
    channel_id: ChannelInstanceId,
) -> Result<ChannelNameValue, RuntimeError> {
    domain
        .channel(channel_id)
        .map(|channel| channel.name().clone())
        .ok_or(RuntimeError::InvalidValue)
}

fn reason(text: &str) -> Result<Option<AwayText>, RuntimeError> {
    if text.is_empty() {
        return Ok(None);
    }
    AwayText::try_from_str(text, ControlPolicy::PermitHorizontalTab)
        .map(Some)
        .map_err(|_| RuntimeError::InvalidValue)
}

/// Builds the canonical command; the domain consumes it, so callers rebuild
/// it for every authorization pass.
// agenc-review: focus owner=runtime reviewed=2026-09-02 reason=one closed match converts every executable opcode arm into its canonical command
pub(super) fn rebuild_command(
    domain: &DomainState,
    operation: &FederatedOperation,
) -> Result<CanonicalCommand, RuntimeError> {
    let invalid = |_: DomainError| RuntimeError::InvalidValue;
    let bad_text = |_: agenc_ircd_types::ValidationError| RuntimeError::InvalidValue;
    match operation {
        FederatedOperation::NickChange { nickname, .. } => Ok(CanonicalCommand::nick(
            NicknameValue::parse(nickname).map_err(invalid)?,
        )),
        FederatedOperation::Join { targets, .. } => {
            let mut converted = Vec::new();
            converted
                .try_reserve_exact(targets.len())
                .map_err(|_| RuntimeError::MemoryExhausted)?;
            for target in targets {
                let name = ChannelNameValue::parse(&target.channel_name).map_err(invalid)?;
                converted.push(ChannelTarget::new(name, !target.join_key.is_empty()));
            }
            CanonicalCommand::join(converted).map_err(invalid)
        }
        FederatedOperation::Part {
            all_channels,
            channels,
            reason: text,
            ..
        } => {
            if *all_channels {
                return Ok(CanonicalCommand::part_all());
            }
            let mut names = Vec::new();
            names
                .try_reserve_exact(channels.len())
                .map_err(|_| RuntimeError::MemoryExhausted)?;
            for channel_id in channels {
                names.push(channel_name(domain, *channel_id)?);
            }
            CanonicalCommand::part(names, reason(text)?).map_err(invalid)
        }
        FederatedOperation::ChannelMode {
            channel_id,
            changes,
            ..
        } => {
            let name = channel_name(domain, *channel_id)?;
            let changes = channel_mode_changes(domain, &name, changes)?;
            CanonicalCommand::mode(name, changes).map_err(invalid)
        }
        FederatedOperation::UserMode {
            session_id,
            changes,
            ..
        } => user_mode_command(domain, *session_id, changes),
        FederatedOperation::Topic {
            channel_id, topic, ..
        } => Ok(CanonicalCommand::topic_set(
            channel_name(domain, *channel_id)?,
            TopicText::try_from_str(topic, ControlPolicy::PermitHorizontalTab).map_err(bad_text)?,
        )),
        FederatedOperation::Invite {
            channel_id,
            target_nickname,
            ..
        } => Ok(CanonicalCommand::invite(
            NicknameValue::parse(target_nickname).map_err(invalid)?,
            channel_name(domain, *channel_id)?,
        )),
        FederatedOperation::Kick {
            channel_id,
            targets,
            reason: text,
            ..
        } => {
            let mut nicknames = Vec::new();
            nicknames
                .try_reserve_exact(targets.len())
                .map_err(|_| RuntimeError::MemoryExhausted)?;
            for user_id in targets {
                let session = domain.session(*user_id).ok_or(RuntimeError::InvalidValue)?;
                nicknames.push(session.nickname().clone());
            }
            CanonicalCommand::kick(channel_name(domain, *channel_id)?, nicknames, reason(text)?)
                .map_err(invalid)
        }
        FederatedOperation::Message {
            kind,
            targets,
            body,
            ..
        } => message_command(domain, *kind, targets, body),
        FederatedOperation::Away { away_text, .. } => {
            CanonicalCommand::presence(PresenceCommand::Away(reason(away_text)?)).map_err(invalid)
        }
        FederatedOperation::Setname { display_name, .. } => Ok(CanonicalCommand::setname(
            DisplayNameValue::prepare(display_name).map_err(invalid)?,
        )),
        FederatedOperation::ChannelRegister { channel_id, .. } => Ok(CanonicalCommand::channel(
            ChannelCommand::Register(*channel_id),
        )),
        FederatedOperation::ChannelUnregister { channel_id, .. } => Ok(CanonicalCommand::channel(
            ChannelCommand::Unregister(*channel_id),
        )),
        FederatedOperation::ChannelSettings {
            channel_id,
            setting_kind,
            ..
        } => {
            if *setting_kind == 5 {
                return Ok(CanonicalCommand::channel(ChannelCommand::HistoryDefault(
                    *channel_id,
                )));
            }
            let policy = history_of_value(u64::from(
                setting_kind
                    .checked_sub(1)
                    .ok_or(RuntimeError::InvalidValue)?,
            ))
            .ok_or(RuntimeError::InvalidValue)?;
            Ok(CanonicalCommand::channel(ChannelCommand::History(
                *channel_id,
                policy,
            )))
        }
        FederatedOperation::AccountSettings {
            setting_kind,
            value,
            ..
        } => account_command(*setting_kind, value).map(CanonicalCommand::account),
        FederatedOperation::SessionOpen { .. }
        | FederatedOperation::SessionClose { .. }
        | FederatedOperation::HistoryQuery { .. }
        | FederatedOperation::DirectoryQuery { .. }
        | FederatedOperation::AccountService { .. } => Err(RuntimeError::InvalidValue),
    }
}

/// Maps B.4 channel mode codes onto the letters the client converter knows.
const fn channel_mode_letter(code: u16) -> Option<char> {
    Some(match code {
        1 => 'b',
        2 => 'e',
        3 => 'I',
        4 => 'k',
        5 => 'l',
        6 => 'i',
        7 => 'm',
        9 => 'p',
        10 => 's',
        11 => 't',
        12 => 'q',
        13 => 'a',
        14 => 'o',
        15 => 'h',
        16 => 'v',
        _ => return None,
    })
}

fn channel_mode_changes(
    domain: &DomainState,
    channel: &ChannelNameValue,
    changes: &[ModeChangeArg],
) -> Result<Vec<ModeChange>, RuntimeError> {
    let mut converted = Vec::new();
    converted
        .try_reserve_exact(changes.len())
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for change in changes {
        let letter = channel_mode_letter(change.mode_code).ok_or(RuntimeError::InvalidValue)?;
        let operation = match change.direction {
            agenc_ircd_domain::federation::ModeDirection::Add => ModeOperation::Add,
            agenc_ircd_domain::federation::ModeDirection::Remove => ModeOperation::Remove,
        };
        let argument =
            std::str::from_utf8(&change.argument).map_err(|_| RuntimeError::InvalidValue)?;
        let arguments: Vec<&str> = if argument.is_empty() {
            Vec::new()
        } else {
            vec![argument]
        };
        let mut index = 0;
        converted.push(crate::command_convert::mode_change_for(
            domain, channel, operation, letter, &arguments, &mut index,
        )?);
        if index != arguments.len() {
            return Err(RuntimeError::InvalidValue);
        }
    }
    Ok(converted)
}

fn user_mode_command(
    domain: &DomainState,
    session_id: SessionId,
    changes: &[ModeChangeArg],
) -> Result<CanonicalCommand, RuntimeError> {
    let [change] = changes else {
        return Err(RuntimeError::InvalidValue);
    };
    if change.mode_code != USER_MODE_CODE_WALLOPS || !change.argument.is_empty() {
        return Err(RuntimeError::InvalidValue);
    }
    let user_id = domain
        .user_for_session(session_id)
        .ok_or(RuntimeError::InvalidValue)?;
    let session = domain.session(user_id).ok_or(RuntimeError::InvalidValue)?;
    let enabled = change.direction == agenc_ircd_domain::federation::ModeDirection::Add;
    Ok(CanonicalCommand::user_operator_notices(
        session.nickname().clone(),
        enabled,
    ))
}

fn message_command(
    domain: &DomainState,
    kind: MessageKind,
    targets: &[MessageTargetArg],
    body: &str,
) -> Result<CanonicalCommand, RuntimeError> {
    let mut converted = Vec::new();
    converted
        .try_reserve_exact(targets.len())
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for target in targets {
        converted.push(match target {
            MessageTargetArg::Channel { channel_id, .. } => {
                MessageTarget::Channel(channel_name(domain, *channel_id)?)
            }
            MessageTargetArg::User { nickname } => MessageTarget::User(
                NicknameValue::parse(nickname).map_err(|_| RuntimeError::InvalidValue)?,
            ),
        });
    }
    let body = if kind == MessageKind::Tagmsg {
        None
    } else {
        Some(MessageText::parse(body).map_err(|_| RuntimeError::InvalidValue)?)
    };
    let message =
        MessageCommand::new(kind, converted, body).map_err(|_| RuntimeError::InvalidValue)?;
    Ok(CanonicalCommand::message(message))
}

fn account_command(setting_kind: u16, value: &[u8]) -> Result<AccountCommand, RuntimeError> {
    let text = || std::str::from_utf8(value).map_err(|_| RuntimeError::InvalidValue);
    let invalid = |_: DomainError| RuntimeError::InvalidValue;
    let bad_id = |_: agenc_ircd_types::ValidationError| RuntimeError::InvalidValue;
    Ok(match setting_kind {
        1 => AccountCommand::Label(Some(AccountLabelValue::parse(text()?).map_err(invalid)?)),
        2 => AccountCommand::Label(None),
        3 => AccountCommand::Presence(PresencePolicy::Public),
        4 => AccountCommand::Presence(PresencePolicy::Private),
        5 => AccountCommand::GuestDirectMessages(GuestDirectMessagePolicy::Allow),
        6 => AccountCommand::GuestDirectMessages(GuestDirectMessagePolicy::Deny),
        7 => AccountCommand::ContactAdd(AccountId::parse_wire_bytes(value).map_err(bad_id)?),
        8 => AccountCommand::ContactRemove(AccountId::parse_wire_bytes(value).map_err(bad_id)?),
        9 => AccountCommand::NickReserve(NicknameValue::parse(text()?).map_err(invalid)?),
        10 => AccountCommand::NickRelease(NicknameValue::parse(text()?).map_err(invalid)?),
        11 => AccountCommand::DeleteStart,
        12 => AccountCommand::DeleteConfirm(AccountDeletionToken::from_bytes(
            value.try_into().map_err(|_| RuntimeError::InvalidValue)?,
        )),
        13 => AccountCommand::DirectMessages(DirectMessagePolicy::Allow),
        14 => AccountCommand::DirectMessages(DirectMessagePolicy::Contacts),
        15 => AccountCommand::DirectMessages(DirectMessagePolicy::Deny),
        _ => return Err(RuntimeError::InvalidValue),
    })
}

/// Supplies the key bytes for one channel-key external request.
pub(super) fn key_for(
    operation: &FederatedOperation,
    request: &ExternalInputRequest,
) -> Option<Zeroizing<Vec<u8>>> {
    match (operation, request) {
        (
            FederatedOperation::Join { targets, .. },
            ExternalInputRequest::ChannelKeyVerification { target_index, .. },
        ) => targets
            .get(usize::from(*target_index))
            .filter(|target| !target.join_key.is_empty())
            .map(|target| target.join_key.clone()),
        (
            FederatedOperation::ChannelMode { changes, .. },
            ExternalInputRequest::ChannelKeyConstruction { change_index, .. },
        ) => changes
            .get(usize::from(*change_index))
            .filter(|change| change.mode_code == 4)
            .map(|change| change.argument.clone()),
        _ => None,
    }
}

/// The intent the projection needs beyond the plan itself.
fn mutation_context(
    context: &StateCoreContext,
    user_id: UserId,
    operation: &FederatedOperation,
) -> MutationContext {
    let received = context
        .utc_now()
        .map(|now| now.get().saturating_mul(1_000))
        .unwrap_or(0);
    let mut mutation = MutationContext {
        actor: Some(user_id),
        received_unix_milliseconds: received,
        ..MutationContext::default()
    };
    match operation {
        FederatedOperation::Part { reason, .. } => mutation.reason = reason.clone(),
        FederatedOperation::Kick { reason, .. } => {
            mutation.reason = reason.clone();
            mutation.kicked = true;
        }
        FederatedOperation::Invite {
            target_nickname, ..
        } => {
            mutation.named_target = NicknameValue::parse(target_nickname)
                .ok()
                .and_then(|nickname| context.domain().resolve_nickname(&nickname));
        }
        FederatedOperation::Message { tags, .. } => mutation.client_tags = tags.clone(),
        _ => {}
    }
    mutation
}

/// Maps a directory query kind onto its registered arm schema.
const fn directory_schema(kind: FederationDirectoryQueryKind) -> &'static str {
    match kind {
        FederationDirectoryQueryKind::List => "directory.list",
        FederationDirectoryQueryKind::Names => "directory.names",
        FederationDirectoryQueryKind::Who => "directory.who",
        FederationDirectoryQueryKind::Whois => "directory.whois",
        FederationDirectoryQueryKind::Whowas => "directory.whowas",
        FederationDirectoryQueryKind::Ison => "directory.ison",
        FederationDirectoryQueryKind::Userhost => "directory.userhost",
        FederationDirectoryQueryKind::Links => "directory.links",
        FederationDirectoryQueryKind::MonitorAdd => "directory.monitor_add",
        FederationDirectoryQueryKind::MonitorRemove => "directory.monitor_remove",
        FederationDirectoryQueryKind::MonitorClear => "directory.monitor_clear",
        FederationDirectoryQueryKind::MonitorList => "directory.monitor_list",
        FederationDirectoryQueryKind::MonitorStatus => "directory.monitor_status",
        FederationDirectoryQueryKind::ChannelTopic => "directory.channel_topic",
        FederationDirectoryQueryKind::ChannelModes => "directory.channel_modes",
        FederationDirectoryQueryKind::ChannelModeList => "directory.channel_mode_list",
    }
}

/// Rebuilds the canonical command of an already decoded query identity;
/// the domain consumes commands, so authorization passes rebuild it.
pub(super) fn rebuild_query(
    _domain: &DomainState,
    identity: &super::query::QueryIdentity,
) -> Result<CanonicalCommand, RuntimeError> {
    let mut budget = DecodeBudget::new(4_096, 256);
    let arm =
        SchemaObject::decode_exact(directory_schema(identity.kind), &identity.arm, &mut budget)
            .map_err(|_| RuntimeError::InvalidValue)?;
    directory_command(identity.kind, &arm).map_err(|_| RuntimeError::InvalidValue)
}

/// Decodes a `DirectoryQuery` into the canonical command and its cursor.
fn directory_query(
    domain: &DomainState,
    bound: BoundSession,
    user_id: UserId,
    query: &SchemaObject,
) -> Result<ConvertedRequest, DomainError> {
    let invalid = |_| DomainError::InvalidArgument;
    let kind = FederationDirectoryQueryKind::from_wire(
        unsigned_u16(query, "query_kind").map_err(invalid)?,
    )
    .map_err(|_| DomainError::InvalidArgument)?;
    let arm_bytes = opaque_field(query, "query").map_err(invalid)?.to_vec();
    let cursor = match opaque_field(query, "cursor").map_err(invalid)? {
        [] => None,
        bytes => Some(<[u8; 32]>::try_from(bytes).map_err(|_| DomainError::InvalidArgument)?),
    };
    let mut budget = DecodeBudget::new(4_096, 256);
    let arm = SchemaObject::decode_exact(directory_schema(kind), &arm_bytes, &mut budget)
        .map_err(invalid)?;
    let command = directory_command(kind, &arm)?;
    let session = domain.session(user_id).ok_or(DomainError::NotFound)?;
    let account = session
        .account_id()
        .map(|account| (account, session.account_session_generation()));
    Ok(ConvertedRequest::Query(Box::new(QueryRequest {
        bound,
        command,
        identity: super::query::QueryIdentity {
            session_id: bound.session_id,
            user_id,
            account,
            kind,
            arm: arm_bytes,
        },
        cursor,
    })))
}

fn nicknames_of(arm: &SchemaObject, field: &str) -> Result<Vec<NicknameValue>, DomainError> {
    let items = vector(arm, field).map_err(|_| DomainError::InvalidArgument)?;
    let mut nicknames = Vec::new();
    nicknames
        .try_reserve_exact(items.len())
        .map_err(|_| DomainError::AllocationFailed)?;
    for item in items {
        nicknames.push(nickname_of(item).map_err(|_| DomainError::InvalidArgument)?);
    }
    Ok(nicknames)
}

fn channel_names_of(arm: &SchemaObject) -> Result<Vec<ChannelNameValue>, DomainError> {
    let items = vector(arm, "channels").map_err(|_| DomainError::InvalidArgument)?;
    let mut names = Vec::new();
    names
        .try_reserve_exact(items.len())
        .map_err(|_| DomainError::AllocationFailed)?;
    for item in items {
        names.push(channel_name_of(item).map_err(|_| DomainError::InvalidArgument)?);
    }
    Ok(names)
}

fn channel_name_field(arm: &SchemaObject) -> Result<ChannelNameValue, DomainError> {
    structure(arm, "channel_name")
        .map_err(|_| DomainError::InvalidArgument)
        .and_then(|name| channel_name_of(name).map_err(|_| DomainError::InvalidArgument))
}

fn nickname_field(arm: &SchemaObject) -> Result<NicknameValue, DomainError> {
    structure(arm, "nickname")
        .map_err(|_| DomainError::InvalidArgument)
        .and_then(|name| nickname_of(name).map_err(|_| DomainError::InvalidArgument))
}

/// Builds the canonical command of one decoded directory arm.
// agenc-review: focus owner=runtime reviewed=2026-09-02 reason=one closed match maps every registered directory query kind onto its canonical command
fn directory_command(
    kind: FederationDirectoryQueryKind,
    arm: &SchemaObject,
) -> Result<CanonicalCommand, DomainError> {
    let invalid = |_| DomainError::InvalidArgument;
    match kind {
        FederationDirectoryQueryKind::List => CanonicalCommand::list(channel_names_of(arm)?),
        FederationDirectoryQueryKind::Names => CanonicalCommand::names(channel_names_of(arm)?),
        FederationDirectoryQueryKind::Who => {
            let target = structure(arm, "target").map_err(invalid)?;
            let value = text(target, "value").map_err(invalid)?;
            let who = match unsigned(target, "target_kind").map_err(invalid)? {
                0 if value.is_empty() => None,
                1 => Some(WhoTarget::Nickname(NicknameValue::parse(value)?)),
                2 => Some(WhoTarget::Channel(ChannelNameValue::parse(value)?)),
                _ => return Err(DomainError::InvalidArgument),
            };
            CanonicalCommand::user_query(UserQuery::Who(who))
        }
        FederationDirectoryQueryKind::Whois => {
            CanonicalCommand::user_query(UserQuery::Whois(nickname_field(arm)?))
        }
        FederationDirectoryQueryKind::Whowas => {
            let count = unsigned_u16(arm, "count").map_err(invalid)?;
            if !(1..=10).contains(&count) {
                return Err(DomainError::InvalidArgument);
            }
            let count = u8::try_from(count).map_err(|_| DomainError::InvalidArgument)?;
            CanonicalCommand::user_query(UserQuery::Whowas(nickname_field(arm)?, count))
        }
        FederationDirectoryQueryKind::Ison => {
            CanonicalCommand::user_query(UserQuery::Ison(nicknames_of(arm, "nicknames")?))
        }
        FederationDirectoryQueryKind::Userhost => {
            CanonicalCommand::user_query(UserQuery::Userhost(nicknames_of(arm, "nicknames")?))
        }
        FederationDirectoryQueryKind::Links => {
            Ok(CanonicalCommand::information(InformationQuery::Links))
        }
        FederationDirectoryQueryKind::MonitorAdd => {
            CanonicalCommand::presence(PresenceCommand::MonitorAdd(nicknames_of(arm, "nicknames")?))
        }
        FederationDirectoryQueryKind::MonitorRemove => CanonicalCommand::presence(
            PresenceCommand::MonitorRemove(nicknames_of(arm, "nicknames")?),
        ),
        FederationDirectoryQueryKind::MonitorClear => {
            CanonicalCommand::presence(PresenceCommand::MonitorClear)
        }
        FederationDirectoryQueryKind::MonitorList => {
            CanonicalCommand::presence(PresenceCommand::MonitorList)
        }
        FederationDirectoryQueryKind::MonitorStatus => {
            CanonicalCommand::presence(PresenceCommand::MonitorStatus)
        }
        FederationDirectoryQueryKind::ChannelTopic => {
            Ok(CanonicalCommand::topic_query(channel_name_field(arm)?))
        }
        FederationDirectoryQueryKind::ChannelModes => Ok(CanonicalCommand::channel_mode_query(
            channel_name_field(arm)?,
        )),
        FederationDirectoryQueryKind::ChannelModeList => {
            let list = match unsigned_u16(arm, "mode_code").map_err(invalid)? {
                1 => MaskList::Ban,
                2 => MaskList::Exception,
                3 => MaskList::InviteException,
                _ => return Err(DomainError::InvalidArgument),
            };
            Ok(CanonicalCommand::channel_mode_list(
                channel_name_field(arm)?,
                list,
            ))
        }
    }
}
