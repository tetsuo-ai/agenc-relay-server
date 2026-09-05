//! Conversion from the state-independent client-wire proof to the pure
//! domain command union.

mod history;

use agenc_ircd_admin::decode_fixed_base64url;
use agenc_ircd_client_wire::{
    AccountControlCommand, ChannelControlCommand, LocalInformationCommand, MonitorCommand,
    PostRegistrationCommandKind, RegisteredCommandKind,
};
use agenc_ircd_domain::{
    AccountCommand, AccountLabelValue, AwayText, CanonicalCommand, ChannelCommand,
    ChannelNameValue, ChannelTarget, DirectMessagePolicy, DisplayNameValue, DomainState,
    GuestDirectMessagePolicy, HistoryPolicy, InformationQuery, MaskList, MessageCommand,
    MessageKind, MessageTarget, ModeChange, ModeOperation, NicknameValue, PresenceCommand,
    PresencePolicy, Role, TopicText, UserQuery, VisibilityMode, WhoTarget,
};
use agenc_ircd_types::{AccountDeletionToken, AccountId, ControlPolicy, TypedMask};

use crate::RuntimeError;

pub(crate) fn convert(
    domain: &DomainState,
    channels: &dyn ChannelResolver,
    kind: RegisteredCommandKind,
    message: &agenc_ircd_client_wire::ParsedMessage,
) -> Result<CanonicalCommand, RuntimeError> {
    match kind {
        RegisteredCommandKind::Nickname => nickname(message),
        RegisteredCommandKind::Public(kind) => convert_public(domain, channels, kind, message),
    }
}

/// Resolves a canonical channel name to its instance: the authoritative
/// domain on a coordinator, the projected replica on an edge.
pub(crate) trait ChannelResolver {
    /// The instance identifier of `name`, when the channel exists.
    fn channel_id_of(&self, name: &ChannelNameValue)
    -> Option<agenc_ircd_types::ChannelInstanceId>;
}

impl ChannelResolver for DomainState {
    fn channel_id_of(
        &self,
        name: &ChannelNameValue,
    ) -> Option<agenc_ircd_types::ChannelInstanceId> {
        self.resolve_channel(name)
    }
}

// agenc-review: focus owner=runtime reviewed=2026-08-29 reason=exhaustive closed wire-to-domain union with each family delegated to a bounded converter
fn convert_public(
    domain: &DomainState,
    channels: &dyn ChannelResolver,
    kind: PostRegistrationCommandKind,
    message: &agenc_ircd_client_wire::ParsedMessage,
) -> Result<CanonicalCommand, RuntimeError> {
    match kind {
        PostRegistrationCommandKind::JoinAll => Ok(CanonicalCommand::part_all()),
        PostRegistrationCommandKind::JoinChannels => join(message),
        PostRegistrationCommandKind::Part => part(message),
        PostRegistrationCommandKind::ModeQuery => mode_query(message),
        PostRegistrationCommandKind::ModeChange => mode_change(domain, message),
        PostRegistrationCommandKind::TopicQuery => topic_query(message),
        PostRegistrationCommandKind::TopicSet => topic_set(message),
        PostRegistrationCommandKind::NamesAll => {
            CanonicalCommand::names(Vec::new()).map_err(closed)
        }
        PostRegistrationCommandKind::NamesChannels => names(message),
        PostRegistrationCommandKind::ListAll => CanonicalCommand::list(Vec::new()).map_err(closed),
        PostRegistrationCommandKind::ListChannels => list(message),
        PostRegistrationCommandKind::Invite => invite(message),
        PostRegistrationCommandKind::Kick => kick(message),
        PostRegistrationCommandKind::Privmsg => message_command(message, MessageKind::Privmsg),
        PostRegistrationCommandKind::Notice => message_command(message, MessageKind::Notice),
        PostRegistrationCommandKind::Tagmsg => message_command(message, MessageKind::Tagmsg),
        PostRegistrationCommandKind::LocalInformation(query) => {
            Ok(CanonicalCommand::information(information_query(query)))
        }
        PostRegistrationCommandKind::WhoSelf => {
            CanonicalCommand::user_query(UserQuery::Who(None)).map_err(closed)
        }
        PostRegistrationCommandKind::WhoTarget => who(message),
        PostRegistrationCommandKind::Whois => whois(message),
        PostRegistrationCommandKind::Whowas => whowas(message),
        PostRegistrationCommandKind::Away => away(message),
        PostRegistrationCommandKind::Ison => nickname_query(message, true),
        PostRegistrationCommandKind::Userhost => nickname_query(message, false),
        PostRegistrationCommandKind::Monitor(operation) => monitor(message, operation),
        PostRegistrationCommandKind::Setname => setname(message),
        PostRegistrationCommandKind::Account(operation) => account(message, operation),
        PostRegistrationCommandKind::ChannelControl(operation) => {
            channel_control(channels, message, operation)
        }
        PostRegistrationCommandKind::ChatHistory(_) => chathistory(channels, message),
    }
}

fn nickname(
    message: &agenc_ircd_client_wire::ParsedMessage,
) -> Result<CanonicalCommand, RuntimeError> {
    let nickname = one(message)?;
    Ok(CanonicalCommand::nick(parse_nickname(nickname)?))
}

fn join(message: &agenc_ircd_client_wire::ParsedMessage) -> Result<CanonicalCommand, RuntimeError> {
    let channels = message.middle().first().ok_or(RuntimeError::InvalidValue)?;
    let keys: Vec<&str> = message
        .middle()
        .get(1)
        .map_or_else(Vec::new, |keys| keys.split(',').collect());
    let mut targets = Vec::new();
    for (index, name) in channels.split(',').enumerate() {
        let key_supplied = keys.get(index).is_some_and(|key| !key.is_empty());
        targets.push(ChannelTarget::new(parse_channel(name)?, key_supplied));
    }
    CanonicalCommand::join(targets).map_err(closed)
}

fn part(message: &agenc_ircd_client_wire::ParsedMessage) -> Result<CanonicalCommand, RuntimeError> {
    let channels = message.middle().first().ok_or(RuntimeError::InvalidValue)?;
    let channels = parse_channels(channels)?;
    let reason = message
        .trailing()
        .map(|reason| AwayText::try_from_str(reason, ControlPolicy::PermitHorizontalTab))
        .transpose()
        .map_err(closed)?;
    CanonicalCommand::part(channels, reason).map_err(closed)
}

fn mode_query(
    message: &agenc_ircd_client_wire::ParsedMessage,
) -> Result<CanonicalCommand, RuntimeError> {
    let target = one(message)?;
    if target.starts_with(['#', '&']) {
        Ok(CanonicalCommand::channel_mode_query(parse_channel(target)?))
    } else {
        Ok(CanonicalCommand::user_mode_query(parse_nickname(target)?))
    }
}

fn mode_change(
    domain: &DomainState,
    message: &agenc_ircd_client_wire::ParsedMessage,
) -> Result<CanonicalCommand, RuntimeError> {
    let target = message.middle().first().ok_or(RuntimeError::InvalidValue)?;
    if !target.starts_with(['#', '&']) {
        return user_mode_change(message);
    }
    channel_mode_change(domain, message, target)
}

fn user_mode_change(
    message: &agenc_ircd_client_wire::ParsedMessage,
) -> Result<CanonicalCommand, RuntimeError> {
    let [target, modes] = message.middle() else {
        return Err(RuntimeError::InvalidValue);
    };
    let (enabled, letter) = single_mode(modes)?;
    if letter != 'w' {
        return Err(RuntimeError::InvalidValue);
    }
    Ok(CanonicalCommand::user_operator_notices(
        parse_nickname(target)?,
        enabled,
    ))
}

fn channel_mode_change(
    domain: &DomainState,
    message: &agenc_ircd_client_wire::ParsedMessage,
    target: &str,
) -> Result<CanonicalCommand, RuntimeError> {
    let mode_string = message.middle().get(1).ok_or(RuntimeError::InvalidValue)?;
    let arguments = mode_arguments(message);
    let channel = parse_channel(target)?;
    if let Some(list) = list_query(mode_string, arguments.as_slice())? {
        return Ok(CanonicalCommand::channel_mode_list(channel, list));
    }
    let changes = parse_mode_changes(domain, &channel, mode_string, &arguments)?;
    CanonicalCommand::mode(channel, changes).map_err(closed)
}

fn parse_mode_changes(
    domain: &DomainState,
    channel: &ChannelNameValue,
    mode_string: &str,
    arguments: &[&str],
) -> Result<Vec<ModeChange>, RuntimeError> {
    let mut operation = None;
    let mut argument_index = 0;
    let mut changes = Vec::new();
    for letter in mode_string.chars() {
        match letter {
            '+' => operation = Some(ModeOperation::Add),
            '-' => operation = Some(ModeOperation::Remove),
            _ => changes.push(mode_change_for(
                domain,
                channel,
                operation.ok_or(RuntimeError::InvalidValue)?,
                letter,
                arguments,
                &mut argument_index,
            )?),
        }
    }
    if argument_index != arguments.len() {
        return Err(RuntimeError::InvalidValue);
    }
    Ok(changes)
}

pub(crate) fn channel_key_parameter_positions(
    message: &agenc_ircd_client_wire::ParsedMessage,
) -> Result<Vec<(u8, usize)>, RuntimeError> {
    let mode_string = message.middle().get(1).ok_or(RuntimeError::InvalidValue)?;
    let mut operation = None;
    let mut parameter_index = 2_usize;
    let mut change_index = 0_u8;
    let mut positions = Vec::new();
    positions
        .try_reserve_exact(mode_string.len())
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for letter in mode_string.chars() {
        if let Some(next_operation) = mode_operation_marker(letter) {
            operation = Some(next_operation);
            continue;
        }
        let operation = operation.ok_or(RuntimeError::InvalidValue)?;
        let consumes = mode_letter_consumes_parameter(letter, operation)?;
        if letter == 'k' && operation == ModeOperation::Add {
            positions.push((change_index, parameter_index));
        }
        if consumes {
            parameter_index = parameter_index
                .checked_add(1)
                .ok_or(RuntimeError::Overflow)?;
        }
        change_index = change_index.checked_add(1).ok_or(RuntimeError::Overflow)?;
    }
    if parameter_index != message.parameter_count() {
        return Err(RuntimeError::InvalidValue);
    }
    Ok(positions)
}

const fn mode_operation_marker(letter: char) -> Option<ModeOperation> {
    match letter {
        '+' => Some(ModeOperation::Add),
        '-' => Some(ModeOperation::Remove),
        _ => None,
    }
}

fn mode_letter_consumes_parameter(
    letter: char,
    operation: ModeOperation,
) -> Result<bool, RuntimeError> {
    match letter {
        'p' | 's' | 'i' | 'm' | 't' => Ok(false),
        'k' | 'l' => Ok(operation == ModeOperation::Add),
        'q' | 'a' | 'o' | 'h' | 'v' | 'b' | 'e' | 'I' => Ok(true),
        _ => Err(RuntimeError::InvalidValue),
    }
}

pub(crate) fn mode_change_for(
    domain: &DomainState,
    channel: &ChannelNameValue,
    operation: ModeOperation,
    letter: char,
    arguments: &[&str],
    argument_index: &mut usize,
) -> Result<ModeChange, RuntimeError> {
    let enabled = operation == ModeOperation::Add;
    match letter {
        'p' => Ok(ModeChange::Visibility {
            operation,
            mode: VisibilityMode::Unlisted,
        }),
        's' => Ok(ModeChange::Visibility {
            operation,
            mode: VisibilityMode::Secret,
        }),
        'i' => Ok(ModeChange::InviteOnly(enabled)),
        'm' => Ok(ModeChange::Moderated(enabled)),
        't' => Ok(ModeChange::TopicProtected(enabled)),
        'k' if !enabled => Ok(ModeChange::JoinKey(false)),
        'k' => {
            let key = take_argument(arguments, argument_index)?;
            if !(crate::bridge::crypto::MIN_CHANNEL_KEY_BYTES
                ..=crate::bridge::crypto::MAX_CHANNEL_KEY_BYTES)
                .contains(&key.len())
            {
                return Err(RuntimeError::InvalidValue);
            }
            Ok(ModeChange::JoinKey(true))
        }
        'l' if !enabled => Ok(ModeChange::MemberLimit(None)),
        'l' => Ok(ModeChange::MemberLimit(Some(
            take_argument(arguments, argument_index)?
                .parse()
                .map_err(|_| RuntimeError::InvalidValue)?,
        ))),
        'q' | 'a' | 'o' | 'h' | 'v' => Ok(ModeChange::Role {
            operation,
            target: parse_nickname(take_argument(arguments, argument_index)?)?,
            role: role_for(letter)?,
        }),
        'b' | 'e' | 'I' => mask_change(
            domain,
            channel,
            operation,
            list_for(letter)?,
            take_argument(arguments, argument_index)?,
        ),
        _ => Err(RuntimeError::InvalidValue),
    }
}

fn mask_change(
    domain: &DomainState,
    channel: &ChannelNameValue,
    operation: ModeOperation,
    list: MaskList,
    text: &str,
) -> Result<ModeChange, RuntimeError> {
    let mask = TypedMask::parse(text).map_err(closed)?;
    if operation == ModeOperation::Add {
        return Ok(ModeChange::AddMask { list, mask });
    }
    let channel_id = domain
        .resolve_channel(channel)
        .ok_or(RuntimeError::InvalidValue)?;
    let channel = domain
        .channel(channel_id)
        .ok_or(RuntimeError::InvalidValue)?;
    let entry = channel
        .mask_list(list)
        .iter()
        .find(|entry| entry.mask() == &mask)
        .ok_or(RuntimeError::InvalidValue)?;
    Ok(ModeChange::RemoveMask {
        list,
        entry_id: entry.entry_id(),
    })
}

fn topic_query(
    message: &agenc_ircd_client_wire::ParsedMessage,
) -> Result<CanonicalCommand, RuntimeError> {
    Ok(CanonicalCommand::topic_query(parse_channel(one(message)?)?))
}

fn topic_set(
    message: &agenc_ircd_client_wire::ParsedMessage,
) -> Result<CanonicalCommand, RuntimeError> {
    let channel = message.middle().first().ok_or(RuntimeError::InvalidValue)?;
    let topic = message.trailing().ok_or(RuntimeError::InvalidValue)?;
    let topic =
        TopicText::try_from_str(topic, ControlPolicy::PermitHorizontalTab).map_err(closed)?;
    Ok(CanonicalCommand::topic_set(parse_channel(channel)?, topic))
}

fn names(
    message: &agenc_ircd_client_wire::ParsedMessage,
) -> Result<CanonicalCommand, RuntimeError> {
    CanonicalCommand::names(parse_channels(one(message)?)?).map_err(closed)
}

fn list(message: &agenc_ircd_client_wire::ParsedMessage) -> Result<CanonicalCommand, RuntimeError> {
    CanonicalCommand::list(parse_channels(one(message)?)?).map_err(closed)
}

fn invite(
    message: &agenc_ircd_client_wire::ParsedMessage,
) -> Result<CanonicalCommand, RuntimeError> {
    let [nickname, channel] = message.middle() else {
        return Err(RuntimeError::InvalidValue);
    };
    Ok(CanonicalCommand::invite(
        parse_nickname(nickname)?,
        parse_channel(channel)?,
    ))
}

fn kick(message: &agenc_ircd_client_wire::ParsedMessage) -> Result<CanonicalCommand, RuntimeError> {
    let [channel, nicknames] = message.middle() else {
        return Err(RuntimeError::InvalidValue);
    };
    let reason = message
        .trailing()
        .map(|reason| AwayText::try_from_str(reason, ControlPolicy::PermitHorizontalTab))
        .transpose()
        .map_err(closed)?;
    CanonicalCommand::kick(parse_channel(channel)?, parse_nicknames(nicknames)?, reason)
        .map_err(closed)
}

fn message_command(
    message: &agenc_ircd_client_wire::ParsedMessage,
    kind: MessageKind,
) -> Result<CanonicalCommand, RuntimeError> {
    let targets = message.middle().first().ok_or(RuntimeError::InvalidValue)?;
    let body = message
        .trailing()
        .map(agenc_ircd_domain::MessageText::parse)
        .transpose()
        .map_err(closed)?;
    let mut parsed = Vec::new();
    for target in targets.split(',') {
        // Status-prefixed delivery is not modeled; refusing keeps a message
        // meant for operators from reaching the whole channel.
        if target.starts_with(['@', '+']) {
            return Err(RuntimeError::InvalidValue);
        }
        parsed.push(if target.starts_with(['#', '&']) {
            MessageTarget::Channel(parse_channel(target)?)
        } else {
            MessageTarget::User(parse_nickname(target)?)
        });
    }
    let message = MessageCommand::new(kind, parsed, body).map_err(closed)?;
    Ok(CanonicalCommand::message(message))
}

fn who(message: &agenc_ircd_client_wire::ParsedMessage) -> Result<CanonicalCommand, RuntimeError> {
    let target = one(message)?;
    let target = if target.starts_with(['#', '&']) {
        WhoTarget::Channel(parse_channel(target)?)
    } else {
        WhoTarget::Nickname(parse_nickname(target)?)
    };
    CanonicalCommand::user_query(UserQuery::Who(Some(target))).map_err(closed)
}

fn whois(
    message: &agenc_ircd_client_wire::ParsedMessage,
) -> Result<CanonicalCommand, RuntimeError> {
    CanonicalCommand::user_query(UserQuery::Whois(parse_nickname(one(message)?)?)).map_err(closed)
}

fn whowas(
    message: &agenc_ircd_client_wire::ParsedMessage,
) -> Result<CanonicalCommand, RuntimeError> {
    let nickname = message.middle().first().ok_or(RuntimeError::InvalidValue)?;
    let count = message.middle().get(1).map_or(Ok(1), |count| {
        count.parse().map_err(|_| RuntimeError::InvalidValue)
    })?;
    CanonicalCommand::user_query(UserQuery::Whowas(parse_nickname(nickname)?, count))
        .map_err(closed)
}

fn away(message: &agenc_ircd_client_wire::ParsedMessage) -> Result<CanonicalCommand, RuntimeError> {
    let away = message
        .trailing()
        .map(|text| AwayText::try_from_str(text, ControlPolicy::PermitHorizontalTab))
        .transpose()
        .map_err(closed)?;
    CanonicalCommand::presence(PresenceCommand::Away(away)).map_err(closed)
}

fn nickname_query(
    message: &agenc_ircd_client_wire::ParsedMessage,
    ison: bool,
) -> Result<CanonicalCommand, RuntimeError> {
    let mut nicknames = Vec::new();
    for nickname in message.middle() {
        nicknames.push(parse_nickname(nickname)?);
    }
    let query = if ison {
        UserQuery::Ison(nicknames)
    } else {
        UserQuery::Userhost(nicknames)
    };
    CanonicalCommand::user_query(query).map_err(closed)
}

fn monitor(
    message: &agenc_ircd_client_wire::ParsedMessage,
    operation: MonitorCommand,
) -> Result<CanonicalCommand, RuntimeError> {
    let command = match operation {
        MonitorCommand::Add => {
            PresenceCommand::MonitorAdd(parse_nicknames(parameter(message, 1)?)?)
        }
        MonitorCommand::Remove => {
            PresenceCommand::MonitorRemove(parse_nicknames(parameter(message, 1)?)?)
        }
        MonitorCommand::Clear => PresenceCommand::MonitorClear,
        MonitorCommand::List => PresenceCommand::MonitorList,
        MonitorCommand::Status => PresenceCommand::MonitorStatus,
    };
    CanonicalCommand::presence(command).map_err(closed)
}

fn setname(
    message: &agenc_ircd_client_wire::ParsedMessage,
) -> Result<CanonicalCommand, RuntimeError> {
    let display = message.trailing().ok_or(RuntimeError::InvalidValue)?;
    Ok(CanonicalCommand::setname(
        DisplayNameValue::prepare(display).map_err(closed)?,
    ))
}

fn account(
    message: &agenc_ircd_client_wire::ParsedMessage,
    operation: AccountControlCommand,
) -> Result<CanonicalCommand, RuntimeError> {
    let command = match operation {
        AccountControlCommand::Label => {
            let value = parameter(message, 1)?;
            AccountCommand::Label(
                (value != "*")
                    .then(|| AccountLabelValue::parse(value))
                    .transpose()
                    .map_err(closed)?,
            )
        }
        AccountControlCommand::Presence => AccountCommand::Presence(match parameter(message, 1)? {
            "PUBLIC" => PresencePolicy::Public,
            "PRIVATE" => PresencePolicy::Private,
            _ => return Err(RuntimeError::InvalidValue),
        }),
        AccountControlCommand::GuestDirectMessages => {
            AccountCommand::GuestDirectMessages(match parameter(message, 1)? {
                "ALLOW" => GuestDirectMessagePolicy::Allow,
                "DENY" => GuestDirectMessagePolicy::Deny,
                _ => return Err(RuntimeError::InvalidValue),
            })
        }
        AccountControlCommand::DirectMessages => {
            AccountCommand::DirectMessages(match parameter(message, 1)? {
                "ALLOW" => DirectMessagePolicy::Allow,
                "CONTACTS" => DirectMessagePolicy::Contacts,
                "DENY" => DirectMessagePolicy::Deny,
                _ => return Err(RuntimeError::InvalidValue),
            })
        }
        AccountControlCommand::ContactAdd => {
            AccountCommand::ContactAdd(AccountId::parse(parameter(message, 2)?).map_err(closed)?)
        }
        AccountControlCommand::ContactRemove => {
            AccountCommand::ContactRemove(AccountId::parse(parameter(message, 2)?).map_err(closed)?)
        }
        AccountControlCommand::NickReserve => {
            AccountCommand::NickReserve(parse_nickname(parameter(message, 2)?)?)
        }
        AccountControlCommand::NickRelease => {
            AccountCommand::NickRelease(parse_nickname(parameter(message, 2)?)?)
        }
        AccountControlCommand::DeleteStart => AccountCommand::DeleteStart,
        AccountControlCommand::DeleteConfirm => {
            let bytes =
                decode_fixed_base64url::<16>(parameter(message, 2)?.as_bytes()).map_err(closed)?;
            AccountCommand::DeleteConfirm(AccountDeletionToken::from_bytes(bytes))
        }
    };
    Ok(CanonicalCommand::account(command))
}

fn channel_control(
    channels: &dyn ChannelResolver,
    message: &agenc_ircd_client_wire::ParsedMessage,
    operation: ChannelControlCommand,
) -> Result<CanonicalCommand, RuntimeError> {
    let channel = parse_channel(parameter(message, 1)?)?;
    let channel_id = channels
        .channel_id_of(&channel)
        .ok_or(RuntimeError::InvalidValue)?;
    let command = match operation {
        ChannelControlCommand::Register => ChannelCommand::Register(channel_id),
        ChannelControlCommand::Unregister => ChannelCommand::Unregister(channel_id),
        ChannelControlCommand::History if parameter(message, 2)? == "ON" => {
            ChannelCommand::HistoryDefault(channel_id)
        }
        ChannelControlCommand::History => ChannelCommand::History(
            channel_id,
            match parameter(message, 2)? {
                "OFF" => HistoryPolicy::Off,
                "1H" => HistoryPolicy::OneHour,
                "24H" => HistoryPolicy::TwentyFourHours,
                "7D" => HistoryPolicy::SevenDays,
                _ => return Err(RuntimeError::InvalidValue),
            },
        ),
    };
    Ok(CanonicalCommand::channel(command))
}

fn chathistory(
    channels: &dyn ChannelResolver,
    message: &agenc_ircd_client_wire::ParsedMessage,
) -> Result<CanonicalCommand, RuntimeError> {
    let channel = parse_channel(parameter(message, 1)?)?;
    let channel_id = channels
        .channel_id_of(&channel)
        .ok_or(RuntimeError::InvalidValue)?;
    Ok(CanonicalCommand::history_query(
        channel_id,
        history::query(message)?,
    ))
}

fn information_query(query: LocalInformationCommand) -> InformationQuery {
    match query {
        LocalInformationCommand::Motd => InformationQuery::Motd,
        LocalInformationCommand::Lusers => InformationQuery::Lusers,
        LocalInformationCommand::Version => InformationQuery::Version,
        LocalInformationCommand::Time => InformationQuery::Time,
        LocalInformationCommand::Admin => InformationQuery::Admin,
        LocalInformationCommand::Info => InformationQuery::Info,
        LocalInformationCommand::Links => InformationQuery::Links,
    }
}

fn parse_channels(raw: &str) -> Result<Vec<ChannelNameValue>, RuntimeError> {
    raw.split(',').map(parse_channel).collect()
}

fn parse_nicknames(raw: &str) -> Result<Vec<NicknameValue>, RuntimeError> {
    raw.split(',').map(parse_nickname).collect()
}

fn parse_channel(raw: &str) -> Result<ChannelNameValue, RuntimeError> {
    ChannelNameValue::parse(raw).map_err(closed)
}

fn parse_nickname(raw: &str) -> Result<NicknameValue, RuntimeError> {
    NicknameValue::parse(raw).map_err(closed)
}

fn one(message: &agenc_ircd_client_wire::ParsedMessage) -> Result<&str, RuntimeError> {
    match (message.middle(), message.trailing()) {
        ([only], None) => Ok(only),
        ([], Some(only)) => Ok(only),
        _ => Err(RuntimeError::InvalidValue),
    }
}

fn parameter(
    message: &agenc_ircd_client_wire::ParsedMessage,
    index: usize,
) -> Result<&str, RuntimeError> {
    message
        .middle()
        .get(index)
        .map(String::as_str)
        .ok_or(RuntimeError::InvalidValue)
}

fn mode_arguments(message: &agenc_ircd_client_wire::ParsedMessage) -> Vec<&str> {
    message
        .middle()
        .iter()
        .skip(2)
        .map(String::as_str)
        .chain(message.trailing())
        .collect()
}

fn take_argument<'a>(arguments: &'a [&str], index: &mut usize) -> Result<&'a str, RuntimeError> {
    let value = arguments
        .get(*index)
        .copied()
        .ok_or(RuntimeError::InvalidValue)?;
    *index = index.checked_add(1).ok_or(RuntimeError::Overflow)?;
    Ok(value)
}

fn single_mode(mode: &str) -> Result<(bool, char), RuntimeError> {
    let mut characters = mode.chars();
    let enabled = match characters.next() {
        Some('+') => true,
        Some('-') => false,
        _ => return Err(RuntimeError::InvalidValue),
    };
    let letter = characters.next().ok_or(RuntimeError::InvalidValue)?;
    if characters.next().is_some() {
        return Err(RuntimeError::InvalidValue);
    }
    Ok((enabled, letter))
}

fn list_query(mode: &str, arguments: &[&str]) -> Result<Option<MaskList>, RuntimeError> {
    if !arguments.is_empty() {
        return Ok(None);
    }
    let letter = match mode.as_bytes() {
        [letter] | [b'+', letter] | [b'-', letter] => char::from(*letter),
        _ => return Ok(None),
    };
    match letter {
        'b' | 'e' | 'I' => list_for(letter).map(Some),
        _ => Ok(None),
    }
}

fn list_for(letter: char) -> Result<MaskList, RuntimeError> {
    match letter {
        'b' => Ok(MaskList::Ban),
        'e' => Ok(MaskList::Exception),
        'I' => Ok(MaskList::InviteException),
        _ => Err(RuntimeError::InvalidValue),
    }
}

fn role_for(letter: char) -> Result<Role, RuntimeError> {
    match letter {
        'q' => Ok(Role::Owner),
        'a' => Ok(Role::Administrator),
        'o' => Ok(Role::Operator),
        'h' => Ok(Role::HalfOperator),
        'v' => Ok(Role::Voice),
        _ => Err(RuntimeError::InvalidValue),
    }
}

fn closed<E>(_: E) -> RuntimeError {
    RuntimeError::InvalidValue
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::io;

    use agenc_ircd_client_wire::{
        FramedLine, RegisteredCommandKind, parse_message, validate_post_registration_command,
    };
    use agenc_ircd_domain::{CanonicalCommandView, DomainCommandKind, DomainState, ModeCommand};

    use super::{channel_key_parameter_positions, convert};
    use crate::RuntimeError;

    #[test]
    fn every_state_independent_public_family_converts_to_its_domain_kind()
    -> Result<(), Box<dyn Error>> {
        let cases = [
            ("JOIN 0", DomainCommandKind::Join),
            ("JOIN #room", DomainCommandKind::Join),
            ("PART #room :gone", DomainCommandKind::Part),
            ("MODE Guest +w", DomainCommandKind::Mode),
            ("MODE #room +im", DomainCommandKind::Mode),
            ("MODE #room b", DomainCommandKind::Mode),
            ("TOPIC #room", DomainCommandKind::Topic),
            ("TOPIC #room :hello", DomainCommandKind::Topic),
            ("NAMES", DomainCommandKind::Names),
            ("NAMES #room", DomainCommandKind::Names),
            ("LIST", DomainCommandKind::List),
            ("LIST #room", DomainCommandKind::List),
            ("INVITE Guest #room", DomainCommandKind::Invite),
            ("KICK #room Guest :gone", DomainCommandKind::Kick),
            ("PRIVMSG Guest :hello", DomainCommandKind::Privmsg),
            ("NOTICE Guest :", DomainCommandKind::Notice),
            ("@+typing=active TAGMSG Guest", DomainCommandKind::Tagmsg),
            ("MOTD", DomainCommandKind::Motd),
            ("LUSERS", DomainCommandKind::Lusers),
            ("VERSION", DomainCommandKind::Version),
            ("TIME", DomainCommandKind::Time),
            ("ADMIN", DomainCommandKind::Admin),
            ("INFO", DomainCommandKind::Info),
            ("LINKS", DomainCommandKind::Links),
            ("WHO", DomainCommandKind::Who),
            ("WHO Guest", DomainCommandKind::Who),
            ("WHOIS Guest", DomainCommandKind::Whois),
            ("WHOWAS Guest 10", DomainCommandKind::Whowas),
            ("AWAY :gone", DomainCommandKind::Away),
            ("ISON Guest Other", DomainCommandKind::Ison),
            ("USERHOST Guest", DomainCommandKind::Userhost),
            ("MONITOR + Guest,Other", DomainCommandKind::Monitor),
            ("MONITOR C", DomainCommandKind::Monitor),
            ("SETNAME :Guest Person", DomainCommandKind::Setname),
            ("ACCT LABEL public", DomainCommandKind::Acct),
            ("ACCT PRESENCE PRIVATE", DomainCommandKind::Acct),
            ("ACCT GUEST-DM DENY", DomainCommandKind::Acct),
            ("ACCT DIRECT-MESSAGES CONTACTS", DomainCommandKind::Acct),
            (
                "ACCT CONTACT ADD a_AAAAAAAAAAAAAAAAAAAAAA",
                DomainCommandKind::Acct,
            ),
            ("ACCT NICK RESERVE Other", DomainCommandKind::Acct),
            ("ACCT DELETE START", DomainCommandKind::Acct),
        ];
        let domain = DomainState::new()?;
        for (line, expected) in cases {
            let message = parsed(line)
                .map_err(|error| io::Error::other(format!("{line}: parse failed: {error}")))?;
            let proof = validate_post_registration_command(&message)
                .map_err(|error| io::Error::other(format!("{line}: grammar failed: {error}")))?;
            let command = convert(
                &domain,
                &domain,
                RegisteredCommandKind::Public(proof.kind()),
                &message,
            )
            .map_err(|error| io::Error::other(format!("{line}: conversion failed: {error}")))?;
            assert_eq!(command.kind(), expected, "{line}");
        }
        Ok(())
    }

    #[test]
    fn channel_mode_list_and_multi_change_remain_distinct() -> Result<(), Box<dyn Error>> {
        let domain = DomainState::new()?;
        let list = converted(&domain, "MODE #room b")?;
        assert!(matches!(
            list.view(),
            CanonicalCommandView::Mode(ModeCommand::ChannelList(_, _))
        ));
        let change = converted(&domain, "MODE #room +im")?;
        let CanonicalCommandView::Mode(ModeCommand::ChannelChange(_, changes)) = change.view()
        else {
            return Err(test_error("missing channel-mode change").into());
        };
        assert_eq!(changes.len(), 2);
        Ok(())
    }

    #[test]
    fn channel_key_modes_enforce_secret_bounds_and_track_each_parameter()
    -> Result<(), Box<dyn Error>> {
        let domain = DomainState::new()?;
        for length in [8, 256] {
            let line = format!("MODE #room +k {}", "k".repeat(length));
            let command = converted(&domain, &line)?;
            let CanonicalCommandView::Mode(ModeCommand::ChannelChange(_, changes)) = command.view()
            else {
                return Err(test_error("missing channel-key mode change").into());
            };
            assert!(matches!(
                changes.as_slice(),
                [agenc_ircd_domain::ModeChange::JoinKey(true)]
            ));
        }
        for length in [7, 257] {
            let line = format!("MODE #room +k {}", "k".repeat(length));
            let message = parsed(&line)?;
            let proof = validate_post_registration_command(&message)?;
            assert_eq!(
                convert(
                    &domain,
                    &domain,
                    RegisteredCommandKind::Public(proof.kind()),
                    &message,
                )
                .err(),
                Some(RuntimeError::InvalidValue)
            );
        }

        let message = parsed("MODE #room +ok-l+k Operator first :second")?;
        assert_eq!(
            channel_key_parameter_positions(&message)?,
            vec![(1, 3), (3, 4)]
        );
        let message = parsed("MODE #room +kk first :second")?;
        assert_eq!(
            channel_key_parameter_positions(&message)?,
            vec![(0, 2), (1, 3)]
        );
        Ok(())
    }

    fn converted(
        domain: &DomainState,
        line: &str,
    ) -> Result<agenc_ircd_domain::CanonicalCommand, Box<dyn Error>> {
        let message = parsed(line)?;
        let proof = validate_post_registration_command(&message)?;
        Ok(convert(
            domain,
            domain,
            RegisteredCommandKind::Public(proof.kind()),
            &message,
        )?)
    }

    fn parsed(line: &str) -> Result<agenc_ircd_client_wire::ParsedMessage, Box<dyn Error>> {
        parse_message(FramedLine::new(line)?)?
            .ok_or_else(|| test_error("empty parsed message").into())
    }

    fn test_error(message: &'static str) -> io::Error {
        io::Error::other(message)
    }
}
