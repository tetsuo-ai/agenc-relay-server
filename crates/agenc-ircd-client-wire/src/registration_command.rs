//! State-independent grammar for commands accepted around registration.

use std::error::Error;
use std::fmt;

use agenc_ircd_types::{
    AccountRandomId, CLIENT_COMMANDS, DisplayName, MAX_PRECIS_INPUT_BYTES, SERVER_COMMANDS,
    ValidationError,
};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use zeroize::Zeroizing;

use crate::{
    ACCOUNT_REQUEST_BYTES, AUTH_CHUNK_CHARACTERS, AccessTokenPolicy, ParsedMessage,
    parse_u64_decimal,
};

const MAX_COMPATIBILITY_PASS_BYTES: usize = 256;
const CONFIGURED_PASS_BYTES: usize = 32;
const CONFIGURED_PASS_CHARACTERS: usize = 43;
const MAX_QUIT_REASON_BYTES: usize = 256;
const MAX_PING_PONG_BYTES: usize = 64;
const MAX_REALNAME_BYTES: usize = 64;
const MAX_SASL_MECHANISM_BYTES: usize = 20;
const MAX_AUTH_CHUNK_BYTES: usize = AUTH_CHUNK_CHARACTERS / 4 * 3;
const MAX_CHANNEL_BYTES: usize = 64;
const MAX_NICKNAME_BYTES: usize = 32;
const MAX_SERVER_NAME_BYTES: usize = 253;
const MAX_CHANNEL_TARGETS: usize = 20;
const MAX_MESSAGE_TARGETS: usize = 4;
const MAX_KICK_TARGETS: usize = 4;
const MAX_MODE_CHANGES: usize = 6;
const MIN_CHANNEL_KEY_BYTES: usize = 8;
const MAX_CHANNEL_KEY_BYTES: usize = 256;
const MAX_PART_KICK_AWAY_BYTES: usize = 256;
const MAX_TOPIC_BYTES: usize = 1_024;
const MAX_MESSAGE_BODY_BYTES: usize = 512;
const MAX_WHOWAS_COUNT: u64 = 10;
const MAX_ISON_NICKNAMES: usize = 20;
const MAX_USERHOST_NICKNAMES: usize = 5;
const MAX_HISTORY_LIMIT: u64 = 100;

/// Appendix-A commands admitted only after registration-state gating.
pub const POST_REGISTRATION_COMMANDS: &[&str] = &[
    "JOIN",
    "PART",
    "MODE",
    "TOPIC",
    "NAMES",
    "LIST",
    "INVITE",
    "KICK",
    "PRIVMSG",
    "NOTICE",
    "TAGMSG",
    "MOTD",
    "LUSERS",
    "VERSION",
    "TIME",
    "ADMIN",
    "INFO",
    "LINKS",
    "WHO",
    "WHOIS",
    "WHOWAS",
    "AWAY",
    "ISON",
    "USERHOST",
    "MONITOR",
    "SETNAME",
    "ACCT",
    "CHANCTL",
    "CHATHISTORY",
];

const RESTRICTED_PUBLIC_COMMANDS: &[&str] = &[
    "AUDIT", "BACKUP", "CHANNEL", "CONNECT", "DIE", "KILL", "OPER", "PEER", "REHASH", "RESTART",
    "SQUIT", "STATS",
];

const DISABLED_UNKNOWN_COMMANDS: &[&str] = &["SERVLIST", "SQUERY", "SUMMON", "USERS"];

/// One context-independent CAP command production.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationCapCommand {
    /// `CAP LS` or `CAP LS 302`.
    ListSupported,
    /// `CAP LIST`.
    ListEnabled,
    /// `CAP REQ :<capability-list>`.
    Request,
    /// `CAP END`.
    End,
}

/// One context-independent account-carrier production.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationAccountCommand {
    /// `START 4726`.
    Start,
    /// `FINISH 4726`.
    Finish,
    /// `DATA <canonical-base64url-chunk>`.
    Data,
    /// `END`.
    End,
}

/// One local-information command with its state-independent shape proved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalInformationCommand {
    /// MOTD for this server.
    Motd,
    /// Local aggregate user counts.
    Lusers,
    /// The local daemon version.
    Version,
    /// The local rounded UTC time.
    Time,
    /// Local administrator information.
    Admin,
    /// Local privacy-safe implementation information.
    Info,
    /// Public server names and availability.
    Links,
}

/// One exact MONITOR production.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MonitorCommand {
    /// Add one bounded nickname CSV.
    Add,
    /// Remove one bounded nickname CSV.
    Remove,
    /// Clear the complete monitor list.
    Clear,
    /// List the monitored nicknames.
    List,
    /// Query monitor status.
    Status,
}

/// One exact ACCT production from Section 14.6.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountControlCommand {
    /// Set or clear the public account label.
    Label,
    /// Select public or private presence.
    Presence,
    /// Select the guest direct-message policy.
    GuestDirectMessages,
    /// Select the authenticated direct-message policy.
    DirectMessages,
    /// Add one immutable account contact.
    ContactAdd,
    /// Remove one immutable account contact.
    ContactRemove,
    /// Reserve one nickname.
    NickReserve,
    /// Release one nickname reservation.
    NickRelease,
    /// Begin account deletion.
    DeleteStart,
    /// Confirm account deletion with one canonical token.
    DeleteConfirm,
}

/// One exact CHANCTL production from Section 14.6.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelControlCommand {
    /// Convert one channel to registered state.
    Register,
    /// Convert one channel to ephemeral state.
    Unregister,
    /// Set the closed plaintext-history retention policy.
    History,
}

/// One enabled Section-17 CHATHISTORY production.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChatHistoryCommand {
    /// Return the latest messages, optionally after one reference.
    Latest,
    /// Return messages before one reference.
    Before,
    /// Return messages after one reference.
    After,
    /// Return messages around one reference.
    Around,
    /// Return messages strictly between two references.
    Between,
}

/// The exact post-registration grammar alternative proved for one message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostRegistrationCommandKind {
    /// `JOIN 0`.
    JoinAll,
    /// A bounded channel CSV with an optional aligned key CSV.
    JoinChannels,
    /// A bounded PART channel CSV and optional trailing reason.
    Part,
    /// A MODE query containing only a target.
    ModeQuery,
    /// A bounded MODE vector and zero through six arguments.
    ModeChange,
    /// A TOPIC query.
    TopicQuery,
    /// A TOPIC set or clear operation.
    TopicSet,
    /// NAMES without an explicit channel list.
    NamesAll,
    /// NAMES with one bounded channel CSV.
    NamesChannels,
    /// LIST without an explicit channel list.
    ListAll,
    /// LIST with one bounded channel CSV.
    ListChannels,
    /// One nickname and one channel.
    Invite,
    /// One channel, one bounded nickname CSV, and an optional reason.
    Kick,
    /// One bounded target CSV and a non-empty trailing body.
    Privmsg,
    /// One bounded target CSV and a possibly empty trailing body.
    Notice,
    /// One target accompanied by at least one client-only tag.
    Tagmsg,
    /// One local-information production.
    LocalInformation(LocalInformationCommand),
    /// WHO without an explicit target.
    WhoSelf,
    /// WHO for one syntactically valid nickname or channel.
    WhoTarget,
    /// WHOIS for one nickname.
    Whois,
    /// WHOWAS for one nickname and an optional bounded decimal count.
    Whowas,
    /// AWAY clear or set.
    Away,
    /// One through twenty nickname parameters.
    Ison,
    /// One through five nickname parameters.
    Userhost,
    /// One exact MONITOR production.
    Monitor(MonitorCommand),
    /// One trailing prepared display name.
    Setname,
    /// One exact account-control production.
    Account(AccountControlCommand),
    /// One exact channel-control production.
    ChannelControl(ChannelControlCommand),
    /// One exact enabled history-query production.
    ChatHistory(ChatHistoryCommand),
}

/// Borrowed proof that one parsed message satisfies a post-registration row.
///
/// The proof owns no peer input and is `Copy`. Its private fields ensure only
/// [`validate_post_registration_command`] can construct it.
#[derive(Clone, Copy)]
pub struct PostRegistrationCommand<'a> {
    kind: PostRegistrationCommandKind,
    message: &'a ParsedMessage,
}

impl<'a> PostRegistrationCommand<'a> {
    /// Returns the exact validated grammar alternative.
    #[must_use]
    pub const fn kind(self) -> PostRegistrationCommandKind {
        self.kind
    }

    /// Borrows the same parsed message whose shape was validated.
    #[must_use]
    pub const fn message(self) -> &'a ParsedMessage {
        self.message
    }
}

impl fmt::Debug for PostRegistrationCommand<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostRegistrationCommand")
            .field("kind", &self.kind)
            .field("parameter_count", &self.message.parameter_count())
            .field("tag_count", &self.message.tags().len())
            .finish()
    }
}

/// Classification of one command after generic IRC syntax parsing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationCommand {
    /// One CAP negotiation production.
    Cap(RegistrationCapCommand),
    /// One state-independent AUTHENTICATE parameter.
    Authenticate,
    /// One PASS token under the selected listener policy.
    Pass,
    /// One ACCTCREATE carrier production.
    AccountCreate(RegistrationAccountCommand),
    /// One ACCTCRED carrier production. Registration state still gates its use.
    AccountCredentials(RegistrationAccountCommand),
    /// One syntactically valid nickname.
    Nick,
    /// The exact four-parameter USER production.
    User,
    /// One bounded PING parameter.
    Ping,
    /// One bounded PONG parameter.
    Pong,
    /// An optional bounded trailing QUIT reason.
    Quit,
    /// A known public command with its state-independent grammar proved.
    PostRegistration(PostRegistrationCommandKind),
}

/// Closed public-wire failures from registration command grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationGrammarError {
    /// The command maps to `ERR_UNKNOWNCOMMAND` on a public listener.
    UnknownCommand,
    /// The command maps to `ERR_NOPRIVILEGES` on a public listener.
    NoPrivileges,
    /// A required parameter was absent.
    NeedMoreParameters,
    /// A parameter exceeded its explicit byte bound.
    InputTooLong,
    /// A token, parameter shape, or exact production was invalid.
    InvalidArgument,
    /// A bounded validation allocation failed.
    AllocationFailed,
}

impl fmt::Display for RegistrationGrammarError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnknownCommand => "command is unavailable on the public client listener",
            Self::NoPrivileges => "command requires the separate administrative listener",
            Self::NeedMoreParameters => "registration command is missing a required parameter",
            Self::InputTooLong => "registration command parameter exceeds its byte bound",
            Self::InvalidArgument => "registration command arguments are invalid",
            Self::AllocationFailed => "registration command validation allocation failed",
        };
        formatter.write_str(message)
    }
}

impl Error for RegistrationGrammarError {}

/// Classifies and validates the Stage-02 registration-wire command surface.
///
/// Known post-registration commands are classified without applying their
/// semantic grammar. Stage 03 owns construction of `CanonicalCommand`, target
/// resolution, mode vectors, and all-or-none command validation.
///
/// # Errors
///
/// Returns a closed public-listener error when the command is unavailable or
/// its Stage-02 registration shape, token encoding, or byte bound is invalid.
pub fn parse_registration_command(
    message: &ParsedMessage,
    access_policy: AccessTokenPolicy,
) -> Result<RegistrationCommand, RegistrationGrammarError> {
    match message.command() {
        "CAP" => parse_cap(message).map(RegistrationCommand::Cap),
        "AUTHENTICATE" => validate_authenticate(message),
        "PASS" => validate_pass(message, access_policy),
        "ACCTCREATE" => parse_account_carrier(message).map(RegistrationCommand::AccountCreate),
        "ACCTCRED" => parse_account_carrier(message).map(RegistrationCommand::AccountCredentials),
        "NICK" => validate_nick(message),
        "USER" => validate_user(message),
        "PING" => validate_ping_pong(message).map(|()| RegistrationCommand::Ping),
        "PONG" => validate_ping_pong(message).map(|()| RegistrationCommand::Pong),
        "QUIT" => validate_quit(message),
        command if CLIENT_COMMANDS.contains(&command) => {
            validate_post_registration_command(message)
                .map(|proof| RegistrationCommand::PostRegistration(proof.kind()))
        }
        command if SERVER_COMMANDS.contains(&command) => {
            Err(RegistrationGrammarError::UnknownCommand)
        }
        "TRACE" => Err(RegistrationGrammarError::NoPrivileges),
        command if RESTRICTED_PUBLIC_COMMANDS.contains(&command) => {
            Err(RegistrationGrammarError::NoPrivileges)
        }
        command if DISABLED_UNKNOWN_COMMANDS.contains(&command) => {
            Err(RegistrationGrammarError::UnknownCommand)
        }
        _ => Err(RegistrationGrammarError::UnknownCommand),
    }
}

/// Validates every state-independent Appendix-A post-registration production.
///
/// The returned proof borrows `message`; validation does not copy command
/// parameters. Target lookup, capability state, configured-server equality,
/// mode semantics, authorization, and canonical domain construction remain
/// later-stage work.
///
/// # Errors
///
/// Returns a closed grammar error for an unknown command, missing or extra
/// parameter, malformed token, noncanonical decimal, or exceeded bound.
pub fn validate_post_registration_command(
    message: &ParsedMessage,
) -> Result<PostRegistrationCommand<'_>, RegistrationGrammarError> {
    let kind = match message.command() {
        "JOIN" => validate_join(message)?,
        "PART" => validate_part(message)?,
        "MODE" => validate_mode(message)?,
        "TOPIC" => validate_topic(message)?,
        "NAMES" => validate_optional_channel_csv(message, true)?,
        "LIST" => validate_optional_channel_csv(message, false)?,
        "INVITE" => validate_invite(message)?,
        "KICK" => validate_kick(message)?,
        "PRIVMSG" => validate_message_command(message, true)?,
        "NOTICE" => validate_message_command(message, false)?,
        "TAGMSG" => validate_tagmsg(message)?,
        "MOTD" => validate_local_information(message, LocalInformationCommand::Motd, true)?,
        "LUSERS" => validate_local_information(message, LocalInformationCommand::Lusers, false)?,
        "VERSION" => validate_local_information(message, LocalInformationCommand::Version, true)?,
        "TIME" => validate_local_information(message, LocalInformationCommand::Time, true)?,
        "ADMIN" => validate_local_information(message, LocalInformationCommand::Admin, true)?,
        "INFO" => validate_local_information(message, LocalInformationCommand::Info, true)?,
        "LINKS" => validate_local_information(message, LocalInformationCommand::Links, false)?,
        "WHO" => validate_who(message)?,
        "WHOIS" => validate_whois(message)?,
        "WHOWAS" => validate_whowas(message)?,
        "AWAY" => validate_away(message)?,
        "ISON" => validate_nickname_parameters(message, MAX_ISON_NICKNAMES, true)?,
        "USERHOST" => validate_nickname_parameters(message, MAX_USERHOST_NICKNAMES, false)?,
        "MONITOR" => validate_monitor(message)?,
        "SETNAME" => validate_setname(message)?,
        "ACCT" => validate_account_control(message)?,
        "CHANCTL" => validate_channel_control(message)?,
        "CHATHISTORY" => validate_chat_history(message)?,
        _ => return Err(RegistrationGrammarError::UnknownCommand),
    };
    Ok(PostRegistrationCommand { kind, message })
}

fn validate_join(
    message: &ParsedMessage,
) -> Result<PostRegistrationCommandKind, RegistrationGrammarError> {
    if message.parameter_count() == 0 {
        return Err(RegistrationGrammarError::NeedMoreParameters);
    }
    match (message.middle(), message.trailing()) {
        ([all], None) if all == "0" => Ok(PostRegistrationCommandKind::JoinAll),
        ([channels], None) => {
            validate_csv(channels, MAX_CHANNEL_TARGETS, validate_channel, ascii_equal)?;
            Ok(PostRegistrationCommandKind::JoinChannels)
        }
        ([channels, keys], None) => {
            let channel_count =
                validate_csv(channels, MAX_CHANNEL_TARGETS, validate_channel, ascii_equal)?;
            let key_count = validate_csv(keys, MAX_CHANNEL_TARGETS, validate_channel_key, str::eq)?;
            if key_count > channel_count {
                return Err(RegistrationGrammarError::InvalidArgument);
            }
            Ok(PostRegistrationCommandKind::JoinChannels)
        }
        _ => Err(RegistrationGrammarError::InvalidArgument),
    }
}

fn validate_part(
    message: &ParsedMessage,
) -> Result<PostRegistrationCommandKind, RegistrationGrammarError> {
    if message.parameter_count() == 0 {
        return Err(RegistrationGrammarError::NeedMoreParameters);
    }
    let ([channels], reason) = (message.middle(), message.trailing()) else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    validate_csv(channels, MAX_CHANNEL_TARGETS, validate_channel, ascii_equal)?;
    validate_optional_bound(reason, MAX_PART_KICK_AWAY_BYTES)?;
    Ok(PostRegistrationCommandKind::Part)
}

fn validate_mode(
    message: &ParsedMessage,
) -> Result<PostRegistrationCommandKind, RegistrationGrammarError> {
    if message.parameter_count() == 0 {
        return Err(RegistrationGrammarError::NeedMoreParameters);
    }
    let Some(target) = message.middle().first().map(String::as_str) else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    validate_target(target, false)?;
    if message.middle().len() == 1 && message.trailing().is_none() {
        return Ok(PostRegistrationCommandKind::ModeQuery);
    }
    let Some(mode_string) = message.middle().get(1).map(String::as_str) else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    validate_mode_string(mode_string)?;
    let middle_arguments = message.middle().len().saturating_sub(2);
    let argument_count = middle_arguments
        .checked_add(usize::from(message.trailing().is_some()))
        .ok_or(RegistrationGrammarError::InvalidArgument)?;
    if argument_count > MAX_MODE_CHANGES {
        return Err(RegistrationGrammarError::InvalidArgument);
    }
    Ok(PostRegistrationCommandKind::ModeChange)
}

fn validate_topic(
    message: &ParsedMessage,
) -> Result<PostRegistrationCommandKind, RegistrationGrammarError> {
    if message.parameter_count() == 0 {
        return Err(RegistrationGrammarError::NeedMoreParameters);
    }
    match (message.middle(), message.trailing()) {
        ([channel], None) => {
            validate_channel(channel)?;
            Ok(PostRegistrationCommandKind::TopicQuery)
        }
        ([channel], Some(topic)) => {
            validate_channel(channel)?;
            validate_bound(topic, MAX_TOPIC_BYTES)?;
            Ok(PostRegistrationCommandKind::TopicSet)
        }
        _ => Err(RegistrationGrammarError::InvalidArgument),
    }
}

fn validate_optional_channel_csv(
    message: &ParsedMessage,
    names: bool,
) -> Result<PostRegistrationCommandKind, RegistrationGrammarError> {
    match (message.middle(), message.trailing()) {
        ([], None) if names => Ok(PostRegistrationCommandKind::NamesAll),
        ([], None) => Ok(PostRegistrationCommandKind::ListAll),
        ([channels], None) => {
            validate_csv(channels, MAX_CHANNEL_TARGETS, validate_channel, ascii_equal)?;
            Ok(if names {
                PostRegistrationCommandKind::NamesChannels
            } else {
                PostRegistrationCommandKind::ListChannels
            })
        }
        _ => Err(RegistrationGrammarError::InvalidArgument),
    }
}

fn validate_invite(
    message: &ParsedMessage,
) -> Result<PostRegistrationCommandKind, RegistrationGrammarError> {
    let [nickname, channel] = require_exact_middle(message, 2)? else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    validate_nickname(nickname)?;
    validate_channel(channel)?;
    Ok(PostRegistrationCommandKind::Invite)
}

fn validate_kick(
    message: &ParsedMessage,
) -> Result<PostRegistrationCommandKind, RegistrationGrammarError> {
    if message.parameter_count() < 2 {
        return Err(RegistrationGrammarError::NeedMoreParameters);
    }
    let ([channel, nicknames], reason) = (message.middle(), message.trailing()) else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    validate_channel(channel)?;
    validate_csv(nicknames, MAX_KICK_TARGETS, validate_nickname, ascii_equal)?;
    validate_optional_bound(reason, MAX_PART_KICK_AWAY_BYTES)?;
    Ok(PostRegistrationCommandKind::Kick)
}

fn validate_message_command(
    message: &ParsedMessage,
    requires_body: bool,
) -> Result<PostRegistrationCommandKind, RegistrationGrammarError> {
    if message.parameter_count() < 2 {
        return Err(RegistrationGrammarError::NeedMoreParameters);
    }
    let ([targets], Some(body)) = (message.middle(), message.trailing()) else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    validate_csv(
        targets,
        MAX_MESSAGE_TARGETS,
        validate_message_target,
        canonical_target_equal,
    )?;
    if requires_body && body.is_empty() {
        return Err(RegistrationGrammarError::InvalidArgument);
    }
    validate_bound(body, MAX_MESSAGE_BODY_BYTES)?;
    Ok(if requires_body {
        PostRegistrationCommandKind::Privmsg
    } else {
        PostRegistrationCommandKind::Notice
    })
}

fn validate_tagmsg(
    message: &ParsedMessage,
) -> Result<PostRegistrationCommandKind, RegistrationGrammarError> {
    let target = require_one_middle(message)?;
    validate_message_target(target)?;
    if !message.tags().iter().any(|tag| tag.is_client_only()) {
        return Err(RegistrationGrammarError::InvalidArgument);
    }
    Ok(PostRegistrationCommandKind::Tagmsg)
}

fn validate_local_information(
    message: &ParsedMessage,
    command: LocalInformationCommand,
    permits_server: bool,
) -> Result<PostRegistrationCommandKind, RegistrationGrammarError> {
    match (message.middle(), message.trailing()) {
        ([], None) => Ok(PostRegistrationCommandKind::LocalInformation(command)),
        ([server], None) if permits_server => {
            validate_server_name(server)?;
            Ok(PostRegistrationCommandKind::LocalInformation(command))
        }
        _ => Err(RegistrationGrammarError::InvalidArgument),
    }
}

fn validate_who(
    message: &ParsedMessage,
) -> Result<PostRegistrationCommandKind, RegistrationGrammarError> {
    match (message.middle(), message.trailing()) {
        ([], None) => Ok(PostRegistrationCommandKind::WhoSelf),
        ([target], None) => {
            validate_target(target, false)?;
            Ok(PostRegistrationCommandKind::WhoTarget)
        }
        _ => Err(RegistrationGrammarError::InvalidArgument),
    }
}

fn validate_whois(
    message: &ParsedMessage,
) -> Result<PostRegistrationCommandKind, RegistrationGrammarError> {
    let nickname = require_one_middle(message)?;
    validate_nickname(nickname)?;
    Ok(PostRegistrationCommandKind::Whois)
}

fn validate_whowas(
    message: &ParsedMessage,
) -> Result<PostRegistrationCommandKind, RegistrationGrammarError> {
    if message.parameter_count() == 0 {
        return Err(RegistrationGrammarError::NeedMoreParameters);
    }
    match (message.middle(), message.trailing()) {
        ([nickname], None) => validate_nickname(nickname)?,
        ([nickname, count], None) => {
            validate_nickname(nickname)?;
            validate_decimal_range(count, 1, MAX_WHOWAS_COUNT)?;
        }
        _ => return Err(RegistrationGrammarError::InvalidArgument),
    }
    Ok(PostRegistrationCommandKind::Whowas)
}

fn validate_away(
    message: &ParsedMessage,
) -> Result<PostRegistrationCommandKind, RegistrationGrammarError> {
    match (message.middle(), message.trailing()) {
        ([], None) => Ok(PostRegistrationCommandKind::Away),
        ([], Some(text)) => {
            validate_bound(text, MAX_PART_KICK_AWAY_BYTES)?;
            Ok(PostRegistrationCommandKind::Away)
        }
        _ => Err(RegistrationGrammarError::InvalidArgument),
    }
}

fn validate_nickname_parameters(
    message: &ParsedMessage,
    maximum: usize,
    ison: bool,
) -> Result<PostRegistrationCommandKind, RegistrationGrammarError> {
    if message.parameter_count() == 0 {
        return Err(RegistrationGrammarError::NeedMoreParameters);
    }
    if message.trailing().is_some() || message.middle().len() > maximum {
        return Err(RegistrationGrammarError::InvalidArgument);
    }
    for nickname in message.middle() {
        validate_nickname(nickname)?;
    }
    Ok(if ison {
        PostRegistrationCommandKind::Ison
    } else {
        PostRegistrationCommandKind::Userhost
    })
}

fn validate_monitor(
    message: &ParsedMessage,
) -> Result<PostRegistrationCommandKind, RegistrationGrammarError> {
    if message.parameter_count() == 0 {
        return Err(RegistrationGrammarError::NeedMoreParameters);
    }
    if message
        .middle()
        .first()
        .is_some_and(|operation| matches!(operation.as_str(), "+" | "-"))
        && message.parameter_count() < 2
    {
        return Err(RegistrationGrammarError::NeedMoreParameters);
    }
    let operation = match (message.middle(), message.trailing()) {
        ([operation, nicknames], None) if matches!(operation.as_str(), "+" | "-") => {
            validate_csv(
                nicknames,
                MAX_CHANNEL_TARGETS,
                validate_nickname,
                ascii_equal,
            )?;
            if operation == "+" {
                MonitorCommand::Add
            } else {
                MonitorCommand::Remove
            }
        }
        ([operation], None) => match operation.as_str() {
            "C" => MonitorCommand::Clear,
            "L" => MonitorCommand::List,
            "S" => MonitorCommand::Status,
            _ => return Err(RegistrationGrammarError::InvalidArgument),
        },
        _ => return Err(RegistrationGrammarError::InvalidArgument),
    };
    Ok(PostRegistrationCommandKind::Monitor(operation))
}

fn validate_setname(
    message: &ParsedMessage,
) -> Result<PostRegistrationCommandKind, RegistrationGrammarError> {
    if message.parameter_count() == 0 {
        return Err(RegistrationGrammarError::NeedMoreParameters);
    }
    let ([], Some(display_name)) = (message.middle(), message.trailing()) else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    if display_name.len() > MAX_PRECIS_INPUT_BYTES {
        return Err(RegistrationGrammarError::InputTooLong);
    }
    if !display_name.is_empty() && !display_name.chars().all(is_precis_space_separator) {
        DisplayName::prepare(display_name).map_err(map_prepared_text_error)?;
    }
    Ok(PostRegistrationCommandKind::Setname)
}

fn validate_account_control(
    message: &ParsedMessage,
) -> Result<PostRegistrationCommandKind, RegistrationGrammarError> {
    if message.parameter_count() == 0 {
        return Err(RegistrationGrammarError::NeedMoreParameters);
    }
    let Some(operation) = message.middle().first().map(String::as_str) else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    let operation = match operation {
        "LABEL" => validate_account_label_control(message)?,
        "PRESENCE" => validate_account_setting(
            message,
            &["PUBLIC", "PRIVATE"],
            AccountControlCommand::Presence,
        )?,
        "GUEST-DM" => validate_account_setting(
            message,
            &["ALLOW", "DENY"],
            AccountControlCommand::GuestDirectMessages,
        )?,
        "DIRECT-MESSAGES" => validate_account_setting(
            message,
            &["ALLOW", "CONTACTS", "DENY"],
            AccountControlCommand::DirectMessages,
        )?,
        "CONTACT" => validate_account_contact(message)?,
        "NICK" => validate_account_nick(message)?,
        "DELETE" => validate_account_delete(message)?,
        _ => return Err(RegistrationGrammarError::InvalidArgument),
    };
    Ok(PostRegistrationCommandKind::Account(operation))
}

fn validate_account_label_control(
    message: &ParsedMessage,
) -> Result<AccountControlCommand, RegistrationGrammarError> {
    let [_, value] = require_exact_middle(message, 2)? else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    if value != "*" {
        validate_account_label(value)?;
    }
    Ok(AccountControlCommand::Label)
}

fn validate_account_setting(
    message: &ParsedMessage,
    allowed: &[&str],
    operation: AccountControlCommand,
) -> Result<AccountControlCommand, RegistrationGrammarError> {
    let [_, value] = require_exact_middle(message, 2)? else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    if !allowed.contains(&value.as_str()) {
        return Err(RegistrationGrammarError::InvalidArgument);
    }
    Ok(operation)
}

fn validate_account_contact(
    message: &ParsedMessage,
) -> Result<AccountControlCommand, RegistrationGrammarError> {
    let [_, action, account] = require_exact_middle(message, 3)? else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    AccountRandomId::parse(account).map_err(|_| RegistrationGrammarError::InvalidArgument)?;
    match action.as_str() {
        "ADD" => Ok(AccountControlCommand::ContactAdd),
        "REMOVE" => Ok(AccountControlCommand::ContactRemove),
        _ => Err(RegistrationGrammarError::InvalidArgument),
    }
}

fn validate_account_nick(
    message: &ParsedMessage,
) -> Result<AccountControlCommand, RegistrationGrammarError> {
    let [_, action, nickname] = require_exact_middle(message, 3)? else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    validate_nickname(nickname)?;
    match action.as_str() {
        "RESERVE" => Ok(AccountControlCommand::NickReserve),
        "RELEASE" => Ok(AccountControlCommand::NickRelease),
        _ => Err(RegistrationGrammarError::InvalidArgument),
    }
}

fn validate_account_delete(
    message: &ParsedMessage,
) -> Result<AccountControlCommand, RegistrationGrammarError> {
    match (message.middle(), message.trailing()) {
        ([_, action], None) if action == "START" => Ok(AccountControlCommand::DeleteStart),
        ([_, action, token], None) if action == "CONFIRM" => {
            validate_fixed_base64url_16(token)?;
            Ok(AccountControlCommand::DeleteConfirm)
        }
        _ => Err(RegistrationGrammarError::InvalidArgument),
    }
}

fn validate_channel_control(
    message: &ParsedMessage,
) -> Result<PostRegistrationCommandKind, RegistrationGrammarError> {
    if message.parameter_count() == 0 {
        return Err(RegistrationGrammarError::NeedMoreParameters);
    }
    let Some(operation) = message.middle().first().map(String::as_str) else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    let operation = match operation {
        "REGISTER" => validate_channel_control_target(message, ChannelControlCommand::Register)?,
        "UNREGISTER" => {
            validate_channel_control_target(message, ChannelControlCommand::Unregister)?
        }
        "HISTORY" => validate_channel_history_control(message)?,
        _ => return Err(RegistrationGrammarError::InvalidArgument),
    };
    Ok(PostRegistrationCommandKind::ChannelControl(operation))
}

fn validate_channel_control_target(
    message: &ParsedMessage,
    operation: ChannelControlCommand,
) -> Result<ChannelControlCommand, RegistrationGrammarError> {
    let [_, channel] = require_exact_middle(message, 2)? else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    validate_channel(channel)?;
    Ok(operation)
}

fn validate_channel_history_control(
    message: &ParsedMessage,
) -> Result<ChannelControlCommand, RegistrationGrammarError> {
    let [_, channel, retention] = require_exact_middle(message, 3)? else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    validate_channel(channel)?;
    if !matches!(retention.as_str(), "OFF" | "ON" | "1H" | "24H" | "7D") {
        return Err(RegistrationGrammarError::InvalidArgument);
    }
    Ok(ChannelControlCommand::History)
}

fn validate_chat_history(
    message: &ParsedMessage,
) -> Result<PostRegistrationCommandKind, RegistrationGrammarError> {
    if message.parameter_count() == 0 {
        return Err(RegistrationGrammarError::NeedMoreParameters);
    }
    let Some(operation) = message.middle().first().map(String::as_str) else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    let operation = match operation {
        "LATEST" => validate_single_history_reference(message, ChatHistoryCommand::Latest, true)?,
        "BEFORE" => validate_single_history_reference(message, ChatHistoryCommand::Before, false)?,
        "AFTER" => validate_single_history_reference(message, ChatHistoryCommand::After, false)?,
        "AROUND" => validate_single_history_reference(message, ChatHistoryCommand::Around, false)?,
        "BETWEEN" => validate_between_history_references(message)?,
        _ => return Err(RegistrationGrammarError::InvalidArgument),
    };
    Ok(PostRegistrationCommandKind::ChatHistory(operation))
}

fn validate_single_history_reference(
    message: &ParsedMessage,
    operation: ChatHistoryCommand,
    permits_wildcard: bool,
) -> Result<ChatHistoryCommand, RegistrationGrammarError> {
    let [_, target, reference, limit] = require_exact_middle(message, 4)? else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    validate_target(target, false)?;
    if reference != "*" {
        validate_history_reference(reference)?;
    } else if !permits_wildcard {
        return Err(RegistrationGrammarError::InvalidArgument);
    }
    validate_decimal_range(limit, 1, MAX_HISTORY_LIMIT)?;
    Ok(operation)
}

fn validate_between_history_references(
    message: &ParsedMessage,
) -> Result<ChatHistoryCommand, RegistrationGrammarError> {
    let [_, target, first, second, limit] = require_exact_middle(message, 5)? else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    validate_target(target, false)?;
    validate_history_reference(first)?;
    validate_history_reference(second)?;
    validate_decimal_range(limit, 1, MAX_HISTORY_LIMIT)?;
    Ok(ChatHistoryCommand::Between)
}

fn require_exact_middle(
    message: &ParsedMessage,
    count: usize,
) -> Result<&[String], RegistrationGrammarError> {
    if message.parameter_count() < count {
        return Err(RegistrationGrammarError::NeedMoreParameters);
    }
    if message.trailing().is_some() || message.middle().len() != count {
        return Err(RegistrationGrammarError::InvalidArgument);
    }
    Ok(message.middle())
}

fn validate_csv(
    raw: &str,
    maximum: usize,
    validate: fn(&str) -> Result<(), RegistrationGrammarError>,
    equal: fn(&str, &str) -> bool,
) -> Result<usize, RegistrationGrammarError> {
    if raw.is_empty() {
        return Err(RegistrationGrammarError::NeedMoreParameters);
    }
    let mut count = 0usize;
    for value in raw.split(',') {
        if value.is_empty() {
            return Err(RegistrationGrammarError::InvalidArgument);
        }
        count = count
            .checked_add(1)
            .ok_or(RegistrationGrammarError::InvalidArgument)?;
        if count > maximum {
            return Err(RegistrationGrammarError::InvalidArgument);
        }
        validate(value)?;
        if raw
            .split(',')
            .take(count.saturating_sub(1))
            .any(|prior| equal(prior, value))
        {
            return Err(RegistrationGrammarError::InvalidArgument);
        }
    }
    Ok(count)
}

fn validate_channel(value: &str) -> Result<(), RegistrationGrammarError> {
    if value.len() > MAX_CHANNEL_BYTES {
        return Err(RegistrationGrammarError::InputTooLong);
    }
    let Some((&prefix, remaining)) = value.as_bytes().split_first() else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    if remaining.is_empty()
        || !matches!(prefix, b'#' | b'&')
        || !remaining
            .iter()
            .copied()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
    {
        return Err(RegistrationGrammarError::InvalidArgument);
    }
    Ok(())
}

fn validate_nickname(value: &str) -> Result<(), RegistrationGrammarError> {
    if value.len() > MAX_NICKNAME_BYTES {
        return Err(RegistrationGrammarError::InputTooLong);
    }
    let Some((&first, remaining)) = value.as_bytes().split_first() else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    if !(first.is_ascii_alphabetic() || first == b'_')
        || !remaining
            .iter()
            .copied()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(RegistrationGrammarError::InvalidArgument);
    }
    Ok(())
}

fn validate_target(
    value: &str,
    permits_status_prefix: bool,
) -> Result<(), RegistrationGrammarError> {
    if permits_status_prefix && let Some(channel) = value.strip_prefix(['@', '+']) {
        return validate_channel(channel);
    }
    if value.starts_with(['#', '&']) {
        validate_channel(value)
    } else {
        validate_nickname(value)
    }
}

fn validate_message_target(value: &str) -> Result<(), RegistrationGrammarError> {
    validate_target(value, true)
}

fn validate_channel_key(value: &str) -> Result<(), RegistrationGrammarError> {
    if value.len() > MAX_CHANNEL_KEY_BYTES {
        return Err(RegistrationGrammarError::InputTooLong);
    }
    if value.len() < MIN_CHANNEL_KEY_BYTES || value.chars().any(char::is_control) {
        return Err(RegistrationGrammarError::InvalidArgument);
    }
    Ok(())
}

fn validate_mode_string(value: &str) -> Result<(), RegistrationGrammarError> {
    let mut changes = 0usize;
    let mut previous_was_sign = false;
    for byte in value.bytes() {
        if matches!(byte, b'+' | b'-') {
            if previous_was_sign {
                return Err(RegistrationGrammarError::InvalidArgument);
            }
            previous_was_sign = true;
            continue;
        }
        if !byte.is_ascii_alphabetic() {
            return Err(RegistrationGrammarError::InvalidArgument);
        }
        changes = changes
            .checked_add(1)
            .ok_or(RegistrationGrammarError::InvalidArgument)?;
        if changes > MAX_MODE_CHANGES {
            return Err(RegistrationGrammarError::InvalidArgument);
        }
        previous_was_sign = false;
    }
    if changes == 0 || previous_was_sign {
        return Err(RegistrationGrammarError::InvalidArgument);
    }
    Ok(())
}

fn validate_server_name(value: &str) -> Result<(), RegistrationGrammarError> {
    if value.len() > MAX_SERVER_NAME_BYTES {
        return Err(RegistrationGrammarError::InputTooLong);
    }
    if value.is_empty() || !value.contains('.') || !value.split('.').all(valid_server_label) {
        return Err(RegistrationGrammarError::InvalidArgument);
    }
    Ok(())
}

fn valid_server_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn validate_account_label(value: &str) -> Result<(), RegistrationGrammarError> {
    if value.len() > MAX_NICKNAME_BYTES {
        return Err(RegistrationGrammarError::InputTooLong);
    }
    let Some((&first, remaining)) = value.as_bytes().split_first() else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    if !first.is_ascii_alphanumeric()
        || !remaining
            .iter()
            .copied()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(RegistrationGrammarError::InvalidArgument);
    }
    Ok(())
}

fn validate_history_reference(value: &str) -> Result<(), RegistrationGrammarError> {
    if let Some(timestamp) = value.strip_prefix("timestamp=") {
        return validate_millisecond_timestamp(timestamp);
    }
    if let Some(message_id) = value.strip_prefix("msgid=") {
        return validate_fixed_base64url_16(message_id);
    }
    Err(RegistrationGrammarError::InvalidArgument)
}

fn validate_millisecond_timestamp(value: &str) -> Result<(), RegistrationGrammarError> {
    let bytes = value.as_bytes();
    validate_timestamp_layout(bytes)?;
    let year = decimal_digits(bytes.get(0..4))?;
    let month = decimal_digits(bytes.get(5..7))?;
    let day = decimal_digits(bytes.get(8..10))?;
    let hour = decimal_digits(bytes.get(11..13))?;
    let minute = decimal_digits(bytes.get(14..16))?;
    let second = decimal_digits(bytes.get(17..19))?;
    validate_calendar_date(year, month, day)?;
    let month_end = days_in_month(year, month).is_some_and(|maximum_day| day == maximum_day);
    validate_clock_time(hour, minute, second, month_end)
}

fn validate_timestamp_layout(bytes: &[u8]) -> Result<(), RegistrationGrammarError> {
    const PUNCTUATION: &[(usize, u8)] = &[
        (4, b'-'),
        (7, b'-'),
        (10, b'T'),
        (13, b':'),
        (16, b':'),
        (19, b'.'),
        (23, b'Z'),
    ];
    if bytes.len() != 24 {
        return Err(RegistrationGrammarError::InvalidArgument);
    }
    for (index, byte) in bytes.iter().copied().enumerate() {
        if let Some((_, expected)) = PUNCTUATION.iter().find(|(position, _)| *position == index) {
            if byte != *expected {
                return Err(RegistrationGrammarError::InvalidArgument);
            }
        } else if !byte.is_ascii_digit() {
            return Err(RegistrationGrammarError::InvalidArgument);
        }
    }
    Ok(())
}

fn validate_calendar_date(year: u32, month: u32, day: u32) -> Result<(), RegistrationGrammarError> {
    let maximum_day =
        days_in_month(year, month).ok_or(RegistrationGrammarError::InvalidArgument)?;
    if !(1..=maximum_day).contains(&day) {
        return Err(RegistrationGrammarError::InvalidArgument);
    }
    Ok(())
}

fn validate_clock_time(
    hour: u32,
    minute: u32,
    second: u32,
    month_end: bool,
) -> Result<(), RegistrationGrammarError> {
    if hour > 23 || minute > 59 || second > 60 {
        return Err(RegistrationGrammarError::InvalidArgument);
    }
    if second == 60 && (hour != 23 || minute != 59 || !month_end) {
        return Err(RegistrationGrammarError::InvalidArgument);
    }
    Ok(())
}

fn decimal_digits(bytes: Option<&[u8]>) -> Result<u32, RegistrationGrammarError> {
    let Some(bytes) = bytes else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    bytes.iter().try_fold(0u32, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u32::from(byte.saturating_sub(b'0'))))
            .ok_or(RegistrationGrammarError::InvalidArgument)
    })
}

fn days_in_month(year: u32, month: u32) -> Option<u32> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 if year.is_multiple_of(400) || (year.is_multiple_of(4) && !year.is_multiple_of(100)) => {
            Some(29)
        }
        2 => Some(28),
        _ => None,
    }
}

fn validate_fixed_base64url_16(value: &str) -> Result<(), RegistrationGrammarError> {
    const ENCODED_BYTES: usize = 22;
    let mut decoded = Zeroizing::new([0_u8; 16]);
    let decoded_length = URL_SAFE_NO_PAD
        .decode_slice(value.as_bytes(), decoded.as_mut_slice())
        .map_err(|_| RegistrationGrammarError::InvalidArgument)?;
    if decoded_length != decoded.len() {
        return Err(RegistrationGrammarError::InvalidArgument);
    }
    let mut canonical = Zeroizing::new([0_u8; ENCODED_BYTES]);
    let canonical_length = URL_SAFE_NO_PAD
        .encode_slice(decoded.as_slice(), canonical.as_mut_slice())
        .map_err(|_| RegistrationGrammarError::InvalidArgument)?;
    if canonical_length != value.len() || canonical.as_slice() != value.as_bytes() {
        return Err(RegistrationGrammarError::InvalidArgument);
    }
    Ok(())
}

fn validate_decimal_range(
    value: &str,
    minimum: u64,
    maximum: u64,
) -> Result<(), RegistrationGrammarError> {
    let parsed = parse_u64_decimal(value).map_err(|_| RegistrationGrammarError::InvalidArgument)?;
    if !(minimum..=maximum).contains(&parsed) {
        return Err(RegistrationGrammarError::InvalidArgument);
    }
    Ok(())
}

fn validate_bound(value: &str, maximum: usize) -> Result<(), RegistrationGrammarError> {
    if value.len() > maximum {
        return Err(RegistrationGrammarError::InputTooLong);
    }
    Ok(())
}

fn validate_optional_bound(
    value: Option<&str>,
    maximum: usize,
) -> Result<(), RegistrationGrammarError> {
    if let Some(value) = value {
        validate_bound(value, maximum)?;
    }
    Ok(())
}

fn map_prepared_text_error(error: ValidationError) -> RegistrationGrammarError {
    match error {
        ValidationError::TooLong => RegistrationGrammarError::InputTooLong,
        ValidationError::AllocationFailed => RegistrationGrammarError::AllocationFailed,
        _ => RegistrationGrammarError::InvalidArgument,
    }
}

fn is_precis_space_separator(character: char) -> bool {
    matches!(
        character,
        '\u{0020}' | '\u{00a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{202f}' | '\u{205f}' | '\u{3000}'
    )
}

fn ascii_equal(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn canonical_target_equal(left: &str, right: &str) -> bool {
    let left = left.strip_prefix(['@', '+']).unwrap_or(left);
    let right = right.strip_prefix(['@', '+']).unwrap_or(right);
    left.eq_ignore_ascii_case(right)
}

fn parse_cap(message: &ParsedMessage) -> Result<RegistrationCapCommand, RegistrationGrammarError> {
    let Some(subcommand) = message.middle().first().map(String::as_str) else {
        return Err(RegistrationGrammarError::NeedMoreParameters);
    };
    match subcommand {
        "LS" => match (message.middle(), message.trailing()) {
            ([_], None) => Ok(RegistrationCapCommand::ListSupported),
            ([_, version], None) if version == "302" => Ok(RegistrationCapCommand::ListSupported),
            _ => Err(RegistrationGrammarError::InvalidArgument),
        },
        "LIST" if message.middle().len() == 1 && message.trailing().is_none() => {
            Ok(RegistrationCapCommand::ListEnabled)
        }
        "REQ" if message.middle().len() == 1 => {
            let Some(request) = message.trailing() else {
                return Err(RegistrationGrammarError::NeedMoreParameters);
            };
            validate_capability_list(request)?;
            Ok(RegistrationCapCommand::Request)
        }
        "END" if message.middle().len() == 1 && message.trailing().is_none() => {
            Ok(RegistrationCapCommand::End)
        }
        _ => Err(RegistrationGrammarError::InvalidArgument),
    }
}

fn validate_capability_list(request: &str) -> Result<(), RegistrationGrammarError> {
    if request.is_empty() {
        return Err(RegistrationGrammarError::NeedMoreParameters);
    }
    for token in request.split(' ') {
        let name = token.strip_prefix('-').unwrap_or(token);
        if name.is_empty()
            || name.contains('=')
            || !name.bytes().all(|byte| matches!(byte, b'!'..=b'~'))
        {
            return Err(RegistrationGrammarError::InvalidArgument);
        }
    }
    Ok(())
}

fn validate_authenticate(
    message: &ParsedMessage,
) -> Result<RegistrationCommand, RegistrationGrammarError> {
    let token = require_one_middle(message)?;
    if token.len() > AUTH_CHUNK_CHARACTERS {
        return Ok(RegistrationCommand::Authenticate);
    }
    if matches!(token, "*" | "+")
        || is_sasl_mechanism(token)
        || is_canonical_padded_base64_chunk(token)
    {
        return Ok(RegistrationCommand::Authenticate);
    }
    Err(RegistrationGrammarError::InvalidArgument)
}

fn is_sasl_mechanism(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_SASL_MECHANISM_BYTES
        && token
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
}

fn is_canonical_padded_base64_chunk(token: &str) -> bool {
    if token.is_empty() || !token.len().is_multiple_of(4) {
        return false;
    }
    let mut decoded = Zeroizing::new([0_u8; MAX_AUTH_CHUNK_BYTES]);
    let Ok(decoded_length) = STANDARD.decode_slice(token.as_bytes(), decoded.as_mut_slice()) else {
        return false;
    };
    let mut canonical = Zeroizing::new([0_u8; AUTH_CHUNK_CHARACTERS]);
    let Some(decoded) = decoded.as_slice().get(..decoded_length) else {
        return false;
    };
    let Ok(canonical_length) = STANDARD.encode_slice(decoded, canonical.as_mut_slice()) else {
        return false;
    };
    canonical_length == token.len() && canonical.get(..canonical_length) == Some(token.as_bytes())
}

fn validate_pass(
    message: &ParsedMessage,
    access_policy: AccessTokenPolicy,
) -> Result<RegistrationCommand, RegistrationGrammarError> {
    let token = require_one_middle(message)?;
    match access_policy {
        AccessTokenPolicy::IgnoreCompatibilityPass
            if token.len() > MAX_COMPATIBILITY_PASS_BYTES =>
        {
            Err(RegistrationGrammarError::InputTooLong)
        }
        AccessTokenPolicy::IgnoreCompatibilityPass => Ok(RegistrationCommand::Pass),
        AccessTokenPolicy::RequireConfiguredToken if is_canonical_configured_pass(token) => {
            Ok(RegistrationCommand::Pass)
        }
        AccessTokenPolicy::RequireConfiguredToken => Err(RegistrationGrammarError::InvalidArgument),
    }
}

fn is_canonical_configured_pass(token: &str) -> bool {
    if token.len() != CONFIGURED_PASS_CHARACTERS {
        return false;
    }
    let mut decoded = Zeroizing::new([0_u8; CONFIGURED_PASS_BYTES]);
    let Ok(decoded_length) = URL_SAFE_NO_PAD.decode_slice(token.as_bytes(), decoded.as_mut_slice())
    else {
        return false;
    };
    if decoded_length != CONFIGURED_PASS_BYTES {
        return false;
    }
    let mut canonical = Zeroizing::new([0_u8; CONFIGURED_PASS_CHARACTERS]);
    let Ok(canonical_length) =
        URL_SAFE_NO_PAD.encode_slice(decoded.as_slice(), canonical.as_mut_slice())
    else {
        return false;
    };
    canonical_length == token.len() && canonical.as_slice() == token.as_bytes()
}

fn parse_account_carrier(
    message: &ParsedMessage,
) -> Result<RegistrationAccountCommand, RegistrationGrammarError> {
    if !message.tags().is_empty() {
        return Err(RegistrationGrammarError::InvalidArgument);
    }
    let Some(subcommand) = message.middle().first().map(String::as_str) else {
        return Err(RegistrationGrammarError::NeedMoreParameters);
    };
    match subcommand {
        "START" => validate_account_length(message).map(|()| RegistrationAccountCommand::Start),
        "FINISH" => validate_account_length(message).map(|()| RegistrationAccountCommand::Finish),
        "DATA" => validate_account_data(message).map(|()| RegistrationAccountCommand::Data),
        "END" if message.middle().len() == 1 && message.trailing().is_none() => {
            Ok(RegistrationAccountCommand::End)
        }
        _ => Err(RegistrationGrammarError::InvalidArgument),
    }
}

fn validate_account_length(message: &ParsedMessage) -> Result<(), RegistrationGrammarError> {
    if message.parameter_count() < 2 {
        return Err(RegistrationGrammarError::NeedMoreParameters);
    }
    let ([_, length], None) = (message.middle(), message.trailing()) else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    let Ok(length) = parse_u64_decimal(length) else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    if length == ACCOUNT_REQUEST_BYTES as u64 {
        return Ok(());
    }
    Err(RegistrationGrammarError::InvalidArgument)
}

fn validate_account_data(message: &ParsedMessage) -> Result<(), RegistrationGrammarError> {
    if message.parameter_count() < 2 {
        return Err(RegistrationGrammarError::NeedMoreParameters);
    }
    let ([_, chunk], None) = (message.middle(), message.trailing()) else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    if chunk.len() > AUTH_CHUNK_CHARACTERS {
        return Err(RegistrationGrammarError::InputTooLong);
    }
    if is_canonical_base64url_chunk(chunk) {
        return Ok(());
    }
    Err(RegistrationGrammarError::InvalidArgument)
}

fn is_canonical_base64url_chunk(token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    let mut decoded = Zeroizing::new([0_u8; MAX_AUTH_CHUNK_BYTES]);
    let Ok(decoded_length) = URL_SAFE_NO_PAD.decode_slice(token.as_bytes(), decoded.as_mut_slice())
    else {
        return false;
    };
    let mut canonical = Zeroizing::new([0_u8; AUTH_CHUNK_CHARACTERS]);
    let Some(decoded) = decoded.as_slice().get(..decoded_length) else {
        return false;
    };
    let Ok(canonical_length) = URL_SAFE_NO_PAD.encode_slice(decoded, canonical.as_mut_slice())
    else {
        return false;
    };
    canonical_length == token.len() && canonical.get(..canonical_length) == Some(token.as_bytes())
}

fn validate_nick(message: &ParsedMessage) -> Result<RegistrationCommand, RegistrationGrammarError> {
    let nickname = require_one_middle(message)?;
    if nickname.len() > 32 {
        return Err(RegistrationGrammarError::InputTooLong);
    }
    let Some((&first, remaining)) = nickname.as_bytes().split_first() else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    if !(first.is_ascii_alphabetic() || first == b'_')
        || !remaining
            .iter()
            .copied()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(RegistrationGrammarError::InvalidArgument);
    }
    Ok(RegistrationCommand::Nick)
}

fn validate_user(message: &ParsedMessage) -> Result<RegistrationCommand, RegistrationGrammarError> {
    if message.parameter_count() < 4 {
        return Err(RegistrationGrammarError::NeedMoreParameters);
    }
    let ([user, _, _], Some(realname)) = (message.middle(), message.trailing()) else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    if !is_valid_user_field(user) {
        return Err(RegistrationGrammarError::InvalidArgument);
    }
    let prepared_length = realname
        .chars()
        .filter(|character| !character.is_control())
        .try_fold(0usize, |used, character| {
            used.checked_add(character.len_utf8())
        })
        .ok_or(RegistrationGrammarError::InputTooLong)?;
    if prepared_length > MAX_REALNAME_BYTES {
        return Err(RegistrationGrammarError::InputTooLong);
    }
    Ok(RegistrationCommand::User)
}

fn is_valid_user_field(user: &str) -> bool {
    !user.is_empty()
        && user.chars().all(|character| {
            character != '@' && !character.is_whitespace() && !character.is_control()
        })
}

fn validate_ping_pong(message: &ParsedMessage) -> Result<(), RegistrationGrammarError> {
    let token = require_one_parameter(message)?;
    if token.len() > MAX_PING_PONG_BYTES {
        return Err(RegistrationGrammarError::InputTooLong);
    }
    Ok(())
}

fn validate_quit(message: &ParsedMessage) -> Result<RegistrationCommand, RegistrationGrammarError> {
    match (message.middle(), message.trailing()) {
        ([], None) => Ok(RegistrationCommand::Quit),
        ([], Some(reason)) if reason.len() <= MAX_QUIT_REASON_BYTES => {
            Ok(RegistrationCommand::Quit)
        }
        ([], Some(_)) => Err(RegistrationGrammarError::InputTooLong),
        _ => Err(RegistrationGrammarError::InvalidArgument),
    }
}

fn require_one_middle(message: &ParsedMessage) -> Result<&str, RegistrationGrammarError> {
    if message.parameter_count() == 0 {
        return Err(RegistrationGrammarError::NeedMoreParameters);
    }
    let ([only], None) = (message.middle(), message.trailing()) else {
        return Err(RegistrationGrammarError::InvalidArgument);
    };
    Ok(only)
}

fn require_one_parameter(message: &ParsedMessage) -> Result<&str, RegistrationGrammarError> {
    if message.parameter_count() == 0 {
        return Err(RegistrationGrammarError::NeedMoreParameters);
    }
    match (message.middle(), message.trailing()) {
        ([only], None) => Ok(only.as_str()),
        ([], Some(only)) => Ok(only),
        _ => Err(RegistrationGrammarError::InvalidArgument),
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

    use agenc_ircd_types::ValidationError;

    use super::{
        MAX_CHANNEL_KEY_BYTES, MAX_MESSAGE_BODY_BYTES, MAX_PART_KICK_AWAY_BYTES, MAX_TOPIC_BYTES,
        RegistrationCommand, RegistrationGrammarError, canonical_target_equal, days_in_month,
        decimal_digits, is_canonical_base64url_chunk, is_canonical_configured_pass,
        is_canonical_padded_base64_chunk, is_precis_space_separator, is_sasl_mechanism,
        is_valid_user_field, map_prepared_text_error, parse_registration_command,
        valid_server_label, validate_bound, validate_calendar_date, validate_capability_list,
        validate_channel, validate_channel_key, validate_clock_time, validate_decimal_range,
        validate_fixed_base64url_16, validate_history_reference, validate_millisecond_timestamp,
        validate_mode_string, validate_nickname, validate_optional_bound,
        validate_post_registration_command, validate_server_name, validate_target,
    };
    use crate::{AccessTokenPolicy, FramedLine, ParsedMessage, parse_message};

    #[test]
    fn semantic_text_ceilings_accept_exact_and_reject_maximum_plus_one() {
        for maximum in [
            MAX_PART_KICK_AWAY_BYTES,
            MAX_MESSAGE_BODY_BYTES,
            MAX_TOPIC_BYTES,
        ] {
            let exact = "x".repeat(maximum);
            let over = "x".repeat(maximum + 1);
            assert_eq!(validate_bound(&exact, maximum), Ok(()));
            assert_eq!(
                validate_bound(&over, maximum),
                Err(RegistrationGrammarError::InputTooLong)
            );
        }
    }

    #[test]
    fn millisecond_timestamp_checks_layout_calendar_and_leap_seconds() {
        for timestamp in [
            "0000-01-01T00:00:00.000Z",
            "2016-12-31T23:59:60.999Z",
            "2100-02-28T23:59:59.999Z",
        ] {
            assert_eq!(validate_millisecond_timestamp(timestamp), Ok(()));
        }
        for timestamp in [
            "2024-01-01t00:00:00.000Z",
            "2024-01-01T00:00:00.000+00:00",
            "2023-02-29T00:00:00.000Z",
            "2024-04-31T00:00:00.000Z",
            "2024-01-01T24:00:00.000Z",
            "2024-01-01T00:60:00.000Z",
            "2024-01-01T00:00:61.000Z",
            "2024-01-01T00:00:60.000Z",
            "2024-01-01T23:59:60.000Z",
            "2024-06-30T22:59:60.000Z",
        ] {
            assert_eq!(
                validate_millisecond_timestamp(timestamp),
                Err(RegistrationGrammarError::InvalidArgument),
                "{timestamp}"
            );
        }
    }

    #[test]
    fn primitive_validators_cover_each_short_circuit_boundary() {
        for (value, expected) in [
            ("#a", Ok(())),
            ("&a-b_1.+", Ok(())),
            ("#", Err(RegistrationGrammarError::InvalidArgument)),
            ("nickname", Err(RegistrationGrammarError::InvalidArgument)),
            ("#bad!", Err(RegistrationGrammarError::InvalidArgument)),
        ] {
            assert_eq!(validate_channel(value), expected, "{value:?}");
        }
        for (value, expected) in [
            ("Nick", Ok(())),
            ("_nick-1", Ok(())),
            ("", Err(RegistrationGrammarError::InvalidArgument)),
            ("9nick", Err(RegistrationGrammarError::InvalidArgument)),
            ("bad.nick", Err(RegistrationGrammarError::InvalidArgument)),
        ] {
            assert_eq!(validate_nickname(value), expected, "{value:?}");
        }
        assert_eq!(validate_target("@#room", true), Ok(()));
        assert_eq!(validate_target("+#room", true), Ok(()));
        assert_eq!(validate_target("#room", false), Ok(()));
        assert_eq!(validate_target("Nick", false), Ok(()));
        assert_eq!(
            validate_target("@#room", false),
            Err(RegistrationGrammarError::InvalidArgument)
        );
        assert!(canonical_target_equal("@#Room", "+#room"));
        assert!(!canonical_target_equal("Nick", "Other"));

        assert_eq!(validate_channel_key("12345678"), Ok(()));
        assert_eq!(
            validate_channel_key("short"),
            Err(RegistrationGrammarError::InvalidArgument)
        );
        assert_eq!(
            validate_channel_key("abcd\0efg"),
            Err(RegistrationGrammarError::InvalidArgument)
        );
        assert_eq!(
            validate_channel_key(&"k".repeat(MAX_CHANNEL_KEY_BYTES + 1)),
            Err(RegistrationGrammarError::InputTooLong)
        );

        for (value, expected) in [
            ("i", Ok(())),
            ("+i-o", Ok(())),
            ("", Err(RegistrationGrammarError::InvalidArgument)),
            ("+", Err(RegistrationGrammarError::InvalidArgument)),
            ("++i", Err(RegistrationGrammarError::InvalidArgument)),
            ("+1", Err(RegistrationGrammarError::InvalidArgument)),
            ("+abcdefg", Err(RegistrationGrammarError::InvalidArgument)),
        ] {
            assert_eq!(validate_mode_string(value), expected, "{value:?}");
        }
    }

    #[test]
    fn server_account_and_history_tokens_reject_every_malformed_component() {
        for (value, expected) in [
            ("irc.example", Ok(())),
            ("irc-1.example", Ok(())),
            ("", Err(RegistrationGrammarError::InvalidArgument)),
            ("localhost", Err(RegistrationGrammarError::InvalidArgument)),
            (".example", Err(RegistrationGrammarError::InvalidArgument)),
            (
                "-irc.example",
                Err(RegistrationGrammarError::InvalidArgument),
            ),
            (
                "irc-.example",
                Err(RegistrationGrammarError::InvalidArgument),
            ),
            (
                "IRC.example",
                Err(RegistrationGrammarError::InvalidArgument),
            ),
        ] {
            assert_eq!(validate_server_name(value), expected, "{value:?}");
        }
        assert!(valid_server_label("a1-b"));
        assert!(!valid_server_label(""));
        assert!(!valid_server_label(&"a".repeat(64)));
        assert_eq!(
            validate_server_name(&format!("{}.example", "a".repeat(246))),
            Err(RegistrationGrammarError::InputTooLong)
        );

        for reference in [
            "reference=unknown",
            "msgid=short",
            "timestamp=2024-13-01T00:00:00.000Z",
            "timestamp=2024-01-00T00:00:00.000Z",
            "timestamp=2024-01-01T00:00:00.00AZ",
        ] {
            assert_eq!(
                validate_history_reference(reference),
                Err(RegistrationGrammarError::InvalidArgument),
                "{reference}"
            );
        }
        let message_id = URL_SAFE_NO_PAD.encode([7_u8; 16]);
        assert_eq!(
            validate_history_reference(&format!("msgid={message_id}")),
            Ok(())
        );
        assert_eq!(
            validate_fixed_base64url_16(&"A".repeat(20)),
            Err(RegistrationGrammarError::InvalidArgument)
        );

        assert_eq!(validate_calendar_date(2000, 2, 29), Ok(()));
        assert_eq!(
            validate_calendar_date(1900, 2, 29),
            Err(RegistrationGrammarError::InvalidArgument)
        );
        assert_eq!(days_in_month(2024, 4), Some(30));
        assert_eq!(days_in_month(2024, 13), None);
        assert_eq!(validate_clock_time(23, 59, 60, true), Ok(()));
        assert_eq!(
            validate_clock_time(23, 59, 60, false),
            Err(RegistrationGrammarError::InvalidArgument)
        );
        assert_eq!(
            decimal_digits(None),
            Err(RegistrationGrammarError::InvalidArgument)
        );
        assert_eq!(
            decimal_digits(Some(b"99999999999999999999")),
            Err(RegistrationGrammarError::InvalidArgument)
        );
        assert_eq!(validate_decimal_range("1", 1, 10), Ok(()));
        assert_eq!(
            validate_decimal_range("11", 1, 10),
            Err(RegistrationGrammarError::InvalidArgument)
        );
    }

    #[test]
    fn registration_carrier_tokens_cover_canonical_and_invalid_encodings() {
        for request in ["batch", "-batch", "batch sasl"] {
            assert_eq!(validate_capability_list(request), Ok(()), "{request:?}");
        }
        for request in ["", "-", "name=value", "batch  sasl", "bad\u{7f}"] {
            assert!(validate_capability_list(request).is_err(), "{request:?}");
        }

        assert!(is_sasl_mechanism("AGENC-OPAQUE"));
        assert!(is_sasl_mechanism("A-1"));
        assert!(!is_sasl_mechanism(""));
        assert!(!is_sasl_mechanism("lowercase"));
        assert!(!is_sasl_mechanism("ABCDEFGHIJKLMNOPQRSTU"));

        let padded = STANDARD.encode([0_u8; 3]);
        assert!(is_canonical_padded_base64_chunk(&padded));
        assert!(!is_canonical_padded_base64_chunk(""));
        assert!(!is_canonical_padded_base64_chunk("A"));
        assert!(!is_canonical_padded_base64_chunk("AA==="));

        let configured = URL_SAFE_NO_PAD.encode([0_u8; 32]);
        assert!(is_canonical_configured_pass(&configured));
        assert!(!is_canonical_configured_pass("short"));
        assert!(!is_canonical_configured_pass(&"!".repeat(43)));

        assert!(is_canonical_base64url_chunk("AA"));
        assert!(!is_canonical_base64url_chunk(""));
        assert!(!is_canonical_base64url_chunk("AA=="));
        assert!(is_valid_user_field("user:name"));
        for user in ["", "bad@user", "bad user", "bad\u{7}user"] {
            assert!(!is_valid_user_field(user), "{user:?}");
        }

        assert_eq!(validate_optional_bound(None, 0), Ok(()));
        assert_eq!(validate_optional_bound(Some(""), 0), Ok(()));
        assert_eq!(
            validate_optional_bound(Some("x"), 0),
            Err(RegistrationGrammarError::InputTooLong)
        );
        assert_eq!(
            map_prepared_text_error(ValidationError::TooLong),
            RegistrationGrammarError::InputTooLong
        );
        assert_eq!(
            map_prepared_text_error(ValidationError::AllocationFailed),
            RegistrationGrammarError::AllocationFailed
        );
        assert_eq!(
            map_prepared_text_error(ValidationError::InvalidCharacter),
            RegistrationGrammarError::InvalidArgument
        );
        assert!(is_precis_space_separator('\u{00a0}'));
        assert!(!is_precis_space_separator('a'));
    }

    #[test]
    fn command_dispatch_and_post_registration_guards_are_closed()
    -> Result<(), RegistrationGrammarError> {
        for line in [
            "CAP LS",
            "AUTHENTICATE +",
            "PASS token",
            "ACCTCREATE END",
            "ACCTCRED END",
            "NICK Nick",
            "USER user 0 * :Real Name",
            "PING token",
            "PONG :token",
            "QUIT :done",
            "JOIN 0",
        ] {
            assert!(classify(line).is_ok(), "{line}");
        }
        for (line, error) in [
            ("ACCOUNT", RegistrationGrammarError::UnknownCommand),
            ("TRACE", RegistrationGrammarError::NoPrivileges),
            ("OPER", RegistrationGrammarError::NoPrivileges),
            ("SERVLIST", RegistrationGrammarError::UnknownCommand),
            ("WHATEVER", RegistrationGrammarError::UnknownCommand),
        ] {
            assert_eq!(classify(line).err(), Some(error), "{line}");
        }

        for line in [
            "JOIN #room",
            "PART #room :reason",
            "MODE #room",
            "MODE #room +i",
            "TOPIC #room :topic",
            "NAMES",
            "NAMES #room",
            "LIST",
            "LIST #room",
            "INVITE Nick #room",
            "KICK #room Nick :reason",
            "PRIVMSG @#room :body",
            "NOTICE #room :",
            "@+draft/test TAGMSG #room",
            "MOTD irc.example",
            "WHO Nick",
            "WHOWAS Nick 10",
            "AWAY :gone",
            "ISON Nick",
            "USERHOST Nick",
            "MONITOR + Nick",
            "MONITOR - Nick",
            "MONITOR C",
            "SETNAME :",
            "SETNAME :   ",
            "SETNAME :Display Name",
            "ACCT LABEL *",
            "CHANCTL HISTORY #room 24H",
            "CHATHISTORY LATEST #room * 1",
        ] {
            assert!(validate(line).is_ok(), "{line}");
        }
        for line in [
            "JOIN",
            "PART",
            "PART #room reason",
            "MODE",
            "MODE :#room",
            "MODE #room :missing-mode",
            "MODE #room +oooooo a b c d e f g",
            "TOPIC",
            "INVITE Nick",
            "INVITE Nick #room extra",
            "KICK #room",
            "PRIVMSG",
            "PRIVMSG #room body",
            "PRIVMSG #room :",
            "TAGMSG #room",
            "LUSERS irc.example",
            "WHOWAS",
            "ISON",
            "ISON :Nick",
            "USERHOST a b c d e f",
            "MONITOR",
            "MONITOR +",
            "SETNAME",
            "SETNAME display",
            "ACCT",
            "ACCT :LABEL",
            "ACCT UNKNOWN value",
            "CHANCTL UNKNOWN #room",
            "CHATHISTORY UNKNOWN #room * 1",
        ] {
            assert!(validate(line).is_err(), "{line}");
        }
        Ok(())
    }

    fn parsed(line: &str) -> Result<ParsedMessage, RegistrationGrammarError> {
        let framed =
            FramedLine::new(line).map_err(|_| RegistrationGrammarError::InvalidArgument)?;
        parse_message(framed)
            .map_err(|_| RegistrationGrammarError::InvalidArgument)?
            .ok_or(RegistrationGrammarError::InvalidArgument)
    }

    fn classify(line: &str) -> Result<RegistrationCommand, RegistrationGrammarError> {
        parse_registration_command(&parsed(line)?, AccessTokenPolicy::IgnoreCompatibilityPass)
    }

    fn validate(line: &str) -> Result<(), RegistrationGrammarError> {
        validate_post_registration_command(&parsed(line)?).map(|_| ())
    }
}
