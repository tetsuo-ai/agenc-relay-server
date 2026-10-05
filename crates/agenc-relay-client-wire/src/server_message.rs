//! Server-to-client message decoding (Architecture 9, Appendix A.2).
//!
//! [`parse_server_message`] reads one line a server sent: optional tags, an
//! optional source prefix, a command or numeric from the closed base
//! registries, and at most 15 parameters. The decoded [`ServerMessage`]
//! borrows the line and owns no heap memory.

use std::error::Error;
use std::fmt;

use agenc_relay_types::{PublicCloak, SERVER_COMMANDS, SERVER_NUMERICS, STANDARD_REPLY_CODES};

use crate::registration_command::{validate_nickname, validate_server_name};
use crate::render::{CLOAK_HOST_FRAME, CLOAK_HOST_SUFFIX, CLOAK_USER_FRAME};
use crate::{
    MAX_PARAMETERS, ServerFramedLine, ServerTagError, ServerTags, parse_server_tags,
    relays_client_only_tags,
};

/// Numerics Appendix A.2 forbids: idle time (317) and the address, real-host
/// and route disclosures (325, 338, 378, 379). None is in the server numeric
/// registry; a line carrying one is refused with its own error.
pub const FORBIDDEN_NUMERICS: [u16; 5] = [317, 325, 338, 378, 379];

/// Standard-reply codes Appendix A.2 makes legal only on the authenticated
/// administrative ALPN, never on a client connection.
pub const ADMIN_ONLY_REPLY_CODES: [&str; 5] =
    ["CHALLENGE", "CHECKPOINT", "CONFIRM", "EVENT", "VALUE"];

/// The queue-owner code, legal only as `WARN * SLOW_CONSUMER :<text>`
/// (Architecture 19.3).
const QUEUE_WARNING_CODE: &str = "SLOW_CONSUMER";
/// Standard-reply codes are `[A-Z0-9_]{1,64}` (Architecture 9.5).
const MAX_REPLY_CODE_BYTES: usize = 64;

/// Closed failures of one server line's syntax and registries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerMessageError {
    /// A tag section had no space ending it.
    UnterminatedTags,
    /// The tag section was invalid.
    Tags(ServerTagError),
    /// The source prefix was neither a server name nor a cloaked user mask
    /// in the framed spelling of Architecture 7.4.
    InvalidPrefix,
    /// No command followed, or a space came where the command should start.
    MissingCommand,
    /// The command was neither upper-case ASCII letters nor three digits.
    InvalidCommand,
    /// The command is not in the server command registry.
    UnregisteredCommand,
    /// The numeric is not in the server numeric registry.
    UnregisteredNumeric,
    /// The numeric is one Appendix A.2 forbids.
    ForbiddenNumeric,
    /// More than 15 parameters.
    TooManyParameters,
    /// A middle parameter was empty: a doubled or trailing space.
    EmptyParameter,
    /// A standard reply lacked its command, its code or a trailing
    /// description.
    MalformedStandardReply,
    /// A standard-reply code violated `[A-Z0-9_]{1,64}`.
    InvalidReplyCode,
    /// A standard-reply code is not in the base registry.
    UnregisteredReplyCode,
    /// A registered standard-reply code that is not legal here: an
    /// administrative code, or `SLOW_CONSUMER` outside `WARN *`.
    InapplicableReplyCode,
    /// A client-only tag on a command that does not relay client-only tags.
    MisplacedClientOnlyTag,
}

impl fmt::Display for ServerMessageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnterminatedTags => "server message tag section lacks a separating space",
            Self::Tags(_) => "server message tags are invalid",
            Self::InvalidPrefix => "server message source is not a server or cloaked user",
            Self::MissingCommand => "server message lacks a command",
            Self::InvalidCommand => "server command is not upper-case letters or a numeric",
            Self::UnregisteredCommand => "server command is not in the server registry",
            Self::UnregisteredNumeric => "server numeric is not in the server registry",
            Self::ForbiddenNumeric => "server numeric discloses forbidden network detail",
            Self::TooManyParameters => "server message has more than 15 parameters",
            Self::EmptyParameter => "server message has an empty middle parameter",
            Self::MalformedStandardReply => "standard reply lacks its command, code or description",
            Self::InvalidReplyCode => "standard-reply code violates the code grammar",
            Self::UnregisteredReplyCode => "standard-reply code is not in the base registry",
            Self::InapplicableReplyCode => {
                "standard-reply code is not legal on a client connection"
            }
            Self::MisplacedClientOnlyTag => "client-only tag on a command that does not relay them",
        };
        formatter.write_str(message)
    }
}

impl Error for ServerMessageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Tags(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ServerTagError> for ServerMessageError {
    fn from(error: ServerTagError) -> Self {
        Self::Tags(error)
    }
}

/// The command of a server line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerCommand {
    /// A registered command, spelled as in the registry.
    Named(&'static str),
    /// A registered numeric (`001` is `1`).
    Numeric(u16),
}

impl ServerCommand {
    /// The registered name, if this is a named command.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        match self {
            Self::Named(name) => Some(name),
            Self::Numeric(_) => None,
        }
    }

    /// The numeric, if this is one.
    #[must_use]
    pub const fn numeric(self) -> Option<u16> {
        match self {
            Self::Named(_) => None,
            Self::Numeric(code) => Some(code),
        }
    }
}

/// A cloaked user source `nickname!u-<10 base32>@h-<16 base32>.invalid`
/// (Architecture 7.4). Every field borrows the line.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ServerUserPrefix<'a> {
    mask: &'a str,
    nickname: &'a str,
    user: &'a str,
    host: &'a str,
    cloak: PublicCloak,
}

impl<'a> ServerUserPrefix<'a> {
    /// The whole mask as received.
    #[must_use]
    pub const fn mask(&self) -> &'a str {
        self.mask
    }

    /// The nickname, in the Section 7.2 grammar.
    #[must_use]
    pub const fn nickname(&self) -> &'a str {
        self.nickname
    }

    /// The visible user field, `u-<10 base32>`.
    #[must_use]
    pub const fn user(&self) -> &'a str {
        self.user
    }

    /// The visible host field, `h-<16 base32>.invalid`.
    #[must_use]
    pub const fn host(&self) -> &'a str {
        self.host
    }

    /// The public cloak the two fields frame.
    #[must_use]
    pub const fn cloak(&self) -> PublicCloak {
        self.cloak
    }
}

impl fmt::Debug for ServerUserPrefix<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerUserPrefix")
            .field("mask_bytes", &self.mask.len())
            .finish()
    }
}

/// The source prefix of a server line.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ServerPrefix<'a> {
    /// A server name in the configured server-name grammar.
    Server(&'a str),
    /// A cloaked user.
    User(ServerUserPrefix<'a>),
}

impl<'a> ServerPrefix<'a> {
    /// The prefix as received, without its colon.
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        match *self {
            Self::Server(name) => name,
            Self::User(user) => user.mask,
        }
    }
}

impl fmt::Debug for ServerPrefix<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Server(_) => formatter.write_str("ServerPrefix::Server"),
            Self::User(_) => formatter.write_str("ServerPrefix::User"),
        }
    }
}

/// The parameters of one server line: at most 15, the last possibly
/// trailing.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ServerParams<'a> {
    items: [&'a str; MAX_PARAMETERS],
    len: usize,
    has_trailing: bool,
}

impl<'a> ServerParams<'a> {
    const fn new() -> Self {
        Self {
            items: [""; MAX_PARAMETERS],
            len: 0,
            has_trailing: false,
        }
    }

    fn push(&mut self, parameter: &'a str, trailing: bool) -> Result<(), ServerMessageError> {
        let slot = self
            .items
            .get_mut(self.len)
            .ok_or(ServerMessageError::TooManyParameters)?;
        *slot = parameter;
        self.len += 1;
        self.has_trailing = trailing;
        Ok(())
    }

    /// Every parameter in order, the trailing one last.
    #[must_use]
    pub fn all(&self) -> &[&'a str] {
        self.items.get(..self.len).unwrap_or_default()
    }

    /// The parameters before the trailing one.
    #[must_use]
    pub fn middle(&self) -> &[&'a str] {
        let count = self.len - usize::from(self.has_trailing);
        self.items.get(..count).unwrap_or_default()
    }

    /// The trailing parameter introduced by a colon, which may be empty.
    #[must_use]
    pub fn trailing(&self) -> Option<&'a str> {
        if self.has_trailing {
            self.all().last().copied()
        } else {
            None
        }
    }

    /// The number of parameters, the trailing one included.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the line had no parameter.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Debug for ServerParams<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerParams")
            .field("len", &self.len)
            .field("has_trailing", &self.has_trailing)
            .finish()
    }
}

/// One decoded server line, borrowing its text.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ServerMessage<'a> {
    tags: ServerTags<'a>,
    prefix: Option<ServerPrefix<'a>>,
    command: ServerCommand,
    params: ServerParams<'a>,
}

impl<'a> ServerMessage<'a> {
    /// The tag section, verbatim and validated.
    #[must_use]
    pub const fn tags(&self) -> &ServerTags<'a> {
        &self.tags
    }

    /// The source prefix, if the line had one.
    #[must_use]
    pub const fn prefix(&self) -> Option<ServerPrefix<'a>> {
        self.prefix
    }

    /// The registered command or numeric.
    #[must_use]
    pub const fn command(&self) -> ServerCommand {
        self.command
    }

    /// The parameters.
    #[must_use]
    pub const fn params(&self) -> &ServerParams<'a> {
        &self.params
    }
}

impl fmt::Debug for ServerMessage<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerMessage")
            .field("command", &self.command)
            .field("prefix", &self.prefix)
            .field("tags", &self.tags)
            .field("params", &self.params)
            .finish()
    }
}

/// Decodes one framed server line.
///
/// The grammar is canonical, as the base renderer writes it:
///
/// ```text
/// line     = [ "@" tags SP ] [ ":" prefix SP ] command *( SP middle ) [ SP ":" trailing ]
/// command  = 1*UPPER / 3DIGIT
/// middle   = 1*( any byte but NUL, CR, LF and SP ), not starting with ":"
/// trailing = *( any byte but NUL, CR and LF )
/// ```
///
/// - Spaces are single: a leading, doubled or trailing space is an error.
/// - The tags are checked by [`parse_server_tags`].
/// - A prefix is a server name in the configured server-name grammar, or a
///   cloaked user mask in the framed spelling of Architecture 7.4 whose
///   nickname follows Section 7.2; a real host, an address or the bare cloak
///   components are refused. A line may omit the prefix.
/// - The command is a member of the base `SERVER_COMMANDS` registry, or a
///   three-digit numeric of `SERVER_NUMERICS`; the numerics of
///   [`FORBIDDEN_NUMERICS`] have their own error. The companion profile's
///   `EGROUP`, `EKEY`, `EDIRECT` and `EOBJECT` are not in the base registry;
///   `agenc_relay_e2ee::wire` reads those lines.
/// - At most 15 parameters, a trailing one included.
/// - `FAIL`, `WARN` and `NOTE` have the Section 9.5 frame `<command|*>
///   <code> [context ...] :<description>`, a code in `[A-Z0-9_]{1,64}` and in
///   the base registry, never one of [`ADMIN_ONLY_REPLY_CODES`], and
///   `SLOW_CONSUMER` only as `WARN *`. Which code may follow which command,
///   and the context values, are the reader's (Section 9.5).
/// - Client-only tags appear only on the commands that relay them,
///   `PRIVMSG`, `NOTICE` and `TAGMSG` (Section 9.2).
///
/// Numeric parameter shapes are Modern IRC's (Appendix A.2) and are left to
/// the reader.
pub fn parse_server_message(
    line: ServerFramedLine<'_>,
) -> Result<ServerMessage<'_>, ServerMessageError> {
    let (tags, rest) = split_tags(line.as_str())?;
    let (prefix, rest) = split_prefix(rest)?;
    let (token, after_command) = match rest.split_once(' ') {
        Some((token, tail)) => (token, Some(tail)),
        None => (rest, None),
    };
    let command = classify_command(token)?;
    let params = parse_params(after_command)?;
    if let ServerCommand::Named(kind @ ("FAIL" | "WARN" | "NOTE")) = command {
        check_standard_reply(kind, &params)?;
    }
    if tags.client_only_count() > 0 && !command.name().is_some_and(relays_client_only_tags) {
        return Err(ServerMessageError::MisplacedClientOnlyTag);
    }
    Ok(ServerMessage {
        tags,
        prefix,
        command,
        params,
    })
}

fn split_tags(line: &str) -> Result<(ServerTags<'_>, &str), ServerMessageError> {
    let Some(tagged) = line.strip_prefix('@') else {
        return Ok((ServerTags::empty(), line));
    };
    let (raw, rest) = tagged
        .split_once(' ')
        .ok_or(ServerMessageError::UnterminatedTags)?;
    Ok((parse_server_tags(raw)?, rest))
}

fn split_prefix(rest: &str) -> Result<(Option<ServerPrefix<'_>>, &str), ServerMessageError> {
    let Some(source) = rest.strip_prefix(':') else {
        return Ok((None, rest));
    };
    let (raw, rest) = source
        .split_once(' ')
        .ok_or(ServerMessageError::MissingCommand)?;
    Ok((Some(parse_prefix(raw)?), rest))
}

fn parse_prefix(raw: &str) -> Result<ServerPrefix<'_>, ServerMessageError> {
    if !raw.contains(['!', '@']) {
        validate_server_name(raw).map_err(|_| ServerMessageError::InvalidPrefix)?;
        return Ok(ServerPrefix::Server(raw));
    }
    let (nickname, rest) = raw
        .split_once('!')
        .ok_or(ServerMessageError::InvalidPrefix)?;
    let (user, host) = rest
        .split_once('@')
        .ok_or(ServerMessageError::InvalidPrefix)?;
    validate_nickname(nickname).map_err(|_| ServerMessageError::InvalidPrefix)?;
    let cloak = framed_cloak(user, host).ok_or(ServerMessageError::InvalidPrefix)?;
    Ok(ServerPrefix::User(ServerUserPrefix {
        mask: raw,
        nickname,
        user,
        host,
        cloak,
    }))
}

/// The cloak a visible user and host field frame (Architecture 7.4).
fn framed_cloak(user: &str, host: &str) -> Option<PublicCloak> {
    let user = user.strip_prefix(CLOAK_USER_FRAME)?;
    let host = host
        .strip_prefix(CLOAK_HOST_FRAME)?
        .strip_suffix(CLOAK_HOST_SUFFIX)?;
    PublicCloak::parse(user, host).ok()
}

fn classify_command(token: &str) -> Result<ServerCommand, ServerMessageError> {
    if token.is_empty() {
        return Err(ServerMessageError::MissingCommand);
    }
    if token.len() == 3 && token.bytes().all(|byte| byte.is_ascii_digit()) {
        return classify_numeric(token);
    }
    if !token.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(ServerMessageError::InvalidCommand);
    }
    SERVER_COMMANDS
        .iter()
        .copied()
        .find(|name| *name == token)
        .map(ServerCommand::Named)
        .ok_or(ServerMessageError::UnregisteredCommand)
}

fn classify_numeric(token: &str) -> Result<ServerCommand, ServerMessageError> {
    let code = token
        .bytes()
        .fold(0_u16, |value, digit| value * 10 + u16::from(digit - b'0'));
    if FORBIDDEN_NUMERICS.contains(&code) {
        return Err(ServerMessageError::ForbiddenNumeric);
    }
    if SERVER_NUMERICS.contains(&code) {
        Ok(ServerCommand::Numeric(code))
    } else {
        Err(ServerMessageError::UnregisteredNumeric)
    }
}

/// Splits the text after the command into parameters; `None` when the
/// command ended the line.
fn parse_params(after_command: Option<&str>) -> Result<ServerParams<'_>, ServerMessageError> {
    let mut params = ServerParams::new();
    let Some(mut rest) = after_command else {
        return Ok(params);
    };
    loop {
        if let Some(trailing) = rest.strip_prefix(':') {
            params.push(trailing, true)?;
            return Ok(params);
        }
        let (middle, tail) = match rest.split_once(' ') {
            Some((middle, tail)) => (middle, Some(tail)),
            None => (rest, None),
        };
        if middle.is_empty() {
            return Err(ServerMessageError::EmptyParameter);
        }
        params.push(middle, false)?;
        let Some(tail) = tail else {
            return Ok(params);
        };
        rest = tail;
    }
}

/// Checks the Section 9.5 frame and the code of one standard reply.
fn check_standard_reply(kind: &str, params: &ServerParams<'_>) -> Result<(), ServerMessageError> {
    let (Some(command), Some(code)) = (params.middle().first(), params.middle().get(1)) else {
        return Err(ServerMessageError::MalformedStandardReply);
    };
    if params.trailing().is_none() {
        return Err(ServerMessageError::MalformedStandardReply);
    }
    if !is_reply_code(code) {
        return Err(ServerMessageError::InvalidReplyCode);
    }
    if !STANDARD_REPLY_CODES.contains(code) {
        return Err(ServerMessageError::UnregisteredReplyCode);
    }
    if !is_client_reply_code(kind, command, code) {
        return Err(ServerMessageError::InapplicableReplyCode);
    }
    Ok(())
}

/// The Section 9.5 code grammar, `[A-Z0-9_]{1,64}`; a middle parameter is
/// never empty.
fn is_reply_code(code: &str) -> bool {
    code.len() <= MAX_REPLY_CODE_BYTES
        && code
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

/// Whether a registered code is legal on a client connection: never an
/// administrative code, and `SLOW_CONSUMER` only as `WARN *`.
fn is_client_reply_code(kind: &str, command: &str, code: &str) -> bool {
    let queue_warning = kind == "WARN" && command == "*";
    !ADMIN_ONLY_REPLY_CODES.contains(&code) && (code != QUEUE_WARNING_CODE || queue_warning)
}

#[cfg(test)]
mod tests {
    use super::ServerMessageError;
    use crate::ServerTagError;
    use std::error::Error as _;

    #[test]
    fn every_discriminant_renders_a_distinct_message() {
        let variants = [
            ServerMessageError::UnterminatedTags,
            ServerMessageError::Tags(ServerTagError::EmptyTag),
            ServerMessageError::InvalidPrefix,
            ServerMessageError::MissingCommand,
            ServerMessageError::InvalidCommand,
            ServerMessageError::UnregisteredCommand,
            ServerMessageError::UnregisteredNumeric,
            ServerMessageError::ForbiddenNumeric,
            ServerMessageError::TooManyParameters,
            ServerMessageError::EmptyParameter,
            ServerMessageError::MalformedStandardReply,
            ServerMessageError::InvalidReplyCode,
            ServerMessageError::UnregisteredReplyCode,
            ServerMessageError::InapplicableReplyCode,
            ServerMessageError::MisplacedClientOnlyTag,
        ];
        let rendered: Vec<String> = variants.iter().map(ToString::to_string).collect();
        assert!(rendered.iter().all(|text| !text.is_empty()));
        let mut unique = rendered.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), rendered.len(), "{rendered:?}");
        let sources = variants
            .iter()
            .filter(|variant| variant.source().is_some())
            .count();
        assert_eq!(sources, 1);
    }
}
