//! Capability-aware client rendering with allocation gated by an exact output reservation.

use std::error::Error;
use std::fmt;
use std::fmt::Write as _;

use agenc_ircd_types::{
    AccountDeletionToken, AccountId, CLIENT_COMMANDS, ChannelName, NetworkId, Nickname,
    PublicErrorCode, RecoveryEpoch, SERVER_COMMANDS, SERVER_NUMERICS, SafeContext,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::{
    CapabilityState, MAX_CLIENT_ONLY_TAGS, MAX_CLIENT_ONLY_TOTAL_BYTES,
    MAX_CLIENT_ONLY_VALUE_BYTES, MAX_CLIENT_TAG_DATA_BYTES, MAX_COMBINED_TAG_SECTION_BYTES,
    MAX_COMMAND_BYTES, MAX_CORRELATION_TAG_BYTES, MAX_PARAMETERS, MAX_PHYSICAL_LINE_BYTES,
    MAX_SERVER_TAG_DATA_BYTES, relays_client_only_tags,
};

const E2EE_TAG: &str = "+agenc.ag/e2ee";
/// The companion-profile server commands `extension_line` admits.
const EXTENSION_COMMANDS: [&str; 7] = [
    "EGROUP", "EKEY", "EDIRECT", "EOBJECT", "BATCH", "TAGMSG", "FAIL",
];
const LABEL_TAG: &str = "label";
const BATCH_TAG: &str = "batch";
const STANDARD_REPLIES_CAPABILITY: &str = "standard-replies";
const MESSAGE_TAGS_CAPABILITY: &str = "message-tags";
const MAX_STANDARD_REPLY_DESCRIPTION_BYTES: usize = 256;

/// Maximum semantic messages in one logical response, excluding wrappers.
pub const MAX_SEMANTIC_REPLIES: usize = 512;
/// Maximum local nesting of response batches.
pub const MAX_BATCH_NESTING: usize = 16;

/// Authority that reserves the exact bytes requested by the renderer.
///
/// Production implementations adapt the runtime memory-budget port and return
/// its private, non-cloneable memory permit. Test implementations may return a
/// deterministic stand-in, but callers cannot pass a self-declared byte count
/// directly to [`MeasuredMessage::encode`].
pub trait OutputBudget {
    /// Reservation token kept alive by the encoded frame.
    type Permit;

    /// Reserves exactly `bytes` logical frame bytes before any frame buffer is
    /// allocated.
    fn try_reserve_exact(&mut self, bytes: usize) -> Result<Self::Permit, RenderError>;
}

/// Closed renderer failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenderError {
    /// A server prefix, command, parameter, or tag shape was invalid.
    InvalidSyntax,
    /// A command, numeric, or standard-reply code was outside its registry.
    UnknownRegistryValue,
    /// Rendering requires a capability that was not negotiated.
    CapabilityRequired,
    /// A closed reply code is reserved for a different authority or context.
    InapplicableReply,
    /// A line or one side of its tag section exceeded its exact budget.
    LineBudget,
    /// The output budget rejected the exact measured reservation.
    ReservationFailed,
    /// A checked size calculation overflowed.
    Overflow,
    /// A bounded output allocation failed after the permit was supplied.
    AllocationFailed,
    /// More than 512 semantic replies were supplied.
    TooManyReplies,
    /// Batch nesting, ID uniqueness, or close order was invalid.
    InvalidBatch,
    /// A label or batch ID exceeded 64 bytes or contained a delimiter.
    InvalidCorrelation,
}

impl fmt::Display for RenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidSyntax => "client reply syntax is invalid",
            Self::UnknownRegistryValue => "client reply registry value is unknown",
            Self::CapabilityRequired => "required client rendering capability is not enabled",
            Self::InapplicableReply => "standard reply code is not applicable here",
            Self::LineBudget => "client reply exceeds an exact line or tag budget",
            Self::ReservationFailed => "exact output reservation failed",
            Self::Overflow => "client reply size calculation overflowed",
            Self::AllocationFailed => "client reply output allocation failed",
            Self::TooManyReplies => "logical response has more than 512 semantic replies",
            Self::InvalidBatch => "response batch nesting or ordering is invalid",
            Self::InvalidCorrelation => "label or batch ID is invalid",
        };
        formatter.write_str(message)
    }
}

impl Error for RenderError {}

#[derive(Eq, Hash, PartialEq)]
struct RenderTag {
    key: String,
    value: Option<String>,
}

struct ExactOutput {
    bytes: Vec<u8>,
    limit: usize,
}

impl ExactOutput {
    fn new(limit: usize) -> Result<Self, RenderError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(limit)
            .map_err(|_| RenderError::AllocationFailed)?;
        Ok(Self { bytes, limit })
    }

    fn push(&mut self, byte: u8) -> Result<(), RenderError> {
        self.ensure_additional(1)?;
        self.bytes.push(byte);
        Ok(())
    }

    fn extend(&mut self, value: &[u8]) -> Result<(), RenderError> {
        self.ensure_additional(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn ensure_additional(&self, additional: usize) -> Result<(), RenderError> {
        let next = self
            .bytes
            .len()
            .checked_add(additional)
            .ok_or(RenderError::Overflow)?;
        if next > self.limit {
            return Err(RenderError::LineBudget);
        }
        Ok(())
    }

    fn finish(self) -> Result<Vec<u8>, RenderError> {
        if self.bytes.len() != self.limit {
            return Err(RenderError::LineBudget);
        }
        Ok(self.bytes)
    }
}

/// One validated server-to-client message plan.
#[derive(Eq, Hash, PartialEq)]
pub struct WireMessage {
    prefix: String,
    command: String,
    middle: Vec<String>,
    trailing: Option<String>,
    server_tags: Vec<RenderTag>,
    client_tags: Vec<RenderTag>,
}

impl fmt::Debug for WireMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WireMessage")
            .field("command", &self.command)
            .field("middle_count", &self.middle.len())
            .field("trailing_present", &self.trailing.is_some())
            .field("server_tag_count", &self.server_tags.len())
            .field("client_tag_count", &self.client_tags.len())
            .finish()
    }
}

impl WireMessage {
    /// Creates a registry-bounded server message plan.
    ///
    /// Numeric frames are owned by [`numeric_reply`]. `BATCH` frames are
    /// deliberately excluded because their open/close and tag liveness
    /// invariants are owned by [`BatchStack`].
    pub fn new(
        prefix: &str,
        command: &str,
        middle: &[&str],
        trailing: Option<&str>,
    ) -> Result<Self, RenderError> {
        if command == "BATCH" {
            return Err(RenderError::InvalidBatch);
        }
        validate_command(command)?;
        if command.len() == 3 && command.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(RenderError::InapplicableReply);
        }
        Self::new_registered(prefix, command, middle, trailing)
    }

    fn new_registered(
        prefix: &str,
        command: &str,
        middle: &[&str],
        trailing: Option<&str>,
    ) -> Result<Self, RenderError> {
        validate_parameter_count(middle, trailing)?;
        if command_bytes(prefix, command, middle, trailing)? > MAX_COMMAND_BYTES {
            return Err(RenderError::LineBudget);
        }
        validate_prefix(prefix)?;
        validate_command(command)?;
        validate_parameters(middle, trailing)?;
        let prefix = copy_string(prefix)?;
        let command = copy_string(command)?;
        let middle = copy_strings(middle)?;
        let trailing = trailing.map(copy_string).transpose()?;
        Ok(Self {
            prefix,
            command,
            middle,
            trailing,
            server_tags: Vec::new(),
            client_tags: Vec::new(),
        })
    }

    fn from_owned(
        prefix: &str,
        command: &str,
        middle: Vec<String>,
        trailing: Option<String>,
    ) -> Result<Self, RenderError> {
        validate_owned_parameters(&middle, trailing.as_deref())?;
        if owned_command_bytes(prefix, command, &middle, trailing.as_deref())? > MAX_COMMAND_BYTES {
            return Err(RenderError::LineBudget);
        }
        validate_prefix(prefix)?;
        validate_command(command)?;
        Ok(Self {
            prefix: copy_string(prefix)?,
            command: copy_string(command)?,
            middle,
            trailing,
            server_tags: Vec::new(),
            client_tags: Vec::new(),
        })
    }

    /// Borrows the command or numeric.
    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
    }

    /// Borrows the middle parameters in order.
    #[must_use]
    pub fn middle(&self) -> &[String] {
        &self.middle
    }

    /// Borrows the trailing parameter.
    #[must_use]
    pub fn trailing(&self) -> Option<&str> {
        self.trailing.as_deref()
    }

    /// Builds one companion-profile line the IRC-MLS renderers produced:
    /// `EGROUP`, `EKEY`, `EDIRECT`, `EOBJECT`, and their `BATCH`, `TAGMSG`,
    /// and `FAIL` forms (E2EE 11.7). The companion registries live outside
    /// the frozen server command table, so the closed set here is the only
    /// bypass of that table; every budget of this crate still applies.
    // agenc-review: focus owner=client-wire reviewed=2026-09-03 reason=the parser walks tags prefix command middles and trailing in wire order; each branch is one grammar production
    pub fn extension_line(line: &str) -> Result<Self, RenderError> {
        let line = line.trim_end_matches("\r\n");
        let (tags, rest) = match line.strip_prefix('@') {
            Some(tagged) => {
                let (tags, rest) = tagged.split_once(' ').ok_or(RenderError::InvalidSyntax)?;
                (Some(tags), rest)
            }
            None => (None, line),
        };
        let rest = rest.strip_prefix(':').ok_or(RenderError::InvalidSyntax)?;
        let (prefix, rest) = rest.split_once(' ').ok_or(RenderError::InvalidSyntax)?;
        let (body, trailing) = match rest.split_once(" :") {
            Some((body, trailing)) => (body, Some(trailing)),
            None => (rest, None),
        };
        let mut words = body.split(' ');
        let command = words.next().ok_or(RenderError::InvalidSyntax)?;
        if !EXTENSION_COMMANDS.contains(&command) {
            return Err(RenderError::UnknownRegistryValue);
        }
        let middle: Vec<&str> = words.collect();
        if middle.iter().any(|word| word.is_empty()) {
            return Err(RenderError::InvalidSyntax);
        }
        validate_parameter_count(&middle, trailing)?;
        if command_bytes(prefix, command, &middle, trailing)? > MAX_COMMAND_BYTES {
            return Err(RenderError::LineBudget);
        }
        validate_prefix(prefix)?;
        validate_parameters(&middle, trailing)?;
        let mut message = Self {
            prefix: copy_string(prefix)?,
            command: copy_string(command)?,
            middle: copy_strings(&middle)?,
            trailing: trailing.map(copy_string).transpose()?,
            server_tags: Vec::new(),
            client_tags: Vec::new(),
        };
        for tag in tags.into_iter().flat_map(|tags| tags.split(';')) {
            let (key, value) = match tag.split_once('=') {
                Some((key, value)) => (key, Some(value)),
                None => (tag, None),
            };
            if key.is_empty() {
                return Err(RenderError::InvalidSyntax);
            }
            if key.starts_with('+') {
                insert_tag(
                    &mut message.client_tags,
                    key,
                    value,
                    MAX_CLIENT_TAG_DATA_BYTES,
                )?;
            } else {
                insert_tag(
                    &mut message.server_tags,
                    key,
                    value,
                    MAX_SERVER_TAG_DATA_BYTES,
                )?;
            }
        }
        if tag_data_bytes(&message.server_tags)?
            .saturating_add(tag_data_bytes(&message.client_tags)?)
            > MAX_COMBINED_TAG_SECTION_BYTES
        {
            return Err(RenderError::LineBudget);
        }
        Ok(message)
    }

    /// Adds one ordinary server-originated tag.
    ///
    /// Correlation tags are excluded: `label` is owned by
    /// [`labeled_response`], while `batch` requires a live [`BatchStack`].
    pub fn add_server_tag(&mut self, key: &str, value: Option<&str>) -> Result<(), RenderError> {
        if key.starts_with('+') || matches!(key, LABEL_TAG | BATCH_TAG) {
            return Err(RenderError::InvalidSyntax);
        }
        insert_tag(&mut self.server_tags, key, value, MAX_SERVER_TAG_DATA_BYTES)
    }

    /// Adds one validated client-only tag after all server-originated tags.
    pub fn add_client_only_tag(
        &mut self,
        capabilities: &CapabilityState,
        key: &str,
        value: Option<&str>,
    ) -> Result<(), RenderError> {
        if !capabilities.enabled(MESSAGE_TAGS_CAPABILITY) {
            return Err(RenderError::CapabilityRequired);
        }
        if !key.starts_with('+') || !relays_client_only_tags(&self.command) {
            return Err(RenderError::InvalidSyntax);
        }
        validate_client_tag_budget(&self.client_tags, key, value)?;
        insert_tag(&mut self.client_tags, key, value, MAX_CLIENT_TAG_DATA_BYTES)
    }

    fn add_correlation_tag(&mut self, key: &'static str, value: &str) -> Result<(), RenderError> {
        if !matches!(key, LABEL_TAG | BATCH_TAG) {
            return Err(RenderError::InvalidCorrelation);
        }
        validate_correlation(value)?;
        insert_tag(
            &mut self.server_tags,
            key,
            Some(value),
            MAX_SERVER_TAG_DATA_BYTES,
        )
    }

    /// Performs heap-free checked measurement of the complete CRLF frame.
    pub fn measure(&self) -> Result<MeasuredMessage<'_>, RenderError> {
        let server_bytes = tag_data_bytes(&self.server_tags)?;
        let client_bytes = tag_data_bytes(&self.client_tags)?;
        if server_bytes > MAX_SERVER_TAG_DATA_BYTES || client_bytes > MAX_CLIENT_TAG_DATA_BYTES {
            return Err(RenderError::LineBudget);
        }
        let command_bytes = self.command_bytes()?;
        if command_bytes > MAX_COMMAND_BYTES {
            return Err(RenderError::LineBudget);
        }
        let tag_section = combined_tag_section(server_bytes, client_bytes)?;
        if tag_section > MAX_COMBINED_TAG_SECTION_BYTES {
            return Err(RenderError::LineBudget);
        }
        let bytes = tag_section
            .checked_add(command_bytes)
            .and_then(|value| value.checked_add(2))
            .ok_or(RenderError::Overflow)?;
        if bytes > MAX_PHYSICAL_LINE_BYTES {
            return Err(RenderError::LineBudget);
        }
        Ok(MeasuredMessage {
            message: self,
            bytes,
        })
    }

    fn command_bytes(&self) -> Result<usize, RenderError> {
        let mut bytes = 1usize
            .checked_add(self.prefix.len())
            .and_then(|value| value.checked_add(1))
            .and_then(|value| value.checked_add(self.command.len()))
            .ok_or(RenderError::Overflow)?;
        for parameter in &self.middle {
            bytes = bytes
                .checked_add(1)
                .and_then(|value| value.checked_add(parameter.len()))
                .ok_or(RenderError::Overflow)?;
        }
        if let Some(trailing) = &self.trailing {
            bytes = bytes
                .checked_add(2)
                .and_then(|value| value.checked_add(trailing.len()))
                .ok_or(RenderError::Overflow)?;
        }
        Ok(bytes)
    }

    fn encode_into(&self, output: &mut ExactOutput) -> Result<(), RenderError> {
        if !self.server_tags.is_empty() || !self.client_tags.is_empty() {
            output.push(b'@')?;
            encode_tag_list(&self.server_tags, output, false)?;
            encode_tag_list(&self.client_tags, output, !self.server_tags.is_empty())?;
            output.push(b' ')?;
        }
        output.push(b':')?;
        output.extend(self.prefix.as_bytes())?;
        output.push(b' ')?;
        output.extend(self.command.as_bytes())?;
        for parameter in &self.middle {
            output.push(b' ')?;
            output.extend(parameter.as_bytes())?;
        }
        if let Some(trailing) = &self.trailing {
            output.extend(b" :")?;
            output.extend(trailing.as_bytes())?;
        }
        output.extend(b"\r\n")
    }
}

/// A checked, heap-free measurement tied to one immutable message plan.
pub struct MeasuredMessage<'a> {
    message: &'a WireMessage,
    bytes: usize,
}

impl MeasuredMessage<'_> {
    /// Returns the exact encoded byte count including CRLF.
    #[must_use]
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    /// Reserves the exact measured bytes, then allocates and encodes.
    pub fn encode<B: OutputBudget>(
        self,
        budget: &mut B,
    ) -> Result<RenderedMessage<B::Permit>, RenderError> {
        let permit = budget.try_reserve_exact(self.bytes)?;
        let mut output = ExactOutput::new(self.bytes)?;
        self.message.encode_into(&mut output)?;
        let bytes = output.finish()?;
        Ok(RenderedMessage { bytes, permit })
    }
}

/// An encoded frame that owns the memory permit for its full lifetime.
///
/// Field order is intentional: Rust drops the byte allocation before it drops
/// the permit that accounts for that allocation.
pub struct RenderedMessage<P> {
    bytes: Vec<u8>,
    permit: P,
}

impl<P> RenderedMessage<P> {
    /// Borrows exact wire bytes including CRLF.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrows the opaque permit for accounting assertions and queue adapters.
    #[must_use]
    pub const fn permit(&self) -> &P {
        &self.permit
    }
}

/// Standard reply command selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplyKind {
    /// FAIL.
    Fail,
    /// WARN.
    Warn,
    /// NOTE.
    Note,
}

impl ReplyKind {
    const fn command(self) -> &'static str {
        match self {
            Self::Fail => "FAIL",
            Self::Warn => "WARN",
            Self::Note => "NOTE",
        }
    }
}

/// Static, validated human text that is safe to expose in a standard reply.
///
/// Requiring a static value prevents request-owned text and internal error
/// strings from being passed through this API accidentally. The constructor is
/// still the trust boundary: descriptions must describe a fixed public result,
/// not a leaked secret promoted to static storage.
///
/// ```compile_fail
/// use agenc_ircd_client_wire::SafeReplyDescription;
///
/// let request_text = String::from("peer controlled");
/// let _ = SafeReplyDescription::new(&request_text);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SafeReplyDescription(&'static str);

impl SafeReplyDescription {
    /// Validates one nonempty, bounded, control-free static description.
    pub fn new(description: &'static str) -> Result<Self, RenderError> {
        if description.is_empty()
            || description.len() > MAX_STANDARD_REPLY_DESCRIPTION_BYTES
            || description.chars().any(char::is_control)
        {
            return Err(RenderError::InvalidSyntax);
        }
        Ok(Self(description))
    }

    /// Borrows the fixed public text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// One provenance-carrying public standard-reply context value.
#[derive(Clone, Copy)]
pub enum SafeReplyContext<'a> {
    /// A validated public channel name.
    Channel(&'a ChannelName),
    /// A validated public nickname.
    Nickname(&'a Nickname),
    /// A public account authority identifier.
    AccountId(AccountId),
    /// The public recovery identity advertised by this listener.
    RecoveryEpoch(RecoveryEpoch),
    /// The one-use token returned only by `ACCT DELETE START`.
    DeletionChallenge(&'a AccountDeletionToken),
    /// A server-owned bounded numeric value. `None` is represented by omitting
    /// the context entry and is rejected if placed in this variant.
    Bounded(SafeContext),
}

impl fmt::Debug for SafeReplyContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Channel(_) => "Channel",
            Self::Nickname(_) => "Nickname",
            Self::AccountId(_) => "AccountId",
            Self::RecoveryEpoch(_) => "RecoveryEpoch",
            Self::DeletionChallenge(_) => "DeletionChallenge",
            Self::Bounded(_) => "Bounded",
        };
        formatter.debug_tuple(variant).field(&"[public]").finish()
    }
}

/// Builds one public-listener standard reply with a frozen, applicable shape.
///
/// Administrative codes and the queue-owner-only `SLOW_CONSUMER` warning are
/// rejected even though they are present in the shared closed registry. Codes
/// whose public command or context shape belongs to a later stage also fail
/// closed until that owning stage adds its explicit mapping.
pub fn standard_reply(
    capabilities: &CapabilityState,
    prefix: &str,
    kind: ReplyKind,
    operation: &str,
    code: PublicErrorCode,
    context: &[SafeReplyContext<'_>],
    description: SafeReplyDescription,
) -> Result<WireMessage, RenderError> {
    if operation != "*"
        && !CLIENT_COMMANDS.contains(&operation)
        && !SERVER_COMMANDS.contains(&operation)
    {
        return Err(RenderError::UnknownRegistryValue);
    }
    if is_restricted_standard_reply(code)
        || (operation != "*" && !CLIENT_COMMANDS.contains(&operation))
    {
        return Err(RenderError::InapplicableReply);
    }
    if !capabilities.enabled(STANDARD_REPLIES_CAPABILITY) {
        return Err(RenderError::CapabilityRequired);
    }
    if !standard_reply_is_applicable(kind, operation, code, context) {
        return Err(RenderError::InapplicableReply);
    }
    standard_reply_unrestricted(prefix, kind, operation, code, context, description)
}

fn standard_reply_is_applicable(
    kind: ReplyKind,
    operation: &str,
    code: PublicErrorCode,
    context: &[SafeReplyContext<'_>],
) -> bool {
    match (kind, operation, code, context) {
        (ReplyKind::Fail, "*", PublicErrorCode::REGISTRATIONREQUIRED, []) => true,
        (ReplyKind::Fail, _, _, _) => failed_standard_reply_is_applicable(operation, code, context),
        (ReplyKind::Note, _, _, _) => note_standard_reply_is_applicable(operation, code, context),
        (ReplyKind::Warn, _, _, _) => false,
    }
}

fn failed_standard_reply_is_applicable(
    operation: &str,
    code: PublicErrorCode,
    context: &[SafeReplyContext<'_>],
) -> bool {
    if !CLIENT_COMMANDS.contains(&operation) {
        return false;
    }
    if operation == "NOTICE" {
        return matches!((code, context), (PublicErrorCode::INVALIDARGUMENT, []));
    }
    matches!(
        (operation, code, context),
        (
            "ACCT" | "ACCTCREATE" | "ACCTCRED" | "AUTHENTICATE",
            PublicErrorCode::BADSTATE,
            [],
        ) | (
            "JOIN",
            PublicErrorCode::E2EEREQUIRED,
            [] | [SafeReplyContext::Channel(_)],
        ) | (
            "PRIVMSG",
            PublicErrorCode::E2EEREQUIRED,
            [SafeReplyContext::Channel(_)],
        ) | (_, PublicErrorCode::INVALIDARGUMENT, [])
            | (_, PublicErrorCode::NETWORKUNAVAILABLE, [])
            | (
                "JOIN",
                PublicErrorCode::NETWORKUNAVAILABLE,
                [SafeReplyContext::Channel(_)],
            )
            | (
                "CHATHISTORY" | "JOIN" | "LIST" | "MONITOR" | "NAMES" | "WHO" | "WHOIS" | "WHOWAS",
                PublicErrorCode::QUERYEXPIRED,
                [],
            )
            | (
                "JOIN" | "MODE" | "NAMES" | "TOPIC",
                PublicErrorCode::SECRETUNAVAILABLE,
                [SafeReplyContext::Channel(_)],
            )
            | (_, PublicErrorCode::SERVERBUSY, [])
            | (
                "ACCTCREATE" | "ACCTCRED" | "AUTHENTICATE",
                PublicErrorCode::UNAVAILABLE,
                [],
            )
            | ("PRIVMSG", PublicErrorCode::UNSAFECTCP, [])
    )
}

fn note_standard_reply_is_applicable(
    operation: &str,
    code: PublicErrorCode,
    context: &[SafeReplyContext<'_>],
) -> bool {
    matches!(
        (operation, code, context),
        ("ACCTCRED", PublicErrorCode::CHANGED, [])
            | (
                "ACCTCREATE",
                PublicErrorCode::CREATED,
                [SafeReplyContext::AccountId(_)],
            )
            | (
                "*",
                PublicErrorCode::RECOVERYEPOCH,
                [SafeReplyContext::RecoveryEpoch(_)],
            )
            | ("ACCT", PublicErrorCode::UPDATED, [])
            | (
                "ACCT",
                PublicErrorCode::DELETECHALLENGE,
                [SafeReplyContext::DeletionChallenge(_)],
            )
            | (
                "CHANCTL",
                PublicErrorCode::UPDATED,
                [SafeReplyContext::Channel(_)],
            )
    )
}

fn standard_reply_unrestricted(
    prefix: &str,
    kind: ReplyKind,
    operation: &str,
    code: PublicErrorCode,
    context: &[SafeReplyContext<'_>],
    description: SafeReplyDescription,
) -> Result<WireMessage, RenderError> {
    let parameter_count = context.len().checked_add(2).ok_or(RenderError::Overflow)?;
    if parameter_count >= MAX_PARAMETERS {
        return Err(RenderError::InvalidSyntax);
    }
    let mut middle = Vec::new();
    middle
        .try_reserve_exact(parameter_count)
        .map_err(|_| RenderError::AllocationFailed)?;
    middle.push(copy_string(operation)?);
    middle.push(copy_string(code.as_str())?);
    for value in context {
        middle.push(reply_context_text(*value)?);
    }
    WireMessage::from_owned(
        prefix,
        kind.command(),
        middle,
        Some(copy_string(description.as_str())?),
    )
}

/// Builds the one queue-owner-only warning shape when standard replies are
/// negotiated.
pub fn slow_consumer_warning(
    capabilities: &CapabilityState,
    prefix: &str,
) -> Result<Option<WireMessage>, RenderError> {
    if !capabilities.enabled(STANDARD_REPLIES_CAPABILITY) {
        return Ok(None);
    }
    let description = SafeReplyDescription::new("Output queue nearing capacity")?;
    standard_reply_unrestricted(
        prefix,
        ReplyKind::Warn,
        "*",
        PublicErrorCode::SLOWCONSUMER,
        &[],
        description,
    )
    .map(Some)
}

const fn is_restricted_standard_reply(code: PublicErrorCode) -> bool {
    matches!(
        code,
        PublicErrorCode::CHALLENGE
            | PublicErrorCode::CHECKPOINT
            | PublicErrorCode::CONFIRM
            | PublicErrorCode::EVENT
            | PublicErrorCode::VALUE
            | PublicErrorCode::SLOWCONSUMER
    )
}

fn reply_context_text(context: SafeReplyContext<'_>) -> Result<String, RenderError> {
    match context {
        SafeReplyContext::Channel(channel) => copy_string(channel.presentation()),
        SafeReplyContext::Nickname(nickname) => copy_string(nickname.presentation()),
        SafeReplyContext::AccountId(account_id) => {
            encode_public_identifier("a_", account_id.random().as_bytes())
        }
        SafeReplyContext::RecoveryEpoch(epoch) => encode_public_identifier("", epoch.as_bytes()),
        SafeReplyContext::DeletionChallenge(token) => {
            encode_public_identifier("", token.expose_for_deletion())
        }
        SafeReplyContext::Bounded(SafeContext::TargetIndex(value)) => {
            decimal_text(u64::from(value))
        }
        SafeReplyContext::Bounded(SafeContext::RetryAfterSeconds(value)) => {
            decimal_text(u64::from(value))
        }
        SafeReplyContext::Bounded(SafeContext::Maximum(value)) => decimal_text(value),
        SafeReplyContext::Bounded(SafeContext::None) => Err(RenderError::InvalidSyntax),
    }
}

fn encode_public_identifier(prefix: &str, bytes: &[u8]) -> Result<String, RenderError> {
    let mut encoded = [0_u8; 43];
    let written = URL_SAFE_NO_PAD
        .encode_slice(bytes, &mut encoded)
        .map_err(|_| RenderError::Overflow)?;
    let encoded = encoded.get(..written).ok_or(RenderError::Overflow)?;
    let encoded = std::str::from_utf8(encoded).map_err(|_| RenderError::InvalidSyntax)?;
    prefixed_value(prefix, encoded)
}

fn decimal_text(value: u64) -> Result<String, RenderError> {
    let mut output = String::new();
    output
        .try_reserve_exact(20)
        .map_err(|_| RenderError::AllocationFailed)?;
    write!(&mut output, "{value}").map_err(|_| RenderError::InvalidSyntax)?;
    Ok(output)
}

/// Builds one three-digit numeric whose shape is owned by Stage 02.
///
/// Registry membership alone is insufficient. Numerics owned by later stages
/// fail closed until their exact parameter shapes are added here.
pub fn numeric_reply(
    prefix: &str,
    code: u16,
    target: &str,
    middle: &[&str],
    trailing: Option<&str>,
) -> Result<WireMessage, RenderError> {
    if !SERVER_NUMERICS.contains(&code) {
        return Err(RenderError::UnknownRegistryValue);
    }
    if !stage_two_numeric_shape_is_applicable(code, middle, trailing) {
        return Err(RenderError::InapplicableReply);
    }
    let command_bytes = [
        b'0' + u8::try_from(code / 100).map_err(|_| RenderError::Overflow)?,
        b'0' + u8::try_from((code / 10) % 10).map_err(|_| RenderError::Overflow)?,
        b'0' + u8::try_from(code % 10).map_err(|_| RenderError::Overflow)?,
    ];
    let command = std::str::from_utf8(&command_bytes).map_err(|_| RenderError::InvalidSyntax)?;
    let parameter_count = middle.len().checked_add(1).ok_or(RenderError::Overflow)?;
    if parameter_count > MAX_PARAMETERS.saturating_sub(usize::from(trailing.is_some())) {
        return Err(RenderError::InvalidSyntax);
    }
    let mut parameters = Vec::new();
    parameters
        .try_reserve_exact(parameter_count)
        .map_err(|_| RenderError::AllocationFailed)?;
    parameters.push(target);
    parameters.extend_from_slice(middle);
    WireMessage::new_registered(prefix, command, &parameters, trailing)
}

fn stage_two_numeric_shape_is_applicable(
    code: u16,
    middle: &[&str],
    trailing: Option<&str>,
) -> bool {
    if code == 4 {
        return middle.len() == 4 && trailing.is_none();
    }
    let trailing_is_applicable = match code {
        221 | 324 | 329 | 333 | 341 | 346 | 348 | 367 => trailing.is_none(),
        302 | 303 | 319 | 322 | 332 | 353 => trailing.is_some(),
        _ => trailing.is_some_and(|description| !description.is_empty()),
    };
    trailing_is_applicable && stage_two_numeric_middle_is_applicable(code, middle)
}

fn stage_two_numeric_middle_is_applicable(code: u16, middle: &[&str]) -> bool {
    match code {
        1..=3
        | 251
        | 255
        | 372
        | 375
        | 376
        | 417
        | 422
        | 431
        | 451
        | 462
        | 464
        | 465
        | 903..=907 => middle.is_empty(),
        5 => (1..=13).contains(&middle.len()) && middle.iter().copied().all(is_isupport_token),
        252..=254 => matches!(middle, [value] if is_ascii_decimal(value)),
        265..=266 => {
            matches!(middle, [local, global] if is_ascii_decimal(local) && is_ascii_decimal(global))
        }
        421 | 432 | 433 | 461 => middle.len() == 1,
        900 => middle.len() == 2,
        908 => middle == ["AGENC-OPAQUE"],
        _ => stage_six_numeric_middle_is_applicable(code, middle),
    }
}

fn stage_six_numeric_middle_is_applicable(code: u16, middle: &[&str]) -> bool {
    stage_six_reply_middle_is_applicable(code, middle)
        || stage_six_error_middle_is_applicable(code, middle)
}

fn stage_six_reply_middle_is_applicable(code: u16, middle: &[&str]) -> bool {
    match code {
        302 | 303 | 305 | 306 | 323 | 371 | 374 | 730..=733 => middle.is_empty(),
        221 => matches!(middle, [modes] if modes.starts_with('+')),
        301 | 315 | 318 | 319 | 321 | 331 | 332 | 347 | 349 | 366 | 368 | 369 | 391 => {
            middle.len() == 1
        }
        311 | 314 => middle.len() == 4,
        312 | 341 | 346 | 348 | 353 => middle.len() == 2,
        322 => matches!(middle, [_, users] if is_ascii_decimal(users)),
        324 => (2..=8).contains(&middle.len()),
        329 => matches!(middle, [_, timestamp] if is_ascii_decimal(timestamp)),
        333 => matches!(middle, [_, _, timestamp] if is_ascii_decimal(timestamp)),
        352 => middle.len() == 6,
        367 => {
            (2..=4).contains(&middle.len())
                && middle
                    .get(3)
                    .is_none_or(|timestamp| is_ascii_decimal(timestamp))
        }
        _ => false,
    }
}

fn stage_six_error_middle_is_applicable(code: u16, middle: &[&str]) -> bool {
    match code {
        263 => middle.len() == 1,
        734 => {
            matches!(middle, [limit, targets] if is_ascii_decimal(limit) && *limit != "0" && !targets.is_empty())
        }
        409 | 411 | 412 | 481 | 483 | 501 | 502 => middle.is_empty(),
        401..=407 | 442 | 471 | 473..=477 | 482 => middle.len() == 1,
        441 | 443 => middle.len() == 2,
        472 => matches!(middle, [mode] if mode.chars().count() == 1),
        _ => false,
    }
}

fn is_ascii_decimal(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_isupport_token(value: &str) -> bool {
    let (name, parameter) = value
        .split_once('=')
        .map_or((value, None), |(name, parameter)| (name, Some(parameter)));
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        && parameter.is_none_or(|parameter| {
            !parameter.is_empty() && parameter.bytes().all(|byte| byte.is_ascii_graphic())
        })
}

/// Builds the mandatory 005 token set in stable, budgeted groups.
pub fn isupport_messages(
    prefix: &str,
    target: &str,
    display_name: &str,
    network_id: &NetworkId,
) -> Result<Vec<WireMessage>, RenderError> {
    let maximum_display_name = MAX_COMMAND_BYTES
        .checked_sub("NETWORK=".len())
        .ok_or(RenderError::Overflow)?;
    if display_name.is_empty()
        || display_name.len() > maximum_display_name
        || !display_name.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(RenderError::InvalidSyntax);
    }
    let network_id = encode_public_identifier("", network_id.as_bytes())?;
    let network = prefixed_value("NETWORK=", display_name)?;
    let agencnet = prefixed_value("AGENCNET=", &network_id)?;
    let groups: [&[&str]; 3] = [
        &[
            "AWAYLEN=256",
            "CASEMAPPING=ascii",
            "CHANNELLEN=64",
            "CHANTYPES=#&",
            "CHANMODES=beI,,kl,imnpst",
            "EXCEPTS=e",
            "INVEX=I",
            "KICKLEN=256",
            "MAXLIST=b:100,e:100,I:100",
            "MODES=6",
        ],
        &[
            "MONITOR=100",
            "NICKLEN=32",
            "PREFIX=(qaohv)~&@%+",
            "SAFELIST",
            "STATUSMSG=@+",
            "TARGMAX=PRIVMSG:4,NOTICE:4,TAGMSG:1,JOIN:20,PART:20",
            "TOPICLEN=1024",
            "UTF8ONLY",
            "EXTBAN=$,auncq",
            "LISTBUCKETS=1,2,5,10,25,50,100",
        ],
        &[network.as_str(), agencnet.as_str()],
    ];
    let mut messages = Vec::new();
    messages
        .try_reserve_exact(groups.len())
        .map_err(|_| RenderError::AllocationFailed)?;
    for group in groups {
        messages.push(numeric_reply(
            prefix,
            5,
            target,
            group,
            Some("are supported by this server"),
        )?);
    }
    Ok(messages)
}

/// A complete logical response after optional label/batch correlation.
#[derive(Default, Eq, PartialEq)]
pub struct LogicalReply {
    messages: Vec<WireMessage>,
}

impl fmt::Debug for LogicalReply {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LogicalReply")
            .field("message_count", &self.messages.len())
            .finish()
    }
}

impl LogicalReply {
    /// Returns the final ordered output plans.
    #[must_use]
    pub fn messages(&self) -> &[WireMessage] {
        &self.messages
    }

    /// Consumes the logical response into ordered output plans.
    #[must_use]
    pub fn into_messages(self) -> Vec<WireMessage> {
        self.messages
    }
}

/// Applies a label exactly once, using a batch only for multi-message replies.
pub fn labeled_response(
    capabilities: &CapabilityState,
    prefix: &str,
    label: Option<&str>,
    batch_id: Option<&str>,
    mut semantic: Vec<WireMessage>,
) -> Result<LogicalReply, RenderError> {
    if semantic.len() > MAX_SEMANTIC_REPLIES {
        return Err(RenderError::TooManyReplies);
    }
    let Some(label) = label else {
        return Ok(LogicalReply { messages: semantic });
    };
    if !capabilities.enabled("labeled-response") {
        return Ok(LogicalReply { messages: semantic });
    }
    validate_correlation(label)?;
    if semantic.is_empty() {
        let mut acknowledgement = WireMessage::new(prefix, "ACK", &[], None)?;
        acknowledgement.add_correlation_tag(LABEL_TAG, label)?;
        return Ok(LogicalReply {
            messages: vec![acknowledgement],
        });
    }
    if semantic.len() == 1 {
        let Some(message) = semantic.first_mut() else {
            return Err(RenderError::TooManyReplies);
        };
        message.add_correlation_tag(LABEL_TAG, label)?;
        return Ok(LogicalReply { messages: semantic });
    }
    if !capabilities.enabled("batch") {
        return Err(RenderError::CapabilityRequired);
    }
    let batch_id = batch_id.ok_or(RenderError::InvalidCorrelation)?;
    let mut batches = BatchStack::default();
    let open = batches.open(capabilities, prefix, batch_id, label)?;
    for message in &mut semantic {
        batches.attach(batch_id, message)?;
    }
    let close = batches.close(prefix, batch_id)?;
    let mut messages = Vec::new();
    let message_count = semantic.len().checked_add(2).ok_or(RenderError::Overflow)?;
    messages
        .try_reserve_exact(message_count)
        .map_err(|_| RenderError::AllocationFailed)?;
    messages.push(open);
    messages.append(&mut semantic);
    messages.push(close);
    Ok(LogicalReply { messages })
}

/// Validates bounded nested BATCH open/close ordering.
///
/// The stack is intentionally move-only so one owner cannot clone live batch
/// IDs and produce a second valid-looking close frame.
///
/// ```compile_fail
/// use agenc_ircd_client_wire::BatchStack;
///
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<BatchStack>();
/// ```
#[derive(Debug, Default, Eq, PartialEq)]
pub struct BatchStack {
    ids: Vec<String>,
}

impl BatchStack {
    /// Opens a pinned plaintext history batch under the same correlation ownership.
    pub fn open_history(
        &mut self,
        capabilities: &CapabilityState,
        prefix: &str,
        id: &str,
        channel: &str,
    ) -> Result<WireMessage, RenderError> {
        if !capabilities.enabled("batch") || !capabilities.enabled("draft/chathistory") {
            return Err(RenderError::CapabilityRequired);
        }
        validate_batch_reference(id)?;
        if self.ids.len() >= MAX_BATCH_NESTING || self.ids.iter().any(|open| open == id) {
            return Err(RenderError::InvalidBatch);
        }
        let open_parameter = prefixed_value("+", id)?;
        let mut message = WireMessage::new_registered(
            prefix,
            "BATCH",
            &[&open_parameter, "chathistory", channel],
            None,
        )?;
        if let Some(parent) = self.ids.last() {
            message.add_correlation_tag(BATCH_TAG, parent)?;
        }
        let id = copy_string(id)?;
        self.ids
            .try_reserve(1)
            .map_err(|_| RenderError::AllocationFailed)?;
        self.ids.push(id);
        Ok(message)
    }

    /// Opens one unique labeled-response batch and returns its opening frame.
    pub fn open(
        &mut self,
        capabilities: &CapabilityState,
        prefix: &str,
        id: &str,
        label: &str,
    ) -> Result<WireMessage, RenderError> {
        if !capabilities.enabled("batch") || !capabilities.enabled("labeled-response") {
            return Err(RenderError::CapabilityRequired);
        }
        validate_batch_reference(id)?;
        validate_correlation(label)?;
        if self.ids.len() >= MAX_BATCH_NESTING || self.ids.iter().any(|open| open == id) {
            return Err(RenderError::InvalidBatch);
        }
        let open_parameter = prefixed_value("+", id)?;
        let mut message = WireMessage::new_registered(
            prefix,
            "BATCH",
            &[&open_parameter, "labeled-response"],
            None,
        )?;
        message.add_correlation_tag(LABEL_TAG, label)?;
        if let Some(parent) = self.ids.last() {
            message.add_correlation_tag(BATCH_TAG, parent)?;
        }
        let id = copy_string(id)?;
        self.ids
            .try_reserve(1)
            .map_err(|_| RenderError::AllocationFailed)?;
        self.ids.push(id);
        Ok(message)
    }

    /// Adds one `batch` tag only when the referenced batch is live.
    pub fn attach(&self, id: &str, message: &mut WireMessage) -> Result<(), RenderError> {
        if !self.ids.iter().any(|open| open == id) {
            return Err(RenderError::InvalidBatch);
        }
        message.add_correlation_tag(BATCH_TAG, id)
    }

    /// Closes the current innermost batch and returns its valid closing frame.
    pub fn close(&mut self, prefix: &str, id: &str) -> Result<WireMessage, RenderError> {
        if self.ids.last().is_none_or(|open| open != id) {
            return Err(RenderError::InvalidBatch);
        }
        let close_parameter = prefixed_value("-", id)?;
        let mut message = WireMessage::new_registered(prefix, "BATCH", &[&close_parameter], None)?;
        if let Some(parent) = self.ids.iter().rev().nth(1) {
            message.add_correlation_tag(BATCH_TAG, parent)?;
        }
        self.ids.pop();
        Ok(message)
    }

    /// Returns the current nesting depth.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.ids.len()
    }
}

fn validate_prefix(prefix: &str) -> Result<(), RenderError> {
    if prefix.is_empty()
        || prefix
            .bytes()
            .any(|byte| !byte.is_ascii_graphic() || byte == b':')
    {
        return Err(RenderError::InvalidSyntax);
    }
    Ok(())
}

fn validate_command(command: &str) -> Result<(), RenderError> {
    let numeric = command.len() == 3
        && command.bytes().all(|byte| byte.is_ascii_digit())
        && command
            .parse::<u16>()
            .is_ok_and(|value| SERVER_NUMERICS.contains(&value));
    if numeric || SERVER_COMMANDS.contains(&command) {
        return Ok(());
    }
    Err(RenderError::UnknownRegistryValue)
}

fn validate_parameters(middle: &[&str], trailing: Option<&str>) -> Result<(), RenderError> {
    validate_parameter_count(middle, trailing)?;
    if middle.iter().any(|value| {
        value.is_empty()
            || value.starts_with(':')
            || value
                .bytes()
                .any(|byte| matches!(byte, 0 | b'\r' | b'\n' | b' '))
    }) {
        return Err(RenderError::InvalidSyntax);
    }
    if trailing.is_some_and(|value| value.bytes().any(|byte| matches!(byte, 0 | b'\r' | b'\n'))) {
        return Err(RenderError::InvalidSyntax);
    }
    Ok(())
}

fn validate_owned_parameters(middle: &[String], trailing: Option<&str>) -> Result<(), RenderError> {
    let count = middle
        .len()
        .checked_add(usize::from(trailing.is_some()))
        .ok_or(RenderError::Overflow)?;
    if count > MAX_PARAMETERS {
        return Err(RenderError::InvalidSyntax);
    }
    if middle.iter().any(|value| {
        value.is_empty()
            || value.starts_with(':')
            || value
                .bytes()
                .any(|byte| matches!(byte, 0 | b'\r' | b'\n' | b' '))
    }) {
        return Err(RenderError::InvalidSyntax);
    }
    if trailing.is_some_and(|value| value.bytes().any(|byte| matches!(byte, 0 | b'\r' | b'\n'))) {
        return Err(RenderError::InvalidSyntax);
    }
    Ok(())
}

fn validate_parameter_count(middle: &[&str], trailing: Option<&str>) -> Result<(), RenderError> {
    let count = middle
        .len()
        .checked_add(usize::from(trailing.is_some()))
        .ok_or(RenderError::Overflow)?;
    if count > MAX_PARAMETERS {
        return Err(RenderError::InvalidSyntax);
    }
    Ok(())
}

fn insert_tag(
    tags: &mut Vec<RenderTag>,
    key: &str,
    value: Option<&str>,
    maximum_encoded_bytes: usize,
) -> Result<(), RenderError> {
    if key.len() > maximum_encoded_bytes
        || value.is_some_and(|value| value.len() > maximum_encoded_bytes)
    {
        return Err(RenderError::LineBudget);
    }
    if key.is_empty()
        || key
            .bytes()
            .any(|byte| matches!(byte, 0 | b'\r' | b'\n' | b' ' | b';' | b'='))
        || tags.iter().any(|tag| tag.key == key)
    {
        return Err(RenderError::InvalidSyntax);
    }
    if matches!(key, "label" | "batch")
        && value.is_some_and(|value| value.len() > MAX_CORRELATION_TAG_BYTES)
    {
        return Err(RenderError::InvalidCorrelation);
    }
    if value.is_some_and(|value| value.bytes().any(|byte| byte == 0)) {
        return Err(RenderError::InvalidSyntax);
    }
    if tag_data_bytes_with(tags, key, value)? > maximum_encoded_bytes {
        return Err(RenderError::LineBudget);
    }
    tags.try_reserve(1)
        .map_err(|_| RenderError::AllocationFailed)?;
    let tag = RenderTag {
        key: copy_string(key)?,
        value: value.map(copy_string).transpose()?,
    };
    let position = tags.partition_point(|tag| tag.key.as_bytes() < key.as_bytes());
    tags.insert(position, tag);
    Ok(())
}

fn validate_client_tag_budget(
    tags: &[RenderTag],
    key: &str,
    value: Option<&str>,
) -> Result<(), RenderError> {
    let count = tags.len().checked_add(1).ok_or(RenderError::Overflow)?;
    if count > MAX_CLIENT_ONLY_TAGS {
        return Err(RenderError::LineBudget);
    }
    if key == E2EE_TAG {
        return Ok(());
    }
    if value.is_some_and(|value| value.len() > MAX_CLIENT_ONLY_VALUE_BYTES) {
        return Err(RenderError::LineBudget);
    }
    let mut decoded = key.len().checked_add(value.map_or(0, str::len));
    for tag in tags.iter().filter(|tag| tag.key != E2EE_TAG) {
        decoded = decoded
            .and_then(|total| total.checked_add(tag.key.len()))
            .and_then(|total| total.checked_add(tag.value.as_ref().map_or(0, String::len)));
    }
    if decoded.ok_or(RenderError::Overflow)? > MAX_CLIENT_ONLY_TOTAL_BYTES {
        return Err(RenderError::LineBudget);
    }
    Ok(())
}

fn tag_data_bytes_with(
    tags: &[RenderTag],
    key: &str,
    value: Option<&str>,
) -> Result<usize, RenderError> {
    let mut bytes = tag_data_bytes(tags)?
        .checked_add(usize::from(!tags.is_empty()))
        .and_then(|total| total.checked_add(key.len()))
        .ok_or(RenderError::Overflow)?;
    if let Some(value) = value {
        bytes = bytes
            .checked_add(1)
            .and_then(|total| escaped_len(value).ok()?.checked_add(total))
            .ok_or(RenderError::Overflow)?;
    }
    Ok(bytes)
}

fn tag_data_bytes(tags: &[RenderTag]) -> Result<usize, RenderError> {
    let mut bytes = tags.len().saturating_sub(1);
    for tag in tags {
        bytes = bytes
            .checked_add(tag.key.len())
            .ok_or(RenderError::Overflow)?;
        if let Some(value) = &tag.value {
            let value_bytes = escaped_len(value)?;
            bytes = bytes
                .checked_add(1)
                .and_then(|total| total.checked_add(value_bytes))
                .ok_or(RenderError::Overflow)?;
        }
    }
    Ok(bytes)
}

fn combined_tag_section(server_bytes: usize, client_bytes: usize) -> Result<usize, RenderError> {
    if server_bytes == 0 && client_bytes == 0 {
        return Ok(0);
    }
    let separator = usize::from(server_bytes != 0 && client_bytes != 0);
    server_bytes
        .checked_add(client_bytes)
        .and_then(|value| value.checked_add(separator))
        .and_then(|value| value.checked_add(2))
        .ok_or(RenderError::Overflow)
}

fn escaped_len(value: &str) -> Result<usize, RenderError> {
    let mut bytes = 0usize;
    for byte in value.bytes() {
        let width = if matches!(byte, b';' | b' ' | b'\\' | b'\r' | b'\n') {
            2
        } else {
            1
        };
        bytes = bytes.checked_add(width).ok_or(RenderError::Overflow)?;
    }
    Ok(bytes)
}

fn encode_tag_list(
    tags: &[RenderTag],
    output: &mut ExactOutput,
    leading_separator: bool,
) -> Result<(), RenderError> {
    for (position, tag) in tags.iter().enumerate() {
        if leading_separator || position != 0 {
            output.push(b';')?;
        }
        output.extend(tag.key.as_bytes())?;
        if let Some(value) = &tag.value {
            output.push(b'=')?;
            encode_escaped(value, output)?;
        }
    }
    Ok(())
}

fn encode_escaped(value: &str, output: &mut ExactOutput) -> Result<(), RenderError> {
    for byte in value.bytes() {
        match byte {
            b';' => output.extend(b"\\:")?,
            b' ' => output.extend(b"\\s")?,
            b'\\' => output.extend(b"\\\\")?,
            b'\r' => output.extend(b"\\r")?,
            b'\n' => output.extend(b"\\n")?,
            other => output.push(other)?,
        }
    }
    Ok(())
}

fn validate_correlation(value: &str) -> Result<(), RenderError> {
    if value.is_empty()
        || value.len() > MAX_CORRELATION_TAG_BYTES
        || value
            .bytes()
            .any(|byte| matches!(byte, 0 | b'\r' | b'\n' | b' ' | b';'))
    {
        return Err(RenderError::InvalidCorrelation);
    }
    Ok(())
}

fn validate_batch_reference(value: &str) -> Result<(), RenderError> {
    if value.is_empty()
        || value.len() > MAX_CORRELATION_TAG_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(RenderError::InvalidCorrelation);
    }
    Ok(())
}

fn command_bytes(
    prefix: &str,
    command: &str,
    middle: &[&str],
    trailing: Option<&str>,
) -> Result<usize, RenderError> {
    let mut bytes = 1usize
        .checked_add(prefix.len())
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(command.len()))
        .ok_or(RenderError::Overflow)?;
    for parameter in middle {
        bytes = bytes
            .checked_add(1)
            .and_then(|value| value.checked_add(parameter.len()))
            .ok_or(RenderError::Overflow)?;
    }
    if let Some(trailing) = trailing {
        bytes = bytes
            .checked_add(2)
            .and_then(|value| value.checked_add(trailing.len()))
            .ok_or(RenderError::Overflow)?;
    }
    Ok(bytes)
}

fn owned_command_bytes(
    prefix: &str,
    command: &str,
    middle: &[String],
    trailing: Option<&str>,
) -> Result<usize, RenderError> {
    let mut bytes = 1usize
        .checked_add(prefix.len())
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(command.len()))
        .ok_or(RenderError::Overflow)?;
    for parameter in middle {
        bytes = bytes
            .checked_add(1)
            .and_then(|value| value.checked_add(parameter.len()))
            .ok_or(RenderError::Overflow)?;
    }
    if let Some(trailing) = trailing {
        bytes = bytes
            .checked_add(2)
            .and_then(|value| value.checked_add(trailing.len()))
            .ok_or(RenderError::Overflow)?;
    }
    Ok(bytes)
}

fn copy_string(value: &str) -> Result<String, RenderError> {
    let mut owned = String::new();
    owned
        .try_reserve_exact(value.len())
        .map_err(|_| RenderError::AllocationFailed)?;
    owned.push_str(value);
    Ok(owned)
}

fn copy_strings(values: &[&str]) -> Result<Vec<String>, RenderError> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(values.len())
        .map_err(|_| RenderError::AllocationFailed)?;
    for value in values {
        owned.push(copy_string(value)?);
    }
    Ok(owned)
}

fn prefixed_value(prefix: &str, value: &str) -> Result<String, RenderError> {
    let length = prefix
        .len()
        .checked_add(value.len())
        .ok_or(RenderError::Overflow)?;
    let mut output = String::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| RenderError::AllocationFailed)?;
    output.push_str(prefix);
    output.push_str(value);
    Ok(output)
}

#[cfg(test)]
mod display_tests {
    use super::RenderError;

    #[test]
    fn every_discriminant_renders_a_distinct_message() {
        let variants = [
            RenderError::InvalidSyntax,
            RenderError::UnknownRegistryValue,
            RenderError::CapabilityRequired,
            RenderError::InapplicableReply,
            RenderError::LineBudget,
            RenderError::ReservationFailed,
            RenderError::Overflow,
            RenderError::AllocationFailed,
            RenderError::TooManyReplies,
            RenderError::InvalidBatch,
            RenderError::InvalidCorrelation,
        ];
        let rendered: Vec<String> = variants.iter().map(ToString::to_string).collect();
        assert!(rendered.iter().all(|text| !text.is_empty()));
        let mut unique = rendered.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), rendered.len(), "{rendered:?}");
    }
}
