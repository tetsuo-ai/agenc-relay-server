#![forbid(unsafe_code)]

//! Bounded client framing, parsing, and rendering.
//!
//! Stage 02 implements transport-independent wire behavior. Runtime socket
//! ownership and network listeners remain outside this crate.
//!
//! The server-to-client direction a client reads is decoded by
//! [`ServerStreamFramer`], [`parse_server_tags`] and [`parse_server_message`];
//! the daemon itself never runs them. A decoding error of
//! [`parse_server_tags`] or [`parse_server_message`] concerns that line only:
//! the framer's stream stays in sync, and only a [`ServerStreamFramer`]
//! failure ends the stream.

mod auth_transport;
mod capability;
mod framing;
mod limits;
mod message;
mod registration;
mod registration_command;
mod render;
mod server_framing;
mod server_message;
mod server_tags;
mod tags;
mod text;
mod websocket;

pub use framing::{FrameProgress, FramedLine, FramingError, StreamFramer};
pub use limits::*;
pub use message::{MessageParseError, ParsedMessage, parse_message};
pub use registration::{
    AccessTokenPolicy, KEEPALIVE_IDLE_MILLIS, KEEPALIVE_PONG_MILLIS, MAX_PENDING_BYTES,
    MAX_PENDING_MESSAGES, PendingInputQueue, REGISTRATION_TIMEOUT_MILLIS, RegisteredCommandHandoff,
    RegisteredCommandKind, RegistrationAction, RegistrationAuthCarrier, RegistrationError,
    RegistrationEvent, RegistrationPhase, RegistrationState, SecretBytes, WelcomeStep,
};
pub use registration_command::{
    AccountControlCommand, ChannelControlCommand, ChatHistoryCommand, LocalInformationCommand,
    MonitorCommand, POST_REGISTRATION_COMMANDS, PostRegistrationCommand,
    PostRegistrationCommandKind, RegistrationAccountCommand, RegistrationCapCommand,
    RegistrationCommand, RegistrationGrammarError, parse_registration_command,
    validate_post_registration_command,
};
pub use render::{
    BatchStack, LogicalReply, MAX_BATCH_NESTING, MAX_SEMANTIC_REPLIES, MAX_USER_MASK_BYTES,
    MeasuredMessage, OutputBudget, RenderError, RenderedMessage, ReplyKind, SafeReplyContext,
    SafeReplyDescription, VISIBLE_CLOAK_HOST_BYTES, VISIBLE_CLOAK_USER_BYTES, VisibleCloak,
    WireMessage, isupport_messages, labeled_response, numeric_reply, slow_consumer_warning,
    standard_reply, user_mask,
};
pub use server_framing::{ServerFramedLine, ServerFramingError, ServerStreamFramer, WireDirection};
pub use server_message::{
    ADMIN_ONLY_REPLY_CODES, FORBIDDEN_NUMERICS, ServerCommand, ServerMessage, ServerMessageError,
    ServerParams, ServerPrefix, ServerUserPrefix, parse_server_message,
};
pub use server_tags::{
    ServerTag, ServerTagError, ServerTagIter, ServerTags, parse_server_tags,
    unescape_server_tag_value, validate_batch_reference, validate_safe_label,
};
pub use tags::{
    MessageTag, MessageTagRef, MessageTagSource, ParsedTagIter, ParsedTags, TagError,
    parse_client_tags, render_tags,
};

pub use auth_transport::{
    ACCOUNT_IDLE_TIMEOUT_MILLIS, ACCOUNT_REQUEST_BYTES, ACCOUNT_REQUEST_CHARACTERS,
    ACCOUNT_RESPONSE_BYTES, ACCOUNT_RESPONSE_CHARACTERS, ACCOUNT_TOTAL_TIMEOUT_MILLIS,
    AUTH_CHUNK_CHARACTERS, AccountCarrierAction, AccountCarrierKind, AccountCarrierPhase,
    AccountTransfer, AuthTransportError, SASL_REQUEST_CHARACTERS, SASL_RESPONSE_CHARACTERS,
    SASL_TIMEOUT_MILLIS, SaslAction, SaslNumeric, SaslTransport, SecretText,
    decode_account_payload, decode_sasl_payload, encode_account_payload, encode_sasl_payload,
};
pub use capability::{
    CapError, CapLine, CapRequestReply, CapabilityChange, CapabilityProfile, CapabilitySpec,
    CapabilityState, split_capability_lines,
};
pub use text::{
    CanonicalBase64Url, E2EE_OBJECT_KINDS, E2eeFragment, E2eeObjectKind, E2eeRequestCommand,
    ExactArity, MAX_E2EE_FRAGMENT_BYTES, MAX_E2EE_FRAGMENT_COUNT, MAX_E2EE_OBJECT_BYTES,
    MailboxKind, SafeLabel, TextCarrierError, parse_u16_decimal, parse_u32_decimal,
    parse_u64_decimal, validate_uppercase_token,
};
pub use websocket::{
    ClientWebSocketFrame, WebSocketClose, WebSocketEvent, WebSocketMessage, WebSocketOpcode,
    WebSocketSubprotocol, WebSocketWire,
};

#[cfg(feature = "wss")]
pub mod websocket_transport;
