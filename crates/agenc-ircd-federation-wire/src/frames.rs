//! Typed parse and render for every Section-20 federation line.
//!
//! A frame is the exact parameter tuple of one registered command form. The
//! parser proves prefix, tag policy, arity, token grammar, and the equality of
//! a fragment's object ID with its descriptor before a link owner sees the
//! value. The renderer produces the one canonical line, including CRLF, and
//! refuses any line above the physical ceiling.

use std::error::Error;
use std::fmt::{self, Write as _};

use agenc_ircd_types::{
    EventId, OriginId, RecoveryEpoch, RequestId, SERVER_PREFIX_NAME_BYTES, ServerId,
    ServerIncarnation, ServerName,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeroize::Zeroize as _;

use crate::codec::CodecError;
use crate::objects::FederationHello;
use crate::text::{
    FEDERATION_FRAGMENT_TAG_NAME, FederationCommandTag, FederationCommandTags, FederationFragment,
    FederationHash32, FederationId16, FederationTextError, StarCursor, StarId,
    parse_federation_u32, parse_federation_u64, validate_federation_command,
};

/// Complete FHELLO line ceiling including CRLF (spec 20.2).
///
/// Every rendered frame fits its ceiling by construction: the server name is
/// at most 127 bytes, every token has a fixed maximum width, and one fragment
/// carries at most 2,940 bytes. The crate's tests render each form at its
/// maximum width against this value and [`CLIENT_PHYSICAL_LINE_BYTES`].
pub const FHELLO_LINE_BYTES: usize = 508;
const CRLF: &str = "\r\n";

/// Closed failures from federation frame parsing or rendering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameError {
    /// A text token or command form was invalid.
    Text(FederationTextError),
    /// The FHELLO payload did not decode to one valid hello object.
    Codec(CodecError),
    /// The line had no source prefix.
    MissingPrefix,
    /// The prefix was not the authenticated peer's configured name.
    WrongPrefix,
    /// The fragment tag named a different object than the descriptor.
    ObjectIdMismatch,
    /// A `*`/value cursor pair was not both present or both absent.
    CursorShape,
    /// A server name is not a valid federation prefix.
    InvalidServerName,
    /// A checked calculation overflowed.
    Overflow,
    /// A bounded allocation failed.
    AllocationFailed,
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(error) => error.fmt(formatter),
            Self::Codec(error) => error.fmt(formatter),
            Self::MissingPrefix => formatter.write_str("federation line has no server prefix"),
            Self::WrongPrefix => formatter.write_str("federation prefix is not the peer name"),
            Self::ObjectIdMismatch => {
                formatter.write_str("federation fragment and descriptor object IDs differ")
            }
            Self::CursorShape => formatter.write_str("federation cursor pair is inconsistent"),
            Self::InvalidServerName => formatter.write_str("federation server name is invalid"),
            Self::Overflow => formatter.write_str("federation frame calculation overflowed"),
            Self::AllocationFailed => formatter.write_str("federation frame allocation failed"),
        }
    }
}

impl Error for FrameError {}

impl From<FederationTextError> for FrameError {
    fn from(error: FederationTextError) -> Self {
        Self::Text(error)
    }
}

impl From<CodecError> for FrameError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error)
    }
}

/// One decoded line offered to the federation frame parser.
#[derive(Clone, Copy)]
pub struct FederationLine<'a> {
    prefix: Option<&'a str>,
    tags: &'a [FederationCommandTag<'a>],
    command: &'a str,
    parameters: &'a [&'a str],
}

impl<'a> FederationLine<'a> {
    /// Borrows the already split parts of one line.
    #[must_use]
    pub const fn new(
        prefix: Option<&'a str>,
        tags: &'a [FederationCommandTag<'a>],
        command: &'a str,
        parameters: &'a [&'a str],
    ) -> Self {
        Self {
            prefix,
            tags,
            command,
            parameters,
        }
    }
}

/// The descriptor of one FREQUEST or FRESULT line.
///
/// FREQUEST names the coordinator in `addressed_server_id`; FRESULT names the
/// home edge. The remaining fields repeat the object's replay key, request
/// identity, and object identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationDescriptor {
    /// The first descriptor parameter.
    pub addressed_server_id: ServerId,
    /// The edge incarnation that owns the origin.
    pub server_incarnation: ServerIncarnation,
    /// The connection-scoped origin.
    pub origin_id: OriginId,
    /// The origin generation.
    pub origin_generation: u64,
    /// The operation sequence within the generation.
    pub operation_sequence: u64,
    /// The request identity.
    pub request_id: RequestId,
    /// The carried object's identity.
    pub object_id: FederationHash32,
}

/// The descriptor of one FEVENT line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventDescriptor {
    /// The edge the event is addressed to.
    pub target_server_id: ServerId,
    /// The contiguous delivery sequence.
    pub delivery_sequence: u64,
    /// The event identity.
    pub event_id: EventId,
    /// The carried object's identity.
    pub object_id: FederationHash32,
}

/// The descriptor of one FORIGIN ADD or UPDATE line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginDescriptor {
    /// The coordinator the origin is declared to.
    pub coordinator_server_id: ServerId,
    /// The declaring edge incarnation.
    pub server_incarnation: ServerIncarnation,
    /// The origin identity.
    pub origin_id: OriginId,
    /// The declared generation.
    pub generation: u64,
    /// The carried object's identity.
    pub object_id: FederationHash32,
}

/// A retained delivery cursor or its explicit absence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryCursor {
    /// `* *`: no prior event in the projection.
    Empty,
    /// The exact last delivery sequence and event identity.
    At {
        /// The last delivery sequence.
        delivery_sequence: u64,
        /// The event identity at that sequence.
        event_id: EventId,
    },
}

/// The identity echoed by FSNAPSHOT BEGIN, READY, and ACTIVE.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotIdentity {
    /// The one-use random token.
    pub snapshot_token: FederationHash32,
    /// The coordinator recovery epoch on this link.
    pub recovery_epoch: RecoveryEpoch,
    /// The projection generation being installed.
    pub projection_generation: u64,
    /// The global state generation of the cut.
    pub state_generation: u64,
    /// The Appendix-B.7 digest.
    pub snapshot_digest: FederationHash32,
}

/// Every registered federation line as a typed value.
pub enum FederationFrame {
    /// `FHELLO <peer-server-id> <base64url-FederationHello>`.
    Hello {
        /// The peer the sender expects.
        peer_server_id: ServerId,
        /// The decoded signed hello.
        hello: FederationHello,
    },
    /// `FREADY <peer-server-id> <hello-nonce>`.
    Ready {
        /// The peer the sender expects.
        peer_server_id: ServerId,
        /// The receiver's echoed hello nonce.
        hello_nonce: [u8; 32],
    },
    /// `FPING <peer-server-id> <nonce>`.
    Ping {
        /// The peer the sender expects.
        peer_server_id: ServerId,
        /// The random keepalive nonce.
        nonce: [u8; 32],
    },
    /// `FPONG <peer-server-id> <nonce>`.
    Pong {
        /// The peer the sender expects.
        peer_server_id: ServerId,
        /// The echoed keepalive nonce.
        nonce: [u8; 32],
    },
    /// One FREQUEST fragment.
    Request {
        /// The repeated descriptor.
        descriptor: OperationDescriptor,
        /// This line's fragment.
        fragment: FederationFragment,
    },
    /// One FRESULT fragment.
    Result {
        /// The repeated descriptor.
        descriptor: OperationDescriptor,
        /// This line's fragment.
        fragment: FederationFragment,
    },
    /// One FEVENT fragment.
    Event {
        /// The repeated descriptor.
        descriptor: EventDescriptor,
        /// This line's fragment.
        fragment: FederationFragment,
    },
    /// `FACK <coordinator-id> <delivery-sequence> <event-id>`.
    Ack {
        /// The coordinator being acknowledged.
        coordinator_server_id: ServerId,
        /// The cumulative acknowledged sequence.
        delivery_sequence: u64,
        /// The event identity at that sequence.
        event_id: EventId,
    },
    /// `FORIGIN RESET <coordinator-id> <server-incarnation>`.
    OriginReset {
        /// The coordinator addressed.
        coordinator_server_id: ServerId,
        /// The declaring edge incarnation.
        server_incarnation: ServerIncarnation,
    },
    /// One FORIGIN ADD fragment.
    OriginAdd {
        /// The repeated descriptor.
        descriptor: OriginDescriptor,
        /// This line's fragment.
        fragment: FederationFragment,
    },
    /// One FORIGIN UPDATE fragment.
    OriginUpdate {
        /// The repeated descriptor.
        descriptor: OriginDescriptor,
        /// This line's fragment.
        fragment: FederationFragment,
    },
    /// `FORIGIN DEL ...`.
    OriginDel {
        /// The coordinator addressed.
        coordinator_server_id: ServerId,
        /// The declaring edge incarnation.
        server_incarnation: ServerIncarnation,
        /// The deleted origin.
        origin_id: OriginId,
        /// The generation at deletion.
        generation: u64,
        /// The next operation sequence retained for replay checking.
        next_operation_sequence: u64,
    },
    /// `FORIGIN ACK ...`.
    OriginAck {
        /// The edge addressed.
        edge_server_id: ServerId,
        /// The edge incarnation.
        server_incarnation: ServerIncarnation,
        /// The acknowledged origin.
        origin_id: OriginId,
        /// The acknowledged generation.
        generation: u64,
        /// The acknowledged object, or `*` for RESET/DEL acknowledgement.
        object_id: Option<FederationHash32>,
    },
    /// `FORIGIN READY <edge-id> <server-incarnation>`.
    OriginReady {
        /// The edge addressed.
        edge_server_id: ServerId,
        /// The edge incarnation.
        server_incarnation: ServerIncarnation,
    },
    /// `FRESUME <coordinator-id> <projection-generation> <cursor>`.
    Resume {
        /// The coordinator addressed.
        coordinator_server_id: ServerId,
        /// The edge's installed projection generation.
        projection_generation: u64,
        /// The edge's durable delivery cursor.
        cursor: DeliveryCursor,
    },
    /// `FRESUME OK <edge-id> <projection-generation> <next-delivery-sequence>`.
    ResumeOk {
        /// The edge addressed.
        edge_server_id: ServerId,
        /// The confirmed projection generation.
        projection_generation: u64,
        /// The next sequence the coordinator will send.
        next_delivery_sequence: u64,
    },
    /// `FRESUME SNAPSHOT <edge-id>`.
    ResumeSnapshot {
        /// The edge addressed.
        edge_server_id: ServerId,
    },
    /// `FSNAPSHOT BEGIN ...`.
    SnapshotBegin {
        /// The edge the snapshot is built for.
        edge_server_id: ServerId,
        /// The complete snapshot identity.
        identity: SnapshotIdentity,
        /// The exact entry count.
        entry_count: u64,
    },
    /// One FSNAPSHOT ENTRY fragment.
    SnapshotEntry {
        /// The edge addressed.
        edge_server_id: ServerId,
        /// The snapshot token.
        snapshot_token: FederationHash32,
        /// The zero-based entry index.
        entry_index: u32,
        /// The carried object's identity.
        object_id: FederationHash32,
        /// This line's fragment.
        fragment: FederationFragment,
    },
    /// `FSNAPSHOT END <edge-id> <snapshot-token> <cursor>`.
    SnapshotEnd {
        /// The edge addressed.
        edge_server_id: ServerId,
        /// The snapshot token.
        snapshot_token: FederationHash32,
        /// The cursor immediately preceding the first post-snapshot event.
        cursor: DeliveryCursor,
    },
    /// `FSNAPSHOT READY <coordinator-id> ...`.
    SnapshotReady {
        /// The coordinator addressed.
        coordinator_server_id: ServerId,
        /// The echoed identity.
        identity: SnapshotIdentity,
    },
    /// `FSNAPSHOT ACTIVE <edge-id> ...`.
    SnapshotActive {
        /// The edge addressed.
        edge_server_id: ServerId,
        /// The echoed identity.
        identity: SnapshotIdentity,
    },
}

/// Content-free classification of one frame for logging and dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationFrameKind {
    /// FHELLO.
    Hello,
    /// FREADY.
    Ready,
    /// FPING.
    Ping,
    /// FPONG.
    Pong,
    /// FREQUEST.
    Request,
    /// FRESULT.
    Result,
    /// FEVENT.
    Event,
    /// FACK.
    Ack,
    /// FORIGIN RESET.
    OriginReset,
    /// FORIGIN ADD.
    OriginAdd,
    /// FORIGIN UPDATE.
    OriginUpdate,
    /// FORIGIN DEL.
    OriginDel,
    /// FORIGIN ACK.
    OriginAck,
    /// FORIGIN READY.
    OriginReady,
    /// FRESUME.
    Resume,
    /// FRESUME OK.
    ResumeOk,
    /// FRESUME SNAPSHOT.
    ResumeSnapshot,
    /// FSNAPSHOT BEGIN.
    SnapshotBegin,
    /// FSNAPSHOT ENTRY.
    SnapshotEntry,
    /// FSNAPSHOT END.
    SnapshotEnd,
    /// FSNAPSHOT READY.
    SnapshotReady,
    /// FSNAPSHOT ACTIVE.
    SnapshotActive,
}

impl FederationFrameKind {
    /// Returns the registered command form name.
    #[must_use]
    pub const fn form(self) -> &'static str {
        match self {
            Self::Hello => "FHELLO",
            Self::Ready => "FREADY",
            Self::Ping => "FPING",
            Self::Pong => "FPONG",
            Self::Request => "FREQUEST",
            Self::Result => "FRESULT",
            Self::Event => "FEVENT",
            Self::Ack => "FACK",
            Self::OriginReset => "FORIGIN_RESET",
            Self::OriginAdd => "FORIGIN_ADD",
            Self::OriginUpdate => "FORIGIN_UPDATE",
            Self::OriginDel => "FORIGIN_DEL",
            Self::OriginAck => "FORIGIN_ACK",
            Self::OriginReady => "FORIGIN_READY",
            Self::Resume => "FRESUME",
            Self::ResumeOk => "FRESUME_OK",
            Self::ResumeSnapshot => "FRESUME_SNAPSHOT",
            Self::SnapshotBegin => "FSNAPSHOT_BEGIN",
            Self::SnapshotEntry => "FSNAPSHOT_ENTRY",
            Self::SnapshotEnd => "FSNAPSHOT_END",
            Self::SnapshotReady => "FSNAPSHOT_READY",
            Self::SnapshotActive => "FSNAPSHOT_ACTIVE",
        }
    }

    const fn command(self) -> (&'static str, Option<&'static str>) {
        match self {
            Self::Hello => ("FHELLO", None),
            Self::Ready => ("FREADY", None),
            Self::Ping => ("FPING", None),
            Self::Pong => ("FPONG", None),
            Self::Request => ("FREQUEST", None),
            Self::Result => ("FRESULT", None),
            Self::Event => ("FEVENT", None),
            Self::Ack => ("FACK", None),
            Self::OriginReset => ("FORIGIN", Some("RESET")),
            Self::OriginAdd => ("FORIGIN", Some("ADD")),
            Self::OriginUpdate => ("FORIGIN", Some("UPDATE")),
            Self::OriginDel => ("FORIGIN", Some("DEL")),
            Self::OriginAck => ("FORIGIN", Some("ACK")),
            Self::OriginReady => ("FORIGIN", Some("READY")),
            Self::Resume => ("FRESUME", None),
            Self::ResumeOk => ("FRESUME", Some("OK")),
            Self::ResumeSnapshot => ("FRESUME", Some("SNAPSHOT")),
            Self::SnapshotBegin => ("FSNAPSHOT", Some("BEGIN")),
            Self::SnapshotEntry => ("FSNAPSHOT", Some("ENTRY")),
            Self::SnapshotEnd => ("FSNAPSHOT", Some("END")),
            Self::SnapshotReady => ("FSNAPSHOT", Some("READY")),
            Self::SnapshotActive => ("FSNAPSHOT", Some("ACTIVE")),
        }
    }
}

/// Move-only rendered federation line that erases its backing allocation.
///
/// The text may carry a complete request, result, or event fragment; it is
/// borrowed only at the transport boundary and is neither `Clone` nor `Debug`.
#[must_use = "a rendered federation line must be sent or explicitly dropped"]
pub struct FederationLineText {
    text: String,
}

/// The physical S2S line ceiling (spec 20.3): 8,191 tag bytes plus a
/// 512-byte line.
const MAX_RENDERED_LINE_BYTES: usize = 8_703;

impl FederationLineText {
    /// Wraps a line rendered elsewhere (a companion frame): it must end with
    /// CRLF, contain no other control byte, and fit the physical ceiling.
    pub fn from_rendered(text: String) -> Result<Self, FrameError> {
        let body = text.strip_suffix(CRLF).ok_or(FrameError::MissingPrefix)?;
        if body.is_empty()
            || text.len() > MAX_RENDERED_LINE_BYTES
            || body
                .bytes()
                .any(|byte| byte == b'\r' || byte == b'\n' || byte == 0)
        {
            return Err(FrameError::Text(FederationTextError::UnknownCommandForm));
        }
        Ok(Self { text })
    }

    /// Borrows the complete line including CRLF.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the encoded byte length including CRLF.
    #[must_use]
    pub fn len(&self) -> usize {
        self.text.len()
    }

    /// Reports whether the line is empty; a rendered line never is.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }
}

impl Drop for FederationLineText {
    fn drop(&mut self) {
        let remaining = self.text.capacity().saturating_sub(self.text.len());
        self.text.extend(std::iter::repeat_n('\0', remaining));
        self.text.as_mut_str().zeroize();
    }
}

impl FederationFrame {
    /// Returns the content-free classification of this frame.
    #[must_use]
    pub const fn kind(&self) -> FederationFrameKind {
        match self {
            Self::Hello { .. } => FederationFrameKind::Hello,
            Self::Ready { .. } => FederationFrameKind::Ready,
            Self::Ping { .. } => FederationFrameKind::Ping,
            Self::Pong { .. } => FederationFrameKind::Pong,
            Self::Request { .. } => FederationFrameKind::Request,
            Self::Result { .. } => FederationFrameKind::Result,
            Self::Event { .. } => FederationFrameKind::Event,
            Self::Ack { .. } => FederationFrameKind::Ack,
            Self::OriginReset { .. } => FederationFrameKind::OriginReset,
            Self::OriginAdd { .. } => FederationFrameKind::OriginAdd,
            Self::OriginUpdate { .. } => FederationFrameKind::OriginUpdate,
            Self::OriginDel { .. } => FederationFrameKind::OriginDel,
            Self::OriginAck { .. } => FederationFrameKind::OriginAck,
            Self::OriginReady { .. } => FederationFrameKind::OriginReady,
            Self::Resume { .. } => FederationFrameKind::Resume,
            Self::ResumeOk { .. } => FederationFrameKind::ResumeOk,
            Self::ResumeSnapshot { .. } => FederationFrameKind::ResumeSnapshot,
            Self::SnapshotBegin { .. } => FederationFrameKind::SnapshotBegin,
            Self::SnapshotEntry { .. } => FederationFrameKind::SnapshotEntry,
            Self::SnapshotEnd { .. } => FederationFrameKind::SnapshotEnd,
            Self::SnapshotReady { .. } => FederationFrameKind::SnapshotReady,
            Self::SnapshotActive { .. } => FederationFrameKind::SnapshotActive,
        }
    }

    /// Borrows the fragment of an object-bearing frame.
    #[must_use]
    pub const fn fragment(&self) -> Option<&FederationFragment> {
        match self {
            Self::Request { fragment, .. }
            | Self::Result { fragment, .. }
            | Self::Event { fragment, .. }
            | Self::OriginAdd { fragment, .. }
            | Self::OriginUpdate { fragment, .. }
            | Self::SnapshotEntry { fragment, .. } => Some(fragment),
            _ => None,
        }
    }

    /// Parses one line whose prefix must equal the authenticated peer name.
    pub fn parse(line: FederationLine<'_>, expected_prefix: &str) -> Result<Self, FrameError> {
        let prefix = line.prefix.ok_or(FrameError::MissingPrefix)?;
        if prefix != expected_prefix {
            return Err(FrameError::WrongPrefix);
        }
        let tags = FederationCommandTags::parse(line.tags)?;
        let descriptor = validate_federation_command(line.command, line.parameters, &tags)?;
        let skip = usize::from(descriptor.subcommand.is_some());
        let parameters = line
            .parameters
            .get(skip..)
            .ok_or(FederationTextError::WrongArity)?;
        let mut cursor = Parameters {
            parameters,
            next: 0,
        };
        let frame = parse_form(descriptor.form, &mut cursor, tags)?;
        cursor.finish()?;
        Ok(frame)
    }

    /// Renders the one canonical line including CRLF.
    pub fn render(&self, server_name: &str) -> Result<FederationLineText, FrameError> {
        validate_server_name(server_name)?;
        let mut text = String::new();
        if let Some(fragment) = self.fragment() {
            let fragment_text = fragment.to_text()?;
            reserve(
                &mut text,
                2 + FEDERATION_FRAGMENT_TAG_NAME.len() + fragment_text.len(),
            )?;
            text.push('@');
            text.push_str(FEDERATION_FRAGMENT_TAG_NAME);
            text.push('=');
            text.push_str(fragment_text.as_str());
            text.push(' ');
        }
        let (command, subcommand) = self.kind().command();
        reserve(&mut text, 1 + server_name.len() + 1 + command.len())?;
        text.push(':');
        text.push_str(server_name);
        text.push(' ');
        text.push_str(command);
        if let Some(subcommand) = subcommand {
            push_parameter(&mut text, subcommand)?;
        }
        self.render_parameters(&mut text)?;
        reserve(&mut text, CRLF.len())?;
        text.push_str(CRLF);
        Ok(FederationLineText { text })
    }

    // agenc-review: focus owner=federation-wire reviewed=2026-09-02 reason=one closed dispatcher writes every registered form's exact parameter tuple
    fn render_parameters(&self, text: &mut String) -> Result<(), FrameError> {
        match self {
            Self::Hello {
                peer_server_id,
                hello,
            } => {
                push_id(text, peer_server_id.as_bytes())?;
                let encoded = hello.encode()?;
                push_parameter(text, &URL_SAFE_NO_PAD.encode(encoded.as_slice()))
            }
            Self::Ready {
                peer_server_id,
                hello_nonce: nonce,
            }
            | Self::Ping {
                peer_server_id,
                nonce,
            }
            | Self::Pong {
                peer_server_id,
                nonce,
            } => {
                push_id(text, peer_server_id.as_bytes())?;
                push_hash(text, nonce)
            }
            Self::Request { descriptor, .. } | Self::Result { descriptor, .. } => {
                push_id(text, descriptor.addressed_server_id.as_bytes())?;
                push_id(text, descriptor.server_incarnation.as_bytes())?;
                push_id(text, descriptor.origin_id.as_bytes())?;
                push_u64(text, descriptor.origin_generation)?;
                push_u64(text, descriptor.operation_sequence)?;
                push_id(text, descriptor.request_id.as_bytes())?;
                push_hash(text, descriptor.object_id.as_bytes())
            }
            Self::Event { descriptor, .. } => {
                push_id(text, descriptor.target_server_id.as_bytes())?;
                push_u64(text, descriptor.delivery_sequence)?;
                push_id(text, descriptor.event_id.as_bytes())?;
                push_hash(text, descriptor.object_id.as_bytes())
            }
            Self::Ack {
                coordinator_server_id,
                delivery_sequence,
                event_id,
            } => {
                push_id(text, coordinator_server_id.as_bytes())?;
                push_u64(text, *delivery_sequence)?;
                push_id(text, event_id.as_bytes())
            }
            Self::OriginReset {
                coordinator_server_id: server_id,
                server_incarnation,
            }
            | Self::OriginReady {
                edge_server_id: server_id,
                server_incarnation,
            } => {
                push_id(text, server_id.as_bytes())?;
                push_id(text, server_incarnation.as_bytes())
            }
            Self::OriginAdd { descriptor, .. } | Self::OriginUpdate { descriptor, .. } => {
                push_id(text, descriptor.coordinator_server_id.as_bytes())?;
                push_id(text, descriptor.server_incarnation.as_bytes())?;
                push_id(text, descriptor.origin_id.as_bytes())?;
                push_u64(text, descriptor.generation)?;
                push_hash(text, descriptor.object_id.as_bytes())
            }
            Self::OriginDel {
                coordinator_server_id,
                server_incarnation,
                origin_id,
                generation,
                next_operation_sequence,
            } => {
                push_id(text, coordinator_server_id.as_bytes())?;
                push_id(text, server_incarnation.as_bytes())?;
                push_id(text, origin_id.as_bytes())?;
                push_u64(text, *generation)?;
                push_u64(text, *next_operation_sequence)
            }
            Self::OriginAck {
                edge_server_id,
                server_incarnation,
                origin_id,
                generation,
                object_id,
            } => {
                push_id(text, edge_server_id.as_bytes())?;
                push_id(text, server_incarnation.as_bytes())?;
                push_id(text, origin_id.as_bytes())?;
                push_u64(text, *generation)?;
                match object_id {
                    Some(object_id) => push_hash(text, object_id.as_bytes()),
                    None => push_parameter(text, "*"),
                }
            }
            Self::Resume {
                coordinator_server_id,
                projection_generation,
                cursor,
            } => {
                push_id(text, coordinator_server_id.as_bytes())?;
                push_u64(text, *projection_generation)?;
                push_cursor(text, *cursor)
            }
            Self::ResumeOk {
                edge_server_id,
                projection_generation,
                next_delivery_sequence,
            } => {
                push_id(text, edge_server_id.as_bytes())?;
                push_u64(text, *projection_generation)?;
                push_u64(text, *next_delivery_sequence)
            }
            Self::ResumeSnapshot { edge_server_id } => push_id(text, edge_server_id.as_bytes()),
            Self::SnapshotBegin {
                edge_server_id,
                identity,
                entry_count,
            } => {
                push_id(text, edge_server_id.as_bytes())?;
                push_hash(text, identity.snapshot_token.as_bytes())?;
                push_id(text, identity.recovery_epoch.as_bytes())?;
                push_u64(text, identity.projection_generation)?;
                push_u64(text, identity.state_generation)?;
                push_u64(text, *entry_count)?;
                push_hash(text, identity.snapshot_digest.as_bytes())
            }
            Self::SnapshotEntry {
                edge_server_id,
                snapshot_token,
                entry_index,
                object_id,
                ..
            } => {
                push_id(text, edge_server_id.as_bytes())?;
                push_hash(text, snapshot_token.as_bytes())?;
                push_u64(text, u64::from(*entry_index))?;
                push_hash(text, object_id.as_bytes())
            }
            Self::SnapshotEnd {
                edge_server_id,
                snapshot_token,
                cursor,
            } => {
                push_id(text, edge_server_id.as_bytes())?;
                push_hash(text, snapshot_token.as_bytes())?;
                push_cursor(text, *cursor)
            }
            Self::SnapshotReady {
                coordinator_server_id,
                identity,
            } => {
                push_id(text, coordinator_server_id.as_bytes())?;
                push_snapshot_echo(text, identity)
            }
            Self::SnapshotActive {
                edge_server_id,
                identity,
            } => {
                push_id(text, edge_server_id.as_bytes())?;
                push_snapshot_echo(text, identity)
            }
        }
    }
}

struct Parameters<'a> {
    parameters: &'a [&'a str],
    next: usize,
}

impl Parameters<'_> {
    fn take(&mut self) -> Result<&str, FrameError> {
        let value = self
            .parameters
            .get(self.next)
            .copied()
            .ok_or(FederationTextError::WrongArity)?;
        self.next = self.next.saturating_add(1);
        Ok(value)
    }

    fn id16(&mut self) -> Result<[u8; 16], FrameError> {
        Ok(*FederationId16::parse(self.take()?)?.as_bytes())
    }

    fn hash32(&mut self) -> Result<FederationHash32, FrameError> {
        Ok(FederationHash32::parse(self.take()?)?)
    }

    fn u64(&mut self) -> Result<u64, FrameError> {
        Ok(parse_federation_u64(self.take()?)?)
    }

    fn u32(&mut self) -> Result<u32, FrameError> {
        Ok(parse_federation_u32(self.take()?)?)
    }

    fn cursor(&mut self) -> Result<DeliveryCursor, FrameError> {
        let sequence = StarCursor::parse(self.take()?)?;
        let event = StarId::parse(self.take()?)?;
        match (sequence, event) {
            (StarCursor::Star, StarId::Star) => Ok(DeliveryCursor::Empty),
            (StarCursor::Value(delivery_sequence), StarId::Value(event_id)) => {
                Ok(DeliveryCursor::At {
                    delivery_sequence,
                    event_id: EventId::from_bytes(*event_id.as_bytes()),
                })
            }
            _ => Err(FrameError::CursorShape),
        }
    }

    fn snapshot_identity(&mut self) -> Result<SnapshotIdentity, FrameError> {
        Ok(SnapshotIdentity {
            snapshot_token: self.hash32()?,
            recovery_epoch: RecoveryEpoch::from_bytes(self.id16()?),
            projection_generation: self.u64()?,
            state_generation: self.u64()?,
            snapshot_digest: self.hash32()?,
        })
    }

    fn operation_descriptor(&mut self) -> Result<OperationDescriptor, FrameError> {
        Ok(OperationDescriptor {
            addressed_server_id: ServerId::from_bytes(self.id16()?),
            server_incarnation: ServerIncarnation::from_bytes(self.id16()?),
            origin_id: OriginId::from_bytes(self.id16()?),
            origin_generation: self.u64()?,
            operation_sequence: self.u64()?,
            request_id: RequestId::from_bytes(self.id16()?),
            object_id: self.hash32()?,
        })
    }

    fn origin_descriptor(&mut self) -> Result<OriginDescriptor, FrameError> {
        Ok(OriginDescriptor {
            coordinator_server_id: ServerId::from_bytes(self.id16()?),
            server_incarnation: ServerIncarnation::from_bytes(self.id16()?),
            origin_id: OriginId::from_bytes(self.id16()?),
            generation: self.u64()?,
            object_id: self.hash32()?,
        })
    }

    fn finish(&self) -> Result<(), FrameError> {
        if self.next == self.parameters.len() {
            return Ok(());
        }
        Err(FederationTextError::WrongArity.into())
    }
}

// agenc-review: focus owner=federation-wire reviewed=2026-09-02 reason=one closed dispatcher reads every registered form's exact parameter tuple
fn parse_form(
    form: &str,
    cursor: &mut Parameters<'_>,
    tags: FederationCommandTags,
) -> Result<FederationFrame, FrameError> {
    Ok(match form {
        "FHELLO" => {
            let peer_server_id = ServerId::from_bytes(cursor.id16()?);
            let hello = decode_hello(cursor.take()?)?;
            FederationFrame::Hello {
                peer_server_id,
                hello,
            }
        }
        "FREADY" => FederationFrame::Ready {
            peer_server_id: ServerId::from_bytes(cursor.id16()?),
            hello_nonce: *cursor.hash32()?.as_bytes(),
        },
        "FPING" => FederationFrame::Ping {
            peer_server_id: ServerId::from_bytes(cursor.id16()?),
            nonce: *cursor.hash32()?.as_bytes(),
        },
        "FPONG" => FederationFrame::Pong {
            peer_server_id: ServerId::from_bytes(cursor.id16()?),
            nonce: *cursor.hash32()?.as_bytes(),
        },
        "FREQUEST" => {
            let descriptor = cursor.operation_descriptor()?;
            let fragment = take_fragment(tags, descriptor.object_id)?;
            FederationFrame::Request {
                descriptor,
                fragment,
            }
        }
        "FRESULT" => {
            let descriptor = cursor.operation_descriptor()?;
            let fragment = take_fragment(tags, descriptor.object_id)?;
            FederationFrame::Result {
                descriptor,
                fragment,
            }
        }
        "FEVENT" => {
            let descriptor = EventDescriptor {
                target_server_id: ServerId::from_bytes(cursor.id16()?),
                delivery_sequence: cursor.u64()?,
                event_id: EventId::from_bytes(cursor.id16()?),
                object_id: cursor.hash32()?,
            };
            let fragment = take_fragment(tags, descriptor.object_id)?;
            FederationFrame::Event {
                descriptor,
                fragment,
            }
        }
        "FACK" => FederationFrame::Ack {
            coordinator_server_id: ServerId::from_bytes(cursor.id16()?),
            delivery_sequence: cursor.u64()?,
            event_id: EventId::from_bytes(cursor.id16()?),
        },
        "FORIGIN_RESET" => FederationFrame::OriginReset {
            coordinator_server_id: ServerId::from_bytes(cursor.id16()?),
            server_incarnation: ServerIncarnation::from_bytes(cursor.id16()?),
        },
        "FORIGIN_ADD" => {
            let descriptor = cursor.origin_descriptor()?;
            let fragment = take_fragment(tags, descriptor.object_id)?;
            FederationFrame::OriginAdd {
                descriptor,
                fragment,
            }
        }
        "FORIGIN_UPDATE" => {
            let descriptor = cursor.origin_descriptor()?;
            let fragment = take_fragment(tags, descriptor.object_id)?;
            FederationFrame::OriginUpdate {
                descriptor,
                fragment,
            }
        }
        "FORIGIN_DEL" => FederationFrame::OriginDel {
            coordinator_server_id: ServerId::from_bytes(cursor.id16()?),
            server_incarnation: ServerIncarnation::from_bytes(cursor.id16()?),
            origin_id: OriginId::from_bytes(cursor.id16()?),
            generation: cursor.u64()?,
            next_operation_sequence: cursor.u64()?,
        },
        "FORIGIN_ACK" => FederationFrame::OriginAck {
            edge_server_id: ServerId::from_bytes(cursor.id16()?),
            server_incarnation: ServerIncarnation::from_bytes(cursor.id16()?),
            origin_id: OriginId::from_bytes(cursor.id16()?),
            generation: cursor.u64()?,
            object_id: match cursor.take()? {
                "*" => None,
                token => Some(FederationHash32::parse(token)?),
            },
        },
        "FORIGIN_READY" => FederationFrame::OriginReady {
            edge_server_id: ServerId::from_bytes(cursor.id16()?),
            server_incarnation: ServerIncarnation::from_bytes(cursor.id16()?),
        },
        "FRESUME" => FederationFrame::Resume {
            coordinator_server_id: ServerId::from_bytes(cursor.id16()?),
            projection_generation: cursor.u64()?,
            cursor: cursor.cursor()?,
        },
        "FRESUME_OK" => FederationFrame::ResumeOk {
            edge_server_id: ServerId::from_bytes(cursor.id16()?),
            projection_generation: cursor.u64()?,
            next_delivery_sequence: cursor.u64()?,
        },
        "FRESUME_SNAPSHOT" => FederationFrame::ResumeSnapshot {
            edge_server_id: ServerId::from_bytes(cursor.id16()?),
        },
        "FSNAPSHOT_BEGIN" => {
            let edge_server_id = ServerId::from_bytes(cursor.id16()?);
            let snapshot_token = cursor.hash32()?;
            let recovery_epoch = RecoveryEpoch::from_bytes(cursor.id16()?);
            let projection_generation = cursor.u64()?;
            let state_generation = cursor.u64()?;
            let entry_count = cursor.u64()?;
            let snapshot_digest = cursor.hash32()?;
            FederationFrame::SnapshotBegin {
                edge_server_id,
                identity: SnapshotIdentity {
                    snapshot_token,
                    recovery_epoch,
                    projection_generation,
                    state_generation,
                    snapshot_digest,
                },
                entry_count,
            }
        }
        "FSNAPSHOT_ENTRY" => {
            let edge_server_id = ServerId::from_bytes(cursor.id16()?);
            let snapshot_token = cursor.hash32()?;
            let entry_index = cursor.u32()?;
            let object_id = cursor.hash32()?;
            let fragment = take_fragment(tags, object_id)?;
            FederationFrame::SnapshotEntry {
                edge_server_id,
                snapshot_token,
                entry_index,
                object_id,
                fragment,
            }
        }
        "FSNAPSHOT_END" => FederationFrame::SnapshotEnd {
            edge_server_id: ServerId::from_bytes(cursor.id16()?),
            snapshot_token: cursor.hash32()?,
            cursor: cursor.cursor()?,
        },
        "FSNAPSHOT_READY" => {
            let coordinator_server_id = ServerId::from_bytes(cursor.id16()?);
            let identity = cursor.snapshot_identity()?;
            FederationFrame::SnapshotReady {
                coordinator_server_id,
                identity,
            }
        }
        "FSNAPSHOT_ACTIVE" => {
            let edge_server_id = ServerId::from_bytes(cursor.id16()?);
            FederationFrame::SnapshotActive {
                edge_server_id,
                identity: cursor.snapshot_identity()?,
            }
        }
        _ => return Err(FederationTextError::UnknownCommandForm.into()),
    })
}

fn decode_hello(token: &str) -> Result<FederationHello, FrameError> {
    let mut decoded = [0_u8; 260];
    let written = URL_SAFE_NO_PAD
        .decode_slice(token.as_bytes(), &mut decoded)
        .map_err(|_| FederationTextError::NonCanonical)?;
    if written != decoded.len() || URL_SAFE_NO_PAD.encode(decoded) != token {
        return Err(FederationTextError::NonCanonical.into());
    }
    Ok(FederationHello::decode(&decoded)?)
}

fn take_fragment(
    tags: FederationCommandTags,
    object_id: FederationHash32,
) -> Result<FederationFragment, FrameError> {
    let fragment = tags
        .into_fragment()
        .ok_or(FederationTextError::WrongTagPolicy)?;
    if fragment.object_id() != object_id {
        return Err(FrameError::ObjectIdMismatch);
    }
    Ok(fragment)
}

fn validate_server_name(server_name: &str) -> Result<(), FrameError> {
    let maximum = usize::try_from(SERVER_PREFIX_NAME_BYTES).map_err(|_| FrameError::Overflow)?;
    if server_name.len() > maximum || ServerName::parse(server_name).is_err() {
        return Err(FrameError::InvalidServerName);
    }
    Ok(())
}

fn reserve(text: &mut String, additional: usize) -> Result<(), FrameError> {
    text.try_reserve(additional)
        .map_err(|_| FrameError::AllocationFailed)
}

fn push_parameter(text: &mut String, parameter: &str) -> Result<(), FrameError> {
    reserve(text, 1 + parameter.len())?;
    text.push(' ');
    text.push_str(parameter);
    Ok(())
}

fn push_id(text: &mut String, id: &[u8; 16]) -> Result<(), FrameError> {
    push_parameter(text, &FederationId16::from_bytes(*id).to_text())
}

fn push_hash(text: &mut String, hash: &[u8; 32]) -> Result<(), FrameError> {
    push_parameter(text, &FederationHash32::from_bytes(*hash).to_text())
}

fn push_u64(text: &mut String, value: u64) -> Result<(), FrameError> {
    reserve(text, 21)?;
    write!(text, " {value}").map_err(|_| FrameError::Overflow)
}

fn push_cursor(text: &mut String, cursor: DeliveryCursor) -> Result<(), FrameError> {
    match cursor {
        DeliveryCursor::Empty => {
            push_parameter(text, "*")?;
            push_parameter(text, "*")
        }
        DeliveryCursor::At {
            delivery_sequence,
            event_id,
        } => {
            push_u64(text, delivery_sequence)?;
            push_id(text, event_id.as_bytes())
        }
    }
}

fn push_snapshot_echo(text: &mut String, identity: &SnapshotIdentity) -> Result<(), FrameError> {
    push_hash(text, identity.snapshot_token.as_bytes())?;
    push_id(text, identity.recovery_epoch.as_bytes())?;
    push_u64(text, identity.projection_generation)?;
    push_u64(text, identity.state_generation)?;
    push_hash(text, identity.snapshot_digest.as_bytes())
}

#[cfg(test)]
#[path = "tests/frames.rs"]
mod tests;
