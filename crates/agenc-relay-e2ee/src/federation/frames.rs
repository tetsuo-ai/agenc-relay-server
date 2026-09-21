//! The companion federation frames (companion Section 12.5): `ECAP`,
//! `EREQUEST`, `EPAYLOAD`, `ERESULT`, `ERESPONSE`, `EEVENT`, `EDATA`,
//! `EACK`, `ERESUME`, `EORIGIN`, `ESTATE`, and the Section 12.5.1
//! `EWITNESS` resolution family, each with exact arity, the Section 11.10
//! token productions, and the 512-byte non-tag bound.
//!
//! Parsing takes the already split command, parameters, and optional
//! fragment tag value; the transport layer owns prefixes and framing.

use crate::error::E2eeError;
use crate::limits::MAX_E2EE_SERVER_PREFIX_BYTES;
use crate::profile::EcapTuple;
use crate::wire::fragment::{FragmentTag, SERVER_FRAGMENT_TAG};
use crate::wire::response::MAX_NON_TAG_LINE_BYTES;
use crate::wire::tokens::{
    base64url_encode, parse_hash, parse_id16, parse_u16, parse_u32, parse_u64,
};

/// The largest S2S tag value (3,999 bytes with its key and `=`).
pub const MAX_S2S_TAG_BYTES: usize = 3_999;
/// The fatal profile violation line, without prefix or CRLF.
pub const PROFILE_MISMATCH_LINE: &str = "ERROR :ARC-MLS profile mismatch";

/// The request or result correlation carried by object-bearing frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Correlation {
    /// The named peer: the coordinator on home-originated frames, the home
    /// server on coordinator-originated frames.
    pub peer_server_id: [u8; 16],
    /// Server incarnation.
    pub server_incarnation: [u8; 16],
    /// Origin identity.
    pub origin_id: [u8; 16],
    /// Origin generation.
    pub origin_generation: u64,
    /// Companion operation sequence.
    pub operation_sequence: u64,
    /// Request identifier.
    pub request_id: [u8; 16],
}

/// The delivery position carried by event frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryPosition {
    /// Target or coordinator server.
    pub server_id: [u8; 16],
    /// Delivery generation.
    pub delivery_generation: u64,
    /// Delivery sequence.
    pub delivery_sequence: u64,
    /// Event identity.
    pub event_id: [u8; 16],
}

/// One companion frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompanionFrame {
    /// `ECAP ARCMLS OFFER ...`.
    EcapOffer(EcapTuple),
    /// `ECAP ARCMLS ACK ...`.
    EcapAck(EcapTuple),
    /// `EREQUEST` with its request object fragment.
    Request {
        /// Correlation.
        correlation: Correlation,
        /// The request object identifier.
        object_id: [u8; 32],
        /// The fragment.
        fragment: FragmentTag,
    },
    /// `EPAYLOAD` with its payload object fragment.
    Payload {
        /// Correlation.
        correlation: Correlation,
        /// The payload object identifier.
        object_id: [u8; 32],
        /// The fragment.
        fragment: FragmentTag,
    },
    /// `ERESULT`.
    Result {
        /// Correlation.
        correlation: Correlation,
        /// The result object identifier.
        object_id: [u8; 32],
        /// The fragment.
        fragment: FragmentTag,
    },
    /// `ERESPONSE`.
    Response {
        /// Correlation.
        correlation: Correlation,
        /// Response index.
        response_index: u16,
        /// The response object identifier.
        object_id: [u8; 32],
        /// The fragment.
        fragment: FragmentTag,
    },
    /// `EEVENT`.
    Event {
        /// Position.
        position: DeliveryPosition,
        /// The event object identifier.
        object_id: [u8; 32],
        /// The fragment.
        fragment: FragmentTag,
    },
    /// `EDATA`.
    Data {
        /// Position.
        position: DeliveryPosition,
        /// The payload object identifier.
        object_id: [u8; 32],
        /// The fragment.
        fragment: FragmentTag,
    },
    /// `EACK`.
    Ack(DeliveryPosition),
    /// `ERESUME`.
    Resume {
        /// Coordinator server.
        coordinator_server_id: [u8; 16],
        /// Server incarnation.
        server_incarnation: [u8; 16],
        /// Delivery generation.
        delivery_generation: u64,
        /// The last acknowledged sequence and event, both or neither.
        last: Option<(u64, [u8; 16])>,
    },
    /// `ERESUME OK`.
    ResumeOk {
        /// Target server.
        target_server_id: [u8; 16],
        /// Server incarnation.
        server_incarnation: [u8; 16],
        /// Delivery generation.
        delivery_generation: u64,
        /// Next delivery sequence.
        next_delivery_sequence: u64,
    },
    /// `EORIGIN RESET`.
    OriginReset {
        /// Coordinator server.
        coordinator_server_id: [u8; 16],
        /// Server incarnation.
        server_incarnation: [u8; 16],
    },
    /// `EORIGIN READY`.
    OriginReady {
        /// Home server.
        home_server_id: [u8; 16],
        /// Server incarnation.
        server_incarnation: [u8; 16],
    },
    /// `EORIGIN ADD` or `EORIGIN UPDATE`.
    OriginState {
        /// Whether this is an update (true) or an add (false).
        update: bool,
        /// Coordinator server.
        coordinator_server_id: [u8; 16],
        /// Server incarnation.
        server_incarnation: [u8; 16],
        /// Origin identity.
        origin_id: [u8; 16],
        /// Origin generation.
        origin_generation: u64,
        /// The origin state object identifier.
        object_id: [u8; 32],
        /// The fragment.
        fragment: FragmentTag,
    },
    /// `EORIGIN DEL`.
    OriginDel {
        /// Coordinator server.
        coordinator_server_id: [u8; 16],
        /// Server incarnation.
        server_incarnation: [u8; 16],
        /// Origin identity.
        origin_id: [u8; 16],
        /// Origin generation.
        origin_generation: u64,
        /// The next unused operation sequence.
        next_operation_sequence: u64,
    },
    /// `EORIGIN ACK`.
    OriginAck {
        /// Home server.
        home_server_id: [u8; 16],
        /// Server incarnation.
        server_incarnation: [u8; 16],
        /// Origin identity.
        origin_id: [u8; 16],
        /// Origin generation.
        origin_generation: u64,
        /// The acknowledged state object, or `*` for a DEL.
        object_id: Option<[u8; 32]>,
    },
    /// `ESTATE BEGIN`.
    StateBegin {
        /// Target server.
        target_server_id: [u8; 16],
        /// Snapshot token.
        snapshot_token: [u8; 32],
        /// State generation.
        state_generation: u64,
        /// Delivery generation.
        delivery_generation: u64,
        /// Page sequence.
        page_sequence: u32,
        /// Total entry count.
        total_entry_count: u32,
        /// Entries in this page.
        page_entry_count: u32,
        /// Snapshot digest.
        snapshot_digest: [u8; 32],
    },
    /// `ESTATE ENTRY`.
    StateEntry {
        /// Target server.
        target_server_id: [u8; 16],
        /// Snapshot token.
        snapshot_token: [u8; 32],
        /// Page sequence.
        page_sequence: u32,
        /// Conversation identifier.
        conversation_id: [u8; 32],
        /// The route state object identifier.
        object_id: [u8; 32],
        /// The fragment.
        fragment: FragmentTag,
    },
    /// `ESTATE END`.
    StateEnd {
        /// Target server.
        target_server_id: [u8; 16],
        /// Snapshot token.
        snapshot_token: [u8; 32],
        /// Page sequence.
        page_sequence: u32,
        /// The next cursor, or `*` on the final page.
        next_cursor: Option<[u8; 32]>,
    },
    /// `ESTATE FETCH`.
    StateFetch {
        /// Coordinator server.
        coordinator_server_id: [u8; 16],
        /// Snapshot token.
        snapshot_token: [u8; 32],
        /// The next page sequence.
        next_page_sequence: u32,
        /// The cursor from the previous END.
        cursor: [u8; 32],
    },
    /// `ESTATE READY` (edge) or `ESTATE ACTIVE` (coordinator).
    StateCut {
        /// Whether this is ACTIVE (true) or READY (false).
        active: bool,
        /// The named peer.
        server_id: [u8; 16],
        /// Snapshot token.
        snapshot_token: [u8; 32],
        /// State generation.
        state_generation: u64,
        /// Delivery generation.
        delivery_generation: u64,
        /// Snapshot digest.
        snapshot_digest: [u8; 32],
    },
    /// `EWITNESS REQUEST` (12.5.1): one durable `witness/v1` row asks the
    /// coordinator how its retained chain continues.
    WitnessRequest {
        /// Coordinator server.
        coordinator_server_id: [u8; 16],
        /// Conversation identifier.
        conversation_id: [u8; 32],
        /// The route sequence the edge expects next.
        expected_sequence: u64,
        /// The head identifier the edge retained.
        expected_head_id: [u8; 32],
    },
    /// `EWITNESS BEGIN` with its one `witness_resolution` object.
    WitnessBegin {
        /// Target edge server.
        target_server_id: [u8; 16],
        /// Conversation identifier.
        conversation_id: [u8; 32],
        /// The token of this one open resolution.
        resolution_token: [u8; 16],
        /// The resolution object identifier.
        object_id: [u8; 32],
        /// The fragment.
        fragment: FragmentTag,
    },
    /// `EWITNESS ENTRY` with one `sequencer_record` object.
    WitnessEntry {
        /// Target edge server.
        target_server_id: [u8; 16],
        /// The token of the open resolution.
        resolution_token: [u8; 16],
        /// The record position inside the set, counted from zero.
        entry_sequence: u32,
        /// The record object identifier.
        object_id: [u8; 32],
        /// The fragment.
        fragment: FragmentTag,
    },
    /// `EWITNESS END`.
    WitnessEnd {
        /// Target edge server.
        target_server_id: [u8; 16],
        /// The token of the open resolution.
        resolution_token: [u8; 16],
        /// The delivered record count.
        record_count: u32,
    },
    /// `EWITNESS RESOLVED`: the durable installation stands.
    WitnessResolved {
        /// Coordinator server.
        coordinator_server_id: [u8; 16],
        /// Conversation identifier.
        conversation_id: [u8; 32],
        /// The token of the resolution installed.
        resolution_token: [u8; 16],
        /// The installed head's route sequence.
        new_head_sequence: u64,
        /// The installed head's semantic identifier.
        new_head_id: [u8; 32],
    },
}

/// Whether `command` is a companion frame command.
#[must_use]
pub fn is_companion_command(command: &str) -> bool {
    matches!(
        command,
        "ECAP"
            | "EREQUEST"
            | "EPAYLOAD"
            | "ERESULT"
            | "ERESPONSE"
            | "EEVENT"
            | "EDATA"
            | "EACK"
            | "ERESUME"
            | "EORIGIN"
            | "ESTATE"
            | "EWITNESS"
    )
}

fn correlation(params: &[&str]) -> Result<Correlation, E2eeError> {
    let [peer, incarnation, origin, generation, sequence, request] = params else {
        return Err(E2eeError::InvalidValue);
    };
    Ok(Correlation {
        peer_server_id: parse_id16(peer)?,
        server_incarnation: parse_id16(incarnation)?,
        origin_id: parse_id16(origin)?,
        origin_generation: parse_u64(generation)?,
        operation_sequence: parse_u64(sequence)?,
        request_id: parse_id16(request)?,
    })
}

fn position(params: &[&str]) -> Result<DeliveryPosition, E2eeError> {
    let [server, generation, sequence, event] = params else {
        return Err(E2eeError::InvalidValue);
    };
    Ok(DeliveryPosition {
        server_id: parse_id16(server)?,
        delivery_generation: parse_u64(generation)?,
        delivery_sequence: parse_u64(sequence)?,
        event_id: parse_id16(event)?,
    })
}

/// The fragment of an object-bearing frame; the explicit object ID must
/// equal the tag's object ID.
fn fragment(tag: Option<&str>, object_id: &[u8; 32]) -> Result<FragmentTag, E2eeError> {
    let raw = tag.ok_or(E2eeError::InvalidValue)?;
    let fragment = FragmentTag::parse(raw)?;
    if fragment.object_id.as_bytes() != object_id {
        return Err(E2eeError::ObjectIdMismatch);
    }
    Ok(fragment)
}

/// Parses one companion frame from its command, parameters, and optional
/// fragment tag value.
pub fn parse_companion_frame(
    command: &str,
    params: &[&str],
    tag: Option<&str>,
) -> Result<CompanionFrame, E2eeError> {
    let frame = match command {
        "ECAP" => parse_ecap(params)?,
        "EREQUEST" | "EPAYLOAD" | "ERESULT" => parse_operation(command, params, tag)?,
        "ERESPONSE" => parse_response(params, tag)?,
        "EEVENT" | "EDATA" => parse_event(command, params, tag)?,
        "EACK" => CompanionFrame::Ack(position(params)?),
        "ERESUME" => parse_resume(params)?,
        "EORIGIN" => parse_origin(params, tag)?,
        "ESTATE" => parse_state(params, tag)?,
        "EWITNESS" => parse_witness(params, tag)?,
        _ => return Err(E2eeError::UnknownDiscriminant),
    };
    if !frame.carries_object() && tag.is_some() {
        return Err(E2eeError::InvalidValue);
    }
    Ok(frame)
}

fn parse_ecap(params: &[&str]) -> Result<CompanionFrame, E2eeError> {
    match params {
        ["ARCMLS", "OFFER", rest @ ..] => EcapTuple::parse(rest).map(CompanionFrame::EcapOffer),
        ["ARCMLS", "ACK", rest @ ..] => EcapTuple::parse(rest).map(CompanionFrame::EcapAck),
        _ => Err(E2eeError::InvalidValue),
    }
}

fn parse_operation(
    command: &str,
    params: &[&str],
    tag: Option<&str>,
) -> Result<CompanionFrame, E2eeError> {
    let (head, object) = params.split_at_checked(6).ok_or(E2eeError::InvalidValue)?;
    let [object] = object else {
        return Err(E2eeError::InvalidValue);
    };
    let correlation = correlation(head)?;
    let object_id = parse_hash(object)?;
    let fragment = fragment(tag, &object_id)?;
    Ok(match command {
        "EREQUEST" => CompanionFrame::Request {
            correlation,
            object_id,
            fragment,
        },
        "EPAYLOAD" => CompanionFrame::Payload {
            correlation,
            object_id,
            fragment,
        },
        _ => CompanionFrame::Result {
            correlation,
            object_id,
            fragment,
        },
    })
}

fn parse_response(params: &[&str], tag: Option<&str>) -> Result<CompanionFrame, E2eeError> {
    let (head, rest) = params.split_at_checked(6).ok_or(E2eeError::InvalidValue)?;
    let [index, object] = rest else {
        return Err(E2eeError::InvalidValue);
    };
    let object_id = parse_hash(object)?;
    Ok(CompanionFrame::Response {
        correlation: correlation(head)?,
        response_index: parse_u16(index)?,
        object_id,
        fragment: fragment(tag, &object_id)?,
    })
}

fn parse_event(
    command: &str,
    params: &[&str],
    tag: Option<&str>,
) -> Result<CompanionFrame, E2eeError> {
    let (head, object) = params.split_at_checked(4).ok_or(E2eeError::InvalidValue)?;
    let [object] = object else {
        return Err(E2eeError::InvalidValue);
    };
    let position = position(head)?;
    let object_id = parse_hash(object)?;
    let fragment = fragment(tag, &object_id)?;
    Ok(if command == "EEVENT" {
        CompanionFrame::Event {
            position,
            object_id,
            fragment,
        }
    } else {
        CompanionFrame::Data {
            position,
            object_id,
            fragment,
        }
    })
}

fn parse_resume(params: &[&str]) -> Result<CompanionFrame, E2eeError> {
    match params {
        ["OK", target, incarnation, generation, next] => Ok(CompanionFrame::ResumeOk {
            target_server_id: parse_id16(target)?,
            server_incarnation: parse_id16(incarnation)?,
            delivery_generation: parse_u64(generation)?,
            next_delivery_sequence: parse_u64(next)?,
        }),
        [coordinator, incarnation, generation, "*", "*"] => Ok(CompanionFrame::Resume {
            coordinator_server_id: parse_id16(coordinator)?,
            server_incarnation: parse_id16(incarnation)?,
            delivery_generation: parse_u64(generation)?,
            last: None,
        }),
        [coordinator, incarnation, generation, sequence, event] => Ok(CompanionFrame::Resume {
            coordinator_server_id: parse_id16(coordinator)?,
            server_incarnation: parse_id16(incarnation)?,
            delivery_generation: parse_u64(generation)?,
            last: Some((parse_u64(sequence)?, parse_id16(event)?)),
        }),
        _ => Err(E2eeError::InvalidValue),
    }
}

fn parse_origin(params: &[&str], tag: Option<&str>) -> Result<CompanionFrame, E2eeError> {
    Ok(match params {
        ["RESET", coordinator, incarnation] => CompanionFrame::OriginReset {
            coordinator_server_id: parse_id16(coordinator)?,
            server_incarnation: parse_id16(incarnation)?,
        },
        ["READY", home, incarnation] => CompanionFrame::OriginReady {
            home_server_id: parse_id16(home)?,
            server_incarnation: parse_id16(incarnation)?,
        },
        [
            verb @ ("ADD" | "UPDATE"),
            coordinator,
            incarnation,
            origin,
            generation,
            object,
        ] => {
            let object_id = parse_hash(object)?;
            CompanionFrame::OriginState {
                update: *verb == "UPDATE",
                coordinator_server_id: parse_id16(coordinator)?,
                server_incarnation: parse_id16(incarnation)?,
                origin_id: parse_id16(origin)?,
                origin_generation: parse_u64(generation)?,
                object_id,
                fragment: fragment(tag, &object_id)?,
            }
        }
        ["DEL", coordinator, incarnation, origin, generation, next] => CompanionFrame::OriginDel {
            coordinator_server_id: parse_id16(coordinator)?,
            server_incarnation: parse_id16(incarnation)?,
            origin_id: parse_id16(origin)?,
            origin_generation: parse_u64(generation)?,
            next_operation_sequence: parse_u64(next)?,
        },
        ["ACK", home, incarnation, origin, generation, object] => CompanionFrame::OriginAck {
            home_server_id: parse_id16(home)?,
            server_incarnation: parse_id16(incarnation)?,
            origin_id: parse_id16(origin)?,
            origin_generation: parse_u64(generation)?,
            object_id: if *object == "*" {
                None
            } else {
                Some(parse_hash(object)?)
            },
        },
        _ => return Err(E2eeError::InvalidValue),
    })
}

fn parse_state(params: &[&str], tag: Option<&str>) -> Result<CompanionFrame, E2eeError> {
    match params.first().copied() {
        Some("BEGIN" | "ENTRY") => parse_state_page(params, tag),
        _ => parse_state_control(params),
    }
}

fn parse_state_page(params: &[&str], tag: Option<&str>) -> Result<CompanionFrame, E2eeError> {
    Ok(match params {
        [
            "BEGIN",
            target,
            token,
            state,
            delivery,
            page,
            total,
            count,
            digest,
        ] => CompanionFrame::StateBegin {
            target_server_id: parse_id16(target)?,
            snapshot_token: parse_hash(token)?,
            state_generation: parse_u64(state)?,
            delivery_generation: parse_u64(delivery)?,
            page_sequence: parse_u32(page)?,
            total_entry_count: parse_u32(total)?,
            page_entry_count: parse_u32(count)?,
            snapshot_digest: parse_hash(digest)?,
        },
        ["ENTRY", target, token, page, conversation, object] => {
            let object_id = parse_hash(object)?;
            CompanionFrame::StateEntry {
                target_server_id: parse_id16(target)?,
                snapshot_token: parse_hash(token)?,
                page_sequence: parse_u32(page)?,
                conversation_id: parse_hash(conversation)?,
                object_id,
                fragment: fragment(tag, &object_id)?,
            }
        }
        _ => return Err(E2eeError::InvalidValue),
    })
}

fn parse_state_control(params: &[&str]) -> Result<CompanionFrame, E2eeError> {
    Ok(match params {
        ["END", target, token, page, cursor] => CompanionFrame::StateEnd {
            target_server_id: parse_id16(target)?,
            snapshot_token: parse_hash(token)?,
            page_sequence: parse_u32(page)?,
            next_cursor: if *cursor == "*" {
                None
            } else {
                Some(parse_hash(cursor)?)
            },
        },
        ["FETCH", coordinator, token, page, cursor] => CompanionFrame::StateFetch {
            coordinator_server_id: parse_id16(coordinator)?,
            snapshot_token: parse_hash(token)?,
            next_page_sequence: parse_u32(page)?,
            cursor: parse_hash(cursor)?,
        },
        [
            verb @ ("READY" | "ACTIVE"),
            server,
            token,
            state,
            delivery,
            digest,
        ] => CompanionFrame::StateCut {
            active: *verb == "ACTIVE",
            server_id: parse_id16(server)?,
            snapshot_token: parse_hash(token)?,
            state_generation: parse_u64(state)?,
            delivery_generation: parse_u64(delivery)?,
            snapshot_digest: parse_hash(digest)?,
        },
        _ => return Err(E2eeError::InvalidValue),
    })
}

fn parse_witness(params: &[&str], tag: Option<&str>) -> Result<CompanionFrame, E2eeError> {
    match params.first().copied() {
        Some("BEGIN" | "ENTRY") => parse_witness_delivery(params, tag),
        _ => parse_witness_control(params),
    }
}

fn parse_witness_delivery(params: &[&str], tag: Option<&str>) -> Result<CompanionFrame, E2eeError> {
    Ok(match params {
        ["BEGIN", target, conversation, token, object] => {
            let object_id = parse_hash(object)?;
            CompanionFrame::WitnessBegin {
                target_server_id: parse_id16(target)?,
                conversation_id: parse_hash(conversation)?,
                resolution_token: parse_id16(token)?,
                object_id,
                fragment: fragment(tag, &object_id)?,
            }
        }
        ["ENTRY", target, token, entry, object] => {
            let object_id = parse_hash(object)?;
            CompanionFrame::WitnessEntry {
                target_server_id: parse_id16(target)?,
                resolution_token: parse_id16(token)?,
                entry_sequence: parse_u32(entry)?,
                object_id,
                fragment: fragment(tag, &object_id)?,
            }
        }
        _ => return Err(E2eeError::InvalidValue),
    })
}

fn parse_witness_control(params: &[&str]) -> Result<CompanionFrame, E2eeError> {
    Ok(match params {
        ["REQUEST", coordinator, conversation, sequence, head] => CompanionFrame::WitnessRequest {
            coordinator_server_id: parse_id16(coordinator)?,
            conversation_id: parse_hash(conversation)?,
            expected_sequence: parse_u64(sequence)?,
            expected_head_id: parse_hash(head)?,
        },
        ["END", target, token, count] => CompanionFrame::WitnessEnd {
            target_server_id: parse_id16(target)?,
            resolution_token: parse_id16(token)?,
            record_count: parse_u32(count)?,
        },
        ["RESOLVED", coordinator, conversation, token, sequence, head] => {
            CompanionFrame::WitnessResolved {
                coordinator_server_id: parse_id16(coordinator)?,
                conversation_id: parse_hash(conversation)?,
                resolution_token: parse_id16(token)?,
                new_head_sequence: parse_u64(sequence)?,
                new_head_id: parse_hash(head)?,
            }
        }
        _ => return Err(E2eeError::InvalidValue),
    })
}

fn id(bytes: &[u8]) -> String {
    base64url_encode(bytes)
}

fn star(hash: Option<&[u8; 32]>) -> String {
    hash.map_or_else(|| "*".to_owned(), |hash| id(hash))
}

impl CompanionFrame {
    /// The fragment carried by an object-bearing frame.
    #[must_use]
    pub const fn fragment(&self) -> Option<&FragmentTag> {
        match self {
            Self::Request { fragment, .. }
            | Self::Payload { fragment, .. }
            | Self::Result { fragment, .. }
            | Self::Response { fragment, .. }
            | Self::Event { fragment, .. }
            | Self::Data { fragment, .. }
            | Self::OriginState { fragment, .. }
            | Self::StateEntry { fragment, .. }
            | Self::WitnessBegin { fragment, .. }
            | Self::WitnessEntry { fragment, .. } => Some(fragment),
            _ => None,
        }
    }

    /// Whether the frame carries an object fragment.
    #[must_use]
    pub const fn carries_object(&self) -> bool {
        self.fragment().is_some()
    }

    /// Whether a coordinator sends this frame (true) or a home edge (false).
    #[must_use]
    pub const fn from_coordinator(&self) -> bool {
        matches!(
            self,
            Self::Result { .. }
                | Self::Response { .. }
                | Self::Event { .. }
                | Self::Data { .. }
                | Self::ResumeOk { .. }
                | Self::OriginReady { .. }
                | Self::OriginAck { .. }
                | Self::StateBegin { .. }
                | Self::StateEntry { .. }
                | Self::StateEnd { .. }
                | Self::StateCut { active: true, .. }
                | Self::WitnessBegin { .. }
                | Self::WitnessEntry { .. }
                | Self::WitnessEnd { .. }
        )
    }

    /// The command token.
    #[must_use]
    pub const fn command(&self) -> &'static str {
        match self {
            Self::EcapOffer(_) | Self::EcapAck(_) => "ECAP",
            Self::Request { .. } => "EREQUEST",
            Self::Payload { .. } => "EPAYLOAD",
            Self::Result { .. } => "ERESULT",
            Self::Response { .. } => "ERESPONSE",
            Self::Event { .. } => "EEVENT",
            Self::Data { .. } => "EDATA",
            Self::Ack(_) => "EACK",
            Self::Resume { .. } | Self::ResumeOk { .. } => "ERESUME",
            Self::OriginReset { .. }
            | Self::OriginReady { .. }
            | Self::OriginState { .. }
            | Self::OriginDel { .. }
            | Self::OriginAck { .. } => "EORIGIN",
            Self::StateBegin { .. }
            | Self::StateEntry { .. }
            | Self::StateEnd { .. }
            | Self::StateFetch { .. }
            | Self::StateCut { .. } => "ESTATE",
            Self::WitnessRequest { .. }
            | Self::WitnessBegin { .. }
            | Self::WitnessEntry { .. }
            | Self::WitnessEnd { .. }
            | Self::WitnessResolved { .. } => "EWITNESS",
        }
    }

    /// The parameters after the command.
    #[must_use]
    pub fn parameters(&self) -> Vec<String> {
        match self {
            Self::EcapOffer(tuple) => with_head(&["ARCMLS", "OFFER"], tuple.render()),
            Self::EcapAck(tuple) => with_head(&["ARCMLS", "ACK"], tuple.render()),
            Self::Request {
                correlation,
                object_id,
                ..
            }
            | Self::Payload {
                correlation,
                object_id,
                ..
            }
            | Self::Result {
                correlation,
                object_id,
                ..
            } => {
                let mut params = correlation_params(correlation);
                params.push(id(object_id));
                params
            }
            Self::Response {
                correlation,
                response_index,
                object_id,
                ..
            } => {
                let mut params = correlation_params(correlation);
                params.push(response_index.to_string());
                params.push(id(object_id));
                params
            }
            Self::Event {
                position,
                object_id,
                ..
            }
            | Self::Data {
                position,
                object_id,
                ..
            } => {
                let mut params = position_params(position);
                params.push(id(object_id));
                params
            }
            Self::Ack(position) => position_params(position),
            Self::Resume { .. } | Self::ResumeOk { .. } => self.resume_parameters(),
            Self::OriginReset { .. }
            | Self::OriginReady { .. }
            | Self::OriginState { .. }
            | Self::OriginDel { .. }
            | Self::OriginAck { .. } => self.origin_parameters(),
            Self::StateBegin { .. } | Self::StateEntry { .. } => self.state_page_parameters(),
            Self::StateEnd { .. } | Self::StateFetch { .. } | Self::StateCut { .. } => {
                self.state_control_parameters()
            }
            Self::WitnessBegin { .. } | Self::WitnessEntry { .. } => {
                self.witness_delivery_parameters()
            }
            Self::WitnessRequest { .. }
            | Self::WitnessEnd { .. }
            | Self::WitnessResolved { .. } => self.witness_control_parameters(),
        }
    }

    fn witness_delivery_parameters(&self) -> Vec<String> {
        match self {
            Self::WitnessBegin {
                target_server_id,
                conversation_id,
                resolution_token,
                object_id,
                ..
            } => vec![
                "BEGIN".to_owned(),
                id(target_server_id),
                id(conversation_id),
                id(resolution_token),
                id(object_id),
            ],
            Self::WitnessEntry {
                target_server_id,
                resolution_token,
                entry_sequence,
                object_id,
                ..
            } => vec![
                "ENTRY".to_owned(),
                id(target_server_id),
                id(resolution_token),
                entry_sequence.to_string(),
                id(object_id),
            ],
            _ => Vec::new(),
        }
    }

    fn witness_control_parameters(&self) -> Vec<String> {
        match self {
            Self::WitnessRequest {
                coordinator_server_id,
                conversation_id,
                expected_sequence,
                expected_head_id,
            } => vec![
                "REQUEST".to_owned(),
                id(coordinator_server_id),
                id(conversation_id),
                expected_sequence.to_string(),
                id(expected_head_id),
            ],
            Self::WitnessEnd {
                target_server_id,
                resolution_token,
                record_count,
            } => vec![
                "END".to_owned(),
                id(target_server_id),
                id(resolution_token),
                record_count.to_string(),
            ],
            Self::WitnessResolved {
                coordinator_server_id,
                conversation_id,
                resolution_token,
                new_head_sequence,
                new_head_id,
            } => vec![
                "RESOLVED".to_owned(),
                id(coordinator_server_id),
                id(conversation_id),
                id(resolution_token),
                new_head_sequence.to_string(),
                id(new_head_id),
            ],
            _ => Vec::new(),
        }
    }

    fn resume_parameters(&self) -> Vec<String> {
        match self {
            Self::Resume {
                coordinator_server_id,
                server_incarnation,
                delivery_generation,
                last,
            } => {
                let mut params = vec![
                    id(coordinator_server_id),
                    id(server_incarnation),
                    delivery_generation.to_string(),
                ];
                params.extend(last_params(*last));
                params
            }
            Self::ResumeOk {
                target_server_id,
                server_incarnation,
                delivery_generation,
                next_delivery_sequence,
            } => vec![
                "OK".to_owned(),
                id(target_server_id),
                id(server_incarnation),
                delivery_generation.to_string(),
                next_delivery_sequence.to_string(),
            ],
            _ => Vec::new(),
        }
    }

    fn origin_parameters(&self) -> Vec<String> {
        match self {
            Self::OriginReset { .. } | Self::OriginReady { .. } => {
                self.origin_handshake_parameters()
            }
            Self::OriginState {
                update,
                coordinator_server_id,
                server_incarnation,
                origin_id,
                origin_generation,
                object_id,
                ..
            } => vec![
                if *update { "UPDATE" } else { "ADD" }.to_owned(),
                id(coordinator_server_id),
                id(server_incarnation),
                id(origin_id),
                origin_generation.to_string(),
                id(object_id),
            ],
            Self::OriginDel {
                coordinator_server_id,
                server_incarnation,
                origin_id,
                origin_generation,
                next_operation_sequence,
            } => vec![
                "DEL".to_owned(),
                id(coordinator_server_id),
                id(server_incarnation),
                id(origin_id),
                origin_generation.to_string(),
                next_operation_sequence.to_string(),
            ],
            Self::OriginAck {
                home_server_id,
                server_incarnation,
                origin_id,
                origin_generation,
                object_id,
            } => vec![
                "ACK".to_owned(),
                id(home_server_id),
                id(server_incarnation),
                id(origin_id),
                origin_generation.to_string(),
                star(object_id.as_ref()),
            ],
            _ => Vec::new(),
        }
    }

    fn origin_handshake_parameters(&self) -> Vec<String> {
        match self {
            Self::OriginReset {
                coordinator_server_id,
                server_incarnation,
            } => vec![
                "RESET".to_owned(),
                id(coordinator_server_id),
                id(server_incarnation),
            ],
            Self::OriginReady {
                home_server_id,
                server_incarnation,
            } => vec![
                "READY".to_owned(),
                id(home_server_id),
                id(server_incarnation),
            ],
            _ => Vec::new(),
        }
    }

    fn state_page_parameters(&self) -> Vec<String> {
        match self {
            Self::StateBegin {
                target_server_id,
                snapshot_token,
                state_generation,
                delivery_generation,
                page_sequence,
                total_entry_count,
                page_entry_count,
                snapshot_digest,
            } => vec![
                "BEGIN".to_owned(),
                id(target_server_id),
                id(snapshot_token),
                state_generation.to_string(),
                delivery_generation.to_string(),
                page_sequence.to_string(),
                total_entry_count.to_string(),
                page_entry_count.to_string(),
                id(snapshot_digest),
            ],
            Self::StateEntry {
                target_server_id,
                snapshot_token,
                page_sequence,
                conversation_id,
                object_id,
                ..
            } => vec![
                "ENTRY".to_owned(),
                id(target_server_id),
                id(snapshot_token),
                page_sequence.to_string(),
                id(conversation_id),
                id(object_id),
            ],
            _ => Vec::new(),
        }
    }

    fn state_control_parameters(&self) -> Vec<String> {
        match self {
            Self::StateEnd {
                target_server_id,
                snapshot_token,
                page_sequence,
                next_cursor,
            } => vec![
                "END".to_owned(),
                id(target_server_id),
                id(snapshot_token),
                page_sequence.to_string(),
                star(next_cursor.as_ref()),
            ],
            Self::StateFetch {
                coordinator_server_id,
                snapshot_token,
                next_page_sequence,
                cursor,
            } => vec![
                "FETCH".to_owned(),
                id(coordinator_server_id),
                id(snapshot_token),
                next_page_sequence.to_string(),
                id(cursor),
            ],
            Self::StateCut {
                active,
                server_id,
                snapshot_token,
                state_generation,
                delivery_generation,
                snapshot_digest,
            } => vec![
                if *active { "ACTIVE" } else { "READY" }.to_owned(),
                id(server_id),
                id(snapshot_token),
                state_generation.to_string(),
                delivery_generation.to_string(),
                id(snapshot_digest),
            ],
            _ => Vec::new(),
        }
    }

    /// Renders the complete line with CRLF under `prefix` (without its
    /// colon), checking the prefix, non-tag, and tag bounds.
    pub fn render(&self, prefix: &str) -> Result<String, E2eeError> {
        // The serialized prefix, colon included, is at most the ceiling.
        if prefix.is_empty()
            || prefix.len() >= MAX_E2EE_SERVER_PREFIX_BYTES
            || prefix.bytes().any(|byte| byte <= b' ')
        {
            return Err(E2eeError::LimitExceeded);
        }
        let mut line = format!(":{prefix} {}", self.command());
        for parameter in self.parameters() {
            line.push(' ');
            line.push_str(&parameter);
        }
        line.push_str("\r\n");
        if line.len() > MAX_NON_TAG_LINE_BYTES {
            return Err(E2eeError::LimitExceeded);
        }
        let Some(fragment) = self.fragment() else {
            return Ok(line);
        };
        let tag = format!("{SERVER_FRAGMENT_TAG}={}", fragment.render());
        if tag.len() > MAX_S2S_TAG_BYTES {
            return Err(E2eeError::LimitExceeded);
        }
        Ok(format!("@{tag} {line}"))
    }
}

fn last_params(last: Option<(u64, [u8; 16])>) -> [String; 2] {
    match last {
        Some((sequence, event)) => [sequence.to_string(), id(&event)],
        None => ["*".to_owned(), "*".to_owned()],
    }
}

fn with_head(head: &[&str], tail: Vec<String>) -> Vec<String> {
    head.iter()
        .map(|word| (*word).to_owned())
        .chain(tail)
        .collect()
}

fn correlation_params(correlation: &Correlation) -> Vec<String> {
    vec![
        id(&correlation.peer_server_id),
        id(&correlation.server_incarnation),
        id(&correlation.origin_id),
        correlation.origin_generation.to_string(),
        correlation.operation_sequence.to_string(),
        id(&correlation.request_id),
    ]
}

fn position_params(position: &DeliveryPosition) -> Vec<String> {
    vec![
        id(&position.server_id),
        position.delivery_generation.to_string(),
        position.delivery_sequence.to_string(),
        id(&position.event_id),
    ]
}

#[cfg(test)]
#[path = "../tests/federation_frames.rs"]
mod tests;
