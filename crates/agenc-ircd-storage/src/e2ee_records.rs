//! Durable companion rows for tables 22 `e2ee_object` and 23 `e2ee_state`
//! (spec 20.8, 23.4, companion 11.6, 12.2 to 12.5, 16, 18.4).
//!
//! Table 22 holds exact validated `IrcWireObject` bytes under their object
//! ID. Table 23 holds typed state under closed ASCII key prefixes; the
//! record kind of a row is fixed by its prefix, and every body is a
//! versioned hand-written codec wrapped in the table- and kind-bound
//! [`ProtocolRecordBody`] envelope so a value accepted for one kind cannot
//! be replayed as another.
//!
//! Key prefixes and record kinds:
//!
//! | prefix | kind | suffix | row |
//! | --- | ---: | --- | --- |
//! | `recovery/v1/` | 1 | conversation ID | [`crate::E2eeRecoveryGate`] |
//! | `route/v1/` | 2 | conversation ID | [`RouteRow`] |
//! | `lock/v1/` | 3 | semantic route lock ID | [`ClaimRow::Lock`] |
//! | `reservation/v1/` | 3 | reservation ID | [`ClaimRow::Reservation`] |
//! | `record/v1/` | 4 | conversation ID, route sequence | [`SequencerRow::Record`] |
//! | `candidate/v1/` | 4 | conversation ID, prior epoch | [`SequencerRow::Candidate`] |
//! | `approval/v1/`, `ack/v1/`, `vote/v1/` | 4 | conversation ID, subject ID, root fingerprint, device ID | [`SequencerRow::Proof`] |
//! | `identity/v1/`, `roster/v1/` | 5 | account digest | [`DirectoryRow`] |
//! | `capability/v1/` | 5 | account digest, device ID | [`DirectoryRow::Capability`] |
//! | `binding-lock/v1/` | 5 | account digest, root fingerprint, sequence | [`DirectoryRow::BindingLock`] |
//! | `package/v1/` | 6 | KeyPackageRef | [`PackageRow::Package`] |
//! | `claim/v1/` | 6 | account digest, operation ID | [`PackageRow::Claim`] |
//! | `attach/v1/` | 7 | account digest, device ID | [`AttachRow`] |
//! | `mailbox/v1/` | 8 | account digest, device ID, kind, sequence | [`MailboxRow::Item`] |
//! | `token/v1/` | 8 | delivery token | [`MailboxRow::Token`] |
//! | `ack-mailbox/v1/` | 8 | account digest, device ID, delivery token | [`MailboxRow::Ack`] |
//! | `replay/v1/irc-mls-v1/` | 9 | home server, incarnation, origin, generation, sequence | [`ReplayRow`] |
//! | `delivery/v1/` | 10 | target server | [`DeliveryRow::Cursor`] |
//! | `outbox/v1/` | 10 | target server, generation, sequence | [`DeliveryRow::Outbox`] |
//! | `estate/v1/` | 10 | target server | [`DeliveryRow::Snapshot`] |
//! | `keyset/v1` | 11 | none | [`KeySetRow`] |
//! | `cross-profile/head/v1/`, `cross-profile/part/v1/` | 12 | Section 20.8 layouts | [`barrier`] |

use agenc_ircd_e2ee::limits::{MAX_FEDERATION_CONTROL_OBJECT, MAX_FINALITY_PRINCIPALS};
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};

use crate::codec::{Decoder, Encoder};
use crate::records::ProtocolRecordBody;
use crate::schema::{MAX_STORED_KEY_BYTES, StoredKey, TableId};
use crate::{MAX_PROTOCOL_BODY_BYTES, ReadPlan, StorageError};

pub mod barrier;

/// The one live `e2ee_object` arm.
pub const OBJECT_RECORD_KIND: u16 = 1;
/// The recovery gate arm, defined in `records.rs`.
pub const RECOVERY_GATE_KIND: u16 = 1;
/// Route rows.
pub const ROUTE_ROW_KIND: u16 = 2;
/// Semantic route lock and reservation rows.
pub const CLAIM_ROW_KIND: u16 = 3;
/// Sequencer log, candidate slot, and proof accumulator rows.
pub const SEQUENCER_ROW_KIND: u16 = 4;
/// Directory head rows.
pub const DIRECTORY_ROW_KIND: u16 = 5;
/// KeyPackage stock and claim rows.
pub const PACKAGE_ROW_KIND: u16 = 6;
/// Device attachment rows.
pub const ATTACH_ROW_KIND: u16 = 7;
/// Mailbox item, token, and acknowledgement rows.
pub const MAILBOX_ROW_KIND: u16 = 8;
/// Companion request replay rows.
pub const REPLAY_ROW_KIND: u16 = 9;
/// Companion delivery cursor, outbox, and ESTATE rows.
pub const DELIVERY_ROW_KIND: u16 = 10;
/// The sequencer key set row.
pub const KEYSET_ROW_KIND: u16 = 11;
/// Cross-profile barrier rows.
pub const BARRIER_ROW_KIND: u16 = 12;

/// Version prefix shared by every companion body codec.
const BODY_VERSION: u16 = 1;
const ID_BYTES: usize = 16;
const HASH_BYTES: usize = 32;
/// Response descriptors retained with a replay row (companion 12.5).
pub const MAX_REPLAY_DESCRIPTORS: usize = 32;
/// Credentials in a key set: the current one and at most its successor.
pub const MAX_KEY_SET_CREDENTIALS: usize = 2;
/// Row limit used by the page helpers.
const PAGE_LIMIT: u16 = 256;

/// Every closed key prefix.
pub mod prefix {
    /// Recovery gate rows (kind 1).
    pub const RECOVERY: &[u8] = b"recovery/v1/";
    /// Route rows.
    pub const ROUTE: &[u8] = b"route/v1/";
    /// Semantic route lock rows.
    pub const LOCK: &[u8] = b"lock/v1/";
    /// Reservation rows.
    pub const RESERVATION: &[u8] = b"reservation/v1/";
    /// Sequencer record rows.
    pub const RECORD: &[u8] = b"record/v1/";
    /// Candidate slot rows.
    pub const CANDIDATE: &[u8] = b"candidate/v1/";
    /// Approval accumulator rows.
    pub const APPROVAL: &[u8] = b"approval/v1/";
    /// ACK accumulator rows.
    pub const ACK: &[u8] = b"ack/v1/";
    /// Finality vote accumulator rows.
    pub const VOTE: &[u8] = b"vote/v1/";
    /// Identity head rows.
    pub const IDENTITY: &[u8] = b"identity/v1/";
    /// Roster head rows.
    pub const ROSTER: &[u8] = b"roster/v1/";
    /// Capability rows.
    pub const CAPABILITY: &[u8] = b"capability/v1/";
    /// Binding lock rows.
    pub const BINDING_LOCK: &[u8] = b"binding-lock/v1/";
    /// KeyPackage rows.
    pub const PACKAGE: &[u8] = b"package/v1/";
    /// Claim rows.
    pub const CLAIM: &[u8] = b"claim/v1/";
    /// Attachment rows.
    pub const ATTACH: &[u8] = b"attach/v1/";
    /// Mailbox item rows.
    pub const MAILBOX: &[u8] = b"mailbox/v1/";
    /// Delivery token rows.
    pub const TOKEN: &[u8] = b"token/v1/";
    /// Mailbox acknowledgement rows.
    pub const ACK_MAILBOX: &[u8] = b"ack-mailbox/v1/";
    /// Companion replay rows.
    pub const REPLAY: &[u8] = b"replay/v1/irc-mls-v1/";
    /// Delivery cursor rows.
    pub const DELIVERY: &[u8] = b"delivery/v1/";
    /// Outbox rows.
    pub const OUTBOX: &[u8] = b"outbox/v1/";
    /// ESTATE rows.
    pub const ESTATE: &[u8] = b"estate/v1/";
    /// The key set row.
    pub const KEYSET: &[u8] = b"keyset/v1";
    /// Barrier head rows.
    pub const BARRIER_HEAD: &[u8] = b"cross-profile/head/v1/";
    /// Barrier part rows.
    pub const BARRIER_PART: &[u8] = b"cross-profile/part/v1/";
}

/// Every `(prefix, record kind)` pair, used by the key classifier.
const PREFIX_KINDS: [(&[u8], u16); 26] = [
    (prefix::RECOVERY, RECOVERY_GATE_KIND),
    (prefix::ROUTE, ROUTE_ROW_KIND),
    (prefix::LOCK, CLAIM_ROW_KIND),
    (prefix::RESERVATION, CLAIM_ROW_KIND),
    (prefix::RECORD, SEQUENCER_ROW_KIND),
    (prefix::CANDIDATE, SEQUENCER_ROW_KIND),
    (prefix::APPROVAL, SEQUENCER_ROW_KIND),
    (prefix::ACK, SEQUENCER_ROW_KIND),
    (prefix::VOTE, SEQUENCER_ROW_KIND),
    (prefix::IDENTITY, DIRECTORY_ROW_KIND),
    (prefix::ROSTER, DIRECTORY_ROW_KIND),
    (prefix::CAPABILITY, DIRECTORY_ROW_KIND),
    (prefix::BINDING_LOCK, DIRECTORY_ROW_KIND),
    (prefix::PACKAGE, PACKAGE_ROW_KIND),
    (prefix::CLAIM, PACKAGE_ROW_KIND),
    (prefix::ATTACH, ATTACH_ROW_KIND),
    (prefix::MAILBOX, MAILBOX_ROW_KIND),
    (prefix::TOKEN, MAILBOX_ROW_KIND),
    (prefix::ACK_MAILBOX, MAILBOX_ROW_KIND),
    (prefix::REPLAY, REPLAY_ROW_KIND),
    (prefix::DELIVERY, DELIVERY_ROW_KIND),
    (prefix::OUTBOX, DELIVERY_ROW_KIND),
    (prefix::ESTATE, DELIVERY_ROW_KIND),
    (prefix::KEYSET, KEYSET_ROW_KIND),
    (prefix::BARRIER_HEAD, BARRIER_ROW_KIND),
    (prefix::BARRIER_PART, BARRIER_ROW_KIND),
];

/// The record kind a table-23 key must carry, from its prefix. `ack/v1/`
/// is matched after `ack-mailbox/v1/` because the classifier takes the
/// longest matching prefix.
pub fn record_kind_for_key(key: &StoredKey) -> Result<u16, StorageError> {
    let bytes = key.as_bytes();
    PREFIX_KINDS
        .iter()
        .filter(|(prefix, _)| bytes.starts_with(prefix))
        .max_by_key(|(prefix, _)| prefix.len())
        .map(|(_, kind)| *kind)
        .ok_or(StorageError::InvalidEncoding)
}

/// Checks that a table-23 key carries the given record kind.
pub fn check_state_key(key: &StoredKey, record_kind: u16) -> Result<(), StorageError> {
    if record_kind_for_key(key)? != record_kind {
        return Err(StorageError::InvalidEncoding);
    }
    Ok(())
}

fn key_of(parts: &[&[u8]]) -> Result<StoredKey, StorageError> {
    let length: usize = parts.iter().map(|part| part.len()).sum();
    if length > MAX_STORED_KEY_BYTES {
        return Err(StorageError::LimitExceeded);
    }
    let mut key = Vec::with_capacity(length);
    for part in parts {
        key.extend_from_slice(part);
    }
    StoredKey::new(key)
}

/// The exclusive upper bound of every key under `prefix`: the prefix padded
/// with `0xff` to the largest stored key, which sorts after every shorter
/// key sharing the prefix.
fn prefix_end(prefix: &[u8]) -> Result<StoredKey, StorageError> {
    let padding = MAX_STORED_KEY_BYTES
        .checked_sub(prefix.len())
        .ok_or(StorageError::LimitExceeded)?;
    key_of(&[prefix, &vec![0xff; padding]])
}

/// A bounded range read over every key under `prefix`.
pub fn prefix_range(prefix: &[u8], limit: u16) -> Result<ReadPlan, StorageError> {
    let start = key_of(&[prefix])?;
    ReadPlan::range(
        TableId::E2eeState,
        start,
        prefix_end(prefix)?,
        limit.clamp(1, PAGE_LIMIT),
    )
}

/// A bounded range read from `start` (inclusive) to the end of `prefix`.
pub fn prefix_range_from(
    prefix: &[u8],
    start: &StoredKey,
    limit: u16,
) -> Result<ReadPlan, StorageError> {
    if !start.as_bytes().starts_with(prefix) {
        return Err(StorageError::InvalidEncoding);
    }
    ReadPlan::range(
        TableId::E2eeState,
        StoredKey::new(start.as_bytes().to_vec())?,
        prefix_end(prefix)?,
        limit.clamp(1, PAGE_LIMIT),
    )
}

// ---------------------------------------------------------------------------
// Table 22: exact objects.

/// The exact validated object stored under its ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectRow {
    /// The complete encoded `IrcWireObject`.
    pub bytes: Vec<u8>,
}

impl ObjectRow {
    /// Wraps validated object bytes; the envelope peek enforces the kind's
    /// maximum and the declared length.
    pub fn new(bytes: Vec<u8>) -> Result<Self, StorageError> {
        IrcWireObject::peek(&bytes).map_err(|_| StorageError::InvalidEncoding)?;
        Ok(Self { bytes })
    }

    /// The object kind from the envelope.
    pub fn kind(&self) -> Result<IrcWireObjectKind, StorageError> {
        IrcWireObject::peek(&self.bytes)
            .map(|(kind, _)| kind)
            .map_err(|_| StorageError::InvalidEncoding)
    }

    /// The table-22 key: the object ID.
    pub fn key(&self) -> Result<StoredKey, StorageError> {
        StoredKey::new(
            agenc_ircd_e2ee::ObjectId::compute(&self.bytes)
                .as_bytes()
                .to_vec(),
        )
    }

    /// Encodes the wrapped body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        ProtocolRecordBody::new(
            TableId::E2eeObject,
            OBJECT_RECORD_KIND,
            1,
            self.bytes.clone(),
        )?
        .encode()
    }

    /// Decodes one wrapped body.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = ProtocolRecordBody::decode(TableId::E2eeObject, OBJECT_RECORD_KIND, body)?;
        Self::new(inner.canonical_object().to_vec())
    }
}

/// The table-22 key for an object ID.
pub fn object_key(object_id: &[u8; HASH_BYTES]) -> Result<StoredKey, StorageError> {
    StoredKey::new(object_id.to_vec())
}

// ---------------------------------------------------------------------------
// Shared codec helpers.

fn wrap(kind: u16, inner: Vec<u8>) -> Result<Vec<u8>, StorageError> {
    ProtocolRecordBody::new(TableId::E2eeState, kind, 1, inner)?.encode()
}

fn unwrap(kind: u16, body: &[u8]) -> Result<Vec<u8>, StorageError> {
    Ok(ProtocolRecordBody::decode(TableId::E2eeState, kind, body)?
        .canonical_object()
        .to_vec())
}

fn encoder() -> Result<Encoder, StorageError> {
    let mut encoder = Encoder::with_capacity(256, MAX_PROTOCOL_BODY_BYTES)?;
    encoder.put_u16(BODY_VERSION)?;
    Ok(encoder)
}

fn decoder(inner: &[u8]) -> Result<Decoder<'_>, StorageError> {
    let mut decoder = Decoder::new(inner);
    if decoder.u16()? != BODY_VERSION {
        return Err(StorageError::UnsupportedVersion);
    }
    Ok(decoder)
}

fn put_bool(encoder: &mut Encoder, value: bool) -> Result<(), StorageError> {
    encoder.put_u16(u16::from(value))
}

fn take_bool(decoder: &mut Decoder<'_>) -> Result<bool, StorageError> {
    match decoder.u16()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(StorageError::InvalidEncoding),
    }
}

fn put_optional_hash(
    encoder: &mut Encoder,
    value: Option<&[u8; HASH_BYTES]>,
) -> Result<(), StorageError> {
    encoder.put_vector_u32(value.map_or(&[][..], |hash| &hash[..]))
}

fn take_optional_hash(decoder: &mut Decoder<'_>) -> Result<Option<[u8; HASH_BYTES]>, StorageError> {
    let bytes = decoder.vector_u32(HASH_BYTES)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    bytes
        .try_into()
        .map(Some)
        .map_err(|_| StorageError::InvalidEncoding)
}

fn put_hashes(
    encoder: &mut Encoder,
    hashes: &[[u8; HASH_BYTES]],
    maximum: usize,
) -> Result<(), StorageError> {
    if hashes.len() > maximum {
        return Err(StorageError::LimitExceeded);
    }
    encoder.put_u16(u16::try_from(hashes.len()).map_err(|_| StorageError::Overflow)?)?;
    for hash in hashes {
        encoder.put_fixed(hash)?;
    }
    Ok(())
}

fn take_hashes(
    decoder: &mut Decoder<'_>,
    maximum: usize,
) -> Result<Vec<[u8; HASH_BYTES]>, StorageError> {
    let count = usize::from(decoder.u16()?);
    if count > maximum {
        return Err(StorageError::LimitExceeded);
    }
    let mut hashes = Vec::with_capacity(count);
    for _ in 0..count {
        hashes.push(decoder.array::<HASH_BYTES>()?);
    }
    Ok(hashes)
}

fn slice_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], StorageError> {
    let end = offset.checked_add(N).ok_or(StorageError::Overflow)?;
    bytes
        .get(offset..end)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(StorageError::InvalidEncoding)
}

fn suffix<'a>(key: &'a StoredKey, prefix: &[u8], length: usize) -> Result<&'a [u8], StorageError> {
    let bytes = key.as_bytes();
    let rest = bytes
        .strip_prefix(prefix)
        .ok_or(StorageError::InvalidEncoding)?;
    if rest.len() != length {
        return Err(StorageError::InvalidEncoding);
    }
    Ok(rest)
}

// ---------------------------------------------------------------------------
// Kind 1 and 2: recovery gate key and route rows.

/// The `recovery/v1/<conversation-id>` key of a kind-1 gate.
pub fn recovery_gate_key(conversation_id: &[u8; HASH_BYTES]) -> Result<StoredKey, StorageError> {
    key_of(&[prefix::RECOVERY, conversation_id])
}

/// The lifecycle of a route row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteLifecycle {
    /// Traffic flows.
    Active,
    /// A close intent is committed; traffic still flows.
    Closing,
    /// An encrypted tombstone; nothing flows and plaintext stays refused.
    Tombstone,
}

impl RouteLifecycle {
    const fn wire_value(self) -> u16 {
        match self {
            Self::Active => 1,
            Self::Closing => 2,
            Self::Tombstone => 3,
        }
    }

    const fn from_wire(value: u16) -> Result<Self, StorageError> {
        match value {
            1 => Ok(Self::Active),
            2 => Ok(Self::Closing),
            3 => Ok(Self::Tombstone),
            _ => Err(StorageError::InvalidEncoding),
        }
    }
}

/// The authoritative route row: the exact encoded `IrcFederationRouteState`
/// plus the lineage the coordinator needs to project and recover it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteRow {
    /// The exact TLS encoding of the current `IrcFederationRouteState`.
    pub route_state: Vec<u8>,
    /// Lifecycle.
    pub lifecycle: RouteLifecycle,
    /// The current binding identifier.
    pub binding_id: [u8; HASH_BYTES],
    /// The semantic route lock identifier.
    pub lock_id: [u8; HASH_BYTES],
    /// The accepted state identifier.
    pub accepted_state_id: [u8; HASH_BYTES],
    /// The sequencer head record identifier.
    pub sequencer_head_id: [u8; HASH_BYTES],
    /// The highest route sequence.
    pub route_sequence: u64,
    /// The close identifier once closing or tombstoned.
    pub close_id: Option<[u8; HASH_BYTES]>,
    /// The predecessor close identifier for a recreated route.
    pub predecessor_close_id: Option<[u8; HASH_BYTES]>,
    /// Whether a kind-1 recovery gate row exists for this conversation.
    pub recovery_gate: bool,
    /// Retained object bytes charged to this conversation.
    pub stored_bytes: u64,
}

impl RouteRow {
    /// The `route/v1/<conversation-id>` key.
    pub fn key(conversation_id: &[u8; HASH_BYTES]) -> Result<StoredKey, StorageError> {
        key_of(&[prefix::ROUTE, conversation_id])
    }

    /// Splits a route key.
    pub fn parse_key(key: &StoredKey) -> Result<[u8; HASH_BYTES], StorageError> {
        slice_array(suffix(key, prefix::ROUTE, HASH_BYTES)?, 0)
    }

    /// Encodes the wrapped body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        if self.route_state.is_empty() || self.route_state.len() > MAX_FEDERATION_CONTROL_OBJECT {
            return Err(StorageError::LimitExceeded);
        }
        let mut encoder = encoder()?;
        encoder.put_vector_u32(&self.route_state)?;
        encoder.put_u16(self.lifecycle.wire_value())?;
        encoder.put_fixed(&self.binding_id)?;
        encoder.put_fixed(&self.lock_id)?;
        encoder.put_fixed(&self.accepted_state_id)?;
        encoder.put_fixed(&self.sequencer_head_id)?;
        encoder.put_u64(self.route_sequence)?;
        put_optional_hash(&mut encoder, self.close_id.as_ref())?;
        put_optional_hash(&mut encoder, self.predecessor_close_id.as_ref())?;
        put_bool(&mut encoder, self.recovery_gate)?;
        encoder.put_u64(self.stored_bytes)?;
        wrap(ROUTE_ROW_KIND, encoder.finish())
    }

    /// Decodes one wrapped body.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = unwrap(ROUTE_ROW_KIND, body)?;
        let mut decoder = decoder(&inner)?;
        let route_state = decoder.vector_u32(MAX_FEDERATION_CONTROL_OBJECT)?.to_vec();
        if route_state.is_empty() {
            return Err(StorageError::InvalidEncoding);
        }
        let row = Self {
            route_state,
            lifecycle: RouteLifecycle::from_wire(decoder.u16()?)?,
            binding_id: decoder.array()?,
            lock_id: decoder.array()?,
            accepted_state_id: decoder.array()?,
            sequencer_head_id: decoder.array()?,
            route_sequence: decoder.u64()?,
            close_id: take_optional_hash(&mut decoder)?,
            predecessor_close_id: take_optional_hash(&mut decoder)?,
            recovery_gate: take_bool(&mut decoder)?,
            stored_bytes: decoder.u64()?,
        };
        decoder.finish()?;
        if row.lifecycle != RouteLifecycle::Active && row.close_id.is_none() {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(row)
    }
}

// ---------------------------------------------------------------------------
// Kind 3: lock and reservation rows.

/// A semantic route lock or a reservation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimRow {
    /// The conversation currently holding a semantic route lock.
    Lock {
        /// Conversation identifier.
        conversation_id: [u8; HASH_BYTES],
        /// Binding identifier.
        binding_id: [u8; HASH_BYTES],
        /// Semantic incarnation of the route.
        incarnation: u64,
    },
    /// A reservation awaiting its BIND.
    Reservation {
        /// Owner account digest.
        owner_account_digest: [u8; HASH_BYTES],
        /// Owner device.
        owner_device_id: [u8; ID_BYTES],
        /// Conversation kind value (companion `IrcConversationKind`).
        kind: u16,
        /// Semantic route lock identifier.
        lock_id: [u8; HASH_BYTES],
        /// Route binding.
        route_binding: [u8; HASH_BYTES],
        /// The retained reservation object identifier.
        reservation_object_id: [u8; HASH_BYTES],
        /// Expiry second.
        expires_at: u64,
    },
}

const LOCK_ARM: u16 = 1;
const RESERVATION_ARM: u16 = 2;

impl ClaimRow {
    /// The `lock/v1/<lock-id>` key.
    pub fn lock_key(lock_id: &[u8; HASH_BYTES]) -> Result<StoredKey, StorageError> {
        key_of(&[prefix::LOCK, lock_id])
    }

    /// The `reservation/v1/<reservation-id>` key.
    pub fn reservation_key(reservation_id: &[u8; ID_BYTES]) -> Result<StoredKey, StorageError> {
        key_of(&[prefix::RESERVATION, reservation_id])
    }

    /// Encodes the wrapped body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let mut encoder = encoder()?;
        match self {
            Self::Lock {
                conversation_id,
                binding_id,
                incarnation,
            } => {
                encoder.put_u16(LOCK_ARM)?;
                encoder.put_fixed(conversation_id)?;
                encoder.put_fixed(binding_id)?;
                encoder.put_u64(*incarnation)?;
            }
            Self::Reservation {
                owner_account_digest,
                owner_device_id,
                kind,
                lock_id,
                route_binding,
                reservation_object_id,
                expires_at,
            } => {
                encoder.put_u16(RESERVATION_ARM)?;
                encoder.put_fixed(owner_account_digest)?;
                encoder.put_fixed(owner_device_id)?;
                encoder.put_u16(*kind)?;
                encoder.put_fixed(lock_id)?;
                encoder.put_fixed(route_binding)?;
                encoder.put_fixed(reservation_object_id)?;
                encoder.put_u64(*expires_at)?;
            }
        }
        wrap(CLAIM_ROW_KIND, encoder.finish())
    }

    /// Decodes one wrapped body.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = unwrap(CLAIM_ROW_KIND, body)?;
        let mut decoder = decoder(&inner)?;
        let row = match decoder.u16()? {
            LOCK_ARM => Self::Lock {
                conversation_id: decoder.array()?,
                binding_id: decoder.array()?,
                incarnation: decoder.u64()?,
            },
            RESERVATION_ARM => Self::Reservation {
                owner_account_digest: decoder.array()?,
                owner_device_id: decoder.array()?,
                kind: decoder.u16()?,
                lock_id: decoder.array()?,
                route_binding: decoder.array()?,
                reservation_object_id: decoder.array()?,
                expires_at: decoder.u64()?,
            },
            _ => return Err(StorageError::InvalidEncoding),
        };
        decoder.finish()?;
        Ok(row)
    }

    /// Whether this row belongs under `key`.
    #[must_use]
    pub fn matches_key(&self, key: &StoredKey) -> bool {
        let bytes = key.as_bytes();
        match self {
            Self::Lock { .. } => bytes.starts_with(prefix::LOCK),
            Self::Reservation { .. } => bytes.starts_with(prefix::RESERVATION),
        }
    }
}

// ---------------------------------------------------------------------------
// Kind 4: sequencer rows.

/// The state of a candidate slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateState {
    /// Sequenced, awaiting a terminal.
    Active,
    /// Finalized.
    Finalized,
    /// Aborted.
    Aborted,
}

impl CandidateState {
    const fn wire_value(self) -> u16 {
        match self {
            Self::Active => 1,
            Self::Finalized => 2,
            Self::Aborted => 3,
        }
    }

    const fn from_wire(value: u16) -> Result<Self, StorageError> {
        match value {
            1 => Ok(Self::Active),
            2 => Ok(Self::Finalized),
            3 => Ok(Self::Aborted),
            _ => Err(StorageError::InvalidEncoding),
        }
    }
}

/// Which accumulator a proof row belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofRole {
    /// A commit approval envelope.
    Approval,
    /// A commit or ReInit ACK.
    Ack,
    /// A finality vote.
    Vote,
}

impl ProofRole {
    const fn wire_value(self) -> u16 {
        match self {
            Self::Approval => 1,
            Self::Ack => 2,
            Self::Vote => 3,
        }
    }

    const fn from_wire(value: u16) -> Result<Self, StorageError> {
        match value {
            1 => Ok(Self::Approval),
            2 => Ok(Self::Ack),
            3 => Ok(Self::Vote),
            _ => Err(StorageError::InvalidEncoding),
        }
    }

    const fn prefix(self) -> &'static [u8] {
        match self {
            Self::Approval => prefix::APPROVAL,
            Self::Ack => prefix::ACK,
            Self::Vote => prefix::VOTE,
        }
    }
}

/// A sequencer log entry, a candidate slot, or a proof accumulator entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SequencerRow {
    /// One position of the per-conversation sequencer log.
    Record {
        /// The retained `sequencer_record` object identifier.
        record_object_id: [u8; HASH_BYTES],
        /// The record identifier.
        record_id: [u8; HASH_BYTES],
        /// The `IrcSequencerRecord` union discriminant.
        record_kind: u16,
        /// Whether the record is terminal (finalization, abort, close).
        terminal: bool,
        /// Whether the record is a security proof retention root.
        security_proof: bool,
        /// The predecessor record identifier.
        predecessor_record_id: [u8; HASH_BYTES],
    },
    /// The candidate slot of one prior epoch.
    Candidate {
        /// Candidate identifier.
        candidate_id: [u8; HASH_BYTES],
        /// Commit object identifier.
        commit_object_id: [u8; HASH_BYTES],
        /// Route sequence of the receipt.
        route_sequence: u64,
        /// Candidate sequence within the epoch.
        candidate_sequence: u32,
        /// Attempts consumed in this epoch.
        attempts: u32,
        /// Slot state.
        state: CandidateState,
        /// The terminal record identifier once finalized or aborted.
        terminal_id: Option<[u8; HASH_BYTES]>,
    },
    /// One accumulated proof.
    Proof {
        /// Accumulator role.
        role: ProofRole,
        /// The retained proof object identifier.
        object_id: [u8; HASH_BYTES],
        /// The finality vote slot, zero for approvals and ACKs.
        slot: u16,
    },
}

const RECORD_ARM: u16 = 1;
const CANDIDATE_ARM: u16 = 2;
const PROOF_ARM: u16 = 3;

impl SequencerRow {
    /// The `record/v1/<conversation-id><route-sequence>` key.
    pub fn record_key(
        conversation_id: &[u8; HASH_BYTES],
        route_sequence: u64,
    ) -> Result<StoredKey, StorageError> {
        key_of(&[
            prefix::RECORD,
            conversation_id,
            &route_sequence.to_be_bytes(),
        ])
    }

    /// Splits a record key.
    pub fn parse_record_key(key: &StoredKey) -> Result<([u8; HASH_BYTES], u64), StorageError> {
        let rest = suffix(key, prefix::RECORD, HASH_BYTES + 8)?;
        Ok((
            slice_array(rest, 0)?,
            u64::from_be_bytes(slice_array(rest, HASH_BYTES)?),
        ))
    }

    /// The `candidate/v1/<conversation-id><prior-epoch>` key.
    pub fn candidate_key(
        conversation_id: &[u8; HASH_BYTES],
        prior_epoch: u64,
    ) -> Result<StoredKey, StorageError> {
        key_of(&[
            prefix::CANDIDATE,
            conversation_id,
            &prior_epoch.to_be_bytes(),
        ])
    }

    /// The proof accumulator key:
    /// `<role>/v1/<conversation-id><subject-id><root-fingerprint><device-id>`.
    pub fn proof_key(
        role: ProofRole,
        conversation_id: &[u8; HASH_BYTES],
        subject_id: &[u8; HASH_BYTES],
        root_fingerprint: &[u8; HASH_BYTES],
        device_id: &[u8; ID_BYTES],
    ) -> Result<StoredKey, StorageError> {
        key_of(&[
            role.prefix(),
            conversation_id,
            subject_id,
            root_fingerprint,
            device_id,
        ])
    }

    /// Every proof of `role` for one subject, in canonical signer order.
    pub fn proof_range(
        role: ProofRole,
        conversation_id: &[u8; HASH_BYTES],
        subject_id: &[u8; HASH_BYTES],
    ) -> Result<ReadPlan, StorageError> {
        let start = key_of(&[role.prefix(), conversation_id, subject_id])?;
        prefix_range(start.as_bytes(), PAGE_LIMIT)
    }

    /// The log from `first_sequence` onward.
    pub fn record_range(
        conversation_id: &[u8; HASH_BYTES],
        first_sequence: u64,
        limit: u16,
    ) -> Result<ReadPlan, StorageError> {
        let scope = key_of(&[prefix::RECORD, conversation_id])?;
        prefix_range_from(
            scope.as_bytes(),
            &Self::record_key(conversation_id, first_sequence)?,
            limit,
        )
    }

    /// Encodes the wrapped body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let mut encoder = encoder()?;
        match self {
            Self::Record {
                record_object_id,
                record_id,
                record_kind,
                terminal,
                security_proof,
                predecessor_record_id,
            } => {
                encoder.put_u16(RECORD_ARM)?;
                encoder.put_fixed(record_object_id)?;
                encoder.put_fixed(record_id)?;
                encoder.put_u16(*record_kind)?;
                put_bool(&mut encoder, *terminal)?;
                put_bool(&mut encoder, *security_proof)?;
                encoder.put_fixed(predecessor_record_id)?;
            }
            Self::Candidate {
                candidate_id,
                commit_object_id,
                route_sequence,
                candidate_sequence,
                attempts,
                state,
                terminal_id,
            } => {
                encoder.put_u16(CANDIDATE_ARM)?;
                encoder.put_fixed(candidate_id)?;
                encoder.put_fixed(commit_object_id)?;
                encoder.put_u64(*route_sequence)?;
                encoder.put_u32(*candidate_sequence)?;
                encoder.put_u32(*attempts)?;
                encoder.put_u16(state.wire_value())?;
                put_optional_hash(&mut encoder, terminal_id.as_ref())?;
            }
            Self::Proof {
                role,
                object_id,
                slot,
            } => {
                encoder.put_u16(PROOF_ARM)?;
                encoder.put_u16(role.wire_value())?;
                encoder.put_fixed(object_id)?;
                encoder.put_u16(*slot)?;
            }
        }
        wrap(SEQUENCER_ROW_KIND, encoder.finish())
    }

    /// Decodes one wrapped body.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = unwrap(SEQUENCER_ROW_KIND, body)?;
        let mut decoder = decoder(&inner)?;
        let row = match decoder.u16()? {
            RECORD_ARM => Self::Record {
                record_object_id: decoder.array()?,
                record_id: decoder.array()?,
                record_kind: decoder.u16()?,
                terminal: take_bool(&mut decoder)?,
                security_proof: take_bool(&mut decoder)?,
                predecessor_record_id: decoder.array()?,
            },
            CANDIDATE_ARM => Self::Candidate {
                candidate_id: decoder.array()?,
                commit_object_id: decoder.array()?,
                route_sequence: decoder.u64()?,
                candidate_sequence: decoder.u32()?,
                attempts: decoder.u32()?,
                state: CandidateState::from_wire(decoder.u16()?)?,
                terminal_id: take_optional_hash(&mut decoder)?,
            },
            PROOF_ARM => Self::Proof {
                role: ProofRole::from_wire(decoder.u16()?)?,
                object_id: decoder.array()?,
                slot: decoder.u16()?,
            },
            _ => return Err(StorageError::InvalidEncoding),
        };
        decoder.finish()?;
        row.check()?;
        Ok(row)
    }

    fn check(&self) -> Result<(), StorageError> {
        let consistent = match self {
            Self::Candidate {
                state, terminal_id, ..
            } => (*state == CandidateState::Active) == terminal_id.is_none(),
            Self::Proof { role, slot, .. } => *role == ProofRole::Vote || *slot == 0,
            Self::Record { .. } => true,
        };
        if consistent {
            Ok(())
        } else {
            Err(StorageError::InvalidEncoding)
        }
    }

    /// Whether this row belongs under `key`.
    #[must_use]
    pub fn matches_key(&self, key: &StoredKey) -> bool {
        let bytes = key.as_bytes();
        match self {
            Self::Record { .. } => bytes.starts_with(prefix::RECORD),
            Self::Candidate { .. } => bytes.starts_with(prefix::CANDIDATE),
            Self::Proof { role, .. } => bytes.starts_with(role.prefix()),
        }
    }
}

// ---------------------------------------------------------------------------
// Kind 5: directory rows.

/// The highest accepted identity, roster, capability, or binding lock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectoryRow {
    /// The account's root head.
    Identity {
        /// Root generation.
        root_generation: u64,
        /// Root fingerprint.
        root_fingerprint: [u8; HASH_BYTES],
        /// The retained root identity object identifier.
        object_id: [u8; HASH_BYTES],
        /// Object identifiers of every generation, oldest first.
        chain_object_ids: Vec<[u8; HASH_BYTES]>,
    },
    /// The account's roster head.
    Roster {
        /// Roster generation.
        roster_generation: u64,
        /// Roster identifier.
        roster_id: [u8; HASH_BYTES],
        /// Root fingerprint the roster is signed under.
        root_fingerprint: [u8; HASH_BYTES],
        /// The retained roster object identifier.
        object_id: [u8; HASH_BYTES],
        /// Active device identities in canonical order.
        active_devices: Vec<[u8; ID_BYTES]>,
    },
    /// One device's highest accepted capability statement.
    Capability {
        /// Capability generation.
        generation: u64,
        /// Capability identifier.
        capability_id: [u8; HASH_BYTES],
        /// Roster identifier named by the statement.
        roster_id: [u8; HASH_BYTES],
        /// The retained object identifier.
        object_id: [u8; HASH_BYTES],
    },
    /// One root binding lock.
    BindingLock {
        /// Lock identifier.
        lock_id: [u8; HASH_BYTES],
        /// Binding identifier.
        binding_id: [u8; HASH_BYTES],
        /// The retained object identifier.
        object_id: [u8; HASH_BYTES],
    },
}

const IDENTITY_ARM: u16 = 1;
const ROSTER_ARM: u16 = 2;
const CAPABILITY_ARM: u16 = 3;
const BINDING_LOCK_ARM: u16 = 4;
/// Root generations retained in one identity head (companion 8.2 chain page).
pub const MAX_ROOT_CHAIN_LENGTH: usize = 1_024;
/// Active devices per account (companion 16).
const MAX_ACTIVE_DEVICES: usize = 64;

impl DirectoryRow {
    /// The `identity/v1/<account-digest>` key.
    pub fn identity_key(account_digest: &[u8; HASH_BYTES]) -> Result<StoredKey, StorageError> {
        key_of(&[prefix::IDENTITY, account_digest])
    }

    /// The `roster/v1/<account-digest>` key.
    pub fn roster_key(account_digest: &[u8; HASH_BYTES]) -> Result<StoredKey, StorageError> {
        key_of(&[prefix::ROSTER, account_digest])
    }

    /// The `capability/v1/<account-digest><device-id>` key.
    pub fn capability_key(
        account_digest: &[u8; HASH_BYTES],
        device_id: &[u8; ID_BYTES],
    ) -> Result<StoredKey, StorageError> {
        key_of(&[prefix::CAPABILITY, account_digest, device_id])
    }

    /// Every capability of one account in canonical Device ID order.
    pub fn capability_range(account_digest: &[u8; HASH_BYTES]) -> Result<ReadPlan, StorageError> {
        let scope = key_of(&[prefix::CAPABILITY, account_digest])?;
        prefix_range(scope.as_bytes(), PAGE_LIMIT)
    }

    /// The `binding-lock/v1/<account-digest><root-fingerprint><sequence>` key.
    pub fn binding_lock_key(
        account_digest: &[u8; HASH_BYTES],
        root_fingerprint: &[u8; HASH_BYTES],
        sequence: u64,
    ) -> Result<StoredKey, StorageError> {
        key_of(&[
            prefix::BINDING_LOCK,
            account_digest,
            root_fingerprint,
            &sequence.to_be_bytes(),
        ])
    }

    /// Binding locks of one root from `first_sequence` onward.
    pub fn binding_lock_range(
        account_digest: &[u8; HASH_BYTES],
        root_fingerprint: &[u8; HASH_BYTES],
        first_sequence: u64,
        limit: u16,
    ) -> Result<ReadPlan, StorageError> {
        let scope = key_of(&[prefix::BINDING_LOCK, account_digest, root_fingerprint])?;
        prefix_range_from(
            scope.as_bytes(),
            &Self::binding_lock_key(account_digest, root_fingerprint, first_sequence)?,
            limit,
        )
    }

    /// Encodes the wrapped body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let mut encoder = encoder()?;
        match self {
            Self::Identity {
                root_generation,
                root_fingerprint,
                object_id,
                chain_object_ids,
            } => {
                encoder.put_u16(IDENTITY_ARM)?;
                encoder.put_u64(*root_generation)?;
                encoder.put_fixed(root_fingerprint)?;
                encoder.put_fixed(object_id)?;
                put_hashes(&mut encoder, chain_object_ids, MAX_ROOT_CHAIN_LENGTH)?;
            }
            Self::Roster {
                roster_generation,
                roster_id,
                root_fingerprint,
                object_id,
                active_devices,
            } => {
                encoder.put_u16(ROSTER_ARM)?;
                encoder.put_u64(*roster_generation)?;
                encoder.put_fixed(roster_id)?;
                encoder.put_fixed(root_fingerprint)?;
                encoder.put_fixed(object_id)?;
                put_device_ids(&mut encoder, active_devices)?;
            }
            Self::Capability {
                generation,
                capability_id,
                roster_id,
                object_id,
            } => {
                encoder.put_u16(CAPABILITY_ARM)?;
                encoder.put_u64(*generation)?;
                encoder.put_fixed(capability_id)?;
                encoder.put_fixed(roster_id)?;
                encoder.put_fixed(object_id)?;
            }
            Self::BindingLock {
                lock_id,
                binding_id,
                object_id,
            } => {
                encoder.put_u16(BINDING_LOCK_ARM)?;
                encoder.put_fixed(lock_id)?;
                encoder.put_fixed(binding_id)?;
                encoder.put_fixed(object_id)?;
            }
        }
        wrap(DIRECTORY_ROW_KIND, encoder.finish())
    }

    /// Decodes one wrapped body.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = unwrap(DIRECTORY_ROW_KIND, body)?;
        let mut decoder = decoder(&inner)?;
        let row = match decoder.u16()? {
            IDENTITY_ARM => Self::Identity {
                root_generation: decoder.u64()?,
                root_fingerprint: decoder.array()?,
                object_id: decoder.array()?,
                chain_object_ids: take_hashes(&mut decoder, MAX_ROOT_CHAIN_LENGTH)?,
            },
            ROSTER_ARM => Self::Roster {
                roster_generation: decoder.u64()?,
                roster_id: decoder.array()?,
                root_fingerprint: decoder.array()?,
                object_id: decoder.array()?,
                active_devices: take_device_ids(&mut decoder)?,
            },
            CAPABILITY_ARM => Self::Capability {
                generation: decoder.u64()?,
                capability_id: decoder.array()?,
                roster_id: decoder.array()?,
                object_id: decoder.array()?,
            },
            BINDING_LOCK_ARM => Self::BindingLock {
                lock_id: decoder.array()?,
                binding_id: decoder.array()?,
                object_id: decoder.array()?,
            },
            _ => return Err(StorageError::InvalidEncoding),
        };
        decoder.finish()?;
        row.check()?;
        Ok(row)
    }

    fn check(&self) -> Result<(), StorageError> {
        let consistent = match self {
            Self::Identity {
                root_generation,
                chain_object_ids,
                object_id,
                ..
            } => {
                chain_object_ids.len()
                    == usize::try_from(*root_generation).unwrap_or(usize::MAX) + 1
                    && chain_object_ids.last() == Some(object_id)
            }
            Self::Roster { active_devices, .. } => active_devices
                .windows(2)
                .all(|pair| matches!(pair, [left, right] if left < right)),
            Self::Capability { .. } | Self::BindingLock { .. } => true,
        };
        if consistent {
            Ok(())
        } else {
            Err(StorageError::InvalidEncoding)
        }
    }

    /// Whether this row belongs under `key`.
    #[must_use]
    pub fn matches_key(&self, key: &StoredKey) -> bool {
        let bytes = key.as_bytes();
        match self {
            Self::Identity { .. } => bytes.starts_with(prefix::IDENTITY),
            Self::Roster { .. } => bytes.starts_with(prefix::ROSTER),
            Self::Capability { .. } => bytes.starts_with(prefix::CAPABILITY),
            Self::BindingLock { .. } => bytes.starts_with(prefix::BINDING_LOCK),
        }
    }
}

fn put_device_ids(encoder: &mut Encoder, devices: &[[u8; ID_BYTES]]) -> Result<(), StorageError> {
    if devices.len() > MAX_ACTIVE_DEVICES {
        return Err(StorageError::LimitExceeded);
    }
    encoder.put_u16(u16::try_from(devices.len()).map_err(|_| StorageError::Overflow)?)?;
    for device in devices {
        encoder.put_fixed(device)?;
    }
    Ok(())
}

fn take_device_ids(decoder: &mut Decoder<'_>) -> Result<Vec<[u8; ID_BYTES]>, StorageError> {
    let count = usize::from(decoder.u16()?);
    if count > MAX_ACTIVE_DEVICES {
        return Err(StorageError::LimitExceeded);
    }
    let mut devices = Vec::with_capacity(count);
    for _ in 0..count {
        devices.push(decoder.array::<ID_BYTES>()?);
    }
    Ok(devices)
}

// ---------------------------------------------------------------------------
// Kind 6: KeyPackage stock and claims.

/// The state of one published KeyPackage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageState {
    /// Available for one claim.
    Published,
    /// Dispensed exactly once.
    Claimed,
    /// Burned by a roster change or expiry sweep.
    Burned,
    /// Revoked by its publisher.
    Revoked,
}

impl PackageState {
    const fn wire_value(self) -> u16 {
        match self {
            Self::Published => 1,
            Self::Claimed => 2,
            Self::Burned => 3,
            Self::Revoked => 4,
        }
    }

    const fn from_wire(value: u16) -> Result<Self, StorageError> {
        match value {
            1 => Ok(Self::Published),
            2 => Ok(Self::Claimed),
            3 => Ok(Self::Burned),
            4 => Ok(Self::Revoked),
            _ => Err(StorageError::InvalidEncoding),
        }
    }
}

/// The stored outcome of one claim operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimOutcome {
    /// A package was dispensed.
    Claimed,
    /// No acceptable package was available.
    KeyUnavailable,
    /// The claim was refused by quota.
    RateLimited,
}

impl ClaimOutcome {
    const fn wire_value(self) -> u16 {
        match self {
            Self::Claimed => 1,
            Self::KeyUnavailable => 2,
            Self::RateLimited => 3,
        }
    }

    const fn from_wire(value: u16) -> Result<Self, StorageError> {
        match value {
            1 => Ok(Self::Claimed),
            2 => Ok(Self::KeyUnavailable),
            3 => Ok(Self::RateLimited),
            _ => Err(StorageError::InvalidEncoding),
        }
    }
}

/// A published package or a claim mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PackageRow {
    /// One published KeyPackage.
    Package {
        /// Publishing account digest.
        account_digest: [u8; HASH_BYTES],
        /// Publishing device.
        device_id: [u8; ID_BYTES],
        /// Cipher suite.
        suite: u16,
        /// Expiry second.
        expires_at: u64,
        /// The retained object identifier.
        object_id: [u8; HASH_BYTES],
        /// State.
        state: PackageState,
        /// The claiming account digest and operation once claimed.
        claimed_by: Option<([u8; HASH_BYTES], [u8; ID_BYTES])>,
    },
    /// One `(claiming account, operation)` mapping.
    Claim {
        /// Target account digest.
        target_account_digest: [u8; HASH_BYTES],
        /// Target device.
        target_device_id: [u8; ID_BYTES],
        /// Requested suite.
        suite: u16,
        /// Outcome.
        outcome: ClaimOutcome,
        /// The dispensed KeyPackageRef, empty unless claimed.
        key_package_ref: Vec<u8>,
        /// The dispensed object identifier, absent unless claimed.
        object_id: Option<[u8; HASH_BYTES]>,
        /// Retention boundary.
        retain_until: u64,
    },
}

const PACKAGE_ARM: u16 = 1;
const CLAIM_ARM: u16 = 2;
const MAX_KEY_PACKAGE_REF_BYTES: usize = 255;

impl PackageRow {
    /// The `package/v1/<key-package-ref>` key.
    pub fn package_key(key_package_ref: &[u8]) -> Result<StoredKey, StorageError> {
        if key_package_ref.is_empty() || key_package_ref.len() > MAX_KEY_PACKAGE_REF_BYTES {
            return Err(StorageError::InvalidEncoding);
        }
        key_of(&[prefix::PACKAGE, key_package_ref])
    }

    /// The `claim/v1/<account-digest><operation-id>` key.
    pub fn claim_key(
        account_digest: &[u8; HASH_BYTES],
        operation_id: &[u8; ID_BYTES],
    ) -> Result<StoredKey, StorageError> {
        key_of(&[prefix::CLAIM, account_digest, operation_id])
    }

    /// Encodes the wrapped body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let mut encoder = encoder()?;
        match self {
            Self::Package {
                account_digest,
                device_id,
                suite,
                expires_at,
                object_id,
                state,
                claimed_by,
            } => {
                encoder.put_u16(PACKAGE_ARM)?;
                encoder.put_fixed(account_digest)?;
                encoder.put_fixed(device_id)?;
                encoder.put_u16(*suite)?;
                encoder.put_u64(*expires_at)?;
                encoder.put_fixed(object_id)?;
                encoder.put_u16(state.wire_value())?;
                put_bool(&mut encoder, claimed_by.is_some())?;
                let (account, operation) = claimed_by.unwrap_or(([0; HASH_BYTES], [0; ID_BYTES]));
                encoder.put_fixed(&account)?;
                encoder.put_fixed(&operation)?;
            }
            Self::Claim {
                target_account_digest,
                target_device_id,
                suite,
                outcome,
                key_package_ref,
                object_id,
                retain_until,
            } => {
                if key_package_ref.len() > MAX_KEY_PACKAGE_REF_BYTES {
                    return Err(StorageError::LimitExceeded);
                }
                encoder.put_u16(CLAIM_ARM)?;
                encoder.put_fixed(target_account_digest)?;
                encoder.put_fixed(target_device_id)?;
                encoder.put_u16(*suite)?;
                encoder.put_u16(outcome.wire_value())?;
                encoder.put_vector_u32(key_package_ref)?;
                put_optional_hash(&mut encoder, object_id.as_ref())?;
                encoder.put_u64(*retain_until)?;
            }
        }
        wrap(PACKAGE_ROW_KIND, encoder.finish())
    }

    /// Decodes one wrapped body.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = unwrap(PACKAGE_ROW_KIND, body)?;
        let mut decoder = decoder(&inner)?;
        let row = match decoder.u16()? {
            PACKAGE_ARM => Self::decode_package(&mut decoder)?,
            CLAIM_ARM => Self::Claim {
                target_account_digest: decoder.array()?,
                target_device_id: decoder.array()?,
                suite: decoder.u16()?,
                outcome: ClaimOutcome::from_wire(decoder.u16()?)?,
                key_package_ref: decoder.vector_u32(MAX_KEY_PACKAGE_REF_BYTES)?.to_vec(),
                object_id: take_optional_hash(&mut decoder)?,
                retain_until: decoder.u64()?,
            },
            _ => return Err(StorageError::InvalidEncoding),
        };
        decoder.finish()?;
        row.check()?;
        Ok(row)
    }

    fn decode_package(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        let account_digest = decoder.array()?;
        let device_id = decoder.array()?;
        let suite = decoder.u16()?;
        let expires_at = decoder.u64()?;
        let object_id = decoder.array()?;
        let state = PackageState::from_wire(decoder.u16()?)?;
        let present = take_bool(decoder)?;
        let account = decoder.array::<HASH_BYTES>()?;
        let operation = decoder.array::<ID_BYTES>()?;
        if !present && (account != [0; HASH_BYTES] || operation != [0; ID_BYTES]) {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self::Package {
            account_digest,
            device_id,
            suite,
            expires_at,
            object_id,
            state,
            claimed_by: present.then_some((account, operation)),
        })
    }

    fn check(&self) -> Result<(), StorageError> {
        let consistent = match self {
            Self::Package {
                state, claimed_by, ..
            } => (*state == PackageState::Claimed) == claimed_by.is_some(),
            Self::Claim {
                outcome,
                key_package_ref,
                object_id,
                ..
            } => {
                let claimed = *outcome == ClaimOutcome::Claimed;
                claimed == !key_package_ref.is_empty() && claimed == object_id.is_some()
            }
        };
        if consistent {
            Ok(())
        } else {
            Err(StorageError::InvalidEncoding)
        }
    }

    /// Whether this row belongs under `key`.
    #[must_use]
    pub fn matches_key(&self, key: &StoredKey) -> bool {
        let bytes = key.as_bytes();
        match self {
            Self::Package { .. } => bytes.starts_with(prefix::PACKAGE),
            Self::Claim { .. } => bytes.starts_with(prefix::CLAIM),
        }
    }
}

// ---------------------------------------------------------------------------
// Kind 7: device attachment.

/// An outstanding attach challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachChallenge {
    /// The connection the challenge was issued to.
    pub connection_id: u64,
    /// The edge connection nonce.
    pub connection_nonce: [u8; HASH_BYTES],
    /// The coordinator's server challenge.
    pub server_challenge: [u8; HASH_BYTES],
    /// The reserved next session generation.
    pub reserved_generation: u64,
    /// Expiry second.
    pub expires_at: u64,
    /// The retained challenge object identifier.
    pub object_id: [u8; HASH_BYTES],
}

/// The durable session generation of one device and its open challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachRow {
    /// The last successful attachment's generation, zero before any.
    pub session_generation: u64,
    /// The outstanding challenge, if any.
    pub challenge: Option<AttachChallenge>,
}

impl AttachRow {
    /// The `attach/v1/<account-digest><device-id>` key.
    pub fn key(
        account_digest: &[u8; HASH_BYTES],
        device_id: &[u8; ID_BYTES],
    ) -> Result<StoredKey, StorageError> {
        key_of(&[prefix::ATTACH, account_digest, device_id])
    }

    /// Encodes the wrapped body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let mut encoder = encoder()?;
        encoder.put_u64(self.session_generation)?;
        put_bool(&mut encoder, self.challenge.is_some())?;
        let challenge = self.challenge.unwrap_or(AttachChallenge {
            connection_id: 0,
            connection_nonce: [0; HASH_BYTES],
            server_challenge: [0; HASH_BYTES],
            reserved_generation: 0,
            expires_at: 0,
            object_id: [0; HASH_BYTES],
        });
        encoder.put_u64(challenge.connection_id)?;
        encoder.put_fixed(&challenge.connection_nonce)?;
        encoder.put_fixed(&challenge.server_challenge)?;
        encoder.put_u64(challenge.reserved_generation)?;
        encoder.put_u64(challenge.expires_at)?;
        encoder.put_fixed(&challenge.object_id)?;
        wrap(ATTACH_ROW_KIND, encoder.finish())
    }

    /// Decodes one wrapped body.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = unwrap(ATTACH_ROW_KIND, body)?;
        let mut decoder = decoder(&inner)?;
        let session_generation = decoder.u64()?;
        let present = take_bool(&mut decoder)?;
        let challenge = AttachChallenge {
            connection_id: decoder.u64()?,
            connection_nonce: decoder.array()?,
            server_challenge: decoder.array()?,
            reserved_generation: decoder.u64()?,
            expires_at: decoder.u64()?,
            object_id: decoder.array()?,
        };
        decoder.finish()?;
        let blank = challenge.connection_id == 0
            && challenge.reserved_generation == 0
            && challenge.expires_at == 0
            && challenge.connection_nonce == [0; HASH_BYTES]
            && challenge.server_challenge == [0; HASH_BYTES]
            && challenge.object_id == [0; HASH_BYTES];
        if present == blank || (present && challenge.reserved_generation <= session_generation) {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self {
            session_generation,
            challenge: present.then_some(challenge),
        })
    }
}

// ---------------------------------------------------------------------------
// Kind 8: mailbox rows.

/// A mailbox kind (companion 11.6 `mailbox-kind`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum MailboxKind {
    /// `APPLICATION`.
    Application,
    /// `BINDING`.
    Binding,
    /// `WELCOME`.
    Welcome,
    /// `STAGED-REINIT`.
    StagedReinit,
}

impl MailboxKind {
    const fn wire_value(self) -> u16 {
        match self {
            Self::Application => 1,
            Self::Binding => 2,
            Self::Welcome => 3,
            Self::StagedReinit => 4,
        }
    }

    const fn from_wire(value: u16) -> Result<Self, StorageError> {
        match value {
            1 => Ok(Self::Application),
            2 => Ok(Self::Binding),
            3 => Ok(Self::Welcome),
            4 => Ok(Self::StagedReinit),
            _ => Err(StorageError::InvalidEncoding),
        }
    }
}

/// An issued delivery token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryGrant {
    /// The token.
    pub token: [u8; HASH_BYTES],
    /// The attachment session generation the token is bound to.
    pub session_generation: u64,
    /// Expiry second.
    pub expires_at: u64,
}

/// A mailbox item, a token index, or an acknowledgement result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MailboxRow {
    /// One queued object.
    Item {
        /// The retained object identifier.
        object_id: [u8; HASH_BYTES],
        /// The conversation the item belongs to, zero for bindings.
        conversation_id: [u8; HASH_BYTES],
        /// Insertion second.
        inserted_at: u64,
        /// Retention boundary.
        expires_at: u64,
        /// The current token, if one is outstanding.
        grant: Option<DeliveryGrant>,
    },
    /// The token index back to its item.
    Token {
        /// Target account digest.
        account_digest: [u8; HASH_BYTES],
        /// Target device.
        device_id: [u8; ID_BYTES],
        /// Mailbox kind.
        kind: MailboxKind,
        /// Item sequence.
        sequence: u64,
        /// The object identifier the token names.
        object_id: [u8; HASH_BYTES],
        /// The bound session generation.
        session_generation: u64,
        /// Expiry second.
        expires_at: u64,
    },
    /// A durable acknowledgement result.
    Ack {
        /// The acknowledged object identifier.
        object_id: [u8; HASH_BYTES],
        /// Acknowledgement second.
        acknowledged_at: u64,
        /// Retention boundary.
        retain_until: u64,
    },
}

const ITEM_ARM: u16 = 1;
const TOKEN_ARM: u16 = 2;
const ACK_ARM: u16 = 3;

impl MailboxRow {
    /// The `mailbox/v1/<account-digest><device-id><kind><sequence>` key.
    pub fn item_key(
        account_digest: &[u8; HASH_BYTES],
        device_id: &[u8; ID_BYTES],
        kind: MailboxKind,
        sequence: u64,
    ) -> Result<StoredKey, StorageError> {
        key_of(&[
            prefix::MAILBOX,
            account_digest,
            device_id,
            &kind.wire_value().to_be_bytes(),
            &sequence.to_be_bytes(),
        ])
    }

    /// Splits an item key.
    pub fn parse_item_key(key: &StoredKey) -> Result<MailboxItemKey, StorageError> {
        let rest = suffix(key, prefix::MAILBOX, HASH_BYTES + ID_BYTES + 2 + 8)?;
        Ok(MailboxItemKey {
            account_digest: slice_array(rest, 0)?,
            device_id: slice_array(rest, HASH_BYTES)?,
            kind: MailboxKind::from_wire(u16::from_be_bytes(slice_array(
                rest,
                HASH_BYTES + ID_BYTES,
            )?))?,
            sequence: u64::from_be_bytes(slice_array(rest, HASH_BYTES + ID_BYTES + 2)?),
        })
    }

    /// One device's items of `kind` from `first_sequence` onward.
    pub fn item_range(
        account_digest: &[u8; HASH_BYTES],
        device_id: &[u8; ID_BYTES],
        kind: MailboxKind,
        first_sequence: u64,
        limit: u16,
    ) -> Result<ReadPlan, StorageError> {
        let scope = key_of(&[
            prefix::MAILBOX,
            account_digest,
            device_id,
            &kind.wire_value().to_be_bytes(),
        ])?;
        prefix_range_from(
            scope.as_bytes(),
            &Self::item_key(account_digest, device_id, kind, first_sequence)?,
            limit,
        )
    }

    /// The `token/v1/<delivery-token>` key.
    pub fn token_key(token: &[u8; HASH_BYTES]) -> Result<StoredKey, StorageError> {
        key_of(&[prefix::TOKEN, token])
    }

    /// The `ack-mailbox/v1/<account-digest><device-id><delivery-token>` key.
    pub fn ack_key(
        account_digest: &[u8; HASH_BYTES],
        device_id: &[u8; ID_BYTES],
        token: &[u8; HASH_BYTES],
    ) -> Result<StoredKey, StorageError> {
        key_of(&[prefix::ACK_MAILBOX, account_digest, device_id, token])
    }

    /// Encodes the wrapped body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let mut encoder = encoder()?;
        match self {
            Self::Item {
                object_id,
                conversation_id,
                inserted_at,
                expires_at,
                grant,
            } => {
                encoder.put_u16(ITEM_ARM)?;
                encoder.put_fixed(object_id)?;
                encoder.put_fixed(conversation_id)?;
                encoder.put_u64(*inserted_at)?;
                encoder.put_u64(*expires_at)?;
                put_grant(&mut encoder, *grant)?;
            }
            Self::Token {
                account_digest,
                device_id,
                kind,
                sequence,
                object_id,
                session_generation,
                expires_at,
            } => {
                encoder.put_u16(TOKEN_ARM)?;
                encoder.put_fixed(account_digest)?;
                encoder.put_fixed(device_id)?;
                encoder.put_u16(kind.wire_value())?;
                encoder.put_u64(*sequence)?;
                encoder.put_fixed(object_id)?;
                encoder.put_u64(*session_generation)?;
                encoder.put_u64(*expires_at)?;
            }
            Self::Ack {
                object_id,
                acknowledged_at,
                retain_until,
            } => {
                encoder.put_u16(ACK_ARM)?;
                encoder.put_fixed(object_id)?;
                encoder.put_u64(*acknowledged_at)?;
                encoder.put_u64(*retain_until)?;
            }
        }
        wrap(MAILBOX_ROW_KIND, encoder.finish())
    }

    /// Decodes one wrapped body.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = unwrap(MAILBOX_ROW_KIND, body)?;
        let mut decoder = decoder(&inner)?;
        let row = match decoder.u16()? {
            ITEM_ARM => Self::Item {
                object_id: decoder.array()?,
                conversation_id: decoder.array()?,
                inserted_at: decoder.u64()?,
                expires_at: decoder.u64()?,
                grant: take_grant(&mut decoder)?,
            },
            TOKEN_ARM => Self::Token {
                account_digest: decoder.array()?,
                device_id: decoder.array()?,
                kind: MailboxKind::from_wire(decoder.u16()?)?,
                sequence: decoder.u64()?,
                object_id: decoder.array()?,
                session_generation: decoder.u64()?,
                expires_at: decoder.u64()?,
            },
            ACK_ARM => Self::Ack {
                object_id: decoder.array()?,
                acknowledged_at: decoder.u64()?,
                retain_until: decoder.u64()?,
            },
            _ => return Err(StorageError::InvalidEncoding),
        };
        decoder.finish()?;
        Ok(row)
    }

    /// Whether this row belongs under `key`.
    #[must_use]
    pub fn matches_key(&self, key: &StoredKey) -> bool {
        let bytes = key.as_bytes();
        match self {
            Self::Item { .. } => bytes.starts_with(prefix::MAILBOX),
            Self::Token { .. } => bytes.starts_with(prefix::TOKEN),
            Self::Ack { .. } => bytes.starts_with(prefix::ACK_MAILBOX),
        }
    }
}

/// The parsed components of one mailbox item key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MailboxItemKey {
    /// Target account digest.
    pub account_digest: [u8; HASH_BYTES],
    /// Target device.
    pub device_id: [u8; ID_BYTES],
    /// Mailbox kind.
    pub kind: MailboxKind,
    /// Sequence.
    pub sequence: u64,
}

fn put_grant(encoder: &mut Encoder, grant: Option<DeliveryGrant>) -> Result<(), StorageError> {
    put_bool(encoder, grant.is_some())?;
    let grant = grant.unwrap_or(DeliveryGrant {
        token: [0; HASH_BYTES],
        session_generation: 0,
        expires_at: 0,
    });
    encoder.put_fixed(&grant.token)?;
    encoder.put_u64(grant.session_generation)?;
    encoder.put_u64(grant.expires_at)
}

fn take_grant(decoder: &mut Decoder<'_>) -> Result<Option<DeliveryGrant>, StorageError> {
    let present = take_bool(decoder)?;
    let grant = DeliveryGrant {
        token: decoder.array()?,
        session_generation: decoder.u64()?,
        expires_at: decoder.u64()?,
    };
    let blank =
        grant.token == [0; HASH_BYTES] && grant.session_generation == 0 && grant.expires_at == 0;
    if present == blank {
        return Err(StorageError::InvalidEncoding);
    }
    Ok(present.then_some(grant))
}

// ---------------------------------------------------------------------------
// Kind 9: companion replay rows.

/// The exact result of one companion request under its replay key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayRow {
    /// Request identifier.
    pub request_id: [u8; ID_BYTES],
    /// Request object identifier.
    pub request_object_id: [u8; HASH_BYTES],
    /// Result object identifier, absent while the request is pending.
    pub result_object_id: Option<[u8; HASH_BYTES]>,
    /// Response descriptor object identifiers in descriptor order.
    pub response_object_ids: Vec<[u8; HASH_BYTES]>,
    /// Whether the result covers a security-state mutation (seven-day replay).
    pub security_mutation: bool,
    /// Retention boundary.
    pub retain_until: u64,
}

/// The parsed components of one replay key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ReplayKey {
    /// Home server.
    pub home_server_id: [u8; ID_BYTES],
    /// Server incarnation.
    pub server_incarnation: [u8; ID_BYTES],
    /// Origin identity.
    pub origin_id: [u8; ID_BYTES],
    /// Origin generation.
    pub origin_generation: u64,
    /// Companion operation sequence.
    pub operation_sequence: u64,
}

impl ReplayRow {
    /// The `replay/v1/irc-mls-v1/...` key.
    pub fn key(parts: &ReplayKey) -> Result<StoredKey, StorageError> {
        key_of(&[
            prefix::REPLAY,
            &parts.home_server_id,
            &parts.server_incarnation,
            &parts.origin_id,
            &parts.origin_generation.to_be_bytes(),
            &parts.operation_sequence.to_be_bytes(),
        ])
    }

    /// Splits a replay key.
    pub fn parse_key(key: &StoredKey) -> Result<ReplayKey, StorageError> {
        let rest = suffix(key, prefix::REPLAY, 3 * ID_BYTES + 16)?;
        Ok(ReplayKey {
            home_server_id: slice_array(rest, 0)?,
            server_incarnation: slice_array(rest, ID_BYTES)?,
            origin_id: slice_array(rest, 2 * ID_BYTES)?,
            origin_generation: u64::from_be_bytes(slice_array(rest, 3 * ID_BYTES)?),
            operation_sequence: u64::from_be_bytes(slice_array(rest, 3 * ID_BYTES + 8)?),
        })
    }

    /// Every replay row of one origin generation, in sequence order.
    pub fn origin_range(
        home_server_id: &[u8; ID_BYTES],
        server_incarnation: &[u8; ID_BYTES],
        origin_id: &[u8; ID_BYTES],
        origin_generation: u64,
    ) -> Result<ReadPlan, StorageError> {
        let scope = key_of(&[
            prefix::REPLAY,
            home_server_id,
            server_incarnation,
            origin_id,
            &origin_generation.to_be_bytes(),
        ])?;
        prefix_range(scope.as_bytes(), PAGE_LIMIT)
    }

    /// Encodes the wrapped body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let mut encoder = encoder()?;
        encoder.put_fixed(&self.request_id)?;
        encoder.put_fixed(&self.request_object_id)?;
        put_optional_hash(&mut encoder, self.result_object_id.as_ref())?;
        put_hashes(
            &mut encoder,
            &self.response_object_ids,
            MAX_REPLAY_DESCRIPTORS,
        )?;
        put_bool(&mut encoder, self.security_mutation)?;
        encoder.put_u64(self.retain_until)?;
        wrap(REPLAY_ROW_KIND, encoder.finish())
    }

    /// Decodes one wrapped body.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = unwrap(REPLAY_ROW_KIND, body)?;
        let mut decoder = decoder(&inner)?;
        let row = Self {
            request_id: decoder.array()?,
            request_object_id: decoder.array()?,
            result_object_id: take_optional_hash(&mut decoder)?,
            response_object_ids: take_hashes(&mut decoder, MAX_REPLAY_DESCRIPTORS)?,
            security_mutation: take_bool(&mut decoder)?,
            retain_until: decoder.u64()?,
        };
        decoder.finish()?;
        if row.result_object_id.is_none() && !row.response_object_ids.is_empty() {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(row)
    }
}

// ---------------------------------------------------------------------------
// Kind 10: delivery rows.

/// The cross-profile tuple carried by an outbox row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrossProfileTuple {
    /// Mutation identifier.
    pub mutation_id: [u8; ID_BYTES],
    /// Zero-based part index.
    pub part_index: u16,
    /// Part count, 2 to 2048.
    pub part_count: u16,
}

/// A delivery cursor, one outbox row, or the ESTATE transfer state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeliveryRow {
    /// The per-target companion delivery cursor.
    Cursor {
        /// Delivery generation.
        generation: u64,
        /// The next sequence to assign.
        next_sequence: u64,
        /// The highest acknowledged sequence.
        acked_sequence: u64,
        /// The event identity at the acknowledged sequence.
        acked_event_id: [u8; ID_BYTES],
        /// Whether later events are held behind an open barrier.
        barrier_open: bool,
    },
    /// One queued event for a target.
    Outbox {
        /// Event identity.
        event_id: [u8; ID_BYTES],
        /// The retained `federation_event` object identifier.
        event_object_id: [u8; HASH_BYTES],
        /// The referenced data object, if the selector has one.
        payload_object_id: Option<[u8; HASH_BYTES]>,
        /// Payload object bytes, zero without a payload.
        payload_bytes: u32,
        /// Whether the row has been acknowledged.
        acked: bool,
        /// The cross-profile tuple, if the event is part of a barrier.
        cross_profile: Option<CrossProfileTuple>,
    },
    /// The pending or active ESTATE transfer for a target.
    Snapshot {
        /// Snapshot generation.
        generation: u64,
        /// Snapshot token.
        token: [u8; HASH_BYTES],
        /// Entry count.
        entry_count: u32,
        /// Digest over the canonical entry partition.
        digest: [u8; HASH_BYTES],
        /// Whether READY was recorded.
        ready: bool,
        /// Token expiry second.
        expires_at: u64,
    },
}

const CURSOR_ARM: u16 = 1;
const OUTBOX_ARM: u16 = 2;
const SNAPSHOT_ARM: u16 = 3;
const MIN_PART_COUNT: u16 = 2;
const MAX_PART_COUNT: u16 = 2_048;

impl DeliveryRow {
    /// The `delivery/v1/<target>` key.
    pub fn cursor_key(target: &[u8; ID_BYTES]) -> Result<StoredKey, StorageError> {
        key_of(&[prefix::DELIVERY, target])
    }

    /// The `outbox/v1/<target><generation><sequence>` key.
    pub fn outbox_key(
        target: &[u8; ID_BYTES],
        generation: u64,
        sequence: u64,
    ) -> Result<StoredKey, StorageError> {
        key_of(&[
            prefix::OUTBOX,
            target,
            &generation.to_be_bytes(),
            &sequence.to_be_bytes(),
        ])
    }

    /// Splits an outbox key into `(target, generation, sequence)`.
    pub fn parse_outbox_key(key: &StoredKey) -> Result<([u8; ID_BYTES], u64, u64), StorageError> {
        let rest = suffix(key, prefix::OUTBOX, ID_BYTES + 16)?;
        Ok((
            slice_array(rest, 0)?,
            u64::from_be_bytes(slice_array(rest, ID_BYTES)?),
            u64::from_be_bytes(slice_array(rest, ID_BYTES + 8)?),
        ))
    }

    /// The outbox of one generation from `first_sequence` onward.
    pub fn outbox_range(
        target: &[u8; ID_BYTES],
        generation: u64,
        first_sequence: u64,
        limit: u16,
    ) -> Result<ReadPlan, StorageError> {
        let scope = key_of(&[prefix::OUTBOX, target, &generation.to_be_bytes()])?;
        prefix_range_from(
            scope.as_bytes(),
            &Self::outbox_key(target, generation, first_sequence)?,
            limit,
        )
    }

    /// The `estate/v1/<target>` key.
    pub fn snapshot_key(target: &[u8; ID_BYTES]) -> Result<StoredKey, StorageError> {
        key_of(&[prefix::ESTATE, target])
    }

    /// Encodes the wrapped body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let mut encoder = encoder()?;
        match self {
            Self::Cursor {
                generation,
                next_sequence,
                acked_sequence,
                acked_event_id,
                barrier_open,
            } => {
                encoder.put_u16(CURSOR_ARM)?;
                encoder.put_u64(*generation)?;
                encoder.put_u64(*next_sequence)?;
                encoder.put_u64(*acked_sequence)?;
                encoder.put_fixed(acked_event_id)?;
                put_bool(&mut encoder, *barrier_open)?;
            }
            Self::Outbox {
                event_id,
                event_object_id,
                payload_object_id,
                payload_bytes,
                acked,
                cross_profile,
            } => {
                encoder.put_u16(OUTBOX_ARM)?;
                encoder.put_fixed(event_id)?;
                encoder.put_fixed(event_object_id)?;
                put_optional_hash(&mut encoder, payload_object_id.as_ref())?;
                encoder.put_u32(*payload_bytes)?;
                put_bool(&mut encoder, *acked)?;
                put_tuple(&mut encoder, *cross_profile)?;
            }
            Self::Snapshot {
                generation,
                token,
                entry_count,
                digest,
                ready,
                expires_at,
            } => {
                encoder.put_u16(SNAPSHOT_ARM)?;
                encoder.put_u64(*generation)?;
                encoder.put_fixed(token)?;
                encoder.put_u32(*entry_count)?;
                encoder.put_fixed(digest)?;
                put_bool(&mut encoder, *ready)?;
                encoder.put_u64(*expires_at)?;
            }
        }
        wrap(DELIVERY_ROW_KIND, encoder.finish())
    }

    /// Decodes one wrapped body.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = unwrap(DELIVERY_ROW_KIND, body)?;
        let mut decoder = decoder(&inner)?;
        let row = match decoder.u16()? {
            CURSOR_ARM => Self::Cursor {
                generation: decoder.u64()?,
                next_sequence: decoder.u64()?,
                acked_sequence: decoder.u64()?,
                acked_event_id: decoder.array()?,
                barrier_open: take_bool(&mut decoder)?,
            },
            OUTBOX_ARM => Self::Outbox {
                event_id: decoder.array()?,
                event_object_id: decoder.array()?,
                payload_object_id: take_optional_hash(&mut decoder)?,
                payload_bytes: decoder.u32()?,
                acked: take_bool(&mut decoder)?,
                cross_profile: take_tuple(&mut decoder)?,
            },
            SNAPSHOT_ARM => Self::Snapshot {
                generation: decoder.u64()?,
                token: decoder.array()?,
                entry_count: decoder.u32()?,
                digest: decoder.array()?,
                ready: take_bool(&mut decoder)?,
                expires_at: decoder.u64()?,
            },
            _ => return Err(StorageError::InvalidEncoding),
        };
        decoder.finish()?;
        row.check()?;
        Ok(row)
    }

    fn check(&self) -> Result<(), StorageError> {
        let consistent = match self {
            Self::Cursor {
                next_sequence,
                acked_sequence,
                ..
            } => acked_sequence <= next_sequence,
            Self::Outbox {
                payload_object_id,
                payload_bytes,
                ..
            } => payload_object_id.is_some() == (*payload_bytes != 0),
            Self::Snapshot { .. } => true,
        };
        if consistent {
            Ok(())
        } else {
            Err(StorageError::InvalidEncoding)
        }
    }

    /// Whether this row belongs under `key`.
    #[must_use]
    pub fn matches_key(&self, key: &StoredKey) -> bool {
        let bytes = key.as_bytes();
        match self {
            Self::Cursor { .. } => bytes.starts_with(prefix::DELIVERY),
            Self::Outbox { .. } => bytes.starts_with(prefix::OUTBOX),
            Self::Snapshot { .. } => bytes.starts_with(prefix::ESTATE),
        }
    }
}

fn put_tuple(encoder: &mut Encoder, tuple: Option<CrossProfileTuple>) -> Result<(), StorageError> {
    put_bool(encoder, tuple.is_some())?;
    let tuple = tuple.unwrap_or(CrossProfileTuple {
        mutation_id: [0; ID_BYTES],
        part_index: 0,
        part_count: 0,
    });
    encoder.put_fixed(&tuple.mutation_id)?;
    encoder.put_u16(tuple.part_index)?;
    encoder.put_u16(tuple.part_count)
}

fn take_tuple(decoder: &mut Decoder<'_>) -> Result<Option<CrossProfileTuple>, StorageError> {
    let present = take_bool(decoder)?;
    let tuple = CrossProfileTuple {
        mutation_id: decoder.array()?,
        part_index: decoder.u16()?,
        part_count: decoder.u16()?,
    };
    if present {
        if !(MIN_PART_COUNT..=MAX_PART_COUNT).contains(&tuple.part_count)
            || tuple.part_index >= tuple.part_count
        {
            return Err(StorageError::InvalidEncoding);
        }
        return Ok(Some(tuple));
    }
    if tuple.mutation_id != [0; ID_BYTES] || tuple.part_index != 0 || tuple.part_count != 0 {
        return Err(StorageError::InvalidEncoding);
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Kind 11: the sequencer key set.

/// The highest accepted sequencer key set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeySetRow {
    /// Key set generation.
    pub generation: u64,
    /// Key set digest.
    pub digest: [u8; HASH_BYTES],
    /// Credential identifiers, current first.
    pub credential_ids: Vec<[u8; HASH_BYTES]>,
}

impl KeySetRow {
    /// The `keyset/v1` key.
    pub fn key() -> Result<StoredKey, StorageError> {
        key_of(&[prefix::KEYSET])
    }

    /// Encodes the wrapped body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        if self.credential_ids.is_empty() {
            return Err(StorageError::InvalidEncoding);
        }
        let mut encoder = encoder()?;
        encoder.put_u64(self.generation)?;
        encoder.put_fixed(&self.digest)?;
        put_hashes(&mut encoder, &self.credential_ids, MAX_KEY_SET_CREDENTIALS)?;
        wrap(KEYSET_ROW_KIND, encoder.finish())
    }

    /// Decodes one wrapped body.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = unwrap(KEYSET_ROW_KIND, body)?;
        let mut decoder = decoder(&inner)?;
        let row = Self {
            generation: decoder.u64()?,
            digest: decoder.array()?,
            credential_ids: take_hashes(&mut decoder, MAX_KEY_SET_CREDENTIALS)?,
        };
        decoder.finish()?;
        if row.credential_ids.is_empty() {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(row)
    }
}

// ---------------------------------------------------------------------------
// Validation entry point used by `records.rs`.

/// Decodes any table-23 body of `record_kind` and discards it, so that the
/// generic record validator can refuse a malformed row before it is sealed.
pub fn validate_state_body(record_kind: u16, body: &[u8]) -> Result<(), StorageError> {
    match record_kind {
        ROUTE_ROW_KIND => RouteRow::decode(body).map(|_| ()),
        CLAIM_ROW_KIND => ClaimRow::decode(body).map(|_| ()),
        SEQUENCER_ROW_KIND => SequencerRow::decode(body).map(|_| ()),
        DIRECTORY_ROW_KIND => DirectoryRow::decode(body).map(|_| ()),
        PACKAGE_ROW_KIND => PackageRow::decode(body).map(|_| ()),
        ATTACH_ROW_KIND => AttachRow::decode(body).map(|_| ()),
        MAILBOX_ROW_KIND => MailboxRow::decode(body).map(|_| ()),
        REPLAY_ROW_KIND => ReplayRow::decode(body).map(|_| ()),
        DELIVERY_ROW_KIND => DeliveryRow::decode(body).map(|_| ()),
        KEYSET_ROW_KIND => KeySetRow::decode(body).map(|_| ()),
        BARRIER_ROW_KIND => barrier::validate_body(body),
        _ => Err(StorageError::InvalidEncoding),
    }
}

/// Decodes a table-22 body and discards it.
pub fn validate_object_body(body: &[u8]) -> Result<(), StorageError> {
    ObjectRow::decode(body).map(|_| ())
}

/// The finality principals bound (re-exported for accumulator sizing).
pub const MAX_VOTE_PRINCIPALS: usize = MAX_FINALITY_PRINCIPALS;

/// Minimal valid bodies for every companion record kind, for codec and
/// construction tests inside and outside this crate. `seed` varies one
/// field so distinct seeds give distinct bodies.
pub mod fixtures {
    use super::barrier::{BarrierHead, BarrierIdentity, BarrierStage};
    use super::*;

    /// A valid table-22 body: a root identity envelope over `seed`.
    pub fn object_body(seed: u8) -> Result<Vec<u8>, StorageError> {
        let object = IrcWireObject::new(IrcWireObjectKind::RootIdentity, vec![seed])
            .map_err(|_| StorageError::InvalidEncoding)?;
        let bytes = agenc_ircd_e2ee::tls::TlsEncode::encode(&object)
            .map_err(|_| StorageError::InvalidEncoding)?;
        ObjectRow::new(bytes)?.encode()
    }

    /// A valid table-23 body of `kind` (2 to 12).
    pub fn state_body(kind: u16, seed: u8) -> Result<Vec<u8>, StorageError> {
        if kind <= DIRECTORY_ROW_KIND {
            structural_body(kind, seed)
        } else {
            operational_body(kind, seed)
        }
    }

    /// Route, claim, sequencer, and directory bodies.
    fn structural_body(kind: u16, seed: u8) -> Result<Vec<u8>, StorageError> {
        let hash = [seed; HASH_BYTES];
        match kind {
            ROUTE_ROW_KIND => RouteRow {
                route_state: vec![seed],
                lifecycle: RouteLifecycle::Active,
                binding_id: hash,
                lock_id: hash,
                accepted_state_id: hash,
                sequencer_head_id: hash,
                route_sequence: u64::from(seed),
                close_id: None,
                predecessor_close_id: None,
                recovery_gate: false,
                stored_bytes: 0,
            }
            .encode(),
            CLAIM_ROW_KIND => ClaimRow::Lock {
                conversation_id: hash,
                binding_id: hash,
                incarnation: u64::from(seed),
            }
            .encode(),
            SEQUENCER_ROW_KIND => SequencerRow::Proof {
                role: ProofRole::Ack,
                object_id: hash,
                slot: 0,
            }
            .encode(),
            DIRECTORY_ROW_KIND => DirectoryRow::Capability {
                generation: u64::from(seed),
                capability_id: hash,
                roster_id: hash,
                object_id: hash,
            }
            .encode(),
            _ => Err(StorageError::InvalidEncoding),
        }
    }

    /// Package, attach, mailbox, replay, delivery, key set, and barrier bodies.
    fn operational_body(kind: u16, seed: u8) -> Result<Vec<u8>, StorageError> {
        let hash = [seed; HASH_BYTES];
        let id = [seed; ID_BYTES];
        match kind {
            PACKAGE_ROW_KIND => PackageRow::Package {
                account_digest: hash,
                device_id: id,
                suite: 1,
                expires_at: u64::from(seed),
                object_id: hash,
                state: PackageState::Published,
                claimed_by: None,
            }
            .encode(),
            ATTACH_ROW_KIND => AttachRow {
                session_generation: u64::from(seed),
                challenge: None,
            }
            .encode(),
            MAILBOX_ROW_KIND => MailboxRow::Ack {
                object_id: hash,
                acknowledged_at: u64::from(seed),
                retain_until: u64::from(seed),
            }
            .encode(),
            REPLAY_ROW_KIND => ReplayRow {
                request_id: id,
                request_object_id: hash,
                result_object_id: None,
                response_object_ids: Vec::new(),
                security_mutation: false,
                retain_until: u64::from(seed),
            }
            .encode(),
            DELIVERY_ROW_KIND => DeliveryRow::Cursor {
                generation: u64::from(seed),
                next_sequence: 0,
                acked_sequence: 0,
                acked_event_id: id,
                barrier_open: false,
            }
            .encode(),
            KEYSET_ROW_KIND => KeySetRow {
                generation: u64::from(seed),
                digest: hash,
                credential_ids: vec![hash],
            }
            .encode(),
            BARRIER_ROW_KIND => BarrierHead::Stage(BarrierStage::empty(BarrierIdentity {
                network_id: hash,
                coordinator_server_id: id,
                coordinator_server_incarnation: id,
                coordinator_recovery_epoch: id,
                target_server_id: id,
                target_server_incarnation: id,
                mutation_id: id,
                coordinator_state_generation: u64::from(seed),
                part_count: 2,
            }))
            .encode(),
            _ => Err(StorageError::InvalidEncoding),
        }
    }
}
