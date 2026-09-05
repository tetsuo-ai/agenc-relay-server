//! Typed views and constructors for the top-level base-federation objects.
//!
//! The generic [`SchemaObject`] codec already enforces every Appendix-B field
//! grammar and cross-field rule. This module adds the few things a link owner
//! needs on top of it: exact object identities, the hello signature input and
//! exporter context, typed headers for the object-bearing wire commands, the
//! closed opcode/result mapping, and the snapshot digest. It never decides
//! authorization; it only names what a decoded object claims.

use agenc_ircd_types::{
    AccountId, ChannelInstanceId, ConnectionId, ENUM_REGISTRY, EventId, FHELLO_BYTES,
    FederationEventKind, FederationOpcode, FederationProjectionKind, FederationResultKind,
    FederationRole, InviteId, MAPPING_DESCRIPTORS, NetworkId, OriginId, RecoveryEpoch,
    RegistryValueError, RequestId, SNAPSHOT_ENTRIES, ServerId, ServerIncarnation, SessionId,
    UserId,
};
use sha2::{Digest as _, Sha256};

use crate::codec::WireValue;
use crate::codec::{CanonicalBytes, CanonicalEncode as _, CodecError, DecodeBudget, SchemaObject};
use crate::text::FederationHash32;

/// Domain-separation label for every base-federation object identity.
pub const FEDERATION_OBJECT_HASH_LABEL: &[u8] = b"agenc-chat federation object v1";
/// Domain-separation label prepended to the hello TBS before signing.
pub const FEDERATION_HELLO_SIGNATURE_LABEL: &[u8] = b"agenc-chat federation hello v1";
/// Domain-separation label for the snapshot digest.
pub const FEDERATION_SNAPSHOT_HASH_LABEL: &[u8] = b"agenc-chat federation snapshot v1";
/// RFC 9846 exporter label used for the hello channel binding.
pub const FEDERATION_EXPORTER_LABEL: &[u8] = b"EXPORTER-agenc-chat-federation-v1";
/// The one base-federation profile version.
pub const FEDERATION_PROFILE_VERSION: u16 = 1;
/// Exact byte length of the exporter context `network_id || min || max`.
pub const FEDERATION_EXPORTER_CONTEXT_BYTES: usize = 64;

const HELLO_TBS_SCHEMA: &str = "FederationHelloTBS";
const HELLO_SCHEMA: &str = "FederationHello";
const REQUEST_SCHEMA: &str = "FederationRequest";
const RESULT_SCHEMA: &str = "FederationResult";
const EVENT_SCHEMA: &str = "FederationEvent";
const ORIGIN_SCHEMA: &str = "FederationOrigin";
const PROJECTION_ENTRY_SCHEMA: &str = "FederationProjectionEntry";
const PROJECTION_VALUE_SCHEMA: &str = "FederationProjectionValue";
const REPLY_SCHEMA: &str = "FederationReply";
const SNAPSHOT_ENTRY_COUNT_PREFIX_BYTES: usize = 3;

/// Computes the Section-20.4 identity of one complete encoded object.
#[must_use]
pub fn federation_object_id(encoded: &[u8]) -> FederationHash32 {
    let mut hasher = Sha256::new();
    hasher.update(FEDERATION_OBJECT_HASH_LABEL);
    hasher.update(encoded);
    FederationHash32::from_bytes(hasher.finalize().into())
}

/// Builds the exact Ed25519 message for one hello TBS encoding.
///
/// Signing and verification live in the crypto adapter; this crate only fixes
/// the bytes that are signed.
pub fn hello_signature_input(encoded_tbs: &[u8]) -> Result<Vec<u8>, CodecError> {
    let length = FEDERATION_HELLO_SIGNATURE_LABEL
        .len()
        .checked_add(encoded_tbs.len())
        .ok_or(CodecError::Overflow)?;
    let mut input = Vec::new();
    input
        .try_reserve_exact(length)
        .map_err(|_| CodecError::AllocationFailed)?;
    input.extend_from_slice(FEDERATION_HELLO_SIGNATURE_LABEL);
    input.extend_from_slice(encoded_tbs);
    Ok(input)
}

/// Builds the exporter context `network_id || min(ServerId) || max(ServerId)`.
#[must_use]
pub fn exporter_context(
    network_id: &NetworkId,
    first: &ServerId,
    second: &ServerId,
) -> [u8; FEDERATION_EXPORTER_CONTEXT_BYTES] {
    let (low, high) = if first.as_bytes() <= second.as_bytes() {
        (first, second)
    } else {
        (second, first)
    };
    let mut context = [0_u8; FEDERATION_EXPORTER_CONTEXT_BYTES];
    let (network, servers) = context.split_at_mut(32);
    network.copy_from_slice(network_id.as_bytes());
    let (first_slot, second_slot) = servers.split_at_mut(16);
    first_slot.copy_from_slice(low.as_bytes());
    second_slot.copy_from_slice(high.as_bytes());
    context
}

/// Computes the Appendix-B.7 snapshot digest over ordered entry object IDs.
///
/// The input is hashed incrementally so a maximum snapshot never needs its
/// 32 MiB identity vector materialized.
pub fn snapshot_digest(
    recovery_epoch: &RecoveryEpoch,
    projection_generation: u64,
    state_generation: u64,
    ordered_entry_object_ids: &[FederationHash32],
) -> Result<FederationHash32, CodecError> {
    let count = u64::try_from(ordered_entry_object_ids.len()).map_err(|_| CodecError::Overflow)?;
    if count > SNAPSHOT_ENTRIES {
        return Err(CodecError::LengthAboveMaximum);
    }
    let count_bytes = count.to_be_bytes();
    let count_prefix = count_bytes
        .get(count_bytes.len() - SNAPSHOT_ENTRY_COUNT_PREFIX_BYTES..)
        .ok_or(CodecError::Overflow)?;
    let mut hasher = Sha256::new();
    hasher.update(FEDERATION_SNAPSHOT_HASH_LABEL);
    hasher.update(recovery_epoch.as_bytes());
    hasher.update(projection_generation.to_be_bytes());
    hasher.update(state_generation.to_be_bytes());
    hasher.update(count_prefix);
    for object_id in ordered_entry_object_ids {
        hasher.update(object_id.as_bytes());
    }
    Ok(FederationHash32::from_bytes(hasher.finalize().into()))
}

/// The signed hello fields, exactly Section 20.3.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HelloTbs {
    /// Network identity both peers must share.
    pub network_id: NetworkId,
    /// The sender's permanent Server ID.
    pub sender_server_id: ServerId,
    /// The Server ID the sender expects to be talking to.
    pub expected_peer_server_id: ServerId,
    /// The sender's current durable incarnation.
    pub server_incarnation: ServerIncarnation,
    /// The sender's current recovery epoch.
    pub recovery_epoch: RecoveryEpoch,
    /// The sender's configured role.
    pub role: FederationRole,
    /// Fresh 32-byte nonce echoed by the peer's FREADY.
    pub hello_nonce: [u8; 32],
    /// SHA-256 of the exact Appendix-B registry.
    pub profile_hash: [u8; 32],
    /// RFC 9846 exporter output for this TLS connection.
    pub tls_exporter: [u8; 32],
}

impl HelloTbs {
    /// Builds the validated `FederationHelloTBS` object.
    pub fn to_object(&self) -> Result<SchemaObject, CodecError> {
        SchemaObject::new(
            HELLO_TBS_SCHEMA,
            vec![
                WireValue::Unsigned(u64::from(FEDERATION_PROFILE_VERSION)),
                opaque(self.network_id.as_bytes())?,
                opaque(self.sender_server_id.as_bytes())?,
                opaque(self.expected_peer_server_id.as_bytes())?,
                opaque(self.server_incarnation.as_bytes())?,
                opaque(self.recovery_epoch.as_bytes())?,
                WireValue::Unsigned(u64::from(self.role.wire_value())),
                opaque(&self.hello_nonce)?,
                opaque(&self.profile_hash)?,
                opaque(&self.tls_exporter)?,
            ],
        )
    }

    /// Reads the typed fields of one validated `FederationHelloTBS` object.
    pub fn from_object(object: &SchemaObject) -> Result<Self, CodecError> {
        expect_schema(object, HELLO_TBS_SCHEMA)?;
        Ok(Self {
            network_id: NetworkId::from_bytes(fixed(object, "network_id")?),
            sender_server_id: ServerId::from_bytes(fixed(object, "sender_server_id")?),
            expected_peer_server_id: ServerId::from_bytes(fixed(
                object,
                "expected_peer_server_id",
            )?),
            server_incarnation: ServerIncarnation::from_bytes(fixed(object, "server_incarnation")?),
            recovery_epoch: RecoveryEpoch::from_bytes(fixed(object, "recovery_epoch")?),
            role: FederationRole::from_wire(unsigned_u16(object, "role")?)
                .map_err(registry_error)?,
            hello_nonce: fixed(object, "hello_nonce")?,
            profile_hash: fixed(object, "profile_hash")?,
            tls_exporter: fixed(object, "tls_exporter")?,
        })
    }

    /// Encodes the exact TBS bytes that precede the signature.
    pub fn encode(&self) -> Result<CanonicalBytes, CodecError> {
        self.to_object()?.encode_canonical()
    }
}

/// One complete signed hello.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationHello {
    /// The signed fields.
    pub tbs: HelloTbs,
    /// Ed25519 signature over [`hello_signature_input`] of the encoded TBS.
    pub signature: [u8; 64],
}

impl FederationHello {
    /// Builds the validated `FederationHello` object.
    pub fn to_object(&self) -> Result<SchemaObject, CodecError> {
        SchemaObject::new(
            HELLO_SCHEMA,
            vec![
                WireValue::Structure(self.tbs.to_object()?),
                opaque(&self.signature)?,
            ],
        )
    }

    /// Reads one validated `FederationHello` object.
    pub fn from_object(object: &SchemaObject) -> Result<Self, CodecError> {
        expect_schema(object, HELLO_SCHEMA)?;
        Ok(Self {
            tbs: HelloTbs::from_object(structure(object, "tbs")?)?,
            signature: fixed(object, "signature")?,
        })
    }

    /// Encodes the exact 260-byte hello.
    pub fn encode(&self) -> Result<CanonicalBytes, CodecError> {
        let bytes = self.to_object()?.encode_canonical()?;
        if u64::try_from(bytes.len()).map_err(|_| CodecError::Overflow)? != FHELLO_BYTES {
            return Err(CodecError::Overflow);
        }
        Ok(bytes)
    }

    /// Decodes exactly 260 bytes into a typed hello.
    pub fn decode(encoded: &[u8]) -> Result<Self, CodecError> {
        if u64::try_from(encoded.len()).map_err(|_| CodecError::Overflow)? != FHELLO_BYTES {
            return Err(CodecError::LengthAboveMaximum);
        }
        let mut budget = DecodeBudget::new(encoded.len(), 64);
        let object = SchemaObject::decode_exact(HELLO_SCHEMA, encoded, &mut budget)?;
        Self::from_object(&object)
    }
}

/// The complete Section-20.5 replay key of one origin operation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReplayKey {
    /// The edge that owns the origin.
    pub home_server_id: ServerId,
    /// The edge incarnation that allocated the origin.
    pub server_incarnation: ServerIncarnation,
    /// The connection-scoped origin.
    pub origin_id: OriginId,
    /// The origin generation the operation executes under.
    pub origin_generation: u64,
    /// The zero-based operation sequence within the generation.
    pub operation_sequence: u64,
}

impl ReplayKey {
    /// Exact byte width of [`Self::to_bytes`].
    pub const BYTES: usize = 64;

    /// Serializes the key as `home || incarnation || origin || generation || sequence`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut bytes = [0_u8; Self::BYTES];
        let (home, rest) = bytes.split_at_mut(16);
        home.copy_from_slice(self.home_server_id.as_bytes());
        let (incarnation, rest) = rest.split_at_mut(16);
        incarnation.copy_from_slice(self.server_incarnation.as_bytes());
        let (origin, rest) = rest.split_at_mut(16);
        origin.copy_from_slice(self.origin_id.as_bytes());
        let (generation, sequence) = rest.split_at_mut(8);
        generation.copy_from_slice(&self.origin_generation.to_be_bytes());
        sequence.copy_from_slice(&self.operation_sequence.to_be_bytes());
        bytes
    }
}

/// Typed fixed fields of one `FederationRequest`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestHeader {
    /// Network identity that must match link configuration.
    pub network_id: NetworkId,
    /// The complete replay key.
    pub replay_key: ReplayKey,
    /// The edge-chosen request identity.
    pub request_id: RequestId,
    /// The closed operation selector.
    pub opcode: FederationOpcode,
}

impl RequestHeader {
    /// Reads the fixed fields of one validated `FederationRequest` object.
    pub fn from_object(object: &SchemaObject) -> Result<Self, CodecError> {
        expect_schema(object, REQUEST_SCHEMA)?;
        Ok(Self {
            network_id: NetworkId::from_bytes(fixed(object, "network_id")?),
            replay_key: replay_key(object)?,
            request_id: RequestId::from_bytes(fixed(object, "request_id")?),
            opcode: FederationOpcode::from_wire(unsigned_u16(object, "opcode")?)
                .map_err(registry_error)?,
        })
    }

    /// Wraps one validated `operation.<opcode>` object into a complete request.
    pub fn build(&self, operation: &SchemaObject) -> Result<SchemaObject, CodecError> {
        expect_schema(operation, operation_schema_name(self.opcode))?;
        let encoded = operation.encode_canonical()?;
        SchemaObject::new(
            REQUEST_SCHEMA,
            vec![
                WireValue::Unsigned(u64::from(FEDERATION_PROFILE_VERSION)),
                opaque(self.network_id.as_bytes())?,
                opaque(self.replay_key.home_server_id.as_bytes())?,
                opaque(self.replay_key.server_incarnation.as_bytes())?,
                opaque(self.replay_key.origin_id.as_bytes())?,
                WireValue::Unsigned(self.replay_key.origin_generation),
                WireValue::Unsigned(self.replay_key.operation_sequence),
                opaque(self.request_id.as_bytes())?,
                WireValue::Unsigned(u64::from(self.opcode.wire_value())),
                opaque(encoded.as_slice())?,
            ],
        )
    }
}

/// Decodes the operation arm of one validated request under its opcode schema.
pub fn decode_request_operation(
    request: &SchemaObject,
    budget: &mut DecodeBudget,
) -> Result<SchemaObject, CodecError> {
    let header = RequestHeader::from_object(request)?;
    let encoded = opaque_field(request, "operation")?;
    SchemaObject::decode_exact(operation_schema_name(header.opcode), encoded, budget)
}

/// Typed fixed fields of one `FederationResult`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResultHeader {
    /// Network identity that must match link configuration.
    pub network_id: NetworkId,
    /// The replay key this result answers.
    pub replay_key: ReplayKey,
    /// The request identity this result answers.
    pub request_id: RequestId,
    /// The Section-20.4 identity of the exact request object.
    pub request_object_id: FederationHash32,
    /// Present exactly for `committed` and `session_registered`.
    pub completion_event_id: Option<EventId>,
    /// The closed result selector.
    pub result_kind: FederationResultKind,
}

impl ResultHeader {
    /// Reads the fixed fields of one validated `FederationResult` object.
    pub fn from_object(object: &SchemaObject) -> Result<Self, CodecError> {
        expect_schema(object, RESULT_SCHEMA)?;
        Ok(Self {
            network_id: NetworkId::from_bytes(fixed(object, "network_id")?),
            replay_key: replay_key(object)?,
            request_id: RequestId::from_bytes(fixed(object, "request_id")?),
            request_object_id: FederationHash32::from_bytes(fixed(object, "request_object_id")?),
            completion_event_id: optional_fixed(object, "completion_event_id")?
                .map(EventId::from_bytes),
            result_kind: FederationResultKind::from_wire(unsigned_u16(object, "result_kind")?)
                .map_err(registry_error)?,
        })
    }

    /// Wraps one validated `result.<kind>` arm and reply list into a result.
    pub fn build(
        &self,
        result: &SchemaObject,
        replies: Vec<SchemaObject>,
    ) -> Result<SchemaObject, CodecError> {
        expect_schema(result, result_schema_name(self.result_kind))?;
        for reply in &replies {
            expect_schema(reply, REPLY_SCHEMA)?;
        }
        let encoded = result.encode_canonical()?;
        let completion_event_id = self.completion_event_id;
        let completion: &[u8] = match &completion_event_id {
            Some(event_id) => event_id.as_bytes(),
            None => &[],
        };
        SchemaObject::new(
            RESULT_SCHEMA,
            vec![
                WireValue::Unsigned(u64::from(FEDERATION_PROFILE_VERSION)),
                opaque(self.network_id.as_bytes())?,
                opaque(self.replay_key.home_server_id.as_bytes())?,
                opaque(self.replay_key.server_incarnation.as_bytes())?,
                opaque(self.replay_key.origin_id.as_bytes())?,
                WireValue::Unsigned(self.replay_key.origin_generation),
                WireValue::Unsigned(self.replay_key.operation_sequence),
                opaque(self.request_id.as_bytes())?,
                opaque(self.request_object_id.as_bytes())?,
                opaque(completion)?,
                WireValue::Unsigned(u64::from(self.result_kind.wire_value())),
                opaque(encoded.as_slice())?,
                WireValue::Vector(replies),
            ],
        )
    }
}

/// Decodes the result arm of one validated result under its kind schema.
pub fn decode_result_arm(
    result: &SchemaObject,
    budget: &mut DecodeBudget,
) -> Result<SchemaObject, CodecError> {
    let header = ResultHeader::from_object(result)?;
    let encoded = opaque_field(result, "result")?;
    SchemaObject::decode_exact(result_schema_name(header.result_kind), encoded, budget)
}

/// The request-correlation tuple carried only by `request_completed`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestCorrelation {
    /// The replay key of the completed request.
    pub replay_key: ReplayKey,
    /// The request identity of the completed request.
    pub request_id: RequestId,
}

/// The cross-profile barrier tuple; a present value is a Stage 08 concern.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrossProfilePart {
    /// The per-target-edge mutation identity.
    pub mutation_id: [u8; 16],
    /// Zero-based index of this event within the barrier.
    pub part_index: u16,
    /// Total base plus companion parts, 2..=2048.
    pub part_count: u16,
}

/// Typed fixed fields of one `FederationEvent`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventHeader {
    /// Network identity that must match link configuration.
    pub network_id: NetworkId,
    /// The edge this copy is addressed to.
    pub target_server_id: ServerId,
    /// The projection generation the delivery stream belongs to.
    pub projection_generation: u64,
    /// The resulting global state generation that produced the event.
    pub coordinator_state_generation: u64,
    /// Contiguous per-generation delivery sequence.
    pub delivery_sequence: u64,
    /// Fresh random identity of this copy.
    pub event_id: EventId,
    /// The closed event selector.
    pub event_kind: FederationEventKind,
    /// Present exactly on `request_completed`.
    pub correlation: Option<RequestCorrelation>,
    /// Present only inside a Stage 08 cross-profile barrier.
    pub cross_profile: Option<CrossProfilePart>,
}

impl EventHeader {
    /// Reads the fixed fields of one validated `FederationEvent` object.
    pub fn from_object(object: &SchemaObject) -> Result<Self, CodecError> {
        expect_schema(object, EVENT_SCHEMA)?;
        let correlation = match optional_fixed::<16>(object, "request_id")? {
            None => None,
            Some(request_id) => Some(RequestCorrelation {
                replay_key: ReplayKey {
                    home_server_id: ServerId::from_bytes(fixed(object, "request_home_server_id")?),
                    server_incarnation: ServerIncarnation::from_bytes(fixed(
                        object,
                        "request_server_incarnation",
                    )?),
                    origin_id: OriginId::from_bytes(fixed(object, "request_origin_id")?),
                    origin_generation: unsigned(object, "request_origin_generation")?,
                    operation_sequence: unsigned(object, "request_operation_sequence")?,
                },
                request_id: RequestId::from_bytes(request_id),
            }),
        };
        let cross_profile = match optional_fixed::<16>(object, "cross_profile_mutation_id")? {
            None => None,
            Some(mutation_id) => Some(CrossProfilePart {
                mutation_id,
                part_index: unsigned_u16(object, "cross_profile_part_index")?,
                part_count: unsigned_u16(object, "cross_profile_part_count")?,
            }),
        };
        Ok(Self {
            network_id: NetworkId::from_bytes(fixed(object, "network_id")?),
            target_server_id: ServerId::from_bytes(fixed(object, "target_server_id")?),
            projection_generation: unsigned(object, "projection_generation")?,
            coordinator_state_generation: unsigned(object, "coordinator_state_generation")?,
            delivery_sequence: unsigned(object, "delivery_sequence")?,
            event_id: EventId::from_bytes(fixed(object, "event_id")?),
            event_kind: FederationEventKind::from_wire(unsigned_u16(object, "event_kind")?)
                .map_err(registry_error)?,
            correlation,
            cross_profile,
        })
    }

    /// Wraps one validated `event.<kind>` arm into a complete base event.
    ///
    /// A present cross-profile tuple marks one part of a Stage 08 barrier;
    /// its count must lie in `2..=2048` with the index below it.
    pub fn build(&self, event: &SchemaObject) -> Result<SchemaObject, CodecError> {
        expect_schema(event, event_schema_name(self.event_kind))?;
        let (mutation_id, part_index, part_count) = match &self.cross_profile {
            None => (&[][..], 0, 0),
            Some(part) => {
                if !(2..=2048).contains(&part.part_count) || part.part_index >= part.part_count {
                    return Err(CodecError::CrossReference);
                }
                (
                    &part.mutation_id[..],
                    u64::from(part.part_index),
                    u64::from(part.part_count),
                )
            }
        };
        let encoded = event.encode_canonical()?;
        let (home, incarnation, origin, generation, sequence, request) = match &self.correlation {
            None => (&[][..], &[][..], &[][..], 0, 0, &[][..]),
            Some(correlation) => (
                &correlation.replay_key.home_server_id.as_bytes()[..],
                &correlation.replay_key.server_incarnation.as_bytes()[..],
                &correlation.replay_key.origin_id.as_bytes()[..],
                correlation.replay_key.origin_generation,
                correlation.replay_key.operation_sequence,
                &correlation.request_id.as_bytes()[..],
            ),
        };
        SchemaObject::new(
            EVENT_SCHEMA,
            vec![
                WireValue::Unsigned(u64::from(FEDERATION_PROFILE_VERSION)),
                opaque(self.network_id.as_bytes())?,
                opaque(self.target_server_id.as_bytes())?,
                WireValue::Unsigned(self.projection_generation),
                WireValue::Unsigned(self.coordinator_state_generation),
                WireValue::Unsigned(self.delivery_sequence),
                opaque(self.event_id.as_bytes())?,
                WireValue::Unsigned(u64::from(self.event_kind.wire_value())),
                opaque(encoded.as_slice())?,
                opaque(mutation_id)?,
                WireValue::Unsigned(part_index),
                WireValue::Unsigned(part_count),
                opaque(home)?,
                opaque(incarnation)?,
                opaque(origin)?,
                WireValue::Unsigned(generation),
                WireValue::Unsigned(sequence),
                opaque(request)?,
            ],
        )
    }
}

/// Decodes the event arm of one validated event under its kind schema.
pub fn decode_event_arm(
    event: &SchemaObject,
    budget: &mut DecodeBudget,
) -> Result<SchemaObject, CodecError> {
    let header = EventHeader::from_object(event)?;
    let encoded = opaque_field(event, "event")?;
    SchemaObject::decode_exact(event_schema_name(header.event_kind), encoded, budget)
}

/// The registered session bound to an origin generation, when any.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginSession {
    /// The authoritative session.
    pub session_id: SessionId,
    /// The session's routing identity.
    pub user_id: UserId,
}

/// The authenticated account bound to an origin generation, when any.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginAccount {
    /// The account identity.
    pub account_id: AccountId,
    /// The nonzero account-session generation.
    pub account_session_generation: u64,
}

/// One complete typed `FederationOrigin`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginRecord {
    /// Network identity that must match link configuration.
    pub network_id: NetworkId,
    /// The edge that owns the origin.
    pub home_server_id: ServerId,
    /// The edge incarnation that allocated it.
    pub server_incarnation: ServerIncarnation,
    /// The connection-scoped origin identity.
    pub origin_id: OriginId,
    /// Zero for the pre-registration principal; incremented by UPDATE.
    pub generation: u64,
    /// All-zero for generation zero, else the accepted predecessor object ID.
    pub previous_origin_object_id: [u8; 32],
    /// The accepted transport identity; never changes.
    pub connection_id: ConnectionId,
    /// Present exactly for a registered session.
    pub session: Option<OriginSession>,
    /// Present exactly for an authenticated session.
    pub account: Option<OriginAccount>,
    /// The connection nonce; never changes.
    pub connection_nonce: [u8; 32],
}

impl OriginRecord {
    /// Reads one validated `FederationOrigin` object.
    pub fn from_object(object: &SchemaObject) -> Result<Self, CodecError> {
        expect_schema(object, ORIGIN_SCHEMA)?;
        let session = match (
            optional_fixed::<16>(object, "session_id")?,
            optional_fixed::<16>(object, "user_id")?,
        ) {
            (None, None) => None,
            (Some(session_id), Some(user_id)) => Some(OriginSession {
                session_id: SessionId::from_bytes(session_id),
                user_id: UserId::from_bytes(user_id),
            }),
            _ => return Err(CodecError::CrossReference),
        };
        let account = match opaque_field(object, "account_id")? {
            [] => None,
            bytes => Some(OriginAccount {
                account_id: AccountId::parse_wire_bytes(bytes)
                    .map_err(|_| CodecError::CrossReference)?,
                account_session_generation: unsigned(object, "account_session_generation")?,
            }),
        };
        Ok(Self {
            network_id: NetworkId::from_bytes(fixed(object, "network_id")?),
            home_server_id: ServerId::from_bytes(fixed(object, "home_server_id")?),
            server_incarnation: ServerIncarnation::from_bytes(fixed(object, "server_incarnation")?),
            origin_id: OriginId::from_bytes(fixed(object, "origin_id")?),
            generation: unsigned(object, "generation")?,
            previous_origin_object_id: fixed(object, "previous_origin_object_id")?,
            connection_id: ConnectionId::from_bytes(fixed(object, "connection_id")?),
            session,
            account,
            connection_nonce: fixed(object, "connection_nonce")?,
        })
    }

    /// Builds the validated `FederationOrigin` object.
    pub fn to_object(&self) -> Result<SchemaObject, CodecError> {
        let (session_id, user_id) = match &self.session {
            None => (&[][..], &[][..]),
            Some(session) => (
                &session.session_id.as_bytes()[..],
                &session.user_id.as_bytes()[..],
            ),
        };
        let (account_text, account_generation) = match &self.account {
            None => (String::new(), 0),
            Some(account) => (
                account.account_id.to_text(),
                account.account_session_generation,
            ),
        };
        SchemaObject::new(
            ORIGIN_SCHEMA,
            vec![
                WireValue::Unsigned(u64::from(FEDERATION_PROFILE_VERSION)),
                opaque(self.network_id.as_bytes())?,
                opaque(self.home_server_id.as_bytes())?,
                opaque(self.server_incarnation.as_bytes())?,
                opaque(self.origin_id.as_bytes())?,
                WireValue::Unsigned(self.generation),
                opaque(&self.previous_origin_object_id)?,
                opaque(self.connection_id.as_bytes())?,
                opaque(session_id)?,
                opaque(user_id)?,
                opaque(account_text.as_bytes())?,
                WireValue::Unsigned(account_generation),
                opaque(&self.connection_nonce)?,
            ],
        )
    }
}

/// Typed fixed fields of one `FederationProjectionEntry`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionEntryHeader {
    /// Network identity that must match link configuration.
    pub network_id: NetworkId,
    /// The edge the entry is projected to.
    pub target_server_id: ServerId,
    /// The projection generation the entry belongs to.
    pub projection_generation: u64,
    /// The closed projection arm selector.
    pub projection_kind: FederationProjectionKind,
}

impl ProjectionEntryHeader {
    /// Reads the fixed fields of one validated `FederationProjectionEntry`.
    pub fn from_object(object: &SchemaObject) -> Result<Self, CodecError> {
        expect_schema(object, PROJECTION_ENTRY_SCHEMA)?;
        let projection = structure(object, "projection")?;
        Ok(Self {
            network_id: NetworkId::from_bytes(fixed(object, "network_id")?),
            target_server_id: ServerId::from_bytes(fixed(object, "target_server_id")?),
            projection_generation: unsigned(object, "projection_generation")?,
            projection_kind: FederationProjectionKind::from_wire(unsigned_u16(
                projection,
                "projection_kind",
            )?)
            .map_err(registry_error)?,
        })
    }

    /// Wraps one validated projection arm into a complete entry.
    pub fn build(&self, arm: &SchemaObject) -> Result<SchemaObject, CodecError> {
        expect_schema(arm, projection_schema_name(self.projection_kind))?;
        let encoded = arm.encode_canonical()?;
        let value = SchemaObject::new(
            PROJECTION_VALUE_SCHEMA,
            vec![
                WireValue::Unsigned(u64::from(self.projection_kind.wire_value())),
                opaque(encoded.as_slice())?,
            ],
        )?;
        SchemaObject::new(
            PROJECTION_ENTRY_SCHEMA,
            vec![
                WireValue::Unsigned(u64::from(FEDERATION_PROFILE_VERSION)),
                opaque(self.network_id.as_bytes())?,
                opaque(self.target_server_id.as_bytes())?,
                WireValue::Unsigned(self.projection_generation),
                WireValue::Structure(value),
            ],
        )
    }
}

/// Decodes the projection arm of one validated entry and returns it with its
/// Appendix-B.4 primary key `(kind, primary-ID bytes)` used for snapshot order.
pub fn decode_projection_arm(
    entry: &SchemaObject,
    budget: &mut DecodeBudget,
) -> Result<(SchemaObject, ProjectionPrimaryKey), CodecError> {
    let header = ProjectionEntryHeader::from_object(entry)?;
    let projection = structure(entry, "projection")?;
    let encoded = opaque_field(projection, "value")?;
    let arm = SchemaObject::decode_exact(
        projection_schema_name(header.projection_kind),
        encoded,
        budget,
    )?;
    let key = ProjectionPrimaryKey::of(header.projection_kind, &arm)?;
    Ok((arm, key))
}

/// The unique snapshot ordering key of one projection entry.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProjectionPrimaryKey {
    kind: u16,
    primary: Vec<u8>,
}

impl ProjectionPrimaryKey {
    /// Derives the key from one validated projection arm.
    pub fn of(kind: FederationProjectionKind, arm: &SchemaObject) -> Result<Self, CodecError> {
        expect_schema(arm, projection_schema_name(kind))?;
        let primary = match kind {
            FederationProjectionKind::Session => fixed::<16>(arm, "user_id")?.to_vec(),
            FederationProjectionKind::ChannelDetail => {
                fixed::<16>(arm, "channel_instance_id")?.to_vec()
            }
            FederationProjectionKind::Membership => {
                concat_fixed(fixed(arm, "channel_instance_id")?, fixed(arm, "user_id")?)
            }
            FederationProjectionKind::Invite => {
                concat_fixed(fixed(arm, "channel_instance_id")?, fixed(arm, "invite_id")?)
            }
            FederationProjectionKind::Account => fixed::<24>(arm, "account_id")?.to_vec(),
        };
        Ok(Self {
            kind: kind.wire_value(),
            primary,
        })
    }

    /// Returns the projection kind discriminant.
    #[must_use]
    pub const fn kind(&self) -> u16 {
        self.kind
    }

    /// Borrows the primary identity bytes.
    #[must_use]
    pub fn primary(&self) -> &[u8] {
        &self.primary
    }

    /// Returns the User ID of a `session` key or the Channel ID of every
    /// channel-scoped key.
    #[must_use]
    pub fn leading_id(&self) -> Option<[u8; 16]> {
        self.primary.get(..16)?.try_into().ok()
    }

    /// Returns the Channel ID of a membership or invite key.
    #[must_use]
    pub fn channel_id(&self) -> Option<ChannelInstanceId> {
        if !matches!(self.kind, 3 | 4 | 6) {
            return None;
        }
        self.leading_id().map(ChannelInstanceId::from_bytes)
    }

    /// Returns the Invite ID of an invite key.
    #[must_use]
    pub fn invite_id(&self) -> Option<InviteId> {
        if self.kind != 6 {
            return None;
        }
        let bytes: [u8; 16] = self.primary.get(16..32)?.try_into().ok()?;
        Some(InviteId::from_bytes(bytes))
    }
}

fn concat_fixed(first: [u8; 16], second: [u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(32);
    key.extend_from_slice(&first);
    key.extend_from_slice(&second);
    key
}

/// Returns the exact `operation.<name>` schema for one opcode.
#[must_use]
pub const fn operation_schema_name(opcode: FederationOpcode) -> &'static str {
    match opcode {
        FederationOpcode::SessionOpen => "operation.session_open",
        FederationOpcode::SessionClose => "operation.session_close",
        FederationOpcode::NickChange => "operation.nick_change",
        FederationOpcode::Join => "operation.join",
        FederationOpcode::Part => "operation.part",
        FederationOpcode::ChannelMode => "operation.channel_mode",
        FederationOpcode::UserMode => "operation.user_mode",
        FederationOpcode::Topic => "operation.topic",
        FederationOpcode::Invite => "operation.invite",
        FederationOpcode::Kick => "operation.kick",
        FederationOpcode::Message => "operation.message",
        FederationOpcode::Away => "operation.away",
        FederationOpcode::Setname => "operation.setname",
        FederationOpcode::ChannelRegister => "operation.channel_register",
        FederationOpcode::ChannelUnregister => "operation.channel_unregister",
        FederationOpcode::AccountSettings => "operation.account_settings",
        FederationOpcode::HistoryQuery => "operation.history_query",
        FederationOpcode::DirectoryQuery => "operation.directory_query",
        FederationOpcode::AccountCreateStart => "operation.account_create_start",
        FederationOpcode::AccountCreateFinish => "operation.account_create_finish",
        FederationOpcode::OpaqueAuthStart => "operation.opaque_auth_start",
        FederationOpcode::OpaqueAuthFinish => "operation.opaque_auth_finish",
        FederationOpcode::ChannelSettings => "operation.channel_settings",
        FederationOpcode::CredentialChangeStart => "operation.credential_change_start",
        FederationOpcode::CredentialChangeFinish => "operation.credential_change_finish",
    }
}

/// Returns the exact `result.<name>` schema for one result kind.
#[must_use]
pub const fn result_schema_name(kind: FederationResultKind) -> &'static str {
    match kind {
        FederationResultKind::Failed => "result.failed",
        FederationResultKind::Committed => "result.committed",
        FederationResultKind::SessionRegistered => "result.session_registered",
        FederationResultKind::AuthChallenge => "result.auth_challenge",
        FederationResultKind::Authenticated => "result.authenticated",
        FederationResultKind::AccountCreated => "result.account_created",
        FederationResultKind::ReplyPage => "result.reply_page",
        FederationResultKind::NoContent => "result.no_content",
        FederationResultKind::HistoryPage => "result.history_page",
        FederationResultKind::HistoryExpired => "result.history_expired",
    }
}

/// Returns the exact `event.<name>` schema for one event kind.
#[must_use]
pub const fn event_schema_name(kind: FederationEventKind) -> &'static str {
    match kind {
        FederationEventKind::SessionVisible => "event.session_visible",
        FederationEventKind::SessionHidden => "event.session_hidden",
        FederationEventKind::NicknameChanged => "event.nickname_changed",
        FederationEventKind::ChannelVisible => "event.channel_visible",
        FederationEventKind::ChannelHidden => "event.channel_hidden",
        FederationEventKind::MemberJoined => "event.member_joined",
        FederationEventKind::MemberParted => "event.member_parted",
        FederationEventKind::ChannelModesChanged => "event.channel_modes_changed",
        FederationEventKind::TopicChanged => "event.topic_changed",
        FederationEventKind::Invited => "event.invited",
        FederationEventKind::Kicked => "event.kicked",
        FederationEventKind::AwayChanged => "event.away_changed",
        FederationEventKind::DisplayNameChanged => "event.display_name_changed",
        FederationEventKind::MessageDelivered => "event.message_delivered",
        FederationEventKind::ChannelDestroyed => "event.channel_destroyed",
        FederationEventKind::AccountLabelChanged => "event.account_label_changed",
        FederationEventKind::NetworkNotice => "event.network_notice",
        FederationEventKind::UserModesChanged => "event.user_modes_changed",
        FederationEventKind::ChannelPolicyChanged => "event.channel_policy_changed",
        FederationEventKind::ChannelMembershipsRecomputed => "event.channel_memberships_recomputed",
        FederationEventKind::AccountStateChanged => "event.account_state_changed",
        FederationEventKind::RequestCompleted => "event.request_completed",
        FederationEventKind::InviteRemoved => "event.invite_removed",
    }
}

/// Returns the exact projection arm schema for one projection kind.
#[must_use]
pub const fn projection_schema_name(kind: FederationProjectionKind) -> &'static str {
    match kind {
        FederationProjectionKind::Session => "FederationSessionProjection",
        FederationProjectionKind::ChannelDetail => "FederationChannelDetail",
        FederationProjectionKind::Membership => "FederationMembership",
        FederationProjectionKind::Invite => "FederationInviteProjection",
        FederationProjectionKind::Account => "FederationAccountProjection",
    }
}

/// Returns the closed Appendix-B.6 success result kinds for one opcode.
///
/// `failed` is permitted for every opcode and is not listed here.
#[must_use]
pub const fn permitted_success_results(
    opcode: FederationOpcode,
) -> &'static [FederationResultKind] {
    use FederationResultKind::{
        AccountCreated, AuthChallenge, Authenticated, Committed, HistoryExpired, HistoryPage,
        NoContent, ReplyPage, SessionRegistered,
    };
    match opcode {
        FederationOpcode::SessionOpen => &[SessionRegistered],
        FederationOpcode::SessionClose
        | FederationOpcode::NickChange
        | FederationOpcode::Join
        | FederationOpcode::Part
        | FederationOpcode::ChannelMode
        | FederationOpcode::UserMode
        | FederationOpcode::Topic
        | FederationOpcode::Invite
        | FederationOpcode::Kick
        | FederationOpcode::Away
        | FederationOpcode::Setname
        | FederationOpcode::ChannelRegister
        | FederationOpcode::ChannelUnregister
        | FederationOpcode::ChannelSettings
        | FederationOpcode::CredentialChangeFinish => &[Committed],
        FederationOpcode::Message | FederationOpcode::AccountSettings => &[Committed, NoContent],
        FederationOpcode::HistoryQuery => &[HistoryPage, HistoryExpired],
        FederationOpcode::DirectoryQuery => &[ReplyPage, NoContent],
        FederationOpcode::AccountCreateStart
        | FederationOpcode::OpaqueAuthStart
        | FederationOpcode::CredentialChangeStart => &[AuthChallenge],
        FederationOpcode::AccountCreateFinish => &[AccountCreated],
        FederationOpcode::OpaqueAuthFinish => &[Authenticated],
    }
}

/// Reports whether one result kind may answer one opcode.
#[must_use]
pub fn result_kind_permitted(opcode: FederationOpcode, kind: FederationResultKind) -> bool {
    kind == FederationResultKind::Failed || permitted_success_results(opcode).contains(&kind)
}

/// Returns the registry spelling of one opcode.
pub fn opcode_registry_name(opcode: FederationOpcode) -> Result<&'static str, CodecError> {
    enum_entry_name("FederationOpcode", opcode.wire_value())
}

/// Returns the registry spelling of one result kind.
pub fn result_kind_registry_name(kind: FederationResultKind) -> Result<&'static str, CodecError> {
    enum_entry_name("FederationResultKind", kind.wire_value())
}

/// Returns the frozen `mapping|result.<opcode>` line value for one opcode.
pub fn result_mapping_value(opcode: FederationOpcode) -> Result<&'static str, CodecError> {
    let opcode_name = opcode_registry_name(opcode)?;
    MAPPING_DESCRIPTORS
        .iter()
        .find(|descriptor| {
            descriptor
                .name
                .strip_prefix("result.")
                .is_some_and(|name| name == opcode_name)
        })
        .map(|descriptor| descriptor.value)
        .ok_or(CodecError::UnknownSchema)
}

fn enum_entry_name(registry: &str, value: u16) -> Result<&'static str, CodecError> {
    ENUM_REGISTRY
        .iter()
        .find(|descriptor| descriptor.name == registry)
        .and_then(|descriptor| descriptor.entries.iter().find(|entry| entry.value == value))
        .map(|entry| entry.name)
        .ok_or(CodecError::UnknownDiscriminant)
}

fn replay_key(object: &SchemaObject) -> Result<ReplayKey, CodecError> {
    Ok(ReplayKey {
        home_server_id: ServerId::from_bytes(fixed(object, "home_server_id")?),
        server_incarnation: ServerIncarnation::from_bytes(fixed(object, "server_incarnation")?),
        origin_id: OriginId::from_bytes(fixed(object, "origin_id")?),
        origin_generation: unsigned(object, "origin_generation")?,
        operation_sequence: unsigned(object, "operation_sequence")?,
    })
}

fn registry_error(_: RegistryValueError) -> CodecError {
    CodecError::UnknownDiscriminant
}

/// Copies bytes into one opaque wire value without a peer-sized overshoot.
pub fn opaque(bytes: &[u8]) -> Result<WireValue, CodecError> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| CodecError::AllocationFailed)?;
    owned.extend_from_slice(bytes);
    Ok(WireValue::Opaque(owned))
}

/// Requires the object to carry the named schema.
pub fn expect_schema(object: &SchemaObject, name: &str) -> Result<(), CodecError> {
    if object.schema().name == name {
        return Ok(());
    }
    Err(CodecError::SchemaMismatch)
}

/// Borrows one named field of a validated object.
pub fn field<'a>(object: &'a SchemaObject, name: &str) -> Result<&'a WireValue, CodecError> {
    object
        .schema()
        .fields
        .iter()
        .zip(object.fields())
        .find_map(|(descriptor, value)| (descriptor.name == name).then_some(value))
        .ok_or(CodecError::SchemaMismatch)
}

/// Borrows one named opaque field.
pub fn opaque_field<'a>(object: &'a SchemaObject, name: &str) -> Result<&'a [u8], CodecError> {
    match field(object, name)? {
        WireValue::Opaque(bytes) => Ok(bytes),
        _ => Err(CodecError::TypeMismatch),
    }
}

/// Borrows one named nested structure.
pub fn structure<'a>(object: &'a SchemaObject, name: &str) -> Result<&'a SchemaObject, CodecError> {
    match field(object, name)? {
        WireValue::Structure(nested) => Ok(nested),
        _ => Err(CodecError::TypeMismatch),
    }
}

/// Borrows one named projection-union arm with its discriminant.
pub fn projection_union<'a>(
    object: &'a SchemaObject,
    name: &str,
) -> Result<(u16, &'a SchemaObject), CodecError> {
    match field(object, name)? {
        WireValue::ProjectionUnion {
            discriminant,
            value,
        } => Ok((*discriminant, value)),
        _ => Err(CodecError::TypeMismatch),
    }
}

/// Borrows one named vector of nested structures.
pub fn vector<'a>(object: &'a SchemaObject, name: &str) -> Result<&'a [SchemaObject], CodecError> {
    match field(object, name)? {
        WireValue::Vector(items) => Ok(items),
        _ => Err(CodecError::TypeMismatch),
    }
}

/// Reads one named unsigned or enumeration field.
pub fn unsigned(object: &SchemaObject, name: &str) -> Result<u64, CodecError> {
    match field(object, name)? {
        WireValue::Unsigned(value) => Ok(*value),
        _ => Err(CodecError::TypeMismatch),
    }
}

/// Reads one named unsigned field that must fit sixteen bits.
pub fn unsigned_u16(object: &SchemaObject, name: &str) -> Result<u16, CodecError> {
    u16::try_from(unsigned(object, name)?).map_err(|_| CodecError::IntegerOutOfRange)
}

/// Reads one named unsigned field that must fit thirty-two bits.
pub fn unsigned_u32(object: &SchemaObject, name: &str) -> Result<u32, CodecError> {
    u32::try_from(unsigned(object, name)?).map_err(|_| CodecError::IntegerOutOfRange)
}

/// Reads one named fixed-length opaque field.
pub fn fixed<const LENGTH: usize>(
    object: &SchemaObject,
    name: &str,
) -> Result<[u8; LENGTH], CodecError> {
    opaque_field(object, name)?
        .try_into()
        .map_err(|_| CodecError::CrossReference)
}

/// Reads one named opaque field that is empty or exactly `LENGTH` bytes.
pub fn optional_fixed<const LENGTH: usize>(
    object: &SchemaObject,
    name: &str,
) -> Result<Option<[u8; LENGTH]>, CodecError> {
    match opaque_field(object, name)? {
        [] => Ok(None),
        bytes => bytes
            .try_into()
            .map(Some)
            .map_err(|_| CodecError::CrossReference),
    }
}

/// Reads one named opaque field as validated UTF-8 text.
pub fn text<'a>(object: &'a SchemaObject, name: &str) -> Result<&'a str, CodecError> {
    std::str::from_utf8(opaque_field(object, name)?).map_err(|_| CodecError::TypeMismatch)
}

#[cfg(test)]
#[path = "tests/objects.rs"]
mod tests;
