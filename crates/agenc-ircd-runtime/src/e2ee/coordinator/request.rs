//! Companion request execution (companion Section 12.5): decoding, the
//! replay classification under the `irc-mls-v1` namespace, opcode
//! dispatch, and the exact result object with its response descriptors.

use agenc_ircd_domain::e2ee::projection::{
    Completion, DescriptorRule, EmptyKind, Opcode, PendingKind, ResultKind, StoreKind,
    completion_for, descriptor_rule,
};
use agenc_ircd_e2ee::DecodeBudget;
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::federation::{
    IrcFederationEmptyKind, IrcFederationPackageKind, IrcFederationPendingKind,
    IrcFederationRequest, IrcFederationResponseDescriptor, IrcFederationResult,
    IrcFederationResultKind, IrcFederationStoreKind,
};
use agenc_ircd_e2ee::tls::{Opaque, TlsDecode, TlsEncode, TlsVec, Writer};
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;
use agenc_ircd_storage::e2ee_records::{REPLAY_ROW_KIND, ReplayKey, ReplayRow};
use agenc_ircd_storage::{PersistentRecordValue, StoredKey, TableId};

use super::events::EventContent;
use super::{CompanionCoordinator, CompanionOriginKey, CompanionState, CompleteRequest, Effect};
use crate::state_core::durable::AccountServiceDurableWrite;

/// Bytes a request object may decode into.
const REQUEST_DECODE_BYTES: usize = 1 << 20;
/// Values a request object may decode into.
const REQUEST_DECODE_VALUES: usize = 1 << 12;

/// The typed result of one executed request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResultBody {
    /// `failed`.
    Failed {
        /// Reply code.
        code: E2eeReplyCode,
        /// Copied request context.
        context: Vec<u8>,
    },
    /// `accepted_event`.
    AcceptedEvent,
    /// `bound`.
    Bound {
        /// Conversation.
        conversation_id: [u8; 32],
        /// Binding.
        binding_id: [u8; 32],
        /// Binding package object.
        binding_object_id: [u8; 32],
    },
    /// `closed`.
    Closed {
        /// Conversation.
        conversation_id: [u8; 32],
        /// Close identifier.
        close_id: [u8; 32],
    },
    /// `stored`.
    Stored(StoreKind, [u8; 32]),
    /// `commit_acked`.
    CommitAcked([u8; 32], [u8; 32], [u8; 32]),
    /// `pending`.
    Pending([u8; 32], PendingKind, [u8; 32]),
    /// `empty`.
    Empty(EmptyKind),
    /// `account`.
    Account([u8; 24], u64),
    /// `attached`.
    Attached([u8; 16], u64),
    /// `attach_challenge`.
    AttachChallenge([u8; 16], [u8; 32]),
    /// `revoked`.
    Revoked(Vec<u8>),
    /// `reserved`.
    Reserved([u8; 16], [u8; 32]),
    /// `finalized`.
    Finalized([u8; 32], u64, [u8; 32], [u8; 32]),
    /// `aborted`.
    Aborted([u8; 32], [u8; 32], [u8; 32], [u8; 32]),
    /// `claimed`.
    Claimed([u8; 16], Vec<u8>, [u8; 32]),
    /// `object_page`.
    ObjectPage,
    /// `mailbox_page`.
    MailboxPage,
    /// `reinit_staged`.
    ReinitStaged([u8; 32], [u8; 32], [u8; 32]),
    /// `reinit_acked`.
    ReinitAcked([u8; 32], [u8; 32], [u8; 32]),
    /// `reinit_activated`.
    ReinitActivated([u8; 32], [u8; 32], [u8; 32], [u8; 32]),
    /// `reinit_aborted`.
    ReinitAborted([u8; 32], [u8; 32], [u8; 32], [u8; 32]),
    /// `mailbox_acked`.
    MailboxAcked([u8; 32], [u8; 32]),
}

impl ResultBody {
    /// The projection result kind.
    #[must_use]
    pub const fn kind(&self) -> ResultKind {
        match self {
            Self::Failed { .. } => ResultKind::Failed,
            Self::AcceptedEvent => ResultKind::AcceptedEvent,
            Self::Bound { .. } => ResultKind::Bound,
            Self::Closed { .. } => ResultKind::Closed,
            Self::Stored(kind, _) => ResultKind::Stored(*kind),
            Self::CommitAcked(..) => ResultKind::CommitAcked,
            Self::Pending(_, kind, _) => ResultKind::Pending(*kind),
            Self::Empty(kind) => ResultKind::Empty(*kind),
            Self::Account(..) => ResultKind::Account,
            Self::Attached(..) => ResultKind::Attached,
            Self::AttachChallenge(..) => ResultKind::AttachChallenge,
            Self::Revoked(_) => ResultKind::Revoked,
            Self::Reserved(..) => ResultKind::Reserved,
            Self::Finalized(..) => ResultKind::Finalized,
            Self::Aborted(..) => ResultKind::Aborted,
            Self::Claimed(..) => ResultKind::Claimed,
            Self::ObjectPage => ResultKind::ObjectPage,
            Self::MailboxPage => ResultKind::MailboxPage,
            Self::ReinitStaged(..) => ResultKind::ReinitStaged,
            Self::ReinitAcked(..) => ResultKind::ReinitAcked,
            Self::ReinitActivated(..) => ResultKind::ReinitActivated,
            Self::ReinitAborted(..) => ResultKind::ReinitAborted,
            Self::MailboxAcked(..) => ResultKind::MailboxAcked,
        }
    }

    fn wire_kind(&self) -> IrcFederationResultKind {
        use IrcFederationResultKind as W;
        match self {
            Self::Failed { .. } => W::Failed,
            Self::AcceptedEvent => W::AcceptedEvent,
            Self::Bound { .. } => W::Bound,
            Self::Closed { .. } => W::Closed,
            Self::Stored(..) => W::Stored,
            Self::CommitAcked(..) => W::CommitAcked,
            Self::Pending(..) => W::Pending,
            Self::Empty(_) => W::Empty,
            Self::Account(..) => W::Account,
            Self::Attached(..) => W::Attached,
            Self::AttachChallenge(..) => W::AttachChallenge,
            Self::Revoked(_) => W::Revoked,
            Self::Reserved(..) => W::Reserved,
            Self::Finalized(..) => W::Finalized,
            Self::Aborted(..) => W::Aborted,
            Self::Claimed(..) => W::Claimed,
            Self::ObjectPage => W::ObjectPage,
            Self::MailboxPage => W::MailboxPage,
            Self::ReinitStaged(..) => W::ReinitStaged,
            Self::ReinitAcked(..) => W::ReinitAcked,
            Self::ReinitActivated(..) => W::ReinitActivated,
            Self::ReinitAborted(..) => W::ReinitAborted,
            Self::MailboxAcked(..) => W::MailboxAcked,
        }
    }

    // agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one match writes every 12.5 result tuple in registry order; splitting it would separate the arms from the kind table they mirror
    /// The exact TLS tuple of the 12.5 result table.
    pub fn encode(&self) -> Result<Vec<u8>, E2eeReplyCode> {
        let mut writer = Writer::new();
        let outcome = match self {
            Self::Failed { code, context } => writer
                .opaque(code.token().as_bytes(), 1, 64)
                .and_then(|()| writer.opaque(context, 0, 255)),
            Self::AcceptedEvent | Self::ObjectPage | Self::MailboxPage => Ok(()),
            Self::Bound {
                conversation_id,
                binding_id,
                binding_object_id,
            } => writer
                .fixed(conversation_id)
                .and_then(|()| writer.fixed(binding_id))
                .and_then(|()| writer.fixed(binding_object_id)),
            Self::Closed {
                conversation_id,
                close_id,
            } => writer
                .fixed(conversation_id)
                .and_then(|()| writer.fixed(close_id)),
            Self::Stored(kind, object_id) => writer
                .u8(store_kind(*kind).value())
                .and_then(|()| writer.fixed(object_id)),
            Self::CommitAcked(a, b, c)
            | Self::ReinitStaged(a, b, c)
            | Self::ReinitAcked(a, b, c) => writer
                .fixed(a)
                .and_then(|()| writer.fixed(b))
                .and_then(|()| writer.fixed(c)),
            Self::Pending(conversation, kind, object) => writer
                .fixed(conversation)
                .and_then(|()| writer.u8(pending_kind(*kind).value()))
                .and_then(|()| writer.fixed(object)),
            Self::Empty(kind) => writer.u8(empty_kind(*kind).value()),
            Self::Account(account, generation) => writer
                .opaque(account, 1, 255)
                .and_then(|()| writer.u64(*generation)),
            Self::Attached(device, generation) => {
                writer.fixed(device).and_then(|()| writer.u64(*generation))
            }
            Self::AttachChallenge(device, object) => {
                writer.fixed(device).and_then(|()| writer.fixed(object))
            }
            Self::Revoked(reference) => writer.opaque(reference, 1, 255),
            Self::Reserved(reservation, object) => writer
                .fixed(reservation)
                .and_then(|()| writer.fixed(object)),
            Self::Finalized(a, epoch, c, d) => writer
                .fixed(a)
                .and_then(|()| writer.u64(*epoch))
                .and_then(|()| writer.fixed(c))
                .and_then(|()| writer.fixed(d)),
            Self::Aborted(a, b, c, d)
            | Self::ReinitActivated(a, b, c, d)
            | Self::ReinitAborted(a, b, c, d) => writer
                .fixed(a)
                .and_then(|()| writer.fixed(b))
                .and_then(|()| writer.fixed(c))
                .and_then(|()| writer.fixed(d)),
            Self::Claimed(device, reference, object) => writer
                .fixed(device)
                .and_then(|()| writer.u8(IrcFederationPackageKind::NormalPackage.value()))
                .and_then(|()| writer.opaque(reference, 1, 255))
                .and_then(|()| writer.fixed(object)),
            Self::MailboxAcked(token, object) => {
                writer.fixed(token).and_then(|()| writer.fixed(object))
            }
        };
        outcome.map_err(|_| E2eeReplyCode::InvalidFragment)?;
        Ok(writer.into_bytes())
    }
}

const fn store_kind(kind: StoreKind) -> IrcFederationStoreKind {
    match kind {
        StoreKind::Authorization => IrcFederationStoreKind::StoreAuthorization,
        StoreKind::Identity => IrcFederationStoreKind::StoreIdentity,
        StoreKind::Roster => IrcFederationStoreKind::StoreRoster,
        StoreKind::Capabilities => IrcFederationStoreKind::StoreCapabilities,
        StoreKind::Package => IrcFederationStoreKind::StorePackage,
        StoreKind::Application => IrcFederationStoreKind::StoreApplication,
        StoreKind::Binding => IrcFederationStoreKind::StoreBinding,
        StoreKind::Welcome => IrcFederationStoreKind::StoreWelcome,
        StoreKind::StagedReinit => IrcFederationStoreKind::StoreStagedReinit,
        StoreKind::Policy => IrcFederationStoreKind::StorePolicy,
    }
}

const fn pending_kind(kind: PendingKind) -> IrcFederationPendingKind {
    match kind {
        PendingKind::Finalization => IrcFederationPendingKind::PendingFinalization,
        PendingKind::Abort => IrcFederationPendingKind::PendingAbort,
        PendingKind::ReinitAttempt => IrcFederationPendingKind::PendingReinitAttempt,
        PendingKind::ReinitActivate => IrcFederationPendingKind::PendingReinitActivate,
        PendingKind::ReinitAbort => IrcFederationPendingKind::PendingReinitAbort,
    }
}

const fn empty_kind(kind: EmptyKind) -> IrcFederationEmptyKind {
    match kind {
        EmptyKind::Authorizations => IrcFederationEmptyKind::EmptyAuthorizations,
        EmptyKind::Acks => IrcFederationEmptyKind::EmptyAcks,
        EmptyKind::Receipts => IrcFederationEmptyKind::EmptyReceipts,
        EmptyKind::Objects => IrcFederationEmptyKind::EmptyObjects,
        EmptyKind::Identity => IrcFederationEmptyKind::EmptyIdentity,
        EmptyKind::RootChain => IrcFederationEmptyKind::EmptyRootChain,
        EmptyKind::Roster => IrcFederationEmptyKind::EmptyRoster,
        EmptyKind::Capabilities => IrcFederationEmptyKind::EmptyCapabilities,
        EmptyKind::Package => IrcFederationEmptyKind::EmptyPackage,
        EmptyKind::Application => IrcFederationEmptyKind::EmptyApplication,
        EmptyKind::Binding => IrcFederationEmptyKind::EmptyBinding,
        EmptyKind::BindingLock => IrcFederationEmptyKind::EmptyBindingLock,
        EmptyKind::Welcome => IrcFederationEmptyKind::EmptyWelcome,
        EmptyKind::StagedReinit => IrcFederationEmptyKind::EmptyStagedReinit,
    }
}

/// One response object with its descriptor fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseObject {
    /// The complete wire object bytes.
    pub bytes: Vec<u8>,
    /// Delivery token for mailbox pages.
    pub delivery_token: Option<[u8; 32]>,
    /// Target device for mailbox pages.
    pub target_device_id: Option<[u8; 16]>,
}

/// What one handler produced.
pub struct Outcome {
    /// The result body.
    pub result: ResultBody,
    /// Response objects in descriptor order.
    pub responses: Vec<ResponseObject>,
    /// The snapshot token for pages and singleton responses.
    pub snapshot_token: Option<[u8; 32]>,
    /// The next cursor for pages.
    pub next_cursor: Option<[u8; 32]>,
    /// Event contents in plan order (the plan is derived from them).
    pub events: Vec<EventContent>,
    /// Durable rows.
    pub(crate) writes: Vec<AccountServiceDurableWrite>,
    /// In-memory effects on commit.
    pub effects: Vec<Effect>,
    /// Whether the mutation is a security-state mutation (seven-day replay).
    pub security_mutation: bool,
    /// The base domain plan the same batch applies, when the operation
    /// changes base state (a channel binding); its events join a
    /// cross-profile barrier at every target that also receives companion
    /// events.
    pub base_plan: Option<agenc_ircd_domain::MutationPlan>,
}

impl Outcome {
    /// A failed outcome with no mutation.
    #[must_use]
    pub fn failed(code: E2eeReplyCode, context: Vec<u8>) -> Self {
        Self {
            result: ResultBody::Failed { code, context },
            responses: Vec::new(),
            snapshot_token: None,
            next_cursor: None,
            events: Vec::new(),
            writes: Vec::new(),
            effects: Vec::new(),
            security_mutation: false,
            base_plan: None,
        }
    }

    /// A scalar outcome without responses or events.
    #[must_use]
    pub fn scalar(result: ResultBody) -> Self {
        Self {
            result,
            responses: Vec::new(),
            snapshot_token: None,
            next_cursor: None,
            events: Vec::new(),
            writes: Vec::new(),
            effects: Vec::new(),
            security_mutation: false,
            base_plan: None,
        }
    }
}

/// The decoded request with its origin and payload.
pub struct Decoded {
    /// The request.
    pub request: IrcFederationRequest,
    /// The request object identifier.
    pub request_object_id: [u8; 32],
    /// The payload wire object, if any.
    pub payload: Option<IrcWireObject>,
    /// The raw payload bytes.
    pub payload_bytes: Option<Vec<u8>>,
}

/// Reads the payload object identifier a request names.
pub fn payload_object_id(request_bytes: &[u8]) -> Result<Option<[u8; 32]>, E2eeReplyCode> {
    let decoded = decode_request(request_bytes)?;
    Ok(decoded.payload_object_id.exactly::<32>().ok())
}

fn decode_request(bytes: &[u8]) -> Result<IrcFederationRequest, E2eeReplyCode> {
    let mut budget = DecodeBudget::new(REQUEST_DECODE_BYTES, REQUEST_DECODE_VALUES);
    let object = IrcWireObject::decode_kind(
        bytes,
        Some(IrcWireObjectKind::FederationRequest),
        &mut budget,
    )
    .map_err(|_| E2eeReplyCode::InvalidFragment)?;
    IrcFederationRequest::decode_exact(object.body(), &mut budget)
        .map_err(|_| E2eeReplyCode::InvalidFragment)
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one function walks the request envelope, parameter length, payload kind requirement, and correlation checks in the order the companion specifies
/// Decodes a complete request and its payload, checking the envelope.
pub fn decode(
    coordinator: &CompanionCoordinator,
    complete: &CompleteRequest,
) -> Result<Decoded, E2eeReplyCode> {
    let request = decode_request(&complete.request)?;
    if request.profile_version != 1 || request.network_id != coordinator.network_id {
        return Err(E2eeReplyCode::InvalidFragment);
    }
    let correlation = &complete.correlation;
    let agrees = request.home_server_id == correlation.peer_server_id_home()
        && request.server_incarnation == correlation.server_incarnation
        && request.origin_id == correlation.origin_id
        && request.origin_generation == correlation.origin_generation
        && request.operation_sequence == correlation.operation_sequence
        && request.request_id == correlation.request_id;
    if !agrees {
        return Err(E2eeReplyCode::InvalidFragment);
    }
    let declared = request.payload_object_id.exactly::<32>().ok();
    let payload = match (&complete.payload, declared) {
        (None, None) => None,
        (Some(bytes), Some(id)) => {
            if *agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes() != id {
                return Err(E2eeReplyCode::HashMismatch);
            }
            let mut budget = DecodeBudget::new(1 << 23, 1 << 16);
            let (kind, _) =
                IrcWireObject::peek(bytes).map_err(|_| E2eeReplyCode::InvalidFragment)?;
            Some(
                IrcWireObject::decode_kind(bytes, Some(kind), &mut budget)
                    .map_err(|_| E2eeReplyCode::InvalidFragment)?,
            )
        }
        _ => return Err(E2eeReplyCode::InvalidFragment),
    };
    Ok(Decoded {
        request_object_id: *agenc_ircd_e2ee::ObjectId::compute(&complete.request).as_bytes(),
        request,
        payload,
        payload_bytes: complete.payload.clone(),
    })
}

trait HomeExt {
    fn peer_server_id_home(&self) -> [u8; 16];
}

impl HomeExt for agenc_ircd_e2ee::federation::frames::Correlation {
    fn peer_server_id_home(&self) -> [u8; 16] {
        // On an EREQUEST the named peer is the coordinator; the request's
        // home server is the sending edge, which the transport already
        // authenticated. The caller substitutes it before comparison.
        self.peer_server_id
    }
}

/// The replay key of a request.
#[must_use]
pub fn replay_key(home: [u8; 16], request: &IrcFederationRequest) -> ReplayKey {
    ReplayKey {
        home_server_id: home,
        server_incarnation: request.server_incarnation,
        origin_id: request.origin_id,
        origin_generation: request.origin_generation,
        operation_sequence: request.operation_sequence,
    }
}

/// How a request relates to the replay namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Classified {
    /// A fresh request at the next sequence.
    Fresh,
    /// An exact duplicate; the stored result is resent.
    Replay(Vec<u8>, Vec<Vec<u8>>),
    /// A gap, a reused request identifier, or different bytes at the key.
    Violation,
}

/// Classifies a request against the origin's sequence and retained rows.
pub fn classify(state: &CompanionState, home: [u8; 16], decoded: &Decoded) -> Classified {
    let key = replay_key(home, &decoded.request);
    if let Some(row) = state.replays.get(&key) {
        if row.request_object_id != decoded.request_object_id
            || row.request_id != decoded.request.request_id
        {
            return Classified::Violation;
        }
        let Some(stored) = state.results.get(&decoded.request_object_id) else {
            return Classified::Violation;
        };
        let responses = stored
            .responses
            .iter()
            .filter_map(|id| state.objects.get(id).cloned())
            .collect();
        return Classified::Replay(stored.result.clone(), responses);
    }
    let origin_key = CompanionOriginKey {
        home_server_id: home,
        server_incarnation: decoded.request.server_incarnation,
        origin_id: decoded.request.origin_id,
    };
    let Some(origin) = state.origins.get(&origin_key) else {
        return Classified::Violation;
    };
    if origin.fenced
        || origin.suspended
        || origin.generation != decoded.request.origin_generation
        || origin.next_sequence != decoded.request.operation_sequence
    {
        return Classified::Violation;
    }
    Classified::Fresh
}

/// A durable row of table 23 (or 22).
pub(crate) fn state_row(
    table: TableId,
    kind: u16,
    key: StoredKey,
    body: Vec<u8>,
) -> Result<AccountServiceDurableWrite, E2eeReplyCode> {
    let encoded = PersistentRecordValue::new(table, kind, 1, 0, None, Vec::new(), body)
        .and_then(|value| value.encode())
        .map_err(|_| E2eeReplyCode::InvalidFragment)?;
    AccountServiceDurableWrite::put(table, key, encoded).map_err(|_| E2eeReplyCode::InvalidFragment)
}

/// The encoded result wire object for one outcome, with its descriptors,
/// after the completion table and descriptor registry have been checked.
pub fn encode_result(
    coordinator: &CompanionCoordinator,
    home: [u8; 16],
    decoded: &Decoded,
    outcome: &Outcome,
    state_generation: u64,
    completion_event_id: Option<[u8; 16]>,
) -> Result<Vec<u8>, E2eeReplyCode> {
    let opcode = Opcode(decoded.request.opcode.value());
    let result_kind = outcome.result.kind();
    let completion =
        completion_for(opcode, result_kind).map_err(|_| E2eeReplyCode::InvalidFragment)?;
    let rule = descriptor_rule(opcode, result_kind).map_err(|_| E2eeReplyCode::InvalidFragment)?;
    check_descriptors(&rule, &outcome.responses)?;
    let (generation, completion_id) = match completion {
        Completion::None => (0, None),
        Completion::Semantic(_) | Completion::Generic => (
            state_generation,
            Some(completion_event_id.ok_or(E2eeReplyCode::InvalidFragment)?),
        ),
    };
    let responses = outcome
        .responses
        .iter()
        .enumerate()
        .map(|(index, response)| descriptor(index, response))
        .collect::<Result<Vec<_>, _>>()?;
    let result = IrcFederationResult {
        profile_version: 1,
        network_id: coordinator.network_id,
        home_server_id: home,
        server_incarnation: decoded.request.server_incarnation,
        origin_id: decoded.request.origin_id,
        origin_generation: decoded.request.origin_generation,
        operation_sequence: decoded.request.operation_sequence,
        request_id: decoded.request.request_id,
        request_object_id: decoded.request_object_id,
        coordinator_state_generation: generation,
        completion_event_id: optional(completion_id)?,
        result_kind: outcome.result.wire_kind(),
        encoded_result: Opaque::new(outcome.result.encode()?)
            .map_err(|_| E2eeReplyCode::InvalidFragment)?,
        snapshot_token: optional(outcome.snapshot_token)?,
        next_cursor: optional(outcome.next_cursor)?,
        responses: TlsVec::new(responses).map_err(|_| E2eeReplyCode::InvalidFragment)?,
    };
    let body = result
        .encode()
        .map_err(|_| E2eeReplyCode::InvalidFragment)?;
    IrcWireObject::new(IrcWireObjectKind::FederationResult, body)
        .and_then(|object| object.encode())
        .map_err(|_| E2eeReplyCode::InvalidFragment)
}

fn optional<const N: usize>(value: Option<[u8; N]>) -> Result<Opaque<0, N>, E2eeReplyCode> {
    Opaque::new(value.map_or_else(Vec::new, |bytes| bytes.to_vec()))
        .map_err(|_| E2eeReplyCode::InvalidFragment)
}

fn descriptor(
    index: usize,
    response: &ResponseObject,
) -> Result<IrcFederationResponseDescriptor, E2eeReplyCode> {
    let (kind, _) =
        IrcWireObject::peek(&response.bytes).map_err(|_| E2eeReplyCode::InvalidFragment)?;
    Ok(IrcFederationResponseDescriptor {
        response_index: u16::try_from(index).map_err(|_| E2eeReplyCode::InvalidFragment)?,
        wire_kind: kind,
        object_id: *agenc_ircd_e2ee::ObjectId::compute(&response.bytes).as_bytes(),
        total_size: u32::try_from(response.bytes.len())
            .map_err(|_| E2eeReplyCode::InvalidFragment)?,
        delivery_token: optional(response.delivery_token)?,
        target_device_id: optional(response.target_device_id)?,
    })
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one function applies every descriptor registry rule for one result kind so the rule table stays in one place
fn check_descriptors(
    rule: &DescriptorRule,
    responses: &[ResponseObject],
) -> Result<(), E2eeReplyCode> {
    let kinds: Vec<u8> = responses
        .iter()
        .filter_map(|response| CompanionCoordinator::kind_of(&response.bytes))
        .map(|kind| kind.value())
        .collect();
    if kinds.len() != responses.len() {
        return Err(E2eeReplyCode::InvalidFragment);
    }
    let count = responses.len();
    let ok = match rule {
        DescriptorRule::None => count == 0,
        DescriptorRule::ExactlyOne(kind) => count == 1 && kinds.first() == Some(kind),
        DescriptorRule::Page(allowed) => {
            (1..=agenc_ircd_domain::e2ee::limits::MAX_BATCH_OBJECTS).contains(&count)
                && kinds.iter().all(|kind| allowed.contains(kind))
        }
        DescriptorRule::MailboxPage => {
            (1..=agenc_ircd_domain::e2ee::limits::MAX_BATCH_OBJECTS).contains(&count)
                && responses.iter().all(|response| {
                    response.delivery_token.is_some() && response.target_device_id.is_some()
                })
        }
    };
    if !ok {
        return Err(E2eeReplyCode::InvalidFragment);
    }
    if !matches!(rule, DescriptorRule::MailboxPage)
        && responses.iter().any(|response| {
            response.delivery_token.is_some() || response.target_device_id.is_some()
        })
    {
        return Err(E2eeReplyCode::InvalidFragment);
    }
    Ok(())
}

/// The replay row and its write for a committed result.
pub(crate) fn replay_write(
    key: &ReplayKey,
    decoded: &Decoded,
    result_bytes: &[u8],
    responses: &[ResponseObject],
    security_mutation: bool,
    retain_until: u64,
) -> Result<(ReplayRow, AccountServiceDurableWrite), E2eeReplyCode> {
    let row = ReplayRow {
        request_id: decoded.request.request_id,
        request_object_id: decoded.request_object_id,
        result_object_id: Some(*agenc_ircd_e2ee::ObjectId::compute(result_bytes).as_bytes()),
        response_object_ids: responses
            .iter()
            .map(|response| *agenc_ircd_e2ee::ObjectId::compute(&response.bytes).as_bytes())
            .collect(),
        security_mutation,
        retain_until,
    };
    let body = row.encode().map_err(|_| E2eeReplyCode::InvalidFragment)?;
    let stored_key = ReplayRow::key(key).map_err(|_| E2eeReplyCode::InvalidFragment)?;
    Ok((
        row,
        state_row(TableId::E2eeState, REPLAY_ROW_KIND, stored_key, body)?,
    ))
}
