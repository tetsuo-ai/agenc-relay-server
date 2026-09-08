//! The forty opcode handlers, grouped by the state they touch. Each handler
//! reads the committed companion state, validates through the e2ee crate,
//! and returns an [`Outcome`] whose rows and effects apply only when the
//! batch commits.

use agenc_ircd_domain::e2ee::projection::{EventKind, PlannedEvent};
use agenc_ircd_e2ee::DecodeBudget;
use agenc_ircd_e2ee::objects::federation::IrcFederationOpcode;
use agenc_ircd_e2ee::tls::Reader;
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;
use agenc_ircd_types::{ChannelInstanceId, EntropySource, ServerId};

use super::events::EventContent;
use super::request::{Decoded, Outcome};
use super::{CompanionCoordinator, CompanionOrigin};

mod binding_delivery;
pub mod directory;
pub mod mailbox;
mod mailbox_grant;
mod mailbox_recovery;
pub(crate) mod mailbox_snapshot;
pub mod policy;
mod recovery;
mod recovery_read;
pub mod route;
pub(super) mod route_successor;
pub mod sequence;
mod terminal_proof;

/// A handler failure: the reply code and the copied request context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fail {
    /// Reply code.
    pub code: E2eeReplyCode,
    /// Context copied from the request, never new material.
    pub context: Vec<u8>,
}

impl From<E2eeReplyCode> for Fail {
    fn from(code: E2eeReplyCode) -> Self {
        Self {
            code,
            context: Vec::new(),
        }
    }
}

impl Fail {
    /// A failure naming `context`.
    #[must_use]
    pub fn with(code: E2eeReplyCode, context: &[u8]) -> Self {
        Self {
            code,
            context: context.to_vec(),
        }
    }
}

/// The base binding planner: the channel and its principal accounts give
/// the base plan, or `None` on a node without base state.
pub type PlanBinding<'a> = dyn Fn(
        ChannelInstanceId,
        &[[u8; 24]],
    ) -> Result<Option<agenc_ircd_domain::MutationPlan>, E2eeReplyCode>
    + 'a;

/// What every handler sees.
pub struct Exec<'a> {
    /// A runtime lookup either needs storage or carries one exact completed read.
    pub(crate) object_source: super::object_read::Source<'a>,
    /// Shared query ceilings for the authoritative base session.
    pub(crate) queries: Option<crate::state_core::query_usage::QueryReservationPort<'a>>,
    /// Reservation-only access to the existing process memory budget.
    pub(crate) backing: crate::budget::BackingReservationPort,
    /// Monotonic milliseconds for process-local cursor expiry.
    pub monotonic_millis: u64,
    /// The coordinator (committed state).
    pub coordinator: &'a CompanionCoordinator,
    /// The home edge.
    pub home: ServerId,
    /// The requesting origin.
    pub origin: &'a CompanionOrigin,
    /// The decoded request.
    pub decoded: &'a Decoded,
    /// Authenticated server time in seconds.
    pub now: u64,
    /// Entropy for tokens, nonces, and identifiers.
    pub entropy: &'a mut dyn EntropySource,
    /// Every configured edge.
    pub peers: &'a [ServerId],
    /// Whether an edge holds a base channel-detail entitlement.
    pub holds_channel: &'a dyn Fn(ServerId, ChannelInstanceId) -> bool,
    /// The edges hosting a base membership of a channel.
    pub hosting: &'a dyn Fn(ChannelInstanceId) -> Vec<ServerId>,
    /// The edges hosting an attached, roster-active device of an account.
    pub attached_edges: &'a dyn Fn(&[u8; 32]) -> Vec<ServerId>,
    /// Whether the requesting origin's base session is a member of a channel.
    pub channel_member: &'a dyn Fn(ChannelInstanceId) -> bool,
    /// The base binding plan for a channel whose members are exactly the
    /// named principal accounts; `None` on a node without base state.
    pub plan_binding: &'a PlanBinding<'a>,
    /// The coordinator state generation the batch will commit.
    pub state_generation: u64,
    /// The encoded base source view of the requesting origin.
    pub source_view: Vec<u8>,
}

impl Exec<'_> {
    /// The request opcode.
    #[must_use]
    pub const fn opcode(&self) -> IrcFederationOpcode {
        self.decoded.request.opcode
    }

    /// A parameter reader over the exact encoded tuple.
    #[must_use]
    pub fn params(&self) -> Params<'_> {
        Params {
            bytes: self.decoded.request.encoded_parameters.as_slice(),
        }
    }

    /// The requester's account digest, required by most operations.
    pub fn account_digest(&self) -> Result<[u8; 32], Fail> {
        self.origin
            .account_digest
            .ok_or_else(|| E2eeReplyCode::AccountRequired.into())
    }

    /// The requester's Account ID.
    pub fn account_id(&self) -> Result<[u8; 24], Fail> {
        self.origin
            .account_id
            .ok_or_else(|| E2eeReplyCode::AccountRequired.into())
    }

    /// The requester's attached, roster-active device and session.
    pub fn attached_device(&self) -> Result<([u8; 16], u64), Fail> {
        let digest = self.account_digest()?;
        let (device, session) = self
            .origin
            .device
            .ok_or_else(|| Fail::from(E2eeReplyCode::DeviceRequired))?;
        let active = self
            .coordinator
            .state
            .directory
            .account(&digest)
            .is_some_and(|entry| entry.device_active(&device));
        if !active {
            return Err(E2eeReplyCode::DeviceRequired.into());
        }
        Ok((device, session))
    }

    /// The payload object, required.
    pub fn payload(&self) -> Result<(&agenc_ircd_e2ee::object::IrcWireObject, &[u8]), Fail> {
        match (&self.decoded.payload, &self.decoded.payload_bytes) {
            (Some(object), Some(bytes)) => Ok((object, bytes)),
            _ => Err(E2eeReplyCode::InvalidFragment.into()),
        }
    }

    /// Fresh random bytes.
    pub fn random<const N: usize>(&mut self) -> Result<[u8; N], Fail> {
        let mut bytes = [0; N];
        self.entropy
            .fill_exact(&mut bytes)
            .map_err(|_| Fail::from(E2eeReplyCode::RateLimited))?;
        Ok(bytes)
    }

    /// An event content for a copy of `kind` to `target`.
    #[must_use]
    pub fn event(
        &self,
        kind: EventKind,
        conversation_id: Option<[u8; 32]>,
        target: ServerId,
        route_sequence: u64,
        encoded_result: Vec<u8>,
        payload: Option<Vec<u8>>,
    ) -> EventContent {
        let source = kind.has_source();
        EventContent {
            planned: PlannedEvent {
                kind,
                conversation_id,
                target,
                payload_object_id: payload
                    .as_ref()
                    .map(|bytes| *agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes()),
                completion: false,
                route_sequence,
                bytes: payload.as_ref().map_or(1_024, |bytes| {
                    u64::try_from(bytes.len()).unwrap_or(u64::MAX) + 1_024
                }),
            },
            origin: source.then_some((self.origin.origin_id, self.origin.generation)),
            source_view: if source {
                self.source_view.clone()
            } else {
                Vec::new()
            },
            correlation: None,
            encoded_result,
            payload,
        }
    }
}

/// A reader over the exact encoded parameter tuple.
pub struct Params<'a> {
    bytes: &'a [u8],
}

impl Params<'_> {
    /// Reads the whole tuple with `read`, refusing trailing bytes.
    pub fn read<T>(
        self,
        read: impl FnOnce(&mut Reader<'_>) -> Result<T, agenc_ircd_e2ee::E2eeError>,
    ) -> Result<T, Fail> {
        let mut budget = DecodeBudget::new(1_024, 64);
        let mut reader = Reader::new(self.bytes, &mut budget);
        let value = read(&mut reader).map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
        reader
            .finish()
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
        Ok(value)
    }

    /// Requires an empty tuple.
    pub fn none(self) -> Result<(), Fail> {
        self.read(|_| Ok(()))
    }
}

/// Reads an `opaque<1..255>` Account ID that must be exactly 24 bytes.
pub fn account(reader: &mut Reader<'_>) -> Result<[u8; 24], agenc_ircd_e2ee::E2eeError> {
    let bytes = reader.opaque(1, 255)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| agenc_ircd_e2ee::E2eeError::InvalidValue)
}

/// Reads a `opaque<0..32>` cursor.
pub fn cursor(reader: &mut Reader<'_>) -> Result<Option<[u8; 32]>, agenc_ircd_e2ee::E2eeError> {
    let bytes = reader.opaque(0, 32)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    bytes
        .as_slice()
        .try_into()
        .map(Some)
        .map_err(|_| agenc_ircd_e2ee::E2eeError::InvalidValue)
}

/// A handler either completes privately or requests one authenticated storage lookup.
pub enum Prepared {
    /// The ordinary result and its effects may now be staged.
    Complete(Box<Outcome>),
    /// Nothing may be staged before this object lookup completes.
    Read(super::object_read::Request),
}

#[cfg(test)]
impl Prepared {
    pub(crate) fn complete(self) -> Result<Outcome, Fail> {
        match self {
            Self::Complete(outcome) => Ok(*outcome),
            Self::Read(_) => Err(E2eeReplyCode::RateLimited.into()),
        }
    }
}

/// Dispatches one decoded request to its handler.
pub fn execute(exec: &mut Exec<'_>) -> Result<Prepared, Fail> {
    recovery::admit(exec)?;
    use IrcFederationOpcode as Op;
    let outcome = match exec.opcode() {
        Op::ApplicationChannel | Op::ApplicationDirect => route::application(exec),
        Op::ReserveChannel | Op::ReserveDirect => route::reserve(exec),
        Op::BindGroup => route::bind(exec),
        Op::QueryChannel | Op::QueryDirect => route::query(exec),
        Op::CloseGroup => route::close(exec),
        Op::SubmitCandidate => sequence::submit_candidate(exec),
        Op::SubmitAuthorization => sequence::submit_authorization(exec),
        Op::SubmitCommitAck => sequence::submit_commit_ack(exec),
        Op::SubmitFinalization => sequence::submit_finalization(exec),
        Op::SubmitAbort => sequence::submit_abort(exec),
        Op::SubmitReinitAttempt => sequence::submit_reinit_attempt(exec),
        Op::SubmitReinitAck => sequence::submit_reinit_ack(exec),
        Op::SubmitReinitActivate => sequence::submit_reinit_terminal(exec, true),
        Op::SubmitReinitAbort => sequence::submit_reinit_terminal(exec, false),
        Op::FetchObject => return sequence::fetch_object(exec),
        Op::FetchAuthorizations => sequence::fetch_authorizations(exec),
        Op::FetchAcks => sequence::fetch_acks(exec),
        Op::FetchReceipts => sequence::fetch_receipts(exec),
        Op::FetchIdentity => directory::fetch_identity(exec),
        Op::FetchRootChain => directory::fetch_root_chain(exec),
        Op::PublishIdentity => directory::publish_identity(exec),
        Op::FetchRoster => directory::fetch_roster(exec),
        Op::PublishRoster => directory::publish_roster(exec),
        Op::FetchCapabilities => directory::fetch_capabilities(exec),
        Op::PublishCapabilities => directory::publish_capabilities(exec),
        Op::FetchBindingLocks => directory::fetch_binding_locks(exec),
        Op::Whoami => directory::whoami(exec),
        Op::AttachBegin => directory::attach_begin(exec),
        Op::AttachFinish => directory::attach_finish(exec),
        Op::ClaimPackage => directory::claim_package(exec),
        Op::ClaimStatus => directory::claim_status(exec),
        Op::PublishPackage => directory::publish_package(exec),
        Op::RevokePackage => directory::revoke_package(exec),
        Op::DeliverBinding => mailbox::deliver_binding(exec),
        Op::DeliverWelcome => mailbox::deliver_welcome(exec),
        Op::FetchMailbox => mailbox::fetch_mailbox(exec),
        Op::AcknowledgeMailbox => mailbox::acknowledge_mailbox(exec),
        Op::SubmitPolicy => policy::submit_policy(exec),
    }?;
    Ok(Prepared::Complete(Box::new(outcome)))
}
