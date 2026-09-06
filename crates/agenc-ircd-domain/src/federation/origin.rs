//! Origin lifecycle, fencing, and request replay classification (spec 20.5,
//! 20.7).
//!
//! The table is the coordinator's in-memory view of every declared origin.
//! It decides; it never persists. The runtime writes the durable rows and
//! rebuilds the table at startup through [`OriginTable::restore_origin`].

use std::error::Error;
use std::fmt;

use std::collections::{BTreeMap, BTreeSet};

use agenc_ircd_types::{
    AccountId, ConnectionId, Generation, MonotonicTick, ORIGIN_DISCONNECT_GRACE_SECONDS, OriginId,
    RequestId, ServerId, ServerIncarnation, SessionId, UserId,
};

/// The identity of one origin across its generations.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct OriginKey {
    /// The edge that owns the connection.
    pub home_server_id: ServerId,
    /// The edge incarnation that allocated the origin.
    pub server_incarnation: ServerIncarnation,
    /// The connection-scoped origin identity.
    pub origin_id: OriginId,
}

/// The replay key of one operation: an origin generation plus sequence.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct OperationKey {
    /// The origin.
    pub origin: OriginKey,
    /// The origin generation.
    pub generation: u64,
    /// The zero-based operation sequence within the generation.
    pub sequence: u64,
}

/// The security principal an origin generation executes as.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginPrincipal {
    /// The registered session, if any.
    pub session: Option<(SessionId, UserId)>,
    /// The authenticated account and its session generation, if any.
    pub account: Option<(AccountId, Generation)>,
}

impl OriginPrincipal {
    /// The pre-registration principal.
    pub const UNREGISTERED: Self = Self {
        session: None,
        account: None,
    };
}

/// The immutable connection binding declared with generation zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginBinding {
    /// The accepted transport identity.
    pub connection_id: ConnectionId,
    /// The connection nonce.
    pub connection_nonce: [u8; 32],
}

/// A complete origin declaration as carried by FORIGIN ADD or UPDATE.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginDeclaration {
    /// The origin.
    pub origin: OriginKey,
    /// The declared generation.
    pub generation: u64,
    /// All-zero for generation zero, else the accepted predecessor object ID.
    pub previous_object_id: [u8; 32],
    /// The immutable binding.
    pub binding: OriginBinding,
    /// The principal for this generation.
    pub principal: OriginPrincipal,
    /// The Section-20.4 identity of the declared object.
    pub object_id: [u8; 32],
}

/// Where one origin stands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginStatus {
    /// Requests execute.
    Live,
    /// The edge link is down; a prompt RESET can resume it.
    Suspended,
    /// A sequence gap blocked the origin until it is replayed.
    Blocked,
    /// FORIGIN DEL was accepted; later requests are rejected permanently.
    Deleted,
    /// The incarnation, epoch, or grace fence permanently ended the origin.
    Fenced,
}

/// One origin's current generation, sequence, status, and principal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginEntry {
    /// The current generation.
    pub generation: u64,
    /// The next expected operation sequence.
    pub next_sequence: u64,
    /// The object identity of the current declaration.
    pub object_id: [u8; 32],
    /// The immutable binding.
    pub binding: OriginBinding,
    /// The principal of the current generation.
    pub principal: OriginPrincipal,
    /// The lifecycle status.
    pub status: OriginStatus,
    /// The edge's next sequence when it deleted the origin. Operations
    /// below it were issued before the deletion and still execute in order;
    /// the deletion fences only what would follow.
    pub deleted_after: Option<u64>,
}

/// The synchronization phase of one edge link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EdgePhase {
    /// No accepted incarnation yet.
    Unknown,
    /// A RESET was accepted; the edge is replaying its origins.
    Resetting,
    /// READY was sent; declarations and requests execute.
    Ready,
    /// The link was lost; origins are suspended until the grace deadline.
    Suspended {
        /// The exclusive monotonic deadline of the grace interval.
        grace_deadline: MonotonicTick,
    },
    /// The grace interval passed; the incarnation is permanently fenced.
    Expired,
}

/// The accepted incarnation and phase of one edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EdgeLink {
    /// The accepted incarnation.
    pub server_incarnation: ServerIncarnation,
    /// The current phase.
    pub phase: EdgePhase,
}

/// How a request relates to its origin's durable history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayDecision {
    /// The next expected operation; execute it.
    Fresh,
    /// The exact retained request; replay its stored result.
    ExactDuplicate,
    /// A different request or object at a retained key; fatal peer violation.
    Conflict,
    /// A reused request identity at another key; fatal peer violation.
    RequestIdReuse,
    /// A sequence beyond the next expected; answer ORIGIN_GAP and block.
    Gap,
    /// A lower sequence without a retained result; answer ORIGIN_EXPIRED and fence.
    Expired,
}

/// The retained record the coordinator holds for one replay key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedRequest {
    /// The request identity accepted at that key.
    pub request_id: RequestId,
    /// The request object identity accepted at that key.
    pub request_object_id: [u8; 32],
}

/// Closed reasons an origin operation is refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginError {
    /// The edge has no accepted incarnation or a different one.
    UnknownIncarnation,
    /// The edge is not in the phase that permits this operation.
    WrongPhase,
    /// The origin is not declared.
    UnknownOrigin,
    /// The origin already exists with a different declaration.
    Conflict,
    /// The declared generation is not the exact successor.
    WrongGeneration,
    /// The predecessor object identity does not match.
    WrongPredecessor,
    /// The binding or principal shape is invalid for the generation.
    InvalidDeclaration,
    /// The origin is deleted or fenced.
    Fenced,
    /// A monotonic calculation overflowed.
    Overflow,
}

impl fmt::Display for OriginError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnknownIncarnation => "federation edge incarnation is not accepted",
            Self::WrongPhase => "federation edge phase does not permit this operation",
            Self::UnknownOrigin => "federation origin is not declared",
            Self::Conflict => "federation origin declaration conflicts",
            Self::WrongGeneration => "federation origin generation is not the successor",
            Self::WrongPredecessor => "federation origin predecessor does not match",
            Self::InvalidDeclaration => "federation origin declaration is invalid",
            Self::Fenced => "federation origin is deleted or fenced",
            Self::Overflow => "federation origin calculation overflowed",
        };
        formatter.write_str(message)
    }
}

impl Error for OriginError {}

/// The coordinator's origin registry across every edge.
#[derive(Default)]
pub struct OriginTable {
    edges: BTreeMap<ServerId, EdgeLink>,
    origins: BTreeMap<OriginKey, OriginEntry>,
    request_ids: BTreeMap<RequestId, OperationKey>,
}

impl OriginTable {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns one edge's accepted link state.
    #[must_use]
    pub fn edge(&self, edge: ServerId) -> Option<EdgeLink> {
        self.edges.get(&edge).copied()
    }

    /// Returns one origin entry.
    #[must_use]
    pub fn origin(&self, key: &OriginKey) -> Option<OriginEntry> {
        self.origins.get(key).copied()
    }

    /// Iterates every origin of one edge incarnation in key order.
    pub fn origins_of(
        &self,
        edge: ServerId,
        incarnation: ServerIncarnation,
    ) -> impl Iterator<Item = (OriginKey, OriginEntry)> + '_ {
        self.origins
            .iter()
            .filter(move |(key, _)| {
                key.home_server_id == edge && key.server_incarnation == incarnation
            })
            .map(|(key, entry)| (*key, *entry))
    }

    /// Rebuilds one durable origin row without protocol checks.
    ///
    /// Startup reconstruction calls this for every stored row; the runtime
    /// proved the rows authentic before handing them over.
    pub fn restore_origin(&mut self, key: OriginKey, entry: OriginEntry) {
        self.origins.insert(key, entry);
    }

    /// Rebuilds one durable edge link state.
    pub fn restore_edge(&mut self, edge: ServerId, link: EdgeLink) {
        self.edges.insert(edge, link);
    }

    /// Records one accepted request identity at its replay key.
    pub fn restore_request_id(&mut self, request_id: RequestId, key: OperationKey) {
        self.request_ids.insert(request_id, key);
    }

    /// Releases the identity of an exact replay row after its durable retention deletion.
    /// Origin generations and sequence floors remain unchanged.
    pub fn retire_request_id(&mut self, request_id: RequestId, key: OperationKey) -> bool {
        if self.request_ids.get(&request_id) != Some(&key) {
            return false;
        }
        self.request_ids.remove(&request_id);
        true
    }

    /// Accepts FORIGIN RESET, fencing execution until READY.
    ///
    /// A new incarnation permanently fences every origin of the previous one.
    pub fn reset(&mut self, edge: ServerId, incarnation: ServerIncarnation) {
        if let Some(link) = self.edges.get(&edge)
            && link.server_incarnation != incarnation
        {
            let previous = link.server_incarnation;
            self.fence_incarnation(edge, previous);
        }
        self.edges.insert(
            edge,
            EdgeLink {
                server_incarnation: incarnation,
                phase: EdgePhase::Resetting,
            },
        );
    }

    /// Reports whether the edge's link is replaying its origins after a
    /// reset, when a DEL may name an origin this coordinator never held.
    #[must_use]
    pub fn is_resetting(&self, edge: ServerId, incarnation: ServerIncarnation) -> bool {
        self.edges.get(&edge).is_some_and(|link| {
            link.server_incarnation == incarnation && link.phase == EdgePhase::Resetting
        })
    }

    /// Accepts FORIGIN READY after every origin was replayed.
    pub fn ready(
        &mut self,
        edge: ServerId,
        incarnation: ServerIncarnation,
    ) -> Result<(), OriginError> {
        let link = self.link_mut(edge, incarnation)?;
        if link.phase != EdgePhase::Resetting {
            return Err(OriginError::WrongPhase);
        }
        link.phase = EdgePhase::Ready;
        for (key, entry) in self.origins.iter_mut() {
            if key.home_server_id == edge
                && key.server_incarnation == incarnation
                && entry.status == OriginStatus::Suspended
            {
                entry.status = OriginStatus::Live;
            }
        }
        Ok(())
    }

    /// Accepts FORIGIN ADD: a new generation-zero origin, or an exact replay.
    pub fn add(&mut self, declaration: OriginDeclaration) -> Result<(), OriginError> {
        let phase = self.require_synchronizing(declaration.origin)?;
        if declaration.generation != 0
            || declaration.previous_object_id != [0; 32]
            || declaration.principal != OriginPrincipal::UNREGISTERED
        {
            return Err(OriginError::InvalidDeclaration);
        }
        match self.origins.get_mut(&declaration.origin) {
            None => {
                self.origins.insert(
                    declaration.origin,
                    OriginEntry {
                        generation: 0,
                        next_sequence: 0,
                        object_id: declaration.object_id,
                        binding: declaration.binding,
                        principal: OriginPrincipal::UNREGISTERED,
                        status: OriginStatus::Live,
                        deleted_after: None,
                    },
                );
                Ok(())
            }
            Some(existing) => {
                if existing.binding != declaration.binding
                    || matches!(existing.status, OriginStatus::Fenced)
                {
                    return Err(OriginError::Conflict);
                }
                if phase == EdgePhase::Resetting && existing.status == OriginStatus::Suspended {
                    existing.status = OriginStatus::Live;
                }
                Ok(())
            }
        }
    }

    /// Accepts FORIGIN UPDATE: the exact next generation of a live origin.
    pub fn update(&mut self, declaration: OriginDeclaration) -> Result<(), OriginError> {
        let phase = self.require_synchronizing(declaration.origin)?;
        let entry = self
            .origins
            .get_mut(&declaration.origin)
            .ok_or(OriginError::UnknownOrigin)?;
        if entry.binding != declaration.binding {
            return Err(OriginError::InvalidDeclaration);
        }
        if declaration.generation == entry.generation && declaration.object_id == entry.object_id {
            if phase == EdgePhase::Resetting && entry.status == OriginStatus::Suspended {
                entry.status = OriginStatus::Live;
            }
            return Ok(());
        }
        match entry.status {
            OriginStatus::Deleted | OriginStatus::Fenced => return Err(OriginError::Fenced),
            OriginStatus::Live | OriginStatus::Suspended | OriginStatus::Blocked => {}
        }
        let expected = entry
            .generation
            .checked_add(1)
            .ok_or(OriginError::Overflow)?;
        if declaration.generation != expected {
            return Err(OriginError::WrongGeneration);
        }
        if declaration.previous_object_id != entry.object_id {
            return Err(OriginError::WrongPredecessor);
        }
        validate_principal(declaration.principal)?;
        entry.generation = declaration.generation;
        entry.next_sequence = 0;
        entry.object_id = declaration.object_id;
        entry.principal = declaration.principal;
        entry.status = OriginStatus::Live;
        Ok(())
    }

    /// Accepts FORIGIN DEL, permanently closing the origin.
    pub fn delete(
        &mut self,
        origin: OriginKey,
        generation: u64,
        next_sequence: u64,
    ) -> Result<(), OriginError> {
        let phase = self.require_synchronizing(origin)?;
        let entry = self
            .origins
            .get_mut(&origin)
            .ok_or(OriginError::UnknownOrigin)?;
        let replay = phase == EdgePhase::Resetting;
        if entry.status == OriginStatus::Deleted {
            return if replay
                || (entry.generation == generation && entry.deleted_after == Some(next_sequence))
            {
                Ok(())
            } else {
                Err(OriginError::Conflict)
            };
        }
        if entry.status == OriginStatus::Fenced {
            return Err(OriginError::Fenced);
        }
        if replay {
            // A DEL replayed after a reset closes an origin whose connection
            // is gone. The edge may name a generation this coordinator never
            // committed, or an older one whose update commit lost its
            // acknowledgement; the origin ends either way, after everything
            // this coordinator executed under its own generation.
            let after = if generation == entry.generation {
                next_sequence.max(entry.next_sequence)
            } else {
                entry.next_sequence
            };
            entry.deleted_after = Some(after);
            entry.status = OriginStatus::Deleted;
            return Ok(());
        }
        if entry.generation != generation || next_sequence < entry.next_sequence {
            return Err(OriginError::WrongGeneration);
        }
        // Requests the edge sent before the deletion may still be in flight
        // or queued; they keep executing up to the deleted sequence.
        entry.deleted_after = Some(next_sequence);
        entry.status = OriginStatus::Deleted;
        Ok(())
    }

    /// Classifies one request against the origin and the retained record at
    /// its replay key.
    pub fn classify_request(
        &self,
        key: OperationKey,
        request_id: RequestId,
        request_object_id: [u8; 32],
        retained: Option<RetainedRequest>,
    ) -> Result<ReplayDecision, OriginError> {
        let link = self.require_ready(key.origin)?;
        let _ = link;
        let entry = self
            .origins
            .get(&key.origin)
            .ok_or(OriginError::UnknownOrigin)?;
        match entry.status {
            OriginStatus::Live => {}
            OriginStatus::Suspended | OriginStatus::Blocked => {
                return Err(OriginError::WrongPhase);
            }
            OriginStatus::Deleted
                if entry
                    .deleted_after
                    .is_some_and(|deleted_after| key.sequence < deleted_after) => {}
            OriginStatus::Deleted | OriginStatus::Fenced => return Err(OriginError::Fenced),
        }
        if key.generation != entry.generation {
            return Err(OriginError::WrongGeneration);
        }
        if let Some(known) = self.request_ids.get(&request_id)
            && *known != key
        {
            return Ok(ReplayDecision::RequestIdReuse);
        }
        if key.sequence == entry.next_sequence {
            return Ok(match retained {
                None => ReplayDecision::Fresh,
                Some(_) => ReplayDecision::Conflict,
            });
        }
        if key.sequence > entry.next_sequence {
            return Ok(ReplayDecision::Gap);
        }
        Ok(match retained {
            None => ReplayDecision::Expired,
            Some(record)
                if record.request_id == request_id
                    && record.request_object_id == request_object_id =>
            {
                ReplayDecision::ExactDuplicate
            }
            Some(_) => ReplayDecision::Conflict,
        })
    }

    /// Records one committed fresh request, advancing the next sequence.
    pub fn commit_request(
        &mut self,
        key: OperationKey,
        request_id: RequestId,
    ) -> Result<(), OriginError> {
        let entry = self
            .origins
            .get_mut(&key.origin)
            .ok_or(OriginError::UnknownOrigin)?;
        if entry.generation != key.generation || entry.next_sequence != key.sequence {
            return Err(OriginError::WrongGeneration);
        }
        entry.next_sequence = key.sequence.checked_add(1).ok_or(OriginError::Overflow)?;
        self.request_ids.insert(request_id, key);
        Ok(())
    }

    /// Blocks one origin after a sequence gap until it is replayed.
    pub fn block(&mut self, origin: &OriginKey) -> Result<(), OriginError> {
        let entry = self
            .origins
            .get_mut(origin)
            .ok_or(OriginError::UnknownOrigin)?;
        if entry.status == OriginStatus::Live {
            entry.status = OriginStatus::Blocked;
        }
        Ok(())
    }

    /// Fences one origin permanently after an expired replay.
    pub fn fence(&mut self, origin: &OriginKey) -> Result<(), OriginError> {
        let entry = self
            .origins
            .get_mut(origin)
            .ok_or(OriginError::UnknownOrigin)?;
        entry.status = OriginStatus::Fenced;
        Ok(())
    }

    /// Records link loss: every origin of the incarnation is suspended and the
    /// fixed grace interval starts.
    pub fn link_lost(
        &mut self,
        edge: ServerId,
        incarnation: ServerIncarnation,
        now: MonotonicTick,
    ) -> Result<MonotonicTick, OriginError> {
        let grace_deadline = now
            .checked_add(
                ORIGIN_DISCONNECT_GRACE_SECONDS
                    .checked_mul(1_000)
                    .ok_or(OriginError::Overflow)?,
            )
            .map_err(|_| OriginError::Overflow)?;
        let link = self.link_mut(edge, incarnation)?;
        if matches!(link.phase, EdgePhase::Expired) {
            return Err(OriginError::Fenced);
        }
        link.phase = EdgePhase::Suspended { grace_deadline };
        for (key, entry) in self.origins.iter_mut() {
            if key.home_server_id == edge
                && key.server_incarnation == incarnation
                && entry.status == OriginStatus::Live
            {
                entry.status = OriginStatus::Suspended;
            }
        }
        Ok(grace_deadline)
    }

    /// Fences an edge incarnation whose grace interval passed, returning the
    /// sessions that cleanup must hide in byte order.
    pub fn expire(&mut self, edge: ServerId, now: MonotonicTick) -> Option<Vec<SessionId>> {
        let link = self.edges.get_mut(&edge)?;
        let EdgePhase::Suspended { grace_deadline } = link.phase else {
            return None;
        };
        if now.get() < grace_deadline.get() {
            return None;
        }
        link.phase = EdgePhase::Expired;
        let incarnation = link.server_incarnation;
        let sessions = self.fence_incarnation(edge, incarnation);
        Some(sessions.into_iter().collect())
    }

    fn fence_incarnation(
        &mut self,
        edge: ServerId,
        incarnation: ServerIncarnation,
    ) -> BTreeSet<SessionId> {
        let mut sessions = BTreeSet::new();
        for (key, entry) in self.origins.iter_mut() {
            if key.home_server_id != edge || key.server_incarnation != incarnation {
                continue;
            }
            if let Some((session_id, _)) = entry.principal.session
                && entry.status != OriginStatus::Deleted
            {
                sessions.insert(session_id);
            }
            entry.status = OriginStatus::Fenced;
        }
        sessions
    }

    fn link_mut(
        &mut self,
        edge: ServerId,
        incarnation: ServerIncarnation,
    ) -> Result<&mut EdgeLink, OriginError> {
        let link = self
            .edges
            .get_mut(&edge)
            .ok_or(OriginError::UnknownIncarnation)?;
        if link.server_incarnation != incarnation {
            return Err(OriginError::UnknownIncarnation);
        }
        Ok(link)
    }

    fn require_synchronizing(&self, origin: OriginKey) -> Result<EdgePhase, OriginError> {
        let link = self
            .edges
            .get(&origin.home_server_id)
            .ok_or(OriginError::UnknownIncarnation)?;
        if link.server_incarnation != origin.server_incarnation {
            return Err(OriginError::UnknownIncarnation);
        }
        match link.phase {
            EdgePhase::Resetting | EdgePhase::Ready => Ok(link.phase),
            _ => Err(OriginError::WrongPhase),
        }
    }

    fn require_ready(&self, origin: OriginKey) -> Result<EdgeLink, OriginError> {
        let link = self
            .edges
            .get(&origin.home_server_id)
            .ok_or(OriginError::UnknownIncarnation)?;
        if link.server_incarnation != origin.server_incarnation {
            return Err(OriginError::UnknownIncarnation);
        }
        if link.phase != EdgePhase::Ready {
            return Err(OriginError::WrongPhase);
        }
        Ok(*link)
    }
}

fn validate_principal(principal: OriginPrincipal) -> Result<(), OriginError> {
    if principal.session.is_none() && principal.account.is_some() {
        return Err(OriginError::InvalidDeclaration);
    }
    if let Some((_, generation)) = principal.account
        && generation.get() == 0
    {
        return Err(OriginError::InvalidDeclaration);
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/origin.rs"]
mod tests;
