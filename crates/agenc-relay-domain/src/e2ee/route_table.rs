//! The route table: every conversation the coordinator knows, its lineage
//! state, the semantic lock slots that prevent forks, and the plaintext
//! downgrade rules (companion Sections 9.4, 11.3 to 11.5, 12.5, and 13.7.1;
//! architecture Sections 18.1, 18.3, and 18.4).

use std::collections::BTreeMap;

use agenc_relay_types::{AccountId, ChannelInstanceId};

use crate::error::DomainError;

mod successor;

/// A 32-byte conversation identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConversationId(pub [u8; 32]);

/// A 32-byte semantic route lock identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SemanticLockId(pub [u8; 32]);

/// A 16-byte reservation identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReservationId(pub [u8; 16]);

/// An ordered direct-conversation account pair.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DirectPair {
    smaller: AccountId,
    larger: AccountId,
}

impl DirectPair {
    /// Orders two distinct accounts canonically.
    pub fn new(first: AccountId, second: AccountId) -> Result<Self, DomainError> {
        // Account IDs order by their 24 canonical ASCII bytes (Section 8.1).
        match first.to_text().as_bytes().cmp(second.to_text().as_bytes()) {
            std::cmp::Ordering::Less => Ok(Self {
                smaller: first,
                larger: second,
            }),
            std::cmp::Ordering::Greater => Ok(Self {
                smaller: second,
                larger: first,
            }),
            std::cmp::Ordering::Equal => Err(DomainError::InvalidArgument),
        }
    }

    /// The smaller Account ID, the only version-one direct creator.
    #[must_use]
    pub const fn smaller(&self) -> AccountId {
        self.smaller
    }

    /// The larger Account ID.
    #[must_use]
    pub const fn larger(&self) -> AccountId {
        self.larger
    }
}

/// The concrete route a conversation is bound to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteTarget {
    /// A global channel instance.
    Channel(ChannelInstanceId),
    /// A direct account pair.
    Direct(DirectPair),
}

/// The Section 18.4 server recovery gate of one route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryState {
    /// An ordinary live route.
    Normal,
    /// Restored and awaiting byte-identical evidence.
    Pending,
    /// Two valid successors at one chain position; permanently blocked.
    Conflict,
    /// A terminal close proven after restore; permanently closed.
    Closed,
}

/// Where a route is in its lineage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteLifecycle {
    /// Bound and accepting encrypted traffic.
    Active,
    /// An active-to-closing transition finalized; no new sending.
    Closing,
    /// Closed; the encrypted tombstone blocks plaintext until the exact
    /// channel instance is destroyed or a new semantic incarnation opens.
    Tombstone {
        /// The semantic close identifier.
        close_id: [u8; 32],
    },
}

/// One bound conversation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteEntry {
    /// Conversation identifier.
    pub conversation_id: ConversationId,
    /// Concrete route.
    pub target: RouteTarget,
    /// Semantic lock.
    pub lock: SemanticLockId,
    /// Semantic incarnation.
    pub incarnation: u64,
    /// Current binding identifier.
    pub binding_id: [u8; 32],
    /// Binding generation.
    pub binding_generation: u64,
    /// Lifecycle.
    pub lifecycle: RouteLifecycle,
    /// Recovery gate.
    pub recovery: RecoveryState,
}

impl RouteEntry {
    /// Whether encrypted application traffic and new sequencer records may
    /// flow: active, not closing, and not behind a recovery gate.
    #[must_use]
    pub const fn accepts_traffic(&self) -> bool {
        matches!(self.lifecycle, RouteLifecycle::Active)
            && matches!(self.recovery, RecoveryState::Normal)
    }
}

/// One live reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteReservation {
    /// Reservation identifier.
    pub reservation_id: ReservationId,
    /// Concrete route reserved.
    pub target: RouteTarget,
    /// The direct conversation nonce, for a direct reservation.
    pub conversation_nonce: Option<[u8; 32]>,
    /// The reserving account.
    pub owner: AccountId,
    /// Expiry second.
    pub expires_at: u64,
}

/// Why a route operation was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteConflict {
    /// A binding or tombstone already occupies the target (`E2EE_GROUP_CONFLICT`).
    GroupConflict,
    /// The semantic lock slot already holds a different binding: a fork.
    ForkedLineage,
    /// The reservation is unknown, expired, or owned by someone else.
    ReservationInvalid,
    /// The route is unknown (`E2EE_ROUTE_INVALID`).
    RouteInvalid,
    /// The lifecycle or recovery gate forbids the transition.
    BadState,
    /// The successor binding does not continue the lineage.
    NotSuccessor,
}

impl std::fmt::Display for RouteConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::GroupConflict => "a binding already exists for the target",
            Self::ForkedLineage => "the semantic lock already holds another lineage",
            Self::ReservationInvalid => "the reservation is invalid",
            Self::RouteInvalid => "the route is unknown",
            Self::BadState => "the route state forbids the transition",
            Self::NotSuccessor => "the binding does not continue the lineage",
        })
    }
}

impl std::error::Error for RouteConflict {}

/// Everything the table needs from a verified binding to admit it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindingSummary {
    /// Conversation identifier.
    pub conversation_id: ConversationId,
    /// Semantic lock.
    pub lock: SemanticLockId,
    /// Semantic incarnation.
    pub incarnation: u64,
    /// Predecessor close identifier, zero at incarnation zero.
    pub predecessor_close_id: [u8; 32],
    /// Binding identifier.
    pub binding_id: [u8; 32],
    /// Binding generation.
    pub binding_generation: u64,
    /// Previous binding identifier, zero at generation zero.
    pub previous_binding_id: [u8; 32],
    /// Concrete channel instance, for a channel binding.
    pub channel_instance_id: Option<ChannelInstanceId>,
    /// Concrete direct nonce, for a direct binding.
    pub conversation_nonce: Option<[u8; 32]>,
}

/// The coordinator's authoritative route table.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RouteTable {
    routes: BTreeMap<ConversationId, RouteEntry>,
    by_channel: BTreeMap<ChannelInstanceId, ConversationId>,
    by_pair: BTreeMap<DirectPair, ConversationId>,
    locks: BTreeMap<SemanticLockId, ConversationId>,
    reservations: BTreeMap<ReservationId, RouteReservation>,
    successor_reservations: BTreeMap<ReservationId, ConversationId>,
}

impl RouteTable {
    /// Creates an empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The route bound to a conversation.
    #[must_use]
    pub fn route(&self, conversation_id: &ConversationId) -> Option<&RouteEntry> {
        self.routes.get(conversation_id)
    }

    /// The route bound to a channel instance, live or tombstoned.
    #[must_use]
    pub fn channel_route(&self, channel_id: &ChannelInstanceId) -> Option<&RouteEntry> {
        self.by_channel
            .get(channel_id)
            .and_then(|conversation| self.routes.get(conversation))
    }

    /// The route bound to a direct pair, live or tombstoned.
    #[must_use]
    pub fn direct_route(&self, pair: &DirectPair) -> Option<&RouteEntry> {
        self.by_pair
            .get(pair)
            .and_then(|conversation| self.routes.get(conversation))
    }

    /// Whether plaintext may reach a channel instance: only when no
    /// binding or tombstone exists for it (`E2EE_REQUIRED` otherwise).
    #[must_use]
    pub fn channel_plaintext_allowed(&self, channel_id: &ChannelInstanceId) -> bool {
        self.channel_route(channel_id).is_none()
    }

    /// Whether plaintext may pass between two accounts: only when no live
    /// or tombstoned direct binding exists for the pair.
    #[must_use]
    pub fn direct_plaintext_allowed(&self, pair: &DirectPair) -> bool {
        self.direct_route(pair).is_none()
    }

    /// Every live reservation.
    pub fn reservations(&self) -> impl Iterator<Item = &RouteReservation> {
        self.reservations.values()
    }

    /// Reserves a channel route. A target already bound, tombstoned, or
    /// reserved is a group conflict.
    pub fn reserve_channel(
        &mut self,
        reservation_id: ReservationId,
        channel_id: ChannelInstanceId,
        owner: AccountId,
        expires_at: u64,
    ) -> Result<(), RouteConflict> {
        if self.by_channel.contains_key(&channel_id)
            || self.target_reserved(&RouteTarget::Channel(channel_id))
        {
            return Err(RouteConflict::GroupConflict);
        }
        self.insert_reservation(RouteReservation {
            reservation_id,
            target: RouteTarget::Channel(channel_id),
            conversation_nonce: None,
            owner,
            expires_at,
        })
    }

    /// Reserves a direct route for the pair; only the smaller account
    /// creates a direct conversation.
    pub fn reserve_direct(
        &mut self,
        reservation_id: ReservationId,
        pair: DirectPair,
        conversation_nonce: [u8; 32],
        owner: AccountId,
        expires_at: u64,
    ) -> Result<(), RouteConflict> {
        if owner != pair.smaller() {
            return Err(RouteConflict::BadState);
        }
        if self.by_pair.contains_key(&pair) || self.target_reserved(&RouteTarget::Direct(pair)) {
            return Err(RouteConflict::GroupConflict);
        }
        self.insert_reservation(RouteReservation {
            reservation_id,
            target: RouteTarget::Direct(pair),
            conversation_nonce: Some(conversation_nonce),
            owner,
            expires_at,
        })
    }

    fn target_reserved(&self, target: &RouteTarget) -> bool {
        self.reservations
            .values()
            .any(|reservation| reservation.target == *target)
    }

    fn insert_reservation(&mut self, reservation: RouteReservation) -> Result<(), RouteConflict> {
        if self.reservations.contains_key(&reservation.reservation_id) {
            return Err(RouteConflict::GroupConflict);
        }
        self.reservations
            .insert(reservation.reservation_id, reservation);
        Ok(())
    }

    /// Restores one durable reservation at startup; a reservation whose
    /// identifier is already held is left in place.
    pub fn restore_reservation(&mut self, reservation: RouteReservation) {
        self.reservations
            .entry(reservation.reservation_id)
            .or_insert(reservation);
    }

    /// Drops every reservation whose expiry passed.
    pub fn expire_reservations(&mut self, now: u64) -> usize {
        let before = self.reservations.len();
        self.reservations
            .retain(|_, reservation| reservation.expires_at > now);
        self.successor_reservations
            .retain(|id, _| self.reservations.contains_key(id));
        before.saturating_sub(self.reservations.len())
    }

    /// Binds a conversation to a reservation atomically. The binding must
    /// name the reserved concrete route, the reservation must be live and
    /// owned by `actor`, and the semantic lock slot must be free or already
    /// hold this exact binding lineage's predecessor incarnation.
    pub fn bind(
        &mut self,
        reservation_id: ReservationId,
        actor: AccountId,
        summary: BindingSummary,
        now: u64,
    ) -> Result<RouteEntry, RouteConflict> {
        if self.successor_reservations.contains_key(&reservation_id) {
            return Err(RouteConflict::BadState);
        }
        let reservation = self
            .reservations
            .get(&reservation_id)
            .copied()
            .filter(|reservation| reservation.owner == actor && reservation.expires_at > now)
            .ok_or(RouteConflict::ReservationInvalid)?;
        let target = match (
            reservation.target,
            summary.channel_instance_id,
            summary.conversation_nonce,
        ) {
            (RouteTarget::Channel(instance), Some(bound), None) if instance == bound => {
                RouteTarget::Channel(instance)
            }
            (RouteTarget::Direct(pair), None, Some(nonce))
                if reservation.conversation_nonce == Some(nonce) =>
            {
                RouteTarget::Direct(pair)
            }
            _ => return Err(RouteConflict::ReservationInvalid),
        };
        if summary.binding_generation != 0 || self.routes.contains_key(&summary.conversation_id) {
            return Err(RouteConflict::BadState);
        }
        self.check_lock_slot(&summary)?;
        let entry = RouteEntry {
            conversation_id: summary.conversation_id,
            target,
            lock: summary.lock,
            incarnation: summary.incarnation,
            binding_id: summary.binding_id,
            binding_generation: 0,
            lifecycle: RouteLifecycle::Active,
            recovery: RecoveryState::Normal,
        };
        self.reservations.remove(&reservation_id);
        self.insert_route(entry);
        Ok(entry)
    }

    /// A semantic lock slot holds at most one lineage; a second live
    /// binding under the same lock is a fork, and a new incarnation must
    /// name the tombstoned predecessor's close identifier.
    fn check_lock_slot(&self, summary: &BindingSummary) -> Result<(), RouteConflict> {
        let Some(existing) = self
            .locks
            .get(&summary.lock)
            .and_then(|id| self.routes.get(id))
        else {
            return if summary.incarnation == 0 {
                Ok(())
            } else {
                Err(RouteConflict::NotSuccessor)
            };
        };
        match existing.lifecycle {
            RouteLifecycle::Tombstone { close_id }
                if existing.incarnation.checked_add(1) == Some(summary.incarnation)
                    && summary.predecessor_close_id == close_id =>
            {
                Ok(())
            }
            RouteLifecycle::Tombstone { .. } => Err(RouteConflict::NotSuccessor),
            RouteLifecycle::Active | RouteLifecycle::Closing => Err(RouteConflict::ForkedLineage),
        }
    }

    fn insert_route(&mut self, entry: RouteEntry) {
        match entry.target {
            RouteTarget::Channel(instance) => {
                self.by_channel.insert(instance, entry.conversation_id);
            }
            RouteTarget::Direct(pair) => {
                self.by_pair.insert(pair, entry.conversation_id);
            }
        }
        self.locks.insert(entry.lock, entry.conversation_id);
        self.routes.insert(entry.conversation_id, entry);
    }

    /// Replaces the binding of a live route in place (a same-group route
    /// migration finalized inside the group).
    pub fn replace_binding(
        &mut self,
        conversation_id: &ConversationId,
        summary: BindingSummary,
    ) -> Result<(), RouteConflict> {
        let entry = self
            .routes
            .get_mut(conversation_id)
            .ok_or(RouteConflict::RouteInvalid)?;
        if !entry.accepts_traffic() {
            return Err(RouteConflict::BadState);
        }
        let continues = entry.binding_generation.checked_add(1) == Some(summary.binding_generation)
            && summary.previous_binding_id == entry.binding_id
            && summary.lock == entry.lock
            && summary.conversation_id == *conversation_id;
        if !continues {
            return Err(RouteConflict::NotSuccessor);
        }
        entry.binding_id = summary.binding_id;
        entry.binding_generation = summary.binding_generation;
        Ok(())
    }

    /// Records the finalized active-to-closing transition.
    pub fn begin_close(&mut self, conversation_id: &ConversationId) -> Result<(), RouteConflict> {
        let entry = self
            .routes
            .get_mut(conversation_id)
            .ok_or(RouteConflict::RouteInvalid)?;
        if !entry.accepts_traffic() {
            return Err(RouteConflict::BadState);
        }
        entry.lifecycle = RouteLifecycle::Closing;
        Ok(())
    }

    /// Installs the encrypted tombstone after an authorized close.
    pub fn close(
        &mut self,
        conversation_id: &ConversationId,
        close_id: [u8; 32],
    ) -> Result<(), RouteConflict> {
        let entry = self
            .routes
            .get_mut(conversation_id)
            .ok_or(RouteConflict::RouteInvalid)?;
        match (entry.lifecycle, entry.recovery) {
            (RouteLifecycle::Closing, RecoveryState::Normal) => {
                entry.lifecycle = RouteLifecycle::Tombstone { close_id };
                Ok(())
            }
            _ => Err(RouteConflict::BadState),
        }
    }

    /// Removes the tombstone of a channel instance that was destroyed. A
    /// live route is never removed this way.
    pub fn destroy_channel_instance(
        &mut self,
        channel_id: &ChannelInstanceId,
    ) -> Result<(), RouteConflict> {
        let conversation_id = *self
            .by_channel
            .get(channel_id)
            .ok_or(RouteConflict::RouteInvalid)?;
        let entry = self
            .routes
            .get(&conversation_id)
            .ok_or(RouteConflict::RouteInvalid)?;
        if !matches!(entry.lifecycle, RouteLifecycle::Tombstone { .. }) {
            return Err(RouteConflict::BadState);
        }
        self.by_channel.remove(channel_id);
        self.routes.remove(&conversation_id);
        // The semantic lock keeps pointing at the closed lineage only while
        // the entry exists; a destroyed instance frees the name for a fresh
        // instance, which then needs a new incarnation under the same lock.
        Ok(())
    }

    /// Marks every nonterminal route pending after a backup restore.
    pub fn restore_pending(&mut self) -> usize {
        let mut changed = 0_usize;
        for entry in self.routes.values_mut() {
            if entry.recovery == RecoveryState::Normal
                && !matches!(entry.lifecycle, RouteLifecycle::Tombstone { .. })
            {
                entry.recovery = RecoveryState::Pending;
                changed = changed.saturating_add(1_usize);
            }
        }
        changed
    }

    /// Resolves a pending gate: `Closed` installs the proven terminal
    /// close, `Conflict` blocks the lineage; `Normal` is never reachable.
    pub fn resolve_recovery(
        &mut self,
        conversation_id: &ConversationId,
        outcome: RecoveryState,
        close_id: Option<[u8; 32]>,
    ) -> Result<(), RouteConflict> {
        let entry = self
            .routes
            .get_mut(conversation_id)
            .ok_or(RouteConflict::RouteInvalid)?;
        if entry.recovery != RecoveryState::Pending {
            return Err(RouteConflict::BadState);
        }
        match (outcome, close_id) {
            (RecoveryState::Closed, Some(close_id)) => {
                entry.recovery = RecoveryState::Closed;
                entry.lifecycle = RouteLifecycle::Tombstone { close_id };
                Ok(())
            }
            (RecoveryState::Conflict, None) => {
                entry.recovery = RecoveryState::Conflict;
                Ok(())
            }
            _ => Err(RouteConflict::BadState),
        }
    }

    /// The Section 12.5 netjoin rule: of two channel routes competing for
    /// one global name, the smaller `(channel_instance_id, binding_id)` wins
    /// the IRC namespace and the other is tombstoned. Returns the loser.
    #[must_use]
    pub fn collision_loser(first: &RouteEntry, second: &RouteEntry) -> ConversationId {
        let key = |entry: &RouteEntry| match entry.target {
            RouteTarget::Channel(instance) => (Some(*instance.as_bytes()), entry.binding_id),
            RouteTarget::Direct(_) => (None, entry.binding_id),
        };
        if key(first) <= key(second) {
            second.conversation_id
        } else {
            first.conversation_id
        }
    }

    /// Every route, for snapshots and projections.
    pub fn routes(&self) -> impl Iterator<Item = &RouteEntry> {
        self.routes.values()
    }

    /// Restores one entry from durable state without lineage checks.
    pub fn restore_entry(&mut self, entry: RouteEntry) {
        let current = match entry.target {
            RouteTarget::Channel(channel) => self.channel_route(&channel),
            RouteTarget::Direct(pair) => self.direct_route(&pair),
        };
        if current.is_some_and(|known| {
            known.lock == entry.lock
                && known.incarnation == entry.incarnation
                && known.binding_generation > entry.binding_generation
        }) {
            self.routes.entry(entry.conversation_id).or_insert(entry);
            return;
        }
        self.insert_route(entry);
    }

    /// Forgets an edge projection whose entitlement ended, including its
    /// target and lock indexes. This does not authorize removal of an
    /// authoritative coordinator binding or tombstone.
    pub fn remove_projection(&mut self, conversation_id: &ConversationId) {
        let Some(entry) = self.routes.remove(conversation_id) else {
            return;
        };
        match entry.target {
            RouteTarget::Channel(channel)
                if self.by_channel.get(&channel) == Some(conversation_id) =>
            {
                self.by_channel.remove(&channel);
            }
            RouteTarget::Direct(pair) if self.by_pair.get(&pair) == Some(conversation_id) => {
                self.by_pair.remove(&pair);
            }
            RouteTarget::Channel(_) | RouteTarget::Direct(_) => {}
        }
        if self.locks.get(&entry.lock) == Some(conversation_id) {
            self.locks.remove(&entry.lock);
        }
    }
}

#[cfg(test)]
#[path = "tests/route_table.rs"]
mod tests;
