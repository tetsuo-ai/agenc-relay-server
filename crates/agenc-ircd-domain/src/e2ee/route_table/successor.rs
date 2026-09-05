//! Reservation and atomic route replacement after a verified ReInit activation.

#![forbid(unsafe_code)]

use super::*;

impl RouteTable {
    /// Whether this conversation still owns its concrete route and semantic lock.
    #[must_use]
    pub fn is_current(&self, conversation: &ConversationId) -> bool {
        self.routes
            .get(conversation)
            .is_some_and(|entry| self.owns_indexes(entry))
    }

    /// Reserves an occupied concrete route without authorizing its replacement.
    /// The caller verifies the owner's current binding-principal authority.
    pub fn reserve_successor(
        &mut self,
        reservation_id: ReservationId,
        predecessor: ConversationId,
        owner: AccountId,
        nonce: Option<[u8; 32]>,
        expires_at: u64,
    ) -> Result<(), RouteConflict> {
        let entry = *self
            .routes
            .get(&predecessor)
            .ok_or(RouteConflict::RouteInvalid)?;
        if !entry.accepts_traffic()
            || !self.owns_indexes(&entry)
            || self.target_reserved(&entry.target)
        {
            return Err(RouteConflict::GroupConflict);
        }
        match (entry.target, nonce) {
            (RouteTarget::Channel(_), None) => {}
            (RouteTarget::Direct(pair), Some(_)) if owner == pair.smaller() => {}
            _ => return Err(RouteConflict::ReservationInvalid),
        }
        self.insert_reservation(RouteReservation {
            reservation_id,
            target: entry.target,
            conversation_nonce: nonce,
            owner,
            expires_at,
        })?;
        self.successor_reservations
            .insert(reservation_id, predecessor);
        Ok(())
    }

    /// The predecessor named by a reservation that cannot create a genesis route.
    #[must_use]
    pub fn reservation_predecessor(&self, id: &ReservationId) -> Option<ConversationId> {
        self.successor_reservations.get(id).copied()
    }

    /// Consumes a live reservation after the caller verifies the retained
    /// activation authorizing this exact successor binding.
    // agenc-review: focus owner=domain reviewed=2026-09-04 reason=one atomic reservation consume checks exact lineage, concrete route, owner, expiry, and index ownership before replacing the route
    pub fn bind_successor(
        &mut self,
        reservation_id: ReservationId,
        actor: AccountId,
        summary: BindingSummary,
        now: u64,
    ) -> Result<RouteEntry, RouteConflict> {
        let predecessor = self
            .reservation_predecessor(&reservation_id)
            .ok_or(RouteConflict::ReservationInvalid)?;
        let old = *self
            .routes
            .get(&predecessor)
            .ok_or(RouteConflict::RouteInvalid)?;
        let reservation = self
            .reservations
            .get(&reservation_id)
            .filter(|value| value.owner == actor && value.expires_at > now)
            .ok_or(RouteConflict::ReservationInvalid)?;
        let concrete_matches = match reservation.target {
            RouteTarget::Channel(instance) => {
                summary.channel_instance_id == Some(instance)
                    && summary.conversation_nonce.is_none()
            }
            RouteTarget::Direct(_) => {
                summary.channel_instance_id.is_none()
                    && summary.conversation_nonce == reservation.conversation_nonce
            }
        };
        if !old.accepts_traffic()
            || !self.owns_indexes(&old)
            || reservation.target != old.target
            || !concrete_matches
            || self.routes.contains_key(&summary.conversation_id)
            || summary.conversation_id == predecessor
            || summary.lock != old.lock
            || summary.incarnation != old.incarnation
            || old.binding_generation.checked_add(1) != Some(summary.binding_generation)
            || summary.previous_binding_id != old.binding_id
        {
            return Err(RouteConflict::NotSuccessor);
        }
        let entry = RouteEntry {
            conversation_id: summary.conversation_id,
            target: old.target,
            lock: old.lock,
            incarnation: old.incarnation,
            binding_id: summary.binding_id,
            binding_generation: summary.binding_generation,
            lifecycle: RouteLifecycle::Active,
            recovery: RecoveryState::Normal,
        };
        self.reservations.remove(&reservation_id);
        self.successor_reservations.remove(&reservation_id);
        self.insert_route(entry);
        Ok(entry)
    }

    fn owns_indexes(&self, entry: &RouteEntry) -> bool {
        let target = match entry.target {
            RouteTarget::Channel(channel) => self.by_channel.get(&channel),
            RouteTarget::Direct(pair) => self.by_pair.get(&pair),
        };
        target == Some(&entry.conversation_id)
            && self.locks.get(&entry.lock) == Some(&entry.conversation_id)
    }

    /// Selects an already-restored successor after the caller rechecks its
    /// retained activation. Read-back order must not select the old route.
    pub fn select_restored_successor(
        &mut self,
        predecessor: ConversationId,
        successor: ConversationId,
    ) -> Result<(), RouteConflict> {
        let old = self
            .routes
            .get(&predecessor)
            .ok_or(RouteConflict::RouteInvalid)?;
        let new = *self
            .routes
            .get(&successor)
            .ok_or(RouteConflict::RouteInvalid)?;
        if old.target != new.target
            || old.lock != new.lock
            || old.incarnation != new.incarnation
            || old.binding_generation.checked_add(1) != Some(new.binding_generation)
        {
            return Err(RouteConflict::NotSuccessor);
        }
        let current = self.locks.get(&new.lock).and_then(|id| self.routes.get(id));
        if current.is_none_or(|entry| entry.binding_generation <= new.binding_generation) {
            self.insert_route(new);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/route_table_successor.rs"]
mod tests;
