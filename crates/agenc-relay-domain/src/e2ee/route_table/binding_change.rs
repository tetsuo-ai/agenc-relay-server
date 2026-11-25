//! Admission to the concrete route selected by old-group binding finality.
#![forbid(unsafe_code)]

use super::*;

impl RouteTable {
    /// Checks the registered grant against the concrete route in the submitted package.
    pub(super) fn reserved_target(
        &self,
        reservation_id: ReservationId,
        actor: AccountId,
        summary: &BindingSummary,
        now: u64,
    ) -> Result<RouteTarget, RouteConflict> {
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
            summary.direct_pair,
        ) {
            (RouteTarget::Channel(instance), Some(bound), None, None) if instance == bound => {
                RouteTarget::Channel(instance)
            }
            (RouteTarget::Direct(pair), None, Some(nonce), Some(named))
                if reservation.conversation_nonce == Some(nonce) && named == pair =>
            {
                RouteTarget::Direct(pair)
            }
            _ => return Err(RouteConflict::ReservationInvalid),
        };
        Ok(target)
    }

    /// Reserves a concrete target for an existing group. The signed grant alone
    /// changes neither routing nor plaintext policy. The caller checks channel
    /// membership and the target's canonical semantic channel name.
    pub fn reserve_binding_change(
        &mut self,
        conversation: ConversationId,
        grant: RouteReservation,
    ) -> Result<(), RouteConflict> {
        let old = self
            .route(&conversation)
            .ok_or(RouteConflict::RouteInvalid)?;
        if !old.accepts_traffic()
            || !self.is_current(&conversation)
            || self.target_reserved(&grant.target)
        {
            return Err(RouteConflict::GroupConflict);
        }
        if !self.migration_grant_matches(old.target, &grant) {
            return Err(RouteConflict::ReservationInvalid);
        }
        self.insert_reservation(grant)
    }

    fn migration_grant_matches(&self, old: RouteTarget, grant: &RouteReservation) -> bool {
        match (old, grant.target) {
            (RouteTarget::Channel(previous), RouteTarget::Channel(next))
                if grant.conversation_nonce.is_none()
                    && (next == previous || self.channel_plaintext_allowed(&next)) =>
            {
                true
            }
            (RouteTarget::Direct(previous), RouteTarget::Direct(next))
                if previous == next
                    && grant.owner == next.smaller()
                    && grant.conversation_nonce.is_some() =>
            {
                true
            }
            _ => false,
        }
    }

    /// Moves the current binding under the exact signed grant, after the caller
    /// has verified old-group finality for this package. No table mutation is
    /// visible until every check of the grant, lineage and target has passed.
    pub fn replace_reserved_binding(
        &mut self,
        reservation_id: ReservationId,
        actor: AccountId,
        summary: BindingSummary,
        now: u64,
    ) -> Result<RouteEntry, RouteConflict> {
        let conversation = summary.conversation_id;
        let mut next = self.continued_binding(&conversation, &summary)?;
        if !self.is_current(&conversation)
            || self.lineages.get(&next.lineage) != Some(&conversation)
        {
            return Err(RouteConflict::BadState);
        }
        let target = self.reserved_target(reservation_id, actor, &summary, now)?;
        match (next.target, target) {
            (RouteTarget::Channel(previous), RouteTarget::Channel(next))
                if previous == next || self.channel_plaintext_allowed(&next) => {}
            (RouteTarget::Direct(previous), RouteTarget::Direct(next)) if previous == next => {}
            _ => return Err(RouteConflict::GroupConflict),
        }
        if let RouteTarget::Channel(previous) = next.target
            && next.target != target
        {
            self.retire_binding_channel(conversation, previous)?;
        }
        next.target = target;
        self.insert_route(next);
        self.remove_reservation(reservation_id);
        Ok(next)
    }

    /// Restores the plaintext guard for an instance superseded by an admitted
    /// binding. The historical instance no longer routes encrypted traffic.
    pub fn retire_binding_channel(
        &mut self,
        conversation: ConversationId,
        instance: ChannelInstanceId,
    ) -> Result<(), RouteConflict> {
        if self
            .by_channel
            .get(&instance)
            .is_some_and(|current| *current != conversation)
        {
            return Err(RouteConflict::GroupConflict);
        }
        self.by_channel.remove(&instance);
        self.retired_channels.insert(instance);
        Ok(())
    }
}
