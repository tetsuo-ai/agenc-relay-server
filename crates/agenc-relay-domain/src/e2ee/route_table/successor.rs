//! Atomic route replacement by a verified ReInit activation, and its restore.

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

    /// Installs the successor of a quorum-activated ReInit in place of its
    /// predecessor's route (companion 13.8): the successor takes the
    /// predecessor's concrete route, semantic lock and incarnation at the
    /// next binding generation, continuing the predecessor's binding, and
    /// the predecessor keeps its entry without the route's indexes. The
    /// caller has verified the activation and the target its attempt
    /// carries, whose binding keeps the predecessor's channel instance or
    /// direct nonce.
    // agenc-review: focus owner=domain reviewed=2026-10-05 reason=one atomic route replacement checks the exact lineage, concrete route and index ownership before the successor takes the predecessor's indexes
    pub fn install_successor(
        &mut self,
        predecessor: ConversationId,
        summary: BindingSummary,
    ) -> Result<RouteEntry, RouteConflict> {
        let old = *self
            .routes
            .get(&predecessor)
            .ok_or(RouteConflict::RouteInvalid)?;
        let concrete_matches = match old.target {
            RouteTarget::Channel(instance) => {
                summary.channel_instance_id == Some(instance)
                    && summary.conversation_nonce.is_none()
            }
            RouteTarget::Direct(_) => {
                summary.channel_instance_id.is_none() && summary.conversation_nonce.is_some()
            }
        };
        if !old.accepts_traffic()
            || !self.owns_indexes(&old)
            || !concrete_matches
            || self.routes.contains_key(&summary.conversation_id)
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
