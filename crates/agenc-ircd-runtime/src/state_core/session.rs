//! Connection and session ownership inside StateCore (spec 12, lines
//! 1680-1730; spec 21.1, lines 3972-3982).
//!
//! StateCore owns the mapping from an admitted connection to its sink and,
//! once registration completes, to its `UserId`/`SessionId`. Everything kept
//! here is either protocol state the coordinator owns or the edge-local
//! `LocalConnectionContext` fields the spec keeps off the federation wire
//! (exact capability hash, admission class, monotonic creation tick). No
//! address ever enters this table: the transport reduced it to a
//! `SourceAddressKey` before the connection was announced (spec ID-04, line
//! 6858).

use std::collections::BTreeMap;

use agenc_ircd_client_wire::CapabilityState;
use agenc_ircd_types::{MonotonicTick, SessionId, UserId};

use crate::RuntimeError;
use crate::admission::EvictionCandidate;
use crate::connection::sink::{ClientQueueSnapshot, ClientSink, ConnectionGeneration};
use crate::purpose::ListenerPurpose;
use crate::state_core::inbox::{PhysicalCloseNotice, SourceAddressKey};
use crate::sync::Arc;

/// Hard maximum client connections one node tracks (spec line 2639).
pub const MAX_TRACKED_CONNECTIONS: usize = 250_000;

/// The admission class a connection was accepted into (spec 19.1, lines
/// 2595-2609).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionClass {
    /// A direct TCP peer keyed by its address prefix.
    Direct,
    /// A peer of the onion listener.
    Onion,
    /// An administrative transport peer.
    Admin,
}

impl AdmissionClass {
    /// Derives the class from the accepting listener.
    #[must_use]
    pub const fn for_purpose(purpose: ListenerPurpose) -> Self {
        match purpose {
            ListenerPurpose::ClientTls
            | ListenerPurpose::ClientWss
            | ListenerPurpose::Federation => Self::Direct,
            ListenerPurpose::ClientOnion => Self::Onion,
            ListenerPurpose::AdminLocal | ListenerPurpose::AdminTls => Self::Admin,
        }
    }
}

/// The registered protocol identity bound to one connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundSession {
    /// The accepted session identity.
    pub session_id: SessionId,
    /// The per-connection user identity.
    pub user_id: UserId,
    /// Hash of the sorted negotiated capability names; the coordinator keeps
    /// only this hash (spec lines 1712-1716).
    pub capability_hash: [u8; 32],
}

/// Edge-local facts about one admitted connection.
pub struct ConnectionEntry {
    sink: Arc<dyn ClientSink>,
    physical: bool,
    purpose: ListenerPurpose,
    source: SourceAddressKey,
    admission: AdmissionClass,
    opened_at: MonotonicTick,
    session: Option<BoundSession>,
    capabilities: Option<CapabilityState>,
    active_query: Option<(u64, u64)>,
    sink_gone: bool,
    last_line_sequence: u64,
    pending_physical_close: Option<PendingPhysicalClose>,
}

struct PendingPhysicalClose {
    notice: PhysicalCloseNotice,
    route_buffered_lines: bool,
}

pub(crate) struct LineAcceptance {
    pub(crate) route: bool,
    pub(crate) completed_close: Option<PhysicalCloseNotice>,
}

impl ConnectionEntry {
    /// Borrows the output owner.
    #[must_use]
    pub fn sink(&self) -> &Arc<dyn ClientSink> {
        &self.sink
    }

    /// Returns the accepting listener purpose.
    #[must_use]
    pub const fn purpose(&self) -> ListenerPurpose {
        self.purpose
    }

    /// Returns the masked rate-prefix or onion admission key.
    #[must_use]
    pub const fn source_prefix(&self) -> SourceAddressKey {
        self.source
    }

    /// Returns the admission class.
    #[must_use]
    pub const fn admission(&self) -> AdmissionClass {
        self.admission
    }

    /// Returns the monotonic tick the connection was announced at.
    #[must_use]
    pub const fn opened_at(&self) -> MonotonicTick {
        self.opened_at
    }

    /// Returns the registered identity, if registration completed.
    #[must_use]
    pub const fn session(&self) -> Option<BoundSession> {
        self.session
    }

    /// Borrows the exact edge-local negotiated capability state.
    #[must_use]
    pub const fn capabilities(&self) -> Option<&CapabilityState> {
        self.capabilities.as_ref()
    }

    /// Returns whether the transport already reported the connection gone.
    #[must_use]
    pub const fn sink_gone(&self) -> bool {
        self.sink_gone
    }
}

/// Every admitted connection and its optional registered session.
#[derive(Default)]
pub struct SessionTable {
    connections: BTreeMap<ConnectionGeneration, ConnectionEntry>,
    users: BTreeMap<UserId, ConnectionGeneration>,
    ceiling: usize,
    query_usage: super::query_usage::QueryUsageLedger,
}

impl SessionTable {
    /// Creates an empty table with the spec connection ceiling.
    #[must_use]
    pub fn new() -> Self {
        Self::with_ceiling(MAX_TRACKED_CONNECTIONS)
    }

    /// Creates an empty table with an explicit ceiling.
    #[must_use]
    pub fn with_ceiling(ceiling: usize) -> Self {
        Self {
            connections: BTreeMap::new(),
            users: BTreeMap::new(),
            ceiling,
            query_usage: super::query_usage::QueryUsageLedger::default(),
        }
    }

    /// Records an admitted connection; a reused generation or a full table
    /// is rejected without changing anything.
    pub fn open(
        &mut self,
        generation: ConnectionGeneration,
        purpose: ListenerPurpose,
        source: SourceAddressKey,
        sink: Arc<dyn ClientSink>,
        now: MonotonicTick,
    ) -> Result<(), RuntimeError> {
        self.open_connection(generation, purpose, source, sink, now, true)
    }

    /// Records an internal account carrier that has no transport close lane.
    pub(crate) fn open_virtual(
        &mut self,
        generation: ConnectionGeneration,
        sink: Arc<dyn ClientSink>,
        now: MonotonicTick,
    ) -> Result<(), RuntimeError> {
        self.open_connection(
            generation,
            ListenerPurpose::ClientTls,
            SourceAddressKey::onion_listener(),
            sink,
            now,
            false,
        )
    }

    fn open_connection(
        &mut self,
        generation: ConnectionGeneration,
        purpose: ListenerPurpose,
        source: SourceAddressKey,
        sink: Arc<dyn ClientSink>,
        now: MonotonicTick,
        physical: bool,
    ) -> Result<(), RuntimeError> {
        if generation != sink.generation()
            || source != source.prefix_key()
            || self.connections.contains_key(&generation)
        {
            return Err(RuntimeError::InvalidValue);
        }
        if self.connections.len() >= self.ceiling {
            return Err(RuntimeError::LimitExceeded);
        }
        self.connections.insert(
            generation,
            ConnectionEntry {
                sink,
                physical,
                purpose,
                source,
                admission: AdmissionClass::for_purpose(purpose),
                opened_at: now,
                session: None,
                capabilities: None,
                active_query: None,
                sink_gone: false,
                last_line_sequence: 0,
                pending_physical_close: None,
            },
        );
        Ok(())
    }

    pub(crate) fn begin_physical_close(
        &mut self,
        notice: PhysicalCloseNotice,
    ) -> Result<Option<PhysicalCloseNotice>, PhysicalCloseNotice> {
        let Some(entry) = self.connections.get_mut(&notice.generation) else {
            return Err(notice);
        };
        if entry.pending_physical_close.is_some()
            || notice.final_line_sequence < entry.last_line_sequence
        {
            return Err(notice);
        }
        let route_buffered_lines = !entry.sink_gone;
        entry.sink_gone = true;
        if notice.final_line_sequence == entry.last_line_sequence {
            return Ok(Some(notice));
        }
        entry.pending_physical_close = Some(PendingPhysicalClose {
            notice,
            route_buffered_lines,
        });
        Ok(None)
    }

    pub(crate) fn accept_line(
        &mut self,
        generation: ConnectionGeneration,
        sequence: u64,
    ) -> Result<Option<LineAcceptance>, RuntimeError> {
        let Some(entry) = self.connections.get_mut(&generation) else {
            return Ok(None);
        };
        let expected = entry
            .last_line_sequence
            .checked_add(1)
            .ok_or(RuntimeError::InvalidValue)?;
        if sequence != expected
            || entry
                .pending_physical_close
                .as_ref()
                .is_some_and(|pending| sequence > pending.notice.final_line_sequence)
        {
            return Err(RuntimeError::InvalidValue);
        }
        entry.last_line_sequence = sequence;
        let route = entry
            .pending_physical_close
            .as_ref()
            .map_or_else(|| !entry.sink_gone, |pending| pending.route_buffered_lines);
        let completed_close = if entry
            .pending_physical_close
            .as_ref()
            .is_some_and(|pending| sequence == pending.notice.final_line_sequence)
        {
            entry
                .pending_physical_close
                .take()
                .map(|pending| pending.notice)
        } else {
            None
        };
        Ok(Some(LineAcceptance {
            route,
            completed_close,
        }))
    }

    /// Associates an internal account carrier with registered authority without
    /// making it a local chat recipient. Replies still address its generation.
    pub(crate) fn bind_virtual_session(
        &mut self,
        generation: ConnectionGeneration,
        session: BoundSession,
    ) -> Result<(), RuntimeError> {
        let entry = self
            .connections
            .get_mut(&generation)
            .ok_or(RuntimeError::InvalidValue)?;
        if entry.physical
            || entry.session.is_some()
            || entry.capabilities.is_some()
            || self.users.contains_key(&session.user_id)
        {
            return Err(RuntimeError::InvalidValue);
        }
        entry.session = Some(session);
        Ok(())
    }

    /// Binds a registered identity to a connection exactly once.
    pub fn bind_session(
        &mut self,
        generation: ConnectionGeneration,
        session: BoundSession,
        capabilities: CapabilityState,
    ) -> Result<(), RuntimeError> {
        let entry = self
            .connections
            .get_mut(&generation)
            .ok_or(RuntimeError::InvalidValue)?;
        if entry.session.is_some()
            || entry.capabilities.is_some()
            || self.users.contains_key(&session.user_id)
        {
            return Err(RuntimeError::InvalidValue);
        }
        entry.session = Some(session);
        entry.capabilities = Some(capabilities);
        self.users.insert(session.user_id, generation);
        Ok(())
    }

    /// Refreshes local rendering state without changing the registered identity.
    /// An unchanged state requires no allocation; a failed copy leaves it intact.
    pub(crate) fn refresh_capabilities(
        &mut self,
        generation: ConnectionGeneration,
        session: BoundSession,
        capabilities: &CapabilityState,
    ) -> Result<(), RuntimeError> {
        let entry = self
            .connections
            .get_mut(&generation)
            .ok_or(RuntimeError::InvalidValue)?;
        if entry.session != Some(session) || self.users.get(&session.user_id) != Some(&generation) {
            return Err(RuntimeError::InvalidValue);
        }
        if entry.capabilities.as_ref() != Some(capabilities) {
            entry.capabilities = Some(
                capabilities
                    .try_clone()
                    .map_err(|_| RuntimeError::MemoryExhausted)?,
            );
        }
        Ok(())
    }

    /// Rolls back a registration binding before its domain insertion became
    /// visible. Both identities must match the entry being unbound.
    pub fn unbind_session(
        &mut self,
        generation: ConnectionGeneration,
        session: BoundSession,
    ) -> Result<(), RuntimeError> {
        let entry = self
            .connections
            .get_mut(&generation)
            .ok_or(RuntimeError::InvalidValue)?;
        if entry.session != Some(session) || self.users.get(&session.user_id) != Some(&generation) {
            return Err(RuntimeError::InvalidValue);
        }
        entry.session = None;
        entry.capabilities = None;
        self.users.remove(&session.user_id);
        Ok(())
    }

    /// Marks the transport gone without removing the entry, so an in-flight
    /// batch still finds the generation and discards its frames on commit
    /// (spec lines 4203-4206).
    pub fn mark_sink_gone(&mut self, generation: ConnectionGeneration) -> bool {
        match self.connections.get_mut(&generation) {
            Some(entry) => {
                entry.sink_gone = true;
                if let Some(pending) = &mut entry.pending_physical_close {
                    pending.route_buffered_lines = false;
                }
                true
            }
            None => false,
        }
    }

    /// Removes a connection and its user binding.
    pub fn close(&mut self, generation: ConnectionGeneration) -> Option<ConnectionEntry> {
        let entry = self.connections.remove(&generation)?;
        if let Some(session) = entry.session
            && self.users.get(&session.user_id) == Some(&generation)
        {
            self.users.remove(&session.user_id);
        }
        Some(entry)
    }

    /// Borrows one connection.
    #[must_use]
    pub fn connection(&self, generation: ConnectionGeneration) -> Option<&ConnectionEntry> {
        self.connections.get(&generation)
    }

    /// Resolves a registered user to its live sink, skipping a connection
    /// whose transport is already gone.
    #[must_use]
    pub fn sink_for_user(
        &self,
        user_id: UserId,
    ) -> Option<(ConnectionGeneration, Arc<dyn ClientSink>)> {
        let generation = *self.users.get(&user_id)?;
        self.sink_for_generation(generation)
            .map(|sink| (generation, sink))
    }

    /// Resolves a connection generation to its live sink.
    #[must_use]
    pub fn sink_for_generation(
        &self,
        generation: ConnectionGeneration,
    ) -> Option<Arc<dyn ClientSink>> {
        let entry = self.connections.get(&generation)?;
        if entry.sink_gone {
            return None;
        }
        Some(Arc::clone(&entry.sink))
    }

    /// Returns the generation currently bound to a user.
    #[must_use]
    pub fn generation_for_user(&self, user_id: UserId) -> Option<ConnectionGeneration> {
        self.users.get(&user_id).copied()
    }

    /// Borrows one registered user's exact edge-local capability state.
    #[must_use]
    pub fn capabilities_for_user(&self, user_id: UserId) -> Option<&CapabilityState> {
        let generation = self.users.get(&user_id)?;
        self.connections.get(generation)?.capabilities()
    }

    /// Returns the number of tracked connections.
    #[must_use]
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Returns whether no connection is tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    /// Whether any transport still owes its final physical-close notice.
    /// A writer acknowledgement or sink failure does not discharge that notice.
    pub(crate) fn has_physical_connections(&self) -> bool {
        self.connections.values().any(|entry| entry.physical)
    }

    /// Returns the number of registered sessions.
    #[must_use]
    pub fn registered_len(&self) -> usize {
        self.users.len()
    }

    /// Iterates every tracked generation in ascending order.
    pub fn generations(&self) -> impl Iterator<Item = ConnectionGeneration> + '_ {
        self.connections.keys().copied()
    }

    /// Clones every live sink in generation order for an owner-wide control
    /// action such as orderly shutdown.
    #[must_use]
    pub fn live_sinks(&self) -> Vec<Arc<dyn ClientSink>> {
        self.connections
            .values()
            .filter(|entry| !entry.sink_gone)
            .map(|entry| Arc::clone(&entry.sink))
            .collect()
    }

    /// Lists every connection whose transport is still live together with the
    /// bytes currently charged to its outbound queue (spec 19.3).
    ///
    /// A connection whose sink is already gone owns no reclaimable queue, so
    /// it is never offered twice. The order is the ascending generation order
    /// of the table, which gives the selector a deterministic tie-break.
    #[must_use]
    pub fn eviction_candidates(&self) -> Vec<EvictionCandidate> {
        self.connections
            .iter()
            .filter(|(_, entry)| !entry.sink_gone)
            .map(|(generation, entry)| EvictionCandidate {
                generation: *generation,
                charged_bytes: entry.sink.queue_snapshot().queued_bytes(),
            })
            .collect()
    }

    /// Sums input-free queue snapshots for every live client sink.
    #[must_use]
    pub fn queue_snapshot(&self) -> ClientQueueSnapshot {
        self.query_usage.global(self.base_queue_snapshot(), |user| {
            self.base_query_usage(user).query_snapshots()
        })
    }

    pub(super) fn base_queue_snapshot(&self) -> ClientQueueSnapshot {
        let mut queued_bytes = 0_u64;
        let mut capacity_bytes = 0_u64;
        let mut query_snapshots = 0_u64;
        let mut query_rows = 0_u64;
        let mut query_bytes = 0_u64;
        let mut largest_query_rows = 0_u64;
        let mut max_query_snapshots_per_session = 0_u64;
        for snapshot in self
            .connections
            .values()
            .filter(|entry| !entry.sink_gone)
            .map(ConnectionEntry::queue_snapshot)
        {
            queued_bytes = queued_bytes.saturating_add(snapshot.queued_bytes());
            capacity_bytes = capacity_bytes.saturating_add(snapshot.capacity_bytes());
            query_snapshots = query_snapshots.saturating_add(snapshot.query_snapshots());
            query_rows = query_rows.saturating_add(snapshot.query_rows());
            query_bytes = query_bytes.saturating_add(snapshot.query_bytes());
            largest_query_rows = largest_query_rows.max(snapshot.largest_query_rows());
            max_query_snapshots_per_session =
                max_query_snapshots_per_session.max(snapshot.max_query_snapshots_per_session());
        }
        ClientQueueSnapshot::with_query_usage(
            queued_bytes,
            capacity_bytes,
            query_snapshots,
            query_rows,
            query_bytes,
            largest_query_rows,
            max_query_snapshots_per_session,
        )
    }

    /// Counts a connection-owned snapshot before its final frame is queued.
    pub(crate) fn begin_active_query(
        &mut self,
        generation: ConnectionGeneration,
        rows: u64,
        bytes: u64,
    ) -> Result<(), RuntimeError> {
        let entry = self
            .connections
            .get_mut(&generation)
            .filter(|entry| !entry.sink_gone)
            .ok_or(RuntimeError::InvalidValue)?;
        if entry.active_query.is_some() || bytes == 0 {
            return Err(RuntimeError::InvalidValue);
        }
        entry.active_query = Some((rows, bytes));
        Ok(())
    }

    /// Releases metadata as the permit moves to the queue, or is abandoned.
    pub(crate) fn end_active_query(&mut self, generation: ConnectionGeneration) {
        if let Some(entry) = self.connections.get_mut(&generation) {
            entry.active_query = None;
        }
    }

    pub(crate) fn query_snapshot_for(
        &self,
        generation: ConnectionGeneration,
    ) -> Option<ClientQueueSnapshot> {
        let entry = self
            .connections
            .get(&generation)
            .filter(|entry| !entry.sink_gone)?;
        let base = entry.queue_snapshot();
        Some(
            entry
                .session
                .map_or(base, |bound| self.query_usage.session(bound.user_id, base)),
        )
    }

    pub(super) fn base_query_usage(&self, user: UserId) -> ClientQueueSnapshot {
        self.users
            .get(&user)
            .and_then(|generation| self.connections.get(generation))
            .filter(|entry| !entry.sink_gone)
            .map(ConnectionEntry::queue_snapshot)
            .unwrap_or_default()
    }

    pub(crate) fn query_reservations(
        &self,
        user: UserId,
        limits: crate::runtime_config::RuntimeResourceLimits,
        backing: crate::budget::BackingReservationPort,
    ) -> super::query_usage::QueryReservationPort<'_> {
        super::query_usage::QueryReservationPort::new(
            self,
            &self.query_usage,
            user,
            limits,
            backing,
        )
    }
}

impl ConnectionEntry {
    fn queue_snapshot(&self) -> ClientQueueSnapshot {
        let queued = self.sink.queue_snapshot();
        let Some((rows, bytes)) = self.active_query else {
            return queued;
        };
        let count = queued.query_snapshots().saturating_add(1);
        ClientQueueSnapshot::with_query_usage(
            queued.queued_bytes(),
            queued.capacity_bytes(),
            count,
            queued.query_rows().saturating_add(rows),
            queued.query_bytes().saturating_add(bytes),
            queued.largest_query_rows().max(rows),
            count,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::{BoundedMemoryCharges, MemoryBudget, MemoryBudgetPort, MemoryCharge};
    use crate::connection::sink::{
        BoundedSharedClientFrames, ClientQueueDemand, ClientQueueReservation, QueueAllocationError,
        SinkReserveError, TentativeClientQueueReservation,
    };
    use agenc_ircd_client_wire::{CapabilityProfile, CapabilitySpec};
    use agenc_ircd_types::SessionId;

    struct ClosedSink(ConnectionGeneration);

    #[test]
    fn active_query_usage_is_counted_until_transfer_or_connection_close() -> Result<(), RuntimeError>
    {
        let mut table = SessionTable::new();
        for value in [1, 2] {
            table.open(
                ConnectionGeneration::new(value),
                ListenerPurpose::ClientTls,
                SourceAddressKey::onion_listener(),
                sink(value),
                MonotonicTick::from_ticks(0),
            )?;
        }
        let first = ConnectionGeneration::new(1);
        let second = ConnectionGeneration::new(2);
        table.begin_active_query(first, 10, 1_024)?;
        table.begin_active_query(second, 20, 2_048)?;
        let usage = table.queue_snapshot();
        assert_eq!(
            (
                usage.query_snapshots(),
                usage.query_rows(),
                usage.query_bytes()
            ),
            (2, 30, 3_072)
        );
        assert_eq!(usage.largest_query_rows(), 20);
        assert_eq!(usage.max_query_snapshots_per_session(), 1);
        let individual = table
            .query_snapshot_for(first)
            .ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(
            (individual.query_snapshots(), individual.query_rows()),
            (1, 10)
        );
        assert_eq!(
            table.begin_active_query(first, 99, 99),
            Err(RuntimeError::InvalidValue)
        );
        table.end_active_query(first);
        table.end_active_query(first);
        assert_eq!(table.queue_snapshot().query_rows(), 20);
        let _closed = table.close(second).ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(table.queue_snapshot().query_snapshots(), 0);
        assert_eq!(
            table.begin_active_query(second, 1, 1),
            Err(RuntimeError::InvalidValue)
        );
        Ok(())
    }

    impl ClientSink for ClosedSink {
        fn generation(&self) -> ConnectionGeneration {
            self.0
        }

        fn try_reserve(
            &self,
            _demand: ClientQueueDemand,
        ) -> Result<TentativeClientQueueReservation, SinkReserveError> {
            Err(SinkReserveError::Closed)
        }

        fn prepare(
            &self,
            _tentative: TentativeClientQueueReservation,
            _backing: Option<crate::budget::MemoryPermit>,
        ) -> Result<ClientQueueReservation, QueueAllocationError> {
            Err(QueueAllocationError::Closed)
        }

        fn commit(&self, _reservation: ClientQueueReservation, _frames: BoundedSharedClientFrames) {
        }

        fn begin_slow_consumer_close(&self) {}

        fn close_after_flush(
            &self,
            _reason: crate::state_core::inbox::CloseReason,
        ) -> crate::connection::FlushAcknowledgement {
            crate::connection::FlushAcknowledgement::complete()
        }

        fn queue_snapshot(&self) -> crate::connection::ClientQueueSnapshot {
            crate::connection::ClientQueueSnapshot::default()
        }
    }

    fn sink(value: u64) -> Arc<dyn ClientSink> {
        Arc::new(ClosedSink(ConnectionGeneration::new(value)))
    }

    fn bound(seed: u8) -> BoundSession {
        BoundSession {
            session_id: SessionId::from_bytes([seed; 16]),
            user_id: UserId::from_bytes([seed; 16]),
            capability_hash: [seed; 32],
        }
    }

    fn enabled_capability(name: &str) -> Result<CapabilityState, RuntimeError> {
        let capability = CapabilitySpec::new(name, None).map_err(|_| RuntimeError::InvalidValue)?;
        let profile =
            CapabilityProfile::new(vec![capability]).map_err(|_| RuntimeError::InvalidValue)?;
        let mut state = CapabilityState::default();
        state
            .ls(Some("302"), &profile)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let reply = state
            .request(name, &profile)
            .map_err(|_| RuntimeError::InvalidValue)?;
        if !matches!(reply, agenc_ircd_client_wire::CapRequestReply::Ack(_)) {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(state)
    }

    #[test]
    fn virtual_carriers_do_not_discharge_a_physical_close() -> Result<(), RuntimeError> {
        let mut table = SessionTable::with_ceiling(2);
        let now = MonotonicTick::from_ticks(1);
        let physical = ConnectionGeneration::new(1);
        let virtual_carrier = ConnectionGeneration::new(2);
        table.open(
            physical,
            ListenerPurpose::ClientOnion,
            SourceAddressKey::onion_listener(),
            sink(1),
            now,
        )?;
        table.open_virtual(virtual_carrier, sink(2), now)?;
        assert!(table.has_physical_connections());
        assert!(table.mark_sink_gone(physical));
        assert!(table.has_physical_connections());
        assert!(table.open_virtual(virtual_carrier, sink(2), now).is_err());
        assert!(
            table
                .open_virtual(ConnectionGeneration::new(3), sink(3), now)
                .is_err()
        );
        assert!(table.close(physical).is_some());
        assert!(!table.has_physical_connections());
        assert_eq!(table.len(), 1);
        assert!(table.connection(virtual_carrier).is_some());
        Ok(())
    }

    #[test]
    fn bindings_refuse_reused_users_unlisted_identities_and_empty_queries()
    -> Result<(), RuntimeError> {
        let mut table = SessionTable::new();
        let now = MonotonicTick::from_ticks(1);
        let first = ConnectionGeneration::new(1);
        let second = ConnectionGeneration::new(2);
        let internal = ConnectionGeneration::new(3);
        for generation in [first, second] {
            table.open(
                generation,
                ListenerPurpose::ClientTls,
                SourceAddressKey::onion_listener(),
                sink(generation.get()),
                now,
            )?;
        }
        table.bind_session(first, bound(1), CapabilityState::default())?;
        // The same user cannot be bound to a second connection.
        assert!(
            table
                .bind_session(second, bound(1), CapabilityState::default())
                .is_err()
        );
        // A virtual carrier is not listed as the user's connection, so a
        // refresh or an unbind addressed to it as a local binding is refused.
        table.open_virtual(internal, sink(3), now)?;
        table.bind_virtual_session(internal, bound(2))?;
        assert!(
            table
                .refresh_capabilities(internal, bound(2), &CapabilityState::default())
                .is_err()
        );
        assert!(table.unbind_session(internal, bound(2)).is_err());
        assert!(table.bind_virtual_session(internal, bound(1)).is_err());
        assert_eq!(
            table.begin_active_query(second, 1, 0),
            Err(RuntimeError::InvalidValue)
        );
        table.begin_active_query(second, 1, 1)?;
        Ok(())
    }

    #[test]
    fn virtual_authority_never_receives_chat_or_removes_a_later_local_binding()
    -> Result<(), RuntimeError> {
        let mut table = SessionTable::new();
        let internal = ConnectionGeneration::new(2);
        let physical = ConnectionGeneration::new(1);
        let now = MonotonicTick::from_ticks(1);
        let bound = BoundSession {
            user_id: UserId::from_bytes([1; 16]),
            session_id: SessionId::from_bytes([2; 16]),
            capability_hash: [3; 32],
        };
        table.open_virtual(internal, sink(2), now)?;
        table.bind_virtual_session(internal, bound)?;
        assert_eq!(
            table
                .connection(internal)
                .and_then(ConnectionEntry::session),
            Some(bound)
        );
        assert!(table.sink_for_user(bound.user_id).is_none());
        assert!(table.generation_for_user(bound.user_id).is_none());
        assert!(table.sink_for_generation(internal).is_some());
        assert!(table.bind_virtual_session(internal, bound).is_err());
        table.open(
            physical,
            ListenerPurpose::ClientOnion,
            SourceAddressKey::onion_listener(),
            sink(1),
            now,
        )?;
        assert!(table.bind_virtual_session(physical, bound).is_err());
        table.bind_session(physical, bound, CapabilityState::default())?;
        assert!(table.close(internal).is_some());
        assert_eq!(table.generation_for_user(bound.user_id), Some(physical));
        assert!(table.close(physical).is_some());
        assert!(table.sink_for_user(bound.user_id).is_none());
        Ok(())
    }

    #[test]
    fn capability_refresh_requires_the_exact_bound_connection_and_session()
    -> Result<(), RuntimeError> {
        let mut table = SessionTable::new();
        let generation = ConnectionGeneration::new(1);
        table.open(
            generation,
            ListenerPurpose::ClientOnion,
            SourceAddressKey::onion_listener(),
            sink(1),
            MonotonicTick::from_ticks(1),
        )?;
        table.bind_session(generation, bound(1), CapabilityState::default())?;
        let enabled = enabled_capability("multi-prefix")?;
        assert!(
            table
                .refresh_capabilities(generation, bound(2), &enabled)
                .is_err()
        );
        assert!(
            table
                .refresh_capabilities(ConnectionGeneration::new(2), bound(1), &enabled)
                .is_err()
        );
        assert!(
            table
                .capabilities_for_user(bound(1).user_id)
                .is_some_and(|state| !state.enabled("multi-prefix"))
        );
        table.refresh_capabilities(generation, bound(1), &enabled)?;
        assert!(
            table
                .capabilities_for_user(bound(1).user_id)
                .is_some_and(|state| state.enabled("multi-prefix"))
        );
        assert_eq!(
            table
                .connection(generation)
                .and_then(ConnectionEntry::session),
            Some(bound(1))
        );
        table.refresh_capabilities(generation, bound(1), &CapabilityState::default())?;
        assert!(
            table
                .capabilities_for_user(bound(1).user_id)
                .is_some_and(|state| !state.enabled("multi-prefix"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn physical_close_waits_for_accepted_lines_without_reopening_a_policy_close()
    -> Result<(), RuntimeError> {
        let mut table = SessionTable::new();
        let generation = ConnectionGeneration::new(5);
        table.open(
            generation,
            ListenerPurpose::ClientTls,
            SourceAddressKey::ipv4([10, 0, 0, 5]).prefix_key(),
            sink(5),
            MonotonicTick::from_ticks(1),
        )?;
        let budget = MemoryBudget::new(1);
        let charges = BoundedMemoryCharges::new(&[MemoryCharge::fixed(1)])?;
        let mut permits = budget.try_acquire_batch(charges)?;
        let permit = permits.split_exact(1).ok_or(RuntimeError::InvalidValue)?;
        let (return_permit, returned_permit) = tokio::sync::oneshot::channel();
        let notice = PhysicalCloseNotice {
            generation,
            reason: crate::state_core::inbox::CloseReason::TransportLoss,
            closed_at: Some(MonotonicTick::from_ticks(2)),
            final_line_sequence: 2,
            state_permit: crate::state_core::inbox::ConnectionStatePermit::new(
                permit,
                return_permit,
            ),
        };
        assert!(
            table
                .begin_physical_close(notice)
                .is_ok_and(|ready| ready.is_none())
        );
        let first = table
            .accept_line(generation, 1)?
            .ok_or(RuntimeError::InvalidValue)?;
        assert!(first.route);
        assert!(first.completed_close.is_none());
        table.mark_sink_gone(generation);
        let second = table
            .accept_line(generation, 2)?
            .ok_or(RuntimeError::InvalidValue)?;
        assert!(!second.route);
        let completed = second.completed_close.ok_or(RuntimeError::InvalidValue)?;
        drop(completed.state_permit);
        drop(returned_permit.await.map_err(|_| RuntimeError::Cancelled)?);
        assert_eq!(budget.available(), 1);
        assert!(table.close(generation).is_some());
        Ok(())
    }

    #[test]
    fn open_bind_resolve_and_close_are_generation_fenced() -> Result<(), RuntimeError> {
        let mut table = SessionTable::new();
        let generation = ConnectionGeneration::new(7);
        let now = MonotonicTick::from_ticks(5);
        table.open(
            generation,
            ListenerPurpose::ClientTls,
            SourceAddressKey::ipv4([10, 0, 0, 1]).prefix_key(),
            sink(7),
            now,
        )?;
        assert_eq!(
            table
                .open(
                    generation,
                    ListenerPurpose::ClientTls,
                    SourceAddressKey::ipv4([10, 0, 0, 1]).prefix_key(),
                    sink(7),
                    now,
                )
                .err(),
            Some(RuntimeError::InvalidValue)
        );
        let entry = table
            .connection(generation)
            .ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(entry.purpose(), ListenerPurpose::ClientTls);
        assert_eq!(entry.admission(), AdmissionClass::Direct);
        assert_eq!(entry.opened_at(), now);
        assert!(entry.session().is_none());
        assert!(!entry.sink_gone());
        assert!(entry.source_prefix() == SourceAddressKey::ipv4([10, 0, 0, 1]).prefix_key());
        assert_eq!(entry.sink().generation(), generation);

        let session = bound(1);
        table.bind_session(generation, session, enabled_capability("message-tags")?)?;
        assert!(
            table
                .capabilities_for_user(session.user_id)
                .is_some_and(|state| state.enabled("message-tags"))
        );
        assert_eq!(
            table
                .bind_session(generation, bound(2), CapabilityState::default())
                .err(),
            Some(RuntimeError::InvalidValue)
        );
        assert_eq!(
            table
                .bind_session(
                    ConnectionGeneration::new(99),
                    bound(3),
                    CapabilityState::default(),
                )
                .err(),
            Some(RuntimeError::InvalidValue)
        );
        assert_eq!(table.registered_len(), 1);
        assert_eq!(table.generation_for_user(session.user_id), Some(generation));
        let (found, live) = table
            .sink_for_user(session.user_id)
            .ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(found, generation);
        assert_eq!(live.generation(), generation);
        assert!(table.sink_for_user(UserId::from_bytes([9; 16])).is_none());

        assert!(table.mark_sink_gone(generation));
        assert!(!table.mark_sink_gone(ConnectionGeneration::new(99)));
        assert!(table.sink_for_user(session.user_id).is_none());
        assert!(table.sink_for_generation(generation).is_none());
        assert!(
            table
                .connection(generation)
                .is_some_and(ConnectionEntry::sink_gone)
        );

        let closed = table.close(generation).ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(closed.session(), Some(session));
        assert!(table.close(generation).is_none());
        assert!(table.is_empty());
        assert_eq!(table.registered_len(), 0);
        assert_eq!(table.generations().count(), 0);
        Ok(())
    }

    #[test]
    fn raw_host_keys_are_rejected_at_the_protocol_state_boundary() {
        let mut table = SessionTable::new();
        assert_eq!(
            table
                .open(
                    ConnectionGeneration::new(8),
                    ListenerPurpose::ClientTls,
                    SourceAddressKey::ipv4([10, 0, 0, 8]),
                    sink(8),
                    MonotonicTick::from_ticks(5),
                )
                .err(),
            Some(RuntimeError::InvalidValue)
        );
        assert!(table.is_empty());
    }

    #[test]
    fn registration_binding_rollback_requires_both_exact_identities() -> Result<(), RuntimeError> {
        let mut table = SessionTable::new();
        let generation = ConnectionGeneration::new(17);
        table.open(
            generation,
            ListenerPurpose::ClientTls,
            SourceAddressKey::ipv4([10, 0, 0, 17]).prefix_key(),
            sink(17),
            MonotonicTick::from_ticks(5),
        )?;
        let session = bound(17);
        table.bind_session(generation, session, enabled_capability("server-time")?)?;
        assert!(table.capabilities_for_user(session.user_id).is_some());
        assert_eq!(
            table.unbind_session(generation, bound(18)).err(),
            Some(RuntimeError::InvalidValue)
        );
        assert_eq!(table.registered_len(), 1);
        table.unbind_session(generation, session)?;
        assert_eq!(table.registered_len(), 0);
        assert!(table.capabilities_for_user(session.user_id).is_none());
        assert!(
            table
                .connection(generation)
                .is_some_and(|entry| entry.session().is_none())
        );
        assert_eq!(
            table.unbind_session(generation, session).err(),
            Some(RuntimeError::InvalidValue)
        );
        Ok(())
    }

    #[test]
    fn a_duplicate_user_binding_and_a_full_table_are_refused() -> Result<(), RuntimeError> {
        let mut table = SessionTable::with_ceiling(1);
        let first = ConnectionGeneration::new(1);
        let second = ConnectionGeneration::new(2);
        let now = MonotonicTick::from_ticks(0);
        table.open(
            first,
            ListenerPurpose::ClientOnion,
            SourceAddressKey::onion_listener(),
            sink(1),
            now,
        )?;
        assert_eq!(
            table
                .open(
                    second,
                    ListenerPurpose::AdminLocal,
                    SourceAddressKey::onion_listener(),
                    sink(2),
                    now,
                )
                .err(),
            Some(RuntimeError::LimitExceeded)
        );
        assert_eq!(table.len(), 1);
        table.bind_session(first, bound(4), CapabilityState::default())?;
        let mut larger = SessionTable::with_ceiling(2);
        larger.open(
            first,
            ListenerPurpose::AdminTls,
            SourceAddressKey::ipv6([1; 16]).prefix_key(),
            sink(1),
            now,
        )?;
        larger.open(
            second,
            ListenerPurpose::ClientTls,
            SourceAddressKey::ipv6([2; 16]).prefix_key(),
            sink(2),
            now,
        )?;
        larger.bind_session(first, bound(4), CapabilityState::default())?;
        assert_eq!(
            larger
                .bind_session(second, bound(4), CapabilityState::default())
                .err(),
            Some(RuntimeError::InvalidValue),
            "one user binds to one live connection"
        );
        assert_eq!(
            AdmissionClass::for_purpose(ListenerPurpose::AdminTls),
            AdmissionClass::Admin
        );
        assert_eq!(
            AdmissionClass::for_purpose(ListenerPurpose::ClientWss),
            AdmissionClass::Direct
        );
        assert_eq!(
            AdmissionClass::for_purpose(ListenerPurpose::Federation),
            AdmissionClass::Direct
        );
        assert_eq!(
            AdmissionClass::for_purpose(ListenerPurpose::ClientOnion),
            AdmissionClass::Onion
        );
        Ok(())
    }
}
