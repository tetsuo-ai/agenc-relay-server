//! Query leases shared by retained protocol snapshots and local queue admission.

#![forbid(unsafe_code)]

use agenc_relay_types::UserId;

use super::session::SessionTable;
use crate::RuntimeError;
use crate::budget::{BackingReservationPort, MemoryPermit};
use crate::connection::ClientQueueSnapshot;
use crate::runtime_config::RuntimeResourceLimits;
use crate::sync::{Arc, Mutex, lock};

#[derive(Clone, Copy)]
struct Record {
    id: u64,
    user: Option<UserId>,
    rows: u64,
    bytes: u64,
}

#[derive(Default)]
struct Records {
    entries: Vec<Record>,
    next_id: u64,
    // The vector is freed before its retained capacity reservation.
    capacity: Option<MemoryPermit>,
}

struct Shared {
    records: Mutex<Records>,
    _allocation: MemoryPermit,
}

/// The empty ledger allocates nothing. Its shared owner is charged on first use.
#[derive(Default)]
pub(crate) struct QueryUsageLedger {
    shared: Mutex<Option<Arc<Shared>>>,
}

/// Dropping one lease returns only that snapshot or shared index's query usage.
pub(crate) struct QueryUsageLease {
    id: u64,
    shared: Arc<Shared>,
}

impl Drop for QueryUsageLease {
    fn drop(&mut self) {
        let mut records = lock(&self.shared.records);
        if let Some(position) = records.entries.iter().position(|entry| entry.id == self.id) {
            records.entries.remove(position);
        }
    }
}

impl QueryUsageLedger {
    fn owner(&self, backing: &BackingReservationPort) -> Result<Arc<Shared>, RuntimeError> {
        let mut shared = lock(&self.shared);
        if let Some(owner) = shared.as_ref() {
            return Ok(Arc::clone(owner));
        }
        let allocation = backing.reserve(size_of::<Shared>() + 2 * size_of::<usize>())?;
        let owner = Arc::new(Shared {
            records: Mutex::new(Records::default()),
            _allocation: allocation,
        });
        *shared = Some(Arc::clone(&owner));
        Ok(owner)
    }

    pub(super) fn global(
        &self,
        base: ClientQueueSnapshot,
        local_count: impl Fn(UserId) -> u64,
    ) -> ClientQueueSnapshot {
        let owner = lock(&self.shared);
        let Some(owner) = owner.as_ref() else {
            return base;
        };
        lock(&owner.records).global(base, local_count)
    }

    pub(super) fn session(&self, user: UserId, base: ClientQueueSnapshot) -> ClientQueueSnapshot {
        let owner = lock(&self.shared);
        let Some(owner) = owner.as_ref() else {
            return base;
        };
        lock(&owner.records).session(user, base)
    }
}

impl Records {
    fn insert(
        &mut self,
        record: Record,
        backing: &BackingReservationPort,
    ) -> Result<(), RuntimeError> {
        if self.entries.len() == self.entries.capacity() {
            let capacity = self
                .entries
                .len()
                .checked_add(1)
                .ok_or(RuntimeError::Overflow)?;
            let capacity = capacity.checked_mul(2).ok_or(RuntimeError::Overflow)?;
            let bytes = capacity
                .checked_mul(size_of::<Record>())
                .ok_or(RuntimeError::Overflow)?;
            let permit = backing.reserve(bytes)?;
            let mut entries = Vec::new();
            entries
                .try_reserve_exact(capacity)
                .map_err(|_| RuntimeError::MemoryExhausted)?;
            if entries.capacity() > capacity {
                return Err(RuntimeError::MemoryExhausted);
            }
            entries.extend_from_slice(&self.entries);
            self.entries = entries;
            self.capacity = Some(permit);
        }
        let key = (record.user, record.id);
        let position = self
            .entries
            .partition_point(|entry| (entry.user, entry.id) < key);
        self.entries.insert(position, record);
        self.next_id = record.id;
        Ok(())
    }

    fn session(&self, user: UserId, base: ClientQueueSnapshot) -> ClientQueueSnapshot {
        self.entries
            .iter()
            .filter(|entry| entry.user == Some(user))
            .fold(base, |usage, entry| {
                let count = usage.query_snapshots().saturating_add(1);
                ClientQueueSnapshot::with_query_usage(
                    usage.queued_bytes(),
                    usage.capacity_bytes(),
                    count,
                    usage.query_rows().saturating_add(entry.rows),
                    usage.query_bytes().saturating_add(entry.bytes),
                    usage.largest_query_rows().max(entry.rows),
                    count,
                )
            })
    }

    fn global(
        &self,
        base: ClientQueueSnapshot,
        local_count: impl Fn(UserId) -> u64,
    ) -> ClientQueueSnapshot {
        let mut snapshots = base.query_snapshots();
        let mut rows = base.query_rows();
        let mut bytes = base.query_bytes();
        let mut largest = base.largest_query_rows();
        let mut maximum = base.max_query_snapshots_per_session();
        let mut previous = None;
        let mut session_count = 0_u64;
        for entry in &self.entries {
            rows = rows.saturating_add(entry.rows);
            bytes = bytes.saturating_add(entry.bytes);
            largest = largest.max(entry.rows);
            if let Some(user) = entry.user {
                snapshots = snapshots.saturating_add(1);
                if previous != Some(user) {
                    previous = Some(user);
                    session_count = local_count(user);
                }
                session_count = session_count.saturating_add(1);
                maximum = maximum.max(session_count);
            }
        }
        ClientQueueSnapshot::with_query_usage(
            base.queued_bytes(),
            base.capacity_bytes(),
            snapshots,
            rows,
            bytes,
            largest,
            maximum,
        )
    }
}

/// This short-lived port borrows current queue usage; a retained lease does not.
pub(crate) struct QueryReservationPort<'a> {
    sessions: &'a SessionTable,
    ledger: &'a QueryUsageLedger,
    user: UserId,
    limits: RuntimeResourceLimits,
    backing: BackingReservationPort,
}

impl<'a> QueryReservationPort<'a> {
    pub(super) fn new(
        sessions: &'a SessionTable,
        ledger: &'a QueryUsageLedger,
        user: UserId,
        limits: RuntimeResourceLimits,
        backing: BackingReservationPort,
    ) -> Self {
        Self {
            sessions,
            ledger,
            user,
            limits,
            backing,
        }
    }

    pub(crate) const fn user(&self) -> UserId {
        self.user
    }

    pub(crate) fn reserve_snapshot(
        &self,
        rows: usize,
        bytes: u64,
    ) -> Result<QueryUsageLease, RuntimeError> {
        let rows = u64::try_from(rows).map_err(|_| RuntimeError::Overflow)?;
        if rows == 0 {
            return Err(RuntimeError::InvalidValue);
        }
        self.reserve(Some(self.user), rows, bytes)
    }

    pub(crate) fn reserve_index(&self, bytes: u64) -> Result<QueryUsageLease, RuntimeError> {
        self.reserve(None, 0, bytes)
    }

    fn reserve(
        &self,
        user: Option<UserId>,
        rows: u64,
        bytes: u64,
    ) -> Result<QueryUsageLease, RuntimeError> {
        let base = self.sessions.base_query_usage(self.user);
        if !self.admits(
            user,
            rows,
            bytes,
            self.ledger.session(self.user, base),
            self.sessions.queue_snapshot(),
        ) {
            return Err(RuntimeError::LimitExceeded);
        }
        let shared = self.ledger.owner(&self.backing)?;
        let mut records = lock(&shared.records);
        let global = records.global(self.sessions.base_queue_snapshot(), |user| {
            self.sessions.base_query_usage(user).query_snapshots()
        });
        let session = records.session(self.user, self.sessions.base_query_usage(self.user));
        if !self.admits(user, rows, bytes, session, global) {
            return Err(RuntimeError::LimitExceeded);
        }
        let id = records
            .next_id
            .checked_add(1)
            .ok_or(RuntimeError::Overflow)?;
        records.insert(
            Record {
                id,
                user,
                rows,
                bytes,
            },
            &self.backing,
        )?;
        drop(records);
        Ok(QueryUsageLease { id, shared })
    }

    fn admits(
        &self,
        user: Option<UserId>,
        rows: u64,
        bytes: u64,
        session: ClientQueueSnapshot,
        global: ClientQueueSnapshot,
    ) -> bool {
        if user.is_some() {
            self.limits.admits_query(session, global, rows, bytes)
        } else {
            global
                .query_bytes()
                .checked_add(bytes)
                .is_some_and(|total| {
                    self.limits
                        .accepts_query_usage(ClientQueueSnapshot::with_query_usage(
                            0,
                            0,
                            global.query_snapshots(),
                            global.query_rows(),
                            total,
                            global.largest_query_rows(),
                            global.max_query_snapshots_per_session(),
                        ))
                })
        }
    }
}

impl super::StateCoreContext {
    pub(crate) fn query_reservations(&self, user: UserId) -> QueryReservationPort<'_> {
        self.sessions.query_reservations(
            user,
            self.runtime_resource_limits,
            self.backing_reservations(),
        )
    }
}
