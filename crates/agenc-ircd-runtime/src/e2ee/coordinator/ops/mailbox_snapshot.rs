//! Charged immutable mailbox cuts and opaque, attachment-bound continuations.

#![forbid(unsafe_code)]

use agenc_ircd_domain::e2ee::mailbox::{Item, MailboxKind, Target};
use agenc_ircd_e2ee::limits::{MAX_BATCH_DECODED_BYTES, MAX_BATCH_FRAGMENTS, MAX_BATCH_OBJECTS};
use agenc_ircd_e2ee::wire::fragment::fragment_count;
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;

use super::{Exec, Fail};
use crate::budget::{BackingReservationPort, MemoryCharge, MemoryPermit};
use crate::state_core::query_usage::QueryUsageLease;
use crate::sync::Arc;

const LIFETIME_MILLIS: u64 = 600_000;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Scope {
    pub user: agenc_ircd_types::UserId,
    pub origin: super::super::CompanionOriginKey,
    pub origin_generation: u64,
    pub target: Target,
    pub kind: MailboxKind,
    pub session_generation: u64,
}

struct Row {
    sequence: u64,
    item: Item,
    begin: usize,
    end: usize,
}

struct BackingVec<T> {
    values: Vec<T>,
    _permit: Option<MemoryPermit>,
    _query: Option<QueryUsageLease>,
}

impl<T> Default for BackingVec<T> {
    fn default() -> Self {
        Self {
            values: Vec::new(),
            _permit: None,
            _query: None,
        }
    }
}

impl<T> std::ops::Deref for BackingVec<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.values
    }
}

struct Snapshot {
    scope: Scope,
    token: [u8; 32],
    expires_at: u64,
    rows: BackingVec<Row>,
    bytes: BackingVec<u8>,
    // Backing is destroyed before these reservations return to the budget.
    _owner_permit: MemoryPermit,
    _query: QueryUsageLease,
}

#[derive(Clone)]
struct Cursor {
    token: [u8; 32],
    snapshot: Arc<Snapshot>,
    position: usize,
}

#[derive(Default)]
pub(crate) struct Store {
    entries: BackingVec<Cursor>,
}

impl Store {
    pub(super) fn publish(mut self, state: &mut super::super::CompanionState) {
        self.entries.values.retain(|entry| {
            let scope = entry.snapshot.scope;
            entry.snapshot.expires_at > state.mailbox_snapshot_now
                && state.origins.get(&scope.origin).is_some_and(|origin| {
                    !origin.fenced
                        && origin.generation == scope.origin_generation
                        && origin.account_digest == Some(scope.target.account_digest)
                        && origin.device == Some((scope.target.device_id, scope.session_generation))
                })
        });
        self.release_empty();
        state.mailbox_snapshots = self;
    }

    fn lookup(&self, token: [u8; 32], scope: Scope, now: u64) -> Result<Cursor, Fail> {
        self.entries
            .iter()
            .find(|entry| {
                entry.token == token
                    && entry.snapshot.scope == scope
                    && entry.snapshot.expires_at > now
            })
            .cloned()
            .ok_or_else(invalid)
    }

    fn next(&self, snapshot: &Arc<Snapshot>, position: usize) -> Option<[u8; 32]> {
        self.entries
            .iter()
            .find(|entry| Arc::ptr_eq(&entry.snapshot, snapshot) && entry.position == position)
            .map(|entry| entry.token)
    }

    fn prepare_append(&self, exec: &Exec<'_>) -> Result<Self, Fail> {
        let now = exec.monotonic_millis;
        let count = self
            .entries
            .iter()
            .filter(|old| old.snapshot.expires_at > now)
            .count()
            .checked_add(1)
            .ok_or_else(limited)?;
        let capacity = count.checked_mul(size_of::<Cursor>()).ok_or_else(limited)?;
        let usage = exec
            .queries
            .as_ref()
            .ok_or_else(invalid)?
            .reserve_index(charge(capacity)?)
            .map_err(|_| limited())?;
        let mut entries = vector(count, &exec.backing)?;
        entries._query = Some(usage);
        entries.values.extend(
            self.entries
                .iter()
                .filter(|old| old.snapshot.expires_at > now)
                .cloned(),
        );
        Ok(Self { entries })
    }

    pub(crate) fn close_origin(
        &mut self,
        origin: super::super::CompanionOriginKey,
        generation: u64,
    ) {
        self.entries.values.retain(|entry| {
            entry.snapshot.scope.origin != origin
                || entry.snapshot.scope.origin_generation != generation
        });
        self.release_empty();
    }

    pub(crate) fn fence_incarnations(&mut self, home: [u8; 16], live: [u8; 16]) {
        self.entries.values.retain(|entry| {
            let origin = entry.snapshot.scope.origin;
            origin.home_server_id != home || origin.server_incarnation == live
        });
        self.release_empty();
    }

    fn release_empty(&mut self) {
        if self.entries.is_empty() {
            *self = Self::default();
        }
    }

    pub(crate) fn expire(&mut self, now: u64) {
        self.entries
            .values
            .retain(|entry| entry.snapshot.expires_at > now);
        if self.entries.is_empty() {
            *self = Self::default();
        }
    }

    pub(crate) fn next_expiry(&self) -> Option<u64> {
        self.entries
            .iter()
            .map(|entry| entry.snapshot.expires_at)
            .min()
    }
}

fn vector<T>(count: usize, port: &BackingReservationPort) -> Result<BackingVec<T>, Fail> {
    let bytes = count.checked_mul(size_of::<T>()).ok_or_else(limited)?;
    let permit = port.reserve(bytes).map_err(|_| limited())?;
    let mut values = Vec::new();
    values.try_reserve_exact(count).map_err(|_| limited())?;
    if values.capacity() > count {
        return Err(limited());
    }
    Ok(BackingVec {
        values,
        _permit: Some(permit),
        _query: None,
    })
}

fn charge(capacity: usize) -> Result<u64, Fail> {
    MemoryCharge::allocation(u64::try_from(capacity).map_err(|_| limited())?)
        .map(|charge| charge.bytes())
        .map_err(|_| limited())
}

fn visit(
    exec: &Exec<'_>,
    scope: Scope,
    mut accept: impl FnMut(u64, &Item, &[u8]) -> Result<(), Fail>,
) -> Result<(), Fail> {
    let mut admission = super::mailbox_recovery::FetchAdmission::default();
    for (sequence, item) in
        exec.coordinator
            .state
            .mailboxes
            .snapshot_items(scope.target, scope.kind, exec.now)
    {
        if !admission.admitted(exec.coordinator, scope.target, scope.kind, item)? {
            continue;
        }
        let bytes = exec
            .coordinator
            .state
            .objects
            .get(&item.object_id)
            .ok_or_else(invalid)?;
        accept(sequence, item, bytes)?;
    }
    Ok(())
}

struct Measured {
    count: usize,
    size: usize,
    fragments: usize,
}

impl Measured {
    fn backing_bytes(&self) -> Result<u64, Fail> {
        let rows = self
            .count
            .checked_mul(size_of::<Row>())
            .ok_or_else(limited)?;
        let owner = charge(size_of::<Snapshot>() + 2 * size_of::<usize>())?;
        charge(rows)?
            .checked_add(charge(self.size)?)
            .and_then(|bytes| bytes.checked_add(owner))
            .ok_or_else(limited)
    }
}

fn measure(exec: &Exec<'_>, scope: Scope) -> Result<Measured, Fail> {
    let mut count = 0_usize;
    let mut size = 0_usize;
    let mut fragments = 0_usize;
    visit(exec, scope, |_, _, bytes| {
        count = count.checked_add(1).ok_or_else(limited)?;
        size = size.checked_add(bytes.len()).ok_or_else(limited)?;
        let pieces = fragment_count(u32::try_from(bytes.len()).map_err(|_| limited())?)
            .map_err(|_| limited())? as usize;
        fragments = fragments.checked_add(pieces).ok_or_else(limited)?;
        Ok(())
    })?;
    Ok(Measured {
        count,
        size,
        fragments,
    })
}

struct Captured {
    snapshot: Arc<Snapshot>,
    index: Option<Store>,
}

fn capture(exec: &mut Exec<'_>, scope: Scope) -> Result<Option<Captured>, Fail> {
    let measured = measure(exec, scope)?;
    let backing_bytes = measured.backing_bytes()?;
    let Measured {
        count,
        size,
        fragments,
    } = measured;
    if count == 0 {
        return Ok(None);
    }
    let owner_size = size_of::<Snapshot>() + 2 * size_of::<usize>();
    let query = exec
        .queries
        .as_ref()
        .ok_or_else(invalid)?
        .reserve_snapshot(count, backing_bytes)
        .map_err(|_| limited())?;
    let mut rows = vector(count, &exec.backing)?;
    let mut bytes = vector(size, &exec.backing)?;
    let owner_permit = exec.backing.reserve(owner_size).map_err(|_| limited())?;
    let index = if count > MAX_BATCH_OBJECTS
        || size > MAX_BATCH_DECODED_BYTES
        || fragments > MAX_BATCH_FRAGMENTS
    {
        Some(
            exec.coordinator
                .state
                .mailbox_snapshots
                .prepare_append(exec)?,
        )
    } else {
        None
    };
    visit(exec, scope, |sequence, item, object| {
        let begin = bytes.len();
        bytes.values.extend_from_slice(object);
        rows.values.push(Row {
            sequence,
            item: *item,
            begin,
            end: bytes.len(),
        });
        Ok(())
    })?;
    let expires_at = exec
        .monotonic_millis
        .checked_add(LIFETIME_MILLIS)
        .ok_or_else(limited)?;
    Ok(Some(Captured {
        snapshot: Arc::new(Snapshot {
            scope,
            token: exec.random()?,
            expires_at,
            rows,
            bytes,
            _owner_permit: owner_permit,
            _query: query,
        }),
        index,
    }))
}

pub(super) struct Prepared {
    snapshot: Arc<Snapshot>,
    begin: usize,
    end: usize,
    pub next_cursor: Option<[u8; 32]>,
    pub replacement: Option<Store>,
}

impl Prepared {
    pub(super) fn snapshot_token(&self) -> [u8; 32] {
        self.snapshot.token
    }

    pub(super) fn items(&self) -> Result<Vec<(u64, Item)>, Fail> {
        self.snapshot
            .rows
            .get(self.begin..self.end)
            .ok_or_else(invalid)
            .map(|rows| rows.iter().map(|row| (row.sequence, row.item)).collect())
    }

    pub(super) fn object(&self, index: usize) -> Result<&[u8], Fail> {
        let row = self
            .snapshot
            .rows
            .get(self.begin.checked_add(index).ok_or_else(invalid)?)
            .filter(|_| index < self.end - self.begin)
            .ok_or_else(invalid)?;
        self.snapshot
            .bytes
            .get(row.begin..row.end)
            .ok_or_else(invalid)
    }
}

fn page_end(exec: &Exec<'_>, snapshot: &Snapshot, begin: usize) -> Result<usize, Fail> {
    let mut bytes = 0_usize;
    let mut fragments = 0_usize;
    let mut end = begin;
    for row in snapshot
        .rows
        .get(begin..)
        .ok_or_else(invalid)?
        .iter()
        .take(MAX_BATCH_OBJECTS)
    {
        let size = row.end.checked_sub(row.begin).ok_or_else(invalid)?;
        let count = fragment_count(u32::try_from(size).map_err(|_| limited())?)
            .map_err(|_| limited())? as usize;
        let next_bytes = bytes.checked_add(size).ok_or_else(limited)?;
        let next_fragments = fragments.checked_add(count).ok_or_else(limited)?;
        if next_bytes > MAX_BATCH_DECODED_BYTES || next_fragments > MAX_BATCH_FRAGMENTS {
            break;
        }
        if !super::mailbox_recovery::admitted(
            exec.coordinator,
            snapshot.scope.target,
            snapshot.scope.kind,
            &row.item,
        )? {
            return Err(E2eeReplyCode::RouteInvalid.into());
        }
        bytes = next_bytes;
        fragments = next_fragments;
        end += 1;
    }
    if end == begin {
        return Err(limited());
    }
    Ok(end)
}

pub(super) fn prepare(
    exec: &mut Exec<'_>,
    scope: Scope,
    cursor: Option<[u8; 32]>,
) -> Result<Option<Prepared>, Fail> {
    let (snapshot, begin, mut replacement) = match cursor {
        Some(cursor) => {
            let entry = exec.coordinator.state.mailbox_snapshots.lookup(
                cursor,
                scope,
                exec.monotonic_millis,
            )?;
            (entry.snapshot, entry.position, None)
        }
        None => match capture(exec, scope)? {
            Some(captured) => (captured.snapshot, 0, captured.index),
            None => return Ok(None),
        },
    };
    let end = page_end(exec, &snapshot, begin)?;
    let next_cursor = if end == snapshot.rows.len() {
        None
    } else if let Some(cursor) = exec
        .coordinator
        .state
        .mailbox_snapshots
        .next(&snapshot, end)
    {
        Some(cursor)
    } else {
        let mut next = match replacement.take() {
            Some(index) => index,
            None => exec
                .coordinator
                .state
                .mailbox_snapshots
                .prepare_append(exec)?,
        };
        let token = exec.random()?;
        if next.entries.iter().any(|entry| entry.token == token) {
            return Err(limited());
        }
        next.entries.values.push(Cursor {
            token,
            snapshot: Arc::clone(&snapshot),
            position: end,
        });
        replacement = Some(next);
        Some(token)
    };
    Ok(Some(Prepared {
        snapshot,
        begin,
        end,
        next_cursor,
        replacement,
    }))
}

fn invalid() -> Fail {
    E2eeReplyCode::ObjectNotFound.into()
}
fn limited() -> Fail {
    E2eeReplyCode::RateLimited.into()
}

pub(crate) fn reserve_expiry(
    timers: &mut crate::state_core::timers::TimerHeap,
    deadline: u64,
    armed: &mut Option<u64>,
) -> Result<(), E2eeReplyCode> {
    use crate::state_core::timers::{TimedId, TimerKind};
    if armed.is_some_and(|current| current <= deadline) {
        return Ok(());
    }
    timers
        .schedule(
            agenc_ircd_types::MonotonicTick::from_ticks(deadline),
            TimerKind::MailboxSnapshotExpiry,
            TimedId::Global,
        )
        .map_err(|_| E2eeReplyCode::RateLimited)?;
    *armed = Some(deadline);
    Ok(())
}
