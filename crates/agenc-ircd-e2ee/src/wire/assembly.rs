//! Fragment reassembly (companion Section 11.8) with quota reservation
//! before allocation, local-ingress ordering, out-of-order remote and
//! response assembly, deadlines by caller ticks, and the recent-object
//! idempotency cache.
//!
//! Ticks are seconds supplied by the caller; the assembler never reads a
//! clock. Every buffer is allocated only after the declared `total` has been
//! reserved against every applicable quota.

use std::collections::BTreeMap;
use std::fmt;

use crate::error::E2eeError;
use crate::limits::{
    MAX_LIVE_REASSEMBLY_BYTES_PER_CONNECTION, MAX_OPEN_REASSEMBLIES_GLOBAL,
    MAX_OPEN_REASSEMBLIES_PER_ACCOUNT, MAX_OPEN_REASSEMBLIES_PER_FEDERATION_PEER,
    MAX_OPEN_REASSEMBLIES_PER_LOCAL_SENDER, MAX_OPEN_REASSEMBLIES_PER_ROUTE,
    MAX_OPEN_REMOTE_OBJECTS_PER_SENDER, MAX_REASSEMBLY_BYTES_GLOBAL,
    MAX_REASSEMBLY_BYTES_PER_ACCOUNT, MAX_REASSEMBLY_BYTES_PER_FEDERATION_PEER,
    MAX_REASSEMBLY_BYTES_PER_ROUTE, RECENT_OBJECT_IDEMPOTENCY_RETENTION_SECONDS,
};
use crate::object::ObjectId;
use crate::wire::carrier::{CarrierCommand, ObjectLimit};
use crate::wire::fragment::FragmentTag;
use crate::wire::reply::E2eeReplyCode;

/// Where a fragment came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Direction {
    /// A local client submission: fragment zero first, then contiguous.
    LocalIngress,
    /// A federated peer's payload: any order within bounds.
    Remote,
    /// A server response being consumed: any order within bounds.
    Response,
}

/// The authenticated sender of an assembly.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Sender {
    /// A local connection at one attachment session generation.
    Connection {
        /// Connection identity.
        connection: u64,
        /// Attachment session generation, zero when unattached.
        session_generation: u64,
    },
    /// A canonical S2S origin.
    Origin([u8; 16]),
    /// A federation peer link.
    Peer([u8; 16]),
}

/// The response scope of a server-originated object.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ResponseScope {
    /// The 16-byte scope token.
    pub scope: [u8; 16],
    /// The batch identifier.
    pub batch_id: String,
}

/// The exact tuple that keys an in-progress object.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct AssemblyKey {
    /// Direction.
    pub direction: Direction,
    /// Sender.
    pub sender: Sender,
    /// Command and subcommand.
    pub command: CarrierCommand,
    /// Normalized route: conversation identifier or channel-name hash.
    pub route: [u8; 32],
    /// Response scope and batch, for response fragments.
    pub scope: Option<ResponseScope>,
    /// Object identifier.
    pub object_id: ObjectId,
}

/// The quota scopes one assembly is charged against.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QuotaScopes {
    /// Local connection.
    pub connection: Option<u64>,
    /// Authenticated account digest.
    pub account: Option<[u8; 32]>,
    /// Route.
    pub route: Option<[u8; 32]>,
    /// Federation peer.
    pub peer: Option<[u8; 16]>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Counter {
    open: usize,
    bytes: usize,
}

impl Counter {
    fn fits(self, open_limit: usize, byte_limit: usize, total: usize) -> bool {
        self.open < open_limit
            && self
                .bytes
                .checked_add(total)
                .is_some_and(|bytes| bytes <= byte_limit)
    }

    fn charge(&mut self, total: usize) {
        self.open = self.open.saturating_add(1);
        self.bytes = self.bytes.saturating_add(total);
    }

    fn release(&mut self, total: usize) {
        self.open = self.open.saturating_sub(1);
        self.bytes = self.bytes.saturating_sub(total);
    }
}

/// Open-object and byte ceilings per scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotaLimits {
    /// Per connection: open objects (remote per connection) and live bytes.
    pub connection: (usize, usize),
    /// Per account.
    pub account: (usize, usize),
    /// Per route.
    pub route: (usize, usize),
    /// Per federation peer.
    pub peer: (usize, usize),
    /// Process-global.
    pub global: (usize, usize),
}

impl Default for QuotaLimits {
    fn default() -> Self {
        Self {
            connection: (
                MAX_OPEN_REMOTE_OBJECTS_PER_SENDER,
                MAX_LIVE_REASSEMBLY_BYTES_PER_CONNECTION,
            ),
            account: (
                MAX_OPEN_REASSEMBLIES_PER_ACCOUNT,
                MAX_REASSEMBLY_BYTES_PER_ACCOUNT,
            ),
            route: (
                MAX_OPEN_REASSEMBLIES_PER_ROUTE,
                MAX_REASSEMBLY_BYTES_PER_ROUTE,
            ),
            peer: (
                MAX_OPEN_REASSEMBLIES_PER_FEDERATION_PEER,
                MAX_REASSEMBLY_BYTES_PER_FEDERATION_PEER,
            ),
            global: (MAX_OPEN_REASSEMBLIES_GLOBAL, MAX_REASSEMBLY_BYTES_GLOBAL),
        }
    }
}

/// Reservation ledger over every scope.
#[derive(Clone, Debug, Default)]
pub struct QuotaLedger {
    limits: QuotaLimits,
    connections: BTreeMap<u64, Counter>,
    accounts: BTreeMap<[u8; 32], Counter>,
    routes: BTreeMap<[u8; 32], Counter>,
    peers: BTreeMap<[u8; 16], Counter>,
    global: Counter,
}

impl QuotaLedger {
    /// A ledger with the given limits.
    #[must_use]
    pub fn new(limits: QuotaLimits) -> Self {
        Self {
            limits,
            ..Self::default()
        }
    }

    /// Whether `total` bytes and one object fit every applicable scope.
    fn fits(&self, scopes: &QuotaScopes, total: usize) -> bool {
        let limits = self.limits;
        let check = |counter: Option<&Counter>, limit: (usize, usize)| {
            counter
                .copied()
                .unwrap_or_default()
                .fits(limit.0, limit.1, total)
        };
        self.global.fits(limits.global.0, limits.global.1, total)
            && scopes
                .connection
                .is_none_or(|id| check(self.connections.get(&id), limits.connection))
            && scopes
                .account
                .is_none_or(|id| check(self.accounts.get(&id), limits.account))
            && scopes
                .route
                .is_none_or(|id| check(self.routes.get(&id), limits.route))
            && scopes
                .peer
                .is_none_or(|id| check(self.peers.get(&id), limits.peer))
    }

    /// Atomically reserves `total` bytes and one object.
    pub fn reserve(&mut self, scopes: &QuotaScopes, total: usize) -> Result<(), E2eeError> {
        if !self.fits(scopes, total) {
            return Err(E2eeError::LimitExceeded);
        }
        self.global.charge(total);
        if let Some(id) = scopes.connection {
            self.connections.entry(id).or_default().charge(total);
        }
        if let Some(id) = scopes.account {
            self.accounts.entry(id).or_default().charge(total);
        }
        if let Some(id) = scopes.route {
            self.routes.entry(id).or_default().charge(total);
        }
        if let Some(id) = scopes.peer {
            self.peers.entry(id).or_default().charge(total);
        }
        Ok(())
    }

    /// Releases a reservation.
    pub fn release(&mut self, scopes: &QuotaScopes, total: usize) {
        self.global.release(total);
        release_scope(&mut self.connections, scopes.connection, total);
        release_scope(&mut self.accounts, scopes.account, total);
        release_scope(&mut self.routes, scopes.route, total);
        release_scope(&mut self.peers, scopes.peer, total);
    }

    /// Reserved bytes across every open assembly.
    #[must_use]
    pub const fn reserved_bytes(&self) -> usize {
        self.global.bytes
    }

    /// Open assemblies across every scope.
    #[must_use]
    pub const fn open_objects(&self) -> usize {
        self.global.open
    }
}

fn release_scope<K: Ord>(map: &mut BTreeMap<K, Counter>, key: Option<K>, total: usize) {
    let Some(key) = key else { return };
    let Some(counter) = map.get_mut(&key) else {
        return;
    };
    counter.release(total);
    if counter.open == 0 && counter.bytes == 0 {
        map.remove(&key);
    }
}

/// Why a fragment was refused; each maps to one reply code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssemblyError {
    /// Grammar, ordering, or consistency with the pinned tuple failed; the
    /// assembly, if any, was discarded.
    InvalidFragment,
    /// The declared total or count exceeds the carrier limit.
    ObjectTooLarge,
    /// A quota, open-object ceiling, or deadline was reached.
    ReassemblyLimit,
    /// The complete bytes did not hash to the object identifier.
    HashMismatch,
}

impl AssemblyError {
    /// The reply code for this refusal.
    #[must_use]
    pub const fn reply_code(self) -> E2eeReplyCode {
        match self {
            Self::InvalidFragment => E2eeReplyCode::InvalidFragment,
            Self::ObjectTooLarge => E2eeReplyCode::ObjectTooLarge,
            Self::ReassemblyLimit => E2eeReplyCode::ReassemblyLimit,
            Self::HashMismatch => E2eeReplyCode::HashMismatch,
        }
    }
}

impl fmt::Display for AssemblyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reply_code().description())
    }
}

impl std::error::Error for AssemblyError {}

/// The outcome of accepting one fragment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Ingest {
    /// More fragments are needed.
    Incomplete,
    /// The complete object bytes, verified against the object identifier.
    Complete(Vec<u8>),
    /// An identical duplicate of an already held fragment; ignored.
    Duplicate,
    /// The object completed recently; the prior outcome applies.
    Recent,
}

#[derive(Clone, Debug)]
struct Assembly {
    scopes: QuotaScopes,
    count: u32,
    total: usize,
    received: Vec<bool>,
    received_count: u32,
    buffer: Vec<u8>,
    started: u64,
    last: u64,
    absolute_seconds: u64,
    idle_seconds: u64,
}

impl Assembly {
    fn expired(&self, now: u64) -> bool {
        now.saturating_sub(self.started) >= self.absolute_seconds
            || now.saturating_sub(self.last) >= self.idle_seconds
    }

    fn next_local_part(&self) -> u32 {
        self.received_count
    }
}

/// The reassembler.
#[derive(Debug, Default)]
pub struct E2eeAssembler {
    open: BTreeMap<AssemblyKey, Assembly>,
    quotas: QuotaLedger,
    recent: BTreeMap<ObjectId, u64>,
}

impl E2eeAssembler {
    /// An assembler with the given quota limits.
    #[must_use]
    pub fn new(limits: QuotaLimits) -> Self {
        Self {
            quotas: QuotaLedger::new(limits),
            ..Self::default()
        }
    }

    /// The quota ledger.
    #[must_use]
    pub const fn quotas(&self) -> &QuotaLedger {
        &self.quotas
    }

    /// Open assemblies.
    #[must_use]
    pub fn open_count(&self) -> usize {
        self.open.len()
    }

    /// Accepts one fragment for the assembly `key` under `limit`, charging
    /// `scopes` on the first fragment.
    pub fn ingest(
        &mut self,
        key: AssemblyKey,
        scopes: QuotaScopes,
        limit: ObjectLimit,
        tag: &FragmentTag,
        now: u64,
    ) -> Result<Ingest, AssemblyError> {
        if tag.object_id != key.object_id {
            return Err(AssemblyError::InvalidFragment);
        }
        if !self.open.contains_key(&key) {
            if self.recent.contains_key(&tag.object_id) {
                return Ok(Ingest::Recent);
            }
            self.open_assembly(&key, scopes, limit, tag, now)?;
        }
        match self.place(&key, tag, now) {
            Ok(Ingest::Incomplete) if self.is_complete(&key) => self.finish(&key),
            Ok(outcome) => Ok(outcome),
            Err(error) => {
                self.discard(&key);
                Err(error)
            }
        }
    }

    fn open_assembly(
        &mut self,
        key: &AssemblyKey,
        scopes: QuotaScopes,
        limit: ObjectLimit,
        tag: &FragmentTag,
        now: u64,
    ) -> Result<(), AssemblyError> {
        let total = usize::try_from(tag.total).map_err(|_| AssemblyError::ObjectTooLarge)?;
        if total > limit.max_bytes || tag.count > limit.max_fragments {
            return Err(AssemblyError::ObjectTooLarge);
        }
        if key.direction == Direction::LocalIngress && tag.part != 0 {
            return Err(AssemblyError::InvalidFragment);
        }
        if self.open_for_sender(key) >= sender_ceiling(key.direction) {
            return Err(AssemblyError::ReassemblyLimit);
        }
        self.quotas
            .reserve(&scopes, total)
            .map_err(|_| AssemblyError::ReassemblyLimit)?;
        let count = usize::try_from(tag.count).map_err(|_| AssemblyError::ObjectTooLarge)?;
        let (absolute_seconds, idle_seconds) = limit.deadline.seconds();
        self.open.insert(
            key.clone(),
            Assembly {
                scopes,
                count: tag.count,
                total,
                received: vec![false; count],
                received_count: 0,
                buffer: vec![0; total],
                started: now,
                last: now,
                absolute_seconds,
                idle_seconds,
            },
        );
        Ok(())
    }

    fn open_for_sender(&self, key: &AssemblyKey) -> usize {
        self.open
            .keys()
            .filter(|open| open.direction == key.direction && open.sender == key.sender)
            .count()
    }

    fn place(
        &mut self,
        key: &AssemblyKey,
        tag: &FragmentTag,
        now: u64,
    ) -> Result<Ingest, AssemblyError> {
        let assembly = self
            .open
            .get_mut(key)
            .ok_or(AssemblyError::InvalidFragment)?;
        if assembly.expired(now) {
            return Err(AssemblyError::ReassemblyLimit);
        }
        let total = u32::try_from(assembly.total).map_err(|_| AssemblyError::InvalidFragment)?;
        if tag.count != assembly.count || tag.total != total {
            return Err(AssemblyError::InvalidFragment);
        }
        let part = usize::try_from(tag.part).map_err(|_| AssemblyError::InvalidFragment)?;
        let offset = tag.offset().map_err(|_| AssemblyError::InvalidFragment)?;
        let end = offset
            .checked_add(tag.segment.len())
            .filter(|end| *end <= assembly.total)
            .ok_or(AssemblyError::InvalidFragment)?;
        if assembly.received.get(part).copied().unwrap_or(false) {
            return if assembly.buffer.get(offset..end) == Some(tag.segment.as_slice()) {
                Ok(Ingest::Duplicate)
            } else {
                Err(AssemblyError::InvalidFragment)
            };
        }
        if key.direction == Direction::LocalIngress && tag.part != assembly.next_local_part() {
            return Err(AssemblyError::InvalidFragment);
        }
        let slot = assembly
            .buffer
            .get_mut(offset..end)
            .ok_or(AssemblyError::InvalidFragment)?;
        slot.copy_from_slice(&tag.segment);
        if let Some(flag) = assembly.received.get_mut(part) {
            *flag = true;
        }
        assembly.received_count = assembly.received_count.saturating_add(1);
        assembly.last = now;
        Ok(Ingest::Incomplete)
    }

    fn is_complete(&self, key: &AssemblyKey) -> bool {
        self.open
            .get(key)
            .is_some_and(|assembly| assembly.received_count == assembly.count)
    }

    fn finish(&mut self, key: &AssemblyKey) -> Result<Ingest, AssemblyError> {
        let Some(assembly) = self.open.remove(key) else {
            return Err(AssemblyError::InvalidFragment);
        };
        self.quotas.release(&assembly.scopes, assembly.total);
        if ObjectId::compute(&assembly.buffer) != key.object_id {
            return Err(AssemblyError::HashMismatch);
        }
        let retained_until = assembly
            .last
            .saturating_add(RECENT_OBJECT_IDEMPOTENCY_RETENTION_SECONDS);
        self.recent.insert(key.object_id, retained_until);
        Ok(Ingest::Complete(assembly.buffer))
    }

    /// Discards one assembly and releases its reservation.
    pub fn discard(&mut self, key: &AssemblyKey) {
        if let Some(assembly) = self.open.remove(key) {
            self.quotas.release(&assembly.scopes, assembly.total);
        }
    }

    /// Discards every assembly of `sender` (detach, logout, disconnect).
    pub fn discard_sender(&mut self, sender: &Sender) -> usize {
        let keys: Vec<AssemblyKey> = self
            .open
            .keys()
            .filter(|key| key.sender == *sender)
            .cloned()
            .collect();
        for key in &keys {
            self.discard(key);
        }
        keys.len()
    }

    /// Discards every assembly past its idle or absolute deadline and
    /// forgets expired recent objects; returns the discarded keys.
    pub fn expire(&mut self, now: u64) -> Vec<AssemblyKey> {
        let expired: Vec<AssemblyKey> = self
            .open
            .iter()
            .filter(|(_, assembly)| assembly.expired(now))
            .map(|(key, _)| key.clone())
            .collect();
        for key in &expired {
            self.discard(key);
        }
        self.recent.retain(|_, until| *until > now);
        expired
    }

    /// Whether `object_id` completed within the idempotency window.
    #[must_use]
    pub fn is_recent(&self, object_id: &ObjectId) -> bool {
        self.recent.contains_key(object_id)
    }
}

const fn sender_ceiling(direction: Direction) -> usize {
    match direction {
        Direction::LocalIngress => MAX_OPEN_REASSEMBLIES_PER_LOCAL_SENDER,
        Direction::Remote | Direction::Response => MAX_OPEN_REMOTE_OBJECTS_PER_SENDER,
    }
}

#[cfg(test)]
#[path = "../tests/assembly.rs"]
mod tests;
