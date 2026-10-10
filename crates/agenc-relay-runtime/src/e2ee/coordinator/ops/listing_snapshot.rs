//! Charged immutable listing cuts and one-use, requester-bound continuations.
//!
//! `EKEY FETCH ROOT-CHAIN`, `BINDING-LOCKS` and `CAPABILITIES` and `EGROUP
//! FETCH AUTHORIZATIONS`, `ACKS` and `RECEIPTS` each page one immutable cut of
//! their listing (companion 11.6, 11.7). A page holds complete objects only,
//! packed against `MAX_BATCH_OBJECTS`, `MAX_BATCH_DECODED_BYTES` and the sum
//! of each object's own fragment count against `MAX_BATCH_FRAGMENTS`
//! together; a root-chain page is one `root_identity_chain` object of at most
//! `MAX_ROOT_CHAIN_OBJECT` holding complete roots. A listing that fits one
//! page is answered from the committed state and keeps nothing. A longer one
//! captures its cut, the identifier and size of every retained object it
//! lists, charged to the requester's query snapshot budget and the process
//! memory budget before any entropy is drawn, and expiring
//! `DIRECTORY_CURSOR_TIMEOUT` after its capture (companion 16).
//!
//! A cut owns exactly one live cursor: 32 random bytes bound to the
//! requesting session, origin generation and account, the current
//! attachment of a device-bound listing, the request kind, its selector and
//! its first position. The receipt of a page consumes the cursor it named and
//! installs the next one; the last page releases the cut. An unknown, forged,
//! consumed, expired or differently bound cursor is refused with
//! `E2EE_OBJECT_NOT_FOUND`, and never restarts the listing. Cuts are
//! process-local: a restart discards them, and so do a closed origin, a
//! fenced incarnation and a closed link.

#![forbid(unsafe_code)]

use agenc_relay_domain::e2ee::projection::EmptyKind;
use agenc_relay_e2ee::limits::{
    DIRECTORY_CURSOR_TIMEOUT_SECONDS, MAX_BATCH_DECODED_BYTES, MAX_BATCH_FRAGMENTS,
    MAX_BATCH_OBJECTS, MAX_FRAGMENT_RAW, MAX_ROOT_CHAIN_OBJECT, WIRE_OBJECT_ENVELOPE_BYTES,
};
use agenc_relay_e2ee::objects::ACCOUNT_ID_BYTES;
use agenc_relay_e2ee::wire::fragment::fragment_count;
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;
use agenc_relay_types::UserId;

use super::super::request::{Outcome, ResponseObject, ResultBody};
use super::super::{CompanionOriginKey, CompanionState};
use super::cut_backing::{BackingVec, charge, vector};
use super::{Exec, Fail};
use crate::budget::MemoryPermit;
use crate::state_core::query_usage::{QueryReservationPort, QueryUsageLease};
use crate::sync::Arc;

/// A cut and its cursor expire `DIRECTORY_CURSOR_TIMEOUT` after the cut was
/// captured.
const LIFETIME_MILLIS: u64 = DIRECTORY_CURSOR_TIMEOUT_SECONDS * 1_000;

/// The bytes of a `root_identity_chain` object besides its roots: the wire
/// envelope, the Account ID with its one-byte length, and the three-byte
/// length of `roots<1..1048576>`.
const CHAIN_OVERHEAD: usize = WIRE_OBJECT_ENVELOPE_BYTES + 1 + ACCOUNT_ID_BYTES + 3;

// agenc-review: internal-assert owner=runtime reviewed=2026-10-09 reason=a root-chain page is one object of at most MAX_ROOT_CHAIN_OBJECT, which these compile-time bounds keep within one batch's bytes and fragments
const _: () = assert!(
    MAX_ROOT_CHAIN_OBJECT <= MAX_BATCH_DECODED_BYTES
        && MAX_ROOT_CHAIN_OBJECT.div_ceil(MAX_FRAGMENT_RAW) <= MAX_BATCH_FRAGMENTS
);

/// The listing a cut is of: the request kind, its selector and, for a
/// contiguous run, its first position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Listing {
    /// `fetch_root_chain`: the named account's roots from `first`.
    RootChain {
        /// The named account's digest.
        account: [u8; 32],
        /// The first root generation.
        first: u64,
    },
    /// `fetch_binding_locks`: one root's locks from `first`.
    BindingLocks {
        /// The named account's digest.
        account: [u8; 32],
        /// The named root's fingerprint.
        root: [u8; 32],
        /// The first lock sequence.
        first: u64,
    },
    /// `fetch_capabilities`: the named account's current capability set.
    Capabilities {
        /// The named account's digest.
        account: [u8; 32],
    },
    /// `fetch_authorizations`: one candidate's retained approvals.
    Authorizations {
        /// The conversation.
        conversation: [u8; 32],
        /// The candidate.
        candidate: [u8; 32],
    },
    /// `fetch_acks`: one candidate's or ReInit attempt's acknowledgements.
    Acks {
        /// The conversation.
        conversation: [u8; 32],
        /// The candidate or ReInit attempt.
        selector: [u8; 32],
    },
    /// `fetch_receipts`: the sequencer records from `first`.
    Receipts {
        /// The conversation.
        conversation: [u8; 32],
        /// The first route sequence.
        first: u64,
    },
}

impl Listing {
    /// Whether the listing is a contiguous run from a requested first
    /// position, which a cut may end early because the next request can
    /// continue it from there, rather than a set a page must hold complete.
    const fn anchored(self) -> bool {
        matches!(
            self,
            Self::RootChain { .. } | Self::BindingLocks { .. } | Self::Receipts { .. }
        )
    }

    /// Whether a page is one root chain object holding the page's roots.
    const fn chain(self) -> bool {
        matches!(self, Self::RootChain { .. })
    }
}

/// Who may continue a cut, and what it is a cut of.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Scope {
    /// The requesting base session.
    user: Option<UserId>,
    /// The requesting companion origin.
    origin: CompanionOriginKey,
    /// The origin generation the request ran under.
    origin_generation: u64,
    /// The requester's authenticated account.
    account_digest: [u8; 32],
    /// The requester's current attachment, for a device-bound listing.
    attachment: Option<([u8; 16], u64)>,
    /// The listing.
    listing: Listing,
}

/// One object of a cut: its identifier and complete encoded size.
#[derive(Clone, Copy)]
struct Entry {
    object_id: [u8; 32],
    size: usize,
}

struct Snapshot {
    scope: Scope,
    token: [u8; 32],
    expires_at: u64,
    entries: BackingVec<Entry>,
    // The entries are destroyed before these reservations return.
    _owner_permit: MemoryPermit,
    _query: QueryUsageLease,
}

/// The one live cursor of a cut and the position its page begins at.
#[derive(Clone)]
struct Slot {
    token: [u8; 32],
    snapshot: Arc<Snapshot>,
    position: usize,
}

/// The live cursors, one for each retained cut.
#[derive(Default)]
pub(crate) struct Store {
    slots: BackingVec<Slot>,
}

impl Store {
    /// Installs this replacement at its batch's receipt, keeping only the
    /// cuts that are unexpired at the receipt time and whose origin is
    /// declared on a live link, unfenced, at the generation, account and,
    /// for a device-bound cut, the current attachment it was bound to.
    pub(super) fn publish(mut self, state: &mut CompanionState) {
        self.slots.values.retain(|slot| {
            let scope = &slot.snapshot.scope;
            slot.snapshot.expires_at > state.mailbox_snapshot_now
                && state.origins.get(&scope.origin).is_some_and(|origin| {
                    !origin.fenced
                        && !origin.suspended
                        && origin.generation == scope.origin_generation
                        && origin.account_digest == Some(scope.account_digest)
                        && scope.attachment.is_none_or(|attachment| {
                            state.current_attachment(origin) == Some(attachment)
                        })
                })
        });
        self.release_empty();
        state.listing_snapshots = self;
    }

    /// The live cursor `token` of a cut bound to exactly `scope` that is
    /// unexpired at `now`.
    fn lookup(&self, token: [u8; 32], scope: &Scope, now: u64) -> Result<Slot, Fail> {
        self.slots
            .iter()
            .find(|slot| {
                slot.token == token
                    && slot.snapshot.scope == *scope
                    && slot.snapshot.expires_at > now
            })
            .cloned()
            .ok_or_else(invalid)
    }

    /// A replacement holding every cursor unexpired at the request's time
    /// except `consumed`, with room for `added` more; its index is charged
    /// to the requester's query usage, `queries`, and the process memory
    /// budget before it is allocated.
    fn prepare_replace(
        &self,
        queries: &QueryReservationPort<'_>,
        exec: &Exec<'_>,
        consumed: Option<[u8; 32]>,
        added: usize,
    ) -> Result<Self, Fail> {
        let now = exec.monotonic_millis;
        let kept = |slot: &&Slot| slot.snapshot.expires_at > now && Some(slot.token) != consumed;
        let count = self
            .slots
            .iter()
            .filter(kept)
            .count()
            .checked_add(added)
            .ok_or_else(limited)?;
        if count == 0 {
            return Ok(Self::default());
        }
        let capacity = count.checked_mul(size_of::<Slot>()).ok_or_else(limited)?;
        let usage = queries
            .reserve_index(charge(capacity)?)
            .map_err(|_| limited())?;
        let mut slots = vector(count, &exec.backing)?;
        slots._query = Some(usage);
        slots.values.extend(self.slots.iter().filter(kept).cloned());
        Ok(Self { slots })
    }

    /// Releases every cut of `origin`, whatever generation it was bound
    /// to: the origin's connection ended or its declaration was refused, so
    /// none of them can continue.
    pub(crate) fn close_origin(&mut self, origin: CompanionOriginKey) {
        self.slots
            .values
            .retain(|slot| slot.snapshot.scope.origin != origin);
        self.release_empty();
    }

    /// Releases the cuts of every incarnation of `home` but `live`.
    pub(crate) fn fence_incarnations(&mut self, home: [u8; 16], live: [u8; 16]) {
        self.slots.values.retain(|slot| {
            let origin = slot.snapshot.scope.origin;
            origin.home_server_id != home || origin.server_incarnation == live
        });
        self.release_empty();
    }

    /// Releases the cuts of every origin of `home`: its link closed.
    pub(crate) fn close_home(&mut self, home: [u8; 16]) {
        self.slots
            .values
            .retain(|slot| slot.snapshot.scope.origin.home_server_id != home);
        self.release_empty();
    }

    fn release_empty(&mut self) {
        if self.slots.is_empty() {
            *self = Self::default();
        }
    }

    /// Releases the cuts expired at `now`.
    pub(crate) fn expire(&mut self, now: u64) {
        self.slots
            .values
            .retain(|slot| slot.snapshot.expires_at > now);
        self.release_empty();
    }

    /// The earliest expiry of a retained cut.
    pub(crate) fn next_expiry(&self) -> Option<u64> {
        self.slots.iter().map(|slot| slot.snapshot.expires_at).min()
    }

    /// The number of live cursors, one for each retained cut.
    #[cfg(test)]
    pub(crate) fn cursors(&self) -> usize {
        self.slots.len()
    }
}

/// One page being packed: complete objects join it while every limit holds.
struct Packer {
    chain: bool,
    count: usize,
    bytes: usize,
    fragments: usize,
}

impl Packer {
    const fn new(chain: bool) -> Self {
        Self {
            chain,
            count: 0,
            bytes: if chain { CHAIN_OVERHEAD } else { 0 },
            fragments: 0,
        }
    }

    /// Admits the next complete object of `size` encoded bytes, or refuses
    /// it when it would take the page over a limit: for a batch page the
    /// object count, the summed bytes or the summed per-object fragment
    /// counts; for a root-chain page the chain object's size, to which a
    /// root adds its object's body.
    fn admit(&mut self, size: usize) -> Result<bool, Fail> {
        if self.chain {
            let root = size
                .checked_sub(WIRE_OBJECT_ENVELOPE_BYTES)
                .ok_or_else(invalid)?;
            let bytes = self.bytes.checked_add(root).ok_or_else(limited)?;
            if bytes > MAX_ROOT_CHAIN_OBJECT {
                return Ok(false);
            }
            self.bytes = bytes;
            self.count = self.count.checked_add(1).ok_or_else(limited)?;
            return Ok(true);
        }
        let pieces =
            fragment_count(u32::try_from(size).map_err(|_| limited())?).map_err(|_| invalid())?;
        let count = self.count.checked_add(1).ok_or_else(limited)?;
        let bytes = self.bytes.checked_add(size).ok_or_else(limited)?;
        let fragments = usize::try_from(pieces)
            .ok()
            .and_then(|pieces| self.fragments.checked_add(pieces))
            .ok_or_else(limited)?;
        if count > MAX_BATCH_OBJECTS
            || bytes > MAX_BATCH_DECODED_BYTES
            || fragments > MAX_BATCH_FRAGMENTS
        {
            return Ok(false);
        }
        self.count = count;
        self.bytes = bytes;
        self.fragments = fragments;
        Ok(true)
    }
}

/// The end of the page of `entries` that begins at `begin`.
fn page_end(entries: &[Entry], begin: usize, chain: bool) -> Result<usize, Fail> {
    let mut packer = Packer::new(chain);
    let mut end = begin;
    // Each entry is paired with the position after it.
    let rest = entries.get(begin..).ok_or_else(invalid)?;
    for (entry, after) in rest.iter().zip(begin.saturating_add(1)..) {
        if !packer.admit(entry.size)? {
            break;
        }
        end = after;
    }
    if end == begin {
        return Err(limited());
    }
    Ok(end)
}

/// The objects the committed `state` lists for `listing`, in page order: a
/// contiguous run from its first position, or its complete set.
fn listed<'a>(
    state: &'a CompanionState,
    listing: &Listing,
) -> Box<dyn Iterator<Item = [u8; 32]> + 'a> {
    match *listing {
        Listing::RootChain { account, first } => {
            let chain = state
                .directory
                .account(&account)
                .and_then(|entry| entry.root.as_ref())
                .map_or(&[][..], |root| root.chain.as_slice());
            let start = usize::try_from(first).unwrap_or(usize::MAX);
            Box::new(chain.iter().skip(start).copied())
        }
        Listing::BindingLocks {
            account,
            root,
            first,
        } => Box::new(run(
            state
                .binding_locks
                .get(&(account, root))
                .into_iter()
                .flat_map(move |locks| locks.range(first..))
                .map(|(sequence, entry)| (*sequence, entry.object_id)),
            first,
        )),
        Listing::Capabilities { account } => Box::new(
            state
                .directory
                .capability_page(&account)
                .into_iter()
                .map(|(_, object_id)| object_id),
        ),
        Listing::Authorizations {
            conversation,
            candidate,
        } => Box::new(
            state
                .conversations
                .get(&conversation)
                .and_then(|known| known.approvals.get(&candidate))
                .into_iter()
                .flat_map(|approvals| approvals.values().copied()),
        ),
        Listing::Acks {
            conversation,
            selector,
        } => Box::new(
            state
                .conversations
                .get(&conversation)
                .and_then(|known| known.acks.get(&selector))
                .into_iter()
                .flat_map(|acks| acks.values().copied()),
        ),
        Listing::Receipts {
            conversation,
            first,
        } => Box::new(run(
            state
                .conversations
                .get(&conversation)
                .into_iter()
                .flat_map(move |known| known.records.range(first..))
                .map(|(sequence, object_id)| (*sequence, *object_id)),
            first,
        )),
    }
}

/// The objects of `sequences` that continue `first` without a gap.
fn run<'a>(
    sequences: impl Iterator<Item = (u64, [u8; 32])> + 'a,
    first: u64,
) -> impl Iterator<Item = [u8; 32]> + 'a {
    let mut expected = Some(first);
    sequences.map_while(move |(sequence, object_id)| {
        (expected == Some(sequence)).then(|| {
            expected = sequence.checked_add(1);
            object_id
        })
    })
}

/// The complete encoded size of a retained object the listing names.
fn object_size(state: &CompanionState, object_id: &[u8; 32]) -> Result<usize, Fail> {
    state
        .objects
        .get(object_id)
        .map(Vec::len)
        .ok_or_else(invalid)
}

/// The scope a listing request binds: the requesting session, origin
/// generation and account, and for a device-bound listing its current
/// attachment.
pub(super) fn scope(
    exec: &Exec<'_>,
    listing: Listing,
    attachment: Option<([u8; 16], u64)>,
) -> Result<Scope, Fail> {
    Ok(Scope {
        user: exec.queries.as_ref().map(QueryReservationPort::user),
        origin: CompanionOriginKey {
            home_server_id: exec.origin.home_server_id,
            server_incarnation: exec.origin.server_incarnation,
            origin_id: exec.origin.origin_id,
        },
        origin_generation: exec.origin.generation,
        account_digest: exec.account_digest()?,
        attachment,
        listing,
    })
}

/// One prepared page.
pub(super) struct Prepared {
    snapshot_token: [u8; 32],
    next_cursor: Option<[u8; 32]>,
    /// The page's objects, in order.
    pub(super) page: Vec<[u8; 32]>,
    replacement: Option<Store>,
}

impl Prepared {
    /// The bytes of the page's objects.
    pub(super) fn objects(&self, exec: &Exec<'_>) -> Result<Vec<Vec<u8>>, Fail> {
        self.page
            .iter()
            .map(|object_id| {
                exec.coordinator
                    .state
                    .objects
                    .get(object_id)
                    .cloned()
                    .ok_or_else(invalid)
            })
            .collect()
    }

    /// The `object_page` result of this page with `responses`; its receipt
    /// publishes the cursor change.
    pub(super) fn outcome(self, responses: Vec<Vec<u8>>) -> Outcome {
        let mut outcome = Outcome::scalar(ResultBody::ObjectPage);
        outcome.snapshot_token = Some(self.snapshot_token);
        outcome.next_cursor = self.next_cursor;
        outcome.listing_expiry = self.replacement.as_ref().and_then(Store::next_expiry);
        outcome.responses = responses
            .into_iter()
            .map(|bytes| ResponseObject {
                bytes,
                delivery_token: None,
                target_device_id: None,
            })
            .collect();
        if let Some(replacement) = self.replacement {
            outcome
                .effects
                .push(Box::new(move |companion| replacement.publish(companion)));
        }
        outcome
    }
}

/// The page `cursor` names, or for `*` the first page of the listing;
/// `None` answers an empty listing.
pub(super) fn prepare(
    exec: &mut Exec<'_>,
    scope: Scope,
    cursor: Option<[u8; 32]>,
) -> Result<Option<Prepared>, Fail> {
    match cursor {
        Some(token) => continue_cut(exec, scope, token).map(Some),
        None => first_page(exec, scope),
    }
}

/// The page `cursor` names of a listing whose page holds its listed objects
/// themselves, or `empty` for an empty listing.
pub(super) fn objects_page(
    exec: &mut Exec<'_>,
    scope: Scope,
    cursor: Option<[u8; 32]>,
    empty: EmptyKind,
) -> Result<Outcome, Fail> {
    let Some(prepared) = prepare(exec, scope, cursor)? else {
        return Ok(Outcome::scalar(ResultBody::Empty(empty)));
    };
    let objects = prepared.objects(exec)?;
    Ok(prepared.outcome(objects))
}

/// The first page: from the committed state when the listing fits one
/// page, otherwise from a newly captured cut.
fn first_page(exec: &mut Exec<'_>, scope: Scope) -> Result<Option<Prepared>, Fail> {
    let coordinator = exec.coordinator;
    let state = &coordinator.state;
    let mut packer = Packer::new(scope.listing.chain());
    let mut page = Vec::new();
    for object_id in listed(state, &scope.listing) {
        if !packer.admit(object_size(state, &object_id)?)? {
            return capture(exec, scope).map(Some);
        }
        page.push(object_id);
    }
    if page.is_empty() {
        return Ok(None);
    }
    Ok(Some(Prepared {
        snapshot_token: exec.random()?,
        next_cursor: None,
        page,
        replacement: None,
    }))
}

/// Captures the cut of a listing longer than one page, at most the query
/// snapshot row ceiling of one cut; a set listing longer than that is
/// refused. Every reservation precedes the entropy.
fn capture(exec: &mut Exec<'_>, scope: Scope) -> Result<Prepared, Fail> {
    let coordinator = exec.coordinator;
    let state = &coordinator.state;
    let store = &state.listing_snapshots;
    let queries = exec.queries.as_ref().ok_or_else(invalid)?;
    let ceiling = queries.snapshot_rows();
    let listed_count = listed(state, &scope.listing)
        .take(ceiling.saturating_add(1))
        .count();
    if listed_count > ceiling && !scope.listing.anchored() {
        return Err(limited());
    }
    let count = listed_count.min(ceiling);
    let owner_size = size_of::<Snapshot>() + 2 * size_of::<usize>();
    let backing_bytes = charge(count.checked_mul(size_of::<Entry>()).ok_or_else(limited)?)?
        .checked_add(charge(owner_size)?)
        .ok_or_else(limited)?;
    let query = queries
        .reserve_snapshot(count, backing_bytes)
        .map_err(|_| limited())?;
    let mut entries = vector(count, &exec.backing)?;
    let owner_permit = exec.backing.reserve(owner_size).map_err(|_| limited())?;
    for object_id in listed(state, &scope.listing).take(count) {
        let size = object_size(state, &object_id)?;
        entries.values.push(Entry { object_id, size });
    }
    let end = page_end(&entries, 0, scope.listing.chain())?;
    let page = entries
        .iter()
        .take(end)
        .map(|entry| entry.object_id)
        .collect();
    let last = end == entries.len();
    let replacement = if last {
        None
    } else {
        Some(store.prepare_replace(queries, exec, None, 1)?)
    };
    let expires_at = exec
        .monotonic_millis
        .checked_add(LIFETIME_MILLIS)
        .ok_or_else(limited)?;
    let snapshot = Arc::new(Snapshot {
        scope,
        token: exec.random()?,
        expires_at,
        entries,
        _owner_permit: owner_permit,
        _query: query,
    });
    let mut prepared = Prepared {
        snapshot_token: snapshot.token,
        next_cursor: None,
        page,
        replacement: None,
    };
    if let Some(mut replacement) = replacement {
        let token = exec.random()?;
        install(&mut replacement, token, &snapshot, end)?;
        prepared.next_cursor = Some(token);
        prepared.replacement = Some(replacement);
    }
    Ok(prepared)
}

/// A continuation: the next page of the cut `token` names, which consumes
/// that cursor and installs the next one unless this page is the last.
fn continue_cut(exec: &mut Exec<'_>, scope: Scope, token: [u8; 32]) -> Result<Prepared, Fail> {
    let coordinator = exec.coordinator;
    let store = &coordinator.state.listing_snapshots;
    // Only a request of a base session holds a cut.
    let queries = exec.queries.as_ref().ok_or_else(invalid)?;
    let slot = store.lookup(token, &scope, exec.monotonic_millis)?;
    let snapshot = slot.snapshot;
    let end = page_end(&snapshot.entries, slot.position, scope.listing.chain())?;
    // An object of the cut that is no longer retained as it was captured
    // cannot be served: the cut is refused rather than spliced.
    let mut page = Vec::new();
    for entry in snapshot.entries.iter().take(end).skip(slot.position) {
        if object_size(&coordinator.state, &entry.object_id)? != entry.size {
            return Err(invalid());
        }
        page.push(entry.object_id);
    }
    let last = end == snapshot.entries.len();
    let mut replacement = store.prepare_replace(queries, exec, Some(token), usize::from(!last))?;
    let next_cursor = if last {
        None
    } else {
        let next = exec.random()?;
        if next == token {
            return Err(limited());
        }
        install(&mut replacement, next, &snapshot, end)?;
        Some(next)
    };
    Ok(Prepared {
        snapshot_token: snapshot.token,
        next_cursor,
        page,
        replacement: Some(replacement),
    })
}

/// Installs the cursor `token` of `snapshot` at `position` in a prepared
/// replacement; a token already live is refused.
fn install(
    replacement: &mut Store,
    token: [u8; 32],
    snapshot: &Arc<Snapshot>,
    position: usize,
) -> Result<(), Fail> {
    if replacement.slots.iter().any(|slot| slot.token == token) {
        return Err(limited());
    }
    replacement.slots.values.push(Slot {
        token,
        snapshot: Arc::clone(snapshot),
        position,
    });
    Ok(())
}

fn invalid() -> Fail {
    E2eeReplyCode::ObjectNotFound.into()
}

fn limited() -> Fail {
    E2eeReplyCode::RateLimited.into()
}

/// Arms the expiry wake of the listing cuts no later than `deadline`; a cut
/// cannot be staged without it.
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
            agenc_relay_types::MonotonicTick::from_ticks(deadline),
            TimerKind::ListingSnapshotExpiry,
            TimedId::Global,
        )
        .map_err(|_| E2eeReplyCode::RateLimited)?;
    *armed = Some(deadline);
    Ok(())
}

#[cfg(test)]
#[path = "listing_snapshot/tests/packing.rs"]
mod tests;
