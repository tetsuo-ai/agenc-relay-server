//! Hierarchical token buckets (spec 19.1, lines 2591-2614; Appendix C.6,
//! lines 9140-9165).
//!
//! Every bucket row of the spec table is a closed [`BucketKind`] with its
//! default and hard rate. Keys are the closed [`BucketKey`] classes, never
//! peer-controlled text. Work is admitted only when every required bucket
//! has capacity, and tokens are charged even when later semantic validation
//! fails, so a rejection cannot become an error oracle (spec lines
//! 2591-2593).

use std::collections::BTreeSet;
use std::collections::hash_map::RandomState;
use std::fmt;
use std::hash::{BuildHasher as _, Hash};
use std::mem::size_of;

use agenc_ircd_domain::{AdmissionSnapshot, DomainError, Principal, RateBucket, RateCharge};
use agenc_ircd_types::{AccountId, ChannelInstanceId, InviteId, MonotonicTick, UserId};

use crate::RuntimeError;
use crate::budget::{
    BoundedMemoryCharges, MemoryBudget, MemoryBudgetPort as _, MemoryCharge, MemoryPermit,
};
use crate::connection::sink::ConnectionGeneration;
use crate::state_core::inbox::SourceAddressKey;
use crate::sync::Arc;

/// Milliseconds in one second; the monotonic tick unit is the millisecond.
pub const MILLIS_PER_SECOND: u64 = 1_000;
/// Smallest configurable `refill_tokens` (spec line 9161).
pub const MIN_REFILL_TOKENS: u64 = 1;
/// Largest configurable `refill_tokens` (spec line 9161).
pub const MAX_REFILL_TOKENS: u64 = 1_000;
/// Smallest configurable `refill_seconds` (spec line 9161).
pub const MIN_REFILL_SECONDS: u64 = 1;
/// Largest configurable `refill_seconds` (spec line 9161).
pub const MAX_REFILL_SECONDS: u64 = 3_600;
/// Smallest configurable burst (spec line 9161).
pub const MIN_BURST: u64 = 1;
/// Largest configurable burst (spec line 9161).
pub const MAX_BURST: u64 = 1_000;
/// Ceiling on live bucket rows across every kind: four rows for each of the
/// 250,000 hard-maximum client connections (spec line 2641). A bucket at
/// full credit is identical to an absent one, so full rows are swept before
/// the ceiling refuses admission.
pub const MAX_TRACKED_BUCKETS: usize = 1_000_000;

/// Initial slot count for a nonempty accounted table.
const INITIAL_ACCOUNTED_SLOTS: usize = 8;
/// The table grows before more than half its slots would be occupied.
const ACCOUNTED_LOAD_DIVISOR: usize = 2;

#[derive(Clone, Copy)]
enum AccountedSlot<K, V> {
    Empty,
    Deleted,
    Occupied { key: K, value: V },
}

/// One reversible logical mutation in an [`AccountedHashTable`].
pub(super) struct AccountedTableMutation<K, V> {
    index: usize,
    previous: AccountedSlot<K, V>,
    previous_len: usize,
}

/// A randomly hashed table whose retained backing always owns its permit.
///
/// The table never asks its `Vec` to grow. A replacement backing is charged
/// and fully populated while the old backing and permit remain live, then the
/// complete candidate is swapped in. Deleted slots are reused, so removal and
/// rollback never allocate.
pub(super) struct AccountedHashTable<K, V> {
    slots: Box<[AccountedSlot<K, V>]>,
    len: usize,
    ceiling: usize,
    hash_builder: RandomState,
    budget: Arc<MemoryBudget>,
    _backing: Option<MemoryPermit>,
}

impl<K, V> AccountedHashTable<K, V>
where
    K: Copy + Eq + Hash,
    V: Copy,
{
    /// Creates an empty table. The first retained backing is allocated lazily.
    pub(super) fn new(ceiling: usize, budget: Arc<MemoryBudget>) -> Self {
        Self {
            slots: Vec::new().into_boxed_slice(),
            len: 0,
            ceiling,
            hash_builder: RandomState::new(),
            budget,
            _backing: None,
        }
    }

    /// Returns the logical row ceiling.
    pub(super) const fn ceiling(&self) -> usize {
        self.ceiling
    }

    /// Returns the number of live rows.
    pub(super) const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether no row is live.
    pub(super) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns whether `key` is present.
    pub(super) fn contains_key(&self, key: &K) -> bool {
        self.index_of(key).is_some()
    }

    /// Borrows the value stored for `key`.
    pub(super) fn get(&self, key: &K) -> Option<&V> {
        let index = self.index_of(key)?;
        match self.slots.get(index) {
            Some(AccountedSlot::Occupied { value, .. }) => Some(value),
            Some(AccountedSlot::Empty | AccountedSlot::Deleted) | None => None,
        }
    }

    /// Mutably borrows the value stored for `key`.
    pub(super) fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let index = self.index_of(key)?;
        match self.slots.get_mut(index) {
            Some(AccountedSlot::Occupied { value, .. }) => Some(value),
            Some(AccountedSlot::Empty | AccountedSlot::Deleted) | None => None,
        }
    }

    /// Inserts or replaces one row after funding any required backing growth.
    pub(super) fn try_insert(&mut self, key: K, value: V) -> Result<Option<V>, RuntimeError> {
        let mutation = self.try_insert_transaction(key, value)?;
        let previous = match mutation.previous {
            AccountedSlot::Occupied { value, .. } => Some(value),
            AccountedSlot::Empty | AccountedSlot::Deleted => None,
        };
        Ok(previous)
    }

    /// Inserts or replaces one row and returns an allocation-free rollback.
    pub(super) fn try_insert_transaction(
        &mut self,
        key: K,
        value: V,
    ) -> Result<AccountedTableMutation<K, V>, RuntimeError> {
        if let Some(index) = self.index_of(&key) {
            return self.replace_at(index, key, value);
        }
        self.reserve_for_one()?;
        let index = self.vacant_index(&key).ok_or(RuntimeError::InvalidValue)?;
        self.replace_at(index, key, value)
    }

    /// Restores one mutation created by this table while its backing was fixed.
    pub(super) fn rollback(&mut self, mutation: AccountedTableMutation<K, V>) {
        let Some(slot) = self.slots.get_mut(mutation.index) else {
            return;
        };
        *slot = mutation.previous;
        self.len = mutation.previous_len;
    }

    /// Removes one row without shrinking or allocating.
    pub(super) fn remove(&mut self, key: &K) -> Option<V> {
        self.remove_transaction(key).map(|(value, _)| value)
    }

    /// Removes one row and returns an allocation-free rollback.
    pub(super) fn remove_transaction(
        &mut self,
        key: &K,
    ) -> Option<(V, AccountedTableMutation<K, V>)> {
        let index = self.index_of(key)?;
        let slot = self.slots.get_mut(index)?;
        let previous_len = self.len;
        let previous = std::mem::replace(slot, AccountedSlot::Deleted);
        let AccountedSlot::Occupied { value, .. } = previous else {
            return None;
        };
        self.len = self.len.saturating_sub(1);
        Some((
            value,
            AccountedTableMutation {
                index,
                previous,
                previous_len,
            },
        ))
    }

    /// Keeps only rows accepted by `predicate` without changing the backing.
    pub(super) fn retain(&mut self, mut predicate: impl FnMut(&K, &mut V) -> bool) {
        let mut removed = 0_usize;
        for slot in &mut self.slots {
            let keep = match slot {
                AccountedSlot::Occupied { key, value } => predicate(key, value),
                AccountedSlot::Empty | AccountedSlot::Deleted => true,
            };
            if !keep {
                *slot = AccountedSlot::Deleted;
                removed = removed.saturating_add(1);
            }
        }
        self.len = self.len.saturating_sub(removed);
    }

    /// Iterates over live values.
    pub(super) fn values(&self) -> impl Iterator<Item = &V> {
        self.slots.iter().filter_map(|slot| match slot {
            AccountedSlot::Occupied { value, .. } => Some(value),
            AccountedSlot::Empty | AccountedSlot::Deleted => None,
        })
    }

    /// Iterates over live keys and values.
    pub(super) fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.slots.iter().filter_map(|slot| match slot {
            AccountedSlot::Occupied { key, value } => Some((key, value)),
            AccountedSlot::Empty | AccountedSlot::Deleted => None,
        })
    }

    /// Mutably iterates over live values while borrowing their keys.
    pub(super) fn iter_mut(&mut self) -> impl Iterator<Item = (&K, &mut V)> {
        self.slots.iter_mut().filter_map(|slot| match slot {
            AccountedSlot::Occupied { key, value } => Some((&*key, value)),
            AccountedSlot::Empty | AccountedSlot::Deleted => None,
        })
    }

    #[cfg(test)]
    pub(super) fn backing_bytes(&self) -> u64 {
        self._backing.as_ref().map_or(0, MemoryPermit::bytes)
    }

    fn reserve_for_one(&mut self) -> Result<(), RuntimeError> {
        if self.len >= self.ceiling {
            return Err(RuntimeError::LimitExceeded);
        }
        let next_len = self.len.checked_add(1).ok_or(RuntimeError::Overflow)?;
        if !self.slots.is_empty() && next_len <= self.slots.len() / ACCOUNTED_LOAD_DIVISOR {
            return Ok(());
        }
        let max_slots = self
            .ceiling
            .checked_mul(ACCOUNTED_LOAD_DIVISOR)
            .ok_or(RuntimeError::Overflow)?;
        let target = if self.slots.is_empty() {
            INITIAL_ACCOUNTED_SLOTS.min(max_slots)
        } else {
            self.slots
                .len()
                .checked_mul(2)
                .ok_or(RuntimeError::Overflow)?
                .min(max_slots)
        };
        if target <= self.slots.len() {
            return Err(RuntimeError::LimitExceeded);
        }
        self.rebuild(target)
    }

    fn rebuild(&mut self, slot_count: usize) -> Result<(), RuntimeError> {
        let charge = Self::backing_charge(slot_count)?;
        let charges = BoundedMemoryCharges::new(&[charge])?;
        let mut batch = self.budget.try_acquire_batch(charges)?;
        let backing = batch
            .split_exact(charge.bytes())
            .ok_or(RuntimeError::InvalidValue)?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(slot_count)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        slots.resize_with(slot_count, || AccountedSlot::Empty);
        let mut replacement = Self {
            slots: slots.into_boxed_slice(),
            len: 0,
            ceiling: self.ceiling,
            hash_builder: self.hash_builder.clone(),
            budget: Arc::clone(&self.budget),
            _backing: Some(backing),
        };
        for (key, value) in self.iter() {
            replacement.insert_without_growth(*key, *value)?;
        }
        std::mem::swap(self, &mut replacement);
        Ok(())
    }

    fn backing_charge(slot_count: usize) -> Result<MemoryCharge, RuntimeError> {
        let bytes = slot_count
            .checked_mul(size_of::<AccountedSlot<K, V>>())
            .ok_or(RuntimeError::Overflow)?;
        MemoryCharge::allocation(u64::try_from(bytes).map_err(|_| RuntimeError::Overflow)?)
    }

    fn insert_without_growth(&mut self, key: K, value: V) -> Result<(), RuntimeError> {
        let index = self.vacant_index(&key).ok_or(RuntimeError::InvalidValue)?;
        let _mutation = self.replace_at(index, key, value)?;
        Ok(())
    }

    fn replace_at(
        &mut self,
        index: usize,
        key: K,
        value: V,
    ) -> Result<AccountedTableMutation<K, V>, RuntimeError> {
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(RuntimeError::InvalidValue)?;
        let previous_len = self.len;
        let previous = std::mem::replace(slot, AccountedSlot::Occupied { key, value });
        if !matches!(previous, AccountedSlot::Occupied { .. }) {
            self.len = self.len.checked_add(1).ok_or(RuntimeError::Overflow)?;
        }
        Ok(AccountedTableMutation {
            index,
            previous,
            previous_len,
        })
    }

    fn index_of(&self, key: &K) -> Option<usize> {
        if self.slots.is_empty() {
            return None;
        }
        let start = self.hash_builder.hash_one(key) as usize % self.slots.len();
        for step in 0..self.slots.len() {
            let index = start.wrapping_add(step) % self.slots.len();
            match self.slots.get(index) {
                Some(AccountedSlot::Occupied { key: live, .. }) if live == key => {
                    return Some(index);
                }
                Some(AccountedSlot::Empty) => return None,
                Some(AccountedSlot::Deleted | AccountedSlot::Occupied { .. }) => {}
                None => return None,
            }
        }
        None
    }

    fn vacant_index(&self, key: &K) -> Option<usize> {
        if self.slots.is_empty() {
            return None;
        }
        let start = self.hash_builder.hash_one(key) as usize % self.slots.len();
        let mut first_deleted = None;
        for step in 0..self.slots.len() {
            let index = start.wrapping_add(step) % self.slots.len();
            match self.slots.get(index) {
                Some(AccountedSlot::Empty) => return first_deleted.or(Some(index)),
                Some(AccountedSlot::Deleted) => {
                    first_deleted = first_deleted.or(Some(index));
                }
                Some(AccountedSlot::Occupied { .. }) => {}
                None => return first_deleted,
            }
        }
        first_deleted
    }
}

/// The closed rows of the spec 19.1 bucket table.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BucketKind {
    /// New direct TCP connection per IPv4 /24 or IPv6 /56.
    NewDirectTcp,
    /// New onion connection on the onion listener globally.
    NewOnionConnection,
    /// TLS handshake per direct prefix or onion listener.
    TlsHandshake,
    /// Pre-authentication command per connection.
    PreAuthCommand,
    /// Registered command per session.
    RegisteredCommand,
    /// Guest message per session.
    GuestMessage,
    /// Account message per Account ID.
    AccountMessage,
    /// Channel message per channel instance.
    ChannelMessage,
    /// Expensive query per session.
    ExpensiveQuery,
    /// Channel-key attempt per Account ID, or guest session plus prefix.
    ChannelKeyAttempt,
    /// Account creation per prefix, onion listener, or verified Invite ID.
    AccountCreation,
    /// OPAQUE attempt per keyed login hash.
    OpaqueAttempt,
    /// Credential change per Account ID; not operator configurable.
    CredentialChange,
}

impl BucketKind {
    /// Every row in spec order.
    pub const ALL: [Self; 13] = [
        Self::NewDirectTcp,
        Self::NewOnionConnection,
        Self::TlsHandshake,
        Self::PreAuthCommand,
        Self::RegisteredCommand,
        Self::GuestMessage,
        Self::AccountMessage,
        Self::ChannelMessage,
        Self::ExpensiveQuery,
        Self::ChannelKeyAttempt,
        Self::AccountCreation,
        Self::OpaqueAttempt,
        Self::CredentialChange,
    ];

    /// Returns the Appendix C.6 table name, or `None` for the fixed
    /// credential-change row that has no configuration entry.
    #[must_use]
    pub const fn config_name(self) -> Option<&'static str> {
        match self {
            Self::NewDirectTcp => Some("new_direct"),
            Self::NewOnionConnection => Some("new_onion"),
            Self::TlsHandshake => Some("tls_handshake"),
            Self::PreAuthCommand => Some("preauth_command"),
            Self::RegisteredCommand => Some("registered_command"),
            Self::GuestMessage => Some("guest_message"),
            Self::AccountMessage => Some("account_message"),
            Self::ChannelMessage => Some("channel_message"),
            Self::ExpensiveQuery => Some("expensive_query"),
            Self::ChannelKeyAttempt => Some("channel_key_attempt"),
            Self::AccountCreation => Some("account_creation"),
            Self::OpaqueAttempt => Some("opaque_attempt"),
            Self::CredentialChange => None,
        }
    }

    /// Returns the default rate (spec lines 2595-2609 and 9148-9159).
    #[must_use]
    pub const fn default_rate(self) -> BucketRate {
        let (tokens, seconds, burst) = match self {
            Self::NewDirectTcp => (1, 1, 8),
            Self::NewOnionConnection => (8, 1, 32),
            Self::TlsHandshake => (4, 1, 16),
            Self::PreAuthCommand => (1, 1, 10),
            Self::RegisteredCommand => (4, 1, 20),
            Self::GuestMessage => (1, 2, 4),
            Self::AccountMessage => (2, 1, 10),
            Self::ChannelMessage => (10, 1, 40),
            Self::ExpensiveQuery => (1, 5, 2),
            Self::ChannelKeyAttempt => (1, 30, 4),
            Self::AccountCreation => (1, 3_600, 2),
            Self::OpaqueAttempt => (1, 180, 5),
            Self::CredentialChange => (1, 600, 2),
        };
        BucketRate::fixed(tokens, seconds, burst)
    }

    /// Returns the hard rate an operator may not exceed (spec lines
    /// 9148-9159); the credential-change row is fixed at its default.
    #[must_use]
    pub const fn hard_rate(self) -> BucketRate {
        let (tokens, seconds, burst) = match self {
            Self::NewDirectTcp => (16, 1, 64),
            Self::NewOnionConnection => (64, 1, 256),
            Self::TlsHandshake => (32, 1, 128),
            Self::PreAuthCommand => (10, 1, 50),
            Self::RegisteredCommand => (40, 1, 200),
            Self::GuestMessage => (5, 1, 20),
            Self::AccountMessage => (20, 1, 100),
            Self::ChannelMessage => (100, 1, 400),
            Self::ExpensiveQuery => (2, 1, 10),
            Self::ChannelKeyAttempt => (1, 1, 20),
            Self::AccountCreation => (10, 3_600, 10),
            Self::OpaqueAttempt => (1, 10, 10),
            Self::CredentialChange => (1, 600, 2),
        };
        BucketRate::fixed(tokens, seconds, burst)
    }
}

/// One validated refill rate and burst.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BucketRate {
    refill_tokens: u64,
    refill_seconds: u64,
    burst: u64,
}

impl BucketRate {
    /// Validates the C.6 ranges: tokens 1..=1,000, seconds 1..=3,600, burst
    /// 1..=1,000 (spec line 9161).
    pub const fn new(
        refill_tokens: u64,
        refill_seconds: u64,
        burst: u64,
    ) -> Result<Self, RuntimeError> {
        if refill_tokens < MIN_REFILL_TOKENS
            || refill_tokens > MAX_REFILL_TOKENS
            || refill_seconds < MIN_REFILL_SECONDS
            || refill_seconds > MAX_REFILL_SECONDS
            || burst < MIN_BURST
            || burst > MAX_BURST
        {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(Self::fixed(refill_tokens, refill_seconds, burst))
    }

    const fn fixed(refill_tokens: u64, refill_seconds: u64, burst: u64) -> Self {
        Self {
            refill_tokens,
            refill_seconds,
            burst,
        }
    }

    /// Returns the tokens added per refill period.
    #[must_use]
    pub const fn refill_tokens(self) -> u64 {
        self.refill_tokens
    }

    /// Returns the refill period in seconds.
    #[must_use]
    pub const fn refill_seconds(self) -> u64 {
        self.refill_seconds
    }

    /// Returns the maximum credit.
    #[must_use]
    pub const fn burst(self) -> u64 {
        self.burst
    }

    const fn refill_millis(self) -> u64 {
        // Seconds are at most 3,600, so the product cannot overflow.
        self.refill_seconds * MILLIS_PER_SECOND
    }

    /// Compares rates by checked cross multiplication and burst (spec line
    /// 9143): `self` is within `hard` when `tokens * hard.seconds <=
    /// hard.tokens * seconds` and `burst <= hard.burst`. Both products are
    /// at most 3,600,000 by the validated ranges.
    #[must_use]
    pub const fn within(self, hard: Self) -> bool {
        self.refill_tokens * hard.refill_seconds <= hard.refill_tokens * self.refill_seconds
            && self.burst <= hard.burst
    }
}

/// The complete configured rate table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimits {
    rates: [BucketRate; 13],
}

impl RateLimits {
    /// Returns the spec defaults for every row, in [`BucketKind::ALL`] order.
    #[must_use]
    pub const fn defaults() -> Self {
        Self {
            rates: [
                BucketKind::NewDirectTcp.default_rate(),
                BucketKind::NewOnionConnection.default_rate(),
                BucketKind::TlsHandshake.default_rate(),
                BucketKind::PreAuthCommand.default_rate(),
                BucketKind::RegisteredCommand.default_rate(),
                BucketKind::GuestMessage.default_rate(),
                BucketKind::AccountMessage.default_rate(),
                BucketKind::ChannelMessage.default_rate(),
                BucketKind::ExpensiveQuery.default_rate(),
                BucketKind::ChannelKeyAttempt.default_rate(),
                BucketKind::AccountCreation.default_rate(),
                BucketKind::OpaqueAttempt.default_rate(),
                BucketKind::CredentialChange.default_rate(),
            ],
        }
    }

    /// Returns the configured rate of one row.
    #[must_use]
    pub fn rate(&self, kind: BucketKind) -> BucketRate {
        self.rates
            .get(kind as usize)
            .copied()
            .unwrap_or_else(|| kind.default_rate())
    }

    /// Replaces one row, refusing a rate above its hard row (spec lines
    /// 2611-2614) or any change to the fixed credential-change row.
    pub fn set(&mut self, kind: BucketKind, rate: BucketRate) -> Result<(), RuntimeError> {
        if !rate.within(kind.hard_rate()) {
            return Err(RuntimeError::LimitExceeded);
        }
        if let Some(slot) = self.rates.get_mut(kind as usize) {
            *slot = rate;
        }
        Ok(())
    }
}

/// The keyed login hash of one OPAQUE attempt; never a login identifier.
///
/// The type has no `Debug` so the private lookup digest cannot reach a log.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct LoginHashKey([u8; 32]);

impl LoginHashKey {
    /// Wraps the exact private lookup digest bytes.
    #[must_use]
    pub const fn from_digest_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// The closed key classes of the spec table; never peer-controlled text.
///
/// The type has no `Debug`: prefix keys and login hashes must not leave the
/// admission owner (spec ID-04, line 6858).
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum BucketKey {
    /// A direct address reduced to its /24 or /56 prefix.
    Prefix(SourceAddressKey),
    /// The onion listener as one shared key.
    OnionListener,
    /// One admitted connection.
    Connection(ConnectionGeneration),
    /// One registered session.
    Session(UserId),
    /// One account.
    Account(AccountId),
    /// One channel instance.
    Channel(ChannelInstanceId),
    /// One keyed login hash.
    LoginHash(LoginHashKey),
    /// One verified invitation.
    Invite(InviteId),
}

/// One bucket's current credit and refill position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenBucket {
    tokens: u64,
    last_refill: MonotonicTick,
}

impl TokenBucket {
    /// Creates a bucket at full credit as of `now`.
    #[must_use]
    pub const fn full(rate: BucketRate, now: MonotonicTick) -> Self {
        Self {
            tokens: rate.burst,
            last_refill: now,
        }
    }

    /// Adds whole refill periods elapsed since the last refill, capped at
    /// the burst. A clock that moved backwards adds nothing (spec line
    /// 2611).
    fn refill(&mut self, rate: BucketRate, now: MonotonicTick) {
        let Some(elapsed) = now.get().checked_sub(self.last_refill.get()) else {
            return;
        };
        let periods = elapsed / rate.refill_millis();
        if periods == 0 {
            return;
        }
        let added = periods.saturating_mul(rate.refill_tokens);
        self.tokens = self.tokens.saturating_add(added).min(rate.burst);
        let advanced = periods.saturating_mul(rate.refill_millis());
        self.last_refill =
            MonotonicTick::from_ticks(self.last_refill.get().saturating_add(advanced));
    }

    /// Returns the credit available at `now` after refilling.
    pub fn available(&mut self, rate: BucketRate, now: MonotonicTick) -> u64 {
        self.refill(rate, now);
        self.tokens.min(rate.burst)
    }

    /// Removes `tokens` after a successful all-or-nothing check.
    fn take(&mut self, tokens: u64) {
        self.tokens = self.tokens.saturating_sub(tokens);
    }

    /// Clamps stored credit to a lowered burst (spec line 9163).
    fn clamp(&mut self, rate: BucketRate) {
        self.tokens = self.tokens.min(rate.burst);
    }

    fn is_full(&mut self, rate: BucketRate, now: MonotonicTick) -> bool {
        self.available(rate, now) >= rate.burst
    }
}

/// One required charge against one bucket.
#[derive(Clone, Copy)]
pub struct BucketDemand {
    kind: BucketKind,
    key: BucketKey,
    tokens: u64,
}

impl BucketDemand {
    /// Creates a nonzero demand.
    pub const fn new(kind: BucketKind, key: BucketKey, tokens: u64) -> Result<Self, RuntimeError> {
        if tokens == 0 {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(Self { kind, key, tokens })
    }

    /// Returns the bucket row.
    #[must_use]
    pub const fn kind(&self) -> BucketKind {
        self.kind
    }

    /// Returns the token count.
    #[must_use]
    pub const fn tokens(&self) -> u64 {
        self.tokens
    }
}

/// Admission refused; no bucket was charged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionRefused {
    /// The named row had insufficient credit; this is the `SERVER_BUSY`
    /// class (spec line 2619).
    Insufficient(BucketKind),
    /// The bucket table is at its ceiling with no full row to reclaim.
    TableFull,
    /// Aggregating the demands overflowed.
    Overflow,
}

impl fmt::Display for AdmissionRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Insufficient(_) => {
                formatter.write_str("admission bucket has insufficient credit")
            }
            Self::TableFull => formatter.write_str("admission bucket table is full"),
            Self::Overflow => formatter.write_str("admission demand overflowed"),
        }
    }
}

/// Every live bucket, keyed by row and closed key.
///
/// The map is keyed by a randomly keyed standard hash, so attacker-chosen
/// keys such as login hashes cannot degrade it (spec line 2884), and it is
/// bounded by [`MAX_TRACKED_BUCKETS`].
pub struct BucketTable {
    limits: RateLimits,
    buckets: AccountedHashTable<(BucketKind, BucketKey), TokenBucket>,
}

impl BucketTable {
    /// Creates an empty table under the default ceiling.
    #[must_use]
    pub fn new(limits: RateLimits, budget: Arc<MemoryBudget>) -> Self {
        Self::with_ceiling(limits, MAX_TRACKED_BUCKETS, budget)
    }

    /// Creates an empty table under an explicit ceiling.
    #[must_use]
    pub fn with_ceiling(limits: RateLimits, ceiling: usize, budget: Arc<MemoryBudget>) -> Self {
        Self {
            limits,
            buckets: AccountedHashTable::new(ceiling, budget),
        }
    }

    /// Returns the configured rates.
    #[must_use]
    pub const fn limits(&self) -> &RateLimits {
        &self.limits
    }

    /// Returns the number of live rows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    /// Returns whether no row is live.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    /// Charges every demand or nothing (spec lines 2591-2593).
    ///
    /// Demands on the same bucket are aggregated first, so a command that
    /// names one bucket twice needs the combined credit.
    pub fn charge_all_or_nothing(
        &mut self,
        now: MonotonicTick,
        demands: &[BucketDemand],
    ) -> Result<(), AdmissionRefused> {
        let aggregated = aggregate(demands)?;
        // Reclaim full rows once, before any row for this charge exists, so a
        // sweep can never discard a row the same charge just created.
        let new_rows = aggregated
            .iter()
            .filter(|(kind, key, _)| !self.buckets.contains_key(&(*kind, *key)))
            .count();
        if self.buckets.len().saturating_add(new_rows) > self.buckets.ceiling() {
            self.sweep_full(now);
        }
        for (kind, key, tokens) in &aggregated {
            let rate = self.limits.rate(*kind);
            let bucket = self.bucket_mut(now, *kind, *key)?;
            if bucket.available(rate, now) < *tokens {
                return Err(AdmissionRefused::Insufficient(*kind));
            }
        }
        for (kind, key, tokens) in &aggregated {
            if let Some(bucket) = self.buckets.get_mut(&(*kind, *key)) {
                bucket.take(*tokens);
            }
        }
        Ok(())
    }

    /// Returns the credit one bucket holds at `now`; an absent row is full.
    pub fn available(&mut self, now: MonotonicTick, kind: BucketKind, key: BucketKey) -> u64 {
        let rate = self.limits.rate(kind);
        match self.buckets.get_mut(&(kind, key)) {
            Some(bucket) => bucket.available(rate, now),
            None => rate.burst(),
        }
    }

    /// Builds the domain admission snapshot for the named buckets.
    pub fn domain_snapshot(
        &mut self,
        now: MonotonicTick,
        buckets: &[RateBucket],
    ) -> Result<AdmissionSnapshot, DomainError> {
        let distinct: BTreeSet<RateBucket> = buckets.iter().copied().collect();
        let mut entries = Vec::with_capacity(distinct.len());
        for bucket in distinct {
            let (kind, key) = domain_bucket(bucket);
            entries.push((bucket, self.available(now, kind, key)));
        }
        AdmissionSnapshot::new(entries)
    }

    /// Charges the domain rate charges of one command all or nothing.
    pub fn apply_domain_charges(
        &mut self,
        now: MonotonicTick,
        charges: &[RateCharge],
    ) -> Result<(), AdmissionRefused> {
        let mut demands = Vec::with_capacity(charges.len());
        for charge in charges {
            let (kind, key) = domain_bucket(charge.bucket());
            demands.push(
                BucketDemand::new(kind, key, charge.tokens())
                    .map_err(|_| AdmissionRefused::Overflow)?,
            );
        }
        self.charge_all_or_nothing(now, &demands)
    }

    /// Erases every row keyed by `key`, for prefix erasure and session end.
    pub fn erase_key(&mut self, key: BucketKey) {
        self.buckets.retain(|(_, live_key), _| *live_key != key);
    }

    /// Removes every row at full credit; a fresh row starts full, so
    /// nothing observable changes.
    pub fn sweep_full(&mut self, now: MonotonicTick) {
        let limits = self.limits;
        self.buckets
            .retain(|(kind, _), bucket| !bucket.is_full(limits.rate(*kind), now));
    }

    /// Installs reloaded rates: lowering clamps existing credit to the new
    /// burst, raising creates no immediate credit (spec lines 9162-9164).
    pub fn reload(&mut self, limits: RateLimits) {
        self.limits = limits;
        for ((kind, _), bucket) in self.buckets.iter_mut() {
            bucket.clamp(limits.rate(*kind));
        }
    }

    fn bucket_mut(
        &mut self,
        now: MonotonicTick,
        kind: BucketKind,
        key: BucketKey,
    ) -> Result<&mut TokenBucket, AdmissionRefused> {
        if !self.buckets.contains_key(&(kind, key)) {
            if self.buckets.len() >= self.buckets.ceiling() {
                return Err(AdmissionRefused::TableFull);
            }
            let rate = self.limits.rate(kind);
            self.buckets
                .try_insert((kind, key), TokenBucket::full(rate, now))
                .map_err(|_| AdmissionRefused::TableFull)?;
        }
        self.buckets
            .get_mut(&(kind, key))
            .ok_or(AdmissionRefused::TableFull)
    }
}

/// Combines demands on the same bucket with checked addition.
fn aggregate(
    demands: &[BucketDemand],
) -> Result<Vec<(BucketKind, BucketKey, u64)>, AdmissionRefused> {
    let mut aggregated: Vec<(BucketKind, BucketKey, u64)> = Vec::with_capacity(demands.len());
    for demand in demands {
        match aggregated
            .iter_mut()
            .find(|(kind, key, _)| *kind == demand.kind && *key == demand.key)
        {
            Some((_, _, tokens)) => {
                *tokens = tokens
                    .checked_add(demand.tokens)
                    .ok_or(AdmissionRefused::Overflow)?;
            }
            None => aggregated.push((demand.kind, demand.key, demand.tokens)),
        }
    }
    Ok(aggregated)
}

/// Maps a domain bucket to its runtime row and key (spec lines 2600-2604).
///
/// A guest channel-key attempt also charges the caller's prefix or onion
/// bucket; StateCore adds that second demand because only the transport
/// owner knows the source key.
#[must_use]
pub fn domain_bucket(bucket: RateBucket) -> (BucketKind, BucketKey) {
    match bucket {
        RateBucket::RegisteredCommand(user) => {
            (BucketKind::RegisteredCommand, BucketKey::Session(user))
        }
        RateBucket::GuestMessage(user) => (BucketKind::GuestMessage, BucketKey::Session(user)),
        RateBucket::AccountMessage(account) => {
            (BucketKind::AccountMessage, BucketKey::Account(account))
        }
        RateBucket::ChannelMessage(channel) => {
            (BucketKind::ChannelMessage, BucketKey::Channel(channel))
        }
        RateBucket::ExpensiveQuery(user) => (BucketKind::ExpensiveQuery, BucketKey::Session(user)),
        RateBucket::ChannelKeyAttempt(Principal::Account(account)) => {
            (BucketKind::ChannelKeyAttempt, BucketKey::Account(account))
        }
        RateBucket::ChannelKeyAttempt(Principal::Guest(user)) => {
            (BucketKind::ChannelKeyAttempt, BucketKey::Session(user))
        }
    }
}

#[cfg(test)]
mod tests {
    use agenc_ircd_types::AccountRandomId;

    use super::*;

    const TEST_BUDGET_BYTES: u64 = 1_048_576;

    fn budget() -> Arc<MemoryBudget> {
        Arc::new(MemoryBudget::new(TEST_BUDGET_BYTES))
    }

    fn tick(millis: u64) -> MonotonicTick {
        MonotonicTick::from_ticks(millis)
    }

    fn demand(kind: BucketKind, key: BucketKey, tokens: u64) -> BucketDemand {
        BucketDemand { kind, key, tokens }
    }

    fn user(byte: u8) -> UserId {
        UserId::from_bytes([byte; 16])
    }

    fn connection(value: u64) -> BucketKey {
        BucketKey::Connection(ConnectionGeneration::new(value))
    }

    #[test]
    fn every_row_default_is_within_its_hard_rate_and_names_match_the_table() {
        let expected_names = [
            Some("new_direct"),
            Some("new_onion"),
            Some("tls_handshake"),
            Some("preauth_command"),
            Some("registered_command"),
            Some("guest_message"),
            Some("account_message"),
            Some("channel_message"),
            Some("expensive_query"),
            Some("channel_key_attempt"),
            Some("account_creation"),
            Some("opaque_attempt"),
            None,
        ];
        for (kind, name) in BucketKind::ALL.iter().zip(expected_names) {
            assert_eq!(kind.config_name(), name, "{kind:?}");
            assert!(kind.default_rate().within(kind.hard_rate()), "{kind:?}");
            assert!(kind.hard_rate().within(kind.hard_rate()), "{kind:?}");
        }
        let limits = RateLimits::defaults();
        assert_eq!(limits.rate(BucketKind::OpaqueAttempt).refill_seconds(), 180);
        assert_eq!(limits.rate(BucketKind::CredentialChange).burst(), 2);
        assert_eq!(BucketKind::GuestMessage.default_rate().refill_tokens(), 1);
    }

    #[test]
    fn rates_validate_their_ranges_and_operator_overrides_stop_at_the_hard_row() {
        for (tokens, seconds, burst) in [
            (0, 1, 1),
            (1_001, 1, 1),
            (1, 0, 1),
            (1, 3_601, 1),
            (1, 1, 0),
            (1, 1, 1_001),
        ] {
            assert_eq!(
                BucketRate::new(tokens, seconds, burst).err(),
                Some(RuntimeError::InvalidValue),
                "{tokens}/{seconds}/{burst}"
            );
        }
        let mut limits = RateLimits::defaults();
        assert_eq!(
            limits.set(BucketKind::NewDirectTcp, BucketRate::fixed(16, 1, 64)),
            Ok(())
        );
        // 33 tokens per 2 seconds is 16.5 per second, above the 16 per second hard row.
        assert_eq!(
            limits.set(BucketKind::NewDirectTcp, BucketRate::fixed(33, 2, 64)),
            Err(RuntimeError::LimitExceeded)
        );
        assert_eq!(
            limits.set(BucketKind::NewDirectTcp, BucketRate::fixed(16, 1, 65)),
            Err(RuntimeError::LimitExceeded)
        );
        assert_eq!(
            limits.set(BucketKind::CredentialChange, BucketRate::fixed(1, 599, 2)),
            Err(RuntimeError::LimitExceeded)
        );
        assert_eq!(
            limits.set(BucketKind::CredentialChange, BucketRate::fixed(1, 600, 2)),
            Ok(())
        );
        assert_eq!(
            BucketRate::new(10, 3_600, 10).map(|rate| rate.burst()),
            Ok(10)
        );
    }

    #[test]
    fn buckets_refill_by_whole_periods_cap_at_burst_and_ignore_rollback() {
        let rate = BucketKind::GuestMessage.default_rate();
        let mut bucket = TokenBucket::full(rate, tick(0));
        assert_eq!(bucket.available(rate, tick(0)), 4);
        bucket.take(4);
        assert_eq!(bucket.available(rate, tick(1_999)), 0);
        assert_eq!(bucket.available(rate, tick(2_000)), 1);
        assert_eq!(bucket.available(rate, tick(3_999)), 1);
        assert_eq!(bucket.available(rate, tick(4_000)), 2);
        assert_eq!(
            bucket.available(rate, tick(1_000)),
            2,
            "rollback adds nothing"
        );
        assert_eq!(bucket.available(rate, tick(100_000)), 4, "capped at burst");
        let hourly_rate = BucketKind::AccountCreation.default_rate();
        let mut hourly = TokenBucket::full(hourly_rate, tick(0));
        hourly.take(2);
        assert_eq!(hourly.available(hourly_rate, tick(3_599_999)), 0);
        assert_eq!(hourly.available(hourly_rate, tick(3_600_000)), 1);
        let mut far = TokenBucket::full(rate, tick(0));
        far.take(4);
        assert_eq!(far.available(rate, MonotonicTick::from_ticks(u64::MAX)), 4);
    }

    #[test]
    fn charging_is_all_or_nothing_and_aggregates_repeated_buckets() {
        let mut table = BucketTable::new(RateLimits::defaults(), budget());
        let session = BucketKey::Session(user(1));
        let now = tick(0);
        let command = demand(BucketKind::RegisteredCommand, session, 1);
        let query = demand(BucketKind::ExpensiveQuery, session, 1);
        assert_eq!(table.charge_all_or_nothing(now, &[command, query]), Ok(()));
        assert_eq!(
            table.available(now, BucketKind::RegisteredCommand, session),
            19
        );
        assert_eq!(table.available(now, BucketKind::ExpensiveQuery, session), 1);
        assert_eq!(
            table.charge_all_or_nothing(now, &[command, query, query]),
            Err(AdmissionRefused::Insufficient(BucketKind::ExpensiveQuery))
        );
        assert_eq!(
            table.available(now, BucketKind::RegisteredCommand, session),
            19,
            "a refused set charges nothing"
        );
        assert_eq!(
            table.charge_all_or_nothing(now, &[command, command]),
            Ok(())
        );
        assert_eq!(
            table.available(now, BucketKind::RegisteredCommand, session),
            17
        );
        let overflow = [
            demand(BucketKind::RegisteredCommand, session, u64::MAX),
            demand(BucketKind::RegisteredCommand, session, 1),
        ];
        assert_eq!(
            table.charge_all_or_nothing(now, &overflow),
            Err(AdmissionRefused::Overflow)
        );
        assert_eq!(
            BucketDemand::new(BucketKind::GuestMessage, session, 0).err(),
            Some(RuntimeError::InvalidValue)
        );
        let accepted = BucketDemand::new(BucketKind::GuestMessage, session, 2)
            .map(|demand| (demand.kind(), demand.tokens()));
        assert_eq!(accepted, Ok((BucketKind::GuestMessage, 2)));
        assert!(!table.is_empty());
        assert_eq!(table.len(), 2);
        assert_eq!(table.limits().rate(BucketKind::GuestMessage).burst(), 4);
    }

    #[test]
    fn the_table_ceiling_reclaims_full_rows_before_refusing() {
        let mut table = BucketTable::with_ceiling(RateLimits::defaults(), 2, budget());
        let now = tick(0);
        let first = demand(BucketKind::PreAuthCommand, connection(1), 1);
        let second = demand(BucketKind::PreAuthCommand, connection(2), 1);
        let third = demand(BucketKind::PreAuthCommand, connection(3), 1);
        assert_eq!(table.charge_all_or_nothing(now, &[first]), Ok(()));
        assert_eq!(table.charge_all_or_nothing(now, &[second]), Ok(()));
        assert_eq!(
            table.charge_all_or_nothing(now, &[third]),
            Err(AdmissionRefused::TableFull)
        );
        // Ten seconds later the first two rows are full again and reclaimable.
        assert_eq!(table.charge_all_or_nothing(tick(10_000), &[third]), Ok(()));
        assert_eq!(table.len(), 1);
        table.sweep_full(tick(20_000));
        assert!(table.is_empty());
    }

    #[test]
    fn a_charge_at_the_ceiling_never_loses_one_of_its_own_rows() {
        let mut table = BucketTable::with_ceiling(RateLimits::defaults(), 2, budget());
        let now = tick(0);
        let occupied = demand(BucketKind::PreAuthCommand, connection(1), 1);
        assert_eq!(table.charge_all_or_nothing(now, &[occupied]), Ok(()));
        let prefix = BucketKey::Prefix(SourceAddressKey::ipv4([10, 0, 0, 2]).prefix_key());
        let tcp = demand(BucketKind::NewDirectTcp, prefix, 1);
        let handshake = demand(BucketKind::TlsHandshake, prefix, 1);
        let tcp_burst = RateLimits::defaults()
            .rate(BucketKind::NewDirectTcp)
            .burst();
        let handshake_burst = RateLimits::defaults()
            .rate(BucketKind::TlsHandshake)
            .burst();
        // Only one slot is free and the other row is not reclaimable yet, so
        // the two-row charge is refused whole; neither prefix row is charged.
        assert_eq!(
            table.charge_all_or_nothing(now, &[tcp, handshake]),
            Err(AdmissionRefused::TableFull)
        );
        assert_eq!(
            table.available(now, BucketKind::NewDirectTcp, prefix),
            tcp_burst
        );
        assert_eq!(
            table.available(now, BucketKind::TlsHandshake, prefix),
            handshake_burst
        );
        // Once the occupied row refills it is reclaimed and both rows charge.
        let later = tick(10_000);
        assert_eq!(
            table.charge_all_or_nothing(later, &[tcp, handshake]),
            Ok(())
        );
        assert_eq!(
            table.available(later, BucketKind::NewDirectTcp, prefix),
            tcp_burst - 1
        );
        assert_eq!(
            table.available(later, BucketKind::TlsHandshake, prefix),
            handshake_burst - 1
        );
    }

    #[test]
    fn erase_reload_and_domain_mapping_behave_as_specified() -> Result<(), DomainError> {
        let mut table = BucketTable::new(RateLimits::defaults(), budget());
        let now = tick(0);
        let prefix = BucketKey::Prefix(SourceAddressKey::ipv4([10, 0, 0, 1]).prefix_key());
        let tcp = demand(BucketKind::NewDirectTcp, prefix, 8);
        let handshake = demand(BucketKind::TlsHandshake, prefix, 3);
        assert_eq!(table.charge_all_or_nothing(now, &[tcp, handshake]), Ok(()));
        assert_eq!(table.available(now, BucketKind::NewDirectTcp, prefix), 0);
        table.erase_key(prefix);
        assert_eq!(table.available(now, BucketKind::NewDirectTcp, prefix), 8);
        assert!(table.is_empty());

        let session = BucketKey::Session(user(2));
        let registered = demand(BucketKind::RegisteredCommand, session, 5);
        assert_eq!(table.charge_all_or_nothing(now, &[registered]), Ok(()));
        let mut lowered = RateLimits::defaults();
        lowered
            .set(BucketKind::RegisteredCommand, BucketRate::fixed(4, 1, 10))
            .map_err(|_| DomainError::InvalidArgument)?;
        table.reload(lowered);
        assert_eq!(
            table.available(now, BucketKind::RegisteredCommand, session),
            10,
            "lowering clamps credit"
        );
        let mut raised = RateLimits::defaults();
        raised
            .set(BucketKind::RegisteredCommand, BucketRate::fixed(40, 1, 200))
            .map_err(|_| DomainError::InvalidArgument)?;
        table.reload(raised);
        assert_eq!(
            table.available(now, BucketKind::RegisteredCommand, session),
            10,
            "raising creates no credit"
        );

        let account = AccountId::from_random(AccountRandomId::from_bytes([3; 16]));
        let channel = ChannelInstanceId::from_bytes([4; 16]);
        let mapping = [
            (
                RateBucket::RegisteredCommand(user(2)),
                (BucketKind::RegisteredCommand, BucketKey::Session(user(2))),
            ),
            (
                RateBucket::GuestMessage(user(2)),
                (BucketKind::GuestMessage, BucketKey::Session(user(2))),
            ),
            (
                RateBucket::AccountMessage(account),
                (BucketKind::AccountMessage, BucketKey::Account(account)),
            ),
            (
                RateBucket::ChannelMessage(channel),
                (BucketKind::ChannelMessage, BucketKey::Channel(channel)),
            ),
            (
                RateBucket::ExpensiveQuery(user(2)),
                (BucketKind::ExpensiveQuery, BucketKey::Session(user(2))),
            ),
            (
                RateBucket::ChannelKeyAttempt(Principal::Account(account)),
                (BucketKind::ChannelKeyAttempt, BucketKey::Account(account)),
            ),
            (
                RateBucket::ChannelKeyAttempt(Principal::Guest(user(2))),
                (BucketKind::ChannelKeyAttempt, BucketKey::Session(user(2))),
            ),
        ];
        for (bucket, (kind, key)) in mapping {
            let (mapped_kind, mapped_key) = domain_bucket(bucket);
            assert_eq!(mapped_kind, kind);
            assert!(mapped_key == key);
        }
        let snapshot = table.domain_snapshot(
            now,
            &[
                RateBucket::RegisteredCommand(user(2)),
                RateBucket::RegisteredCommand(user(2)),
                RateBucket::AccountMessage(account),
            ],
        )?;
        drop(snapshot);
        let charge = RateCharge::new(RateBucket::AccountMessage(account), 10)?;
        assert_eq!(table.apply_domain_charges(now, &[charge]), Ok(()));
        assert_eq!(
            table.apply_domain_charges(now, &[charge]),
            Err(AdmissionRefused::Insufficient(BucketKind::AccountMessage))
        );
        for refusal in [
            AdmissionRefused::Insufficient(BucketKind::AccountMessage),
            AdmissionRefused::TableFull,
            AdmissionRefused::Overflow,
        ] {
            assert!(refusal.to_string().is_ascii());
        }
        let login = BucketKey::LoginHash(LoginHashKey::from_digest_bytes([9; 32]));
        let invite = BucketKey::Invite(InviteId::from_bytes([1; 16]));
        assert!(login != invite);
        assert!(BucketKey::OnionListener == BucketKey::OnionListener);
        Ok(())
    }

    #[test]
    fn accounted_table_refuses_unfunded_backing_without_retaining_state() {
        let budget = Arc::new(MemoryBudget::new(4_095));
        let mut table = AccountedHashTable::<u64, u64>::new(8, Arc::clone(&budget));

        assert_eq!(
            table.try_insert(1, 1).err(),
            Some(RuntimeError::MemoryExhausted)
        );
        assert!(table.is_empty());
        assert_eq!(table.backing_bytes(), 0);
        assert_eq!(budget.charged(), 0);
    }

    #[test]
    fn accounted_table_holds_old_and_new_permits_until_growth_commits() -> Result<(), RuntimeError>
    {
        let budget = Arc::new(MemoryBudget::new(4_096));
        let mut table = AccountedHashTable::<u64, u64>::new(64, Arc::clone(&budget));
        for value in 0..4 {
            let _previous = table.try_insert(value, value)?;
        }
        assert_eq!(table.len(), 4);
        assert_eq!(table.backing_bytes(), 4_096);
        assert_eq!(budget.charged(), 4_096);

        assert_eq!(
            table.try_insert(4, 4).err(),
            Some(RuntimeError::MemoryExhausted)
        );
        assert_eq!(table.len(), 4);
        for value in 0..4 {
            assert_eq!(table.get(&value), Some(&value));
        }
        drop(table);
        assert_eq!(budget.charged(), 0);
        Ok(())
    }

    #[test]
    fn accounted_table_rollback_restores_the_logical_row_without_freeing_backing()
    -> Result<(), RuntimeError> {
        let budget = Arc::new(MemoryBudget::new(8_192));
        let mut table = AccountedHashTable::<u64, u64>::new(8, Arc::clone(&budget));
        let mutation = table.try_insert_transaction(7, 9)?;
        assert_eq!(table.get(&7), Some(&9));
        table.rollback(mutation);

        assert!(table.is_empty());
        assert_eq!(table.backing_bytes(), 4_096);
        assert_eq!(budget.charged(), 4_096);
        Ok(())
    }
}
