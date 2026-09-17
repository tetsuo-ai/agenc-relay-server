//! Process-wide memory admission and RAII permits (spec 19.2, lines 2703-2812).
//!
//! All count-scaled or peer-influenced heap storage is charged against one
//! `MemoryBudget` owned by the root supervisor. Other owners hold
//! non-cloneable permits and can neither inspect nor modify the counter.

mod backing_reservation;
#[cfg(test)]
#[path = "tests/idle_model.rs"]
mod idle_model;
mod output_budget;
mod permit;
mod retained_queue;

use std::error::Error;
use std::fmt;

pub(crate) use backing_reservation::BackingReservationPort;
pub use output_budget::PermitCursor;
pub use permit::{MemoryPermit, MemoryPermitBatch};
pub(crate) use retained_queue::RetainedQueue;

use crate::RuntimeError;
use crate::purpose::ListenerPurpose;
use crate::sync::{Arc, Mutex, lock};

/// Allocator size-class rounding applied to every backing allocation
/// (spec line 2722).
pub const MEMORY_QUANTUM_BYTES: u64 = 4_096;
/// Bookkeeping bytes charged for one logical backing allocation (spec line
/// 2722).
pub const ALLOCATION_BOOKKEEPING_BYTES: u64 = 256;
/// Fixed charge held for an entire admitted client connection (spec line
/// 2742).
pub const CLIENT_CONNECTION_BASE_BYTES: u64 = 65_536;
/// Fixed charge held for an entire live federation link (spec line 2743).
pub const FEDERATION_CONNECTION_BASE_BYTES: u64 = 262_144;
/// Fixed charge held for an entire admitted admin connection (spec line
/// 2744).
pub const ADMIN_CONNECTION_BASE_BYTES: u64 = 65_536;
/// Fixed charge held from TLS-handshake admission until handshake-only
/// allocations are destroyed (spec line 2745).
pub const TLS_SETUP_INCREMENT_BYTES: u64 = 262_144;
/// Fixed charge held from HTTP-upgrade admission until upgrade-only
/// allocations are destroyed (spec line 2746).
pub const WEBSOCKET_SETUP_INCREMENT_BYTES: u64 = 65_536;
/// Bytes reserved by each admitted durable batch (spec lines 2793-2795).
pub const DURABLE_BATCH_RESERVE_BYTES: u64 = 58_720_240;
/// Storage handoff slots permanently backed at startup (spec line 2765).
pub const STORAGE_HANDOFF_SLOTS: u64 = 2;
/// Bytes each crypto worker contributes to the worker pool (spec line 2805).
pub const CRYPTO_WORKER_RESERVED_BYTES: u64 = 75_497_472;
/// Minimum unavailable runtime and allocator headroom (spec line 2762).
pub const RUNTIME_HEADROOM_FLOOR_BYTES: u64 = 268_435_456;
/// Headroom is at least one eighth of the configured budget (spec line 2762).
pub const RUNTIME_HEADROOM_DIVISOR: u64 = 8;
/// Maximum charges in one batch: twice the members-per-channel hard maximum
/// of 65,535 (spec line 2647), covering one frame buffer and one queue
/// backing charge per recipient.
pub const MAX_MEMORY_CHARGES: usize = 131_072;

/// One complete client input frame, 8,703 bytes (spec line 2778).
const CLIENT_INPUT_FRAME_BYTES: u64 = 8_703;
/// One complete WebSocket message, 8,701 bytes (spec line 2779).
const WEBSOCKET_MESSAGE_BYTES: u64 = 8_701;
/// One federation ingress budget, 16 MiB (spec line 2780).
const FEDERATION_INGRESS_BYTES: u64 = 16_777_216;
/// Direct client working-set floor beside the base charge (spec line 2778).
const CLIENT_WORKING_SET_FLOOR_BYTES: u64 = 262_144;
/// WebSocket client working-set floor beside the base charge (spec line 2779).
const WEBSOCKET_WORKING_SET_FLOOR_BYTES: u64 = 327_680;
/// Federation and admin TLS working-set floor (spec lines 2780 and 2782).
const TLS_WORKING_SET_FLOOR_BYTES: u64 = 262_144;

/// One already checked charge against the process-wide budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryCharge(u64);

impl MemoryCharge {
    /// Computes the permit charge for one backing allocation of `capacity`
    /// bytes: zero for an empty allocation, otherwise the capacity plus
    /// bookkeeping rounded up to whole quanta (spec lines 2720-2723).
    pub const fn allocation(capacity: u64) -> Result<Self, RuntimeError> {
        if capacity == 0 {
            return Ok(Self(0));
        }
        let Some(padded) = capacity.checked_add(ALLOCATION_BOOKKEEPING_BYTES) else {
            return Err(RuntimeError::Overflow);
        };
        let Some(bytes) = padded
            .div_ceil(MEMORY_QUANTUM_BYTES)
            .checked_mul(MEMORY_QUANTUM_BYTES)
        else {
            return Err(RuntimeError::Overflow);
        };
        Ok(Self(bytes))
    }

    /// Wraps one of the fixed charges from the table at spec lines 2740-2746.
    #[must_use]
    pub const fn fixed(bytes: u64) -> Self {
        Self(bytes)
    }

    /// Returns the charged bytes.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.0
    }
}

/// A nonempty, count-bounded allocation-free plan of checked charges.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundedMemoryCharges {
    count: usize,
    total: u64,
}

impl BoundedMemoryCharges {
    /// Validates a borrowed charge list and computes its checked total without
    /// allocating.
    pub fn new(charges: &[MemoryCharge]) -> Result<Self, RuntimeError> {
        if charges.is_empty() {
            return Err(RuntimeError::InvalidValue);
        }
        if charges.len() > MAX_MEMORY_CHARGES {
            return Err(RuntimeError::LimitExceeded);
        }
        let mut accumulator = MemoryChargeAccumulator::new();
        for charge in charges {
            accumulator.try_push(*charge)?;
        }
        accumulator.finish()
    }

    /// Returns the exact sum of every charge.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.total
    }

    /// Returns the number of charges represented by this plan.
    #[must_use]
    pub const fn charge_count(&self) -> usize {
        self.count
    }
}

/// A heap-free checked accumulator for charge sets whose length is known only
/// while walking bounded runtime state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MemoryChargeAccumulator {
    count: usize,
    total: u64,
}

impl MemoryChargeAccumulator {
    pub(crate) const fn new() -> Self {
        Self { count: 0, total: 0 }
    }

    /// Adds one charge without changing the accumulator on refusal.
    pub(crate) fn try_push(&mut self, charge: MemoryCharge) -> Result<(), RuntimeError> {
        if self.count == MAX_MEMORY_CHARGES {
            return Err(RuntimeError::LimitExceeded);
        }
        let total = self
            .total
            .checked_add(charge.bytes())
            .ok_or(RuntimeError::Overflow)?;
        self.count += 1;
        self.total = total;
        Ok(())
    }

    /// Seals a nonempty accumulator as an acquisition plan.
    pub(crate) const fn finish(self) -> Result<BoundedMemoryCharges, RuntimeError> {
        if self.count == 0 {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(BoundedMemoryCharges {
            count: self.count,
            total: self.total,
        })
    }
}

/// The budget refused a batch; no permit was minted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryExhausted {
    requested: u64,
    available: u64,
}

impl MemoryExhausted {
    /// Returns the bytes the refused batch needed.
    #[must_use]
    pub const fn requested(self) -> u64 {
        self.requested
    }

    /// Returns the bytes that were available at refusal.
    #[must_use]
    pub const fn available(self) -> u64 {
        self.available
    }
}

impl fmt::Display for MemoryExhausted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("memory budget exhausted")
    }
}

impl Error for MemoryExhausted {}

impl From<MemoryExhausted> for RuntimeError {
    fn from(_: MemoryExhausted) -> Self {
        Self::MemoryExhausted
    }
}

/// The one authority that changes the live permit total (spec 24.2, lines
/// 6483-6486).
pub trait MemoryBudgetPort {
    /// Acquires the complete batch or nothing.
    fn try_acquire_batch(
        &self,
        charges: BoundedMemoryCharges,
    ) -> Result<MemoryPermitBatch, MemoryExhausted>;
}

/// Checked counter shared between the budget and its outstanding permits.
pub(crate) struct Ledger {
    capacity: u64,
    available: Mutex<u64>,
}

impl Ledger {
    /// Takes `bytes` atomically or reports the bytes that were available.
    fn try_take(&self, bytes: u64) -> Result<(), u64> {
        let mut available = lock(&self.available);
        match available.checked_sub(bytes) {
            Some(remaining) => {
                *available = remaining;
                Ok(())
            }
            None => Err(*available),
        }
    }

    /// Returns `bytes`; the counter never exceeds the pool capacity.
    pub(crate) fn release(&self, bytes: u64) {
        let mut available = lock(&self.available);
        *available = available
            .checked_add(bytes)
            .map_or(self.capacity, |total| total.min(self.capacity));
    }

    fn available(&self) -> u64 {
        *lock(&self.available)
    }
}

/// The process-wide live protocol permit pool.
pub struct MemoryBudget {
    ledger: Arc<Ledger>,
}

impl MemoryBudget {
    /// Creates a budget whose live pool holds exactly `pool_bytes`.
    #[must_use]
    pub fn new(pool_bytes: u64) -> Self {
        Self {
            ledger: Arc::new(Ledger {
                capacity: pool_bytes,
                available: Mutex::new(pool_bytes),
            }),
        }
    }

    /// Returns the fixed pool capacity.
    #[must_use]
    pub fn capacity(&self) -> u64 {
        self.ledger.capacity
    }

    /// Returns the bytes not held by any live permit.
    #[must_use]
    pub fn available(&self) -> u64 {
        self.ledger.available()
    }

    /// Returns the bytes held by live permits, the overload input of spec
    /// 19.3.
    #[must_use]
    pub fn charged(&self) -> u64 {
        self.ledger.capacity.saturating_sub(self.available())
    }
}

impl MemoryBudgetPort for MemoryBudget {
    fn try_acquire_batch(
        &self,
        charges: BoundedMemoryCharges,
    ) -> Result<MemoryPermitBatch, MemoryExhausted> {
        let requested = charges.total();
        self.ledger
            .try_take(requested)
            .map_err(|available| MemoryExhausted {
                requested,
                available,
            })?;
        Ok(MemoryPermitBatch::new(requested, Arc::clone(&self.ledger)))
    }
}

/// The checked startup pools derived from `server.memory_budget_bytes`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PermitPool {
    budget_bytes: u64,
    headroom_bytes: u64,
    storage_handoff_bytes: u64,
    crypto_pool_bytes: u64,
    protocol_pool_bytes: u64,
    working_set_floor_bytes: u64,
}

impl PermitPool {
    /// Returns `B`, the configured budget.
    #[must_use]
    pub const fn budget_bytes(self) -> u64 {
        self.budget_bytes
    }

    /// Returns `H`, the unavailable runtime and allocator headroom.
    #[must_use]
    pub const fn headroom_bytes(self) -> u64 {
        self.headroom_bytes
    }

    /// Returns `D`, the bytes backing both storage handoff slots.
    #[must_use]
    pub const fn storage_handoff_bytes(self) -> u64 {
        self.storage_handoff_bytes
    }

    /// Returns `C`, the crypto worker reservation pool.
    #[must_use]
    pub const fn crypto_pool_bytes(self) -> u64 {
        self.crypto_pool_bytes
    }

    /// Returns `P`, the live protocol permit pool.
    #[must_use]
    pub const fn protocol_pool_bytes(self) -> u64 {
        self.protocol_pool_bytes
    }

    /// Returns the largest enabled listener working set that `P` must cover.
    #[must_use]
    pub const fn working_set_floor_bytes(self) -> u64 {
        self.working_set_floor_bytes
    }
}

/// Computes `H`, `D`, `C`, and `P` exactly as spec lines 2760-2783 require.
///
/// `parsed_arena_bytes` is the configured per-connection parsed command
/// arena; it enters the client working-set rows.
pub fn startup_arithmetic(
    budget_bytes: u64,
    crypto_workers: u64,
    enabled: &[ListenerPurpose],
    parsed_arena_bytes: u64,
) -> Result<PermitPool, RuntimeError> {
    let headroom_bytes =
        RUNTIME_HEADROOM_FLOOR_BYTES.max(budget_bytes.div_ceil(RUNTIME_HEADROOM_DIVISOR));
    let storage_handoff_bytes = STORAGE_HANDOFF_SLOTS
        .checked_mul(DURABLE_BATCH_RESERVE_BYTES)
        .ok_or(RuntimeError::Overflow)?;
    let crypto_pool_bytes = crypto_workers
        .checked_mul(CRYPTO_WORKER_RESERVED_BYTES)
        .ok_or(RuntimeError::Overflow)?;
    let protocol_pool_bytes = budget_bytes
        .checked_sub(headroom_bytes)
        .and_then(|rest| rest.checked_sub(storage_handoff_bytes))
        .and_then(|rest| rest.checked_sub(crypto_pool_bytes))
        .ok_or(RuntimeError::BudgetArithmetic)?;
    let mut working_set_floor_bytes = 0;
    for purpose in enabled {
        let working_set = minimum_working_set(*purpose, parsed_arena_bytes)?;
        working_set_floor_bytes = working_set_floor_bytes.max(working_set);
    }
    if protocol_pool_bytes < working_set_floor_bytes {
        return Err(RuntimeError::BudgetBelowWorkingSet);
    }
    Ok(PermitPool {
        budget_bytes,
        headroom_bytes,
        storage_handoff_bytes,
        crypto_pool_bytes,
        protocol_pool_bytes,
        working_set_floor_bytes,
    })
}

/// Evaluates one row of the minimum working-set table (spec lines
/// 2775-2783).
pub fn minimum_working_set(
    purpose: ListenerPurpose,
    parsed_arena_bytes: u64,
) -> Result<u64, RuntimeError> {
    let charge = |capacity: u64| MemoryCharge::allocation(capacity).map(MemoryCharge::bytes);
    let arena_and_frame = |frame: u64| -> Result<u64, RuntimeError> {
        charge(parsed_arena_bytes)?
            .checked_add(charge(frame)?)
            .ok_or(RuntimeError::Overflow)
    };
    let (base, variable) = match purpose {
        ListenerPurpose::ClientTls | ListenerPurpose::ClientOnion => (
            CLIENT_CONNECTION_BASE_BYTES,
            CLIENT_WORKING_SET_FLOOR_BYTES.max(arena_and_frame(CLIENT_INPUT_FRAME_BYTES)?),
        ),
        ListenerPurpose::ClientWss => (
            CLIENT_CONNECTION_BASE_BYTES,
            WEBSOCKET_WORKING_SET_FLOOR_BYTES.max(arena_and_frame(WEBSOCKET_MESSAGE_BYTES)?),
        ),
        ListenerPurpose::Federation => (
            FEDERATION_CONNECTION_BASE_BYTES,
            TLS_WORKING_SET_FLOOR_BYTES.max(charge(FEDERATION_INGRESS_BYTES)?),
        ),
        ListenerPurpose::AdminLocal => (
            ADMIN_CONNECTION_BASE_BYTES,
            charge(CLIENT_INPUT_FRAME_BYTES)?,
        ),
        ListenerPurpose::AdminTls => (
            ADMIN_CONNECTION_BASE_BYTES,
            TLS_WORKING_SET_FLOOR_BYTES.max(charge(CLIENT_INPUT_FRAME_BYTES)?),
        ),
    };
    base.checked_add(variable).ok_or(RuntimeError::Overflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Appendix C.2 default `server.memory_budget_bytes` (spec line 8908).
    const DEFAULT_BUDGET_BYTES: u64 = 6_442_450_944;
    /// Appendix C.6 default `parsed_arena_bytes`, 32 KiB (spec line 2672).
    const DEFAULT_PARSED_ARENA_BYTES: u64 = 32_768;

    #[test]
    fn allocation_charges_follow_the_exact_quantum_table() -> Result<(), RuntimeError> {
        let table = [
            (0, 0),
            (1, 4_096),
            (3_840, 4_096),
            (3_841, 8_192),
            (7_936, 8_192),
            (7_937, 12_288),
            (8_703, 12_288),
        ];
        for (capacity, expected) in table {
            assert_eq!(
                MemoryCharge::allocation(capacity)?.bytes(),
                expected,
                "{capacity}"
            );
        }
        assert_eq!(
            MemoryCharge::allocation(u64::MAX).err(),
            Some(RuntimeError::Overflow)
        );
        assert_eq!(
            MemoryCharge::allocation(u64::MAX - ALLOCATION_BOOKKEEPING_BYTES).err(),
            Some(RuntimeError::Overflow)
        );
        Ok(())
    }

    #[test]
    fn bounded_charges_are_nonempty_count_bounded_and_overflow_checked() -> Result<(), RuntimeError>
    {
        assert_eq!(
            BoundedMemoryCharges::new(&[]).err(),
            Some(RuntimeError::InvalidValue)
        );
        let too_many = vec![MemoryCharge::fixed(1); MAX_MEMORY_CHARGES + 1];
        assert_eq!(
            BoundedMemoryCharges::new(&too_many).err(),
            Some(RuntimeError::LimitExceeded)
        );
        let overflow = [MemoryCharge::fixed(u64::MAX), MemoryCharge::fixed(1)];
        assert_eq!(
            BoundedMemoryCharges::new(&overflow).err(),
            Some(RuntimeError::Overflow)
        );
        let charges = BoundedMemoryCharges::new(&[
            MemoryCharge::fixed(CLIENT_CONNECTION_BASE_BYTES),
            MemoryCharge::fixed(TLS_SETUP_INCREMENT_BYTES),
        ])?;
        assert_eq!(charges.total(), 327_680);
        assert_eq!(charges.charge_count(), 2);

        let empty = MemoryChargeAccumulator::new();
        assert_eq!(empty.finish().err(), Some(RuntimeError::InvalidValue));

        let mut count_bounded = MemoryChargeAccumulator::new();
        for _ in 0..MAX_MEMORY_CHARGES {
            count_bounded.try_push(MemoryCharge::fixed(0))?;
        }
        assert_eq!(count_bounded.finish()?.charge_count(), MAX_MEMORY_CHARGES);
        let full = count_bounded;
        assert_eq!(
            count_bounded.try_push(MemoryCharge::fixed(0)),
            Err(RuntimeError::LimitExceeded)
        );
        assert_eq!(count_bounded, full);

        let mut overflow_checked = MemoryChargeAccumulator::new();
        overflow_checked.try_push(MemoryCharge::fixed(u64::MAX))?;
        let before_overflow = overflow_checked;
        assert_eq!(
            overflow_checked.try_push(MemoryCharge::fixed(1)),
            Err(RuntimeError::Overflow)
        );
        assert_eq!(overflow_checked, before_overflow);
        Ok(())
    }

    #[test]
    fn a_batch_is_acquired_whole_or_not_at_all_and_returns_on_drop() -> Result<(), RuntimeError> {
        let budget = MemoryBudget::new(100_000);
        let accepted =
            budget.try_acquire_batch(BoundedMemoryCharges::new(&[MemoryCharge::fixed(60_000)])?)?;
        assert_eq!(budget.available(), 40_000);
        assert_eq!(budget.charged(), 60_000);
        let refused = budget.try_acquire_batch(BoundedMemoryCharges::new(&[
            MemoryCharge::fixed(30_000),
            MemoryCharge::fixed(20_000),
        ])?);
        let Err(exhausted) = refused else {
            return Err(RuntimeError::InvalidValue);
        };
        assert_eq!(exhausted.requested(), 50_000);
        assert_eq!(exhausted.available(), 40_000);
        assert_eq!(
            budget.available(),
            40_000,
            "a refused batch changes nothing"
        );
        assert_eq!(RuntimeError::from(exhausted), RuntimeError::MemoryExhausted);
        assert!(exhausted.to_string().is_ascii());
        drop(accepted);
        assert_eq!(budget.available(), 100_000);
        assert_eq!(budget.capacity(), 100_000);
        Ok(())
    }

    #[test]
    fn releases_never_lift_the_counter_above_capacity() {
        let ledger = Ledger {
            capacity: 10,
            available: Mutex::new(10),
        };
        ledger.release(5);
        assert_eq!(ledger.available(), 10);
        ledger.release(u64::MAX);
        assert_eq!(ledger.available(), 10);
    }

    #[test]
    fn startup_arithmetic_matches_the_spec_constants_for_the_default_budget()
    -> Result<(), RuntimeError> {
        let pool = startup_arithmetic(
            DEFAULT_BUDGET_BYTES,
            4,
            &[ListenerPurpose::ClientTls, ListenerPurpose::AdminLocal],
            DEFAULT_PARSED_ARENA_BYTES,
        )?;
        assert_eq!(pool.budget_bytes(), DEFAULT_BUDGET_BYTES);
        assert_eq!(pool.headroom_bytes(), 805_306_368);
        assert_eq!(pool.storage_handoff_bytes(), 117_440_480);
        assert_eq!(pool.crypto_pool_bytes(), 301_989_888);
        assert_eq!(pool.protocol_pool_bytes(), 5_217_714_208);
        assert_eq!(pool.working_set_floor_bytes(), 65_536 + 262_144);
        let small = startup_arithmetic(1_073_741_824, 1, &[], DEFAULT_PARSED_ARENA_BYTES)?;
        assert_eq!(small.headroom_bytes(), RUNTIME_HEADROOM_FLOOR_BYTES);
        Ok(())
    }

    #[test]
    fn startup_arithmetic_rejects_underflow_and_a_pool_below_the_working_set() {
        assert_eq!(
            startup_arithmetic(RUNTIME_HEADROOM_FLOOR_BYTES, 1, &[], 32_768).err(),
            Some(RuntimeError::BudgetArithmetic)
        );
        let just_enough_pools =
            RUNTIME_HEADROOM_FLOOR_BYTES + 117_440_480 + CRYPTO_WORKER_RESERVED_BYTES + 100_000;
        assert_eq!(
            startup_arithmetic(just_enough_pools, 1, &[ListenerPurpose::Federation], 32_768,).err(),
            Some(RuntimeError::BudgetBelowWorkingSet)
        );
        assert_eq!(
            startup_arithmetic(u64::MAX, u64::MAX, &[], 32_768).err(),
            Some(RuntimeError::Overflow)
        );
    }

    #[test]
    fn working_set_rows_match_the_spec_table() -> Result<(), RuntimeError> {
        let arena = DEFAULT_PARSED_ARENA_BYTES;
        assert_eq!(
            minimum_working_set(ListenerPurpose::ClientTls, arena)?,
            65_536 + 262_144
        );
        assert_eq!(
            minimum_working_set(ListenerPurpose::ClientOnion, arena)?,
            65_536 + 262_144
        );
        assert_eq!(
            minimum_working_set(ListenerPurpose::ClientWss, arena)?,
            65_536 + 327_680
        );
        assert_eq!(
            minimum_working_set(ListenerPurpose::Federation, arena)?,
            262_144 + 16_781_312
        );
        assert_eq!(
            minimum_working_set(ListenerPurpose::AdminLocal, arena)?,
            65_536 + 12_288
        );
        assert_eq!(
            minimum_working_set(ListenerPurpose::AdminTls, arena)?,
            65_536 + 262_144
        );
        let large_arena = 131_072;
        assert_eq!(
            minimum_working_set(ListenerPurpose::ClientTls, large_arena)?,
            65_536 + 262_144
        );
        assert_eq!(
            minimum_working_set(ListenerPurpose::ClientTls, u64::MAX).err(),
            Some(RuntimeError::Overflow)
        );
        Ok(())
    }
}
