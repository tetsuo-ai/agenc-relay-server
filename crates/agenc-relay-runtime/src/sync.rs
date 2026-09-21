//! Synchronization primitives behind one crate-local alias.
//!
//! Production code names standard-library primitives through this module so
//! the Stage 06 schedule models can compile the same sources under the loom
//! scheduler without a compile-time configuration flag (spec 28.3, lines
//! 7058-7070).

pub(crate) use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

/// Locks a mutex and keeps serving after a poisoned guard.
///
/// Poisoning is an application policy, not a soundness guarantee: every
/// ledger protected here holds only checked counters, so a panic elsewhere
/// leaves the counter consistent and the runtime terminates through the
/// panic hook rather than through a second failure at this lock.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
