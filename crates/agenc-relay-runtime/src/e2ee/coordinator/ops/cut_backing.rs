//! Charged backing of the process-local companion cuts: vectors whose exact
//! capacity is reserved from the process memory budget before allocation,
//! shared by the mailbox and listing cuts.

#![forbid(unsafe_code)]

use agenc_relay_e2ee::wire::reply::E2eeReplyCode;

use super::Fail;
use crate::budget::{BackingReservationPort, MemoryCharge, MemoryPermit};
use crate::state_core::query_usage::QueryUsageLease;

/// A vector with its memory permit and, for a cursor index, its query
/// usage; the values drop before either reservation returns.
pub(super) struct BackingVec<T> {
    pub(super) values: Vec<T>,
    pub(super) _permit: Option<MemoryPermit>,
    pub(super) _query: Option<QueryUsageLease>,
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

/// An empty vector of exactly `count` reserved values.
pub(super) fn vector<T>(
    count: usize,
    port: &BackingReservationPort,
) -> Result<BackingVec<T>, Fail> {
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

/// The memory charge of an allocation of `capacity` bytes.
pub(super) fn charge(capacity: usize) -> Result<u64, Fail> {
    MemoryCharge::allocation(u64::try_from(capacity).map_err(|_| limited())?)
        .map(|charge| charge.bytes())
        .map_err(|_| limited())
}

fn limited() -> Fail {
    E2eeReplyCode::RateLimited.into()
}
