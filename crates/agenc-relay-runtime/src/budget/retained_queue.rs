//! A bounded queue whose capacity remains charged while its allocation lives.

#![forbid(unsafe_code)]

use std::collections::{VecDeque, vec_deque::Drain};

use super::{MemoryCharge, MemoryPermit};
use crate::RuntimeError;

pub(crate) struct RetainedQueue<T> {
    entries: VecDeque<T>,
    limit: usize,
    // Fields drop in declaration order: free the deque before returning its charge.
    permit: Option<MemoryPermit>,
}

impl<T> Default for RetainedQueue<T> {
    fn default() -> Self {
        Self {
            entries: VecDeque::new(),
            limit: 0,
            permit: None,
        }
    }
}

impl<T> RetainedQueue<T> {
    pub(crate) fn reserve(
        &mut self,
        limit: usize,
        acquire: impl FnOnce(usize) -> Result<MemoryPermit, RuntimeError>,
    ) -> Result<(), RuntimeError> {
        if self.permit.is_some() {
            return if limit == self.limit {
                Ok(())
            } else {
                Err(RuntimeError::InvalidValue)
            };
        }
        if limit == 0 {
            return Err(RuntimeError::InvalidValue);
        }
        let bytes = limit
            .checked_mul(size_of::<T>())
            .ok_or(RuntimeError::Overflow)?;
        let required =
            MemoryCharge::allocation(u64::try_from(bytes).map_err(|_| RuntimeError::Overflow)?)?;
        let permit = acquire(bytes)?;
        if permit.bytes() < required.bytes() {
            return Err(RuntimeError::InvalidValue);
        }
        self.entries
            .try_reserve_exact(limit)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        self.limit = limit;
        self.permit = Some(permit);
        Ok(())
    }

    pub(crate) fn push_back(&mut self, value: T) -> Result<(), T> {
        if self.entries.len() >= self.limit {
            return Err(value);
        }
        self.entries.push_back(value);
        Ok(())
    }

    pub(crate) fn pop_front(&mut self) -> Option<T> {
        self.entries.pop_front()
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn drain(&mut self) -> Drain<'_, T> {
        self.entries.drain(..)
    }
}
