//! Write transactions with a typed physical allocation allowance and explicit phases.
//!
//! An ordinary [`WriteTransaction`](crate::WriteTransaction) allocates pages and extends the
//! file whenever a mutation or its commit needs space. A bounded transaction charges every such
//! allocation to one [`AllocationAllowance`] first and refuses, without side effects, when the
//! allowance would be exceeded. Its life is:
//!
//! 1. `begin_write_bounded`: user writes through the [`BoundedWriteTransaction`], which
//!    dereferences to the ordinary transaction API.
//! 2. [`BoundedWriteTransaction::prepare`]: every allocation-bearing step of the commit runs,
//!    writing only into new pages while every prior user and system root stays valid. A
//!    refusal here aborts cleanly. The result is a frozen [`PreparedTransaction`].
//! 3. [`PreparedTransaction::publish`]: the header slots are written and flushed. Nothing is
//!    allocated and the file is never extended; the account is frozen and would refuse.
//! 4. Deferred cleanup: [`Database::reclaim_bounded`](crate::Database::reclaim_bounded) frees
//!    the pages earlier transactions released, a bounded number of records at a time.
//! 5. Close: [`Database::persist_allocator_state_bounded`](crate::Database::persist_allocator_state_bounded)
//!    writes the allocator state within an allowance, after which dropping the database only
//!    flushes and closes the file.
//!
//! Real I/O failures keep their ordinary meaning: an uncertain publication latches the
//! database until it is reopened and repaired.

use crate::error::CommitError;
use crate::{AllocationPhase, AllowanceRefusal, Result, StorageError, WriteTransaction};
use core::fmt::{Debug, Formatter};
use core::ops::Deref;

/// The physical allocation allowance of one bounded transaction, in bytes.
///
/// The account debits every page extent at its rounded buddy-allocator size and every file
/// extension at its exact length before the allocation happens. Nothing is refunded: a page the
/// transaction frees or reuses does not lower the charge, so the allowance bounds physical
/// growth from above rather than measuring it exactly. Reader-retained pages cost nothing
/// directly; they keep freed-page records in the system tables, whose pages are charged like
/// any other.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationAllowance(u64);

impl AllocationAllowance {
    /// An allowance of `bytes`.
    pub const fn new(bytes: u64) -> Self {
        Self(bytes)
    }

    /// The allowance in bytes.
    pub const fn bytes(self) -> u64 {
        self.0
    }
}

/// What one bounded reclamation removed and whether more is waiting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReclaimProgress {
    /// Freed-page records removed from the freed tables.
    pub records: usize,
    /// Pages returned to the allocator.
    pub pages: usize,
    /// Whether records that no live reader needs remain to be reclaimed.
    pub remaining: bool,
}

/// A write transaction in its mutation phase, bounded by an [`AllocationAllowance`].
///
/// It dereferences to [`WriteTransaction`] for table access. Dropping it aborts.
pub struct BoundedWriteTransaction {
    inner: WriteTransaction,
}

impl BoundedWriteTransaction {
    pub(crate) fn new(inner: WriteTransaction) -> Self {
        Self { inner }
    }

    fn account_view<T>(&self, read: impl FnOnce(&crate::tree_store::AllocationAccount) -> T) -> Result<T> {
        let account = self
            .inner
            .account()
            .ok_or_else(|| StorageError::Corrupted("bounded transaction without an account".into()))?;
        let guard = account.lock()?;
        Ok(read(&guard))
    }

    /// The allowance not yet charged, in bytes.
    pub fn allowance_remaining(&self) -> Result<u64> {
        self.account_view(|account| account.remaining())
    }

    /// The bytes charged so far.
    pub fn allowance_charged(&self) -> Result<u64> {
        self.account_view(|account| account.charged())
    }

    /// The refusal that latched this transaction, if any. A latched transaction can only abort;
    /// `prepare` returns the same refusal.
    pub fn refusal(&self) -> Result<Option<AllowanceRefusal>> {
        self.account_view(|account| account.refusal())
    }

    /// The phase the account is charging: [`AllocationPhase::Mutation`] until `prepare`.
    pub fn phase(&self) -> Result<AllocationPhase> {
        self.account_view(|account| account.phase())
    }

    /// Runs every allocation-bearing step of the commit and freezes the result.
    ///
    /// On an [`AllowanceRefusal`] the transaction has been aborted: no root changed, every page
    /// it freed is allocated again, and the next writer is unaffected. On any other error the
    /// database refuses further writes until reopened, as an ordinary failed commit does.
    pub fn prepare(mut self) -> core::result::Result<PreparedTransaction, CommitError> {
        self.inner.mark_completed();
        self.inner.prepare_bounded(0)?;
        Ok(PreparedTransaction {
            inner: Some(self.inner),
        })
    }

    /// Aborts the transaction, rolling back all of its writes.
    pub fn abort(self) -> Result {
        self.inner.abort()
    }
}

impl Debug for BoundedWriteTransaction {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BoundedWriteTransaction")
            .field("phase", &self.phase().ok())
            .field("charged", &self.allowance_charged().ok())
            .field("remaining", &self.allowance_remaining().ok())
            .finish_non_exhaustive()
    }
}

impl Deref for BoundedWriteTransaction {
    type Target = WriteTransaction;

    fn deref(&self) -> &WriteTransaction {
        &self.inner
    }
}

/// A prepared bounded transaction: frozen, fully written into new pages, and waiting only for
/// its header publication. Dropping it aborts, exactly like cancelling before preparation.
pub struct PreparedTransaction {
    inner: Option<WriteTransaction>,
}

impl PreparedTransaction {
    /// The bytes the transaction charged in its mutation and preparation phases.
    pub fn allowance_charged(&self) -> Result<u64> {
        let inner = self
            .inner
            .as_ref()
            .ok_or_else(|| StorageError::Corrupted("prepared transaction already consumed".into()))?;
        let account = inner
            .account()
            .ok_or_else(|| StorageError::Corrupted("bounded transaction without an account".into()))?;
        let charged = account.lock()?.charged();
        Ok(charged)
    }

    /// Publishes the prepared state durably. This never allocates or extends the file.
    pub fn publish(mut self) -> core::result::Result<(), CommitError> {
        let mut inner = self.inner.take().ok_or_else(|| {
            CommitError::Storage(StorageError::Corrupted(
                "prepared transaction already consumed".into(),
            ))
        })?;
        inner.publish_bounded().map(|_| ())
    }

    /// Abandons the prepared state: every root and page is exactly as before the transaction.
    pub fn abort(mut self) -> Result {
        match self.inner.take() {
            Some(mut inner) => inner.abort_prepared(),
            None => Ok(()),
        }
    }
}

impl Debug for PreparedTransaction {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PreparedTransaction")
            .field("charged", &self.allowance_charged().ok())
            .finish_non_exhaustive()
    }
}

impl Drop for PreparedTransaction {
    fn drop(&mut self) {
        if let Some(mut inner) = self.inner.take()
            && !crate::panicking()
        {
            #[allow(unused_variables)]
            if let Err(error) = inner.abort_prepared() {
                #[cfg(feature = "logging")]
                log::warn!("Failure automatically aborting prepared transaction: {error}");
            }
        }
    }
}
