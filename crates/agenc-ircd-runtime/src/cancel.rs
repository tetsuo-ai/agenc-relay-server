//! Owned cancellation tokens for the supervised task tree.
//!
//! Every spawn owns a token, a supervisor registration, and a bounded
//! completion path (spec 21.2, lines 4064-4066). Cancelling a token cancels
//! every descendant; a child never cancels its parent. The tree is finite:
//! each parent admits at most [`MAX_CHILD_TOKENS`] live children.

use tokio::sync::watch;

use crate::RuntimeError;
use crate::sync::{Arc, Mutex, Weak, lock};

/// Maximum live children under one token: the hard client-connection
/// maximum of 250,000 (spec 19.2, line 2641) rounded up to cover the fixed
/// tree of spec 21.2.
pub const MAX_CHILD_TOKENS: usize = 262_144;

struct Inner {
    flag: watch::Sender<bool>,
    children: Mutex<Vec<Weak<Inner>>>,
}

/// One node of the owned cancellation tree.
///
/// Cloning a token yields another handle to the same node; dropping every
/// handle lets the parent forget the node lazily.
#[derive(Clone)]
pub struct CancellationToken {
    inner: Arc<Inner>,
}

impl CancellationToken {
    /// Creates the root token owned by the supervisor.
    #[must_use]
    pub fn root() -> Self {
        Self {
            inner: Arc::new(Inner {
                flag: watch::Sender::new(false),
                children: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Creates a child that starts cancelled when this token already is.
    ///
    /// The children list is pruned of dropped nodes only when it reaches the
    /// ceiling, so steady churn stays amortized while the bound holds.
    pub fn child(&self) -> Result<Self, RuntimeError> {
        let mut children = lock(&self.inner.children);
        if children.len() >= MAX_CHILD_TOKENS {
            children.retain(|weak| weak.strong_count() > 0);
        }
        if children.len() >= MAX_CHILD_TOKENS {
            return Err(RuntimeError::LimitExceeded);
        }
        let child = Arc::new(Inner {
            flag: watch::Sender::new(*self.inner.flag.borrow()),
            children: Mutex::new(Vec::new()),
        });
        children.push(Arc::downgrade(&child));
        Ok(Self { inner: child })
    }

    /// Cancels this token and every live descendant, depth first.
    pub fn cancel(&self) {
        let mut pending = vec![Arc::clone(&self.inner)];
        while let Some(node) = pending.pop() {
            node.flag.send_replace(true);
            let children = lock(&node.children);
            pending.extend(children.iter().filter_map(Weak::upgrade));
        }
    }

    /// Returns whether this token or any ancestor has been cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        *self.inner.flag.borrow()
    }

    /// Resolves once this token is cancelled; resolves immediately when it
    /// already is.
    pub async fn cancelled(&self) {
        let mut receiver = self.inner.flag.subscribe();
        while !*receiver.borrow_and_update() {
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }

    /// Counts children that still have a live handle, pruning the rest.
    #[must_use]
    pub fn live_children(&self) -> usize {
        let mut children = lock(&self.inner.children);
        children.retain(|weak| weak.strong_count() > 0);
        children.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancelling_a_parent_reaches_every_descendant_but_not_the_reverse()
    -> Result<(), RuntimeError> {
        let root = CancellationToken::root();
        let listener = root.child()?;
        let connection = listener.child()?;
        let sibling = root.child()?;
        assert!(!connection.is_cancelled());

        connection.cancel();
        assert!(connection.is_cancelled());
        assert!(!listener.is_cancelled());
        assert!(!root.is_cancelled());

        let waiter = tokio::spawn({
            let sibling = sibling.clone();
            async move { sibling.cancelled().await }
        });
        root.cancel();
        assert!(listener.is_cancelled());
        assert!(sibling.is_cancelled());
        waiter.await.map_err(|_| RuntimeError::Cancelled)?;
        Ok(())
    }

    #[tokio::test]
    async fn a_child_of_a_cancelled_parent_starts_cancelled_and_resolves_at_once()
    -> Result<(), RuntimeError> {
        let root = CancellationToken::root();
        root.cancel();
        let child = root.child()?;
        assert!(child.is_cancelled());
        child.cancelled().await;
        Ok(())
    }

    #[test]
    fn the_child_ceiling_holds_until_dropped_children_are_pruned() -> Result<(), RuntimeError> {
        let root = CancellationToken::root();
        let mut held = Vec::with_capacity(MAX_CHILD_TOKENS);
        for _ in 0..MAX_CHILD_TOKENS {
            held.push(root.child()?);
        }
        assert_eq!(root.child().err(), Some(RuntimeError::LimitExceeded));
        assert_eq!(root.live_children(), MAX_CHILD_TOKENS);
        held.clear();
        let survivor = root.child()?;
        assert_eq!(root.live_children(), 1);
        drop(survivor);
        assert_eq!(root.live_children(), 0);
        Ok(())
    }
}
