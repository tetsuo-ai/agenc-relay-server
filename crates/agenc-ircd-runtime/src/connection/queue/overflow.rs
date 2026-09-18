//! Committed demands beyond the fixed entry ring (spec 15.3; spec 19.2).
//!
//! The ring inside the connection state holds the demands the open-response
//! ceiling admits without any allocation. A demand reserved beyond it brings
//! one charged cell that `prepare` allocates, so `commit` links it without
//! allocating and the sink stays bounded by its byte and item ceilings, never
//! by how many small demands it holds. Cells form two stacks: `commit` pushes
//! on `back`, the writer pops from `front`, and `back` is relinked into
//! `front` when `front` drains. Relinking moves cells and allocates nothing.

use super::Response;
use crate::budget::{ALLOCATION_BOOKKEEPING_BYTES, MEMORY_QUANTUM_BYTES, MemoryPermit};
use crate::connection::sink::QueueAllocationError;

/// The exact charge of one overflow cell allocation (spec 19.2).
pub(crate) const OVERFLOW_CELL_CHARGE: u64 = (size_of::<OverflowNode>() as u64)
    .saturating_add(ALLOCATION_BOOKKEEPING_BYTES)
    .div_ceil(MEMORY_QUANTUM_BYTES)
    .saturating_mul(MEMORY_QUANTUM_BYTES);

/// One committed demand and the cell behind it.
pub(crate) struct OverflowNode {
    // Fields drop in declaration order: free the frames before their permit.
    response: Response,
    _backing: Option<MemoryPermit>,
    next: OverflowCell,
}

/// A heap cell of exactly one node; an empty cell created by `Default` owns
/// no allocation.
#[derive(Default)]
pub(crate) struct OverflowCell(Vec<OverflowNode>);

impl OverflowCell {
    /// Allocates the one-node capacity its reservation charged.
    pub(crate) fn allocate() -> Result<Self, QueueAllocationError> {
        let mut cell = Vec::new();
        cell.try_reserve_exact(1)
            .map_err(|_| QueueAllocationError::AllocationFailed)?;
        Ok(Self(cell))
    }

    fn is_vacant(&self) -> bool {
        self.0.is_empty()
    }
}

/// The ordered demands committed beyond the ring.
#[derive(Default)]
pub(super) struct OverflowQueue {
    front: OverflowCell,
    back: OverflowCell,
}

impl OverflowQueue {
    /// Links a committed demand last. The cell already has its capacity, so
    /// this never allocates; a cell without capacity returns the response.
    pub(super) fn push_back(
        &mut self,
        mut cell: OverflowCell,
        response: Response,
        backing: Option<MemoryPermit>,
    ) -> Result<(), Response> {
        if cell.0.capacity() == 0 || !cell.is_vacant() {
            return Err(response);
        }
        cell.0.push(OverflowNode {
            response,
            _backing: backing,
            next: std::mem::take(&mut self.back),
        });
        self.back = cell;
        Ok(())
    }

    /// Returns the commit sequence of the oldest demand.
    pub(super) fn front_sequence(&mut self) -> Option<u64> {
        self.front_node().map(|node| node.response.sequence)
    }

    /// Borrows the oldest demand's response.
    pub(super) fn front_response(&mut self) -> Option<&mut Response> {
        self.front_node().map(|node| &mut node.response)
    }

    /// Removes the oldest demand: its cell is freed first, then its frames,
    /// then its permit.
    pub(super) fn remove_front(&mut self) {
        let mut cell = std::mem::take(&mut self.front);
        if let Some(mut node) = cell.0.pop() {
            self.front = std::mem::take(&mut node.next);
            drop(cell);
            drop(node);
        }
    }

    /// Releases every demand without recursing through the chain.
    pub(super) fn clear(&mut self) {
        while self.front_node().is_some() {
            self.remove_front();
        }
    }

    /// Visits every queued response in no particular order.
    pub(super) fn responses(&self) -> impl Iterator<Item = &Response> {
        chain(&self.front).chain(chain(&self.back))
    }

    fn front_node(&mut self) -> Option<&mut OverflowNode> {
        if self.front.is_vacant() {
            self.relink();
        }
        self.front.0.first_mut()
    }

    /// Moves `back`, newest first, onto `front`, oldest first.
    fn relink(&mut self) {
        let mut pending = std::mem::take(&mut self.back);
        while let Some(node) = pending.0.first_mut() {
            let rest = std::mem::take(&mut node.next);
            node.next = std::mem::take(&mut self.front);
            self.front = pending;
            pending = rest;
        }
    }
}

impl Drop for OverflowQueue {
    fn drop(&mut self) {
        self.clear();
    }
}

fn chain(cell: &OverflowCell) -> impl Iterator<Item = &Response> {
    std::iter::successors(cell.0.first(), |node| node.next.0.first()).map(|node| &node.response)
}
