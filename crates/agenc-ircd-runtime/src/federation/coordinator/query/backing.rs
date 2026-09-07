//! One reservation covers query preparation, retained pages, and their receipt.

#![forbid(unsafe_code)]

use super::*;
use crate::budget::{
    ALLOCATION_BOOKKEEPING_BYTES, MEMORY_QUANTUM_BYTES, MemoryCharge, MemoryPermit,
};
use crate::state_core::query_usage::QueryUsageLease;
use crate::sync::Arc;
use agenc_ircd_federation_wire::WireValue;

/// The immutable snapshot has one quota lease even while two pages own backing.
pub(super) struct DirectoryQueryReservation {
    _backing: MemoryPermit,
    _usage: QueryUsageLease,
}

/// Root leaves remain allocated after the last cursor or retained page is removed.
pub(super) struct CursorRootReservation {
    _retained: MemoryPermit,
    _cursors: MemoryPermit,
}

impl CursorRootReservation {
    fn prepare(context: &StateCoreContext) -> Result<Self, DomainError> {
        let port = context.backing_reservations();
        let retained = port
            .reserve(root_backing_bytes::<Retained>()?)
            .map_err(|_| DomainError::ServerBusy)?;
        let cursors = port
            .reserve(root_backing_bytes::<
                agenc_ircd_domain::federation::LiveCursor,
            >()?)
            .map_err(|_| DomainError::ServerBusy)?;
        Ok(Self {
            _retained: retained,
            _cursors: cursors,
        })
    }
}

fn root_backing_bytes<Value>() -> Result<usize, DomainError> {
    // Pinned Rust 1.98 BTree leaf: 11 keys/values, a parent pointer, and two
    // u16 fields. Cover alignment between all five fields and the final tail.
    const ROOT_CAPACITY: usize = 11;
    let alignment = align_of::<Value>().max(align_of::<usize>());
    size_of::<Value>()
        .checked_add(size_of::<[u8; 32]>())
        .and_then(|n| n.checked_mul(ROOT_CAPACITY))
        .and_then(|n| n.checked_add(size_of::<usize>() + 2 * size_of::<u16>()))
        .and_then(|n| n.checked_add(alignment.checked_mul(6)?))
        .ok_or(DomainError::ServerBusy)
}

/// A receipt can retire only the successor made by this exact reservation.
pub(in super::super) struct QueryReceipt {
    pub(super) successor: Option<[u8; 32]>,
    pub(super) owner: Arc<DirectoryQueryReservation>,
}

impl DirectoryQueryReservation {
    pub(super) fn prepare(
        context: &StateCoreContext,
        identity: &QueryIdentity,
        bounds: &shape::Bounds,
    ) -> Result<Arc<Self>, DomainError> {
        let bytes = backing_bytes(bounds, identity.arm.len())?;
        let charge =
            MemoryCharge::allocation(u64::try_from(bytes).map_err(|_| DomainError::ServerBusy)?)
                .map_err(|_| DomainError::ServerBusy)?;
        let usage = context
            .query_reservations(identity.user_id)
            .reserve_snapshot(bounds.rows.max(1), charge.bytes())
            .map_err(|_| DomainError::ServerBusy)?;
        let backing = context
            .backing_reservations()
            .reserve(bytes)
            .map_err(|_| DomainError::ServerBusy)?;
        Ok(Arc::new(Self {
            _backing: backing,
            _usage: usage,
        }))
    }
}

fn backing_bytes(bounds: &shape::Bounds, arm: usize) -> Result<usize, DomainError> {
    // Both owned encodings coexist during conversion. Charge each string and
    // nested vector's worst size-class slack, not just their serialized bytes.
    let padding = usize::try_from(ALLOCATION_BOOKKEEPING_BYTES + MEMORY_QUANTUM_BYTES)
        .map_err(|_| DomainError::ServerBusy)?;
    let middle = bounds.middle_parameters;
    let allocations = middle.checked_mul(3).and_then(|n| n.checked_add(9));
    let tables = middle
        .checked_mul(size_of::<String>() + size_of::<SchemaObject>() + size_of::<WireValue>());
    let per_frame = allocations
        .and_then(|n| n.checked_mul(padding))
        .and_then(|n| n.checked_add(tables?))
        .and_then(|n| n.checked_add(2 * agenc_ircd_client_wire::MAX_COMMAND_BYTES))
        .and_then(|n| {
            n.checked_add(
                4 * size_of::<WireValue>()
                    + 2 * size_of::<WireMessage>()
                    + 3 * size_of::<SchemaObject>()
                    + size_of::<ReplySize>(),
            )
        })
        .ok_or(DomainError::ServerBusy)?;
    // Result encoding/staging scratch is page bounded. The fixed allowance also
    // owns additional BTree nodes, the Arc header, and transient rendering chunks.
    // The two residual root leaves have a separate table-lifetime reservation.
    bounds
        .frames
        .checked_mul(per_frame)
        .and_then(|n| n.checked_add(bounds.scratch_bytes))
        .and_then(|n| n.checked_add(arm.checked_mul(4)?))
        .and_then(|n| n.checked_add(8 * crate::query_pages::MAX_PAGE_BYTES))
        .ok_or(DomainError::ServerBusy)
}

impl Queries {
    pub(super) fn reserve_roots(&mut self, context: &StateCoreContext) -> Result<(), DomainError> {
        if self.root_backing.is_none() {
            self.root_backing = Some(CursorRootReservation::prepare(context)?);
        }
        Ok(())
    }

    pub(in super::super) fn reject_page(&mut self, receipt: QueryReceipt, now: MonotonicTick) {
        let Some(cursor) = receipt.successor else {
            return;
        };
        let owned = self.retained.get(&cursor).is_some_and(|retained| {
            retained
                .reservation
                .as_ref()
                .is_some_and(|owner| Arc::ptr_eq(owner, &receipt.owner))
        });
        if owned {
            self.retained.remove(&cursor);
            let _released = self.cursors.replace(&cursor, None, now);
        }
    }
}
