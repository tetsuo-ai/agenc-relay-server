//! One page is constructed under a reservation before entering the storage batch.
#![forbid(unsafe_code)]

use agenc_ircd_storage::e2ee_records::delivery_recovery::{
    DeliveryOwner, DeliveryRecoveryRow, SnapshotEntry, SnapshotPage, SnapshotPageIdentity,
};

use super::super::super::sync::{CompanionHost, Snapshot};
use super::super::super::{CompanionFault, CompanionState};
use crate::budget::MemoryPermit;
use crate::state_core::durable::AccountServiceDurableWrite;

// Input entries, row encoder, protocol wrapper, domain envelope, and semantic
// validation may coexist. Each encoding is bounded by the same complete page;
// the reservation remains owned until the staged write's receipt is consumed.
const PAGE_WORKING_BUFFERS: usize = 8;
const PAGE_RECORD_OVERHEAD: usize = 4_096;

pub(super) struct PageMemory {
    _buffers: [Option<MemoryPermit>; PAGE_WORKING_BUFFERS],
    entries: [Option<MemoryPermit>; 32],
}

pub(super) fn write(
    snapshot: &Snapshot,
    owner: &DeliveryOwner,
    page_index: usize,
    state: &CompanionState,
    host: &dyn CompanionHost,
) -> Result<(AccountServiceDurableWrite, PageMemory), CompanionFault> {
    let entries = snapshot.capture.page(page_index)?;
    let capacity = entries
        .iter()
        .try_fold(PAGE_RECORD_OVERHEAD, |total, entry| {
            total.checked_add(state.objects.get(&entry.object)?.len())
        })
        .ok_or(CompanionFault::Protocol)?;
    let mut memory = PageMemory {
        _buffers: std::array::from_fn(|_| None),
        entries: std::array::from_fn(|_| None),
    };
    for slot in &mut memory._buffers {
        *slot = Some(host.reserve_cut_backing(capacity)?);
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(entries.len())
        .map_err(|_| CompanionFault::Ceiling)?;
    for (entry, permit) in entries.iter().zip(&mut memory.entries) {
        let bytes = state
            .objects
            .get(&entry.object)
            .ok_or(CompanionFault::Protocol)?;
        *permit = Some(host.reserve_cut_backing(bytes.len())?);
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| CompanionFault::Ceiling)?;
        if owned.capacity() != bytes.len() {
            return Err(CompanionFault::Ceiling);
        }
        owned.extend_from_slice(bytes);
        values.push(
            SnapshotEntry::new(entry.conversation, owned).map_err(|_| CompanionFault::Storage)?,
        );
    }
    let identity = SnapshotPageIdentity::new(
        owner.scope().target_server_id(),
        owner.cut().delivery_generation(),
        owner.cut().token(),
        u32::try_from(page_index).map_err(|_| CompanionFault::Ceiling)?,
    )
    .map_err(|_| CompanionFault::Storage)?;
    let page = SnapshotPage::new(identity, values, snapshot.capture.cursor(page_index))
        .map_err(|_| CompanionFault::Storage)?;
    page.validate_for(owner)
        .map_err(|_| CompanionFault::Storage)?;
    let row = DeliveryRecoveryRow::CutPage(page);
    let key = row.key().map_err(|_| CompanionFault::Storage)?;
    let body = row.encode().map_err(|_| CompanionFault::Storage)?;
    drop(row);
    let write = super::super::super::request::state_row(
        agenc_ircd_storage::TableId::E2eeState,
        agenc_ircd_storage::e2ee_records::DELIVERY_RECOVERY_ROW_KIND,
        key,
        body,
    )
    .map_err(|_| CompanionFault::Storage)?;
    Ok((write, memory))
}
