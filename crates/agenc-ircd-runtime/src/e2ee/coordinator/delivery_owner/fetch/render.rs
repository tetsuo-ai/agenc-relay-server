//! The immutable stored page uses the same exact BEGIN/ENTRY/END framing.
#![forbid(unsafe_code)]

use super::{CompanionFault, CompanionHost, Output};
use crate::budget::MemoryPermit;
use agenc_ircd_e2ee::ObjectId;
use agenc_ircd_e2ee::federation::frames::CompanionFrame;
use agenc_ircd_e2ee::wire::fragment::fragment_object;
use agenc_ircd_storage::e2ee_records::delivery_recovery::{
    DeliveryOwner, MAX_PAGE_BODY_BYTES, SnapshotPage,
};
use agenc_ircd_types::ServerId;

const OUTPUT_BACKING_BYTES: usize = MAX_PAGE_BODY_BYTES * 4 + 65_536;

pub(super) fn reserve(host: &dyn CompanionHost) -> Result<MemoryPermit, CompanionFault> {
    host.reserve_cut_backing(OUTPUT_BACKING_BYTES)
}

pub(super) fn stored(
    server: &str,
    peer: ServerId,
    owner: &DeliveryOwner,
    page: &SnapshotPage,
    host: &dyn CompanionHost,
) -> Result<Output, CompanionFault> {
    let memory = reserve(host)?;
    let cut = owner.cut();
    let target = *peer.as_bytes();
    let sequence = page.identity().page_sequence();
    let mut lines = vec![super::super::super::sync::line(
        server,
        &CompanionFrame::StateBegin {
            target_server_id: target,
            snapshot_token: cut.token(),
            state_generation: cut.state_generation(),
            delivery_generation: cut.delivery_generation(),
            page_sequence: sequence,
            total_entry_count: cut.entry_count(),
            page_entry_count: u32::try_from(page.entries().len())
                .map_err(|_| CompanionFault::Ceiling)?,
            snapshot_digest: cut.digest(),
        },
    )?];
    for entry in page.entries() {
        for fragment in fragment_object(entry.bytes()).map_err(|_| CompanionFault::Storage)? {
            lines.push(super::super::super::sync::line(
                server,
                &CompanionFrame::StateEntry {
                    target_server_id: target,
                    snapshot_token: cut.token(),
                    page_sequence: sequence,
                    conversation_id: entry.conversation_id(),
                    object_id: *ObjectId::compute(entry.bytes()).as_bytes(),
                    fragment,
                },
            )?);
        }
    }
    lines.push(super::super::super::sync::line(
        server,
        &CompanionFrame::StateEnd {
            target_server_id: target,
            snapshot_token: cut.token(),
            page_sequence: sequence,
            next_cursor: page.next_cursor(),
        },
    )?);
    Ok(Output {
        lines,
        _memory: std::sync::Arc::new(memory),
    })
}
