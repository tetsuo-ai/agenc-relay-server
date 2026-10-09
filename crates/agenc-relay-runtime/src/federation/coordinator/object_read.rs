//! A fresh object read keeps the original request until authorization and atomic staging resume.
#![forbid(unsafe_code)]

mod io;

use super::{FederationCoordinator, Violation, companion};
use crate::bridge::StorageReadId;
use crate::budget::MemoryPermit;
use crate::e2ee::coordinator::object_read::{PendingRequest, Resolved};
use crate::e2ee::coordinator::response_read::Identity;
use crate::federation::LinkId;
use crate::state_core::StateCoreContext;
use agenc_relay_e2ee::ObjectId;
use agenc_relay_storage::{ReadPlan, TableId};
use agenc_relay_types::ServerId;

pub(super) use io::completed;

pub(super) struct Pending {
    operation: PendingRequest,
    identity: Identity,
    id: StorageReadId,
    /// The coordinator's own commits when the read was submitted.
    own_commits: u64,
    link: LinkId,
    base_epoch: u64,
    _metadata: MemoryPermit,
    _raw: MemoryPermit,
    _decode: MemoryPermit,
}

pub(super) fn owns(coordinator: &FederationCoordinator, id: StorageReadId) -> bool {
    coordinator
        .companion_object_read
        .as_ref()
        .is_some_and(|read| read.id == id)
}

pub(super) fn submit(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    operation: PendingRequest,
) -> Result<(), Violation> {
    if coordinator.replay_io_busy()
        || coordinator.pending.is_some()
        || coordinator.loader.blocks_admission()
        || context.in_flight()
        || context.pending_len() != 0
        || context.is_quiescing()
    {
        return Err(Violation::Ceiling);
    }
    let identity = Identity {
        peer,
        correlation: operation.complete.correlation,
        request_object_id: *ObjectId::compute(&operation.complete.request).as_bytes(),
    };
    let base_epoch = coordinator
        .peers
        .get(&peer)
        .ok_or(Violation::Phase)?
        .client_resync_epoch;
    super::response_read::validate_link(coordinator, context, link, identity, base_epoch)?;
    if coordinator
        .companion_exec
        .as_ref()
        .is_none_or(|executor| executor.has_pending())
    {
        return Err(Violation::Phase);
    }
    let metadata_bytes = operation
        .complete
        .request
        .len()
        .checked_add(operation.complete.payload.as_ref().map_or(0, Vec::len))
        .and_then(|n| n.checked_add(65_536))
        .ok_or(Violation::Ceiling)?;
    let metadata = context
        .reserve_output_backing(metadata_bytes)
        .map_err(|_| Violation::Ceiling)?;
    let raw = context
        .reserve_output_backing(io::RAW_BYTES)
        .map_err(|_| Violation::Ceiling)?;
    let decode = context
        .reserve_output_backing(io::DECODE_BYTES)
        .map_err(|_| Violation::Ceiling)?;
    let key = agenc_relay_storage::e2ee_records::object_key(&operation.request.object_id)
        .map_err(|_| Violation::Codec)?;
    let id = context
        .submit_storage_read(ReadPlan::exact(TableId::E2eeObject, key))
        .map_err(|_| Violation::Ceiling)?;
    coordinator.companion_object_read = Some(Box::new(Pending {
        operation,
        identity,
        id,
        own_commits: coordinator.own_commits,
        link,
        base_epoch,
        _metadata: metadata,
        _raw: raw,
        _decode: decode,
    }));
    Ok(())
}

/// Whether the read is still current once its link is checked: no batch is
/// open, since its completion waits for one, and no batch of the
/// coordinator's own committed since it was submitted. A commit another
/// router made leaves it current, since no other router writes companion
/// rows.
fn validate(
    coordinator: &FederationCoordinator,
    context: &StateCoreContext,
    pending: &Pending,
) -> Result<bool, Violation> {
    super::response_read::validate_link(
        coordinator,
        context,
        pending.link,
        pending.identity,
        pending.base_epoch,
    )?;
    if context.in_flight() || context.pending_len() != 0 {
        return Err(Violation::Phase);
    }
    Ok(coordinator.own_commits == pending.own_commits)
}
