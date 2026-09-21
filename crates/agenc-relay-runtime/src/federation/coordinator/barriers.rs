//! A barrier's coverage changes in the same transaction as its stream cursor.
#![forbid(unsafe_code)]

use super::{FederationCoordinator, OpenBarrier, Violation};
use crate::state_core::durable::AccountServiceDurableWrite;
use crate::state_core::projector::barrier;
use agenc_relay_storage::e2ee_records::delivery_recovery::DeliveryBarrierFields;
use agenc_relay_types::ServerId;

pub(super) enum Side {
    Base,
    Companion,
}

pub(super) struct Prepared {
    peer: ServerId,
    before: OpenBarrier,
    after: OpenBarrier,
}

pub(super) fn prepare(
    coordinator: &FederationCoordinator,
    peer: ServerId,
    side: Side,
    sequence: u64,
    event_id: [u8; 16],
) -> Result<Option<Box<Prepared>>, Violation> {
    let Some(before) = coordinator.barriers.get(&peer) else {
        return Ok(None);
    };
    let (endpoint, covered) = match side {
        Side::Base => (before.base(), before.base_acked()),
        Side::Companion => (before.companion(), before.companion_acked()),
    };
    if sequence < endpoint.first() {
        return Ok(None);
    }
    if sequence != endpoint.last() || event_id != endpoint.final_event_id() {
        return Err(Violation::Acknowledgement);
    }
    if covered {
        return Ok(None);
    }
    let after = OpenBarrier::new(DeliveryBarrierFields {
        scope: *before.scope(),
        mutation_id: before.mutation_id(),
        state_generation: before.state_generation(),
        part_count: before.part_count(),
        base: *before.base(),
        companion: *before.companion(),
        base_acked: before.base_acked() || matches!(side, Side::Base),
        companion_acked: before.companion_acked() || matches!(side, Side::Companion),
    })
    .map_err(|_| Violation::Codec)?;
    Ok(Some(Box::new(Prepared {
        peer,
        before: before.clone(),
        after,
    })))
}

impl Prepared {
    pub(super) fn write(&self, revision: u64) -> Result<AccountServiceDurableWrite, Violation> {
        if self.after.base_acked() && self.after.companion_acked() {
            barrier::delete(&self.after)
        } else {
            barrier::write(&self.after, revision)
        }
        .map_err(|_| Violation::Codec)
    }

    pub(super) fn apply(self, coordinator: &mut FederationCoordinator) -> Result<(), Violation> {
        if coordinator.barriers.get(&self.peer) != Some(&self.before) {
            return Err(Violation::Codec);
        }
        coordinator.barriers.insert(self.peer, self.after);
        Ok(())
    }
}
