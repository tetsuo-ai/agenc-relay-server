//! A new authenticated coordinator must durably fence collecting old-incarnation work.

use super::{EdgeFederation, PendingCommit, Violation};
use crate::state_core::StateCoreContext;
use agenc_ircd_storage::e2ee_records::barrier::{BarrierPart, BarrierStage};

/// The collecting head and remaining immutable rows of a fenced barrier.
/// Missing parts are allowed only after its coordinator identity was fenced.
pub(super) struct FencedBarrier {
    pub(super) stage: BarrierStage,
    pub(super) parts: Vec<BarrierPart>,
}

pub(super) fn needed(edge: &EdgeFederation) -> bool {
    let Some(live) = edge.live.as_ref() else {
        return false;
    };
    edge.barrier.open.as_ref().is_some_and(|open| {
        let identity = open.assembly.identity();
        identity.coordinator_server_incarnation != *live.coordinator_incarnation.as_bytes()
            || identity.coordinator_recovery_epoch != *live.coordinator_epoch.as_bytes()
    })
}

pub(super) fn stage(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
) -> Result<(), Violation> {
    // The peer row records the new authenticated identity. The old projection
    // remains snapshot-required; no delivery cursor advances in the fence.
    super::events::stage_rows(
        edge,
        context,
        None,
        PendingCommit::BarrierFence,
        super::render::EventFanout::default().finish()?,
        |_, _, _| Vec::new(),
    )
}

pub(super) fn committed(edge: &mut EdgeFederation, context: &mut StateCoreContext) {
    if let Some(open) = edge.barrier.open.take() {
        let stage = open.assembly.head().clone();
        let parts = open.assembly.parts().into_iter().cloned().collect();
        edge.barrier
            .fenced
            .insert(stage.identity.mutation_id, FencedBarrier { stage, parts });
    }
    edge.barrier.ready = false;
    edge.installed_epoch = None;
    if let Some(live) = edge.live.as_ref() {
        edge.accepted_epoch = Some(live.coordinator_epoch);
        edge.installed_incarnation = Some(live.coordinator_incarnation);
    }
    edge.start_companion(context);
    super::sync::begin(edge, context);
}
