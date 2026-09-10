//! Bounded cleanup of expired barrier receipts, immutable parts, and payload roots.

use agenc_ircd_storage::e2ee_records::barrier::BarrierReceipt;
use agenc_ircd_storage::{StoredKey, TableId};
use std::collections::BTreeSet;

use super::{EdgeFederation, PendingCommit, Violation};
use crate::state_core::StateCoreContext;
use crate::state_core::durable::AccountServiceDurableWrite;

const MAX_CLEANUP_ROWS: usize = 999; // One additional peer row accompanies the batch.
const MAX_CLEANUP_BYTES: u64 = 16 * 1024 * 1024;

pub(super) fn cursors_cover(edge: &EdgeFederation, receipt: &BarrierReceipt) -> bool {
    let Some(((base_sequence, base_id), (generation, sequence, id))) =
        super::barrier::last_entries(receipt)
    else {
        return false;
    };
    let base_generation = receipt
        .entries
        .iter()
        .find(|entry| {
            entry.stream == agenc_ircd_storage::e2ee_records::barrier::CrossProfileStream::Base
        })
        .map_or(0, |entry| entry.delivery_generation);
    let base = edge.replica.projection_generation() > base_generation
        || (edge.replica.projection_generation() == base_generation
            && edge.cursor.is_some_and(|(seen, event)| {
                seen > base_sequence || (seen == base_sequence && *event.as_bytes() == base_id)
            }));
    let companion = edge.barrier.companion_generation > generation
        || (edge.barrier.companion_generation == generation
            && edge
                .barrier
                .companion_cursor
                .is_some_and(|(seen, event)| seen > sequence || (seen == sequence && event == id)));
    base && companion
}

impl EdgeFederation {
    /// Removes at most one bounded batch of expired barrier material.
    pub(crate) fn retain_barriers(
        &mut self,
        context: &mut StateCoreContext,
        companion_pending: bool,
    ) {
        if !cleanup_ready(self, context, companion_pending) {
            return;
        }
        if let Some(mutation) = self
            .barrier
            .fenced
            .iter()
            .find(|(_, barrier)| {
                !super::journal::needs_fenced_evidence(
                    self,
                    barrier.stage.identity.coordinator_state_generation,
                )
            })
            .map(|(mutation, _)| *mutation)
        {
            if let Err(violation) = cleanup_fenced(self, context, mutation) {
                self.fail_link(context, violation);
            }
            return;
        }
        let Ok(now) = context.utc_now() else {
            return;
        };
        let receipt = self
            .barrier
            .applied
            .values()
            .find(|receipt| receipt.retain_until <= now.get() && cursors_cover(self, receipt))
            .cloned();
        let Some(receipt) = receipt else {
            return;
        };
        if let Err(violation) = cleanup(self, context, &receipt) {
            self.fail_link(context, violation);
        }
    }
}

fn cleanup_ready(
    edge: &EdgeFederation,
    context: &StateCoreContext,
    companion_pending: bool,
) -> bool {
    context.drift().wall_trusted()
        && edge.commit.is_none()
        && context.pending_len() == 0
        && !context.in_flight()
        && !companion_pending
        && edge.pending.is_empty()
}

fn cleanup(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    receipt: &BarrierReceipt,
) -> Result<(), Violation> {
    let mut candidates = Vec::new();
    for index in 0..receipt.identity.part_count {
        candidates.push((
            TableId::E2eeState,
            receipt
                .identity
                .part_key(index)
                .map_err(|_| Violation::Codec)?,
        ));
    }
    let payloads: BTreeSet<_> = receipt
        .entries
        .iter()
        .filter_map(|entry| entry.payload_object_id)
        .collect();
    for id in payloads {
        if !other_payload_root(edge, receipt.identity.mutation_id, &id) {
            candidates.push((
                TableId::E2eeObject,
                StoredKey::new(id.to_vec()).map_err(|_| Violation::Codec)?,
            ));
        }
    }
    // The head survives every partial cleanup. Its entries identify remaining
    // immutable rows and payloads after a crash, without a new storage format.
    candidates.push((
        TableId::E2eeState,
        receipt.identity.head_key().map_err(|_| Violation::Codec)?,
    ));
    let (writes, finished) = bounded_deletions(context, candidates)?;
    if writes.is_empty() {
        return Err(Violation::Consistency);
    }
    super::events::stage_rows(
        edge,
        context,
        None,
        PendingCommit::BarrierCleanup {
            mutation_id: receipt.identity.mutation_id,
            finished,
        },
        super::render::EventFanout::default().finish()?,
        |_, _, _| Ok(writes),
    )
}

fn other_payload_root(edge: &EdgeFederation, mutation: [u8; 16], id: &[u8; 32]) -> bool {
    let retained = edge.barrier.applied.values().any(|other| {
        other.identity.mutation_id != mutation
            && other
                .entries
                .iter()
                .any(|entry| entry.payload_object_id.as_ref() == Some(id))
    });
    let staged = edge.barrier.open.as_ref().is_some_and(|open| {
        open.assembly
            .parts()
            .into_iter()
            .any(|part| part.payload_object_id.as_ref() == Some(id))
    });
    let fenced = edge.barrier.fenced.iter().any(|(other, barrier)| {
        *other != mutation
            && barrier
                .parts
                .iter()
                .any(|part| part.payload_object_id.as_ref() == Some(id))
    });
    retained || staged || fenced
}

fn bounded_deletions(
    context: &StateCoreContext,
    candidates: Vec<(TableId, StoredKey)>,
) -> Result<(Vec<AccountServiceDurableWrite>, bool), Violation> {
    let mut writes = Vec::new();
    let mut bytes = 1024_u64; // Reserve the small peer row in this checkpoint.
    for (table, key) in candidates {
        let Some(existing) = context
            .index()
            .existing(table, &key)
            .map_err(|_| Violation::Ceiling)?
        else {
            continue;
        };
        let next = bytes
            .checked_add(u64::from(existing.sealed_record_bytes()))
            .ok_or(Violation::Ceiling)?;
        if writes.len() >= MAX_CLEANUP_ROWS || next > MAX_CLEANUP_BYTES {
            return Ok((writes, false));
        }
        writes.push(AccountServiceDurableWrite::delete(table, key).map_err(|_| Violation::Codec)?);
        bytes = next;
    }
    Ok((writes, true))
}

pub(super) fn committed(edge: &mut EdgeFederation, mutation: [u8; 16], finished: bool) {
    if finished {
        edge.barrier.applied.remove(&mutation);
        edge.barrier.fenced.remove(&mutation);
        edge.barrier.replayed.remove(&mutation);
    }
}

fn cleanup_fenced(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    mutation: [u8; 16],
) -> Result<(), Violation> {
    let fenced = edge
        .barrier
        .fenced
        .get(&mutation)
        .ok_or(Violation::Consistency)?;
    let mut candidates = Vec::new();
    let mut payloads = BTreeSet::new();
    for part in &fenced.parts {
        if let Some(id) = part.payload_object_id
            && payloads.insert(id)
            && !other_payload_root(edge, mutation, &id)
        {
            // Payload precedes its last durable reference: a truncated batch
            // never loses the only key identifying an unfinished cleanup.
            candidates.push((
                TableId::E2eeObject,
                StoredKey::new(id.to_vec()).map_err(|_| Violation::Codec)?,
            ));
        }
        candidates.push((
            TableId::E2eeState,
            part.identity
                .part_key(part.part_index)
                .map_err(|_| Violation::Codec)?,
        ));
    }
    candidates.push((
        TableId::E2eeState,
        fenced
            .stage
            .identity
            .head_key()
            .map_err(|_| Violation::Codec)?,
    ));
    let (writes, finished) = bounded_deletions(context, candidates)?;
    if writes.is_empty() {
        return Err(Violation::Consistency);
    }
    super::events::stage_rows(
        edge,
        context,
        None,
        PendingCommit::BarrierCleanup {
            mutation_id: mutation,
            finished,
        },
        super::render::EventFanout::default().finish()?,
        |_, _, _| Ok(writes),
    )
}
