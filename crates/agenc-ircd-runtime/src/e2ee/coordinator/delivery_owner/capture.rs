//! Charged immutable references pin a cut without duplicating its object payloads.
#![forbid(unsafe_code)]

use agenc_ircd_e2ee::ids::federation_snapshot_digest_iter;
use agenc_ircd_e2ee::limits::{
    MAX_FEDERATION_STATE_ENTRIES_PER_EDGE, MAX_FEDERATION_STATE_SNAPSHOT_BYTES_PER_EDGE,
};
use agenc_ircd_storage::e2ee_records::delivery_recovery::ENTRIES_PER_PAGE;
use agenc_ircd_types::{EntropySource, ServerId};

use super::super::sync::CompanionHost;
use super::super::{CompanionFault, CompanionState};
use crate::budget::MemoryPermit;

pub(crate) struct CapturedEntry {
    pub(crate) conversation: [u8; 32],
    pub(crate) object: [u8; 32],
}

pub(crate) struct Capture {
    entries: ChargedVec<CapturedEntry>,
    cursors: ChargedVec<[u8; 32]>,
    total_object_bytes: u64,
}

impl Capture {
    pub(crate) fn new(
        state: &CompanionState,
        peer: ServerId,
        host: &dyn CompanionHost,
        entropy: &mut dyn EntropySource,
    ) -> Result<Self, CompanionFault> {
        let count = state.entitlements.snapshot_iter(peer).count();
        if u64::try_from(count).map_err(|_| CompanionFault::Ceiling)?
            > MAX_FEDERATION_STATE_ENTRIES_PER_EDGE
        {
            return Err(CompanionFault::Ceiling);
        }
        let mut entries = reserved(count, host)?;
        let mut total = 0_u64;
        for conversation in state.entitlements.snapshot_iter(peer) {
            let object = state
                .conversations
                .get(&conversation)
                .ok_or(CompanionFault::Protocol)?
                .route_object_id;
            let bytes = state.objects.get(&object).ok_or(CompanionFault::Protocol)?;
            total = total
                .checked_add(u64::try_from(bytes.len()).map_err(|_| CompanionFault::Ceiling)?)
                .ok_or(CompanionFault::Ceiling)?;
            if total > MAX_FEDERATION_STATE_SNAPSHOT_BYTES_PER_EDGE {
                return Err(CompanionFault::Ceiling);
            }
            entries.values.push(CapturedEntry {
                conversation,
                object,
            });
        }
        let cursor_count = count.div_ceil(ENTRIES_PER_PAGE as usize).max(1) - 1;
        let mut cursors = reserved(cursor_count, host)?;
        for _ in 0..cursor_count {
            let mut cursor = [0; 32];
            entropy
                .fill_exact(&mut cursor)
                .map_err(|_| CompanionFault::Storage)?;
            cursors.values.push(cursor);
        }
        Ok(Self {
            entries,
            cursors,
            total_object_bytes: total,
        })
    }

    pub(crate) fn digest(
        &self,
        state_generation: u64,
        delivery_generation: u64,
        _host: &dyn CompanionHost,
    ) -> Result<[u8; 32], CompanionFault> {
        federation_snapshot_digest_iter(
            state_generation,
            delivery_generation,
            self.entries.values.len(),
            self.entries.values.iter().map(|entry| &entry.object),
        )
        .map_err(|_| CompanionFault::Ceiling)
    }

    pub(crate) fn entry_count(&self) -> Result<u32, CompanionFault> {
        u32::try_from(self.entries.values.len()).map_err(|_| CompanionFault::Ceiling)
    }

    pub(crate) fn page_count(&self) -> usize {
        self.entries
            .values
            .len()
            .div_ceil(ENTRIES_PER_PAGE as usize)
            .max(1)
    }

    pub(crate) const fn total_object_bytes(&self) -> u64 {
        self.total_object_bytes
    }

    pub(crate) fn cursor(&self, page: usize) -> Option<[u8; 32]> {
        self.cursors.values.get(page).copied()
    }

    pub(crate) fn page(&self, page: usize) -> Result<&[CapturedEntry], CompanionFault> {
        if page >= self.page_count() {
            return Err(CompanionFault::Protocol);
        }
        let start = page
            .checked_mul(ENTRIES_PER_PAGE as usize)
            .ok_or(CompanionFault::Ceiling)?;
        let end = start
            .checked_add(ENTRIES_PER_PAGE as usize)
            .ok_or(CompanionFault::Ceiling)?
            .min(self.entries.values.len());
        self.entries
            .values
            .get(start..end)
            .ok_or(CompanionFault::Protocol)
    }
}

struct ChargedVec<T> {
    values: Vec<T>,
    _backing: MemoryPermit,
}

fn reserved<T>(count: usize, host: &dyn CompanionHost) -> Result<ChargedVec<T>, CompanionFault> {
    let capacity = count
        .checked_mul(std::mem::size_of::<T>())
        .ok_or(CompanionFault::Ceiling)?;
    let backing = host.reserve_cut_backing(capacity)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| CompanionFault::Ceiling)?;
    if values.capacity().checked_mul(std::mem::size_of::<T>()) != Some(capacity) {
        return Err(CompanionFault::Ceiling);
    }
    Ok(ChargedVec {
        values,
        _backing: backing,
    })
}

#[cfg(test)]
mod tests;
