//! The origin table used for request classification follows the committed terminal row.
#![forbid(unsafe_code)]

use super::{
    FederationCoordinator, OriginEntry, OriginError, OriginKey, OriginStatus, StateCoreContext,
    Violation,
};
use agenc_relay_domain::federation::OperationKey;

pub(in super::super) struct TerminalOrigin {
    key: OriginKey,
    entry: OriginEntry,
    refused_generation: Option<u64>,
}

impl TerminalOrigin {
    pub(super) fn deletion(
        coordinator: &FederationCoordinator,
        key: OriginKey,
        generation: u64,
        next_sequence: u64,
        refused_generation: Option<u64>,
    ) -> Result<Self, OriginError> {
        let entry = coordinator
            .origins
            .proposed_deletion(key, generation, next_sequence)?;
        Ok(Self {
            key,
            entry,
            refused_generation,
        })
    }

    pub(in super::super) fn at_capacity(
        coordinator: &FederationCoordinator,
        request: &OperationKey,
    ) -> Result<Self, Violation> {
        let entry = coordinator
            .origins
            .origin(&request.origin)
            .ok_or(Violation::Origin)?;
        if entry.generation != request.generation || entry.next_sequence != request.sequence {
            return Err(Violation::Origin);
        }
        // A DEL may already cover queued, still executable requests. A full budget
        // ends admission at the first unaccepted request, retaining earlier results.
        if entry.status == OriginStatus::Live {
            return Self::deletion(
                coordinator,
                request.origin,
                request.generation,
                request.sequence,
                Some(request.generation),
            )
            .map_err(|_| Violation::Origin);
        }
        if entry.status != OriginStatus::Deleted
            || entry
                .deleted_after
                .is_none_or(|cut| request.sequence >= cut)
        {
            return Err(Violation::Origin);
        }
        let entry = OriginEntry {
            deleted_after: Some(request.sequence),
            ..entry
        };
        Ok(Self {
            key: request.origin,
            entry,
            refused_generation: Some(request.generation),
        })
    }

    pub(in super::super) fn fence(
        coordinator: &FederationCoordinator,
        key: OriginKey,
    ) -> Result<Self, Violation> {
        let before = coordinator.origins.origin(&key).ok_or(Violation::Origin)?;
        Ok(Self {
            key,
            entry: OriginEntry {
                status: OriginStatus::Fenced,
                ..before
            },
            refused_generation: None,
        })
    }

    pub(in super::super) fn row(
        &self,
        coordinator: &FederationCoordinator,
        revision: u64,
    ) -> Result<super::AccountServiceDurableWrite, Violation> {
        super::origin_entry_row(
            coordinator,
            self.key,
            self.entry,
            self.entry.next_sequence,
            revision,
        )
    }

    pub(in super::super) fn receipt(
        self,
        context: &StateCoreContext,
        revision: u64,
    ) -> TerminalReceipt {
        TerminalReceipt {
            origin: self,
            staged_after: context.head().storage_commit_sequence,
            revision,
        }
    }

    fn commit(
        self,
        coordinator: &mut FederationCoordinator,
        context: &StateCoreContext,
    ) -> Result<(), Violation> {
        let current = coordinator
            .origins
            .origin(&self.key)
            .ok_or(Violation::Origin)?;
        // A link loss may suspend the same declaration while the writer is busy.
        // Its generation, sequence, principal and declaration identity must still agree.
        if (OriginEntry {
            status: self.entry.status,
            deleted_after: self.entry.deleted_after,
            ..current
        }) != self.entry
        {
            return Err(Violation::Origin);
        }
        if current.status != OriginStatus::Fenced {
            coordinator.origins.restore_origin(self.key, self.entry);
        }
        if let Some(generation) = self.refused_generation {
            coordinator
                .refused_declarations
                .insert(self.key, generation);
        }
        if self.entry.status == OriginStatus::Deleted {
            super::close_sessions(coordinator, context, self.key.home_server_id, self.key);
            if let Some(generation) = coordinator
                .remote_carrier_for_origin(self.key.home_server_id, *self.key.origin_id.as_bytes())
            {
                coordinator.retire_remote_carrier(generation);
            }
        }
        Ok(())
    }
}

pub(in super::super) struct TerminalReceipt {
    origin: TerminalOrigin,
    pub(in super::super) staged_after: u64,
    revision: u64,
}

impl TerminalReceipt {
    pub(in super::super) fn published(
        self,
        coordinator: &mut FederationCoordinator,
        context: &StateCoreContext,
    ) -> bool {
        if self.staged_after.checked_add(1) == Some(context.head().storage_commit_sequence)
            && self.revision == context.domain().revision().get()
            && self.origin.commit(coordinator, context).is_ok()
        {
            true
        } else {
            super::super::startup::fail_restore(coordinator);
            false
        }
    }
}
