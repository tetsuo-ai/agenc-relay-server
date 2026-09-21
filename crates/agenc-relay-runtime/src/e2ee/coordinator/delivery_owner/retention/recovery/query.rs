//! Only full-scope, bounded delivery reads can be requested by this reader.
#![forbid(unsafe_code)]

use super::{CompanionFault, DeliveryOwner, PAGE_ROWS};
use agenc_relay_storage::e2ee_records::delivery_recovery::outbox::replay;
use agenc_relay_storage::e2ee_records::delivery_recovery::{DeliveryScope, outbox};
use agenc_relay_storage::{ReadPlan, TableId};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Kind {
    Owner,
    Ranges(u64),
    Rows(u64),
}

#[derive(Clone, Eq, PartialEq)]
pub(in crate::e2ee::coordinator) struct Query {
    pub(super) scope: DeliveryScope,
    pub(super) generation: u64,
    pub(super) kind: Kind,
}

impl Query {
    pub(super) fn new(current: &DeliveryOwner, kind: Kind) -> Self {
        Self {
            scope: *current.scope(),
            generation: current.cursor().generation(),
            kind,
        }
    }

    pub(in crate::e2ee::coordinator) fn plan(&self) -> Result<ReadPlan, CompanionFault> {
        match self.kind {
            Kind::Owner => replay::replay_owner_key(&self.scope, self.generation)
                .map(|key| ReadPlan::exact(TableId::E2eeState, key)),
            Kind::Ranges(first) => {
                replay::ack_ranges_from(&self.scope, self.generation, first, PAGE_ROWS)
            }
            Kind::Rows(first) => {
                outbox::outbox_from(&self.scope, self.generation, first, PAGE_ROWS)
            }
        }
        .map_err(|_| CompanionFault::Storage)
    }
}
