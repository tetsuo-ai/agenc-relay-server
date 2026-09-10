//! Requests expose bounded plans while keeping their expected phase private.
#![forbid(unsafe_code)]

use super::{CompanionFault, recovery};
use agenc_ircd_storage::{ReadPlan, StoredKey, TableId};

#[derive(Clone, Eq, PartialEq)]
pub(super) enum Kind {
    Metadata(recovery::Query),
    Bodies(Vec<[u8; 32]>),
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct Request {
    pub(super) kind: Kind,
}

impl Request {
    pub(crate) fn table(&self) -> TableId {
        match self.kind {
            Kind::Metadata(_) => TableId::E2eeState,
            Kind::Bodies(_) => TableId::E2eeObject,
        }
    }

    pub(crate) fn plan(&self) -> Result<ReadPlan, CompanionFault> {
        match &self.kind {
            Kind::Metadata(query) => query.plan(),
            Kind::Bodies(ids) => {
                let keys = ids
                    .iter()
                    .map(|id| StoredKey::new(id.to_vec()))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| CompanionFault::Storage)?;
                ReadPlan::exact_keys(TableId::E2eeObject, keys).map_err(|_| CompanionFault::Storage)
            }
        }
    }

    pub(crate) fn record_limit(&self) -> usize {
        match &self.kind {
            Kind::Metadata(_) => 128,
            Kind::Bodies(ids) => ids.len(),
        }
    }

    pub(crate) fn sealed_record_limit(&self) -> usize {
        match self.kind {
            Kind::Metadata(_) => 8_192,
            Kind::Bodies(_) => 4_194_304 + 8_192,
        }
    }

    pub(crate) fn sealed_page_limit(&self) -> usize {
        match &self.kind {
            Kind::Metadata(_) => 128 * 8_192,
            Kind::Bodies(ids) => super::BODY_BYTES as usize + ids.len() * 8_192,
        }
    }
}
