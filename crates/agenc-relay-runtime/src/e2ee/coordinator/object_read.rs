//! A fresh lookup distinguishes unread storage from confirmed absence and scoped body bytes.
#![forbid(unsafe_code)]

use super::{CompanionFault, CompleteRequest};
use crate::budget::{BackingReservationPort, MemoryPermit};
use agenc_relay_e2ee::ObjectId;
use agenc_relay_e2ee::object::ArcWireObject;
use agenc_relay_storage::e2ee_records::{OBJECT_RECORD_KIND, ObjectRow};
use agenc_relay_storage::{PersistentRecordValue, StoredKey};
use std::sync::Arc;

/// The exact public-object lookup authorized by the original request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request {
    pub(crate) conversation_id: [u8; 32],
    pub(crate) object_id: [u8; 32],
}

/// An accepted lookup has not yet staged a result or consumed the origin sequence.
pub struct PendingRequest {
    pub(crate) complete: CompleteRequest,
    pub(crate) request: Request,
}

#[derive(Clone, Copy)]
pub(crate) enum Source<'a> {
    Unread,
    Resolved(&'a Resolved),
    /// Handler fixtures own their complete object set and have no external storage owner.
    #[cfg(test)]
    CompleteMemory,
}

pub(crate) struct Resolved {
    request: Request,
    bytes: Option<Vec<u8>>,
    _memory: Arc<MemoryPermit>,
}

impl Resolved {
    pub(crate) fn admit(
        request: Request,
        records: Vec<(StoredKey, PersistentRecordValue)>,
        backing: &BackingReservationPort,
    ) -> Result<Self, CompanionFault> {
        if records.len() > 1 {
            return Err(CompanionFault::Storage);
        }
        let size = records.first().map_or(0, |(_, value)| value.body().len());
        // Covers the body, outcome/effect copies, wrapped writes, pending response, and rendering.
        let capacity = size
            .checked_mul(12)
            .and_then(|n| n.checked_add(65_536))
            .ok_or(CompanionFault::Ceiling)?;
        let memory = backing
            .reserve(capacity)
            .map_err(|_| CompanionFault::Ceiling)?;
        let bytes = records
            .into_iter()
            .next()
            .map(|(key, value)| {
                if value.record_kind() != OBJECT_RECORD_KIND {
                    return Err(CompanionFault::Storage);
                }
                let row = ObjectRow::decode(value.body()).map_err(|_| CompanionFault::Storage)?;
                let (kind, _) =
                    ArcWireObject::peek(&row.bytes).map_err(|_| CompanionFault::Storage)?;
                if row.key().map_err(|_| CompanionFault::Storage)? != key
                    || ObjectId::compute(&row.bytes).as_bytes() != &request.object_id
                    || row.bytes.len() > kind.maximum_object_bytes()
                {
                    return Err(CompanionFault::Storage);
                }
                Ok(row.bytes)
            })
            .transpose()?;
        Ok(Self {
            request,
            bytes,
            _memory: Arc::new(memory),
        })
    }

    pub(crate) fn lookup(&self, request: Request) -> Result<Option<&[u8]>, CompanionFault> {
        if request != self.request {
            return Err(CompanionFault::Protocol);
        }
        Ok(self.bytes.as_deref())
    }

    pub(crate) fn uncached_id(&self) -> Option<[u8; 32]> {
        self.bytes.as_ref().map(|_| self.request.object_id)
    }

    pub(crate) fn backing(&self) -> Arc<MemoryPermit> {
        Arc::clone(&self._memory)
    }
}
