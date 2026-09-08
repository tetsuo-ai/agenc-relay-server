//! Mailbox metadata fixes the payload bodies that must remain resident after startup.
#![forbid(unsafe_code)]
use crate::budget::{BackingReservationPort, MemoryPermit};
use crate::e2ee::coordinator::CompanionFault;
use agenc_ircd_e2ee::object::IrcWireObjectKind as Kind;
use agenc_ircd_storage::StoredKey;
use agenc_ircd_storage::e2ee_records::{MailboxKind, MailboxRow};
use std::collections::BTreeMap;

pub(super) struct Selection {
    required: BTreeMap<[u8; 32], Kind>,
    backing: BackingReservationPort,
    _metadata: MemoryPermit,
}
impl Selection {
    pub(super) fn new(
        rows: &[(StoredKey, MailboxRow)],
        backing: BackingReservationPort,
    ) -> Result<Self, CompanionFault> {
        let bytes = rows
            .len()
            .checked_mul(128)
            .and_then(|n| n.checked_add(8192))
            .ok_or(CompanionFault::Ceiling)?;
        let metadata = backing
            .reserve(bytes)
            .map_err(|_| CompanionFault::Ceiling)?;
        let mut required = BTreeMap::new();
        for (key, row) in rows {
            let MailboxRow::Item { object_id, .. } = row else {
                continue;
            };
            let key = MailboxRow::parse_item_key(key).map_err(|_| CompanionFault::Storage)?;
            let kind = match key.kind {
                MailboxKind::Application => Kind::ApplicationMls,
                MailboxKind::Binding => Kind::ConversationBinding,
                MailboxKind::Welcome => Kind::WelcomeMls,
                MailboxKind::StagedReinit => Kind::StagedReinit,
            };
            if required
                .insert(*object_id, kind)
                .is_some_and(|previous| previous != kind)
            {
                return Err(CompanionFault::Storage);
            }
        }
        Ok(Self {
            required,
            backing,
            _metadata: metadata,
        })
    }
    pub(super) fn retain(&self, id: &[u8; 32], kind: Kind) -> Result<bool, CompanionFault> {
        if let Some(expected) = self.required.get(id) {
            return if *expected == kind {
                Ok(true)
            } else {
                Err(CompanionFault::Storage)
            };
        }
        Ok(!matches!(
            kind,
            Kind::ApplicationMls | Kind::WelcomeMls | Kind::StagedReinit | Kind::FederationEvent
        ))
    }
    pub(super) fn reserve(&self, capacity: usize) -> Result<MemoryPermit, CompanionFault> {
        let bytes = capacity.checked_add(128).ok_or(CompanionFault::Ceiling)?;
        self.backing
            .reserve(bytes)
            .map_err(|_| CompanionFault::Ceiling)
    }
    pub(super) fn complete(
        &self,
        existing: &BTreeMap<[u8; 32], Vec<u8>>,
        loaded: &BTreeMap<[u8; 32], Vec<u8>>,
    ) -> Result<(), CompanionFault> {
        for (id, expected) in &self.required {
            let bytes = loaded
                .get(id)
                .or_else(|| existing.get(id))
                .ok_or(CompanionFault::Storage)?;
            let (kind, _) = agenc_ircd_e2ee::object::IrcWireObject::peek(bytes)
                .map_err(|_| CompanionFault::Storage)?;
            if kind != *expected || agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes() != id {
                return Err(CompanionFault::Storage);
            }
        }
        Ok(())
    }
}
