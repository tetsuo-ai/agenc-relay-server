//! The complete owner pass precedes every authoritative pending page read.
#![forbid(unsafe_code)]

use super::super::super::CompanionFault;
use super::super::pages::{PageIndex, Validator};
use crate::budget::BackingReservationPort;
use agenc_ircd_storage::StoredKey;
use agenc_ircd_storage::e2ee_records::delivery_recovery::{
    CutPhase, DeliveryOwner, DeliveryRecoveryRow,
};
use agenc_ircd_types::ServerId;
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Pending {
    started: bool,
    active: Option<(ServerId, Validator)>,
    pages: BTreeMap<ServerId, PageIndex>,
}

impl Pending {
    pub(super) const fn started(&self) -> bool {
        self.started
    }

    pub(super) fn next(
        &mut self,
        owners: &BTreeMap<ServerId, DeliveryOwner>,
        backing: &BackingReservationPort,
    ) -> Result<Option<StoredKey>, CompanionFault> {
        self.started = true;
        if let Some((_, validator)) = &self.active {
            return validator.next_key();
        }
        let next = owners.iter().find(|(peer, owner)| {
            matches!(owner.phase(), CutPhase::Pending { .. }) && !self.pages.contains_key(peer)
        });
        let Some((peer, owner)) = next else {
            return Ok(None);
        };
        let validator = Validator::new(owner.clone(), backing)?;
        let key = validator.next_key()?;
        self.active = Some((*peer, validator));
        Ok(key)
    }

    pub(super) fn admit(&mut self, key: &StoredKey, body: &[u8]) -> Result<(), CompanionFault> {
        let (_, validator) = self.active.as_mut().ok_or(CompanionFault::Storage)?;
        let DeliveryRecoveryRow::CutPage(page) =
            DeliveryRecoveryRow::decode_at(key, body).map_err(|_| CompanionFault::Storage)?
        else {
            return Err(CompanionFault::Storage);
        };
        validator.admit(key, body, &page)?;
        if validator.next_key()?.is_none() {
            let (peer, validator) = self.active.take().ok_or(CompanionFault::Storage)?;
            let (_, pages) = validator.finish()?;
            if self.pages.insert(peer, pages).is_some() {
                return Err(CompanionFault::Storage);
            }
        }
        Ok(())
    }

    pub(super) fn take(&mut self, peer: ServerId) -> Result<PageIndex, CompanionFault> {
        self.pages.remove(&peer).ok_or(CompanionFault::Storage)
    }

    pub(super) fn inventory(
        &self,
        owners: &BTreeMap<ServerId, DeliveryOwner>,
        key: &StoredKey,
        body: &[u8],
    ) -> Result<(), CompanionFault> {
        if !self.started || self.active.is_some() {
            return Err(CompanionFault::Storage);
        }
        let DeliveryRecoveryRow::CutPage(page) =
            DeliveryRecoveryRow::decode_at(key, body).map_err(|_| CompanionFault::Storage)?
        else {
            return Err(CompanionFault::Storage);
        };
        let identity = page.identity();
        let peer = ServerId::from_bytes(identity.target_server_id());
        let Some(owner) = owners.get(&peer) else {
            return Ok(());
        };
        if !matches!(owner.phase(), CutPhase::Pending { .. })
            || identity.token() != owner.cut().token()
            || identity.delivery_generation() != owner.cut().delivery_generation()
        {
            return Ok(());
        }
        page.validate_for(owner)
            .map_err(|_| CompanionFault::Storage)?;
        let pages = self.pages.get(&peer).ok_or(CompanionFault::Storage)?;
        if !pages.matches(identity.page_sequence() as usize, body) {
            return Err(CompanionFault::Storage);
        }
        Ok(())
    }
}
