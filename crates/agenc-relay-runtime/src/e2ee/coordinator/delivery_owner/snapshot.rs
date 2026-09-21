//! A live cut keeps captured references or a validated durable page index.
#![forbid(unsafe_code)]

use super::super::{CompanionFault, sync::Snapshot};
use super::{
    capture::{Capture, CapturedEntry},
    pages::PageIndex,
};
use agenc_relay_storage::e2ee_records::delivery_recovery::{
    CutPhase, DeliveryOwner, RetirementReason,
};

pub(crate) enum Pages {
    Captured(Capture),
    Stored(PageIndex),
}

impl Pages {
    pub(crate) fn page_count(&self) -> usize {
        match self {
            Self::Captured(capture) => capture.page_count(),
            Self::Stored(index) => index.len(),
        }
    }

    pub(crate) fn total_object_bytes(&self) -> u64 {
        match self {
            Self::Captured(capture) => capture.total_object_bytes(),
            Self::Stored(index) => index.total_object_bytes(),
        }
    }

    pub(crate) fn cursor(&self, page: usize) -> Option<[u8; 32]> {
        match self {
            Self::Captured(capture) => capture.cursor(page),
            Self::Stored(index) => index.cursor(page),
        }
    }

    pub(crate) fn page(&self, page: usize) -> Result<&[CapturedEntry], CompanionFault> {
        match self {
            Self::Captured(capture) => capture.page(page),
            Self::Stored(_) => Err(CompanionFault::Storage),
        }
    }
}

impl Snapshot {
    pub(super) fn restored(
        owner: &DeliveryOwner,
        pages: PageIndex,
        stored_version: (u64, u64),
    ) -> Result<Self, CompanionFault> {
        let CutPhase::Pending {
            offered_pages,
            deadline,
        } = owner.phase()
        else {
            return Err(CompanionFault::Storage);
        };
        let observed = super::clock::sample();
        let retirement = match observed {
            Ok(sample) => sample.observe(deadline, None).err(),
            Err(reason) => Some(reason),
        };
        Ok(Self {
            cut: super::cut(owner),
            scope: *owner.scope(),
            capture: Pages::Stored(pages),
            pages_sent: offered_pages as usize,
            expires_at_millis: 0,
            deadline,
            observed: observed.ok(),
            retirement,
            stored_version: Some(stored_version),
        })
    }

    pub(crate) fn observe_at(
        &mut self,
        now_millis: u64,
        host: &dyn super::super::sync::CompanionHost,
    ) -> Result<(), RetirementReason> {
        if let Some(reason) = self.retirement {
            return Err(reason);
        }
        let result = self.observe_inner(now_millis, host);
        if let Err(reason) = result {
            self.retirement = Some(reason);
        }
        result
    }

    fn observe_inner(
        &mut self,
        now_millis: u64,
        host: &dyn super::super::sync::CompanionHost,
    ) -> Result<(), RetirementReason> {
        let sample = host.cut_clock_sample()?;
        self.deadline = sample.observe(self.deadline, self.observed)?;
        self.observed = Some(sample);
        let remaining = u64::try_from(sample.remaining(self.deadline)?.as_millis())
            .map_err(|_| RetirementReason::ClockInvalid)?;
        self.expires_at_millis = now_millis
            .checked_add(remaining)
            .ok_or(RetirementReason::ClockInvalid)?;
        Ok(())
    }
}
