//! A charged immutable page index and constant-memory whole-cut validation.
#![forbid(unsafe_code)]

use super::super::CompanionFault;
use crate::budget::{BackingReservationPort, MemoryPermit};
use agenc_relay_e2ee::ObjectId;
use agenc_relay_e2ee::ids::FederationSnapshotDigest;
use agenc_relay_storage::StoredKey;
use agenc_relay_storage::e2ee_records::delivery_recovery::{
    DeliveryOwner, SnapshotPage, SnapshotPageIdentity, cut_page_key,
};

/// No plaintext is retained by this entry. Its index is the exact page sequence.
#[derive(Clone, Copy)]
pub(super) struct PageMeta {
    body_id: [u8; 32],
    encoded_bytes: usize,
    next_cursor: Option<[u8; 32]>,
}

/// Values drop before their allocation's charge on every path.
pub(crate) struct PageIndex {
    values: Vec<PageMeta>,
    _backing: MemoryPermit,
    total_object_bytes: u64,
}

impl PageIndex {
    pub(super) fn len(&self) -> usize {
        self.values.len()
    }

    pub(super) const fn total_object_bytes(&self) -> u64 {
        self.total_object_bytes
    }

    fn reserved(count: usize, backing: &BackingReservationPort) -> Result<Self, CompanionFault> {
        let bytes = count
            .checked_mul(std::mem::size_of::<PageMeta>())
            .ok_or(CompanionFault::Ceiling)?;
        let permit = backing
            .reserve(bytes)
            .map_err(|_| CompanionFault::Ceiling)?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| CompanionFault::Ceiling)?;
        if values
            .capacity()
            .checked_mul(std::mem::size_of::<PageMeta>())
            != Some(bytes)
        {
            return Err(CompanionFault::Ceiling);
        }
        Ok(Self {
            values,
            _backing: permit,
            total_object_bytes: 0,
        })
    }

    pub(super) fn cursor(&self, index: usize) -> Option<[u8; 32]> {
        self.values.get(index).and_then(|page| page.next_cursor)
    }

    pub(super) fn matches(&self, index: usize, body: &[u8]) -> bool {
        self.values.get(index).is_some_and(|page| {
            page.encoded_bytes == body.len() && page.body_id == *ObjectId::compute(body).as_bytes()
        })
    }
}

/// Exists only after the complete owner scan, before any pending cut is usable.
pub(super) struct Validator {
    owner: DeliveryOwner,
    index: PageIndex,
    digest: FederationSnapshotDigest,
    entries: u32,
    object_bytes: u64,
    last_conversation: Option<[u8; 32]>,
}

impl Validator {
    pub(super) fn new(
        owner: DeliveryOwner,
        backing: &BackingReservationPort,
    ) -> Result<Self, CompanionFault> {
        let cut = owner.cut();
        let index = PageIndex::reserved(cut.page_count() as usize, backing)?;
        let digest = FederationSnapshotDigest::new(
            cut.state_generation(),
            cut.delivery_generation(),
            cut.entry_count() as usize,
        )
        .map_err(|_| CompanionFault::Storage)?;
        Ok(Self {
            owner,
            index,
            digest,
            entries: 0,
            object_bytes: 0,
            last_conversation: None,
        })
    }

    pub(super) fn next_key(&self) -> Result<Option<StoredKey>, CompanionFault> {
        if self.index.values.len() == self.owner.cut().page_count() as usize {
            return Ok(None);
        }
        let identity = SnapshotPageIdentity::new(
            self.owner.scope().target_server_id(),
            self.owner.cut().delivery_generation(),
            self.owner.cut().token(),
            u32::try_from(self.index.values.len()).map_err(|_| CompanionFault::Ceiling)?,
        )
        .map_err(|_| CompanionFault::Storage)?;
        cut_page_key(&identity)
            .map(Some)
            .map_err(|_| CompanionFault::Storage)
    }

    /// The caller retains charged plaintext and a fully decoded exact-key row.
    pub(super) fn admit(
        &mut self,
        key: &StoredKey,
        body: &[u8],
        page: &SnapshotPage,
    ) -> Result<(), CompanionFault> {
        if self.next_key()?.as_ref() != Some(key)
            || cut_page_key(&page.identity()).map_err(|_| CompanionFault::Storage)? != *key
        {
            return Err(CompanionFault::Storage);
        }
        page.validate_for(&self.owner)
            .map_err(|_| CompanionFault::Storage)?;
        for entry in page.entries() {
            let conversation = entry.conversation_id();
            if self
                .last_conversation
                .is_some_and(|previous| previous >= conversation)
            {
                return Err(CompanionFault::Storage);
            }
            self.last_conversation = Some(conversation);
            self.entries = self.entries.checked_add(1).ok_or(CompanionFault::Storage)?;
            self.object_bytes = self
                .object_bytes
                .checked_add(
                    u64::try_from(entry.bytes().len()).map_err(|_| CompanionFault::Storage)?,
                )
                .ok_or(CompanionFault::Storage)?;
            if self.entries > self.owner.cut().entry_count()
                || self.object_bytes > self.owner.cut().total_object_bytes()
            {
                return Err(CompanionFault::Storage);
            }
            self.digest
                .push(ObjectId::compute(entry.bytes()).as_bytes())
                .map_err(|_| CompanionFault::Storage)?;
        }
        self.index.values.push(PageMeta {
            body_id: *ObjectId::compute(body).as_bytes(),
            encoded_bytes: body.len(),
            next_cursor: page.next_cursor(),
        });
        Ok(())
    }

    pub(super) fn finish(mut self) -> Result<(DeliveryOwner, PageIndex), CompanionFault> {
        if self.index.values.len() != self.owner.cut().page_count() as usize
            || self.entries != self.owner.cut().entry_count()
            || self.object_bytes != self.owner.cut().total_object_bytes()
            || self.digest.finish().map_err(|_| CompanionFault::Storage)?
                != self.owner.cut().digest()
        {
            return Err(CompanionFault::Storage);
        }
        self.index.total_object_bytes = self.object_bytes;
        Ok((self.owner, self.index))
    }
}
