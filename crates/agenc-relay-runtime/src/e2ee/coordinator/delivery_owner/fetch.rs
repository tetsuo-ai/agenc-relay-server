//! Exact page reads and unpublished FETCH output belong to one owner transition.
#![forbid(unsafe_code)]

mod render;

use super::super::sync::{Action, CompanionHost, PendingWork};
use super::super::{CompanionCoordinator, CompanionFault};
use super::snapshot::Pages;
use crate::budget::MemoryPermit;
use crate::federation::LinkId;
use agenc_relay_federation_wire::FederationLineText;
use agenc_relay_storage::e2ee_records::delivery_recovery::{
    CutPhase, DeliveryOwner, DeliveryRecoveryRow, SnapshotPageIdentity, cut_page_key,
};
use agenc_relay_storage::{PersistentRecordValue, StoredKey};
use agenc_relay_types::ServerId;
use std::sync::Arc;

/// A read cannot substitute a different owner, page, link, or original cursor.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct Request {
    peer: ServerId,
    link: LinkId,
    owner: DeliveryOwner,
    page: usize,
    cursor: [u8; 32],
}

#[cfg(test)]
impl Request {
    /// A page read over `owner`, for the federation read-path tests.
    pub(crate) const fn for_test(
        peer: ServerId,
        link: LinkId,
        owner: DeliveryOwner,
        page: usize,
        cursor: [u8; 32],
    ) -> Self {
        Self {
            peer,
            link,
            owner,
            page,
            cursor,
        }
    }
}

/// Lines remain charged until the adapter transfers each one to the link queue.
pub(crate) struct Output {
    lines: Vec<FederationLineText>,
    _memory: Arc<MemoryPermit>,
}

impl Output {
    #[cfg(test)]
    pub(crate) fn for_fixture(lines: Vec<FederationLineText>, memory: MemoryPermit) -> Self {
        Self {
            lines,
            _memory: Arc::new(memory),
        }
    }

    #[cfg(test)]
    pub(crate) fn lines(&self) -> &[FederationLineText] {
        &self.lines
    }
    pub(crate) fn backing(&self) -> Arc<MemoryPermit> {
        Arc::clone(&self._memory)
    }
    pub(crate) fn drain(&mut self) -> std::vec::Drain<'_, FederationLineText> {
        self.lines.drain(..)
    }
}

/// A FETCH advance is invisible until the exact Owner Put has committed.
pub struct Prepared {
    request: Request,
    proposed: DeliveryOwner,
    output: Output,
}

impl Request {
    pub(crate) const fn peer(&self) -> ServerId {
        self.peer
    }
    pub(crate) const fn link(&self) -> LinkId {
        self.link
    }
    pub(crate) fn key(&self) -> Result<StoredKey, CompanionFault> {
        let id = SnapshotPageIdentity::new(
            *self.peer.as_bytes(),
            self.owner.cut().delivery_generation(),
            self.owner.cut().token(),
            u32::try_from(self.page).map_err(|_| CompanionFault::Protocol)?,
        )
        .map_err(|_| CompanionFault::Storage)?;
        cut_page_key(&id).map_err(|_| CompanionFault::Storage)
    }

    fn validate(
        &self,
        coordinator: &mut CompanionCoordinator,
        now: u64,
        host: &dyn CompanionHost,
    ) -> Result<(), CompanionFault> {
        if coordinator.pending.is_some() {
            return Err(CompanionFault::Ceiling);
        }
        if coordinator
            .state
            .streams
            .get(&self.peer)
            .and_then(|stream| stream.owner.as_ref())
            != Some(&self.owner)
        {
            return Err(CompanionFault::Protocol);
        }
        let sync = coordinator
            .peers
            .get_mut(&self.peer)
            .ok_or(CompanionFault::Protocol)?;
        if sync.link != Some(self.link) {
            return Err(CompanionFault::Protocol);
        }
        let snapshot = sync.snapshot.as_mut().ok_or(CompanionFault::Protocol)?;
        super::super::sync::require_cut_scope(snapshot.scope, self.peer, host)?;
        if snapshot.cut != super::cut(&self.owner)
            || snapshot.scope != *self.owner.scope()
            || snapshot
                .capture
                .cursor(self.page.checked_sub(1).ok_or(CompanionFault::Protocol)?)
                != Some(self.cursor)
        {
            return Err(CompanionFault::Protocol);
        }
        if snapshot.expires_at_millis != 0 && now >= snapshot.expires_at_millis {
            return Err(CompanionFault::Protocol);
        }
        snapshot
            .observe_at(now, host)
            .map_err(|_| CompanionFault::Protocol)
    }

    pub(crate) fn complete(
        self,
        coordinator: &mut CompanionCoordinator,
        key: &StoredKey,
        value: &PersistentRecordValue,
        now: u64,
        host: &dyn CompanionHost,
    ) -> Result<Vec<Action>, CompanionFault> {
        self.validate(coordinator, now, host)?;
        if self.key()? != *key
            || value.record_kind() != agenc_relay_storage::e2ee_records::DELIVERY_RECOVERY_ROW_KIND
        {
            return Err(CompanionFault::Storage);
        }
        let DeliveryRecoveryRow::CutPage(page) = DeliveryRecoveryRow::decode_at(key, value.body())
            .map_err(|_| CompanionFault::Storage)?
        else {
            return Err(CompanionFault::Storage);
        };
        page.validate_for(&self.owner)
            .map_err(|_| CompanionFault::Storage)?;
        let snapshot = coordinator
            .peers
            .get(&self.peer)
            .and_then(|sync| sync.snapshot.as_ref())
            .ok_or(CompanionFault::Protocol)?;
        let Pages::Stored(index) = &snapshot.capture else {
            return Err(CompanionFault::Storage);
        };
        if !index.matches(self.page, value.body()) {
            return Err(CompanionFault::Storage);
        }
        let output = render::stored(
            &coordinator.server_name,
            self.peer,
            &self.owner,
            &page,
            host,
        )?;
        self.finish(coordinator, output)
    }

    fn finish(
        self,
        coordinator: &CompanionCoordinator,
        output: Output,
    ) -> Result<Vec<Action>, CompanionFault> {
        let CutPhase::Pending { offered_pages, .. } = self.owner.phase() else {
            return Err(CompanionFault::Protocol);
        };
        if self.page.checked_add(1) == Some(offered_pages as usize) {
            return Ok(vec![Action::SendPage(output)]);
        }
        if self.page != offered_pages as usize {
            return Err(CompanionFault::Protocol);
        }
        let snapshot = coordinator
            .peers
            .get(&self.peer)
            .and_then(|sync| sync.snapshot.as_ref())
            .ok_or(CompanionFault::Protocol)?;
        let proposed = DeliveryOwner::new(
            *self.owner.scope(),
            *self.owner.cursor(),
            *self.owner.cut(),
            CutPhase::Pending {
                offered_pages: offered_pages
                    .checked_add(1)
                    .ok_or(CompanionFault::Ceiling)?,
                deadline: snapshot.deadline,
            },
        )
        .map_err(|_| CompanionFault::Storage)?;
        let write = super::write(&proposed)?;
        Ok(vec![Action::Stage {
            writes: vec![write],
            work: PendingWork::Fetch(Box::new(Prepared {
                request: self,
                proposed,
                output,
            })),
        }])
    }
}

impl Prepared {
    pub(crate) fn peer(&self) -> ServerId {
        self.request.peer
    }
    pub(crate) fn link(&self) -> LinkId {
        self.request.link
    }

    pub(crate) fn committed(
        self,
        coordinator: &mut CompanionCoordinator,
        now: u64,
        host: &dyn CompanionHost,
    ) -> Result<Vec<Action>, CompanionFault> {
        let request = &self.request;
        coordinator.validate_delivery_scope(self.proposed.scope())?;
        let stream = coordinator
            .state
            .streams
            .get_mut(&request.peer)
            .ok_or(CompanionFault::Storage)?;
        if stream.owner.as_ref() != Some(&request.owner)
            || super::cursor(stream)? != *self.proposed.cursor()
        {
            return Err(CompanionFault::Storage);
        }
        stream.owner = Some(self.proposed);
        let sync = coordinator
            .peers
            .get_mut(&request.peer)
            .ok_or(CompanionFault::Storage)?;
        let snapshot = sync.snapshot.as_mut().ok_or(CompanionFault::Storage)?;
        if snapshot.cut != super::cut(&request.owner) || snapshot.scope != *request.owner.scope() {
            return Err(CompanionFault::Storage);
        }
        snapshot.pages_sent = request.page.checked_add(1).ok_or(CompanionFault::Storage)?;
        let current = sync.link == Some(request.link)
            && super::super::sync::require_cut_scope(snapshot.scope, request.peer, host).is_ok();
        if !current || snapshot.observe_at(now, host).is_err() {
            return Ok(Vec::new());
        }
        Ok(vec![Action::SendPage(self.output)])
    }
}

impl CompanionCoordinator {
    pub(crate) fn prepare_snapshot_fetch(
        &mut self,
        peer: ServerId,
        token: [u8; 32],
        page: u32,
        cursor: [u8; 32],
        now: u64,
        host: &dyn CompanionHost,
    ) -> Result<Vec<Action>, CompanionFault> {
        let owner = self
            .state
            .streams
            .get(&peer)
            .and_then(|stream| stream.owner.as_ref())
            .ok_or(CompanionFault::Protocol)?;
        let CutPhase::Pending { offered_pages, .. } = owner.phase() else {
            return Err(CompanionFault::Protocol);
        };
        if owner.cut().token() != token
            || page == 0
            || page >= owner.cut().page_count()
            || !(page == offered_pages || page.checked_add(1) == Some(offered_pages))
        {
            return Err(CompanionFault::Protocol);
        }
        let link = self
            .peers
            .get(&peer)
            .and_then(|sync| sync.link)
            .ok_or(CompanionFault::Protocol)?;
        let request = Request {
            peer,
            link,
            owner: owner.clone(),
            page: page as usize,
            cursor,
        };
        request.validate(self, now, host)?;
        let snapshot = self
            .peers
            .get(&peer)
            .and_then(|sync| sync.snapshot.as_ref())
            .ok_or(CompanionFault::Protocol)?;
        match &snapshot.capture {
            Pages::Stored(_) => Ok(vec![Action::ReadSnapshotPage(request)]),
            Pages::Captured(_) => {
                let output = captured(self, peer, request.page, host)?;
                request.finish(self, output)
            }
        }
    }
}

/// First publication and FETCH use the same charged rendering/queue handoff.
pub(super) fn captured(
    coordinator: &CompanionCoordinator,
    peer: ServerId,
    page: usize,
    host: &dyn CompanionHost,
) -> Result<Output, CompanionFault> {
    let snapshot = coordinator
        .peers
        .get(&peer)
        .and_then(|sync| sync.snapshot.as_ref())
        .ok_or(CompanionFault::Storage)?;
    let memory = render::reserve(host)?;
    let lines = super::super::sync::render_page(
        &coordinator.server_name,
        peer,
        snapshot,
        page,
        &coordinator.state,
    )?;
    Ok(Output {
        lines,
        _memory: Arc::new(memory),
    })
}
