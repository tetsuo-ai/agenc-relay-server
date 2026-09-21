//! Receipt-owned page construction publishes the cut only after every page is durable.
#![forbid(unsafe_code)]

mod page;

use agenc_relay_storage::e2ee_records::delivery_recovery::{CutPhase, DeliveryOwner};
use agenc_relay_types::ServerId;

use super::super::events::DeliveryStream;
use super::super::sync::{Action, CompanionHost, PendingWork, Snapshot};
use super::super::{CompanionCoordinator, CompanionFault};
use crate::federation::LinkId;

/// Private progress moved through the exact staging receipt; no cursor authority escapes it.
pub struct Publication {
    peer: ServerId,
    link: LinkId,
    snapshot: Snapshot,
    owner: DeliveryOwner,
    next_page: usize,
    owner_staged: bool,
    page_memory: Option<page::PageMemory>,
}

impl Publication {
    pub(crate) fn new(
        peer: ServerId,
        link: LinkId,
        snapshot: Snapshot,
    ) -> Result<Self, CompanionFault> {
        let stream = DeliveryStream {
            generation: snapshot.cut.delivery_generation,
            ..DeliveryStream::default()
        };
        let ready = super::ready(
            snapshot.scope,
            snapshot.cut,
            snapshot.capture.total_object_bytes(),
            &stream,
        )?;
        let owner = DeliveryOwner::new(
            *ready.scope(),
            *ready.cursor(),
            *ready.cut(),
            CutPhase::Pending {
                offered_pages: 1,
                deadline: snapshot.deadline,
            },
        )
        .map_err(|_| CompanionFault::Storage)?;
        Ok(Self {
            peer,
            link,
            snapshot,
            owner,
            next_page: 0,
            owner_staged: false,
            page_memory: None,
        })
    }

    pub(crate) const fn peer(&self) -> ServerId {
        self.peer
    }
    pub(crate) const fn link(&self) -> LinkId {
        self.link
    }

    pub(super) fn next(
        mut self,
        coordinator: &mut CompanionCoordinator,
        now_millis: u64,
        host: &dyn CompanionHost,
    ) -> Result<Vec<Action>, CompanionFault> {
        self.page_memory = None;
        if self.owner_staged {
            return self.publish(coordinator, now_millis, host);
        }
        if coordinator.peers.get(&self.peer).and_then(|sync| sync.link) != Some(self.link) {
            return Ok(Vec::new());
        }
        super::super::sync::require_cut_scope(self.snapshot.scope, self.peer, host)?;
        self.observe(host)?;
        if self.next_page < self.snapshot.capture.page_count() {
            let (write, memory) = page::write(
                &self.snapshot,
                &self.owner,
                self.next_page,
                &coordinator.state,
                host,
            )?;
            self.page_memory = Some(memory);
            self.next_page = self
                .next_page
                .checked_add(1)
                .ok_or(CompanionFault::Ceiling)?;
            return Ok(vec![Action::Stage {
                writes: vec![write],
                work: PendingWork::Snapshot(Box::new(self)),
            }]);
        }
        let write = super::write(&self.owner)?;
        self.owner_staged = true;
        Ok(vec![Action::Stage {
            writes: vec![write],
            work: PendingWork::Snapshot(Box::new(self)),
        }])
    }

    fn observe(&mut self, host: &dyn CompanionHost) -> Result<(), CompanionFault> {
        let sample = host
            .cut_clock_sample()
            .map_err(|_| CompanionFault::Protocol)?;
        let deadline = sample
            .observe(self.snapshot.deadline, self.snapshot.observed)
            .map_err(|_| CompanionFault::Protocol)?;
        self.snapshot.deadline = deadline;
        self.snapshot.observed = Some(sample);
        self.owner = DeliveryOwner::new(
            *self.owner.scope(),
            *self.owner.cursor(),
            *self.owner.cut(),
            CutPhase::Pending {
                offered_pages: 1,
                deadline,
            },
        )
        .map_err(|_| CompanionFault::Storage)?;
        Ok(())
    }

    fn publish(
        mut self,
        coordinator: &mut CompanionCoordinator,
        now_millis: u64,
        host: &dyn CompanionHost,
    ) -> Result<Vec<Action>, CompanionFault> {
        coordinator.validate_delivery_scope(self.owner.scope())?;
        coordinator.state.streams.insert(
            self.peer,
            DeliveryStream {
                generation: self.owner.cursor().generation(),
                owner: Some(self.owner.clone()),
                ..DeliveryStream::default()
            },
        );
        self.snapshot.pages_sent = 1;
        let current = coordinator.peers.get(&self.peer).and_then(|sync| sync.link)
            == Some(self.link)
            && super::super::sync::require_cut_scope(self.snapshot.scope, self.peer, host).is_ok();
        let sync = coordinator.peers.entry(self.peer).or_default();
        sync.incarnation = Some(self.owner.scope().target_incarnation());
        sync.resync_epoch = self.owner.scope().covered_base_client_resync_epoch();
        sync.transfer_incomplete = true;
        sync.ready_cut = None;
        sync.snapshot = Some(self.snapshot);
        if !current {
            return Ok(Vec::new());
        }
        publish_first_page(coordinator, self.peer, now_millis, host)
    }
}

impl CompanionCoordinator {
    pub(crate) fn continue_snapshot_publication(
        &mut self,
        publication: Publication,
        now_millis: u64,
        host: &dyn CompanionHost,
    ) -> Result<Vec<Action>, CompanionFault> {
        if self.pending.is_some() {
            return Err(CompanionFault::Ceiling);
        }
        publication.next(self, now_millis, host)
    }
}

impl CompanionCoordinator {
    /// Publishes the pending cut of `peer` again from its first page, for a
    /// resume on a link that replaced the one the transfer started on.
    pub(in crate::e2ee::coordinator) fn restart_transfer(
        &mut self,
        peer: ServerId,
        now_millis: u64,
        host: &dyn CompanionHost,
    ) -> Result<Vec<Action>, CompanionFault> {
        let snapshot = self
            .peers
            .get_mut(&peer)
            .and_then(|sync| sync.snapshot.as_mut())
            .ok_or(CompanionFault::Protocol)?;
        snapshot.pages_sent = 1;
        publish_first_page(self, peer, now_millis, host)
    }
}

fn publish_first_page(
    coordinator: &mut CompanionCoordinator,
    peer: ServerId,
    now: u64,
    host: &dyn CompanionHost,
) -> Result<Vec<Action>, CompanionFault> {
    let snapshot = coordinator
        .peers
        .get_mut(&peer)
        .and_then(|sync| sync.snapshot.as_mut())
        .ok_or(CompanionFault::Storage)?;
    if snapshot.observe_at(now, host).is_err() {
        return Ok(Vec::new());
    }
    let deadline = snapshot.expires_at_millis;
    let output = super::fetch::captured(coordinator, peer, 0, host)?;
    Ok(vec![
        Action::ScheduleExpiry {
            at_millis: deadline,
        },
        Action::SendPage(output),
    ])
}
