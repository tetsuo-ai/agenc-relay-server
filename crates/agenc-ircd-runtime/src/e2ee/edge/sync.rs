//! Companion synchronization on the edge (12.5): after the profile is
//! active the edge resumes from its durable cursor or installs the ESTATE
//! snapshot the coordinator cuts, records READY durably before ACTIVE, and
//! then replays its origin set; `STATE_ACTIVE` follows EORIGIN READY.

use agenc_ircd_domain::e2ee::limits::MAX_BATCH_OBJECTS;
use agenc_ircd_e2ee::federation::frames::{CompanionFrame, DeliveryPosition};
use agenc_ircd_e2ee::ids::federation_snapshot_digest;
use agenc_ircd_e2ee::object::IrcWireObjectKind;
use agenc_ircd_e2ee::wire::assembly::{AssemblyKey, Direction, Ingest, QuotaScopes, Sender};
use agenc_ircd_e2ee::wire::carrier::CarrierCommand;
use agenc_ircd_e2ee::wire::fragment::FragmentTag;
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;
use agenc_ircd_storage::e2ee_records::{DELIVERY_ROW_KIND, DeliveryRow};

use super::router::Refusal;
use super::{ClientOutput, E2eeEdge, PendingCommit, Phase};
use crate::federation::edge::EdgeFederation;
use crate::state_core::StateCoreContext;

/// The edge's companion delivery position.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct DeliveryState {
    /// The delivery generation in use.
    pub(crate) generation: u64,
    /// The last applied and acknowledged position.
    pub(crate) cursor: Option<(u64, [u8; 16])>,
}

impl DeliveryState {
    /// The next sequence the coordinator must deliver.
    pub(crate) fn next_sequence(&self) -> u64 {
        self.cursor
            .map_or(0, |(sequence, _)| sequence.saturating_add(1))
    }

    /// Advances to `position` after its apply.
    pub(crate) fn advance(&mut self, position: DeliveryPosition) {
        self.generation = position.delivery_generation;
        self.cursor = Some((position.delivery_sequence, position.event_id));
    }
}

/// One ESTATE transfer being installed.
pub(crate) struct SnapshotInstall {
    token: [u8; 32],
    state_generation: u64,
    delivery_generation: u64,
    total: u32,
    digest: [u8; 32],
    next_page: u32,
    entries: Vec<([u8; 32], Vec<u8>)>,
    page_expected: u32,
    page_seen: u32,
    complete: bool,
}

impl E2eeEdge {
    /// The companion profile became active on the link: resume from the
    /// durable cursor, or announce a fresh scope.
    pub fn link_active(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
    ) -> bool {
        if self.phase != Phase::Down {
            return true;
        }
        let frame = CompanionFrame::Resume {
            coordinator_server_id: *self.config.coordinator_server_id.as_bytes(),
            server_incarnation: self.config.incarnation,
            delivery_generation: self.delivery.generation,
            last: self.delivery.cursor,
        };
        let Ok(line) = self.line(&frame) else {
            return false;
        };
        self.phase = Phase::Resuming;
        self.send(context, edge, vec![line])
    }

    /// `ERESUME OK`: the retained cursor continues; the origin set replays.
    pub(super) fn resume_ok(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        delivery_generation: u64,
        next_delivery_sequence: u64,
    ) -> Result<(), Refusal> {
        if self.phase != Phase::Resuming
            || delivery_generation != self.delivery.generation
            || next_delivery_sequence != self.delivery.next_sequence()
        {
            return Err(E2eeReplyCode::Syncing.into());
        }
        self.begin_origins(context, edge)
    }

    /// `ESTATE BEGIN`: every page repeats the cut; page zero opens it.
    // agenc-review: allow owner=runtime reviewed=2026-09-03 reason=a page opener carries the token cut generation counts and digest the spec repeats on every page
    #[allow(clippy::too_many_arguments)]
    pub(super) fn state_begin(
        &mut self,
        token: [u8; 32],
        state_generation: u64,
        delivery_generation: u64,
        page_sequence: u32,
        total: u32,
        page_count: u32,
        digest: [u8; 32],
    ) -> Result<(), Refusal> {
        match self.snapshot.as_mut() {
            None if page_sequence == 0 && self.phase == Phase::Resuming => {
                let expected_pages = usize::try_from(total)
                    .map_err(|_| E2eeReplyCode::Syncing)?
                    .div_ceil(MAX_BATCH_OBJECTS)
                    .max(1);
                let last_page = expected_pages == 1;
                let page_ok = if last_page {
                    usize::try_from(page_count).map_err(|_| E2eeReplyCode::Syncing)?
                        == usize::try_from(total).map_err(|_| E2eeReplyCode::Syncing)?
                } else {
                    usize::try_from(page_count).map_err(|_| E2eeReplyCode::Syncing)?
                        == MAX_BATCH_OBJECTS
                };
                if !page_ok {
                    return Err(E2eeReplyCode::Syncing.into());
                }
                self.snapshot = Some(SnapshotInstall {
                    token,
                    state_generation,
                    delivery_generation,
                    total,
                    digest,
                    next_page: 0,
                    entries: Vec::new(),
                    page_expected: page_count,
                    page_seen: 0,
                    complete: false,
                });
                self.phase = Phase::Transferring;
                Ok(())
            }
            Some(snapshot)
                if snapshot.token == token
                    && snapshot.state_generation == state_generation
                    && snapshot.delivery_generation == delivery_generation
                    && snapshot.total == total
                    && snapshot.digest == digest
                    && page_sequence == snapshot.next_page
                    && snapshot.page_seen == 0 =>
            {
                snapshot.page_expected = page_count;
                Ok(())
            }
            _ => Err(E2eeReplyCode::Syncing.into()),
        }
    }

    /// `ESTATE ENTRY` fragments assemble one route state object each.
    pub(super) fn state_entry(
        &mut self,
        context: &StateCoreContext,
        token: [u8; 32],
        page_sequence: u32,
        conversation_id: [u8; 32],
        object_id: [u8; 32],
        fragment: FragmentTag,
    ) -> Result<(), Refusal> {
        let coordinator = *self.config.coordinator_server_id.as_bytes();
        let snapshot = self.snapshot.as_mut().ok_or(E2eeReplyCode::Syncing)?;
        if snapshot.token != token || snapshot.next_page != page_sequence {
            return Err(E2eeReplyCode::Syncing.into());
        }
        let command = CarrierCommand::Federation(IrcWireObjectKind::FederationState);
        let key = AssemblyKey {
            direction: Direction::Remote,
            sender: Sender::Peer(coordinator),
            command,
            route: conversation_id,
            scope: None,
            object_id: agenc_ircd_e2ee::ObjectId::from_bytes(object_id),
        };
        let scopes = QuotaScopes {
            peer: Some(coordinator),
            ..QuotaScopes::default()
        };
        let now = context.now().get() / 1_000;
        match self
            .assembler
            .ingest(key, scopes, command.limit(), &fragment, now)
        {
            Ok(Ingest::Complete(bytes)) => {
                let ordered = snapshot
                    .entries
                    .last()
                    .is_none_or(|(previous, _)| *previous < conversation_id);
                if !ordered {
                    return Err(E2eeReplyCode::Syncing.into());
                }
                snapshot.entries.push((conversation_id, bytes));
                snapshot.page_seen = snapshot.page_seen.saturating_add(1);
                Ok(())
            }
            Ok(Ingest::Incomplete | Ingest::Duplicate | Ingest::Recent) => Ok(()),
            Err(error) => Err(error.reply_code().into()),
        }
    }

    /// `ESTATE END`: the page must be complete; a cursor asks for the next
    /// page and `*` closes the transfer with READY.
    pub(super) fn state_end(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        token: [u8; 32],
        page_sequence: u32,
        next_cursor: Option<[u8; 32]>,
    ) -> Result<(), Refusal> {
        let coordinator = *self.config.coordinator_server_id.as_bytes();
        let snapshot = self.snapshot.as_mut().ok_or(E2eeReplyCode::Syncing)?;
        if snapshot.token != token
            || snapshot.next_page != page_sequence
            || snapshot.page_seen != snapshot.page_expected
        {
            return Err(E2eeReplyCode::Syncing.into());
        }
        snapshot.next_page = snapshot.next_page.saturating_add(1);
        snapshot.page_seen = 0;
        match next_cursor {
            Some(cursor) => {
                let frame = CompanionFrame::StateFetch {
                    coordinator_server_id: coordinator,
                    snapshot_token: token,
                    next_page_sequence: snapshot.next_page,
                    cursor,
                };
                let line = self.line(&frame)?;
                self.send(context, edge, vec![line]);
                Ok(())
            }
            None => self.state_complete(context, edge),
        }
    }

    /// Verifies the complete snapshot, installs the routes in memory, and
    /// records READY durably; ACTIVE is awaited after the commit.
    fn state_complete(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
    ) -> Result<(), Refusal> {
        let snapshot = self.snapshot.as_mut().ok_or(E2eeReplyCode::Syncing)?;
        if usize::try_from(snapshot.total).map_err(|_| E2eeReplyCode::Syncing)?
            != snapshot.entries.len()
        {
            return Err(E2eeReplyCode::Syncing.into());
        }
        let ids: Vec<[u8; 32]> = snapshot
            .entries
            .iter()
            .map(|(_, bytes)| *agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes())
            .collect();
        let digest = federation_snapshot_digest(
            snapshot.state_generation,
            snapshot.delivery_generation,
            &ids,
        )
        .map_err(|_| E2eeReplyCode::Syncing)?;
        if digest != snapshot.digest {
            return Err(E2eeReplyCode::Syncing.into());
        }
        snapshot.complete = true;
        let entries = snapshot.entries.clone();
        let delivery_generation = snapshot.delivery_generation;
        let mut writes = Vec::new();
        for (_, bytes) in &entries {
            writes.push(self.route_changed(bytes)?);
        }
        self.delivery = DeliveryState {
            generation: delivery_generation,
            cursor: None,
        };
        writes.push(
            super::events::cursor_write(&self.config, &self.delivery).map_err(Refusal::from)?,
        );
        let _ = edge;
        self.stage(context, writes, PendingCommit::Ready)
    }

    /// The READY record committed: READY goes out.
    pub(super) fn ready_recorded(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
    ) {
        let Some(snapshot) = self.snapshot.as_ref() else {
            return;
        };
        let frame = CompanionFrame::StateCut {
            active: false,
            server_id: *self.config.coordinator_server_id.as_bytes(),
            snapshot_token: snapshot.token,
            state_generation: snapshot.state_generation,
            delivery_generation: snapshot.delivery_generation,
            snapshot_digest: snapshot.digest,
        };
        if let Ok(line) = self.line(&frame) {
            self.phase = Phase::AwaitingActive;
            self.send(context, edge, vec![line]);
        }
    }

    /// `ESTATE ACTIVE`: the pending generation is in use; origins replay.
    pub(super) fn state_active(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        token: [u8; 32],
        state_generation: u64,
        delivery_generation: u64,
        digest: [u8; 32],
    ) -> Result<(), Refusal> {
        let snapshot = self.snapshot.take().ok_or(E2eeReplyCode::Syncing)?;
        let matches = self.phase == Phase::AwaitingActive
            && snapshot.token == token
            && snapshot.state_generation == state_generation
            && snapshot.delivery_generation == delivery_generation
            && snapshot.digest == digest;
        if !matches {
            return Err(E2eeReplyCode::Syncing.into());
        }
        self.begin_origins(context, edge)
    }

    /// Sends EORIGIN RESET and re-declares every origin whose base
    /// declaration is acknowledged.
    fn begin_origins(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
    ) -> Result<(), Refusal> {
        self.phase = Phase::Origins;
        let reset = self.line(&CompanionFrame::OriginReset {
            coordinator_server_id: *self.config.coordinator_server_id.as_bytes(),
            server_incarnation: self.config.incarnation,
        })?;
        for origin in self.origins.values_mut() {
            origin.declared = None;
            origin.acked = None;
        }
        if !self.send(context, edge, vec![reset]) {
            return Err(E2eeReplyCode::Syncing.into());
        }
        self.declare_origins(context, edge);
        Ok(())
    }

    /// `EORIGIN READY`: requests flow.
    pub(super) fn origins_ready(&mut self) -> Result<(), Refusal> {
        if self.phase != Phase::Origins {
            return Err(E2eeReplyCode::Syncing.into());
        }
        self.phase = Phase::Active;
        Ok(())
    }

    /// The durable rows a restart reads back: the delivery cursor row of
    /// this edge's coordinator.
    #[must_use]
    pub fn cursor_row_kind() -> u16 {
        DELIVERY_ROW_KIND
    }

    /// Restores the durable cursor at startup.
    pub fn restore_cursor(&mut self, row: &DeliveryRow) {
        if let DeliveryRow::Cursor {
            generation,
            acked_sequence,
            acked_event_id,
            next_sequence,
            ..
        } = row
        {
            self.delivery = DeliveryState {
                generation: *generation,
                cursor: (*next_sequence > 0).then_some((*acked_sequence, *acked_event_id)),
            };
        }
    }

    /// Frames from the coordinator once the profile is active.
    pub fn handle_frames(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        frames: Vec<CompanionFrame>,
    ) -> Vec<ClientOutput> {
        let mut outputs = Vec::new();
        self.adopt_barrier_cursor(edge);
        for frame in frames {
            match self.handle_frame(context, edge, frame) {
                Ok(more) => outputs.extend(more),
                Err(_) => {
                    self.counters.violations = self.counters.violations.saturating_add(1);
                    edge.fail_companion_link(context);
                    self.link_down();
                    break;
                }
            }
        }
        outputs
    }

    // agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one match routes every coordinator frame to its handler with the exact fields the line carried
    fn handle_frame(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        frame: CompanionFrame,
    ) -> Result<Vec<ClientOutput>, Refusal> {
        match frame {
            CompanionFrame::ResumeOk {
                delivery_generation,
                next_delivery_sequence,
                ..
            } => self
                .resume_ok(context, edge, delivery_generation, next_delivery_sequence)
                .map(|()| Vec::new()),
            CompanionFrame::StateBegin {
                snapshot_token,
                state_generation,
                delivery_generation,
                page_sequence,
                total_entry_count,
                page_entry_count,
                snapshot_digest,
                ..
            } => self
                .state_begin(
                    snapshot_token,
                    state_generation,
                    delivery_generation,
                    page_sequence,
                    total_entry_count,
                    page_entry_count,
                    snapshot_digest,
                )
                .map(|()| Vec::new()),
            CompanionFrame::StateEntry {
                snapshot_token,
                page_sequence,
                conversation_id,
                object_id,
                fragment,
                ..
            } => self
                .state_entry(
                    context,
                    snapshot_token,
                    page_sequence,
                    conversation_id,
                    object_id,
                    fragment,
                )
                .map(|()| Vec::new()),
            CompanionFrame::StateEnd {
                snapshot_token,
                page_sequence,
                next_cursor,
                ..
            } => self
                .state_end(context, edge, snapshot_token, page_sequence, next_cursor)
                .map(|()| Vec::new()),
            CompanionFrame::StateCut {
                active: true,
                snapshot_token,
                state_generation,
                delivery_generation,
                snapshot_digest,
                ..
            } => self
                .state_active(
                    context,
                    edge,
                    snapshot_token,
                    state_generation,
                    delivery_generation,
                    snapshot_digest,
                )
                .map(|()| Vec::new()),
            CompanionFrame::OriginReady { .. } => self.origins_ready().map(|()| Vec::new()),
            CompanionFrame::OriginAck {
                origin_id,
                origin_generation,
                object_id,
                ..
            } => self
                .origin_acked(
                    context,
                    edge,
                    origin_id,
                    origin_generation,
                    object_id.is_some(),
                )
                .map(|()| Vec::new()),
            CompanionFrame::Result { .. } | CompanionFrame::Response { .. } => {
                self.on_result_frame(context, frame)
            }
            CompanionFrame::Event {
                position,
                object_id,
                fragment,
            } => self.on_event_frame(context, edge, position, object_id, fragment, false),
            CompanionFrame::Data {
                position,
                object_id,
                fragment,
            } => self.on_event_frame(context, edge, position, object_id, fragment, true),
            _ => Err(E2eeReplyCode::InvalidFragment.into()),
        }
    }
}
