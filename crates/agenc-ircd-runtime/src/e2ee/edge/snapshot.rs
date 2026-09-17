//! The edge's ESTATE receiver as a bounded, durable pending-generation
//! owner (companion 12.5): every page is verified and staged in its own
//! batch under the pending generation's keys, READY is recorded durably
//! before it is sent and resent identically after reconnect, ACTIVE alone
//! swaps the generation into use, and the rows then migrate into the active
//! keys in bounded batches while an abandoned generation is cleaned up the
//! same way.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use agenc_ircd_domain::e2ee::RouteTable;
use agenc_ircd_domain::e2ee::limits::MAX_BATCH_OBJECTS;
use agenc_ircd_e2ee::federation::frames::CompanionFrame;
use agenc_ircd_e2ee::ids::FederationSnapshotDigest;
use agenc_ircd_e2ee::limits::{
    FEDERATION_STATE_SNAPSHOT_TIMEOUT_SECONDS, MAX_BATCH_DECODED_BYTES,
    MAX_FEDERATION_STATE_ENTRIES_PER_EDGE, MAX_FEDERATION_STATE_SNAPSHOT_BYTES_PER_EDGE,
};
use agenc_ircd_e2ee::object::IrcWireObjectKind;
use agenc_ircd_e2ee::wire::assembly::{AssemblyKey, Direction, Ingest, QuotaScopes, Sender};
use agenc_ircd_e2ee::wire::carrier::CarrierCommand;
use agenc_ircd_e2ee::wire::fragment::FragmentTag;
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;
use agenc_ircd_storage::TableId;
use agenc_ircd_storage::e2ee_records::{
    PENDING_ROUTE_ROW_KIND, PendingRouteRow, ROUTE_ROW_KIND, RouteRow, SNAPSHOT_MARKER_ROW_KIND,
    SnapshotMarkerRow, SnapshotPhase,
};

use super::events::{Conversation, state_row};
use super::router::Refusal;
use super::sync::DeliveryState;
use super::{E2eeEdge, PendingCommit, Phase};
use crate::budget::{BackingReservationPort, MemoryPermit};
use crate::federation::edge::EdgeFederation;
use crate::state_core::StateCoreContext;
use crate::state_core::durable::AccountServiceDurableWrite;

/// Rows one migration or cleanup batch touches.
const STEP_ROWS: usize = 256;
/// The bytes charged for one retained conversation beside its object.
const ENTRY_OVERHEAD: usize = 256;

/// The new generation's projection, kept beside the live one until ACTIVE.
#[derive(Default)]
pub(crate) struct PendingProjection {
    pub(crate) routes: RouteTable,
    pub(crate) conversations: BTreeMap<[u8; 32], Conversation>,
    pub(crate) route_objects: BTreeMap<[u8; 32], Vec<u8>>,
}

/// Where the durable generation stands.
pub(crate) enum Stage {
    /// Pages are being received; the pending rows of accepted pages are
    /// durable, the marker says `Staging`.
    Staging,
    /// Every page is durable and verified; READY is sent (again after
    /// every reconnect) until ACTIVE.
    Ready,
    /// ACTIVE is durable: the generation is live and its rows migrate into
    /// the active keys; `remaining` still hold pending rows, `stale` are
    /// old active rows the generation dropped.
    Active {
        switched_through: Option<[u8; 32]>,
        remaining: BTreeSet<[u8; 32]>,
        stale: BTreeSet<[u8; 32]>,
    },
    /// The generation was abandoned: its pending rows are deleted in
    /// bounded batches, then its marker.
    Discarding { keys: Vec<[u8; 32]> },
}

/// One ESTATE generation, from its first page to the end of its migration.
pub(crate) struct SnapshotInstall {
    pub(crate) token: [u8; 32],
    pub(crate) state_generation: u64,
    pub(crate) delivery_generation: u64,
    pub(crate) total: u32,
    pub(crate) digest: [u8; 32],
    pub(super) opened_at: u64,
    next_page: u32,
    page_expected: u32,
    page_writes: Vec<AccountServiceDurableWrite>,
    page_bytes: usize,
    staged_entries: u32,
    staged_bytes: u64,
    running: Option<FederationSnapshotDigest>,
    last_conversation: Option<[u8; 32]>,
    pub(crate) pending: PendingProjection,
    permits: Vec<MemoryPermit>,
    pub(crate) stage: Stage,
}

impl SnapshotInstall {
    fn cut_matches(
        &self,
        token: [u8; 32],
        state_generation: u64,
        delivery_generation: u64,
        digest: [u8; 32],
    ) -> bool {
        self.token == token
            && self.state_generation == state_generation
            && self.delivery_generation == delivery_generation
            && self.digest == digest
    }

    /// The marker row for the current progress.
    fn marker(
        &self,
        phase: SnapshotPhase,
        switched_through: Option<[u8; 32]>,
    ) -> SnapshotMarkerRow {
        SnapshotMarkerRow {
            token: self.token,
            state_generation: self.state_generation,
            delivery_generation: self.delivery_generation,
            total_entries: self.total,
            digest: self.digest,
            staged_entries: self.staged_entries,
            staged_bytes: self.staged_bytes,
            phase,
            opened_at: self.opened_at,
            switched_through,
        }
    }

    fn expired(&self, now_millis: u64) -> bool {
        now_millis
            >= self
                .opened_at
                .saturating_add(FEDERATION_STATE_SNAPSHOT_TIMEOUT_SECONDS.saturating_mul(1_000))
    }

    /// The generation a durable marker describes, before its rows are
    /// scanned: a `Staging` marker is abandoned outright.
    pub(super) fn restored(row: &SnapshotMarkerRow) -> Self {
        let stage = match row.phase {
            SnapshotPhase::Staging => Stage::Discarding { keys: Vec::new() },
            SnapshotPhase::Ready => Stage::Ready,
            SnapshotPhase::Active => Stage::Active {
                switched_through: row.switched_through,
                remaining: BTreeSet::new(),
                stale: BTreeSet::new(),
            },
        };
        Self {
            token: row.token,
            state_generation: row.state_generation,
            delivery_generation: row.delivery_generation,
            total: row.total_entries,
            digest: row.digest,
            opened_at: row.opened_at,
            next_page: 0,
            page_expected: 0,
            page_writes: Vec::new(),
            page_bytes: 0,
            staged_entries: row.staged_entries,
            staged_bytes: row.staged_bytes,
            running: None,
            last_conversation: None,
            pending: PendingProjection::default(),
            permits: Vec::new(),
            stage,
        }
    }
}

pub(super) fn page_partition(
    total: u32,
    page_sequence: u32,
    page_count: u32,
) -> Result<(), Refusal> {
    let total = usize::try_from(total).map_err(|_| E2eeReplyCode::Syncing)?;
    let page = usize::try_from(page_sequence).map_err(|_| E2eeReplyCode::Syncing)?;
    let count = usize::try_from(page_count).map_err(|_| E2eeReplyCode::Syncing)?;
    let pages = total.div_ceil(MAX_BATCH_OBJECTS).max(1);
    let expected = if page.checked_add(1) == Some(pages) {
        total.checked_sub(page.saturating_mul(MAX_BATCH_OBJECTS))
    } else if page < pages {
        Some(MAX_BATCH_OBJECTS)
    } else {
        None
    };
    (expected == Some(count))
        .then_some(())
        .ok_or_else(|| E2eeReplyCode::Syncing.into())
}

impl E2eeEdge {
    /// Installs the memory admission port every retained snapshot body is
    /// charged against.
    pub(crate) fn install_snapshot_backing(&mut self, port: BackingReservationPort) {
        self.snapshot_backing = Some(port);
    }

    /// Whether a READY generation waits for ACTIVE, which a reconnect
    /// announces with the identical READY instead of ERESUME.
    pub(crate) fn snapshot_ready_pending(&self) -> bool {
        self.snapshot
            .as_ref()
            .is_some_and(|snapshot| matches!(snapshot.stage, Stage::Ready))
    }

    /// Sends the identical READY of the durable generation.
    pub(super) fn resend_ready(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
    ) -> bool {
        self.try_resend_ready(context, edge).unwrap_or(false)
    }

    fn try_resend_ready(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
    ) -> Option<bool> {
        let snapshot = self.snapshot.as_ref()?;
        let frame = CompanionFrame::StateCut {
            active: false,
            server_id: *self.config.coordinator_server_id.as_bytes(),
            snapshot_token: snapshot.token,
            state_generation: snapshot.state_generation,
            delivery_generation: snapshot.delivery_generation,
            snapshot_digest: snapshot.digest,
        };
        let line = self.line(&frame).ok()?;
        self.phase = Phase::AwaitingActive;
        Some(self.send(context, edge, vec![line]))
    }

    /// `ESTATE BEGIN`: page zero opens a generation whose declared size
    /// fits the published ceilings before anything is retained; every later
    /// page repeats the cut and continues the exact partition.
    // agenc-review: allow owner=runtime reviewed=2026-09-17 reason=a page opener carries the token cut generation counts and digest the spec repeats on every page
    #[allow(clippy::too_many_arguments)]
    pub(super) fn state_begin(
        &mut self,
        context: &StateCoreContext,
        token: [u8; 32],
        state_generation: u64,
        delivery_generation: u64,
        page_sequence: u32,
        total: u32,
        page_count: u32,
        digest: [u8; 32],
    ) -> Result<(), Refusal> {
        let now = context.now().get();
        match self.snapshot.as_mut() {
            None if page_sequence == 0 && self.phase == Phase::Resuming => {
                if u64::from(total) > MAX_FEDERATION_STATE_ENTRIES_PER_EDGE {
                    return Err(E2eeReplyCode::Syncing.into());
                }
                page_partition(total, 0, page_count)?;
                let running = FederationSnapshotDigest::new(
                    state_generation,
                    delivery_generation,
                    total as usize,
                )
                .map_err(|_| E2eeReplyCode::Syncing)?;
                self.snapshot = Some(SnapshotInstall {
                    token,
                    state_generation,
                    delivery_generation,
                    total,
                    digest,
                    opened_at: now,
                    next_page: 0,
                    page_expected: page_count,
                    page_writes: Vec::new(),
                    page_bytes: 0,
                    staged_entries: 0,
                    staged_bytes: 0,
                    running: Some(running),
                    last_conversation: None,
                    pending: PendingProjection::default(),
                    permits: Vec::new(),
                    stage: Stage::Staging,
                });
                self.phase = Phase::Transferring;
                Ok(())
            }
            Some(snapshot)
                if matches!(snapshot.stage, Stage::Staging)
                    && snapshot.cut_matches(
                        token,
                        state_generation,
                        delivery_generation,
                        digest,
                    )
                    && snapshot.total == total
                    && page_sequence == snapshot.next_page
                    && snapshot.page_writes.is_empty()
                    && !snapshot.expired(now) =>
            {
                page_partition(total, page_sequence, page_count)?;
                snapshot.page_expected = page_count;
                Ok(())
            }
            _ => Err(E2eeReplyCode::Syncing.into()),
        }
    }

    /// `ESTATE ENTRY`: fragments of one object at a time assemble one route
    /// state object, which is verified and charged before it is retained.
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
        let now = context.now().get();
        let snapshot = self.snapshot.as_mut().ok_or(E2eeReplyCode::Syncing)?;
        let open = matches!(snapshot.stage, Stage::Staging)
            && snapshot.token == token
            && snapshot.next_page == page_sequence
            && snapshot.page_writes.len() < usize::try_from(snapshot.page_expected).unwrap_or(0)
            && !snapshot.expired(now);
        if !open {
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
        // A route state object is far below one fragment, so an object is
        // complete with its first fragment; the assembler still owns any
        // multi-fragment carrier.
        match self
            .assembler
            .ingest(key, scopes, command.limit(), &fragment, now / 1_000)
        {
            Ok(Ingest::Complete(bytes)) => self.retain_entry(conversation_id, bytes),
            Ok(Ingest::Incomplete | Ingest::Duplicate | Ingest::Recent) => Ok(()),
            Err(error) => Err(error.reply_code().into()),
        }
    }

    /// Verifies one complete entry against the cut and the live witness
    /// heads, charges it, and adds it to the pending projection and page.
    fn retain_entry(&mut self, conversation_id: [u8; 32], bytes: Vec<u8>) -> Result<(), Refusal> {
        let object_id = *agenc_ircd_e2ee::ObjectId::compute(&bytes).as_bytes();
        let (state, entry, conversation) = self.decode_route(&bytes)?;
        if state.conversation_id != conversation_id {
            return Err(E2eeReplyCode::Syncing.into());
        }
        let port = self
            .snapshot_backing
            .clone()
            .ok_or(E2eeReplyCode::RateLimited)?;
        let snapshot = self.snapshot.as_mut().ok_or(E2eeReplyCode::Syncing)?;
        let ordered = snapshot
            .last_conversation
            .is_none_or(|previous| previous < conversation_id);
        let page_bytes = snapshot
            .page_bytes
            .checked_add(bytes.len())
            .ok_or(E2eeReplyCode::Syncing)?;
        let total_bytes = snapshot
            .staged_bytes
            .checked_add(u64::try_from(page_bytes).map_err(|_| E2eeReplyCode::Syncing)?)
            .ok_or(E2eeReplyCode::Syncing)?;
        if !ordered {
            return Err(E2eeReplyCode::Syncing.into());
        }
        // Well-formed route states never reach either byte ceiling (an
        // object is far below a page's share), so these are guards.
        let within_page = page_bytes <= MAX_BATCH_DECODED_BYTES;
        let within_snapshot = total_bytes <= MAX_FEDERATION_STATE_SNAPSHOT_BYTES_PER_EDGE;
        (within_page & within_snapshot)
            .then_some(())
            .ok_or(E2eeReplyCode::Syncing)?;
        let permit = port
            .reserve(bytes.len().saturating_add(ENTRY_OVERHEAD))
            .map_err(|_| E2eeReplyCode::RateLimited)?;
        snapshot
            .running
            .as_mut()
            .ok_or(E2eeReplyCode::Syncing)?
            .push(&object_id)
            .map_err(|_| E2eeReplyCode::Syncing)?;
        let row = super::events::route_row(&state, &bytes);
        let write = state_row(
            PendingRouteRow::key(snapshot.delivery_generation, &conversation_id)
                .map_err(|_| E2eeReplyCode::InvalidFragment)?,
            PENDING_ROUTE_ROW_KIND,
            PendingRouteRow::encode_route(&row).map_err(|_| E2eeReplyCode::InvalidFragment)?,
        )?;
        snapshot.page_writes.push(write);
        snapshot.page_bytes = page_bytes;
        snapshot.last_conversation = Some(conversation_id);
        snapshot.permits.push(permit);
        snapshot.pending.routes.restore_entry(entry);
        snapshot
            .pending
            .conversations
            .insert(conversation_id, conversation);
        snapshot
            .pending
            .route_objects
            .insert(conversation_id, bytes);
        Ok(())
    }

    /// `ESTATE END`: the complete page is staged as one bounded batch; a
    /// cursor continues with FETCH after the commit, and `*` verifies the
    /// whole generation and records READY in the same batch as its last page.
    pub(super) fn state_end(
        &mut self,
        context: &mut StateCoreContext,
        token: [u8; 32],
        page_sequence: u32,
        next_cursor: Option<[u8; 32]>,
    ) -> Result<(), Refusal> {
        let now = context.now().get();
        let snapshot = self.snapshot.as_mut().ok_or(E2eeReplyCode::Syncing)?;
        let complete = matches!(snapshot.stage, Stage::Staging)
            && snapshot.token == token
            && snapshot.next_page == page_sequence
            && snapshot.page_writes.len() == usize::try_from(snapshot.page_expected).unwrap_or(1)
            && !snapshot.expired(now);
        if !complete {
            return Err(E2eeReplyCode::Syncing.into());
        }
        let staged_entries = snapshot
            .staged_entries
            .checked_add(snapshot.page_expected)
            .ok_or(E2eeReplyCode::Syncing)?;
        let final_page = next_cursor.is_none();
        if final_page {
            let ordered_ids = snapshot.pending.route_objects.len();
            let digest = snapshot
                .running
                .take()
                .ok_or(E2eeReplyCode::Syncing)?
                .finish()
                .map_err(|_| E2eeReplyCode::Syncing)?;
            // The exact partition already makes the count exact; the
            // digest is the verification.
            let counted = staged_entries == snapshot.total;
            let retained = ordered_ids == usize::try_from(snapshot.total).unwrap_or(usize::MAX);
            (counted & retained & (digest == snapshot.digest))
                .then_some(())
                .ok_or(E2eeReplyCode::Syncing)?;
        }
        snapshot.staged_entries = staged_entries;
        snapshot.staged_bytes = snapshot
            .staged_bytes
            .saturating_add(u64::try_from(snapshot.page_bytes).unwrap_or(u64::MAX));
        snapshot.page_bytes = 0;
        snapshot.next_page = snapshot.next_page.saturating_add(1);
        let phase = if final_page {
            SnapshotPhase::Ready
        } else {
            SnapshotPhase::Staging
        };
        let mut writes = std::mem::take(&mut snapshot.page_writes);
        writes.push(self.marker_write(phase, None)?);
        let pending = match next_cursor {
            Some(cursor) => PendingCommit::SnapshotPage { cursor },
            None => PendingCommit::Ready,
        };
        self.stage(context, writes, pending)
    }

    /// The marker row write for the current generation.
    fn marker_write(
        &self,
        phase: SnapshotPhase,
        switched_through: Option<[u8; 32]>,
    ) -> Result<AccountServiceDurableWrite, Refusal> {
        let snapshot = self.snapshot.as_ref().ok_or(E2eeReplyCode::Syncing)?;
        let row = snapshot.marker(phase, switched_through);
        state_row(
            SnapshotMarkerRow::key(self.config.coordinator_server_id.as_bytes())
                .map_err(|_| E2eeReplyCode::InvalidFragment)?,
            SNAPSHOT_MARKER_ROW_KIND,
            row.encode().map_err(|_| E2eeReplyCode::InvalidFragment)?,
        )
    }

    /// The write that removes the generation's marker.
    fn marker_delete(&self) -> Result<AccountServiceDurableWrite, Refusal> {
        let key = SnapshotMarkerRow::key(self.config.coordinator_server_id.as_bytes())
            .map_err(|_| E2eeReplyCode::InvalidFragment)?;
        AccountServiceDurableWrite::delete(TableId::E2eeState, key)
            .map_err(|_| E2eeReplyCode::InvalidFragment.into())
    }

    /// A page committed: the next page is fetched.
    pub(super) fn snapshot_page_committed(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        cursor: [u8; 32],
    ) {
        let _fetched = self.try_fetch_next(context, edge, cursor);
    }

    fn try_fetch_next(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        cursor: [u8; 32],
    ) -> Option<bool> {
        let frame = self.fetch_frame(cursor)?;
        let line = self.line(&frame).ok()?;
        Some(self.send(context, edge, vec![line]))
    }

    /// The FETCH frame for the next page of the open generation.
    fn fetch_frame(&self, cursor: [u8; 32]) -> Option<CompanionFrame> {
        let snapshot = self.snapshot.as_ref()?;
        Some(CompanionFrame::StateFetch {
            coordinator_server_id: *self.config.coordinator_server_id.as_bytes(),
            snapshot_token: snapshot.token,
            next_page_sequence: snapshot.next_page,
            cursor,
        })
    }

    /// The READY marker committed: the generation is durable and READY goes
    /// out; the delivery position does not move until ACTIVE.
    pub(super) fn ready_recorded(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
    ) {
        let _marked = self.snapshot.as_mut().map(|snapshot| {
            snapshot.stage = Stage::Ready;
        });
        // On the link that transferred it READY goes out now; after a link
        // loss the next link announces it.
        if self.phase == Phase::Transferring {
            self.resend_ready(context, edge);
        }
    }

    /// `ESTATE ACTIVE`: the exact cut of the durable READY generation is
    /// recorded active together with the new delivery cursor; the swap
    /// happens when that batch commits.
    pub(super) fn state_active(
        &mut self,
        context: &mut StateCoreContext,
        token: [u8; 32],
        state_generation: u64,
        delivery_generation: u64,
        digest: [u8; 32],
    ) -> Result<(), Refusal> {
        let snapshot = self.snapshot.as_ref().ok_or(E2eeReplyCode::Syncing)?;
        let matches = self.phase == Phase::AwaitingActive
            && matches!(snapshot.stage, Stage::Ready)
            && snapshot.cut_matches(token, state_generation, delivery_generation, digest);
        if !matches {
            return Err(E2eeReplyCode::Syncing.into());
        }
        let delivery = DeliveryState {
            generation: delivery_generation,
            cursor: None,
        };
        let writes = vec![
            self.marker_write(SnapshotPhase::Active, None)?,
            super::events::cursor_write(&self.config, &delivery).map_err(Refusal::from)?,
        ];
        self.stage(context, writes, PendingCommit::SnapshotActive)
    }

    /// The ACTIVE marker committed: the pending projection becomes the live
    /// one, the delivery position restarts in the new generation, the
    /// origins replay, and the migration begins.
    pub(super) fn snapshot_active_committed(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
    ) {
        let _swapped = self.try_activate(context, edge);
    }

    fn try_activate(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
    ) -> Option<()> {
        let snapshot = self.snapshot.as_mut()?;
        let pending = std::mem::take(&mut snapshot.pending);
        let remaining: BTreeSet<[u8; 32]> = pending.route_objects.keys().copied().collect();
        let stale: BTreeSet<[u8; 32]> = self
            .route_objects
            .keys()
            .filter(|conversation| !remaining.contains(*conversation))
            .copied()
            .collect();
        snapshot.stage = Stage::Active {
            switched_through: None,
            remaining,
            stale,
        };
        self.routes = pending.routes;
        self.conversations = pending.conversations;
        self.route_objects = pending.route_objects;
        self.delivery = DeliveryState {
            generation: snapshot.delivery_generation,
            cursor: None,
        };
        self.witness_snapshot_required = false;
        edge.note_companion_delivery(self.delivery.generation, None);
        if self.begin_origins(context, edge).is_err() {
            self.fail_frame(context, edge);
        }
        Some(())
    }

    /// A migration or cleanup step committed.
    pub(super) fn snapshot_step_committed(
        &mut self,
        done: bool,
        switched_through: Option<[u8; 32]>,
    ) {
        let _advanced = self.try_step_committed(switched_through);
        if done {
            self.snapshot = None;
        }
    }

    /// Advances the migration cursor of a live generation.
    fn try_step_committed(&mut self, switched_through: Option<[u8; 32]>) -> Option<()> {
        let snapshot = self.snapshot.as_mut()?;
        if let Stage::Active {
            switched_through: cursor,
            ..
        } = &mut snapshot.stage
            && switched_through.is_some()
        {
            *cursor = switched_through;
        }
        Some(())
    }

    /// Stages the next bounded migration or cleanup batch when no other
    /// batch is pending; a live generation's rows migrate into the active
    /// keys and an abandoned generation's rows are deleted, the marker
    /// last.
    pub fn continue_snapshot(&mut self, context: &mut StateCoreContext) {
        let busy = self.commit.is_some() | context.in_flight() | (context.pending_len() != 0);
        if busy {
            return;
        }
        if self.snapshot.is_none() {
            self.continue_strays(context);
            return;
        }
        let _stepped = self.try_continue_snapshot(context);
    }

    fn try_continue_snapshot(&mut self, context: &mut StateCoreContext) -> Option<()> {
        let snapshot = self.snapshot.as_mut()?;
        let generation = snapshot.delivery_generation;
        let step = match &mut snapshot.stage {
            Stage::Active {
                remaining, stale, ..
            } => migration_step(&self.route_objects, generation, remaining, stale),
            Stage::Discarding { keys } => discard_step(generation, keys),
            Stage::Staging | Stage::Ready => return None,
        };
        let (mut writes, done, switched_through) = step.ok()?;
        let marker = if done {
            self.marker_delete()
        } else {
            self.marker_write(SnapshotPhase::Active, switched_through)
        };
        writes.push(marker.ok()?);
        let _staged = self.stage(
            context,
            writes,
            PendingCommit::SnapshotStep {
                done,
                switched_through,
            },
        );
        Some(())
    }

    /// The link went down: a generation still being received is abandoned
    /// and cleaned up; a READY or ACTIVE generation is durable and kept.
    pub(super) fn snapshot_link_down(&mut self) {
        let _abandoned = self.try_abandon_staging();
    }

    fn try_abandon_staging(&mut self) -> Option<()> {
        let snapshot = self.snapshot.as_mut()?;
        if !matches!(snapshot.stage, Stage::Staging) {
            return None;
        }
        let keys: Vec<[u8; 32]> = snapshot
            .pending
            .route_objects
            .keys()
            .take(usize::try_from(snapshot.staged_entries).unwrap_or(usize::MAX))
            .copied()
            .collect();
        snapshot.pending = PendingProjection::default();
        snapshot.permits.clear();
        snapshot.page_writes.clear();
        snapshot.running = None;
        // A page is durable (or committing) once END staged it.
        if snapshot.next_page == 0 {
            self.snapshot = None;
            return Some(());
        }
        snapshot.stage = Stage::Discarding { keys };
        Some(())
    }

    /// The live route change of `conversation` during a migration also
    /// refreshes its pending row so the migration copies the current
    /// object, or removes it from the migration when hidden.
    pub(super) fn snapshot_live_change(
        &mut self,
        conversation: [u8; 32],
        row: Option<&RouteRow>,
        writes: &mut Vec<AccountServiceDurableWrite>,
    ) -> Result<(), Refusal> {
        let Some(snapshot) = self.snapshot.as_mut() else {
            return Ok(());
        };
        let generation = snapshot.delivery_generation;
        let Stage::Active {
            switched_through,
            remaining,
            stale,
        } = &mut snapshot.stage
        else {
            return Ok(());
        };
        let migrated = switched_through.is_some_and(|cursor| conversation <= cursor);
        stale.remove(&conversation);
        let key = PendingRouteRow::key(generation, &conversation)
            .map_err(|_| E2eeReplyCode::InvalidFragment)?;
        match row {
            Some(row) if !migrated => {
                remaining.insert(conversation);
                writes.push(state_row(
                    key,
                    PENDING_ROUTE_ROW_KIND,
                    PendingRouteRow::encode_route(row)
                        .map_err(|_| E2eeReplyCode::InvalidFragment)?,
                )?);
            }
            None if remaining.remove(&conversation) => {
                writes.push(
                    AccountServiceDurableWrite::delete(TableId::E2eeState, key)
                        .map_err(|_| E2eeReplyCode::InvalidFragment)?,
                );
            }
            _ => {}
        }
        Ok(())
    }
}

type Step = Result<(Vec<AccountServiceDurableWrite>, bool, Option<[u8; 32]>), Refusal>;

/// One migration batch: in conversation order, a stale active row of the
/// previous generation is deleted and a remaining conversation is written to
/// its active key and removed from the pending keys, until `STEP_ROWS` rows;
/// every stale row before the new cursor is therefore gone once the cursor
/// passes it. `done` when nothing remains.
fn migration_step(
    route_objects: &BTreeMap<[u8; 32], Vec<u8>>,
    generation: u64,
    remaining: &mut BTreeSet<[u8; 32]>,
    stale: &mut BTreeSet<[u8; 32]>,
) -> Step {
    let mut writes = Vec::new();
    let mut cursor = None;
    while writes.len().saturating_add(2) <= STEP_ROWS {
        let next = remaining.first().copied();
        match (next, stale.first().copied()) {
            (_, Some(old)) if next.is_none_or(|new| old < new) => {
                stale.remove(&old);
                writes.push(
                    AccountServiceDurableWrite::delete(
                        TableId::E2eeState,
                        RouteRow::key(&old).map_err(|_| E2eeReplyCode::InvalidFragment)?,
                    )
                    .map_err(|_| E2eeReplyCode::InvalidFragment)?,
                );
            }
            (Some(new), _none_or_later) => {
                remaining.remove(&new);
                let bytes = route_objects.get(&new).ok_or(E2eeReplyCode::Syncing)?;
                let (state, _, _) = super::events::decode_route_state(bytes)?;
                let row = super::events::route_row(&state, bytes);
                writes.push(state_row(
                    RouteRow::key(&new).map_err(|_| E2eeReplyCode::InvalidFragment)?,
                    ROUTE_ROW_KIND,
                    row.encode().map_err(|_| E2eeReplyCode::InvalidFragment)?,
                )?);
                writes.push(
                    AccountServiceDurableWrite::delete(
                        TableId::E2eeState,
                        PendingRouteRow::key(generation, &new)
                            .map_err(|_| E2eeReplyCode::InvalidFragment)?,
                    )
                    .map_err(|_| E2eeReplyCode::InvalidFragment)?,
                );
                cursor = Some(new);
            }
            (None, _) => break,
        }
    }
    let done = remaining.is_empty() & stale.is_empty();
    Ok((writes, done, cursor))
}

/// One cleanup batch of an abandoned generation.
fn discard_step(generation: u64, keys: &mut Vec<[u8; 32]>) -> Step {
    let mut writes = Vec::new();
    while writes.len() < STEP_ROWS {
        let Some(conversation) = keys.pop() else {
            break;
        };
        writes.push(
            AccountServiceDurableWrite::delete(
                TableId::E2eeState,
                PendingRouteRow::key(generation, &conversation)
                    .map_err(|_| E2eeReplyCode::InvalidFragment)?,
            )
            .map_err(|_| E2eeReplyCode::InvalidFragment)?,
        );
    }
    Ok((writes, keys.is_empty(), None))
}

impl E2eeEdge {
    /// A pending row of another generation than the marker's: deleted with
    /// the abandoned rows.
    pub(super) fn snapshot_stray_row(&mut self, generation: u64, conversation: [u8; 32]) {
        let stray = self.snapshot_strays.entry(generation).or_default();
        stray.push(conversation);
    }

    /// One restored pending row of the marker's generation.
    pub(super) fn snapshot_restore_entry(
        &mut self,
        conversation: [u8; 32],
        entry: agenc_ircd_domain::e2ee::RouteEntry,
        facts: Conversation,
        bytes: &[u8],
    ) -> Result<(), crate::RuntimeError> {
        let port = self.snapshot_backing.clone();
        let snapshot = self
            .snapshot
            .as_mut()
            .ok_or(crate::RuntimeError::InvalidValue)?;
        let permit = port
            .ok_or(crate::RuntimeError::InvalidValue)?
            .reserve(bytes.len().saturating_add(ENTRY_OVERHEAD))?;
        snapshot.permits.push(permit);
        match &mut snapshot.stage {
            Stage::Discarding { keys } => keys.push(conversation),
            Stage::Ready => {
                snapshot.pending.routes.restore_entry(entry);
                snapshot.pending.conversations.insert(conversation, facts);
                snapshot
                    .pending
                    .route_objects
                    .insert(conversation, bytes.to_vec());
            }
            Stage::Active { remaining, .. } => {
                // Beyond the migration cursor the pending row is the live
                // route; before it the row is a leftover of a batch whose
                // deletion did not land, and migrates again.
                remaining.insert(conversation);
                self.routes.restore_entry(entry);
                self.conversations.insert(conversation, facts);
                self.route_objects.insert(conversation, bytes.to_vec());
            }
            Stage::Staging => return Err(crate::RuntimeError::InvalidValue),
        }
        Ok(())
    }

    /// Whether a restored active route row is authoritative: not while a
    /// migrating generation owns the conversation through its pending row
    /// (beyond the cursor), and a row beyond the cursor without a pending
    /// row is a stale row of the previous generation.
    pub(super) fn snapshot_admits_active_row(&mut self, conversation: &[u8; 32]) -> bool {
        let Some(Stage::Active {
            switched_through,
            remaining,
            stale,
        }) = self.snapshot.as_mut().map(|snapshot| &mut snapshot.stage)
        else {
            return true;
        };
        if switched_through.is_some_and(|cursor| *conversation <= cursor) {
            return true;
        }
        if !remaining.contains(conversation) {
            stale.insert(*conversation);
        }
        false
    }

    /// After the restore scan: a READY generation must hold every entry,
    /// and abandoned rows are queued for deletion.
    pub(super) fn snapshot_finish_restore(&mut self) -> Result<(), Refusal> {
        let strays = std::mem::take(&mut self.snapshot_strays);
        if let Some(snapshot) = self.snapshot.as_mut()
            && matches!(snapshot.stage, Stage::Ready)
            && snapshot.pending.route_objects.len()
                != usize::try_from(snapshot.total).map_err(|_| E2eeReplyCode::Syncing)?
        {
            return Err(E2eeReplyCode::Syncing.into());
        }
        if !strays.is_empty() {
            self.snapshot_stray_generations = strays;
        }
        Ok(())
    }
}

impl E2eeEdge {
    /// Deletes the pending rows of generations no marker describes, one
    /// bounded batch at a time.
    fn continue_strays(&mut self, context: &mut StateCoreContext) {
        let _dropped = self.try_continue_strays(context);
    }

    fn try_continue_strays(&mut self, context: &mut StateCoreContext) -> Option<()> {
        let (generation, keys) = self.snapshot_stray_generations.iter_mut().next()?;
        let generation = *generation;
        let (writes, done, _) = discard_step(generation, keys).ok()?;
        if done {
            self.snapshot_stray_generations.remove(&generation);
        }
        if writes.is_empty() {
            return None;
        }
        let _staged = self.stage(
            context,
            writes,
            PendingCommit::SnapshotStep {
                done: false,
                switched_through: None,
            },
        );
        Some(())
    }
}
