//! The ESTATE receiver as a bounded durable pending-generation owner
//! (companion 12.5): pages stage in their own batches, READY and ACTIVE are
//! exact durable phases, and refusals retain nothing.
#![forbid(unsafe_code)]

use agenc_relay_domain::e2ee::limits::MAX_BATCH_OBJECTS;
use agenc_relay_e2ee::ids::federation_snapshot_digest;
use agenc_relay_e2ee::limits::MAX_FEDERATION_STATE_ENTRIES_PER_EDGE;
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::conversation::ArcConversationKind;
use agenc_relay_e2ee::objects::federation::{ArcFederationRouteState, ArcRouteStateKind};
use agenc_relay_e2ee::tls::{Opaque, TlsEncode};
use agenc_relay_e2ee::wire::fragment::fragment_object;
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;
use agenc_relay_storage::PersistentRecordValue;
use agenc_relay_storage::e2ee_records::{RouteRow, SnapshotMarkerRow};

use super::projection::{CONVERSATION, base_edge, install_route};
use super::*;
use crate::budget::{BackingReservationPort, MemoryBudget};
use crate::e2ee::edge::snapshot::{Stage, page_partition};
use crate::federation::edge::EdgeFederation;
use crate::state_core::durable::AccountServiceDurableWrite;
use crate::sync::Arc;
use crate::test_support::StateCoreFixture;

const TOKEN: [u8; 32] = [6; 32];
const STATE_GENERATION: u64 = 5;
const DELIVERY_GENERATION: u64 = 2;

pub(super) fn install_backing(edge: &mut E2eeEdge) {
    edge.install_snapshot_backing(BackingReservationPort::new(Arc::new(MemoryBudget::new(
        64 << 20,
    ))));
}

fn route_state(seed: u8, sequence: u64) -> TestResult<Vec<u8>> {
    let state = ArcFederationRouteState {
        profile_version: 1,
        network_id: [1; 32],
        state_generation: 4,
        conversation_id: [seed; 32],
        conversation_kind: ArcConversationKind::Channel,
        route_binding: [26; 32],
        semantic_route_lock_id: [23; 32],
        channel_instance_id: Opaque::new([seed; 16].to_vec())?,
        canonical_channel_name_hash: [116; 32],
        direct_account_a: Opaque::new(Vec::new())?,
        direct_account_b: Opaque::new(Vec::new())?,
        binding_id: [34; 32],
        finalized_epoch: 1,
        accepted_state_id: [58; 32],
        sequencer_record_head_sequence: sequence,
        sequencer_record_head_id: [59; 32],
        state: ArcRouteStateKind::ActiveRoute,
    };
    Ok(ArcWireObject::new(ArcWireObjectKind::FederationState, state.encode()?)?.encode()?)
}

fn object_id(bytes: &[u8]) -> [u8; 32] {
    *agenc_relay_e2ee::ObjectId::compute(bytes).as_bytes()
}

/// `count` entries with distinct ascending conversations.
fn entries(count: usize) -> TestResult<Vec<([u8; 32], Vec<u8>)>> {
    (0..count)
        .map(|index| {
            let seed = u8::try_from(index + 10)?;
            Ok(([seed; 32], route_state(seed, 4)?))
        })
        .collect()
}

fn digest_of(entries: &[([u8; 32], Vec<u8>)]) -> TestResult<[u8; 32]> {
    let ids: Vec<[u8; 32]> = entries.iter().map(|(_, bytes)| object_id(bytes)).collect();
    Ok(federation_snapshot_digest(
        STATE_GENERATION,
        DELIVERY_GENERATION,
        &ids,
    )?)
}

struct Fixture {
    core: StateCoreFixture,
    edge: E2eeEdge,
    base: EdgeFederation,
    /// Whether the base edge is left without the entitlement an entry
    /// needs; the receiver's own tests host every channel they feed.
    unentitled: bool,
}

impl Fixture {
    fn resuming(prior_route: bool) -> TestResult<Self> {
        let core = StateCoreFixture::new(vec![0; 4_096])?;
        let mut edge = edge();
        install_backing(&mut edge);
        if prior_route {
            install_route(&mut edge)?;
            edge.link_down();
        }
        let mut fixture = Self {
            core,
            edge,
            base: base_edge(),
            unentitled: false,
        };
        fixture
            .edge
            .link_active(fixture.core.context_mut()?, &mut fixture.base);
        assert_eq!(fixture.edge.phase(), Phase::Resuming);
        Ok(fixture)
    }

    fn begin(&mut self, page: u32, total: u32, count: u32, digest: [u8; 32]) -> Result<(), String> {
        let context = self.core.context_mut().map_err(|error| error.to_string())?;
        self.edge
            .state_begin(
                context,
                &self.base,
                TOKEN,
                STATE_GENERATION,
                DELIVERY_GENERATION,
                page,
                total,
                count,
                digest,
            )
            .map_err(|refusal| refusal.code.to_string())
    }

    fn entry(&mut self, page: u32, conversation: [u8; 32], bytes: &[u8]) -> Result<(), String> {
        self.entry_named(page, conversation, object_id(bytes), bytes)
    }

    fn entry_named(
        &mut self,
        page: u32,
        conversation: [u8; 32],
        id: [u8; 32],
        bytes: &[u8],
    ) -> Result<(), String> {
        self.host_entry(bytes)?;
        for fragment in fragment_object(bytes).map_err(|error| error.to_string())? {
            let context = self.core.context_mut().map_err(|error| error.to_string())?;
            self.edge
                .state_entry(context, &self.base, TOKEN, page, conversation, id, fragment)
                .map_err(|refusal| refusal.code.to_string())?;
        }
        Ok(())
    }

    /// Gives the base edge the channel-detail entitlement of the channel
    /// route `bytes` carries, as a coordinator cut presumes (companion 12.5).
    fn host_entry(&mut self, bytes: &[u8]) -> Result<(), String> {
        let channel = crate::e2ee::edge::events::decode_route_state(bytes)
            .ok()
            .and_then(|(_, _, facts)| facts.channel);
        match channel {
            Some(channel) if !self.unentitled => {
                crate::federation::edge::host_channels(&mut self.base, &[channel])
                    .map_err(|error| error.to_string())
            }
            _ => Ok(()),
        }
    }

    fn end(&mut self, page: u32, cursor: Option<[u8; 32]>) -> Result<(), String> {
        let context = self.core.context_mut().map_err(|error| error.to_string())?;
        self.edge
            .state_end(context, TOKEN, page, cursor)
            .map_err(|refusal| refusal.code.to_string())
    }

    /// The rows the last stage call put in the batch, then the commit.
    fn commit(&mut self) -> TestResult<Vec<AccountServiceDurableWrite>> {
        let rows = self.core.context_mut()?.staged_rows_for_test()?;
        self.core.context_mut()?.discard_pending_for_test();
        self.edge
            .batch_applied(self.core.context_mut()?, &mut self.base);
        Ok(rows)
    }

    fn activate(&mut self, digest: [u8; 32]) -> Result<(), String> {
        let context = self.core.context_mut().map_err(|error| error.to_string())?;
        self.edge
            .state_active(
                context,
                TOKEN,
                STATE_GENERATION,
                DELIVERY_GENERATION,
                digest,
            )
            .map_err(|refusal| refusal.code.to_string())
    }

    /// Feeds every page of `entries` and returns the rows of each page batch.
    fn transfer(
        &mut self,
        entries: &[([u8; 32], Vec<u8>)],
    ) -> TestResult<Vec<Vec<AccountServiceDurableWrite>>> {
        let digest = digest_of(entries)?;
        let total = u32::try_from(entries.len())?;
        let pages = entries.len().div_ceil(MAX_BATCH_OBJECTS).max(1);
        let mut batches = Vec::new();
        for page in 0..pages {
            let slice = entries
                .iter()
                .skip(page * MAX_BATCH_OBJECTS)
                .take(MAX_BATCH_OBJECTS)
                .collect::<Vec<_>>();
            let page = u32::try_from(page)?;
            self.begin(page, total, u32::try_from(slice.len())?, digest)?;
            for (conversation, bytes) in slice {
                self.entry(page, *conversation, bytes)?;
            }
            let last = usize::try_from(page)? + 1 == pages;
            self.end(page, (!last).then_some([page as u8 + 1; 32]))?;
            batches.push(self.commit()?);
        }
        Ok(batches)
    }
}

fn kinds(rows: &[AccountServiceDurableWrite]) -> Vec<(bool, Vec<u8>)> {
    rows.iter()
        .map(|write| match write {
            AccountServiceDurableWrite::Put { key, .. } => (true, key.as_bytes().to_vec()),
            AccountServiceDurableWrite::Delete { key, .. } => (false, key.as_bytes().to_vec()),
        })
        .collect()
}

fn marker_of(rows: &[AccountServiceDurableWrite]) -> TestResult<Option<SnapshotMarkerRow>> {
    let key = SnapshotMarkerRow::key(&[3; 16])?;
    for write in rows {
        if let AccountServiceDurableWrite::Put {
            table,
            key: stored,
            plaintext,
        } = write
            && *stored == key
        {
            let value = PersistentRecordValue::decode(*table, plaintext)?;
            return Ok(Some(SnapshotMarkerRow::decode(value.body())?));
        }
    }
    Ok(None)
}

#[tokio::test]
async fn pages_stage_in_bounded_batches_and_activate_exactly_once() -> TestResult {
    let entries = entries(MAX_BATCH_OBJECTS + 1)?;
    let mut fixture = Fixture::resuming(true)?;
    let batches = fixture.transfer(&entries)?;
    assert_eq!(batches.len(), 2);
    // Every page is its own batch: its pending rows and the marker.
    assert_eq!(
        batches.iter().map(Vec::len).collect::<Vec<_>>(),
        vec![MAX_BATCH_OBJECTS + 1, 2]
    );
    let first = marker_of(batches.first().ok_or("batch 0")?)?.ok_or("first marker")?;
    assert_eq!(
        (first.phase, first.staged_entries, first.total_entries),
        (
            agenc_relay_storage::e2ee_records::SnapshotPhase::Staging,
            32,
            33
        )
    );
    let ready = marker_of(batches.get(1).ok_or("batch 1")?)?.ok_or("ready marker")?;
    assert_eq!(
        (ready.phase, ready.staged_entries),
        (agenc_relay_storage::e2ee_records::SnapshotPhase::Ready, 33)
    );
    assert!(
        kinds(batches.first().ok_or("batch 0")?)
            .iter()
            .all(|(put, key)| {
                *put && (key.starts_with(b"pending-route/v1/")
                    || key.starts_with(b"edge-snapshot/v1/"))
            })
    );
    assert_eq!(fixture.edge.phase(), Phase::AwaitingActive);
    // The prior route is still the live projection until ACTIVE.
    assert_eq!(fixture.edge.route_objects.len(), 1);
    assert!(matches!(
        fixture
            .edge
            .snapshot
            .as_ref()
            .map(|snapshot| &snapshot.stage),
        Some(Stage::Ready)
    ));
    fixture.activate(digest_of(&entries)?)?;
    let active = fixture.commit()?;
    assert_eq!(active.len(), 2, "the marker and the new cursor");
    assert_eq!(
        marker_of(&active)?.map(|marker| marker.phase),
        Some(agenc_relay_storage::e2ee_records::SnapshotPhase::Active)
    );
    assert_eq!(fixture.edge.route_objects.len(), entries.len());
    assert!(
        !fixture
            .edge
            .route_objects
            .contains_key(&super::projection::CONVERSATION)
    );
    assert_eq!(fixture.edge.delivery.generation, DELIVERY_GENERATION);
    assert_eq!(fixture.edge.delivery.cursor, None);
    // The migration copies every pending row into its active key, deletes
    // the pending rows and the stale prior route, then drops the marker.
    fixture.edge.continue_snapshot(fixture.core.context_mut()?);
    let step = fixture.commit()?;
    let rows = kinds(&step);
    assert_eq!(
        rows.iter()
            .filter(|(put, key)| *put && key.starts_with(b"route/v1/"))
            .count(),
        entries.len()
    );
    assert_eq!(
        rows.iter()
            .filter(|(put, key)| !*put && key.starts_with(b"pending-route/v1/"))
            .count(),
        entries.len()
    );
    assert!(
        rows.contains(&(
            false,
            RouteRow::key(&super::projection::CONVERSATION)?
                .as_bytes()
                .to_vec()
        ))
    );
    assert!(rows.contains(&(false, SnapshotMarkerRow::key(&[3; 16])?.as_bytes().to_vec())));
    assert!(fixture.edge.snapshot.is_none());
    Ok(())
}

#[tokio::test]
async fn declarations_and_pages_beyond_the_contract_are_refused_without_retention() -> TestResult {
    let entries = entries(3)?;
    let digest = digest_of(&entries)?;
    // A declared count above the ceiling is refused before any allocation.
    let mut fixture = Fixture::resuming(false)?;
    let over = u32::try_from(MAX_FEDERATION_STATE_ENTRIES_PER_EDGE + 1)?;
    assert_eq!(
        fixture.begin(0, over, 32, digest),
        Err(E2eeReplyCode::Syncing.to_string())
    );
    assert!(fixture.edge.snapshot.is_none());
    // A wrong first-page partition.
    assert_eq!(
        fixture.begin(0, 40, 31, digest),
        Err(E2eeReplyCode::Syncing.to_string())
    );
    assert!(fixture.edge.snapshot.is_none());
    // Entries out of conversation order, or naming another object.
    fixture.begin(0, 3, 3, digest)?;
    fixture.entry(
        0,
        entries.get(1).ok_or("entry")?.0,
        &entries.get(1).ok_or("entry")?.1,
    )?;
    assert_eq!(
        fixture.entry(
            0,
            entries.first().ok_or("entry")?.0,
            &entries.first().ok_or("entry")?.1
        ),
        Err(E2eeReplyCode::Syncing.to_string())
    );
    let mut fixture = Fixture::resuming(false)?;
    fixture.begin(0, 3, 3, digest)?;
    assert_eq!(
        fixture.entry_named(
            0,
            entries.first().ok_or("entry")?.0,
            [77; 32],
            &entries.first().ok_or("entry")?.1
        ),
        Err(E2eeReplyCode::InvalidFragment.to_string())
    );
    // Too many entries for the page, and END before the page is complete.
    let mut fixture = Fixture::resuming(false)?;
    fixture.begin(0, 2, 2, digest)?;
    fixture.entry(
        0,
        entries.first().ok_or("entry")?.0,
        &entries.first().ok_or("entry")?.1,
    )?;
    fixture.entry(
        0,
        entries.get(1).ok_or("entry")?.0,
        &entries.get(1).ok_or("entry")?.1,
    )?;
    assert_eq!(
        fixture.entry(
            0,
            entries.get(2).ok_or("entry")?.0,
            &entries.get(2).ok_or("entry")?.1
        ),
        Err(E2eeReplyCode::Syncing.to_string())
    );
    let mut fixture = Fixture::resuming(false)?;
    fixture.begin(0, 3, 3, digest)?;
    fixture.entry(
        0,
        entries.first().ok_or("entry")?.0,
        &entries.first().ok_or("entry")?.1,
    )?;
    assert_eq!(
        fixture.end(0, None),
        Err(E2eeReplyCode::Syncing.to_string())
    );
    // A digest or count that does not match the transferred set.
    let mut fixture = Fixture::resuming(false)?;
    fixture.begin(0, 3, 3, [99; 32])?;
    for (conversation, bytes) in &entries {
        fixture.entry(0, *conversation, bytes)?;
    }
    assert_eq!(
        fixture.end(0, None),
        Err(E2eeReplyCode::Syncing.to_string())
    );
    assert!(
        fixture
            .core
            .context_mut()?
            .staged_rows_for_test()?
            .is_empty()
    );
    // A second page that changes the cut.
    let mut fixture = Fixture::resuming(false)?;
    let two_pages = self::entries(MAX_BATCH_OBJECTS + 1)?;
    let digest = digest_of(&two_pages)?;
    fixture.begin(0, 33, 32, digest)?;
    for (conversation, bytes) in two_pages.iter().take(MAX_BATCH_OBJECTS) {
        fixture.entry(0, *conversation, bytes)?;
    }
    fixture.end(0, Some([1; 32]))?;
    fixture.commit()?;
    assert_eq!(
        fixture.begin(1, 33, 1, [98; 32]),
        Err(E2eeReplyCode::Syncing.to_string())
    );
    assert_eq!(
        fixture.begin(2, 33, 1, digest),
        Err(E2eeReplyCode::Syncing.to_string())
    );
    fixture.begin(1, 33, 1, digest)?;
    Ok(())
}

#[tokio::test]
async fn an_expired_token_and_a_lost_link_abandon_the_staged_generation() -> TestResult {
    let entries = entries(MAX_BATCH_OBJECTS + 1)?;
    let digest = digest_of(&entries)?;
    let mut fixture = Fixture::resuming(false)?;
    fixture.begin(0, 33, 32, digest)?;
    for (conversation, bytes) in entries.iter().take(MAX_BATCH_OBJECTS) {
        fixture.entry(0, *conversation, bytes)?;
    }
    fixture.end(0, Some([1; 32]))?;
    fixture.commit()?;
    // The lifetime is measured from page zero and never extended.
    let opened_at = fixture
        .edge
        .snapshot
        .as_ref()
        .map(|snapshot| snapshot.opened_at)
        .ok_or("snapshot")?;
    let deadline = opened_at + 15 * 60 * 1_000;
    let now = fixture.core.context_mut()?.now().get();
    assert!(now < deadline);
    fixture.core.context_mut()?.set_monotonic_for_test(deadline);
    assert_eq!(
        fixture.begin(1, 33, 1, digest),
        Err(E2eeReplyCode::Syncing.to_string())
    );
    // The link drops: the durable page rows are deleted in bounded batches,
    // then the marker; nothing of the generation is live.
    fixture.edge.link_down();
    assert!(matches!(
        fixture.edge.snapshot.as_ref().map(|snapshot| &snapshot.stage),
        Some(Stage::Discarding { keys }) if keys.len() == MAX_BATCH_OBJECTS
    ));
    assert!(fixture.edge.route_objects.is_empty());
    fixture.edge.continue_snapshot(fixture.core.context_mut()?);
    let step = fixture.commit()?;
    let rows = kinds(&step);
    assert_eq!(rows.len(), MAX_BATCH_OBJECTS + 1);
    assert!(rows.iter().all(|(put, _)| !*put));
    assert!(rows.contains(&(false, SnapshotMarkerRow::key(&[3; 16])?.as_bytes().to_vec())));
    assert!(fixture.edge.snapshot.is_none());
    Ok(())
}

#[tokio::test]
async fn memory_admission_refuses_an_entry_before_it_is_retained() -> TestResult {
    let entries = entries(2)?;
    let digest = digest_of(&entries)?;
    let mut fixture = Fixture::resuming(false)?;
    fixture
        .edge
        .install_snapshot_backing(BackingReservationPort::new(Arc::new(MemoryBudget::new(16))));
    fixture.begin(0, 2, 2, digest)?;
    assert_eq!(
        fixture.entry(
            0,
            entries.first().ok_or("entry")?.0,
            &entries.first().ok_or("entry")?.1
        ),
        Err(E2eeReplyCode::RateLimited.to_string())
    );
    let snapshot = fixture.edge.snapshot.as_ref().ok_or("snapshot")?;
    assert!(snapshot.pending.route_objects.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_cut_behind_the_witnessed_head_is_a_witness_violation() -> TestResult {
    let mut fixture = Fixture::resuming(true)?;
    // The prior route's head is at sequence 4; a snapshot cut at 3 for the
    // same conversation goes backwards.
    let behind = route_state(9, 3)?;
    let entries = vec![([9; 32], behind)];
    let digest = digest_of(&entries)?;
    fixture.begin(0, 1, 1, digest)?;
    assert_eq!(
        fixture.entry(0, [9; 32], &entries.first().ok_or("entry")?.1),
        Err(E2eeReplyCode::RouteInvalid.to_string())
    );
    assert!(fixture.edge.witnessed.is_some());
    Ok(())
}

/// The durable rows of one route as the receiver writes them.
fn pending_row(generation: u64, bytes: &[u8]) -> TestResult<AccountServiceDurableWrite> {
    let (state, _, _) = crate::e2ee::edge::events::decode_route_state(bytes)
        .map_err(|refusal| refusal.code.to_string())?;
    let row = crate::e2ee::edge::events::route_row(&state, bytes);
    Ok(crate::e2ee::edge::events::state_row(
        agenc_relay_storage::e2ee_records::PendingRouteRow::key(
            generation,
            &state.conversation_id,
        )?,
        agenc_relay_storage::e2ee_records::PENDING_ROUTE_ROW_KIND,
        agenc_relay_storage::e2ee_records::PendingRouteRow::encode_route(&row)?,
    )
    .map_err(|refusal| refusal.code.to_string())?)
}

fn active_row(bytes: &[u8]) -> TestResult<AccountServiceDurableWrite> {
    let (state, _, _) = crate::e2ee::edge::events::decode_route_state(bytes)
        .map_err(|refusal| refusal.code.to_string())?;
    let row = crate::e2ee::edge::events::route_row(&state, bytes);
    Ok(crate::e2ee::edge::events::state_row(
        RouteRow::key(&state.conversation_id)?,
        agenc_relay_storage::e2ee_records::ROUTE_ROW_KIND,
        row.encode()?,
    )
    .map_err(|refusal| refusal.code.to_string())?)
}

fn marker_row(
    entries: &[([u8; 32], Vec<u8>)],
    phase: agenc_relay_storage::e2ee_records::SnapshotPhase,
    switched_through: Option<[u8; 32]>,
) -> TestResult<AccountServiceDurableWrite> {
    let total = u32::try_from(entries.len())?;
    let row = SnapshotMarkerRow {
        token: TOKEN,
        state_generation: STATE_GENERATION,
        delivery_generation: DELIVERY_GENERATION,
        total_entries: total,
        digest: digest_of(entries)?,
        staged_entries: total,
        staged_bytes: entries.iter().map(|(_, bytes)| bytes.len() as u64).sum(),
        phase,
        opened_at: 1_000,
        switched_through,
    };
    Ok(crate::e2ee::edge::events::state_row(
        SnapshotMarkerRow::key(&[3; 16])?,
        agenc_relay_storage::e2ee_records::SNAPSHOT_MARKER_ROW_KIND,
        row.encode()?,
    )
    .map_err(|refusal| refusal.code.to_string())?)
}

#[tokio::test]
async fn a_ready_generation_survives_a_sealed_restart_and_the_reconnect_resends_ready() -> TestResult
{
    let entries = entries(2)?;
    let mut fixture = Fixture::resuming(false)?;
    let digest = digest_of(&entries)?;
    fixture.begin(0, 2, 2, digest)?;
    for (conversation, bytes) in &entries {
        fixture.entry(0, *conversation, bytes)?;
    }
    fixture.end(0, None)?;
    let rows = fixture.core.context_mut()?.staged_rows_for_test()?;
    assert_eq!(rows.len(), 3);
    let mut reloaded = edge();
    let mut base = base_edge();
    fixture
        .core
        .commit_and_restore_edge(rows, &mut base, Some(&mut reloaded))?;
    assert!(matches!(
        reloaded.snapshot.as_ref().map(|snapshot| &snapshot.stage),
        Some(Stage::Ready)
    ));
    assert_eq!(
        reloaded
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.pending.route_objects.len()),
        Some(2)
    );
    // Nothing of the pending generation is live, and the delivery position
    // is still the previous generation's.
    assert!(reloaded.route_objects.is_empty());
    assert_eq!(reloaded.delivery.generation, 0);
    assert!(reloaded.snapshot_ready_pending());
    // The reconnect announces the identical READY instead of ERESUME.
    reloaded.link_active(fixture.core.context_mut()?, &mut base);
    assert_eq!(reloaded.phase(), Phase::AwaitingActive);
    // A conflicting cut is refused; the exact cut is accepted.
    fixture.core.context_mut()?.discard_pending_for_test();
    assert!(
        reloaded
            .state_active(
                fixture.core.context_mut()?,
                TOKEN,
                STATE_GENERATION,
                DELIVERY_GENERATION,
                [1; 32],
            )
            .is_err()
    );
    reloaded
        .state_active(
            fixture.core.context_mut()?,
            TOKEN,
            STATE_GENERATION,
            DELIVERY_GENERATION,
            digest,
        )
        .map_err(|refusal| refusal.code.to_string())?;
    let active = fixture.core.context_mut()?.staged_rows_for_test()?;
    assert_eq!(active.len(), 2);
    assert_eq!(
        marker_of(&active)?.map(|marker| marker.phase),
        Some(agenc_relay_storage::e2ee_records::SnapshotPhase::Active)
    );
    Ok(())
}

#[tokio::test]
async fn an_active_generation_restarts_live_and_resumes_its_migration() -> TestResult {
    let entries = entries(3)?;
    let mut fixture = Fixture::resuming(false)?;
    // The rows exactly as the ACTIVE batch leaves them: every pending row,
    // the ACTIVE marker before its first migration batch, and the new
    // cursor; plus one stale route of the previous generation.
    let stale = route_state(2, 4)?;
    let mut writes = vec![
        active_row(&stale)?,
        marker_row(
            &entries,
            agenc_relay_storage::e2ee_records::SnapshotPhase::Active,
            None,
        )?,
        crate::e2ee::edge::events::cursor_write(
            &fixture.edge.config,
            &crate::e2ee::edge::sync::DeliveryState {
                generation: DELIVERY_GENERATION,
                cursor: None,
            },
        )
        .map_err(|code| code.to_string())?,
    ];
    for (_, bytes) in &entries {
        writes.push(pending_row(DELIVERY_GENERATION, bytes)?);
    }
    let mut restarted = edge();
    let mut base = base_edge();
    fixture
        .core
        .commit_and_restore_edge(writes, &mut base, Some(&mut restarted))?;
    assert_eq!(restarted.route_objects.len(), 3);
    assert!(!restarted.route_objects.contains_key(&[2; 32]));
    assert_eq!(restarted.delivery.generation, DELIVERY_GENERATION);
    assert!(matches!(
        restarted.snapshot.as_ref().map(|snapshot| &snapshot.stage),
        Some(Stage::Active { remaining, stale, switched_through: None })
            if remaining.len() == 3 && stale.len() == 1
    ));
    // The migration resumes: every row moves to its active key, the stale
    // row is deleted, and the marker goes last.
    fixture.core.context_mut()?.discard_pending_for_test();
    restarted.continue_snapshot(fixture.core.context_mut()?);
    let step = kinds(&fixture.core.context_mut()?.staged_rows_for_test()?);
    assert_eq!(
        step.iter()
            .filter(|(put, key)| *put && key.starts_with(b"route/v1/"))
            .count(),
        3
    );
    assert!(step.contains(&(false, RouteRow::key(&[2; 32])?.as_bytes().to_vec())));
    assert!(step.contains(&(false, SnapshotMarkerRow::key(&[3; 16])?.as_bytes().to_vec())));
    Ok(())
}

#[tokio::test]
async fn a_restart_in_the_middle_of_a_migration_restores_the_exact_route_set() -> TestResult {
    let entries = entries(3)?;
    let mut fixture = Fixture::resuming(false)?;
    // The first conversation migrated (its active row exists, its pending
    // row is gone); the other two are still pending; a stale row of the
    // previous generation beyond the cursor was not deleted yet.
    let stale = route_state(99, 4)?;
    let writes = vec![
        active_row(&entries.first().ok_or("entry")?.1)?,
        pending_row(DELIVERY_GENERATION, &entries.get(1).ok_or("entry")?.1)?,
        pending_row(DELIVERY_GENERATION, &entries.get(2).ok_or("entry")?.1)?,
        active_row(&stale)?,
        marker_row(
            &entries,
            agenc_relay_storage::e2ee_records::SnapshotPhase::Active,
            Some(entries.first().ok_or("entry")?.0),
        )?,
        crate::e2ee::edge::events::cursor_write(
            &fixture.edge.config,
            &crate::e2ee::edge::sync::DeliveryState {
                generation: DELIVERY_GENERATION,
                cursor: None,
            },
        )
        .map_err(|code| code.to_string())?,
    ];
    let mut restarted = edge();
    let mut base = base_edge();
    fixture
        .core
        .commit_and_restore_edge(writes, &mut base, Some(&mut restarted))?;
    let live: Vec<[u8; 32]> = restarted.route_objects.keys().copied().collect();
    assert_eq!(
        live,
        vec![
            entries.first().ok_or("entry")?.0,
            entries.get(1).ok_or("entry")?.0,
            entries.get(2).ok_or("entry")?.0
        ]
    );
    assert!(matches!(
        restarted.snapshot.as_ref().map(|snapshot| &snapshot.stage),
        Some(Stage::Active { remaining, stale, switched_through: Some(cursor) })
            if remaining.len() == 2 && stale.contains(&[99; 32]) && *cursor == entries.first().ok_or("entry")?.0
    ));
    Ok(())
}

#[tokio::test]
async fn a_staging_marker_is_abandoned_at_restart_and_its_rows_are_deleted() -> TestResult {
    let entries = entries(2)?;
    let mut fixture = Fixture::resuming(false)?;
    let mut writes = vec![
        marker_row(
            &entries,
            agenc_relay_storage::e2ee_records::SnapshotPhase::Staging,
            None,
        )?,
        // An active route of the live generation stays live.
        active_row(&route_state(77, 4)?)?,
    ];
    for (_, bytes) in &entries {
        writes.push(pending_row(DELIVERY_GENERATION, bytes)?);
    }
    // A row of a generation no marker describes is a stray.
    writes.push(pending_row(7, &route_state(50, 4)?)?);
    let mut restarted = edge();
    let mut base = base_edge();
    fixture
        .core
        .commit_and_restore_edge(writes, &mut base, Some(&mut restarted))?;
    assert_eq!(
        restarted.route_objects.keys().copied().collect::<Vec<_>>(),
        vec![[77; 32]]
    );
    assert!(matches!(
        restarted.snapshot.as_ref().map(|snapshot| &snapshot.stage),
        Some(Stage::Discarding { keys }) if keys.len() == 2
    ));
    fixture.core.context_mut()?.discard_pending_for_test();
    restarted.continue_snapshot(fixture.core.context_mut()?);
    let step = kinds(&fixture.core.context_mut()?.staged_rows_for_test()?);
    assert_eq!(step.len(), 3);
    assert!(step.iter().all(|(put, _)| !*put));
    fixture.core.context_mut()?.discard_pending_for_test();
    restarted.batch_applied(fixture.core.context_mut()?, &mut base);
    assert!(restarted.snapshot.is_none());
    // Then the stray generation.
    let stray = kinds(&fixture.core.context_mut()?.staged_rows_for_test()?);
    assert_eq!(stray.len(), 1);
    assert!(
        stray
            .first()
            .ok_or("stray")?
            .1
            .starts_with(b"pending-route/v1/")
    );
    Ok(())
}

/// Entries whose conversations are ordered by a 16-bit index.
fn many_entries(count: usize) -> TestResult<Vec<([u8; 32], Vec<u8>)>> {
    (0..count)
        .map(|index| {
            let index = u16::try_from(index)?;
            let mut conversation = [0; 32];
            conversation[1..3].copy_from_slice(&index.to_be_bytes());
            Ok((conversation, route_state_for(conversation, 4)?))
        })
        .collect()
}

fn route_state_for(conversation: [u8; 32], sequence: u64) -> TestResult<Vec<u8>> {
    route_state_in([1; 32], conversation, sequence)
}

fn route_state_in(network: [u8; 32], conversation: [u8; 32], sequence: u64) -> TestResult<Vec<u8>> {
    let mut instance = [0; 16];
    instance.copy_from_slice(&conversation[..16]);
    let state = ArcFederationRouteState {
        profile_version: 1,
        network_id: network,
        state_generation: 4,
        conversation_id: conversation,
        conversation_kind: ArcConversationKind::Channel,
        route_binding: [26; 32],
        semantic_route_lock_id: [23; 32],
        channel_instance_id: Opaque::new(instance.to_vec())?,
        canonical_channel_name_hash: [116; 32],
        direct_account_a: Opaque::new(Vec::new())?,
        direct_account_b: Opaque::new(Vec::new())?,
        binding_id: [34; 32],
        finalized_epoch: 1,
        accepted_state_id: [58; 32],
        sequencer_record_head_sequence: sequence,
        sequencer_record_head_id: [59; 32],
        state: ArcRouteStateKind::ActiveRoute,
    };
    Ok(ArcWireObject::new(ArcWireObjectKind::FederationState, state.encode()?)?.encode()?)
}

#[test]
fn the_page_partition_is_exact() {
    assert!(page_partition(0, 0, 0).is_ok());
    assert!(page_partition(33, 0, 32).is_ok());
    assert!(page_partition(33, 1, 1).is_ok());
    assert!(page_partition(64, 1, 32).is_ok());
    assert!(page_partition(33, 0, 31).is_err());
    assert!(page_partition(33, 1, 2).is_err());
    assert!(page_partition(33, 2, 1).is_err());
    assert!(page_partition(1, 0, 0).is_err());
}

#[tokio::test]
async fn a_generation_opens_only_at_page_zero_while_resuming() -> TestResult {
    let entries = entries(3)?;
    let digest = digest_of(&entries)?;
    let mut fixture = Fixture::resuming(false)?;
    assert_eq!(
        fixture.begin(1, 3, 3, digest),
        Err(E2eeReplyCode::Syncing.to_string())
    );
    assert!(fixture.edge.snapshot.is_none());
    // Not resuming: no link came up.
    let core = StateCoreFixture::new(vec![0; 4_096])?;
    let mut edge = edge();
    install_backing(&mut edge);
    let mut down = Fixture {
        core,
        edge,
        base: base_edge(),
        unentitled: false,
    };
    assert_eq!(down.edge.phase(), Phase::Down);
    assert_eq!(
        down.begin(0, 3, 3, digest),
        Err(E2eeReplyCode::Syncing.to_string())
    );
    assert!(down.edge.snapshot.is_none());
    Ok(())
}

#[tokio::test]
async fn later_pages_repeat_the_cut_and_follow_a_complete_page() -> TestResult {
    let entries = entries(MAX_BATCH_OBJECTS + 1)?;
    let digest = digest_of(&entries)?;
    let mut fixture = Fixture::resuming(false)?;
    fixture.begin(0, 33, 32, digest)?;
    // A second BEGIN of the same page while entries are pending.
    let first = entries.first().ok_or("entry")?;
    fixture.entry(0, first.0, &first.1)?;
    assert_eq!(
        fixture.begin(0, 33, 32, digest),
        Err(E2eeReplyCode::Syncing.to_string())
    );
    for (conversation, bytes) in entries.iter().skip(1).take(MAX_BATCH_OBJECTS - 1) {
        fixture.entry(0, *conversation, bytes)?;
    }
    fixture.end(0, Some([1; 32]))?;
    fixture.commit()?;
    // A changed total, then the exact continuation.
    assert_eq!(
        fixture.begin(1, 34, 1, digest),
        Err(E2eeReplyCode::Syncing.to_string())
    );
    fixture.begin(1, 33, 1, digest)?;
    Ok(())
}

#[tokio::test]
async fn entries_and_ends_are_refused_for_another_token_page_or_conversation() -> TestResult {
    let entries = entries(3)?;
    let digest = digest_of(&entries)?;
    let mut fixture = Fixture::resuming(false)?;
    fixture.begin(0, 3, 3, digest)?;
    let first = entries.first().ok_or("entry")?;
    for (token, page) in [([9; 32], 0), (TOKEN, 1)] {
        for fragment in fragment_object(&first.1)? {
            let context = fixture.core.context_mut()?;
            assert_eq!(
                fixture
                    .edge
                    .state_entry(
                        context,
                        &fixture.base,
                        token,
                        page,
                        first.0,
                        object_id(&first.1),
                        fragment
                    )
                    .map_err(|refusal| refusal.code.to_string()),
                Err(E2eeReplyCode::Syncing.to_string())
            );
        }
    }
    // The ENTRY names one conversation, the object another.
    assert_eq!(
        fixture.entry(0, [1; 32], &first.1),
        Err(E2eeReplyCode::Syncing.to_string())
    );
    for (conversation, bytes) in &entries {
        fixture.entry(0, *conversation, bytes)?;
    }
    for (token, page) in [([9; 32], 0), (TOKEN, 1)] {
        let context = fixture.core.context_mut()?;
        assert_eq!(
            fixture
                .edge
                .state_end(context, token, page, None)
                .map_err(|refusal| refusal.code.to_string()),
            Err(E2eeReplyCode::Syncing.to_string())
        );
    }
    fixture.end(0, None)?;
    Ok(())
}

#[tokio::test]
async fn active_waits_for_ready_and_migration_waits_for_the_pending_batch() -> TestResult {
    let digest = federation_snapshot_digest(STATE_GENERATION, DELIVERY_GENERATION, &[])?;
    let mut fixture = Fixture::resuming(false)?;
    fixture.begin(0, 0, 0, digest)?;
    assert!(fixture.activate(digest).is_err());
    fixture.end(0, None)?;
    // The READY batch is pending: no migration or cleanup batch joins it.
    let staged = fixture.core.context_mut()?.staged_rows_for_test()?.len();
    fixture.edge.continue_snapshot(fixture.core.context_mut()?);
    assert_eq!(
        fixture.core.context_mut()?.staged_rows_for_test()?.len(),
        staged
    );
    Ok(())
}

#[tokio::test]
async fn a_link_loss_before_any_page_is_durable_forgets_the_generation() -> TestResult {
    let entries = entries(MAX_BATCH_OBJECTS + 1)?;
    let mut fixture = Fixture::resuming(false)?;
    fixture.begin(0, 33, 32, digest_of(&entries)?)?;
    let first = entries.first().ok_or("entry")?;
    fixture.entry(0, first.0, &first.1)?;
    fixture.edge.link_down();
    assert!(fixture.edge.snapshot.is_none());
    Ok(())
}

#[tokio::test]
async fn a_large_generation_migrates_in_several_bounded_steps() -> TestResult {
    let entries = many_entries(300)?;
    let mut fixture = Fixture::resuming(true)?;
    // Two stale routes of the previous generation: one between the new
    // conversations and one beyond them.
    let mut middle = [0; 32];
    middle[1..4].copy_from_slice(&[0, 150, 7]);
    fixture.edge.link_down();
    fixture
        .edge
        .route_changed(&route_state_for(middle, 4)?)
        .map_err(|refusal| refusal.code.to_string())?;
    fixture
        .edge
        .link_active(fixture.core.context_mut()?, &mut fixture.base);
    let batches = fixture.transfer(&entries)?;
    assert_eq!(batches.len(), 10);
    fixture.activate(digest_of(&entries)?)?;
    fixture.commit()?;
    assert_eq!(fixture.edge.route_objects.len(), 300);
    let mut steps = Vec::new();
    while fixture.edge.snapshot.is_some() {
        fixture.edge.continue_snapshot(fixture.core.context_mut()?);
        let rows = kinds(&fixture.commit()?);
        assert!(rows.len() <= 257, "one bounded batch");
        steps.push(rows);
    }
    assert!(steps.len() >= 3);
    let flat: Vec<&(bool, Vec<u8>)> = steps.iter().flatten().collect();
    assert_eq!(
        flat.iter()
            .filter(|(put, key)| *put && key.starts_with(b"route/v1/"))
            .count(),
        300
    );
    assert!(flat.contains(&&(false, RouteRow::key(&middle)?.as_bytes().to_vec())));
    assert!(flat.contains(&&(false, RouteRow::key(&CONVERSATION)?.as_bytes().to_vec())));
    // The marker goes with the last step only.
    let marker = SnapshotMarkerRow::key(&[3; 16])?.as_bytes().to_vec();
    assert!(
        steps
            .last()
            .is_some_and(|rows| rows.contains(&(false, marker.clone())))
    );
    assert!(
        steps
            .iter()
            .take(steps.len() - 1)
            .all(|rows| !rows.contains(&(false, marker.clone())))
    );
    Ok(())
}

#[tokio::test]
async fn a_large_abandoned_generation_is_deleted_in_several_bounded_steps() -> TestResult {
    let entries = many_entries(288)?;
    let mut fixture = Fixture::resuming(false)?;
    // Nine pages are durable; the tenth never arrives.
    let digest = digest_of(&many_entries(300)?)?;
    for page in 0..9_u32 {
        fixture.begin(page, 300, 32, digest)?;
        for (conversation, bytes) in entries.iter().skip(page as usize * 32).take(32) {
            fixture.entry(page, *conversation, bytes)?;
        }
        fixture.end(page, Some([page as u8 + 1; 32]))?;
        fixture.commit()?;
    }
    fixture.edge.link_down();
    let mut steps = 0;
    while fixture.edge.snapshot.is_some() {
        fixture.edge.continue_snapshot(fixture.core.context_mut()?);
        let rows = kinds(&fixture.commit()?);
        assert!(rows.len() <= 257 && rows.iter().all(|(put, _)| !*put));
        steps += 1;
    }
    assert_eq!(steps, 2);
    Ok(())
}

fn active_fixture(
    entries: &[([u8; 32], Vec<u8>)],
    cursor: Option<[u8; 32]>,
) -> TestResult<(Fixture, E2eeEdge, EdgeFederation)> {
    let mut fixture = Fixture::resuming(false)?;
    let mut writes = vec![
        marker_row(
            entries,
            agenc_relay_storage::e2ee_records::SnapshotPhase::Active,
            cursor,
        )?,
        crate::e2ee::edge::events::cursor_write(
            &fixture.edge.config,
            &crate::e2ee::edge::sync::DeliveryState {
                generation: DELIVERY_GENERATION,
                cursor: None,
            },
        )
        .map_err(|code| code.to_string())?,
    ];
    for (conversation, bytes) in entries {
        if cursor.is_some_and(|cursor| *conversation <= cursor) {
            writes.push(active_row(bytes)?);
        } else {
            writes.push(pending_row(DELIVERY_GENERATION, bytes)?);
        }
    }
    let mut restarted = edge();
    let mut base = base_edge();
    fixture
        .core
        .commit_and_restore_edge(writes, &mut base, Some(&mut restarted))?;
    fixture.core.context_mut()?.discard_pending_for_test();
    Ok((fixture, restarted, base))
}

#[tokio::test]
async fn live_changes_during_a_migration_keep_the_pending_rows_current() -> TestResult {
    let entries = entries(3)?;
    let cursor = entries.first().ok_or("entry")?.0;
    let (mut fixture, mut restarted, _base) = active_fixture(&entries, Some(cursor))?;
    // A change beyond the cursor refreshes the pending row too; one before
    // it touches only the active row.
    let second = entries.get(1).ok_or("entry")?;
    let updated = route_state_for(second.0, 5)?;
    let writes = kinds(
        &restarted
            .route_changed(&updated)
            .map_err(|refusal| refusal.code.to_string())?,
    );
    assert_eq!(writes.len(), 2);
    assert!(
        writes
            .iter()
            .any(|(put, key)| *put && key.starts_with(b"pending-route/v1/"))
    );
    let first = entries.first().ok_or("entry")?;
    let writes = restarted
        .route_changed(&route_state_for(first.0, 5)?)
        .map_err(|refusal| refusal.code.to_string())?;
    assert_eq!(writes.len(), 1);
    // A hidden route beyond the cursor leaves the migration; hiding an
    // unknown one changes nothing.
    let third = entries.get(2).ok_or("entry")?;
    let writes = kinds(
        &restarted
            .route_hidden(fixture.core.context_mut()?, third.0)
            .map_err(|refusal| refusal.code.to_string())?,
    );
    assert!(
        writes
            .iter()
            .any(|(put, key)| !*put && key.starts_with(b"pending-route/v1/"))
    );
    assert!(
        restarted
            .route_hidden(fixture.core.context_mut()?, [200; 32])
            .map_err(|refusal| refusal.code.to_string())?
            .is_empty()
    );
    assert!(matches!(
        restarted.snapshot.as_ref().map(|snapshot| &snapshot.stage),
        Some(Stage::Active { remaining, .. }) if remaining.len() == 1
    ));
    Ok(())
}

#[tokio::test]
async fn an_active_row_beyond_the_cursor_yields_to_the_pending_row() -> TestResult {
    let entries = entries(3)?;
    let cursor = entries.first().ok_or("entry")?.0;
    let mut fixture = Fixture::resuming(false)?;
    let second = entries.get(1).ok_or("entry")?;
    let older = route_state_for(second.0, 2)?;
    let mut writes = vec![
        marker_row(
            &entries,
            agenc_relay_storage::e2ee_records::SnapshotPhase::Active,
            Some(cursor),
        )?,
        active_row(&entries.first().ok_or("entry")?.1)?,
        active_row(&older)?,
    ];
    for (_, bytes) in entries.iter().skip(1) {
        writes.push(pending_row(DELIVERY_GENERATION, bytes)?);
    }
    let mut restarted = edge();
    let mut base = base_edge();
    fixture
        .core
        .commit_and_restore_edge(writes, &mut base, Some(&mut restarted))?;
    assert_eq!(restarted.route_objects.get(&second.0), Some(&second.1));
    Ok(())
}

#[tokio::test]
async fn an_incomplete_ready_generation_refuses_the_restore() -> TestResult {
    let entries = entries(3)?;
    let mut fixture = Fixture::resuming(false)?;
    let mut writes = vec![marker_row(
        &entries,
        agenc_relay_storage::e2ee_records::SnapshotPhase::Ready,
        None,
    )?];
    for (_, bytes) in entries.iter().take(2) {
        writes.push(pending_row(DELIVERY_GENERATION, bytes)?);
    }
    let mut restarted = edge();
    let mut base = base_edge();
    // The refusal must name the companion snapshot it could not complete: the
    // step alone once printed as a bare stale-state line, which is what sent
    // the first report of this failure to the storage layer (#124).
    let refusal = fixture
        .core
        .commit_and_restore_edge(writes, &mut base, Some(&mut restarted))
        .err()
        .ok_or("an incomplete READY generation was accepted")?;
    assert_eq!(
        refusal.to_string(),
        "companion-snapshot-restore (companion snapshot generation is incomplete): storage owner \
         failed: storage state is stale or inconsistent",
    );
    Ok(())
}

#[tokio::test]
async fn route_projection_refuses_another_network_and_accepts_a_cut_ahead() -> TestResult {
    let mut fixture = Fixture::resuming(true)?;
    assert_eq!(
        fixture
            .edge
            .route_changed(&route_state_in([2; 32], CONVERSATION, 5)?)
            .map(|writes| writes.len())
            .map_err(|refusal| refusal.code.to_string()),
        Err(E2eeReplyCode::RouteInvalid.to_string())
    );
    let ahead = route_state_for(CONVERSATION, 5)?;
    let writes = fixture
        .edge
        .route_changed(&ahead)
        .map_err(|refusal| refusal.code.to_string())?;
    assert_eq!(writes.len(), 1);
    // Hiding a route whose row is not durable deletes nothing but drops
    // the projection.
    let hidden = fixture
        .edge
        .route_hidden(fixture.core.context_mut()?, CONVERSATION)
        .map_err(|refusal| refusal.code.to_string())?;
    assert!(hidden.is_empty());
    assert!(!fixture.edge.route_objects.contains_key(&CONVERSATION));
    Ok(())
}

/// ENC-15 (#160): the wire form of one Account ID.
fn account(seed: u8) -> TestResult<[u8; 24]> {
    let id = agenc_relay_types::AccountId::from_random(
        agenc_relay_types::AccountRandomId::from_bytes([seed; 16]),
    );
    Ok(id.to_text().as_bytes().try_into()?)
}

/// A direct route between `pair`, in canonical account order.
fn direct_route_state(conversation: [u8; 32], pair: ([u8; 24], [u8; 24])) -> TestResult<Vec<u8>> {
    let (first, second) = if pair.0 <= pair.1 {
        pair
    } else {
        (pair.1, pair.0)
    };
    let state = ArcFederationRouteState {
        profile_version: 1,
        network_id: [1; 32],
        state_generation: 4,
        conversation_id: conversation,
        conversation_kind: ArcConversationKind::Direct,
        route_binding: [26; 32],
        semantic_route_lock_id: [23; 32],
        channel_instance_id: Opaque::new(Vec::new())?,
        canonical_channel_name_hash: [0; 32],
        direct_account_a: Opaque::new(first.to_vec())?,
        direct_account_b: Opaque::new(second.to_vec())?,
        binding_id: [34; 32],
        finalized_epoch: 1,
        accepted_state_id: [58; 32],
        sequencer_record_head_sequence: 4,
        sequencer_record_head_id: [59; 32],
        state: ArcRouteStateKind::ActiveRoute,
    };
    Ok(ArcWireObject::new(ArcWireObjectKind::FederationState, state.encode()?)?.encode()?)
}

/// A local companion origin authenticated as `held`, attached or not.
fn hosting_origin(held: [u8; 24], attached: bool) -> LocalOrigin {
    LocalOrigin {
        origin_id: [5; 16],
        declared: Some(1),
        acked: Some(1),
        predates_device: None,
        next_sequence: 0,
        sequenced: Some(1),
        state_id: [0; 32],
        declaration: None,
        user_id: None,
        account: Some(held),
        device: attached.then_some(([7; 16], 1)),
        device_principal: attached.then_some((None, Some(held))),
    }
}

/// A one-entry transfer of the direct route between accounts 40 and 41.
fn direct_transfer() -> TestResult<([u8; 32], Vec<u8>, [u8; 32])> {
    let conversation = [77; 32];
    let bytes = direct_route_state(conversation, (account(40)?, account(41)?))?;
    let digest = digest_of(&[(conversation, bytes.clone())])?;
    Ok((conversation, bytes, digest))
}

#[tokio::test]
async fn an_unentitled_channel_entry_refuses_the_whole_snapshot_with_nothing_staged() -> TestResult
{
    let entries = entries(2)?;
    let digest = digest_of(&entries)?;
    let mut fixture = Fixture::resuming(false)?;
    let [first, second] = entries.as_slice() else {
        return Err("two entries".into());
    };
    // The base profile hosts the first channel and not the second.
    fixture.host_entry(&first.1)?;
    fixture.unentitled = true;
    fixture.begin(0, 2, 2, digest)?;
    fixture.entry(0, first.0, &first.1)?;
    assert_eq!(
        fixture.entry(0, second.0, &second.1),
        Err(E2eeReplyCode::Syncing.to_string())
    );
    // Nothing of the refused entry is retained and nothing was staged.
    let snapshot = fixture.edge.snapshot.as_ref().ok_or("open generation")?;
    assert_eq!(snapshot.pending.route_objects.len(), 1);
    assert!(!snapshot.pending.route_objects.contains_key(&second.0));
    assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
    // The frame failure closes the link and abandons the whole generation
    // before any READY: no page, no marker, no projection.
    fixture
        .edge
        .fail_frame(fixture.core.context_mut()?, &mut fixture.base);
    assert_eq!(fixture.edge.phase(), Phase::Down);
    assert!(fixture.edge.snapshot.is_none());
    assert!(!fixture.edge.snapshot_ready_pending());
    assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
    assert!(fixture.edge.conversations.is_empty());
    // The same cut installs once the base profile hosts both channels.
    let mut entitled = Fixture::resuming(false)?;
    entitled.begin(0, 2, 2, digest)?;
    for (conversation, bytes) in &entries {
        entitled.entry(0, *conversation, bytes)?;
    }
    entitled.end(0, None)?;
    assert_ne!(entitled.core.context_mut()?.pending_len(), 0);
    Ok(())
}

#[tokio::test]
async fn an_unentitled_direct_entry_refuses_the_whole_snapshot_with_nothing_staged() -> TestResult {
    let (conversation, bytes, digest) = direct_transfer()?;
    let mut fixture = Fixture::resuming(false)?;
    // A session for a third account, and an unattached origin of a named
    // one, entitle this edge to nothing.
    fixture.edge.origins.insert(
        ConnectionGeneration::new(1),
        hosting_origin(account(42)?, true),
    );
    fixture.edge.origins.insert(
        ConnectionGeneration::new(2),
        hosting_origin(account(40)?, false),
    );
    fixture.begin(0, 1, 1, digest)?;
    assert_eq!(
        fixture.entry(0, conversation, &bytes),
        Err(E2eeReplyCode::Syncing.to_string())
    );
    let snapshot = fixture.edge.snapshot.as_ref().ok_or("open generation")?;
    assert!(snapshot.pending.route_objects.is_empty());
    assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
    fixture
        .edge
        .fail_frame(fixture.core.context_mut()?, &mut fixture.base);
    assert!(fixture.edge.snapshot.is_none());
    assert!(fixture.edge.routes.routes().next().is_none());
    Ok(())
}

#[tokio::test]
async fn a_direct_entry_installs_for_an_attached_device_of_either_account() -> TestResult {
    let (conversation, bytes, digest) = direct_transfer()?;
    for seed in [40, 41] {
        let mut fixture = Fixture::resuming(false)?;
        fixture.edge.origins.insert(
            ConnectionGeneration::new(1),
            hosting_origin(account(seed)?, true),
        );
        fixture.begin(0, 1, 1, digest)?;
        fixture.entry(0, conversation, &bytes)?;
        fixture.end(0, None)?;
        assert_ne!(fixture.core.context_mut()?.pending_len(), 0);
    }
    Ok(())
}

#[tokio::test]
async fn hosting_is_read_as_it_stood_when_the_transfer_opened() -> TestResult {
    let (conversation, bytes, digest) = direct_transfer()?;
    let mut fixture = Fixture::resuming(false)?;
    let generation = ConnectionGeneration::new(1);
    fixture
        .edge
        .origins
        .insert(generation, hosting_origin(account(41)?, true));
    fixture.begin(0, 1, 1, digest)?;
    // A paired base resynchronization closes the session the cut counted
    // while the pages are still arriving.
    fixture.edge.connection_closed(generation);
    assert!(fixture.edge.origins.is_empty());
    fixture.entry(0, conversation, &bytes)?;
    // An origin that closed before the transfer opened entitles nothing.
    let mut late = Fixture::resuming(false)?;
    late.begin(0, 1, 1, digest)?;
    assert_eq!(
        late.entry(0, conversation, &bytes),
        Err(E2eeReplyCode::Syncing.to_string())
    );
    Ok(())
}

#[tokio::test]
async fn a_cut_may_restate_a_direct_route_this_edge_already_projects() -> TestResult {
    let (conversation, bytes, digest) = direct_transfer()?;
    let mut fixture = Fixture::resuming(false)?;
    fixture
        .edge
        .route_changed(&bytes)
        .map_err(|refusal| refusal.code.to_string())?;
    fixture.begin(0, 1, 1, digest)?;
    fixture.entry(0, conversation, &bytes)?;
    // The same conversation under another pair is a new disclosure.
    let other = direct_route_state(conversation, (account(40)?, account(43)?))?;
    let mut changed = Fixture::resuming(false)?;
    changed
        .edge
        .route_changed(&bytes)
        .map_err(|refusal| refusal.code.to_string())?;
    changed.begin(0, 1, 1, digest_of(&[(conversation, other.clone())])?)?;
    assert_eq!(
        changed.entry(0, conversation, &other),
        Err(E2eeReplyCode::Syncing.to_string())
    );
    Ok(())
}

#[tokio::test]
async fn a_page_published_again_on_the_next_link_stages_again() -> TestResult {
    let entries = entries(3)?;
    let digest = digest_of(&entries)?;
    let mut fixture = Fixture::resuming(false)?;
    fixture.begin(0, 3, 3, digest)?;
    for (conversation, bytes) in entries.iter().take(2) {
        fixture.entry(0, *conversation, bytes)?;
    }
    fixture.edge.link_down();
    assert!(fixture.edge.snapshot.is_none());
    fixture
        .edge
        .link_active(fixture.core.context_mut()?, &mut fixture.base);
    assert_eq!(fixture.edge.phase(), Phase::Resuming);
    // The coordinator publishes the pending cut again from its first page,
    // and the entries the closed link carried stage again.
    let batches = fixture.transfer(&entries)?;
    assert_eq!(batches.len(), 1);
    assert_eq!(fixture.edge.phase(), Phase::AwaitingActive);
    Ok(())
}

#[tokio::test]
async fn entries_assemble_whatever_the_client_cache_holds() -> TestResult {
    let entries = entries(2)?;
    let mut fixture = Fixture::resuming(false)?;
    super::fill_client_cache(&mut fixture.edge)?;
    let batches = fixture.transfer(&entries)?;
    assert_eq!(batches.len(), 1);
    assert_eq!(fixture.edge.phase(), Phase::AwaitingActive);
    Ok(())
}
