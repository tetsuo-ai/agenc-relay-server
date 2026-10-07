#![forbid(unsafe_code)]

//! Synchronization tests: EORIGIN mirroring, ERESUME, and the ESTATE
//! transfer, driven through the frame entry point with a fake base host.

mod delivery_restart;
pub(crate) mod edge_peer;
mod frame_addressing;
mod inactive_ready;
mod origin_admission;
mod origin_mirror;
mod origin_refusals;
mod review_witness;

use agenc_relay_crypto::SemanticHashDomain;
use agenc_relay_e2ee::federation::frames::{CompanionFrame, DeliveryPosition};
use agenc_relay_e2ee::ids::{federation_snapshot_digest, semantic_id_of};
use agenc_relay_e2ee::object::ArcWireObjectKind;
use agenc_relay_e2ee::objects::federation::ArcFederationOrigin;
use agenc_relay_e2ee::tls::Opaque;
use agenc_relay_e2ee::wire::fragment::fragment_object;
use agenc_relay_federation_wire::FederationLineText;
use agenc_relay_types::ServerId;

use agenc_relay_storage::e2ee_records::{ReplayKey, ReplayRow};

use super::super::sync::{Action, BaseOriginView, Committed, CompanionHost, Cut, PendingWork};
use super::super::{CompanionFault, CompanionOriginKey};
use super::{Counter, HOME, Harness, INCARNATION, NETWORK, ORIGIN, TestResult, object_id, wire};
use crate::federation::LinkId;
use crate::federation::link::{ParsedLine, parse_line};

const COORDINATOR: [u8; 16] = [3; 16];
const CONNECTION: [u8; 16] = [11; 16];
const NONCE: [u8; 32] = [6; 32];
const SERVER_NAME: &str = "coordinator.example";
const NOW_MILLIS: u64 = 5_000_000;

/// A fake base: every configured fact is set directly by the test.
pub(crate) struct FakeHost {
    incarnation: Option<[u8; 16]>,
    origin: Option<BaseOriginView>,
    ready: bool,
    resync_epoch: u64,
    pub(super) revision: u64,
    backing: crate::budget::BackingReservationPort,
    clock: Result<
        super::super::sync::CutClockSample,
        agenc_relay_storage::e2ee_records::delivery_recovery::RetirementReason,
    >,
}

impl Default for FakeHost {
    fn default() -> Self {
        Self {
            incarnation: Some(INCARNATION),
            origin: Some(BaseOriginView {
                generation: 0,
                connection_id: CONNECTION,
                connection_nonce: NONCE,
                session: Some(([21; 16], [22; 16])),
                account: None,
            }),
            ready: true,
            resync_epoch: 0,
            revision: 40,
            clock: super::super::delivery_owner::clock::sample(),
            backing: crate::budget::BackingReservationPort::new(crate::sync::Arc::new(
                crate::budget::MemoryBudget::new(1_073_741_824),
            )),
        }
    }
}

impl CompanionHost for FakeHost {
    fn cut_clock_sample(
        &self,
    ) -> Result<
        super::super::sync::CutClockSample,
        agenc_relay_storage::e2ee_records::delivery_recovery::RetirementReason,
    > {
        self.clock
    }

    fn reserve_cut_backing(
        &self,
        capacity: usize,
    ) -> Result<crate::budget::MemoryPermit, CompanionFault> {
        self.backing
            .reserve(capacity)
            .map_err(|_| CompanionFault::Ceiling)
    }

    fn live_incarnation(&self, _peer: ServerId) -> Option<[u8; 16]> {
        self.incarnation
    }

    fn base_origin(&self, _key: &CompanionOriginKey) -> Option<BaseOriginView> {
        self.origin
    }

    fn base_origins_ready(&self, _peer: ServerId) -> bool {
        self.ready
    }

    fn base_resync_epoch(&self, _peer: ServerId) -> u64 {
        self.resync_epoch
    }

    fn state_generation(&self) -> u64 {
        self.revision
    }

    fn holds_channel(&self, _instance: [u8; 16]) -> bool {
        false
    }

    fn hosts_account(&self, _account: &[u8; 24]) -> bool {
        false
    }
}

fn home() -> ServerId {
    ServerId::from_bytes(HOME)
}

fn parse(line: &FederationLineText) -> TestResult<CompanionFrame> {
    let text = line.as_str().trim_end_matches("\r\n");
    match parse_line(text, SERVER_NAME).map_err(|error| format!("{error:?}"))? {
        ParsedLine::Companion(frame) => Ok(frame),
        ParsedLine::Base(_) => Err("expected a companion frame".into()),
    }
}

fn frames(actions: &[Action]) -> TestResult<Vec<CompanionFrame>> {
    let mut frames = Vec::new();
    for action in actions {
        let lines = match action {
            Action::Send(lines) => lines.as_slice(),
            Action::SendPage(output) => output.lines(),
            _ => continue,
        };
        for line in lines {
            frames.push(parse(line)?);
        }
    }
    Ok(frames)
}

fn origin_object(
    generation: u64,
    previous: [u8; 32],
    account: Option<([u8; 24], u64)>,
    device: Option<([u8; 16], u64)>,
) -> TestResult<(ArcFederationOrigin, Vec<u8>)> {
    let origin = ArcFederationOrigin {
        profile_version: 1,
        network_id: NETWORK,
        home_server_id: HOME,
        server_incarnation: INCARNATION,
        origin_id: ORIGIN,
        origin_generation: generation,
        previous_origin_state_id: previous,
        connection_id: CONNECTION,
        session_id: Opaque::new(vec![21; 16])?,
        user_id: Opaque::new(vec![22; 16])?,
        account_id: Opaque::new(
            account
                .map(|(account, _)| account.to_vec())
                .unwrap_or_default(),
        )?,
        account_session_generation: account.map_or(0, |(_, generation)| generation),
        connection_nonce: NONCE,
        attached_device_id: Opaque::new(
            device
                .map(|(device, _)| device.to_vec())
                .unwrap_or_default(),
        )?,
        device_session_generation: device.map_or(0, |(_, generation)| generation),
    };
    let bytes = wire(ArcWireObjectKind::FederationOrigin, &origin)?;
    Ok((origin, bytes))
}

fn origin_frame(update: bool, generation: u64, bytes: &[u8]) -> TestResult<Vec<CompanionFrame>> {
    let object = object_id(bytes);
    Ok(fragment_object(bytes)?
        .into_iter()
        .map(|fragment| CompanionFrame::OriginState {
            update,
            coordinator_server_id: COORDINATOR,
            server_incarnation: INCARNATION,
            origin_id: ORIGIN,
            origin_generation: generation,
            object_id: object,
            fragment,
        })
        .collect())
}

struct Sync {
    harness: Harness,
    host: FakeHost,
    entropy: Counter,
}

impl Sync {
    fn new() -> TestResult<Self> {
        let mut harness = Harness::new()?;
        // The harness pre-registers its origin; synchronization tests declare
        // origins through EORIGIN instead.
        harness.coordinator.state.origins.clear();
        Ok(Self {
            harness,
            host: FakeHost::default(),
            entropy: Counter(0),
        })
    }

    fn frame(&mut self, frame: CompanionFrame) -> Result<Vec<Action>, CompanionFault> {
        self.frame_at(frame, NOW_MILLIS)
    }

    fn frame_at(
        &mut self,
        frame: CompanionFrame,
        now_millis: u64,
    ) -> Result<Vec<Action>, CompanionFault> {
        let actions = self.harness.coordinator.on_frame(
            LinkId::new(1),
            home(),
            frame,
            now_millis,
            &self.host,
            &mut self.entropy,
        )?;
        self.finish_snapshot_actions(actions, now_millis)
    }

    // These are state-machine controls. RestartFixture separately uses real storage receipts.
    fn finish_snapshot_actions(
        &mut self,
        mut actions: Vec<Action>,
        now: u64,
    ) -> Result<Vec<Action>, CompanionFault> {
        for _ in 0..agenc_relay_storage::e2ee_records::delivery_recovery::MAX_SNAPSHOT_PAGES + 2 {
            if !matches!(
                actions.as_slice(),
                [Action::Stage {
                    work: PendingWork::Snapshot(_) | PendingWork::Fetch(_),
                    ..
                }]
            ) {
                return Ok(actions);
            }
            let Some(Action::Stage { work, .. }) = actions.into_iter().next() else {
                return Err(CompanionFault::Protocol);
            };
            self.harness.coordinator.set_pending(work);
            actions = match self
                .harness
                .coordinator
                .batch_applied(Some(self.host.resync_epoch))?
            {
                Some(Committed::Snapshot(publication)) => self
                    .harness
                    .coordinator
                    .continue_snapshot_publication(*publication, now, &self.host)?,
                Some(Committed::Fetch(publication)) => {
                    publication.committed(&mut self.harness.coordinator, now, &self.host)?
                }
                _ => return Err(CompanionFault::Protocol),
            };
        }
        Err(CompanionFault::Ceiling)
    }

    fn reset(&mut self) -> TestResult<Vec<CompanionFrame>> {
        let actions = self.frame(CompanionFrame::OriginReset {
            coordinator_server_id: COORDINATOR,
            server_incarnation: INCARNATION,
        })?;
        frames(&actions)
    }

    fn declare(
        &mut self,
        update: bool,
        generation: u64,
        bytes: &[u8],
    ) -> Result<Vec<Action>, CompanionFault> {
        let mut actions = Vec::new();
        for frame in
            origin_frame(update, generation, bytes).map_err(|_| CompanionFault::Protocol)?
        {
            actions.extend(self.frame(frame)?);
        }
        Ok(actions)
    }

    fn resume(
        &mut self,
        generation: u64,
        last: Option<(u64, [u8; 16])>,
    ) -> Result<Vec<Action>, CompanionFault> {
        self.frame(CompanionFrame::Resume {
            coordinator_server_id: COORDINATOR,
            server_incarnation: INCARNATION,
            delivery_generation: generation,
            last,
        })
    }

    /// Runs the READY, commits its batch, and returns the lines that follow.
    fn ready(&mut self, cut: Cut) -> TestResult<Vec<CompanionFrame>> {
        let actions = self.frame(CompanionFrame::StateCut {
            active: false,
            server_id: COORDINATOR,
            snapshot_token: cut.token,
            state_generation: cut.state_generation,
            delivery_generation: cut.delivery_generation,
            snapshot_digest: cut.digest,
        })?;
        let [Action::Stage { writes, work }] = actions.as_slice() else {
            return Err("expected one staged batch".into());
        };
        assert_ready_owner(writes, cut)?;
        assert!(matches!(work, PendingWork::Activate { .. }));
        let Some(Action::Stage { work, .. }) = actions.into_iter().next() else {
            return Err("expected one staged batch".into());
        };
        self.harness.coordinator.set_pending(work);
        let committed = self
            .harness
            .coordinator
            .batch_applied(Some(self.host.resync_epoch))
            .map_err(|fault| format!("{fault:?}"))?;
        let Some(Committed::Lines(lines)) = committed else {
            return Err("expected committed lines".into());
        };
        lines.iter().map(|(_, line)| parse(line)).collect()
    }
}

fn assert_ready_owner(
    writes: &[crate::state_core::durable::AccountServiceDurableWrite],
    cut: Cut,
) -> TestResult {
    assert_ready_owner_for(writes, cut, home())
}

fn assert_ready_owner_for(
    writes: &[crate::state_core::durable::AccountServiceDurableWrite],
    cut: Cut,
    peer: ServerId,
) -> TestResult {
    use crate::state_core::durable::AccountServiceDurableWrite;
    use agenc_relay_storage::e2ee_records::delivery_recovery::{
        CutPhase, DeliveryRecoveryRow, LastAcknowledged,
    };
    use agenc_relay_storage::{PersistentRecordValue, TableId};
    let [
        AccountServiceDurableWrite::Put {
            table,
            key,
            plaintext,
        },
    ] = writes
    else {
        return Err("one exact Ready owner write".into());
    };
    assert_eq!(*table, TableId::E2eeState);
    let value = PersistentRecordValue::decode(*table, plaintext)?;
    assert_eq!(value.record_kind(), 14);
    let DeliveryRecoveryRow::Owner(owner) = DeliveryRecoveryRow::decode_at(key, value.body())?
    else {
        return Err("Ready owner arm".into());
    };
    assert_eq!(owner.phase(), CutPhase::Ready);
    assert_eq!(owner.scope().target_server_id(), *peer.as_bytes());
    assert_eq!(owner.scope().target_incarnation(), INCARNATION);
    assert_eq!(owner.cut().token(), cut.token);
    assert_eq!(owner.cut().state_generation(), cut.state_generation);
    assert_eq!(owner.cut().digest(), cut.digest);
    assert_eq!(owner.cut().entry_count(), cut.entry_count);
    assert_eq!(owner.cursor().generation(), cut.delivery_generation);
    assert_eq!(owner.cursor().next_sequence(), 0);
    assert_eq!(owner.cursor().last_ack(), LastAcknowledged::BeforeFirst);
    Ok(())
}

fn begin_cut(frames: &[CompanionFrame]) -> TestResult<(Cut, u32, Option<[u8; 32]>)> {
    let Some(CompanionFrame::StateBegin {
        snapshot_token,
        state_generation,
        delivery_generation,
        total_entry_count,
        page_entry_count,
        snapshot_digest,
        ..
    }) = frames.first()
    else {
        return Err("expected ESTATE BEGIN".into());
    };
    let Some(CompanionFrame::StateEnd { next_cursor, .. }) = frames.last() else {
        return Err("expected ESTATE END".into());
    };
    Ok((
        Cut {
            token: *snapshot_token,
            state_generation: *state_generation,
            delivery_generation: *delivery_generation,
            digest: *snapshot_digest,
            entry_count: *total_entry_count,
        },
        *page_entry_count,
        *next_cursor,
    ))
}

#[test]
fn origins_mirror_the_acked_base_declaration() -> TestResult {
    let (first, bytes) = origin_object(0, [0; 32], None, None)?;
    // A declaration before RESET is refused.
    let mut early = Sync::new()?;
    assert_eq!(
        early.declare(false, 0, &bytes).err(),
        Some(CompanionFault::Protocol)
    );
    let mut sync = Sync::new()?;
    let ready = sync.reset()?;
    assert!(matches!(
        ready.as_slice(),
        [CompanionFrame::OriginReady { home_server_id, server_incarnation }]
            if *home_server_id == HOME && *server_incarnation == INCARNATION
    ));
    let acks = frames(&sync.declare(false, 0, &bytes)?)?;
    assert!(matches!(
        acks.as_slice(),
        [CompanionFrame::OriginAck { origin_generation: 0, object_id: Some(id), .. }] if *id == object_id(&bytes)
    ));
    let key = CompanionOriginKey {
        home_server_id: HOME,
        server_incarnation: INCARNATION,
        origin_id: ORIGIN,
    };
    let stored = sync
        .harness
        .coordinator
        .state
        .origins
        .get(&key)
        .cloned()
        .ok_or("origin")?;
    assert_eq!(
        stored.state_id,
        semantic_id_of(SemanticHashDomain::FederationOriginState, &first)?
    );
    assert!(!stored.suspended);
    // The identical declaration again is accepted without change.
    assert_eq!(frames(&sync.declare(false, 0, &bytes)?)?.len(), 1);

    // A principal that differs from the base is refused: the object names
    // an account the base origin does not carry.
    let (_, unauthenticated) = origin_object(0, [0; 32], Some((sync.harness.account, 3)), None)?;
    assert_eq!(
        sync.declare(false, 0, &unauthenticated).err(),
        Some(CompanionFault::Protocol)
    );

    // The base moved to generation one with an account; the companion
    // UPDATE must name the accepted predecessor and mirror the account.
    sync.host.origin = Some(BaseOriginView {
        generation: 1,
        account: Some((sync.harness.account, 3)),
        ..FakeHost::default().origin.ok_or("origin")?
    });
    let (_, wrong_previous) = origin_object(1, [9; 32], Some((sync.harness.account, 3)), None)?;
    assert_eq!(
        sync.declare(true, 1, &wrong_previous).err(),
        Some(CompanionFault::Protocol)
    );
    let (_, wrong_generation) =
        origin_object(1, stored.state_id, Some((sync.harness.account, 4)), None)?;
    assert_eq!(
        sync.declare(true, 1, &wrong_generation).err(),
        Some(CompanionFault::Protocol)
    );
    let (_, attached) = origin_object(
        1,
        stored.state_id,
        Some((sync.harness.account, 3)),
        Some(([7; 16], 1)),
    )?;
    // The device is not attached in the directory yet.
    assert_eq!(
        sync.declare(true, 1, &attached).err(),
        Some(CompanionFault::Protocol)
    );
    let (_, update) = origin_object(1, stored.state_id, Some((sync.harness.account, 3)), None)?;
    sync.harness
        .coordinator
        .state
        .origins
        .get_mut(&key)
        .ok_or("origin")?
        .next_sequence = 5;
    assert_eq!(frames(&sync.declare(true, 1, &update)?)?.len(), 1);
    let updated = sync
        .harness
        .coordinator
        .state
        .origins
        .get(&key)
        .cloned()
        .ok_or("origin")?;
    assert_eq!(updated.generation, 1);
    assert_eq!(updated.next_sequence, 0);
    assert_eq!(updated.account_id, Some(sync.harness.account));

    // DEL must name the generation in force; then the origin is fenced.
    assert_eq!(
        sync.frame(CompanionFrame::OriginDel {
            coordinator_server_id: COORDINATOR,
            server_incarnation: INCARNATION,
            origin_id: ORIGIN,
            origin_generation: 0,
            next_operation_sequence: 5,
        })
        .err(),
        Some(CompanionFault::Protocol)
    );
    let acks = frames(&sync.frame(CompanionFrame::OriginDel {
        coordinator_server_id: COORDINATOR,
        server_incarnation: INCARNATION,
        origin_id: ORIGIN,
        origin_generation: 1,
        next_operation_sequence: 0,
    })?)?;
    assert!(matches!(
        acks.as_slice(),
        [CompanionFrame::OriginAck {
            object_id: None,
            ..
        }]
    ));
    assert!(
        sync.harness
            .coordinator
            .state
            .origins
            .get(&key)
            .is_some_and(|origin| origin.fenced)
    );
    assert_eq!(
        sync.declare(true, 2, &update).err(),
        Some(CompanionFault::Protocol)
    );
    Ok(())
}

#[test]
fn origin_ready_waits_for_the_base_set() -> TestResult {
    let mut sync = Sync::new()?;
    sync.host.ready = false;
    assert!(sync.reset()?.is_empty());
    let line = sync
        .harness
        .coordinator
        .origins_ready(home(), INCARNATION)
        .map_err(|fault| format!("{fault:?}"))?
        .ok_or("the READY line")?;
    assert!(matches!(parse(&line)?, CompanionFrame::OriginReady { .. }));
    assert!(
        sync.harness
            .coordinator
            .origins_ready(home(), INCARNATION)
            .map_err(|fault| format!("{fault:?}"))?
            .is_none()
    );
    sync.host.incarnation = Some([9; 16]);
    assert!(sync.reset().is_err());
    Ok(())
}

#[test]
fn resume_opens_a_transfer_for_a_new_scope_then_replays_the_exact_cursor() -> TestResult {
    let mut sync = Sync::new()?;
    let actions = sync.resume(0, None).map_err(|fault| format!("{fault:?}"))?;
    assert!(
        matches!(actions.first(), Some(Action::ScheduleExpiry { at_millis }) if *at_millis == NOW_MILLIS + 15 * 60 * 1_000)
    );
    let page = frames(&actions)?;
    let (cut, page_count, next) = begin_cut(&page)?;
    assert_eq!(page.len(), 2);
    assert_eq!((cut.entry_count, page_count, next), (0, 0, None));
    assert_eq!(cut.delivery_generation, 0);
    assert_eq!(cut.state_generation, 40);
    assert_eq!(cut.digest, federation_snapshot_digest(40, 0, &[])?);
    assert!(!sync.harness.coordinator.delivering(home()));
    // A second ERESUME during the transfer is a violation.
    assert_eq!(sync.resume(0, None).err(), Some(CompanionFault::Protocol));
    let lines = sync.ready(cut)?;
    assert!(matches!(
        lines.as_slice(),
        [CompanionFrame::StateCut { active: true, snapshot_token, .. }] if *snapshot_token == cut.token
    ));
    assert!(sync.harness.coordinator.delivering(home()));
    // A repeated READY after the record is answered by the identical ACTIVE.
    let again = sync.frame(CompanionFrame::StateCut {
        active: false,
        server_id: COORDINATOR,
        snapshot_token: cut.token,
        state_generation: cut.state_generation,
        delivery_generation: cut.delivery_generation,
        snapshot_digest: cut.digest,
    })?;
    assert!(matches!(
        frames(&again)?.as_slice(),
        [CompanionFrame::StateCut { active: true, .. }]
    ));

    // Link loss pauses delivery; the same scope resumes at the exact cursor.
    sync.harness.coordinator.link_closed(home());
    assert!(!sync.harness.coordinator.delivering(home()));
    let actions = sync.resume(0, None).map_err(|fault| format!("{fault:?}"))?;
    assert!(matches!(
        frames(&actions)?.as_slice(),
        [CompanionFrame::ResumeOk {
            delivery_generation: 0,
            next_delivery_sequence: 0,
            ..
        }]
    ));
    assert!(sync.harness.coordinator.delivering(home()));

    // Queue two rows, acknowledge the first, and resume from it: the second
    // row is retransmitted after ERESUME OK.
    sync.harness.coordinator.link_closed(home());
    let stream = sync
        .harness
        .coordinator
        .state
        .streams
        .get_mut(&home())
        .ok_or("stream")?;
    for sequence in 0..2 {
        stream.rows.push_back(super::super::events::StreamRow {
            sequence,
            event_id: [u8::try_from(sequence)? + 1; 16],
            event: super::super::events::SharedBytes::for_fixture(wire(
                ArcWireObjectKind::FederationOrigin,
                &origin_object(0, [0; 32], None, None)?.0,
            )?)?,
            payload: None,
            acknowledgement: agenc_relay_storage::e2ee_records::delivery_recovery::Acknowledgement::Unacknowledged,
        });
        stream.next_sequence = sequence + 1;
    }
    stream
        .acknowledge(0, [1; 16], agenc_relay_storage::e2ee_records::delivery_recovery::Acknowledgement::AcknowledgedTimeUnknown)
        .map_err(|fault| format!("{fault:?}"))?;
    assert_eq!(sync.resume(0, None).err(), Some(CompanionFault::Protocol));
    assert_eq!(
        sync.resume(1, Some((0, [1; 16]))).err(),
        Some(CompanionFault::Protocol)
    );
    assert_eq!(
        sync.resume(0, Some((0, [9; 16]))).err(),
        Some(CompanionFault::Protocol)
    );
    let actions = sync
        .resume(0, Some((0, [1; 16])))
        .map_err(|fault| format!("{fault:?}"))?;
    let replay = frames(&actions)?;
    assert!(matches!(
        replay.first(),
        Some(CompanionFrame::ResumeOk {
            next_delivery_sequence: 1,
            ..
        })
    ));
    assert!(matches!(
        replay.get(1),
        Some(CompanionFrame::Event { position: DeliveryPosition { delivery_sequence: 1, event_id, .. }, .. }) if *event_id == [2; 16]
    ));
    assert_eq!(replay.len(), 2);
    Ok(())
}

#[test]
fn a_base_reset_opens_the_next_delivery_generation() -> TestResult {
    let mut sync = Sync::new()?;
    let page = frames(&sync.resume(0, None).map_err(|fault| format!("{fault:?}"))?)?;
    let (cut, _, _) = begin_cut(&page)?;
    sync.ready(cut)?;
    sync.harness.coordinator.link_closed(home());
    sync.host.resync_epoch = 1;
    let page = frames(&sync.resume(0, None).map_err(|fault| format!("{fault:?}"))?)?;
    let (next, _, _) = begin_cut(&page)?;
    assert_eq!(next.delivery_generation, 1);
    assert_eq!(
        sync.harness
            .coordinator
            .state
            .streams
            .get(&home())
            .map(|stream| stream.generation),
        Some(1)
    );
    // Link loss alone retains this pending cut and cannot mint a new
    // generation: the resume on the next link publishes the same cut again
    // from its first page.
    sync.harness.coordinator.link_closed(home());
    let page = frames(&sync.resume(1, None).map_err(|fault| format!("{fault:?}"))?)?;
    let (retained, _, _) = begin_cut(&page)?;
    assert_eq!(retained, next);
    assert_eq!(
        sync.harness
            .coordinator
            .peer_sync(home())
            .and_then(|peer| peer.snapshot.as_ref())
            .map(|snapshot| snapshot.cut),
        Some(next)
    );
    sync.host.resync_epoch = 2;
    let page = frames(&sync.resume(1, None).map_err(|fault| format!("{fault:?}"))?)?;
    let (again, _, _) = begin_cut(&page)?;
    assert_eq!(again.delivery_generation, 2);
    Ok(())
}

fn entitle(sync: &mut Sync, count: usize) -> TestResult<Vec<[u8; 32]>> {
    let mut ids = Vec::new();
    for index in 0..count {
        let conversation = {
            let mut id = [0; 32];
            id[..8].copy_from_slice(&u64::try_from(index)?.to_be_bytes());
            id
        };
        let bytes = snapshot_route(NETWORK, conversation, 40)?;
        let object = object_id(&bytes);
        let state = sync
            .harness
            .coordinator
            .state
            .conversations
            .entry(conversation)
            .or_default();
        state.route_object_id = object;
        sync.harness.coordinator.state.objects.insert(object, bytes);
        sync.harness
            .coordinator
            .state
            .entitlements
            .set_channel(home(), conversation, true);
        ids.push(object);
    }
    Ok(ids)
}

fn fetch(
    sync: &mut Sync,
    cut: &Cut,
    page: u32,
    cursor: [u8; 32],
) -> Result<Vec<CompanionFrame>, CompanionFault> {
    let actions = sync.frame(CompanionFrame::StateFetch {
        coordinator_server_id: COORDINATOR,
        snapshot_token: cut.token,
        next_page_sequence: page,
        cursor,
    })?;
    frames(&actions).map_err(|_| CompanionFault::Protocol)
}

/// ENC-15 (#160): a full cut re-derives direct standing from what the edge
/// hosts. A direct reference left by an earlier event, for accounts the
/// edge hosts nothing for, is fenced with the reset and leaves the cut, so
/// an honest cut is exactly what the edge verifies.
#[test]
fn a_full_cut_drops_direct_standing_the_edge_no_longer_hosts() -> TestResult {
    use agenc_relay_domain::e2ee::projection::EntitlementReason;
    let mut sync = Sync::new()?;
    let channels = entitle(&mut sync, 1)?;
    let stale = [0xd1; 32];
    let bytes = snapshot_route(NETWORK, stale, 40)?;
    let object = object_id(&bytes);
    let state = &mut sync.harness.coordinator.state;
    state
        .conversations
        .entry(stale)
        .or_default()
        .route_object_id = object;
    state.objects.insert(object, bytes);
    state
        .entitlements
        .require_direct(home(), stale, EntitlementReason::Event)?;
    assert!(state.entitlements.entitled(home(), &stale));
    let actions = sync.resume(0, None).map_err(|fault| format!("{fault:?}"))?;
    let (cut, page_count, _) = begin_cut(&frames(&actions)?)?;
    assert_eq!((cut.entry_count, page_count), (1, 1));
    assert_eq!(cut.digest, federation_snapshot_digest(40, 0, &channels)?);
    assert!(
        !sync
            .harness
            .coordinator
            .state
            .entitlements
            .entitled(home(), &stale)
    );
    Ok(())
}

#[test]
fn state_pages_partition_entries_by_batch_size() -> TestResult {
    for (count, pages) in [(1, 1), (31, 1), (32, 1), (33, 2), (65, 3)] {
        let mut sync = Sync::new()?;
        let ids = entitle(&mut sync, count)?;
        let first = frames(&sync.resume(0, None).map_err(|fault| format!("{fault:?}"))?)?;
        let (cut, page_count, mut cursor) = begin_cut(&first)?;
        assert_eq!(cut.entry_count, u32::try_from(count)?);
        assert_eq!(cut.digest, federation_snapshot_digest(40, 0, &ids)?);
        assert_eq!(usize::try_from(page_count)?, count.min(32));
        let mut seen = usize::try_from(page_count)?;
        let mut sent_pages = 1;
        while let Some(next) = cursor {
            // A wrong cursor or a page out of order is fatal for the link.
            assert!(fetch(&mut sync, &cut, sent_pages, [0; 32]).is_err());
            assert!(fetch(&mut sync, &cut, sent_pages + 1, next).is_err());
            let page =
                fetch(&mut sync, &cut, sent_pages, next).map_err(|fault| format!("{fault:?}"))?;
            let retry =
                fetch(&mut sync, &cut, sent_pages, next).map_err(|fault| format!("{fault:?}"))?;
            assert_eq!(page, retry);
            let (_, entries, following) = begin_cut(&page)?;
            seen += usize::try_from(entries)?;
            sent_pages += 1;
            cursor = following;
            if following.is_some() {
                assert_eq!(entries, 32);
            }
        }
        assert_eq!(sent_pages, pages);
        assert_eq!(seen, count);
        // READY before the final page went out, or with a wrong digest, is refused.
        let wrong = Cut {
            digest: [1; 32],
            ..cut
        };
        assert!(
            sync.frame(CompanionFrame::StateCut {
                active: false,
                server_id: COORDINATOR,
                snapshot_token: wrong.token,
                state_generation: wrong.state_generation,
                delivery_generation: wrong.delivery_generation,
                snapshot_digest: wrong.digest,
            })
            .is_err()
        );
        sync.ready(cut)?;
    }
    Ok(())
}

#[test]
fn the_snapshot_token_expires_after_fifteen_minutes() -> TestResult {
    let mut sync = Sync::new()?;
    entitle(&mut sync, 40)?;
    let first = frames(&sync.resume(0, None).map_err(|fault| format!("{fault:?}"))?)?;
    let (cut, _, cursor) = begin_cut(&first)?;
    let cursor = cursor.ok_or("a second page")?;
    let late = NOW_MILLIS + 15 * 60 * 1_000;
    assert!(!sync.harness.coordinator.snapshot_expired(home(), late - 1));
    assert_eq!(
        sync.frame_at(
            CompanionFrame::StateFetch {
                coordinator_server_id: COORDINATOR,
                snapshot_token: cut.token,
                next_page_sequence: 1,
                cursor,
            },
            late,
        )
        .err(),
        Some(CompanionFault::Protocol)
    );
    assert!(sync.harness.coordinator.snapshot_expired(home(), late));
    assert!(!sync.harness.coordinator.snapshot_expired(home(), late));
    Ok(())
}

#[test]
fn a_retransmitted_request_replays_its_stored_result() -> TestResult {
    use agenc_relay_e2ee::objects::federation::ArcFederationOpcode as Op;
    let mut sync = Sync::new()?;
    let complete = sync.harness.request(Op::Whoami, &[], None)?;
    let request_object = object_id(&complete.request);
    // On the wire the request names the coordinator as its peer.
    let wire_correlation = agenc_relay_e2ee::federation::frames::Correlation {
        peer_server_id: COORDINATOR,
        ..complete.correlation
    };
    let fragments: Vec<CompanionFrame> = fragment_object(&complete.request)?
        .into_iter()
        .map(|fragment| CompanionFrame::Request {
            correlation: wire_correlation,
            object_id: request_object,
            fragment,
        })
        .collect();
    // The request completes and is handed over for execution.
    let mut first = Vec::new();
    for frame in fragments.clone() {
        first.extend(sync.frame(frame)?);
    }
    assert!(matches!(first.as_slice(), [Action::Execute(_)]));
    // Before the answer is recorded a retransmission is a violation.
    let mut again = Vec::new();
    let mut refused = false;
    for frame in fragments.clone() {
        match sync.frame(frame) {
            Ok(actions) => again.extend(actions),
            Err(CompanionFault::Protocol) => refused = true,
            Err(other) => return Err(format!("{other:?}").into()),
        }
    }
    assert!(refused && again.is_empty());
    // With the replay row and result recorded, the same bytes replay it.
    let decoded = super::super::request::decode(&sync.harness.coordinator, &complete)
        .map_err(|code| format!("{code:?}"))?;
    let key = super::super::request::replay_key(HOME, &decoded.request);
    sync.harness.coordinator.state.replays.insert(
        key,
        agenc_relay_storage::e2ee_records::ReplayRow {
            request_id: decoded.request.request_id,
            request_object_id: request_object,
            result_object_id: Some([1; 32]),
            response_object_ids: Vec::new(),
            security_mutation: false,
            retain_until: 1_000,
        },
    );
    let result = wire(
        ArcWireObjectKind::FederationResult,
        &origin_object(0, [0; 32], None, None)?.0,
    )?;
    super::super::results::Prepared::capture(&result, std::iter::empty(), &sync.harness.backing)?
        .apply(&mut sync.harness.coordinator.state.results, request_object);
    let mut replay = Vec::new();
    for frame in fragments {
        replay.extend(sync.frame(frame)?);
    }
    let lines = frames(&replay)?;
    assert!(matches!(lines.first(), Some(CompanionFrame::Result { .. })));
    Ok(())
}

#[test]
fn requests_need_an_active_ready_peer() -> TestResult {
    let mut sync = Sync::new()?;
    assert!(!sync.harness.coordinator.accepting_requests(home()));
    let page = frames(&sync.resume(0, None).map_err(|fault| format!("{fault:?}"))?)?;
    let (cut, _, _) = begin_cut(&page)?;
    sync.ready(cut)?;
    assert!(!sync.harness.coordinator.accepting_requests(home()));
    sync.reset()?;
    assert!(sync.harness.coordinator.accepting_requests(home()));
    Ok(())
}

/// A coordinator that reloaded without its companion origins meets the
/// replayed UPDATE of an origin it acknowledged before its restart: the
/// matched base origin anchors it and the operation sequence continues
/// from the durable origin floor. A DEL for an origin it never learned is
/// acknowledged with nothing to fence.
#[test]
fn a_reloaded_coordinator_accepts_a_replayed_origin_update() -> TestResult {
    let mut sync = Sync::new()?;
    sync.reset()?;
    sync.host.origin = Some(BaseOriginView {
        generation: 1,
        account: Some((sync.harness.account, 3)),
        ..FakeHost::default().origin.ok_or("origin")?
    });
    sync.harness.coordinator.state.replays.insert(
        ReplayKey {
            home_server_id: HOME,
            server_incarnation: INCARNATION,
            origin_id: ORIGIN,
            origin_generation: 1,
            operation_sequence: 4,
        },
        ReplayRow {
            request_id: [1; 16],
            request_object_id: [2; 32],
            result_object_id: None,
            response_object_ids: Vec::new(),
            security_mutation: false,
            retain_until: 0,
        },
    );
    sync.harness.coordinator.state.origin_sequences.insert(
        CompanionOriginKey {
            home_server_id: HOME,
            server_incarnation: INCARNATION,
            origin_id: ORIGIN,
        },
        agenc_relay_storage::e2ee_records::origin::OriginSequenceRow {
            origin_generation: 1,
            next_sequence: 5,
        },
    );
    let (_, update) = origin_object(1, [9; 32], Some((sync.harness.account, 3)), None)?;
    assert_eq!(frames(&sync.declare(true, 1, &update)?)?.len(), 1);
    let key = CompanionOriginKey {
        home_server_id: HOME,
        server_incarnation: INCARNATION,
        origin_id: ORIGIN,
    };
    let origin = sync
        .harness
        .coordinator
        .state
        .origins
        .get(&key)
        .cloned()
        .ok_or("origin")?;
    assert_eq!(origin.generation, 1);
    assert_eq!(origin.next_sequence, 5);
    assert_eq!(origin.account_id, Some(sync.harness.account));

    // A replayed UPDATE at generation zero is still an ADD's job.
    let (_, zero) = origin_object(0, [0; 32], None, None)?;
    assert_eq!(
        sync.declare(true, 0, &zero).err(),
        Some(CompanionFault::Protocol)
    );

    let acks = frames(&sync.frame(CompanionFrame::OriginDel {
        coordinator_server_id: COORDINATOR,
        server_incarnation: INCARNATION,
        origin_id: [8; 16],
        origin_generation: 2,
        next_operation_sequence: 7,
    })?)?;
    assert!(matches!(
        acks.as_slice(),
        [CompanionFrame::OriginAck {
            origin_generation: 2,
            object_id: None,
            ..
        }]
    ));
    Ok(())
}

pub(super) fn snapshot_route(
    network_id: [u8; 32],
    conversation_id: [u8; 32],
    state_generation: u64,
) -> TestResult<Vec<u8>> {
    use agenc_relay_e2ee::objects::conversation::ArcConversationKind;
    use agenc_relay_e2ee::objects::federation::{ArcFederationRouteState, ArcRouteStateKind};
    wire(
        ArcWireObjectKind::FederationState,
        &ArcFederationRouteState {
            profile_version: 1,
            network_id,
            state_generation,
            conversation_id,
            conversation_kind: ArcConversationKind::Channel,
            route_binding: [11; 32],
            semantic_route_lock_id: [12; 32],
            channel_instance_id: Opaque::new(vec![13; 16])?,
            canonical_channel_name_hash: [14; 32],
            direct_account_a: Opaque::new(Vec::new())?,
            direct_account_b: Opaque::new(Vec::new())?,
            binding_id: [15; 32],
            finalized_epoch: 1,
            accepted_state_id: [16; 32],
            sequencer_record_head_sequence: 0,
            sequencer_record_head_id: [17; 32],
            state: ArcRouteStateKind::ActiveRoute,
        },
    )
}

/// Completes the initial cut and Ready receipt for a handler-only fixture peer.
pub(super) fn initial_ready_peer(
    coordinator: &mut super::super::CompanionCoordinator,
    peer: ServerId,
) -> TestResult {
    let host = FakeHost {
        revision: super::STATE_GENERATION,
        ..FakeHost::default()
    };
    let mut entropy = Counter(60);
    let mut actions = coordinator.on_frame(
        LinkId::new(1),
        peer,
        CompanionFrame::Resume {
            coordinator_server_id: COORDINATOR,
            server_incarnation: INCARNATION,
            delivery_generation: 0,
            last: None,
        },
        NOW_MILLIS,
        &host,
        &mut entropy,
    )?;
    for _ in 0..agenc_relay_storage::e2ee_records::delivery_recovery::MAX_SNAPSHOT_PAGES + 2 {
        if !matches!(
            actions.as_slice(),
            [Action::Stage {
                work: PendingWork::Snapshot(_),
                ..
            }]
        ) {
            break;
        }
        let Some(Action::Stage { work, .. }) = actions.into_iter().next() else {
            return Err("expected exact initial page or owner stage".into());
        };
        coordinator.set_pending(work);
        let Some(Committed::Snapshot(publication)) = coordinator.batch_applied(Some(0))? else {
            return Err("expected exact initial page or owner receipt".into());
        };
        actions = coordinator.continue_snapshot_publication(*publication, NOW_MILLIS, &host)?;
    }
    let (cut, _, _) = begin_cut(&frames(&actions)?)?;
    let actions = coordinator.on_frame(
        LinkId::new(1),
        peer,
        CompanionFrame::StateCut {
            active: false,
            server_id: COORDINATOR,
            snapshot_token: cut.token,
            state_generation: cut.state_generation,
            delivery_generation: cut.delivery_generation,
            snapshot_digest: cut.digest,
        },
        NOW_MILLIS,
        &host,
        &mut entropy,
    )?;
    let Some(Action::Stage { writes, work }) = actions.into_iter().next() else {
        return Err("Ready must stage its durable owner".into());
    };
    assert_ready_owner_for(&writes, cut, peer)?;
    assert!(matches!(work, PendingWork::Activate { .. }));
    coordinator.set_pending(work);
    assert!(matches!(
        coordinator.batch_applied(Some(0))?,
        Some(Committed::Lines(_))
    ));
    assert!(coordinator.delivering(peer));
    Ok(())
}

#[test]
fn a_resume_on_an_active_stream_is_a_violation() -> TestResult {
    let mut sync = Sync::new()?;
    let page = frames(&sync.resume(0, None).map_err(|fault| format!("{fault:?}"))?)?;
    let (cut, _, _) = begin_cut(&page)?;
    sync.ready(cut)?;
    assert_eq!(sync.resume(0, None).err(), Some(CompanionFault::Protocol));
    Ok(())
}

#[test]
fn a_base_epoch_behind_the_stream_scope_is_a_violation() -> TestResult {
    let mut sync = Sync::new()?;
    let page = frames(&sync.resume(0, None).map_err(|fault| format!("{fault:?}"))?)?;
    let (cut, _, _) = begin_cut(&page)?;
    sync.ready(cut)?;
    sync.harness.coordinator.link_closed(home());
    sync.host.resync_epoch = 1;
    let page = frames(&sync.resume(0, None).map_err(|fault| format!("{fault:?}"))?)?;
    let (next, _, _) = begin_cut(&page)?;
    sync.ready(next)?;
    // The stream scope now covers base epoch one; an older base epoch on
    // the next link cannot resume it.
    sync.harness.coordinator.link_closed(home());
    sync.host.resync_epoch = 0;
    assert_eq!(sync.resume(1, None).err(), Some(CompanionFault::Protocol));
    Ok(())
}

#[test]
fn an_expired_pending_cut_resets_to_the_next_delivery_generation() -> TestResult {
    let mut sync = Sync::new()?;
    entitle(&mut sync, 40)?;
    let first = frames(&sync.resume(0, None).map_err(|fault| format!("{fault:?}"))?)?;
    let (cut, _, _) = begin_cut(&first)?;
    let late = NOW_MILLIS + 15 * 60 * 1_000;
    assert!(sync.harness.coordinator.snapshot_expired(home(), late));
    sync.harness.coordinator.link_closed(home());
    let page = frames(&sync.resume(0, None).map_err(|fault| format!("{fault:?}"))?)?;
    let (next, _, _) = begin_cut(&page)?;
    assert_eq!(next.delivery_generation, 1);
    assert_ne!(next.token, cut.token);
    Ok(())
}

fn state_cut(cut: &Cut) -> CompanionFrame {
    CompanionFrame::StateCut {
        active: false,
        server_id: COORDINATOR,
        snapshot_token: cut.token,
        state_generation: cut.state_generation,
        delivery_generation: cut.delivery_generation,
        snapshot_digest: cut.digest,
    }
}

#[test]
fn a_ready_is_refused_behind_a_pending_batch_for_another_cut_scope_or_after_expiry() -> TestResult {
    let mut sync = Sync::new()?;
    let page = frames(&sync.resume(0, None).map_err(|fault| format!("{fault:?}"))?)?;
    let (cut, _, _) = begin_cut(&page)?;
    let mut other_cut = cut;
    other_cut.token = [9; 32];
    assert_eq!(
        sync.frame(state_cut(&other_cut)).err(),
        Some(CompanionFault::Protocol),
        "another cut"
    );
    let late = NOW_MILLIS + 16 * 60 * 1_000;
    assert_eq!(
        sync.frame_at(state_cut(&cut), late).err(),
        Some(CompanionFault::Protocol),
        "an expired cut"
    );
    sync.host.incarnation = Some([9; 16]);
    assert_eq!(
        sync.frame(state_cut(&cut)).err(),
        Some(CompanionFault::Protocol),
        "another live incarnation"
    );
    sync.host.incarnation = Some(INCARNATION);
    let actions = sync.frame(state_cut(&cut))?;
    let Some(Action::Stage { work, .. }) = actions.into_iter().next() else {
        return Err("expected one staged batch".into());
    };
    sync.harness.coordinator.set_pending(work);
    assert_eq!(
        sync.frame(state_cut(&cut)).err(),
        Some(CompanionFault::Ceiling),
        "a READY behind the pending batch"
    );
    Ok(())
}

#[test]
fn a_resumed_final_ack_commit_never_activates_an_active_stream() -> TestResult {
    let mut sync = Sync::new()?;
    let page = frames(&sync.resume(0, None).map_err(|fault| format!("{fault:?}"))?)?;
    let (cut, _, _) = begin_cut(&page)?;
    sync.ready(cut)?;
    assert_eq!(
        sync.harness
            .coordinator
            .resume_ack_committed(home(), LinkId::new(1))
            .err(),
        Some(CompanionFault::Protocol)
    );
    assert!(
        sync.harness
            .coordinator
            .resume_ack_committed(home(), LinkId::new(2))?
            .is_empty(),
        "another link's commit is ignored"
    );
    Ok(())
}
