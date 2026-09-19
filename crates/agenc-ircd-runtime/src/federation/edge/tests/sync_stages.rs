#![forbid(unsafe_code)]

//! The stages of link synchronization the edge refuses, abandons or resumes.

use agenc_ircd_domain::federation::{ProjectionRecord, SessionRecord};
use agenc_ircd_domain::{DisplayNameValue, NicknameValue};
use agenc_ircd_federation_wire::CanonicalEncode;
use agenc_ircd_storage::federation_records::{ProjectionGenerationState, ProjectionMarkerRecord};
use agenc_ircd_types::{
    EventId, FederationRole, NetworkId, RecoveryEpoch, Revision, ServerId, ServerIncarnation,
    SessionId, UserId,
};

use super::*;
use crate::connection::ConnectionGeneration;
use crate::federation::edge::startup::EdgeRestoreCause;
use crate::federation::edge::{EdgeConfig, LiveLink};
use crate::federation::link::{LinkQueue, link_queue};
use crate::federation::{LinkId, PeerIdentity};
use crate::test_support::StateCoreFixture;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const NETWORK: NetworkId = NetworkId::from_bytes([1; 32]);
const EDGE: ServerId = ServerId::from_bytes([2; 16]);
const HUB: ServerId = ServerId::from_bytes([3; 16]);
const EDGE_INCARNATION: ServerIncarnation = ServerIncarnation::from_bytes([4; 16]);
const HUB_EPOCH: RecoveryEpoch = RecoveryEpoch::from_bytes([5; 16]);
const HUB_INCARNATION: ServerIncarnation = ServerIncarnation::from_bytes([17; 16]);
const CONNECTION: ConnectionGeneration = ConnectionGeneration::new(1);

fn edge() -> EdgeFederation {
    EdgeFederation::new(EdgeConfig {
        network_id: NETWORK,
        server_id: EDGE,
        server_name: "edge.example".to_owned(),
        incarnation: EDGE_INCARNATION,
        coordinator: PeerIdentity::new(
            HUB,
            "coordinator.example",
            FederationRole::Coordinator,
            HUB_EPOCH,
            agenc_ircd_crypto::Ed25519SecretKey::from_bytes([6; 32]).public_key(),
            [7; 32],
        ),
    })
}

fn link(edge: &mut EdgeFederation, epoch: RecoveryEpoch) -> LinkQueue {
    let (handle, queue) = link_queue(1 << 20);
    edge.live = Some(LiveLink {
        link: LinkId::new(1),
        handle,
        coordinator_epoch: epoch,
        coordinator_incarnation: HUB_INCARNATION,
    });
    queue
}

async fn next_line(queue: &mut LinkQueue) -> TestResult<String> {
    let line = tokio::time::timeout(std::time::Duration::from_secs(5), queue.recv())
        .await?
        .ok_or("the link closed")?;
    Ok(line.as_str().to_owned())
}

fn rendered(frame: &FederationFrame) -> TestResult<String> {
    Ok(frame.render("edge.example")?.as_str().to_owned())
}

fn session(seed: u8) -> TestResult<SessionRecord> {
    Ok(SessionRecord {
        session_id: SessionId::from_bytes([seed; 16]),
        user_id: UserId::from_bytes([seed; 16]),
        home_server_id: EDGE,
        session_revision: Revision::new(1)?,
        account: None,
        nickname: NicknameValue::parse(&format!("member{seed}"))?,
        display_name: DisplayNameValue::prepare("Real Name")?,
        public_cloak: agenc_ircd_testkit::deterministic_cloak(seed)?,
        account_label: None,
        user_mode_bits: 1,
        away: None,
    })
}

fn sessions(seeds: &[u8]) -> TestResult<Vec<ProjectionRecord>> {
    let mut entries = Vec::new();
    for seed in seeds {
        entries.push(ProjectionRecord::Session(session(*seed)?));
    }
    entries.sort_by_key(ProjectionRecord::key);
    Ok(entries)
}

fn identity(generation: u64) -> SnapshotIdentity {
    SnapshotIdentity {
        snapshot_token: FederationHash32::from_bytes([9; 32]),
        recovery_epoch: HUB_EPOCH,
        projection_generation: generation,
        state_generation: 7,
        snapshot_digest: FederationHash32::from_bytes([8; 32]),
    }
}

fn installing(entries: Vec<ProjectionRecord>) -> SnapshotInstall {
    SnapshotInstall {
        identity: identity(2),
        coordinator_incarnation: HUB_INCARNATION,
        expected: u64::try_from(entries.len()).unwrap_or(u64::MAX),
        entries,
        ids: Vec::new(),
        bytes: 0,
        verified: false,
        written: 0,
        ready_sent: false,
        cursor: None,
        staged_end: None,
        resync: Vec::new(),
    }
}

fn ready(entries: Vec<ProjectionRecord>) -> SnapshotInstall {
    let written = entries.len();
    SnapshotInstall {
        verified: true,
        ready_sent: true,
        written,
        ..installing(entries)
    }
}

#[test]
fn a_stopping_edge_holds_the_safe_point_only_for_a_staged_batch() {
    let mut edge = edge();
    assert!(!holds_safe_point(&edge));
    edge.snapshot = Some(installing(Vec::new()));
    assert!(
        holds_safe_point(&edge),
        "a running edge finishes its install"
    );
    edge.stopping = true;
    assert!(
        !holds_safe_point(&edge),
        "the coordinator is not waited for"
    );
    abandon_for_shutdown(&mut edge);
    assert!(edge.snapshot.is_none());
    abandon_for_shutdown(&mut edge);
    edge.snapshot = Some(SnapshotInstall {
        staged_end: Some(0),
        ..installing(Vec::new())
    });
    assert!(holds_safe_point(&edge), "a staged batch must settle");
    abandon_for_shutdown(&mut edge);
    assert!(edge.snapshot.is_some());
}

#[tokio::test]
async fn a_ready_snapshot_is_resent_only_to_the_coordinator_that_cut_it() -> TestResult {
    let other_epoch = RecoveryEpoch::from_bytes([99; 16]);
    for (epoch, installed, kept) in [
        (other_epoch, Some(HUB_INCARNATION), false),
        (HUB_EPOCH, Some(EDGE_INCARNATION), false),
        (HUB_EPOCH, None, false),
        (HUB_EPOCH, Some(HUB_INCARNATION), true),
    ] {
        let mut fixture = StateCoreFixture::new(vec![1; 256])?;
        let mut edge = edge();
        let mut queue = link(&mut edge, epoch);
        edge.installed_incarnation = installed;
        edge.snapshot = Some(ready(Vec::new()));
        begin(&mut edge, fixture.context_mut()?);
        assert_eq!(edge.snapshot.is_some(), kept);
        let line = next_line(&mut queue).await?;
        if kept {
            assert_eq!(edge.phase, Phase::Snapshot);
            let expected = FederationFrame::SnapshotReady {
                coordinator_server_id: HUB,
                identity: identity(2),
            };
            assert_eq!(line, rendered(&expected)?);
        } else {
            assert_eq!(edge.phase, Phase::Resuming);
            assert!(line.contains("FRESUME"), "{line}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn resume_offers_a_cursor_only_for_the_epoch_that_produced_it() -> TestResult {
    let at = |delivery_sequence, event_id| DeliveryCursor::At {
        delivery_sequence,
        event_id,
    };
    let unknown = at(u64::MAX, EventId::from_bytes([0; 16]));
    let known = EventId::from_bytes([44; 16]);
    for (installed, cursor, standing, expected) in [
        (Some(HUB_EPOCH), None, false, DeliveryCursor::Empty),
        (Some(HUB_EPOCH), None, true, unknown),
        (Some(HUB_EPOCH), Some((6, known)), true, at(6, known)),
        (None, Some((6, known)), true, unknown),
    ] {
        let mut fixture = StateCoreFixture::new(vec![1; 256])?;
        let mut edge = edge();
        let mut queue = link(&mut edge, HUB_EPOCH);
        edge.installed_epoch = installed;
        edge.cursor = cursor;
        if standing {
            edge.replica.install_recovered(1, sessions(&[20])?)?;
        }
        begin(&mut edge, fixture.context_mut()?);
        let frame = FederationFrame::Resume {
            coordinator_server_id: HUB,
            projection_generation: edge.replica.projection_generation(),
            cursor: expected,
        };
        assert_eq!(next_line(&mut queue).await?, rendered(&frame)?);
        assert_eq!(edge.phase, Phase::Resuming);
    }
    Ok(())
}

#[tokio::test]
async fn resume_ok_must_continue_the_exact_generation_and_sequence() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![1; 256])?;
    let context = fixture.context_mut()?;
    let mut edge = edge();
    let _queue = link(&mut edge, HUB_EPOCH);
    edge.cursor = Some((6, EventId::from_bytes([44; 16])));
    assert_eq!(resume_ok(&mut edge, context, 1, 7), Err(Violation::Phase));
    assert_eq!(resume_snapshot(&mut edge), Err(Violation::Phase));
    edge.phase = Phase::Resuming;
    let generation = edge.replica.projection_generation();
    for (claimed, next) in [(generation, 6), (generation, 8), (generation + 1, 7)] {
        assert_eq!(
            resume_ok(&mut edge, context, claimed, next),
            Err(Violation::Consistency)
        );
        assert_eq!(edge.phase, Phase::Resuming);
        assert_eq!(edge.installed_epoch, None);
    }
    assert_eq!(resume_ok(&mut edge, context, generation, 7), Ok(()));
    assert_eq!(edge.phase, Phase::Origins);
    assert_eq!(edge.installed_epoch, Some(HUB_EPOCH));
    assert_eq!(edge.accepted_epoch, Some(HUB_EPOCH));
    assert_eq!(edge.installed_incarnation, Some(HUB_INCARNATION));
    Ok(())
}

#[tokio::test]
async fn an_origin_reset_that_cannot_be_written_leaves_every_acknowledgement() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![1; 256])?;
    let context = fixture.context_mut()?;
    for dead_link in [false, true] {
        let mut edge = edge();
        edge.connection_opened(context, CONNECTION);
        edge.origins
            .get_mut(&CONNECTION)
            .ok_or("origin")?
            .acked_generation = Some(0);
        if dead_link {
            drop(link(&mut edge, HUB_EPOCH));
        }
        edge.phase = Phase::Resuming;
        assert_eq!(resume_ok(&mut edge, context, 1, 0), Ok(()));
        assert_eq!(
            edge.origins
                .get(&CONNECTION)
                .ok_or("origin")?
                .acked_generation,
            Some(0)
        );
        assert_eq!(edge.installed_epoch.is_some(), dead_link);
        assert_eq!(edge.counters.violations, 0);
    }
    Ok(())
}

#[tokio::test]
async fn origins_activate_only_when_every_declaration_and_deletion_is_settled() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![1; 256])?;
    let context = fixture.context_mut()?;
    let mut edge = edge();
    edge.connection_opened(context, CONNECTION);
    edge.phase = Phase::Origins;
    assert_eq!(
        origin_ready(&mut edge, context, HUB_INCARNATION),
        Err(Violation::Consistency)
    );
    assert_eq!(origin_ready(&mut edge, context, EDGE_INCARNATION), Ok(()));
    assert_eq!(
        edge.phase,
        Phase::Origins,
        "the declaration is unacknowledged"
    );
    let origin = edge.origins.get_mut(&CONNECTION).ok_or("origin")?;
    origin.acked_generation = Some(0);
    origin.session = Some((
        SessionId::from_bytes([41; 16]),
        UserId::from_bytes([42; 16]),
    ));
    edge.session_bound(context, CONNECTION);
    let origin = edge.origins.get_mut(&CONNECTION).ok_or("origin")?;
    origin.acked_generation = Some(0);
    activate_origins(&mut edge, context);
    assert_eq!(edge.phase, Phase::Origins, "an update is still in flight");
    let origin = edge.origins.get_mut(&CONNECTION).ok_or("origin")?;
    origin.pending_updates.clear();
    origin.deleted = true;
    activate_origins(&mut edge, context);
    assert_eq!(edge.phase, Phase::Origins, "the deletion is unacknowledged");
    edge.origins.get_mut(&CONNECTION).ok_or("origin")?.del_acked = true;
    activate_origins(&mut edge, context);
    assert_eq!(
        edge.phase,
        Phase::Origins,
        "the deletion is not yet durable"
    );
    edge.origins.clear();
    activate_origins(&mut edge, context);
    assert_eq!(edge.phase, Phase::Active);
    Ok(())
}

fn entry_object(record: &ProjectionRecord, generation: u64) -> TestResult<Vec<u8>> {
    let arm = crate::federation::codec::projection::projection_arm_object(record)?;
    let entry = ProjectionEntryHeader {
        network_id: NETWORK,
        target_server_id: EDGE,
        projection_generation: generation,
        projection_kind: crate::federation::codec::projection::projection_kind(record),
    }
    .build(&arm)?;
    Ok(entry.encode_canonical()?.as_slice().to_vec())
}

fn assembled(bytes: &[u8], token: FederationHash32) -> TestResult<AssembledObject> {
    use agenc_ircd_federation_wire::{
        AssemblyProgress, FragmentAssembler, federation_object_id, split_fragments,
    };
    let object_id = federation_object_id(bytes);
    let mut assembler = FragmentAssembler::new();
    for fragment in split_fragments(object_id, bytes)? {
        let frame = FederationFrame::SnapshotEntry {
            edge_server_id: EDGE,
            snapshot_token: token,
            entry_index: 0,
            object_id,
            fragment,
        };
        let (_, key) = crate::federation::link::carrier_of(&frame).map_err(|e| e.to_string())?;
        if let AssemblyProgress::Complete(object) =
            assembler.admit(key, frame.fragment().ok_or("fragment")?, 0)?
        {
            return Ok(object);
        }
    }
    Err("object did not assemble".into())
}

#[test]
fn an_entry_that_crosses_the_snapshot_byte_ceiling_is_refused() -> TestResult {
    let mut edge = edge();
    let record = ProjectionRecord::Session(session(20)?);
    let bytes = entry_object(&record, 2)?;
    let token = identity(2).snapshot_token;
    let object = assembled(&bytes, token)?;
    edge.snapshot = Some(SnapshotInstall {
        expected: 1,
        bytes: MAX_SNAPSHOT_BYTES,
        ..installing(Vec::new())
    });
    assert_eq!(
        snapshot_entry(&mut edge, token, 0, object.object_id(), &object),
        Err(Violation::Ceiling)
    );
    let snapshot = edge.snapshot.as_mut().ok_or("snapshot")?;
    assert!(snapshot.entries.is_empty(), "the entry was not admitted");
    snapshot.bytes = 0;
    assert_eq!(
        snapshot_entry(&mut edge, token, 0, object.object_id(), &object),
        Ok(())
    );
    let snapshot = edge.snapshot.as_ref().ok_or("snapshot")?;
    assert_eq!(snapshot.bytes, u64::try_from(bytes.len())?);
    assert!(snapshot.holds(&record.key()));
    Ok(())
}

#[tokio::test]
async fn a_settled_install_batch_is_the_last_one_of_a_stopping_edge() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![1; 256])?;
    let context = fixture.context_mut()?;
    let mut edge = edge();
    assert!(installed(&mut edge, context).is_empty());
    edge.snapshot = Some(SnapshotInstall {
        verified: true,
        staged_end: Some(1),
        ..installing(sessions(&[20, 21])?)
    });
    edge.stopping = true;
    assert!(installed(&mut edge, context).is_empty());
    assert!(
        edge.snapshot.is_none(),
        "the rest of the install is abandoned"
    );
    assert_eq!(edge.counters.snapshots_installed, 0);
    assert_eq!(context.pending_len(), 0);
    Ok(())
}

#[tokio::test]
async fn the_last_install_batch_sends_ready_and_resyncs_its_clients() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![1; 256])?;
    let context = fixture.context_mut()?;
    let mut edge = edge();
    let mut queue = link(&mut edge, HUB_EPOCH);
    edge.snapshot = Some(SnapshotInstall {
        verified: true,
        staged_end: Some(1),
        resync: vec![CONNECTION],
        ..installing(sessions(&[20])?)
    });
    let completions = installed(&mut edge, context);
    assert!(matches!(
        completions.as_slice(),
        [EdgeCompletion::Resync {
            generation: CONNECTION
        }]
    ));
    assert!(has_durable_ready(&edge));
    assert_eq!(pending_generation(&edge), Some(2));
    assert_eq!(edge.installed_incarnation, Some(HUB_INCARNATION));
    assert_eq!(edge.counters.snapshots_installed, 1);
    let expected = FederationFrame::SnapshotReady {
        coordinator_server_id: HUB,
        identity: identity(2),
    };
    assert_eq!(next_line(&mut queue).await?, rendered(&expected)?);
    Ok(())
}

#[tokio::test]
async fn active_is_refused_before_ready_for_another_cut_or_over_an_open_batch() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![1; 256])?;
    let context = fixture.context_mut()?;
    let mut edge = edge();
    assert_eq!(
        snapshot_active(&mut edge, context, identity(2)),
        Err(Violation::Phase)
    );
    edge.snapshot = Some(installing(Vec::new()));
    assert_eq!(
        snapshot_active(&mut edge, context, identity(2)),
        Err(Violation::Consistency)
    );
    edge.snapshot = Some(ready(Vec::new()));
    assert_eq!(
        snapshot_active(&mut edge, context, identity(3)),
        Err(Violation::Consistency)
    );
    edge.commit = Some(PendingCommit::SnapshotInstalled);
    assert_eq!(
        snapshot_active(&mut edge, context, identity(2)),
        Err(Violation::Ceiling)
    );
    assert_eq!(context.pending_len(), 0);
    edge.commit = None;
    assert_eq!(snapshot_active(&mut edge, context, identity(2)), Ok(()));
    assert!(matches!(
        edge.commit,
        Some(PendingCommit::SnapshotActivated { .. })
    ));
    assert_eq!(context.pending_len(), 1);
    Ok(())
}

#[tokio::test]
async fn an_activated_cut_the_replica_refuses_fails_the_link() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![1; 256])?;
    let context = fixture.context_mut()?;
    let mut edge = edge();
    assert!(activated(&mut edge, context, Vec::new()).is_empty());
    let mut queue = link(&mut edge, HUB_EPOCH);
    let mut unordered = sessions(&[20, 21])?;
    unordered.reverse();
    edge.snapshot = Some(ready(unordered));
    assert!(activated(&mut edge, context, Vec::new()).is_empty());
    assert_eq!(edge.counters.violations, 1);
    assert!(edge.live.is_none());
    assert_eq!(edge.phase, Phase::Down);
    assert_eq!(edge.installed_epoch, None);
    assert_eq!(edge.replica.entry_count(), 0);
    let closed = tokio::time::timeout(std::time::Duration::from_secs(5), queue.recv()).await?;
    assert!(closed.is_none());
    Ok(())
}

#[tokio::test]
async fn an_activation_that_outlives_its_link_waits_in_the_origin_phase() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![1; 256])?;
    let context = fixture.context_mut()?;
    let mut edge = edge();
    let cursor = Some((6, EventId::from_bytes([44; 16])));
    edge.snapshot = Some(SnapshotInstall {
        cursor,
        ..ready(sessions(&[20, 21])?)
    });
    assert!(activated(&mut edge, context, Vec::new()).is_empty());
    assert_eq!(edge.phase, Phase::Origins);
    assert_eq!(edge.replica.projection_generation(), 2);
    assert_eq!(edge.replica.entry_count(), 2);
    assert_eq!(edge.cursor, cursor);
    assert_eq!(edge.snapshot_cut, Some((2, 7)));
    assert_eq!(edge.installed_epoch, Some(HUB_EPOCH));
    assert!(edge.snapshot.is_none());
    Ok(())
}

#[test]
fn a_refused_install_batch_keeps_only_a_durably_ready_snapshot() {
    let mut edge = edge();
    rejected_install(&mut edge);
    assert!(edge.snapshot.is_none());
    edge.snapshot = Some(SnapshotInstall {
        staged_end: Some(0),
        ..installing(Vec::new())
    });
    rejected_install(&mut edge);
    assert!(edge.snapshot.is_none(), "an unmarked generation is dropped");
    edge.snapshot = Some(SnapshotInstall {
        staged_end: Some(0),
        ..ready(Vec::new())
    });
    rejected_install(&mut edge);
    assert!(has_durable_ready(&edge));
    assert_eq!(pending_generation(&edge), Some(2));
}

fn marker(entries: &[ProjectionRecord], generation: u64) -> TestResult<ProjectionMarkerRecord> {
    let mut ids = Vec::new();
    let mut bytes = 0_u64;
    for record in entries {
        let encoded = entry_object(record, generation)?;
        bytes = bytes.saturating_add(u64::try_from(encoded.len())?);
        ids.push(agenc_ircd_federation_wire::federation_object_id(&encoded));
    }
    Ok(ProjectionMarkerRecord {
        state: ProjectionGenerationState::Pending,
        state_generation: 7,
        entry_count: u64::try_from(entries.len())?,
        entry_bytes: bytes,
        digest: *snapshot_digest(&HUB_EPOCH, generation, 7, &ids)?.as_bytes(),
        snapshot_token: Some([9; 32]),
        cut_cursor: None,
        recovery_epoch: *HUB_EPOCH.as_bytes(),
    })
}

type Defect = fn(&mut ProjectionMarkerRecord, &mut Vec<ProjectionRecord>);

#[test]
fn a_restored_pending_generation_must_match_its_marker_exactly() -> TestResult {
    let defects: [Defect; 7] = [
        |marker, _| marker.snapshot_token = None,
        |marker, _| marker.state = ProjectionGenerationState::Active,
        |marker, _| marker.entry_count = 3,
        |_, entries| entries.reverse(),
        |marker, _| marker.digest = [0; 32],
        |marker, _| marker.entry_bytes += 1,
        |marker, _| marker.state_generation = 8,
    ];
    for defect in defects {
        let mut edge = edge();
        edge.installed_incarnation = Some(HUB_INCARNATION);
        let mut entries = sessions(&[20, 21])?;
        let mut marker = marker(&entries, 2)?;
        defect(&mut marker, &mut entries);
        let mut cause = EdgeRestoreCause::Unclassified;
        let refused = restore_pending(&mut edge, 2, marker, entries, &mut cause);
        assert!(matches!(
            refused,
            Err(crate::RuntimeError::Storage(
                agenc_ircd_storage::StorageError::StaleState
            ))
        ));
        assert_eq!(cause, EdgeRestoreCause::Unclassified);
        assert!(edge.snapshot.is_none());
    }
    Ok(())
}

#[test]
fn a_restored_pending_generation_names_a_ceiling_or_a_stale_generation() -> TestResult {
    let entries = sessions(&[20, 21])?;
    let mut edge = edge();
    edge.installed_incarnation = Some(HUB_INCARNATION);
    let mut cause = EdgeRestoreCause::Unclassified;
    let mut oversized = marker(&entries, 2)?;
    oversized.entry_count = MAX_SNAPSHOT_ENTRIES + 1;
    let mut many = EdgeRestoreCause::Unclassified;
    assert!(restore_pending(&mut edge, 2, oversized, Vec::new(), &mut many).is_err());
    assert_eq!(
        many,
        EdgeRestoreCause::Unclassified,
        "the count is checked first"
    );
    let stale = marker(&entries, 1)?;
    assert!(restore_pending(&mut edge, 1, stale, entries.clone(), &mut cause).is_err());
    assert_eq!(cause, EdgeRestoreCause::Unclassified);
    assert!(edge.snapshot.is_none());
    edge.installed_incarnation = None;
    let honest = marker(&entries, 2)?;
    assert!(restore_pending(&mut edge, 2, honest, entries.clone(), &mut cause).is_err());
    assert!(
        edge.snapshot.is_none(),
        "no coordinator incarnation was installed"
    );
    edge.installed_incarnation = Some(HUB_INCARNATION);
    let honest = marker(&entries, 2)?;
    restore_pending(&mut edge, 2, honest, entries, &mut cause)?;
    assert!(has_durable_ready(&edge));
    assert_eq!(pending_generation(&edge), Some(2));
    Ok(())
}

#[test]
fn a_restored_cut_over_the_entry_ceiling_is_an_admission_refusal() -> TestResult {
    let edge = edge();
    let mut oversized = marker(&[], 2)?;
    oversized.entry_count = MAX_SNAPSHOT_ENTRIES + 1;
    let mut cause = EdgeRestoreCause::Unclassified;
    let refused = verify_restored_cut(&edge, 2, (&oversized, &[]), &mut cause);
    assert!(matches!(refused, Err(crate::RuntimeError::LimitExceeded)));
    assert_eq!(cause, EdgeRestoreCause::PendingProjectionCeiling);
    Ok(())
}
