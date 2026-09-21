#![forbid(unsafe_code)]

//! A coordinator that breaks the snapshot exchange is refused frame by frame, and the honest
//! exchange still completes from the state the refusal left behind.

use agenc_relay_domain::federation::ProjectionRecord;
use agenc_relay_federation_wire::{
    DeliveryCursor, FederationHash32, ProjectionEntryHeader, SnapshotIdentity, snapshot_digest,
};

use super::*;

const GENERATION: u64 = 2;

/// Two sessions in strict key order, each as its canonical snapshot entry object.
fn entries(network: NetworkId, target: ServerId, generation: u64) -> TestResult<Vec<Vec<u8>>> {
    let mut records = Vec::new();
    for seed in [1_u8, 2] {
        records.push(ProjectionRecord::Session(session_record(
            SessionId::from_bytes([seed; 16]),
            UserId::from_bytes([seed; 16]),
            &format!("snap{seed}"),
            1,
            seed,
        )?));
    }
    records.sort_by_key(ProjectionRecord::key);
    records
        .iter()
        .map(|record| {
            let arm = crate::federation::codec::projection::projection_arm_object(record)?;
            let entry = ProjectionEntryHeader {
                network_id: network,
                target_server_id: target,
                projection_generation: generation,
                projection_kind: crate::federation::codec::projection::projection_kind(record),
            }
            .build(&arm)?;
            Ok(entry.encode_canonical()?.as_slice().to_vec())
        })
        .collect()
}

fn identity_of(objects: &[Vec<u8>]) -> TestResult<SnapshotIdentity> {
    let ids: Vec<_> = objects
        .iter()
        .map(|bytes| federation_object_id(bytes))
        .collect();
    Ok(SnapshotIdentity {
        snapshot_token: FederationHash32::from_bytes([86; 32]),
        recovery_epoch: COORDINATOR_EPOCH,
        projection_generation: GENERATION,
        state_generation: 10,
        snapshot_digest: snapshot_digest(&COORDINATOR_EPOCH, GENERATION, 10, &ids)?,
    })
}

struct Scene {
    fixture: StateCoreFixture,
    edge: EdgeFederation,
    objects: Vec<Vec<u8>>,
    identity: SnapshotIdentity,
    _queue: LinkQueue,
}

impl Scene {
    /// An edge in the snapshot phase on a live link, before BEGIN.
    fn new() -> TestResult<Self> {
        let fixture = StateCoreFixture::new(entropy_script())?;
        let mut edge = resync_edge();
        let queue = resync_snapshot_link(&mut edge);
        let objects = entries(NETWORK, EDGE, GENERATION)?;
        let identity = identity_of(&objects)?;
        Ok(Self {
            fixture,
            edge,
            objects,
            identity,
            _queue: queue,
        })
    }

    fn frame(&mut self, frame: FederationFrame) -> TestResult<Option<Violation>> {
        Ok(self
            .edge
            .handle_frame(self.fixture.context_mut()?, frame)
            .err())
    }

    fn begin(&mut self, identity: SnapshotIdentity, count: u64) -> TestResult<Option<Violation>> {
        self.frame(FederationFrame::SnapshotBegin {
            edge_server_id: EDGE,
            identity,
            entry_count: count,
        })
    }

    fn entry(
        &mut self,
        token: FederationHash32,
        index: u32,
        claimed: FederationHash32,
        bytes: &[u8],
    ) -> TestResult<Option<Violation>> {
        let object = resync_assembled(bytes, |fragment| FederationFrame::SnapshotEntry {
            edge_server_id: EDGE,
            snapshot_token: token,
            entry_index: index,
            object_id: claimed,
            fragment,
        })?;
        let carrier = ObjectCarrier::SnapshotEntry {
            edge_server_id: EDGE,
            snapshot_token: token,
            entry_index: index,
            object_id: claimed,
        };
        Ok(self
            .edge
            .handle_object(self.fixture.context_mut()?, carrier, object, None)
            .err())
    }

    fn honest_entry(&mut self, index: usize) -> TestResult<Option<Violation>> {
        let bytes = self.objects.get(index).ok_or("entry")?.clone();
        let token = self.identity.snapshot_token;
        self.entry(
            token,
            u32::try_from(index)?,
            federation_object_id(&bytes),
            &bytes,
        )
    }

    fn end(&mut self, token: FederationHash32) -> TestResult<Option<Violation>> {
        self.frame(FederationFrame::SnapshotEnd {
            edge_server_id: EDGE,
            snapshot_token: token,
            cursor: DeliveryCursor::Empty,
        })
    }

    /// The honest remainder of the exchange still verifies.
    fn finishes_from(&mut self, next_entry: usize) -> TestResult {
        for index in next_entry..self.objects.len() {
            assert_eq!(self.honest_entry(index)?, None);
        }
        assert_eq!(self.end(self.identity.snapshot_token)?, None);
        assert_eq!(self.edge.phase, Phase::Snapshot);
        Ok(())
    }
}

#[tokio::test]
async fn a_begin_the_link_does_not_authorize_allocates_nothing() -> TestResult {
    let forgeries: [fn(&mut SnapshotIdentity, &mut u64); 3] = [
        |identity, _| identity.recovery_epoch = RecoveryEpoch::from_bytes([1; 16]),
        |_, count| *count = u64::MAX,
        |identity, _| identity.projection_generation = 0,
    ];
    for forge in forgeries {
        let mut scene = Scene::new()?;
        let (mut identity, mut count) = (scene.identity, 2);
        forge(&mut identity, &mut count);
        assert_eq!(scene.begin(identity, count)?, Some(Violation::Consistency));
        assert!(scene.edge.snapshot.is_none());
        assert_eq!(scene.begin(scene.identity, 2)?, None);
        scene.finishes_from(0)?;
    }
    Ok(())
}

#[tokio::test]
async fn frames_outside_their_phase_are_refused_and_leave_the_phase_alone() -> TestResult {
    let mut scene = Scene::new()?;
    let out_of_phase = [
        FederationFrame::ResumeOk {
            edge_server_id: EDGE,
            projection_generation: 0,
            next_delivery_sequence: 0,
        },
        FederationFrame::ResumeSnapshot {
            edge_server_id: EDGE,
        },
    ];
    for frame in out_of_phase {
        assert_eq!(scene.frame(frame)?, Some(Violation::Phase));
        assert_eq!(scene.edge.phase, Phase::Snapshot);
    }
    let ready = FederationFrame::OriginReady {
        edge_server_id: EDGE,
        server_incarnation: EDGE_INCARNATION,
    };
    assert_eq!(scene.frame(ready)?, Some(Violation::Consistency));
    let active = FederationFrame::SnapshotActive {
        edge_server_id: EDGE,
        identity: scene.identity,
    };
    assert_eq!(scene.frame(active)?, Some(Violation::Phase));
    assert_eq!(scene.begin(scene.identity, 2)?, None);
    assert_eq!(scene.begin(scene.identity, 2)?, Some(Violation::Phase));
    let early = FederationFrame::SnapshotActive {
        edge_server_id: EDGE,
        identity: scene.identity,
    };
    assert_eq!(scene.frame(early)?, Some(Violation::Consistency));
    assert!(scene.edge.replica.projection_generation() < GENERATION);
    scene.finishes_from(0)
}

#[tokio::test]
async fn a_resume_answer_must_name_the_edges_own_generation_and_cursor() -> TestResult {
    for (ahead, next) in [(2, 0), (0, 5)] {
        let mut scene = Scene::new()?;
        scene.edge.phase = Phase::Resuming;
        let generation = scene.edge.replica.projection_generation() + ahead;
        let frame = FederationFrame::ResumeOk {
            edge_server_id: EDGE,
            projection_generation: generation,
            next_delivery_sequence: next,
        };
        assert_eq!(scene.frame(frame)?, Some(Violation::Consistency));
        assert_eq!(scene.edge.phase, Phase::Resuming);
        assert_eq!(scene.begin(scene.identity, 2)?, Some(Violation::Phase));
        assert!(scene.edge.snapshot.is_none());
        let wrong_incarnation = FederationFrame::OriginReady {
            edge_server_id: EDGE,
            server_incarnation: ServerIncarnation::from_bytes([1; 16]),
        };
        assert_eq!(
            scene.frame(wrong_incarnation)?,
            Some(Violation::Consistency)
        );
        assert!(!scene.edge.origin_ready);
    }
    Ok(())
}

#[tokio::test]
async fn an_entry_outside_the_announced_snapshot_is_refused_and_the_honest_one_still_fits()
-> TestResult {
    let mut scene = Scene::new()?;
    assert_eq!(scene.begin(scene.identity, 2)?, None);
    let first = scene.objects.first().ok_or("first")?.clone();
    let id = federation_object_id(&first);
    let token = scene.identity.snapshot_token;
    let other = FederationHash32::from_bytes([1; 32]);
    let refused = Some(Violation::Consistency);
    assert_eq!(scene.entry(other, 0, id, &first)?, refused);
    assert_eq!(scene.entry(token, 1, id, &first)?, refused);
    assert_eq!(scene.entry(token, 0, other, &first)?, refused);
    for (network, target, generation) in [
        (NetworkId::from_bytes([1; 32]), EDGE, GENERATION),
        (NETWORK, HUB, GENERATION),
        (NETWORK, EDGE, GENERATION + 1),
    ] {
        let forged = entries(network, target, generation)?;
        let bytes = forged.first().ok_or("forged")?;
        let claimed = federation_object_id(bytes);
        assert_eq!(scene.entry(token, 0, claimed, bytes)?, refused);
    }
    assert_eq!(scene.honest_entry(0)?, None);
    // The same key again is not strictly after the entry already held.
    assert_eq!(scene.entry(token, 1, id, &first)?, refused);
    assert_eq!(scene.end(token)?, refused);
    assert_eq!(scene.end(other)?, refused);
    assert_eq!(scene.honest_entry(1)?, None);
    let beyond = scene.objects.first().ok_or("first")?.clone();
    assert_eq!(scene.entry(token, 2, id, &beyond)?, refused);
    scene.finishes_from(2)
}

#[tokio::test]
async fn an_end_whose_digest_does_not_cover_the_entries_is_refused() -> TestResult {
    let mut scene = Scene::new()?;
    let mut identity = scene.identity;
    identity.snapshot_digest = FederationHash32::from_bytes([1; 32]);
    assert_eq!(scene.begin(identity, 2)?, None);
    assert_eq!(scene.honest_entry(0)?, None);
    assert_eq!(scene.honest_entry(1)?, None);
    assert_eq!(
        scene.end(identity.snapshot_token)?,
        Some(Violation::Consistency)
    );
    assert!(scene.edge.replica.projection_generation() < GENERATION);
    assert_eq!(scene.fixture.context_mut()?.pending_len(), 0);
    Ok(())
}
