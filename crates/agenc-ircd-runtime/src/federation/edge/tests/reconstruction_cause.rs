#![forbid(unsafe_code)]

//! RUN-08: a refused edge restore must carry out the cause it was given.
//!
//! Two arms of the restore mapped an owner's own refusal to
//! `StorageError::StaleState` and threw the cause away, which is what sent
//! #124 to the storage layer. These cases pin the operator-visible line for a
//! refusal the edge replica raised, for an incomplete companion snapshot
//! generation, and for the restore's own admission ceilings, which must not
//! read as stale durable state.

use super::*;

use agenc_ircd_domain::Role;
use agenc_ircd_domain::federation::{
    MembershipRecord, ProjectionRecord, ReplicaError, SessionRecord,
};
use agenc_ircd_federation_wire::CanonicalEncode;
use agenc_ircd_storage::federation_records::{
    FederationPeerRecord, PEER_RECORD_KIND, PROJECTION_ENTRY_KIND, PeerPhase,
    ProjectionEntryRecord, peer_key, projection_entry_key,
};
use agenc_ircd_storage::{InitialStorageRecord, PersistentRecordValue, StorageError, TableId};

use crate::federation::edge::{EdgeRestoreCause, EdgeRestoreStep};

/// The coordinator row of an edge holding one standing entry at `generation`.
fn peer_row(generation: u64, entries: u64) -> TestResult<InitialStorageRecord> {
    let record = FederationPeerRecord {
        fenced_incarnations: Vec::new(),
        server_incarnation: *HUB_INCARNATION.as_bytes(),
        recovery_epoch: *COORDINATOR_EPOCH.as_bytes(),
        accepted_epochs: Vec::new(),
        phase: PeerPhase::Suspended,
        projection_generation: generation,
        next_delivery_sequence: 0,
        cursor: None,
        active_entry_count: entries,
        active_entry_bytes: 0,
        pending_generation: None,
        snapshot_required: false,
        cleanup_cursor: None,
        quarantined: false,
        client_resync_epoch: 0,
    };
    durable_row(
        TableId::FederationPeer,
        peer_key(COORDINATOR)?,
        (PEER_RECORD_KIND, 0),
        record.encode()?,
    )
}

/// One durable `EdgeProjection` entry row under its own semantic key.
fn projection_row(generation: u64, record: &ProjectionRecord) -> TestResult<InitialStorageRecord> {
    let arm = crate::federation::codec::projection::projection_arm_object(record)
        .map_err(|error| format!("arm: {error:?}"))?;
    let entry = agenc_ircd_federation_wire::ProjectionEntryHeader {
        network_id: NETWORK,
        target_server_id: EDGE,
        projection_generation: generation,
        projection_kind: crate::federation::codec::projection::projection_kind(record),
    }
    .build(&arm)
    .map_err(|error| format!("entry: {error:?}"))?
    .encode_canonical()
    .map_err(|error| format!("encode: {error:?}"))?;
    let bytes = entry.as_slice().to_vec();
    let row = ProjectionEntryRecord {
        entry_object_id: *agenc_ircd_federation_wire::federation_object_id(&bytes).as_bytes(),
        entry_object: bytes,
    };
    let semantic = record.key();
    durable_row(
        TableId::EdgeProjection,
        projection_entry_key(EDGE, generation, semantic.kind(), semantic.primary())?,
        (PROJECTION_ENTRY_KIND, generation),
        row.encode()?,
    )
}

/// Wraps one encoded record body as a seeded initial storage row.
fn durable_row(
    table: TableId,
    key: agenc_ircd_storage::StoredKey,
    record: (u16, u64),
    body: Vec<u8>,
) -> TestResult<InitialStorageRecord> {
    let (kind, generation) = record;
    let value =
        PersistentRecordValue::new(table, kind, 1, generation, None, Vec::new(), body)?.encode()?;
    Ok(InitialStorageRecord::new(table, key, 1, value)?)
}

/// A membership whose channel and member were never projected. The replica
/// refuses it as a dangling reference, which the restore used to report as
/// stale storage state.
fn dangling_membership() -> TestResult<ProjectionRecord> {
    Ok(ProjectionRecord::Membership(MembershipRecord {
        channel_id: ChannelInstanceId::from_bytes([91; 16]),
        user_id: UserId::from_bytes([92; 16]),
        role: Role::Member,
        membership_revision: Revision::new(4)?,
        joined_at: agenc_ircd_types::UtcSecond::new(1_700_000_000)?,
    }))
}

#[tokio::test]
async fn a_projection_the_replica_refuses_names_the_replica_and_not_the_storage_layer() -> TestResult
{
    let mut records = peer_row(1, 1).map(|row| vec![row])?;
    records.push(projection_row(1, &dangling_membership()?)?);
    let fixture =
        StateCoreFixture::with_registration_router_and_records(entropy_script(), records)?;
    let mut edge = resync_edge();
    let refusal = fixture
        .restore_edge_refusal(&mut edge, None)?
        .err()
        .ok_or("the restore installed a projection the replica cannot hold")?;
    assert_eq!(refusal.step, EdgeRestoreStep::ProjectionInstall);
    assert_eq!(
        refusal.cause,
        EdgeRestoreCause::ActiveProjection(ReplicaError::DanglingReference),
        "the replica's own refusal must survive the restore's error mapping"
    );
    assert_eq!(
        refusal.error,
        RuntimeError::Storage(StorageError::StaleState)
    );
    assert_eq!(
        crate::daemon::DaemonError::from(refusal).to_string(),
        "runtime startup failed: edge federation restore at edge-projection-install (active \
         projection: federation replica reference does not resolve) refused the recovered state: \
         storage owner failed: storage state is stale or inconsistent",
    );
    Ok(())
}

#[tokio::test]
async fn an_unnamed_refusal_still_prints_the_line_the_step_label_alone_produced() -> TestResult {
    let fixture = StateCoreFixture::with_registration_router_and_records(
        entropy_script(),
        vec![peer_row(1, 7)?],
    )?;
    let mut edge = resync_edge();
    let refusal = fixture
        .restore_edge_refusal(&mut edge, None)?
        .err()
        .ok_or("the restore accepted a count no durable row supports")?;
    assert_eq!(refusal.cause, EdgeRestoreCause::Unclassified);
    assert_eq!(
        crate::daemon::DaemonError::from(refusal).to_string(),
        "runtime startup failed: edge federation restore at edge-projection-install refused the \
         recovered state: storage owner failed: storage state is stale or inconsistent",
    );
    Ok(())
}

/// RUN-08 (issue #134): a kill between the two events that bracket a channel
/// must not brick the edge.
///
/// This is the state three reproduced production refusals carried, byte for
/// byte in shape: the coordinator row's `active_entry_count` matches the
/// durable rows exactly, every membership resolves, and exactly one channel
/// detail has no local member because `ChannelVisible` arrives before the
/// `MemberJoined` that entitles the edge to it and `SessionHidden` removes
/// the last membership while only the coordinator's later `ChannelHidden`
/// removes the channel. Each of those is its own durable batch, so a running
/// edge holds this state between two of them. The restore used to rebuild it
/// through the snapshot's closed install and refuse the whole startup with
/// `edge federation restore at edge-projection-install (active projection:
/// federation replica reference does not resolve)`.
#[tokio::test]
async fn a_channel_awaiting_its_bracketing_event_restores_instead_of_refusing() -> TestResult {
    let (records, entries) = bracketed_channel_rows()?;
    let fixture =
        StateCoreFixture::with_registration_router_and_records(entropy_script(), records)?;
    let mut edge = resync_edge();
    fixture.restore_edge_state(&mut edge, None)?;
    assert_eq!(
        edge.replica.entry_count(),
        entries,
        "the restore must rebuild every durable row it was given"
    );
    Ok(())
}

/// The same rows plus a membership whose channel was never projected still
/// refuse, so the relaxation is exactly one invariant wide.
#[tokio::test]
async fn a_dangling_membership_beside_the_same_rows_still_refuses() -> TestResult {
    let (rows, entries) = bracketed_channel_rows()?;
    // Re-declare the coordinator row for the larger set, then seed the rest.
    let mut records = vec![peer_row(1, u64::try_from(entries)?.saturating_add(1))?];
    records.extend(rows.into_iter().skip(1));
    records.push(projection_row(1, &dangling_membership()?)?);
    let fixture =
        StateCoreFixture::with_registration_router_and_records(entropy_script(), records)?;
    let mut edge = resync_edge();
    let refusal = fixture
        .restore_edge_refusal(&mut edge, None)?
        .err()
        .ok_or("the restore installed a membership whose channel is absent")?;
    assert_eq!(refusal.step, EdgeRestoreStep::ProjectionInstall);
    assert_eq!(
        refusal.cause,
        EdgeRestoreCause::ActiveProjection(ReplicaError::DanglingReference)
    );
    Ok(())
}

/// One local session in one channel, beside a second channel detail that no
/// membership names. Returns the seeded rows and the entry-row count the
/// coordinator row declares.
fn bracketed_channel_rows() -> TestResult<(Vec<InitialStorageRecord>, usize)> {
    let session = SessionRecord {
        session_id: SessionId::from_bytes([41; 16]),
        user_id: UserId::from_bytes([42; 16]),
        home_server_id: EDGE,
        session_revision: Revision::new(1)?,
        account: None,
        nickname: NicknameValue::parse("member")?,
        display_name: DisplayNameValue::prepare("Member")?,
        public_cloak: agenc_ircd_testkit::deterministic_cloak(43)?,
        account_label: None,
        user_mode_bits: 1,
        away: None,
    };
    let joined = ChannelInstanceId::from_bytes([44; 16]);
    let bracketed = ChannelInstanceId::from_bytes([45; 16]);
    let entries = vec![
        ProjectionRecord::Session(session.clone()),
        ProjectionRecord::ChannelDetail(channel_detail(joined, "#joined")?),
        // Visible, with no local member and no invite: the window between
        // `ChannelVisible` and `MemberJoined`, and the window `SessionHidden`
        // leaves behind until `ChannelHidden` arrives.
        ProjectionRecord::ChannelDetail(channel_detail(bracketed, "#bracketed")?),
        ProjectionRecord::Membership(MembershipRecord {
            channel_id: joined,
            user_id: session.user_id,
            role: Role::Member,
            membership_revision: Revision::new(1)?,
            joined_at: agenc_ircd_types::UtcSecond::new(1_700_000_000)?,
        }),
    ];
    let count = entries.len();
    let mut records = vec![peer_row(1, u64::try_from(count)?)?];
    for entry in &entries {
        records.push(projection_row(1, entry)?);
    }
    Ok((records, count))
}

/// A listed plaintext channel detail at revision one.
fn channel_detail(
    channel_id: ChannelInstanceId,
    name: &str,
) -> TestResult<agenc_ircd_domain::federation::ChannelDetailRecord> {
    Ok(agenc_ircd_domain::federation::ChannelDetailRecord {
        channel_id,
        name: agenc_ircd_domain::ChannelNameValue::parse(name)?,
        channel_revision: Revision::new(1)?,
        visibility: agenc_ircd_domain::Visibility::Listed,
        content_policy: agenc_ircd_domain::ContentPolicy::Plaintext,
        persistence: agenc_ircd_domain::PersistencePolicy::Ephemeral,
        simple_mode_bits: 4,
        history: agenc_ircd_domain::HistoryPolicy::Off,
        e2ee_route_binding: None,
    })
}
