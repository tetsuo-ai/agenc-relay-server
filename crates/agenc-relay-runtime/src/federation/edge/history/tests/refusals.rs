//! History admission, page binding and authorization refuse without publishing or moving state.
#![forbid(unsafe_code)]

use super::*;
use agenc_relay_federation_wire::ResultHeader;
use agenc_relay_types::FederationResultKind;

const GENERATION: ConnectionGeneration = ConnectionGeneration::new(1);
const OBJECT: FederationHash32 = FederationHash32::from_bytes([14; 32]);

type PageEdit = fn(&mut HistoryPageMetadata, &mut Vec<HistoryMessageRecord>);
type EdgeEdit = fn(&mut StateCoreFixture, &mut EdgeFederation) -> TestResult;

/// Re-encodes the fixture page after one edit, keeping selection and messages consistent.
pub(super) fn rebuilt(page: &HistoryPage, edit: PageEdit) -> TestResult<HistoryPage> {
    let channel = ChannelNameValue::parse("#room")?;
    let mut messages = codec::messages_of(page, &channel)?;
    let mut metadata = HistoryPageMetadata {
        authorization: codec::authorization_of(page.authorization()?.as_object())?,
        channel_id: *CHANNEL.as_bytes(),
        channel_name: "#room".into(),
        snapshot_token: page.snapshot_token()?,
        state_cut: 30,
        page_sequence: 0,
        next_cursor: None,
        selected: Vec::new(),
        created_unix_milliseconds: 1_000_000,
        deadline_unix_milliseconds: 1_600_000,
    };
    edit(&mut metadata, &mut messages);
    metadata.selected = messages
        .iter()
        .map(|message| HistoryRowReference {
            channel_sequence: message.channel_sequence,
            message_id: *message.message_id.as_bytes(),
            received_unix_milliseconds: message.received_unix_milliseconds,
            expires_unix_milliseconds: message.expires_unix_milliseconds,
        })
        .collect();
    Ok(codec::page_object(&metadata, &messages)?)
}

/// The result header the coordinator would send for the fixture's pending request.
pub(super) fn result_header(
    edge: &EdgeFederation,
    kind: FederationResultKind,
) -> TestResult<ResultHeader> {
    let pending = edge.pending.get(&ID).ok_or("pending")?;
    Ok(ResultHeader {
        network_id: pending.header.network_id,
        replay_key: pending.header.replay_key,
        request_id: ID,
        request_object_id: federation_object_id(&pending.bytes),
        completion_event_id: None,
        result_kind: kind,
    })
}

fn receive_page(
    fixture: &mut StateCoreFixture,
    edge: &mut EdgeFederation,
    page: HistoryPage,
) -> TestResult<Result<Vec<EdgeCompletion>, Violation>> {
    let header = result_header(edge, FederationResultKind::HistoryPage)?;
    Ok(receive(
        edge,
        fixture.context_mut()?,
        header,
        OBJECT,
        ResultArm::HistoryPage(page),
    ))
}

/// The record of the history batch waiting on storage.
pub(super) fn staged(edge: &EdgeFederation) -> TestResult<&HistoryEdgeRequestRecord> {
    match edge.commit.as_ref() {
        Some(PendingCommit::History(prepared)) => Ok(&prepared.record),
        _ => Err("no staged history batch".into()),
    }
}

/// Commits the staged batch through storage and runs the edge's commit callback once.
pub(super) async fn apply(
    fixture: &mut StateCoreFixture,
    edge: &mut EdgeFederation,
) -> TestResult<Vec<EdgeCompletion>> {
    fixture.commit_staged_batch().await?;
    Ok(edge.batch_applied(fixture.context_mut()?))
}

fn assert_untouched(edge: &EdgeFederation, sink: &FrameSink) -> TestResult {
    assert!(edge.commit.is_none());
    assert!(sink.lines().is_empty());
    assert!(edge.pending.contains_key(&ID));
    let record = edge.history.records.get(&ID).ok_or("record")?;
    assert_eq!(record.phase, HistoryEdgePhase::Pending);
    assert_eq!(edge.phase, Phase::Active);
    Ok(())
}

#[tokio::test]
async fn a_page_bound_to_another_query_is_a_consistency_violation() -> TestResult {
    let page_edits: [PageEdit; 2] = [
        |metadata, _| metadata.channel_id = [99; 16],
        |metadata, _| metadata.page_sequence = 1,
    ];
    let edge_edits: [EdgeEdit; 3] = [
        |_, edge| {
            edge.history
                .batches
                .get_mut(&GENERATION)
                .ok_or("batch")?
                .token = Some([9; 32]);
            Ok(())
        },
        |_, edge| {
            let batch = edge.history.batches.get_mut(&GENERATION).ok_or("batch")?;
            batch.authorization = Some(HistoryAuthorizationBinding {
                session_id: [1; 16],
                user_id: [2; 16],
                session_generation: 1,
                account_id: None,
                account_session_generation: 0,
                membership_revision: 1,
                history_authorization_generation: 1,
            });
            Ok(())
        },
        |_, edge| {
            let record = edge.history.records.get_mut(&ID).ok_or("record")?;
            record.original_result_object_id = Some([1; 32]);
            Ok(())
        },
    ];
    for edit in page_edits {
        let (mut fixture, mut edge, sink, page) = fixture()?;
        let outcome = receive_page(&mut fixture, &mut edge, rebuilt(&page, edit)?)?;
        assert_eq!(outcome.err(), Some(Violation::Consistency));
        assert_untouched(&edge, &sink)?;
    }
    for edit in edge_edits {
        let (mut fixture, mut edge, sink, page) = fixture()?;
        edit(&mut fixture, &mut edge)?;
        let outcome = receive_page(&mut fixture, &mut edge, page)?;
        assert_eq!(outcome.err(), Some(Violation::Consistency));
        assert!(edge.commit.is_none());
        assert!(sink.lines().is_empty());
        assert!(edge.pending.contains_key(&ID));
    }
    Ok(())
}

#[tokio::test]
async fn a_result_outside_the_history_contract_is_refused_without_staging() -> TestResult {
    let (mut fixture, mut edge, sink, page) = fixture()?;
    let mut header = result_header(&edge, FederationResultKind::HistoryPage)?;
    header.completion_event_id = Some(agenc_relay_types::EventId::from_bytes([3; 16]));
    let arm = ResultArm::HistoryPage(rebuilt(&page, |_, _| {})?);
    let outcome = receive(&mut edge, fixture.context_mut()?, header, OBJECT, arm);
    assert_eq!(outcome.err(), Some(Violation::Consistency));
    assert_untouched(&edge, &sink)?;

    let header = result_header(&edge, FederationResultKind::HistoryPage)?;
    let outcome = receive(
        &mut edge,
        fixture.context_mut()?,
        header,
        OBJECT,
        ResultArm::NoContent,
    );
    assert_eq!(outcome.err(), Some(Violation::Consistency));
    assert_untouched(&edge, &sink)?;

    let mut unknown = header;
    unknown.request_id = RequestId::from_bytes([77; 16]);
    let outcome = receive(
        &mut edge,
        fixture.context_mut()?,
        unknown,
        OBJECT,
        ResultArm::NoContent,
    );
    assert_eq!(outcome.err(), Some(Violation::Consistency));
    assert_untouched(&edge, &sink)?;

    edge.commit = Some(PendingCommit::BarrierFence);
    let outcome = receive(
        &mut edge,
        fixture.context_mut()?,
        header,
        OBJECT,
        ResultArm::HistoryPage(page),
    );
    assert_eq!(outcome.err(), Some(Violation::Consistency));
    assert!(matches!(edge.commit, Some(PendingCommit::BarrierFence)));
    assert!(sink.lines().is_empty());
    Ok(())
}

fn reinstall(
    edge: &mut EdgeFederation,
    edit: fn(&mut ChannelDetailRecord, &mut MembershipRecord),
) -> TestResult {
    let mut entries: Vec<_> = edge.replica.entries().collect();
    let mut detail = None;
    let mut membership = None;
    for record in &entries {
        match record {
            ProjectionRecord::ChannelDetail(value) => detail = Some(value.clone()),
            ProjectionRecord::Membership(value) => membership = Some(*value),
            _ => {}
        }
    }
    let mut detail = detail.ok_or("detail")?;
    let mut membership = membership.ok_or("membership")?;
    edit(&mut detail, &mut membership);
    entries.retain(|record| matches!(record, ProjectionRecord::Session(_)));
    entries.push(ProjectionRecord::ChannelDetail(detail));
    entries.push(ProjectionRecord::Membership(membership));
    edge.replica.install(2, entries)?;
    Ok(())
}

fn revocations() -> [EdgeEdit; 8] {
    [
        |_, edge| {
            edge.phase = Phase::Down;
            Ok(())
        },
        |fixture, _| {
            fixture.context_mut()?.set_untrusted_wall_for_test(None);
            Ok(())
        },
        |fixture, _| {
            fixture.context_mut()?.set_wall_for_test(5_000);
            Ok(())
        },
        |_, edge| {
            edge.history
                .batches
                .get_mut(&GENERATION)
                .ok_or("batch")?
                .deadline = 5;
            Ok(())
        },
        |_, edge| bump_membership(edge),
        |_, edge| reinstall(edge, |detail, _| detail.visibility = Visibility::Secret),
        |_, edge| {
            reinstall(edge, |detail, _| {
                detail.persistence = PersistencePolicy::Ephemeral
            })
        },
        |_, edge| reinstall(edge, |detail, _| detail.history = HistoryPolicy::Off),
    ]
}

fn bump_membership(edge: &mut EdgeFederation) -> TestResult {
    reinstall(edge, |_, membership| {
        if let Ok(revision) = Revision::new(2) {
            membership.membership_revision = revision;
        }
    })
}

/// A lapsed page stages only its sink-loss receipt, then expires its own query.
async fn expires_quietly(
    fixture: &mut StateCoreFixture,
    edge: &mut EdgeFederation,
    sink: &FrameSink,
    page: HistoryPage,
) -> TestResult {
    let was_active = edge.phase == Phase::Active;
    let outcome = receive_page(fixture, edge, page)?;
    assert_eq!(outcome.err(), None);
    assert!(sink.lines().is_empty());
    assert!(staged(edge)?.sink_gone);
    assert_eq!(staged(edge)?.phase, HistoryEdgePhase::Received);
    apply(fixture, edge).await?;
    assert!(edge.commit.is_none());
    let lines = sink.lines();
    assert_eq!(lines.len(), 1);
    assert!(lines.first().ok_or("line")?.contains("QUERY_EXPIRED"));
    assert!(!edge.pending.contains_key(&ID));
    assert!(edge.history.batches.is_empty());
    assert!(edge.history.records.is_empty());
    assert_eq!(edge.phase == Phase::Active, was_active);
    Ok(())
}

#[tokio::test]
async fn a_page_whose_authorization_lapsed_expires_only_its_own_query() -> TestResult {
    for revoke in revocations() {
        let (mut fixture, mut edge, sink, page) = fixture()?;
        revoke(&mut fixture, &mut edge)?;
        expires_quietly(&mut fixture, &mut edge, &sink, page).await?;
    }
    Ok(())
}

#[tokio::test]
async fn a_page_authorized_for_an_account_the_session_lacks_expires() -> TestResult {
    let (mut fixture, mut edge, sink, page) = fixture()?;
    let page = rebuilt(&page, |metadata, _| {
        let text = agenc_relay_types::AccountRandomId::from_bytes([5; 16]).to_text();
        metadata.authorization.account_id = text.as_bytes().try_into().ok();
        metadata.authorization.account_session_generation = 1;
    })?;
    expires_quietly(&mut fixture, &mut edge, &sink, page).await
}

#[tokio::test]
async fn a_page_authorized_for_another_principal_is_a_consistency_violation() -> TestResult {
    let edits: [PageEdit; 2] = [
        |metadata, _| metadata.authorization.session_id = [88; 16],
        |metadata, _| metadata.authorization.user_id = [88; 16],
    ];
    for edit in edits {
        let (mut fixture, mut edge, sink, page) = fixture()?;
        let outcome = receive_page(&mut fixture, &mut edge, rebuilt(&page, edit)?)?;
        assert_eq!(outcome.err(), Some(Violation::Consistency));
        assert_untouched(&edge, &sink)?;
    }
    Ok(())
}
