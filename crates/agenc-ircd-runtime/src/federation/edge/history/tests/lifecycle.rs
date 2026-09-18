//! A history query's send, paging, failure and expiry steps each sit behind their own commit.
#![forbid(unsafe_code)]

use super::refusals::{apply, rebuilt, result_header, staged};
use super::*;
use agenc_ircd_types::FederationResultKind;

const GENERATION: ConnectionGeneration = ConnectionGeneration::new(1);
const OBJECT: FederationHash32 = FederationHash32::from_bytes([14; 32]);

pub(super) type Parts = (
    StateCoreFixture,
    EdgeFederation,
    Arc<FrameSink>,
    HistoryPage,
);
type EdgeEdit = fn(&mut StateCoreFixture, &mut EdgeFederation) -> TestResult;
/// One change to a successor page's metadata and messages.
type PageEdit = fn(&mut HistoryPageMetadata, &mut Vec<HistoryMessageRecord>);

/// The fixture with no query in flight, plus the client's original command.
fn idle() -> TestResult<(Parts, Box<ParsedMessage>)> {
    let (fixture, mut edge, sink, page) = fixture()?;
    let pending = edge.pending.remove(&ID).ok_or("pending")?;
    let PendingKind::Command { message } = pending.kind else {
        return Err("command".into());
    };
    edge.history.records.clear();
    edge.history.batches.clear();
    Ok(((fixture, edge, sink, page), message))
}

fn query(edge: &EdgeFederation, limit: u16) -> TestResult<FederatedOperation> {
    let origin = edge.origins.get(&GENERATION).ok_or("origin")?;
    Ok(FederatedOperation::HistoryQuery {
        session_id: origin.session.ok_or("session")?.0,
        channel_id: CHANNEL,
        selector: codec::selector_object(agenc_ircd_domain::HistorySelector::Latest(None))?,
        limit,
        cursor: None,
    })
}

fn sequence(edge: &EdgeFederation) -> TestResult<u64> {
    Ok(edge.origins.get(&GENERATION).ok_or("origin")?.sequence)
}

fn spare_batch(edge: &EdgeFederation) -> TestResult<Batch> {
    let _ = edge;
    Ok(Batch {
        channel: CHANNEL,
        query: HistoryQuery::new(agenc_ircd_domain::HistorySelector::Latest(None), 7)?,
        id: "other".into(),
        token: None,
        authorization: None,
        page: 0,
        count: 0,
        last_sequence: 0,
        deadline: 600_000,
    })
}

fn busy_cases() -> [EdgeEdit; 5] {
    [
        |_, edge| {
            let batch = spare_batch(edge)?;
            edge.history.batches.insert(GENERATION, batch);
            Ok(())
        },
        |_, edge| {
            for other in 0..MAX_ACTIVE {
                let batch = spare_batch(edge)?;
                let generation = ConnectionGeneration::new(u64::try_from(other)? + 100);
                edge.history.batches.insert(generation, batch);
            }
            Ok(())
        },
        |_, edge| {
            edge.commit = Some(PendingCommit::BarrierFence);
            Ok(())
        },
        |_, edge| {
            let origin = edge.origins.get_mut(&GENERATION).ok_or("origin")?;
            origin
                .pending_updates
                .push_back(agenc_ircd_federation_wire::OriginRecord {
                    network_id: NetworkId::from_bytes([1; 32]),
                    home_server_id: ServerId::from_bytes([2; 16]),
                    server_incarnation: ServerIncarnation::from_bytes([6; 16]),
                    origin_id: origin.origin_id,
                    generation: 1,
                    previous_origin_object_id: [0; 32],
                    connection_id: origin.connection_id,
                    session: None,
                    account: None,
                    connection_nonce: [7; 32],
                });
            Ok(())
        },
        |fixture, _| {
            fixture.context_mut()?.set_untrusted_wall_for_test(None);
            Ok(())
        },
    ]
}

#[tokio::test]
async fn a_query_the_edge_cannot_admit_is_busy_and_consumes_no_sequence() -> TestResult {
    for case in busy_cases() {
        let ((mut fixture, mut edge, sink, _), message) = idle()?;
        case(&mut fixture, &mut edge)?;
        let before = (sequence(&edge)?, edge.history.batches.len());
        let operation = query(&edge, 7)?;
        let outcome = begin(
            &mut edge,
            fixture.context_mut()?,
            GENERATION,
            message,
            operation,
        );
        assert_eq!(
            outcome.err().map(|(_, error)| error),
            Some(DomainError::ServerBusy)
        );
        assert_eq!((sequence(&edge)?, edge.history.batches.len()), before);
        assert!(edge.pending.is_empty());
        assert!(edge.history.records.is_empty());
        assert!(!matches!(edge.commit, Some(PendingCommit::History(_))));
        assert!(sink.lines().is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn a_malformed_history_operation_is_an_invalid_argument() -> TestResult {
    let ((_, edge, _, _), _) = idle()?;
    let session_id = edge
        .origins
        .get(&GENERATION)
        .ok_or("origin")?
        .session
        .ok_or("session")?
        .0;
    let operations = [
        FederatedOperation::SessionClose {
            session_id,
            reason_code: 1,
        },
        query(&edge, 0)?,
    ];
    for operation in operations {
        let ((mut fixture, mut edge, sink, _), message) = idle()?;
        let before = sequence(&edge)?;
        let outcome = begin(
            &mut edge,
            fixture.context_mut()?,
            GENERATION,
            message,
            operation,
        );
        assert_eq!(
            outcome.err().map(|(_, error)| error),
            Some(DomainError::InvalidArgument)
        );
        assert_eq!(sequence(&edge)?, before);
        assert!(edge.history.batches.is_empty());
        assert!(edge.commit.is_none());
        assert!(sink.lines().is_empty());
    }
    Ok(())
}

pub(super) fn begun() -> TestResult<(Parts, u64)> {
    let ((mut fixture, mut edge, sink, page), message) = idle()?;
    let before = sequence(&edge)?;
    let operation = query(&edge, 7)?;
    begin(
        &mut edge,
        fixture.context_mut()?,
        GENERATION,
        message,
        operation,
    )
    .map_err(|(_, error)| format!("begin: {error:?}"))?;
    assert_eq!(sequence(&edge)?, before + 1);
    assert!(edge.pending.is_empty());
    assert_eq!(edge.history.batches.len(), 1);
    Ok(((fixture, edge, sink, page), before))
}

#[tokio::test]
async fn a_committed_send_registers_the_request_only_while_its_client_remains() -> TestResult {
    for closed in [false, true] {
        let ((mut fixture, mut edge, sink, _), before) = begun()?;
        connection_closed(&mut edge, ConnectionGeneration::new(9));
        assert_eq!(sequence(&edge)?, before + 1);
        assert_eq!(edge.history.batches.len(), 1);
        if closed {
            connection_closed(&mut edge, GENERATION);
            assert_eq!(sequence(&edge)?, before);
            assert!(edge.history.batches.is_empty());
        }
        assert_eq!(staged(&edge)?.sink_gone, closed);
        apply(&mut fixture, &mut edge).await?;
        assert_eq!(edge.pending.len(), usize::from(!closed));
        assert_eq!(edge.history.records.len(), usize::from(!closed));
        assert!(sink.lines().is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn a_rejected_send_returns_its_sequence_and_fails_the_link() -> TestResult {
    let ((mut fixture, mut edge, sink, _), before) = begun()?;
    let violations = edge.counters.violations;
    fixture.context_mut()?.discard_pending_for_test();
    edge.batch_rejected(fixture.context_mut()?);
    assert_eq!(sequence(&edge)?, before);
    assert!(edge.history.batches.is_empty());
    assert!(edge.pending.is_empty());
    assert_eq!(edge.counters.violations, violations + 1);
    assert!(sink.lines().is_empty());
    Ok(())
}

/// Drives one received page through both of its durable commits.
async fn deliver(
    fixture: &mut StateCoreFixture,
    edge: &mut EdgeFederation,
    page: HistoryPage,
) -> TestResult {
    let header = result_header(edge, FederationResultKind::HistoryPage)?;
    receive(
        edge,
        fixture.context_mut()?,
        header,
        OBJECT,
        ResultArm::HistoryPage(page),
    )
    .map_err(|error| format!("receive: {error:?}"))?;
    assert_eq!(staged(edge)?.phase, HistoryEdgePhase::Received);
    apply(fixture, edge).await?;
    assert_eq!(staged(edge)?.phase, HistoryEdgePhase::Rendered);
    apply(fixture, edge).await?;
    Ok(())
}

/// Delivers a first page that names a successor and registers the successor request.
async fn paged() -> TestResult<(Parts, RequestId)> {
    let (mut fixture, mut edge, sink, page) = fixture()?;
    let before = sequence(&edge)?;
    let first = rebuilt(&page, |metadata, _| metadata.next_cursor = Some([21; 32]))?;
    deliver(&mut fixture, &mut edge, first).await?;
    assert_eq!(sink.lines().len(), 2);
    assert!(!edge.pending.contains_key(&ID));
    assert_eq!(sequence(&edge)?, before + 1);
    assert_eq!(staged(&edge)?.phase, HistoryEdgePhase::Pending);
    apply(&mut fixture, &mut edge).await?;
    let next = *edge.pending.keys().next().ok_or("successor request")?;
    let batch = edge.history.batches.get(&GENERATION).ok_or("batch")?;
    assert_eq!((batch.page, batch.count, batch.last_sequence), (1, 1, 20));
    Ok(((fixture, edge, sink, page), next))
}

pub(super) fn successor_header(edge: &EdgeFederation, id: RequestId) -> TestResult<ResultHeader> {
    let pending = edge.pending.get(&id).ok_or("pending")?;
    Ok(ResultHeader {
        network_id: pending.header.network_id,
        replay_key: pending.header.replay_key,
        request_id: id,
        request_object_id: federation_object_id(&pending.bytes),
        completion_event_id: None,
        result_kind: FederationResultKind::HistoryPage,
    })
}

#[tokio::test]
async fn a_successor_page_must_advance_the_batch_it_continues() -> TestResult {
    let edits: [(PageEdit, bool); 3] = [
        (|metadata, _| metadata.page_sequence = 1, false),
        (
            |metadata, messages| {
                metadata.page_sequence = 1;
                for message in messages {
                    message.channel_sequence = 21;
                }
            },
            true,
        ),
        (
            |metadata, messages| {
                metadata.page_sequence = 1;
                metadata.snapshot_token = [66; 32];
                for message in messages {
                    message.channel_sequence = 21;
                }
            },
            false,
        ),
    ];
    for (edit, accepted) in edits {
        let ((mut fixture, mut edge, sink, page), next) = paged().await?;
        let header = successor_header(&edge, next)?;
        let arm = ResultArm::HistoryPage(rebuilt(&page, edit)?);
        let outcome = receive(&mut edge, fixture.context_mut()?, header, OBJECT, arm);
        assert_eq!(outcome.is_ok(), accepted);
        assert_eq!(edge.commit.is_some(), accepted);
        assert_eq!(sink.lines().len(), 2);
        assert!(edge.pending.contains_key(&next));
    }
    Ok(())
}

#[tokio::test]
async fn a_successor_page_beyond_the_query_limit_is_refused() -> TestResult {
    let ((mut fixture, mut edge, sink, page), next) = paged().await?;
    edge.history
        .batches
        .get_mut(&GENERATION)
        .ok_or("batch")?
        .count = 7;
    let header = successor_header(&edge, next)?;
    let arm = ResultArm::HistoryPage(rebuilt(&page, |metadata, messages| {
        metadata.page_sequence = 1;
        for message in messages {
            message.channel_sequence = 21;
        }
    })?);
    let outcome = receive(&mut edge, fixture.context_mut()?, header, OBJECT, arm);
    assert_eq!(outcome.err(), Some(Violation::Consistency));
    assert!(edge.commit.is_none());
    assert_eq!(sink.lines().len(), 2);
    Ok(())
}

#[tokio::test]
async fn an_expiry_naming_another_original_result_is_refused() -> TestResult {
    let (mut fixture, mut edge, sink, _) = fixture()?;
    let record = edge.history.records.get_mut(&ID).ok_or("record")?;
    record.original_result_object_id = Some([14; 32]);
    let header = result_header(&edge, FederationResultKind::HistoryExpired)?;
    let arm = ResultArm::HistoryExpired {
        original_result_object_id: [15; 32],
    };
    let outcome = receive(&mut edge, fixture.context_mut()?, header, OBJECT, arm);
    assert_eq!(outcome.err(), Some(Violation::Consistency));
    assert!(edge.commit.is_none());
    assert!(edge.pending.contains_key(&ID));
    assert!(sink.lines().is_empty());
    Ok(())
}

#[tokio::test]
async fn a_render_commit_the_core_refuses_fails_the_link_without_output() -> TestResult {
    let (mut fixture, mut edge, sink, page) = fixture()?;
    let header = result_header(&edge, FederationResultKind::HistoryPage)?;
    let arm = ResultArm::HistoryPage(page);
    receive(&mut edge, fixture.context_mut()?, header, OBJECT, arm)
        .map_err(|error| format!("receive: {error:?}"))?;
    fixture.commit_staged_batch().await?;
    fixture.context_mut()?.quiesce_for_test();
    let violations = edge.counters.violations;
    edge.batch_applied(fixture.context_mut()?);
    assert!(edge.commit.is_none());
    assert_eq!(edge.counters.violations, violations + 1);
    assert!(sink.lines().is_empty());
    Ok(())
}
