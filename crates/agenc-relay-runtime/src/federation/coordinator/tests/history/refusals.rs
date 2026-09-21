//! History paging refuses a cursor presented outside its own selection and a
//! second open query of one origin; retention cleanup never stages over
//! pending work.
#![forbid(unsafe_code)]

use super::*;
use crate::bridge::{StorageReadCompletionMessage, StorageReadId};
use agenc_relay_domain::federation::{OperationKey, OriginKey, RetainedRequest};
use agenc_relay_storage::history_records::HISTORY_COORDINATOR_RESULT_KIND;
use agenc_relay_storage::{ReadRecord, ReadResult, StorageError, StoredKey};

const PEER: ServerId = ServerId::from_bytes([41; 16]);

fn latest(
    session_id: SessionId,
    channel_id: agenc_relay_types::ChannelInstanceId,
    limit: u16,
    cursor: Option<[u8; 32]>,
) -> TestResult<FederatedOperation> {
    Ok(FederatedOperation::HistoryQuery {
        session_id,
        channel_id,
        selector: crate::federation::codec::history::selector_object(HistorySelector::Latest(
            None,
        ))?,
        limit,
        cursor,
    })
}

/// A reader in `#history` with ten retained messages and the cursor that
/// follows its first page.
async fn paged_reader(
    edge: &mut Edge,
    origin: &mut Origin,
) -> TestResult<(SessionId, agenc_relay_types::ChannelInstanceId, [u8; 32])> {
    let (session, _, revision) = open_session(edge, origin, "reader", &mut Vec::new()).await?;
    let channel = join_channel(edge, origin, session, revision, "#history").await?;
    for number in 0..10 {
        let expected_revision = *edge
            .channel_revisions
            .get(&channel)
            .ok_or("channel revision")?;
        let message = FederatedOperation::Message {
            session_id: session,
            kind: MessageKind::Privmsg,
            targets: vec![MessageTargetArg::Channel {
                channel_id: channel,
                expected_revision,
            }],
            tags: Vec::new(),
            body: format!("original-{number}"),
        };
        complete(edge, origin, &message).await?;
    }
    let first = complete(edge, origin, &latest(session, channel, 100, None)?).await?;
    let ResultArm::HistoryPage(page) = &first.arm else {
        return Err("first page".into());
    };
    let cursor = page.next_cursor()?.ok_or("next cursor")?;
    Ok((session, channel, cursor))
}

fn failure_code(answer: &Answer) -> Option<&str> {
    match &answer.arm {
        ResultArm::Failed { code, .. } => Some(code.as_str()),
        _ => None,
    }
}

#[tokio::test]
async fn a_cursor_presented_with_another_query_expires_but_stays_usable() -> TestResult {
    run_history(|inbox| async move {
        let mut edge = Edge::new(inbox, 41);
        let mut origin = Origin::new(61);
        edge.establish().await?;
        synchronize_ok(&mut edge, &mut [&mut origin]).await?;
        let (session, channel, cursor) = paged_reader(&mut edge, &mut origin).await?;
        let other_limit = latest(session, channel, 99, Some(cursor))?;
        let refused = complete(&mut edge, &mut origin, &other_limit).await?;
        assert_eq!(failure_code(&refused), Some("QUERY_EXPIRED"));
        let unknown = latest(session, channel, 100, Some([9; 32]))?;
        let refused = complete(&mut edge, &mut origin, &unknown).await?;
        assert_eq!(failure_code(&refused), Some("QUERY_EXPIRED"));

        let second = latest(session, channel, 100, Some(cursor))?;
        let second = complete(&mut edge, &mut origin, &second).await?;
        let ResultArm::HistoryPage(page) = &second.arm else {
            return Err("the untouched cursor no longer pages".into());
        };
        assert_eq!(page.messages()?.len(), 3);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn an_origin_with_an_open_cursor_is_refused_a_second_fresh_query() -> TestResult {
    run_history(|inbox| async move {
        let mut edge = Edge::new(inbox, 41);
        let mut origin = Origin::new(61);
        edge.establish().await?;
        synchronize_ok(&mut edge, &mut [&mut origin]).await?;
        let (session, channel, _cursor) = paged_reader(&mut edge, &mut origin).await?;
        let again = complete(
            &mut edge,
            &mut origin,
            &latest(session, channel, 100, None)?,
        )
        .await?;
        assert_eq!(
            failure_code(&again),
            Some("SERVER_BUSY"),
            "a second open selection was admitted"
        );
        Ok(())
    })
    .await
}

struct Retaining {
    fixture: StateCoreFixture,
    coordinator: FederationCoordinator,
}

fn retaining() -> TestResult<Retaining> {
    let mut fixture = StateCoreFixture::with_federation_coordinator(
        entropy_script(),
        vec![peer_identity(PEER, "edge.example")],
    )?;
    fixture.context_mut()?.enable_history_for_test(true);
    Ok(Retaining {
        fixture,
        coordinator: standalone_coordinator(PEER),
    })
}

impl Retaining {
    /// Begins one retention pass and returns the page storage read for it.
    async fn page(&mut self) -> TestResult<StorageReadCompletionMessage> {
        self.coordinator.retain_history(self.fixture.context_mut()?);
        self.owned_read(std::time::Duration::from_secs(20))
            .await?
            .ok_or_else(|| "retention issued no read".into())
    }

    /// The next read retention owns; reads of the fixture's own router are
    /// skipped.
    async fn owned_read(
        &mut self,
        patience: std::time::Duration,
    ) -> TestResult<Option<StorageReadCompletionMessage>> {
        while let Ok(message) =
            tokio::time::timeout(patience, self.fixture.next_storage_read()).await
        {
            let message = message?;
            if self.coordinator.history.owns(message.read_id) {
                return Ok(Some(message));
            }
        }
        Ok(None)
    }

    fn complete(&mut self, message: StorageReadCompletionMessage) -> TestResult {
        let context = self.fixture.context_mut()?;
        history::read_completed(&mut self.coordinator, context, message);
        Ok(())
    }

    fn staged(&mut self) -> TestResult<bool> {
        Ok(self.coordinator.pending.is_some() || self.fixture.context_mut()?.pending_len() != 0)
    }
}

#[tokio::test]
async fn retention_does_not_begin_behind_a_pending_commit() -> TestResult {
    let mut retaining = retaining()?;
    retaining.coordinator.pending = Some(PendingCommit::SnapshotRows { peer: PEER });
    retaining
        .coordinator
        .retain_history(retaining.fixture.context_mut()?);
    let read = retaining
        .owned_read(std::time::Duration::from_millis(100))
        .await?;
    assert!(read.is_none(), "retention read behind a pending commit");
    retaining.coordinator.pending = None;
    assert!(
        retaining.page().await.is_ok(),
        "an idle coordinator retains"
    );
    Ok(())
}

#[tokio::test]
async fn an_empty_retention_page_frees_retention_without_staging() -> TestResult {
    let mut retaining = retaining()?;
    let page = retaining.page().await?;
    let read_id = page.read_id;
    retaining.complete(page)?;
    assert!(!retaining.coordinator.history.owns(read_id));
    assert!(!retaining.staged()?);
    // A completion nobody waits for is ignored.
    retaining.complete(StorageReadCompletionMessage {
        read_id: StorageReadId::new(u64::MAX),
        result: Err(StorageError::Unavailable),
    })?;
    assert!(!retaining.staged()?);
    Ok(())
}

#[tokio::test]
async fn a_retention_page_is_dropped_behind_pending_work_or_a_failed_read() -> TestResult {
    let mut behind_commit = retaining()?;
    let page = behind_commit.page().await?;
    behind_commit.coordinator.pending = Some(PendingCommit::SnapshotRows { peer: PEER });
    behind_commit.complete(page)?;
    assert!(matches!(
        behind_commit.coordinator.pending,
        Some(PendingCommit::SnapshotRows { .. })
    ));
    assert_eq!(behind_commit.fixture.context_mut()?.pending_len(), 0);

    let mut failed = retaining()?;
    let page = failed.page().await?;
    failed.complete(StorageReadCompletionMessage {
        read_id: page.read_id,
        result: Err(StorageError::Unavailable),
    })?;
    assert!(!failed.staged()?);
    assert!(!failed.coordinator.history.owns(page.read_id));
    Ok(())
}

#[tokio::test]
async fn a_retention_page_with_an_unreadable_row_stages_nothing() -> TestResult {
    let mut retaining = retaining()?;
    let page = retaining.page().await?;
    retaining.complete(StorageReadCompletionMessage {
        read_id: page.read_id,
        result: Ok(ReadResult {
            storage_commit_sequence: 1,
            records: vec![ReadRecord {
                table: TableId::RequestResult,
                key: StoredKey::new(vec![7; 64])?,
                sealed_record: vec![0xAB; 64],
            }],
            truncated: false,
        }),
    })?;
    assert!(!retaining.staged()?);
    Ok(())
}

fn key_bytes(key: &OperationKey) -> [u8; 64] {
    let mut bytes = [0_u8; 64];
    let parts: [&[u8]; 5] = [
        key.origin.home_server_id.as_bytes(),
        key.origin.server_incarnation.as_bytes(),
        key.origin.origin_id.as_bytes(),
        &key.generation.to_be_bytes(),
        &key.sequence.to_be_bytes(),
    ];
    let mut offset = 0;
    for part in parts {
        for byte in part {
            if let Some(slot) = bytes.get_mut(offset) {
                *slot = *byte;
            }
            offset += 1;
        }
    }
    bytes
}

#[test]
fn committed_cleanup_forgets_exactly_the_retained_requests_it_deleted() -> TestResult {
    let mut retaining = retaining()?;
    let key = |sequence| OperationKey {
        origin: OriginKey {
            home_server_id: PEER,
            server_incarnation: ServerIncarnation::from_bytes([42; 16]),
            origin_id: OriginId::from_bytes([43; 16]),
        },
        generation: 1,
        sequence,
    };
    for sequence in [1, 2] {
        retaining.coordinator.retained.insert(
            key(sequence),
            RetainedRequest {
                request_id: RequestId::from_bytes([u8::try_from(sequence)?; 16]),
                request_object_id: [5; 32],
            },
        );
    }
    let context = retaining.fixture.context_mut()?;
    let empty = ReadResult {
        storage_commit_sequence: 1,
        records: Vec::new(),
        truncated: false,
    };
    let mut cleanup = crate::federation::history_retention::Retention::default().prepare(
        context,
        &empty,
        1,
        HISTORY_COORDINATOR_RESULT_KIND,
        |_| true,
    )?;
    cleanup.deleted = vec![key_bytes(&key(1)), key_bytes(&key(9))];
    history::cleanup_committed(&mut retaining.coordinator, context, cleanup);
    assert!(!retaining.coordinator.retained.contains_key(&key(1)));
    assert!(retaining.coordinator.retained.contains_key(&key(2)));
    assert_eq!(retaining.coordinator.retained.len(), 1);
    Ok(())
}

/// Like `paged_reader`, also returning the session revision the join committed.
async fn paged_reader_with_join_revision(
    edge: &mut Edge,
    origin: &mut Origin,
) -> TestResult<(
    SessionId,
    agenc_relay_types::ChannelInstanceId,
    [u8; 32],
    u64,
)> {
    let (session, _, revision) = open_session(edge, origin, "reader", &mut Vec::new()).await?;
    let channel = join_channel(edge, origin, session, revision, "#history").await?;
    let joined_revision = *edge
        .channel_revisions
        .get(&channel)
        .ok_or("join revision")?;
    for number in 0..10 {
        let expected_revision = *edge
            .channel_revisions
            .get(&channel)
            .ok_or("channel revision")?;
        let message = FederatedOperation::Message {
            session_id: session,
            kind: MessageKind::Privmsg,
            targets: vec![MessageTargetArg::Channel {
                channel_id: channel,
                expected_revision,
            }],
            tags: Vec::new(),
            body: format!("original-{number}"),
        };
        complete(edge, origin, &message).await?;
    }
    let first = complete(edge, origin, &latest(session, channel, 100, None)?).await?;
    let ResultArm::HistoryPage(page) = &first.arm else {
        return Err("first page".into());
    };
    let cursor = page.next_cursor()?.ok_or("next cursor")?;
    Ok((session, channel, cursor, joined_revision))
}

#[tokio::test]
async fn a_cursor_binds_its_origin_channel_session_and_membership() -> TestResult {
    run_history(|inbox| async move {
        let mut edge = Edge::new(inbox, 41);
        let mut origin = Origin::new(61);
        let mut other = Origin::new(63);
        edge.establish().await?;
        synchronize_ok(&mut edge, &mut [&mut origin, &mut other]).await?;
        let (session, channel, cursor, joined_revision) =
            paged_reader_with_join_revision(&mut edge, &mut origin).await?;

        let (other_session, _, other_revision) =
            open_session(&mut edge, &mut other, "other", &mut Vec::new()).await?;
        let joined = complete(
            &mut edge,
            &mut other,
            &FederatedOperation::Join {
                session_id: other_session,
                expected_session_revision: other_revision,
                targets: vec![JoinTarget {
                    channel_name: "#history".to_owned(),
                    join_key: zeroize::Zeroizing::new(Vec::new()),
                }],
            },
        )
        .await?;
        assert_eq!(joined.header.result_kind, FederationResultKind::Committed);
        let elsewhere = complete(
            &mut edge,
            &mut other,
            &latest(other_session, channel, 100, Some(cursor))?,
        )
        .await?;
        assert_eq!(
            failure_code(&elsewhere),
            Some("QUERY_EXPIRED"),
            "another origin"
        );

        let wrong_channel = latest(
            session,
            agenc_relay_types::ChannelInstanceId::from_bytes([9; 16]),
            100,
            Some(cursor),
        )?;
        let refused = complete(&mut edge, &mut origin, &wrong_channel).await?;
        assert_eq!(
            failure_code(&refused),
            Some("QUERY_EXPIRED"),
            "another channel"
        );

        let (second_session, _, _) =
            open_session(&mut edge, &mut origin, "reader2", &mut Vec::new()).await?;
        let refused = complete(
            &mut edge,
            &mut origin,
            &latest(second_session, channel, 100, Some(cursor))?,
        )
        .await?;
        assert_eq!(
            failure_code(&refused),
            Some("QUERY_EXPIRED"),
            "another session"
        );

        let parted = complete(
            &mut edge,
            &mut origin,
            &FederatedOperation::Part {
                session_id: session,
                expected_session_revision: joined_revision,
                all_channels: false,
                channels: vec![channel],
                reason: "done".into(),
            },
        )
        .await?;
        assert_eq!(parted.header.result_kind, FederationResultKind::Committed);
        let refused = complete(
            &mut edge,
            &mut origin,
            &latest(session, channel, 100, Some(cursor))?,
        )
        .await?;
        assert_eq!(
            failure_code(&refused),
            Some("QUERY_EXPIRED"),
            "after parting"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_cursor_presented_by_a_later_session_of_the_same_origin_expires() -> TestResult {
    run_history(|inbox| async move {
        let mut edge = Edge::new(inbox, 41);
        let mut origin = Origin::new(61);
        edge.establish().await?;
        synchronize_ok(&mut edge, &mut [&mut origin]).await?;
        let (session, channel, cursor) = paged_reader(&mut edge, &mut origin).await?;
        complete(
            &mut edge,
            &mut origin,
            &FederatedOperation::SessionClose {
                session_id: session,
                reason_code: 2,
            },
        )
        .await?;
        let (later, _, _) = open_session(&mut edge, &mut origin, "reader", &mut Vec::new()).await?;
        assert_ne!(later, session, "the reopened session has its own identity");
        let refused = complete(
            &mut edge,
            &mut origin,
            &latest(later, channel, 100, Some(cursor))?,
        )
        .await?;
        assert_eq!(
            failure_code(&refused),
            Some("QUERY_EXPIRED"),
            "a cursor is bound to the session that selected it"
        );
        Ok(())
    })
    .await
}
