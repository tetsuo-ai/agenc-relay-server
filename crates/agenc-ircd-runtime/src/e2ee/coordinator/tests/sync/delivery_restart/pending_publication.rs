//! Cut publication is advanced only by actual StorageOwner receipts.
#![forbid(unsafe_code)]

mod retention;

use super::*;
use agenc_ircd_storage::e2ee_records::delivery_recovery::{CutPhase, DeliveryRecoveryRow};

impl RestartFixture {
    pub(super) async fn publish_cut(
        &mut self,
        mut actions: Vec<Action>,
    ) -> TestResult<Vec<CompanionFrame>> {
        for _ in 0..agenc_ircd_storage::e2ee_records::delivery_recovery::MAX_SNAPSHOT_PAGES + 2 {
            if !matches!(
                actions.as_slice(),
                [Action::Stage {
                    work: PendingWork::Snapshot(_),
                    ..
                }]
            ) {
                return frames(&actions);
            }
            actions = self.commit_cut_stage(actions).await?;
        }
        Err("cut exceeded its fixed page bound".into())
    }

    async fn commit_cut_stage(&mut self, actions: Vec<Action>) -> TestResult<Vec<Action>> {
        let Some(Action::Stage { writes, work }) = actions.into_iter().next() else {
            return Err("expected one exact cut stage".into());
        };
        self.coordinator.set_pending(work);
        self.commit(writes).await?;
        let Some(Committed::Snapshot(publication)) = self
            .coordinator
            .batch_applied(Some(self.host.resync_epoch))?
        else {
            return Err("expected the matching cut receipt".into());
        };
        Ok(self
            .coordinator
            .continue_snapshot_publication(*publication, NOW_MILLIS, &self.host)?)
    }
}

async fn unstarted() -> TestResult<RestartFixture> {
    let storage = StateCoreFixture::new(vec![44; 65_536])?;
    let mut coordinator = CompanionCoordinator::new(
        *storage.identity.network_id.as_bytes(),
        storage.identity.server_id,
        SERVER_NAME.into(),
    );
    coordinator.configure_delivery_identity(
        storage.identity.server_incarnation,
        storage.identity.recovery_epoch,
    )?;
    Ok(RestartFixture {
        storage,
        coordinator,
        host: FakeHost::default(),
        entropy: Counter(60),
        keys: Vec::new(),
        copies: Vec::new(),
    })
}

fn initial_frame(fixture: &mut RestartFixture) -> TestResult<Vec<Action>> {
    fixture.frame(CompanionFrame::Resume {
        coordinator_server_id: *fixture.storage.identity.server_id.as_bytes(),
        server_incarnation: INCARNATION,
        delivery_generation: 0,
        last: None,
    })
}

fn row_in(actions: &[Action]) -> TestResult<DeliveryRecoveryRow> {
    let [
        Action::Stage {
            writes,
            work: PendingWork::Snapshot(_),
        },
    ] = actions
    else {
        return Err("BEGIN escaped before the immutable cut was durable".into());
    };
    let [
        AccountServiceDurableWrite::Put {
            table,
            plaintext,
            key,
            ..
        },
    ] = writes.as_slice()
    else {
        return Err("each cut step must put exactly one bounded row".into());
    };
    let value = PersistentRecordValue::decode(*table, plaintext)?;
    Ok(DeliveryRecoveryRow::decode_at(key, value.body())?)
}

#[tokio::test]
async fn even_an_empty_cut_waits_for_its_page_and_owner_receipts_before_begin() -> TestResult {
    let mut fixture = unstarted().await?;
    let actions = initial_frame(&mut fixture)?;
    assert!(
        matches!(row_in(&actions)?, DeliveryRecoveryRow::CutPage(page) if page.entries().is_empty() && page.next_cursor().is_none())
    );
    assert!(fixture.coordinator.state.streams.is_empty());
    let actions = fixture.commit_cut_stage(actions).await?;
    let DeliveryRecoveryRow::Owner(owner) = row_in(&actions)? else {
        return Err("owner must follow exact page receipt".into());
    };
    assert!(matches!(
        owner.phase(),
        CutPhase::Pending {
            offered_pages: 1,
            ..
        }
    ));
    assert!(fixture.coordinator.state.streams.is_empty());
    let actions = fixture.commit_cut_stage(actions).await?;
    let (cut, count, cursor) = begin_cut(&frames(&actions)?)?;
    assert_eq!(count, 0);
    assert_eq!(cursor, None);
    assert_eq!(cut.token, owner.cut().token());
    assert_eq!(
        fixture
            .coordinator
            .state
            .streams
            .get(&home())
            .and_then(|stream| stream.owner.as_ref()),
        Some(&owner)
    );
    Ok(())
}

#[tokio::test]
async fn rejecting_a_cut_page_cannot_publish_a_new_stream_or_begin() -> TestResult {
    let mut fixture = unstarted().await?;
    let actions = initial_frame(&mut fixture)?;
    let _row = row_in(&actions)?;
    let Some(Action::Stage { work, .. }) = actions.into_iter().next() else {
        return Err("page stage".into());
    };
    fixture.coordinator.set_pending(work);
    fixture.coordinator.batch_rejected();
    assert!(fixture.coordinator.state.streams.is_empty());
    assert!(
        fixture
            .coordinator
            .peer_sync(home())
            .is_none_or(|sync| sync.snapshot.is_none())
    );
    assert!(fixture.coordinator.batch_applied(Some(0))?.is_none());
    Ok(())
}
