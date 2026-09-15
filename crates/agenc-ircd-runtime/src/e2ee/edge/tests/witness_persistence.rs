#![forbid(unsafe_code)]

//! Chain violations retain only metadata and close after their storage receipt.

use std::time::Duration;

use crate::federation::link::{LinkHandle, LinkQueue, link_queue};
use crate::federation::{FederationInbound, LinkEvent, LinkId, LinkSession};
use agenc_ircd_e2ee::federation::frames::CompanionFrame;
use agenc_ircd_storage::e2ee_records::{WITNESS_ROW_KIND, WitnessRow};

use super::*;

struct WitnessFixture {
    core: StateCoreFixture,
    companion: E2eeEdge,
    base: EdgeFederation,
    handle: LinkHandle,
    queue: LinkQueue,
}

impl WitnessFixture {
    async fn new() -> TestResult<Self> {
        let mut core = StateCoreFixture::new(vec![0; 16_384])?;
        let mut base = base_edge();
        let (handle, mut queue) = link_queue(1 << 20);
        establish(&mut core, &mut base, &handle, 1)?;
        for _ in 0..4 {
            if core.context_mut()?.pending_len() == 0 {
                break;
            }
            core.commit_staged_batch().await?;
            assert!(base.batch_applied(core.context_mut()?).is_empty());
        }
        assert_eq!(core.context_mut()?.pending_len(), 0);
        while let Ok(line) = tokio::time::timeout(Duration::from_millis(5), queue.recv()).await {
            drop(line.ok_or("base link closed during setup")?);
        }
        let mut companion = edge();
        install_route(&mut companion)?;
        companion.phase = crate::e2ee::edge::Phase::Active;
        companion.delivery.generation = 2;
        companion.delivery.cursor = Some((6, [12; 16]));
        Ok(Self {
            core,
            companion,
            base,
            handle,
            queue,
        })
    }

    fn violate(&mut self) -> TestResult {
        let mut open = part(IrcFederationEventKind::ClosedEvent, 6)?;
        open.event.cross_profile_mutation_id = Opaque::new(Vec::new())?;
        open.event.cross_profile_part_index = 0;
        open.event.cross_profile_part_count = 0;
        let bytes = IrcWireObject::new(IrcWireObjectKind::FederationEvent, open.event.encode()?)?
            .encode()?;
        let object_id = *agenc_ircd_e2ee::ObjectId::compute(&bytes).as_bytes();
        let frames = agenc_ircd_e2ee::wire::fragment::fragment_object(&bytes)?
            .into_iter()
            .map(|fragment| CompanionFrame::Event {
                position: open.position,
                object_id,
                fragment,
            })
            .collect();
        assert!(
            self.companion
                .handle_frames(self.core.context_mut()?, &mut self.base, frames)
                .is_empty()
        );
        Ok(())
    }

    fn staged_witness(&mut self) -> TestResult<WitnessRow> {
        let rows = self.core.context_mut()?.staged_rows_for_test()?;
        assert_eq!(
            rows.len(),
            1,
            "the refused event must stage only its witness metadata"
        );
        let AccountServiceDurableWrite::Put {
            table,
            key,
            plaintext,
        } = rows.first().ok_or("missing witness row")?
        else {
            return Err("witness must be a put".into());
        };
        assert_eq!(*table, TableId::E2eeState);
        assert!(*key == WitnessRow::key(&CONVERSATION)?);
        let value = PersistentRecordValue::decode(*table, plaintext)?;
        assert_eq!(value.record_kind(), WITNESS_ROW_KIND);
        let row = WitnessRow::decode(value.body())?;
        assert_eq!(value.body(), row.encode()?);
        Ok(row)
    }
}

fn establish(
    core: &mut StateCoreFixture,
    base: &mut EdgeFederation,
    handle: &LinkHandle,
    id: u64,
) -> TestResult {
    let link = LinkId::new(id);
    let peer = ServerId::from_bytes([3; 16]);
    let session = LinkSession {
        link,
        peer,
        peer_incarnation: ServerIncarnation::from_bytes([17; 16]),
        peer_recovery_epoch: RecoveryEpoch::from_bytes([5; 16]),
        transition: agenc_ircd_federation_wire::EpochTransition::Initial,
    };
    assert!(
        base.inbound(
            core.context_mut()?,
            FederationInbound {
                link,
                peer,
                event: LinkEvent::Established {
                    session,
                    handle: handle.clone()
                },
                charge: None,
            }
        )
        .is_empty()
    );
    Ok(())
}

async fn assert_open_and_silent(queue: &mut LinkQueue) -> TestResult {
    assert!(
        tokio::time::timeout(Duration::from_millis(20), queue.recv())
            .await
            .is_err(),
        "a witness violation published a frame or closed before its durable receipt"
    );
    Ok(())
}

#[tokio::test]
async fn a_witness_violation_closes_only_after_its_durable_receipt() -> TestResult {
    let mut fixture = WitnessFixture::new().await?;
    let head = fixture.core.context_mut()?.head().storage_commit_sequence;
    fixture.violate()?;
    let row = fixture.staged_witness()?;
    assert_eq!(row.event_kind, IrcFederationEventKind::ClosedEvent.value());
    assert_eq!(row.expected_sequence, 5);
    assert_eq!(row.expected_head_id, [59; 32]);
    assert_eq!(row.observed_sequence, 6);
    assert_eq!(row.observed_id, [60; 32]);
    assert_eq!(row.observed_predecessor_id, None);
    assert_eq!(fixture.companion.delivery.cursor, Some((6, [12; 16])));
    assert_eq!(fixture.base.counters().violations, 0);
    assert_open_and_silent(&mut fixture.queue).await?;
    assert!(
        fixture
            .companion
            .batch_applied(fixture.core.context_mut()?, &mut fixture.base)
            .is_empty()
    );
    assert_open_and_silent(&mut fixture.queue).await?;
    fixture.core.commit_staged_batch().await?;
    assert_eq!(
        fixture.core.context_mut()?.head().storage_commit_sequence,
        head.checked_add(1).ok_or("head overflow")?
    );
    assert_open_and_silent(&mut fixture.queue).await?;
    assert!(
        fixture
            .companion
            .batch_applied(fixture.core.context_mut()?, &mut fixture.base)
            .is_empty()
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(1), fixture.queue.recv())
            .await?
            .is_none()
    );
    assert_eq!(fixture.handle.queued_bytes(), 0);
    assert_eq!(fixture.base.counters().violations, 1);
    assert_eq!(fixture.companion.counters().chain_violations, 1);
    assert_eq!(fixture.companion.delivery.cursor, Some((6, [12; 16])));
    assert_eq!(
        fixture
            .companion
            .conversations
            .get(&CONVERSATION)
            .map(|known| known.head.sequence),
        Some(4)
    );
    Ok(())
}

fn due_witness(fixture: &mut WitnessFixture) -> TestResult<crate::state_core::timers::TimerEntry> {
    let timers = fixture.core.context_mut()?.timers_mut();
    for _ in 0..16 {
        let deadline = timers
            .next_deadline()
            .ok_or("missing reserved witness wake")?;
        let entry = timers.pop_due(deadline).ok_or("missing due witness wake")?;
        if entry.kind == crate::state_core::timers::TimerKind::CompanionWitnessRetry {
            return Ok(entry);
        }
    }
    Err("witness wake hidden behind unrelated timers".into())
}

fn reject_witness(
    fixture: &mut WitnessFixture,
) -> TestResult<crate::e2ee::edge::witness_failure::WitnessRejection> {
    fixture
        .core
        .state_mut()?
        .reject_fixture_batch_before_submission(
            agenc_ircd_storage::StorageError::FilesystemRejected(
                agenc_ircd_storage::FilesystemCause::IoFailure,
            ),
        )?;
    let rejected = fixture
        .companion
        .witness_rejection(fixture.core.context_mut()?)
        .ok_or("missing witness rejection owner")?;
    assert!(fixture.companion.witness_batch_rejected(Some(rejected)));
    Ok(rejected)
}

#[tokio::test]
async fn a_refused_witness_keeps_exact_metadata_until_a_later_timer_commits_it() -> TestResult {
    let mut fixture = WitnessFixture::new().await?;
    fixture.violate()?;
    let original = fixture.staged_witness()?.encode()?;
    let rejected = reject_witness(&mut fixture)?;
    for _ in 0..4 {
        assert!(fixture.companion.witness_batch_rejected(Some(rejected)));
        assert!(
            fixture
                .companion
                .batch_applied(fixture.core.context_mut()?, &mut fixture.base)
                .is_empty()
        );
    }
    assert!(fixture.companion.retention_blocked());
    assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
    assert_open_and_silent(&mut fixture.queue).await?;
    let timer = due_witness(&mut fixture)?;
    assert!(fixture.companion.witness_timer_fired(
        fixture.core.context_mut()?,
        &mut fixture.base,
        timer
    ));
    assert_eq!(fixture.staged_witness()?.encode()?, original);
    // Duplicated old rejection and timer events cannot consume the new stage.
    assert!(fixture.companion.witness_batch_rejected(Some(rejected)));
    assert!(fixture.companion.witness_timer_fired(
        fixture.core.context_mut()?,
        &mut fixture.base,
        timer
    ));
    assert_eq!(fixture.staged_witness()?.encode()?, original);
    fixture.core.commit_staged_batch().await?;
    assert!(
        fixture
            .companion
            .batch_applied(fixture.core.context_mut()?, &mut fixture.base)
            .is_empty()
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(1), fixture.queue.recv())
            .await?
            .is_none()
    );
    assert!(fixture.companion.retention_blocked());
    assert!(fixture.companion.witness_recovery_pending());
    assert!(
        fixture
            .core
            .stored_row_exists(TableId::E2eeState, WitnessRow::key(&CONVERSATION)?)?
    );
    Ok(())
}

#[tokio::test]
async fn an_old_witness_receipt_cannot_close_a_replacement_link() -> TestResult {
    let mut fixture = WitnessFixture::new().await?;
    fixture.violate()?;
    let original = fixture.staged_witness()?.encode()?;
    let (replacement, mut queue) = link_queue(1 << 20);
    establish(&mut fixture.core, &mut fixture.base, &replacement, 2)?;
    fixture.companion.link_down();
    assert!(
        !fixture
            .companion
            .link_active(fixture.core.context_mut()?, &mut fixture.base)
    );
    // Base-profile negotiation can proceed, while the companion remains blocked.
    while let Ok(line) = tokio::time::timeout(Duration::from_millis(5), queue.recv()).await {
        let line = line.ok_or("replacement was closed before the old receipt")?;
        assert!(!line.as_str().contains(" ERESUME "));
    }
    assert_eq!(fixture.staged_witness()?.encode()?, original);
    assert!(
        fixture
            .companion
            .batch_applied(fixture.core.context_mut()?, &mut fixture.base)
            .is_empty()
    );
    assert_open_and_silent(&mut queue).await?;
    fixture.core.commit_staged_batch().await?;
    assert!(
        fixture
            .companion
            .batch_applied(fixture.core.context_mut()?, &mut fixture.base)
            .is_empty()
    );
    assert_eq!(
        fixture.base.current_companion_link_id(),
        Some(LinkId::new(2))
    );
    assert_open_and_silent(&mut queue).await?;
    assert_eq!(replacement.queued_bytes(), 0);
    assert_eq!(fixture.companion.counters().chain_violations, 1);
    Ok(())
}

#[tokio::test]
async fn exhausted_witness_timer_capacity_refuses_before_consuming_the_chain_event() -> TestResult {
    let mut fixture = WitnessFixture::new().await?;
    *fixture.core.context_mut()?.timers_mut() =
        crate::state_core::timers::TimerHeap::with_ceiling(0);
    fixture.violate()?;
    assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
    assert!(!fixture.companion.witness_pending());
    assert_eq!(fixture.companion.counters().chain_violations, 0);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), fixture.queue.recv())
            .await?
            .is_none()
    );
    *fixture.core.context_mut()?.timers_mut() =
        crate::state_core::timers::TimerHeap::with_ceiling(1);
    let (replacement, mut queue) = link_queue(1 << 20);
    establish(&mut fixture.core, &mut fixture.base, &replacement, 2)?;
    while let Ok(line) = tokio::time::timeout(Duration::from_millis(5), queue.recv()).await {
        drop(line.ok_or("replacement refused despite returned timer capacity")?);
    }
    fixture.companion.phase = crate::e2ee::edge::Phase::Active;
    fixture.violate()?;
    assert_eq!(fixture.staged_witness()?.observed_sequence, 6);
    assert_open_and_silent(&mut queue).await?;
    Ok(())
}

#[tokio::test]
async fn a_reserved_witness_wake_survives_a_full_timer_heap_and_repeated_refusal() -> TestResult {
    let mut fixture = WitnessFixture::new().await?;
    *fixture.core.context_mut()?.timers_mut() =
        crate::state_core::timers::TimerHeap::with_ceiling(1);
    fixture.violate()?;
    let original = fixture.staged_witness()?.encode()?;
    for _ in 0..3 {
        reject_witness(&mut fixture)?;
        let entry = due_witness(&mut fixture)?;
        assert!(fixture.companion.witness_timer_fired(
            fixture.core.context_mut()?,
            &mut fixture.base,
            entry
        ));
        assert_eq!(fixture.core.context_mut()?.timers_mut().live_len(), 1);
        assert_eq!(fixture.staged_witness()?.encode()?, original);
    }
    fixture.core.commit_staged_batch().await?;
    assert!(
        fixture
            .companion
            .batch_applied(fixture.core.context_mut()?, &mut fixture.base)
            .is_empty()
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(1), fixture.queue.recv())
            .await?
            .is_none()
    );
    Ok(())
}

fn stage_unrelated_cursor(fixture: &mut WitnessFixture) -> TestResult {
    let write = crate::e2ee::edge::events::cursor_write(
        &fixture.companion.config,
        &fixture.companion.delivery,
    )
    .map_err(|code| code.to_string())?;
    let context = fixture.core.context_mut()?;
    let plan = context.domain().plan_account_service_checkpoint()?;
    let write = write.at_revision(plan.resulting_revision().get())?;
    let fanout = crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())?;
    context
        .stage_durable_with_account_service(plan, fanout, None, 0, vec![write])
        .map_err(|error| format!("unrelated cursor admission: {error:?}"))?;
    assert_ne!(context.pending_len(), 0);
    Ok(())
}

#[tokio::test]
async fn a_witness_receipt_is_not_hidden_by_a_newly_staged_unrelated_batch() -> TestResult {
    let mut fixture = WitnessFixture::new().await?;
    fixture.violate()?;
    assert_eq!(fixture.staged_witness()?.observed_sequence, 6);
    fixture.core.commit_staged_batch().await?;
    stage_unrelated_cursor(&mut fixture)?;
    assert!(
        fixture
            .companion
            .batch_applied(fixture.core.context_mut()?, &mut fixture.base,)
            .is_empty()
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(1), fixture.queue.recv())
            .await?
            .is_none()
    );
    assert_eq!(fixture.companion.counters().chain_violations, 1);
    assert!(!fixture.companion.witness_pending());
    assert!(
        fixture
            .core
            .stored_row_exists(TableId::E2eeState, WitnessRow::key(&CONVERSATION)?)?
    );
    assert_ne!(fixture.core.context_mut()?.pending_len(), 0);
    Ok(())
}

#[tokio::test]
async fn a_witness_rejection_is_not_hidden_by_a_newly_staged_unrelated_batch() -> TestResult {
    let mut fixture = WitnessFixture::new().await?;
    fixture.violate()?;
    let original = fixture.staged_witness()?.encode()?;
    fixture
        .core
        .state_mut()?
        .reject_fixture_batch_before_submission(
            agenc_ircd_storage::StorageError::FilesystemRejected(
                agenc_ircd_storage::FilesystemCause::IoFailure,
            ),
        )?;
    let rejected = fixture
        .companion
        .witness_rejection(fixture.core.context_mut()?)
        .ok_or("missing settled witness attempt")?;
    stage_unrelated_cursor(&mut fixture)?;
    assert!(fixture.companion.witness_batch_rejected(Some(rejected)));
    assert_open_and_silent(&mut fixture.queue).await?;
    fixture.core.commit_staged_batch().await?;
    assert!(
        fixture
            .companion
            .batch_applied(fixture.core.context_mut()?, &mut fixture.base,)
            .is_empty()
    );
    assert_open_and_silent(&mut fixture.queue).await?;
    assert_eq!(fixture.companion.counters().chain_violations, 0);
    let timer = due_witness(&mut fixture)?;
    assert!(fixture.companion.witness_timer_fired(
        fixture.core.context_mut()?,
        &mut fixture.base,
        timer,
    ));
    assert_eq!(fixture.staged_witness()?.encode()?, original);
    fixture.core.commit_staged_batch().await?;
    assert!(
        fixture
            .companion
            .batch_applied(fixture.core.context_mut()?, &mut fixture.base,)
            .is_empty()
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(1), fixture.queue.recv())
            .await?
            .is_none()
    );
    assert_eq!(fixture.companion.counters().chain_violations, 1);
    Ok(())
}

#[path = "witness_gating.rs"]
mod gating;
