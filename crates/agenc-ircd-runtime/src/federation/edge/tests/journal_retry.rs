#![forbid(unsafe_code)]

//! Definite journal refusals retain exact ownership without cycling the link.

use super::*;
use crate::state_core::timers::TimerHeap;
use agenc_ircd_storage::StorageError;

mod closed_origin;

#[test]
fn journal_retry_classifies_only_definite_resource_refusals() {
    use crate::connection::sink::QueueAllocationError;
    use crate::state_core::StageRefused;
    use crate::state_core::fanout::FanoutRefused;
    use agenc_ircd_domain::DomainError;
    for error in [
        StageRefused::Busy,
        StageRefused::Domain(DomainError::ServerBusy),
        StageRefused::Fanout(FanoutRefused::MemoryExhausted),
        StageRefused::Fanout(FanoutRefused::Prepare(
            QueueAllocationError::AllocationFailed,
        )),
    ] {
        assert!(super::super::journal_retry::stage_retryable(&error));
    }
    for error in [
        StageRefused::Quiescing,
        StageRefused::Domain(DomainError::InvariantViolation),
        StageRefused::Fanout(FanoutRefused::Invalid(RuntimeError::Overflow)),
        StageRefused::Fanout(FanoutRefused::Prepare(QueueAllocationError::PermitMismatch)),
        StageRefused::Fanout(FanoutRefused::Prepare(QueueAllocationError::Closed)),
    ] {
        assert!(!super::super::journal_retry::stage_retryable(&error));
    }
}

#[tokio::test]
async fn journal_retry_timer_exhaustion_never_reenters_staging() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let (mut edge, _queue) = active_edge(fixture.context_mut()?)?;
    *fixture.context_mut()?.timers_mut() = TimerHeap::with_ceiling(0);
    let id = start_request(&mut edge, fixture.context_mut()?)?;
    reject_request(&mut edge, &mut fixture, StorageError::AllocationFailed)?;
    assert_eq!(edge.phase, Phase::Down);
    assert!(edge.journal.retry.recovering);
    for _ in 0..10 {
        edge.batch_rejected_with_error(fixture.context_mut()?, StorageError::FilesystemRejected);
        edge.continue_request_journal(fixture.context_mut()?);
    }
    assert!(
        edge.commit.is_none(),
        "a callback bypassed the unavailable retry timer"
    );
    assert_eq!(fixture.context_mut()?.pending_len(), 0);
    assert_eq!(fixture.context_mut()?.timers_mut().len(), 0);
    assert!(edge.pending.contains_key(&id));
    assert!(!edge.pending.get(&id).ok_or("request")?.sent);
    Ok(())
}

fn active_edge(context: &mut StateCoreContext) -> TestResult<(EdgeFederation, LinkQueue)> {
    *context.timers_mut() = TimerHeap::new();
    active_edge_without_timer_reset(context)
}

fn active_edge_without_timer_reset(
    context: &mut StateCoreContext,
) -> TestResult<(EdgeFederation, LinkQueue)> {
    let mut edge = resync_edge();
    let generation = ConnectionGeneration::new(1);
    edge.connection_opened(context, generation);
    let (handle, queue) = link_queue(1 << 20);
    edge.live = Some(LiveLink {
        link: LinkId::new(1),
        handle,
        coordinator_epoch: COORDINATOR_EPOCH,
        coordinator_incarnation: HUB_INCARNATION,
    });
    edge.phase = Phase::Active;
    edge.origins
        .get_mut(&generation)
        .ok_or("origin")?
        .acked_generation = Some(0);
    Ok((edge, queue))
}

fn start_request(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
) -> TestResult<RequestId> {
    request::send_session_open(
        edge,
        context,
        ConnectionGeneration::new(1),
        1,
        "retained",
        "Retained",
        [1; 32],
        None,
    )
    .map_err(|error| format!("session open: {error:?}"))?;
    edge.pending
        .keys()
        .next()
        .copied()
        .ok_or_else(|| "request missing".into())
}

fn retry_entry(context: &mut StateCoreContext) -> TestResult<TimerEntry> {
    let deadline = context
        .timers_mut()
        .next_deadline()
        .ok_or("retry deadline")?;
    let entry = context
        .timers_mut()
        .pop_due(deadline)
        .ok_or("retry entry")?;
    assert_eq!(entry.kind, TimerKind::FederationJournalRetry);
    Ok(entry)
}

#[tokio::test]
async fn refused_journal_storage_keeps_the_link_and_retries_exact_bytes_after_storage() -> TestResult
{
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let (mut edge, _queue) = active_edge(fixture.context_mut()?)?;
    let id = start_request(&mut edge, fixture.context_mut()?)?;
    reject_request(&mut edge, &mut fixture, StorageError::AllocationFailed)?;
    let bytes = edge.pending.get(&id).ok_or("request")?.bytes.clone();
    assert_eq!(
        edge.phase,
        Phase::Active,
        "a definite refusal closed the live link"
    );
    assert!(edge.journal.retry.recovering);
    assert_eq!(fixture.context_mut()?.pending_len(), 0);
    assert!(!edge.pending.get(&id).ok_or("request")?.sent);
    assert!(!journal::is_durable(&edge, journal::Identity::Request(id)));
    let deadline = fixture.context_mut()?.timers_mut().next_deadline();
    for _ in 0..10 {
        edge.continue_request_journal(fixture.context_mut()?);
    }
    assert_eq!(fixture.context_mut()?.timers_mut().len(), 1);
    assert_eq!(
        fixture.context_mut()?.timers_mut().next_deadline(),
        deadline
    );
    let entry = retry_entry(fixture.context_mut()?)?;
    assert!(edge.timer_fired(fixture.context_mut()?, entry));
    assert_eq!(fixture.context_mut()?.pending_len(), 1);
    assert!(!edge.pending.get(&id).ok_or("request")?.sent);
    fixture.commit_staged_batch().await?;
    assert!(edge.batch_applied(fixture.context_mut()?).is_empty());
    assert!(journal::is_durable(&edge, journal::Identity::Request(id)));
    let pending = edge.pending.get(&id).ok_or("request")?;
    assert_eq!(pending.bytes, bytes);
    assert!(pending.sent);
    assert!(!edge.journal.retry.recovering);
    assert_eq!(fixture.context_mut()?.timers_mut().live_len(), 0);
    Ok(())
}

#[tokio::test]
async fn rejected_journal_receipts_do_not_reenter_or_extend_the_retry() -> TestResult {
    for error in [
        StorageError::FilesystemRejected,
        StorageError::QueueFull,
        StorageError::AllocationFailed,
    ] {
        let mut fixture = StateCoreFixture::new(entropy_script())?;
        let (mut edge, _queue) = active_edge(fixture.context_mut()?)?;
        let id = start_request(&mut edge, fixture.context_mut()?)?;
        let bytes = edge.pending.get(&id).ok_or("request")?.bytes.clone();
        reject_request(&mut edge, &mut fixture, error)?;
        let staged = fixture.context_mut()?.pending_len();
        assert_eq!(
            edge.phase,
            Phase::Active,
            "determinate rejection closed link"
        );
        assert!(edge.commit.is_none(), "rejection reentered staging");
        let deadline = fixture.context_mut()?.timers_mut().next_deadline();
        edge.batch_rejected_with_error(fixture.context_mut()?, error);
        edge.continue_request_journal(fixture.context_mut()?);
        assert_eq!(fixture.context_mut()?.pending_len(), staged);
        assert_eq!(fixture.context_mut()?.timers_mut().len(), 1);
        assert_eq!(
            fixture.context_mut()?.timers_mut().next_deadline(),
            deadline
        );
        assert_eq!(edge.pending.get(&id).ok_or("request")?.bytes, bytes);
        let (mut other, _other_queue) = active_edge_without_timer_reset(fixture.context_mut()?)?;
        start_request(&mut other, fixture.context_mut()?)?;
        let entry = retry_entry(fixture.context_mut()?)?;
        edge.timer_fired(fixture.context_mut()?, entry);
        assert!(edge.commit.is_none(), "busy owner was overwritten");
        assert_eq!(fixture.context_mut()?.timers_mut().live_len(), 1);
    }
    Ok(())
}

#[tokio::test]
async fn journal_pressure_refuses_new_work_before_sequence_or_deferred_admission() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let (mut edge, _queue) = active_edge(fixture.context_mut()?)?;
    let generation = ConnectionGeneration::new(1);
    let id = start_request(&mut edge, fixture.context_mut()?)?;
    reject_request(&mut edge, &mut fixture, StorageError::AllocationFailed)?;
    let origin = edge.origins.get_mut(&generation).ok_or("origin")?;
    origin.session = Some((SessionId::from_bytes([1; 16]), UserId::from_bytes([2; 16])));
    let sequence = origin.sequence;
    assert_eq!(
        queue_deferred_query(&mut edge, fixture.context_mut()?, generation)?,
        Err(agenc_ircd_domain::DomainError::ServerBusy)
    );
    assert!(
        edge.deferred.is_empty(),
        "refused command entered the deferred queue"
    );
    assert!(start_request(&mut edge, fixture.context_mut()?).is_err());
    assert_eq!(
        edge.origins.get(&generation).ok_or("origin")?.sequence,
        sequence
    );
    assert_eq!(edge.pending.len(), 1);
    assert!(edge.pending.contains_key(&id));
    Ok(())
}

#[tokio::test]
async fn journal_retry_ignores_stale_tokens_and_cancels_when_quiescing() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let (mut edge, _queue) = active_edge(fixture.context_mut()?)?;
    let id = start_request(&mut edge, fixture.context_mut()?)?;
    reject_request(&mut edge, &mut fixture, StorageError::AllocationFailed)?;
    let entry = retry_entry(fixture.context_mut()?)?;
    edge.timer_fired(fixture.context_mut()?, entry);
    reject_request(&mut edge, &mut fixture, StorageError::AllocationFailed)?;
    let token = edge.journal.retry.waiting;
    edge.timer_fired(fixture.context_mut()?, entry);
    assert_eq!(edge.journal.retry.waiting, token);
    assert_eq!(fixture.context_mut()?.timers_mut().live_len(), 1);
    fixture.state_mut()?.step_message(StateCoreMessage::Signal(
        crate::state_core::inbox::SignalEvent::Terminate,
    ));
    edge.continue_request_journal(fixture.context_mut()?);
    assert_eq!(fixture.context_mut()?.timers_mut().live_len(), 0);
    assert!(edge.pending.contains_key(&id));
    assert!(edge.commit.is_none());
    Ok(())
}

#[tokio::test]
async fn journal_invariant_rejection_keeps_the_existing_closed_failure_boundary() -> TestResult {
    for error in [
        StorageError::Unavailable,
        StorageError::AuthenticationFailed,
        StorageError::StaleState,
        StorageError::InvalidEncoding,
        StorageError::LimitExceeded,
    ] {
        let mut fixture = StateCoreFixture::new(entropy_script())?;
        let (mut edge, _queue) = active_edge(fixture.context_mut()?)?;
        let id = start_request(&mut edge, fixture.context_mut()?)?;
        reject_request(&mut edge, &mut fixture, error)?;
        assert_eq!(edge.phase, Phase::Down);
        assert!(edge.pending.contains_key(&id));
        assert!(edge.journal.retry.waiting.is_none());
    }
    Ok(())
}

fn reject_request(
    edge: &mut EdgeFederation,
    fixture: &mut StateCoreFixture,
    error: StorageError,
) -> TestResult {
    let before = fixture.context_mut()?.head().storage_commit_sequence;
    fixture
        .state_mut()?
        .reject_fixture_batch_before_submission(error)?;
    edge.batch_rejected_with_error(fixture.context_mut()?, error);
    assert_eq!(
        fixture.context_mut()?.head().storage_commit_sequence,
        before
    );
    assert_eq!(fixture.context_mut()?.pending_len(), 0);
    Ok(())
}

#[tokio::test]
async fn closing_a_client_keeps_the_original_retry_and_tombstones_before_transmission() -> TestResult
{
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let (mut edge, _queue) = active_edge(fixture.context_mut()?)?;
    let id = start_request(&mut edge, fixture.context_mut()?)?;
    let bytes = edge.pending.get(&id).ok_or("request")?.bytes.clone();
    reject_request(&mut edge, &mut fixture, StorageError::FilesystemRejected)?;
    let token = edge.journal.retry.waiting;
    let deadline = fixture.context_mut()?.timers_mut().next_deadline();
    edge.connection_closed(
        fixture.context_mut()?,
        ConnectionGeneration::new(1),
        "client left",
    );
    assert_eq!(edge.journal.retry.waiting, token);
    assert_eq!(
        fixture.context_mut()?.timers_mut().next_deadline(),
        deadline
    );
    let entry = retry_entry(fixture.context_mut()?)?;
    edge.timer_fired(fixture.context_mut()?, entry);
    fixture.commit_staged_batch().await?;
    edge.batch_applied(fixture.context_mut()?);
    let pending = edge.pending.get(&id).ok_or("retained closed request")?;
    assert_eq!(pending.bytes, bytes);
    assert!(pending.sink_gone);
    assert!(!pending.sent);
    assert!(journal::is_durable(&edge, journal::Identity::Request(id)));
    assert!(
        edge.origins
            .get(&ConnectionGeneration::new(1))
            .ok_or("origin")?
            .deleted
    );
    Ok(())
}

#[tokio::test]
async fn a_new_authenticated_link_rearms_journal_retry_after_timer_capacity_returns() -> TestResult
{
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let (mut edge, _queue) = active_edge(fixture.context_mut()?)?;
    let id = start_request(&mut edge, fixture.context_mut()?)?;
    let bytes = edge.pending.get(&id).ok_or("request")?.bytes.clone();
    *fixture.context_mut()?.timers_mut() = TimerHeap::with_ceiling(0);
    reject_request(&mut edge, &mut fixture, StorageError::FilesystemRejected)?;
    let _failed_queue = establish_retry_link(&mut edge, fixture.context_mut()?, 2);
    assert_eq!(edge.phase, Phase::Down);
    assert_eq!(fixture.context_mut()?.pending_len(), 0);
    *fixture.context_mut()?.timers_mut() = TimerHeap::new();
    let _stale_queue = establish_retry_link(&mut edge, fixture.context_mut()?, 2);
    assert_eq!(fixture.context_mut()?.timers_mut().live_len(), 0);
    let _new_queue = establish_retry_link(&mut edge, fixture.context_mut()?, 3);
    let token = edge.journal.retry.waiting;
    assert!(token.is_some());
    assert_eq!(
        fixture.context_mut()?.pending_len(),
        0,
        "establishment staged a retry"
    );
    let _duplicate_queue = establish_retry_link(&mut edge, fixture.context_mut()?, 3);
    assert_eq!(edge.journal.retry.waiting, token);
    assert!(
        edge.live
            .as_ref()
            .is_some_and(|live| live.link == LinkId::new(3))
    );
    let entry = retry_entry(fixture.context_mut()?)?;
    edge.timer_fired(fixture.context_mut()?, entry);
    fixture.commit_staged_batch().await?;
    edge.batch_applied(fixture.context_mut()?);
    assert!(journal::is_durable(&edge, journal::Identity::Request(id)));
    assert_eq!(edge.pending.get(&id).ok_or("request")?.bytes, bytes);
    assert_eq!(
        edge.origins
            .get(&ConnectionGeneration::new(1))
            .ok_or("origin")?
            .sequence,
        1
    );
    assert!(!edge.journal.retry.recovering);
    acknowledge_recovered_origin(&mut edge, fixture.context_mut()?)?;
    assert!(edge.pending.get(&id).ok_or("request")?.sent);
    Ok(())
}

fn acknowledge_recovered_origin(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
) -> TestResult {
    let projection_generation = edge.replica.projection_generation();
    super::super::sync::resume_ok(edge, context, projection_generation, 0)
        .map_err(|error| format!("resume: {error:?}"))?;
    super::super::sync::origin_ready(edge, context, EDGE_INCARNATION)
        .map_err(|error| format!("ready: {error:?}"))?;
    let origin = edge
        .origins
        .get(&ConnectionGeneration::new(1))
        .ok_or("origin")?;
    edge.origin_acked(
        context,
        EDGE_INCARNATION,
        origin.origin_id,
        origin.generation,
        Some(agenc_ircd_federation_wire::FederationHash32::from_bytes(
            origin.object_id,
        )),
    )
    .map_err(|error| format!("origin ACK: {error:?}"))?;
    Ok(())
}

fn establish_retry_link(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    attempt: u64,
) -> LinkQueue {
    let (handle, queue) = link_queue(1 << 20);
    edge.link_established(
        context,
        LinkSession {
            link: LinkId::new(attempt),
            peer: COORDINATOR,
            peer_incarnation: HUB_INCARNATION,
            peer_recovery_epoch: COORDINATOR_EPOCH,
            transition: agenc_ircd_federation_wire::EpochTransition::Initial,
        },
        handle,
    );
    queue
}
