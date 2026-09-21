//! The live local router with a deterministic output-occupancy boundary.

#![forbid(unsafe_code)]

use super::*;
use crate::connection::sink::{
    BoundedSharedClientFrames, ClientQueueDemand, ClientQueueReservation, QueueAllocationError,
    SinkReserveError, TentativeClientQueueReservation,
};
use crate::state_core::inbox::CloseReason;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

struct PressureSink {
    inner: Arc<FrameSink>,
    queued: AtomicU64,
    closed: AtomicBool,
}

impl ClientSink for PressureSink {
    fn generation(&self) -> ConnectionGeneration {
        self.inner.generation()
    }
    fn try_reserve(
        &self,
        demand: ClientQueueDemand,
    ) -> Result<TentativeClientQueueReservation, SinkReserveError> {
        self.inner.try_reserve(demand)
    }
    fn prepare(
        &self,
        tentative: TentativeClientQueueReservation,
        backing: Option<crate::budget::MemoryPermit>,
    ) -> Result<ClientQueueReservation, QueueAllocationError> {
        self.inner.prepare(tentative, backing)
    }
    fn commit(&self, reservation: ClientQueueReservation, frames: BoundedSharedClientFrames) {
        self.inner.commit(reservation, frames);
    }
    fn begin_slow_consumer_close(&self) {
        self.inner.begin_slow_consumer_close();
    }
    fn close_after_flush(&self, reason: CloseReason) -> crate::connection::FlushAcknowledgement {
        self.closed.store(true, Ordering::SeqCst);
        self.inner.close_after_flush(reason)
    }
    fn queue_snapshot(&self) -> crate::connection::ClientQueueSnapshot {
        crate::connection::ClientQueueSnapshot::new(self.queued.load(Ordering::SeqCst), 1_048_576)
    }
}

async fn local_line(
    inbox: &mpsc::Sender<StateCoreMessage>,
    sequence: &mut u64,
    line: &str,
) -> TestResult {
    *sequence += 1;
    let message = parse_message(FramedLine::new(line)?)?.ok_or("empty line")?;
    send(
        inbox,
        StateCoreMessage::Line {
            generation: ConnectionGeneration::new(1),
            sequence: *sequence,
            message: Box::new(message),
        },
    )
    .await
}

async fn begin_paused_join(
    inbox: &mpsc::Sender<StateCoreMessage>,
    sink: &Arc<PressureSink>,
) -> TestResult<u64> {
    let mut sequence = 0;
    for line in [
        "CAP LS 302",
        "NICK alice",
        "USER alice 0 * :Alice",
        "CAP REQ :message-tags batch labeled-response",
        "CAP END",
    ] {
        local_line(inbox, &mut sequence, line).await?;
    }
    let recorded = [Arc::clone(&sink.inner)];
    drive_script(inbox, &recorded, &[(1, "WAIT  001 ")]).await?;
    sink.queued.store(524_288, Ordering::SeqCst);
    local_line(inbox, &mut sequence, "@label=local-join JOIN #local-join").await?;
    drive_script(inbox, &recorded, &[(1, "WAIT  331 ")]).await?;
    Ok(sequence)
}

async fn drive_paused_join(
    inbox: &mpsc::Sender<StateCoreMessage>,
    sink: &Arc<PressureSink>,
) -> TestResult {
    let mut sequence = begin_paused_join(inbox, sink).await?;
    let recorded = [Arc::clone(&sink.inner)];
    local_line(inbox, &mut sequence, "AWAY :queued-behind-join").await?;
    local_line(inbox, &mut sequence, "PING :after-queued-command").await?;
    drive_script(inbox, &recorded, &[(1, "WAIT PONG :after-queued-command")]).await?;
    let paused = sink.inner.lines();
    assert!(
        !paused.iter().any(|line| line.contains(" 353 ")),
        "a half-full queue must not fetch NAMES: {paused:?}"
    );
    assert!(
        !paused.iter().any(|line| line.contains(" 306 ")),
        "later registered commands wait behind JOIN: {paused:?}"
    );
    sink.queued.store(0, Ordering::SeqCst);
    drive_script(
        inbox,
        &recorded,
        &[(1, "WAIT BATCH -fq1"), (1, "WAIT  306 ")],
    )
    .await?;
    local_line(inbox, &mut sequence, "QUIT :done").await?;
    Ok(())
}

#[tokio::test]
async fn a_local_join_uses_one_label_batch_and_blocks_commands_until_names_can_resume() -> TestResult
{
    let sink = Arc::new(PressureSink {
        inner: FrameSink::new(ConnectionGeneration::new(1), true),
        queued: AtomicU64::new(0),
        closed: AtomicBool::new(false),
    });
    let (exit, (_inbox, sink, stopped)) = run_core(true, |inbox, lifecycle, _token| async move {
        let (acknowledgement, accepted) = oneshot::channel();
        send(
            &inbox,
            StateCoreMessage::Opened {
                generation: ConnectionGeneration::new(1),
                purpose: ListenerPurpose::ClientOnion,
                source: SourceAddressKey::onion_listener(),
                sink: Arc::clone(&sink) as Arc<dyn ClientSink>,
                acknowledgement,
            },
        )
        .await?;
        assert!(matches!(accepted.await?, ConnectionOpenOutcome::Accepted));
        drive_paused_join(&inbox, &sink).await?;
        let stopped = lifecycle.request(LifecyclePhase::Stop).await;
        Ok((inbox, sink, stopped))
    })
    .await?;
    assert!(stopped.is_ok());
    assert!(matches!(exit, StateCoreExit::Stopped), "{exit:?}");
    let lines = sink.inner.lines();
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.contains("@label=local-join "))
            .count(),
        1
    );
    let tagged: Vec<_> = lines
        .iter()
        .filter(|line| line.starts_with("@batch=fq1 "))
        .collect();
    assert_eq!(tagged.len(), 4, "{lines:?}");
    for (frame, command) in tagged.iter().zip([" JOIN ", " 331 ", " 353 ", " 366 "]) {
        assert!(frame.contains(command), "{frame}");
    }
    let ending = lines
        .iter()
        .position(|line| line.contains("BATCH -fq1"))
        .ok_or("batch end")?;
    let resumed = lines
        .iter()
        .position(|line| line.contains(" 306 "))
        .ok_or("resumed AWAY")?;
    assert!(ending < resumed);
    Ok(())
}

#[tokio::test]
async fn local_deferred_input_refuses_exhausted_backing_and_releases_every_permit() -> TestResult {
    use crate::budget::{BoundedMemoryCharges, MemoryBudgetPort, MemoryCharge};
    let sink = Arc::new(PressureSink {
        inner: FrameSink::new(ConnectionGeneration::new(1), true),
        queued: AtomicU64::new(0),
        closed: AtomicBool::new(false),
    });
    let (exit, (_inbox, sink, budget, closed, stopped)) = run_core_with(
        true,
        |fixture| Ok(Arc::clone(&fixture.context_mut()?.budget)),
        |inbox, lifecycle, _token, budget| async move {
            let (acknowledgement, accepted) = oneshot::channel();
            send(
                &inbox,
                StateCoreMessage::Opened {
                    generation: ConnectionGeneration::new(1),
                    purpose: ListenerPurpose::ClientOnion,
                    source: SourceAddressKey::onion_listener(),
                    sink: Arc::clone(&sink) as Arc<dyn ClientSink>,
                    acknowledgement,
                },
            )
            .await?;
            assert!(matches!(accepted.await?, ConnectionOpenOutcome::Accepted));
            let mut sequence = begin_paused_join(&inbox, &sink).await?;
            let exhausted =
                budget.try_acquire_batch(BoundedMemoryCharges::new(&[MemoryCharge::fixed(
                    budget.available(),
                )])?)?;
            assert_eq!(budget.available(), 0);
            local_line(&inbox, &mut sequence, "AWAY :cannot-retain-without-backing").await?;
            let closed = tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while !sink.closed.load(Ordering::SeqCst) {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .is_ok();
            drop(exhausted);
            let stopped = lifecycle.request(LifecyclePhase::Stop).await;
            Ok((inbox, sink, budget, closed, stopped))
        },
    )
    .await?;
    assert!(stopped.is_ok());
    assert!(matches!(exit, StateCoreExit::Stopped), "{exit:?}");
    assert!(
        closed,
        "deferred parsed input must reserve its retained backing"
    );
    assert_eq!(budget.available(), budget.capacity());
    assert!(
        !sink
            .inner
            .lines()
            .iter()
            .any(|line| line.contains(" 353 ") || line.contains(" 306 "))
    );
    Ok(())
}
