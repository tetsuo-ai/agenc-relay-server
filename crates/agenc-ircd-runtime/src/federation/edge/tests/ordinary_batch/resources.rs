#![forbid(unsafe_code)]

use super::*;

use crate::connection::FlushAcknowledgement;
use crate::connection::sink::{
    BoundedSharedClientFrames, ClientQueueDemand, ClientQueueReservation, ClientQueueSnapshot,
    ClientSink, QueueAllocationError, SinkReserveError, TentativeClientQueueReservation,
};
use crate::state_core::inbox::CloseReason;
use std::sync::atomic::{AtomicUsize, Ordering};

struct OneFrameSink {
    inner: Arc<FrameSink>,
    closes: AtomicUsize,
}

impl ClientSink for OneFrameSink {
    fn generation(&self) -> ConnectionGeneration {
        self.inner.generation()
    }
    fn try_reserve(
        &self,
        demand: ClientQueueDemand,
    ) -> Result<TentativeClientQueueReservation, SinkReserveError> {
        if demand.frame_count() > 1 {
            return Err(SinkReserveError::Full);
        }
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
        self.closes.fetch_add(1, Ordering::SeqCst);
    }
    fn close_after_flush(&self, reason: CloseReason) -> FlushAcknowledgement {
        self.inner.close_after_flush(reason)
    }
    fn queue_snapshot(&self) -> ClientQueueSnapshot {
        self.inner.queue_snapshot()
    }
}

fn constrain_sink(fixture: &mut PrefixFixture) -> TestResult<Arc<OneFrameSink>> {
    let generation = ConnectionGeneration::new(1);
    let context = fixture.core.context_mut()?;
    let connection = context
        .sessions_mut()
        .close(generation)
        .ok_or("connection")?;
    let sink = Arc::new(OneFrameSink {
        inner: Arc::clone(&fixture.sink),
        closes: AtomicUsize::new(0),
    });
    let now = context.now();
    context.sessions_mut().open(
        generation,
        connection.purpose(),
        connection.source_prefix(),
        Arc::clone(&sink) as Arc<dyn ClientSink>,
        now,
    )?;
    context.sessions_mut().bind_session(
        generation,
        connection.session().ok_or("session")?,
        CapabilityState::default(),
    )?;
    Ok(sink)
}

#[tokio::test]
async fn an_oversized_aggregate_shrinks_without_closing_its_healthy_recipient() -> TestResult {
    let mut fixture = PrefixFixture::new()?;
    let sink = constrain_sink(&mut fixture)?;
    fixture.receive(0)?;
    fixture.receive(1)?;
    fixture.receive(2)?;
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_next_ack(&mut fixture.queue, 0).await?;
    assert!(matches!(
        fixture.edge.commit,
        Some(PendingCommit::Event { .. })
    ));
    assert_eq!(sink.closes.load(Ordering::SeqCst), 0);
    for sequence in 1..=2 {
        fixture.core.commit_staged_batch().await?;
        fixture.settle_edge()?;
        assert_next_ack(&mut fixture.queue, sequence).await?;
    }
    assert_outputs(&fixture.sink, 3);
    assert_eq!(sink.closes.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.edge.phase, Phase::Active);
    Ok(())
}

#[tokio::test]
async fn acknowledgement_slot_pressure_shrinks_before_storage_without_retiring_the_link()
-> TestResult {
    let mut fixture = PrefixFixture::new()?;
    fixture.receive(0)?;
    fixture.receive(1)?;
    fixture.receive(2)?;
    fixture.core.commit_staged_batch().await?;
    let count = crate::federation::link::OUTBOUND_QUEUE_ITEMS
        .checked_sub(2)
        .ok_or("slots")?;
    for _ in 0..count {
        fixture.handle.try_send(
            agenc_ircd_federation_wire::FederationLineText::from_rendered(
                ":edge FPONG :occupied\r\n".to_owned(),
            )?,
        )?;
    }
    fixture.settle_edge()?;
    assert!(matches!(
        fixture.edge.commit,
        Some(PendingCommit::Event { .. })
    ));
    assert_eq!(fixture.edge.phase, Phase::Active);
    for _ in 0..count {
        assert_eq!(
            fixture.queue.recv().await.ok_or("occupied slot")?.as_str(),
            ":edge FPONG :occupied\r\n"
        );
    }
    assert_next_ack(&mut fixture.queue, 0).await?;
    for sequence in 1..=2 {
        fixture.core.commit_staged_batch().await?;
        fixture.settle_edge()?;
        assert_next_ack(&mut fixture.queue, sequence).await?;
    }
    assert_outputs(&fixture.sink, 3);
    assert_eq!(fixture.handle.queued_bytes(), 0);
    Ok(())
}
