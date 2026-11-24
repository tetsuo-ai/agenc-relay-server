//! One ordered authenticated client batch, rendered one physical line at a time.

use agenc_relay_client_wire::{MAX_PHYSICAL_LINE_BYTES, WireMessage};
use agenc_relay_e2ee::object::ArcWireObjectKind;
use agenc_relay_e2ee::wire::{reply::E2eeReplyCode, response::render_eobject};
use std::collections::VecDeque;

use crate::budget::MemoryPermit;
use crate::e2ee::outbound::{ObjectBytes, Segments};
use std::sync::Arc;

enum Part {
    Line(String),
    Object {
        kind: ArcWireObjectKind,
        segments: Segments,
        next: u32,
    },
}

/// The connection's writer owns these immutable authenticated bytes from
/// admission until the ordered BATCH close or a transport failure.
pub struct ClientBatch {
    server: String,
    batch_id: String,
    scope: [u8; 16],
    parts: VecDeque<Part>,
    window: usize,
    backing: Arc<MemoryPermit>,
}

impl std::fmt::Debug for ClientBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientBatch")
            .field("parts", &self.parts.len())
            .field("window", &self.window)
            .finish_non_exhaustive()
    }
}

impl ClientBatch {
    pub(super) fn new(
        server: String,
        batch_id: String,
        scope: [u8; 16],
        backing: MemoryPermit,
    ) -> Self {
        Self {
            server,
            batch_id,
            scope,
            parts: VecDeque::new(),
            window: 0,
            backing: Arc::new(backing),
        }
    }

    pub(super) fn line(&mut self, line: String) -> Result<(), E2eeReplyCode> {
        self.measure(&line)?;
        self.parts.push_back(Part::Line(line));
        Ok(())
    }

    pub(super) fn object<T: AsRef<[u8]> + Send + Sync + 'static>(
        &mut self,
        kind: ArcWireObjectKind,
        bytes: T,
    ) -> Result<(), E2eeReplyCode> {
        let segments = Segments::new(bytes)?;
        for part in [segments.count.saturating_sub(2), segments.count - 1] {
            let tag = segments
                .fragment(part)
                .ok_or(E2eeReplyCode::InvalidFragment)?;
            let line = render_eobject(&self.server, &self.batch_id, &tag, kind, &self.scope)
                .map_err(|_| E2eeReplyCode::InvalidFragment)?;
            self.measure(&line)?;
        }
        self.parts.push_back(Part::Object {
            kind,
            segments,
            next: 0,
        });
        Ok(())
    }

    fn measure(&mut self, line: &str) -> Result<(), E2eeReplyCode> {
        let message =
            WireMessage::extension_line(line).map_err(|_| E2eeReplyCode::InvalidFragment)?;
        message
            .measure()
            .map_err(|_| E2eeReplyCode::InvalidFragment)?;
        if line.len() > MAX_PHYSICAL_LINE_BYTES || !line.ends_with("\r\n") {
            return Err(E2eeReplyCode::InvalidFragment);
        }
        self.window = self.window.max(line.len());
        Ok(())
    }

    pub(crate) fn empty(&self) -> bool {
        self.parts.is_empty()
    }

    pub(crate) fn next_output(&mut self) -> crate::connection::queue::QueuePop {
        match self.next_line() {
            Ok(Some(line)) => crate::connection::QueuePop::Companion(line),
            _ => {
                self.parts.clear();
                crate::connection::queue::QueuePop::Closed(
                    crate::state_core::inbox::CloseReason::ProtocolError,
                )
            }
        }
    }

    /// Maximum number of bytes in any one physical line of the batch.
    pub fn window(&self) -> usize {
        self.window
    }

    /// Renders the next physical line in wire order, including CRLF.
    pub fn next_line(&mut self) -> Result<Option<ClientLine>, E2eeReplyCode> {
        match self.parts.pop_front() {
            None => Ok(None),
            Some(Part::Line(line)) => Ok(Some(self.line_owner(line, None))),
            Some(Part::Object {
                kind,
                segments,
                next,
            }) => self.render_part(kind, segments, next).map(Some),
        }
    }

    fn line_owner(&self, line: String, source: Option<ObjectBytes>) -> ClientLine {
        ClientLine {
            line,
            _source: source,
            _backing: Arc::clone(&self.backing),
        }
    }

    fn render_part(
        &mut self,
        kind: ArcWireObjectKind,
        segments: Segments,
        next: u32,
    ) -> Result<ClientLine, E2eeReplyCode> {
        let fragment = segments
            .fragment(next)
            .ok_or(E2eeReplyCode::InvalidFragment)?;
        let line = render_eobject(&self.server, &self.batch_id, &fragment, kind, &self.scope)
            .map_err(|_| E2eeReplyCode::InvalidFragment)?;
        let source = Arc::clone(&segments.bytes);
        if next + 1 < segments.count {
            self.parts.push_front(Part::Object {
                kind,
                segments,
                next: next + 1,
            });
        }
        Ok(self.line_owner(line, Some(source)))
    }
}

/// One UTF-8 companion line whose permitted storage survives the socket write.
pub struct ClientLine {
    line: String,
    _source: Option<ObjectBytes>,
    _backing: Arc<MemoryPermit>,
}

impl ClientLine {
    pub(crate) fn into_text(self) -> String {
        self.line
    }

    /// Complete physical bytes, including CRLF.
    pub fn as_bytes(&self) -> &[u8] {
        self.line.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::{BackingReservationPort, MemoryBudget};
    use crate::cancel::CancellationToken;
    use crate::connection::{
        ClientQueueDemand, ClientSink, ConnectionGeneration, QueueLimits, WriterQueue,
    };
    use crate::test_support::TestResult;
    use std::future::Future as _;
    use std::task::Poll;

    struct ChargedObject {
        bytes: Vec<u8>,
        _backing: MemoryPermit,
    }

    impl AsRef<[u8]> for ChargedObject {
        fn as_ref(&self) -> &[u8] {
            &self.bytes
        }
    }

    #[tokio::test]
    async fn the_final_client_write_keeps_the_only_remaining_source_receipt() -> TestResult {
        let source = Arc::new(MemoryBudget::new(1 << 20));
        let source_port = BackingReservationPort::new(Arc::clone(&source));
        let working = Arc::new(MemoryBudget::new(1 << 20));
        let working_port = BackingReservationPort::new(Arc::clone(&working));
        let mut batch = ClientBatch::new(
            "edge.example".to_owned(),
            "x".to_owned(),
            [3; 16],
            working_port.reserve(8704)?,
        );
        batch
            .object(
                ArcWireObjectKind::WelcomeMls,
                ChargedObject {
                    bytes: vec![19; 128],
                    _backing: source_port.reserve(128)?,
                },
            )
            .map_err(|e| e.to_string())?;
        let queue = WriterQueue::new(ConnectionGeneration::new(3), QueueLimits::DEFAULT)?;
        let logical = queue.try_reserve(ClientQueueDemand::new(vec![batch.window()])?)?;
        assert_eq!(logical.backing_charge(), 0);
        queue.commit_companion(queue.prepare(logical, None)?, Box::new(batch))?;
        let (stream, stalled) = tokio::io::duplex(1);
        let mut writer = Box::pin(crate::connection::run_writer(
            stream,
            Arc::clone(&queue),
            CancellationToken::root(),
        ));
        std::future::poll_fn(|cx| {
            assert!(matches!(writer.as_mut().poll(cx), Poll::Pending));
            Poll::Ready(())
        })
        .await;
        assert_eq!(queue.queue_snapshot().queued_bytes(), 0);
        assert!(source.charged() >= 128);
        assert!(working.charged() >= 8704);
        drop(stalled);
        assert_eq!(
            writer.await,
            crate::state_core::inbox::CloseReason::TransportLoss
        );
        assert_eq!(source.charged(), 0);
        assert_eq!(working.charged(), 0);
        Ok(())
    }
    /// With a real large object held between commands, both forms of the
    /// 65th group close only this sink and release all of its source receipts.
    #[tokio::test]
    async fn a_full_privacy_floor_never_publishes_a_later_group_before_a_large_reply() -> TestResult
    {
        use crate::connection::QueuePop;
        use crate::state_core::inbox::{CloseReason, SourceAddressKey};
        use crate::state_core::secret_floor::MAX_QUEUED_GROUPS;
        for overflow_is_bulk in [false, true] {
            let mut fixture = crate::test_support::StateCoreFixture::new(vec![0; 4096])?;
            let context = fixture.context_mut()?;
            let generation = ConnectionGeneration::new(73);
            let queue = WriterQueue::new(generation, QueueLimits::DEFAULT)?;
            context.set_monotonic_for_test(100);
            let now = context.now();
            context.sessions_mut().open(
                generation,
                crate::purpose::ListenerPurpose::ClientTls,
                SourceAddressKey::onion_listener(),
                Arc::clone(&queue) as Arc<dyn ClientSink>,
                now,
            )?;
            let source = Arc::new(MemoryBudget::new(16 << 20));
            let port = BackingReservationPort::new(Arc::clone(&source));
            let bulk = |bytes: usize| -> TestResult<super::super::ClientOutput> {
                let mut batch = ClientBatch::new(
                    "edge.example".to_owned(),
                    "x".to_owned(),
                    [3; 16],
                    port.reserve(64 << 10)?,
                );
                batch
                    .object(
                        ArcWireObjectKind::WelcomeMls,
                        ChargedObject {
                            bytes: vec![17; bytes],
                            _backing: port.reserve(bytes)?,
                        },
                    )
                    .map_err(|e| e.to_string())?;
                Ok(super::super::ClientOutput {
                    generation,
                    batch: Some(Box::new(batch)),
                    frames: Vec::new(),
                })
            };
            let notice = || WireMessage::new("edge.example", "NOTICE", &["nick"], Some("later"));
            context.begin_secret_floor(generation);
            assert!(
                context
                    .hold_secret_floor(generation, vec![notice()?])
                    .is_ok()
            );
            context.send_companion_output(bulk(3 << 20)?);
            for _ in 2..MAX_QUEUED_GROUPS {
                let retained = context.send_to(generation, vec![notice()?])?;
                assert_eq!(retained.committed_sinks, 0);
                assert_eq!(retained.slow_consumers_closed, 0);
            }
            assert!(!queue.is_closed());
            assert!(matches!(queue.pop(), QueuePop::Empty));
            assert!(source.charged() >= 3 << 20);
            if overflow_is_bulk {
                context.send_companion_output(bulk(5000)?);
            } else {
                let overflow = context.send_to(generation, vec![notice()?])?;
                assert_eq!(overflow.committed_sinks, 0);
                assert_eq!(overflow.slow_consumers_closed, 1);
                assert_eq!(
                    overflow.slow_consumer_generations().collect::<Vec<_>>(),
                    vec![generation]
                );
            }
            assert!(queue.is_closed());
            assert!(matches!(
                queue.pop(),
                QueuePop::Closed(CloseReason::SlowConsumer)
            ));
            assert_eq!(source.charged(), 0);
            assert!(context.sessions().sink_for_generation(generation).is_none());
            assert!(!context.secret_floor_pending(generation));
            context.set_monotonic_for_test(200);
            assert!(!context.release_secret_floor(generation));
        }
        Ok(())
    }
}
