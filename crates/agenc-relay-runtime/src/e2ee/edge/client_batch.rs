//! One ordered authenticated client batch, rendered one physical line at a time.

use agenc_relay_client_wire::{MAX_PHYSICAL_LINE_BYTES, WireMessage};
use agenc_relay_e2ee::object::ArcWireObjectKind;
use agenc_relay_e2ee::wire::{reply::E2eeReplyCode, response::render_eobject};
use std::collections::VecDeque;

use crate::budget::MemoryPermit;
use crate::e2ee::outbound::Segments;

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
    backing: std::sync::Arc<MemoryPermit>,
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
            backing: std::sync::Arc::new(backing),
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
            Ok(Some(line)) => crate::connection::queue::QueuePop::Companion(ClientLine {
                line,
                _backing: std::sync::Arc::clone(&self.backing),
            }),
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
    pub fn next_line(&mut self) -> Result<Option<String>, E2eeReplyCode> {
        match self.parts.pop_front() {
            None => Ok(None),
            Some(Part::Line(line)) => Ok(Some(line)),
            Some(Part::Object {
                kind,
                segments,
                next,
            }) => self.render_part(kind, segments, next).map(Some),
        }
    }

    fn render_part(
        &mut self,
        kind: ArcWireObjectKind,
        segments: Segments,
        next: u32,
    ) -> Result<String, E2eeReplyCode> {
        let fragment = segments
            .fragment(next)
            .ok_or(E2eeReplyCode::InvalidFragment)?;
        let line = render_eobject(&self.server, &self.batch_id, &fragment, kind, &self.scope)
            .map_err(|_| E2eeReplyCode::InvalidFragment)?;
        if next + 1 < segments.count {
            self.parts.push_front(Part::Object {
                kind,
                segments,
                next: next + 1,
            });
        }
        Ok(line)
    }
}

/// One UTF-8 companion line whose permitted storage survives the socket write.
pub struct ClientLine {
    line: String,
    _backing: std::sync::Arc<MemoryPermit>,
}

impl ClientLine {
    /// Complete physical bytes, including CRLF.
    pub fn as_bytes(&self) -> &[u8] {
        self.line.as_bytes()
    }
}
