//! The bounded link loop: framing, reassembly, keepalive, and the two queues
//! between a link and the state owner (spec 20.3, 20.4, 21.3).

mod reservation;
pub(crate) use reservation::ReservedFrames;

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use agenc_relay_client_wire::{FramingError, StreamFramer};
use agenc_relay_e2ee::federation::frames::{
    CompanionFrame, is_companion_command, parse_companion_frame,
};
use agenc_relay_federation_wire::{
    AssemblyProgress, FederationCommandTag, FederationFrame, FederationLine, FederationLineText,
    FragmentAssembler, FragmentDescriptorKey, FrameError,
};
use agenc_relay_types::{
    BASE_FRAGMENT_IDLE_SECONDS, EntropySource, FEDERATION_KEEPALIVE_IDLE_SECONDS,
    FEDERATION_KEEPALIVE_TIMEOUT_SECONDS, ServerId,
};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::Instant;

use crate::RuntimeError;
use crate::cancel::CancellationToken;
use crate::federation::line::split_line;
use crate::federation::{
    FederationInbound, IngressCharge, LinkCloseReason, LinkEvent, LinkId, ObjectCarrier,
};

/// Items the state owner can hold from one link before reads pause.
pub const INBOUND_QUEUE_ITEMS: usize = 256;
/// The shared per-link ingress budget for reassembly and queued items.
pub const INBOUND_BUDGET_BYTES: u32 = 16 * 1024 * 1024;
/// Rendered lines the writer can hold before the link is unhealthy.
pub const OUTBOUND_QUEUE_ITEMS: usize = 1_024;
/// Nominal ingress charge of one control frame.
pub const CONTROL_FRAME_CHARGE_BYTES: u32 = 1_024;
/// How long a link waits for the state owner before closing.
pub const INGRESS_STALL_BUDGET: Duration = Duration::from_secs(30);
const READ_CHUNK_BYTES: usize = 4_096;

/// The keepalive and reassembly-sweep intervals of one link.
///
/// Production uses [`LinkTiming::SPEC`]; tests inject shorter values because
/// the pinned runtime profile offers no virtual clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkTiming {
    /// Idle time before this side sends FPING.
    pub keepalive_idle: Duration,
    /// Time allowed for the matching FPONG.
    pub keepalive_timeout: Duration,
    /// How often incomplete objects are checked for expiry.
    pub assembly_sweep: Duration,
}

impl LinkTiming {
    /// The fixed Section-20.3 and Section-20.4 values.
    pub const SPEC: Self = Self {
        keepalive_idle: Duration::from_secs(FEDERATION_KEEPALIVE_IDLE_SECONDS),
        keepalive_timeout: Duration::from_secs(FEDERATION_KEEPALIVE_TIMEOUT_SECONDS),
        assembly_sweep: Duration::from_secs(BASE_FRAGMENT_IDLE_SECONDS),
    };
}

/// Why a frame could not be read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadFailure {
    /// The transport failed.
    Io,
    /// The peer closed the transport.
    PeerClosed,
    /// A line violated framing or the line grammar.
    Framing,
    /// A line was well formed but not a valid frame.
    Frame(FrameError),
}

/// One parsed line: a base federation frame or a companion frame.
pub enum ParsedLine {
    /// A base `F*` frame.
    Base(FederationFrame),
    /// A companion `E*` frame.
    Companion(CompanionFrame),
}

/// Reads complete typed frames from one transport.
pub struct FrameReader<S> {
    stream: S,
    framer: StreamFramer,
    pending: VecDeque<ParsedLine>,
    rejected: bool,
    buffer: Vec<u8>,
    expected_prefix: String,
}

impl<S: AsyncRead + Unpin> FrameReader<S> {
    /// Wraps one transport whose peer must use `expected_prefix`.
    pub fn new(stream: S, expected_prefix: &str) -> Result<Self, RuntimeError> {
        let framer = StreamFramer::new().map_err(|_| RuntimeError::MemoryExhausted)?;
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(READ_CHUNK_BYTES)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        buffer.resize(READ_CHUNK_BYTES, 0);
        Ok(Self {
            stream,
            framer,
            pending: VecDeque::new(),
            rejected: false,
            buffer,
            expected_prefix: expected_prefix.to_owned(),
        })
    }

    /// Borrows the transport, for writes during the hello exchange.
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consumes the reader and returns the transport.
    pub fn into_stream(self) -> S {
        self.stream
    }

    /// Returns the next base frame; a companion frame here is a grammar
    /// failure, as it was before the companion profile existed.
    pub async fn next_frame(&mut self) -> Result<FederationFrame, ReadFailure> {
        match self.next_line().await? {
            ParsedLine::Base(frame) => Ok(frame),
            ParsedLine::Companion(_) => Err(ReadFailure::Frame(FrameError::Text(
                agenc_relay_federation_wire::FederationTextError::UnknownCommandForm,
            ))),
        }
    }

    /// Returns the next complete line, reading as needed.
    pub async fn next_line(&mut self) -> Result<ParsedLine, ReadFailure> {
        loop {
            if let Some(frame) = self.pending.pop_front() {
                return Ok(frame);
            }
            let read = self
                .stream
                .read(&mut self.buffer)
                .await
                .map_err(|_| ReadFailure::Io)?;
            if read == 0 {
                return Err(ReadFailure::PeerClosed);
            }
            let chunk = self.buffer.get(..read).ok_or(ReadFailure::Io)?;
            let expected_prefix = self.expected_prefix.as_str();
            let pending = &mut self.pending;
            let mut failure = None;
            let progress = self.framer.feed(chunk, |line| {
                if failure.is_some() {
                    return;
                }
                match parse_line(line.as_str(), expected_prefix) {
                    Ok(frame) => pending.push_back(frame),
                    Err(error) => failure = Some(error),
                }
            });
            if let Err(error) = progress {
                self.rejected = true;
                return Err(match error {
                    FramingError::UnexpectedEof => ReadFailure::PeerClosed,
                    _ => ReadFailure::Framing,
                });
            }
            if let Some(error) = failure {
                self.rejected = true;
                return Err(error);
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> FrameReader<S> {
    /// Splits the transport after the hello so the link loop can own the
    /// read and write halves separately. Frames already buffered survive.
    pub fn split(self) -> (FrameReader<tokio::io::ReadHalf<S>>, tokio::io::WriteHalf<S>) {
        let (read, write) = tokio::io::split(self.stream);
        (
            FrameReader {
                stream: read,
                framer: self.framer,
                pending: self.pending,
                rejected: self.rejected,
                buffer: self.buffer,
                expected_prefix: self.expected_prefix,
            },
            write,
        )
    }
}

/// Parses one complete line into a base or companion frame. A companion
/// line must carry the authenticated peer prefix and, when tagged, the
/// companion tag key; a base line never carries the companion key.
pub fn parse_line(line: &str, expected_prefix: &str) -> Result<ParsedLine, ReadFailure> {
    let parts = split_line(line).map_err(|_| ReadFailure::Framing)?;
    if is_companion_command(parts.command) {
        if parts.prefix != expected_prefix {
            return Err(ReadFailure::Frame(FrameError::WrongPrefix));
        }
        if parts.tag_value.is_some() && !parts.companion_tag {
            return Err(ReadFailure::Framing);
        }
        return parse_companion_frame(parts.command, &parts.parameters, parts.tag_value)
            .map(ParsedLine::Companion)
            .map_err(|_| ReadFailure::Framing);
    }
    if parts.companion_tag {
        return Err(ReadFailure::Framing);
    }
    parse_base_frame(parts, expected_prefix).map(ParsedLine::Base)
}

/// Parses one complete line into a base frame; a companion line fails.
pub fn parse_frame(line: &str, expected_prefix: &str) -> Result<FederationFrame, ReadFailure> {
    match parse_line(line, expected_prefix)? {
        ParsedLine::Base(frame) => Ok(frame),
        ParsedLine::Companion(_) => Err(ReadFailure::Framing),
    }
}

fn parse_base_frame(
    parts: crate::federation::line::LineParts<'_>,
    expected_prefix: &str,
) -> Result<FederationFrame, ReadFailure> {
    let tags: Vec<FederationCommandTag<'_>> = parts
        .tag_value
        .into_iter()
        .map(|value| {
            FederationCommandTag::new(
                agenc_relay_federation_wire::FEDERATION_FRAGMENT_TAG_NAME,
                Some(value),
            )
        })
        .collect();
    FederationFrame::parse(
        FederationLine::new(Some(parts.prefix), &tags, parts.command, &parts.parameters),
        expected_prefix,
    )
    .map_err(ReadFailure::Frame)
}

/// Writes one rendered line and flushes it.
pub async fn write_line<W: AsyncWrite + Unpin>(
    stream: &mut W,
    line: &FederationLineText,
) -> Result<(), ReadFailure> {
    stream
        .write_all(line.as_str().as_bytes())
        .await
        .map_err(|_| ReadFailure::Io)?;
    stream.flush().await.map_err(|_| ReadFailure::Io)
}

/// One rendered line queued for the writer.
pub struct LinkOutbound {
    /// The line to write, or `None` when the owner asks the link to close.
    line: Option<FederationLineText>,
    _reservation: Option<reservation::QueuedReservation>,
}

/// Why one line was not queued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendRefusal {
    /// The item or byte ceiling would be exceeded.
    QueueFull,
    /// The link task already ended; the owner's `Closed` event follows.
    Closed,
}

impl std::fmt::Display for SendRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::QueueFull => "federation link queue is full",
            Self::Closed => "federation link is closed",
        })
    }
}

impl std::error::Error for SendRefusal {}

/// The state owner's handle to one link's writer queue.
#[derive(Clone)]
pub struct LinkHandle {
    sender: mpsc::Sender<LinkOutbound>,
    queued_bytes: Arc<AtomicU64>,
    capacity_bytes: u64,
    closed: Arc<std::sync::Mutex<bool>>,
}

impl LinkHandle {
    /// Queues one line unless the item or byte ceiling would be exceeded
    /// or the link task already ended.
    pub fn try_send(&self, line: FederationLineText) -> Result<(), SendRefusal> {
        let bytes = u64::try_from(line.len()).map_err(|_| SendRefusal::QueueFull)?;
        let capacity = self.capacity_bytes;
        let reserved =
            self.queued_bytes
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |queued| {
                    queued.checked_add(bytes).filter(|total| *total <= capacity)
                });
        if reserved.is_err() {
            return Err(SendRefusal::QueueFull);
        }
        match self.sender.try_send(LinkOutbound {
            line: Some(line),
            _reservation: None,
        }) {
            Ok(()) => Ok(()),
            Err(error) => {
                release_queued(&self.queued_bytes, bytes);
                Err(match error {
                    mpsc::error::TrySendError::Full(_) => SendRefusal::QueueFull,
                    mpsc::error::TrySendError::Closed(_) => SendRefusal::Closed,
                })
            }
        }
    }

    /// Asks the link task to close after the lines already queued.
    pub fn close(&self) {
        let _sent = self.sender.try_send(LinkOutbound {
            line: None,
            _reservation: None,
        });
    }

    /// Returns the bytes currently queued.
    #[must_use]
    pub fn queued_bytes(&self) -> u64 {
        self.queued_bytes.load(Ordering::Acquire)
    }
}

fn release_queued(queued_bytes: &AtomicU64, bytes: u64) {
    let _ = queued_bytes.fetch_update(Ordering::AcqRel, Ordering::Acquire, |queued| {
        Some(queued.saturating_sub(bytes))
    });
}

/// The writer's end of one link queue.
pub struct LinkQueue {
    receiver: mpsc::Receiver<LinkOutbound>,
    queued_bytes: Arc<AtomicU64>,
    closed: Arc<std::sync::Mutex<bool>>,
}

impl Drop for LinkQueue {
    fn drop(&mut self) {
        // A publisher that wins this lock sends before receiver draining; a
        // publisher that follows it drops its frames without calling send.
        if let Ok(mut closed) = self.closed.lock() {
            *closed = true;
        }
        self.receiver.close();
    }
}

impl LinkQueue {
    /// Receives the next queued line, releasing its byte reservation.
    pub async fn recv(&mut self) -> Option<FederationLineText> {
        let item = self.receiver.recv().await?;
        let line = item.line?;
        let bytes = u64::try_from(line.len()).unwrap_or(u64::MAX);
        if item._reservation.is_none() {
            release_queued(&self.queued_bytes, bytes);
        }
        Some(line)
    }
}

/// Creates one bounded writer queue with the configured byte ceiling.
#[must_use]
pub fn link_queue(capacity_bytes: u64) -> (LinkHandle, LinkQueue) {
    let (sender, receiver) = mpsc::channel(OUTBOUND_QUEUE_ITEMS);
    let queued_bytes = Arc::new(AtomicU64::new(0));
    let closed = Arc::new(std::sync::Mutex::new(false));
    (
        LinkHandle {
            sender,
            queued_bytes: Arc::clone(&queued_bytes),
            capacity_bytes,
            closed: Arc::clone(&closed),
        },
        LinkQueue {
            receiver,
            queued_bytes,
            closed,
        },
    )
}

/// Creates the per-link ingress budget.
#[must_use]
pub fn ingress_budget() -> Arc<Semaphore> {
    Arc::new(Semaphore::new(INBOUND_BUDGET_BYTES as usize))
}

/// What the link loop needs beyond its transport.
pub struct LinkContext {
    /// The link attempt.
    pub link: LinkId,
    /// The configured peer.
    pub peer: ServerId,
    /// The local prefix used on every rendered line.
    pub local_name: String,
    /// The state owner's inbound queue.
    pub inbound: mpsc::Sender<FederationInbound>,
    /// The per-link ingress budget in bytes.
    pub budget: Arc<Semaphore>,
    /// The owning cancellation token.
    pub token: CancellationToken,
    /// The keepalive and sweep intervals.
    pub timing: LinkTiming,
    /// The process observer for the closed companion log codes.
    pub observer: Option<Arc<crate::observe::adapter::RuntimeObserver>>,
}

struct Keepalive {
    idle: Duration,
    timeout: Duration,
    idle_deadline: Instant,
    outstanding: Option<([u8; 32], Instant)>,
}

impl Keepalive {
    fn next_deadline(&self) -> Instant {
        match self.outstanding {
            Some((_, deadline)) => deadline,
            None => self.idle_deadline,
        }
    }

    fn frame_received(&mut self, now: Instant) {
        self.idle_deadline = now + self.idle;
    }
}

/// Runs one authenticated link until it closes, returning why.
pub async fn run_link<R, W, E>(
    mut reader: FrameReader<R>,
    writer: W,
    mut queue: LinkQueue,
    context: LinkContext,
    entropy: &mut E,
) -> LinkCloseReason
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    E: EntropySource,
{
    let started = Instant::now();
    let mut link = LinkLoop {
        writer,
        keepalive: Keepalive {
            idle: context.timing.keepalive_idle,
            timeout: context.timing.keepalive_timeout,
            idle_deadline: started + context.timing.keepalive_idle,
            outstanding: None,
        },
        assembler: FragmentAssembler::new(),
        reservations: BTreeMap::new(),
        next_sweep: started + context.timing.assembly_sweep,
        started,
        context,
    };
    loop {
        let deadline = link.keepalive.next_deadline().min(link.next_sweep);
        let step = tokio::select! {
            () = link.context.token.cancelled() => return LinkCloseReason::Cancelled,
            outbound = queue.receiver.recv() => Step::Outbound(outbound),
            frame = reader.next_line() => Step::Inbound(frame.map(Box::new)),
            () = tokio::time::sleep_until(deadline) => Step::Deadline,
        };
        let now = Instant::now();
        let outcome = match step {
            Step::Outbound(None) => Err(LinkCloseReason::QueueClosed),
            Step::Outbound(Some(item)) => link.on_outbound(item, &queue).await,
            Step::Inbound(Err(failure)) => Err(close_reason(failure)),
            Step::Inbound(Ok(frame)) => link.on_inbound(*frame, now).await,
            Step::Deadline => link.on_deadline(entropy, now).await,
        };
        if let Err(reason) = outcome {
            return reason;
        }
    }
}

const fn close_reason(failure: ReadFailure) -> LinkCloseReason {
    match failure {
        ReadFailure::PeerClosed => LinkCloseReason::PeerClosed,
        ReadFailure::Io => LinkCloseReason::Transport,
        ReadFailure::Framing | ReadFailure::Frame(_) => LinkCloseReason::Framing,
    }
}

/// The mutable state of one running link between select steps.
struct LinkLoop<W> {
    writer: W,
    keepalive: Keepalive,
    assembler: FragmentAssembler,
    reservations: BTreeMap<[u8; 32], OwnedSemaphorePermit>,
    next_sweep: Instant,
    started: Instant,
    context: LinkContext,
}

impl<W: AsyncWrite + Unpin> LinkLoop<W> {
    async fn on_outbound(
        &mut self,
        item: LinkOutbound,
        queue: &LinkQueue,
    ) -> Result<(), LinkCloseReason> {
        let Some(line) = item.line else {
            return Err(LinkCloseReason::QueueClosed);
        };
        let bytes = u64::try_from(line.len()).unwrap_or(u64::MAX);
        let written = write_line(&mut self.writer, &line).await;
        if item._reservation.is_none() {
            release_queued(&queue.queued_bytes, bytes);
        }
        written.map_err(|_| LinkCloseReason::Transport)
    }

    async fn on_inbound(&mut self, line: ParsedLine, now: Instant) -> Result<(), LinkCloseReason> {
        self.keepalive.frame_received(now);
        let now_millis = millis_since(self.started, now);
        let frame = match line {
            ParsedLine::Base(frame) => frame,
            ParsedLine::Companion(frame) => {
                if let (CompanionFrame::EcapAck(_), Some(observer)) =
                    (&frame, &self.context.observer)
                {
                    observer.e2ee_profile_acknowledged();
                }
                let bytes = frame
                    .fragment()
                    .map_or(0, |fragment| fragment.segment.len());
                let charge = u32::try_from(bytes)
                    .ok()
                    .and_then(|bytes| bytes.checked_add(CONTROL_FRAME_CHARGE_BYTES))
                    .ok_or(LinkCloseReason::Transport)?;
                return forward(&self.context, LinkEvent::Companion(frame), charge).await;
            }
        };
        handle_frame(
            frame,
            &mut self.writer,
            &mut self.keepalive,
            &mut self.assembler,
            &mut self.reservations,
            &self.context,
            now_millis,
        )
        .await
    }

    /// Runs the reassembly sweep and the keepalive step that fell due.
    async fn on_deadline<E: EntropySource>(
        &mut self,
        entropy: &mut E,
        now: Instant,
    ) -> Result<(), LinkCloseReason> {
        if now >= self.next_sweep {
            if self.assembler.expire(millis_since(self.started, now)) > 0 {
                return Err(LinkCloseReason::Assembly(
                    agenc_relay_federation_wire::AssemblyError::Timeout,
                ));
            }
            self.next_sweep = now + self.context.timing.assembly_sweep;
        }
        if now >= self.keepalive.next_deadline() {
            if self.keepalive.outstanding.is_some() {
                return Err(LinkCloseReason::KeepaliveTimeout);
            }
            send_ping(
                &mut self.writer,
                &mut self.keepalive,
                &self.context,
                entropy,
                now,
            )
            .await?;
        }
        Ok(())
    }
}

enum Step {
    Outbound(Option<LinkOutbound>),
    Inbound(Result<Box<ParsedLine>, ReadFailure>),
    Deadline,
}

fn millis_since(started: Instant, now: Instant) -> u64 {
    u64::try_from(now.saturating_duration_since(started).as_millis()).unwrap_or(u64::MAX)
}

async fn send_ping<W: AsyncWrite + Unpin, E: EntropySource>(
    writer: &mut W,
    keepalive: &mut Keepalive,
    context: &LinkContext,
    entropy: &mut E,
    now: Instant,
) -> Result<(), LinkCloseReason> {
    let mut nonce = [0_u8; 32];
    entropy
        .fill_exact(&mut nonce)
        .map_err(|_| LinkCloseReason::Transport)?;
    let line = FederationFrame::Ping {
        peer_server_id: context.peer,
        nonce,
    }
    .render(&context.local_name)
    .map_err(|_| LinkCloseReason::Transport)?;
    write_line(writer, &line)
        .await
        .map_err(|_| LinkCloseReason::Transport)?;
    keepalive.outstanding = Some((nonce, now + keepalive.timeout));
    Ok(())
}

// agenc-review: focus owner=runtime reviewed=2026-09-02 reason=one closed dispatcher routes every inbound frame kind to the keepalive, the assembler, or the state owner
async fn handle_frame<W: AsyncWrite + Unpin>(
    frame: FederationFrame,
    writer: &mut W,
    keepalive: &mut Keepalive,
    assembler: &mut FragmentAssembler,
    reservations: &mut BTreeMap<[u8; 32], OwnedSemaphorePermit>,
    context: &LinkContext,
    now_millis: u64,
) -> Result<(), LinkCloseReason> {
    match frame {
        FederationFrame::Ping {
            peer_server_id,
            nonce,
        } => {
            let line = FederationFrame::Pong {
                peer_server_id,
                nonce,
            }
            .render(&context.local_name)
            .map_err(|_| LinkCloseReason::Transport)?;
            write_line(writer, &line)
                .await
                .map_err(|_| LinkCloseReason::Transport)
        }
        FederationFrame::Pong { nonce, .. } => match keepalive.outstanding.take() {
            Some((expected, _)) if expected == nonce => Ok(()),
            _ => Err(LinkCloseReason::Protocol(
                agenc_relay_federation_wire::FederationFrameKind::Pong,
            )),
        },
        FederationFrame::Hello { .. } | FederationFrame::Ready { .. } => {
            Err(LinkCloseReason::Protocol(frame.kind()))
        }
        frame if frame.fragment().is_some() => {
            admit_fragment(frame, assembler, reservations, context, now_millis).await
        }
        frame => forward(context, LinkEvent::Frame(frame), CONTROL_FRAME_CHARGE_BYTES).await,
    }
}

async fn admit_fragment(
    frame: FederationFrame,
    assembler: &mut FragmentAssembler,
    reservations: &mut BTreeMap<[u8; 32], OwnedSemaphorePermit>,
    context: &LinkContext,
    now_millis: u64,
) -> Result<(), LinkCloseReason> {
    let (carrier, key) = carrier_of(&frame)?;
    let Some(fragment) = frame.fragment() else {
        return Err(LinkCloseReason::Protocol(frame.kind()));
    };
    let object_id = *fragment.object_id().as_bytes();
    if fragment.part() == 0 && !reservations.contains_key(&object_id) {
        let permit = acquire(context, fragment.total()).await?;
        reservations.insert(object_id, permit);
    }
    let progress = assembler.admit(key, fragment, now_millis);
    match progress {
        Ok(AssemblyProgress::Incomplete { .. }) => Ok(()),
        Ok(AssemblyProgress::Complete(object)) => {
            let bytes = u32::try_from(object.len()).map_err(|_| LinkCloseReason::Transport)?;
            let permit = reservations
                .remove(&object_id)
                .ok_or(LinkCloseReason::Transport)?;
            forward_charged(
                context,
                LinkEvent::Object { carrier, object },
                IngressCharge::new(permit, bytes),
            )
            .await
        }
        Err(error) => {
            reservations.remove(&object_id);
            Err(LinkCloseReason::Assembly(error))
        }
    }
}

pub(crate) fn carrier_of(
    frame: &FederationFrame,
) -> Result<(ObjectCarrier, FragmentDescriptorKey), LinkCloseReason> {
    let carrier = match frame {
        FederationFrame::Request { descriptor, .. } => ObjectCarrier::Request(*descriptor),
        FederationFrame::Result { descriptor, .. } => ObjectCarrier::Result(*descriptor),
        FederationFrame::Event { descriptor, .. } => ObjectCarrier::Event(*descriptor),
        FederationFrame::OriginAdd { descriptor, .. } => ObjectCarrier::OriginAdd(*descriptor),
        FederationFrame::OriginUpdate { descriptor, .. } => {
            ObjectCarrier::OriginUpdate(*descriptor)
        }
        FederationFrame::SnapshotEntry {
            edge_server_id,
            snapshot_token,
            entry_index,
            object_id,
            ..
        } => ObjectCarrier::SnapshotEntry {
            edge_server_id: *edge_server_id,
            snapshot_token: *snapshot_token,
            entry_index: *entry_index,
            object_id: *object_id,
        },
        other => return Err(LinkCloseReason::Protocol(other.kind())),
    };
    let key = descriptor_key(&carrier);
    Ok((carrier, key))
}

/// Fingerprints the command form and every descriptor parameter so later
/// fragments must repeat them exactly.
pub(crate) fn descriptor_key(carrier: &ObjectCarrier) -> FragmentDescriptorKey {
    match carrier {
        ObjectCarrier::Request(descriptor) | ObjectCarrier::Result(descriptor) => {
            let form = if matches!(carrier, ObjectCarrier::Request(_)) {
                "FREQUEST"
            } else {
                "FRESULT"
            };
            FragmentDescriptorKey::derive(
                form,
                &[
                    &descriptor.addressed_server_id.to_base64url(),
                    &descriptor.server_incarnation.to_base64url(),
                    &descriptor.origin_id.to_base64url(),
                    &descriptor.origin_generation.to_string(),
                    &descriptor.operation_sequence.to_string(),
                    &descriptor.request_id.to_base64url(),
                    &descriptor.object_id.to_text(),
                ],
            )
        }
        ObjectCarrier::Event(descriptor) => FragmentDescriptorKey::derive(
            "FEVENT",
            &[
                &descriptor.target_server_id.to_base64url(),
                &descriptor.delivery_sequence.to_string(),
                &descriptor.event_id.to_base64url(),
                &descriptor.object_id.to_text(),
            ],
        ),
        ObjectCarrier::OriginAdd(descriptor) | ObjectCarrier::OriginUpdate(descriptor) => {
            let form = if matches!(carrier, ObjectCarrier::OriginAdd(_)) {
                "FORIGIN_ADD"
            } else {
                "FORIGIN_UPDATE"
            };
            FragmentDescriptorKey::derive(
                form,
                &[
                    &descriptor.coordinator_server_id.to_base64url(),
                    &descriptor.server_incarnation.to_base64url(),
                    &descriptor.origin_id.to_base64url(),
                    &descriptor.generation.to_string(),
                    &descriptor.object_id.to_text(),
                ],
            )
        }
        ObjectCarrier::SnapshotEntry {
            edge_server_id,
            snapshot_token,
            entry_index,
            object_id,
        } => FragmentDescriptorKey::derive(
            "FSNAPSHOT_ENTRY",
            &[
                &edge_server_id.to_base64url(),
                &snapshot_token.to_text(),
                &entry_index.to_string(),
                &object_id.to_text(),
            ],
        ),
    }
}

async fn acquire(
    context: &LinkContext,
    bytes: u32,
) -> Result<OwnedSemaphorePermit, LinkCloseReason> {
    let budget = Arc::clone(&context.budget);
    match tokio::time::timeout(INGRESS_STALL_BUDGET, budget.acquire_many_owned(bytes)).await {
        Ok(Ok(permit)) => Ok(permit),
        Ok(Err(_)) => Err(LinkCloseReason::QueueClosed),
        Err(_) => Err(LinkCloseReason::IngressStall),
    }
}

async fn forward(
    context: &LinkContext,
    event: LinkEvent,
    bytes: u32,
) -> Result<(), LinkCloseReason> {
    let permit = acquire(context, bytes).await?;
    forward_charged(context, event, IngressCharge::new(permit, bytes)).await
}

async fn forward_charged(
    context: &LinkContext,
    event: LinkEvent,
    charge: IngressCharge,
) -> Result<(), LinkCloseReason> {
    let message = FederationInbound {
        link: context.link,
        peer: context.peer,
        event,
        charge: Some(charge),
    };
    match tokio::time::timeout(INGRESS_STALL_BUDGET, context.inbound.send(message)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(LinkCloseReason::QueueClosed),
        Err(_) => Err(LinkCloseReason::IngressStall),
    }
}

/// Delivers a link lifecycle notice that carries no peer bytes.
pub async fn notify(
    inbound: &mpsc::Sender<FederationInbound>,
    link: LinkId,
    peer: ServerId,
    event: LinkEvent,
) -> bool {
    let message = FederationInbound {
        link,
        peer,
        event,
        charge: None,
    };
    inbound.send(message).await.is_ok()
}

#[cfg(test)]
mod companion_line_tests {
    use agenc_relay_e2ee::wire::tokens::base64url_encode;

    use super::*;

    #[test]
    fn companion_lines_parse_only_under_the_peer_prefix_and_key() {
        let sid = base64url_encode(&[1; 16]);
        let ack = format!(":edge.example EACK {sid} 1 2 {sid}");
        assert!(matches!(
            parse_line(&ack, "edge.example"),
            Ok(ParsedLine::Companion(CompanionFrame::Ack(_)))
        ));
        assert!(matches!(
            parse_line(&ack, "other.example"),
            Err(ReadFailure::Frame(FrameError::WrongPrefix))
        ));
        assert!(matches!(
            parse_frame(&ack, "edge.example"),
            Err(ReadFailure::Framing)
        ));
        let tagged = format!("@agenc.ag/fed=v1.x.0.1.3.YWJj :edge.example EACK {sid} 1 2 {sid}");
        assert!(matches!(
            parse_line(&tagged, "edge.example"),
            Err(ReadFailure::Framing)
        ));
        let base_with_companion_tag =
            format!("@agenc.ag/e2ee=v1.x.0.1.3.YWJj :edge.example FACK {sid} 1 {sid}");
        assert!(matches!(
            parse_line(&base_with_companion_tag, "edge.example"),
            Err(ReadFailure::Framing)
        ));
        let malformed = format!(":edge.example EACK {sid} 01 2 {sid}");
        assert!(matches!(
            parse_line(&malformed, "edge.example"),
            Err(ReadFailure::Framing)
        ));
    }
}

#[cfg(test)]
#[path = "link/tests/awaited_write.rs"]
mod awaited_write_tests;
