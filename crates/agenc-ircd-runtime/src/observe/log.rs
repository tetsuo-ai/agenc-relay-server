//! The bounded log writer (spec 25.2, lines 6676-6697).
//!
//! Emitters never block: an event that finds the queue full is counted and
//! the count is reported later as its own closed event. The writer opens
//! one segment per coarse UTC hour with an atomic create, retires segments
//! older than the retention window in bounded sweeps, and never enables
//! debug output for a public listener.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};

use agenc_ircd_types::{ServerId, UtcSecond};
use tokio::sync::mpsc;

use crate::RuntimeError;
use crate::observe::events::{CorrelationSource, CountBucket, LogEvent, LogEventCode, Severity};
use crate::purpose::ListenerPurpose;
use crate::sync::Arc;

/// Events queued ahead of the writer task.
pub const LOG_QUEUE_CAPACITY: usize = 1_024;
/// Default retention, 24 hours (spec line 6693).
pub const DEFAULT_LOG_RETENTION_HOURS: u64 = 24;
/// Hard maximum retention, 30 days (spec line 6694).
pub const MAX_LOG_RETENTION_HOURS: u64 = 720;
/// Seconds in one coarse UTC hour, the segment unit.
pub const SECONDS_PER_HOUR: u64 = 3_600;
/// Segments deleted by one retention sweep (spec line 6696: deletion is
/// bounded).
pub const MAX_SEGMENT_DELETIONS_PER_SWEEP: usize = 64;
/// Directory entries examined by one retention sweep. Unrelated entries
/// cannot turn rotation into an unbounded blocking operation.
pub const MAX_DIRECTORY_ENTRIES_PER_SWEEP: usize = 4_096;
/// Segment file prefix under the log directory.
pub const SEGMENT_PREFIX: &str = "agenc-ircd-";
/// Segment file suffix.
pub const SEGMENT_SUFFIX: &str = ".log";
/// Exact private mode of the derived log directory.
pub const LOG_DIRECTORY_MODE: u32 = 0o700;
/// Exact private mode of each log segment.
pub const LOG_SEGMENT_MODE: u32 = 0o600;
/// The operating-system name of the joined blocking log owner.
pub const LOG_OWNER_THREAD_NAME: &str = "agenc-ircd-log";

/// Retention in whole hours, 1..=720.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogRetention(u64);

impl LogRetention {
    /// The 24-hour default.
    pub const DEFAULT: Self = Self(DEFAULT_LOG_RETENTION_HOURS);

    /// Validates a retention window in hours.
    pub const fn hours(hours: u64) -> Result<Self, RuntimeError> {
        if hours == 0 || hours > MAX_LOG_RETENTION_HOURS {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(Self(hours))
    }

    /// Returns the window in hours.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Which events reach the queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogFilter {
    minimum: Severity,
}

impl LogFilter {
    /// Admits `minimum` and above.
    #[must_use]
    pub const fn new(minimum: Severity) -> Self {
        Self { minimum }
    }

    /// Returns whether the event is written.
    ///
    /// Debug output is never admitted for a public listener purpose,
    /// whatever the configured minimum (spec line 6696).
    #[must_use]
    pub fn admits(self, event: &LogEvent) -> bool {
        if event.severity() < self.minimum {
            return false;
        }
        !(event.severity() == Severity::Debug && event.purpose().is_some_and(is_public))
    }
}

const fn is_public(purpose: ListenerPurpose) -> bool {
    matches!(
        purpose,
        ListenerPurpose::ClientTls
            | ListenerPurpose::ClientWss
            | ListenerPurpose::ClientOnion
            | ListenerPurpose::Federation
    )
}

/// The cloneable emitter handed to every owner.
#[derive(Clone)]
pub struct LogHandle {
    sender: mpsc::Sender<LogQueueItem>,
    dropped: Arc<AtomicU64>,
    retention: Arc<AtomicU64>,
    filter: LogFilter,
}

impl LogHandle {
    /// Queues an event without blocking; returns whether it was queued.
    ///
    /// A filtered event is not counted as dropped; a full queue is.
    pub fn try_emit(&self, event: LogEvent) -> bool {
        if !self.filter.admits(&event) {
            return false;
        }
        match self.sender.try_send(LogQueueItem::Event(event)) {
            Ok(()) => true,
            Err(_) => {
                self.dropped.fetch_add(1, Ordering::AcqRel);
                false
            }
        }
    }

    /// Returns the events dropped because the queue was full.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Acquire)
    }

    /// Returns the current bounded queue depth.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.sender
            .max_capacity()
            .saturating_sub(self.sender.capacity())
    }

    /// Publishes a validated retention window for the blocking owner.
    pub fn set_retention(&self, retention: LogRetention) {
        self.retention.store(retention.get(), Ordering::Release);
    }
}

enum LogQueueItem {
    Event(LogEvent),
    Flush(std::sync::mpsc::SyncSender<()>),
    Stop(std::sync::mpsc::SyncSender<()>),
}

/// Where segments are written.
pub trait LogTarget: Send {
    /// Opens the segment for `hour` atomically, creating it if absent.
    fn open_segment(&mut self, hour: u64) -> io::Result<()>;

    /// Appends one line to the open segment.
    fn write_line(&mut self, line: &str) -> io::Result<()>;

    /// Deletes at most `limit` segments strictly older than `hour` and
    /// returns how many were deleted.
    fn retire_before(&mut self, hour: u64, limit: usize) -> io::Result<usize>;
}

/// The writer task state.
pub struct LogWriter<T: LogTarget> {
    receiver: mpsc::Receiver<LogQueueItem>,
    target: T,
    retention: Arc<AtomicU64>,
    applied_retention: u64,
    current_hour: Option<u64>,
    dropped: Arc<AtomicU64>,
    reported_dropped: u64,
    server_id: ServerId,
    correlation: Arc<CorrelationSource>,
    write_failures: u64,
}

impl<T: LogTarget> LogWriter<T> {
    /// Creates the writer and its emitter handle.
    #[must_use]
    pub fn start(
        target: T,
        retention: LogRetention,
        filter: LogFilter,
        server_id: ServerId,
        correlation: Arc<CorrelationSource>,
    ) -> (Self, LogHandle) {
        let (sender, receiver) = mpsc::channel(LOG_QUEUE_CAPACITY);
        let dropped = Arc::new(AtomicU64::new(0));
        let retention_hours = Arc::new(AtomicU64::new(retention.get()));
        let handle = LogHandle {
            sender,
            dropped: Arc::clone(&dropped),
            retention: Arc::clone(&retention_hours),
            filter,
        };
        let writer = Self {
            receiver,
            target,
            retention: retention_hours,
            applied_retention: retention.get(),
            current_hour: None,
            dropped,
            reported_dropped: 0,
            server_id,
            correlation,
            write_failures: 0,
        };
        (writer, handle)
    }

    /// Test-only async driver for in-memory targets. Production uses only
    /// the named blocking owner below.
    #[cfg(test)]
    pub(in crate::observe) async fn run(mut self) -> (T, u64) {
        while let Some(item) = self.receiver.recv().await {
            if self.handle_item(item) {
                break;
            }
        }
        (self.target, self.write_failures)
    }

    fn run_blocking(mut self) -> u64 {
        while let Some(item) = self.receiver.blocking_recv() {
            if self.handle_item(item) {
                break;
            }
        }
        self.write_failures
    }

    // agenc-review: focus owner=runtime reviewed=2026-08-31 reason=single blocking-owner dispatch preserves event flush stop drain and acknowledgement ordering on the bounded queue
    fn handle_item(&mut self, item: LogQueueItem) -> bool {
        match item {
            LogQueueItem::Event(event) => {
                self.write(&event);
                self.report_dropped(event.utc_second());
                false
            }
            LogQueueItem::Flush(reply) => {
                let _sent = reply.send(());
                false
            }
            LogQueueItem::Stop(reply) => {
                self.receiver.close();
                while let Ok(item) = self.receiver.try_recv() {
                    match item {
                        LogQueueItem::Event(event) => {
                            self.write(&event);
                            self.report_dropped(event.utc_second());
                        }
                        LogQueueItem::Flush(waiter) | LogQueueItem::Stop(waiter) => {
                            let _sent = waiter.send(());
                        }
                    }
                }
                let _sent = reply.send(());
                true
            }
        }
    }

    /// Writes one event synchronously; segments roll at hour boundaries.
    pub fn write(&mut self, event: &LogEvent) {
        let hour = event.utc_second().get() / SECONDS_PER_HOUR;
        if self.current_hour != Some(hour) {
            if self.roll(hour).is_err() {
                self.write_failures = self.write_failures.saturating_add(1);
                return;
            }
        } else {
            let retention = self.retention.load(Ordering::Acquire);
            if retention != self.applied_retention {
                if self.sweep(hour, retention).is_err() {
                    self.write_failures = self.write_failures.saturating_add(1);
                } else {
                    self.applied_retention = retention;
                }
            }
        }
        if self.target.write_line(&event.to_string()).is_err() {
            self.write_failures = self.write_failures.saturating_add(1);
        }
    }

    fn roll(&mut self, hour: u64) -> io::Result<()> {
        self.target.open_segment(hour)?;
        self.current_hour = Some(hour);
        let retention = self.retention.load(Ordering::Acquire);
        self.sweep(hour, retention)?;
        self.applied_retention = retention;
        Ok(())
    }

    fn sweep(&mut self, hour: u64, retention: u64) -> io::Result<()> {
        let oldest_kept = hour.saturating_sub(retention.saturating_sub(1));
        self.target
            .retire_before(oldest_kept, MAX_SEGMENT_DELETIONS_PER_SWEEP)?;
        Ok(())
    }

    fn report_dropped(&mut self, utc_second: UtcSecond) {
        let dropped = self.dropped.load(Ordering::Acquire);
        let newly = dropped.saturating_sub(self.reported_dropped);
        if newly == 0 {
            return;
        }
        self.reported_dropped = dropped;
        let event = LogEvent::new(
            LogEventCode::LogDropped,
            Severity::Warning,
            utc_second,
            self.server_id,
            self.correlation.next(),
        )
        .with_count(CountBucket::from_count(newly));
        self.write(&event);
    }
}

/// Segments as hourly files under one directory.
pub struct FileLogTarget {
    directory: PathBuf,
    open: Option<File>,
}

impl FileLogTarget {
    /// Writes under `directory`, which must already exist with the
    /// operator's permissions.
    #[must_use]
    pub fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            open: None,
        }
    }

    fn segment_path(&self, hour: u64) -> PathBuf {
        self.directory
            .join(format!("{SEGMENT_PREFIX}{hour}{SEGMENT_SUFFIX}"))
    }
}

/// Cloneable control path for the joined blocking log owner.
#[derive(Clone)]
pub struct FileLogControl {
    sender: mpsc::Sender<LogQueueItem>,
}

impl FileLogControl {
    fn send_blocking(&self, mut item: LogQueueItem) -> Result<(), RuntimeError> {
        loop {
            match self.sender.try_send(item) {
                Ok(()) => return Ok(()),
                Err(mpsc::error::TrySendError::Full(returned)) => {
                    item = returned;
                    thread::yield_now();
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(RuntimeError::Cancelled);
                }
            }
        }
    }

    fn flush_blocking(&self) -> Result<(), RuntimeError> {
        let (reply, response) = std::sync::mpsc::sync_channel(0);
        self.send_blocking(LogQueueItem::Flush(reply))?;
        response.recv().map_err(|_| RuntimeError::Cancelled)
    }

    fn stop_blocking(&self) -> Result<(), RuntimeError> {
        let (reply, response) = std::sync::mpsc::sync_channel(0);
        self.send_blocking(LogQueueItem::Stop(reply))?;
        response.recv().map_err(|_| RuntimeError::Cancelled)
    }

    /// Waits until every event queued before this call has reached the file
    /// owner. The wait itself runs on Tokio's blocking pool.
    pub async fn flush(&self) -> Result<(), RuntimeError> {
        let control = self.clone();
        tokio::task::spawn_blocking(move || control.flush_blocking())
            .await
            .map_err(|_| RuntimeError::Cancelled)??;
        Ok(())
    }
}

/// The named filesystem owner. The thread is joined explicitly during the
/// runtime stop phase; no filesystem operation runs on an async worker.
pub struct FileLogOwner {
    control: FileLogControl,
    thread: Option<JoinHandle<u64>>,
}

impl FileLogOwner {
    /// Creates and validates `data_dir/logs`, then starts the bounded writer.
    pub fn start(
        data_dir: &Path,
        retention: LogRetention,
        filter: LogFilter,
        server_id: ServerId,
        correlation: Arc<CorrelationSource>,
    ) -> io::Result<(Self, LogHandle)> {
        let directory = prepare_log_directory(data_dir)?;
        let (writer, handle) = LogWriter::start(
            FileLogTarget::new(directory),
            retention,
            filter,
            server_id,
            correlation,
        );
        let control = FileLogControl {
            sender: handle.sender.clone(),
        };
        let thread = thread::Builder::new()
            .name(LOG_OWNER_THREAD_NAME.to_owned())
            .spawn(move || writer.run_blocking())?;
        Ok((
            Self {
                control,
                thread: Some(thread),
            },
            handle,
        ))
    }

    /// Returns the flush authority retained by shutdown composition.
    #[must_use]
    pub fn control(&self) -> FileLogControl {
        self.control.clone()
    }

    /// Returns the fixed operating-system thread name while it is live.
    #[must_use]
    pub fn thread_name(&self) -> Option<&str> {
        self.thread
            .as_ref()
            .and_then(|thread| thread.thread().name())
    }

    /// Stops and joins the named thread on Tokio's blocking pool.
    pub async fn shutdown(mut self) -> Result<u64, RuntimeError> {
        let thread = self.thread.take().ok_or(RuntimeError::InvalidValue)?;
        let control = self.control.clone();
        tokio::task::spawn_blocking(move || {
            control.stop_blocking()?;
            thread.join().map_err(|_| RuntimeError::Cancelled)
        })
        .await
        .map_err(|_| RuntimeError::Cancelled)?
    }
}

impl Drop for FileLogOwner {
    fn drop(&mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        let _stopped = self.control.stop_blocking();
        let _joined = thread.join();
    }
}

/// Creates the fixed private log directory or validates an existing one.
pub fn prepare_log_directory(data_dir: &Path) -> io::Result<PathBuf> {
    let directory = data_dir.join("logs");
    match std::fs::symlink_metadata(&directory) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.mode(LOG_DIRECTORY_MODE).create(&directory)?;
        }
        Err(error) => return Err(error),
    }
    let metadata = std::fs::symlink_metadata(&directory)?;
    if !metadata.file_type().is_dir() || metadata.permissions().mode() & 0o777 != LOG_DIRECTORY_MODE
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "log directory is not a private directory",
        ));
    }
    Ok(directory)
}

/// Parses the hour of one segment file name.
#[must_use]
pub fn segment_hour(name: &str) -> Option<u64> {
    let digits = name
        .strip_prefix(SEGMENT_PREFIX)?
        .strip_suffix(SEGMENT_SUFFIX)?;
    if digits.is_empty() || digits.len() > 20 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

impl LogTarget for FileLogTarget {
    fn open_segment(&mut self, hour: u64) -> io::Result<()> {
        // A restart inside the same hour appends; a fresh hour creates
        // atomically so a rotation is never observable half-done.
        let path = self.segment_path(hour);
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(LOG_SEGMENT_MODE)
            .open(&path)?;
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file()
            || metadata.permissions().mode() & 0o777 != LOG_SEGMENT_MODE
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "log segment is not a private regular file",
            ));
        }
        self.open = Some(file);
        Ok(())
    }

    fn write_line(&mut self, line: &str) -> io::Result<()> {
        let file = self
            .open
            .as_mut()
            .ok_or_else(|| io::Error::other("no open log segment"))?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")
    }

    fn retire_before(&mut self, hour: u64, limit: usize) -> io::Result<usize> {
        let mut deleted = 0;
        for entry in std::fs::read_dir(&self.directory)?.take(MAX_DIRECTORY_ENTRIES_PER_SWEEP) {
            if deleted >= limit {
                break;
            }
            let entry = entry?;
            let name = entry.file_name();
            let Some(segment) = name.to_str().and_then(segment_hour) else {
                continue;
            };
            if segment < hour && remove_segment(&entry.path())? {
                deleted = deleted.saturating_add(1);
            }
        }
        Ok(deleted)
    }
}

fn remove_segment(path: &Path) -> io::Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::observe::events::PublicErrorCode;

    struct MemoryTarget {
        segments: BTreeMap<u64, Vec<String>>,
        open: Option<u64>,
        fail_open: bool,
        fail_write: bool,
    }

    impl MemoryTarget {
        fn new() -> Self {
            Self {
                segments: BTreeMap::new(),
                open: None,
                fail_open: false,
                fail_write: false,
            }
        }
    }

    impl LogTarget for MemoryTarget {
        fn open_segment(&mut self, hour: u64) -> io::Result<()> {
            if self.fail_open {
                return Err(io::Error::other("open refused"));
            }
            self.segments.entry(hour).or_default();
            self.open = Some(hour);
            Ok(())
        }

        fn write_line(&mut self, line: &str) -> io::Result<()> {
            if self.fail_write {
                return Err(io::Error::other("write refused"));
            }
            let hour = self.open.ok_or_else(|| io::Error::other("closed"))?;
            self.segments.entry(hour).or_default().push(line.to_owned());
            Ok(())
        }

        fn retire_before(&mut self, hour: u64, limit: usize) -> io::Result<usize> {
            let victims: Vec<u64> = self
                .segments
                .keys()
                .copied()
                .filter(|segment| *segment < hour)
                .take(limit)
                .collect();
            for victim in &victims {
                self.segments.remove(victim);
            }
            Ok(victims.len())
        }
    }

    fn server_id() -> ServerId {
        ServerId::from_bytes([3; 16])
    }

    fn event(code: LogEventCode, severity: Severity, second: u64) -> LogEvent {
        LogEvent::new(
            code,
            severity,
            UtcSecond::from_unix_seconds(second),
            server_id(),
            CorrelationSource::new(0).next(),
        )
    }

    fn writer(target: MemoryTarget, retention: u64) -> (LogWriter<MemoryTarget>, LogHandle) {
        LogWriter::start(
            target,
            LogRetention::hours(retention).unwrap_or(LogRetention::DEFAULT),
            LogFilter::new(Severity::Debug),
            server_id(),
            Arc::new(CorrelationSource::new(100)),
        )
    }

    #[test]
    fn retention_validates_and_the_filter_never_admits_public_debug() {
        assert_eq!(
            LogRetention::hours(0).err(),
            Some(RuntimeError::InvalidValue)
        );
        assert_eq!(
            LogRetention::hours(721).err(),
            Some(RuntimeError::InvalidValue)
        );
        assert_eq!(LogRetention::hours(720).map(LogRetention::get), Ok(720));
        assert_eq!(LogRetention::DEFAULT.get(), 24);
        let filter = LogFilter::new(Severity::Debug);
        let public_debug = event(LogEventCode::ConnectionClosed, Severity::Debug, 0)
            .with_purpose(ListenerPurpose::ClientTls);
        assert!(!filter.admits(&public_debug));
        let onion_debug = event(LogEventCode::ConnectionClosed, Severity::Debug, 0)
            .with_purpose(ListenerPurpose::ClientOnion);
        assert!(!filter.admits(&onion_debug));
        let admin_debug = event(LogEventCode::AdminAuthenticated, Severity::Debug, 0)
            .with_purpose(ListenerPurpose::AdminLocal);
        assert!(filter.admits(&admin_debug));
        let bare_debug = event(LogEventCode::ProcessStarted, Severity::Debug, 0);
        assert!(filter.admits(&bare_debug));
        let strict = LogFilter::new(Severity::Warning);
        assert!(!strict.admits(&event(LogEventCode::ProcessStarted, Severity::Info, 0)));
        assert!(strict.admits(&event(LogEventCode::Crash, Severity::Critical, 0)));
    }

    #[tokio::test]
    async fn the_writer_rolls_segments_by_hour_and_retires_beyond_retention() {
        let (writer, handle) = writer(MemoryTarget::new(), 2);
        assert!(handle.try_emit(event(LogEventCode::ProcessStarted, Severity::Info, 10)));
        assert!(handle.try_emit(event(LogEventCode::ListenerOpened, Severity::Info, 3_599)));
        assert!(handle.try_emit(event(LogEventCode::ListenerOpened, Severity::Info, 3_600)));
        assert!(handle.try_emit(event(LogEventCode::ListenerClosed, Severity::Info, 7_200)));
        assert!(handle.try_emit(event(LogEventCode::ShutdownPhase, Severity::Info, 10_800)));
        drop(handle);
        let (target, failures) = writer.run().await;
        assert_eq!(failures, 0);
        assert_eq!(
            target.segments.keys().copied().collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert_eq!(target.segments.get(&2).map(Vec::len), Some(1));
        assert!(
            target
                .segments
                .get(&3)
                .and_then(|lines| lines.first())
                .is_some_and(
                    |line| line.starts_with("event=shutdown_phase severity=info utc=10800")
                )
        );
    }

    #[tokio::test]
    async fn dropped_events_are_counted_and_reported_once_as_a_closed_event() {
        let (mut writer, handle) = writer(MemoryTarget::new(), 24);
        for second in 0..LOG_QUEUE_CAPACITY as u64 {
            assert!(handle.try_emit(event(
                LogEventCode::ConnectionAdmitted,
                Severity::Info,
                second
            )));
        }
        assert!(!handle.try_emit(event(LogEventCode::ConnectionAdmitted, Severity::Info, 1)));
        assert!(!handle.try_emit(event(LogEventCode::ConnectionAdmitted, Severity::Info, 2)));
        assert_eq!(handle.dropped(), 2);
        let filtered = event(LogEventCode::ConnectionAdmitted, Severity::Debug, 3)
            .with_purpose(ListenerPurpose::ClientTls);
        assert!(!handle.try_emit(filtered));
        assert_eq!(handle.dropped(), 2, "a filtered event is not a drop");
        let first = writer.receiver.recv().await;
        assert!(matches!(first, Some(LogQueueItem::Event(_))));
        writer.write(&event(LogEventCode::ConnectionAdmitted, Severity::Info, 0));
        writer.report_dropped(UtcSecond::from_unix_seconds(5));
        writer.report_dropped(UtcSecond::from_unix_seconds(6));
        let lines = writer.target.segments.get(&0).cloned().unwrap_or_default();
        assert_eq!(lines.len(), 2);
        assert!(lines.get(1).is_some_and(
            |line| line.contains("event=log_dropped severity=warning")
                && line.contains("count=le_10")
                && line.contains("utc=5")
        ));
    }

    #[test]
    fn target_failures_are_counted_and_never_block() {
        let mut failing = MemoryTarget::new();
        failing.fail_open = true;
        let (mut writer, _handle) = writer(failing, 24);
        writer.write(&event(LogEventCode::Crash, Severity::Critical, 0));
        assert_eq!(writer.write_failures, 1);
        writer.target.fail_open = false;
        writer.target.fail_write = true;
        writer.write(&event(LogEventCode::Crash, Severity::Critical, 0));
        assert_eq!(writer.write_failures, 2);
        let with_error = event(LogEventCode::MemoryExhausted, Severity::Error, 0)
            .with_error(PublicErrorCode::MemoryExhausted);
        writer.target.fail_write = false;
        writer.write(&with_error);
        assert_eq!(writer.write_failures, 2);
    }

    #[test]
    fn segment_names_parse_only_canonical_hours() {
        assert_eq!(segment_hour("agenc-ircd-17.log"), Some(17));
        assert_eq!(segment_hour("agenc-ircd-0.log"), Some(0));
        assert_eq!(segment_hour("agenc-ircd-.log"), None);
        assert_eq!(segment_hour("agenc-ircd-1a.log"), None);
        assert_eq!(segment_hour("other-1.log"), None);
        assert_eq!(segment_hour("agenc-ircd-1.txt"), None);
        assert_eq!(
            segment_hour("agenc-ircd-999999999999999999999.log"),
            None,
            "21 digits never fit u64"
        );
    }

    #[test]
    fn the_file_target_appends_within_an_hour_and_retires_older_segments() -> io::Result<()> {
        let directory = std::env::temp_dir().join(format!(
            "agenc-ircd-log-target-{}-{}",
            std::process::id(),
            CorrelationSource::new(7).next().get()
        ));
        std::fs::create_dir_all(&directory)?;
        let mut target = FileLogTarget::new(directory.clone());
        assert!(
            target.write_line("early").is_err(),
            "no segment is open yet"
        );
        target.open_segment(1)?;
        target.write_line("one")?;
        target.open_segment(1)?;
        target.write_line("two")?;
        target.open_segment(2)?;
        target.write_line("three")?;
        std::fs::write(directory.join("unrelated.txt"), b"keep")?;
        assert_eq!(target.retire_before(2, 64)?, 1);
        assert_eq!(target.retire_before(2, 64)?, 0);
        let remaining = std::fs::read_to_string(directory.join("agenc-ircd-2.log"))?;
        assert_eq!(remaining, "three\n");
        assert!(!directory.join("agenc-ircd-1.log").exists());
        assert!(directory.join("unrelated.txt").exists());
        assert!(remove_segment(&directory.join("agenc-ircd-9.log")).is_ok_and(|removed| !removed));
        std::fs::remove_dir_all(&directory)?;
        Ok(())
    }

    #[test]
    fn a_lowered_live_retention_is_applied_without_waiting_for_rotation() {
        let (mut writer, handle) = writer(MemoryTarget::new(), 4);
        for hour in 0..4 {
            writer.write(&event(
                LogEventCode::ProcessStarted,
                Severity::Info,
                hour * SECONDS_PER_HOUR,
            ));
        }
        assert_eq!(
            writer.target.segments.keys().copied().collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
        handle.set_retention(LogRetention::hours(2).unwrap_or(LogRetention::DEFAULT));
        writer.write(&event(
            LogEventCode::ReloadApplied,
            Severity::Info,
            3 * SECONDS_PER_HOUR,
        ));
        assert_eq!(
            writer.target.segments.keys().copied().collect::<Vec<_>>(),
            vec![2, 3]
        );
    }

    #[tokio::test]
    async fn the_named_file_owner_creates_private_paths_flushes_and_joins() -> io::Result<()> {
        let data_directory = std::env::temp_dir().join(format!(
            "agenc-ircd-log-owner-{}-{}",
            std::process::id(),
            CorrelationSource::new(19).next().get()
        ));
        let mut builder = DirBuilder::new();
        builder.mode(LOG_DIRECTORY_MODE).create(&data_directory)?;
        let correlation = Arc::new(CorrelationSource::new(20));
        let (owner, handle) = FileLogOwner::start(
            &data_directory,
            LogRetention::DEFAULT,
            LogFilter::new(Severity::Info),
            server_id(),
            correlation,
        )?;
        assert_eq!(owner.thread_name(), Some(LOG_OWNER_THREAD_NAME));
        let log_directory = data_directory.join("logs");
        let directory_mode = std::fs::metadata(&log_directory)?.permissions().mode() & 0o777;
        assert_eq!(directory_mode, LOG_DIRECTORY_MODE);
        assert!(handle.try_emit(event(
            LogEventCode::ProcessStarted,
            Severity::Info,
            2 * SECONDS_PER_HOUR,
        )));
        owner
            .control()
            .flush()
            .await
            .map_err(|_| io::Error::other("flush failed"))?;
        let segment = log_directory.join("agenc-ircd-2.log");
        assert!(std::fs::read_to_string(&segment)?.contains("event=process_started"));
        assert_eq!(
            std::fs::metadata(&segment)?.permissions().mode() & 0o777,
            LOG_SEGMENT_MODE
        );
        drop(handle);
        assert_eq!(
            owner
                .shutdown()
                .await
                .map_err(|_| io::Error::other("shutdown failed"))?,
            0
        );
        std::fs::remove_dir_all(data_directory)?;
        Ok(())
    }

    #[test]
    fn existing_broad_or_non_directory_log_paths_are_rejected() -> io::Result<()> {
        let data_directory = std::env::temp_dir().join(format!(
            "agenc-ircd-log-mode-{}-{}",
            std::process::id(),
            CorrelationSource::new(21).next().get()
        ));
        let mut builder = DirBuilder::new();
        builder.mode(LOG_DIRECTORY_MODE).create(&data_directory)?;
        let logs = prepare_log_directory(&data_directory)?;
        std::fs::set_permissions(&logs, std::fs::Permissions::from_mode(0o750))?;
        assert_eq!(
            prepare_log_directory(&data_directory)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        std::fs::remove_dir_all(&logs)?;
        std::fs::write(&logs, b"not a directory")?;
        assert_eq!(
            prepare_log_directory(&data_directory)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        std::fs::remove_dir_all(data_directory)?;
        Ok(())
    }
}
