//! Panic containment (spec 21.2, lines 4067-4069).
//!
//! A panic is a bug, not a protocol outcome. The installed hook renders one
//! body-free crash event, which carries only the closed common fields, and
//! terminates the process. The default panic message is not printed because
//! a payload could carry input bytes.

use agenc_relay_types::{ServerId, UtcSecond, WallClock};

use crate::observe::events::{CorrelationSource, LogEvent, LogEventCode, Severity};
use crate::sync::Arc;

/// The exit status after a contained panic: `EX_SOFTWARE`.
pub const CRASH_EXIT_CODE: i32 = 70;

/// Renders the crash event and terminates the process.
pub struct CrashReporter {
    server_id: ServerId,
    correlation: Arc<CorrelationSource>,
    clock: Arc<dyn WallClock + Send + Sync>,
    fallback: UtcSecond,
    exit: fn(i32),
}

impl CrashReporter {
    /// Creates a reporter; the wall clock must be readable once so a later
    /// clock failure cannot suppress the crash event.
    pub fn new(
        server_id: ServerId,
        correlation: Arc<CorrelationSource>,
        clock: Arc<dyn WallClock + Send + Sync>,
        exit: fn(i32),
    ) -> Option<Self> {
        let fallback = clock.utc_now().ok()?;
        Some(Self {
            server_id,
            correlation,
            clock,
            fallback,
            exit,
        })
    }

    /// Renders the body-free crash event.
    #[must_use]
    pub fn crash_event(&self) -> LogEvent {
        let now = self.clock.utc_now().unwrap_or(self.fallback);
        LogEvent::new(
            LogEventCode::Crash,
            Severity::Critical,
            now,
            self.server_id,
            self.correlation.next(),
        )
    }

    /// Reports one crash to standard error and terminates.
    pub fn report_and_exit(&self) {
        eprintln!("{}", self.crash_event());
        (self.exit)(CRASH_EXIT_CODE);
    }

    /// Installs the process panic hook.
    pub fn install(self) {
        std::panic::set_hook(Box::new(move |_| self.report_and_exit()));
    }
}

/// Terminates the process with `code`; the production exit function.
pub fn exit_process(code: i32) -> ! {
    std::process::exit(code)
}

#[cfg(test)]
mod tests {
    use agenc_relay_types::ClockError;

    use super::*;

    struct FixedClock(Result<UtcSecond, ClockError>);

    impl WallClock for FixedClock {
        fn utc_now(&self) -> Result<UtcSecond, ClockError> {
            self.0
        }
    }

    fn server_id() -> ServerId {
        ServerId::from_bytes([7; 16])
    }

    #[test]
    fn the_crash_event_carries_only_closed_fields() -> Result<(), ClockError> {
        let second = UtcSecond::new(1_700_000_000).map_err(|_| ClockError::Unavailable)?;
        let reporter = CrashReporter::new(
            server_id(),
            Arc::new(CorrelationSource::new(5)),
            Arc::new(FixedClock(Ok(second))),
            |_| {},
        )
        .ok_or(ClockError::Unavailable)?;
        let event = reporter.crash_event();
        assert_eq!(event.code(), LogEventCode::Crash);
        assert_eq!(event.severity(), Severity::Critical);
        let rendered = event.to_string();
        assert!(rendered.contains("crash"));
        assert!(rendered.contains("1700000000"));
        assert!(!rendered.contains("panicked"));
        assert_eq!(CRASH_EXIT_CODE, 70);
        Ok(())
    }

    #[test]
    fn an_unreadable_clock_blocks_installation_and_a_later_failure_uses_the_fallback()
    -> Result<(), ClockError> {
        assert!(
            CrashReporter::new(
                server_id(),
                Arc::new(CorrelationSource::new(1)),
                Arc::new(FixedClock(Err(ClockError::Unavailable))),
                |_| {},
            )
            .is_none()
        );
        let second = UtcSecond::new(1_700_000_001).map_err(|_| ClockError::Unavailable)?;
        struct FlakyClock {
            first: std::sync::atomic::AtomicBool,
            second: UtcSecond,
        }
        impl WallClock for FlakyClock {
            fn utc_now(&self) -> Result<UtcSecond, ClockError> {
                if self.first.swap(false, std::sync::atomic::Ordering::SeqCst) {
                    Ok(self.second)
                } else {
                    Err(ClockError::Unavailable)
                }
            }
        }
        let reporter = CrashReporter::new(
            server_id(),
            Arc::new(CorrelationSource::new(1)),
            Arc::new(FlakyClock {
                first: std::sync::atomic::AtomicBool::new(true),
                second,
            }),
            |_| {},
        )
        .ok_or(ClockError::Unavailable)?;
        assert!(reporter.crash_event().to_string().contains("1700000001"));
        reporter.report_and_exit();
        Ok(())
    }
}
