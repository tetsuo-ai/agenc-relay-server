//! System clock adapters for the `agenc-relay-types` clock traits.
//!
//! Durations, deadlines, and rate limits read the monotonic clock; wall time
//! serves only displayed timestamps, credential validity, and durable
//! retention boundaries (spec 21.6, lines 4224-4227).

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use agenc_relay_types::{ClockError, MonotonicClock, MonotonicTick, UtcSecond, WallClock};

/// Process-local monotonic clock counting milliseconds since construction.
#[derive(Clone, Copy, Debug)]
pub struct SystemMonotonicClock {
    origin: Instant,
}

impl SystemMonotonicClock {
    /// Starts counting from the current instant.
    #[must_use]
    pub fn start() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl MonotonicClock for SystemMonotonicClock {
    fn now(&self) -> MonotonicTick {
        // A process would need to run for more than 584 million years to
        // exhaust the tick domain; saturating keeps the conversion total.
        let millis = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX);
        MonotonicTick::from_ticks(millis)
    }
}

/// Whole-second UTC clock for displayed timestamps and durable boundaries.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemWallClock;

impl WallClock for SystemWallClock {
    fn utc_now(&self) -> Result<UtcSecond, ClockError> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ClockError::Unavailable)?;
        Ok(UtcSecond::from_unix_seconds(elapsed.as_secs()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-01-01T00:00:00Z, the fixture validity start used across Stage 06.
    const STAGE_SIX_EPOCH_SECONDS: u64 = 1_767_225_600;

    #[test]
    fn monotonic_ticks_never_decrease() {
        let clock = SystemMonotonicClock::start();
        let first = clock.now();
        let second = clock.now();
        assert!(second >= first);
    }

    #[test]
    fn wall_clock_reads_a_post_stage_six_utc_second() -> Result<(), ClockError> {
        let now = SystemWallClock.utc_now()?;
        assert!(now.get() >= STAGE_SIX_EPOCH_SECONDS);
        Ok(())
    }
}
