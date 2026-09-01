//! Prefix-row lifetime for direct source addresses (spec 6.1, lines 290-295;
//! invariant ID-04, line 6858).
//!
//! A raw source address is reduced to its rate prefix at admission and the
//! prefix row is erased no later than ten minutes after the last connection
//! using it closes. Erasing earlier is allowed and happens when the registry
//! reaches its ceiling.

use std::collections::HashMap;

use agenc_ircd_types::MonotonicTick;

use crate::RuntimeError;
use crate::state_core::inbox::SourceAddressKey;

/// Idle prefix rows are erased at or after this delay (spec line 294).
pub const PREFIX_ERASURE_MILLIS: u64 = 600_000;
/// Ceiling on tracked prefix rows: the 250,000 hard-maximum client
/// connections (spec line 2641) rounded up, so every live connection can
/// hold its own prefix and idle rows are evicted first.
pub const MAX_TRACKED_PREFIXES: usize = 262_144;

#[derive(Clone, Copy)]
struct PrefixRow {
    live: u64,
    last_close: MonotonicTick,
}

/// Live-connection counts per prefix and the erasure clock for idle rows.
pub struct PrefixRegistry {
    rows: HashMap<SourceAddressKey, PrefixRow>,
    ceiling: usize,
    next_idle_erasure: Option<MonotonicTick>,
}

impl PrefixRegistry {
    /// Creates an empty registry under the default ceiling.
    #[must_use]
    pub fn new() -> Self {
        Self::with_ceiling(MAX_TRACKED_PREFIXES)
    }

    /// Creates an empty registry under an explicit ceiling.
    #[must_use]
    pub fn with_ceiling(ceiling: usize) -> Self {
        Self {
            rows: HashMap::new(),
            ceiling,
            next_idle_erasure: None,
        }
    }

    /// Records one admitted connection on `prefix`.
    ///
    /// A new row at the ceiling first evicts the longest-idle row; when every
    /// row still has a live connection the registry is genuinely full.
    pub fn connection_opened(
        &mut self,
        prefix: SourceAddressKey,
        _now: MonotonicTick,
    ) -> Result<Option<SourceAddressKey>, RuntimeError> {
        if let Some(row) = self.rows.get_mut(&prefix) {
            row.live = row.live.checked_add(1).ok_or(RuntimeError::Overflow)?;
            return Ok(None);
        }
        let evicted = if self.rows.len() >= self.ceiling {
            Some(
                self.evict_longest_idle()
                    .ok_or(RuntimeError::LimitExceeded)?,
            )
        } else {
            None
        };
        self.rows.insert(
            prefix,
            PrefixRow {
                live: 1,
                last_close: MonotonicTick::from_ticks(0),
            },
        );
        Ok(evicted)
    }

    /// Records one closed connection on `prefix` and starts its idle clock.
    pub fn connection_closed(
        &mut self,
        prefix: SourceAddressKey,
        now: MonotonicTick,
    ) -> Result<(), RuntimeError> {
        let deadline = {
            let row = self
                .rows
                .get_mut(&prefix)
                .ok_or(RuntimeError::InvalidValue)?;
            row.live = row.live.checked_sub(1).ok_or(RuntimeError::InvalidValue)?;
            row.last_close = row.last_close.max(now);
            if row.live == 0 {
                Some(idle_erasure_deadline(row.last_close))
            } else {
                None
            }
        };
        if let Some(deadline) = deadline {
            self.next_idle_erasure = Some(
                self.next_idle_erasure
                    .map_or(deadline, |current| current.min(deadline)),
            );
        }
        Ok(())
    }

    /// Erases every row idle for at least [`PREFIX_ERASURE_MILLIS`] and
    /// returns the erased keys so the bucket table can drop their rows too.
    pub fn erase_idle(&mut self, now: MonotonicTick) -> Vec<SourceAddressKey> {
        let mut erased = Vec::new();
        self.rows.retain(|prefix, row| {
            let idle = row.live == 0
                && now
                    .get()
                    .checked_sub(row.last_close.get())
                    .is_some_and(|elapsed| elapsed >= PREFIX_ERASURE_MILLIS);
            if idle {
                erased.push(*prefix);
            }
            !idle
        });
        self.recompute_next_idle_erasure();
        erased
    }

    /// Returns the milliseconds remaining before the next idle-row cleanup
    /// check. A stale deadline may wake early after an idle row becomes live,
    /// but the cached value never wakes later than an idle row's deadline.
    #[must_use]
    pub(crate) fn millis_until_next_erasure(&self, now: MonotonicTick) -> Option<u64> {
        self.next_idle_erasure
            .map(|deadline| deadline.get().saturating_sub(now.get()))
    }

    /// Returns the cached absolute cleanup deadline. The value may be early
    /// after a reopen, but never later than a row's actual erasure deadline.
    #[must_use]
    pub(crate) const fn next_erasure_deadline(&self) -> Option<MonotonicTick> {
        self.next_idle_erasure
    }

    /// Returns the live connections on `prefix`.
    #[must_use]
    pub fn live(&self, prefix: SourceAddressKey) -> u64 {
        self.rows.get(&prefix).map_or(0, |row| row.live)
    }

    /// Returns the number of tracked rows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Returns whether no row is tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    fn evict_longest_idle(&mut self) -> Option<SourceAddressKey> {
        let victim = self
            .rows
            .iter()
            .filter(|(_, row)| row.live == 0)
            .min_by_key(|(_, row)| row.last_close)
            .map(|(prefix, _)| *prefix);
        if let Some(prefix) = victim {
            self.rows.remove(&prefix);
            self.recompute_next_idle_erasure();
        }
        victim
    }

    fn recompute_next_idle_erasure(&mut self) {
        self.next_idle_erasure = self
            .rows
            .values()
            .filter(|row| row.live == 0)
            .map(|row| idle_erasure_deadline(row.last_close))
            .min();
    }
}

fn idle_erasure_deadline(last_close: MonotonicTick) -> MonotonicTick {
    MonotonicTick::from_ticks(last_close.get().saturating_add(PREFIX_ERASURE_MILLIS))
}

impl Default for PrefixRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tick(millis: u64) -> MonotonicTick {
        MonotonicTick::from_ticks(millis)
    }

    /// Distinct /24 prefixes: the third octet varies, so no two collide.
    fn prefix(third: u8) -> SourceAddressKey {
        SourceAddressKey::ipv4([192, 0, third, 1]).prefix_key()
    }

    #[test]
    fn idle_rows_are_erased_exactly_at_the_ten_minute_boundary() -> Result<(), RuntimeError> {
        let mut registry = PrefixRegistry::new();
        let key = prefix(1);
        let _evicted = registry.connection_opened(key, tick(0))?;
        let _evicted = registry.connection_opened(key, tick(0))?;
        assert_eq!(registry.live(key), 2);
        registry.connection_closed(key, tick(1_000))?;
        assert!(registry.erase_idle(tick(700_000)).is_empty(), "still live");
        registry.connection_closed(key, tick(5_000))?;
        assert_eq!(
            registry.millis_until_next_erasure(tick(5_000)),
            Some(PREFIX_ERASURE_MILLIS)
        );
        assert_eq!(registry.millis_until_next_erasure(tick(604_999)), Some(1));
        assert!(registry.erase_idle(tick(604_999)).is_empty());
        assert!(
            registry.erase_idle(tick(4_999)).is_empty(),
            "rollback erases nothing"
        );
        let erased = registry.erase_idle(tick(605_000));
        assert_eq!(erased.len(), 1);
        assert!(erased.first().is_some_and(|value| *value == key));
        assert!(registry.is_empty());
        assert_eq!(registry.live(key), 0);
        assert_eq!(registry.millis_until_next_erasure(tick(605_000)), None);
        Ok(())
    }

    #[test]
    fn independently_owned_registries_keep_their_own_last_close_deadlines()
    -> Result<(), RuntimeError> {
        let key = SourceAddressKey::ipv4([203, 0, 113, 9]).prefix_key();
        let mut transport = PrefixRegistry::new();
        let mut state_core = PrefixRegistry::new();
        let _evicted = transport.connection_opened(key, tick(0))?;
        let _evicted = state_core.connection_opened(key, tick(0))?;
        transport.connection_closed(key, tick(0))?;
        state_core.connection_closed(key, tick(100))?;

        let transport_erased = transport.erase_idle(tick(600_000));
        assert!(
            transport_erased.len() == 1
                && transport_erased
                    .first()
                    .is_some_and(|prefix| *prefix == key)
        );
        assert_eq!(
            state_core.millis_until_next_erasure(tick(600_000)),
            Some(100)
        );
        assert!(state_core.erase_idle(tick(600_099)).is_empty());
        let state_core_erased = state_core.erase_idle(tick(600_100));
        assert!(
            state_core_erased.len() == 1
                && state_core_erased
                    .first()
                    .is_some_and(|prefix| *prefix == key)
        );
        Ok(())
    }

    #[test]
    fn cached_deadline_may_wake_early_after_reopen_but_never_stays_stale()
    -> Result<(), RuntimeError> {
        let key = prefix(2);
        let mut registry = PrefixRegistry::new();
        let _evicted = registry.connection_opened(key, tick(0))?;
        registry.connection_closed(key, tick(0))?;
        let _evicted = registry.connection_opened(key, tick(100))?;

        assert_eq!(registry.millis_until_next_erasure(tick(100)), Some(599_900));
        assert!(registry.erase_idle(tick(600_000)).is_empty());
        assert_eq!(registry.millis_until_next_erasure(tick(600_000)), None);

        registry.connection_closed(key, tick(600_001))?;
        assert_eq!(
            registry.millis_until_next_erasure(tick(600_001)),
            Some(PREFIX_ERASURE_MILLIS)
        );
        Ok(())
    }

    #[test]
    fn reordered_close_notices_keep_the_latest_physical_close_tick() -> Result<(), RuntimeError> {
        let key = prefix(3);
        let mut registry = PrefixRegistry::new();
        let _evicted = registry.connection_opened(key, tick(1_000))?;
        let _evicted = registry.connection_opened(key, tick(1_000))?;
        registry.connection_closed(key, tick(900))?;
        registry.connection_closed(key, tick(800))?;

        assert_eq!(
            registry.millis_until_next_erasure(tick(900)),
            Some(PREFIX_ERASURE_MILLIS)
        );
        assert!(registry.erase_idle(tick(600_899)).is_empty());
        let erased = registry.erase_idle(tick(600_900));
        assert!(erased.len() == 1 && erased.first().is_some_and(|prefix| *prefix == key));
        Ok(())
    }

    #[test]
    fn closing_an_unknown_or_already_idle_prefix_is_an_invariant_violation() {
        let mut registry = PrefixRegistry::new();
        assert_eq!(
            registry.connection_closed(prefix(1), tick(0)).err(),
            Some(RuntimeError::InvalidValue)
        );
        assert!(registry.connection_opened(prefix(1), tick(0)).is_ok());
        assert_eq!(registry.connection_closed(prefix(1), tick(0)), Ok(()));
        assert_eq!(
            registry.connection_closed(prefix(1), tick(0)).err(),
            Some(RuntimeError::InvalidValue)
        );
    }

    #[test]
    fn the_ceiling_evicts_the_longest_idle_row_and_refuses_when_all_are_live()
    -> Result<(), RuntimeError> {
        let mut registry = PrefixRegistry::with_ceiling(2);
        let _evicted = registry.connection_opened(prefix(1), tick(0))?;
        let _evicted = registry.connection_opened(prefix(2), tick(0))?;
        assert_eq!(
            registry.connection_opened(prefix(3), tick(0)).err(),
            Some(RuntimeError::LimitExceeded)
        );
        registry.connection_closed(prefix(1), tick(10))?;
        registry.connection_closed(prefix(2), tick(20))?;
        let evicted = registry.connection_opened(prefix(3), tick(30))?;
        assert!(evicted.is_some_and(|key| key == prefix(1)));
        assert_eq!(registry.len(), 2);
        assert_eq!(registry.live(prefix(1)), 0);
        assert_eq!(registry.live(prefix(2)), 0);
        assert!(registry.erase_idle(tick(30)).is_empty());
        assert_eq!(registry.live(prefix(3)), 1);
        let defaulted = PrefixRegistry::default();
        assert!(defaulted.is_empty());
        Ok(())
    }
}
