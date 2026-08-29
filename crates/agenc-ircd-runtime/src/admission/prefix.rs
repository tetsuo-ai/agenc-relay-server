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
        }
    }

    /// Records one admitted connection on `prefix`.
    ///
    /// A new row at the ceiling first evicts the longest-idle row; when every
    /// row still has a live connection the registry is genuinely full.
    pub fn connection_opened(
        &mut self,
        prefix: SourceAddressKey,
        now: MonotonicTick,
    ) -> Result<(), RuntimeError> {
        if let Some(row) = self.rows.get_mut(&prefix) {
            row.live = row.live.checked_add(1).ok_or(RuntimeError::Overflow)?;
            return Ok(());
        }
        if self.rows.len() >= self.ceiling && !self.evict_longest_idle() {
            return Err(RuntimeError::LimitExceeded);
        }
        self.rows.insert(
            prefix,
            PrefixRow {
                live: 1,
                last_close: now,
            },
        );
        Ok(())
    }

    /// Records one closed connection on `prefix` and starts its idle clock.
    pub fn connection_closed(
        &mut self,
        prefix: SourceAddressKey,
        now: MonotonicTick,
    ) -> Result<(), RuntimeError> {
        let row = self
            .rows
            .get_mut(&prefix)
            .ok_or(RuntimeError::InvalidValue)?;
        row.live = row.live.checked_sub(1).ok_or(RuntimeError::InvalidValue)?;
        if row.live == 0 {
            row.last_close = now;
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
        erased
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

    fn evict_longest_idle(&mut self) -> bool {
        let victim = self
            .rows
            .iter()
            .filter(|(_, row)| row.live == 0)
            .min_by_key(|(_, row)| row.last_close)
            .map(|(prefix, _)| *prefix);
        match victim {
            Some(prefix) => self.rows.remove(&prefix).is_some(),
            None => false,
        }
    }
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
        registry.connection_opened(key, tick(0))?;
        registry.connection_opened(key, tick(0))?;
        assert_eq!(registry.live(key), 2);
        registry.connection_closed(key, tick(1_000))?;
        assert!(registry.erase_idle(tick(700_000)).is_empty(), "still live");
        registry.connection_closed(key, tick(5_000))?;
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
        Ok(())
    }

    #[test]
    fn closing_an_unknown_or_already_idle_prefix_is_an_invariant_violation() {
        let mut registry = PrefixRegistry::new();
        assert_eq!(
            registry.connection_closed(prefix(1), tick(0)).err(),
            Some(RuntimeError::InvalidValue)
        );
        assert_eq!(registry.connection_opened(prefix(1), tick(0)), Ok(()));
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
        registry.connection_opened(prefix(1), tick(0))?;
        registry.connection_opened(prefix(2), tick(0))?;
        assert_eq!(
            registry.connection_opened(prefix(3), tick(0)).err(),
            Some(RuntimeError::LimitExceeded)
        );
        registry.connection_closed(prefix(1), tick(10))?;
        registry.connection_closed(prefix(2), tick(20))?;
        registry.connection_opened(prefix(3), tick(30))?;
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
