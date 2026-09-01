//! Memory-overload classification and the disk-space gate (spec 19.3,
//! lines 2816-2876).

use agenc_ircd_storage::MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH;

use crate::RuntimeError;
use crate::connection::sink::ConnectionGeneration;

/// One outbound queue sends one slow-consumer warning at this fill (spec
/// line 2818).
pub const QUEUE_WARNING_PERCENT: u64 = 75;
/// Guests and expensive queries stop at this budget usage (spec line 2822).
pub const GUEST_STOP_PERCENT: u64 = 80;
/// New connections and channel creation stop at this usage (spec line 2823).
pub const CONNECTION_STOP_PERCENT: u64 = 90;
/// Whole-connection eviction begins at this usage (spec line 2823).
pub const EVICTION_PERCENT: u64 = 95;
/// Eviction continues until usage is below this value (spec line 2825).
pub const RECOVERY_PERCENT: u64 = 85;
/// Smallest configurable `storage.disk_reserve_percent` (spec line 9019).
pub const MIN_DISK_RESERVE_PERCENT: u8 = 1;
/// Largest configurable `storage.disk_reserve_percent` (spec line 9019).
pub const MAX_DISK_RESERVE_PERCENT: u8 = 25;
/// `G`, the fixed physical growth allowance of one legal redb transaction
/// (spec lines 2837-2839).
pub const TRANSACTION_GROWTH_ALLOWANCE_BYTES: u64 = MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH;

/// The closed overload classes of spec 19.3.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OverloadClass {
    /// Below 80 percent of the live budget.
    Normal,
    /// At or above 80 percent: no guests, no expensive queries.
    NoGuests,
    /// At or above 90 percent: no new connections or channel creation.
    NoNewConnections,
    /// At or above 95 percent, until usage falls below 85 percent.
    Evict,
}

/// Overload class with the eviction hysteresis of spec line 2825.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OverloadState {
    class: OverloadClass,
}

impl OverloadState {
    /// Starts in the normal class.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            class: OverloadClass::Normal,
        }
    }

    /// Returns the current class.
    #[must_use]
    pub const fn class(self) -> OverloadClass {
        self.class
    }

    /// Reclassifies from the charged and capacity bytes of the live budget.
    pub fn classify(&mut self, charged: u64, capacity: u64) -> OverloadClass {
        let reaches = |percent| usage_reaches(charged, capacity, percent);
        self.class = if reaches(EVICTION_PERCENT)
            || (self.class == OverloadClass::Evict && reaches(RECOVERY_PERCENT))
        {
            OverloadClass::Evict
        } else if reaches(CONNECTION_STOP_PERCENT) {
            OverloadClass::NoNewConnections
        } else if reaches(GUEST_STOP_PERCENT) {
            OverloadClass::NoGuests
        } else {
            OverloadClass::Normal
        };
        self.class
    }
}

impl Default for OverloadState {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns whether `charged / capacity` is at least `percent` percent,
/// computed without overflow; an empty capacity is always reached.
#[must_use]
pub fn usage_reaches(charged: u64, capacity: u64, percent: u64) -> bool {
    u128::from(charged) * 100 >= u128::from(capacity) * u128::from(percent)
}

/// One client connection considered for eviction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvictionCandidate {
    /// The connection's queue generation.
    pub generation: ConnectionGeneration,
    /// Bytes charged to the connection's queue.
    pub charged_bytes: u64,
}

/// Selects whole connections in descending charged-byte order until the
/// projected usage is below [`RECOVERY_PERCENT`] (spec lines 2823-2826).
///
/// Ties keep the earlier generation first so the choice is deterministic.
/// Every selected connection is closed with its entire queue; no frame is
/// evicted on its own.
#[must_use]
pub fn select_evictions(
    candidates: &mut [EvictionCandidate],
    charged: u64,
    capacity: u64,
) -> Vec<ConnectionGeneration> {
    candidates.sort_by(|left, right| {
        right
            .charged_bytes
            .cmp(&left.charged_bytes)
            .then(left.generation.cmp(&right.generation))
    });
    let mut projected = charged;
    let mut selected = Vec::new();
    for candidate in candidates.iter() {
        if !usage_reaches(projected, capacity, RECOVERY_PERCENT) {
            break;
        }
        projected = projected.saturating_sub(candidate.charged_bytes);
        selected.push(candidate.generation);
    }
    selected
}

/// Computes `R(F)`: the greater of the fixed reserve and the checked
/// ceiling of `total_bytes * reserve_percent / 100` (spec lines 2831-2834).
pub fn required_reserve(
    total_bytes: u64,
    reserve_bytes: u64,
    reserve_percent: u8,
) -> Result<u64, RuntimeError> {
    if !(MIN_DISK_RESERVE_PERCENT..=MAX_DISK_RESERVE_PERCENT).contains(&reserve_percent) {
        return Err(RuntimeError::InvalidValue);
    }
    let scaled = u128::from(total_bytes) * u128::from(reserve_percent);
    let percent_reserve =
        u64::try_from(scaled.div_ceil(100)).map_err(|_| RuntimeError::Overflow)?;
    Ok(reserve_bytes.max(percent_reserve))
}

/// Returns whether a live write may start: available bytes must be at least
/// `R(F) + G` (spec lines 2839-2842).
pub fn admit_write(
    available_bytes: u64,
    total_bytes: u64,
    reserve_bytes: u64,
    reserve_percent: u8,
) -> Result<bool, RuntimeError> {
    admit_growth(
        available_bytes,
        total_bytes,
        reserve_bytes,
        reserve_percent,
        TRANSACTION_GROWTH_ALLOWANCE_BYTES,
    )
}

/// Returns whether `BACKUP CREATE` may start: available bytes must be at
/// least `R(F) + backup_stream_bytes` (spec lines 2858-2861).
pub fn admit_backup(
    available_bytes: u64,
    total_bytes: u64,
    reserve_bytes: u64,
    reserve_percent: u8,
    backup_stream_bytes: u64,
) -> Result<bool, RuntimeError> {
    admit_growth(
        available_bytes,
        total_bytes,
        reserve_bytes,
        reserve_percent,
        backup_stream_bytes,
    )
}

fn admit_growth(
    available_bytes: u64,
    total_bytes: u64,
    reserve_bytes: u64,
    reserve_percent: u8,
    growth_bytes: u64,
) -> Result<bool, RuntimeError> {
    let reserve = required_reserve(total_bytes, reserve_bytes, reserve_percent)?;
    let needed = reserve
        .checked_add(growth_bytes)
        .ok_or(RuntimeError::Overflow)?;
    Ok(available_bytes >= needed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAPACITY: u64 = 1_000;

    #[test]
    fn classes_switch_at_exact_thresholds_with_eviction_hysteresis() {
        let mut state = OverloadState::new();
        assert_eq!(state.class(), OverloadClass::Normal);
        let rising = [
            (790, OverloadClass::Normal),
            (800, OverloadClass::NoGuests),
            (890, OverloadClass::NoGuests),
            (900, OverloadClass::NoNewConnections),
            (940, OverloadClass::NoNewConnections),
            (950, OverloadClass::Evict),
            (900, OverloadClass::Evict),
            (850, OverloadClass::Evict),
            (849, OverloadClass::NoGuests),
            (790, OverloadClass::Normal),
        ];
        for (charged, expected) in rising {
            assert_eq!(state.classify(charged, CAPACITY), expected, "{charged}");
        }
        let mut direct = OverloadState::default();
        assert_eq!(
            direct.classify(949, CAPACITY),
            OverloadClass::NoNewConnections
        );
        assert!(
            usage_reaches(1, 0, 95),
            "an empty capacity is always reached"
        );
        assert!(usage_reaches(u64::MAX, u64::MAX, 100));
        assert!(!usage_reaches(0, 1, 1));
        assert!(OverloadClass::Normal < OverloadClass::Evict);
        assert_eq!(QUEUE_WARNING_PERCENT, 75);
    }

    #[test]
    fn eviction_selects_whole_connections_by_descending_bytes_until_recovery() {
        let mut candidates = vec![
            EvictionCandidate {
                generation: ConnectionGeneration::new(3),
                charged_bytes: 20,
            },
            EvictionCandidate {
                generation: ConnectionGeneration::new(1),
                charged_bytes: 60,
            },
            EvictionCandidate {
                generation: ConnectionGeneration::new(2),
                charged_bytes: 60,
            },
            EvictionCandidate {
                generation: ConnectionGeneration::new(4),
                charged_bytes: 10,
            },
        ];
        // 960 - 60 = 900 is still at 85 percent or above; 900 - 60 = 840 is below.
        let selected = select_evictions(&mut candidates, 960, CAPACITY);
        assert_eq!(
            selected,
            vec![ConnectionGeneration::new(1), ConnectionGeneration::new(2)]
        );
        let mut single = vec![EvictionCandidate {
            generation: ConnectionGeneration::new(5),
            charged_bytes: 300,
        }];
        assert_eq!(
            select_evictions(&mut single, 960, CAPACITY),
            vec![ConnectionGeneration::new(5)],
            "one large connection restores usage below 85 percent"
        );
        let mut nothing = vec![EvictionCandidate {
            generation: ConnectionGeneration::new(9),
            charged_bytes: 10,
        }];
        assert!(select_evictions(&mut nothing, 840, CAPACITY).is_empty());
        let mut exhausted = vec![EvictionCandidate {
            generation: ConnectionGeneration::new(9),
            charged_bytes: 10,
        }];
        assert_eq!(
            select_evictions(&mut exhausted, 990, CAPACITY),
            vec![ConnectionGeneration::new(9)],
            "every candidate is selected when recovery is unreachable"
        );
    }

    #[test]
    fn the_disk_gate_uses_the_larger_reserve_plus_the_growth_allowance() -> Result<(), RuntimeError>
    {
        let total = 100_000_000_000;
        assert_eq!(required_reserve(total, 1_073_741_824, 5)?, 5_000_000_000);
        assert_eq!(required_reserve(total, 6_000_000_000, 5)?, 6_000_000_000);
        assert_eq!(required_reserve(1, 0, 1)?, 1, "the ceiling rounds up");
        assert_eq!(
            required_reserve(total, 0, 0).err(),
            Some(RuntimeError::InvalidValue)
        );
        assert_eq!(
            required_reserve(total, 0, 26).err(),
            Some(RuntimeError::InvalidValue)
        );
        let needed = 5_000_000_000 + TRANSACTION_GROWTH_ALLOWANCE_BYTES;
        assert!(!admit_write(needed - 1, total, 1_073_741_824, 5)?);
        assert!(admit_write(needed, total, 1_073_741_824, 5)?);
        assert!(admit_backup(
            5_000_000_000 + 2_773,
            total,
            1_073_741_824,
            5,
            2_773
        )?);
        assert!(!admit_backup(
            5_000_000_000 + 2_772,
            total,
            1_073_741_824,
            5,
            2_773
        )?);
        assert_eq!(
            admit_write(u64::MAX, u64::MAX, u64::MAX, 1).err(),
            Some(RuntimeError::Overflow)
        );
        assert_eq!(
            required_reserve(u64::MAX, 0, 25).err(),
            None,
            "a quarter of u64::MAX fits"
        );
        Ok(())
    }
}
