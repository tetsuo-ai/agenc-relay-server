//! Checked quantities whose units remain visible at call sites.

use crate::{ClockError, EntropyError, ValidationError};

macro_rules! quantity {
    ($name:ident, $minimum:expr, $maximum:expr, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(u64);

        impl $name {
            /// Inclusive minimum accepted by this domain.
            pub const MIN: u64 = $minimum;
            /// Inclusive maximum accepted by this domain.
            pub const MAX: u64 = $maximum;

            /// Constructs a checked quantity.
            pub const fn new(value: u64) -> Result<Self, ValidationError> {
                if value < Self::MIN || value > Self::MAX {
                    return Err(ValidationError::OutOfRange);
                }
                Ok(Self(value))
            }

            /// Returns the primitive value in this type's documented unit.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0
            }

            /// Adds a primitive quantity while retaining this domain's bound.
            pub const fn checked_add(self, amount: u64) -> Result<Self, ValidationError> {
                let Some(value) = self.0.checked_add(amount) else {
                    return Err(ValidationError::Overflow);
                };
                Self::new(value)
            }

            /// Subtracts a primitive quantity without wrapping.
            pub const fn checked_sub(self, amount: u64) -> Result<Self, ValidationError> {
                let Some(value) = self.0.checked_sub(amount) else {
                    return Err(ValidationError::Underflow);
                };
                Self::new(value)
            }
        }
    };
}

quantity!(
    ByteCount,
    0,
    1_099_511_627_776,
    "A checked byte count capped at the one-tebibyte storage maximum."
);
quantity!(
    ObjectCount,
    0,
    1_000_000,
    "A checked count for bounded protocol object collections."
);
quantity!(
    QueueDemand,
    0,
    67_108_864,
    "A checked number of bytes requested from a bounded queue."
);
quantity!(
    UnixMilliseconds,
    0,
    u64::MAX,
    "An unsigned UTC timestamp measured in Unix milliseconds."
);
quantity!(
    UtcSecond,
    0,
    u64::MAX,
    "An unsigned UTC wall-clock timestamp measured in whole Unix seconds."
);
quantity!(
    MonotonicTick,
    0,
    u64::MAX,
    "A process-local monotonic clock tick with no wall-time meaning."
);
quantity!(
    DurationMilliseconds,
    0,
    u64::MAX,
    "A nonnegative duration measured in milliseconds."
);
quantity!(Revision, 0, u64::MAX, "A checked state revision.");
quantity!(Generation, 0, u64::MAX, "A checked state generation.");
quantity!(
    SequenceNumber,
    0,
    u64::MAX,
    "A checked monotonically assigned protocol sequence number."
);
quantity!(
    Quota,
    1,
    u64::MAX,
    "A nonzero configured quota; zero never means unlimited."
);

impl MonotonicTick {
    /// Constructs any representable process-local tick.
    #[must_use]
    pub const fn from_ticks(ticks: u64) -> Self {
        Self(ticks)
    }
}

impl UtcSecond {
    /// The Unix epoch, useful for deterministic fixtures with no wall clock.
    pub const UNIX_EPOCH: Self = Self(0);

    /// Constructs any representable whole-second Unix timestamp.
    #[must_use]
    pub const fn from_unix_seconds(seconds: u64) -> Self {
        Self(seconds)
    }
}

impl Revision {
    /// The first nonzero authoritative state revision.
    pub const INITIAL: Self = Self(1);
}

/// Supplies unpredictable bytes to identifier constructors.
pub trait EntropySource {
    /// Fills the complete destination or leaves its documented state unchanged.
    fn fill_exact(&mut self, destination: &mut [u8]) -> Result<(), EntropyError>;
}

/// Supplies process-local monotonic time.
pub trait MonotonicClock {
    /// Returns the current monotonic tick.
    fn now(&self) -> MonotonicTick;
}

/// Supplies UTC wall time separately from monotonic policy time.
pub trait WallClock {
    /// Returns the current whole-second UTC timestamp or a closed read failure.
    fn utc_now(&self) -> Result<UtcSecond, ClockError>;
}
