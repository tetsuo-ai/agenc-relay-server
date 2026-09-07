//! Absolute pending-cut deadlines retain their original clock coordinate.
#![forbid(unsafe_code)]

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::time::Duration;

use agenc_ircd_storage::e2ee_records::delivery_recovery::{
    PendingDeadline, PendingDeadlineFields, RetirementReason,
};
use rustix::time::{ClockId, DynamicClockId, clock_gettime_dynamic};

const LIFETIME_SECONDS: u64 = 900;
const NANOSECONDS: u32 = 1_000_000_000;

#[cfg(test)]
mod tests;

/// One validated Linux monotonic reading in its boot and namespace coordinate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sample {
    boot_id: [u8; 16],
    offset_seconds: i64,
    offset_nanoseconds: u32,
    seconds: u64,
    nanoseconds: u32,
}

impl Sample {
    fn position(self) -> (u64, u32) {
        (self.seconds, self.nanoseconds)
    }

    /// Arms one nonextendable fifteen-minute deadline.
    pub fn deadline(self) -> Result<PendingDeadline, RetirementReason> {
        let seconds = self
            .seconds
            .checked_add(LIFETIME_SECONDS)
            .ok_or(RetirementReason::ClockInvalid)?;
        self.with_deadline(seconds, self.nanoseconds)
    }

    fn with_deadline(
        self,
        deadline_seconds: u64,
        deadline_nanoseconds: u32,
    ) -> Result<PendingDeadline, RetirementReason> {
        PendingDeadline::new(PendingDeadlineFields {
            boot_id: self.boot_id,
            offset_seconds: self.offset_seconds,
            offset_nanoseconds: self.offset_nanoseconds,
            deadline_seconds,
            deadline_nanoseconds,
            observed_seconds: self.seconds,
            observed_nanoseconds: self.nanoseconds,
        })
        .map_err(|_| RetirementReason::ClockInvalid)
    }

    /// Advances the observed coordinate without changing the original deadline.
    pub fn observe(
        self,
        deadline: PendingDeadline,
        volatile: Option<Sample>,
    ) -> Result<PendingDeadline, RetirementReason> {
        let same_scope = self.boot_id == deadline.boot_id()
            && self.offset_seconds == deadline.offset_seconds()
            && self.offset_nanoseconds == deadline.offset_nanoseconds();
        if !same_scope {
            return Err(RetirementReason::ClockScopeLost);
        }
        self.require_high_water(deadline, volatile)?;
        if self.position() >= (deadline.deadline_seconds(), deadline.deadline_nanoseconds()) {
            return Err(RetirementReason::DeadlineReached);
        }
        self.with_deadline(deadline.deadline_seconds(), deadline.deadline_nanoseconds())
    }

    fn require_high_water(
        self,
        deadline: PendingDeadline,
        volatile: Option<Sample>,
    ) -> Result<(), RetirementReason> {
        if self.nanoseconds >= NANOSECONDS
            || self.position() < (deadline.observed_seconds(), deadline.observed_nanoseconds())
            || volatile.is_some_and(|old| {
                self.position() < old.position()
                    || self.boot_id != old.boot_id
                    || self.offset_seconds != old.offset_seconds
                    || self.offset_nanoseconds != old.offset_nanoseconds
            })
        {
            return Err(RetirementReason::ClockInvalid);
        }
        Ok(())
    }

    /// A wake hint only; the callback must sample the clock again.
    pub fn remaining(self, deadline: PendingDeadline) -> Result<Duration, RetirementReason> {
        self.observe(deadline, None)?;
        Duration::new(deadline.deadline_seconds(), deadline.deadline_nanoseconds())
            .checked_sub(Duration::new(self.seconds, self.nanoseconds))
            .ok_or(RetirementReason::ClockInvalid)
    }
}

/// Current and children time namespaces must be identical before the latter's
/// procfs offset can describe this process's clock. Keep both descriptors alive.
struct Namespace {
    current: File,
    children: File,
    identity: (u64, u64),
}

impl Namespace {
    fn open() -> Result<Self, RetirementReason> {
        let current =
            File::open("/proc/self/ns/time").map_err(|_| RetirementReason::ClockScopeLost)?;
        let children = File::open("/proc/self/ns/time_for_children")
            .map_err(|_| RetirementReason::ClockScopeLost)?;
        let identity = namespace_identity(&current)?;
        if namespace_identity(&children)? != identity {
            return Err(RetirementReason::ClockScopeLost);
        }
        Ok(Self {
            current,
            children,
            identity,
        })
    }

    fn unchanged(&self) -> Result<(), RetirementReason> {
        let after = Self::open()?;
        if namespace_identity(&self.current)? != self.identity
            || namespace_identity(&self.children)? != self.identity
            || after.identity != self.identity
        {
            return Err(RetirementReason::ClockScopeLost);
        }
        Ok(())
    }
}

fn namespace_identity(file: &File) -> Result<(u64, u64), RetirementReason> {
    let metadata = file
        .metadata()
        .map_err(|_| RetirementReason::ClockScopeLost)?;
    Ok((metadata.dev(), metadata.ino()))
}

pub(crate) fn sample() -> Result<Sample, RetirementReason> {
    let namespace = Namespace::open()?;
    let mut boot = [0; 37];
    let boot = read_bounded("/proc/sys/kernel/random/boot_id", &mut boot)?;
    let boot_id = parse_boot_id(boot)?;
    let mut offsets = [0; 256];
    let offsets = read_bounded("/proc/self/timens_offsets", &mut offsets)?;
    let (offset_seconds, offset_nanoseconds) = parse_offset(offsets)?;
    let value = clock_gettime_dynamic(DynamicClockId::Known(ClockId::Monotonic))
        .map_err(|_| RetirementReason::ClockInvalid)?;
    let seconds = u64::try_from(value.tv_sec).map_err(|_| RetirementReason::ClockInvalid)?;
    let nanoseconds = u32::try_from(value.tv_nsec).map_err(|_| RetirementReason::ClockInvalid)?;
    if nanoseconds >= NANOSECONDS {
        return Err(RetirementReason::ClockInvalid);
    }
    namespace.unchanged()?;
    Ok(Sample {
        boot_id,
        offset_seconds,
        offset_nanoseconds,
        seconds,
        nanoseconds,
    })
}

fn read_bounded<'a>(path: &str, bytes: &'a mut [u8]) -> Result<&'a [u8], RetirementReason> {
    let mut file = File::open(path).map_err(|_| RetirementReason::ClockScopeLost)?;
    let mut used = 0;
    while used < bytes.len() {
        let count = file
            .read(
                bytes
                    .get_mut(used..)
                    .ok_or(RetirementReason::ClockInvalid)?,
            )
            .map_err(|_| RetirementReason::ClockScopeLost)?;
        if count == 0 {
            return bytes.get(..used).ok_or(RetirementReason::ClockInvalid);
        }
        used = used
            .checked_add(count)
            .ok_or(RetirementReason::ClockInvalid)?;
    }
    let mut extra = [0];
    if file
        .read(&mut extra)
        .map_err(|_| RetirementReason::ClockScopeLost)?
        != 0
    {
        return Err(RetirementReason::ClockInvalid);
    }
    Ok(bytes)
}

fn parse_boot_id(bytes: &[u8]) -> Result<[u8; 16], RetirementReason> {
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if bytes.len() != 36 {
        return Err(RetirementReason::ClockInvalid);
    }
    let mut value = [0; 16];
    let mut nibble = 0;
    for (offset, byte) in bytes.iter().copied().enumerate() {
        if [8, 13, 18, 23].contains(&offset) {
            if byte != 45 {
                return Err(RetirementReason::ClockInvalid);
            }
            continue;
        }
        let digit = match byte {
            48..=57 => byte - 48,
            65..=70 => byte - 65 + 10,
            97..=102 => byte - 97 + 10,
            _ => return Err(RetirementReason::ClockInvalid),
        };
        let part = value
            .get_mut(nibble / 2)
            .ok_or(RetirementReason::ClockInvalid)?;
        *part = (*part << 4) | digit;
        nibble += 1;
    }
    Ok(value)
}

fn parse_offset(bytes: &[u8]) -> Result<(i64, u32), RetirementReason> {
    let text = std::str::from_utf8(bytes).map_err(|_| RetirementReason::ClockInvalid)?;
    let mut monotonic = None;
    let mut boottime = false;
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let kind = fields.next().ok_or(RetirementReason::ClockInvalid)?;
        let seconds = fields
            .next()
            .ok_or(RetirementReason::ClockInvalid)?
            .parse::<i64>()
            .map_err(|_| RetirementReason::ClockInvalid)?;
        let nanos = fields
            .next()
            .ok_or(RetirementReason::ClockInvalid)?
            .parse::<u32>()
            .map_err(|_| RetirementReason::ClockInvalid)?;
        if fields.next().is_some() || nanos >= NANOSECONDS {
            return Err(RetirementReason::ClockInvalid);
        }
        match kind {
            "monotonic" if monotonic.is_none() => monotonic = Some((seconds, nanos)),
            "boottime" if !boottime => boottime = true,
            _ => return Err(RetirementReason::ClockInvalid),
        }
    }
    if !boottime {
        return Err(RetirementReason::ClockInvalid);
    }
    monotonic.ok_or(RetirementReason::ClockInvalid)
}
