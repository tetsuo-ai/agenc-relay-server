//! Host control probes for `check-config` and process hardening (spec 25.1 6657-6675).

use std::fmt;
use std::fs;

use rustix::mm::{MlockAllFlags, mlockall};
use rustix::process::{
    DumpableBehavior, Resource, Rlimit, getrlimit, set_dumpable_behavior, setrlimit,
};

use crate::error::ConfigError;

/// The Section 25.1 controls `check-config` reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum HostControl {
    /// The process runs as a dedicated unprivileged account.
    UnprivilegedAccount,
    /// `NoNewPrivileges` is set.
    NoNewPrivileges,
    /// The root filesystem is mounted read-only.
    ReadOnlyImage,
    /// `/tmp` is a private temporary directory.
    PrivateTmp,
    /// A seccomp filter restricts system calls.
    SyscallFilter,
    /// Address-family restrictions (not observable from inside the process).
    AddressFamilies,
    /// `CAP_SYS_PTRACE` is outside the bounding set.
    PtraceDenied,
    /// `/dev` is a private device tree.
    DeviceAccessDenied,
    /// `CAP_SYS_MODULE` is outside the bounding set.
    KernelModulesDenied,
    /// `CAP_NET_RAW` is outside the bounding set.
    RawSocketsDenied,
    /// `RLIMIT_CORE` is zero.
    CoreDumpsDisabled,
    /// `RLIMIT_MEMLOCK` covers the memory budget.
    SecretLocking,
}

impl HostControl {
    /// Every control in report order.
    pub const ALL: [Self; 12] = [
        Self::UnprivilegedAccount,
        Self::NoNewPrivileges,
        Self::ReadOnlyImage,
        Self::PrivateTmp,
        Self::SyscallFilter,
        Self::AddressFamilies,
        Self::PtraceDenied,
        Self::DeviceAccessDenied,
        Self::KernelModulesDenied,
        Self::RawSocketsDenied,
        Self::CoreDumpsDisabled,
        Self::SecretLocking,
    ];

    /// Returns the fixed report name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnprivilegedAccount => "unprivileged-account",
            Self::NoNewPrivileges => "no-new-privileges",
            Self::ReadOnlyImage => "read-only-image",
            Self::PrivateTmp => "private-tmp",
            Self::SyscallFilter => "syscall-filter",
            Self::AddressFamilies => "address-families",
            Self::PtraceDenied => "ptrace-denied",
            Self::DeviceAccessDenied => "device-access-denied",
            Self::KernelModulesDenied => "kernel-modules-denied",
            Self::RawSocketsDenied => "raw-sockets-denied",
            Self::CoreDumpsDisabled => "core-dumps-disabled",
            Self::SecretLocking => "secret-locking",
        }
    }
}

/// The observed state of one control; unreadable input is never reported as present.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ControlState {
    /// The control was observed in effect.
    Present,
    /// The control was observed absent.
    Absent,
    /// The control could not be observed.
    Unknown,
}

impl ControlState {
    /// Returns the fixed report name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Absent => "absent",
            Self::Unknown => "unknown",
        }
    }
}

/// The complete control report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostControlReport {
    states: [ControlState; 12],
}

impl HostControlReport {
    /// Returns the state of one control.
    #[must_use]
    pub fn state(&self, control: HostControl) -> ControlState {
        let position = HostControl::ALL
            .iter()
            .position(|candidate| *candidate == control)
            .unwrap_or(0);
        self.states
            .get(position)
            .copied()
            .unwrap_or(ControlState::Unknown)
    }

    /// Iterates every control with its state in report order.
    pub fn iter(&self) -> impl Iterator<Item = (HostControl, ControlState)> + '_ {
        HostControl::ALL
            .iter()
            .copied()
            .zip(self.states.iter().copied())
    }

    /// Returns the controls observed absent.
    #[must_use]
    pub fn absent(&self) -> Vec<HostControl> {
        self.iter()
            .filter(|(_, state)| *state == ControlState::Absent)
            .map(|(control, _)| control)
            .collect()
    }
}

impl fmt::Display for HostControlReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (control, state) in self.iter() {
            writeln!(
                formatter,
                "control={} state={}",
                control.as_str(),
                state.as_str()
            )?;
        }
        Ok(())
    }
}

/// A procfs source the probes read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostSource {
    /// `/proc/self/status`.
    ProcStatus,
    /// `/proc/self/mountinfo`.
    MountInfo,
}

/// A resource limit the probes read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostLimit {
    /// `RLIMIT_CORE`.
    Core,
    /// `RLIMIT_MEMLOCK`.
    Memlock,
}

/// Host facts, injectable so fixtures drive every branch.
pub trait HostReader {
    /// Reads one source, or `None` when unreadable.
    fn read(&self, source: HostSource) -> Option<String>;
    /// The effective user id.
    fn euid(&self) -> u32;
    /// A resource limit as `(current, maximum)` with `None` for unlimited, or
    /// `None` when unreadable.
    fn rlimit(&self, limit: HostLimit) -> Option<(Option<u64>, Option<u64>)>;
}

/// The live process as a host reader.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemHostReader;

impl HostReader for SystemHostReader {
    fn read(&self, source: HostSource) -> Option<String> {
        let path = match source {
            HostSource::ProcStatus => "/proc/self/status",
            HostSource::MountInfo => "/proc/self/mountinfo",
        };
        fs::read_to_string(path).ok()
    }

    fn euid(&self) -> u32 {
        rustix::process::geteuid().as_raw()
    }

    fn rlimit(&self, limit: HostLimit) -> Option<(Option<u64>, Option<u64>)> {
        let resource = match limit {
            HostLimit::Core => Resource::Core,
            HostLimit::Memlock => Resource::Memlock,
        };
        let value = getrlimit(resource);
        Some((value.current, value.maximum))
    }
}

/// Capability bounding-set bits (Linux `capability.h`).
const CAP_NET_RAW: u32 = 13;
const CAP_SYS_MODULE: u32 = 16;
const CAP_SYS_PTRACE: u32 = 19;

/// Probes every control (spec 6659-6675); absent controls are reported, not claimed.
pub fn probe_host_controls(
    reader: &impl HostReader,
    memory_budget_bytes: u64,
) -> HostControlReport {
    let status = reader.read(HostSource::ProcStatus);
    let mounts = reader.read(HostSource::MountInfo);
    let bounding = status.as_deref().and_then(capability_bounding_set);
    let states = [
        present_if(reader.euid() != 0),
        status_flag(status.as_deref(), "NoNewPrivs:", "1"),
        mount_state(mounts.as_deref(), read_only_root),
        mount_state(mounts.as_deref(), private_tmp),
        status_flag(status.as_deref(), "Seccomp:", "2"),
        ControlState::Unknown,
        capability_denied(bounding, CAP_SYS_PTRACE),
        mount_state(mounts.as_deref(), private_devices),
        capability_denied(bounding, CAP_SYS_MODULE),
        capability_denied(bounding, CAP_NET_RAW),
        core_dumps(reader.rlimit(HostLimit::Core)),
        memlock(reader.rlimit(HostLimit::Memlock), memory_budget_bytes),
    ];
    HostControlReport { states }
}

fn present_if(condition: bool) -> ControlState {
    if condition {
        ControlState::Present
    } else {
        ControlState::Absent
    }
}

fn status_value<'a>(status: &'a str, key: &str) -> Option<&'a str> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(key))
        .map(str::trim)
}

fn status_flag(status: Option<&str>, key: &str, present_value: &str) -> ControlState {
    match status.and_then(|status| status_value(status, key)) {
        Some(value) => present_if(value == present_value),
        None => ControlState::Unknown,
    }
}

fn capability_bounding_set(status: &str) -> Option<u64> {
    let value = status_value(status, "CapBnd:")?;
    u64::from_str_radix(value, 16).ok()
}

fn capability_denied(bounding: Option<u64>, bit: u32) -> ControlState {
    match bounding {
        Some(mask) => present_if(mask & (1_u64 << bit) == 0),
        None => ControlState::Unknown,
    }
}

fn mount_state(mounts: Option<&str>, probe: fn(&str) -> bool) -> ControlState {
    match mounts {
        Some(mounts) => present_if(probe(mounts)),
        None => ControlState::Unknown,
    }
}

/// One `/proc/self/mountinfo` line: root, mount point, options, and filesystem type.
struct MountEntry<'a> {
    root: &'a str,
    mount_point: &'a str,
    options: &'a str,
    fs_type: &'a str,
}

fn mount_entries(mounts: &str) -> impl Iterator<Item = MountEntry<'_>> {
    mounts.lines().filter_map(|line| {
        let (before, after) = line.split_once(" - ")?;
        let mut fields = before.split(' ');
        let root = fields.nth(3)?;
        let mount_point = fields.next()?;
        let options = fields.next()?;
        let fs_type = after.split(' ').next()?;
        Some(MountEntry {
            root,
            mount_point,
            options,
            fs_type,
        })
    })
}

fn read_only_root(mounts: &str) -> bool {
    mount_entries(mounts)
        .find(|entry| entry.mount_point == "/")
        .is_some_and(|entry| entry.options.split(',').any(|option| option == "ro"))
}

fn private_tmp(mounts: &str) -> bool {
    mount_entries(mounts)
        .filter(|entry| entry.mount_point == "/tmp")
        .any(|entry| entry.root.contains("systemd-private-"))
}

fn private_devices(mounts: &str) -> bool {
    mount_entries(mounts)
        .find(|entry| entry.mount_point == "/dev")
        .is_some_and(|entry| entry.fs_type == "tmpfs")
}

fn core_dumps(limit: Option<(Option<u64>, Option<u64>)>) -> ControlState {
    match limit {
        Some((current, _)) => present_if(current == Some(0)),
        None => ControlState::Unknown,
    }
}

fn memlock(limit: Option<(Option<u64>, Option<u64>)>, budget: u64) -> ControlState {
    match limit {
        Some((None, _)) => ControlState::Present,
        Some((Some(current), _)) => present_if(current >= budget),
        None => ControlState::Unknown,
    }
}

/// What process hardening achieved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HardeningOutcome {
    /// The process is no longer dumpable.
    pub dumpable_disabled: bool,
    /// `RLIMIT_CORE` is zero.
    pub core_limit_zero: bool,
    /// Current and future memory is locked.
    pub secrets_locked: bool,
}

/// Disables core dumps and locks process memory (spec 6673-6675).
///
/// A failed lock is a warning through `secrets_locked = false` unless
/// `require_locked_secrets` is set, in which case it is fatal.
pub fn apply_process_hardening(
    require_locked_secrets: bool,
) -> Result<HardeningOutcome, ConfigError> {
    let dumpable_disabled = set_dumpable_behavior(DumpableBehavior::NotDumpable).is_ok();
    let core_limit = getrlimit(Resource::Core);
    let core_limit_zero = core_limit.current == Some(0)
        || (setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        )
        .is_ok()
            && getrlimit(Resource::Core).current == Some(0));
    let secrets_locked = mlockall(MlockAllFlags::CURRENT | MlockAllFlags::FUTURE).is_ok();
    if require_locked_secrets && !secrets_locked {
        return Err(ConfigError::HostControl);
    }
    Ok(HardeningOutcome {
        dumpable_disabled,
        core_limit_zero,
        secrets_locked,
    })
}
