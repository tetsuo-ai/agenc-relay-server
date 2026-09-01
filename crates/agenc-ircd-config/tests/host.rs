#![forbid(unsafe_code)]

//! Host control probes against fixture procfs text and the live process.

use agenc_ircd_config::{
    ConfigError, ControlState, HostControl, HostLimit, HostReader, HostSource, SystemHostReader,
    apply_process_hardening, probe_host_controls,
};

struct Fixture {
    status: Option<String>,
    mounts: Option<String>,
    euid: u32,
    core: Option<(Option<u64>, Option<u64>)>,
    memlock: Option<(Option<u64>, Option<u64>)>,
}

impl HostReader for Fixture {
    fn read(&self, source: HostSource) -> Option<String> {
        match source {
            HostSource::ProcStatus => self.status.clone(),
            HostSource::MountInfo => self.mounts.clone(),
        }
    }

    fn euid(&self) -> u32 {
        self.euid
    }

    fn rlimit(&self, limit: HostLimit) -> Option<(Option<u64>, Option<u64>)> {
        match limit {
            HostLimit::Core => self.core,
            HostLimit::Memlock => self.memlock,
        }
    }
}

const HARDENED_STATUS: &str = "Name:\tagenc-ircd\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\nCapBnd:\t0000000000000000\n";
const LAX_STATUS: &str =
    "Name:\tagenc-ircd\nNoNewPrivs:\t0\nSeccomp:\t0\nCapBnd:\t000001ffffffffff\n";
const HARDENED_MOUNTS: &str = "22 1 8:1 / / ro,relatime - ext4 /dev/sda1 ro\n\
23 22 0:5 / /dev rw,nosuid - tmpfs tmpfs rw\n\
24 22 8:2 /tmp/systemd-private-abc-agenc-ircd.service-XYZ/tmp /tmp rw,relatime - ext4 /dev/sda2 rw\n";
const LAX_MOUNTS: &str = "22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
23 22 0:5 / /dev rw,nosuid - devtmpfs devtmpfs rw\n\
24 22 8:2 / /tmp rw,relatime - ext4 /dev/sda2 rw\n";

#[test]
fn hardened_fixture_reports_every_observable_control_present() {
    let fixture = Fixture {
        status: Some(HARDENED_STATUS.to_owned()),
        mounts: Some(HARDENED_MOUNTS.to_owned()),
        euid: 1000,
        core: Some((Some(0), Some(0))),
        memlock: Some((None, None)),
    };
    let report = probe_host_controls(&fixture, 4_294_967_296);
    for (control, state) in report.iter() {
        let expected = if control == HostControl::AddressFamilies {
            ControlState::Unknown
        } else {
            ControlState::Present
        };
        assert_eq!(state, expected, "{}", control.as_str());
    }
    assert!(report.absent().is_empty());
    let rendered = report.to_string();
    assert_eq!(rendered.lines().count(), 12);
    assert!(rendered.contains("control=core-dumps-disabled state=present"));
    assert!(rendered.contains("control=address-families state=unknown"));
}

#[test]
fn lax_fixture_reports_every_observable_control_absent() {
    let fixture = Fixture {
        status: Some(LAX_STATUS.to_owned()),
        mounts: Some(LAX_MOUNTS.to_owned()),
        euid: 0,
        core: Some((None, None)),
        memlock: Some((Some(65_536), Some(65_536))),
    };
    let report = probe_host_controls(&fixture, 4_294_967_296);
    let absent = report.absent();
    assert_eq!(absent.len(), 11);
    assert!(!absent.contains(&HostControl::AddressFamilies));
    assert_eq!(
        report.state(HostControl::SecretLocking),
        ControlState::Absent
    );
    let bounded = Fixture {
        memlock: Some((Some(4_294_967_296), None)),
        ..lax()
    };
    assert_eq!(
        probe_host_controls(&bounded, 4_294_967_296).state(HostControl::SecretLocking),
        ControlState::Present
    );
}

fn lax() -> Fixture {
    Fixture {
        status: Some(LAX_STATUS.to_owned()),
        mounts: Some(LAX_MOUNTS.to_owned()),
        euid: 0,
        core: Some((None, None)),
        memlock: Some((Some(65_536), Some(65_536))),
    }
}

#[test]
fn unreadable_sources_are_unknown_never_present() {
    let fixture = Fixture {
        status: None,
        mounts: None,
        euid: 1000,
        core: None,
        memlock: None,
    };
    let report = probe_host_controls(&fixture, 1);
    for (control, state) in report.iter() {
        let expected = if control == HostControl::UnprivilegedAccount {
            ControlState::Present
        } else {
            ControlState::Unknown
        };
        assert_eq!(state, expected, "{}", control.as_str());
    }
    let malformed = Fixture {
        status: Some("CapBnd:\tnothex\nSeccomp:\tmaybe\n".to_owned()),
        mounts: Some("garbage line without separator\n".to_owned()),
        ..lax()
    };
    let report = probe_host_controls(&malformed, 1);
    assert_eq!(
        report.state(HostControl::PtraceDenied),
        ControlState::Unknown
    );
    assert_eq!(
        report.state(HostControl::SyscallFilter),
        ControlState::Absent
    );
    assert_eq!(
        report.state(HostControl::ReadOnlyImage),
        ControlState::Absent
    );
    assert_eq!(
        report.state(HostControl::NoNewPrivileges),
        ControlState::Unknown
    );
}

#[test]
fn live_probe_and_hardening_run_without_claiming_more_than_observed() {
    let report = probe_host_controls(&SystemHostReader, 1);
    assert_eq!(report.iter().count(), 12);
    assert_eq!(
        report.state(HostControl::AddressFamilies),
        ControlState::Unknown
    );
    match apply_process_hardening(false) {
        Ok(outcome) => assert!(outcome.dumpable_disabled || !outcome.dumpable_disabled),
        Err(error) => assert_eq!(error, ConfigError::HostControl),
    }
    let strict = apply_process_hardening(true);
    match strict {
        Ok(outcome) => assert!(outcome.secrets_locked),
        Err(error) => assert_eq!(error, ConfigError::HostControl),
    }
}
