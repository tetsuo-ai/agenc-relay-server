//! Loopback listener addresses for fixtures that start the production binary.
//!
//! The daemon rejects port 0 in its configuration (Appendix C listener
//! `bind`), so a fixture must name a concrete port before the daemon binds
//! it. Probing `127.0.0.1:0`, closing the probe, and handing the port to the
//! daemon leaves a window in which the kernel gives the same ephemeral port
//! to any other socket on the host: nextest runs one process per test, so an
//! in-process claim set never saw the other processes, and the daemon then
//! failed its bind with `EADDRINUSE` (QA-04, issue #175).
//!
//! This allocator removes the window instead of narrowing it:
//!
//! * ports come only from outside the kernel's ephemeral range
//!   (`ip_local_port_range`), so neither an outgoing connection nor a
//!   port-0 bind anywhere on the host can be handed a fixture port; and
//! * each port is claimed with an exclusive advisory lock on a per-port file
//!   that the claiming process holds until it exits, so no other test
//!   process, nor another fixture in this process, selects it, and a crashed
//!   test releases its claims with its descriptors.
//!
//! The probe bind that follows the lock only skips a port that some
//! unrelated, fixed-port service already holds.
#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

/// Directory under the temporary root that holds one lock file per port.
const CLAIM_DIRECTORY: &str = "agenc-ircd-fixture-port-claims";
/// Lowest port a fixture uses; everything below is left to fixed services.
const LOWEST_FIXTURE_PORT: u16 = 10_240;
/// Fewest candidate ports that make a usable fixture range.
const MINIMUM_RANGE: u16 = 2_048;
/// The Linux default ephemeral range, assumed when `/proc` is unreadable.
const DEFAULT_EPHEMERAL: (u16, u16) = (32_768, 60_999);

/// Lock files this process holds; a claim lasts until the process exits.
static HELD_CLAIMS: Mutex<Vec<File>> = Mutex::new(Vec::new());
/// Spreads successive searches in one process across the range.
static SEARCHES: AtomicU32 = AtomicU32::new(0);

/// Returns a loopback address no other cooperating fixture holds and the
/// kernel never assigns on its own.
pub(crate) fn reserve() -> io::Result<SocketAddr> {
    let range = fixture_range(ephemeral_range());
    let directory = claim_directory()?;
    let span = u32::from(range.end.saturating_sub(range.start));
    if span == 0 {
        return Err(io::Error::other("no fixture port range is available"));
    }
    let search = SEARCHES.fetch_add(1, Ordering::Relaxed);
    let start = std::process::id()
        .wrapping_mul(2_654_435_761)
        .wrapping_add(search.wrapping_mul(40_503))
        % span;
    for step in 0..span {
        let offset = u16::try_from((start + step) % span).map_err(io::Error::other)?;
        let port = range.start.saturating_add(offset);
        if let Some(address) = claim(&directory, port)? {
            return Ok(address);
        }
    }
    Err(io::Error::other("every fixture port is claimed"))
}

/// Claims one port, or returns `None` when another fixture or an unrelated
/// listener already holds it.
fn claim(directory: &std::path::Path, port: u16) -> io::Result<Option<SocketAddr>> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(directory.join(port.to_string()))?;
    match file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return Ok(None),
        Err(TryLockError::Error(error)) => return Err(error),
    }
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    if TcpListener::bind(address).is_err() {
        // Dropping the file releases the lock; the port belongs to a
        // service outside the fixtures.
        return Ok(None);
    }
    HELD_CLAIMS
        .lock()
        .map_err(|_| io::Error::other("fixture port claims are poisoned"))?
        .push(file);
    Ok(Some(address))
}

fn claim_directory() -> io::Result<PathBuf> {
    let directory = std::env::temp_dir().join(CLAIM_DIRECTORY);
    fs::create_dir_all(&directory)?;
    Ok(directory)
}

/// Reads the kernel's ephemeral port range as an inclusive pair.
fn ephemeral_range() -> (u16, u16) {
    fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|text| parse_ephemeral(&text))
        .unwrap_or(DEFAULT_EPHEMERAL)
}

fn parse_ephemeral(text: &str) -> Option<(u16, u16)> {
    let mut fields = text.split_ascii_whitespace();
    let low = fields.next()?.parse().ok()?;
    let high = fields.next()?.parse().ok()?;
    (low <= high).then_some((low, high))
}

/// Chooses the fixture ports: below the ephemeral range when that leaves
/// enough room, otherwise above it; empty when neither side has room.
fn fixture_range((low, high): (u16, u16)) -> Range<u16> {
    if low >= LOWEST_FIXTURE_PORT.saturating_add(MINIMUM_RANGE) {
        return LOWEST_FIXTURE_PORT..low;
    }
    let above = high.saturating_add(1).max(LOWEST_FIXTURE_PORT);
    if u16::MAX.saturating_sub(above) >= MINIMUM_RANGE {
        return above..u16::MAX;
    }
    0..0
}

#[test]
fn fixture_ports_never_overlap_the_ephemeral_range() {
    assert_eq!(fixture_range((32_768, 60_999)), 10_240..32_768);
    assert_eq!(fixture_range((1_024, 49_999)), 50_000..u16::MAX);
    assert_eq!(fixture_range((1_024, 65_535)), 0..0);
    assert_eq!(parse_ephemeral("32768\t60999\n"), Some((32_768, 60_999)));
    assert_eq!(parse_ephemeral("9 1"), None);
    assert_eq!(parse_ephemeral("x"), None);
    let (low, high) = ephemeral_range();
    let range = fixture_range((low, high));
    assert!(range.end <= low || range.start > high);
}

#[test]
fn a_claimed_port_is_refused_to_every_later_claim_until_the_holder_exits() -> io::Result<()> {
    let first = reserve()?;
    let directory = claim_directory()?;
    assert_eq!(
        claim(&directory, first.port())?,
        None,
        "a second descriptor must not take a port this process still claims"
    );
    let (low, high) = ephemeral_range();
    assert!(first.port() < low || first.port() > high);
    Ok(())
}

#[test]
fn a_port_held_by_an_unrelated_listener_is_skipped() -> io::Result<()> {
    let address = reserve()?;
    let _listener = TcpListener::bind(address)?;
    // Another process sees the lock; this models one that does not take
    // locks at all by probing a fresh claim file for the same bound port.
    let directory = claim_directory()?.join("probe");
    fs::create_dir_all(&directory)?;
    assert_eq!(claim(&directory, address.port())?, None);
    Ok(())
}

#[test]
fn parallel_fixtures_keep_distinct_addresses() -> io::Result<()> {
    std::thread::scope(|scope| {
        let mut jobs = Vec::new();
        for _ in 0..8 {
            jobs.push(scope.spawn(|| (0..16).map(|_| reserve()).collect::<io::Result<Vec<_>>>()));
        }
        let mut addresses = std::collections::BTreeSet::new();
        for job in jobs {
            let assigned = job
                .join()
                .map_err(|_| io::Error::other("fixture address worker failed"))??;
            for address in assigned {
                assert!(
                    addresses.insert(address),
                    "fixture address was assigned twice"
                );
            }
        }
        assert_eq!(addresses.len(), 128);
        Ok(())
    })
}
