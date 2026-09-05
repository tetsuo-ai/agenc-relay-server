//! Released probe sockets must not give two parallel fixtures the same port.
#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::net::{SocketAddr, TcpListener};
use std::sync::Mutex;

use super::{TestResult, failure};

const PORT_COUNT: usize = 65_536;
const CANDIDATE_LIMIT: usize = 128;
static CLAIMED_PORTS: Mutex<[bool; PORT_COUNT]> = Mutex::new([false; PORT_COUNT]);

pub(super) fn reserve() -> TestResult<SocketAddr> {
    let mut claims = CLAIMED_PORTS
        .lock()
        .map_err(|_| failure("fixture address claims were poisoned"))?;
    reserve_from(&mut claims, || {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        Ok(listener.local_addr()?)
    })
}

fn reserve_from(
    claims: &mut [bool; PORT_COUNT],
    mut candidate: impl FnMut() -> TestResult<SocketAddr>,
) -> TestResult<SocketAddr> {
    for _ in 0..CANDIDATE_LIMIT {
        let address = candidate()?;
        let claimed = claims
            .get_mut(usize::from(address.port()))
            .ok_or_else(|| failure("fixture port exceeds its bitmap"))?;
        if !*claimed {
            *claimed = true;
            return Ok(address);
        }
    }
    Err(failure(
        "distinct fixture port allocation exhausted its attempt limit",
    ))
}

#[test]
fn repeated_kernel_candidates_cannot_reassign_a_fixture_port() -> TestResult {
    let first = SocketAddr::from(([127, 0, 0, 1], 25_000));
    let second = SocketAddr::from(([127, 0, 0, 1], 25_001));
    let mut claims = [false; PORT_COUNT];
    assert_eq!(reserve_from(&mut claims, || Ok(first))?, first);
    let mut candidates = [first, second].into_iter();
    let selected = reserve_from(&mut claims, || {
        candidates
            .next()
            .ok_or_else(|| failure("candidate sequence exhausted"))
    })?;
    assert_eq!(selected, second);
    assert!(reserve_from(&mut claims, || Ok(first)).is_err());
    Ok(())
}

#[test]
fn parallel_fixtures_keep_distinct_addresses_after_probe_sockets_close() -> TestResult {
    std::thread::scope(|scope| {
        let mut jobs = Vec::new();
        for _ in 0..8 {
            jobs.push(scope.spawn(|| (0..64).map(|_| reserve()).collect::<TestResult<Vec<_>>>()));
        }
        let mut addresses = BTreeSet::new();
        for job in jobs {
            let assigned = job
                .join()
                .map_err(|_| failure("fixture address worker failed"))??;
            for address in assigned {
                assert!(
                    addresses.insert(address),
                    "fixture address was assigned twice"
                );
            }
        }
        assert_eq!(addresses.len(), 512);
        Ok(())
    })
}
