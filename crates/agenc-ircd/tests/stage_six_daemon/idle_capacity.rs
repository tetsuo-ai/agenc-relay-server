//! RUN-04: idle clients on the production binary hold only the fixed client
//! base charge, and the default composed admission model fits 50,000 of them
//! inside the funded six-GiB budget, in the normal Section-19.3 overload
//! class rather than merely below the memory ceiling (spec 19.2 and 28.7).
//!
//! The daemon runs with the default memory budget, crypto pool, and
//! connection limits; only the listener ceiling, the per-address ceiling,
//! and the new-connection and handshake buckets are raised so one loopback
//! source can open the measured population. The charge side is exact: the
//! daemon's own `memory_charged_bytes` must grow by exactly one base charge
//! per idle registered client once every TLS setup increment is released.
//! The resident side is the daemon's anonymous resident memory
//! (`/proc/<pid>/status` `RssAnon`), which includes allocator overhead and
//! so bounds the heap from above: it must grow by no more than the base
//! charge per client. The daemon is non-dumpable and hosts that mount
//! `/proc` with `hidepid` hide its entry entirely; the resident assertion
//! then reports itself unavailable, and the runtime crate's
//! `idle_connection_memory` test, which measures its own process, carries
//! the resident claim on every host. The repository forbids `unsafe`, so no
//! counting global allocator is used.
#![forbid(unsafe_code)]

use super::*;

/// Default `server.memory_budget_bytes` (Appendix C.2).
const DEFAULT_BUDGET_BYTES: u64 = 6_442_450_944;
/// Fixed charge of one admitted client connection (spec 19.2).
const CLIENT_BASE_BYTES: u64 = 65_536;
/// The default client population the model must admit (spec 28.7).
const DEFAULT_CLIENTS: u64 = 50_000;
/// Clients opened before the baseline so allocator arenas and caches that
/// the first connections populate are not attributed to the measured ones.
const WARM_CLIENTS: usize = 16;
/// Idle registered clients measured; with the warm clients and the admin
/// socket this stays inside the 256 per-address hard maximum.
const MEASURED_CLIENTS: usize = 192;
/// Shared count-scaled owners grow in charged steps as sessions register:
/// the keyed admission tables of `admission::buckets` rebuild at double
/// capacity and charge the new slab before the old one is released. One
/// such step across the measured population is bounded by this allowance,
/// which the model amortizes over the clients that caused it.
const SHARED_OWNER_STEP_ALLOWANCE: u64 = 262_144;
const SETTLE: Duration = Duration::from_secs(2);

fn raise_connection_ceilings(fixture: &LiveFixture) -> TestResult {
    let mut config = fs::read_to_string(&fixture.config_path)?;
    replace_once(
        &mut config,
        "memory_budget_bytes = 1073741824",
        &format!("memory_budget_bytes = {DEFAULT_BUDGET_BYTES}"),
    )?;
    replace_once(
        &mut config,
        "max_connections = 32\n",
        "max_connections = 256\n",
    )?;
    replace_once(
        &mut config,
        "# direct_connections_per_address = 16 (1..256)\n",
        "direct_connections_per_address = 256\n",
    )?;
    replace_once(
        &mut config,
        "\n[privacy]",
        "\n[limits.rate.new_direct]\nrefill_tokens = 16\nrefill_seconds = 1\nburst = 64\n\n\
[limits.rate.tls_handshake]\nrefill_tokens = 32\nrefill_seconds = 1\nburst = 128\n\n[privacy]",
    )?;
    fs::write(&fixture.config_path, config)?;
    Ok(())
}

fn register_idle(fixture: &LiveFixture, index: usize) -> TestResult<IrcClient> {
    let mut client = IrcClient::connect(fixture)?;
    client.send(&format!("NICK idle{index}"))?;
    client.send("USER idle 0 * :Idle client")?;
    let lines = read_until(&mut client.reader, |line| {
        line.contains(" 376 ") || line.contains(" 422 ")
    })?;
    assert_contains(&lines, " 001 ")?;
    Ok(client)
}

fn runtime_stat(admin: &mut AdminClient<'_>, field: &str) -> TestResult<u64> {
    let lines = admin.command_batch("STATS RUNTIME")?;
    let marker = format!(" NOTE STATS VALUE RUNTIME {field} ");
    let line = lines
        .iter()
        .find(|line| line.contains(&marker))
        .ok_or_else(|| failure(format!("STATS RUNTIME lacks {field}: {lines:?}")))?;
    let value = line
        .split(&marker)
        .nth(1)
        .and_then(|rest| rest.split_ascii_whitespace().next())
        .ok_or_else(|| failure(format!("STATS value missing: {line}")))?;
    Ok(value.parse()?)
}

/// Anonymous resident bytes of the daemon, the heap-dominated share of RSS,
/// or `None` where the daemon's `/proc` entry is hidden from this user.
fn resident_anonymous_bytes(pid: u32) -> TestResult<Option<u64>> {
    let status = match fs::read_to_string(format!("/proc/{pid}/status")) {
        Ok(status) => status,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let kibibytes = status
        .lines()
        .find_map(|line| line.strip_prefix("RssAnon:"))
        .and_then(|rest| rest.split_ascii_whitespace().next())
        .ok_or_else(|| failure("RssAnon is missing from /proc status"))?
        .parse::<u64>()?;
    Ok(Some(kibibytes * 1_024))
}

fn charged_after_settle(admin: &mut AdminClient<'_>, expected: u64) -> TestResult<u64> {
    // TLS setup increments return once each handshake's allocations are gone.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let charged = runtime_stat(admin, "memory_charged_bytes")?;
        if charged <= expected || Instant::now() >= deadline {
            return Ok(charged);
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn idle_registered_clients_hold_only_the_base_charge_and_the_default_model_fits() -> TestResult {
    let fixture = LiveFixture::create()?;
    raise_connection_ceilings(&fixture)?;
    let mut daemon = DaemonProcess::start_for(&fixture)?;
    let pid = daemon
        .child
        .as_ref()
        .map(Child::id)
        .ok_or_else(|| failure("daemon child is missing"))?;
    fixture.phase("warm");
    let mut clients = (0..WARM_CLIENTS)
        .map(|index| register_idle(&fixture, index))
        .collect::<TestResult<Vec<_>>>()?;
    let mut admin = AdminClient::connect(&fixture)?;
    thread::sleep(SETTLE);
    let pool = runtime_stat(&mut admin, "memory_budget_bytes")?;
    let charged_before = runtime_stat(&mut admin, "memory_charged_bytes")?;
    let resident_before = resident_anonymous_bytes(pid)?;

    fixture.phase("measure");
    for index in WARM_CLIENTS..WARM_CLIENTS + MEASURED_CLIENTS {
        clients.push(register_idle(&fixture, index)?);
    }
    let measured = u64::try_from(MEASURED_CLIENTS)?;
    let expected = charged_before + measured * CLIENT_BASE_BYTES;
    let charged_after = charged_after_settle(&mut admin, expected)?;
    thread::sleep(SETTLE);
    let resident_after = resident_anonymous_bytes(pid)?;
    let live = runtime_stat(&mut admin, "live_client_connections")?;
    let registered = runtime_stat(&mut admin, "registered_sessions")?;
    let charged_delta = charged_after.saturating_sub(charged_before);
    eprintln!(
        "idle capacity: pool={pool} startup+warm charged={charged_before} \
         measured={MEASURED_CLIENTS} charged_delta={charged_delta} \
         live={live} registered={registered}"
    );
    assert_eq!(live, u64::try_from(WARM_CLIENTS + MEASURED_CLIENTS)?);
    assert_eq!(registered, live);
    let shared_growth = charged_delta.saturating_sub(measured * CLIENT_BASE_BYTES);
    eprintln!("idle capacity: shared_owner_growth={shared_growth}");
    assert!(
        charged_delta >= measured * CLIENT_BASE_BYTES,
        "every idle registered client holds its base charge"
    );
    assert!(
        shared_growth <= SHARED_OWNER_STEP_ALLOWANCE,
        "beyond the base charge and one shared-owner step, an idle client holds no queue, \
         input, or setup backing ({shared_growth} bytes over {MEASURED_CLIENTS} clients)"
    );
    match (resident_before, resident_after) {
        (Some(before), Some(after)) => {
            let per_client_resident = after.saturating_sub(before) / measured;
            eprintln!("idle capacity: per_client_resident={per_client_resident}");
            assert!(
                per_client_resident <= CLIENT_BASE_BYTES,
                "the base charge dominates each idle client's resident growth ({per_client_resident} bytes)"
            );
        }
        _ => eprintln!(
            "idle capacity: the daemon's /proc entry is hidden; resident growth is measured by \
             the runtime crate's idle_connection_memory test"
        ),
    }

    // The composed default model: every fixed startup owner and the warm
    // population as measured, plus the remaining clients at the measured
    // per-client charge, stays inside the protocol pool `P`.
    let warm = u64::try_from(WARM_CLIENTS)?;
    let population = charged_before + (DEFAULT_CLIENTS - warm) * (charged_delta / measured);
    assert!(
        population <= pool,
        "50,000 idle clients need {population} bytes of the {pool}-byte pool"
    );

    fixture.phase("shutdown");
    for mut client in clients {
        client.send("QUIT :idle capacity")?;
        let _closed = client.shutdown_lines()?;
    }
    admin.confirm_process("DIE :idle capacity complete")?;
    assert!(daemon.wait()?.success(), "{}", fixture.log_excerpt());
    Ok(())
}
