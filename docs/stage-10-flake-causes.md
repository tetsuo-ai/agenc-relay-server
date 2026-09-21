# Flake causes found by the dynamic-analysis sweep

This record covers QA-04 (issue #175): a dynamic-analysis sweep ran the whole
workspace suite repeatedly under adverse scheduling (64 and 256 nextest
threads, then the same beside 64 and 128 CPU hogs) and traced every failure
that passed alone to its cause. Three causes were harness defects and are
repaired here, one was a product diagnosability defect and is repaired here,
and two product behaviours are reported with their evidence and left open.

## Repaired harness defects

### Probe-and-release port reservation

Every fixture that starts the production binary named its listener ports by
binding `127.0.0.1:0`, reading the port, closing the probe and writing the
port into the daemon's configuration. The kernel may give a released ephemeral
port to any other socket before the daemon binds it, and the in-process claim
sets could not see the other test processes nextest runs. Under `strace` the
failing daemons show `bind(...) = -1 EADDRINUSE` (139 of 139 startup failures
in 384 pressured iterations); the same race also let a test reach another
fixture's daemon, which surfaced as `InvalidCertificate(BadSignature)`,
`NoApplicationProtocol` and `InvalidContentType`.

The daemon rejects port 0 by specification (Appendix C listener `bind`) and
does not adopt inherited sockets, so the fixtures cannot read a bound port
back. `crates/agenc-relay-server/tests/support/loopback_ports.rs` removes the window
instead: ports are taken only from outside the kernel's
`ip_local_port_range`, so no connect or port-0 bind on the host can be handed
one, and each port is claimed by an exclusive advisory lock on a per-port file
held until the claiming test process exits. Stage 06, Stage 07 and Stage 08
fixtures all allocate through it; the two per-file claim sets are removed.

### Wall-clock deadline in `StateCoreFixture::commit_fixture_batch`

The fixture waited five seconds for a real storage owner to acknowledge a
batch. Six `delivery_restart` tests seed 4,097 bodies in one batch and failed
with `Elapsed(())` on every hog round while the commit was still progressing
(`rust-gdb` stops `tokio::time::error::Elapsed::new` under
`commit_fixture_batch` from `seed_retained`). The receipts are now awaited
without a deadline; a stopped storage owner closes its channel, which still
ends the wait with an error.

### Close race in `local_admin_lines_never_enter_the_public_client_inbox`

The listener refuses the admin peer as `AdminOwner` and closes it unread. The
test's client thread raced that close with its write and failed on `EPIPE`
(38 of 144 runs under load). `EPIPE`, `ECONNRESET` and `ENOTCONN` on that
write are now the refusal under test; the `Refused(AdminLocal, AdminOwner)`
observation is still asserted.

### Fixed settle in `DrillNodes::start_capturing`

The drill network waited for the federation links and then slept two seconds
before its first account operation. A link is established before an edge can
serve an account, so on a loaded host the first creation was answered `FAIL
ACCTCREATE UNAVAILABLE`. QA-03 repaired the same gap in `restart`; the start
path now also waits for `wait_for_account_authority` on both edges.

## Repaired product diagnosability

A listener the operating system refuses to bind was reported as `runtime
startup failed: runtime value violates its invariant`. `ListenerError::TcpBind`
now keeps the configured address, the `std::io::ErrorKind` and the raw
`errno`, `DaemonError::Listener` carries it, and the operator reads `listener
startup failed: listener socket could not be bound: address=127.0.0.1:6697
error=EADDRINUSE os_error=98`. The regression is
`production_serve_names_the_address_and_the_os_error_of_a_refused_bind`.

A timed-out shutdown phase was reported as `daemon shutdown exceeded its
deadline` with the phase dropped. `DaemonError::ShutdownPhaseTimeout` keeps
it (`... : phase=drain`), which is what identified the two behaviours below.

## Open product behaviours

**An edge cannot drain while a snapshot install awaits its coordinator.** An
`rr` recording of `sequencer_rotation_and_leaf_retirement_hold_the_encrypted_channel`
(`/mnt/data/agenc-dev/sweep/rr/rotation/trace-1`, edge pid 2671151) shows the
edge's `ShutdownReport` with `Drain` and `Flush` timed out while every thread
of the process is parked. Walking back from the timeout, the last
`EdgeFederation::reload_ready` returned `false` because `snapshot` held a
`SnapshotInstall { verified: true, ready_sent: true, written: 0, .. }`: the
edge had sent `READY` and was waiting for an answer the coordinator never
sent. The state core acknowledges `Drain` only at a reload-ready safe point,
so a stopping edge whose coordinator is slow or gone spends its drain and
flush budgets and exits 1. It is not patched here.

**`flush` outlives a four-second budget under extreme load.** With 128 hogs
and 256 test threads, a single node holding 208 clients and an edge in
`a_recovering_member_rejoins_and_reads_only_the_history_it_is_entitled_to`
both ended with `phase=flush`. The fixtures shorten the default ten-second
flush to four.

In that recording the coordinator died of `SIGSEGV` inside rustix's direct
vDSO `clock_gettime` call (`delivery_owner/clock.rs`), in both
federation recordings and never outside `rr`; it is treated as an artefact of
this `rr` build and is why the deletion-drill recording could not be used.
The idle-capacity recording failed on a resident-memory assertion that only
runs when `rr` makes the daemon's `/proc` entry visible.

## Rounds

Failures per round, 3,253 tests before and 3,262 after:

| Condition | Before | After |
| --- | --- | --- |
| 64 threads, 64 hogs | 4, 4, 4, 3 | 0, 0 |
| 256 threads, 128 hogs | 7, 7, 6, 8 | 1, 4 |

The five remaining failures are the two `phase=flush` exits above, two
daemons that had not opened their listener inside the fixtures' twenty-second
start budget, and one single-node `FAIL ACCTCREATE UNAVAILABLE`; none shows a
bind refusal.
