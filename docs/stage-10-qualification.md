# Stage 10 production qualification

Stage 10 is in progress. Stage 09 supplies the implemented optional profiles
and its recorded checkpoint. Stage 10 requires evidence from the exact
release binaries on both native targets. No Stage 10 release decision has
been signed.

## Current repair status

The findings below distinguish observed faults, tested worktree repairs, and
remaining implementation work. Development runs do not qualify an immutable
release candidate.

| Area | Current evidence and remaining work |
| --- | --- |
| Restored account authentication | CAP-9 and CAP-54 repairs pass strict restore and disaster-restore drills with existing and new accounts. CAP-7 passes post-restart authentication in the uninstrumented 64-client campaign at `b735700`. |
| Account deletion and rekey | CAP-11, CAP-57, and CAP-62 through CAP-67 pass the complete strict deletion drill, including exact authenticated rows, both deleted-login refusals, the surviving account, and all final stops. |
| Federation and client replies | CAP-47 through CAP-60 have focused regression evidence and passing workspace gates. The uninstrumented 64-client campaign at `b735700` passes all eight scenarios. |
| Disk pressure | CAP-44 and CAP-45 fix reset cleanup and durable request reconstruction. CAP-3 preserves the original refused session through pressure recovery. CAP-87 removes premature origin retirement after a pending or refused journal write; both regressions and all 100 edge tests pass. The uninstrumented 64-client campaign at `b735700` passes original-session pressure recovery. |
| Reconnect and shutdown load | The current CAP-4 release probe survives the unpaced reconnect wave, admits eight fresh clients after recovery, and stops all three daemons cleanly. The 64-client campaign at `b735700` also returns all clients to its resource envelope and stops all three daemons cleanly. |
| Implementation under qualification | CAP-5 stopped rotation commands, live two-account migration, and stale START cleanup pass. Actual rotation passes the 64-client, five-minute capacity campaign in `cap91-rotation-final`. The explicit maintenance export profile passes signed transport, actual storage, and full repository gates. CAP-13 batching passes the 64-client campaign at `b735700`; CAP-91 adds two controlled gathering-checkpoint regressions. |
| Companion delivery recovery | CAP-70 and CAP-71 now persist and reconstruct both endpoints of unfinished combined barriers. Real-storage tests cover both ACK orders, refused writes, lost publication callbacks, and final-ACK resume. CAP-79 still requires the published replay retention bounds. |
| Declared recovery | CAP-72 discards obsolete companion delivery, replay, and barrier state and marks typed live routes pending. CAP-73 now gates ordinary mutations before signing; terminal-evidence ingestion remains open. CAP-74 persists witnesses and blocks ordinary resume across restart; authenticated witness resolution remains open. |
| ReInit admission | CAP-86 now rejects outside binding accounts before attempt, activation, or abort signing. Three regressions fail without the checks and pass with them, including valid in-group controls and absent-signer refusal. The remaining device-to-leaf and continuing-member checks need separate evidence. |
| Physical storage growth | STO-1 remains open. The measured storage batch exceeds both the qualification ceiling and operational reserve; a smaller page size alone does not establish a universal bound. |
| Release qualification | The release coverage floor, full fuzz and model runs, both native targets, seven-day soak, external E2EE review, and signed decision remain open. |

The repair set committed as `74b869d` passes the required development gates
on 2026-09-07:
`cargo fmt --all --check`, workspace Clippy with all targets and features and
warnings denied, the locked all-feature workspace test suite, source check
and self-test, workspace policy check, and the critical coverage self-test.
The exact test command reports 2,093 passing tests, no failures, and 21 ignored
qualification tests across 118 targets. The source checker accepts 596 Rust
files. Both coverage inventories bind the same 472 production source files;
the release policy names 115 critical regions and retains its 90 percent
overall and 100 percent critical branch floors. These checks do not replace
the outstanding coverage measurement or ignored qualification campaigns.

The CAP-3 repair committed as `e6dd301` also passes every required development
gate. Its workspace
run reports 2,115 passing tests, no failures, and 21 ignored qualification
tests across 118 targets. Source policy accepts 600 Rust files. Both reviewed
inventories bind 476 production source files, and the release policy covers
127 critical regions with its coverage floors unchanged. The strict release
campaign passes original-session pressure recovery but fails later restart
synchronization, so this repair does not close capacity qualification.

The resumed schema-3 repair checkpoint passes every required development gate
on 2026-09-07. The locked all-feature workspace suite reports 2,400 passing
tests, zero failures, and 21 ignored qualification tests across 120 test
results. Formatting, all-target Clippy with warnings denied, source check and
self-test, workspace policy, and coverage-checker self-test all pass. Source
policy accepts 748 Rust files. Both reviewed inventories bind 617 source files;
the release policy contains 656 critical regions with its existing coverage
floors unchanged. This validates policy structure and source identity; no new
branch-coverage measurement is claimed. Exact commands and logs are recorded
in `resumed-final-gates.json` in the qualification scratch directory.

The uninstrumented release campaign in `resumed-capacity-64` fails after
251.19 seconds at the strict post-coordinator-restart readiness check. The
64-client run reaches reconnect, churn, snapshot queries, OPAQUE login,
first-attempt disk-pressure recovery, backup, and edge-b loss/return. Both
edges then repeatedly reconnect and acknowledge the encrypted profile without
reaching active base federation. The campaign does not reach rekey, its final
drain, or the required duration. This reproduces the earlier intermittent
restart loop; no cause or repair is established by this run. The exact daemon
and test executable hashes remain unchanged throughout, as recorded in
`resumed-capacity-result.json`. All three daemon logs and worker errors are
preserved. This campaign still exercises index reconstruction rather than
actual login-index rotation, which remains separate under CAP-5.

## Current implementation

The shutdown fix allows unrelated database writes while a signed audit scan
runs. The admin owner serializes audit mutations, and the scan checks its
captured event and checkpoint chain heads. It continues to reject malformed
rows, invalid signatures, gaps, changed audit heads, regressing storage
positions, and truncated pages that make no progress. Shutdown errors now
identify the failed phase and owner using fixed labels.

Local build information is available without starting a node or reading its
secrets.

```sh
agenc-ircd --version
agenc-ircd version --json
agenc-ircd conformance --json
```

The JSON reports the compiler, target, storage schema, compiled optional
features, and source identities supplied by the release builder. Ordinary
development builds report unknown source identities. The conformance command
reports each compiled profile separately and leaves `qualified_claims` empty.
A detached signed release decision supplies completed qualification. The IRC
`VERSION` response retains its existing disclosure limits.

The test client has separate unverified, verified, transparency-observed, and
security-changed states. Unexpected changes block sending until the changed
bindings are authenticated and explicitly reviewed. Decrypted text is
rendered as data, with controls and HTML metacharacters escaped. These tests
do not certify the presentation behavior of third-party clients.

## Candidate and execution records

`scripts/qualify-release.py` defines `check`, `prepare`, `run`, `resume`,
`status`, `close`, and `verify`. Candidate preparation requires a clean detached source
checkout, one independently reproduced build record for each native target
named with `--target`, and one client tools record per target from
`scripts/build-qualification-tools.py` named with `--tools`. The tools image
carries the pinned WeeChat, Irssi, Tor, and packet capture tools for the
interoperability job; it is distinct from the release build image, and its
record must name the committed client pins and Dockerfile digest. `prepare`
copies the binaries, build evidence, and tools records into a new candidate
directory. Source, lockfile, policy, command, binary, build-record, and
tools-record hashes bind each attempt to that candidate.

Every attempt has an immutable start record, a bounded combined output log,
measured elapsed and child CPU time, a driver report, and a result record.
The runner allows one active job per candidate directory. Separate native
hosts can execute separate copies, preserving their target-specific attempt
directories when the evidence is collected.

`resume` retains prior attempts. A successful attempt can be reused only when
its evidence still verifies and its host tool identity matches. A failed or
interrupted attempt remains visible and prevents closure. A successful retry
does not dispose of a failure. Fixes that change the source require a new
candidate and new qualification.

The runner rejects duplicate JSON fields, non-finite numbers, path traversal,
symlink artifacts, non-regular inputs, altered logs, modified artifacts,
unknown fields, and mismatched source or target identities. Log exhaustion
and command timeouts produce failures. The CPU accounting includes descendants
that drivers join, so each driver must wait for its workers before exiting.

## Release builds

`scripts/build-release.py build` exports the tracked source, acquires locked
dependencies, and performs two clean native builds inside the same container
image pinned by digest. Each build has a separate output directory, a
read-only source and dependency mount, and networking disabled for the whole
container. Cargo runs with `--frozen`. Compiler and native-library identities
are recorded, and the two binary hashes must match.

An image reference must contain a repository digest or a local `sha256` image
ID. The builder names each container and removes it even if its Docker client
times out. Both runs must reproduce the binary, tool identities, SBOM, and
notice file.

The container image must provide Python 3.11 or later, the pinned Rust 1.98.0
toolchain, Cargo, a native C compiler and linker, and `ldd`. The image must
already be present locally. Cross-compilation or emulation does not count as
the other target's native qualification.

`scripts/build-release-image.py` builds that image from
`conformance/release/Dockerfile`: Ubuntu 24.04 pinned by digest with
build-essential and Python, plus the host's pinned Rust 1.98.0 sysroot copied
into the build context, so no network is needed for the toolchain. The record
it writes names the image ID, the base image, the Dockerfile digest, the
compiler the image reports, and the digest of the installed package list,
which it retains. Pass the printed image ID to `build-release.py build`.

```sh
python3 scripts/build-release-image.py --output /path/to/release-image
python3 scripts/build-release.py build \
  --image "$(cat /path/to/release-image/image-id.txt)" --output /path/to/build
```

The SBOM resolves each native library the binary links to its Ubuntu
package, version, and architecture with dpkg and records a `pkg:deb/ubuntu`
package URL and the digest of the package's copyright file. The glibc and
libgcc copyright files are free-form rather than machine-readable, so the
SPDX license expression for a native package comes only from
`conformance/release-dependency-decisions.toml`, which names the reviewed
expression for an exact package, version, architecture, and copyright
digest. The same file records an explicit decision for each workspace crate,
which has no download location and no license file, and for the patched
`opaque-ke` tree. `build-release.py verify`, the reproducibility job, refuses
a build whose SBOM still carries a `NOASSERTION` without a matching decision.
A rebuilt image with a newer libc therefore fails until the new version is
reviewed and recorded.

`.github/workflows/stage-10-aarch64.yml` runs the same two steps on a hosted
`ubuntu-24.04-arm` runner and uploads the image record and the build
directory. `prepare` on a machine holding both build records creates a
two-target candidate; the aarch64 qualification jobs must then run on an
aarch64 host against that candidate, which the hosted six-hour job limit does
not allow for the fuzz and soak campaigns. Until that evidence exists, an
x86_64-only candidate is prepared with `--target x86_64-unknown-linux-gnu`.

Build output includes a deterministic archive, an SPDX 2.3 dependency report,
available dependency license and notice text, compiler metadata, and both raw
build logs. The dependency report includes build and test dependencies as well
as production dependencies. `NOASSERTION` identifies unavailable license or
native-package information and must be resolved during release review.

The workspace currently uses version `0.0.0`; source-qualified archive names
identify development candidates without inventing a release version or a
license for the project.

## Required campaign lengths

Each fuzz target must accumulate at least 86,400 measured CPU seconds with
the recorded sanitizer and corpus. The driver records bounded segments and
stops at the first failure. Short deterministic fuzz tests remain useful
development checks and cannot satisfy this requirement.

The sustained-operation gate requires at least 604,800 elapsed seconds on
named hardware. It must demonstrate configured capacity, record the required
latency classes and resource limits, exercise every required operational
scenario, and return within its resource limits after load ends. Neither the
existing short soak test nor a report with an asserted duration supplies
that evidence.

Release coverage requires at least 90 percent branches, 90 percent lines,
and 100 percent of all designated critical branches. The inherited coverage
policy retains its 75 percent interim branch floor for development. The
release policy and the current measurement are described under Coverage.

## Remaining work

The network driver now compiles integration-test executables into a private
target directory, installs the frozen daemon at their `CARGO_BIN_EXE` path,
and checks its hash before and after each test. It refuses an absent, ignored,
or incomplete selected test. Live WeeChat and Irssi development sessions pass
with the documented ALPN patches. The isolated Tor development test also
passes. Three native client sessions used separate circuits for two contexts,
reused the first context's circuit on reconnect, returned encrypted PONGs, and
shut down cleanly. Packet capture reported zero DNS packets, zero plaintext
canary matches, and zero kernel drops. This evidence covers the local x86_64
development build.

The capacity and sustained-operation driver, the operational drill driver,
the source-status checker, the claims checker, the release image builder,
and the release coverage inventory are implemented (below). `check` refuses a
policy whose required driver is absent. The x86_64 release build reproduced
bit for bit in two independent containers; the aarch64 build record, the
branch coverage floor, and the long campaigns have not been completed. The
detached signing path is exercised only with disposable keys.

Network evidence must include real WeeChat and Irssi sessions, the native
account protocol, OpenMLS and mls-rs, an isolated Tor v3 network, SOCKS
isolation, packet and DNS-leak capture, privacy canaries, and the client-policy
tests. Configuration parsing alone cannot close the Tor requirement.

Storage evidence comes from the final binary's own `storage qualify` command
(below). Earlier redb component measurements cannot substitute for it.

Operational evidence must cover restore, migration, deletion, rekey,
login-index transition, each signing and transport key rotation, compromise
response, resynchronization, host hardening, and observability.

## Storage qualification on the final binary

`agenc-ircd storage qualify` is a stopped-daemon command. It creates a fresh
database in a new state directory, opens the production storage owner with a
measurement-only boundary probe attached, and commits every Section 28.7
mutation shape through the production engine: empty, single, replaced, and
deleted rows; the largest value; the largest legal replacement, which the
tracked-byte ceiling limits to about 8 MB because the replaced and replacing
sealed rows are charged together; the largest key; 65,535-row inserts,
deletes, and a mixed batch; B-tree split, merge, and fragmented layouts; and a
checkpoint. Allocated blocks of the whole state directory are measured around
each case and at every guard, manifest, checkpoint, backup, and transaction
boundary the engine passes, so the guard temporary sync, rename, and directory
sync cases come from the production guard replacement itself. Reserve
boundaries use the real `R(F) + G` and `R(F) + O` admission checks on a second
minimal database: the fixed reserve is set one byte below, at, and one byte
above the free space the engine samples in a steady session, and the command
records admission, admission, and a side-effect-free refusal. When the
filesystem has more free space than the largest configurable reserve, the
command fallocates a ballast file in the scratch directory for the duration of
the boundary cases and removes it afterwards.

```sh
agenc-ircd storage qualify --state-dir /var/lib/agenc-ircd/qualify/state \
  --scratch-dir /var/lib/agenc-ircd/qualify/scratch \
  --unsigned-report storage.unsigned --raw-log storage.log --json storage.json
```

The command writes the raw log and the JSON summary in every case and the
unsigned report only when the largest observed growth is at or below the
134,217,728-byte qualification ceiling. `conformance --json` lists the signed
tuple the binary embeds and its maximum growth. Startup reproduces that tuple
lookup: the driver runs the command on the native ext4 tuple, which the
binary admits, and on tmpfs, which it refuses.

The embedded signed report and the fresh measurement are distinct evidence.
Startup admits a tuple from the report compiled into the binary; the fresh
measurement comes from the final binary and is bound into the attempt
evidence and the signed release decision. Re-signing the embedded report from
a fresh measurement changes the source and therefore starts a new candidate.

## Capacity and sustained operation

`scripts/qualify-stage-ten-capacity.py capacity|soak` runs the campaign engine
`stage_ten_capacity::sustained_operation_campaign`, an ignored integration
test compiled from the frozen source with the frozen daemon installed at its
`CARGO_BIN_EXE` path. The capacity job runs 300 seconds with 64 connections;
the soak job runs 604,800 seconds with 256 connections. The driver measures
the elapsed time itself and refuses a record that claims more.

The engine starts one coordinator and two edges at the campaign capacity and
drives N TLS clients split across the edges. Every client arrives from the
loopback address, so the nodes raise `direct_connections_per_address` to the
per-edge share plus headroom (48 for the capacity job, 144 for the soak,
under the 256 ceiling of that key) and set the `new_direct` and
`tls_handshake` buckets, keyed by the source /24, to their configuration
maxima. The per-address pre-authentication bucket is already at its maximum
of 10 commands per second, about 1.25 registrations per second per edge, so
the population connects and resumes after every maintenance window at 400 ms
per client index (consecutive indices alternate edges), the warm-up covers
that pacing, and the post-restart login runs before the workers return. The
first candidate run with the template defaults admitted only 32 of 64
clients; the second admitted 53 and starved the post-restart login behind
the reconnect herd. Real deployments spread clients across addresses, so
these settings model the aggregate capacity, not the per-address abuse
limits, which keep their own tests. The listener ceiling and the memory
budget stay at the template values. Every client joins `#load` and
its own channel, sends a sequenced timestamped channel message each second,
a direct message every two seconds, and a topic change every five seconds,
and records the six latency classes: admission (connect to 001), message
(direct), durable mutation (own topic), fanout (channel message), OPAQUE
(account login), and snapshot (the paged NAMES the coordinator serves through
the edge after a JOIN). Workers negotiate `standard-replies`, so a refused
channel message reaches them as `FAIL PRIVMSG`, is counted as refused, and
is re-sent under the same sequence; a gap in a sender's sequence at any
observer is a missed event, and the record names the observing worker and
its edge for the first 256. Every cycle runs reconnect, churn, snapshot, OPAQUE
login, disk pressure, backup, peer loss, login-index reconstruction, and rekey,
samples resources every ten seconds, and ends with a quiescence check
against the warm baseline. The campaign record lists every sample, the
percentiles per class, the scenario counts, missed events, refused messages,
envelope violations, whether resources returned to the envelope, whether each
daemon stopped cleanly, and the hardware string.

Disk pressure sets every node's fixed reserve close to the free space and
fallocates a ballast in the campaign directory to cross `R(F) + G`; the
probe expects a durable JOIN to be refused and a registration to be refused,
drops the ballast, and polls fresh sessions until a durable JOIN is admitted
again. Backup writes a signed backup of the stopped edge through the
production storage owner. Rekey restores that edge through the frozen
binary's `storage restore` with a new master and guard key, re-pins the new
recovery epoch on the coordinator, and restarts both. Peer loss kills an edge
and restarts it. Scenarios that stop a node open a maintenance window in
which the clients idle instead of reconnecting, as clients do during an
announced maintenance; sequence gaps are counted only outside those windows
and each settle period resets every observer's expectations first.

The daemon is non-dumpable and this host mounts `/proc` with
`hidepid=invisible`, so no unprivileged observer can read a daemon's `/proc`
entry. The engine therefore takes memory (`memory.stat anon`) and task counts
(`pids.current`) from a cgroup v2 leaf per daemon when it runs alone inside a
delegated cgroup, which the driver arranges with `systemd-run --user --scope
-p Delegate=yes`, and falls back to `/proc/<pid>/status` where that is
visible. The descriptor class is measured from the kernel socket table: the
established and close-wait sockets under each node's listener ports. The
record names its resource source.

A development run of 150 seconds with eight connections completes every
scenario on this host. The 300-second capacity job and the seven-day soak
have not been run against a prepared candidate.

## Operational drills

`scripts/qualify-stage-ten-drills.py` runs sixteen ignored integration tests
in `stage_ten_drills`, one per required drill, against the frozen daemon
installed at the test executables' `CARGO_BIN_EXE` path. Every drill starts
its own coordinator and two edges with the local admin listener enabled,
performs the operation the way the operator guide describes it, and writes
`<name>.json` with its steps, per-step timings, facts, and verdict. The
driver copies each record into the evidence directory, counts a drill only
when its record is well formed and marked passed, and fails the job naming
every drill that did not pass. Before the daemon drills it runs the shipped
deployment checks: `check-deploy.py`, `systemd-analyze verify` of the
service unit under each of the four profiles, `tor --verify-config` on the
onion snippet, and the forbidden socket, proxy, and DNS path scan.

Restore stops the coordinator, writes a signed backup through the production
storage owner, restores it into a new directory with `storage restore`,
re-pins the new recovery epoch on both edges, restarts everything, and
authenticates the drill account and re-reads the drill channel's topic.
Disaster restore removes the coordinator's state directory first and expects
the receipt to report no current guard witness. Migration builds a
generation-1 twin of an edge database through the storage crate's
`legacy-fixtures` constructor, runs `storage migrate`, kills it part way,
completes it with `--resume`, and serves the installed directory. Deletion
creates and deletes an account through the client protocol, takes backups
before creation, after creation, and after deletion, rekeys the coordinator
from the last one, and checks the deleted login stays refused. It verifies
exact authenticated deletion tombstones, credential absence, and preservation
of an unrelated account and credential; total counts remain observations.
Rekey restores an edge under a new master and guard key
and authenticates an existing login through it. TLS rotation mints a new
leaf under the same CA, reloads it with `REHASH`, and checks that a new
connection sees the new leaf while an existing one continues. Federation
rotation replaces an edge's signing key and its pinned public key on the
coordinator. Sequencer rotation installs a new sequencer key and credentials
document on every node and checks both edges acknowledge the E2EE profile
again. Backup and audit rotation append a second key to the trust manifest,
activate it, and verify artifacts under both keys: a backup written under
each key restores, and every exported audit event verifies under one of the
two. Compromise lowers the listener ceiling by reload, exports the audit
range, restores the edge into a fenced incarnation, and sends the security
notice. Rollback puts an older database file under the current guard and
expects startup to refuse it. Resynchronization keeps a native client
attached through an epoch change and re-onboards it. Host hardening checks
listener exposure from the kernel socket table, private modes on state,
keys, backups, and logs, the core limit where procfs is visible, injected
privacy canaries in logs and captured stderr, crash containment under
`SIGSEGV` and a repeated `SIGTERM`, and `require_locked_secrets = true`
startup. Observability checks that every STATS selector answers with exactly
its declared field set and that every log line names a registered event
with a severity and timestamp.

Earlier development runs on this host passed twelve drills: migration (interrupted and
resumed), rekey, TLS rotation (same-key renewal by reload, new key by
restart, which `REHASH` refuses with `RESTART_REQUIRED`), federation
rotation, sequencer rotation (a generation-1 set chaining from the previous
credential), backup rotation, audit rotation, compromise (quiesced through
the restart path, see CAP-8), rollback, resynchronization (see CAP-10), host
hardening, and observability. At that point four failed: restore and disaster
restore (CAP-9), login-index transition (CAP-5), and deletion (CAP-11). The
current worktree also passes strict restore, disaster restore, and deletion,
and repeats strict resynchronization with retained-topic assertions. Their
records and repaired evidence checks appear under CAP-61 and CAP-65 through
CAP-67. The missing login-index transition driver remains open. All drills
still require rerunning against the next immutable candidate.

## Coverage

`conformance/release-critical-coverage.toml` is the Stage 10 coverage policy.
It uses the same schema as the interim `critical-coverage.toml`, carries the
90 percent branch and line floors, and lists the complete critical inventory:
115 regions across the five categories the architecture names. Each region is
anchored to a declaration and bound to its file digest and line range: the
Display match of every parser error enum in the client, federation, E2EE,
admin, config, and storage crates and the client message parser; every
authorization function of the domain decision model, the E2EE policy,
quorum, and commit authorization checks, the edge history authorization, and
the admin confirmation and replay checks; every closed registry decoder in
the generated type registry and the storage table decoder; the storage
recovery classification, migration source validation, restore and migration
commands, and the signed audit scan; and the Section 27 checkers of the
domain state, the edge replica, and the E2EE route bindings. Branch-free
decision functions use the region metric so an unexecuted body is still a
failure. `check-coverage.py` accepts a policy that raises a floor above the
inherited value and refuses one that weakens it, so both policies are
validated by the same code; the Stage 10 workspace job validates the interim
policy first and the release policy second, and it also runs the doc tests,
`cargo audit`, and `cargo deny` before the feature matrix.

The 2026-09-05 workspace measurement on this branch reports 75.62 percent
branches (14,310 of 18,924) and 90.66 percent lines, with all nine interim
regions at 100 percent. That measurement needed 2,722 more covered branch
outcomes to reach the release floor. The interim policy passed; the release
policy failed on the floor and on 21 of its then 96 regions, listed in the
workspace job's coverage log. The largest gaps are the runtime account
service, state core, registration, daemon, admin, edge history, and E2EE
coordinator startup modules, and the domain federation projection. This
change added replica validation, projection event, and error rendering tests
and removed two replica validation arms that no public operation could
reach, since every membership and invite is keyed by its own record. The
workspace job therefore stays failing until the coverage push completes, in
the same way the drills job fails on its open findings.

## Native targets and scoped decisions

A candidate records the native targets it covers. `prepare --target` is
repeated once per build record, jobs run only for recorded targets, and
`status` summarizes only those targets. A host whose target the candidate
does not cover cannot attempt a job.

```sh
python3 scripts/build-qualification-tools.py --output /path/to/tools
python3 scripts/qualify-release.py prepare --output /path/to/candidate \
  --target x86_64-unknown-linux-gnu --build /path/to/x86_64/build.json \
  --tools /path/to/tools/tools.json
```

`close --target` restricts a decision to a subset of the candidate's targets.
The decision lists those targets and only their artifacts, the qualification
summary it binds covers only their jobs, and `verify` checks the same scope.
Unresolved evidence for one target therefore blocks only the claims that
target would carry. A two-target candidate can be closed for x86_64 while the
aarch64 jobs are still running on another host, and closed again for aarch64
only through a second candidate directory, because one candidate holds one
decision. The aarch64 jobs must run on an aarch64 host; the workflow that
produces the aarch64 build record is described with the release builds.

## Source status decisions

`scripts/check-release-sources.py` no longer hashes web pages. It reads the
RFC Editor status record for every RFC the source ledger's published-standards
section names, the Datatracker document record and state names for the pinned
MLS post-quantum draft, and `git ls-remote` output for the three living
specification repositories, then fetches each pinned commit into a bare
repository to prove the remote still serves it. Every response body is
retained under the attempt's evidence directory.

`conformance/release-source-decisions.toml` records one entry per source with
the status fields that were observed, the pinned identity, an explicit
`adopt`, `narrow`, `supersede`, or `reject` decision, a note, and the ledger's
SHA-256 at the time of the decision. A status, obsoletion, update, revision,
state, default branch, or head that differs from the entry fails the job and
names the source. An RFC the ledger names without a recorded decision, or a
recorded decision the ledger no longer names, also fails. The job then runs
`cargo audit --deny warnings` and `cargo deny check`.

The 2026-09-05 check found the Tor specification repository's default branch
twelve commits past the pinned commit. The diff was reviewed and recorded in
the decision note: typo fixes in the rendezvous specification, a shared random
value tie-breaker for directory authorities, ntor handshake wording, and a
pluggable-transport variable. The pin stays authoritative. RFC 9325 is now
also updated by RFC 10015, which the ledger already reviews as not applicable.
Errata are not compared structurally; each retained RFC record carries its
errata URL for review.

## Claims and decision inspection

`scripts/check-release-claims.py` runs the candidate binary's `version --json`
and `conformance --json` and compares every field with the candidate build
record (source identities, compiler line, target, features, storage schema)
and with `conformance/spec-baseline.toml` (document and profile digests and
their base64url tokens). `qualified_claims` must be empty and the compiled
profile map must be complete. `conformance/release-claims.toml` lists each
claim, the jobs it requires, the external review the encrypted profile
requires, and the limit statements that must remain in this document. The
checker also lints `README.md`, `TODO.md`, this document, and
`conformance/README.md` for completion phrases, which are refused while the
candidate has no decision directory.

The binary can inspect a signed decision without any bundled key:

```sh
agenc-ircd conformance --json --release-decision /path/to/candidate/decision \
  --trusted-public-key /path/to/trusted-release-public.pem
```

It reads `release.json` under a 64 KiB bound with a reader that accepts only
the runner's canonical form (sorted keys, no whitespace, ASCII, one trailing
line feed), verifies `release.sig` under the `ReleaseDecision` signature
domain with the supplied key, and requires the decision's public key digest
to match that key file. It reports `qualified_claims` only when the decision's
source commit equals the compiled commit, its target list contains the
compiled target, and its artifact digest for that target equals the SHA-256 of
the running executable. A verified decision that describes another source,
target, or binary leaves `qualified_claims` empty with a fixed reason. A bad
key, missing file, failed signature, or malformed document is a command error.
The claims job exercises this path with disposable keys generated inside the
attempt: the binary must refuse the decision under an untrusted key and must
grant nothing from a well-signed decision for another source. No disposable
decision names the candidate. The Python signer and the daemon share a
committed fixture under `test-data/release-decision` that both verify, and
the reader has its own fuzz target and seed corpus.

## Open findings

### CLM-1: the onboarding descriptor carried the Stage 06 base profile token

Found by the claims checker on 2026-09-05 and fixed in the same change. The
config crate's `BASE_PROFILE_SHA256_TOKEN`, which `print-onboarding` writes
into every descriptor and which descriptor import compares against, still
held the Stage 06 base federation profile hash. Stage 09 changed the base
profile hash for the history selectors and updated the specification, the
baseline, and the generated wire constants, but not this literal, so the
descriptor advertised a profile no peer negotiates. The token now equals the
compiled registry hash, and a runtime test binds both descriptor tokens to
the compiled profile hashes so the next revision cannot skip them. Existing
descriptors printed by Stage 09 builds are stale and must be reprinted.

### STO-1: physical growth after a large-value leaf exceeds the qualification ceiling

On the x86_64 ext4 tuple, a legal 65,535-mutation transaction of 40-byte rows
grew the state directory by 258,048,000 bytes when the inserted keys sorted
before an existing row whose value was about 100 KB or larger. The same
transaction on a database holding only small rows grew by 19,394,560 bytes.
Raw redb 4.2.0 reproduces the behaviour without the engine: with an existing
larger row after the inserted keys, the file grew by about 4 KiB per inserted
row and the file length jumped from 69 MB to 553 MB; with an open read
transaction it reached 266,510,336 bytes. A later transaction of the same
shape reused that space and cost 10,571,776 bytes, so the growth is a one-time
allocation, but it is charged to one transaction.

The observed maximum exceeds the 134,217,728-byte ceiling that gives the
256 MiB reserve its twofold margin, and one variant came within 1.9 MB of the
reserve itself. Section 28.9 does not allow a durability finding to be waived.
Until the engine or the pinned redb version avoids the allocation, the storage
job fails on this tuple and no release may claim `S10-006`. The Stage 05
report measured a bare redb table with a different row order and does not
show the behaviour; its embedded tuple remains what startup admits. A fix must
be followed by a new candidate and a rerun of every storage measurement.

The 2026-09-07 investigation reproduced a stronger counterexample through the
production storage owner. With database and backup limits both set to 1 GiB,
65,536 existing 4,096-byte sanction corpus values occupied even keys. A batch
accepted by the storage layer
inserted 65,535 small values at the intervening odd keys. Allocated storage
grew from 551,469,056 to 832,065,536 bytes, a 280,596,480-byte increase that
exceeds the operational reserve as well as the qualification ceiling. All
131,071 rows reconstructed through the storage owner after restart. These
opaque corpus payloads do not satisfy the domain's bare sanction-tombstone
schema, so this is not a complete DomainState restart or one client command.
Descending insertion with a held
redb snapshot still grew by 280,621,056 bytes, so reversing writes does not
repair the general case. The scratch record `sto1-contract-decision.md`
contains the exact production probe, contract references, and repair choices.
Neither growth bound has been raised, and this finding remains open.

The analytical follow-up `sto1-512-page-analysis.md` uses valid live sanction
body sizes and shows why 512-byte pages alone cannot establish the universal
128 MiB bound. It is an allocation counterexample design, not a measured
512-byte-page reserve breach. `sto1-allocation-budget-feasibility.md` maps
the additional transaction lifecycle, commit-tail, cleanup, and close-path
changes needed for a typed physical allocation budget. No storage engine or
dependency patch has been applied yet.

### CAP-1: edges refuse explicit directory queries

A registered client at an edge that sends `NAMES #load`, `WHO #load`,
`WHOIS`, or a TOPIC query receives `482` (channel targets) or `481`. The edge
converts client commands into federated operations and forwards only
mutations and the NAMES page it requests itself after a JOIN; every other
query falls through to `BadState`. The appendix command table lists WHO and
NAMES as supported. The campaign measures the snapshot class on the paged
NAMES that the JOIN triggers and records the numeric each explicit query
receives.

The worktree now forwards the closed directory query variants and retains the
original request across page continuation. A bridge regression exercises
explicit NAMES, WHO, WHOIS, TOPIC, LIST, MODE, ban-list, ISON, and USERHOST
queries through the real edge and coordinator harness. The original NAMES
refusal and missing WHO continuation fail in `cap1-red.log` and
`cap1-continuation-red.log`; corrected behavior passes in `cap1-green.log`
and the continuation run. USERHOST exposed the separate CAP-48 renderer
fault. Full candidate qualification remains pending.

### CAP-2: registration under disk pressure is not always a bounded refusal

With the coordinator's storage under the reserve, a new registration at an
edge received `FAIL USER NETWORK_UNAVAILABLE` in some runs, a close before any
reply in others, and in one run no reply within twenty seconds. The campaign
records the outcome it observed each cycle.

Two reply-loss paths are corrected in the worktree. A rejected durable
registration now feeds `RegistrationCommitted(false)` into the registration
machine so it produces its ERROR reply. Ordinary router and asynchronous
registration closes use the bounded writer flush rather than discarding
queued replies as slow-consumer output. Real writer-queue regressions fail
with the original close paths in `cap2-red.log` and `cap2-quit-red.log` and
pass with the correction in `cap2-green.log`. Numeric 263 now has its exact
closed wire shape. Reverting that registry correction drops the pre-authentication
rate refusal in `cap2-preauth-red.log`; `cap2-preauth-green.log` verifies the
reply is delivered while the transport remains open.

### CAP-3: a refused durable mutation under pressure closes the session

A registered session whose JOIN was refused with `FAIL JOIN
NETWORK_UNAVAILABLE` during disk pressure lost its transport within two
seconds. The link is already unavailable when the edge refuses that JOIN.
Section 28.7 permits a side-effect-free `SERVER_BUSY` or a close required by
the protocol; Section 20.9 requires a close when a full snapshot replaces a
global client's projection. The original campaign re-registers for its
recovery check. The strict campaign instead requires the original transport
to survive this pressure scenario, exposing unnecessary snapshot recovery.

The strict release run `campaign-strict-cap47-67.log` reproduces the fault
after the current authentication and shutdown repairs. At 85.2 seconds the
original pressure client receives `FAIL JOIN NETWORK_UNAVAILABLE`; the next
liveness check fails with BrokenPipe. The run ends after 109.05 seconds and
does not reach rekey or post-restart authentication. The assertion retains
the original session and does not retry that transport, so this finding stays
open. Its daemon logs are preserved in `campaign-strict-cap47-67/logs`.

The diagnostic release run at committed source `74b869d` also fails after
109.28 seconds in `campaign-cap3-diagnostic-74b869d.log`. Temporary fixed-label
diagnostics identify the first rejected operation on each affected node:
the coordinator owns an origin acknowledgement, and edge-a owns an ordinary
event while active. Both receive `FilesystemRejected` in the same UTC second;
their separate monotonic clocks do not establish cross-process ordering.
The edge's journal rejection occurs later, while its link is already down.

On the first reconnect, both reported cursors exactly match retained outbox
events. Their projection generations match, neither peer requires or owns a
snapshot, and neither has an open in-memory barrier. The requested sequences
are 3,573 and 3,467; the last durable acknowledgements are 3,493 and 3,389.
The coordinator nevertheless selects snapshots because it recognizes only
equality with the last durable acknowledgement. Refused snapshot writes then
discard that in-memory retained window. After storage recovers, the diagnostic
records the actual snapshot client-close path on edge-a before BrokenPipe.

The worktree repair validates the complete ordinary retained prefix through
sealed reads of at most 64 rows. It checks every key, sequence, immutable event
identity, and authenticated link scope before deleting any row. Each durable
checkpoint deletes at most 256 covered rows and updates the peer cursor in the
same transaction. ResumeOk follows the final matching receipt, then the
existing resend path replays successors. A prefix containing a cross-profile
part is refused without deleting it or substituting a snapshot; this ordinary
path does not repair the separate companion faults below.

Thirteen coordinator regressions pass in
`cap3-retained-resume-thirteen-green.log`. They include a real restart after the
first 256-row checkpoint, exact continuation through the remaining rows,
timer-capacity exhaustion, rejected writes, intermediate identity mismatch,
duplicate resume, link replacement, quiescence, and cross-profile exclusion.
`cap3-retained-resume-red.log` records the old branch choosing a new snapshot
generation after a rejected acknowledgement instead of retaining the cursor.

The edge correction retains exact dirty journal versions after classified
determinate resource refusal and retries through a matching delayed timer.
New commands are refused before consuming an origin sequence. The recovery
latch opens only after every retained change commits. Timer allocation failure
keeps admission closed; a later authenticated link can arm a new delayed
attempt, while duplicate or stale establishment cannot replace its owner.
Nine regressions pass in `cap3-journal-green.log`. The separate reverted
failures are `cap3-journal-red.log` and `cap3-journal-admission-red.log`.
Indeterminate receipts retain StateCore's fatal reconciliation handling.
The inherited closed-origin reset fixture now allocates a fresh checked link
ID for each authentication, matching the production owner. Reusing ID 7 made
the new stale-establishment guard correctly ignore its reconnect. That fixture
fails in `cap3-link-fixture-red.log` and passes in
`cap3-link-fixture-green.log`; the production guard remains unchanged.

All temporary logging was removed before the fixed release build. Exact source,
binaries, and hashes are preserved in `cap3-fixed-release-74b869d`. The unchanged
strict campaign now passes its first pressure scenario: the original session
survives, the first recovery mutation commits, and fresh registration succeeds.
The complete run nevertheless fails after 250.30 seconds in
`campaign-cap3-fixed-74b869d.log`: the edges do not finish synchronization after
coordinator restart. Preserved logs show edge-b repeatedly reconnecting as soon
as it returns from the earlier forced kill; edge-a stays linked during that
interval. After the coordinator restart, edge-b remains the sustained blocker.
The existing logs lack the rejecting phase and violation, so they do not yet
identify its cause. Rekey and the strict post-restart authentication check are
not reached. All required workspace gates pass, and capacity qualification remains open.

The subsequent diagnostic campaign on `e6dd301` passes in 305.81 seconds,
recorded in `campaign-restart-diagnostic-e6dd301.log` and its `campaign.json`.
The original pressure session recovers on its first attempt. After the forced
edge-b restart, its reported cursor exactly equals the durable cursor at 4,278
with no retained backlog, so direct replay succeeds. Both edges reconcile after
the later coordinator restart, and the strict existing-account login succeeds.
Rekey fences the old incarnation once, completes cleanup, and synchronizes.
The final drain reaches zero on all three nodes in 5.2 seconds, and every daemon
stops cleanly. The actual workload lasts 300.32 seconds with 64 clients, no
missed events, and no resource or population violations.

This instrumented run does not reproduce or explain the earlier restart loop.
Its source and executable hashes are in `cap3-restart-diagnostic/frozen-build.json`;
all five diagnostic source files and both coverage policies were restored to
the committed bytes before execution. A successful uninstrumented repeat and
full candidate qualification remain required. The report also retains the
substantial busy refusals and latency discussed under CAP-13.

### CAP-4: a coordinator restart under a client reconnection storm fails closed

Restarting the coordinator while eight clients reconnected through the edges
ended one second after `state_core_ready` with "a supervised daemon owner
failed" in every run that tried it; one run saw the same exit on the
coordinator a second after an edge restart re-linked and the clients resumed.
With the clients idling through the maintenance window and resuming in
staggered order the restarts complete. The supervisor reports only the
fail-closed exit, not the owner; the coordinator log shows a warning-level
`federation_link_closed` immediately before `shutdown_quiesce`, which points
at the listener owner ending after a failed inbound handshake, but that is a
hypothesis. The daemon's behaviour under an unthrottled reconnection storm
remains open.

The current eight-client probe in `cap4-unpaced-corrected.log` does not
reproduce the owner failure. All three daemons survive and stop cleanly.
The original clients receive the resynchronization close required by the snapshot
protocol and their immediate, single registration attempts receive explicit
`NETWORK_UNAVAILABLE` while recovery is unfinished. Those refused attempts
are not retried. The run establishes daemon survival through that wave;
a fresh client cohort after both edges become active remains to be checked.

The stricter release probe passes in `cap4-final-release.log` after 30.99
seconds. Four original clients reconnect successfully on their one attempt;
four receive the documented early refusal and are not retried. Every worker's
unexpected-refusal count is zero. After both edges are active, all eight fresh
clients receive 001, complete JOIN, and receive their committed TOPIC reply.
All three daemons survive and stop cleanly. This current trigger no longer
reproduces the historical owner failure; it does not establish which earlier
repair removed that failure or cover every possible reconnect pattern.

### CAP-5: the login-index key transition has no stopped-daemon driver

Swapping `login_index_key_file` to a new key with the previous key configured
fails at storage open with "storage authentication failed", because the
stored login-index key state still names the old generation. `storage
restore` keeps one login key for source, current, and target, so it cannot
rotate the key either. The transition is the runtime start/finalize
construction of Section 23.9, which no command exposes. The campaign's
`index_transition` scenario exercises login-index reconstruction and
generation validation across a coordinator restart and re-authenticates the
campaign account; a genuine key rotation stays an external drill item.

The schema-3 prerequisite now has explicit legacy admission. The schema-two
command grammar remains separate from current extensions. A streaming runtime
validator checks original audit signatures, command meanings, chain anchors,
and matched external-action outcomes before migration creates a backup or
target. Legacy backup admission verifies both complete signed passes and
requires their exact stream identity before completing semantic validation.
Legacy restore preserves schema two and requires a separate validated migration
before service; fresh, resumed, and already-installed paths require admission.

Fourteen real migration, backup, and restore tests pass. Reversing the restore
admission and same-stream guards produces four behavioral failures, including
installation of a source whose validator refused it; ten controls remain green.
The exact restoration and rebuilt binary match are archived in
`legacy-restore-admission-reversal` and `legacy-restore-fixed-final`. All 199
storage unit tests pass. The actual CLI restore-then-migrate test also preserves
the original signed audit bytes, and both CLI migration tests pass in
`legacy-restore-query-witness-proof`.

The maintenance codec now has an exact 358-byte signed body and a 454-byte
event, independently generated start and finish golden vectors, and strict
operation, scope, key-selector, counter, hash, and signature validation. All
45 admin and thirty crypto unit tests pass at that checkpoint. The new-key
loader uses the complete configured purpose inventory in one pass. Reverting
that shared inventory produces three behavioral failures with two controls
still passing; all five fixed loader tests pass. These records are archived in
`cap5-rotation-secrets-reversal-proof` and
`maintenance-query-pending-second-proof`.

Schema three admits outer Audit kind two, while schema one and two still
refuse it and AuditCheckpoint remains kind one. The exact signed fixture fails
against the old registry with InvalidEncoding. Both fixed registry controls
and all 204 storage unit tests pass in `cap5-audit-kind-fixed-proof`. The red
proof includes a held-source rebuild in `cap5-audit-kind-red-proof`.

The mixed audit chain and stopped start/finish commands now compile with the
whole workspace. The driver
uses the existing exclusive storage startup, typed stale account cleanup,
complete commit-pinned login-index scans, an atomic key-state and signed audit
batch, exact durable receipt validation, and sealed readback. Actual CLI
restart-mapping tests pass, including an exact 257-entry scan and a finish
refusal that preserves every retained old-generation row. Four tests using the
actual storage fault injector distinguish start and finish refusal from an
indeterminate result after the durable commit. All four pass. The sealed
mixed-chain, receipt, retention, and refusal tests pass fourteen cases.

The corrected signed transport fixture exposes a separate legacy-export
failure: selecting a valid maintenance event closes the session with no reply
instead of returning `FAIL AUDIT UNAVAILABLE`. The fixed classification keeps
unsupported profile selection separate from invalid authenticated source data,
and completes the full chain and captured-cursor checks before returning that
classification. All eighteen fixed mixed-audit cases pass, including three
later invalid-source checks. These results and the
actual daemon and test binaries are archived in
`mixed-audit-rotation-startup-fourth-proof`, with all 232 changed source inputs
held throughout the build.

The actual live rotation drill passes in 33.50 seconds. Two real accounts begin
on the old generation. One normal authentication moves exactly one index entry,
and finish refuses without a success reply or durable change while the other
account remains dormant. Authenticating the second account reduces the old
count to zero and allows finish. The original OPAQUE rows remain byte-for-byte
unchanged; both accounts authenticate under the final single key. The exact
signed maintenance events append to the unchanged historical audit prefix,
and all three daemons stop cleanly. This result is archived in
`mixed-audit-rotation-startup-fifth-proof` with the actual daemon hash.

Reversing the CLI command dispatch reproduces both missing-command failures.
Reversing only mixed event dispatch breaks the valid sealed mixed chain, while
five legacy source controls and the old administration decoder control pass.
Stopping the login-index scan after its first page makes the 257-entry case
fail authenticated reconstruction with StaleState; the empty rotation control
still passes. These proofs are archived in
`recovery-audit-command-boundary-red-proof` and `cap5-complete-scan-red-proof`.
The exact fixed files are restored and the rebuilt daemon and test binaries
match the prior fixed checkpoint. All 932 runtime unit tests pass in
`recovery-audit-command-boundary-fixed-proof`.

The complete stale START test now passes after correcting CAP-85's unrelated
invitation restart rule. It reconstructs three typed cleanup owners, commits
their exact cleanup receipts, preserves unrelated account, invitation, login,
and OPAQUE rows, then signs the complete remaining count and reconstructs the
finished rotation. Bypassing only cleanup leaves the three AuthTransaction
rows and fails the exact empty-table assertion. All four rotation fault tests
and four invitation restart controls still pass. The fixed and reversed
proofs are archived in `invitation-owner-fixed-proof` and
`stopped-start-cleanup-red-proof`. Full repository gates subsequently pass
at the resumed repair checkpoint. The maintenance-aware export grammar
remains open.

The capacity scenario now runs the actual stopped start and finish commands.
It opens authenticated stopped state before the transition, verifies the new
key generation and exact start receipt, migrates the existing account through
live OPAQUE authentication, and requires the previous-generation count to
reach zero. After finish it checks the exact stable key state and receipt,
removes the previous key mapping, and requires another live login before
counting the scenario. Fresh private keys come from the host entropy source;
the campaign log contains only generation and commit numbers.

The restart-only scenario fails the new generation check with actual 1 and
required 2 in `cap5-capacity-rotation-red`. Its assertion bypassed worker stop
during panic cleanup, so the verified test process needed SIGTERM after all
daemons had stopped. The recorded exit is -15, with unchanged executables;
this is a behavioral red with forced cleanup, not a completed campaign.
The implemented scenario returns operational evidence failures through the
controller's normal error path so its worker stop runs.

The first implemented capacity run reaches rotation start, then fails because
its reopened-commit assertion omits the command's final shutdown checkpoint.
The existing two-account drill already checks that the reopened commit is one
past the rotation receipt. The corrected scenario uses that exact relation.
`cap91-production-rotation` preserves this 211.06-second failed run, unchanged
executables, and daemon logs. Its database copies are invalid live captures
under CAP-92. This run does not prove a runtime rotation failure or a passing
capacity result.

The corrected uninstrumented campaign passes in 306.62 seconds with 64 clients
and a measured workload duration of 300.35 seconds. All eight scenario counters
reach one. The login-index generation advances from 1 to 2; its start receipt
is commit 18873 and finish receipt is commit 19183. Both required live logins
pass, followed by the existing rekey scenario. All clients return to the
resource envelope, with zero missed events, envelope violations, population
shortfalls, or sample failures, and all three daemons stop cleanly. The run
also records 56 worker errors and 6,171 message refusals during its workload;
it does not establish an unrestricted throughput or latency claim.
`cap91-rotation-final` binds the exact unchanged release executables and all
nine modified or new source inputs. Its copied databases are excluded from
evidence under CAP-92.

The explicit `AUDIT EXPORT <from> <to> maintenance-v1` profile now renders the
shared chain with distinct maintenance record labels and the
`agenc.ag/audit-maintenance-v1` batch type. The original event and checkpoint
bytes are preserved. The profile remains bound to the signed command through
complete source verification, range selection, observed-event rendering, and
its storage receipt. Legacy export behavior and frozen schema-two admission
remain covered by their existing controls. The exact extension is documented
in `docs/admin-audit-maintenance-v1.md`.

The signed transport regression fails at checkpoint `8f14b85` because the new
command cannot reach its observed audit submission; its actual executed binary
and inputs are in `cap5-export-red-proof`. The fixed refused-commit test emits
only STORAGE_UNAVAILABLE. A separate successful transport test runs the actual
StateCore and storage owner, returns byte-identical historical admin and
maintenance records plus its committed observed event, and reconstructs the
advanced cursor from sealed storage. Profile, permission, range, checkpoint,
record-limit, unselected-tail signature, and captured-cursor controls also pass.
All 69 admin-focused runtime tests pass. Final repository gates pass 2,443
tests with no failures and 21 ignored qualification tests, formatting,
all-target/all-feature workspace Clippy, source check and self-test, workspace
policy, and coverage-checker self-tests. Requirement and pinned-spec checks
also pass. Both inventories bind 636 source files at
`f827bddd83f136ae786e0d54b46db632a21c9503e0516dc8da0725b7071bcaca`;
the release policy binds 709 regions with unchanged coverage floors.
`cap5-export-final-proof` retains the exact inputs, executed runtime binary,
command logs, and hashes. These are development checks, not a new coverage
measurement or release qualification.

The first gate stops at unchecked indexing in two new tests; those accesses
now use checked lookups. The next gate passes all tests but requests source
review of the expanded export handler. Job preparation is now a focused helper.
Both failed gate records remain in `cap5-export-first-gates` and
`cap5-export-before-decomposition-gates`; the final complete run passes.

### CAP-6: the coordinator refused channel messages whose edge named a trailing channel revision

Fixed. Every channel message carries the channel revision the sending edge
last applied, and the coordinator refused the message with `SERVER_BUSY`
whenever that revision trailed its own. An edge replica trails the
coordinator by the event delivery latency, so under concurrent joins,
parts, topic and mode changes the refusals scaled with channel activity:
the 64-client development runs refused about half of all channel messages
during the join storm. The earlier description of a silent loss was the
engine's accounting. Load workers registered without `standard-replies`, so
the refusal reached them as a legacy numeric the engine did not recognize,
and every observer counted a gap. Workers now negotiate `standard-replies`,
count each `FAIL PRIVMSG` and re-send the refused sequence, and the
coordinator accepts a message whose expected channel revision is older than
its own: the message is authorized and its recipients derived at the
coordinator's current revision (STA-05, STA-07), so the older revision
changes nothing. A revision the coordinator has not reached is still refused,
since no committed event could have produced it. Compare-and-set operations
(topic, mode, invite, kick, registration, settings) keep the exact check. A
coordinator unit test commits a message one revision behind and refuses one
ahead.

The refusal breakdown the engine now records showed a second `SERVER_BUSY`
source once the revision check was gone: the coordinator planned a request
while another router's plan was still open in the state core (a session
close retried after a batch applied, most often), the staging was refused as
busy, and the request was answered `SERVER_BUSY` for a slot that freed a few
milliseconds later. About a quarter of the channel messages in a cycle were
refused that way. A request now waits in its peer's queue while any batch is
staged or in flight, exactly as it already waited for the coordinator's own
batch, and a coordinator unit test holds a batch open and requires the
request to queue rather than answer.

The queue itself had three faults the same runs exposed. A request arriving
while its peer already had requests queued executed at once, so one origin's
operations could reach the coordinator out of sequence, and the gap was
treated as an origin violation that retired the link; the four origin
violations of one two-cycle run were exactly that. The queue drained one
request per applied batch, so a request answered without a batch (a query
page, a replay) left the rest waiting for the next unrelated commit, and at
rest the edges held twenty to thirty requests without results while their
clients' later commands piled up behind them until the edge refused them
busy. And peers drained in key order, so a busy edge starved the other. A
request now queues behind its peer's queued requests, the drain continues
until a request stages a batch or starts a crypto job, and peers take turns
from the one drained last. Unit tests cover the ordering and the rotation.

With the queue holding requests longer, a fourth fault surfaced in the
thousands: a client's QUIT sends its session close as a request and then
the origin deletion as a frame. The deletion is not queued, so it overtook
the close, the close later classified as fenced and retired the link, and
the session lingered and held its nickname, so every reconnect of that
client was refused until the grace interval hid it. The origin table now
records the sequence at which an origin was deleted and keeps executing the
operations the edge issued below it, in order, fencing only what would
follow; a domain unit test covers the rule and the durable row keeps the
deleted sequence for a restart.

### CAP-7: the first OPAQUE login after a coordinator restart can fail with 904

After a coordinator restart, with both edge links re-established, the first
authentication of an existing account at an edge was answered with `904 SASL
authentication failed` in some runs and succeeded in others. Earlier engines
retried within a thirty-second grace after a restart and reported the retry
count if a later attempt succeeded.

The first release-profile development run with CAP-44 and CAP-45 fixed,
`campaign-cap44-45-1`, exhausted that grace and stopped before rekey. During
the grace interval, edge b established its federation link 28 times and
closed it 29 times. The logs do not identify the coordinator's rejection
reason. A second run reached rekey after two SASL failures. CAP-7 remains
open; a transport establishment alone does not prove federation requests
are available.

CAP-47 identifies a companion-origin replay defect that can repeatedly reject
the link. Its regression is fixed in the worktree. The capacity engine
now waits for both edges to report active federation service and then treats
an explicit SASL failure as a failed campaign. Only transport interruptions
are retried. The diagnostic campaign on `e6dd301` completes both OPAQUE
checks, including the first strict post-restart login after active federation,
and reaches rekey with no explicit authentication refusal. Its two samples
include a 675.57-millisecond median. The earlier uninstrumented run stopped
before this login because edge-b did not synchronize. The diagnostic result
therefore establishes a successful current path but does not explain the
intermittent restart loop or close immutable-candidate qualification.

### CAP-8: a listener ceiling lowered by reload is not enforced

Lowering the client listener's `max_connections` from 32 to 1 and reloading
with `REHASH` returned `NOTE REHASH OK`, yet the next connection registered
while one session was held and no `connection_refused` event was logged. The
same configuration applied at a restart refuses the second connection.
Section 22.6 lists a lowered listener ceiling as reloadable. The compromise
drill records both outcomes and quiesces through the restart path.

The pending accept had checked its ceiling before waiting for the next
socket. The worktree checks both listener and handshake ceilings again after
accept and before starting TLS. Tests suspend the accept future, lower each
ceiling, and verify refusal and permit release when a socket arrives. Their
original failure is in `cap8-red.log`; `cap8-green.log` and all 15 listener
accept integration tests pass. The full compromise drill remains to be rerun.

### CAP-9: the coordinator does not start on a directory restored from its own backup

`storage restore` of a coordinator backup taken with the coordinator stopped
completed and reported `state generation: source=30, current=30, target=0`,
with and without a current guard witness. Starting the coordinator on the
restored directory failed with "runtime startup failed: storage owner
failed: storage state is stale or inconsistent". The same restore of an edge
serves afterwards, and the rekey and resynchronization drills depend on it.
The restore and disaster restore drills fail on this finding until the
coordinator restore path preserves a startable state.

The restored Account advances its authority generation while the normative
RestoreCopy transform preserves its OPAQUE record exactly. Reconstruction
incorrectly required matching generations, and login also required a matching
Account revision even after unrelated account-policy changes. Both now share
an admission predicate that requires the exact account reference, a live
credential without expiry, and a nonzero credential generation no newer than
the current Account. In the same generation its revision cannot be newer
than the Account revision. Authentication still issues current Account facts.

The regression uses the actual RestoreAccount and RestoreCopy transforms on
sealed source records. It fails with the original predicate in
`cap9-opaque-recovery-final-red.log` and passes in
`cap9-opaque-recovery-final-green.log`. All 73 account-service and
reconstruction tests pass in `cap9-account-reconstruction-tests-final.log`.
The first new restore and disaster-restore drills exposed CAP-51's virtual
connection shutdown error. After that correction, restore reached domain
reconstruction and exposed a second independent defect: a registered channel
retained memberships, invitations, and pending removals whose sessions the
restore had correctly omitted. Restore now removes those transient fields,
preserves durable policy and role grants, and advances the channel revision
once. Ephemeral channels and their name indexes are omitted together. Stored
keys must still match the encoded channel identity, including omitted rows.

The actual channel transform and domain reconstruction fail in
`cap9-channel-restore-red.log` and pass in `cap9-channel-restore-green.log`.
Ephemeral channel and name omission has separate red and green evidence in
`cap9-ephemeral-restore-red.log` and `cap9-ephemeral-restore-green.log`.
All 27 construction runtime tests pass in `cap9-construction-tests.log`.
The next restore drill successfully starts all restored nodes and registers a
guest in `drills-cap9-green-2/restore.json`. Its account probes exposed the
separate CAP-54 client epoch-binding error. After that helper correction,
`drills-cap9-54-green/restore.json` and
`drills-cap9-54-green/disaster_restore.json` both pass in about 12 seconds.
They require existing-account login, new-account creation and login, correct
guard witness handling, a changed incarnation, and clean stops on all three
nodes. The seed channel is ephemeral, so its absent topic after restore is
expected. CAP-9 is fixed in the worktree; immutable candidate reruns remain.

### CAP-10: the admin DIE is refused while an account session is attached to the edge

With an authenticated account session attached to an edge, every signed
`DIE` from a fresh local admin session was rejected with
`admin_rejected error=authentication_failed` and the admin transport closed,
for sixty seconds of retries. After that client sent `QUIT`, the same
command from the same operator identity was accepted at once. Guest
sessions do not trigger it. The resynchronization drill records the refusal
and stops the node after detaching the client.

Source tracing identifies a confounder in that drill: its first request signs
`DIE :resync`, which violates the canonical command grammar because the colon
is unnecessary for a single-word final parameter. The later detached request
uses `DIE :resync detached`, which is canonical. The observed authentication
category also misclassifies authenticated failures, recorded as CAP-56.
The corrected constructor passes six valid reasons through a real signed
admin confirmation and rejects malformed reasons. Reverting it makes
`cap10-red.log` fail with `Canonical`; `cap10-green.log` passes. The actual
debug resynchronization drill in `cap10-resync-green/resynchronization.json`
accepts the canonical DIE while the account remains attached, restores a new
edge epoch, disconnects the old session, and re-onboards the account. It stops
all three nodes cleanly. Its old topic observations are not persistence proof,
as recorded in CAP-61. CAP-10 is fixed in the worktree. This cause is distinct
from CAP-19's target revision.

### CAP-11: account deletion has no reachable path in the federated profile

Fixed in the worktree. `ACCT DELETE START` from an authenticated, freshly re-authenticated session
at an edge is answered `FAIL ACCT BAD_STATE`: the edge forwards no account
command to the coordinator. The coordinator's own client listener answers
`CAP * NAK` for the sasl and account capabilities, so the account service
cannot be reached there either. The deletion drill records both refusals and
does not pass in the original implementation.

The edge now forwards account mutations with their exact origin and session
authority. Private challenges preserve the public session revision, and
completion waits for the covering storage receipt and cross-profile barrier.
The private-revision regression fails in `cap11-private-revision-red.log`
and passes in `cap11-private-revision-green.log`; the real storage barrier
tests pass in `cap11-barrier-final-green.log`. After the separate reply,
closure, shutdown, readiness, and evidence repairs below, the complete strict
deletion and rekey drill passes in `cap66-67-strict-deletion/deletion.json`.

### CAP-12: a snapshot marker refused under disk pressure left the edge waiting on the coordinator

Found by the third 64-client development run of the capacity engine and
fixed in the same commit. The disk pressure scenario fills the filesystem
under all three nodes. When the coordinator's link to an edge dropped and
came back while the reserve was still breached, the edge's cursor no longer
matched the coordinator's and the coordinator opened a new projection
generation. The announcement, the cut, and END left on the wire at once; the
generation marker row behind them was a durable batch, and storage refused
it. Nothing re-staged the marker afterwards: the edge answered READY, the
READY marker was refused too, and the coordinator's own expiry skips a
snapshot that reached READY, so the edge stayed in the snapshot phase and
answered every registration with `NETWORK_UNAVAILABLE` after the pressure
cleared. The first cycle of the same run passed because its cursor was
retained and the resume needed no durable write. The coordinator now drops
the unfinished generation and retires the link when either marker batch is
refused; the edge reconnects and resumes from its committed projection once
storage accepts writes again. A coordinator unit test stages the marker,
refuses the batch, and requires the retired link, the dropped generation,
and the cancelled expiry timer.

The same runs showed the other two batches the coordinator dropped on a
refusal. A federated request whose batch storage refused was never answered:
the edge kept it pending, its client's next request from the same origin
arrived one sequence ahead, and the coordinator treated the gap as an origin
violation, blocked the origin, and retired the link, which every client on
that edge saw as a second of `NETWORK_UNAVAILABLE` until the resume healed
it. The coordinator now answers such a request with a side-effect-free
`SERVER_BUSY` without a result row, so the client retries and a byte-identical
resend after a link loss still classifies as fresh. An origin acknowledgement
whose batch storage refused now retires the link, so the edge declares again
on its next link. Both have coordinator unit tests.

### CAP-13: bursts overflow a connection's deferred commands at the edge

Open. With the refusals above gone, the two-cycle 64-client development runs
still refuse about a third of the channel messages sent during the reconnect
and churn rounds, all with `SERVER_BUSY` from the edge: a connection may
have one request in flight until its completion event is applied, later
commands wait in a per-connection queue of 32, and the queue overflows.
The edge applies every event and stages every request as its own durable
batch, so under a burst of joins, parts, and registrations its commit rate
bounds how fast completions come back, and 64 clients on one host sit at
that bound. The refusal is side-effect-free and the clients re-send, so the
campaign records it (`messages_refused`, `refused_by_code`,
`refused_by_time`) without losing a message; the steady-state windows refuse
nothing. Batching several events into one durable commit at the edge is the
remedy and stays open.

The full diagnostic campaign on `e6dd301` completes but reports 5,961
SERVER_BUSY refusals, including the steady workload after 200 seconds.
Its message p99 is 59.01 seconds and durable-mutation p99 is 58.91 seconds.
The campaign records these measurements and its clients account for refusals;
a passed campaign assertion is not evidence of acceptable interactive latency.
The earlier steady-state observation above does not describe this current run.
Bounded batching remains required, with ordered per-event acknowledgements,
complete rollback, exact completion ownership, and aggregate memory admission.

A real-storage regression now reproduces the missing batching boundary in
`cap13-ordinary-batch-red.log`. Three ordinary events enter the edge while
the first receipt is pending. No event or FACK appears before that receipt,
and only the first event and FACK appear before the second commit. After the
second real commit, the old path has delivered two events instead of the
required three, so the test fails in 0.09 seconds. The complete fixture uses
a bound client sink and a bounded live federation output queue. Exact source,
executable, and hashes are parked in `cap13-ordinary-batch-proof`; the failing
test was removed from the repair checkpoint while batching is implemented.

### CAP-14: a coordinator stopped with an acknowledgement backlog exceeds its shutdown budget

Open. When the campaign stopped the coordinator while it still held sixty to
eighty unacknowledged events for an edge that was catching up, the process
reported `daemon shutdown exceeded its deadline` and exited unclean; the
flush phase ended within its budget and the stop phase, which waits for the
storage owner's final checkpoint, did not. Stopped after the federation
drained, it exits cleanly every time. The campaign now polls every node's
`STATS FEDERATION` for up to sixty seconds and stops only when no base
outbox object remains, which is how an operator stops a coordinator after
its links go quiet. Bounding the stop phase against an outstanding
acknowledgement backlog in the daemon itself stays open.

A 2026-09-07 production probe withheld one edge's ACKs with SIGSTOP and sent
80 real cross-edge channel events. The coordinator retained exactly 80
outbox objects totaling 19,350 bytes and exited cleanly 25.76 milliseconds
after SIGTERM. `cap14-backlog-2.log` retains the measurement. Backlog count
alone therefore does not reproduce the historical failure on the current
worktree. A stop during the full campaign's recovery state remains required.

The stricter deletion drill now reproduces a shutdown deadline after successful
deletion, clean client EOF, and refusal of the deleted credentials. The record
`drill-cap11-64-green/deletion.json` is explicitly failed despite its directory
name. It stops after 37.05 seconds with coordinator exit status 1 and
`daemon shutdown exceeded its deadline` on stderr. The later rekey checks do
not run. This narrows the next shutdown trace to the post-deletion state.

CAP-51 and CAP-65 subsequently repair physical-session checkpoint ordering
and abandoned virtual authentication carriers. The strict deletion drill now
passes its formerly blocked coordinator stop, rekey, and final stops in 39.20
seconds. The diagnostic capacity run on `e6dd301` also stops all three daemons
cleanly after its explicit final drain. That drained stop does not by itself
prove every possible stop during recovery with an outstanding acknowledgement
backlog; the historical failure and current 80-event positive probe remain
separate evidence.

### CAP-15: a batch gathered during the index read-back stopped the coordinator as corrupt

Fixed. After a commit, the state core reads the committed rows back into
its durable index, and until that read completes those rows are pending.
A plan staged in the same turn, most often by the federation coordinator
draining its queue right after the commit, gathered for its one-millisecond
window and was then submitted by the wake timer while the read-back was
still in flight; its projection met a pending row, reported a stale state,
and the state core stopped as corrupt. The daemon then shut down with only
`a supervised daemon owner failed` on stderr. Under disk pressure the
read-back takes longer and the window widens: the third candidate's
capacity job lost its coordinator this way in the first cycle, and one in
four release-profile development runs reproduced it. The state core now
holds a gathered batch while a read-back is in flight and submits it when
the index is current, with a unit test that stages a plan, marks a read-back
in flight, and requires the batch to wait. The daemon also names the state
owner's exit cause on stderr, from a closed label set, so the next such
stop is attributable without a rebuild.

### CAP-16: a standing key removed before its snapshot cut row landed stopped the coordinator as corrupt

Fixed. When an edge resumes from a cursor the coordinator no longer
holds, the coordinator cuts a snapshot: it installs the edge's complete
standing projection under a new projection generation and then writes the
rows of that generation in pages of 256 behind the generation marker. From
the cut onward every mutation projects its standing deltas under the new
generation. A mutation that removed a standing key before the page holding
that key was written, or after a page batch had been refused, emitted a
delete for a row that did not exist; the projection reported a stale state
and the state core stopped as corrupt. Under disk pressure the marker and
page batches are refused and each refusal fails the link, so the standing
stays installed with no rows while the sessions of the closed transports
are hidden. Release-profile runs after CAP-15 still lost the coordinator
this way at the onset of the disk pressure scenario, about one run in
three, and the failure is consistent with the coordinator loss seen once
after a restart under churn. The projector now consults the durable index
and omits the delete when no row exists under the current generation: the
standing drops the key when the batch commits and the cut skips it. A unit
test installs a standing under a fresh generation with no rows,
disconnects the session, and requires the batch to project and reach
storage.

### CAP-17: a refused snapshot cut page was skipped

Fixed. The coordinator writes the rows of a snapshot generation in pages
after its own batches commit, and it advanced the page cursor before the
page was staged. Staging a page is refused whenever another role staged a
plan first in the same completion turn, because the page's checkpoint
plan no longer chains on the open batch, and during quiescence. The
refused page was then never written: the edge received its entries over
the link, but the rows behind them were missing, so a coordinator restart
restored an incomplete standing for that edge and later removals of the
missing keys were never projected. Found by reading the snapshot write
path while fixing CAP-16, not by a campaign. The cursor now advances only
when a page is staged or holds nothing to write, and the background
continuation retries the same page once the batch slot is free. A unit
test stages a page while another batch is with storage and requires the
cursor to stay at the page.

### CAP-18: a client that left while the link was down kept its nickname at the coordinator

Fixed. A registered client that closed its connection while the edge's
coordinator link was down could not be reported: the edge queued the
session close on a link that was gone and dropped the origin after a
FORIGIN DEL the link never carried. After the next reset the edge replayed
only the origins it still held, and at READY the coordinator revived every
origin of the incarnation it had suspended at link loss, so the orphan
scan found nothing and the stale session kept its nickname. Every later
registration under that nickname was refused as a bad state, rendered to
the client as a rejected registration, and the client retried. In every
64-client run the disk-pressure scenario retired edge-a's link while the
workers dropped their sessions for the maintenance window; from then on
edge-a admitted and closed about sixteen connections per second, none of
its thirty-two workers registered again for the rest of the run, and a
300-second diagnostic run counted 2,610 session opens from that edge
refused by the coordinator against 38 accepted. Edge-b recovered only
because the peer-loss and rekey scenarios restarted it and the new
incarnation fenced its sessions. The campaign counted no missed events
because the missing observers were not there to miss anything, and the
capacity job of the fourth candidate passed with 46 to 53 of 64 clients
connected after its first cycle. A second path left the same residue
with the link up: a session close refused as busy, because storage
refused its batch under disk pressure, was dropped, while the DEL that
followed it went through, so the session outlived its origin.

The edge now retains a closed connection's origin, marked deleted, until
the coordinator acknowledges the DEL, and after FORIGIN RESET it replays
the DEL of every retained origin, which is the replay the specification
assigns to the edge; the companion origin mirror and the snapshot resync
skip retained origins. The coordinator accepts a replayed DEL during the
reset whatever generation it names, acknowledges one for an origin it
never committed without a row, and hides a deleted origin's session with
the deletion, since nobody can close it any more. Unit tests close a
registered client while the link is down and require the next reset to
replay the DEL and a later reset to replay nothing, delete an origin
whose close never arrived and require its session hidden, and replay a
deletion at a stale generation against the origin table. The campaign's
quiescence check now also requires the whole population back, waiting up
to 90 seconds for its paced return, and records population shortfalls,
which the driver refuses; a 300-second development run with the change
holds all 64 clients at both quiescence checks.

### CAP-19: a process action's confirmation is refused by any commit in between

Fixed in the worktree. Process-action confirmation used the database state
generation as the process target revision. Any intervening durable commit
therefore rejected a valid confirmation with INVALID_TARGET. The target now
uses the fixed live-process revision. The confirmation remains bound to its
admin session and operator authority, and quiescence still rejects it.
Account and channel actions retain their own changing target revisions.

The regression registers a real client and commits a JOIN between process
revision reads, verifies that storage generation advanced, and requires the
process revision to remain equal. It then requires quiescence to invalidate
the target. The original behavior fails in `cap19-red.log`; the fix passes in
`cap19-green.log`. The campaign now requires its first signed DIE confirmation
to succeed instead of retrying INVALID_TARGET.

### CAP-20: restart skipped committed outbox rows and reused delivery sequences

Fixed in the worktree. Review R01. A coordinator restart restored its delivery head from
a peer checkpoint that could lag committed outbox rows. Replay could skip those rows,
and a later append could reuse their keys.

Startup now reads and validates the durable outbox before admitting links, reconstructs
each reserved head, and restores the unacknowledged window. Read failures retain a
continuation; invalid rows quarantine admission. Unit regressions include
`resync_restart_recovers_the_delivery_head_from_committed_outbox_rows`. The red and
green evidence is recorded in [federation-resync-fixes.md](federation-resync-fixes.md).
Qualification acceptance remains pending; no capacity campaign was run for this change.

### CAP-21: a refused request consumed an edge sequence without a durable result

Fixed in the worktree. Review R02. A refused request batch produced a non-durable
SERVER_BUSY result. The edge consumed that answer and advanced while the coordinator
still expected the original sequence.

Rejection now retires the link without inventing a result. The edge keeps the exact
request and replays it after reset; only a committed result consumes its sequence. Unit
regressions include
`resync_refused_request_retires_the_link_without_consuming_its_sequence`. The red and
green evidence is recorded in [federation-resync-fixes.md](federation-resync-fixes.md).
Qualification acceptance remains pending; no capacity campaign was run for this change.

### CAP-22: an account callback settled a federation result before its own receipt

Fixed in the worktree. Review R03. The account completion callback staged a federation
checkpoint and the same callback consumed it as though the earlier account receipt
covered it. A crash between the account transaction and that checkpoint could also lose
the outer replay binding.

Request callbacks now check the storage commit sequence that owns their batch. Remote
account transactions include the exact federation response and origin successor in their
own write set; closed carriers still settle committed replay state without a client
sink. Unit regressions include
`resync_callback_cannot_settle_a_request_staged_after_its_receipt` and
`resync_account_transaction_contains_its_exact_federation_response`. The red and green
evidence is recorded in [federation-resync-fixes.md](federation-resync-fixes.md).
Qualification acceptance remains pending; no capacity campaign was run for this change.

### CAP-23: client close discarded unresolved requests and an unbound session

Fixed in the worktree. Review R04. Connection close swept pending work, including its
newly prepared close. A committed registration whose principal UPDATE had not arrived
also escaped DEL cleanup.

Closing a connection marks its retained requests sink-gone. The coordinator tracks
sessions created by each origin from committed registration results and reconstructs
that ownership at startup, so DEL includes unbound sessions. Unit regressions include
`resync_client_close_retains_the_close_until_its_answer` and
`resync_del_hides_a_session_registered_before_origin_update`. The red and green evidence
is recorded in [federation-resync-fixes.md](federation-resync-fixes.md). Qualification
acceptance remains pending; no capacity campaign was run for this change.

### CAP-24: cleanup forgot sessions before a hide committed

Fixed in the worktree. Review R05. Cleanup removed its front entry before planning,
rendering, or storage succeeded. A refusal could leave a physical session and nickname
with no remaining cleanup owner.

The front entry now survives planning, rendering, staging, and storage refusal. The
hide, origin tombstones, and next Session-ID cursor commit together; only that receipt
advances cleanup. Unit regressions include
`resync_rejected_cleanup_keeps_its_session_until_commit` and
`resync_cleanup_cursor_commits_with_the_hide_and_restarts_in_session_order`. The red and
green evidence is recorded in [federation-resync-fixes.md](federation-resync-fixes.md).
Qualification acceptance remains pending; no capacity campaign was run for this change.

### CAP-25: outbox overflow left an active edge waiting forever

Fixed in the worktree. Review R06. Outbox overflow only set a memory flag after append
and suppressed later delivery while leaving the link active. Disconnected targets
escaped the accounting.

Projection admission now checks object and byte budgets and commits the
snapshot-required peer fence with the mutation before an overflowing append. Receipt
handling retires the link, further ephemeral reservations stop, and restart and resume
preserve the retained budget. Unit regressions include
`resync_outbox_limit_fences_in_the_mutation_batch_before_append` and
`resync_resume_preserves_the_retained_outbox_budget`. The red and green evidence is
recorded in [federation-resync-fixes.md](federation-resync-fixes.md). Qualification
acceptance remains pending; no capacity campaign was run for this change.

### CAP-26: failed outbox reads were treated as replay progress

Fixed in the worktree. Review R07. A refused replay read or an unreadable row could
clear the resend continuation or be skipped. An empty decoded page then counted as
progress over unacknowledged work.

Read submission and completion failures retire the link. Each page must contain the
expected consecutive delivery positions with matching durable keys and event identities;
missing work never advances the replay cursor. Unit regressions include
`resync_failed_outbox_read_retires_the_link` and
`resync_missing_outbox_sequence_never_counts_as_acknowledged`. The red and green
evidence is recorded in [federation-resync-fixes.md](federation-resync-fixes.md).
Qualification acceptance remains pending; no capacity campaign was run for this change.

### CAP-27: snapshot recovery left a received registration result unresolved

Fixed in the worktree. Review R08. A registration result could arrive before its
completion event and remain pending after a snapshot replaced that event stream.

The ACTIVE transaction now records exact snapshot coverage for eligible committed
results, including session registration, when the cut covers their state generation.
Sink-gone requests then resolve without rendering registration to a replacement
connection. Unit regressions include
`resync_snapshot_covers_registration_whose_completion_was_lost`. The red and green
evidence is recorded in [federation-resync-fixes.md](federation-resync-fixes.md).
Qualification acceptance remains pending; no capacity campaign was run for this change.

### CAP-28: incarnation expiry lacked a durable authority fence

Fixed in the worktree. Review R09. Expiry and incarnation replacement hid sessions
individually without first committing the authority fence or successor projection
generation. A restart could restore authority or lose cleanup progress.

A constant-size peer fence now commits before physical cleanup, and authorization,
direct-message targeting, nickname lookup, and projection queries honor it. Cleanup
proceeds in Session-ID order with an atomic cursor and terminal Clean phase; permanent
incarnation history survives later replacements and restarts. Unit regressions include
`resync_expiry_stages_the_authority_fence_before_any_hide`,
`resync_restart_keeps_the_replaced_incarnation_fenced`, `and
resync_cleanup_cursor_commits_with_the_hide_and_restarts_in_session_order`. The red and
green evidence is recorded in [federation-resync-fixes.md](federation-resync-fixes.md).
Qualification acceptance remains pending; no capacity campaign was run for this change.

### CAP-29: ordinary edge request and completion state disappeared on restart

Fixed in the worktree. Review R10. Ordinary request bytes, origin lifecycle work,
results, and completion correlation existed only in memory. A cursor receipt could
outlive the evidence needed to resolve its request.

A bounded journal now commits origins and exact outbound requests before transmission,
commits results before terminal output, and joins completion evidence to the event or
combined barrier transaction. Startup restores unresolved entries as sink-gone; terminal
requests and acknowledged DELs have durable retirement states and do not reappear as
pending work. Unit regressions include
`resync_request_is_durable_before_its_first_send`,
`resync_restart_retains_completion_received_before_result`, `and
resync_a_completed_request_does_not_return_after_restart`. The red and green evidence is
recorded in [federation-resync-fixes.md](federation-resync-fixes.md). Qualification
acceptance remains pending; no capacity campaign was run for this change.

### CAP-30: a rejected snapshot page left the edge without a continuation

Fixed in the worktree. Review R11. Storage rejection of SnapshotInstalled left the edge
waiting on an image that had not committed.

Snapshot-page rejection now clears the uncommitted install continuation and retires the
link while preserving the active generation. The next connection renegotiates from
durable state. Unit regressions include
`resync_rejected_snapshot_install_retires_the_edge_link`. The red and green evidence is
recorded in [federation-resync-fixes.md](federation-resync-fixes.md). Qualification
acceptance remains pending; no capacity campaign was run for this change.

### CAP-31: snapshot READY and ACTIVE lacked durable recovery states

Fixed in the worktree. Review R12. The edge changed active projection state during
download and did not retain the pending READY identity needed after a crash or lost
link.

Verified pages now form a durable pending generation before READY. The exact identity is
restored and replayed; ACTIVE atomically swaps the peer generation and eligible result
coverage before origin admission. A snapshot cannot stand in for incomplete
cross-profile completion evidence. Unit regressions include
`resync_snapshot_keeps_the_active_generation_until_active_commits`,
`resync_restart_resends_the_exact_durable_snapshot_ready`, `and
resync_snapshot_cannot_replace_an_incomplete_cross_profile_completion`. The red and
green evidence is recorded in [federation-resync-fixes.md](federation-resync-fixes.md).
Qualification acceptance remains pending; no capacity campaign was run for this change.

### CAP-32: a lost first origin ACK caused the edge to discard DEL

Fixed in the worktree. Review R13. The edge treated the absence of an ACK as proof that
an origin had never committed. Closing that connection could discard the only deletion
obligation.

An encoded declaration now retains DEL even if its first ACK was lost. Only a
declaration that never acquired an object identity and owns no pending request can be
forgotten immediately; an acknowledged DEL is checkpointed before retirement. Unit
regressions include `resync_closed_origin_without_first_ack_is_retained_for_del` and
`resync_an_acknowledged_del_does_not_return_after_restart`. The red and green evidence
is recorded in [federation-resync-fixes.md](federation-resync-fixes.md). Qualification
acceptance remains pending; no capacity campaign was run for this change.

### CAP-33: delivery acknowledgements advanced before storage committed

Fixed in the worktree. Review R14. ACK handling removed unacknowledged entries and moved
the memory cursor before the deletion batch committed. Refusal left subsequent
checkpoints free to claim coverage that storage had not accepted.

The prospective cursor now stays in PendingCommit until the deletion and peer checkpoint
commit. Rejection preserves the window and retires the link so resume reconciles the
durable cursor. Unit regressions include
`resync_acknowledgement_does_not_advance_before_its_commit`. The red and green evidence
is recorded in [federation-resync-fixes.md](federation-resync-fixes.md). Qualification
acceptance remains pending; no capacity campaign was run for this change.

### CAP-34: partial origin resets cancelled or extended the grace deadline

Fixed in the worktree. Review R15. Link establishment and incomplete RESET traffic could
keep stale origins alive by cancelling or replacing their original disconnect deadline.

The origin table retains the first deadline across partial resets, including Resetting
state. Only the completed origin READY checkpoint resumes authority and cancels grace;
expiry fences the incarnation. Unit regressions include
`resync_partial_reset_does_not_extend_or_cancel_grace`. The red and green evidence is
recorded in [federation-resync-fixes.md](federation-resync-fixes.md). Qualification
acceptance remains pending; no capacity campaign was run for this change.

### CAP-35: origin updates advanced before an exact acknowledgement

Fixed in the worktree. Review R16. The edge advanced an origin generation and sequence
before receiving the matching UPDATE acknowledgement, and the acknowledgement path did
not require the exact incarnation and object hash.

Updates now retain their predecessor chain and wait for an exact ACK before advancing
committed generation and sequence. Requests wait while that chain is unresolved, and
mismatched acknowledgements retire the link. Unit regressions include
`resync_principal_update_waits_for_the_exact_origin_ack` and
`resync_origin_ack_rejects_the_wrong_hash_or_incarnation`. The red and green evidence is
recorded in [federation-resync-fixes.md](federation-resync-fixes.md). Qualification
acceptance remains pending; no capacity campaign was run for this change.

### CAP-36: optional row builders erased required persistence errors

Fixed in the worktree. Review R17. Projection row conversion returned optional values,
making an encoding or index error indistinguishable from a deletion that legitimately
needed no write.

Required row builders and staging closures now return Result, while optional deletion
retains Result<Option<_>>. Conversion failure aborts the event or install batch before
its cursor can commit. Unit regressions include
`resync_unencodable_projection_cannot_commit_its_delivery_cursor`. The red and green
evidence is recorded in [federation-resync-fixes.md](federation-resync-fixes.md).
Qualification acceptance remains pending; no capacity campaign was run for this change.

### CAP-37: successor event admission compared only the committed cursor

Fixed in the worktree. Review R18. An event following an admitted but uncommitted
predecessor was checked against the older committed cursor and could fail an otherwise
ordered stream.

Admission now checks the tail of received or staged work. Application still revalidates
against the committed cursor after the predecessor receipt, preserving ordering across
refusal and replay. Unit regressions include
`resync_successor_event_waits_behind_the_uncommitted_predecessor`. The red and green
evidence is recorded in [federation-resync-fixes.md](federation-resync-fixes.md).
Qualification acceptance remains pending; no capacity campaign was run for this change.

### CAP-38: expired replay wrote a fresh busy result and could rewind sequence

Fixed in the worktree. Review R19. A request below the retained sequence with no exact
result was treated as a fresh busy checkpoint. Its row could record a lower successor
than the live origin table.

Expired replay now persists an origin fence at the unchanged next sequence and answers
ORIGIN_EXPIRED only after that checkpoint. Refusal retires the link and does not create
a new request result. Unit regressions include
`resync_expired_request_fences_without_rewinding_the_origin`. The red and green evidence
is recorded in [federation-resync-fixes.md](federation-resync-fixes.md). Qualification
acceptance remains pending; no capacity campaign was run for this change.

### CAP-39: FORIGIN READY ran in the wrong direction

Fixed in the worktree. Review R20. The edge sent FORIGIN READY, reversing the normative
synchronization gate and allowing request admission to precede the required coordinator
acknowledgement.

Base resume or snapshot activation now precedes RESET and origin replay. The coordinator
publishes READY after its checkpoint; the edge requires that frame, exact declaration
ACKs, and reconciled DELs before activating requests. Unit regressions include
`resync_coordinator_sends_ready_after_the_origin_reset_commits` and
`resync_coordinator_ready_opens_the_origin_admission_gate`. The red and green evidence
is recorded in [federation-resync-fixes.md](federation-resync-fixes.md). Qualification
acceptance remains pending; no capacity campaign was run for this change.

### CAP-40: storage rejection left queued requests without a wakeup

Fixed in the worktree. Review R21. The rejected-batch callback drained the link backlog
but did not resume the separate per-peer request queues. A request waiting behind
another operation could remain indefinitely idle.

Rejection now drains the request queues before continuing the backlog. The regression
uses two peers so retiring the refused link cannot remove the request that must resume.
Unit regressions include `resync_rejected_batch_drains_requests_waiting_behind_crypto`.
The red and green evidence is recorded in
[federation-resync-fixes.md](federation-resync-fixes.md). Qualification acceptance
remains pending; no capacity campaign was run for this change.

### CAP-41: the durable reload treated the account service's result rows as invalid coordinator results

Fixed. Found by the workspace test suite after the resynchronization
change, which its validation had not run: the real-daemon E2EE test that
kills and restarts the coordinator never saw either edge become active
again. The account service keeps its per-request results in the request
result table under the same record kind as coordinator results, keyed by
the client's 16-byte request id, while a coordinator result is keyed by
its 64-byte replay key. The reload used to skip a row whose key it could
not read as a replay key; the resynchronization change turned every such
skip into a codec violation, and the first account row failed the reload,
which quarantines every peer. From then on the restarted coordinator
accepted each edge's link at the hello and closed it at once, 115 times in
a minute in that test, and the edge dialled again every second while
refusing its clients as network-unavailable. Any coordinator restart after
the first account request disabled federation until an operator
intervened. The reload now leaves a row whose key is not a replay key to
its owner and judges only its own rows. A unit test seeds an account-style
row beside a restored peer, requires the reload to complete without
quarantining the peer, and requires the peer to link again; it fails
without the change, and the E2EE restart test passes again.

### CAP-42: a deletion behind an unacknowledged update named the old generation

Fixed. The resynchronization change advances an origin's generation only
when the coordinator acknowledges the update (CAP-35), but the DEL a
closing connection sends still named the generation the edge held. A
client that left while its registration update was in flight, which the
64-client campaign does at every churn and reconnect round, sent a DEL
for generation 0 behind an update the coordinator had already applied at
generation 1; the coordinator refused it as a wrong generation and retired
the whole link, with every client of that edge. The DEL now names the
in-flight update's generation with no operation under it, and the
deletion acknowledgement accepts that generation. A unit test registers a
client, holds the update unacknowledged, closes the client, and requires
the DEL to name generation 1 and the link to stay up; it fails without
the change.

### CAP-43: recovery after a link retirement under disk pressure loops on an origin violation

Fixed. With CAP-42 fixed, the 64-client campaign reaches the disk-pressure
scenario, the refused marker batch retires edge a's link as CAP-12
describes, and before this fix the edge never recovered: over the next
minute it re-linked many times and the coordinator failed each fresh link
with an origin violation, until the recovery wait expired with no durable
join admitted. The cause was a closed client's unfinished request. When a
client leaves, or a resync covers its session, the edge marks the
connection's origin deleted and its in-flight request sink-gone, and
replays the deletion after the next reset. The coordinator drops the origin
on that deletion. The edge, once active again, still re-sent the unfinished
request under the dropped origin, which the coordinator could only answer
with an origin violation, and the same request pinned the deleted origin
against retirement, so the deleted origins accumulated and the activation
gate never cleared. The fix abandons such a request. The edge does not
transmit a request whose origin is deleted, and origin retirement drops
every unfinished request bound to the acknowledged deletion before removing
the origin. The request neither replays nor holds the origin open, the
deleted origins retire, and the edge admits a durable join inside the
recovery window. Regression:
`a_retired_origin_abandons_its_unfinished_request_and_does_not_replay_it`
in the edge harness, which fails without the retirement change. Evidence:
the 300-second campaign passes end to end, recording the disk-pressure
scenario as refused and recovered, then clearing backup, peer loss,
login-index reconstruction, and rekey.

### CAP-44: snapshot activation discarded completed incarnation cleanup

Fixed. A rekeyed edge repeatedly hit the reset-incarnation fence because
snapshot activation changed the peer's authority phase from Clean to Ready.
The first RESET correctly fenced the old incarnation and waited for its
durable session cleanup. After cleanup committed Clean, the replacement
reconnected and completed the base snapshot before sending RESET. The
snapshot callback overwrote Clean, so RESET fenced the same predecessor
again. The rejected replacement was never recorded.

Snapshot activation now preserves the authority phase. The replacement
stays blocked through the fence and cleanup, then completes its snapshot
with Clean intact. RESET can accept the new incarnation, and origin replay
commits Ready. The old incarnation remains permanently fenced. A returning
incarnation also remains Suspended through snapshot activation, preserving
the companion profile's origin-readiness gate. Wire and record formats are
unchanged.

Two coordinator regressions fail without the change. The replacement test
commits a hosted session, the authority fence, the cleanup, and the new
snapshot, then requires the replacement RESET and Ready checkpoint to
succeed. The second requires a returning incarnation to remain Suspended
after snapshot activation. Red logs are `cap44-red.log` and
`cap44-suspended-red.log` under the qualification scratch directory. The
coordinator test run passes with the change in `cap44-green.log`.
Qualification acceptance remains pending.

### CAP-45: a client close left its durable request body out of date

Fixed. Release disk-pressure runs sometimes entered a snapshot rejection
loop. A committed registration result could still be waiting for its
completion event when the client disconnected. Closing the connection
changed the pending request's sink flag without marking its journal row
dirty. The later snapshot compared the changed request with the old durable
body and rejected ACTIVE with a phase violation. Reconnecting replayed READY
for the same snapshot and repeated the rejection. Waiting longer could not
repair the missing write.

Connection close now marks each affected request for a journal write and
continues the journal. Snapshot activation still requires the exact durable
request body. The regression retains a registration result without its
completion event, closes the client, commits the journal, and activates a
covering snapshot. The request is retired without replying to the closed
client and stays retired after restart. With the fix absent, the snapshot
fails with `active after close: Phase`; the log is `cap45-snapshot-red.log`
under the qualification scratch directory. The final regression passes in
`cap45-closed-result-green.log`. Wire formats, record formats, and the
recovery timeout are unchanged. Qualification acceptance remains pending.

### CAP-46: the campaign stopped before its configured deadline

Fixed. The release-profile development campaign `campaign-cap44-45-2`
completed every scenario, restored all 64 clients, and drained all three
base outboxes in 5.2 seconds. Its runtime assertions passed, but the
qualification validator rejected the report's 299,391,685,354 nanoseconds
against the required 300 seconds. The closing wait converted the remaining
duration to whole seconds by truncation, dropping the fractional second.
Daemon shutdown ran later and correctly did not count toward the campaign
duration.

The final wait now rounds a fractional second upward. The report continues
to measure actual monotonic elapsed time, and the qualification validator
still requires the full configured duration. A boundary regression requires
the wait to cover the remaining duration with less than one second of
rounding overhead. Its red log is `cap46-final-wait-red.log`, and the
corrected test passes in `cap46-final-wait-green.log` under the qualification
scratch directory. The earlier short report is retained as failed duration
evidence and is not accepted for qualification.

### CAP-47: a companion origin replay names itself as its predecessor

Fixed in the worktree. Link loss cleared the edge's declared and acknowledged
companion-origin generations but retained the last state ID. Rebuilding an
already declared nonzero generation then used that state ID as its new
predecessor. The bytes and object ID changed under the same generation, so
the coordinator correctly rejected the declaration. Retrying rebuilt the
same invalid successor.

Each local companion origin now retains its last declaration's exact encoded
bytes and replays them across link loss. A new generation alone constructs a
new successor. The regression covers repeated reconnects, a lost declaration
ACK, preserving a same-generation request sequence, and resetting the sequence
only after a new generation is acknowledged. It fails on changed wire bytes
in `cap47-red.log`; all 32 companion-edge tests pass in
`cap47-edge-tests.log`. The strict restart campaign remains pending.

### CAP-48: USERHOST uses the ISON reply renderer

Fixed in the worktree. USERHOST shared ISON's renderer and produced numeric
303 containing nicknames instead of numeric 302 containing cloak entries.
The new renderer uses the authorized session projection, preserves the away
indicator, and exposes only its ephemeral user and host components. An
invisible target remains indistinguishable from an offline nickname.

Appendix A.2 had also omitted 302, preventing the correct renderer from
passing the closed numeric validator. The specification registry, generated
artifacts, source bindings, and exact parameter-shape checks now include it.
The federation profile hashes and persistent format are unchanged. The bridge
and cloak/away/privacy regressions fail in `cap48-red.log` and pass in
`cap48-green.log`.

### CAP-49: MONITOR list, status, and add replies are missing or use ISON

Fixed in the worktree. MONITOR L and S rendered ISON numeric 303, and adding
subscriptions produced no status reply. The corrected closed registry and
renderers use 732 followed by 733 for the list, 730 for online status, 731 for
offline status, and 734 for bounded-list refusal. Lists retain the requester's
hidden and offline subscription names; status replies apply current presence
visibility. Empty status produces the permitted NoContent result.

Private subscription changes now preserve the public Session revision and
commit their exact result without an unsupported completion marker. A later
nickname change therefore uses the same published revision. The empty status,
private revision, and full local/federated reply regressions fail on the
original behavior and pass in `cap1-49-empty-green.log`,
`cap49-revision-green.log`, and `cap49-bridge-green.log`. The bridge exercises
add, list, status, clear, empty status/list, and a subsequent nickname change.

### CAP-50: WHOWAS has no bounded retention implementation

Fixed in the worktree under the specified privacy boundary. WHOWAS always
returned 406 and 369 because no nickname history was retained. StateCore now
retains only nickname, ephemeral public cloak, public account label, and the
retention second for 15 minutes, bounded by the configured maximum and the
10,000-record network ceiling. Edges retain no duplicate history. Memory is
charged before admission; exhaustion omits a cache entry and cannot fail an
already committed mutation. History becomes visible only after the mutation
commits, and an independent expiry wake clears it even during durable reload
or index refresh.

Disclosure requires a currently visible session with the same public cloak.
Losing that live authority hides the record. The implementation does not infer
account identity from a public label or retain an unauthorized historical
audience. The specification permits no historical Account ID or audience
fields, so post-disconnect disclosure remains unavailable. Appendix A.2 now
includes 314 and defines its public cloak and label fields; 312 carries the
public reply prefix and retained Unix second, never a hidden route identity.

Reinstating the original empty renderer fails in `cap50-red.log`, returning
406 and 369 where an authorized retained nickname requires 314, 312, and 369.
All six runtime tests pass in `cap50-final-runtime.log`, covering visibility,
commit admission, expiry, capacity, public labels, and count bounds. Exact
314 wire-shape acceptance and rejection pass in `cap50-wire-green.log`.

### CAP-51: final checkpoint starts before physical client cleanup

Fixed in the worktree. A writer could acknowledge Flush before its physical
close notice reached StateCore. The checkpoint then preceded durable session
removal, leaving the storage owner's Stop phase to checkpoint again. The
regression delays the real close notice and requires cleanup before the final
checkpoint. The original behavior fails in `cap14-close-red.log`.

The restore drills exposed an error in the initial fix: virtual remote
account carriers enter the same session table but own no socket and cannot
send a physical close notice. SessionTable now records physical ownership,
and the final checkpoint waits for physical cleanup plus the existing
pending-work barrier. A physical connection whose sink is already gone still
requires its close notice. Virtual carriers retain duplicate and capacity
checks but cannot block shutdown on a notice they will never send.

The mixed physical and virtual regression fails with the initial gate in
`cap51-virtual-red.log`; all four checkpoint ordering tests pass in
`cap51-virtual-green.log`, including a later `NotNeeded` checkpoint. A real
coordinator with remote authenticated sessions now stops and proceeds to
backup and restore in `cap51-virtual-green-restore.log`. That run then exposed
the independent CAP-9 channel reconstruction fault.

### CAP-52: graceful client output has no total drain deadline

Fixed in the worktree. Each queued frame received a fresh 30-second write
timeout, so a slow reader could keep a closed connection draining for many
such intervals. The queue now records the first close instant. All subsequent
writes share its single 30-second drain deadline; repeated close requests do
not extend it. Before closure, the existing per-write timeout remains.

A deterministic paused-clock regression accepts one frame every 20 seconds.
The original writer finishes three frames after 60 seconds with ClientQuit
instead of timing out once at 30 seconds. That failure is recorded in
`cap52-red.log`; all four final writer tests pass in `cap52-final-green.log`,
including closure during an already active write. Tokio's
clock-control feature is enabled only in runtime dev-dependencies. The
workspace manifest policy permits that exact test feature and rejects it on
the production dependency or with unapproved extra features.

### CAP-53: shared channel events exhaust the fanout frame ceiling

Fixed in the worktree. The edge allocated a separate frame for each recipient
of an identical channel event. Its 1,024-frame ceiling therefore rejected
valid events long before the 65,535-recipient ceiling. EventFanout now groups
exactly equal wire messages by their position in each recipient's stream.
Different tags stay separate, and repeated equal messages at different
positions remain distinct deliveries. Existing frame, recipient, and output
reservation limits are unchanged.

The full-recipient regression fails with `LimitExceeded` on the original
collector in `cap53-red.log`. All three regressions pass in `cap53-green.log`:
65,535 recipients receive the exact line only after reservation commit,
interleaved recipient streams preserve repeated messages and order, and a
recipient without the account tag never receives another recipient's tag.

### CAP-54: recovery drills seal account requests under a stale coordinator epoch

Fixed in the worktree. The account integration helper sealed every request
with the initial constant coordinator recovery epoch. A coordinator restore
installs a new epoch and the drill updates the peer configuration, but the
helper ignored that fixture and still sealed login and account-creation
requests under the old binding. The server correctly refused them.

All four creation and authentication start/finish helpers now use the enabled
coordinator's current pin from the validated fixture configuration. Missing
or mismatched pins fail the helper. The boundary regression changes only that
pin and requires old and new envelopes to decrypt only in their own epochs.
It fails in `cap54-epoch-red.log` and passes in `cap54-epoch-green.log`.
Both restore drills pass in `drills-cap9-54-green`, including existing and new
accounts. No daemon fallback or epoch-rejection rule changed.

### CAP-55: user mode changes use the wrong wire code and never reach the home edge

Fixed in the worktree. The edge and coordinator used mode code 2 for `w`, while the closed
registry and wire validator require code 18. A valid MODE request therefore
failed local request encoding before transmission. The edge also discarded
the requested nickname and could silently apply another-nickname MODE command
to the requester. The domain's durable operator-notice mutation emitted no semantic event, the coordinator
emitted no UserModesChanged projection, and the edge discarded that projected
event when rendering client output.

The domain now emits UserModesChanged and projects the resulting session only
to its home edge. The regression fails on the missing event in
`cap55-projection-red.log`; all nine projection tests pass in
`cap55-projection-green.log`. It drives enable, disable, and enable while
another edge shares a channel, checks that the other edge receives no private
mode update, and compares incremental records with the authoritative snapshot.
The runtime uses code 18, rejects another nickname as the target, and renders
the committed change to the home client. The full bridge passes enable and
disable, target rejection, actual flags on both users, and labeled MODE
queries in `cap59-bridge-green.log`.
The permanently enabled invisible mode remains immutable.

### CAP-56: authenticated admin failures are logged as authentication failures

Fixed in the worktree. AdminOwner classified rejection after the admin session has already
entered Closed. Reading the operator from that closed state loses evidence
that authentication succeeded, so a malformed signed command or confirmation
failure is mislabeled authentication_failed. This misleading category obscured
CAP-10's noncanonical command. The worktree correction captures authentication state before accepting the
line, retaining the existing bounded public log categories. The regression
fails in `cap56-red.log` because three authenticated rejections are counted
as zero. It passes in `cap56-green.log` with three authenticated command
rejections and one actual unauthenticated handshake rejection.

### CAP-57: the deletion drill mistakes a different account ID for login refusal

Fixed in the worktree. The drill deletes `delete-account`, but its original refusal helper always logs
in as `drill-account`. Passing the deleted account's expected ID makes a
successful login to that healthy account look like a failed deletion login.
The assertion can therefore pass without testing the deleted credential.

The correction must authenticate the deleted login explicitly with its known
password and accept only the expected OPAQUE invalid-login result. Identity
mismatches, framing errors, timeouts, and lost transports are drill errors.
The regression uses a healthy account's committed completion to prove that
a different Account ID cannot satisfy the deletion assertion. It also rejects
transport loss and SASL 904 as evidence of an invalid password. This test passes
in `cap67-green.log`. The full strict drill in
`cap66-67-strict-deletion/deletion.json` refuses the exact deleted login before
and after rekey and successfully authenticates the separate seed account.

### CAP-58: post-registration CAP changes leave recipient renderers on old settings

Fixed in the worktree. RegistrationState accepted CAP changes and returned ACK
after registration, but SessionTable retained only the capability snapshot
captured when the session was first bound. Recipient renderers and the edge's
own-user mode query read that stale snapshot. Later enabled features were
omitted and later disabled features could still be rendered.

The registration dispatcher now synchronizes the exact local capability state
before publishing negotiation replies or follow-up actions. The update checks
the bound session and reverse user-to-connection identity, allocates only when
the state changes, and leaves the old state intact if copying fails. It covers
CAP LS side effects as well as accepted requests. Registered identity fields
and their existing durable binding are unchanged.

The live two-client regression fails in `cap58-red.log` because an enabled
server-time tag is absent. All five related tests pass in `cap58-green.log`,
including actual tagged delivery after enable, untagged delivery after disable,
and rejection of another session or connection's update. Independent review
found no additional issue.

### CAP-59: federated query replies lose labels and pagination can release later commands

Fixed in the worktree for explicit directory queries. The edge sent federation reply frames directly without the original
request's logical response framing. Labeled directory queries therefore
receive uncorrelated replies. Completing a page can also release deferred
commands before the next query page is submitted.

The correction retains one bounded logical response batch across all pages,
validates page order, closes it on the final page or failure, and holds later
commands until pagination finishes. Replies stream through normal per-page
reservations. Disconnected sessions discard the response state. Empty labeled
results produce ACK, and private ACCT replies respect current standard-replies
negotiation. Six boundary tests pass in `cap59-final-green.log`. The live raw
delivery revert fails specifically at uncorrelated NAMES 353/366 in
`cap59-live-red.log`; `cap59-live-green.log` passes the same bridge with the
correction restored. A further regression removes the unlabelled page hold
and rejects an out-of-order continuation in `cap59-unlabeled-order-red.log`;
all seven response-boundary tests pass with the hold restored. Automatic JOIN
continuation is separately tracked as CAP-60.

### CAP-60: global JOIN omits committed topic replies and a bounded NAMES continuation

Fixed in the worktree. Section 14.2 requires JOIN events, committed topic numerics and target
failures, then a connection-owned NAMES continuation. The coordinator stages
an empty reply vector for JOIN, so topics and partial failures disappear.
The edge starts independent synthetic NAMES requests for every original
target, including failed targets. It discards the original label, releases
deferred commands before scheduling those queries, and lacks the specified
one-slot continuation with output-queue backpressure.

The correction carries bounded topic replies and failures in the membership's
stored committed result. Only accepted targets proceed to the NAMES snapshot.
One local continuation retains the original label, channel list, cursor, and
batch until completion, controls refill by client queue occupancy, and closes
the client on an interrupted burst. Coordinator, edge, local snapshot, and live bridge regressions cover these
boundaries. No federation schema change is required.

The coordinator result regression fails on the old empty reply vector in
`cap60-result-red.log` and passes in `cap60-result-green.log`. It checks exact
result replay, topics on existing channels, no-topic replies for new channels,
and a mixed successful/failed target set. A separate actual E2EE binding
regression fails on 331 in `cap60-placeholder-red.log` and passes with the fixed
332 placeholder in `cap60-placeholder-green.log`. The continuation, accounting,
and requester JOIN echo checks are recorded below.

The scripted edge now checks that an acknowledged membership event cannot
publish the requester's JOIN before its stored result is covered. Bypassing
capture fails that assertion in `cap60-echo-red.log`. Removing the continuation
hold sends a later command early in `cap60-hold-red.log`; bypassing interruption
cleanup leaves the client attached in `cap60-abort-red.log`. The earlier
`cap60-pending-join-link-red.log` also covers link loss before the first echo.
The fixed live coordinator-to-edge bridge passes in
`cap60-live-bridge-green.log`, with one labelled batch containing the exact
extended JOIN, topic, and complete NAMES response. Local output-queue and
snapshot accounting review is complete. Local snapshots reserve capacity
before the JOIN is admitted and open only after their exact revision commits.
An unrelated later batch cannot hold an already committed seed. Closed or
rebound generations cannot receive its output, and all retained capacity is
returned on refusal. Shared pages bound users, reply count, and encoded and
rendered bytes, and keep every terminal 366 on the final page.

Seven separate implementation reverts reproduce early output at half queue
capacity, oversized NAMES chunks, early terminal replies, split terminal
groups, excess users per page, missing active-query accounting, and blocked
committed seeds. Each corresponding `cap60-*-restored-green.log` passes. The
additional identity check passes in `cap60-generation-fence-green.log`;
`cap60-local-snapshot-final-green.log` and `cap60-shared-page-final-green.log`
cover the complete local snapshot and shared page tests. Both deferred queues now charge parsed commands and retain their backing
allocation permit through drain and reuse. The old undercharge and early
release fail in `cap60-edge-memory-red.log`, `cap60-local-memory-red.log`,
`cap60-join-backing-red.log`, and `cap60-queue-capacity-red.log`. The fixed
memory, continuation, echo-boundary, and complete live bridge checks pass in
the corresponding final green logs. Final review finds one additional retained
allocation: the local pending-seed vector keeps its backing after the last
snapshot permit disappears. On x86_64 the requested backing can reach 47,104
bytes, requiring a 49,152-byte rounded charge. The container needs its own
permit through empty, rejected, closed, and reused states. It now reserves all
256 slots before allocation and retains that permit until the buffer drops.
Both new tests fail under the old allocation path in
`cap60-local-capacity-red.log`; all seven local JOIN tests pass with the fix in
`cap60-local-capacity-green.log`. The strict capacity campaign still fails at
the separate disk-pressure session-loss defect in CAP-3. All required
development gates now pass for this repair set.

### CAP-61: recovery drills can pass without preserving their seeded topic

Fixed in the worktree. The seed client sets a topic on an ephemeral channel and then leaves
its only membership. The channel is correctly destroyed before the operation
being qualified. Restore and resynchronization record false topic observations
but omit them from their pass criteria. Resynchronization also labels its JOIN
completion boolean as topic visibility in progress text.

The corrected evidence must seed a registered channel, query its exact topic
explicitly, and require that topic before and after resynchronization and after
coordinator restore. Membership success alone cannot satisfy these checks.
Earlier green drill records establish their account, epoch, and shutdown
assertions only. The replacement fixture registers the channel before setting
its topic and leaving.

The strict resynchronization regression fails in `cap61-resync-red.log` after
22.53 seconds. Both exact TOPIC queries show no topic, while membership,
canonical attached-account shutdown, old-session disconnection, re-onboarding,
and all three final stops succeed. The corrected strict resynchronization
passes in `cap61-strict-recovery/resynchronization.json` in 19.61 seconds.
The same fixture also passes strict restore in 19.81 seconds and disaster
restore in 20.75 seconds, recorded beside it in `restore.json` and
`disaster_restore.json`. Both restore records require the exact topic, existing
and new account authentication, the expected guard witness, a changed
incarnation, and clean shutdown of all three daemons. These runs also require
first-attempt signed shutdown confirmation and never retry explicit
authentication refusals.

### CAP-62: a federated AWAY mutation omits its private acknowledgement

Fixed in the worktree. The edge projects AWAY notifications to recipients, but the coordinator
stores no private 306 or 305 reply in the committed result. The deletion drill
reaches ACCT DELETE START, then times out waiting for the AWAY acknowledgement
before CONFIRM. The phase trace is `drill-cap11-57-trace.log`; all nodes stop
cleanly.

The correction renders the appropriate numeric into the same durable result
as the AWAY mutation. The regression requires exact away and return replies,
and an identical replay that creates no new event. The drill retains its AWAY
assertion so public session-revision handling remains exercised between START
and CONFIRM. `cap62-red.log` fails on the old empty reply vector;
`cap62-green.log` passes exact 306, identical durable replay with no new event,
and exact 305. The actual deletion drill now passes the AWAY acknowledgement
and proceeds through deletion confirmation and credential refusal. Its later
shutdown failure is traced separately under CAP-65.

### CAP-63: the deletion drill requires an ERROR instead of the specified close sequence

Fixed in the worktree. The protocol requires the final committed NOTE followed by connection
closure. The drill waits specifically for ERROR and can reject a correct
NOTE followed by clean EOF. Its replacement assertion must require the final
NOTE and a clean transport end, while rejecting missing replies, ERROR alone,
timeout, reset, and truncated TLS. The boundary regression fails the valid
NOTE-to-EOF sequence under the old reader in `cap63-close-red.log` and passes
in `cap63-close-green.log`. It also rejects a fake NOTICE containing the
expected words, ERROR alone, timeout, would-block, reset, and TLS truncation.
This evidence error is separate from the confirmed production closure failure
in CAP-64.

### CAP-64: a committed federated account deletion leaves its requester connected

Fixed in the worktree. The strict deletion drill reaches CONFIRM and receives the final
`NOTE ACCT UPDATED`, then times out because the connection remains open.
`drill-cap11-62-63-trace.log` and its `deletion.json` record the failure after
47.58 seconds, with all three daemons stopping cleanly. The edge treats the
committed deletion as ordinary replies and omits the required requester close.

The correction emits a distinct completion only for a committed account-delete
confirmation with the exact successful NOTE. The router queues that response
before closing the transport. Ordinary completion and cross-profile barrier
regressions both fail on the missing close in `cap64-close-red.log`; a refused
confirmation remains an ordinary reply and keeps its client open. All three
fixed completion tests pass in `cap64-close-green.log`. The actual deletion
drill observes the required NOTE and clean TLS EOF, then correctly refuses
the deleted account's credentials. That run later failed at coordinator
shutdown, traced separately under CAP-65. With the later shutdown and evidence
repairs, `cap66-67-strict-deletion/deletion.json` completes the entire deletion
and rekey drill. Neither a stored result alone
nor an uncommitted covering event may trigger success or closure.

### CAP-65: abandoned account exchanges can outlive their remote origin and block shutdown

Fixed in the worktree. Source review finds that committing an origin DEL removes its domain
session but does not close the associated remote account carrier. A client
that receives an OPAQUE challenge and disconnects before FINISH can leave its
authentication transaction in the account service. The router's drain check
waits for account-service readiness, which requires those transactions to be
absent. The trace in `drill-cap65-diagnostic/deletion-logs/coordinator.stderr`
confirms one abandoned virtual carrier, zero physical connections, and no
pending or in-flight storage work. Drain exceeds its four-second deadline; the
final checkpoint takes 52 milliseconds. The real actor regressions in
`cap65-lifecycle-red.log` reproduce both a carrier surviving durable origin DEL
and local and remote unfinished OPAQUE exchanges blocking drain.

The correction must close the exact carrier after durable origin deletion and
cancel unfinished exchanges during shutdown. Already staged account mutations
must still settle through their storage receipts. Cancellation also needs a
narrow shutdown admission path for owned transaction-cleanup records, because
ordinary staging is correctly refused once quiescing begins. That path must
not admit arbitrary writes, new account mutations, or client fanout, and must
retain the normal storage and resource checks.

The implementation now captures the exact virtual connection generation in
the staged origin acknowledgement and retires it only after that receipt
commits. Shutdown cancels incomplete exchanges after staged account authority
settles; a private cleanup type admits only bounded transaction and reservation
deletes through the existing storage path. New remote authentication is refused
once quiescing begins. The nine focused tests in `cap65-final-green.log` cover
these lifecycle paths, stale origin identities, prohibited writes, resource
bounds, staged authority, and an indeterminate cleanup receipt. Reverting the
new guards fails in `cap65-readmission-red.log`,
`cap65-cleanup-authority-red.log`, and
`cap65-cancellation-authority-red.log`. The actual strict drill now passes
the formerly blocked coordinator stop and completes rekeying. Its later
authentication check reveals the separate controller failure in CAP-66. The
failed record remains `cap65-strict-deletion/deletion.json`; it is not a
passing complete-drill claim. With CAP-66 and CAP-67 corrected, the full drill
passes in `cap66-67-strict-deletion/deletion.json` in 39.20 seconds. It requires
deleted-login refusal before and after rekey, exact authenticated deletion rows,
a preserved unrelated credential and successful login, and clean shutdown of
all three daemons.

### CAP-66: a restarted drill network accepts historical link events as readiness

Fixed in the worktree. `DrillNodes::restart_all` reads cumulative link counts after starting
its nodes and subtracts one before waiting. Old log events therefore satisfy
the wait even when the new process has established no federation link. The
deleted-login helper also omits the active-authority wait used by normal
account-login probes. In `cap65-strict-deletion/deletion.json`, deletion,
credential refusal, shutdown, and rekey succeed, then the probe receives 904.
The edge-b log shows its new listener and client connection but no established
federation link or profile acknowledgement in that process.

The correction captures link counts before restarting, requires new link
events and active federation on both edges, and checks active authority before
the deleted-login attempt. An explicit 904 remains a failed probe. No retry of
authentication refusal is introduced. The full strict drill now passes in
`cap66-67-strict-deletion/deletion.json` in 39.20 seconds. Reverting only the
readiness correction fails in `cap66-readiness-red/deletion.json` after
41.04 seconds, with an explicit edge-b SASL 904 after rekey. The authenticated
deletion records and surviving credential remain correct in that failing run.

### CAP-67: deletion evidence uses unrelated total backup size as an acceptance gate

Fixed in the worktree. The deletion drill requires total record count and total backup bytes to
fall after deleting an account. Those totals include independent federation
journals, audit records, and other retained state. The strict run records
61 rows and 136,182 bytes after account creation, then 78 rows and 185,311
bytes after deletion and further protocol work. Those measurements cannot
establish whether the account's credentials were erased. The later CAP-66
failure prevents the run from reaching this already-false final predicate.

The replacement evidence must inspect exact authenticated account, OPAQUE,
and login-index rows before deletion, after deletion, and after rekey. It
must require the canonical deletion tombstones, the deleted credential's
absence, and preservation of an unrelated account and credential. Whole-backup
counts remain observations. The actual deleted login must be refused before
and after rekey, while the unrelated account must still authenticate. The old
predicate falsely rejects valid deletion with journal growth in
`cap67-growth-red.log` and accepts a still-live account when unrelated totals
shrink in `cap67-falsepositive-red.log`. The corrected three evidence tests
pass in `cap67-green.log`, including wrong identities, retained credentials,
post-rekey revival, and changes to the unrelated credential. The full strict
drill also passes in `cap66-67-strict-deletion/deletion.json`.

### CAP-68: the integration fixture can assign one port to multiple listeners

Fixed in the worktree. The full workspace gate rejects the encrypted network's coordinator
configuration before startup because two listener endpoints overlap. Both
edges then exhaust their link wait. The failure is retained in
`cap68-workspace-red.log`; it is not a runtime federation failure.

The fixture selects a loopback port by binding port zero and immediately
dropping the socket. Later selections may return that same address before
any daemon binds it. A process-wide synchronized claim set must prevent reuse
within a network and across parallel fixture construction, with a bounded
selection loop. A failed daemon must not be retried to hide the fixture error.
This addresses duplicate selections in the integration executable. An
unrelated external process can still race the existing bind-to-spawn gap;
the tests do not pass inherited listeners to the daemon.

The helper now retains synchronized address claims for the lifetime of the
test executable and limits selection to 128 attempts. Reverting that loop
returns the same claimed address and fails both deterministic tests in
`cap68-red.log`. All four fixed tests pass in `cap68-green.log`, covering
duplicate selection, exhaustion, preservation of the original bind error,
and 64 real allocations across four concurrent fixture builders. The exact
full workspace gate now passes, including the parallel encrypted fixtures.

### CAP-69: the local account test can accept refused deletion as success

Fixed in the worktree. The inherited account test sends a wrong deletion token, then reuses
the original token even though every confirmation consumes its challenge and
fresh authentication. Its deletion assertion accepts any collected reply,
including a refusal. The later login probe sends only START and ignores the
outcome, so that step cannot establish credential erasure either.

The corrected test must require the wrong-token refusal while preserving the
connection, complete fresh authentication and obtain a new challenge, and
then require the exact committed deletion NOTE followed by clean closure.
A complete login attempt with the deleted account's known password must fail
with the expected OPAQUE invalid-login result. Unexpected replies, transport
errors, and account-identity mismatches cannot count as evidence of deletion.

The strict assertion rejects the original stale-token flow in
`cap69-stale-token-red.log`, where CONFIRM returns BAD_STATE. The corrected
live flow passes in `cap69-local-deletion-green.log` after 11.84 seconds.
Logout uses a separate connection so deletion can exercise its fresh
authentication within the specified two SASL attempts per connection. The
wrong-token refusal and PING precede the second authentication, a distinct
new challenge, the exact committed NOTE and clean EOF, and the late known
password's typed invalid-login result. `cap69-evidence-green.log` rejects
refusal text, extra output, transport failures, successful authentication,
and account-identity mismatch as false evidence.

### CAP-70: intact companion restart drops retained delivery scope and events

Partially repaired. The original ordinary daemon restart preserved its stored
incarnation and recovery epoch. Companion startup collected delivery records but restored only
cursor rows, leaving the retained event queue, barrier, and peer synchronization
state empty. ERESUME then treats the absent in-memory peer scope as initial
admission and opens a new ESTATE generation, even if no paired base snapshot
advanced the durable client resynchronization epoch.

Companion Section 12.5 requires byte-identical replay of unacknowledged rows
within the same authenticated scope. Its ESTATE rules permit initial admission,
a new recovery scope, or an explicit paired base snapshot. An intact process
restart alone satisfies none of those exceptions. Restoring only the cursor
therefore loses the evidence required to resume the existing delivery stream.

The source audit is `cap3-companion-recovery-audit.md` in the qualification
scratch directory. The real-storage regression in `cap70-intact-restart-red.log`
commits ESTATE activation and two production events, discards the owner, and
reloads authenticated rows into a fresh owner. With unchanged incarnations,
epochs, and base resynchronization state, ERESUME produces StateBegin and
StateEnd at generation 1 instead of ResumeOk at generation 0 and the original
event bytes. The behavioral failure takes 0.07 seconds; an earlier fixture
revision error is not counted as evidence. Exact regression source and its
frozen executable are retained in `cap70-71-proof` outside the worktree.

The schema-3 repair retains an authenticated delivery scope, cursor, scoped
outbox rows, snapshot cut pages, and exact READY and FETCH progress. Production
loader tests cover intact replay, interrupted snapshots, retained random
cursors, exact receipt publication, storage refusal, and scope changes.

The interrupted workspace gate exposed a further startup refusal. The loader
rejected every retained cross-profile row, including rows already covered by
a committed companion ACK. The resumed regression fails with Storage against
that predicate. The corrected loader preserves acknowledged rows with their
exact event bytes and stored cross-profile headers. Its negative control still
refuses an unacknowledged barrier without a combined durable record. Both cases
pass in `resumed-acknowledged-barriers-green.log`; the behavioral failure is
`resumed-acknowledged-barriers-red.log`. The real three-daemon encrypted restart
also passes in `resumed-workspace-tests-final.log`.

The base loader now separately refuses a retained cross-profile part above its
durable base cursor, including when a snapshot flag is set. Without this guard,
a committed companion ACK could leave the unfinished base half eligible for
ordinary replay. Both unsafe startup cases fail in `resumed-base-barrier-red.log`
and pass in `resumed-base-barrier-green.log`; a retained part covered by the
base cursor remains a passing control. These tests run through authenticated
storage reconstruction.

The combined-barrier repair now writes the validated DeliveryBarrier with
both streams' event rows. The final base event carries that exact prepared
record through the mutation receipt. A coalesced batch cannot reconstruct its
endpoints by collecting unrelated events for the same target. Admission refuses
a second combined barrier for a target whose earlier gate remains open.

Startup reads companion owner and gate metadata before the base outbox at one
pinned storage commit. It checks both complete part sequences, mutation and
state generation, delivery generations, final event identities, historical
scope, and independently committed cursor coverage. The base peer may be Ready
or Suspended in that unchanged scope. Missing parts or companion bytes,
contradictory coverage, changed scope, and snapshot replacement remain errors.

The original companion reconstruction test fails for all three unfinished
coverage states and passes for the completed state in
`cap70-combined-owner-red.log`. Those tests use an explicit codec fixture for
the base endpoint. The new full coordinator tests separately use the real
storage owner and both event streams. They cover both ACK orders, restart
after each half, and restart after storage commit without the old coordinator's
publication callback. Replay on either profile stops at the gate, including
when later ordinary rows share the same base read page. Outbox overflow refuses
the new mutation while a gate is open; it cannot replace that gate with a
snapshot. These component tests do not qualify a Stage 10 release.

### CAP-71: companion acknowledgement coverage has no durable receipt owner

Partially repaired. The original EACK path validated its addressed delivery
stream and then changed its in-memory acknowledged cursor and replay class.
It returned no staged action,
updates no durable outbox row, and owns no storage receipt. A later event may
write the cursor incidentally, but an ACK followed by an intact restart can
recover older coverage. The outer coordinator can also release a combined
barrier immediately from this in-memory companion cursor when the base half
is already durable.

The companion stream must retain its last acknowledged cursor and move rows
to acknowledged replay atomically. Base Section 20.8 requires both barrier
halves to have durable acknowledgement coverage before release. The current
companion path cannot establish that condition. Correct restoration under
CAP-70 must therefore include an explicit acknowledgement transaction and its
receipt ownership, with complete barrier metadata reconstructed from durable
evidence.

The independent real-storage regression in `cap71-ack-receipt-red.log`
reproduces the fault in 0.07 seconds: EACK returns no Stage action for its cursor
transition. The exact source and frozen executable are retained alongside the
CAP-70 proof. This failure establishes the missing durable owner; it does not
claim successful rejection or restart recovery.

The current ordinary companion ACK path stages the scoped cursor and changed
outbox classes together, then updates memory only after the exact storage
receipt. Real-storage tests cover refusal, commit followed by restart without
an unrelated event, original acknowledgement timestamps, and malformed or
partial acknowledgements. The acknowledged-barrier replay correction under
CAP-70 preserves those committed companion flags.

Each final ACK now stages its gate flag with that stream's cursor and outbox
changes. A prepared update owns the exact prior gate. Memory changes only when
its transaction receipt is handled; determinate refusal leaves both owners
unchanged. The second ACK deletes the durable gate in its transaction and
releases later events after the receipt. The companion replay hold remains
active after its own ACK while the base half is outstanding.

A reconnect presenting the exact final endpoint of an unfinished barrier can
stage the missing ACK. Neither FRESUME OK nor ERESUME OK is emitted before that
transaction's receipt. Partial endpoints and wrong final identities remain
invalid. Real-storage tests cover both final-ACK resume paths, both completion
orders, refusal at either half, all four restart states, and loss of the
in-memory callback after a successful storage commit. The published replay
retention obligation remains separate under CAP-79.

### CAP-72: declared recovery preserves obsolete companion state and live routes

The old restore selector sent every E2eeState row to RestoreE2eeState.
That transform updated only the legacy kind-1 recovery gate and copied every
other kind unchanged. Typed route rows use kind 2, replay rows and origin
floors use kind 9, delivery cursors and outboxes use kind 10, and combined
barrier records use kind 12. The route's recovery_gate therefore stayed false,
while obsolete stream and barrier ownership survived into the new incarnation.

Section 23.7 requires every live encrypted route to enter recovery pending
while preserving its counters and proof head. It also requires discarding old
base and companion delivery scope, barriers, their parts and receipts, and
federation request replay roots. Four original regressions in `cap72-red.log`
reproduced the fault through the actual selector and RecoveryTransformV1.

The correction uses a closed typed classifier. It validates each obsolete
record's key and body before omitting it, including cursor, witnessed cursor,
outbox, snapshot, replay, origin floor, barrier head, and barrier part records.
A stale construction plan cannot bypass the classifier and copy those rows.
Active and closing routes become pending without changing their stored proof
heads, counters, revision, or generation. Tombstones are not reopened. Existing
terminal recovery gates keep their terminal state, and retained sequencer,
mailbox, and key-set bytes remain exact.

Route keys must match the conversation in a complete FederationState object.
Legacy recovery-gate keys must match their body's conversation. Tests reject
mismatched identities, truncated keys and route objects, wrong delivery arms,
and barrier identities. The final eleven-test suite passes in
`cap72-focused-green.log`. Replacing the classifier and transformer with their
old behavior produces ten behavioral failures while the preserved-proof
control still passes in `cap72-final-proof/red.log`. The upgraded fixtures,
exact reverted and fixed helper bytes, frozen executable, and hashes are
retained in `cap72-final-proof` outside the worktree.

These are typed storage regressions, including complete route-state object
encoding. They do not establish a complete signed encrypted-conversation
recovery. All required repository gates pass: formatting, Clippy, 2,126 workspace
tests with no failures and 21 ignored qualification tests, source checks and
self-tests, workspace policy, and coverage rejection self-tests. At repair checkpoint `9beaafd`, both reviewed
inventories bind 478 production source files. The release policy now lists
134 critical regions with unchanged coverage floors; that inventory update
is not a new branch-coverage measurement. CAP-73 still requires runtime
admission, recovery provenance, and terminal-evidence handling before declared
recovery can satisfy the complete encrypted recovery contract.

### CAP-73: pending encrypted routes lack admission and recovery-evidence handling

Partially repaired; terminal-evidence ingestion remains open. Startup derives
both domain recovery gates from RouteRow.recovery_gate. The original code had
the following admission gaps.
Several admitted upload handlers do not consult either gate. In particular,
submit_finalization reads a retained candidate through a map lookup and signs
a new CommitFinalization certificate. Abort and ReInit-attempt handling have
the same missing restriction; policy, authorization, and ACK handling also
admit new state without the pending-route check. Candidate creation and
application ciphertext already check their lifecycle, so those checks do not
protect every mutation path.

Base Section 18.4 and companion Section 13.7.1 prohibit new encrypted authority
while the restored route is pending. They permit only exact previously signed
recovery evidence under the specified validation rules. Before these repairs,
neither domain resolve_recovery method had a runtime caller, and the loader
ignored per-route recovery records and source-guard provenance. Setting the
typed flag under CAP-72 did not complete encrypted recovery.

Two runtime regressions now reproduce the finalization defect. The fixture
first verifies a valid finalization on a normal route, then changes only the
typed recovery flag and reloads the same retained evidence through the real
startup loader. Both reconstructed gates are Pending. The real operation
dispatcher still returns new rows for storage, failing
`cap73-finalization-red.log` in 0.20 seconds. A second case removes the signer
only after the normal-route control passes. It reaches the signer-dependent
failure instead of the required early RouteInvalid refusal, failing
`cap73-signer-order-red.log` in 0.20 seconds. The test does not count internal
signing calls or claim a subsequent storage commit. Exact source, executable,
and hashes are parked in `cap73-proof`; the temporary failing test is removed
from the independent storage repair checkpoint.

The repair must enforce the closed operation policy and implement the
validated recovery-evidence owner with exact restored heads, target epoch,
and source guard. It must preserve byte-identical allowed evidence replay and
cannot synthesize a successful recovery transition from the current live
state. The terminal-evidence ingress and its profile compatibility require an
explicit implementation contract in addition to the early mutation guards.

The current admission repair passes all 18 recovery runtime cases and two
mailbox scan cases in the second frozen build. Both route and lifecycle gates
are checked before mutation handlers. The tests cover private object lineage,
mailbox selection before token allocation, exact retained ACK replay, malformed
retained metadata, independent conversations, and ReInit successor admission.
The scan charges every inspected encoded object against the existing account
mailbox byte ceiling, including excluded and repeated objects. These focused
results do not close the terminal-evidence lifecycle or replace the required
reverted-behavior proofs for the additional guards.

The next restore-provenance review finds that the one-source transform copies
heads from a Normal gate even when the authenticated RouteRow has advanced.
The resulting Pending declaration then disagrees with the restored route and
startup refuses it. A normal live source route without a gate produces no
declared source-guard record. The repair must bind a gate to the RouteRow from
the same backup, preserve terminal declarations and retain the blocked state
of an already-pending legacy route with no trustworthy declaration. New
planner/transformer tests now reproduce three failures in 0.01 seconds: stale
Normal heads survive, a normal source route gets no declaration, and an orphan
gate forms a plan. Matching Pending, terminal Closed and ambiguous legacy
Pending controls pass. The first attempt stopped at a test formatting trait
error. The corrected inputs and executable are frozen in
`cap73-restore-provenance-red-proof`; the three failures do not by themselves
prove backup signature verification or daemon startup.

The restore planner now pairs each declared gate with its route source in a
bounded scratch index. The index and output entries share the plan byte limit,
and unfinished or duplicate declarations refuse the plan. Normal source heads
come from the paired route. Pending heads and guard state must agree; Closed
and Conflict retain their original provenance. A normal source route without
a declaration receives one. An already-pending legacy route without a
declaration stays blocked without an invented source guard. Existing terminal
route metadata remains terminal; this is not new endpoint close validation.

All fourteen planner and transform cases pass, including scratch-file reuse.
The signed-backup integration case passes seven source-state variants in 0.77
seconds: it creates the backup,
stops storage, verifies the backup, executes and resumes restore, then reads
the installed records through authenticated storage validation. The new
declarations name the exact signed backup guard, target epoch and source route
heads. The route wire bytes remain unchanged. These typed route fixtures do
not claim an MLS endpoint lifecycle or composed-daemon recovery-evidence
validation. The old standalone-gate transformer tests now supply paired route
sources. All eight checkpoint gates pass: formatting, all-target all-feature
Clippy, locked all-feature workspace tests, source policy and its self-test,
workspace policy, coverage-policy self-test and diff checks. The workspace
passes 2,684 tests with no failures and 22 default-ignored tests in 183.54
seconds, including 229 storage unit tests and 1,201 runtime tests. Both catalogs
cover 760 source files with hash
`2e3cc8f004bdafac63261c365c6ace2d2853343b8d982d408ac7cab2c1b79d0f`.
The release catalog has 1,064 regions, including twenty reviewed restore
regions. This adds no coverage measurement and changes no threshold.
`cap73-restore-provenance-final-proof` retains exact inputs, check logs and
five executed binaries. That checkpoint left Normal-row live persistence and
complete terminal recovery-evidence ingestion open.

The live Normal follow-up reproduces two missing-record failures: a successful
BIND has no durable declaration, and its private outcome contains none. Both
fail in 0.06 seconds; `cap73-normal-red-proof` retains the four exact inputs,
runtime executable and log. An earlier missing test import is only a compile
failure. The dispatcher now prepares a Normal declaration for each newly
written ordinary route that lacks one. This includes successor BIND and the
next head mutation of a legacy Normal route. The declaration uses the current
daemon epoch, creation heads and a zero source-guard hash because no restore
has occurred. It retains its owned memory only when the route's commit effect
applies. Missing identity, insufficient backing or a blocked route refuses the
private outcome. Existing Normal heads can advance without rewriting this
declaration; restore derives current heads from the authenticated source route.
An ordinary close retains Normal metadata with its tombstone. It does not
invent a restored terminal proof or downgrade an existing blocked gate.

Eight new tests pass in the 1,209-test runtime suite. They cover durable and
private declarations, memory ownership and refusal, absent daemon identity,
head advancement, legacy Normal admission and actual storage shutdown/reopen.
The storage case verifies both callback delivery and callback loss, exact
commit advancement, sealed readback and reconstruction of matching route and
gate heads. It drives the real handler and StateCore storage transaction;
callback application is explicit in the fixture. It does not claim a full
federation dispatch or terminal MLS recovery-evidence chain. Existing tests
cover successor BIND and ordinary close with the new declarations.

The first full runtime run passes 1,203 tests and exposes six fixture failures,
retained in `cap73-normal-fixture-failures-proof`. Two incomplete-history tests
now expect startup refusal because their declared gates cannot outlive routes
that fail reconstruction. The sealed successor helper now reserves backing
when admitting records. The new storage fixture installs its database identity
before binding a route. All six cases pass after those corrections.
Normal live persistence is implemented; complete terminal recovery-evidence
ingestion remains open.

All eight checkpoint checks pass with 2,692 workspace tests, no failures and
22 default-ignored tests in 180.42 seconds. Clippy first found two unnecessary
map lookups in new tests; those are corrected and its final run passes in
5.41 seconds. Source policy checks 898 Rust files. Both coverage catalogs bind
763 source files to
`93747a17dca00476604ff52a5d125b04f2e29ff8fef8e1e68b851e984298f0eb`;
the release catalog has 1,066 critical regions, including the two new Normal
preparation functions. Sixteen existing region bindings follow changed source
files. No coverage measurement or threshold changes. The exact changed inputs,
check logs and executed binaries are retained in `cap73-normal-final-proof`.

The declared kind-one recovery regression proves that the original companion
loader ignores the entire row, including the restored
binding, accepted state, sequencer head, recovery epoch and source guard.
New direct reconstruction cases pair a valid retained candidate and normal
finalization control with the typed Pending route and a declared recovery
gate. The matching declaration must preserve both Pending guards; separate
changes to each restored head or epoch must refuse reconstruction. All four
contradictory declarations are wrongly accepted; the matching control passes.
The run records four failures and one pass in 0.27 seconds, with exact inputs
and executable frozen in `cap73-declared-gates-red-proof`. The first attempt
had an incorrect fixture import and is not behavioral evidence. This fixture
tests the real companion collector, without claiming a signed backup or
storage-owner restart.

Declared recovery rows now reserve memory before capture and retain their
exact source guard, epoch and heads until coordinator destruction. Invalid
keys, missing backing, refused memory and late metadata make reconstruction
fail even if valid rows arrive later. Pending declarations require the exact
route heads, current recovery epoch and Pending flag. Normal declarations
require the current epoch and normal flag; ordinary live heads may advance.
Closed and Conflict declarations preserve their original source epoch and
blocked guards. Closed requires a tombstone and close identifier.
This validates retained terminal metadata, without establishing a new signed
terminal chain. Legacy typed Pending routes remain blocked without an invented
source guard.

Recovery installation follows successor validation and requires the route,
log, lifecycle and conversation to remain present. The new lifecycle transition
preserves pending joins, bootstrap state and pending removals. An introduced
ordering regression discarded a successor after installing its recovery row;
the exact failing run is frozen in `cap73-declared-successor-order-red-proof`.
An introduced Normal-head equality check rejected a valid finalized route on
restart; its failing run is frozen in `cap73-declared-normal-heads-red-proof`.
Both cases now pass.

All 23 new recovery tests pass within the runtime suite's 1,190 passes, zero
failures and one explicitly ignored capacity test. This includes storage-owner
shutdown and reopen for all four orphan gate kinds, with exact sealed readback,
composed startup refusal, unchanged storage commit and released memory. That
case does not construct a signed backup or a valid closed conversation. The
original four Pending-head/epoch failures and both introduced regressions
remain archived. All eight checkpoint gates pass with 2,653 workspace tests,
zero failures and 22 default-ignored tests. Both inventories cover 751 source
files. The release catalog contains 1,037 critical regions, including ten new
regions and 42 existing-region rebindings. Coverage thresholds are unchanged;
this catalog update is not a new coverage measurement. The first gate attempt
found three unchecked vector accesses in a new test, and the second passed
the workspace suite before the source policy required predicate decomposition.
Both attempts are archived; checked accesses and a focused head-comparison
helper pass the final gates.

Normal-row persistence, binding declared restore to the authentic current
source heads, terminal-evidence ingestion and historical authority validation
remain open. The new startup checks do not qualify those paths.

### CAP-74: the persistent registry rejects every chain-witness evidence row

Partially repaired; authenticated witness resolution remains open. The edge
constructs a WitnessRow after detecting a skipped or conflicting
sequencer position. Its typed codec and key use E2eeState kind 13, but the
outer persistent record registry accepts only kinds 1 through 12. Consequently,
record_witness cannot construct the storage write even for a valid witness.
It still reports the violation and closes the link; the required durable
evidence is lost before a storage transaction can be staged.

Companion Section 12.5 requires a durable witness/v1 row containing only the
conversation and expected and observed chain identifiers. The existing tests
exercise the in-memory witness and its inner codec, so they do not reach this
outer registry refusal. The regression now fails at the intended persistent
boundary in `cap74-proof/red.log`: the inner WitnessRow round trip succeeds,
then PersistentRecordValue::new returns InvalidEncoding. The sealing and
restart assertions are not reached. Exact test source, registry source, and
the frozen executable are bound by `cap74-proof/manifest.json` outside the
worktree. The temporary failing test is parked while the repair proceeds.

The schema-3 integration must admit the closed current record kind and retain
explicit legacy source-generation rejection. The actual failure-frame staging
and receipt path also needs a regression; admitting the record alone does not
prove that a refused or unfinished write is retained correctly.

The current schema-3 envelope admits kinds 13 and 14 while legacy source
validation rejects either new kind in generations 1 and 2. The previously
failing witness test now reaches sealing and two storage-owner restarts and
passes in 0.02 seconds. `cap74-storage-green.log` records that result, with the
exact source and executable retained in `schema3-storage-first-integrated`.
The actual failure-frame regression now reaches the exact kind-13 metadata
write and then fails because the base link closes before its receipt. That
behavioral result is retained in `cap74-runtime-first-red.log` and
`cap74-first-runtime-proof`. The first receipt repair retains one bounded
witness through determinate refusal, reserves a retry timer before consuming
the witness, and closes only the original link after its committed storage
head. Five real storage and link tests pass in `cap74-witness-final-green.log`
from `cap70-scoped-fixed-final`.

The callback correction now captures an exact witness attempt token before
earlier rejection callbacks can stage successor work. Success uses the owned
committed head, so a newly pending batch cannot hide the witness receipt. All
seven receipt cases pass in `legacy-restore-query-witness-proof/witness.log`,
including successor staging and stale rejection-token replay. Durable recovery
gating across restart and a proven snapshot resolution path remain open. A
larger route-cut sequence alone does not prove ancestry to the witnessed head.

### CAP-75: an attached nonparticipant can deliver a valid binding

Fixed in the worktree. The original binding-delivery handler authenticated the
attached account and
target device but does not require the sender to be an approved participant
in the binding. Companion Section 11.4 requires that participant authority.
Possession of a publicly retrievable binding object does not grant delivery
authority.

The regression keeps the exact valid binding bytes, establishes a different
real identity and attachment, and submits delivery from that account. The
handler admits it, producing the behavioral failure "nonparticipant binding
delivery was admitted". The exact source and executable are retained in
`cap13-boundary-fixed`; `cap73-76-boundary-results.log` records the result.
The repair must verify participant authority without trusting an unverified
principal list or rejecting an exact previously bound artifact solely because
its participant roster has since changed. Public object retrieval remains a
separate operation.

The focused repair now checks the exact retained binding's participant
authority, or verifies a new binding package against the trusted principal
rosters before using its participant list. The nonparticipant regression and
the forged-approval negative pass with a valid participant control. The three
cases pass in `cap73-76-third-results.log`. Full workspace and release
qualification of this change remain pending.

### CAP-76: ReInit can overwrite an existing normal successor conversation

Fixed in the worktree. The original ReInit admission checked the predecessor's
recovery state, but ordinary
Attempt and Activate requests can name an already occupied successor. The
activation handler replaces that successor's log and lifecycle before later
BIND route checks could reject reuse. Checking whether the successor is in
Normal recovery state does not establish that its identifier is vacant.

Two regressions create separate real bound conversations and use the second
conversation's actual identifier and group in the first one's otherwise valid
ReInit request. An absent successor passes the positive controls. The existing
normal successor is still admitted for Attempt, and Activate replaces its
retained head. Both behavioral failures are recorded in
`cap73-76-boundary-results.log` with exact source and executable in
`cap13-boundary-fixed`. The activation fixture uses actual server sequencing
and quorum evidence; it is not a complete MLS client ReInit campaign. The
repair must reject any retained route, conversation, log, or lifecycle at the
successor identifier before handler signing or mutation.

The admission guard now requires complete absence of the successor from the
route, conversation, log, and lifecycle maps before handler signing. The two
behavioral regressions and an empty-successor control pass in
`cap73-76-third-results.log`. Startup now rejects duplicate successor claims
before creating inferred anchors and refuses an incompatible occupied target
without deleting its independent route. Three sealed reconstruction tests pass
under the corrected ReInit signature domain: occupied target refusal,
duplicate target refusal in both row orders, and preservation of an advanced
legitimate successor. Reversing only the startup guard under those corrected
signatures produces both collision failures and preserves the advanced
successor control. The old behavior loses the independent occupied route.
Exact fixed source is restored and all three rebuilt cases pass. These
results are archived in `recovery-audit-command-boundary-red-proof` and
`recovery-audit-command-boundary-fixed-proof`.

### CAP-77: acknowledged mailbox items are offered again after reconstruction

Fixed for schema three; legacy ambiguity is refused during migration. The
original successful mailbox ACK persisted the ACK and token deletion without
retiring the item row. Startup restores the item, so a later normal fetch
offers it again. The regression applies every actual ACK Delete to the
surviving row set before reconstruction, avoiding the fixture's older Put-only
shortcut. FetchMailbox then returns MailboxPage instead of Empty(Binding), as
recorded in `cap73-76-boundary-results.log`. Exact source and executable are
retained in `cap13-boundary-fixed`.

Deleting the item alone would remove the only retained sequence high-water
evidence when the queue becomes empty. The repair therefore needs a durable
mailbox sequence owner, atomic item retirement and ACK replay state, and exact
startup reconciliation. Legacy ACK records do not identify an individual
consumed sequence when the same object was delivered more than once. Migration
must not resolve that ambiguity by deleting every matching object or inventing
a missing historical counter.

The schema-3 repair adds an exact key-bound kind-15 sequence owner, writes the
owner with delivery, and retires the exact item and token in the same durable
ACK transition. Startup requires the retained owner and validates every item
against its exclusive sequence floor. In `cap13-combined-join`, seven runtime
cases, seven domain mailbox cases, and two owner-codec cases pass. They include
the original post-ACK reconstruction failure, empty-queue restart, sequence
exhaustion, missing-owner refusal, and exact ACK replay preserving a later
duplicate delivery. The logs are `cap77-first-runtime-results.log`,
`cap77-domain-results.log`, and `cap77-codec-results.log`. Legacy ambiguity and
the full repository gates remain open.

Two construction regressions then exposed missing checks at the maintenance
boundary. The declared-recovery selector accepted a kind-15 owner under a
different account key, and the new migration installed a legacy kind-8 item
without durable sequence evidence. Both fail behaviorally in
`cap77-construction-red-proof`, while exact-owner preservation passes. The
selector now checks the repeated owner identity, and migration refuses legacy
mailbox state before creating the backup or target. Thirteen recovery
classification tests and seven real migration tests pass in
`cap77-construction-fixed-proof`. This refusal prevents installation of an
unreconstructible target; it does not resolve missing historical evidence or
authorize deleting legacy deliveries.

### CAP-78: mailbox continuation does not preserve a random immutable snapshot

Fixed in the worktree. Companion Section 11.7 requires random continuation and snapshot tokens bound
to the original identity, request kind, scope, immutable snapshot, and timeout.
The current FetchMailbox handler instead reads a live sequence from the final
eight cursor bytes, ignores the first 24 bytes, and generates another snapshot
token for every page. A delivery added between pages can enter the old cursor's
result set. CAP-77's durable sequence owner does not provide this snapshot
contract.

Three tests use 33 valid participant deliveries to obtain a real continuation.
They separately check stable snapshot identity, exclusion of a 34th delivery
inserted after the first page, and refusal of a changed opaque cursor prefix.
The source evidence and additional required identity, timeout, and restart
cases are recorded in `cap78-mailbox-cursor-evidence.md` in the qualification
scratch directory.

All three assertions fail in `cap78-cursor-red.log` from `cap13-guards-fixed`.
Review then found that the inherited fixture entropy repeats delivery tokens
within a full page. The fixture now uses separate deterministic entropy and
asserts that all 32 delivery tokens are distinct. All three original failures
remain reproducible in `cap78-distinct-cursor-red.log` after that correction.

The repair retains one charged immutable snapshot with random opaque cursors,
exact mailbox and attachment scope, a fixed expiry, and live recovery checks
on each page. It reserves timer admission before staging and keeps the armed
timer outside prepared storage effects. All ten focused tests pass in
`cap78-cursor-scoped-final.log` from `cap70-scoped-fixed-final`. Shared configured
query counters and immediate release on exact origin close were added next.
The shared ledger combines local and mailbox usage for admission, reload
floors, and statistics. Fifteen cursor tests pass in
`legacy-restore-query-witness-proof/cursor.log`, including five accounting and
rollback cases. Three publication regressions also pass in the resumed workspace suite.
They reject a prepared cut after origin close, prevent revival of a different
closed origin, and discard a cut that expires before its storage receipt.
The base federation accounting gap is recorded as CAP-81.

### CAP-79: companion replay discards acknowledged rows below published limits

Open. The original coordinator trimmed acknowledged replay to 4,096 rows, although
Companion Section 16 publishes limits of 1,000,000 rows, 1 GiB, and 24 hours
per target. A test retaining 4,097 valid event rows below those bounds actually
keeps only 4,096. It fails in 0.28 seconds in `cap79-retention-red.log`, with
the exact executable and source frozen in `cap13-combined-join`.

The repair needs the published bounds, authenticated acknowledgement age,
and bounded ownership of replay bytes during reconstruction and delivery.
Raising the row constant alone would leave those obligations unresolved.

A second regression commits the ACK through the actual storage owner. It
starts with 4,097 sealed outbox rows, including 4,096 already acknowledged
rows, and observes only 4,096 after the next committed ACK. The failing run
and exact inputs are in `cap79-durable-retention-red-proof`; it seeds the
previous ACK history instead of executing 4,096 earlier transactions. Its
original runtime test source is preserved in `cap79-pending-runtime-regression`.
The test was temporarily excluded during the separate format and migration
checkpoint; the current adapted regression is back in the compiled suite.

The [generation-4 storage contract](storage-schema-generation-4.md) adds
versioned replay-owner and acknowledgement-range codecs plus an explicit
3-to-4 stopped migration. This lets a later ACK implementation commit a
logical retention cutoff without rewriting an arbitrarily large prefix.
Generation-3 source admission remains pinned to the original delivery codec.
Both earlier migration registries remain unchanged. Eight codec/admission
cases, three real storage migration cases, and three CLI cases pass, including
2-to-3-to-4 migration, legacy restore, mixed-signature preservation, installed
resume, and refusal before output creation. All eight checkpoint gates
pass: 2,463 tests pass, none fail, and 21 qualification tests remain ignored.
The source inventory covers 647 files; the release catalog contains 746
critical regions, with unchanged coverage floors and no new measurement.
The first full suite also passes, but its source-policy check rejects one
constructor's complexity. Splitting suffix validation resolves that failure;
`cap79-schema-four-pre-decomposition-gates.json` preserves the earlier run.
The final logs and exact inputs are in `cap79-schema-four-final-proof`.
The working runtime now writes an ACK as three records: the delivery owner,
replay owner, and one acknowledgement range. Receipt application checks the
prior owner and replay state before publishing the cursor and retention
metadata. Legacy replay metadata comes from complete sealed-storage recovery.
The adapted regression seeds and reconstructs 4,096 legacy ACKs, commits the
next ACK through the storage owner, and preserves all 4,097 physical references.
Their original per-row fields remain unchanged; the journal covers the new ACK.
Composed startup validates all 4,097 bodies and restores their effective ACKs
while keeping 4,096 in the cache. The test passes in 8.08 seconds; its 51 source
inputs, log, and executable are frozen in `cap79-durable-retention-journal-proof`.

Startup uses charged metadata pages and body batches, validates every retained
body, and keeps recovered streams private until their jobs finish. Composed
tests also refuse an absent body outside the cache. Actual sealed-read tests
verify that cancellation and repeated startup retain read reservations until
the matching completion is discarded.

The live ACK adapter now reads an unavailable retention prefix through bounded
sealed metadata pages. Each request keeps the accepted ACK time and exact
source owner, replay inventory, link, and recovery scope. The reader requires
one storage commit and stops at the first retained head. It cannot remove an
open barrier part. Reload waits for the read, and peer traffic stays queued
until the read or subsequent receipt finishes. Cancellation keeps ownership
until the matching result is discarded and cannot fail a replacement link.
Five actual-storage adapter tests cover expiry with paired barrier receipts,
refused writes, cancellation, a commit change between pages, and a persisted
cutoff that discards open barrier proof. The last case exposed a failure after
stream installation in the first integrated reader. The private job now
rejects the cutoff before returning a recovered stream. The separate
4,097-row prefix test crosses cold history in 35 metadata reads without
reloading bodies or publishing an ACK.

The live cache now keeps at most 4,096 acknowledged rows and 16 MiB of complete
event-plus-payload bytes. Eviction releases shared body reservations and keeps
the unacknowledged tail. The bookkeeping regression fails with five 4 MiB
acknowledged payloads before the byte bound is applied; its 61 dirty source
inputs, log, and executable are in `cap79-live-hot-bytes-red-proof`. This test
constructs cache rows and does not claim object-codec or storage validation.
An acknowledged barrier can use the complete validated replay inventory when
its bodies are cold; missing inventory, a different generation, or a cutoff
inside the barrier still fails. Unacknowledged parts remain resident.

All eight runtime checkpoint gates pass: 2,517 tests pass, none fail, and
21 qualification tests remain ignored. The runtime unit suite contains 1,060
passing tests. Source policy covers 816 Rust files; both reviewed inventories
cover 683 files. The release catalog contains 848 critical regions, including
102 additions, with unchanged coverage floors and no new measurement. The
final logs, source inputs, and actual workspace executables are preserved in
`cap79-live-ack-final-proof`.
The next maintenance unit adds idle expiry and physical metadata cleanup.
Its first actual-storage regression fails in 0.19 seconds because offline
history never schedules expiry without another ACK. The exact inputs and
executable are in `cap79-idle-expiry-red-proof`; that test drives idle progress,
while a separate passing case consumes the startup timer from the real timer
heap. After expiry is implemented, a second regression fails in 0.09 seconds:
the committed cutoff leaves two outbox references and one ACK range without
scheduling deletion. Its 15 dirty source inputs and executable are preserved
in `cap79-physical-cleanup-red-proof`.

Startup now arms maintenance for the encrypted profile. Expiry binds the
complete reconstructed delivery owner, accepted time, recovery scope, and
one storage commit. It publishes a new retention floor only on the exact
receipt and preserves the ACK cursor. Unknown acknowledgement age or an
untrusted current clock prevents age-based removal. An open combined barrier
protects its replay evidence from idle maintenance.

Physical cleanup follows an already persisted floor. Each transaction deletes
at most 128 obsolete outbox references or ACK ranges. It validates metadata
keys, grammar, scope, order, and the captured owner before staging deletes.
An interval overlapping the floor remains intact, as does the unacknowledged
tail. Cleanup can use the committed floor when the current wall clock is
unavailable. It keeps raw and decoding reservations until the matching read
completion and retries refused work from a timer. A charged marker suppresses
repeat scans of a fully cleaned floor; restart resumes from physical storage.

All 14 targeted maintenance tests pass in 0.41 seconds. They cover startup
timers, receipt loss, refused transactions, changed owners and recovery epochs,
mixed storage commits, bad page ordering, truncated empty pages, clock failures,
and open barriers. The 132-row fixture deletes only 128 rows in its first batch,
restarts, removes one more obsolete row, and preserves an overlapping ACK
range, two retained ACK rows, the unacknowledged tail, and an object body whose
reference was removed. This fixture seeds its historical journal; it does not
execute 131 prior ACK transactions.

All eight maintenance checkpoint gates pass: 2,531 tests pass, none fail,
and 21 qualification tests remain ignored. The runtime suite has 1,074 passes.
Source policy covers 829 Rust files; both reviewed inventories cover 696
source files. The release catalog contains 905 critical regions, including
57 additions, with unchanged coverage floors and no new measurement. The
exact staged inputs, logs, and workspace executables are preserved in
`cap79-maintenance-final-proof`.

Retained result delivery now reads response bodies that are absent from
memory. The initial regression commits three signed capability bodies through
the actual storage owner, evicts one memory copy, and fails in 0.08 seconds
when the recent-fragment shortcut cannot continue. Its exact test source,
executable, and log are preserved in `cap79-cold-response-red-proof`. That
initial fixture applies replay metadata through in-memory receipt effects;
the later coordinator fixtures also commit the result and replay records.

Both complete duplicate requests and recently assembled requests can start
the reader. Before issuing storage work, it binds the original result hash,
request tuple, and every response descriptor in order. It reads one exact
object key at a time, including repeated IDs, at one captured storage commit.
A missing body, wrong key, hash, kind, size, or changed metadata refuses the
entire reply before rendering. The coordinator rechecks the authenticated
link, incarnation, recovery epoch, and origin/delivery readiness on completion.
Reload and queued requests wait for the read. Shutdown cancels publication
without running the queued requests, and a replacement link remains untouched.
Raw results, decoding buffers, retained bodies, and rendered output keep
their memory reservations until their owner releases them. A stalled writer
retains the output reservation until its queue drains or drops.

All 14 coordinator and decoder-boundary cases pass in 0.80 seconds. The
coordinator fixtures complete an empty delivery snapshot and origin reset
before replay. They cover both assembler entry paths, missing first/middle/last
disk bodies, malformed read completions, changed commit and replay metadata,
lost synchronization readiness, replacement links, shutdown, refused memory,
queued requests, duplicate response IDs, and stalled output. The tests alter
selected returned records or in-memory metadata for negative cases; they do
not claim a network TLS exchange or corrupt a live database. A separate inner
reader regression reads all three sealed bodies and compares the rendered
reply with the complete in-memory response.

All eight response-reader checkpoint gates pass: 2,549 tests pass, none fail,
and 21 qualification tests remain ignored. The runtime suite has 1,092 passes.
The total includes one nested clock-test process whose output interleaves
with its parent; its result tuple and parent status both report success.
Source policy covers 837 Rust files. Both inventories cover 704 source files,
and the release catalog has 931 critical regions, including 25 additions.
Coverage floors remain unchanged, with no new measurement. Exact inputs,
logs, and workspace executables are preserved in
`cap79-cold-response-final-proof`.

Fresh `FetchObject` requests now read retained bodies absent from memory.
The original regression commits and reads back a valid private Commit object,
evicts its memory copy, then observes an empty fetch. That failure takes
0.20 seconds, with a passing inline fetch before eviction, and is preserved
with its two exact test inputs and executable in
`cap79-fresh-object-red-proof`. The authority fixture uses verified handler
effects; it does not claim a daemon TLS exchange or an MLS client round trip.

The dispatcher distinguishes a completed outcome from a required storage read.
It keeps the original request without staging a result or advancing the origin
sequence. One exact object lookup captures the storage commit, authenticated
link, incarnation, base recovery epoch, and synchronization readiness. Completion
validates the sealed row and requested hash, then repeats request classification,
attachment checks, and current recovery authorization. Only a successful,
complete read with no row becomes an empty result. A read failure never does.
The fetched body stays out of the memory cache. Its reservation covers decoding,
response copies, wrapped writes, pending effects, and rendered output through
the storage receipt and link queue. Ordinary cached requests retain their
existing behavior.

All 16 fresh-fetch and decoder cases pass in 1.50 seconds. Thirteen exercise
the root storage adapter, two check decoded values, and the original regression
checks the inner dispatcher against a real stored body. The root fixture
completes actual delivery synchronization receipts and supplies verified
attachment and log state from the handler fixture. Its empty base projection
supplies no channel membership or MLS leaf proof. Cases cover exact cold replay
after a fresh receipt, confirmed absence, changed attachment and recovery state,
malformed completions, changed commits, wrong read IDs, replacement links,
changed base epochs, shutdown with queued work, refused memory before I/O and
after decoding, rejected writes, and stalled output. Invalid kind/body values
are refused by the storage-value codec before reaching the reader; wrong keys
and hashes are checked after decoding. Negative cases alter returned records
or fixture state, without corrupting a live database.

Both inventories now cover 712 source files, and the release catalog has 951
critical regions, including 20 additions and 41 source rebindings. Coverage
floors remain unchanged, with no new measurement. All eight checkpoint gates
pass: 2,565 tests pass, none fail, and 21 qualification tests remain ignored.
The runtime suite has 1,108 passes. Source policy covers 845 Rust files. Exact
inputs, logs, and workspace executables are in `cap79-fresh-object-final-proof`.
The first checkpoint attempt stopped at Clippy's enum-size check; boxing the
completed dispatch outcome resolves it. Its earlier log remains archived.

Composed startup now reads E2EE metadata before object bodies. It seals the
mailbox item references, then validates every object row while retaining
application, Welcome, and StagedReInit bodies only when a mailbox needs them.
Scoped delivery loads its own event and payload bodies. Historical Commit,
binding, policy, roster, and other control bodies remain available for
authorization reconstruction. Required bodies bind their hash and expected
kind; a missing body or late metadata refuses startup. Retained startup bodies
carry memory reservations into the companion state. The existing unordered
full-collection API still enforces CAP-95's complete 256 MiB bound.

Every ordinary startup table read now owns its raw and decoding reservations
through its exact completion, including shutdown and repeated startup calls.
The reader binds table, key range, row count, ordering, byte bounds, and storage
commit. It releases the completed buffers before reserving the next read.
Live application delivery also stops adding a global payload copy; its stored
object and complete event payloads retain their existing ownership. Mailbox
delivery continues to retain the body it needs.

The startup failure in `cap79-selective-startup-red-proof` verifies an application
envelope, commits it through the storage owner, observes identical authenticated
readback during composed startup, then finds an unnecessary global memory copy.
It fails in 0.08 seconds and passes after selection. Nine startup-actor cases
pass in 0.47 seconds, covering mailbox retention, absent or mismatched required
bodies, late metadata, malformed unselected rows, exact read ownership, shutdown,
retry, and memory refusal. Seven collector cases separately test shared references,
required kinds, existing bodies, and byte ownership. Their small body fixtures
validate outer envelopes, without claiming MLS decryption. The existing 26 startup
cases, including the 4,097-row replay recovery and CAP-95 collector bounds, also
pass with the initial wiring.

The live application effect has a separate failure in
`cap79-live-payload-red-proof`: a valid application grows the global cache by
527 bytes after the handler has assigned its complete payload to delivery.
It fails in 0.06 seconds and passes after removing that effect. This fixture
manually activates the bootstrap lifecycle and applies handler effects; it does
not claim an actual receipt, sequenced event, or network exchange. Its 14 exact
source inputs include the ongoing startup changes.

Both inventories cover 720 source files, and the release catalog has 968
critical regions, including 17 additions and 24 source rebindings. Coverage
floors remain unchanged, with no new measurement. All eight checkpoint gates
pass: 2,582 tests pass, none fail, and 21 qualification tests remain ignored.
The runtime suite has 1,125 passes. Source policy covers 853 Rust files. Exact
inputs, logs, and workspace executables are in `cap79-selective-final-proof`.
These small fixtures do not qualify startup above the former global object-cache
capacity or establish the physical storage ceiling.

Live admission has an additional executed failure in
`cap79-resident-admission-red-proof`. Direct assembly of a valid empty-identity
result succeeds with a zero process memory budget, before any storage submission
or receipt. The one-case regression fails in 0.00 seconds; its two exact test
inputs and executable are archived. The new admission step passes that case.

Assembly now derives the required resident set from its complete object and
mailbox writes. It validates object keys, kinds, shared references, and combined
capacity before staging. Temporary decoding and retained bodies carry separate
memory reservations. Only the successful receipt transfers prepared bodies
into coordinator state, before their dependent metadata effects. Rejected
batches drop the private bodies and reservations. Directory, mailbox, policy,
route, and sequencer effects no longer attempt fallible cache insertion after
acceptance. The handler fixture uses the same admission step before applying
its simulated receipt effects.

Eight admission tests pass, covering shared bodies, cold payloads, required
kinds, malformed keys, combined capacity, and release after partial preparation.
Their row fixtures validate outer envelopes without claiming MLS semantics.
Eighteen related actor and decoder cases pass in 1.26 seconds. Two new actor
cases prove receipt ownership and refusal before storage submission; the latter
models a full resident counter and does not contain 256 MiB of objects. The
stalled-writer assertion now checks both output release and the resident result's
remaining charge, then verifies its release when coordinator state drops.

Both inventories cover 725 source files and the release catalog has 976 critical
regions, including eight additions and 23 source rebindings. Coverage floors
remain unchanged, without a new measurement. All eight checkpoint gates pass:
2,593 tests pass, none fail, and 21 qualification tests remain ignored. The
runtime suite has 1,136 passes. Source policy covers 858 Rust files. Exact
inputs, logs, and workspace executables are in `cap79-resident-final-proof`.

Mailbox ACK retirement has a separate executed failure in
`cap79-mailbox-retirement-red-proof`. An admitted application envelope with an
exact seeded mailbox grant passes the normal attachment and ACK checks. Its
last item disappears, but the payload remains resident. The case fails in
0.14 seconds and passes after retirement. The fixture applies handler effects
and retains logical write rows; it does not claim an actual storage receipt or
MLS decryption. Its two test inputs and executable are archived.

A committed ACK now releases the memory copy of an Application, Welcome, or
StagedReInit body only after its last retained mailbox item is removed. Other
targets and expired-but-unremoved items still protect the body. Binding,
Commit, and other control objects remain resident. The body drops before its
memory reservation. Stored objects remain unchanged, so retained responses
can continue to read them through the charged storage adapter.

Review found an admission-order failure: a full resident counter refuses an
ACK's smaller result before releasing its larger payload. The introduced
integration case fails in 0.00 seconds; eight exact changed source inputs and
the executable are in `cap79-mailbox-retirement-headroom-red-proof`. It uses
small valid outer object rows and a modeled full counter, without claiming a
256 MiB load or complete result semantics. Admission now credits one exact
sole-item deletion when its body kind agrees and no new item references that
body. Old bytes and their charge remain owned until the receipt. Multiple item
deletions receive no credit. Shared references, unrelated deletes, new
references, and control bodies cannot fund a result.

Twelve new tests pass in the 13-case retirement filter, which also includes one
existing history test. They cover the last ACK, shared bodies, discarded
unapplied effects, repeated ACKs, protected binding objects, all three payload
kinds, conservative reference and counter guards, and net capacity across
rejection and publication. Five cases run mailbox handlers; the others test
the row-admission and memory boundaries. Both inventories cover 729 source
files, and the release catalog has 981 critical regions, including five
additions and 19 source rebindings. Coverage floors remain unchanged, without
a new measurement. All eight checkpoint gates pass: 2,605 tests pass, none
fail, and 21 qualification tests remain ignored. The runtime suite has 1,148
passes. Source policy covers 862 Rust files. Exact inputs, logs, and workspace
executables are in `cap79-mailbox-retirement-final-proof`.

The durable-expiry follow-up reproduces three failures at source checkpoint
`23ecb6c34de1e13dd87a3a4ebb60713407b22094`. A valid application envelope and
matching conversation metadata are committed through StateCore and restored by
the composed no-peer coordinator. Its actual idle timer stages no cleanup:
one test fails in 0.08 seconds. `cap79-mailbox-expiry-red-proof` preserves the
exact test inputs, runtime executable, and log. This fixture proves storage,
startup and timer behavior; it does not claim a device membership proof or MLS
decryption.

Two domain tests fail before cleanup: ACK lookup replays a retained result at
its expiry boundary, and consumes an expired item whose delivery grant is
still live. `cap79-mailbox-expiry-admission-red-proof` preserves both tests and
the exact domain executable. An earlier module-path compiler error is not
behavioral evidence. ACK lookup now enforces both retention boundaries before
cleanup. Idle maintenance selects at most 128 Item or ACK metadata rows per
page, including unexpired rows, and reserves memory before capturing the page
or constructing its writes. Expired grants clear the exact Item grant and
Token row; expired items and ACKs are deleted. Sequence high-water rows remain.

Only the matching storage commit and domain revision publish the captured
page. Every changed Item, token index and ACK must still match before any
memory mutation. A rejected write keeps the cursor at the same position, and
a restart begins another safe scan. Unknown or regressed wall time and a
quiescing owner cannot stage expiry. An admitted deletion follows its receipt
even if the wall clock later changes. The existing retention sweep provides a
fallback when timer admission fails; no connected peer or client request is
required.

After publication, the existing last-reference check releases only payload
memory and its reservation. Shared mailbox references and stored object
bodies remain. The selection page is bounded; the inherited last-reference
check still examines retained mailbox references. No new claim about its
worst-case CPU cost is made here.

Nine storage-owner tests and six domain tests pass, including all three
original failures. A 130-item dataset commits its first 128 deletions, loses
the publication callback, restarts with the two remaining items, and preserves
the exclusive sequence floor of 130 after cleanup. Other tests cover exact
sealed readback, grant and ACK expiry, shared bodies, rejected writes, memory
refusal, timer exhaustion, changed captured metadata, and clock and shutdown
boundaries. An initial memory-fixture allocation error and Clippy's oversized
enum diagnostic were corrected without policy waivers.

Both inventories cover 736 source files and the release catalog contains
1,007 critical regions. This is a source review update, without a new coverage
measurement or a lower floor. All eight checkpoint gates pass: 2,620 tests
pass, none fail, and 21 qualification tests remain ignored. The runtime suite
has 1,157 passes and source policy covers 869 Rust files. Exact inputs, logs,
and workspace executables are in `cap79-mailbox-expiry-final-proof`.

The retained-request follow-up reproduces a missing idle cleanup path at
`ad6cf20cdccf7afbbc3299eb146d3a5cbbf34d13`. A validated FetchIdentity request
and encoded empty result are paired with a replay row whose deadline uses the
published 24-hour retention and an explicit durable next-sequence floor of
one. StateCore commits the records, composed startup restores the result and
replay row, and idle maintenance stages no expiry. The test fails in 0.08
seconds; `cap79-request-expiry-red-proof` preserves its exact inputs,
executable and log. This proves sealed storage, startup and idle maintenance,
without claiming an authenticated handler invocation or TLS session. The
first attempt had fixture type errors and is not behavioral evidence.
A second test omits the replay owner and proves startup still warmed the
orphaned result. Both failures are frozen in
`cap79-request-expiry-startup-red-proof` before the production changes.

Idle maintenance now inspects at most 128 replay rows per page. A completed
row is eligible only after its nonzero retained deadline and only when an
independent durable origin sequence floor covers its operation. Pending rows
and rows without that floor remain. Capture validates the complete result
identity and bounded response descriptors. The exact replay metadata and
origin floor must still match when the storage receipt publishes cleanup.
The receipt removes the replay row and releases unreferenced result copies
and their resident backing; the origin floor and stored object bodies remain.
Startup warms a result only while a retained replay row owns it.

Ten storage-owner tests pass. They cover early and lost publication,
determinate refusal and retry, a 130-request partial cleanup followed by
restart, persisted seven-day retention, changed metadata, missing ownership,
clock and memory refusal, quiescing, and exhausted timers. The seven-day case
uses persisted security-retention metadata; it does not invoke a security
mutation handler. Corruption cases that modify in-memory state are reported
as such. Captured metadata and write plans own memory reservations. Existing
reference checks may scan all retained rows; the 128-row limit bounds page
selection and mutation, without establishing a new total CPU bound.

Both reviewed inventories bind 744 source files and the release catalog has
1,027 critical regions. Sixty-seven existing regions were rebound, including
the moved receipt-sequence helper, and twenty regions were added. No coverage
measurement or threshold change is claimed. All eight checkpoint gates pass:
2,630 tests pass, none fail, and 21 qualification tests remain ignored. The
runtime suite has 1,167 passes and source policy covers 877 Rust files.
`cap79-request-expiry-final-proof` preserves exact inputs, logs and executables.

The larger startup corpus now passes on the local x86_64 ext4 filesystem.
It commits 4,097 distinct 65,536-byte application objects through StateCore,
then stops and reopens the actual storage owner. The coordinator reads and
verifies every sealed body against its regenerated bytes and content ID.
One matching mailbox item retains one 65,536-byte payload; all other bodies
remain in storage. The corpus totals 268,500,992 object bytes, above the former
256 MiB global memory limit. Peak additional charged startup memory is
68,276,224 bytes. This counter measures owned runtime reservations, not
process RSS or a production memory envelope. The run passes in 325.49 seconds.
Its private-message envelopes, AAD and visible route fields validate, but the
ciphertext is synthetic and the test does not claim client authentication,
MLS decryption, live traffic capacity or production storage qualification.

`cap79-large-startup-first-proof` freezes the three exact input files and
passing executable on base `eef82aff3ae9760e7a342e7ea5939dc4a5dd3fab`.
The subsequent source review proves only two changes after execution: an
explicit qualification-test selection attribute and removal of a binding to
shutdown's unit result. The test assertions and production code are unchanged.
Run the committed test explicitly with a private `TMPDIR` on the intended
qualification filesystem:

```sh
cargo test -p agenc-ircd-runtime --lib --all-features --locked \
  selective_startup_recovers_more_than_256_mib_from_reopened_storage \
  -- --ignored --nocapture
```

All eight final gates pass with 2,630 workspace passes, no failures and 22
ignored tests. One of those ignored tests is the separately executed capacity
corpus above; the other 21 remain qualification work. The runtime suite has
1,167 passes and one explicit capacity test. Source policy covers 878 Rust
files. Both inventories bind 745 source files, with the existing nine
development and 1,027 release critical regions; no coverage measurement or
threshold changed. Final inputs, logs and scope review are frozen in
`cap79-large-startup-final-proof`.

CAP-79 still needs independent shared-body retention and production capacity
qualification. Cleanup does not delete shared object bodies whose
independent retention requirements remain unresolved. Every surviving body
still counts against the disk ceiling, and the global object collector
continues to refuse capacity loss under CAP-95.

The retained-result memory follow-up proves that startup makes a second
persistent copy outside the object-body charge. Three canonical sealed replay
results occupy another 507 bytes while the isolated budget charges exactly
12,288 bytes for their object owners. The regression fails in 0.09 seconds;
`cap79-result-memory-red-proof` retains five exact inputs, the runtime binary
and log. Live assembly has the same uncharged copy. The repair gives every
stored result its own permit, reserved before copying and retained until the
last replay owner expires. Startup prepares the complete result map before
installing it. This does not change physical shared-body retention.

Six new tests pass in the 1,215-test runtime suite. They cover sealed startup,
refusal after partial result preparation, abandoned assembly, committed
ownership, replacement overlap, vector limits and release on removal or drop.
The existing real-storage fetch test now checks the separate result-copy
charge after its receipt and exact return to the initial budget after output
and coordinator destruction. Temporary replay-read copies retain their
existing independent reservations. Result-store mutation is private except
for explicit corruption access compiled only in tests.

The first runtime run passes 1,207 tests and fails three fixture expectations:
two old reload cases omit backing, and one receipt case counts only the object
copy. Exact inputs and executable are retained in
`cap79-result-memory-fixture-failures-proof`. The reload helper now supplies
backing and the receipt case measures both allocations. All eight final
checks pass with 2,698 workspace tests, no failures and 22 default-ignored tests
in 184.37 seconds; Clippy passes in 6.91 seconds. Source policy covers 901 Rust
files. Both inventories bind 766 source files to
`245662262a4a32d4a7017c7961ebd0b64cd6823c78b8941e8d79f0db66d78f26`.
The release catalog has 1,073 critical regions, including seven newly reviewed
regions; 23 existing bindings follow changed source files. No coverage
measurement or threshold changes. Exact changed inputs, logs and executed
binaries are retained in `cap79-result-memory-final-proof`.

### CAP-80: mailbox reconstruction can replace the current delivery grant

Fixed in the worktree. The original renewed mailbox grant left an older Token
row, and reconstruction
chooses a grant according to token-key order instead of an exact durable Item
owner. The Item codec already has a grant field, but the writer leaves it empty
and startup does not use it. A superseded token can therefore replace the
current grant after restart.

The regression obtains two real attachments and fetches, retains both token
rows, and arranges for the old token key to sort after the new one. The current
grant succeeds against the live state. After reconstructing the exact surviving
rows, the same current grant fails with ObjectNotFound. The phased failure is
recorded in `mailbox-stale-token-phased-red.log`, with exact source and executable
in `cap13-audit-cursor-warm`. It is separate from CAP-78's pagination failures.

The repair must atomically persist the current Item grant, its exact Token,
and deletion of the superseded Token. Startup must verify object, target,
mailbox kind, item sequence, attachment generation, and expiry agreement.
Contradictory retained rows must fail reconstruction rather than selecting
whichever token happens to sort last. The contract is recorded in
`cap80-current-grant-contract.md` in the qualification scratch directory.

The repair writes the exact current grant in the Item and Token rows together
and deletes a superseded token when renewing a grant. Startup requires their
object ID, scope, attachment, and expiry to agree and rejects missing or
contradictory rows. All five grant reconstruction cases pass in
`cap80-grant-scoped-final.log` from `cap70-scoped-fixed-final`; the complete
recovery admission group passes 46 cases. Full repository gates remain open.

Declared restore also accepted kind-eight records with truncated, extended, or
wrong-arm mailbox keys because its classifier checked only the outer prefix.
The classifier now decodes the Item, Token, or Ack arm and validates its exact
key grammar before selection or transformation. Two actual negative tests fail
against the original classifier while the valid-row preservation control passes.
The repair passes all sixteen recovery-classification cases and all 202 storage
unit tests. Exact sources, binaries, and results are in
`mailbox-restore-key-red-proof` and `mailbox-restore-key-fixed-proof`.

### CAP-81: base federation queries bypass shared snapshot limits

Fixed in the worktree. The original coordinator's Queries::first_page
renders and measures the complete reply set before splitting pages and stores
continuations under a private 4,096-cursor ceiling. The renderer explicitly
omits snapshot permits, and neither first_page nor finish_query_decision
performs the configured shared query admission. A per-page wire limit does
not bound the complete retained allocation or combine it with local and
companion query usage.

The repair must share per-session and process query accounting, charge the
retained backing, and release ownership on consumption, expiry, and origin
retirement. A real StateCore regression that combines local or mailbox usage
with a new FQUERY is being added before changing this admission path. The
source and accounting design are recorded in `cap78-query-usage-close-design.md`
in the qualification scratch directory. The real shared-session regression
now fails in 0.07 seconds at FQUERY admission while the equivalent local
reservation is refused. Its exact command and executable are recorded in
`legacy-restore-query-witness-proof/fquery-exact-red.log` and the proof manifest.

The shared admission repair now reserves backing before full rendering and
keeps one query lease through page delivery, continuation retention, and the
request's durable receipt. Exact expiry and stale-receipt checks release only
the matching owner. Empty B-tree roots retain their backing reservation until
destruction, and continuation checks borrow the request arm. Seven admission
and two receipt tests pass, along with all 152 domain tests, in
`cap74-cap81-cap82-fixed-proof`. Full workspace and release qualification
remain open.

### CAP-82: snapshot hashing cannot reach the advertised entry ceiling

Fixed in the worktree. A federation snapshot permits 1,000,000 ordered
route object IDs. Its version-one digest input has 20 fixed bytes and 32 bytes
per ID, making the maximum canonical input 32,000,020 bytes. The generic
semantic digest helper refuses inputs over 16,777,215 bytes, so a cut with
524,288 entries already fails despite remaining within the published entry
and payload limits.

The repair needs a dedicated streaming adapter over the existing cryptographic
implementation, preserving the exact domain and canonical framing. It must
validate the declared count and order, prove equivalence to existing digests,
and exercise the actual million-entry boundary. Raising the generic input
ceiling does not provide that bounded ownership. The precise source map is
recorded in `cap82-snapshot-digest-limit.md` in the qualification scratch
directory.

An actual one-million-ID regression fails with LimitExceeded against the old
helper in 0.06 seconds. The fixed E2EE path frames both generations and the
exact vector length, then streams the ordered IDs through a dedicated bounded
crypto adapter. The generic semantic hash limit remains unchanged. The adapter
requires exactly the declared byte count and permits at most 32,000,020 bytes.
All 120 E2EE and thirty crypto unit tests pass, including the maximum input,
old digest equivalence, supplied order, chunk boundaries, short and extra input,
and refusal of an excessive declared count before consuming the iterator.
Exact held source inputs and executables are in `cap82-e2ee-red-proof` and
`cap82-hash-fixed-proof`.

Runtime capture now streams the same digest from its charged million-entry
cut with no additional canonical buffer. Reverting only that runtime adapter
produces a real memory-ceiling failure while the empty version-one control
passes. The restored capture suite passes all three cases. A stateful digest
adapter also supports bounded asynchronous page verification, preserving exact
declared count and framing across page boundaries. All 121 E2EE tests pass in
`cap74-cap81-cap82-fixed-proof`; the runtime reversal is archived in
`cap74-cap82-reversal-proof`. Pending snapshot restart and delivery ownership
remain separate open work under CAP-70 and CAP-71.

### CAP-83: ReInit votes use the ordinary disposition signature domain

Fixed in the worktree. The original `QuorumLedger::record_reinit` passed
its canonical bytes through `record_encoded`, which selects
`SignatureDomain::DispositionVote`. The companion profile requires the
distinct `ReinitDisposition` domain for this operation. The runtime fixture
also signs with the ordinary domain, so its positive ReInit tests do not
exercise the required separation.

The repair needs a correctly signed ReInit quorum acceptance test and an
ordinary-domain refusal test that also proves refusal consumes no vote slot.
Ordinary disposition voting must retain its own exact domain and behavior.
The earlier CAP-76 sealed successor fixture used histories accepted by this
implementation under its wrong-domain behavior. CAP-76 must also be proved
with the corrected, profile-valid signatures before closure. No behavioral
result or production repair was available at the initial finding.

Both exact-domain regressions now fail against the old verifier: a correctly
signed ReInit vote is refused, while an ordinary-domain vote is accepted. The
ordinary disposition control passes. The repair passes the registered domain
explicitly into the private shared verifier and updates the runtime ReInit
fixture accordingly. All 123 E2EE tests pass. The held-source fixed proof differs
from the failing proof only in `finality.rs`; both are archived under
`cap83-quorum-domain-second-red-proof` and `cap83-quorum-domain-fixed-proof`.
The three sealed successor recovery tests also pass with these corrected
signatures in `mixed-audit-rotation-startup-fourth-proof`.

### CAP-84: queued companion pages release their memory charge before transmission

Fixed in the worktree. The original snapshot FETCH and first-page publication
produce a charged `SnapshotPageOutput`. The base companion adapter drains its
lines through `LinkHandle::try_send`, which increments the queue byte counter
but stores no memory reservation in the queued `LinkOutbound`. The page owner
then drops while accepted strings can remain in a stalled writer queue. The
queue has no separate process memory permit covering those strings.

The correction must transfer shared page backing into each accepted queued
frame and retain it through the awaited writer or cancellation. Refused frames
must drop before their owner. The existing reserved ACK path already provides
the queued reservation and the close/publication latch; the page adapter must
preserve those contracts. A real stalled-queue regression is being added to
prove that queued bytes and the process memory charge remain owned until the
receiver or writer releases them. This finding is limited to the new page
path. The actual stalled-queue test now fails after publication with queued
strings still present and a zero memory charge instead of the required 20,480
bytes. Its replacement-link control passes. The 0.12-second behavioral red,
all 240 held source inputs, and executable are archived in
`cap84-queued-page-red-and-stale-start-proof`. The shared backing transfer now
passes the stalled queue and replacement-link tests, three partial admission
and queue closure tests, and three actual awaited writer completion, failure,
and cancellation tests. Two sealed startup-read cancellation tests also pass.
The fixed workspace build held all 244 changed inputs; these ten focused
checks are archived in `queued-backing-invitation-checkpoint`. Full repository
gates and release capacity qualification remain pending.

### CAP-85: storage restart rejects the invitation tombstone its account writer emits

Fixed in the worktree. Successful account creation
stores a kind-two RegistrationInvite tombstone referencing its Account.
Runtime reconstruction requires that exact Account reference. Storage startup
instead rejects every kind-two invitation with any reference, so the canonical
writer and both reconstruction layers disagree. Removing the reference would
make the row invalid for the runtime and would not repair the contract.

Four isolated real-storage restart cases now reproduce both sides of the
mismatch: the canonical Account reference is rejected, and a missing Account
reference is accepted. Extra ownership and wrong-target controls refuse as
required. Test-only phase context localizes the stale START failure to the
same seeded storage reconstruction. The 0.31-second isolated proof and exact
held sources are archived in `queued-backing-invitation-checkpoint`. The
validator now requires exact single-Account ownership and preserves generic
target existence checks and the separate Account, Session, and
invitation-reservation rules. All four fixed restart cases and the complete
stale START cleanup and rotation case pass in `invitation-owner-fixed-proof`.

### CAP-86: a ReInit attempt checks attachment without checking old-group membership

The outside-account admission defect is fixed in the worktree. The attempt,
activation, and abort handlers previously required only a directory-active
attachment before reaching the signer. Possession of a valid public attempt
and quorum evidence therefore let a different attached account submit all
three operations.

Three regressions reproduce successful admission by that outside account,
using the same payload as an accepted in-group control. The attempt approval
uses the registered ReinitAttemptAuthorization domain. All three fail
behaviorally in `resumed-reinit-admission-red.log`. Each handler now requires
the account to be a principal of the retained old binding before accessing
the signer. The regressions pass with the signer present and absent, preserve
all retained conversation, log, and object state on refusal, and stage no
storage writes. All thirteen ReInit tests pass in
`resumed-reinit-admission-green.log`.

This is the server's retained-binding account check. It does not establish
that a particular attached device is an old MLS leaf, that an activation
submitter continues into the new group, or that a ReInit ACK matches that
leaf's signer. Those operation-matrix obligations remain open and require a
validated device-to-leaf admission contract; account membership alone does
not prove them.

### CAP-87: reconnect drops a closed origin while its journal write is unsettled

The diagnostic campaign on checkpoint `52808b9` fails pressure recovery before
reaching the coordinator restart. Its edge repeatedly closes the link from
`journal::attempt_write` with `Violation::Phase` during origin synchronization.
The preserved trace and unchanged binary hashes are in
`resumed-restart-diagnostic/campaign-result.json` and its campaign logs.
This identifies a separate recovery failure; it does not establish the cause
of the earlier post-restart failure.

`replay_origin` removed a deleted origin whose declaration had never been
transmitted and which owned no request. Its pending or refused journal write
still referred to that origin. Subsequent staging could not encode the missing
owner, so reconnecting repeated the same failure.

Two real-storage regressions fail against the checkpoint with the first write
pending and refused, respectively. The fix retains every deleted origin until
its deletion acknowledgement commits. The coordinator already acknowledges
deletion of an unknown origin. The tests verify no deletion is transmitted
before its tombstone commits, no retirement occurs before the acknowledgement
commits, unacknowledged deletion survives storage reconstruction, acknowledged
deletion retires on reconstruction, and a fresh origin still commits afterward.
All 100 edge tests pass. An existing outage test now acknowledges both the
registered origin and the never-transmitted origin before checking that another
reset has nothing to replay. The failure and passing logs are `cap87-red.log`
and `cap87-edge-green.log`; temporary diagnostic changes have been removed.

All required repository gates pass for this fix: 2,402 workspace tests pass,
zero fail, and 21 qualification tests remain ignored. Both reviewed inventories
bind 618 source files; the release policy retains 656 critical regions and its
existing floors. Exact commands and results are in `cap87-final-gates.json`.
The uninstrumented 64-client release repeat passes pressure recovery on the
first retry but still fails coordinator-restart synchronization, ending after
237.93 seconds. `cap87-capacity-64-result.json` binds the unchanged daemon and
test executable. This closes the reproduced premature-retirement defect only;
the separate restart loop and capacity qualification remain open.

### CAP-88: membership revision changes are omitted from durable projection rows

The restart loop is localized to a replayed `MessageDelivered` event on edge B.
The event passes header and sequence validation, then the replica rejects its
target channel revision. The exact event trace in `cap87-event-diagnostic`
repeats that refusal at sequence 4029 while the durable cursor remains 4028.
The final diagnostic campaign fails after 236.50 seconds with unchanged
executables. The private fixture copies in both `captured` and
`captured-stopped` are invalid live copies, as corrected under CAP-92.
The event trace and controlled real-storage regressions remain the evidence
for this repair.

The domain replica advances channel and home-session revisions during JOIN,
PART, KICK, and related events, but its returned row changes omit several of
those revisions. Runtime storage writes only the returned rows. A restart can
therefore reload an older channel revision while retaining the committed
delivery cursor and membership. The next valid channel message then fails the
revision check on every replay.

Four real-storage regressions fail against `1482e84`. Both single-event and
batched JOIN receipts reload home-session revision 10 instead of 13, and both
paths reject the next valid channel message with `Consistency`. The corrected
revision helpers report their changed rows through the existing event outcome;
the dispatcher removes superseded upserts and duplicates. All four regressions
pass. The independent domain reconstruction check covers twelve event cases;
reverting only the fix identifies nine cases with omitted writes, while the
three control cases retain complete row changes. Its exact reversal log is
`cap88-domain-red.log`. The runtime failure and passing logs are `cap88-red.log`
and `cap88-green.log`; temporary diagnostics are restored to their production
originals.

All required gates pass with 2,407 workspace tests, zero failures, and 21 ignored
qualification tests across 120 results. Source policy accepts 751 Rust files;
both inventories bind 620 source files and the release policy includes 659
critical regions. Exact commands and results are in `cap88-final-gates.json`.
The uninstrumented capacity repeat still fails the restart readiness check
after 250.87 seconds, despite passing first-attempt pressure recovery, backup,
and peer return. `cap88-capacity-64-result.json` records unchanged executables.
The omitted-row defect is repaired; another cause of the remaining restart
failure has not yet been established. Capacity qualification remains open.

### CAP-89: completion replay rejects a durably retired request

Durable origin deletion abandons requests without a result once their client
sink is gone. An older `RequestCompleted` event can still remain in the
coordinator outbox. The edge's completion validator unconditionally requires
the request when checking retained JOIN echoes, so replay fails after the
origin and request have already been retired. The combined barrier writer
also unconditionally attempts to persist request coverage for that absent
owner. Sections 20.6 through 20.8 require ordered durable replay; origin
retirement does not remove the event from the stream.

Three real-storage regressions fail against `e0a7008`: ordinary replay after
durable DEL acknowledgement, replay in an ordinary batch, and application of
a restored combined barrier with an absent request. The fix retains generation
and conflicting-owner checks, then treats an absent request as having no
completion consumer. Its stream cursor or combined barrier receipt still
commits before acknowledgement. No request owner, completion marker, or client
reply is recreated. Existing owners retain the exact result, correlation, and
JOIN-echo checks. All three regressions and the additional negative control
pass; `cap89-red.log` and `cap89-green.log` record the runs.

All required gates pass with 2,411 workspace tests, zero failures, and 21
ignored qualification tests. The focused run passes all 120 edge tests.
Both source inventories bind 622 files; the release policy now includes 660
critical regions. `cap89-final-gates.json` records the exact commands and
results. The production changes are limited to completion ownership and the
combined barrier's request-coverage selection.

This defect was found while investigating the remaining capacity failure.
The preceding diagnostic run in `cap88-restart-diagnostic` passed pressure
recovery and backup, returned edge B, then failed SASL authentication after
207.93 seconds. Its trace includes coordinator companion-protocol refusals;
the cause of that authentication failure remains under investigation. The
run records unchanged binaries and daemon logs. Its private database copies
are invalid live captures under CAP-92. The completion repair alone does not
establish capacity qualification.

### CAP-90: cached companion declarations bypass current origin admission

The diagnostic trace in `cap89-admission-diagnostic` first rejects an EORIGIN
declaration because its base origin is unavailable. Fragment assembly has
already cached that object as complete. Each retry then takes the duplicate
path, which cannot find a matching accepted companion origin and rejects it
again. A previously accepted cached declaration has the opposite problem:
the duplicate path can resume it without checking whether its base origin
remains live at the same generation. Both behaviors violate the current
base-origin mirroring required by companion Section 12.5.

Five frame-entry regressions fail against `3a58e09`. Three valid retries remain
stuck after RESET, base-origin availability, or base-generation advancement.
Two cached declarations incorrectly resume when the base origin is absent or
has advanced. Admission now checks RESET, live base authority, and the exact
base generation before assembly or duplicate-cache handling. Object decoding,
mirrored principal and device validation, predecessor checking, and the bounded
duplicate cache retain their existing rules. All five regressions and all 155
focused coordinator tests pass; `cap90-red.log` and `cap90-green.log` record the
results. Temporary diagnostics have been restored to their production originals.

All required gates pass with 2,416 workspace tests, zero failures, and 21
ignored qualification tests. Both source inventories bind 623 files, and the
release policy contains 661 critical regions. Exact commands and results are
recorded in `cap90-final-gates.json`.

The preceding five-minute diagnostic campaign passes with 64 clients after
306.37 seconds, including coordinator restart, live login, rekey, and final
draining. Its companion refusals expose this additional defect despite the
passing campaign result. `campaign-result.json` records unchanged executables;
its claimed stopped-state copies are invalid under CAP-92. The recorded
event-admission refusal is `Quiescing` during an intentional daemon stop, so
that trace does not prove the separate hypothesis about a staged batch conflict.
The uninstrumented repeat passes at exact source commit
`b735700ada3a65fa3dc4a2016d81a59defe408ca` in 305.96 seconds. Its
64-client workload runs for 300.48 seconds, completes all eight scenarios,
records no missed events, envelope violations, population shortfalls, or
sample failures, and stops all three daemons cleanly. There are 31 worker
errors during the disruption scenarios. The scenario named index transition
still tests reconstruction in this run. `cap90-production-repeat` preserves
the unchanged daemon and test executable hashes and full campaign logs. Its
claimed stopped-state copies are invalid under CAP-92. This result covers
that exact source; later changes need their own campaign.

### CAP-91: incoming events collide with an unsubmitted checkpoint

The edge event entry path tests only whether a storage batch is in flight.
A different owner can already hold a gathering or exclusive checkpoint that
has not been submitted. The event then attempts an incompatible checkpoint,
receives Busy, and reports a Ceiling violation for valid federation traffic.

Two real-storage regressions reproduce the defect with ordinary gathering and
exclusive checkpoints. Both fail at event admission in `cap91-red.log`. The
entry path now uses the same complete checkpoint-readiness predicate as its
queue drain. The bounded queue holds the event until the other owner's
receipt. Only the event's own subsequent receipt advances its cursor, emits
its client message, and sends its exact acknowledgement. The tests verify
both commit sequences, no early publication, and an active link throughout.
All 122 edge tests pass in `cap91-green.log`.

This defect is established by those two controlled regressions. The earlier
capacity trace's Quiescing result during shutdown is a different condition.

All required gates pass with 2,418 workspace tests, zero failures, and 21
ignored qualification tests across 120 results. Source policy accepts 756
Rust files. Both reviewed inventories bind 624 source files; the release
policy contains 661 critical regions with unchanged coverage floors. Exact
commands and logs are recorded in `cap91-final-gates.json`.

The first full gate attempt fails the native storage workload at an unstable
free-space boundary. Its exact log is retained in `cap91-first-gates` and
`cap91-filesystem-boundary-failure.log`. The unchanged isolated test then
passes, followed by the complete gate run. Its measured allocation remains
above the qualification ceiling under STO-1; the passing test proves correct
measurement and refusal to sign that result, not acceptable storage growth.

### CAP-92: the scratch capture helper mistakes unreadable processes for exited daemons

The external `capture-next-stopped.py` helper ignores PermissionError while
reading `/proc/<pid>/exe`. The daemon disables dumpability. An empty list from
that scan therefore does not establish that all daemons have exited.

All six supposed stopped captures occur near peer return, about 120 to 122
seconds into their campaigns, before later live operations and final shutdown.
The affected archives are `cap87-event-diagnostic`, `cap88-restart-diagnostic`,
`cap89-admission-diagnostic`, `cap90-production-repeat`,
`cap91-production-rotation`, and `cap91-rotation-final`. Each now has an
`INVALID-LIVE-COPY.txt` notice and a `capture-stopped.invalid.json` withdrawal
bound to the original manifest hash. The original records remain available
for audit. None of these copied databases is valid crash-recovery evidence.

The helper is retired and refuses to run. A future capture must be performed
by the owning test after it has waited for every daemon to exit and before
fixture cleanup. Campaign exit codes, unchanged executable hashes, metrics,
daemon logs, and the controlled storage-owner regression tests remain usable.
This correction changes evidence claims, with no runtime change.

### CAP-93: replay and overflow bypass an unfinished combined barrier

The combined-barrier review found three paths that did not apply the existing
per-target gate. A base resend checked the barrier endpoint before requesting
a page, but the page's upper bound could extend past that endpoint. It then
published every returned row. Companion resume replay rendered every
unacknowledged row without checking the outer gate. Outbox overflow refused
snapshot fallback only when the current mutation itself opened a barrier;
a later ordinary mutation could request replacement of an earlier open gate.

Base Section 20.8 requires later events on both profiles to wait for both
final acknowledgements. The repair clips base read pages to the held endpoint,
keeps a companion replay hold until both ACK receipts complete, and includes
the existing gate in the projector's outbox budget. Overflow under that gate
refuses the new mutation without writing a snapshot fence.

The real-storage replay test retains two barrier parts and a later ordinary
row on each profile. Both initial replays publish only the barrier parts.
The first ACK and the second storage commit publish no later events; handling
the second receipt releases exactly the later row on each stream. Removing
only the base page bound reproduces one failure in `cap70-red-base-page`.
Removing only the companion hold reproduces one failure in
`cap70-red-companion-replay`. The outbox planning test independently proves
that the former overflow behavior writes a snapshot fence, in
`cap70-red-outbox-overflow-behavior`. Each directory retains the exact reversed
source, executable, hashes, and test log. All fixed source is restored.

The first overflow reversal in `cap70-red-outbox-overflow` failed to compile
because it left the new gate field unused. No regression ran in that attempt;
its copied executable belonged to the preceding replay test. Its proof is
marked invalid and accompanied by `INVALID-BUILD-FAILURE.txt`. Only the later
behavioral reversal counts as evidence. These tests qualify the repair's
component behavior, not release capacity or cryptographic review.

The final checkpoint passes formatting, all-target/all-feature workspace
Clippy, 2,433 workspace tests with no failures and 21 ignored qualification
tests, source policy and its self-test, workspace policy, and coverage-checker
self-tests. `cap70-final-gates.json` records the commands and results. Both
source inventories bind 632 Rust files at
`140416a123ebcdefec70d2362dab74ccb3921c946c6f9fdac97330395df88da5`.
The release policy now includes 688 critical regions, including 27 additional
barrier construction, recovery, and receipt regions. Coverage floors remain
unchanged; this binding is not a new branch-coverage measurement.

An earlier gate passed the same 2,433 tests but failed source policy because
the new overflow test was outside a `tests/` directory. That run remains in
`cap70-first-gates`. The test now resides in `outbox/tests/mod.rs` and the full
final gate passes. The later event-record boxing and barrier-key admission
changes also passed complete gates before the final checkpoint. Exact source
inputs, the final runtime test executable, and hashes are retained in
`cap70-final-proof`.

### CAP-94: final barrier resume rejects a lost ordinary acknowledgement prefix

The coordinator rejects an exact final companion resume when acknowledgements
for ordinary events before that barrier were also lost. Both the staging
validator and the receipt application require the next expected sequence to
have reached the barrier's first part. A valid reconnect therefore fails even
when the coordinator retains every ordinary and barrier row in order.

The real-storage regression first commits ordinary companion sequences 0 and 1,
then a combined mutation with companion parts 2 and 3. It commits the base ACK
and reconstructs the coordinator from sealed storage. Companion ERESUME at the
exact final sequence and event ID fails against checkpoint `4d2f230` with
`Companion(Request)`. `cap94-red-proof` retains that behavioral failure, the
actual executed test binary, source inputs, and hashes.

The repair gives final barrier resume a separate coverage validator. It checks
every retained unacknowledged row from the durable cursor through the exact
barrier endpoint, then commits those acknowledgements with the gate update.
The receipt repeats coverage validation before publishing the cursor. Ordinary
EACK continues to require the next ordinary event or the current barrier end.
No new wire or persistent record format is introduced.

The full coordinator test confirms that neither staging nor the storage commit
alone sends ERESUME OK. After the receipt, the gate is deleted; another restart
recovers cursor 3 and next sequence 4 with all four rows acknowledged. Refusal
cases cover an inconsistent in-memory prefix, a partial endpoint, a wrong event
ID, a wrong delivery generation, and an ordinary EACK that skips the prefix.
The inconsistent-prefix case injects an in-memory defect after valid startup;
it does not claim that the startup loader accepted a missing durable row.

The final checkpoint passes formatting, all-target/all-feature workspace
Clippy, 2,436 workspace tests with no failures and 21 ignored qualification
tests, source policy and its self-test, workspace policy, and coverage-checker
self-tests. Both inventories bind 633 source files at
`64ec554fa8e8aedf638f80c61c4e2eebf1b7f63b36f8a5c9c156dbb53b297549`.
The release policy binds 691 critical regions with unchanged floors. This is
source review and test evidence, not a new branch-coverage measurement.
`cap94-final-proof` retains the exact inputs, workspace runtime executable,
command logs, and hashes.

## Release claims and limits

The signing command requires an explicit Ed25519 signing key and matching
public key. No signing key is bundled in the daemon. The decision is separate
from the tested binaries, so recording qualification does not rebuild them.
It binds the candidate and all accepted attempt records. Nothing is uploaded
or published by the qualification commands.

Verify a completed decision with a separately trusted public key:

```sh
python3 scripts/qualify-release.py verify --candidate /path/to/candidate \
  --public-key /path/to/trusted-release-public.pem
```

The verifier checks the signature, candidate artifacts, the decision's target
scope, native attempt records, decision chronology, and the external review
when the decision claims the encrypted profile. It does not trust the public
key bundled beside a signature. The daemon's own `conformance --json
--release-decision` inspection applies the same key rule to a deployed binary.

An `encrypted-v1` decision also requires the completed external cryptographic
and protocol review recorded by `S08-039`, including remediation verification.
That review remains open. Internal tests and implementation review do not
replace it. Review records must describe work that was performed.

The server observes routing, membership, timing, sizes, and other metadata
described in the specifications. First-contact encryption does not
authenticate an identity out of band. Transparency observation does not
grant Verified status. A compromised client can read its plaintext, and
authorized recipients can disclose messages. Tor testing cannot establish
protection against every traffic-analysis adversary.

### CAP-95: startup reports success after dropping retained object bodies

The CAP-79 retention review found that companion startup collects all object
bodies, then ignores refusals from the 256 MiB object cache. A direct startup
regression supplies 65 distinct, valid storage object envelopes of 4 MiB each.
Startup reports success with an incomplete cache. The control with two smaller
objects passes. The behavioral red has one failure and one pass in 9.55 seconds;
its source, log, and actual executable are frozen in
`cap95-startup-object-red-proof`. This exercises the startup API and storage
envelope codecs; it is not a stopped-daemon database capture. Earlier test
compilation failures are not behavioral evidence.

The repair validates each object against its exact storage key, bounds collected
object body bytes before dependency reconstruction, and retains a failed
collection state after any refusal. It releases the collected bodies on failure.
Before publishing any objects, reconstruction checks the combined capacity of
existing and restored objects. Duplicate objects count once, and the bodies
move into the object map without another complete copy. The 256 MiB limit is
unchanged. This byte bound does not claim to measure allocator overhead or
provide charged asynchronous replay reads. CAP-79's disk-backed retention and
paged reconstruction work remain open.

The checkpoint passes formatting, all-target/all-feature workspace Clippy with
warnings denied, the complete all-feature workspace suite (2,448 passed, zero
failed, 21 ignored, 120 result groups), source policy and its self-test,
workspace policy, coverage-policy self-test, and diff checks. All 1,003 runtime
tests pass, including the five object startup cases. The source inventory now
contains 638 files with SHA-256
`179a6042ca1cf0fd1e3fcf7962dfb6a20d0126d22e88bad5a399b9cd592d2340`.
Three new release critical regions bind object collection and publication.
Both policies validate with their existing floors; this is not a coverage
measurement or Stage 10 qualification. Final logs and exact inputs are frozen
in `cap95-startup-final-proof`.

### CAP-96: duplicate requests can replay an incomplete response set

The CAP-79 object-read review found that request classification uses
`filter_map` to gather retained response bodies. When a body is missing from
the object cache, the result remains unchanged while the returned response
list becomes shorter. The sender would assign new consecutive indices to the
surviving objects, contradicting the original result descriptors.

The regression builds a three-object capability page with signed objects
through the production result assembler and applies its receipt effects. A
complete replay preserves the exact bytes and order. After removal of the
first response body, classification still accepts the replay. The behavioral
red has one failure and one passing control in 0.01 seconds, frozen with exact
source and executable in `cap96-response-red-proof`. This test uses in-memory
receipt effects, not a real storage commit. The earlier module compilation
failure and invalid singleton-result fixture are excluded from that evidence.

Classification now refuses the complete replay if any required response is
missing. It constructs the response list privately and returns it only when
every lookup succeeds. Empty results remain replayable. Tests remove the
first, middle, and final response separately and preserve a complete-response
control. This prevents incomplete publication while CAP-79's charged disk-read
path remains open; it does not supply missing bodies from storage.

All eight checkpoint gates pass: formatting, all-target/all-feature workspace
Clippy with warnings denied, all-feature workspace tests (2,451 passed, zero
failed, 21 ignored, 120 result groups), source policy and its self-test,
workspace policy, coverage-policy self-test, and diff checks. The runtime
suite passes all 1,006 tests. Both critical-coverage policies validate with
unchanged floors, and the release inventory adds the replay classification
decision. The source inventory has 639 files with SHA-256
`9eb1467863bea8d1cf2e1dd69ee9423875505056990faa5472f82d6c10c0df69`.
Exact inputs, the actual workspace test executable, and passing logs are
frozen in `cap96-response-final-proof`. This is a development checkpoint, not
a coverage measurement or Stage 10 qualification.

### CAP-97: recent-fragment replay bypasses response completeness

The follow-up object-read review found another response lookup in
`CompanionCoordinator::replay_recent`. When the assembler reports a request
object as recently completed, this shortcut renders the retained result
without passing through the classification repaired under CAP-96. It still
skips missing response bodies and assigns new indices to the survivors.

The regression uses the same three signed capability objects and production
result assembly as CAP-96, then calls the shortcut directly. Removing the
first response still returns output. A passing control parses the rendered
responses and verifies all three original indices and object IDs. The run
reports one failure and one pass in 0.00 seconds. Exact inputs and executable
are in `cap97-recent-fragment-red-proof`. This test applies in-memory receipt
effects; it does not claim a storage commit or exercise fragment-cache timing.

The shortcut now requires the complete response set before rendering any
lines. Tests remove the first, middle, and final response separately, verify
a complete response set, and preserve results with no response objects.
All three targeted cases pass in 0.01 seconds. All eight checkpoint gates
pass with 2,534 tests, no failures, and 21 ignored qualification tests. The
runtime suite has 1,077 passes. Both inventories cover 696 source files,
and the release catalog contains 906 critical regions with unchanged floors
and no new coverage measurement. Exact inputs, workspace executables, and
passing logs are in `cap97-final-proof`. Charged reads for bodies absent
from memory remain part of CAP-79.

### CAP-98 Close admission does not validate controller authority or closing intent

Source review finds that CloseGroup checks the attached sender, current binding
and presence of an authorizing proof identifier. The close-ID helper validates
structural fields and approval ordering, without verifying signatures. The
handler does not require the retained finalization to authorize the exact
active-to-closing intent. Companion Sections 9.3 and 11.5 require that intent
binding and approvals meeting the last finalized policy's controller rule.

The first fixture attempt failed before handler execution because its typed
approval vector was empty. The corrected run has two passing controls and
four behavioral failures in 0.09 seconds, frozen with its exact inputs and
executable in `cap98-close-authority-red-proof`. The authorized-close control
publishes and activates the operational policy, then finalizes a closing
transition with real controller signatures, receipt bindings and council
votes. Separate cases corrupt a close signature, use a correctly signed approval
from an unrelated root, substitute an ordinary finalization, or change the
close intent while signing the new close request correctly. All four are
wrongly accepted. The existing codec rejects the empty-approval control. Ciphertext and MLS leaf acknowledgements remain
synthetic; these are server public-authorization checks, without claiming
endpoint MLS validation or a storage transaction.

The handler now binds the request reason, network, conversation and binding to
the current accepted terminal. Its retained finalization must carry the exact
closing action and intent, current policy and epoch, and matching public
core and authorization hashes. The E2EE validator checks controller authority,
certificate identity, registered signature labels, threshold and distinct roots
and public keys. Proof decoding and roster copies hold a bounded temporary
memory reservation; refusal returns E2EE_RATE_LIMITED without close effects.

All eleven handler cases and five public-validator cases pass. They include
reconstruction before close, preservation of the tombstone after another
reconstruction, correctly signed context substitutions, missing or changed
proof ownership, memory refusal, controller thresholds, duplicate roots or
keys, certificate changes and signature-label changes. The alternate-roster
key-count test calls the validator directly and does not claim a runtime
roster-chain transition.

The first full workspace run found two daemon fixtures that closed under a
bootstrap or member-add finalization. Both now refuse those requests, sequence
a separate closing candidate with controller signatures and both council
votes, refuse a close signature made under the wrong label, and then accept
the authorized close. The two daemon tests pass in 23.82 seconds. Their closing
candidate and leaf acknowledgements remain synthetic, including after the
real openmls and mls-rs application exchange. These checks prove public close
admission over TLS; they do not prove endpoint validation of a committed MLS
closing lifecycle. The first fixture revision also exposed a regressing test
validation timestamp; the corrected candidate preserves the validation floor,
and certification reads its time from the candidate AAD.

All eight checkpoint gates pass: formatting, all-target all-feature Clippy,
the locked all-feature workspace tests, source policy and its self-test,
workspace policy, the coverage-policy self-test and diff checks. The workspace
run passes 2,669 tests with no failures and 22 default-ignored tests in 164.03
seconds; the runtime suite passes 1,201 tests with one ignored capacity test.
Both coverage inventories cover 756 source files with hash
`152d1173e974d1437df636a7e618648478045923d3a6437f0e290bc3e0e146ed`.
The release catalog has 1,044 regions, including seven reviewed close-authority
regions. This checkpoint adds no coverage measurement and changes no threshold.
Exact inputs, check logs and five executed binaries are retained in
`cap98-close-authority-final-proof`. Full recovery-chain validation and Stage 10
production qualification remain open.


### CAP-99 ACKs accept inconsistent public context

Commit and ReInit ACK handlers accepted substituted profile, network and epoch
fields. ReInit also accepted a different successor, staged result or creator.
Finalization and activation accepted inconsistent embedded ACKs after their
set digests and council votes were recomputed. Against source commit
`883260b0bdcfa9eaa8514b7ac0a4a1d3008473e1`, all 37 regression cases fail in
0.15 seconds. Each case first accepts its normal control. The exact five
inputs and executed runtime binary are retained in
`cap99-ack-context-expanded-red-proof`; the earlier six-case failure remains
in `cap99-ack-context-red-proof`.

Standalone Commit ACKs now match the current candidate's profile, network,
conversation and adjacent epochs. Finalization compares every embedded ACK's
public identity and result fields with the finalization core. Standalone
Commit result digests have no independently authenticated reference until a
terminal request supplies its voted result; an arbitrary first submitted ACK
does not establish that reference.

ReInit ACKs now name the exact retained attempt receipt and object. The checks
cover the old and new conversations, old state, attempt, all four result
fields, creator identity fields, and the role's KeyPackageRef shape. A Welcome
ACK must name a non-creator plan entry's reserved ref. Both standalone and
embedded ACKs use the same public comparison. Retained-object reads reserve
memory before decoding and keep that reservation through validation. The
maximum 3,145,728-byte initial Commit succeeds with enough memory; three
smaller budgets refuse without writes or retained temporary reservations.
Missing retained attempts and invalid package references also fail closed.

These fixtures sign changed ACK fields with a deterministic key and sign
terminal votes under the fixture council. They do not prove that the ACK key
belongs to an authenticated old MLS leaf. Creator and Welcome fixtures use
synthetic MLS bodies. Old-to-new leaf identity, coverage, and continuing-member
vote admission remain open under CAP-86. No wire or storage format changes.

All eight checkpoint checks pass. The locked all-feature workspace run passes
2,739 tests with no failures and 22 default-ignored tests across 120 result
groups in 178.18 seconds. The runtime suite passes 1,256 tests, including 41
new ACK cases, with one ignored capacity test. Both inventories cover 769
source files with hash
`8140f666dc04531ccd721ec8842bc717ee65e818664815d24c60779a723242dc`.
The release catalog has 1,083 critical regions, including ten reviewed ACK
regions. This checkpoint adds no coverage measurement and changes no threshold.
Exact changed inputs, check logs and five executed binaries are retained in
`cap99-ack-context-final-proof`. Stage 10 production qualification remains open.


### CAP-100 ReInit attempts bypass public controller authorization

The ReInit attempt handler signed a receipt without verifying its controller
proofs. On source commit `1aea3a3395b42233405c8841dd960d942bf0765f`, all 26
behavioral regressions accept bad authorization signatures, substituted
controller roots or certificates, duplicate approvals, changed repeated fields,
or an initial Commit or KeyPackage plan different from the authorized hash.
Each case accepts a normal control first. Exact inputs and the executed runtime
binary are retained in `cap100-reinit-authority-red-proof`; the run has no
passes and 26 failures in 0.15 seconds.

The public validator now checks all 17 repeated authorization fields, the
authorization ID, the KeyPackage-plan ID and the complete initial Commit digest.
Canonical approvals must use the ReInit attempt authorization signature domain,
name certificates in the retained active roster, carry policy authority and
meet the current old policy's threshold. Repeated controller roots and keys
cannot count twice. The runtime reserves bounded work memory before cloning
rosters or encoding public hash inputs. Validation precedes receipt signing,
including when the sequencer signing key is absent.

The first full runtime run then exposed an independent state substitution:
when the old log was already in the ReInit phase, a fully controller-signed
attempt could name a different old ReInit state. That run passes 1,287 tests,
fails one and ignores one capacity test in 10.86 seconds. Its ten changed Rust
inputs and executed binary are retained in `cap100-reinit-state-red-proof`.
The runtime now requires the attempt's old state to equal the log's original
accepted state. This test opens the domain ReInit phase directly; it does not
claim a complete MLS ReInit or an abort/restart lifecycle.

Thirty-two new tests cover public substitutions, signing-key absence, distinct
controller thresholds, canonical ordering, shared keys, missing devices,
removed policy authority, refused work memory and the original-state check.
Existing ReInit fixtures now sign the correct authorization domain and rebind
hashes after changing a plan or initial Commit. Their MLS Commit bodies and
creator leaf signatures remain synthetic. This repair does not establish old
MLS membership, validate the target tree or prove continuing-member finality
eligibility; those obligations remain under CAP-86. No wire or storage format
changes.

All eight checkpoint checks pass. The locked all-feature workspace run passes
2,771 tests with no failures and 22 default-ignored tests across 120 result
groups in 180.68 seconds. The runtime suite passes 1,288 tests with one ignored
capacity test. Both inventories cover 773 source files with hash
`877545710b151f64d68648cdd8710621669f7deb9c57f2335b9f6214ddb0b352`.
The release catalog has 1,089 critical regions, including six reviewed ReInit
regions. No coverage threshold or measurement changes. Exact changed inputs,
check logs and five executed binaries are retained in
`cap100-reinit-authority-final-proof`. Stage 10 production qualification remains
open.

### CAP-73 historical record authentication

The new public verifier authenticates one complete sequencer record against an
independently established network, conversation, sequence, predecessor and
historical credential. Each of the six record arms uses its registered
signature domain. Terminal IDs are recomputed from their registered cores,
whose context must match the outer certificate. An attempt receipt requires
the exact referenced ReInit attempt object and its recomputed semantic ID.
Informational sequencing time cannot select a credential. A continuous key
rotation does not authorize its successor at an older position.

Eighteen integration tests cover correct signatures, all incorrect record
signature domains, substituted positions and credentials, false terminal IDs,
changed core and attempt fields, missing or unused evidence, malformed wire
objects, decode exhaustion and a maximum-size initial Commit. Alternative
signed proof wrappers retain one semantic ID and distinct transport IDs. The
outer signatures and credential rotation are real; the nested MLS bodies,
controller approvals and votes are synthetic. These tests establish record
authentication, without claiming a valid MLS lifecycle or terminal recovery.

This API has no installed runtime or maintenance caller. It cannot close a
route, clear a witness or construct a terminal recovery result. Complete
historical authority, chain traversal, finality validation, evidence ingestion
and atomic gate installation remain open under CAP-73 and CAP-74. No wire or
storage format changes. There is no old-behavior regression claim for this new
API. Initial validation caught an unused test import, an oversized function
and a non-idempotent formatting pattern; each was corrected before the final
checks.

All eight checkpoint checks pass. The locked all-feature workspace run passes
2,789 tests with no failures and 22 default-ignored tests across 121 result
groups in 183.27 seconds. Source policy accepts 914 Rust files. Both inventories
cover 776 source files with hash
`c9a2077818cfbf2a06c3864973f8ea72f33eb279ad5c2c775b8a14afe06ea537`.
The release catalog contains 1,097 critical regions, including eight new
record-authentication regions. Coverage thresholds are unchanged and no new
coverage measurement is claimed. Exact inputs, check logs and executed binaries
are retained in `cap73-record-authentication-final-proof`.

### CAP-101 sequencer credential selection and candidate validity time

Startup accepts a private key matching either credential in the advertised
overlap set. Installation previously labeled every signature with the first
credential ID, including signatures made by the successor key. Candidate
signing also omitted the check that the credential covers the Commit's
canonical AAD validation time. Four regressions fail against the preceding
implementation and one endpoint control passes. The failed tests and exact
executable are retained in `cap101-sequencer-eligibility-red`. One failure is
the direct installation API accepting an incompatible private key; startup
already rejected a private key absent from the credentials file.

Installation now selects the exact supplied credential by its semantic ID and
checks its network, profile, secret/public key, signer role, interval,
generation and predecessor against the verified key set. Every check finishes
before any installed state changes. The three existing callers propagate an
installation error. Candidate receipt signing requires the selected credential
to cover the Commit's canonical time, including both interval endpoints. The
server's informational signing time does not replace that input.

Thirteen focused tests pass, including daemon startup with both overlap keys,
invalid installation on empty and populated coordinators, substituted verified
metadata and distinct credentials sharing one public key. Candidate bindings
have real device approvals and root-binding locks over the selected credential.
MLS ciphertext and the context digest are synthetic public-envelope fixtures;
these tests do not establish a complete MLS lifecycle. Two initial test-code
compile errors are archived separately from the behavioral failures.

All eight checkpoint checks pass. The locked all-feature workspace run passes
2,802 tests with no failures and 22 default-ignored tests across 121 result
groups in 173.81 seconds. The runtime suite passes 1,301 tests with one ignored
test. Source policy accepts 917 Rust files. Both inventories cover 779 source
files with hash
`f6c393f57a88157872fff74e3be492ac8a51ae78d249f0a32f6f90d9dffc34e1`.
The release catalog contains 1,100 critical regions, including three new
signer-selection regions. No coverage threshold or measurement changes. Exact
inputs, logs and executed binaries are retained in
`cap101-sequencer-eligibility-final-proof`.

Per-conversation context key transitions, retained old signers, terminal
records after a key switch and historical recovery authority remain open.
This repair changes no wire or storage format and clears no recovery gate.
