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
| Restored account authentication | CAP-9 and CAP-54 repairs pass strict restore and disaster-restore drills with existing and new accounts. CAP-7 still needs the strict release capacity run. |
| Account deletion and rekey | CAP-11, CAP-57, and CAP-62 through CAP-67 pass the complete strict deletion drill, including exact authenticated rows, both deleted-login refusals, the surviving account, and all final stops. |
| Federation and client replies | CAP-47 through CAP-60 have focused regression evidence, and all required workspace gates pass. A successful new release capacity run remains required. |
| Disk pressure | CAP-44 and CAP-45 fix reset cleanup and durable request reconstruction. CAP-3 still requires proof that the original refused session survives and recovers. |
| Reconnect and shutdown load | The current CAP-4 release probe survives the unpaced reconnect wave, admits eight fresh clients after recovery, and stops all three daemons cleanly. CAP-14 needs a fresh capacity result after the CAP-51 and CAP-65 shutdown repairs. |
| Missing implementation | CAP-5 needs stopped login-index rotation commands and their authenticated audit and migration contract. CAP-13 needs bounded ordinary-event batching with complete receipt, rollback, and resource checks. |
| Companion delivery recovery | CAP-70 records lost retained delivery scope and rows at intact restart. CAP-71 records companion acknowledgements that change memory without owning a durable cursor transition. Production-loader and acknowledgement regressions reproduce both faults; durable repairs remain open. |
| Declared recovery | CAP-72 records obsolete companion delivery, replay, and barrier rows copied into the new incarnation, plus typed live routes left outside recovery pending. A typed transform regression is being prepared. |
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

The CAP-3 repair also passes every required development gate. Its workspace
run reports 2,115 passing tests, no failures, and 21 ignored qualification
tests across 118 targets. Source policy accepts 600 Rust files. Both reviewed
inventories bind 476 production source files, and the release policy covers
127 critical regions with its coverage floors unchanged. The strict release
campaign passes original-session pressure recovery but fails later restart
synchronization, so this repair does not close capacity qualification.

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
are retried. A new campaign must establish whether any CAP-7 symptom remains.

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

Open. The ordinary daemon restart preserves its stored incarnation and
recovery epoch. Companion startup collects delivery records but restores only
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

The legacy cursor and snapshot records omit the historical scope needed to
reconstruct empty streams and exact READY retries. The repair therefore needs
an explicit successor storage format and migration rules. It cannot infer the
old companion scope from the current base peer. A legitimate paired reset
remains a separate positive case. The CAP-3 pressure trace does not establish
this companion failure, and no repair is claimed yet.

### CAP-71: companion acknowledgement coverage has no durable receipt owner

Open. EACK validates its addressed delivery stream and then changes its
in-memory acknowledged cursor and replay class. It returns no staged action,
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

The repair also requires rejection before submission, successful commit followed
by restart without an unrelated event, and the four combinations of durable
base and companion coverage. It must preserve the existing fatal handling of
indeterminate storage and prohibit snapshot substitution for an unfinished
barrier. Those tests and the production correction remain in progress.

### CAP-72: declared recovery preserves obsolete companion state and live routes

Open. The restore selector sends every E2eeState row to RestoreE2eeState.
That transform updates only the legacy kind-1 recovery gate and copies every
other kind unchanged. Typed route rows use kind 2, replay rows and origin
floors use kind 9, delivery cursors and outboxes use kind 10, and combined
barrier records use kind 12. The route's recovery_gate therefore stays false,
while obsolete stream and barrier ownership survives into the new incarnation.

Section 23.7 requires every live encrypted route to enter recovery pending
while preserving its counters and proof head. It also requires discarding old
base and companion delivery scope, barriers, their parts and receipts, and
federation request replay roots. The current table-wide selection cannot apply
those distinct rules. This source finding needs a typed restore regression;
no executed repair or successful recovery is claimed yet.

The correction must select and validate each closed record kind, preserve
non-federation proof and mailbox state, and apply the route recovery transition
without changing counters or inventing evidence. Until that repair passes,
the existing declared-recovery command is not a valid escape route for the
ambiguous legacy companion scope identified in CAP-70.

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
