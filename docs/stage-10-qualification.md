# Stage 10 production qualification

Stage 10 is in progress. Stage 09 supplies the implemented optional profiles
and its recorded checkpoint. Stage 10 requires evidence from the exact
release binaries on both native targets. No Stage 10 release decision has
been signed.

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
the edge after a JOIN). Every cycle runs reconnect, churn, snapshot, OPAQUE
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
from the last one, and checks the deleted login stays refused and the record
and byte counts fell. Rekey restores an edge under a new master and guard key
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

Development runs on this host pass twelve drills: migration (interrupted and
resumed), rekey, TLS rotation (same-key renewal by reload, new key by
restart, which `REHASH` refuses with `RESTART_REQUIRED`), federation
rotation, sequencer rotation (a generation-1 set chaining from the previous
credential), backup rotation, audit rotation, compromise (quiesced through
the restart path, see CAP-8), rollback, resynchronization (see CAP-10), host
hardening, and observability. Four do not pass and keep the drills job
failing: restore and disaster restore (CAP-9), login-index transition
(CAP-5), and deletion (CAP-11).

## Coverage

`conformance/release-critical-coverage.toml` is the Stage 10 coverage policy.
It uses the same schema as the interim `critical-coverage.toml`, carries the
90 percent branch and line floors, and lists the complete critical inventory:
96 regions across the five categories the architecture names. Each region is
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
regions at 100 percent. Reaching the release floor needs 2,722 more covered
branch outcomes. The interim policy passes; the release policy fails on the
floor and on 21 of its 96 regions, which are listed with their counts in the
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

### CAP-1: edges refuse explicit directory queries

A registered client at an edge that sends `NAMES #load`, `WHO #load`,
`WHOIS`, or a TOPIC query receives `482` (channel targets) or `481`. The edge
converts client commands into federated operations and forwards only
mutations and the NAMES page it requests itself after a JOIN; every other
query falls through to `BadState`. The appendix command table lists WHO and
NAMES as supported. The campaign measures the snapshot class on the paged
NAMES that the JOIN triggers and records the numeric each explicit query
receives.

### CAP-2: registration under disk pressure is not always a bounded refusal

With the coordinator's storage under the reserve, a new registration at an
edge received `FAIL USER NETWORK_UNAVAILABLE` in some runs, a close before any
reply in others, and in one run no reply within twenty seconds. The campaign
records the outcome it observed each cycle.

### CAP-3: a refused durable mutation under pressure closes the session

A registered session whose JOIN was refused with `FAIL JOIN
NETWORK_UNAVAILABLE` during disk pressure lost its transport within two
seconds. Section 28.7 asks for a side-effect-free `SERVER_BUSY`; the edge
instead reports the coordinator refusal as network loss and drops the client.
The campaign re-registers for its recovery check and notes the close.

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

### CAP-6: every sender on an edge silently loses one channel message during an OPAQUE login

While the campaign account authenticates and registers at edge A, every
other client on edge A loses exactly one channel message to every observer on
both edges, at the same instant, with no `FAIL PRIVMSG` reply to the senders
and no link or storage event in any daemon log. Three of four development
runs reproduced it at the same point (the forty-third message of each sender,
about fifty-five seconds into the cycle). Section 19 requires all-or-none
fanout and a side-effect-free `SERVER_BUSY`; a silently dropped committed
message violates it. The engine records every `FAIL PRIVMSG` reply and
re-sends the refused sequence, so a refusal and a silent loss stay
distinguishable, and it carries the refused count in the record. Missed
events stay the gate: the capacity job fails on this finding until the loss
is fixed and the campaign reruns with zero missed events.

### CAP-7: the first OPAQUE login after a coordinator restart can fail with 904

After a coordinator restart, with both edge links re-established, the first
authentication of an existing account at an edge was answered with `904 SASL
authentication failed` in some runs and succeeded in others. The engine
retries within a thirty-second grace after a restart and notes every such
retry in the record.

### CAP-8: a listener ceiling lowered by reload is not enforced

Lowering the client listener's `max_connections` from 32 to 1 and reloading
with `REHASH` returned `NOTE REHASH OK`, yet the next connection registered
while one session was held and no `connection_refused` event was logged. The
same configuration applied at a restart refuses the second connection.
Section 22.6 lists a lowered listener ceiling as reloadable. The compromise
drill records both outcomes and quiesces through the restart path.

### CAP-9: the coordinator does not start on a directory restored from its own backup

`storage restore` of a coordinator backup taken with the coordinator stopped
completed and reported `state generation: source=30, current=30, target=0`,
with and without a current guard witness. Starting the coordinator on the
restored directory failed with "runtime startup failed: storage owner
failed: storage state is stale or inconsistent". The same restore of an edge
serves afterwards, and the rekey and resynchronization drills depend on it.
The restore and disaster restore drills fail on this finding until the
coordinator restore path preserves a startable state.

### CAP-10: the admin DIE is refused while an account session is attached to the edge

With an authenticated account session attached to an edge, every signed
`DIE` from a fresh local admin session was rejected with
`admin_rejected error=authentication_failed` and the admin transport closed,
for sixty seconds of retries. After that client sent `QUIT`, the same
command from the same operator identity was accepted at once. Guest
sessions do not trigger it. The resynchronization drill records the refusal
and stops the node after detaching the client.

### CAP-11: account deletion has no reachable path in the federated profile

`ACCT DELETE START` from an authenticated, freshly re-authenticated session
at an edge is answered `FAIL ACCT BAD_STATE`: the edge forwards no account
command to the coordinator. The coordinator's own client listener answers
`CAP * NAK` for the sasl and account capabilities, so the account service
cannot be reached there either. The deletion drill records both refusals and
does not pass; the deletion and rekey evidence it would produce stays open.

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
