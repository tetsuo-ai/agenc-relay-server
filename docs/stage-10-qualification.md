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
checkout and independently reproduced build records for both native targets.
It copies the binaries and build evidence into a new candidate directory.
Source, lockfile, policy, command, binary, and build-record hashes bind each
attempt to that candidate.

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
complete Stage 10 critical-branch inventory and its coverage remain open.

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

The capacity and sustained-operation driver is implemented (below). The
deployment drill driver is still being implemented. `check` refuses a policy
whose required driver is absent.
Source-status decisions, the complete critical coverage inventory, native
build reproduction, and the long campaigns have not been completed. The
release builder and detached signing path still need their full integration
qualification.

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
drives N TLS clients split across the edges. Every client joins `#load` and
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

## Open findings

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

The verifier checks the signature, candidate artifacts, native attempt records,
decision chronology, and the external review when the decision claims the
encrypted profile. It does not trust the public key bundled beside a signature.

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
