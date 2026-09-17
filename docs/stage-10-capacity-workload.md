# Stage 10 capacity workload

This record covers CAP-01 (issue #56): the advertised capacity workload and
the bounded resources measured at the production limits. It is a harness and
measurement record, not a qualification result. The production campaign named
in Section 28.7 is **not** run here, and this document says exactly which
parts were measured, on what host, and which were not.

## The defect this replaces

The production capacity launcher set `CAPACITY_CONNECTIONS = 64` while the
release verifier required at least 50,000, so the launcher could never produce
accepted capacity evidence. Four further problems made the number the smaller
of the issues.

1. **The campaign summed its population across nodes.** `take_sample` added
   `live_client_connections` from the coordinator and both edges into one
   scalar, and both the driver and `release_qualification/verify.py` compared
   that aggregate against the floor. Section 19.2 publishes its limits per
   node, so an aggregate of three daemons could have closed a per-node claim
   without any node ever holding the advertised population.
2. **The population was unconfigurable.** The Rust harness refused any
   population above `MAX_CONNECTIONS = 4_096`, and its whole load shared one
   `#load` channel, whose membership would have exceeded the Section 19.2
   default of 4,096 members per channel long before the population did.
3. **The generator could not source the population.** Every client connected
   from one loopback address, and `direct_connections_per_address` admits at
   most 256 connections from one IPv4 /32 at its hard maximum. Registration
   was also paced globally at 400 ms per client index, which at the production
   population would have spent about eleven hours warming up before the first
   sample.
4. **The campaign did not run the advertised budget.** The Stage 08 fixture's
   `apply_common_overrides` lowers `server.memory_budget_bytes` from the
   Appendix C.2 default of four GiB to one GiB for every node, and the
   campaign inherited it. The first pilot run of this work confirmed it: each
   node reported a live pool of 385,876,000 bytes, not 3,338,666,016. No
   advertised capacity claim can rest on an eighth of the published pool.

## What the workload does now

`crates/agenc-ircd/tests/stage_eight_e2ee/stage_ten_capacity/workload.rs`
derives the whole matrix from the driver's population, using the production
functions rather than restated constants (`startup_arithmetic` and the
Section 19.3 percentages in `agenc_ircd_runtime::admission::overload`).

- **Per-node first.** The total is split across the two client-admitting
  edges, and the per-node share decides the profile. `production` means every
  edge holds the Section 19.2 default of 50,000 simultaneous clients, so the
  production aggregate is 100,000. Anything smaller is `below-default` and can
  never close the capacity claim, whatever else it measures. The seven-day
  soak's 256-client minimum is deliberately one of these.
- **Node budget.** `B = 4,294,967,296`, `H = 536,870,912`, `D = 117,440,480`,
  `C = 301,989,888`, `P = 3,338,666,016`: the Appendix C defaults, unchanged.
  The campaign now restores that budget over the Stage 08 fixture's lowered
  one (`CapacityPlan::memory_budget_bytes`; the two functional drills keep
  theirs). Every sample carries each node's own live pool, and the driver
  refuses a record whose pool is anything but that value, so a campaign can
  neither run a smaller budget nor raise a ceiling or a reserve to pass.
- **Active channel and member configuration.** The population is partitioned
  into `#load<n>` channels so no channel exceeds 4,096 members: 25 channels of
  4,000 members at the production population, one channel for a pilot.
- **Generator.** The per-/32 ceiling stays at the Section 19.2 hard maximum of
  256. One production edge therefore needs 196 distinct loopback source
  addresses, which the generator spreads over 25 /24s because the
  new-connection and TLS-handshake buckets are keyed by the source /24. Each
  worker binds its own source address before connecting
  (`IrcClient::connect_from`).
- **Bounded warm-up.** Registration is paced per source address rather than
  globally: only the 256 workers that share one address wait for each other,
  so the production warm-up is about 102 seconds instead of about eleven
  hours.
- **Blockers.** The matrix names every reason the selected population cannot
  close production capacity on the unchanged default configuration
  (`population_below_default`, `idle_charges_exceed_pool`,
  `overload_stops_admission`, `generator_address_space`), and a run is
  `qualifying` only when it is a production population with no blocker.

## What the record and the driver now require

`campaign.json` gains per-node triples for `live_client_connections`,
`memory_charged_bytes` and `memory_budget_bytes`, plus the `workload` and
`node_budget` objects. Node 0 of every triple is the coordinator, which admits
no campaign client; nodes 1 and 2 are the edges.

`scripts/qualify-stage-ten-capacity.py` now selects 50,000 clients per
client-admitting node (100,000 in total) for the `capacity` job and refuses:

- a record whose smallest client-admitting node never held the per-node
  population, which is what an aggregate substitute looks like;
- a node whose live pool is not the default `P`, or that charged more than its
  own pool;
- a workload whose profile, `qualifying` flag or blocker set does not match
  the job it claims to close;
- a raised `connections_per_address`, too few generator source addresses, or
  too few load channels for the population;
- a missing `workload` or `node_budget` object.

`scripts/release_qualification/verify.py` gains `per_node_connections`,
`peak_node_live_connections`, `workload_profile`, `capacity_qualifying` and
`node_budget` to the attested capacity facts, with a per-node floor of 50,000
for `capacity` and 128 for `soak`, and requires the default node budget.

`qualify-stage-ten-capacity.py pilot <campaign.json>` prints a development
pilot's verdict. It closes no job and refuses any record that claims a
production population or an empty blocker set.

## Host

Every measurement below was taken on one host:

- AMD Ryzen Threadripper PRO 9975WX, 32 cores / 64 threads
- 1,055,751,292 kB of memory
- Linux 7.0.0-31-generic (Ubuntu 24.04), `/proc` mounted `hidepid=invisible`
- `rustc 1.98.0 (88d9e12ae 2026-08-18)`, unoptimized `dev`/`test` profile
- repository worktree on xfs (`/mnt/data`), daemon fixtures on ext4 (`/`)
- `ulimit -n` 1,048,576, `net.ipv4.ip_local_port_range` 32768-60999

Because `/proc` hides other processes, the campaign cannot sample a daemon
through procfs on this host; it must run inside a delegated cgroup
(`systemd-run --user --scope -p Delegate=yes`), exactly as the driver's
`delegated_scope_wrapper` arranges. The pilot below did.

## Measured

### One node admits the default idle population inside the default budget

`crates/agenc-ircd-runtime/tests/idle_connection_memory.rs::one_node_admits_the_default_idle_population_within_the_default_budget`
opens the Section 19.2 default client population through the real listener,
TLS endpoint, connection supervisor, reader, writer and writer queue of one
process against one `MemoryBudget` built from the unchanged Appendix C
defaults. A child copy of the test binary holds every handshaken TLS stream
idle, so the client side never shares this process's heap, and the population
is spread over eight listener sockets because one loopback destination port
cannot hold 50,000 connections from one source address.

```text
population=50000 listeners=8 pool=3338666016 charged=3278897152
charged_per_connection=65536 resident_before=3031040 resident_after=1863389184
resident_per_connection=37207 admitted_in_ms=34963
```

- 50,000 simultaneously admitted idle TLS connections on one node, plus 32
  warm-up connections, charged exactly 65,536 bytes each: composed queue and
  session backing is acquired on demand and an idle connection holds only its
  base charge.
- 3,278,897,152 of the 3,338,666,016-byte live pool `P`, inside the unchanged
  four-GiB budget with no ceiling raised.
- 37,207 bytes of anonymous resident growth per connection, below the 65,536
  base charge, so the charge dominates the real allocation.
- Every permit returned when the connections closed: the budget was back to
  zero.

### The advertised domain scans

`crates/agenc-ircd-domain/src/decision/tests/advertised_scans.rs` builds the
Section 19.2 advertised populations (100,000 global channels, 10,000 local
channels, 100,000 network-wide invitations at 256 per channel, one channel of
4,096 members, 50,000 accounts each holding a reserved nickname, 1,024
sessions) and measures the linear scans `TODO.md` recorded as "fine at Stage
06 scale". Each is measured in its worst case: an identity or nickname nothing
holds, so the whole map is visited.

```text
channels=110000 invites=100000 members=4096 accounts=50000 sessions=1024
operational_usage_us=82511 channel_scope_counts_us=8835
validate_new_invite_id_us=11396 invite_capacity_us=34562
reserved_nickname_owner_us=12242 close_session_invite_purge_us=20844
```

| Scan | Site | Cost at the advertised populations |
| --- | --- | ---: |
| `operational_usage` | `domain/model.rs` | 82.5 ms |
| new-channel scope counting | `domain/model.rs::channel_scope_counts` | 8.8 ms |
| `validate_new_invite_id` | `domain/decision.rs` | 11.4 ms |
| network invite total | `domain/decision.rs::validate_invite_capacity` | 34.6 ms |
| `reserved_nickname_owner` | `domain/decision.rs` | 12.2 ms |
| session-close invite purge | `domain/decision.rs::apply_close_session` | 20.8 ms |

These run on the single-threaded StateCore owner, so at the advertised
populations one INVITE costs about 46 ms of exclusive domain time
(`validate_new_invite_id` plus the network total) and one session close about
21 ms. That is an ordering of roughly twenty invitations or fifty session
closes per second network-wide in an unoptimized build, and it is measured
work rather than an asserted deadline: the test only fails a pathological
regression. Indexing these maps is the obligation `TODO.md` already records;
this record supplies the number that decides when it becomes urgent.

### A development pilot of the campaign harness

The harness was run three times at a 64-client development population inside a
delegated cgroup, exactly the way the driver launches it; the third run is the
control described in blocker 2:

```text
AGENC_STAGE10_CAMPAIGN_DIR=<dir> AGENC_STAGE10_CAMPAIGN_SECONDS=<n> \
AGENC_STAGE10_CAMPAIGN_CONNECTIONS=64 \
systemd-run --user --scope --quiet -p Delegate=yes -- \
  target/debug/deps/stage_eight_e2ee-<hash> \
  stage_ten_capacity::sustained_operation_campaign --exact --nocapture --ignored
```

A 60-second run passed end to end: three daemons started, 64 workers
registered from their generator source addresses and joined `#load0`, the
baseline and quiescence samples recorded per-node occupancy
(`live=64/64 per_node=[0, 32, 32]/32`, so the coordinator held none and each
edge held its own share), 44 `SERVER_BUSY` channel refusals were retained with
their codes and ten-second buckets, the federation drained in 7.7 seconds and
all three daemons stopped cleanly. Its `campaign.json` carried the workload
matrix (`profile=below-default`, `qualifying=false`,
`blockers=[population_below_default]`) and the node budget. That first run is
also what exposed the one-GiB fixture budget: it reported a live pool of
385,876,000 bytes per node.

A 300-second run with the restored default budget then executed a full cycle
and reached seven of the eight scenarios — reconnect, churn, snapshot (through
`#load0`), OPAQUE login, disk pressure (refused and recovered), backup, and
peer loss — before failing on the killed edge's restart. That failure is
blocker 2 below, and it is what a development pilot is for.

Neither 300-second run finished. The control run described in blocker 2 ran
all eight scenarios, ended its cycle at 241.4 s and passed quiescence at
262.7 s (`inside=true population=true live=64/64 per_node=[0, 32, 32]/32`),
then failed in the final settle with
`Os { code: 11, kind: WouldBlock, message: "Resource temporarily unavailable" }`
— an admin-socket read that exceeded its timeout while several other
worktrees were compiling on the same host. That is a second, unrelated
fragility of the campaign controller: one timed-out `STATS` read during the
settle fails the whole campaign rather than being recorded as a sample
failure, which the record already has a counter for
(`sample_failures`). It is not investigated here.

Both runs also confirm two harness properties the production population needs:
`resource_source=cgroup`, because this host's `hidepid` mount makes procfs
sampling impossible, and a warm-up paced per generator source address.

## Not measured

- **The production capacity campaign.** No three-daemon campaign was run at
  50,000 clients per edge. It is blocked (see below) and, even unblocked,
  needs a host budget this session did not have.
- **The seven-day soak.** Section 28.7's 256-client minimum soak with all
  eight recovery/churn scenarios over 604,800 seconds was not run. The harness
  changes preserve it: the soak job keeps its 256-client population, its
  per-node floor of 128 and all eight scenarios.
- **The six latency classes and the eight lifecycle scenarios at the
  production population.** The pilot exercised the harness, not the advertised
  population.
- **AArch64.** Every number here is x86_64. Nothing measured is
  target-specific, but the `stage-10-aarch64` workflow cannot run until
  organization Actions are enabled (issue #41).
- **StateCore batch-size-one at the advertised population.** The campaign's
  `durable_mutation` latency class is the measurement that would show what one
  plan per batch costs under the advertised load, and it needs the campaign.
  The mechanism itself is already recorded in `TODO.md`: every plan is built
  against the committed revision, so `pending.rs` never chains a second one,
  and the state core holds its inbox while a batch is pending. Section 19.2
  permits "up to 256", so one is legal and this is measured work, not a
  defect.
- **Release-profile numbers.** All measurements are from unoptimized `dev`
  builds. The release campaign runs the frozen release binary through
  `DaemonTests`, and its numbers will differ.
- **`python3 scripts/qualify-stage-ten-capacity.py capacity`.** The driver
  itself was not executed: it runs only inside a release candidate attempt
  through `qualify-release.py run`, which this issue does not own (REL-09,
  issue #83). Its record validation is covered by the fixtures below.

## Open blockers before a production campaign can close

1. **Issue #113 — Section 19.3 refuses the population Section 28.7 requires.**
   50,000 idle base charges are 3,276,800,000 bytes, 98% of the live pool, so
   the connection-stop class refuses the 45,850th client and eviction starts
   at 48,396. The workload matrix reports this as the
   `overload_stops_admission` blocker for any production population, and
   `workload.rs::the_default_population_is_charged_within_the_pool_but_stopped_by_overload`
   pins the three thresholds. A production campaign cannot pass until the
   normative choice in #113 is made. The idle occupancy measurement above is
   not affected: it exercises the listener and the budget directly, without
   the Section 19.3 classifier that a daemon applies.
2. **A killed edge cannot restart: the peer-loss scenario.** In the 300-second
   pilot, `scenario_peer_loss` SIGKILLed edge B under load and the restarted
   daemon refused to start:

   ```text
   agenc-ircd: runtime startup failed: storage owner failed: storage state is
   stale or inconsistent
   ```

   The campaign then failed the cycle with "edge never established its
   coordinator link" after the 60-second link wait. This is a blocker for
   every campaign, not only a production one, because the peer-loss scenario
   is one of the eight Section 28.7 lifecycle scenarios.

   **Correction (STO-10, issue #124).** This record originally attributed the
   refusal to `verify_guard_pair`
   (`crates/agenc-ircd-storage/src/control.rs`) refusing the database/guard
   pair after a kill between the database commit and the guard replacement.
   That attribution is withdrawn. The line above carries the
   `runtime startup failed: ` prefix that only `DaemonError::Runtime` adds,
   while a refusal from `StorageOwner::start` is `DaemonError::Storage` and
   prints `storage owner failed: ...` on its own, so edge B's storage opened
   and reconstructed and the daemon refused afterwards, during runtime
   startup. An on-disk crash matrix over both guard publications of a commit
   and of a checkpoint also shows that window already reopens at its exact
   prior or successor state. The exact message and the two runs stand; the
   refusing function named here did not. See
   [the storage guard reopen record](stage-10-storage-guard-reopen.md), which
   also names the surfaces the follow-up issue must cover.

   One control run of the same campaign with the fixture's one-GiB budget
   survived the kill (`peer loss: edge b back`), completed all eight scenarios
   and passed quiescence, so this failure was observed only with the default
   budget. That is one run each and is not a proof of causation: a kill
   under load is a race, and a live pool 8.7 times larger admits far more
   concurrent durable work at the instant of the kill, which makes any such
   window easier to hit. The control run then failed for its own,
   unrelated reason in the final settle, so no 300-second campaign completed
   on this host. Running the campaign
   at an eighth of the published pool is not an option — it is defect 4 above
   — so this needs its own prerequisite issue against the edge's startup
   reconstruction. This record claims no root cause beyond the exact message
   and the two runs that produced and avoided it.
3. **Host budget.** One production campaign needs three daemons, 100,000 TLS
   client sessions with their per-session state, 196 source addresses per edge
   and a delegated cgroup, for at least 300 seconds; the soak needs seven
   days. Neither fits a development session.

## Evidence

Commands run for this record, all from the worktree root:

```text
cargo fmt --all
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
python3 scripts/check-source.py check
python3 scripts/test-release-qualification.py
python3 scripts/qualify-release.py check
cargo test -p agenc-ircd-runtime --all-features --locked --lib
cargo test -p agenc-ircd-domain --all-features --locked --lib
cargo test -p agenc-ircd --test stage_eight_e2ee --all-features --locked -- workload::
cargo test -p agenc-ircd-runtime --all-features --locked --test idle_connection_memory
cargo test -p agenc-ircd-runtime --all-features --locked --test idle_connection_memory \
    -- --ignored --nocapture --test-threads=1
cargo test -p agenc-ircd-domain --all-features --locked --lib -- advertised_scans --nocapture
```

The development pilot was launched with the delegated-cgroup command shown
above, at 60 and 300 seconds with 64 connections.

Tests that carry the claims:

- `stage_ten_capacity::workload::*` (12 tests): the per-node production
  population and its aggregate, an aggregate-only population classified as
  `below-default`, the 64-client development run's inability to qualify, the
  published node budget arithmetic, the Section 19.3 blocker with its exact
  thresholds, the generator's source spread and per-/32 ceiling, distinct and
  bounded source addresses, the load-channel partition under the 4,096-member
  ceiling, the bounded paced warm-up, and the listener ceiling at the hard
  maximum.
- `idle_connection_memory::one_node_admits_the_default_idle_population_within_the_default_budget`
  (ignored by default): the per-node occupancy measurement above.
- `idle_connection_memory::idle_tls_connections_hold_the_base_charge_and_no_more_resident_memory`:
  the existing RUN-04 regression, unchanged apart from the driver's now
  multi-address connect.
- `decision::advertised_scans::every_advertised_scan_is_measured_at_the_published_limits`
  and `..._at_a_reduced_population`: the profiling matrix.
- `CapacityDriverTests` in `scripts/test-release-qualification.py`: the
  complete record, the aggregate substitute in both its spread and lopsided
  forms, the workload matrix and node budget refusals, a raised or overdrawn
  pool, the soak's below-default population, the development pilot's verdict
  and the refusal of a pilot that claims to qualify.
- `VerifierTests.test_capacity_report_requires_resource_source_and_refusal_count`
  and `test_small_campaign_cannot_close_production_capacity`: the attested
  facts, including the per-node floor, the profile and the default budget.
