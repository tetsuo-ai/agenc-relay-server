# Stage 10 peer-loss reproduction and the edge restore that refused it

This record closes RUN-08 (issue #134): CAP-01's observation that an edge
SIGKILLed under load refuses runtime startup **reproduces**, and this states
what it is. It continues
[the edge startup reconstruction record](stage-10-edge-startup-reconstruction.md)
and [the edge restore refusal cause record](stage-10-reconstruction-cause.md),
which narrowed the failure without reproducing it, and
[the storage guard reopen record](stage-10-storage-guard-reopen.md), which
cleared the storage open by proof. Both earlier records were right about where
it was not; neither reached it, because it is a race that needs about seventy
kills to show once.

The observation being reproduced is one pilot run recorded in
[the capacity workload record](stage-10-capacity-workload.md):
`scenario_peer_loss` SIGKILLed edge B, the restarted daemon printed

```text
agenc-ircd: runtime startup failed: storage owner failed: storage state is
stale or inconsistent
```

and the cycle failed with "edge never established its coordinator link".

**It reproduced three times in 209 SIGKILLs**, and PR #138's and PR #144's
labelling named it on sight:

```text
agenc-ircd: runtime startup failed: edge federation restore at
edge-projection-install (active projection: federation replica reference does
not resolve) refused the recovered state: storage owner failed: storage state
is stale or inconsistent
```

Every one of the three killed edges left the same durable state, and it is not
a torn write. It is a complete, committed, ordinary state of a correctly
running edge, which the edge's own restore could not rebuild.

## What was driven

Everything ran from one worktree at `99956df` (the `origin/main` tip of
2026-09-17) against the unmodified daemon, so the reproduction tests the
shipped binary. The host is the one
[the capacity workload record](stage-10-capacity-workload.md) names: AMD Ryzen
Threadripper PRO 9975WX (32 cores / 64 threads), 1,055,751,292 kB of memory,
Linux 7.0.0-31-generic, `/proc` mounted `hidepid=invisible`, daemon fixtures on
the ext4 root filesystem, `rustc 1.98.0`, unoptimized `dev`/`test` profile.

Both vehicles build the same three-daemon network through
`build_network_with(Some(CapacityPlan { .. }))` with
`memory_budget_bytes: DEFAULT_BUDGET_BYTES = 6_442_450_944`, hold the same
64-client population (32 per client-admitting edge) through the same
`worker`/`run_session` load, and kill edge B with the same
`DaemonProcess::kill`, which is `Child::kill`, a SIGKILL. Every node reported a
live protocol pool of `5,217,714,208` bytes in `STATS RUNTIME`, which is the
published `P` for the current default budget, so no run was accidentally taken
at the Stage 08 fixture's lowered one.

### The campaign, at the configuration that produced the observation

`stage_ten_capacity::sustained_operation_campaign`, driven as the capacity
record's pilot was, inside a delegated cgroup because this host's `hidepid`
mount makes procfs sampling of a daemon impossible:

```text
AGENC_STAGE10_CAMPAIGN_DIR=<dir> AGENC_STAGE10_CAMPAIGN_SECONDS=300 \
AGENC_STAGE10_CAMPAIGN_CONNECTIONS=64 \
  target/debug/deps/stage_eight_e2ee-<hash> \
  stage_ten_capacity::sustained_operation_campaign --exact --nocapture --ignored
```

This is the smallest configuration that still exercises the same kill: the
cycle reaches `scenario_peer_loss` only after `scenario_reconnect`,
`scenario_churn`, `scenario_snapshot`, `scenario_opaque`,
`scenario_disk_pressure` and `scenario_backup`, and a 300-second budget admits
exactly one cycle, so one run is one peer-loss kill under the same preceding
durable history the pilot had. A shorter budget runs no cycle at all: the loop
starts a cycle only while `now + FINAL_RESERVE + last_cycle < deadline`, which
at 60 seconds is already false when the warm-up ends.

### The kill drill, which repeats only that kill

One campaign run is one kill in about five minutes, which cannot tell "does not
reproduce" from "reproduces rarely" — and at the rate measured below, five
campaign runs were expected to see nothing, and saw nothing.
`stage_ten_capacity::peer_loss_kill_drill` holds the same population against
the same three daemons at the same budget and repeats **only** the peer-loss
kill:

```text
AGENC_RUN08_KILL_DIR=<dir> AGENC_RUN08_KILL_ROUNDS=60 \
AGENC_RUN08_KILL_CONNECTIONS=64 \
  target/debug/deps/stage_eight_e2ee-<hash> \
  stage_ten_capacity::peer_loss_kill_drill --exact --nocapture --ignored
```

Each round raises the same maintenance flag `scenario_peer_loss` raises,
SIGKILLs edge B, waits the same five seconds, restarts it through the same
`Nodes::restart_edge_b`, and waits for the same `wait_for_link`. It adds two
things. A **phase sweep**: round *n* waits `1.5 s × ((n - 1) mod 24)` after the
link is re-established before killing again, so kills land from 0 to 34.5
seconds after a restart — the coordinator's post-restart resynchronization, the
whole 12.4-second paced return of the population, and the settled state beyond
it, including `scenario_peer_loss`'s own twelve seconds. And a **startup
kill**: every second round kills the restart again before it reaches its link,
stepping that second kill's phase by one second across twenty steps, so the
start that has to survive reads a state a kill tore inside the startup work.

A refused restart copies the killed edge's whole durable directory to
`<AGENC_RUN08_KILL_DIR>/edge-b-durable-state` and its stderr to
`edge-b-refusal.log` before the fixture is removed, which is how the three
crash images below were read.

The drill does not reproduce `scenario_disk_pressure`, `scenario_rekey` or
`scenario_index_transition`, and after its first round each kill is preceded by
a kill rather than by the backup's clean stop.

## What was observed

| vehicle | runs | SIGKILLs | refused restarts |
| --- | ---: | ---: | ---: |
| campaign, 300 s, 64 clients | 5 | 5 | 0 |
| kill drill, 64 clients | 6 | 180 | 3 |
| kill drill, 512 clients | 1 | 24 | 0 |
| **total** | **12** | **209** | **3** |

Four of the five campaign runs completed the whole 300-second cycle with all
eight scenarios and both quiescence checks inside the warm envelope, which no
300-second campaign had previously done on this host; the fifth failed later in
the same cycle, in `scenario_index_transition`, with "edges did not finish
synchronization after coordinator restart" while three drills were running
beside it. Its peer-loss kill had already succeeded.

The three refusals are drill `d1` round 26, drill `d2` round 26 and drill `s1`
round 18. Each printed the labelled line above and each left its whole durable
directory behind. Three refusals in 209 kills is about one in seventy; a single
pilot run seeing it once is exactly what that rate looks like, and it is also
why two passes of synchronous prefix sweeps never met it.

The kills were taken under real load. Edge B held between 2 and 32 of its 32
clients at the instant of the kill, and the three nodes together held between
about 2 and 12 megabytes of charged protocol memory against their
5,217,714,208-byte pools — about one part in a thousand.

### The durable state of the killed edge

All three preserved directories were opened through the real storage owner and
scanned. They carry the same shape:

```text
d1: peer generation=2 active_entry_count=38 pending_generation=None snapshot_required=false
    EdgeProjection generation 2: 38 entry rows, marker Active entry_count=0
    9 sessions, 11 channel details, 18 memberships; install -> DanglingReference
d2: peer generation=2 active_entry_count=78 pending_generation=None snapshot_required=false
    EdgeProjection generation 2: 78 entry rows, marker Active entry_count=0
    19 sessions, 21 channel details, 38 memberships; install -> DanglingReference
s1: peer generation=2 active_entry_count=52 pending_generation=None snapshot_required=false
    EdgeProjection generation 2: 52 entry rows, marker Active entry_count=0
    13 sessions, 14 channel details, 25 memberships; install -> DanglingReference
```

Read what that says. The coordinator row's `active_entry_count` equals the
durable row count **exactly**, in all three: nothing is missing and nothing is
extra, so the count invariant `Restore::install_projection` enforces passes.
Every membership names a channel and a session the set holds. The generation's
own ACTIVE marker declares `entry_count = 0`, so the whole standing projection
was built by the live delta path out of projected events, not by a snapshot
install. And in each image **exactly one channel detail has no local member and
no invite**.

That last row is the whole failure.

## The diagnosis

`EdgeReplica::install` — the install a **coordinator snapshot** goes through —
finishes with `validate`, and `validate` requires the entry set to be closed
under entitlement: every channel it holds must have a local member or an invite
(`has_entitlement`, `crates/agenc-ircd-domain/src/federation/replica.rs`).
`Restore::install_projection` rebuilt the edge's own active generation through
that same install, so a channel standing without a member refused the restore
with `ReplicaError::DanglingReference`, which the restore reports as
`StorageError::StaleState` — the captured line.

**`apply` reaches that state and holds it, by design, in two windows.** A
channel and its memberships are separate projected events, each applied and
committed in its own durable batch:

- `ProjectedEvent::ChannelVisible` inserts the channel detail with no member at
  all, and `apply` accepts it; the `MemberJoined` that entitles the edge to it
  is the next event. Between the two, the edge durably holds a memberless
  channel.
- `ProjectedEvent::SessionHidden` removes the session and every membership it
  held (`apply_session_hidden`) and removes nothing else — it drops an
  unreferenced account, but it has no equivalent for a channel left with no
  local member. The channel goes only when the coordinator's later
  `ProjectedEvent::ChannelHidden` arrives, which `apply` refuses with
  `ChildrenRemain` until the memberships are gone. Between the two, the edge
  durably holds a memberless channel again.

So the state is not half-built and it is not a torn write. Every batch that
produced it committed whole, the peer row in each batch recorded the replica's
own entry count, and the node kept running correctly — `apply` never calls
`validate`, and nothing on the live path does. A SIGKILL is only the thing that
forces the node to rebuild itself from rows it was always allowed to hold. Any
restart in that window would have done it; the kill is incidental.

That also explains the shape of the evidence. The window is one channel wide
and closes as soon as the next event for that channel arrives, which is why the
failure is a race of about one kill in seventy, why a 64-client population
running real joins and parts meets it while a synchronous 40-connection prefix
sweep does not, and why every image shows exactly one offending channel.

### The two candidates the earlier records left open are closed

**The memory budget is not the mechanism, and cannot be.**
`server.memory_budget_bytes` reaches one function: `memory_budget`
(`crates/agenc-ircd-runtime/src/daemon.rs`) passes it to `startup_arithmetic`
and wraps the resulting `protocol_pool_bytes` in a `MemoryBudget`, and the
reload check re-runs the same arithmetic. It sizes nothing durable:
`storage_open_config` builds `StorageEngineLimits` with
`redb_cache_bytes: DEFAULT_REDB_CACHE_BYTES`, a fixed `67_108_864` in
`agenc-ircd-config`'s bounds, and takes its reserve, database and backup
ceilings from `[storage]`. No commit batching, no flush boundary and no cache
size moves with the budget. The measured charge at every kill was one part in a
thousand of the pool, so the restore's own admission was never near a ceiling
either. CAP-01's four-GiB run failing where its one-GiB control survived was
one run each of a one-in-seventy race, exactly as the capacity record warned
when it declined to claim causation.

**The projection-charge repair is not it either.** The defect
[the refusal cause record](stage-10-reconstruction-cause.md) fixed refuses with
`RuntimeError::LimitExceeded`, printing `runtime ceiling exceeded`, never the
captured line, and its ceilings are 536,870,912 bytes or 1,000,000 rows against
an edge state directory under ten megabytes.

## The decision

**A restore that cannot rebuild a state the live path legitimately reaches is
not a legitimate refusal.** That is the principle
[the refusal cause record](stage-10-reconstruction-cause.md) already settled
for the restore's admission pools, and it decides this the same way: the
entitlement closure is an invariant of a **coordinator snapshot**, which the
coordinator builds whole and which must be complete, not an invariant of a
running edge replica, which `apply` moves through the two windows above. The
writer ordering is not wrong — the two events are separate facts that arrive
separately and each must be durable when it is applied — and coupling them
would be a federation protocol change for a refusal that never had to happen.

So `EdgeReplica` now distinguishes the two installs
(`crates/agenc-ircd-domain/src/federation/replica.rs`):

- `install` is unchanged and still closed: `snapshot_end`'s verifying install,
  `sync::activated`'s install of the snapshot the coordinator sent, and
  `sync::restore_pending`'s verification of a pending generation — which is a
  coordinator snapshot's own rows and is never touched by `apply` — all keep
  it.
- `install_recovered` is the restore's install of the edge's **own** active
  generation. It admits a channel with no local member and no invite, and
  relaxes nothing else.

Everything else still **fails closed**, and the regression requires it: a
membership whose channel was never projected, a membership whose session is
absent, an unreferenced account, a foreign home, a revision fault, an unsorted
or duplicated set and every per-record rule all still refuse, through both
installs. `Restore::install_projection` still enforces the coordinator row's
`active_entry_count` against the restored rows, and still never installs a
projection partially.

The three preserved crash images were replayed against the repair: each one
refuses under `install` with `DanglingReference` and restores under
`install_recovered`. Those are the states the production daemon actually left
behind, which is the closest thing to an end-to-end proof this work can offer.

## Evidence

- `crates/agenc-ircd/tests/stage_eight_e2ee/stage_ten_capacity.rs::peer_loss_kill_drill`
  (ignored): the repeated kill at the published budget with its phase sweep and
  startup kill, the per-round occupancy record in `peer-loss-kill-drill.json`,
  and the durable-state capture that produced the three crash images.
- `federation::replica::tests::a_channel_between_its_bracketing_events_is_admitted_only_by_the_recovered_install`
  (domain): the snapshot install still refuses the memberless channel, the
  recovered install accepts it, and four other shapes still refuse through the
  recovered install.
- `federation::edge::tests::reconstruction_cause::a_channel_awaiting_its_bracketing_event_restores_instead_of_refusing`:
  the same rows seeded durably through the real storage owner, with the
  coordinator row declaring their exact count, restore instead of refusing.
- `federation::edge::tests::reconstruction_cause::a_dangling_membership_beside_the_same_rows_still_refuses`
  and the existing
  `a_projection_the_replica_refuses_names_the_replica_and_not_the_storage_layer`:
  the relaxation is one invariant wide, and the operator-visible line for a
  genuine dangling reference is unchanged.
- `daemon::tests::the_recovered_session_reconciliation_labels_at_its_only_conversion`
  and `daemon::tests::no_recovered_session_refusal_prints_either_unlabelled_line`:
  the second repair below.

## The second repair, found while looking for this one

The recovered session reconciliation was the one startup surface no pass had
swept, and it could still print the captured line naming no surface.
`reconcile_recovered_sessions` labelled only the refusals it built through
`startup_stale_state()`; its own commit path did not. `commit_startup_plan`
converted `project_batch`'s `RuntimeError` through `?` into
`DaemonError::Runtime`, which for a stale-state refusal prints
`runtime startup failed: storage owner failed: storage state is stale or
inconsistent` — the captured line, naming no surface — and converted
`try_commit`, its `wait` and `try_read` into `DaemonError::Storage`, which
prints the storage open's own single-prefix line, the one #124 was misfiled on.
`refresh_startup_rows` did the same for `read_back_record` and
`DurableIndex::refresh`.

The repair is structural rather than a list of `map_err` arms:
`commit_startup_plan` and `refresh_startup_rows` return `RuntimeError`,
`reconcile_recovered_session_scope` carries the loop, and
`reconcile_recovered_sessions` holds the **only** conversion to a `DaemonError`
and always adds `ReconstructionSurface::RecoveredSessions`. An inner step
cannot escape unlabelled because it has no way to build a `DaemonError` at all.
No error kind changed and no live path changed. This surface is not what
refused here, and it is now identified if it ever does.

## What is not settled

- **The rate is measured, not bounded.** Three refusals in 209 kills at this
  population is the only number this work has. It says nothing about the rate
  at the advertised 50,000-client population, where the windows are the same
  width but far more numerous.
- **The 512-client probe saw none.** One drill ran 24 kills at 256 clients per
  edge and refused nothing, which at one in seventy is the expected outcome and
  settles nothing either way.
- **Only the active generation was relaxed.** A pending generation's rows are a
  coordinator snapshot and keep the closed install. If some other state `apply`
  can reach is also outside what the restore rebuilds, this work did not find
  it; the drill is the vehicle that would.
- **The production campaign is still not run.** The peer-loss scenario at the
  advertised population still needs the host budget the capacity record names.
- **The campaign alone is not an acceptance for this.** Five campaign runs and
  five peer-loss kills saw nothing, because one kill per run cannot reach a
  one-in-seventy race. The drill is what an acceptance has to run.

## Commands

Run from the branch worktree.

```text
cargo test -p agenc-ircd-runtime --all-features
cargo test -p agenc-ircd-domain --all-features
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo fmt --all
python3 scripts/check-source.py check
```

Results are recorded in the pull request, with the two launcher commands above.
The storage suite was not re-run: no storage source changed.
