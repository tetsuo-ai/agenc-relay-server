# An edge drains with a snapshot install outstanding

This record covers RUN-11 (issue #178). An edge asked to stop exited 1 with
`daemon shutdown exceeded its deadline: phase=drain` whenever a base snapshot
install was outstanding and its coordinator was slow or gone. The `rr`
recording `/mnt/data/agenc-dev/sweep/rr/rotation/trace-1` (edge pid 2671151)
showed every thread parked at the timeout and, walking back,
`EdgeFederation::reload_ready` returning `false` for a `SnapshotInstall {
verified: true, ready_sent: true, written: 0 }`. The state owner acknowledges
`Drain` only at a reload-ready safe point, so the edge waited for an `ACTIVE`
that only the coordinator can send, through drain and then flush.

## The decision per install stage

`reload_ready` still refuses a safe point for every install stage while the
edge is running, so a reload never activates across a generation change. Once
StateCore starts the router's shutdown (which it does only with no storage
work in flight), `EdgeFederation::begin_shutdown` marks the edge as stopping
and `sync::abandon_for_shutdown` applies this table; from then on only a
staged install batch holds the safe point (`sync::holds_safe_point`).

| Stage | Durable at that point | At shutdown | The next start |
| --- | --- | --- | --- |
| receiving (`verified == false`) | nothing | abandoned | sends `FRESUME`; the coordinator offers the snapshot again |
| installing, a batch staged | the staged batch | the batch settles, the remaining batches are abandoned | ignores the rows of a generation the peer record does not name; sends `FRESUME` |
| ready-sent | every row, the `Pending` marker and the peer's `pending_generation` | the wait for `ACTIVE` is abandoned | `restore_pending` rebuilds the install and `begin` sends `READY` again, or drops it for a changed coordinator epoch or incarnation and resumes |
| switching (`SnapshotActivated` staged) | the swap commit | finishes: it is a local durable commit, held by `commit` and the in-flight batch | stands on the new generation |

Each abandonment leaves exactly what a crash at the same point leaves, which
startup already reconciles, so no new durable shape exists. An install is up
to 1,000,000 rows in batches of 256; `installed` therefore stops chaining
batches once shutdown is requested rather than spending the drain budget on
rows the next start requests again.

The companion E2EE transfer (`crates/agenc-ircd-runtime/src/e2ee/edge/snapshot.rs`)
needed no change. Its `Staging` and `Ready` stages never entered
`reload_ready`, so they never held drain; its `Active` migration and
`Discarding` cleanup are chains of local commits that a restart resumes from
the durable marker (`SnapshotInstall::restored`).

## Regressions

`crates/agenc-ircd-runtime/src/federation/edge/tests/shutdown_pending_install.rs`
runs the production edge actor over real redb storage against a scripted
coordinator, stops it through `run_shutdown` under the RUN-05 tightened plan
(2 s, 5 s, 5 s, 2 s), requires all four phases `Completed`, no stop-deadline
expiry and `StateCoreExit::Stopped`, then seals and reopens the same
directory and restores a fresh edge from it:

- `a_ready_sent_install_with_a_dead_coordinator_stops_clean_and_replays_ready`
  and `..._with_a_silent_coordinator_...`: `READY` was sent, `ACTIVE` never
  comes, with the link lost and with it open. The reopened edge holds the
  pending generation and its first frame on a new link is `READY` for the
  same identity.
- `a_receiving_install_is_abandoned_and_the_reopened_edge_resumes`: entries
  announced and never sent. The reopened edge holds no pending generation and
  sends `FRESUME`.
- `a_staged_install_batch_settles_and_the_rest_of_the_install_is_abandoned`:
  a 300-row snapshot with the first batch's commit receipt withheld. The stop
  is observed still waiting while the receipt is held, completes once it is
  released, exactly 256 rows are durable, and the reopened edge ignores them
  and sends `FRESUME`.
- `a_staged_generation_swap_finishes_before_the_edge_stops`: `ACTIVE`
  arrives and the swap's receipt is withheld. The stop waits, then completes,
  and the reopened edge stands on generation 2 with nothing pending.

With the fix neutralized the first three time out in drain, which is the
defect; the last two pass either way. The staged-batch case passes without
the new `installed` guard because staging the next batch is already refused
while quiescing, which ended the link through a violation; the guard reaches
the same durable state without failing the link.

## What `flush` waits on: a different family, not patched

The `phase=flush` exits seen under extreme load were recorded without CPU
hogs in `/mnt/data/agenc-dev/sweep/rr2/recovering/trace-1` (edge pid 3433368,
built with this fix: `Drain` completes there with its coordinator dead). At
the flush timeout the state owner's last safe-point evaluation still has
`lifecycle_target == Drain`: the flush hook had not yet asked the state owner
to flush. `flush_admin_and_state` awaits the admin owner's flush first, and
that is `retention_sweep`, whose `spawn_blocking` scan returns only after the
timeout. The one busy thread at the timeout is that scan, in
`AuditExportSource::retention_tbs` → `scan_events` →
`EventVerifier::verify_event` → `ed25519_dalek::verify_strict`: every
shutdown re-verifies the signature of every retained audit event inside the
flush budget. That is local CPU-bound work proportional to the audit log, not
a wait on a remote peer, so it is reported here and left for its own issue.

## Limitations

- As in RUN-05, the regressions prove ordering and the reopened state under a
  tightened plan, not the native ext4 shutdown deadline (STO-03, #61).
- No regression starts a snapshot after shutdown has begun; that path is
  covered only by the `stopping` rule in `holds_safe_point` and `installed`.
