# Stage 10 edge restore refusal causes

This record continues RUN-08 (issue #134) from [the edge startup
reconstruction record](stage-10-edge-startup-reconstruction.md), which narrowed
the failure and left one hypothesis untested:

> Two arms swallow a non-`StaleState` cause into `StaleState`:
> `edge.replica.install(...).map_err(|_| invalid())` in
> `Restore::install_projection`, and `companion.snapshot_finish_restore()` in
> `E2eeEdge::finish_snapshot_restore`. Under a budget that admits more live
> state than the restore can rebuild, an allocation refusal from either one
> prints as a stale-state refusal.

**The hypothesis does not hold.** Neither inner call has an allocation or an
admission path at all, so neither arm can be reached by one. That is settled by
construction below. The arms are still repaired, because discarding a cause is
a defect in its own right, and a different capacity defect — a real one, with
exactly the admission-versus-restore shape the hypothesis was reaching for —
was found beside them and fixed.

## The classification, by construction

### `edge.replica.install(...)` in `Restore::install_projection`

`EdgeReplica::install` (`crates/agenc-ircd-domain/src/federation/replica.rs`)
returns `Result<(), ReplicaError>`, and `ReplicaError` is a closed eight-arm
enum. Every arm is a statement about the entries themselves:

| arm | what it states |
| --- | --- |
| `UnknownEntity` | an entry names or duplicates an entity the replica does not hold |
| `WrongHome` | a home projection or membership belongs to another edge |
| `Revision` | a revision regressed, jumped or repeated inconsistently |
| `HomeSessionRevision` | a home-session revision is present or absent contrary to locality |
| `DanglingReference` | a membership, invite or child record names an absent parent |
| `SnapshotOrder` | the entry set is not unique and sorted |
| `ChildrenRemain` | a channel is hidden while local children remain |
| `InvalidRecord` | a record's fields violate a B.4 invariant |

None of them is an allocation or an admission refusal, and none can become one:
`EdgeReplica` is a domain value with five `BTreeMap`s, it never touches
`MemoryBudget`, it never calls `try_reserve`, and it has no `MemoryExhausted`,
`LimitExceeded` or `Overflow` arm to return. A heap failure inside it aborts
through the global allocator rather than returning, so there is no value of the
process memory budget at which `install` reports one.

### `companion.snapshot_finish_restore()` in `E2eeEdge::finish_snapshot_restore`

`snapshot_finish_restore`
(`crates/agenc-ircd-runtime/src/e2ee/edge/snapshot.rs`) returns
`Result<(), Refusal>` and has exactly two `Err` sites, both inside one `if`:
`usize::try_from(snapshot.total)`, unreachable on a 64-bit target, and the
condition it guards, which is `snapshot.pending.route_objects.len() !=
snapshot.total` for a `Stage::Ready` generation. Both produce
`E2eeReplyCode::Syncing`. The only fact either states is that a READY
generation's restored pending-route rows do not add up to the count its own
durable marker names. It reads no budget and reserves nothing.

The companion restore *does* have an admission path, one step earlier:
`snapshot_restore_entry` reserves every restored row's bytes through
`BackingReservationPort::reserve`, and `WitnessRecovery::restore` reserves its
own backing the same way. Both already propagate `RuntimeError::MemoryExhausted`
unchanged, at `EdgeRestoreStep::CompanionState`, so a companion snapshot that
cannot be rebuilt within the configured budget already refuses as an exhausted
budget and never reaches `snapshot_finish_restore`.

### So the pilot's asymmetry is not these two arms

The four-GiB run failing where the one-GiB control survived is not explained by
either arm, and this record claims no explanation for it. What it does settle is
that the two arms named in #134 cannot be the mechanism, so a recurrence that
prints `edge-projection-install` or `companion-snapshot-restore` is a statement
about the restored rows and not about how much memory the node was given.

## The capacity defect that is real

`Restore::charge` held **one** pool, `MAX_RESTORE_BYTES = 536_870_912` and
`MAX_RESTORE_ROWS = 1_000_000`, and charged six record families into it: the
active generation's projection entry rows, the pending generation's projection
entry rows, and the companion witness, route, pending-route and barrier rows.

Those two numbers are the fixed standing-projection ceilings of spec 20.8, and
they are what the live path admits for **one** projection generation:
`sync::snapshot_start` refuses an entry count above `MAX_SNAPSHOT_ENTRIES` and
`sync::snapshot_entry` refuses aggregate bytes above `MAX_SNAPSHOT_BYTES`
(`crates/agenc-ircd-runtime/src/federation/edge/sync.rs`).

An edge holds two generations' entry rows at once by design. `sync::snapshot_active`
switches the peer row to the new generation and writes the ACTIVE marker without
deleting the superseded entry rows in that batch; retention sweeps them
afterwards. The restore's own invariant depends on it: `install_projection`
requires `active_entry_count` to equal the restored active entry count while
`pending_generation` is `Some`, so both generations' rows must be durable
together. `Restore::projection` charges both of them, and a `MemoryExhausted`
refusal was therefore reachable at up to half of what the admission side can
admit — 1 GiB of entry objects, or two million entry rows, before a single
companion row is charged.

**A restore that cannot rebuild an admitted projection is not a legitimate
refusal.** It bricks a node that crossed no ceiling, and it does so only after a
kill, so the node runs correctly until the moment it is restarted. The bound
belongs on the admission side, and the admission side already has it: each
generation is bounded at the spec-20.8 ceiling when it is installed. The restore
now charges against those same bounds, per family, so it fits every state the
admission side can admit:

- the active generation against `MAX_GENERATION_BYTES` / `MAX_GENERATION_ROWS`,
- the pending generation against its own copy of the same two numbers,
- the companion, barrier and delivery rows against `MAX_COMPANION_BYTES` /
  `MAX_COMPANION_ROWS`.

No spec ceiling moved and no live admission path changed. Every pool still
**fails closed** at its own ceiling, with `RuntimeError::LimitExceeded` and a
named cause, and nothing is ever installed partially: `install_projection`
builds the whole entry set before `EdgeReplica::install` replaces the replica in
one move, and `install` itself validates a candidate and only then assigns it.

## The decision on causes

**A refusal from an allocation, an admission or a ceiling path must not print as
`StorageError::StaleState`.** That is what sent #124 to the storage layer.
`EdgeRestoreRefusal` therefore carries a third field beside the step that PR
#138 added:

```rust
pub struct EdgeRestoreRefusal {
    pub step: EdgeRestoreStep,
    pub cause: EdgeRestoreCause,
    pub error: RuntimeError,
}
```

`EdgeRestoreCause` (`crates/agenc-ircd-runtime/src/federation/edge/startup.rs`)
names `Unclassified`, `ActiveProjection(ReplicaError)`,
`PendingProjection(ReplicaError)`, `ActiveProjectionCeiling`,
`PendingProjectionCeiling`, `CompanionCeiling`, `CompanionSnapshotIncomplete`,
`BarrierAssembly(BarrierFault)` and `MissingAdmissionPort`.
`ReconstructionSurface::EdgeFederation` carries it, and prints
`edge federation restore at {step} ({cause})`; an `Unclassified` cause prints
the line PR #138 already produced, unchanged, so the previously pinned string
still holds.

Five arms stopped destroying what they were given:

- `Restore::install_projection` keeps the `ReplicaError` as
  `ActiveProjection(..)`. The error stays `StaleState`, which is the right kind:
  the replica's arms are all statements about the restored rows.
- `sync::restore_pending` keeps the verifying replica's `ReplicaError` as
  `PendingProjection(..)`.
- `E2eeEdge::finish_snapshot_restore` records
  `CompanionSnapshotIncomplete`, and keeps `StaleState` for the same reason.
- `install_stage` keeps the `BarrierFault`. `BarrierFault::Aggregate` — "barrier
  aggregate bytes over the ceiling" — now raises `RuntimeError::LimitExceeded`
  instead of `StaleState`, because an aggregate over a ceiling is an admission
  fact, not a disagreement between rows. Every other fault stays `StaleState`.
- `sync::verify_restored_cut` raised `StaleState` for
  `marker.entry_count > MAX_SNAPSHOT_ENTRIES` and for
  `bytes > MAX_SNAPSHOT_BYTES`, which are the same two conditions the live
  install reports as `Violation::Ceiling`. They now raise
  `RuntimeError::LimitExceeded` with `PendingProjectionCeiling`.

Two more kinds were corrected while the causes were threaded: `Restore::charge`
reported its own `checked_add` overflow as `StaleState` and now raises
`RuntimeError::Overflow`, and `restore_steps` reported a missing
`BackingReservationPort` as `StaleState` and now raises
`RuntimeError::InvalidValue` with `MissingAdmissionPort`.

Decode arms were left alone. `SchemaObject::decode_exact`,
`IrcWireObject::decode_kind`, `decode_projection_arm` and their neighbours mean
exactly "this durable object does not decode under its schema", which is stale
durable state and is already what the step label points at.

## Evidence

- `crates/agenc-ircd-runtime/src/federation/edge/tests/reconstruction_pools.rs`
  drives the restore's accounting directly.
  `both_projection_generations_and_the_companion_rows_fit_beside_one_another`
  charges each generation a whole standing-projection ceiling and then the
  companion pool a whole ceiling of its own; the second charge is the one the
  single pool refused.
  `each_pool_fails_closed_at_its_own_ceiling_and_names_the_ceiling` and
  `each_generation_admits_its_whole_admitted_entry_count_before_it_refuses`
  require every pool to refuse one byte and one row past its own ceiling with
  `RuntimeError::LimitExceeded` and the cause that names it, so the repair did
  not open a hole.
- `crates/agenc-ircd-runtime/src/federation/edge/tests/reconstruction_cause.rs`
  seeds durable rows through the real storage owner.
  `a_projection_the_replica_refuses_names_the_replica_and_not_the_storage_layer`
  commits a coordinator row counting one standing entry and one `EdgeProjection`
  entry row holding a membership whose channel and member were never projected,
  and requires the whole operator-visible line:

  ```text
  runtime startup failed: edge federation restore at edge-projection-install
  (active projection: federation replica reference does not resolve) refused the
  recovered state: storage owner failed: storage state is stale or inconsistent
  ```

  `an_unnamed_refusal_still_prints_the_line_the_step_label_alone_produced` pins
  the unchanged `Unclassified` rendering beside it.
- `e2ee::edge::tests::snapshot::an_incomplete_ready_generation_refuses_the_restore`
  already drove an incomplete READY generation through a real commit and reload;
  it now pins `companion-snapshot-restore (companion snapshot generation is
  incomplete): storage owner failed: storage state is stale or inconsistent`
  instead of asserting only that the restore refused.
- `daemon::tests::every_startup_refusal_prints_the_reconstruction_that_refused`
  gains the ceiling line, so an admission refusal is pinned never to render as
  the stale-state line that misfiled #124.

## What is still unexplained

- **The CAP-01 refusal is still unexplained and still unreproduced.** This
  record eliminates the last hypothesis #134 carried; it does not replace it.
  The captured line is `RuntimeError::Storage(StorageError::StaleState)` raised
  after `StorageOwner::start` returned, and the surfaces that can raise it are
  the durable state reconstruction, the recovered session reconciliation, the
  edge federation restore and the history load — all four of which PR #138
  already labels, so a recurrence identifies itself.
- The capacity defect repaired here **is** capacity-dependent in the direction
  the pilot observed, but it is not the pilot's line: it refuses with
  `runtime ceiling exceeded`, never with `storage state is stale or
  inconsistent`. It cannot be the failure CAP-01 captured.
- The peer-loss acceptance re-run at the published 6,442,450,944-byte budget was
  not performed. It needs the production campaign, which is still blocked on the
  Section 19.3 conflict in #113.
- The two projection ceilings are not driven end to end. Reaching one through
  real durable rows requires 512 MiB of entry objects or a million entry rows,
  so the accounting is driven directly instead; the end-to-end cases drive the
  cause-preservation half.

## Commands

Run from the branch worktree.

```text
cargo test -p agenc-ircd-runtime --all-features
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo fmt --all
python3 scripts/check-source.py check
```

Results are recorded in the pull request. No storage source changed, so the
storage suite was not re-run.
