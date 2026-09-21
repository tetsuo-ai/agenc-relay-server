# Stage 10 edge startup reconstruction after a kill

This record covers RUN-08 (issue #134), the successor to STO-10 (#124). CAP-01's
capacity pilot SIGKILLed edge B in `scenario_peer_loss` and the restarted daemon
refused to come up with

```text
agenc-relay-server: runtime startup failed: storage owner failed: storage state is
stale or inconsistent
```

after which the cycle failed with "edge never established its coordinator link".

**The defect is unreproduced.** No half-built durable state that a kill can
leave behind was found to refuse the edge's startup reconstruction. This record
states exactly what was driven, what it rules out, and what evidence would
settle the remainder. It changes no writer ordering and adds no reconciliation.
It does make the refusal operator-actionable, which is the part of #134 that can
be delivered against a negative result: the line above named neither the surface
nor the record, which is precisely why the failure was first filed against the
wrong component.

## Where the refusal cannot be

The storage open is already cleared by proof. `arcd serve` prints
`agenc-relay-server: {DaemonError}`; `DaemonError::Storage` renders as `storage owner
failed: {error}` alone and only `DaemonError::Runtime` adds `runtime startup
failed: `. The captured line carries both prefixes, so it is raised after
`StorageOwner::start` returned, and STO-10's fault sweep over all 31
`StorageFaultSite`s across both guard publications shows the guard pair already
reconciles every disagreement the publication order can produce and refuses
everything else ([the storage guard reopen record](stage-10-storage-guard-reopen.md)).

`state_core/reconstruct.rs` holds 82 of the runtime's `StaleState` sites, 66 of
them reachable, but it cannot see any edge-shaped state. Its scan admits
`RequestResult`, `FederationPeer`, `FederationOrigin`, `EdgeOutbox`,
`EdgeProjection`, `E2eeObject`, `E2eeState`, `Audit` and `AuditCheckpoint` for
identity and sizing only (`crates/agenc-relay-runtime/src/state_core/reconstruct.rs`,
the `Ok(())` arm at the end of `admit`). Every invariant it enforces is over the
account, channel, session and account-service tables, which edge B's kill under
load does not tear: the four shapes #134 names — a standing projection, a
barrier assembly, a durable outbox and live sessions — are all in the tables
`reconstruct` only indexes. So the durable reconstruction is not the surface for
this shape either, and the candidates are the two edge restores and the daemon's
own recovered-session reconciliation.

## The writer, exactly

Every edge write reaches storage through one atomic transaction, and the edge
serializes its own writes: `events::stage_rows`
(`crates/agenc-relay-runtime/src/federation/edge/events.rs`) refuses while
`edge.commit.is_some()`, and **it appends the peer row to every batch it
stages**. A SIGKILL therefore leaves exactly a prefix of committed batches, and
the question is only whether any logical operation spans more than one batch in
a way the restore cannot prove.

Three do span more than one batch, and all three are same-kind bulk drains with
explicit prefix ordering:

- The journal drains at most `BATCH_ROWS = 64` dirty identities per commit
  (`federation/edge/journal.rs`). `Identity` derives `Ord` with `Origin` before
  `Request`, so a `BTreeSet` prefix always drains origins first and a request
  row can never become durable ahead of the origin row that
  `journal::restore_request` requires.
- A snapshot install writes `INSTALL_BATCH_ROWS = 256` entry rows per commit and
  pushes the generation marker only into the last one
  (`federation/edge/sync.rs`). `sync::pending_generation` returns `Some` only
  once `staged_end == entries.len()`, so the peer row does not name the
  generation until the marker is in the same batch; entry rows from a truncated
  install are named by no peer row and `Restore::projection` ignores them.
- Barrier retention deletes at most `MAX_CLEANUP_ROWS = 999` rows per commit
  (`federation/edge/retention.rs`), pushing the head last so it is deleted last,
  and in `cleanup_fenced` pushing each payload before its last durable
  reference.

Every cross-kind coupling the restore checks is written in one batch: the
completion-coverage row with the delivery cursor that covers it
(`journal::completion_write` inside the same `stage_rows` batch as the peer
row), the barrier head with its part and payload (`barrier::stage_part`), and
the ACTIVE marker with the peer row that counts its entries
(`sync::snapshot_active`).

## The reproduction

The capacity campaign is not needed. `crates/agenc-relay-runtime/src/federation/edge/tests/kill_reconstruction.rs`
drives a live edge synchronously through the real writers and, **after every
commit**, reconstructs a fresh `EdgeFederation` from exactly the rows storage
holds at that moment. Each commit boundary is a durable prefix a SIGKILL can
leave, because a kill cannot stop a redb two-phase commit anywhere else and the
storage layer's own reopen at those boundaries is already proven.

- `an_edge_killed_under_load_reconstructs_every_durable_journal_prefix` opens 40
  connection origins and one federated session-open request on each, which is 80
  dirty journal identities against the 64-row bound, so the drain tears across
  commits exactly as it does under load. Every prefix reconstructs. The test
  requires more than one commit, so a change that made the drain fit in one
  batch would fail it rather than silently stop proving anything.
- `an_edge_killed_under_load_reconstructs_every_durable_event_prefix` builds a
  40-entry standing projection out of delivered `SessionVisible` events, so
  every entry row it names is durable beside the peer row that counts it, then
  adds the same 80-identity journal load and delivers eight further projection
  events, reconstructing after every commit of all three. Every prefix
  reconstructs.

Both refuse nothing. The barrier assembly's own windows are already swept by the
existing crash-image suite in
`crates/agenc-relay-runtime/src/federation/edge/tests/restart.rs`: collection
with one part received and with the complete set, the payload-missing refusal,
the wrong-incarnation refusal, the apply that turns the stage head into a
receipt and restarts both committed cursors, the companion part that commits its
payload with the collecting head, and the retained-image cases for receipt
cleanup. Those cases were left alone rather than duplicated.

An earlier iteration of the event sweep did reproduce the exact captured line.
It was a defect in the test, not in the edge: it installed the standing
projection into `edge.replica` in memory without writing the entry rows, so the
first peer row it committed carried an `active_entry_count` of 41 against one
durable entry row and `Restore::install_projection` correctly refused. That is
worth recording because it is the shape a real writer-ordering defect would
have, and it confirms that the count invariant bites.

## The decision

**No writer ordering changed and no reconciliation was added.** Only an exactly
characterised reachable case may reconcile, and no such case was found; every
state the reconstruction cannot prove still refuses, unchanged.

What did change is the identification the daemon prints. `storage state is
stale or inconsistent` names neither the surface nor the record. The error type
keeps its meaning — the refusals are still
`RuntimeError::Storage(StorageError::StaleState)` and the arithmetic of
`DaemonError::Storage` and `DaemonError::Runtime` is untouched — and the
identification is added where the daemon reports it:

- `DaemonError::Reconstruction(ReconstructionSurface, RuntimeError)`
  (`crates/agenc-relay-runtime/src/daemon.rs`) is the labelled refusal. It
  renders as `runtime startup failed: {surface} refused the recovered state:
  {error}`.
- `ReconstructionSurface` names `durable state reconstruction`, `recovered
  session reconciliation`, `edge federation restore at {step}` and `history
  reconstruction`. The daemon labels `reconstruct`,
  `reconcile_recovered_sessions` (through `startup_stale_state`),
  `router.restore_edge` and `HistoryState::load` at their call sites.
- `EdgeRestoreStep`
  (`crates/agenc-relay-runtime/src/federation/edge/startup.rs`) names the record
  family the edge restore had reached:
  `companion-witness-backing`, `federation-peer-record`,
  `edge-projection-rows`, `edge-projection-install`,
  `federation-origin-journal`, `request-result-journal`, `e2ee-state-rows`,
  `companion-snapshot-restore` and `barrier-install`. `EdgeFederation::restore`
  records the step it is on and returns `EdgeRestoreRefusal { step, error }`.

The same kill would now print, for example:

```text
agenc-relay-server: runtime startup failed: edge federation restore at barrier-install
refused the recovered state: storage owner failed: storage state is stale or
inconsistent
```

which names the owner and the record family from the stderr line alone. Had this
existed, #124 could not have been filed against the storage open.

## What is not settled

- The pilot's own conditions were not reproduced. CAP-01 saw the failure once,
  at the restored Appendix C.2 four-GiB budget, against a control run at the
  Stage 08 fixture's one-GiB budget; one run each, and no causation is claimed
  by the budget. The sweeps here run a 40-connection load, not the advertised
  50,000-client population, and they drive the writers directly rather than
  through TLS links and the actor loop.
- The acceptance #134 asks for — re-running the capacity campaign's peer-loss
  scenario at the current published budget — was not run. It needs the
  production campaign, which is itself blocked on the Section 19.3 conflict in
  #113.
- Two refusal paths in the edge restore swallow a non-`StaleState` cause into
  `StaleState`: `edge.replica.install(...).map_err(|_| invalid())` in
  `Restore::install_projection` and
  `companion.snapshot_finish_restore().map_err(|_| invalid())` in
  `E2eeEdge::finish_snapshot_restore`. Under a budget that admits more state
  than the restore can rebuild, an allocation refusal from either would print as
  a stale-state refusal. That is consistent with the pilot's budget observation
  and is not ruled out here, because the sweeps run well inside their
  reservations. **This is the evidence that would settle it**: capture the
  restarted edge's memory accounting at the moment of the refusal, or run the
  peer-loss kill at the published budget with those two `map_err` arms
  distinguishing their causes. The new step label already narrows the target to
  one of `edge-projection-install` or `companion-snapshot-restore` if it is
  this.

## Commands

Run from the branch worktree.

```text
cargo test -p agenc-relay-runtime --all-features
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo fmt --all
python3 scripts/check-source.py check
```

Results are recorded in the pull request. The storage suite was not re-run: no
storage source changed, and STO-10 already pins the reopen.
