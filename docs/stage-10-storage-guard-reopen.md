# Stage 10 storage guard pair and the reopen after a kill

This record covers STO-10 (issue #124). It was filed on CAP-01's reading that
a SIGKILL at the published Appendix C.2 memory budget left edge B unable to
reopen its storage because `verify_guard_pair`
(`crates/agenc-relay-storage/src/control.rs`) refused the database/guard pair.

**That reading is wrong, and this record withdraws it.** The refusal CAP-01
captured cannot have come from the storage open at all, and the exhaustive
crash matrix added here shows the guard pair already reconciles every
disagreement the publication order can produce and already refuses everything
else. No storage behaviour changed. The real refusal is raised after the open
succeeds, and it needs its own issue against the edge's startup
reconstruction.

## The publication window, exactly

Every durable storage operation publishes its control state twice. For an
ordinary commit, `StorageEngine::commit_inner`
(`crates/agenc-relay-storage/src/engine.rs`) performs, in this order:

1. `reserve_nonce_block` writes the `NonceReserved` reservation record through
   `RedbStore::write_meta`, which is an `Immediate`, two-phase redb commit, so
   the record is durable when the call returns.
2. `install_reserved_guard` replaces the guard file through
   `StateDirectory::replace_guard`: create-exclusive temporary, `fsync`,
   `renameat`, parent-directory `fsync`, then a read-back comparison. The
   guard is durable and atomic when the call returns.
3. `commit_records` writes the mutations, the manifest, the new StateMeta and
   the `Committed` reservation record in one `Immediate`, two-phase redb
   transaction.
4. `replace_guard` publishes the committed guard.

`install_scanned_checkpoint` performs the same four steps around
`commit_checkpoint`, and initialization performs `initialize_database` before
`install_initial_guard`. **In every path the in-database record is durable
before the guard that names it is replaced.** A guard can therefore only lag
its record, never lead it.

A kill stops that sequence after one of exactly five durable prefixes, and
each one is a state `classify_recovery_state`
(`crates/agenc-relay-storage/src/recovery.rs`) already names:

| prefix | database record | on-disk guard | disposition |
| --- | --- | --- | --- |
| before 1 | committed, sequence *r* | committed, *r* | `ExactCommitted` |
| after 1 | reserved, *r+1* | committed, *r* | `InstallReservedGuard` |
| after 2 | reserved, *r+1* | reserved, *r+1* | `ExactReserved` |
| after 3 | committed, *r+1* | reserved, *r+1* | `InstallCommittedGuard` |
| after 4 | committed, *r+1* | committed, *r+1* | `ExactCommitted` |

A two-step divergence would require the database to advance twice across one
unpublished guard. It is unreachable: step 2 sits between steps 1 and 3, a
failure there is either `Rejected`, which returns before step 3 and leaves the
engine's own record unchanged, or `Indeterminate`, which closes the owner.

## The decision

**The in-database reservation record is authoritative and the guard is
repaired from it; `verify_guard_pair` stays an exact equality fence and
reconciles nothing.**

This is the behaviour already implemented, and it is the right one. The record
is the side that is made durable first and the side that the commit binds to
the data, the manifest and the StateMeta inside one transaction. The guard is
an independently authenticated external witness of that record, so a reopen
that finds them one publication step apart can rebuild the guard from the
record, but a reopen that finds them any other distance apart has no proof of
which side is real and must refuse.

`reconcile_open_guard` therefore repairs only `InstallReservedGuard` and
`InstallCommittedGuard`, and only after `classify_recovery_state` has checked,
for the candidate successor, the predecessor's own complete guard hash, the
complete header hash, the database instance, the reservation sequence, the
nonce-block boundary, the commit, manifest and state-generation sequences and
the StateMeta record binding. Everything else is `StorageError::StaleState`.
The two decisions are now written into the doc comments of
`verify_guard_pair` and `classify_recovery_state` so the next reader does not
have to rediscover the ordering to know why the fence is exact.

Nothing in the publication order needed to change, so no production source
changed: this work adds test evidence and doc comments only.

## Why the CAP-01 refusal was not the guard pair

CAP-01 recorded the daemon's exact stderr line:

```text
agenc-relay-server: runtime startup failed: storage owner failed: storage state is
stale or inconsistent
```

`arcd serve` prints `agenc-relay-server: {DaemonError}`
(`crates/agenc-relay-server/src/main.rs`). `DaemonError::Storage` renders as
`storage owner failed: {error}` and `DaemonError::Runtime` renders as
`runtime startup failed: {error}`, which for `RuntimeError::Storage` adds its
own `storage owner failed: {error}`
(`crates/agenc-relay-runtime/src/daemon.rs`,
`crates/agenc-relay-runtime/src/error.rs`). The captured line carries **both**
prefixes, so it is
`DaemonError::Runtime(RuntimeError::Storage(StorageError::StaleState))`.

`LiveStorage::open` opens storage with
`StorageOwner::start(storage_open_config(...))?`, whose `?` converts
`StorageError` through `From<StorageError> for DaemonError` into
`DaemonError::Storage`. A refusal from `verify_guard_pair`, from
`classify_recovery_state`, from `validate_open_accounting` or from
`startup_scan` can only produce the single-prefix line. It is the only
`StorageOwner::start` on the live daemon path.

So edge B's storage opened, reconstructed and reported its recovered state,
and the daemon then refused during runtime startup. `daemon.rs`'s
`startup_stale_state`, the edge federation restore
(`crates/agenc-relay-runtime/src/federation/edge/startup.rs`), the edge E2EE
restore (`.../e2ee/edge/startup.rs`) and the durable reconstruction
(`crates/agenc-relay-runtime/src/state_core/reconstruct.rs`, which alone holds
82 of the runtime's `StorageError::StaleState` sites) all produce exactly that
two-prefix line. Edge B is an edge under load with a projection, a barrier
assembly, an outbox and live sessions, so those are the surfaces a kill can
leave half-built.

`daemon::tests::a_storage_open_refusal_and_a_later_startup_refusal_print_different_lines`
pins both strings so this distinction cannot rot.

## What is now proven

`crates/agenc-relay-storage/tests/guard_reopen.rs` abandons a real storage
owner inside the publication window and reopens the same directory. The
abandonment is the owner's own indeterminate failure, which closes the owner
without any shutdown checkpoint, so the directory keeps exactly the durable
prefix a kill at that boundary would have left.

- `every_commit_guard_publication_boundary_reopens_at_its_prior_or_successor_state`
  and
  `every_checkpoint_guard_publication_boundary_reopens_at_its_prior_or_successor_state`
  abandon both guard publications of a commit and of an explicitly requested
  checkpoint at all five boundaries of `replace_guard`
  (`guard-temporary-create`, `guard-write`, `guard-file-sync`,
  `guard-rename`, `guard-directory-sync`), on both the before and after side:
  40 abandonments in all. Every one reopens, and reopens at exactly the prior
  commit sequence for the reserved publication and exactly the successor for
  the committed publication.
- `a_guard_one_publication_step_behind_its_committed_database_reconciles_from_the_record`
  is the reconcilable disagreement on its own: it captures the lagging guard,
  requires the reopen to report the successor state, requires the published
  guard to have changed, and requires a further reopen to find an exact pair
  that it neither refuses nor rewrites again.
- `a_guard_two_publication_steps_behind_its_committed_database_still_refuses`
  takes the same window and pushes the guard one publication step further
  back — the committed guard of the previous state, published over the
  directory through `StateDirectory::replace_guard`, a distance no kill can
  produce — and requires `StorageError::StaleState`.
- `an_exact_pair_reopens_without_rewriting_its_guard` is the clean control: a
  cleanly closed directory reopens at its committed sequence with the guard
  file byte-identical, twice.

A negative control confirms the cases bite: with the two repairing arms of
`reconcile_open_guard` replaced by `Err(StorageError::StaleState)`, the three
reconciliation cases fail and the two fail-closed cases still pass.

The existing per-field negatives stay where they are:
`codec_matrix.rs` mutates thirteen guard fields against `verify_guard_pair`
and `recovery_matrix.rs` drives the synthetic four-state matrix, including
every invalid successor. This record adds the on-disk, real-owner half of that
evidence.

## Limitations

- **The real CAP-01 failure is not reproduced here and is not fixed here.**
  This record disproves the attribution and bounds the storage open; it does
  not identify which runtime startup fence refused. That needs a killed edge
  under load, which is the capacity campaign's own environment, and it should
  be a new issue against the edge startup reconstruction rather than against
  the storage open path.
- The abandonment is an injected indeterminate failure at a logical boundary,
  not a signal. For this window the two are equivalent — a process kill and an
  abort at a boundary both leave a durable prefix of the same ordered writes,
  and `StorageFaultSite`'s guard and two-phase-commit sites are exactly those
  boundaries — but no test in this record sends `SIGKILL` to a process.
- The matrix covers the commit and checkpoint publication windows. The
  offline construction, restore and login-index transition paths build a whole
  directory and install it by rename; they are covered by their own existing
  fault campaigns and are not re-driven here.
- `verify_guard_pair` is proved complete against the publication order of this
  source. It is not proved against a filesystem that reorders a completed
  `rename` behind a completed redb commit; the state directory's qualification
  requirements, not this record, carry that.

## Evidence

Sources:

- `crates/agenc-relay-storage/tests/guard_reopen.rs` — new, test-only, under a
  `tests` path component; `tests/stage_five.rs` gains one `mod` line and
  `tests/stage_five_completion.rs` raises four existing fixture helpers to
  `pub(crate)` so the new module can open the same live fixture.
- `crates/agenc-relay-storage/src/control.rs` and
  `crates/agenc-relay-storage/src/recovery.rs` — doc comments only, recording
  the ordering argument and the authority decision.
- `crates/agenc-relay-runtime/src/daemon.rs` — one added unit test in the
  existing `#[cfg(test)] mod tests`.

No production behaviour, wire format, storage format, dependency pin or limit
changed, and no normative requirement changed: ARCH-DUR-08 already states the
four admissible startup states and is already `implemented` in
`conformance/requirements.toml`. This work adds evidence for it.

Commands and results at this branch:

```sh
cargo test -p agenc-relay-storage --all-features --test stage_five guard_reopen
# 5 passed; 0 failed; 116 filtered out

cargo test -p agenc-relay-storage --all-features -- --skip qualification_workload
# 217 passed and 120 passed; 0 failed

cargo test -p agenc-relay-runtime --all-features --locked --lib
# 1,530 passed; 0 failed; 1 ignored

cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
# clean

cargo fmt --all
python3 scripts/check-source.py check
# source policy: ok (981 Rust files)

python3 /mnt/data/agenc-dev/tools/verify-regions.py .
# conformance/critical-coverage.toml 21 regions
# conformance/release-critical-coverage.toml 1144 regions
# stale regions: 0
```

The coverage source inventory in `conformance/critical-coverage.toml` and
`conformance/release-critical-coverage.toml` is reanchored to the 824 current
production sources. The added doc comment moves `classify_recovery_state` and
its two helpers down twelve lines, so the whole-file
`storage-recovery-state-classification` region and the three
`crates/agenc-relay-storage/src/recovery.rs` release regions move with them. No
region changed what it covers and no region digest beyond those files changed.

`qualification_workload::production_workload_measures_every_required_case_and_phase`
is skipped above because it is not stable on this development host: it
`fallocate`s an 11.1 TB ballast under `CARGO_TARGET_TMPDIR` to drive the
shared filesystem to its reserve boundary, and its own raw log reports
`boundary-unstable|reserve-minus-one` while other work is building on the same
filesystem. It fails identically at the merge base `165570e` with this
branch's changes stashed, so it is not a regression from this work, and it was
not re-run afterwards so as not to disturb the other worktrees on that
filesystem.
