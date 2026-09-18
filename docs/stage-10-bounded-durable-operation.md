# Stage 10 bounded durable operation

This record covers STO-03 (issue #61): every durable operation on the core
write path is now charged against one physical growth allowance derived from
Section 19.3's `G`, through the project-owned redb fork's bounded write
transaction ([the redb fork record](stage-10-redb-fork.md)). The issue's
"published upstream release" is that vendored source.

Before this change `StateDirectory::admit_transaction` sampled `R(F) + G` and
then `StorageEngine::commit_inner` committed the nonce reservation, replaced
the guard, committed the application rows and replaced the guard again through
redb's unrestricted API. The gate made room for `G`; nothing held an operation
to it. The gate is unchanged. The allowance is what makes `G` exact.

## The allowance, and how it is derived

`crates/agenc-ircd-storage/src/bounded.rs` holds `OperationAllowance`. One is
created per admitted operation, immediately after the `R(F) + G` gate:

1. It starts at `MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH = G = 268,435,456`.
2. Each guard replacement of the operation is charged first, as a fixed
   headroom at filesystem block granularity (`guard_replacement_charge`): the
   324-byte guard temporary rounded up to the block size, one directory block
   for the entry the temporary adds, and 32,768 bytes of inode allocation
   rounded up to the block size, which is one dynamically allocated inode
   chunk and bounds a preallocated inode table from above. On a 4 KiB
   filesystem that is 40,960 bytes per replacement. The rename frees the old
   guard's block afterwards, but nothing is refunded. A commit and a
   checkpoint replace the guard twice; initialization installs it once; a
   close replaces nothing.
3. The remainder is handed to the operation's redb transactions in turn. The
   nonce reservation is `begin_write_bounded(remainder)`; the bytes it reports
   charging are debited; the main (or checkpoint) transaction receives what is
   left; its charge is debited; the deferred cleanup receives the rest.

The fork's account debits every page extent at its rounded buddy-allocator
size and every file extension at its exact length, before the allocation
happens, and refunds nothing, so the allowance bounds the operation's physical
growth from above. It is a bound on bytes the operation may cause to be
allocated, not a measurement of the blocks a filesystem eventually backs.

`StorageStatistics::last_operation_charged_bytes` reports what the last
completed operation charged against `G`, guard headroom included. It is outside
the normative `STATS STORAGE` field order.

Every bounded transaction is `Immediate` and two-phase. The fork's bounded
handle originally exposed only an immutable view of the inner transaction, so
`set_two_phase_commit` was unreachable and a bounded publication was
single-phase, which Section 21.5 forbids and under which
`StorageFaultSite::TransactionPhaseTwo` never fires. That gap was reported and
the fork gained a narrow `BoundedWriteTransaction::set_two_phase_commit`
passthrough (PR #157); `RedbStore::begin_bounded_write` sets it on every
transaction, and the prepare-and-publish pair is wrapped in the same flush
counter that labels the two phases.

## The refusal mapping

| redb outcome | storage outcome |
| --- | --- |
| `StorageError::Allowance` or `TableError::Storage(Allowance)` from a table write or open | `Rejected(StorageError::AllowanceRefused(Mutation))`; the transaction is dropped and aborts |
| `CommitError::Allowance` from `prepare` | `Rejected(StorageError::AllowanceRefused(Preparation))`; the fork has already rolled the transaction back, re-marked every journaled page and left the next writer usable |
| `CommitError::TransactionPoisoned` from `prepare` | `Rejected(DatabaseRejected)`, as before |
| any other `prepare` failure | `Indeterminate`, as every commit error was before |
| any `publish` failure, whatever redb calls it | `Indeterminate` |
| `Error::Allowance` from `reclaim_bounded` or `persist_allocator_state_bounded` | `MaintenanceOutcome::Refused`; nothing was reclaimed or persisted and the database stays usable |
| any other reclaim or persist failure | uncertain |

`StorageError::AllowanceRefused(AllowancePhase)` is a new closed variant. The
phase (`mutation`, `preparation`, `cleanup`, `close`) is diagnostic only, in
the way `FilesystemCause` is. A refusal is never an I/O failure, never
`StaleState` and never `Indeterminate`. The runtime classes it `Rejected`
beside `LimitExceeded`, the admin backup path maps it to
`StorageUnavailable`, and the companion retirement loader paces it with the
other bounded refusals, because a later cleanup can change what the same shape
charges.

A refusal after the reservation leaves the reserved nonce block burned exactly
as any rejection past the reservation always has: the engine records the
reserved record and guard before it debits the reservation's charge, the next
operation reserves after the burned block, and a reopen classifies
`ExactReserved`. A refusal of the reservation itself burns nothing. Once the
main transaction has published, nothing determinate is reported any more: a
ledger contradiction or an uncertain cleanup after that point is
`Indeterminate`, never `Rejected`, so StateCore can never discard a durable
batch.

## Cleanup and close

Bounded transactions never reclaim freed pages in their own commit.
`StorageEngine::finish_operation` runs after the committed guard of every
commit and checkpoint: it records the operation's charge and calls
`RedbStore::reclaim_deferred` with what is left of the same allowance, for at
most `MAX_DEFERRED_RECLAIM_RECORDS = 64` freed-page records. A refused cleanup
leaves the operation committed and waits for a later one; progress is durable
and monotonic, so a backlog left by a stopped owner is drained by the first
operation after the restart. Records a live reader still needs are not
eligible and are reclaimed by the first cleanup after the reader releases.
`StorageStatistics::deferred_cleanup_pending` and
`reclaimed_pages_since_open` report this. A close never reclaims.

`StorageEngine::close_bounded` persists the allocator state through
`persist_allocator_state_bounded` under its own admission and its own
allowance of `G`, and takes that duty from redb's drop path, which would
otherwise run an unmetered transaction. It runs at the end of a clean
shutdown and, once, when the owner loop exits any other way. A refused
admission still hands the close an empty allowance so the drop path stays
disarmed. A close never fails a shutdown: refused or unable to persist, it
leaves the repair to the next open exactly as a crash does, and
`RecoveredStorageState::database_repaired` reports that the open repaired.
Initialization is bounded the same way: one allowance spans the initializing
transaction, the first guard and the close of the freshly created store.

## Region size

redb doubles a file below one region and then extends it by up to two regions
at a time, and the account charges each extension at its full length. With
the upstream 4 GiB region the first extension past 256 MiB could never fit and
no bounded database could grow. The fork made `Builder::set_region_size`
public; `bounded::live_database_builder` creates every live database with
`LIVE_DATABASE_REGION_BYTES = 64 MiB` regions, so one growth step is at most
128 MiB, half of `G`. Initialization and the restore and rekey target
initialization both create through `RedbStore::open_with_faults`, so both are
covered.

The region size is fixed at creation and recorded in the file header.
**A database whose header records larger regions is refused at open** with
`StorageError::UnboundedRegion(bytes)`, whose message names the region size
found and the 67,108,864-byte size required, and says to recreate the
database. `require_bounded_region` reads the two header fields exactly as the
vendored parser does, before redb opens the file. Running such a database
unbounded was rejected, and so was opening it bounded and letting it refuse
every write once it filled. There are no deployed databases; one created
before this change is recreated by initialization or restore.

Section 19.3 now states the enforcement, the guard headroom, the refusal, the
cleanup, the close and the region rule. The edit uses no new normative
keyword, so the regenerated ledger is the same 251 records with only the
document hash and the line numbers below the insertion changed. The
specification took the full refreeze.

## Shared helpers for the sibling lanes

All in `crates/agenc-ircd-storage/src/bounded.rs`, crate-visible:

- `OperationAllowance::new(block_size, guard_replacements)`, `.capped(..)`,
  `.allowance()`, `.charge(bytes)`, `.charged()`: one ledger per operation.
- `guard_replacement_charge(block_size)` and `round_up_to_blocks`.
- `map_write_error`, `map_table_error`, `map_preparation_error`,
  `map_publication_error`, `map_maintenance` and `MaintenanceOutcome`: the
  refusal mapping above, producing `RedbCommitFailure`.
- `live_database_builder(cache_bytes)` and `LIVE_DATABASE_REGION_BYTES`: any
  path that creates a future live database must build it through this.
- `MAX_DEFERRED_RECLAIM_RECORDS`.

`StorageFaultInjector::with_growth_cap(bytes)` lowers every operation's redb
allowance for the qualification campaign and the tests. It can only lower the
allowance, leaves the gate untouched, and does not enable the handle, so the
production redb backend stays selected.

The recovery and reference scratch databases (STO-04, #65), the backup phases
(#68) and the restore and rekey scratch-plan transactions (STO-07, #69) still
use redb's ordinary transactions and are not metered by this change.

## Evidence

Unit, `bounded.rs` (4): guard headroom at 512, 4,096 and 65,536-byte blocks;
the ledger exact at `G`, one byte over refused as an overflow; a cap only
lowers; every refusal phase determinate and every uncertainty indeterminate.

Unit, `redb_store.rs` (3): one fixed transaction replayed on fresh stores
against its measured charge (fits to the byte), one byte less (refused in
preparation, row absent, reservation record untouched, the next writer on the
same store commits) and zero (refused in mutation); a reclamation refused
without allowance, then draining, then finding nothing; a refused close
followed by a repairing open and a persisted close followed by a clean one; a
database created with the upstream region refused with `UnboundedRegion`.

Unit, `engine.rs` (6): an operation and a checkpoint charged and cleaned up;
the exact boundary with the cleanup refused, and one byte less refused in
preparation with the block burned, nothing charged, and the reopened writer
starting after the burned block; an allowance too small for the reservation
burning nothing; a checkpoint refused by its allowance installing nothing; a
live reader pinning an operation's frees until a reopen drains them; a close
refused by the gate leaving the repair to the next open.

Through the real `StorageOwner`, `tests/bounded_operation.rs` (9): fits and
cleans up, with a checkpoint; the boundary exact to the byte, and one byte
less refused in preparation with unchanged state, then a reopen whose next
commit leaves the nonce high water two blocks up; an eight MiB row refused
under a small cap, the next small writer and a checkpoint committing on the
same owner; `TransactionPhaseOne` and `TransactionPhaseTwo`, before and after,
on the reservation and on the main transaction, each required to fire through
the bounded handle, to yield exactly `Indeterminate`, and to reopen to the
exact prior or successor state (16 abandonments); 2,048 rows deleted by an
operation cut off after its committed guard, whose freed leaves the first
operation after the restart reclaims; a clean close reopening without repair
and a close whose sync fails reopening with repair and intact state, the
shutdown still succeeding; eight MiB rows growing the file past 256 MiB with
every operation under exactly `G`, the largest charging at least one whole
region and less than `G`, and the several-region database closing inside its
allowance; and an unbounded-region header refused before the open. The
existing fault matrix, including
`every_commit_fault_reopens_to_exact_prior_or_successor_state`, passes
unchanged through the bounded handle. The closed failure-surface test pins
both new messages and the four phase labels.

Commands, on the workspace-pinned toolchain in the lane's own target:

```text
cargo test -p agenc-ircd-storage --all-features --locked -- --skip qualification_workload
cargo test -p agenc-ircd-runtime --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo fmt --all --check
python3 scripts/check-source.py check
python3 scripts/check-workspace.py check
python3 scripts/requirements.py check
```

## Limitations

- The native ext4 qualification workload was not run here: it fallocates a
  multi-terabyte ballast on a shared filesystem. Acceptance items 1, 2 and 5,
  the archived STO-1 shapes replayed with allocated-block measurement at every
  sync and rename boundary, the 134,217,728-byte phase ceiling, and the rebuilt
  source-bound qualification metadata, stay open for the storage qualification
  that depends on STO-03, STO-04 and STO-07 together. The probe now sees the
  cleanup inside the enclosing `Manifest` and `CheckpointInstall` pairs and the
  close inside a `CapacityAdmission` pair.
- The guard headroom is a fixed upper bound, not a measurement.
- `reclaim_bounded` publishes single-phase inside the fork. It carries no
  application data and its flushes are labeled `DatabaseSync` only.
- The growth test writes about 270 MiB and takes over a minute in a debug
  build.
- The boundary cases replay one deterministic operation on fresh databases;
  the charge of the same shape on a different history can differ, because a
  file extension depends on the allocator's free space.
- An owner stopped by an indeterminate database failure cannot persist at
  close; the next open repairs, as before.
