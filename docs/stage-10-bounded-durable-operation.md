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

`crates/agenc-relay-storage/src/bounded.rs` holds `OperationAllowance`. One is
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
`reclaimed_pages_since_open` report this.

`StorageEngine::close_bounded` persists the allocator state through
`persist_allocator_state_bounded` under its own admission and its own
allowance of `G`, and takes that duty from redb's drop path, which would
otherwise run an unmetered transaction. It runs at the end of a clean
shutdown and, once, when the owner loop exits any other way. A clean stop
reclaims first and gives the reclamation and the persistence half of the
close's one allowance each, because the fork does not report what a
reclamation charged; an owner stopped by an uncertain outcome only persists.
A refused admission still hands the close an empty allowance so the drop path
stays disarmed. A close never fails a shutdown: refused or unable to persist, it
leaves the repair to the next open exactly as a crash does, and
`RecoveredStorageState::database_repaired` reports that the open repaired.
Initialization is bounded the same way: one allowance spans the initializing
transaction, the first guard and the close of the freshly created store.

## The maximum legal transaction, measured

The first gate over this change failed in
`qualification_workload::production_workload_measures_every_required_case_and_phase`:
`insert-max-records`, 65,535 rows of 134 bytes, was refused with
`AllowanceRefused(Mutation)`. The charge was measured, not estimated, with
per-phase probes on the bounded handle, an instrumented scratch copy of the
fork, and gdb breakpoints on the fork's debit and on the leaf build.

At the refusal: 81,920 bytes of guard headroom, 16,384 for the reservation,
and the whole remaining 268,337,152 consumed in the mutation phase while the
file grew by only 67,108,864. With the allowance lifted the transaction
charged 825,901,056 bytes: 268,435,456 of file extensions (four 64 MiB
regions), 282,955,776 of distinct page extents, and 274,509,824 of extents the
transaction had already been charged for and was charged for again. The file
grew by 257,761,280 allocated bytes, the same figure `main` records for this
case and 1.92 times the 134,217,728 qualified ceiling.

gdb showed where the bytes go. Every one of the 65,535 inserts reached
`LeafBuilder::build` for a 164-byte leaf holding one row, from the
single-large-value fast path at `btree_mutator.rs:759`, and then
`BranchBuilder::build` for a branch 46 bytes larger than the last. The leaf the
insert landed in had one pair of 8,380,124 bytes: the workload's live
`replace-max-value` row, whose key (`0x13...`) sorts directly above the
`0x12...` run. redb 4.2.0 never rebuilds a leaf holding one value of at least a
page; an insert that lands there becomes a new sibling leaf, and with
ascending keys the sibling's separator is the key just inserted, so the next
key is routed to the large leaf again. Every row received a page of its own.
This is upstream behaviour, not the fork's patch, and not the allowance
derivation: the same 65,535 rows through the engine on a database without the
large neighbour charge 63,090,688 bytes.

The fix is one place, `redb_store::apply_writes`: each same-table run is
applied in descending key order, so the first sibling's separator bounds every
later key and the rows share ordinary leaves. Keys are distinct within a batch,
so the order inside the transaction is unobservable. Under the real `G` the
case now charges 71,286,784 bytes and grows the file by 16,625,664;
`delete-max-records` went from 510,951,424 charged to 50,962,432; the greatest
growth of any case is `insert-max-value` at 16,789,504, inside the qualified
ceiling. Nothing legal was lowered and no case was skipped.

The same run exposed a second defect, in the close. The workload's boundary
cases need two idle open-and-close samples to agree, and each clean close grew
the database by 24,576 bytes: the persisting transaction frees the pages of the
state it replaces and, being bounded, never reclaims them. redb's own close
held a fixed length over the same cycles. A bounded reclamation before the
persistence holds the length too, which is why a clean close now reclaims
first.

Two properties of the fork's charge model were measured and are reported, not
changed: a file extension and the page extents later allocated inside it are
both charged for the same bytes, and an extent the transaction frees and
allocates again is charged again. With the tree no longer degenerate the
maximum case is charged 4.3 times its real growth and still uses 27 percent of
`G`. `ReclaimProgress` does not report what a reclamation charged, which is
why the close splits its allowance in halves.

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

All in `crates/agenc-relay-storage/src/bounded.rs`, crate-visible:

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

Unit, `redb_store.rs` (4): 8,192 ascending rows inserted directly below an
8 MiB value charging under 2,048 bytes a row; one fixed transaction replayed on fresh stores
against its measured charge (fits to the byte), one byte less (refused in
preparation, row absent, reservation record untouched, the next writer on the
same store commits) and zero (refused in mutation); a reclamation refused
without allowance, then draining, then finding nothing; a refused close
followed by a repairing open and a persisted close followed by a clean one; a
database created with the upstream region refused with `UnboundedRegion`.

Unit, `engine.rs` (7): six idle open-and-clean-close cycles keeping the
database length fixed; an operation and a checkpoint charged and cleaned up;
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
cargo test -p agenc-relay-storage --all-features --locked -- --skip qualification_workload
cargo test -p agenc-relay-storage --all-features --locked qualification_workload
cargo test -p agenc-relay-runtime --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo fmt --all --check
python3 scripts/check-source.py check
python3 scripts/check-workspace.py check
python3 scripts/requirements.py check
```

## Limitations

- The production qualification workload was run once on the development host,
  with the machine held quiet for its multi-terabyte ballast, and completes
  under the real `G`. It is not the native ext4 release qualification.
  Acceptance items 1, 2 and 5,
  the archived STO-1 shapes replayed with allocated-block measurement at every
  sync and rename boundary, the 134,217,728-byte phase ceiling, and the rebuilt
  source-bound qualification metadata, stay open for the storage qualification
  that depends on STO-03, STO-04 and STO-07 together. The probe now sees the
  cleanup inside the enclosing `Manifest` and `CheckpointInstall` pairs and the
  close inside a `CapacityAdmission` pair.
- The guard headroom is a fixed upper bound, not a measurement.
- redb's single-large-value fast path still gives a row a page of its own when
  one transaction at a time inserts ascending keys directly below a large
  value; each such transaction is small, so this costs space, not an
  allowance, and belongs to the fork.
- `reclaim_bounded` publishes single-phase inside the fork. It carries no
  application data and its flushes are labeled `DatabaseSync` only.
- The growth test writes about 270 MiB and takes over a minute in a debug
  build.
- The boundary cases replay one deterministic operation on fresh databases;
  the charge of the same shape on a different history can differ, because a
  file extension depends on the allocator's free space.
- An owner stopped by an indeterminate database failure cannot persist at
  close; the next open repairs, as before.
