# Stage 10 bounded recovery and reference scratch

This record covers STO-04 (issue #65). Startup integrity reconstruction,
startup reference validation, stopped-daemon inspection, construction
verification and the checkpoint's own readback all rebuild a tracked-record
index in a private redb scratch file. Before this work each of them held one
unbounded write transaction over the whole current record set, no scratch
transaction was admitted against the filesystem, and the checkpoint ran its
verifier *after* it had committed the checkpoint transaction and replaced the
committed guard, mapping every failure to `Indeterminate`. A large database
with free space for a normal commit but not for its verifier scratch therefore
turned a consistent, durable checkpoint into an owner that closed and a restart
into offline recovery, although nothing was wrong with the durable state.

Every one of those scratch transactions is now admitted against the exact
filesystem immediately before it begins, bounded by a typed allowance from the
project-owned redb fork, and sliced so that no transaction ever covers the
full current record set. The checkpoint reads its cut back through that
bounded scratch before it reserves a nonce block, replaces a guard or opens
its transaction, and refuses determinately, with nothing written, when the
scratch cannot be admitted. Startup proves the recovered state within the
same bound from both directory authorities.

## What is now bounded

The new module `crates/agenc-ircd-storage/src/scratch.rs` owns one
`ScratchDatabase`: a redb database created from a descriptor the state
directory handed out, whose every write transaction goes through
`Database::begin_write_bounded(AllocationAllowance)` of the fork and is
published through the frozen `prepare`/`publish` pair. `RecoveryScratch` and
`ReferenceScratch` in `redb_store.rs` are built on it and keep their table
layout and their checks; only their transaction shape changed.

- **Admission.** Before creation, before every slice, before every
  reclamation and before nothing else, the scratch asks its
  `ScratchAdmission` for the transaction's allowance. The engine's
  `ScratchGate` samples the state filesystem afresh (`fstatvfs` through the
  retained directory descriptor, the same sample `admit_transaction` takes)
  and requires `available >= R(F) + allowance`. The gate is the Section 19.3
  `R(F) + G` gate with `G` spelled out, and it works for both authorities:
  the writer-locked `StateDirectory` and the read-only
  `InspectionStateDirectory`, which samples capacity without the lock.
- **Allowance.** Every scratch transaction is bounded by
  `MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH`, the fixed 268,435,456-byte `G`
  of Section 19.3. The fork's account debits every page extent at its rounded
  buddy size and every file extension at its full length before the
  allocation happens and refunds nothing, so `G` bounds the physical growth
  of one transaction from above.
- **Slices.** A slice is at most `SCRATCH_SLICE_ROWS` (4,096) rows or
  `SCRATCH_SLICE_BYTES` (1,048,576) logical key and value bytes, whichever
  fills first. The recovery index buffers current rows and publishes a slice
  when either budget is reached; the reference index does the same for
  records and their references, and a record's references may span slices
  because validation reads the complete published index. The reverse replay
  of a manifest is chunked by the same two budgets, in exact reverse manifest
  order, at most 4,096 mutations or 1 MiB of keys per transaction. The byte
  budget also bounds the resident row buffer: at most one budget plus the row
  that crossed it.
- **Creation, reclamation and close.** The creation of the file and the
  transaction that opens its tables are admitted and bounded like every
  slice. After every publication the scratch runs
  `Database::reclaim_bounded` under the same admission and allowance, at most
  64 freed-page records per publication and at most four publications, so the
  pages a slice or a reverse chunk rewrote return to the allocator instead of
  growing the file. The close calls `persist_allocator_state_bounded` with a
  **zero** allowance on purpose: nothing in a scratch survives, so its
  allocator state is never written, and after that call redb's drop only
  flushes and closes the descriptor instead of running its unmetered close
  transaction. The entry is then unlinked by name through the retained
  directory descriptor.
- **Region size.** A bounded database is created with regions of at most
  half its allowance, because the account charges a file extension at its
  full length and redb grows a full file by up to two regions at once; with
  redb's default 4 GiB region no bounded transaction could ever extend the
  file past 256 MiB. Every scratch is created with
  `Builder::set_region_size(64 MiB)`, a quarter of `G`, which the fork now
  exposes for exactly this reason.
- **Two-phase commit.** Scratch publications are single-phase. The fork's
  `set_two_phase_commit` exists for durable publications that a restart must
  find; a scratch is never trusted across a restart and is removed on the
  next open, so it needs no second header flush.

## Where the scratch lives

Section 23.5.3 places the verification scratch "in the private runtime
directory" and charges its bytes against the memory/disk reservation. The
configuration defines no runtime directory apart from the state directory,
and the reservation `R(F)` is measured on the state filesystem. This record
reads "private runtime directory" as the daemon's private mode-0700 state
directory, and the implementation keeps the scratch there deliberately:

- the scratch is created with `O_EXCL` and mode 0600 through the retained
  directory descriptor (`StateDirectory::create_recovery_scratch`), so it is
  descriptor-bound and its removal is descriptor-relative;
- it sits on the qualified filesystem the reserve is sampled on, so every
  admission of a scratch slice sees the space the previous slices consumed
  and the checkpoint's own transaction, admitted after the readback, sees
  what the readback left;
- inspection, which holds no writer authority, uses an anonymous `O_TMPFILE`
  inode of the same directory, which never appears as an entry and vanishes
  with its descriptor.

A different location would need a second reserve on a second filesystem and
a specification change; neither is warranted by the text, so no
specification changed and the mismatch the audit named is resolved by this
reading rather than retained silently. The `ScratchLocation` type is the
explicit authority the audit asked for: the exclusive entry with the
descriptor it is unlinked through, or the anonymous inode.

## The checkpoint reads its cut back before it publishes

`install_scanned_checkpoint` now performs, in this order:

1. `verify_checkpoint_cut`, unchanged;
2. `readback_checkpoint_cut`: every current tracked row is indexed in
   bounded slices, every manifest after the cut is reversed through the index
   in bounded chunks, and the resulting count and digest must equal the
   count and digest the scan recorded at the cut. The scratch is removed
   before this returns; only its metered usage survives, into the receipt;
3. `admit_transaction`, the existing `R(F) + G` gate for the checkpoint's
   own transaction, now sampled after the readback has released its space;
4. nonce reservation, reserved guard, the checkpoint transaction and the
   committed guard, unchanged.

After publication, `commit_prepared_checkpoint` verifies the control chain
only (`verify_integrity_chain`: checkpoint decode and anchors, table counts,
the forward manifest walk and the accumulators) and requires the durable
checkpoint's count and digest to repeat the readback's. No scratch is
allocated after publication: the record set was proven against the cut
before the transaction and no tracked table changes in a checkpoint
transaction. A chain that does not reproduce the proof closes the owner
through `Indeterminate`, exactly as the post-publication verification always
did, because it is a durable state the owner cannot vouch for.

`verify_integrity_ledger`, which startup, inspection and construction
verification call, is the same two halves in sequence: the read-only chain,
then the bounded reconstruction, then the comparison. Every control-chain
refusal is now raised before any scratch is created.

## The refusal mapping

| where | cause | outcome |
| --- | --- | --- |
| scratch admission, before any scratch transaction | `available < R(F) + G` on the fresh sample, or the sample itself failed | `StorageError::FilesystemRejected(InsufficientCapacity)`, or the sample's own error; a checkpoint reports `CheckpointOutcome::Rejected(error)` |
| scratch mutation, table open, preparation or reclamation | the typed allowance refused an allocation | `StorageError::AllowanceRefused(phase)`, the variant STO-03 (#61) introduced, with the phase the fork reported (`Mutation`, `Preparation` or `Cleanup`); a checkpoint reports `Rejected(AllowanceRefused(phase))` |
| scratch I/O | a genuine write, sync or read failure of the scratch file | `StorageError::DatabaseRejected`; a checkpoint reports `Rejected(DatabaseRejected)` |
| readback comparison, before any publication | the current records reversed to the cut do not reproduce the scan | `CheckpointOutcome::Indeterminate`: the owner closes and the restart's startup verification fails closed, the same fatal path a corrupt ledger always took; nothing was published |
| post-publication chain | the durable chain does not reproduce the readback, or a real uncertain I/O outcome of the commit or guard | `Indeterminate`, unchanged (Section 21.5) |

A refusal is never `StaleState`, never `Indeterminate`, and never an
uncertain commit: at every refusal the database, the reservation record and
the guard are byte-for-byte what they were, no nonce block was reserved, the
scratch entry is gone, and the owner keeps serving; the same checkpoint
installs as soon as its samples are admitted again. The classification
lives in `readback_failure` in `engine.rs`: `AllowanceRefused`,
`AllocationFailed` (a refused in-memory reservation), `UnboundedRegion`,
`FilesystemRejected`, `DatabaseRejected`, `QueueFull` and `Unavailable` are
resource refusals and reject; every other error is a ledger that does not
reproduce the scan and is fatal.

The scratch maps redb's refusals through the helpers STO-03 owns in
`bounded.rs`: `map_write_error` for table writes and a refused begin,
`map_table_error` for table opens, and `refusal_phase` for preparation and
reclamation. Two of STO-03's mappers are deliberately not used.
`map_preparation_error` and `map_publication_error` keep every non-refusal
failure `Indeterminate`, which is right for the live database and wrong for a
scratch: a scratch that fails its own commit has written nothing anyone will
ever trust, so the verification fails determinately with `DatabaseRejected`.
`map_maintenance` reports a refused reclamation as a completed outcome the
live operation may ignore; a scratch reclamation that is refused stops the
verification like any other refused step, so it is mapped directly.

The Section 21.5 indeterminate path for real uncertain I/O is untouched: a
commit error, a guard write, sync or rename error after the transaction, or
a post-publication chain failure still yields `Indeterminate`, the
`CheckpointInstall`/`CheckpointPrune` fault matrix still reopens to a
verified commit or checkpoint, and the STO-10 guard publication window is
unchanged.

## What the account charges, measured

`ScratchUsage` is the metered ownership of one scratch and is carried by
`RecoveredStorageState::verification_scratch()`,
`RecoveredStorageState::reference_scratch()` and
`CheckpointReceipt::readback_scratch`: bounded transactions and
reclamations published, the sum of every transaction's charge, the peak
charge of one transaction, the peak resident row buffer, the file length at
creation, the peak file length, the pages reclaimed, the configured cache
(8 MiB) and the allowance (`G`). Through the real storage owner, on the
5,120-account set of `many_records_verify_in_several_bounded_slices_at_checkpoint_and_startup`:

| scratch | transactions | charged bytes | peak transaction | peak buffer | file at creation / peak |
| --- | --- | --- | --- | --- | --- |
| checkpoint readback | 3 (creation, two slices) | 774,144 | 589,824 | 253,952 | 1,056,768 / 1,056,768 |
| startup reference index | 3 | 421,888 | 294,912 | 106,496 | 1,056,768 / 1,056,768 |
| one-account readback | 2 | 24,576 | 16,384 | 135 | 1,056,768 / 1,056,768 |

Two facts the measurement made visible shaped the design. First, the fork's
account charges every copy-on-write rewrite of a leaf and refunds the page
it freed, so a transaction's charge grows with its rows times the leaf size
its rows produce, not with its row bytes: a 4,096-row slice of maximum
4,096-byte stored keys charged 233,775,104 bytes, about fourteen times its
logical bytes and 87 percent of `G`. That is why a slice is bounded by
logical bytes as well as rows; one byte budget of maximum keys now charges
less than an eighth of `G`
(`a_byte_budget_of_maximum_keys_charges_far_less_than_the_allowance`).
Second, opening a table allocates its root, so a refusal can surface from
`open_table` as well as from an insert or from `prepare`; all three map to
`AllowanceRefused` with their phase.

## Evidence

Storage crate, `cargo test -p agenc-ircd-storage --all-features --locked --
--skip qualification_workload`:

- `scratch::tests`: the fixed workload fits exactly at its measured peak,
  refuses one byte below it and fits one byte above it, and a zero allowance
  refuses creation; a refused slice publishes nothing and leaves the next
  writer of the same scratch usable; every transaction is admitted afresh
  with the fixed allowance, an admission refused between two slices is
  `FilesystemRejected(InsufficientCapacity)` and a refusal on creation
  never creates the database; a genuine write failure through a failing
  backend is `DatabaseRejected`, not the allowance; the close persists
  nothing, removes the entry, meters creation, peak, cache and reclamation,
  and an anonymous scratch needs no cleanup; one byte budget of maximum
  keys charges less than an eighth of the allowance.
- `redb_store::tests`: duplicates are refused when their slice publishes,
  whether the first copy is in an earlier slice or the same buffer; reverse
  transitions still require the exact `after` version; malformed rows are
  still refused by the digest.
- `engine::tests::bounded_scratch`: every capacity-admission occurrence of a
  checkpoint readback, from the scratch's creation through its slice, its
  reclamations and the transaction's own sample, is a determinate
  `Rejected(DatabaseRejected)` that leaves StateMeta and the guard hash
  unchanged and no scratch entry, after which the same checkpoint installs,
  the ledger verifies and the next commit goes through; a record substituted
  behind the scan's back is found by the readback and closes the owner
  through `Indeterminate` without publishing; startup meters both scratches
  from the writer authority and from inspection, which changes nothing in
  the directory; a refused startup admission fails closed and leaves no
  entry; the scratch gate admits at exactly `R(F) + allowance`, refuses one
  byte below and admits one byte above on the real filesystem.
- `stage_five_completion::bounded_scratch`, through the real storage owner:
  the same checkpoint refusal sweep with the guard file byte-identical, the
  retried checkpoint installed, the next commit certain and the reopen
  verified; a refused startup admission fails `StorageOwner::start` closed
  and leaves nothing behind; 5,120 accounts verify in several bounded slices
  at the checkpoint and at startup; a scratch entry an interrupted
  verification left behind is removed on the next open while an unrelated
  entry survives.
- The existing checkpoint fault matrix
  (`every_checkpoint_fault_reopens_to_a_verified_commit_or_checkpoint`), the
  STO-10 guard publication window, every integrity-ledger corruption case and
  the inspection cases pass unchanged: 350 storage tests and 1,588 runtime
  tests.

## Limitations

- The gate admits one transaction at a time against the space it finds; it
  does not project the total scratch a verification will need. A database
  whose scratch is larger than the free space is refused at the first slice
  that no longer fits, before publication, which is safe but not early.
- Every slice publication is followed by at least one bounded reclamation
  publication, each with its own flush, so a verification of `n` rows costs
  about `2n / 4,096` scratch flushes on top of the reads. The measurement
  shows this is small beside the AEAD work; it was not tuned.
- `ScratchGate` still repeats the `R(F) + allowance` comparison of
  `StateDirectory::admit_transaction`. STO-03 (#61) kept that gate fixed at
  `G`, bound to the writer-locked directory and refusing the inspection
  authority outright, and its `OperationAllowance` spreads one `G` across the
  transactions of one durable operation, whereas every scratch transaction is
  admitted afresh with a whole `G` of its own. Neither swap is mechanical, so
  the gate stays private to `engine.rs`. Scratch databases likewise keep their
  own builder rather than `live_database_builder`, which carries the live
  cache and is documented for files that become a live database; both use
  64 MiB regions.
- The qualification workload was not rerun on this branch; its checkpoint
  cases now sample capacity a few more times per checkpoint, inside the
  existing sample ceiling.
- A readback that does not reproduce the scan is reported as
  `Indeterminate` because that is the only fatal outcome the checkpoint has;
  nothing was published in that case, and the restart's startup
  verification, not a reconciliation, is what follows.
