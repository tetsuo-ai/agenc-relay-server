# Bounded exact-filesystem admission of every restore and rekey transaction

This record covers STO-07 (issue #69). Architecture Section 19.3 requires
restore, rekey, scratch-plan and target-construction databases to "prove their
exact logical and backup-stream ceilings in preflight and apply this same
`R(F) + G` gate independently before every scratch or target redb transaction",
to stop safely for a later `--resume` when space is unavailable, and never to
weaken `R(F)`. Section 28.7 requires construction tests to prove that every
scratch and target transaction rechecks `R(F) + G` rather than relying on stale
preflight space.

Before this work the scratch plan was one ordinary redb write transaction held
open across the whole streamed source and committed once at `finish`; nothing
sampled the scratch filesystem at all, and only the target batches were gated,
inside the engine. Wherever the issue says "published release" it means the
project-owned fork at `vendor/redb-4.2.0`
([the redb fork record](stage-10-redb-fork.md)).

## The admission authority

`crates/agenc-relay-storage/src/construction_runtime/admission.rs` adds one
descriptor-bound authority:

- `ConstructionAdmissionPolicy` takes `storage.disk_reserve_bytes` and
  `storage.disk_reserve_percent` from validated `StorageEngineLimits`.
- `ConstructionAdmission` binds that policy to one open descriptor and
  `admit(transaction)` takes a fresh `fstatvfs` sample of that descriptor's
  filesystem, computes `R(F) = max(fixed, ceil(total * percent / 100))` and
  UID-available bytes exactly as the live write path does, and refuses with
  `FilesystemRejected(InsufficientCapacity)` unless
  `available >= R(F) + G`. `R(F)` is never lowered and `G` is the fixed
  268,435,456 bytes.
- `ConstructionDirectory::scratch_admission` binds the policy to the directory
  that holds the plan: the staging directory while constructing, and the
  validated parent that holds the anonymous plan when an installed output is
  reverified. `ConstructionDirectory::target_admission` binds it to the staging
  directory that holds the target database. The source, state and backup
  filesystems are never sampled for a construction transaction.
- `ConstructionTransaction` names every admitted transaction:
  `ScratchCreate`, `ScratchReset`, `ScratchObserve(n)`, `ScratchVerify(n)`,
  `ScratchOrder(n)`, `ScratchReclaim(n)`, `ScratchClose`, `TargetInitialize`,
  `TargetBatch(committed_before)`, `TargetFinalize` and `TargetCheckpoint`.

## Every scratch transaction is bounded and admitted

`ConstructionPlanBuilder` no longer holds one transaction. Each scratch
transaction is admitted immediately before it begins and then runs through
`Database::begin_write_bounded(AllocationAllowance::new(G))` with
`set_two_phase_commit(true)`, `prepare` and `publish`:

| Transaction | What it writes |
| --- | --- |
| `ScratchCreate` | redb's metadata initialization of the fresh mode-0600 plan file |
| `ScratchReset` | creates and empties every plan table, including the recovery-gate index |
| `ScratchObserve(n)` | one slice of plan entries and the channel, discarded-channel, current-record, reference, manifest and recovery-gate indexes |
| `ScratchVerify(n)` | one slice of the reverse replay of the manifests after the checkpoint cut |
| `ScratchOrder(n)` | one slice of the unsorted-to-ordered copy, with the plan hash carried across slices |
| `ScratchReclaim(n)` | `Database::reclaim_bounded`, 64 freed-page records at a time, until none remains |
| `ScratchClose` | `Database::persist_allocator_state_bounded`, after which closing the plan database allocates nothing |

A slice ends when it reaches `batch_records` writes or `batch_bytes` of keys
and values; both are checked before a record's writes, so one record's writes
land in one slice and a slice exceeds the byte bound by at most one record.
Reference validation, the checkpoint re-derivation and the final independent
re-read use read transactions between slices. The in-process cursor is the
phase, the slice ordinal, the last copied unsorted key and the running plan
hash; at most two source records plus one plan entry are in memory, the
canonical plan-byte ceiling is unchanged and separate from physical scratch
growth, and no decrypted value or secret enters the plan.

An allowance refusal inside a slice is STO-03's shared
`StorageError::AllowanceRefused(phase)`, through its `map_write_error`,
`map_table_error` and `refusal_phase`; every other redb failure keeps
`DatabaseRejected`. An abandoned builder aborts its open slice
and calls `persist_allocator_state_bounded` with a zero allowance, so closing
the database of a refused or failed construction writes nothing either.

### A bounded database is created with regions of at most half its allowance

The bounded account charges a file extension at its full length before the
file grows, and redb doubles a file below its first full region and then grows
by the trailing region plus one full region. With redb's default 4 GiB region
no transaction under `G` could ever extend a file past 256 MiB: the
256-to-512 MiB step alone costs `G`. The fork now exposes
`Builder::set_region_size`, and STO-03 (#61) owns the rule in
`bounded.rs`: `live_database_builder` creates every live and target database
with `LIVE_DATABASE_REGION_BYTES = 67,108,864`, and the scratch plan is
created through the same builder. One extension is then at most two regions
(134,217,728 bytes), half of `G`, and the other half is left for the pages the
transaction writes. An existing database keeps the region size in its header.
The recovery and reference scratch databases of STO-04 (#65) are not touched
here.

## Every target transaction has exactly one admission

The target's initialization, every batch, the finalization and the checkpoint
run through the storage engine, and STO-03 (#61) now admits each of them once:
`admit_transaction` samples `R(F) + G` on the staging directory immediately
before the transaction, which then runs under its bounded `OperationAllowance`.
This lane adds no second sample. `ConstructionTarget` owns a
`ConstructionAdmission` bound to the staging directory and names
`TargetInitialize`, `TargetBatch(committed_before)`, `TargetFinalize` and
`TargetCheckpoint` to an installed test observer immediately before the engine
begins each one (`recheck_observed`); without an observer it samples nothing.
That seam is how the tests place a refusal at one exact target transaction and
prove the stop and the resume around it. A commit error or uncertain I/O inside the engine is still
`CommitOutcome::Indeterminate`, surfaced as `Unavailable`, and a restart
reconciles the database and guard pair under Section 21.5.

## Refusal and resume

A refusal is determinate: the refused transaction has not begun, nothing is
written, the source is never opened for writing, and no target is published.
`arcd storage restore` now reports it apart from every other storage
failure (`OfflineError::InsufficientCapacity`: "storage free space is below the
reserve; nothing was written, rerun with --resume when space is available").

- **Stopped at a scratch transaction, or at `TargetInitialize`.** The staging
  directory holds at most an unfinished plan file and no database.
  `--resume` previously failed on that directory because it required a staging
  database; `ConstructionDirectory::target_database_exists` now lets the resume
  build a fresh target. The plan is rebuilt in full, as it is on every resume:
  a scratch plan is never trusted across a restart.
- **Stopped at `TargetBatch(n)` or `TargetFinalize`.** The authenticated marker
  still names the refused batch. `--resume` rebuilds and re-hashes the plan,
  and the first target transaction it admits is exactly the refused one.
- **Stopped at `TargetCheckpoint`.** The completion record is durable, so the
  resume takes the existing finalized-but-not-renamed path: it reverifies the
  completion and installs it with no further target transaction.

## Tests

`crates/agenc-relay-storage/tests/stage_five_completion/construction_admission.rs`
drives the real `execute_restore_command` through
`execute_restore_command_with_observer`, whose only difference is that every
live `fstatvfs` sample passes through a test observer. The observer records
each admitted transaction and, at one named transaction, stands in for an
external writer that leaves exactly `R(F) + G + delta` bytes available. The
source is a live database with 1,200 accounts committed in two transactions
and a signed backup, so the command runs several observation slices, two
reverse-replay manifests, two ordered-copy slices and two target batches.

| Test | What it proves |
| --- | --- |
| `restore_admits_every_scratch_and_target_transaction_in_order` | A construction that fits admits create, reset, contiguous observe, verify, order and reclaim slices, close, initialize, `TargetBatch(0)`, `TargetBatch(1000)`, finalize and checkpoint, in that order; the source bytes are unchanged; an installed output is reverified with no target transaction |
| `restore_refused_at_each_scratch_transaction_writes_no_target_and_resumes` | One byte short at `ScratchReset`, `ScratchObserve(2)`, `ScratchVerify(1)`, `ScratchOrder(2)`, `ScratchReclaim(1)`, `ScratchClose` and `TargetInitialize`: each is the last admitted transaction, no target database or output exists, the source is unchanged, and the final `--resume` admits the full sequence and installs |
| `restore_refused_at_a_target_transaction_resumes_at_exactly_that_transaction` | One byte short at `TargetBatch(1000)`, `TargetFinalize` and `TargetCheckpoint`: the resume rebuilds the same scratch sequence and its target transactions are exactly the remainder, never `TargetInitialize` or `TargetBatch(0)` again |
| `restore_rechecks_the_exact_boundary_at_the_first_scratch_and_target_transactions` | `R(F) + G - 1` refuses and `R(F) + G` and `R(F) + G + 1` admit, at `ScratchObserve(1)` and at `TargetBatch(0)`, with the consumption injected after preflight and after the target was initialized with room |
| `rekey_scratch_and_target_transactions_are_admitted_and_refused_at_the_exact_boundary` | The same three points on the rekey plan built from the locked current database and on a rekey target batch; a refusal at the second batch leaves the marker there and the resumed executor admits `TargetBatch(1)` first, then finalizes and verifies |

Inside the crate,
`construction_runtime::tests::scratch_growth::a_bounded_scratch_plan_grows_past_the_allowance_in_steps_of_at_most_two_regions`
observes eighteen 15 MiB manifests under an allowance of exactly `G`: the plan
file grows past 268,435,456 bytes, no growth step exceeds two regions, and the
build finishes. `construction_runtime::admission::tests` pins the reserve arithmetic
and the minus, equal and plus one boundary on the gate itself, and
`construction_directory::tests::admissions_follow_the_directory_that_holds_the_plan_and_the_target`
pins which directory each admission samples. Every existing construction,
restore, fault-campaign and corruption test was moved onto the admitted API.

## Commands

- `cargo test -p agenc-relay-storage --all-features --locked -- --skip qualification_workload`
- `cargo test -p agenc-relay-runtime --all-features --locked`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `cargo fmt --all`, `python3 scripts/check-source.py check`,
  `python3 scripts/check-workspace.py check`

## Limitations

- The observer replaces the sampled capacity at one transaction; it does not
  fill a filesystem. The native ext4 boundary with a real ballast stays with
  the storage qualification workload and REL-08.
- A target refusal in the tests is raised by the observer seam immediately
  before the engine's transaction; the engine's own gate and allowance, which
  are the production admission of that transaction, are proved by STO-03.
- `capacity_from_statistics` is repeated privately in
  `construction_runtime/admission.rs` rather than shared from `platform.rs`, so the
  sibling lanes' platform changes cannot conflict with it.
- Scratch slices are bounded by record count and key and value bytes, not by a
  measured physical charge; the growth test and the fixed allowance are the
  evidence that a legal slice fits `G`. Peak cache and per-transaction physical
  measurements on native ext4 remain with REL-08.
