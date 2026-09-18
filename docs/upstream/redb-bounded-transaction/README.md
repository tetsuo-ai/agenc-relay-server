# redb bounded write transactions

This directory records the STO-1 work (issue #47, STO-01) and is the
provenance of the project-owned redb fork. The patch is applied to the
published redb 4.2.0 source vendored at `vendor/redb-4.2.0`, which the
workspace's `[patch.crates-io]` selects and `scripts/check-workspace.py`
verifies by complete tree digest. Upstream submission was STO-02 and is
withdrawn: the fork is owned here and owes nothing to upstream acceptance.
Application integration with one allowance across nonce reservation, guard
replacement, the main transaction and maintenance is STO-03.

Apply [bounded-transaction.patch](bounded-transaction.patch) with `git apply`
to upstream redb commit `23b6ba05473b13e69ed4db82f4b5bc07f0c33be9`
(`v4.2.0`), the provenance of the published crate agenc-ircd uses.
[source.json](source.json) records the patch digest and the before/after
digest of every changed file; applying the patch to a pristine checkout of
that commit reproduces every `after_sha256`. The source retains redb's
MIT/Apache-2.0 license. This patch supersedes the earlier allocation probe,
whose metering it keeps and whose inability to publish it removes.

## Implemented behavior

`Database::begin_write_bounded(AllocationAllowance)` starts a write
transaction whose physical growth is charged to one typed allowance. The
account debits every page extent at its rounded buddy-allocator size and
every file extension at its exact length before the allocation happens;
nothing is refunded, so the allowance bounds physical growth from above and
a page the transaction frees or reuses never lowers the charge. Each phase is
explicit and typed (`AllocationPhase`):

- **Mutation.** Table writes through the `BoundedWriteTransaction`, which
  dereferences to the ordinary read/write API. A refusal (`AllowanceRefusal`)
  is latched: every later allocation of the transaction is refused, a write
  that fits a page the transaction already owns still goes through, and
  `prepare` returns the first refusal. A refusal is never an I/O error and
  never sets the backend's I/O latch.
- **Preparation.** `prepare` runs every allocation-bearing step of the
  commit: the user tree flush, the freed-page and allocation records, the
  system tree, and the allocator state table when quick repair is enabled.
  All of it is written into pages the transaction allocates, so every prior
  user and system root stays valid. The one in-memory side effect, returning
  freed pages of earlier transactions to the allocator, is journaled; a
  refusal rolls the transaction's pages back, re-marks every journaled page
  allocated, and aborts like any other refused transaction, leaving the next
  writer usable. Records that earlier non-durable commits keep in memory
  are copied out and only discarded by publication. The result is a frozen
  `PreparedTransaction`; the account then refuses everything as `Frozen`.
- **Publication.** `publish` writes and flushes the header slots and
  nothing else. It cannot allocate: the frozen account would refuse, and the
  only file-growth path (`allocate_helper`) is never reached; a recorded
  backend proves the file length is unchanged and every write lands inside
  the prepared file. Real uncertain I/O keeps upstream's contract: the
  allocator state is invalidated and the database refuses writers until it
  is reopened and repaired.
- **Deferred cleanup.** Bounded transactions never reclaim old freed pages
  in their own commit. `Database::reclaim_bounded(allowance, max_records)`
  removes at most `max_records` freed-page records that no live reader or
  savepoint needs, journaled the same way, in one bounded publication. Its
  progress is monotonic and resumable; `remaining` reports the horizon of
  that publication (an ordinary commit's epilogue records become eligible one
  publication after a durable commit clears their pending marker).
- **Close.** `Database::persist_allocator_state_bounded(allowance)` writes
  the allocator state within the allowance and takes that duty from the
  drop path, whatever the outcome; on a refusal the next open repairs, as
  after a crash. Ordinary transactions and their close are unchanged, and a
  later ordinary write transaction restores the ordinary close.

Every bound is an upper bound on bytes the transaction may cause to be
allocated or extended, not a measurement of the bytes a filesystem
eventually backs; sparse regions, allocator rounding above the buddy order,
and filesystem metadata are outside it. Reader-retained pages cost nothing
directly; they keep freed-page records in the system tables, whose pages are
charged like any other. Savepoint restore is not reachable through the
bounded handle. No storage format changes; the legal transaction ceiling is
unchanged.

## Validation on 2026-09-15

All commands ran on the recorded v4.2.0 checkout with the patch applied,
using the workspace-pinned toolchain (Rust 1.98.0) and, for fuzzing, the
`nightly-2026-08-24` toolchain the probe record used.

- `cargo test -p redb@4.2.0 --all-features`: 433 tests pass, none ignored,
  including the new `tests/bounded_transaction.rs` (15 tests): positive
  publication of inserts, replacements, deletions and multi-table changes
  verified after close and reopen; empty and 4,000-byte keys, empty, 3 MiB
  and mixed large/small leaf values; fragmented free pages, a held reader,
  a refused retry and a following ordinary writer; zero, exact, one-less and
  one-more allowances against the deterministic charge of a fixed workload;
  cumulative charging across tables with no refund on reuse; sticky
  exhaustion after a partly successful operation and an ignored refusal that
  cannot publish; a preparation-phase refusal with the allocator state
  proven exact by a later integrity check; cancellation before and after
  prepare and drop of a prepared transaction; a recorded backend proving
  publication writes only inside the prepared file and never extends it;
  crashes frozen at every sync from before preparation through every
  publication flush recovering exactly the old or the new roots, passing a
  full integrity check, and accepting further writes; an I/O failure during
  publication latching the database until reopen; an I/O failure during
  mutation surfacing through the abort; bounded reclamation refused whole,
  making one-record monotonic progress, and finishing after the reader
  releases; and bounded close persisting the state or leaving the repair,
  observed through the repair callback, to the next open.
- Three unit tests cover the account itself: extent rounding at 512- and
  4,096-byte pages with no refund, the latched first refusal with unused
  allowance, and overflow and frozen refusals.
- `cargo clippy -p redb@4.2.0 --all-targets --all-features -- -D warnings`
  passes.
- `RUSTFLAGS='-C panic=abort' cargo check -p redb@4.2.0 --no-default-features
  --features experimental-api-5` passes.
- `cargo fmt --all --check` passes.
- API-aware fuzzing: `cargo +nightly-2026-08-24 fuzz run --sanitizer=none
  fuzz_bounded -- -max_len=4096 -max_total_time=120`. The
  `fuzz/fuzz_targets/fuzz_bounded.rs` state machine drives begin with an
  arbitrary allowance, inserts and removals with ignored refusals, prepare,
  publish, abort and drop at every phase, up to four live readers, bounded
  reclamation and persistence with arbitrary allowances, and reopen; it
  checks the committed model and every reader's snapshot after each step and
  runs a full integrity check at every reopen and at the end. Two runs on
  the final sources completed 133,584 and 81,350 executions in 121 seconds
  each without a failure.
- Upstream's `just test` and `just fuzz` still stop at their Podman sandbox
  step, which this host cannot provide; the host checks above do not
  satisfy that gate.

The patch has not been submitted, accepted or published upstream.

## Remaining STO-1 work

STO-02 submits this mechanism upstream and integrates a published release.
STO-03 replaces the application's storage-owner transactions with bounded
ones under one physical allowance spanning nonce reservation, guard
replacement, the main transaction and maintenance, and reruns every storage
measurement on a new candidate. The archived reserve overruns remain valid
failures of the earlier contract until then.
