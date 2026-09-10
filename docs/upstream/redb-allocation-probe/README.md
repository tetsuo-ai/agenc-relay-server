# redb allocation and rollback prototype

This patch is preliminary upstream work for STO-1. It is not linked into
agenc-ircd and does not close the storage growth finding. The application
continues to use its published redb dependency and unchanged physical limits.

Apply [allocation-probe.patch](allocation-probe.patch) with
`git apply --unidiff-zero` to upstream redb commit
`23b6ba05473b13e69ed4db82f4b5bc07f0c33be9` (`v4.2.0`). That commit matches
the provenance of the published crate used by agenc-ircd.
[source.json](source.json) records the patch digest and the before/after
digest of each changed file. The source retains redb's MIT/Apache-2.0 license.

## Implemented behavior

`Database::begin_write_allocation_probe(limit)` installs one shared cumulative
allocation account before constructing transaction namespaces. Both allocator
entry points debit the rounded page extent before entering the memory or
filesystem allocator. Freed pages do not refund the account. Refusal remains
latched even when some allowance remains, and it uses a typed error without
setting the backend I/O error latch.

Probe transactions cannot publish. `commit` explicitly aborts and returns
`AllocationProbeRefusal::Exhausted` or `CommitUnavailable`. A failed abort
propagates its storage error. Ordinary transactions retain their commit path.

## Validation on 2026-09-10

- Six actual transaction tests pass: explicit abort, ignored refusal followed
  by commit, refusal during a branch update, shared limits across tables,
  unexhausted commit refusal and zero-budget refusal. Checks include retained
  readers, unchanged rows after reopen and a successful next ordinary writer.
- Three unit tests pass for extent rounding, cumulative charges, overflow and
  sticky refusal with unused allowance.
- `cargo test -p redb@4.2.0 --all-features` passes 424 tests with no failures
  or ignored tests.
- `cargo clippy -p redb@4.2.0 --all-targets --all-features -- -D warnings`
  passes. Formatting and changed-source ASCII checks pass.
- `RUSTFLAGS='-C panic=abort' cargo check -p redb@4.2.0 --no-default-features
  --features experimental-api-5` passes.
- The existing upstream fuzz target completes 79,314 executions in 61 seconds
  without a crash, using `cargo +nightly-2026-08-24 fuzz run --sanitizer=none
  fuzz_redb -- -max_len=10000 -max_total_time=60`. This is a smoke test of the
  existing transaction API; it does not fuzz the new probe entry point.
- Upstream's required `just test` and `just fuzz` both pass their dependency
  and formatting steps, then stop because Podman is missing. User-namespace
  mapping also fails in this environment. The host checks above do not satisfy
  that sandbox gate.

The patch has not been submitted, accepted or published upstream.

## Remaining STO-1 work

The probe meters mutation allocations only. It does not bound physical file
growth, allocator metadata, commit preparation, publication, cleanup or close.
The next implementation must preserve the old roots throughout abortable user
and system metadata preparation, retain pages pinned by readers, and freeze
all allocation-bearing work before publication. It also needs bounded cleanup
that makes progress, bounded close, failure injection and crash/reopen proofs.

Application integration requires one physical allowance spanning nonce
reservation, guard replacement, the main transaction and maintenance. A
published upstream release, the reviewed admission contract and both native
ext4 qualification runs remain required. The archived reserve overruns remain
valid failures of the earlier contract.
