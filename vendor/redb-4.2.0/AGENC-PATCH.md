# AgenC `redb` 4.2.0 patch

This directory starts from the crates.io `redb` 4.2.0 source whose published
checksum is recorded in `docs/protocol-sources-and-decisions.md` and in
`conformance/vendored-dependencies.toml`. Only `src/`, the crate manifests,
the licences and this note are vendored; the crate's own tests, examples,
fuzz targets and documentation stay upstream.

The local patch is the bounded write transaction of STO-01 (issue #47),
applied from `docs/upstream/redb-bounded-transaction/bounded-transaction.patch`
whose digest and per-file before-and-after digests are recorded in
`docs/upstream/redb-bounded-transaction/source.json`. It adds
`Database::begin_write_bounded(AllocationAllowance)`, the typed
`AllocationPhase` account that debits every page extent and file extension
before the allocation happens, the frozen `PreparedTransaction` whose
`publish` cannot allocate, `Database::reclaim_bounded` for resumable
deferred cleanup, and `Database::persist_allocator_state_bounded` for a
bounded close, and `BoundedWriteTransaction::set_two_phase_commit`, a passthrough
that lets a bounded publication keep the two-phase commit Section 21.5 requires. Ordinary transactions, their commit path, their close, the
on-disk format and the crate version are unchanged; the eight modified source
files are listed in the vendored-dependency manifest.

This fork is owned by the project. It is not submitted upstream and no
upstream acceptance is assumed or awaited. `scripts/check-workspace.py`
verifies the complete patched tree digest before accepting this source
override, exactly as it does for the `opaque-ke` patch.
