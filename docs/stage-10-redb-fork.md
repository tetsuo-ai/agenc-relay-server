# Stage 10 project-owned redb fork

This record closes STO-02 (issue #55) by withdrawing it. STO-02 asked for the
STO-01 bounded write transaction to be submitted to the redb maintainers,
accepted, and shipped in a published release before the storage work could
use it. That placed twenty issues behind a decision nobody in this project
can make, for a 2,100-line change to a third party's allocator and commit
path built around this project's disk-reserve rule. The owner's decision on
2026-09-17 was to own the fork instead.

## What changed

The patch in `docs/upstream/redb-bounded-transaction/` is applied to the
published redb 4.2.0 archive and vendored at `vendor/redb-4.2.0`, following
the convention `opaque-ke` already uses: only `src/`, the manifests, the
licences and an `AGENC-PATCH.md` note are vendored; the workspace's
`[patch.crates-io]` selects the directory; `conformance/vendored-dependencies.toml`
records the published upstream checksum as the provenance value and the
complete patched-tree digest; and `scripts/check-workspace.py` refuses any
other source override or tree content. That checker previously assumed
exactly one reviewed patch and now validates every entry of one table.

The architecture's Section 24.5 already permitted reviewed source patches
and vendoring manifests. It now says what a reviewed local source patch is:
a project-owned fork of a published crate that starts from the published
archive, records its complete patched-tree digest, and owes nothing to
upstream acceptance. The persistence row of the dependency table names the
fork, and the source ledger carries the same paragraph the `opaque-ke` patch
has. Both documents were refrozen.

## Provenance

- Published archive: redb 4.2.0, crates.io checksum
  `de6c3b63e007e90ce536ec2ae4690826136a20ec8dbbbb400daef1bb999d2e36`.
- Patch: `bounded-transaction.patch`, SHA-256
  `a210fb6523d8ef3ca35831bb1e90a354f5214a5b967448592f59a350f60c43e9`,
  applied with `git apply --directory=vendor/redb-4.2.0 --include='*src/*'`.
  Every one of the eight modified `src/` files matches the `after_sha256`
  that `source.json` records. The patch was also applied to a pristine
  checkout of upstream commit `23b6ba05473b13e69ed4db82f4b5bc07f0c33be9`
  (tag `v4.2.0`), where all twelve recorded digests matched, including the
  changelog, fuzz target and integration test that are not vendored.
- Vendored tree digest:
  `5e61f6ded5791fac67267a03ed774d96c1057e5f2a3ad2aa8e12b5a321bdbbba`.

## Evidence

- `cargo build -p agenc-relay-storage --all-features --locked` compiles the
  fork; `cargo test -p agenc-relay-storage --all-features --locked -- --skip
  qualification_workload` passes 217 and 120 tests, so the ordinary API the
  storage crate uses today is unchanged.
- `python3 scripts/check-workspace.py check` reports 13 workspace packages
  and 319 locked packages; its self-test keeps all 26 rejection cases.
- `cargo deny check` and the gate's strict clippy pass with the path patch.

## What this does and does not close

STO-02 (#55) is withdrawn. STO-03 (#61) is unblocked and now integrates the
bounded API from the fork rather than from a published release; its text
should be read with "published" meaning this vendored source. STO-04, STO-05
and STO-07 follow it as before. The daemon's behaviour is unchanged by this
record: nothing calls the bounded API yet.
