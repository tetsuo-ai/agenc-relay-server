# Reviewed OPAQUE source in the fuzz workspace

This record covers X-09 of the SDK program (2026-10-01, outside master #35).
X-09 asked for the reviewed local `opaque-ke` 4.0.1 source in
`vendor/opaque-ke-4.0.1` to be selected by an explicit path on the root
workspace declaration instead of a root `[patch.crates-io]` entry, because
Cargo applies a `[patch]` table only to the workspace that declares it. Two
resolvers outside the root workspace therefore took the unpatched crates.io
release without a warning: the fuzz workspace and any separately rooted
consumer of the auth crate, such as the SDK. This change repairs the fuzz
workspace. The explicit edge was built and measured, and it is not applied,
because it fails a gate that the frozen architecture names (below).

## What changed

- `fuzz/Cargo.toml`: the fuzz workspace's own `[patch.crates-io]`, which
  already selects the redb fork, now also selects `../vendor/opaque-ke-4.0.1`.
- `fuzz/Cargo.lock`: regenerated offline. Its `opaque-ke` entry loses the
  registry source and checksum and resolves the vendored copy; nothing else
  in it changed.
- `scripts/check-stage-four.py` requires the fuzz workspace's override to
  name the reviewed directory and requires both `Cargo.lock` and
  `fuzz/Cargo.lock` to resolve exactly one `opaque-ke` 4.0.1 with neither a
  source nor a checksum, which is how Cargo records a local path. Six new
  self-test cases cover a missing or moved fuzz
  override, a registry entry in the fuzz lock, a second package in a lock, a
  Git entry without a checksum and a local entry at another version (10
  cases, 4 before).
- `conformance/stage-four-evidence.md` describes the comparison.

The root manifest, `Cargo.lock`, the vendored tree and its digest
`3365ac7382b2ed771d71c933c7bd1cf772e024042ed8db0899045ea1497a9678`, and the
daemon's resolution are unchanged.

## Evidence

- Failing before, fixed after: with `fuzz/Cargo.toml` and `fuzz/Cargo.lock`
  restored to their previous bytes, `python3 scripts/check-stage-four.py
  check` fails with `fuzz workspace does not select the reviewed local OPAQUE
  source`, and `cargo +nightly-2026-08-24 check --manifest-path
  fuzz/Cargo.toml --bins --locked` compiles the registry `opaque-ke`. With the
  change, the checker passes and
  `cargo +nightly-2026-08-24 tree --manifest-path fuzz/Cargo.toml --locked -i
  opaque-ke` names `vendor/opaque-ke-4.0.1`.
- `cargo deny --manifest-path fuzz/Cargo.toml check` and
  `cargo +nightly-2026-08-24 fmt --manifest-path fuzz/Cargo.toml -- --check`
  pass.

## The explicit edge (not applied)

The edge was built exactly as X-09 describes: `path =
"vendor/opaque-ke-4.0.1"` on the root declaration, `[workspace] exclude` for
that directory, opaque-ke removed from the root `[patch.crates-io]`, a
selection field in `conformance/vendored-dependencies.toml` and the Stage 04
profile, and the workspace and Stage 04 checkers taught the declaration,
the exclude, the patch table and both lockfiles. It kept thirteen members and
a byte-identical `Cargo.lock`, and a separately rooted consumer depending on
`agenc-relay-auth` by Git resolved exactly one `opaque-ke`, from the Git
source's `vendor/opaque-ke-4.0.1` with the reviewed tree digest, where the
same consumer of the base tree (`70c832c`) resolves the unpatched crates.io
release. A consumer that also names crates.io `opaque-ke` itself resolves two
packages with the edge, the registry release and the vendored copy, with no
warning; on the base tree it resolves one, the unpatched release.

It also makes `cargo fmt --all --check` fail. Cargo-fmt's `--all` formats
every package and its local path dependencies; a `[patch]` entry is not one,
a path on the declaration is. The vendored tree holds `src/` and the
manifests only, so its declared tests, benches and examples and its
`src/tests.rs` module are absent and cannot be formatted. Architecture
Section 28.8 lists `cargo fmt --all --check` among the mandatory release
gates, and `conformance/gates.toml`, `scripts/check-ci.py` and
`scripts/run-stage-ten-workspace.py` pin it, so the edge would need either a
Section 28.8 amendment to `cargo fmt --check` (equivalent here, because the
workspace has no path dependency outside its members) in a normative series,
or a complete vendored crate with a new tree digest. Both are left to the
owner; until then a separately rooted consumer must repeat the root `[patch]`.

## Limits

- Separately rooted consumers still resolve the unpatched release unless
  they repeat the root `[patch]`; the SDK's interim root patch remains
  necessary.
- The redb fork stays a root and fuzz `[patch]` as before.

No Stage 04 or Stage 10 task changes state.
