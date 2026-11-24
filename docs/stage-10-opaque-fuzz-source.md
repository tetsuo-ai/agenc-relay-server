# Reviewed OPAQUE source for the server, fuzz targets and SDK consumers

X-09 is implemented. The workspace declares the reviewed `opaque-ke` 4.0.1 tree as an explicit path dependency. Cargo carries that edge into separately rooted applications that depend on the auth crate through Git. The vendor tree is excluded from workspace membership. Architecture §28.8 already specifies workspace-member formatting, so adopting the explicit edge requires no contract amendment.

## Workspace and independent consumer qualification

Architecture Section 28.8 specifies `cargo fmt --check`.
The workspace edge selects `vendor/opaque-ke-4.0.1` directly and excludes it
from workspace membership. The fuzz auth dependency follows that same edge.
The redb overrides remain in both workspaces. Both lockfiles and the reviewed
OPAQUE tree remain byte-for-byte identical.

The workspace and Stage 04 checkers pin the explicit path, workspace
exclusion, and reviewed tree digest. The Stage 04 checker requires both lock
files to contain one local OPAQUE package and refuses a registry override.
The Stage 09 and Stage 10 command pins use the accepted formatting scope.

The Stage 04 gate runs `python3 scripts/check-opaque-consumer.py` against its
checked-out commit. Run `python3 scripts/check-opaque-consumer.py --git <server-git-url> --rev
<full-server-commit>` to build and exercise the shared registration API
from a fresh workspace with no Cargo patch. The check verifies the
consumer-owned lock and Cargo metadata resolve exactly one OPAQUE package
from the same Git revision as auth. It also rehashes the vendored checkout.

## October 2026 fuzz-workspace qualification

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

### Fuzz-workspace evidence

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

### Earlier formatter investigation

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
`scripts/run-stage-ten-workspace.py` pin it. The edge therefore needs
either a Section 28.8 amendment to `cargo fmt --check` (equivalent here,
because the workspace has no path dependency outside its members) in a
normative series, or a vendored tree that `cargo fmt --all` can format.

The second takes more than vendoring the complete published crate. The
published 4.0.1 package itself omits `src/tests.rs`, which its `lib.rs`
declares under `#[cfg(test)]`, so formatting it fails the same way. Measured
on 2026-10-02 with rustfmt 1.98.0 at the crate's edition 2024, every source
file of the vendored tree and every bench, example and integration test of
the published package already matches this repository's `rustfmt.toml`, so
the missing module is the only obstacle. It would have to come from outside
the reviewed package, or `lib.rs` would need a further reviewed patch, and
either changes the tree digest. At that revision, a separately rooted consumer had to repeat the root `[patch]`.
