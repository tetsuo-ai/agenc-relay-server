# Dependency patch evidence for 2026-11-23

The server candidate based on `ba3a59e8714900cf0277c04284d7285b30d06a6d`
applies the following same-series security patches to the workspace and fuzz
lockfiles. Architecture §24.4 permits patch upgrades when canonical vectors
remain byte-identical.

| Package | Previous | Patched | RustSec |
| --- | --- | --- | --- |
| `ctutils` | 0.4.2 | 0.4.4 | [RUSTSEC-2026-0385](https://rustsec.org/advisories/RUSTSEC-2026-0385.html) |
| `tokio` | 1.53.1 | 1.53.3 | [RUSTSEC-2026-0386](https://rustsec.org/advisories/RUSTSEC-2026-0386.html) |
| `rustix` | 1.1.4 | 1.1.6 | [RUSTSEC-2026-0486](https://rustsec.org/advisories/RUSTSEC-2026-0486.html) |
| `rustls` | 0.23.45 | 0.23.46 | [RUSTSEC-2026-0346](https://rustsec.org/advisories/RUSTSEC-2026-0346.html), [0347](https://rustsec.org/advisories/RUSTSEC-2026-0347.html), [0348](https://rustsec.org/advisories/RUSTSEC-2026-0348.html), [0349](https://rustsec.org/advisories/RUSTSEC-2026-0349.html) |
| `rustls-webpki` | 0.103.15 | 0.103.16 | [RUSTSEC-2026-0382](https://rustsec.org/advisories/RUSTSEC-2026-0382.html) |

The first three rows are the first commit of the topic, and the sections
below up to the combined results record that commit. The last two rows are
its second commit, which moves the `rustls` pin, the `rustls-webpki` lock
entry, the Stage 06 inventory and the workspace checker, and keeps the
initial `rustls` and `tokio` records in the frozen source ledger. `rustls`
and `rustls-webpki` are in the workspace lock file only; the fuzz graph
holds neither.

Both lockfile diffs contain only the three version and checksum pairs.
The direct dependency feature sets are identical. The current dependency
inventories and workspace checker enforce the patched pins. The workspace
checker also verifies Tokio 1.53.1 in the frozen initial source ledger.
The specification manifest, canonical vectors, reviewed vendor trees, and
both advisory policies match the base revision byte-for-byte.

## Validation

- `bash scripts/check-spec.sh`, `cargo fmt --all --check`, and
  `git diff --check` passed.
- `python3 scripts/check-workspace.py check` and
  `python3 scripts/check-workspace.py self-test` passed with 27 rejection
  cases. The Stage 04 check and self-test passed with 10 rejection cases via
  `python3 scripts/check-stage-four.py check` and
  `python3 scripts/check-stage-four.py self-test`. The Stage 05 and 06
  checks passed via `python3 scripts/check-stage-five.py check` and
  `python3 scripts/check-stage-six.py check`.
- `cargo test --locked --offline -p agenc-relay-crypto -p agenc-relay-auth --test stage_four_vectors`
  passed all eight tests against the canonical crypto and OPAQUE vectors.
- `cargo test --locked --offline -p agenc-relay-runtime --lib registration::tests`
  passed all 12 runtime registration tests.
- `cargo test --locked --offline -p agenc-relay-storage --test stage_five`
  passed 157 cases on shared XFS. Its production qualification workload
  returned `StaleState` after the boundary samples registered changing
  free space between the refusal and check. A serial rerun of just that case
  with `CARGO_TARGET_DIR` on a quiet user tmpfs passed via
  `cargo test --locked --offline -p agenc-relay-storage --test stage_five qualification_workload::production_workload_measures_every_required_case_and_phase -- --exact`.
  The same isolated run passed at the base revision. The signed ext4
  evidence remains unchanged.

## Audit results

`cargo deny --offline --locked --all-features check` and
`cargo deny --offline --locked --manifest-path fuzz/Cargo.toml --config fuzz/deny.toml check`
used cargo-deny 0.20.2 and RustSec database revision
`8b75c83c3c9142dd18e93d75b8d895a13d285861`. Bans, licenses, and sources
passed in both. Comparing both commands on an archive of the base revision
confirmed that the three patched advisories disappeared and every remaining
advisory predates the candidate.

Both graphs still report `crypto-bigint` 0.5.5 via `elliptic-curve` 0.13.8 and
the reviewed `opaque-ke` 4.0.1 used by `agenc-relay-auth`. The workspace has
additional independent elliptic-curve users. RustSec lists a fix starting at
0.7.6 and no patched 0.5 release exists. At this commit the Stage 09 gate
remained blocked; the exception recorded below resolves it.
[RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html)

At the first commit the workspace additionally reported `rustls` 0.23.45
and `rustls-webpki` 0.103.15, whose same-series patches the second commit
applies (the last two rows of the table).

## Combined results on `main`

The topic was merged on `main` at `cb77838bf05216a9ed667b8994fcc0c64f7262c0`
(#198). On the merged tree:

- `cargo fmt --all --check` and `cargo clippy --workspace --all-targets
  --all-features --locked --offline -- -D warnings` exit 0.
- `cargo nextest run --workspace --all-features --locked --offline
  --no-fail-fast` passes 5,174 of 5,174 tests; it skips the 23 ignored tests
  and the storage qualification workload the default profile leaves out.
- `bash scripts/run-stage-eight-model.sh` exits 0.
- `cargo deny check`, `cargo audit --deny warnings` and `cargo deny
  --manifest-path fuzz/Cargo.toml check` report one advisory where the base
  reported nine: RUSTSEC-2026-0387.

## RUSTSEC-2026-0387 is a recorded exception

`crypto-bigint` 0.5.5 cannot be patched in place: the fix starts at 0.7.6,
which needs `elliptic-curve` 0.14, and the newest `opaque-ke` and `voprf`
releases on that series are prereleases (5.0.0-pre.0 and 0.6.0-pre.2), while
`openmls_rust_crypto` 0.6.0 and `mls-rs-crypto-rustcrypto` 0.22.1 hold the
0.13 series of the curve crates. The advisory names timing variability in
subtraction, zero counting, division and Montgomery multiplication on secret
integers. The daemon runs none of that code:

- `crypto-bigint` has one dependent, `elliptic-curve` 0.13.8 (`cargo tree
  --workspace --all-features --locked -i crypto-bigint@0.5.5 --depth 1`).
- The production dependents of `elliptic-curve` are the reviewed `opaque-ke`
  4.0.1 and its `voprf` 0.5.0 alone (`cargo tree -p agenc-relay-server
  --all-features --locked -e normal,build -i elliptic-curve@0.13.8`), built
  with `ristretto255` as their only group, whose arithmetic is
  `curve25519-dalek`'s. The fuzz graph has the same two dependents.
- Neither names `crypto-bigint` in its sources. `voprf`'s ristretto255 group
  takes `hash2curve::{ExpandMsg, ExpandMsgXmd, Expander}` from
  `elliptic-curve`, a hash expansion that uses no big integer; `opaque-ke`
  uses `elliptic-curve` only in its generic curve group and its ECDSA
  variant, which no ristretto255 build instantiates.
- The unoptimized daemon holds no `crypto_bigint` symbol (`nm -C
  target/debug/arcd | grep -c crypto_bigint` prints 0), and its only
  `elliptic_curve` symbols are of `hash2curve::hash2field::expand_msg` and
  `error`: the modules of `elliptic-curve` that call `crypto-bigint`
  (`scalar`, `field`, `arithmetic` and `ops`) are not in it.

The other dependents of `elliptic-curve` (`p256`, `p384`, `k256`, `ecdsa`
and `primeorder`) are reached only by the Stage 08 test clients, which are
never shipped. What keeps this true is already checked: the vendored
`opaque-ke` tree digest, its pinned feature set and the closed list of
direct dependencies in `scripts/check-workspace.py`.

`.cargo/audit.toml`, `deny.toml` and `fuzz/deny.toml` record the exception
with this reason. It is to be removed when a stable `opaque-ke` release uses
`elliptic-curve` 0.14 and the test clients' curve crates move. With it, all
three advisory commands exit 0 and the 59 static-lane commands of the
Stage 09 gate all exit 0.
