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
0.7.6 and no patched 0.5 release exists. The current Stage 09 gate remains blocked.
[RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html)

The workspace additionally reports `rustls` 0.23.45 and `rustls-webpki`
0.103.15. Same-series patches are available in 0.23.46 and 0.103.16,
respectively. These upgrades remain pending.
[RUSTSEC-2026-0346](https://rustsec.org/advisories/RUSTSEC-2026-0346.html),
[RUSTSEC-2026-0347](https://rustsec.org/advisories/RUSTSEC-2026-0347.html),
[RUSTSEC-2026-0348](https://rustsec.org/advisories/RUSTSEC-2026-0348.html),
[RUSTSEC-2026-0349](https://rustsec.org/advisories/RUSTSEC-2026-0349.html),
[RUSTSEC-2026-0382](https://rustsec.org/advisories/RUSTSEC-2026-0382.html)
