# Stage 00 Evidence

Status: passed on 2026-08-24. This report applies to the exact staged tree that
was exported with `git checkout-index` and then committed without changing its
contents or executable modes.

## Verification summary

`bash scripts/check-stage-zero.sh` passed from the clean staged-tree export.
The gate used Rust 1.98.0 and checked both
`x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`. It ran the frozen
specification check, every policy validator and negative self-test, formatting,
compilation, Clippy, unit/integration/doc tests, dependency-tree inspection,
`cargo-deny` 0.20.2, `cargo-audit` 0.22.2, and `cargo-llvm-cov` 0.9.0.

Measured Stage-00 coverage is 91.18% branches and 98.87% lines. Branch
instrumentation uses `RUSTC_BOOTSTRAP=1` only for the coverage command because
the pinned compiler still gates LLVM branch instrumentation behind `-Z`; the
variable is forbidden from ordinary build, test, and release compilation.

The 243 normative records and all later roadmap requirements remain explicitly
`unimplemented`. The binary's only behavior is an unsuccessful refusal stating
that daemon behavior is unavailable. These results establish the implementation
foundation, not a claim that the daemon or protocol is implemented or secure.

## S00-001

`EVID-S00-001-BASELINE`: `spec-baseline.toml` records all six frozen artifact
hashes and both derived profile hashes. The original specification checker and
the independent baseline checker pass without normative byte changes.

## S00-002

`EVID-S00-002-REQUIREMENTS`: the generated ledger maps 163 BCP 14 statements
and all 80 Section-27 invariants to stable source, crate, evidence, and status
records. Nine negative fixtures reject missing, duplicate, stale, waived, or
unbound mappings.

## S00-003

`EVID-S00-003-BUILD-CONTRACT`: `rust-toolchain.toml`, package metadata, resolver
3, lockfile format 4, and both target checks prove the pinned Rust contract.

## S00-004

`EVID-S00-004-CRATE-GRAPH`: Cargo metadata contains exactly 13 packages and the
Section-24 edge set. The graph validator rejects forbidden edges, cycles,
missing crates, binary back-edges, and production testkit reachability.

## S00-005

`EVID-S00-005-SOURCE-POLICY`: all crate roots forbid unsafe code. Workspace
lints and the source scanner reject unsafe tokens, panic/placeholder paths,
unbounded channels, unreviewed production assertions, and code-shape triggers;
11 seeded cases exercise those branches.

## S00-006

`EVID-S00-006-DEPENDENCIES`: root declarations exactly match the frozen direct
versions, features, and crates.io checksums. Git, wildcard, default-feature,
unknown-source, license, yanked, duplicate, and advisory policies are closed;
`cargo deny check` and `cargo audit --deny warnings` pass.

## S00-007

`EVID-S00-007-EVIDENCE-LAYOUT`: unit/integration, vector, transcript, property,
fuzz, Loom, fault, interoperability, capacity, and release locations are named.
The catalogs expose 254 unique stable evidence bindings.

## S00-008

`EVID-S00-008-TESTKIT-ISOLATION`: bounded deterministic clock, scripted entropy,
pure reference model, fault store, and transcript driver tests pass. Cargo
metadata proves testkit is absent from every production edge and release
closure, with no deterministic production feature.

## S00-009

`EVID-S00-009-CI-BASELINE`: the least-privilege workflow pins its sole action
and every tool, then invokes the same complete gate. CI validator mutations
reject floating actions, write permission, weakened failures, missing audit
policy, and globally widened coverage instrumentation.

## S00-010

`EVID-S00-010-MANIFEST-SCHEMA`: the closed JSON Schema and validator bind every
record to a catalog ID and require command, tool, source/lock, target, feature,
time, result, artifact, and limitation fields. Fifteen malformed fixtures cover
missing, duplicate, stale, invalid, and unbound categories.

## S00-900

`EVID-S00-900-STAGE-GATE`: the complete gate passes from the clean staged-tree
export on both targets, coverage exceeds 90%, the release graph excludes
testkit, the binary refuses to impersonate a server, and every later normative
record remains `unimplemented`.
