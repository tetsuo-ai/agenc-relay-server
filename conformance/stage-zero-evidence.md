# Stage 00 Evidence

Status: historical pass on 2026-08-24 for commit
`6b48ecb73afd471ed576146483098c19c12893f9`. This report applies only to the
staged tree that was exported with `git checkout-index` and committed without
changing its contents or executable modes. It does not provide evidence for
the current uncommitted tree. No current manifest with a verifiable artifact
path closes `S00-900` under the current evidence policy.

## Verification summary

`bash scripts/check-stage-zero.sh` passed from the clean staged-tree export.
The recorded run used Rust 1.98.0 and checked both
`x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`. It ran the frozen
specification check, every policy validator and negative self-test, formatting,
compilation, Clippy, unit/integration/doc tests, dependency-tree inspection,
`cargo-deny` 0.20.2, `cargo-audit` 0.22.2, and `cargo-llvm-cov` 0.9.0.

Measured Stage-00 coverage is 91.18% branches and 98.87% lines. Branch
instrumentation uses `RUSTC_BOOTSTRAP=1` only for the coverage command because
the pinned compiler still gates LLVM branch instrumentation behind `-Z`; the
variable is forbidden from ordinary build, test, and release compilation.

The corrected ledger contains 237 normative records. At this gate the binary's
only behavior was an unsuccessful refusal stating that daemon behavior was
unavailable. These results establish the implementation foundation; later-stage
status and evidence are recorded separately.

## S00-001

`EVID-S00-001-BASELINE`: `spec-baseline.toml` records all six frozen artifact
hashes and both derived profile hashes. The original specification checker and
the independent baseline checker pass without normative byte changes.

## S00-002

`EVID-S00-002-REQUIREMENTS`: the generated ledger maps 157 BCP 14 statements
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
The catalog exposes 76 unique stable evidence bindings at this commit.

## S00-008

`EVID-S00-008-TESTKIT-ISOLATION`: bounded deterministic clocks and scripted
entropy implement the production clock and entropy traits. Pure reference
model, fault store, and transcript driver tests pass. Cargo
metadata proves testkit is absent from every production edge and release
closure, with no deterministic production feature.

## S00-009

`EVID-S00-009-CI-BASELINE`: the least-privilege workflow pins its sole action
and every tool, then invokes the same recorded command set. CI validator
mutations reject floating actions, write permission, weakened failures, missing
audit policy, and globally widened coverage instrumentation.

## S00-010

`EVID-S00-010-MANIFEST-SCHEMA`: the closed JSON Schema and validator bind every
record to a catalog ID and require command, tool, source/lock, target, feature,
time, result, artifact, and limitation fields. Fifteen malformed fixtures cover
missing, duplicate, stale, invalid, and unbound categories.

## S00-900

`EVID-S00-900-STAGE-GATE`: the recorded run passed from the clean staged-tree
export on both targets, coverage exceeded 90%, the release graph excluded
testkit, and the binary refused to impersonate a server. This historical
observation has no verifiable artifact path and does not close `S00-900`.
