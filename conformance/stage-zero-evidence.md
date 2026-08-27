# Stage 00 Evidence

Status: implementation complete; schema version 2 checkpoint refresh pending.
The [historical
manifest](evidence/stage-00-8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb.json)
binds a clean Stage 00 gate run for source commit
`8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb` to its checked-in
[artifact](evidence/artifacts/stage-zero-implementation-8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb.json).
The 2026-08-24 pass for commit
`6b48ecb73afd471ed576146483098c19c12893f9` remains historical evidence.

## Verification summary

`bash scripts/check-stage-zero.sh` passed from a clean detached worktree at the
exact source commit.
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
and every reviewed Rust and Cargo policy tool, then invokes the same recorded
command set. CI validator
mutations reject floating actions, write permission, weakened failures, missing
audit policy, and globally widened coverage instrumentation.

## S00-010

`EVID-S00-010-MANIFEST-SCHEMA`: the closed JSON Schema and validator bind every
record to a catalog ID and require command, exact ordered toolchain and policy
hash, source and lock hashes, target, feature, time, result, artifact, and
nonempty limitation fields. Schema version 1 remains archive-only. Seventy-four
seeded rejection cases cover missing, duplicate, stale, invalid, unbound,
legacy, toolchain, and artifact-provenance categories.

## S00-900

`EVID-S00-900-STAGE-GATE`: the recorded run passed from a clean detached
worktree at the exact source commit on both targets, coverage exceeded 90%, the
release graph excluded testkit, and the binary refused to impersonate a server.
The historical manifest records the earlier required gate on exact source commit
`8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb` with a verified artifact path and
is retained as archive evidence. A fresh schema version 2 run is required to
close `S00-900` for the current source.
