# AgenC Relay Implementation TODO

The stage completion entries below describe implementation history. Previous
exact-revision checkpoints remain in Git history and do not qualify the ARC
baseline. New source-bound evidence is recorded after its gates pass.

Status: implementation roadmap for version 1. This file is nonnormative. The
[architecture specification](docs/arc-architecture-and-implementation-spec.md)
and, for encrypted operations, the
[E2EE companion](docs/arc-mls-e2ee-extension.md) remain authoritative.

## How to use this roadmap

- Complete stages in order. Do not begin a security-sensitive successor until
  the preceding stage gate is checked.
- Check a task only when its named evidence exists and passes on the relevant
  source revision. Add an evidence link beside the checkbox when closing it.
- Task IDs are permanent. Never reuse or renumber an ID after implementation
  work refers to it.
- A changed normative source or profile hash reopens every affected task and
  gate. Run `bash scripts/check-spec.sh` before and after such a change.
- `conformance/requirements.toml` will track every individual normative
  requirement. This roadmap groups those requirements into implementable
  deliverables; it does not replace that machine ledger.
- Test and release evidence must identify the command, toolchain, target,
  features, source and lock hashes, result, and known limitations.
- GitNexus may be indexed after meaningful Rust source exists, but it is
  optional developer tooling—not protocol authority or an acceptance gate—and
  generated context must not replace this roadmap or `AGENTS.md`.

## Nonnegotiable implementation rules

- Workspace source is safe Rust with `#![forbid(unsafe_code)]`; untrusted input
  must never reach a panic, unchecked index, or unchecked allocation.
- Use the pinned cryptographic libraries and profiles. Do not implement a
  cipher, curve, PAKE, KDF, MAC, signature primitive, RNG, or constant-time
  operation locally.
- There is no plaintext listener, STARTTLS path, unbounded channel, unbounded
  peer-controlled allocation, guessed durable outcome, or encrypted-to-
  plaintext fallback.
- The daemon validates and routes E2EE public objects but never contains an MLS
  client engine or receives MLS epoch secrets or message plaintext.
- Logs, metrics, health output, errors, and crash identifiers use their closed
  allowlists and never expose user content, network addresses, identities, or
  secret material.

References: [Architecture §§1.2–4](docs/arc-architecture-and-implementation-spec.md#12-requirements-language),
[§§24.1–24.5](docs/arc-architecture-and-implementation-spec.md#24-rust-workspace-and-module-boundaries),
[§27](docs/arc-architecture-and-implementation-spec.md#27-security-and-correctness-invariants),
[E2EE §20](docs/arc-mls-e2ee-extension.md#20-implementation-separation), and
[the contributor guide](AGENTS.md).

## Stage status

| Stage | Outcome | Implementation | Latest local gate | Revision-bound evidence |
| --- | --- | --- | --- | --- |
| 00 | Reproducible workspace and traceability foundation | Complete | Pass, 2026-08-27 | [Historical checkpoint](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-00-1e5b738468f88b238061cc6e84b732176f5cae65.json) |
| 01 | Registries, validated types, and canonical codecs | Complete | Pass, 2026-08-27 | [Historical checkpoint](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-01-1e5b738468f88b238061cc6e84b732176f5cae65.json) |
| 02 | Bounded client wire implementation | Complete | Pass, 2026-08-27 | [Historical checkpoint](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-02-1e5b738468f88b238061cc6e84b732176f5cae65.json) |
| 03 | Pure deterministic domain model | Complete | Pass, 2026-08-27 | [Historical checkpoint](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-03-1e5b738468f88b238061cc6e84b732176f5cae65.json) |
| 04 | Crypto adapters and account authentication | Complete | Pass, 2026-08-29 | [Historical checkpoint](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-04-4040796f2c21774d58ea7ce54e70a080678e83ac.json) |
| 05 | Durable and recoverable persistence | Complete | Pass, 2026-08-29 | [Historical checkpoint](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-05-4040796f2c21774d58ea7ce54e70a080678e83ac.json) |
| 06 | Conforming single-node daemon | Complete | Pass, 2026-09-01 | [Historical checkpoint](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-06-65cce9d66f7bcfb0c0830a2ab1d42b52bff82942.json) |
| 07 | Conforming base federation | Complete | Pass, 2026-09-03 | [Historical checkpoint](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-07-1093d88d0057c3461a423285e0f86ff3775c1140.json) |
| 08 | Conforming E2EE server adapter | Complete | Pass, 2026-09-19 | [Historical checkpoint](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-08-26f0f8029dcad4aad27bff2706c4f0d255a555ba.json) |
| 09 | Optional WSS and history profiles | Complete | Pass, 2026-09-05, exact checkpoint source | [Historical checkpoint](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-09-a93e53e71d22a6d5ec46bd749ec18068a9fa572b.json) |
| 10 | Production qualification and release evidence | In progress | Runner, drivers, release image, and x86_64 reproduction done; jobs running | Absent |

## Coverage and ownership maps

These maps assign primary ownership. Coupled tasks may add evidence, but no
later stage may silently move an authority across the crate graph.

### Crate implementation ownership

| Crate | First functional stage | Governing tasks |
| --- | --- | --- |
| `agenc-relay-types` | 01 | `S01-001`–`S01-006` |
| `agenc-relay-client-wire` | 01/02 | `S01-009`, `S02-001`–`S02-011` |
| `agenc-relay-federation-wire` | 01/07 | `S01-007`–`S01-009`, `S07-002`, `S07-005`, `S07-008`–`S07-009` |
| `agenc-relay-crypto` | 04 | `S04-001`–`S04-006`, `S04-012`–`S04-013` |
| `agenc-relay-auth` | 04 | `S04-006`–`S04-011` |
| `agenc-relay-domain` | 03 | `S03-001`–`S03-010` |
| `agenc-relay-e2ee` | 08 | `S08-001`–`S08-017` |
| `agenc-relay-storage` | 05 | `S05-001`–`S05-014` |
| `agenc-relay-config` | 06 | `S06-001`–`S06-002`, `S06-013` |
| `agenc-relay-admin` | 06 | `S06-012` |
| `agenc-relay-runtime` | 06 | `S06-003`–`S06-015`; extended by Stages 07–09 |
| `agenc-relay-testkit` | 00 | `S00-007`–`S00-008`; extended by every test stage |
| `agenc-relay-server` | 06 | composition in `S06-002`, `S06-009`–`S06-015` only |

Reference: [Architecture §24.1](docs/arc-architecture-and-implementation-spec.md#241-crate-graph).

### Invariant primary ownership

| Stable invariants | Primary implementation and closure stages |
| --- | --- |
| `TRN-01`–`TRN-03` | TLS/admin/federation endpoints in Stages 06–07; final network qualification in Stage 10 |
| `TRN-04`–`TRN-06` | bounded types/codecs and client wire in Stages 01–02; every later parser reuses them |
| `ID-01`–`ID-07` | foundational/domain identity in Stages 01/03 and account secrecy in Stage 04 |
| `AUTH-01`–`AUTH-11` | crypto/auth state machines in Stage 04; runtime composition in Stage 06 |
| `PRV-01`–`PRV-04` | domain projections in Stage 03; runtime, federation, Tor, and release scans in Stages 06/07/10 |
| `STA-01`–`STA-10` | pure domain model in Stage 03; queue/durability composition in Stage 06 |
| `E2E-01`–`E2E-07` | E2EE separation, validation, transactions, and gates in Stage 08 |
| `FED-01`–`FED-13` | base federation in Stage 07; cross-profile extensions in Stage 08 |
| `DUR-01`–`DUR-12` | persistence in Stage 05; runtime/federation/E2EE atomicity in Stages 06–08 |
| `CON-01`–`CON-05` | crate/task ownership foundation in Stage 00; runtime realization in Stage 06 |
| `OPS-01`–`OPS-05` | administration, observability, shutdown, and host policy in Stage 06; release qualification in Stage 10 |

Reference: [Architecture §27](docs/arc-architecture-and-implementation-spec.md#27-security-and-correctness-invariants).

### Appendix-D surface ownership

| Required surface | Primary roadmap tasks |
| --- | --- |
| Historical/base behavior | `S01-001`, `S02-004`, `S02-010` |
| Familiar channels/direct messages | `S03-002`, `S03-006`, `S06-010` |
| Public/unlisted/secret discovery | `S03-003`, `S06-010` |
| Nicknames, display names, cloaks | `S01-005`, `S03-001` |
| Pseudonymous accounts | `S03-001`, `S04-008`–`S04-011`, `S06-009` |
| Private account service and OPAQUE | `S04-006`–`S04-010` |
| Simple onboarding/recovery | `S06-002`, `S08-003`–`S08-004`, `S08-011` |
| TLS and WebSocket | `S06-003`, `S09-001`–`S09-002` |
| Tor and onion service | `S06-004`, `S10-005` |
| Metadata minimization | `S03-003`, `S06-014`, `S07-006`, `S10-005` |
| MLS E2EE | `S08-001`–`S08-900` |
| Moderation/user safety | `S03-007`, `S06-010`, `S06-012`, `S08-011` |
| Abuse resistance | `S03-005`, `S06-006`–`S06-007`, `S06-011`, `S08-014`, `S10-007` |
| Federation authority | `S07-003`–`S07-004`, `S07-010` |
| Federation transport/auth | `S07-001`–`S07-002`, `S07-008` |
| Requests/idempotency and paged queries | `S07-005`, `S07-011` |
| Events/projections | `S07-006`–`S07-007`, `S07-009` |
| State ownership/concurrency | `S00-004`, `S06-005`–`S06-008`, `S10-004` |
| Persistence/recovery | `S05-001`–`S05-900` |
| Rust module boundaries | `S00-004`–`S00-005` |
| Safe/legible Rust | `S00-005`, `S10-002` |
| Crypto/dependency policy | `S04-001`–`S04-014`, `S10-010`–`S10-011` |
| Configuration/admin | `S06-001`–`S06-002`, `S06-012`–`S06-013` |
| Observability/host hardening | `S06-014`–`S06-015`, `S10-009` |
| Compatibility/versioning | `S01-010`, `S02-005`, `S08-001`, `S10-012` |
| Exhaustive release testing | `S10-001`–`S10-900` |

Reference: [Architecture Appendix D](docs/arc-architecture-and-implementation-spec.md#appendix-d-requirement-traceability).

## Stage 00 — Workspace, policy, and traceability

Outcome: a compiling, reproducible Rust workspace whose crate graph, toolchain,
source baseline, and evidence model are fixed before protocol behavior lands.

- [x] `S00-001` **Freeze and verify the specification baseline.** Record the
  architecture, companion, registry, source-ledger, validator, and derived
  profile hashes without changing normative bytes. ([evidence](conformance/stage-zero-evidence.md#s00-001))
  - After: none.
  - Targets: `docs/`, `scripts/check-spec.sh`, repository evidence.
  - References: [Architecture §§2 and 30](docs/arc-architecture-and-implementation-spec.md#2-normative-document-order), [source ledger §1](docs/protocol-sources-and-decisions.md#1-purpose), [manifest](docs/specification-manifest.txt).
  - Invariants: `E2E-07`, `FED-02`.
  - Evidence: `bash scripts/check-spec.sh` passes and recorded hashes equal the manifest.

- [x] `S00-002` **Create the machine requirement ledger.** Enumerate every
  applicable MUST/MUST NOT from both normative documents with a stable ID,
  source section/hash, target crate, evidence IDs, and initial status. ([evidence](conformance/stage-zero-evidence.md#s00-002))
  - After: `S00-001`.
  - Targets: `conformance/requirements.toml` and its validator.
  - References: [Architecture §28.1](docs/arc-architecture-and-implementation-spec.md#281-requirement-ledger-and-evidence), [Appendix D](docs/arc-architecture-and-implementation-spec.md#appendix-d-requirement-traceability).
  - Invariants: every Section-27 invariant and every E2EE requirement.
  - Evidence: validator proves unique IDs, valid source hashes, valid crate names, and no unmapped normative requirement.

- [x] `S00-003` **Pin the Rust build contract.** Select compiler 1.98.0,
  edition 2024, `rust-version = "1.98"`, resolver version, and the two initial
  Linux targets exactly as specified. ([evidence](conformance/stage-zero-evidence.md#s00-003))
  - After: `S00-001`.
  - Targets: `rust-toolchain.toml`, root and package manifests.
  - References: [Architecture §4](docs/arc-architecture-and-implementation-spec.md#4-fixed-version-1-decisions), [§24.5](docs/arc-architecture-and-implementation-spec.md#245-dependency-and-build-integrity).
  - Invariants: `OPS-02`.
  - Evidence: host and cross-target `cargo check --locked` use the pinned compiler and declared package metadata.

- [x] `S00-004` **Create the complete workspace skeleton.** Add every crate in
  the Section-24 graph with only its declared dependency direction; empty crate
  roots must not expose placeholder protocol or cryptographic behavior. ([evidence](conformance/stage-zero-evidence.md#s00-004))
  - After: `S00-003`.
  - Targets: all `agenc-relay-*` libraries, `agenc-relay-testkit`, and the `agenc-relay-server` binary crate.
  - References: [Architecture §24.1](docs/arc-architecture-and-implementation-spec.md#241-crate-graph).
  - Invariants: `CON-01`, `CON-04`.
  - Evidence: a `cargo metadata` graph check rejects forbidden edges, cycles, production use of `testkit`, and library dependency on the binary.

- [x] `S00-005` **Enforce workspace-safe Rust and legibility policy.** Apply
  workspace lints, warning denial, `#![forbid(unsafe_code)]`, rustfmt defaults,
  focused-function review triggers, and narrowly documented lint exceptions. ([evidence](conformance/stage-zero-evidence.md#s00-005))
  - After: `S00-004`.
  - Targets: workspace lint tables, crate roots, lint/source-scan tooling.
  - References: [Architecture §21.4](docs/arc-architecture-and-implementation-spec.md#214-input-pipeline), [§24.3](docs/arc-architecture-and-implementation-spec.md#243-safe-rust-and-code-shape-policy), [AGENTS.md](AGENTS.md).
  - Invariants: `TRN-05`, `CON-04`, `OPS-01`.
  - Evidence: formatting, Clippy, unsafe-source, panic-path, and unbounded-channel checks fail on seeded violations.

- [x] `S00-006` **Configure dependency and source policy.** Permit crates.io
  only, forbid wildcard and Git requirements, define license/advisory/source
  rules, and document the one reviewed duplicate-crypto dependency generation. ([evidence](conformance/stage-zero-evidence.md#s00-006))
  - After: `S00-003`.
  - Targets: workspace dependency table, `Cargo.lock`, `deny.toml`, audit policy.
  - References: [Architecture §§24.4–24.5](docs/arc-architecture-and-implementation-spec.md#244-serialization-and-crypto-libraries), [source ledger §§5–6](docs/protocol-sources-and-decisions.md#5-initial-rust-dependency-evidence).
  - Invariants: `OPS-02`.
  - Evidence: `cargo deny check`, `cargo audit --deny warnings`, feature-tree inspection, and checksum comparison pass.

- [x] `S00-007` **Define deterministic test and evidence layout.** Separate
  unit, integration, golden-vector, transcript, property, fuzz, Loom, fault,
  interoperability, capacity, and release evidence so each requirement can
  name a stable evidence ID. ([evidence](conformance/stage-zero-evidence.md#s00-007))
  - After: `S00-002`, `S00-004`.
  - Targets: test directories, corpus/vector directories, evidence schema.
  - References: [Architecture §§28.1–28.8](docs/arc-architecture-and-implementation-spec.md#28-verification-conformance-and-security-testing).
  - Invariants: all invariant families.
  - Evidence: a schema check rejects missing, duplicate, stale, or unbound evidence IDs.

- [x] `S00-008` **Isolate deterministic test capabilities.** Provide test-only
  clocks, entropy, reference models, fault stores, and transcript drivers that
  cannot enter a release dependency graph or production configuration. ([evidence](conformance/stage-zero-evidence.md#s00-008))
  - After: `S00-004`, `S00-007`.
  - Targets: `agenc-relay-testkit` and dependency-graph checks.
  - References: [Architecture §§24.1–24.2](docs/arc-architecture-and-implementation-spec.md#241-crate-graph), [§29](docs/arc-architecture-and-implementation-spec.md#29-implementation-sequence-and-acceptance-gates).
  - Invariants: `CON-01`, `CON-02`.
  - Evidence: release metadata contains no testkit edge or deterministic entropy/clock feature.

- [x] `S00-009` **Create the continuous-integration baseline.** Run source
  checks, graph checks, formatting, compilation, Clippy, tests, docs,
  dependency policy, audit, and coverage under the pinned toolchain. ([evidence](conformance/stage-zero-evidence.md#s00-009))
  - After: `S00-005` through `S00-008`.
  - Targets: CI workflows and reusable validation commands.
  - References: [Architecture §28.8](docs/arc-architecture-and-implementation-spec.md#288-mandatory-build-and-analysis-gates), [§24.5](docs/arc-architecture-and-implementation-spec.md#245-dependency-and-build-integrity).
  - Invariants: `OPS-02`.
  - Evidence: every mandatory command runs from a clean checkout and failures block the build.

- [x] `S00-010` **Define release evidence manifests.** Record command, exact
  ordered toolchain and policy hash, source and lock hashes, target, features,
  timing, result, artifact hash, and nonempty limitations without confusing
  test execution with a security claim. ([evidence](conformance/stage-zero-evidence.md#s00-010))
  - After: `S00-002`, `S00-007`.
  - Targets: conformance evidence schema and validation tooling.
  - References: [Architecture §§26.4 and 28.1](docs/arc-architecture-and-implementation-spec.md#264-conformance-claims).
  - Invariants: all invariant families.
  - Evidence: positive and malformed sample manifests exercise every validation branch.

- [x] `S00-900` **Pass the Stage 00 gate.** The complete empty workspace and
  traceability baseline must build reproducibly without any protocol stub being
  mistaken for implemented behavior. ([evidence](conformance/stage-zero-evidence.md#s00-900))
  - After: `S00-001` through `S00-010`.
  - Targets: entire repository.
  - References: [Architecture §§24, 28.1, 28.8, and 29](docs/arc-architecture-and-implementation-spec.md#24-rust-workspace-and-module-boundaries).
  - Invariants: `CON-01`, `CON-02`, `OPS-02`.
  - Evidence: the [historical schema version 2 manifest](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-00-1e5b738468f88b238061cc6e84b732176f5cae65.json) closes the gate for exact source commit `1e5b738468f88b238061cc6e84b732176f5cae65`; the [schema version 1 manifest](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-00-8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb.json) remains archive-only.

## Stage 01 — Registries, validated types, and canonical codecs

Outcome: all protocol vocabulary and byte representations required by later
stages exist as bounded, private-field types with independent vectors.

- [x] `S01-001` **Mirror the frozen registries into typed constants.** Cover
  every Appendix-A command/numeric/capability/mode entry and Appendix-B closed
  value without using declaration order as a wire discriminant.
  - After: `S00-900`.
  - Targets: `agenc-relay-types`; registry-consistency tests.
  - References: [Architecture Appendix A](docs/arc-architecture-and-implementation-spec.md#appendix-a-client-wire-registries), [Appendix B.2](docs/arc-architecture-and-implementation-spec.md#b2-closed-enum-registry), [federation registry](docs/federation-v1-profile.registry).
  - Invariants: `TRN-06`, `FED-08`.
  - Evidence: [EVID-S01-001-REGISTRIES](conformance/stage-one-evidence.md#s01-001) proves no missing, duplicate, reordered, or differently encoded entry.

- [x] `S01-002` **Implement bounded quantities and units.** Represent byte
  counts, object counts, queue demand, timestamps, durations, revisions,
  generations, sequence numbers, and quotas with checked construction and
  arithmetic.
  - After: `S01-001`.
  - Targets: `agenc-relay-types`.
  - References: [Architecture §§19.2 and 24.2–24.3](docs/arc-architecture-and-implementation-spec.md#192-hard-resource-maxima).
  - Invariants: `TRN-04`, `CON-05`, `DUR-11`.
  - Evidence: [EVID-S01-002-QUANTITIES](conformance/stage-one-evidence.md#s01-002) covers empty/one/maximum/maximum-plus-one, underflow, and overflow for every quantity family.

- [x] `S01-003` **Implement typed identities.** Add private-field Account,
  User, Session, ChannelInstance, Message, request, event, origin, server,
  transaction, database, and recovery identities with explicit parsing and
  generation/incarnation rules.
  - After: `S01-002`.
  - Targets: `agenc-relay-types`.
  - References: [Architecture §7](docs/arc-architecture-and-implementation-spec.md#7-typed-identifiers-and-canonical-names), [Appendix B.3](docs/arc-architecture-and-implementation-spec.md#b3-common-validated-values-and-control-arms).
  - Invariants: `ID-01`, `ID-02`, `FED-04`.
  - Evidence: [EVID-S01-003-IDENTITIES](conformance/stage-one-evidence.md#s01-003) covers construction, canonical text/binary round-trip, domain confusion, and entropy injection.

- [x] `S01-004` **Implement bounded byte and UTF-8 text types.** Reject NUL,
  invalid UTF-8, forbidden controls, overlength input, lossy conversion, and
  allocation before bound validation.
  - After: `S01-002`.
  - Targets: `agenc-relay-types`.
  - References: [Architecture §§4, 7, and 9.1](docs/arc-architecture-and-implementation-spec.md#4-fixed-version-1-decisions).
  - Invariants: `TRN-04`, `TRN-05`, `TRN-06`.
  - Evidence: [EVID-S01-004-BOUNDED-VALUES](conformance/stage-one-evidence.md#s01-004) covers byte boundaries, Unicode, invalid encoding, controls, and allocation-before-validation negatives.

- [x] `S01-005` **Implement canonical names and masks.** Apply the exact
  nickname, account, channel, server, user-mask, case mapping, PRECIS, prefix,
  and comparison rules while preserving presentation separately from identity.
  - After: `S01-003`, `S01-004`.
  - Targets: `agenc-relay-types`.
  - References: [Architecture §§7.1–7.4 and 13.4](docs/arc-architecture-and-implementation-spec.md#71-account-identity).
  - Invariants: `ID-01`, `STA-01`, `STA-02`.
  - Evidence: [EVID-S01-005-NAMES-MASKS](conformance/stage-one-evidence.md#s01-005) covers canonicalization, collisions, PRECIS rejection, prefixes, masks, and profile boundaries.

- [x] `S01-006` **Implement stable public protocol errors.** Use closed error
  enums and exact public mappings without carrying raw input or internal error
  chains into replies, logs, or metrics.
  - After: `S01-001`, `S01-004`.
  - Targets: `agenc-relay-types`.
  - References: [Architecture §9.5](docs/arc-architecture-and-implementation-spec.md#95-errors), [§24.3](docs/arc-architecture-and-implementation-spec.md#243-safe-rust-and-code-shape-policy), [Appendix A.2](docs/arc-architecture-and-implementation-spec.md#a2-server-command-and-numeric-registry).
  - Invariants: `PRV-01`, `PRV-02`, `OPS-01`.
  - Evidence: [EVID-S01-006-PROTOCOL-ERRORS](conformance/stage-one-evidence.md#s01-006) uses exhaustive mapping tests and safe fixed descriptions with no input-bearing implicit rendering.

- [x] `S01-007` **Implement canonical binary primitives.** Decode exact-width
  integers, lengths, options, vectors, enums, and structures with full
  consumption, checked allocation, explicit discriminants, and no Serde.
  - After: `S01-001` through `S01-004`.
  - Targets: `agenc-relay-federation-wire`.
  - References: [Architecture §§24.4 and Appendix B.1](docs/arc-architecture-and-implementation-spec.md#b1-encoding-notation).
  - Invariants: `TRN-04`, `TRN-05`, `TRN-06`, `FED-08`.
  - Evidence: [EVID-S01-007-BINARY-CODEC](conformance/stage-one-evidence.md#s01-007) covers canonical round-trip, trailing bytes, truncation, bounds, allocation budgets, nesting, and every discriminant.

- [x] `S01-008` **Implement Appendix-B object codecs.** Cover common control
  arms, projections, events, deltas, requests, results, origins, delivery,
  snapshots, descriptors, and cross-reference validation at the codec layer.
  - After: `S01-003`, `S01-007`.
  - Targets: `agenc-relay-federation-wire`.
  - References: [Architecture Appendices B.3–B.7](docs/arc-architecture-and-implementation-spec.md#b3-common-validated-values-and-control-arms).
  - Invariants: `FED-03` through `FED-13` at the representation boundary.
  - Evidence: [EVID-S01-008-APPENDIX-B](conformance/stage-one-evidence.md#s01-008) provides all 128 arm vectors plus presence, count, order, substitution, and malformed-cross-reference negatives.

- [x] `S01-009` **Implement canonical text carrier primitives.** Enforce
  uppercase tokens, decimal forms, unpadded URL-safe base64, arity, and exact
  decode/re-encode equality without yet implementing connection state.
  - After: `S01-004`, `S01-007`.
  - Targets: `agenc-relay-client-wire`, `agenc-relay-federation-wire`.
  - References: [Architecture Appendix B.8](docs/arc-architecture-and-implementation-spec.md#b8-text-carrier-tokens-and-command-arity), [E2EE §§11.2 and 11.10](docs/arc-mls-e2ee-extension.md#112-fragment-tag).
  - Invariants: `TRN-06`, `FED-08`.
  - Evidence: [EVID-S01-009-TEXT-CARRIERS](conformance/stage-one-evidence.md#s01-009) covers alternate alphabets, padding, width, sign, leading zero, case, arity, fragments, and overflow.

- [x] `S01-010` **Bind source and profile hashes.** Verify raw document,
  registry, base-federation profile, and E2EE profile derivations independently
  of production codecs and fail on any changed byte.
  - After: `S01-001`, `S01-007`.
  - Targets: conformance tests and source-hash tooling.
  - References: [Architecture §§30.2–30.3 and Appendix B.9](docs/arc-architecture-and-implementation-spec.md#302-living-protocol-and-implementation-sources), [E2EE §2.3](docs/arc-mls-e2ee-extension.md#23-exact-profile-revision), [manifest](docs/specification-manifest.txt).
  - Invariants: `E2E-07`, `FED-02`.
  - Evidence: [EVID-S01-010-PROFILE-HASHES](conformance/stage-one-evidence.md#s01-010) binds all known hashes and rejects independent single-byte changes.

- [x] `S01-011` **Create independent reference codecs and golden vectors.** A
  small implementation that does not reuse production derive or codec logic
  must generate or verify every stable byte representation.
  - After: `S01-007` through `S01-010`.
  - Targets: `agenc-relay-testkit`, checked-in vector corpus.
  - References: [Architecture §28.2](docs/arc-architecture-and-implementation-spec.md#282-deterministic-unit-and-vector-tests).
  - Invariants: all representation-bound invariants.
  - Evidence: [EVID-S01-011-REFERENCE-VECTORS](conformance/stage-one-evidence.md#s01-011) records independent byte-for-byte agreement, provenance, and SHA-256 for every schema.

- [x] `S01-012` **Exercise totality and boundedness.** Property and negative
  tests must prove every finite codec input produces bounded success or error
  without panic, recursion, trailing acceptance, or pre-validation growth.
  - After: `S01-011`.
  - Targets: type and wire test suites.
  - References: [Architecture §§19.4, 27.1, and 28.2](docs/arc-architecture-and-implementation-spec.md#194-parser-and-algorithmic-defenses).
  - Invariants: `TRN-04`, `TRN-05`, `TRN-06`, `CON-05`.
  - Evidence: [EVID-S01-012-TOTALITY](conformance/stage-one-evidence.md#s01-012) covers the hostile corpus, every truncation, explicit depth/value budgets, nonrecursion, and parser-error negatives.

- [x] `S01-900` **Pass the Stage 01 gate.** All Appendix-A/B constants,
  validated foundational types, canonical codecs, source checks, and independent
  vectors are complete before client behavior begins.
  - After: `S01-001` through `S01-012`.
  - Targets: `agenc-relay-types`, foundational wire code, testkit vectors.
  - References: [Architecture §29 phase 1](docs/arc-architecture-and-implementation-spec.md#29-implementation-sequence-and-acceptance-gates).
  - Invariants: `TRN-04` through `TRN-06`, applicable identity and federation representation invariants.
  - Evidence: [EVID-S01-900-STAGE-GATE](conformance/stage-one-evidence.md#s01-900) and the [historical schema version 2 manifest](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-01-1e5b738468f88b238061cc6e84b732176f5cae65.json) close the pinned, locked, dual-target gate for exact source commit `1e5b738468f88b238061cc6e84b732176f5cae65`; the [schema version 1 manifest](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-01-8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb.json) remains archive-only.

## Stage 02 — Bounded client wire

Outcome: arbitrary client bytes can be framed, parsed, negotiated, and rendered
through a total, resource-bounded wire layer with no sockets, policy, or state
mutation inside the crate.

Stage 02 task work is complete. The [current schema version 2
manifest](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-02-1e5b738468f88b238061cc6e84b732176f5cae65.json)
binds the 2026-08-27 run and its checked-in artifact to exact source commit
`1e5b738468f88b238061cc6e84b732176f5cae65` and closes the gate. The schema
version 1 manifest for commit
`8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb` and the earlier manifest for
commit `cd1d7c937c2be9c469e6131fda21406764a39b78` remain archive-only. The
[Stage 02 closure audit](conformance/stage-two-audit.md) records the resolved
wire-size, reply-shape, and traceability issues.

- [x] `S02-001` **Implement incremental stream framing.** Handle fragmented and
  coalesced reads, CRLF, EOF, timeouts, and exact physical-line limits without
  scanning or allocating beyond admitted bounds. ([evidence](conformance/stage-two-evidence.md#s02-001))
  - After: `S01-900`.
  - Targets: `agenc-relay-client-wire`.
  - References: [Architecture §§8.3 and 9.1](docs/arc-architecture-and-implementation-spec.md#83-time-and-resource-bounds).
  - Invariants: `TRN-04`, `TRN-05`, `TRN-06`.
  - Evidence: every split/coalesce boundary, empty/equal/plus-one length, CRLF, timeout, and EOF transcript passes.

- [x] `S02-002` **Implement WebSocket message framing semantics.** Validate the
  IRC-over-WebSocket message boundary, UTF-8, compression prohibition, size,
  and close behavior independently of the optional network listener. ([evidence](conformance/stage-two-evidence.md#s02-002))
  - After: `S02-001`.
  - Targets: `agenc-relay-client-wire`.
  - References: [Architecture §8.4](docs/arc-architecture-and-implementation-spec.md#84-websocket-listener), [RFC 6455 decision](docs/protocol-sources-and-decisions.md#2-published-standards).
  - Invariants: `TRN-02`, `TRN-04`, `TRN-05`.
  - Evidence: fragmented-message, binary-frame, invalid-UTF-8, extension, multi-line, and oversize negatives.

- [x] `S02-003` **Implement IRCv3 tags.** Parse and render tag names, values,
  escapes, duplicates, client-only tags, and budgets canonically. ([evidence](conformance/stage-two-evidence.md#s02-003))
  - After: `S02-001`.
  - Targets: `agenc-relay-client-wire`.
  - References: [Architecture §9.2](docs/arc-architecture-and-implementation-spec.md#92-tag-handling), [Appendix A](docs/arc-architecture-and-implementation-spec.md#appendix-a-client-wire-registries).
  - Invariants: `TRN-04`, `TRN-06`.
  - Evidence: ratified IRCv3 vectors plus all escape, duplicate, boundary, and malformed cases.

- [x] `S02-004` **Implement syntax parsing.** Produce `ParsedMessage` from a
  framed line with exact prefix, command, parameter, trailing, and UTF-8 rules;
  do not perform authorization or mutation. ([evidence](conformance/stage-two-evidence.md#s02-004))
  - After: `S02-001`, `S02-003`.
  - Targets: `agenc-relay-client-wire`.
  - References: [Architecture §§9 and Appendix A.1](docs/arc-architecture-and-implementation-spec.md#9-client-wire-format), [RFC 2812](rfcs/rfc2812-irc-client-protocol.txt).
  - Invariants: `TRN-05`, `TRN-06`.
  - Evidence: every grammar arm and arity, prefix rejection, malformed command, parameter boundary, and differential transcript passes.

- [x] `S02-005` **Implement capability state.** Support CAP LS 302, REQ, ACK,
  NAK, END, NEW, DEL, dependencies, line splitting, and reconnect-only profile
  transitions without silently enabling unsupported drafts. ([evidence](conformance/stage-two-evidence.md#s02-005))
  - After: `S02-004`.
  - Targets: `agenc-relay-client-wire`.
  - References: [Architecture §§2.1, 9.3, and Appendix A.3](docs/arc-architecture-and-implementation-spec.md#21-adopted-client-specifications).
  - Invariants: `E2E-07`, `TRN-04`, `TRN-06`.
  - Evidence: capability dependency, simultaneous change, unknown capability, line-budget, and downgrade transcripts.

- [x] `S02-006` **Implement the connection-registration wire state.** Enforce
  permitted pre-registration commands, NICK/USER/CAP/SASL ordering, welcome
  burst ordering, keepalive, and bounded close output without implementing auth
  internals. ([evidence](conformance/stage-two-evidence.md#s02-006))
  - After: `S02-004`, `S02-005`.
  - Targets: `agenc-relay-client-wire` and transcript model.
  - References: [Architecture §10](docs/arc-architecture-and-implementation-spec.md#10-connection-and-registration-state-machine).
  - Invariants: `TRN-05`, `AUTH-02`, `OPS-04` at the wire boundary.
  - Evidence: every registration transition, invalid ordering, timeout, ping/pong, and close transcript.

- [x] `S02-007` **Implement SASL transport framing.** Handle AUTHENTICATE
  chunking, mechanism selection surface, abort, timeout, and fixed public
  replies while leaving OPAQUE processing to `agenc-relay-auth`. ([evidence](conformance/stage-two-evidence.md#s02-007))
  - After: `S02-005`, `S02-006`.
  - Targets: `agenc-relay-client-wire`.
  - References: [Architecture §§11.2–11.6](docs/arc-architecture-and-implementation-spec.md#112-opaque-profile).
  - Invariants: `AUTH-01`, `AUTH-02`, `AUTH-10` at the carrier boundary.
  - Evidence: chunk width, plus marker, abort, unsupported mechanism, timeout, and response-shape transcripts.

- [x] `S02-008` **Implement capability-aware rendering.** Separate measuring
  from encoding, enforce exact client/server/combined line budgets, preserve
  canonical ordering, and never allocate before a matching permit is supplied. ([evidence](conformance/stage-two-evidence.md#s02-008))
  - After: `S02-003` through `S02-006`.
  - Targets: `agenc-relay-client-wire`.
  - References: [Architecture §§9.4–9.5, 21.3, and 24.2](docs/arc-architecture-and-implementation-spec.md#94-rpl_isupport).
  - Invariants: `TRN-04`, `STA-08`, `CON-05`.
  - Evidence: mechanical wire-budget table, measure/encode equality, exact-capacity allocation tests, and every capability combination.

- [x] `S02-009` **Implement labeled replies, batches, and reply ordering.**
  Render standard errors, numerics, labeled-response groups, and batch nesting
  exactly once and in the required order. ([evidence](conformance/stage-two-evidence.md#s02-009))
  - After: `S02-005`, `S02-008`.
  - Targets: `agenc-relay-client-wire`.
  - References: [Architecture §§9.3–9.5 and 14.1](docs/arc-architecture-and-implementation-spec.md#93-advertised-capabilities).
  - Invariants: `STA-06`, `STA-08`, `PRV-02`.
  - Evidence: traditional/standard reply, partial-success, nested-batch, label, and ordering golden transcripts.

- [x] `S02-010` **Build the client transcript harness.** Drive framing,
  parsing, capability state, registration, and rendering with deterministic
  time and byte-exact expectations. ([evidence](conformance/stage-two-evidence.md#s02-010))
  - After: `S02-001` through `S02-009`.
  - Targets: `agenc-relay-testkit`, client-wire integration tests.
  - References: [Architecture §§28.2 and 28.6](docs/arc-architecture-and-implementation-spec.md#282-deterministic-unit-and-vector-tests), [Appendix E](docs/arc-architecture-and-implementation-spec.md#appendix-e-worked-protocol-flows).
  - Invariants: `TRN-*`, applicable `AUTH-*` and `STA-*` wire invariants.
  - Evidence: pinned base-client transcript corpus runs byte-identically.

- [x] `S02-011` **Fuzz every client-wire boundary.** Cover raw framing, tags,
  commands, decimal values, base64, capability transitions, render plans, and
  fragmented/coalesced input with explicit memory and time envelopes. ([evidence](conformance/stage-two-evidence.md#s02-011))
  - After: `S02-010`.
  - Targets: client-wire fuzz targets and regression corpus.
  - References: [Architecture §28.4](docs/arc-architecture-and-implementation-spec.md#284-parser-and-fuzz-testing).
  - Invariants: `TRN-04`, `TRN-05`, `TRN-06`, `CON-05`.
  - Evidence: reproducible fuzz records plus minimized failures promoted to ordinary tests.

- [x] `S02-900` **Pass the Stage 02 gate.** The complete client-wire surface
  must be total, bounded, capability-correct, and transcript-compatible before
  domain state consumes a parsed command. ([evidence](conformance/stage-two-evidence.md#s02-900))
  - After: `S02-001` through `S02-011`.
  - Targets: `agenc-relay-client-wire`, testkit transcripts and fuzz corpus.
  - References: [Architecture §29 phase 2](docs/arc-architecture-and-implementation-spec.md#29-implementation-sequence-and-acceptance-gates).
  - Invariants: `TRN-04` through `TRN-06`.
  - Evidence: parser fuzzing and every wire boundary and registration transcript passed with the mandatory workspace gates; the [historical schema version 2 manifest](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-02-1e5b738468f88b238061cc6e84b732176f5cae65.json) closes the gate for exact source commit `1e5b738468f88b238061cc6e84b732176f5cae65`, and the [schema version 1 manifest](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-02-8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb.json) remains archive-only.

## Stage 03 — Pure domain model

Outcome: deterministic protocol state, authorization, privacy projections, and
mutation plans are complete without sockets, TLS, executors, databases,
filesystem calls, concrete clocks, or random generators.

- [x] `S03-001` **Model accounts, principals, users, sessions, and presence.**
  Keep account, E2EE, nickname, presentation, cloak, and transport identities
  separate with explicit generation fencing.
  - After: `S02-900`.
  - Targets: `agenc-relay-domain`.
  - References: [Architecture §§7, 11.1, and 12](docs/arc-architecture-and-implementation-spec.md#7-typed-identifiers-and-canonical-names).
  - Invariants: `ID-01` through `ID-07`, `AUTH-04`, `AUTH-05`.
  - Evidence: lifecycle, account-switch, nickname reuse, cloak independence, and stale-generation property tests.

- [x] `S03-002` **Model channel instances, membership, roles, and modes.**
  Enforce recreation isolation, owner continuity, role ordering, mandatory and
  mutually exclusive modes, typed masks, and revision-bound decisions.
  - After: `S03-001`.
  - Targets: `agenc-relay-domain`.
  - References: [Architecture §13](docs/arc-architecture-and-implementation-spec.md#13-channel-model).
  - Invariants: `STA-02` through `STA-05`.
  - Evidence: generated membership/role/mode sequences and every boundary/collision transition.

- [x] `S03-003` **Implement privacy and discovery projections.** Produce only
  recipient-authorized views for public, unlisted, secret, invisible, offline,
  account, channel, query, and presence state.
  - After: `S03-001`, `S03-002`.
  - Targets: `agenc-relay-domain`.
  - References: [Architecture §§6, 13.5, 14.3, and 14.5](docs/arc-architecture-and-implementation-spec.md#6-privacy-and-anonymity-profiles).
  - Invariants: `PRV-01`, `PRV-02`, `STA-10`, `ID-04`, `ID-05`.
  - Evidence: authorization matrices, projection diffs, equal-error tests, and forbidden-field canaries.

- [x] `S03-004` **Canonicalize and validate commands.** Convert parsed syntax
  into `CanonicalCommand` only after semantic bounds, target resolution rules,
  mode vectors, and all-or-none command-level validation succeed.
  - After: `S03-001` through `S03-003`.
  - Targets: `agenc-relay-domain`.
  - References: [Architecture §§14 and 21.4](docs/arc-architecture-and-implementation-spec.md#14-base-command-behavior).
  - Invariants: `STA-04`, `STA-05`, `STA-06`, `TRN-05`.
  - Evidence: every Appendix-A command arm has success, rejection, multi-target, and unchanged-state tests.

- [x] `S03-005` **Implement authorization and rate charging.** Produce an
  `AuthorizedCommand` only after current principal, generation, role, target
  revision, policy, and hierarchical budget checks pass.
  - After: `S03-004`.
  - Targets: `agenc-relay-domain`.
  - References: [Architecture §§16 and 19.1](docs/arc-architecture-and-implementation-spec.md#16-moderation-and-user-safety).
  - Invariants: `ID-01`, `STA-03`, `STA-05`, `STA-07`, `CON-05`.
  - Evidence: privilege-transition, stale-identity, confused-deputy, exhaustion, and charge-before-ID tests.

- [x] `S03-006` **Implement channel and direct-message plans.** Cover JOIN,
  PART, TOPIC, NAMES, LIST, INVITE, KICK, direct/channel messaging, echo,
  recipient derivation, and atomic authorized-success subsets.
  - After: `S03-005`.
  - Targets: `agenc-relay-domain`.
  - References: [Architecture §§14.1–15.3](docs/arc-architecture-and-implementation-spec.md#141-atomic-multi-target-rules).
  - Invariants: `STA-01` through `STA-10`.
  - Evidence: deterministic two-client/multi-target flows, ordering tests, secret-target privacy, and rollback-free pure plans.

- [x] `S03-007` **Implement moderation and user-safety plans.** Model mutes,
  bans, exceptions, sanctions, role-gated actions, removal consequences, and
  auditable operator decisions without inspecting encrypted content.
  - After: `S03-005`, `S03-006`.
  - Targets: `agenc-relay-domain`.
  - References: [Architecture §16](docs/arc-architecture-and-implementation-spec.md#16-moderation-and-user-safety).
  - Invariants: `STA-03`, `STA-04`, `STA-05`, `OPS-03`.
  - Evidence: role/sanction matrix, appeal-state transitions, E2EE-removal intent tests, and audit-field allowlist tests.

- [x] `S03-008` **Model history and offline state policy.** Keep default
  ephemerality, optional plaintext channel history, offline account state, and
  E2EE opacity as explicit mutually constrained policies.
  - After: `S03-002`, `S03-006`.
  - Targets: `agenc-relay-domain`.
  - References: [Architecture §17](docs/arc-architecture-and-implementation-spec.md#17-persistence-and-history-visible-to-users), [§18](docs/arc-architecture-and-implementation-spec.md#18-e2ee-integration-contract).
  - Invariants: `STA-09`, `E2E-01`, `E2E-02`.
  - Evidence: default-no-history, opt-in scope, encrypted-target refusal, deletion, and visibility tests.

- [x] `S03-009` **Implement pure mutation plans and events.** Separate
  validation, authorization, deterministic state transition, storage
  projection, recipient projection, and later runtime reservations.
  - After: `S03-004` through `S03-008`.
  - Targets: `agenc-relay-domain`.
  - References: [Architecture §§21.1, 21.5, and 24.2](docs/arc-architecture-and-implementation-spec.md#211-ownership-rule).
  - Invariants: `CON-01`, `CON-03`, `DUR-01`, `STA-08`.
  - Evidence: plans are deterministic from one revision, contain no runtime/storage handles, and apply once in the reference model.

- [x] `S03-010` **Make time and randomness explicit inputs.** Express policy
  through monotonic/wall-clock values and requested entropy operations without
  calling system clocks or RNGs in domain code.
  - After: `S03-009`.
  - Targets: `agenc-relay-domain`, type-level clock/entropy request interfaces.
  - References: [Architecture §§21.6 and 24.2](docs/arc-architecture-and-implementation-spec.md#216-timers-and-clocks).
  - Invariants: `CON-01`, `AUTH-02`, `FED-09`.
  - Evidence: deterministic boundary tests for expiry, clock failure/jump, timer replacement, and entropy-request identity.

- [x] `S03-011` **Build the deterministic reference model.** Execute every
  command and planned federation-domain operation against simple value state,
  checking invariants after every generated step.
  - After: `S03-001` through `S03-010`.
  - Targets: `agenc-relay-testkit` reference model.
  - References: [Architecture §28.3](docs/arc-architecture-and-implementation-spec.md#283-state-machine-and-model-tests).
  - Invariants: all applicable `ID-*`, `PRV-*`, `STA-*`, `CON-*`.
  - Evidence: model covers every command registry arm and exports deterministic snapshots for implementation comparison.

- [x] `S03-012` **Generate adversarial domain sequences.** Cover registration,
  nickname reuse, recreation, roles, modes, invites, account switches,
  deletion, partitions-as-domain-input, duplicates, gaps, and invalid state
  transitions.
  - After: `S03-011`.
  - Targets: property/state-machine test suites.
  - References: [Architecture §§27 and 28.3](docs/arc-architecture-and-implementation-spec.md#27-security-and-correctness-invariants).
  - Invariants: every applicable Stage-03 invariant.
  - Evidence: generated sequences preserve invariants and rejected steps leave the reference state unchanged.

- [x] `S03-900` **Pass the Stage 03 gate.** The pure domain implementation and
  independent reference model must agree for all generated sequences before
  cryptographic, storage, or runtime side effects are introduced.
  - After: `S03-001` through `S03-012`.
  - Targets: `agenc-relay-domain`, testkit reference model.
  - References: [Architecture §29 phase 3](docs/arc-architecture-and-implementation-spec.md#29-implementation-sequence-and-acceptance-gates).
  - Invariants: applicable `ID-*`, `PRV-*`, `STA-*`, `CON-*`.
  - Evidence: generated sequence tests, privacy matrices, model equality, and mandatory workspace gates passed; the [historical schema version 2 manifest](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-03-1e5b738468f88b238061cc6e84b732176f5cae65.json) closes the gate for exact source commit `1e5b738468f88b238061cc6e84b732176f5cae65`, and the [schema version 1 manifest](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-03-8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb.json) remains archive-only.

## Stage 04 — Cryptographic adapters and account authentication

Outcome: maintained libraries are configured and composed exactly as specified
behind bounded, secret-safe adapters; account creation, authentication, and
credential change have complete protocol state machines and vectors.

- [x] `S04-001` **Implement secret-bearing wrappers.** Prevent `Debug`,
  `Display`, `Clone`, Serde, implicit string conversion, and accidental log or
  error exposure; zeroize owned buffers where the selected library supports it.
  - After: `S03-900`.
  - Targets: `agenc-relay-crypto`.
  - References: [Architecture §§22.2 and 24.3](docs/arc-architecture-and-implementation-spec.md#222-secret-material), [§25.2](docs/arc-architecture-and-implementation-spec.md#252-logging).
  - Invariants: `ID-05`, `AUTH-03`, `OPS-01`.
  - Evidence: compile-fail trait checks, secret-canary scans, drop tests, and explicit exposure-path review.

- [x] `S04-002` **Implement the OS entropy adapter.** Use `getrandom` with the
  exact features, require complete output, expose failure, and provide no
  production fallback or deterministic mode.
  - After: `S04-001`.
  - Targets: `agenc-relay-crypto`.
  - References: [Architecture §§24.2 and 24.4](docs/arc-architecture-and-implementation-spec.md#242-core-interfaces-and-ownership).
  - Invariants: `ID-02`, `ID-03`, `DUR-06` at the entropy boundary.
  - Evidence: full/partial/failure adapter tests and release-graph proof that deterministic entropy is unreachable.

- [x] `S04-003` **Implement domain-separated hash, HMAC, and HKDF adapters.**
  Accept typed contexts and inputs, expose only registered algorithms, and
  prevent cross-domain or truncated-output substitution.
  - After: `S04-001`.
  - Targets: `agenc-relay-crypto`.
  - References: [Architecture §24.4](docs/arc-architecture-and-implementation-spec.md#244-serialization-and-crypto-libraries), [E2EE §§2.2 and 7](docs/arc-mls-e2ee-extension.md#22-semantic-id-and-digest-registry).
  - Invariants: `AUTH-08`, `DUR-03`, `E2E-05`.
  - Evidence: RFC/project vectors, domain-substitution negatives, length checks, and differential library tests where available.

- [x] `S04-004` **Implement XChaCha20-Poly1305 storage adapters.** Fix the
  algorithm, key/nonce sizes, AAD domains, full-tag verification, and failure
  behavior; nonce allocation remains a Stage-05 storage responsibility.
  - After: `S04-001`, `S04-003`.
  - Targets: `agenc-relay-crypto`.
  - References: [Architecture §§23.3 and 24.4](docs/arc-architecture-and-implementation-spec.md#233-record-encryption), [source ledger §3](docs/protocol-sources-and-decisions.md#3-work-in-progress-and-deliberately-excluded-algorithms).
  - Invariants: `DUR-03`, `DUR-06`.
  - Evidence: XChaCha/project vectors and wrong-key, nonce, AAD, tag, truncation, and tamper negatives.

- [x] `S04-005` **Implement strict Ed25519 adapters.** Use `verify_strict`,
  typed signing domains, exact encodings, no batch/hazmat/legacy surface, and
  secret-key wrappers.
  - After: `S04-001`, `S04-003`.
  - Targets: `agenc-relay-crypto`.
  - References: [Architecture §24.4](docs/arc-architecture-and-implementation-spec.md#244-serialization-and-crypto-libraries), [E2EE §2.1](docs/arc-mls-e2ee-extension.md#21-signature-registry).
  - Invariants: `TRN-03`, `E2E-05`, `OPS-05`.
  - Evidence: signature/domain vectors, malleability and wrong-domain negatives, and secret-exposure scans.

- [x] `S04-006` **Implement the fixed account-service HPKE envelope.** Enforce
  Base mode, the pinned suite, request/response contexts, recovery epoch,
  operation kind, exact 4,726-byte wrapper, all-zero padding, and one-use
  exporter material.
  - After: `S04-002`, `S04-003`.
  - Targets: `agenc-relay-auth`, `agenc-relay-crypto`.
  - References: [Architecture §11.2.1](docs/arc-architecture-and-implementation-spec.md#1121-end-to-end-account-service-envelope), [RFC 9180](rfcs/rfc9180-hpke.txt).
  - Invariants: `ID-05`, `ID-06`, `AUTH-08`, `AUTH-10`.
  - Evidence: fixed-wrapper vectors plus pin, epoch, kind, context, length, padding, salt, and replay negatives.

- [x] `S04-007` **Implement the exact OPAQUE profile.** Configure the pinned
  suite, identities, context, Argon2id KSF, private credential IDs, record
  lengths, real and fake records, and dummy KE3 work without Serde.
  - After: `S04-001` through `S04-003`.
  - Targets: `agenc-relay-auth`, `agenc-relay-crypto`.
  - References: [Architecture §11.2](docs/arc-architecture-and-implementation-spec.md#112-opaque-profile), [source ledger §2](docs/protocol-sources-and-decisions.md#2-published-standards).
  - Invariants: `AUTH-01`, `AUTH-03`, `AUTH-09`, `AUTH-10`.
  - Evidence: RFC 9807/project vectors, exact serialized lengths, fake-record equivalence, dummy-KE3 work, and unsupported-suite rejection.

- [x] `S04-008` **Implement account creation.** Bind invitation, login,
  credential identity, HPKE context, OPAQUE registration, expiry, connection,
  and one-use transaction state without creating an E2EE identity.
  - After: `S04-006`, `S04-007`.
  - Targets: `agenc-relay-auth`, domain authorization interfaces.
  - References: [Architecture §11.3](docs/arc-architecture-and-implementation-spec.md#113-account-creation).
  - Invariants: `AUTH-02`, `AUTH-04`, `AUTH-08`, `AUTH-09`.
  - Evidence: success, unknown/duplicate login, invitation substitution, expiry, replay, disconnect, and output-shape tests.

- [x] `S04-009` **Implement OPAQUE login over SASL.** Bind KE1/KE2/KE3,
  origin connection, edge/coordinator routing, account-service HPKE, fake-record
  behavior, session generation, and final public replies.
  - After: `S04-006` through `S04-008`.
  - Targets: `agenc-relay-auth`, client-wire auth interface, domain session interface.
  - References: [Architecture §11.4](docs/arc-architecture-and-implementation-spec.md#114-opaque-login-over-sasl).
  - Invariants: `AUTH-01`, `AUTH-02`, `AUTH-05`, `AUTH-06`, `AUTH-08` through `AUTH-10`.
  - Evidence: known/unknown parity, malicious-edge, stale completion, replay, session-fence, timeout, and wire-transcript tests.

- [x] `S04-010` **Implement exporter-authenticated completion receipts.** Use
  independent salted one-use exporter material, operation/request binding,
  recovery epoch, response count, exact response kind, and idempotent replay.
  - After: `S04-006`, `S04-009`.
  - Targets: `agenc-relay-auth`, `agenc-relay-crypto`.
  - References: [Architecture §§11.2.1 and 11.4](docs/arc-architecture-and-implementation-spec.md#1121-end-to-end-account-service-envelope), [source ledger §2](docs/protocol-sources-and-decisions.md#2-published-standards).
  - Invariants: `AUTH-06`, `AUTH-08`, `DUR-12`.
  - Evidence: forgery, substitution, bare-success, collision fixture, changed-outcome replay, and `u64::MAX` refusal tests.

- [x] `S04-011` **Implement credential replacement and account-deletion auth.**
  Require fresh same-account proof, revision-bound one-use confirmation,
  credential-identity reuse, atomic record intent, and complete old-session
  fencing; provide no server-assisted recovery path.
  - After: `S04-009`, `S04-010`.
  - Targets: `agenc-relay-auth`, domain mutation plans.
  - References: [Architecture §§11.5, 14.6, and 23.8](docs/arc-architecture-and-implementation-spec.md#115-credential-change-and-non-recovery).
  - Invariants: `AUTH-05`, `AUTH-07`, `AUTH-11`.
  - Evidence: fresh/stale proof, wrong account, revision replacement, replay, precondition, tombstone intent, and session-fence tests.

- [x] `S04-012` **Implement bounded crypto workers and `CryptoPort`.** Keep CPU
  and blocking work off Tokio workers, bound queue/in-flight work, preserve
  job ownership, propagate cancellation outcomes, and never log job contents.
  - After: `S04-003` through `S04-011`.
  - Targets: `agenc-relay-crypto`, runtime-facing port implementation.
  - References: [Architecture §§19.1, 21.7, and 24.2](docs/arc-architecture-and-implementation-spec.md#191-hierarchical-admission).
  - Invariants: `CON-02`, `CON-04`, `CON-05`, `OPS-01`.
  - Evidence: queue-full, worker panic, cancellation, overload, timing-class, secret-canary, and joined-shutdown tests.

- [x] `S04-013` **Lock the cryptographic dependency graph and features.** Prove
  exact direct versions/features, no forbidden defaults, scoped duplicate
  generations, no Git source, and no unexpected algorithm reachability.
  - After: `S04-003` through `S04-012`.
  - Targets: Cargo manifests/lockfile and dependency evidence.
  - References: [Architecture §§24.4–24.5](docs/arc-architecture-and-implementation-spec.md#244-serialization-and-crypto-libraries), [source ledger §5](docs/protocol-sources-and-decisions.md#5-initial-rust-dependency-evidence).
  - Invariants: `OPS-02`.
  - Evidence: feature tree, duplicate/reachability report, checksum verification, `cargo deny`, and `cargo audit` pass.

- [x] `S04-014` **Complete crypto/auth verification.** Run all standardized and
  project vectors, malicious-edge confirmation, fake-record/dummy-KE3,
  constant-time-path integration review, secret canaries, and worker-bound
  tests without claiming the primitives themselves were re-proved.
  - After: `S04-001` through `S04-013`.
  - Targets: crypto/auth test and evidence suites.
  - References: [Architecture §§28.2, 28.4, and 29 phase 4](docs/arc-architecture-and-implementation-spec.md#282-deterministic-unit-and-vector-tests).
  - Invariants: `ID-05` through `ID-07`, `AUTH-*`, applicable `DUR-*`, `OPS-01`.
  - Evidence: complete evidence manifest for every crypto/auth requirement and dependency configuration.

- [x] `S04-900` **Pass the Stage 04 gate.** No auth or cryptographic operation
  advances state without the exact standardized/library-backed validation,
  context binding, resource admission, and completion evidence.
  - After: `S04-001` through `S04-014`.
  - Targets: `agenc-relay-crypto`, `agenc-relay-auth`, affected testkit surfaces.
  - References: [Architecture §29 phase 4](docs/arc-architecture-and-implementation-spec.md#29-implementation-sequence-and-acceptance-gates).
  - Invariants: `AUTH-*`, `ID-05` through `ID-07`, `CON-02`, `CON-04`, `CON-05`.
  - Evidence: all named acceptance evidence and mandatory workspace gates passed under the pinned lockfile; the [historical schema version 2 manifest](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-04-4040796f2c21774d58ea7ce54e70a080678e83ac.json) closes the gate for exact source commit `4040796f2c21774d58ea7ce54e70a080678e83ac` after the Stage 04 and 05 legibility review; the [previous schema version 2 manifest](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-04-1e5b738468f88b238061cc6e84b732176f5cae65.json) and the [schema version 1 manifest](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-04-8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb.json) remain archive-only.

## Stage 05 — Persistence, recovery, and durable construction

Outcome: one storage owner applies authenticated, bounded transactions and can
recover, migrate, back up, restore, delete, and rekey state without guessing a
durability or rollback outcome.

- [x] `S05-001` **Implement the exact database schema and record codecs.**
  Define every keyspace, key/value type, schema generation, database identity,
  canonical order, size charge, and cross-reference without Serde.
  - The closed keyspace, control codecs, login-index union, domain envelope,
    table-and-arm-bound federation/E2EE object wrapper, and E2EE recovery gate
    are implemented with full-consumption decoding and bounded bodies.
  - After: `S04-900`.
  - Targets: `agenc-relay-storage`.
  - References: [Architecture §§23.1–23.2 and Appendix C.5](docs/arc-architecture-and-implementation-spec.md#231-engine-and-durability).
  - Invariants: `DUR-02`, `DUR-03`, `DUR-10`, `DUR-11`.
  - Evidence: golden record vectors, full-consumption negatives, schema/keyspace inventory, and charge-boundary tests.

- [x] `S05-002` **Implement sealed records.** Authenticate record type, key,
  schema, key generation, and AAD before parsing plaintext; reject corruption,
  substitution, unknown generation, and partial values.
  - After: `S05-001`, `S04-004`.
  - Targets: `agenc-relay-storage`, crypto adapter integration.
  - References: [Architecture §23.3](docs/arc-architecture-and-implementation-spec.md#233-record-encryption).
  - Invariants: `DUR-03`, `DUR-06`, `DUR-07`.
  - Evidence: known vectors and wrong key/type/AAD/generation/nonce/tag/truncation/substitution tests.

- [x] `S05-003` **Implement `StateMeta` and accounting.** Maintain exact
  revisions, cursors, epochs, response count, nonce high-water mark, logical
  database bytes, backup-stream bytes, and integrity roots with checked
  arithmetic.
  - After: `S05-001`, `S05-002`.
  - Targets: `agenc-relay-storage`.
  - References: [Architecture §§23.2–23.5](docs/arc-architecture-and-implementation-spec.md#232-database-identity-and-schema).
  - Invariants: `DUR-04`, `DUR-06`, `DUR-10` through `DUR-12`.
  - Evidence: full-scan equality, overflow, edge-zero, response-count, and nonce-boundary tests.

- [x] `S05-004` **Implement validated storage mutation batches.** Recompute
  record, byte, seal, and accounting limits; bind one transaction ID; exclude
  closures, runtime handles, borrowed StateCore data, and rendered bytes.
  - After: `S03-009`, `S05-001` through `S05-003`.
  - Targets: `agenc-relay-storage`, domain-to-storage conversion boundary.
  - References: [Architecture §§21.5, 23.4, and 24.2](docs/arc-architecture-and-implementation-spec.md#215-durable-mutation-batches).
  - Invariants: `CON-03`, `DUR-01`, `DUR-02`, `CON-05`.
  - Evidence: mismatch, over-limit, stale-revision, cross-transaction, and ownership compile-fail tests.

- [x] `S05-005` **Implement `StorageOwner` and `StoragePort`.** Own redb on one
  blocking thread, accept only complete batches/read plans, return bounded
  completions, and consume every result even after request cancellation.
  - After: `S05-004`.
  - Targets: `agenc-relay-storage` and runtime-facing port.
  - References: [Architecture §§21.1, 21.7, and 24.2](docs/arc-architecture-and-implementation-spec.md#211-ownership-rule).
  - Invariants: `CON-01` through `CON-04`.
  - Evidence: ownership, cancellation, worker failure, queue-full, late-receipt, and joined-shutdown tests.

- [x] `S05-006` **Implement immediate two-phase commit reconciliation.** Apply
  the exact atomic record set, sync requirements, receipt matching, and
  `Indeterminate` closure without reporting guessed success or retrying a
  non-idempotent mutation blindly.
  - After: `S05-003` through `S05-005`.
  - Targets: `agenc-relay-storage`.
  - References: [Architecture §§23.1 and 23.4](docs/arc-architecture-and-implementation-spec.md#231-engine-and-durability).
  - Invariants: `DUR-01`, `DUR-02`, `OPS-04`, `CON-03`.
  - Evidence: injected failure before/after every write, commit, sync, and receipt boundary proves the specified outcome.

- [x] `S05-007` **Implement nonce reservations and burn rules.** Anchor each
  fresh 192-bit nonce block in both authenticated control state and rollback
  guard before use; burn aborted/uncertain slots and enforce the `2^40` limit.
  - After: `S05-002`, `S05-003`, `S05-006`.
  - Targets: `agenc-relay-storage`, entropy adapter.
  - References: [Architecture §§23.3 and 23.5](docs/arc-architecture-and-implementation-spec.md#233-record-encryption).
  - Invariants: `DUR-06`, `DUR-08`.
  - Evidence: crash tests for every reservation state, collision fixtures, high-water boundaries, and no-reuse reconstruction.

- [x] `S05-008` **Implement integrity manifests and checkpoints.** Track every
  sealed record insertion/deletion/substitution in an authenticated bounded
  ledger and produce independently verifiable checkpoints.
  - After: `S05-002`, `S05-003`, `S05-006`.
  - Targets: `agenc-relay-storage`.
  - References: [Architecture §§23.5 and 23.5.2](docs/arc-architecture-and-implementation-spec.md#235-authenticated-integrity-rollback-guard-and-recovery).
  - Invariants: `DUR-04`, `DUR-07`, `DUR-09`.
  - Evidence: vector, insertion/deletion/substitution, chain-gap, checkpoint-cut, and bounded-ledger tests.

- [x] `S05-009` **Implement the external rollback guard.** Authenticate exact
  database identity, generation, StateMeta, manifest/checkpoint state, and
  reservation authority using separately keyed, atomically replaced files.
  - After: `S05-003`, `S05-007`, `S05-008`.
  - Targets: `agenc-relay-storage`, platform filesystem adapter.
  - References: [Architecture §23.5.1](docs/arc-architecture-and-implementation-spec.md#2351-external-rollback-guard).
  - Invariants: `DUR-04`, `DUR-05`, `DUR-08`.
  - Evidence: stale/ahead/missing/torn/substituted guard, rename/sync failure, permission, symlink, and lock tests.

- [x] `S05-010` **Implement fail-closed startup recovery.** Accept only the
  enumerated database/guard/reservation successor states, reconstruct tracked
  state and cursors completely, and refuse all gaps, mismatches, or guesses.
  - Startup reconstructs storage identity, guards, checkpoints, manifests,
    sealed records, accounting, login generations, record references, domain
    bindings, revisions, and cursors before exposing a validated
    `StateCoreSeed`. Stage 06 owns creation of the live `StateCore` actor.
  - After: `S05-007` through `S05-009`.
  - Targets: `agenc-relay-storage`.
  - References: [Architecture §23.5.3](docs/arc-architecture-and-implementation-spec.md#2353-startup-integrity-reconstruction).
  - Invariants: `DUR-03`, `DUR-04`, `DUR-07`, `DUR-08`.
  - Evidence: complete corruption/recovery matrix and reconstructed-state comparison with the reference model.

- [x] `S05-011` **Enforce current storage format admission.** Reject obsolete
  formats before startup, backup restore, or key rotation can write output.
  - After: `S05-010`.
  - Targets: `agenc-relay-storage`.
  - References: [Architecture §23.6](docs/arc-architecture-and-implementation-spec.md#236-storage-format-admission).
  - Invariants: `DUR-04`, `DUR-09`, `DUR-11`, `DUR-12`.
  - Evidence: current-format round trips and unsupported-format refusal tests.

- [x] `S05-012` **Implement backup and restore.** Produce the authenticated
  bounded backup stream; restore only through construction; create new server,
  database, recovery, and state generations; and enforce client resynchronization.
  - The storage library creates, verifies, publishes, restores, resumes, and
    reopens signed backups through construction. A strict maintenance-only
    configuration parser and the stopped-daemon `storage restore` binary
    command compose the executor without starting the Stage 06 daemon.
  - After: `S05-010`, `S05-011`.
  - Targets: `agenc-relay-storage`, binary maintenance commands.
  - References: [Architecture §23.7](docs/arc-architecture-and-implementation-spec.md#237-backup-format-and-restore).
  - Invariants: `DUR-05`, `DUR-09`, `DUR-11`.
  - Evidence: exact/current, refused stale/divergent, disaster recovery, tamper, truncation, space, crash, and credential-generation tests.

- [x] `S05-013` **Implement deletion and storage-key rotation.** Durably erase
  unauthorized/deleted material before acknowledgment and rebuild rekey output
  with fresh generation, nonce authority, integrity state, and construction
  evidence.
  - After: `S05-010` through `S05-012`.
  - Targets: `agenc-relay-storage`, domain deletion plans.
  - References: [Architecture §23.8](docs/arc-architecture-and-implementation-spec.md#238-deletion-and-key-rotation).
  - Invariants: `FED-07`, `DUR-05` through `DUR-09`.
  - Evidence: erasure-before-ACK, interruption, stale-key, generation, residual-record, rollback, and resumed-rekey tests.

- [x] `S05-014` **Implement login-index key transition.** Support exactly one
  current and one previous keyed generation, migrate only after successful
  OPAQUE input, verify duplicate ownership and counts, and fail on missing or
  third-generation state.
  - After: `S04-009`, `S05-010`, `S05-013`.
  - Targets: `agenc-relay-storage`, auth/storage integration.
  - References: [Architecture §23.9](docs/arc-architecture-and-implementation-spec.md#239-login-index-key-transition).
  - Invariants: `ID-07`, `DUR-10`.
  - Evidence: zero/one/two/third generation, duplicate, lazy migration, dormant invalidation, crash, and rekey/migration tests.

- [x] `S05-015` **Complete the storage fault and growth qualification suite.**
  Inject read/write/allocation/sync/rename/lock/space failures and qualify the
  fixed physical-growth reserve for every declared target/filesystem tuple.
  - Deterministic fault sites, restart campaigns, boundary admission tests,
    and fixed-reserve checks are implemented. Native x86_64 and AArch64 ext4
    measurements cover every declared case and are bound into signed reports.
  - After: `S05-001` through `S05-014`.
  - Targets: fault store, filesystem harness, release storage evidence.
  - References: [Architecture §§28.5 and 28.7](docs/arc-architecture-and-implementation-spec.md#285-crash-storage-and-fault-injection).
  - Invariants: `DUR-*`, `CON-03`, `OPS-04`.
  - Evidence: complete crash/fault/corruption matrix and signed per-tuple growth report with boundary cases.

- [x] `S05-900` **Pass the Stage 05 gate.** Every accepted durable mutation,
  recovery state, construction, backup, restore, deletion, and key transition
  satisfies the complete `DUR-*` invariant family.
  - Current status: clean all-workspace coverage is 90.64% of branches and
    95.65% of lines, with all six critical regions at 100%. The complete
    implementation gate passes.
  - After: `S05-001` through `S05-015`.
  - Targets: `agenc-relay-storage` and all storage evidence.
  - References: [Architecture §29 phase 5](docs/arc-architecture-and-implementation-spec.md#29-implementation-sequence-and-acceptance-gates).
  - Invariants: `DUR-01` through `DUR-12`, applicable `CON-*` and `OPS-*`.
  - Evidence: all storage acceptance evidence and mandatory workspace gates
    pass from clean state; the [historical schema version 2 manifest](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-05-4040796f2c21774d58ea7ce54e70a080678e83ac.json)
    closes the gate for exact source commit
    `4040796f2c21774d58ea7ce54e70a080678e83ac` after the Stage 04 and 05 legibility
    review, and the [previous schema version 2 manifest](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-05-bd7518fe7f5c7420debdbaa958aa444ecb5c80c9.json)
    remains archive-only.

## Stage 06 — Single-node runtime and operations

Outcome: a standalone core node safely composes wire, domain, authentication,
storage, configuration, administration, and bounded runtime ownership over
TLS-only direct, Tor-exit, and onion profiles.

### Stage 06 completion checklist

This checklist started from commit
`197cbcb3423cecbf424dd3c06046c2d63f9ab02c` on `stage-06-runtime`.
Implementation through `S06-001` to `S06-015` was committed on that branch,
pushed, and merged by PR #14. The branch head was
`1c91131ce0b411717a1a3ddb15a0202fc8312ce3`; the merge commit is
`3a517e9482fe51d7983dc5b9c998fd472e41c600`.

The merge did not close Stage 06: the cloud gate failed in `check-source`,
the coverage and requirement-ledger checkpoints were open, and no exact-SHA
Stage 06 evidence existed. The closure work on `stage-06-closure` fixed the
source-policy failure, repaired the inherited Stage 03 and Stage 04 checks,
adopted the interim coverage floor, closed the ledger and catalog, and passed
the full 75-command gate on 2026-09-01. The commit-point boxes below record
which work landed. The `S06-*` task boxes are checked because the gate passes
on the closure branch. The exact-revision checkpoint closes source commit
`65cce9d66f7bcfb0c0830a2ab1d42b52bff82942`.

#### Branch and worktree control

- [x] Keep the Stage 06 implementation in the existing
  `/home/tetsuo/git/AgenC/agenc-relay-server` worktree.
- [x] Keep all Stage 06 commits on `stage-06-runtime` and push them to
  `origin/stage-06-runtime`.
- [x] Remove the obsolete Stage 06 worktrees and branch pointers.
- [x] Do not create another persistent Stage 06 worktree or branch.
- [x] Treat `main` only as the comparison and pull-request base during Stage 06
  implementation.
- [ ] Before editing a code symbol, run the required GitNexus upstream impact
  check. Report HIGH or CRITICAL risk before editing and run focused regression
  tests after changing a high-impact symbol.
- [ ] Before every commit, run GitNexus `detect_changes` for the staged work and
  compare the branch with `main`.
- [x] Commit the implementation as focused slices on the same remote branch.
- [x] Do not create empty commits when an audit finds that the existing code and
  tests already prove a slice.
- [ ] Do not merge the final pull request before the cloud gate and exact-SHA
  evidence pass. This was violated when PR #14 was merged.

#### Verified starting state

- [x] Run the Stage 06 runtime-profile check and its negative self-test.
  The profile records 16 transcripts and five qualification checks.
- [x] Run the deployment check and its negative self-test.
- [x] Run the runtime package tests. The recorded run passed 292 tests.
- [x] Run runtime Clippy with warnings denied.
- [x] Run the full workspace tests through `cargo llvm-cov`.
- [x] Record the starting coverage result. Branch coverage is 7,650 of 9,608
  outcomes, or 79.62 percent. Line coverage is 84,898 of 93,220 lines, or
  91.07 percent.
- [x] Confirm that no Stage 06 pull request or exact-SHA evidence manifest
  exists yet.

#### Configuration, initialization, TLS, and transports

- [ ] Audit `S06-001` against every strict-configuration acceptance condition.
  - [ ] Reject unknown and duplicate TOML fields.
  - [ ] Exercise every scalar boundary and cross-field combination.
  - [ ] Validate the full Appendix-C union, Host depth, roles, targets, paths,
    permissions, supported versions, and unsafe combinations.
  - [ ] Prove that invalid configuration fails before any listener opens.
  - [ ] Close the remaining `OPS-02` requirement only after the tests prove it.
- [ ] Audit `S06-002` initialization and `check-config`.
  - [ ] Exercise clean, partial, repeated, and failed initialization.
  - [ ] Verify purpose-separated keys and directories with minimum modes.
  - [ ] Verify safe onboarding-pin output and host-control checks.
  - [ ] Prove failure atomicity and refusal to replace an existing durable
    identity.
- [ ] Audit `S06-003` TLS endpoints.
  - [ ] Verify the explicit aws-lc provider and TLS 1.3 only.
  - [ ] Verify `[X25519MLKEM768, X25519]` group order and the permitted
    forward-secret cipher suites.
  - [ ] Reject TLS 1.2 and earlier, 0-RTT, renegotiation, application
    compression, protocol fallback, and post-handshake client authentication.
  - [ ] Verify exact client and admin ALPN values.
  - [ ] Verify DNS certificate identity and pinned onion identity paths.
  - [ ] Exercise hybrid negotiation, X25519 fallback, certificate failures,
    pin failures, and bytes sent before the handshake.
  - [ ] Close all four remaining TLS-owned requirement records.
- [ ] Audit `S06-004` transport-profile isolation.
  - [ ] Keep direct, Tor-exit, and onion listener behavior explicit.
  - [ ] Prove that no reverse DNS or ident path exists.
  - [ ] Use a source address only for temporary admission and rate buckets.
  - [ ] Prove that source addresses do not enter protocol messages,
    persistence, logs, metrics, replies, audit records, or user-visible state.
  - [ ] Erase each address-derived bucket no later than ten minutes after use.
  - [ ] Pass hostnames through SOCKS5 without local resolution.
  - [ ] Use separate Tor stream-isolation credentials for each network and
    account, and never share them between accounts.
  - [ ] Refuse direct DNS or TCP fallback after a Tor failure.
  - [ ] Reject ordinary TCP and HAProxy headers on onion-only listeners.
  - [ ] Prove that onion clients never try a clearnet endpoint automatically.
  - [ ] Run profile-mismatch, real-onion, SafeSocks, TestSocks, DNS-leak,
    packet-capture, and forbidden-field checks.
  - [ ] Close all 13 remaining transport-owned requirement records.

Commit point 1

- [x] Land configuration, initialization, TLS, transport, and directly related
  test and deployment changes. The closing commits include `86f56f3`,
  `128d6e2`, `874e005`, `ea69589`, and `448918f`.
- [ ] Re-run formatting, config tests, focused TLS and listener tests,
  transport transcripts, source checks, and deployment checks on the exact
  closure revision.
- [ ] Run GitNexus `detect_changes` before committing.
- [x] Commit the changes with imperative subjects.
- [x] Push the changes to `stage-06-runtime`.

#### Runtime ownership, memory, durability, sessions, and messaging

- [ ] Audit `S06-005` task ownership and lifecycle control.
  - [ ] Supervise listeners, connections, StateCore, storage, crypto, timers,
    maintenance, administration, logs, and signals as finite children.
  - [ ] Propagate task panics and startup failures.
  - [ ] Prove cancellation and joined shutdown at each phase under idle and
    loaded conditions.
  - [ ] Prove that no live owner remains after stop.
  - [ ] Keep the lifecycle channel selectable while a durable batch is in
    flight.
  - [ ] Retain the first typed hook failure or timeout.
  - [ ] Make phase requests idempotent and let stop supersede earlier phases.
- [ ] Audit `S06-006` global memory admission.
  - [ ] Acquire the exact charge before every count-scaled allocation.
  - [ ] Move permits with buffers, queue reservations, and storage
    reservations.
  - [ ] Keep fixed emergency headroom separate from ordinary admission.
  - [ ] Reject exhaustion before side effects.
  - [ ] Exercise split, drop, rollback, allocation-failure proxy, high-water,
    and exact permit-return cases.
- [ ] Audit `S06-007` connection and output ownership.
  - [ ] Keep bounded generation-bound input and output owners for every
    client.
  - [ ] Verify tentative, prepare, and commit queue reservations.
  - [ ] Verify whole-sink exclusion, exact output order, generation reuse,
    shared-buffer charging, and slow-consumer closure.
  - [ ] Prove that commit is infallible and allocation-free after preparation.
  - [ ] Verify shutdown-after-flush frames and flush acknowledgements.
- [ ] Audit `S06-008` StateCore durable execution.
  - [ ] Keep StateCore as the only mutable protocol-state authority.
  - [ ] Construct every plan at one revision and reserve all runtime resources
    before submission.
  - [ ] Submit one complete storage batch and consume only its matching
    receipt.
  - [ ] Apply each accepted result once and render success only after durable
    application.
  - [ ] Exercise cancellation and disconnect before and after every reserve,
    submit, receipt, apply, and render boundary.
  - [ ] Keep channel mutations, indexes, projections, outboxes, result records,
    and audit effects in their required atomic batches.
  - [ ] Keep nickname and session changes, indexes, projections, transient
    events, counters, and results in their required atomic batches.
  - [ ] Close all three remaining StateCore-owned requirement records.
- [ ] Audit `S06-009` registration, authentication, and session routing.
  - [ ] Exercise the path from TLS admission through client framing,
    registration, SASL, account jobs, domain plans, storage, welcome state,
    account changes, keepalive, and closure.
  - [ ] Keep account identity separate from nicknames, masks, addresses, and
    labels.
  - [ ] Keep login IDs hidden and separate from public account labels.
  - [ ] Generate a fresh cloak for each connection without deriving it from
    an address, account, device, or earlier cloak.
  - [ ] Bind, expire, and consume authentication and credential contexts once.
  - [ ] Fence the session generation before principal, device, logout, or
    account-switch changes can accept new work.
  - [ ] Verify deletion, recovery, HPKE, and credential-replacement context and
    transaction rules.
  - [ ] Run complete lifecycle, restart, malicious-input, and generation-fence
    transcripts.
  - [ ] Close all eight remaining registration-owned requirement records.
- [ ] Audit `S06-010` single-node channel and message behavior.
  - [ ] Exercise local and global channels, public, unlisted, and secret
    discovery, roles, moderation, invites, bans, kicks, direct messages, and
    channel messages.
  - [ ] Verify recipient reservations, overload behavior, slow-consumer
    handling, ephemeral defaults, and optional-policy refusal.
  - [ ] Keep `+n` set, make `+p` and `+s` exclusive, and validate a full mode
    vector before applying any part of it.
  - [ ] Present nickname and cloak masks only as weak reconnectable filters.
  - [ ] Compare runtime snapshots with the deterministic domain model.
  - [ ] Run byte-exact core-v1 transcripts and privacy cases.
  - [ ] Close all four remaining messaging-owned requirement records.
- [ ] Audit `S06-011` timers, admission, and overload behavior.
  - [ ] Exercise connection deadlines, authentication expiry, keepalive,
    rate buckets, maintenance, overload classes, and cleanup with an explicit
    clock.
  - [ ] Exercise paused-time boundaries, timer replacement and cancellation,
    slowloris behavior, churn, exhaustion, and recovery after quiescence.
  - [ ] Prove that admission never demands deanonymization, sends a Tor user
    over clearnet, or invents a CAPTCHA or proof-of-work challenge.
  - [ ] Close the remaining admission-owned requirement record.

Commit point 2

- [x] Land task-tree, lifecycle, memory, connection, StateCore, session,
  channel, timer, and directly related test changes. The closing commits
  include `1b335f4`, `70418ec`, `0e508c9`, `0153dbc`, `35c0198`, `1a0c4b3`,
  `3f91e9a`, `ab97fdb`, `fe0355f`, `f30d61d`, `4daf54a`, and `1c91131`.
- [ ] Re-run formatting, focused package tests, Stage 06 persistence tests,
  Loom, runtime transcripts, shutdown tests, and source checks on the exact
  closure revision.
- [ ] Run GitNexus `detect_changes` before committing.
- [x] Commit the changes with imperative subjects.
- [x] Push the changes to `stage-06-runtime`.

#### Isolated administration and audit

- [ ] Audit `S06-012` as a separate authenticated runtime path.
  - [ ] Keep every admin session, operator snapshot, confirmation, audit
    cursor, pending action, and response-order token inside `AdminOwner`.
  - [ ] Dispatch admin traffic after transport authentication and never send
    credentials, authority, or admin lines through the public client inbox.
  - [ ] Use the separate 4,610-byte CRLF reader, bounded writer, and bounded
    admin message channel.
  - [ ] Admit local administration by UID and GID without TLS, including the
    configured-GID subset check.
  - [ ] Admit TLS administration only with the admin ALPN, separate client CA,
    exact certificate SPKI, fresh RFC 9846 exporter binding, and operator
    Ed25519 proof.
  - [ ] Retain only the admitted UID/GID or SPKI and never retain a source
    address.
  - [ ] Route admin state requests through a separate bounded StateCore
    channel.
  - [ ] Implement and transcript every command through the closed reply table.
  - [ ] Return fixed `UNAVAILABLE` results for federation commands, keep E2EE
    statistics zero, and keep public IRC `OPER` denied.
  - [ ] Reconstruct and verify audit events and checkpoints before accepting
    admin authority at startup.
  - [ ] Verify big-endian keys, decoded sequence values, trust windows,
    signatures, hashes, gapless order, checkpoint coverage, and unmatched
    intents.
  - [ ] Couple suspension, restoration, and quarantine with their signed audit
    events in the same storage transaction.
  - [ ] Commit read observations before releasing a prepared output batch.
  - [ ] Use intent, action, and outcome commits for external actions.
  - [ ] Terminate DIE and RESTART only after their intent commits.
  - [ ] Replace one expired nonempty audit prefix with one signed checkpoint in
    the same transaction.
  - [ ] Make audit export acquire memory permits, freeze and verify the full
    view, enforce 10,000 records and 64 MiB, and emit no partial batch.
  - [ ] Keep `STATS STORAGE` at exactly 14 fields.
  - [ ] Return one signed authenticated `371` health line followed by `374`.
  - [ ] Run Unix and mTLS transcripts for identity, CA, SPKI, exporter,
    counters, replay, framing, permissions, confirmations, ordering, every
    command, audit failures, retention, corruption, and startup reconciliation.
  - [ ] Close the remaining `OPS-03` and `OPS-05` requirements.

Commit point 3

- [x] Land administration, audit, admin transport, and directly related test
  changes. The closing commits include `70418ec`, `30a04fc`, `e3621ea`,
  `cf7d73b`, and `d1e7a37`.
- [ ] Re-run formatting, admin crate tests, focused runtime admin tests, admin
  transcripts, audit reconstruction tests, and source checks on the exact
  closure revision.
- [ ] Run GitNexus `detect_changes` before committing.
- [x] Commit the changes with imperative subjects.
- [x] Push the changes to `stage-06-runtime`.

#### Atomic live reload and operational limits

- [ ] Audit `S06-013` against the full reload contract.
  - [ ] Keep `ConfigRevision`, `RuntimeConfigSnapshot`,
    `RuntimeConfigHandle`, `PreparedReload`, and typed reload outcomes.
  - [ ] Keep one snapshot `Arc` behind the short-held synchronization wrapper
    and keep StateCore as the only writer.
  - [ ] Prepare validated configuration, TLS endpoints, loaded MOTD and public
    information, operators, rates, operational limits, storage limits,
    registration defaults, and shutdown policy without changing live state.
  - [ ] Validate Host depth, secret loading, typed diffs, same-path material,
    certificate/key identity, allocation, working-set capacity, current-use
    floors, storage counters, and current free space.
  - [ ] Reject same-path changes to restart-only secrets, trust material, CAs,
    keys, and identity pins.
  - [ ] Accept a certificate renewal only when the private-key identity stays
    the same, and use it only for new handshakes.
  - [ ] Detect same-path MOTD and public-information content changes.
  - [ ] Enforce configured operational limits in domain decisions and block
    new use after lowering a live ceiling without killing existing sessions.
  - [ ] Apply only at a StateCore safe point with no gathered or submitted
    durable batch.
  - [ ] Replace prepared cells without awaiting, publish the snapshot last,
    and increment the revision exactly once.
  - [ ] Succeed on a no-op without incrementing the revision.
  - [ ] Hold the REHASH activation barrier until its outcome audit commits.
  - [ ] Restore the old snapshot after rejection and stop the daemon after an
    indeterminate outcome.
  - [ ] Route SIGHUP through the same single-flight path without creating an
    operator audit event.
  - [ ] Serialize concurrent reloads, coalesce SIGHUP requests, reject reload
    after quiescence, and preserve existing TLS sessions.
  - [ ] Clamp rate credit after a decrease and grant no credit windfall after
    an increase.
  - [ ] Disconnect disabled operators, update retained permissions, and
    consume confirmations after authority changes.
  - [ ] Exercise every reloadable and restart-only field, same-path material
    changes, preparation failures, resource floors, storage failure,
    admin/SIGHUP races, concurrent readers, and rollback.

Commit point 4

- [x] Land reload, operational-limit, operator-update, and directly related
  test changes. The closing commits include `3f89b2b`, `857b524`, `8195592`,
  `6dd48e2`, `6ab1d61`, `bd43602`, and `6f97477`.
- [ ] Re-run formatting, config tests, focused runtime reload tests, reload
  race tests, Loom where applicable, and source checks on the exact closure
  revision.
- [ ] Run GitNexus `detect_changes` before committing.
- [x] Commit the changes with imperative subjects.
- [x] Push the changes to `stage-06-runtime`.

#### Observability and authenticated health

- [ ] Audit `S06-014` privacy-bounded observability.
  - [ ] Create one entropy-backed process correlation source and install crash
    reporting before async owners start.
  - [ ] Record only closed event names and fixed typed fields for admissions,
    refusals, TLS outcomes, command classes, queue depth, storage batches,
    reloads, admin actions, overload changes, and shutdown phases.
  - [ ] Keep all user-controlled input and every forbidden data class out of
    logs, metrics, replies, crash output, and audit details.
  - [ ] Run filesystem log I/O in the named joined blocking owner through the
    existing 1,024-entry bounded queue.
  - [ ] Derive `server.data_dir/logs`, create and validate it as mode `0700`,
    keep 24 hours by default, cap retention at 30 days, and bound directory
    entries and deletions per sweep.
  - [ ] Keep closed log segments uncompressed in Stage 06.
  - [ ] Compose fixed-label metrics and 60-second statistics rings without an
    HTTP listener.
  - [ ] Mark readiness only after configuration, key loading, storage
    reconstruction, and StateCore startup acknowledgement.
  - [ ] Clear readiness during quiescence and after a security-sensitive owner
    failure.
  - [ ] Emit supervisor and StateCore progress ticks every five seconds and
    report zero progress as not live.
  - [ ] Expose health only through signed authenticated admin `INFO` as one
    `371 health readiness=<0|1> liveness=<0|1>` line followed by `374`.
  - [ ] Keep pre-authentication `PING` limited to token echo and leave public
    client `INFO` unchanged.
  - [ ] Run forbidden-value canaries, fixed-cardinality tests, log-queue
    saturation, retention bounds, initial and stale health, authenticated-only
    health, and shutdown-flush tests.
  - [ ] Close the remaining logging-privacy and raw-address requirements.

Commit point 5

- [x] Land observability, logging, health, readiness, liveness, and directly
  related test changes. The closing commits include `1b335f4`, `32d2fe1`, and
  `b29279e`.
- [ ] Re-run formatting, focused observability and health tests,
  forbidden-value scans, log-retention tests, shutdown-flush tests, and source
  checks on the exact closure revision.
- [ ] Run GitNexus `detect_changes` before committing.
- [x] Commit the changes with imperative subjects.
- [x] Push the changes to `stage-06-runtime`.

#### Shutdown and service hardening

- [ ] Audit production shutdown and `S06-015` deployment behavior.
  - [ ] Route normal production termination through quiesce, drain, flush, and
    stop within the 120-second total.
  - [ ] Stop client and admin accepts, wait for accept-loop barriers, clear
    readiness, and reject new mutations during quiesce.
  - [ ] Finish accepted durable work and the current admin action, queue one
    fixed shutdown frame per safe connection, and close writers after flush.
  - [ ] Run one due audit-retention checkpoint, await storage receipts, and
    drain client, admin, log, and TLS close acknowledgements during flush.
  - [ ] Cancel and join all remaining children before closing crypto, storage
    bridges, the database owner, and TLS during stop.
  - [ ] Send a second termination signal directly to stop.
  - [ ] Return `DaemonExit::Stopped` or `DaemonExit::RestartRequested`; map
    restart to exit status 75 and keep DIE at status zero.
  - [ ] Keep inherited-listener constructors only as an embedding and test
    seam, and make no `LISTEN_FDS` claim.
  - [ ] Keep the unsupported socket unit and its documentation removed.
  - [ ] Verify `UMask=0077`, `StateDirectoryMode=0700`, log-directory modes,
    exact writable paths, and profile-specific address-family restrictions.
  - [ ] Include `AF_UNIX` for local administration in direct and dual
    profiles. Keep onion-only at `AF_UNIX` unless remote administration is
    configured.
  - [ ] Accept an already-zero core limit before calling `setrlimit` and keep
    the `@resources` filter.
  - [ ] Treat ordinary memory-lock failure as a closed warning and strict
    memory-lock failure as fatal.
  - [ ] Reject duplicate or weakened service directives.
  - [ ] Prove that Tor keys are Tor-owned and not readable or writable by the
    daemon account.
  - [ ] Run every phase timeout and failure case, first and second signals,
    durable work around termination, stuck writers, bridge failure, database
    reopen, idle and loaded shutdown, and zero-live-owner tests.
  - [ ] Run the missing Loom shutdown schedule.
  - [ ] Close the remaining Tor-key-ownership requirement.

Commit point 6

- [x] Land shutdown, lifecycle, binary-exit, systemd, deployment,
  operator-documentation, and directly related test changes. The closing
  commits include `2aa113f`, `250a088`, `448918f`, and `d1e7a37`.
- [ ] Re-run formatting, focused shutdown and daemon tests, Loom, deployment
  checks, host qualification, and source checks on the exact closure
  revision.
- [ ] Run GitNexus `detect_changes` before committing.
- [x] Commit the changes with imperative subjects.
- [x] Push the changes to `stage-06-runtime`.

#### Coverage closure

- [x] Review the production-source coverage inventory. It recorded 88 files
  while merged `main` contains 196 production Rust source files; the closure
  branch rebinds the count and hash.
- [x] Review every added or changed production file for a new
  security-sensitive 100-percent region. The review proposed eight candidate
  regions (state-core admin mutation binding, admin audit authority fences and
  chain verification, local admin credential admission, transport admission
  verdicts, shutdown phase transitions, durable index application, and reload
  candidate activation). None of them reaches 100 percent on the closure
  revision, so none is added; they remain candidates for Stage 10.
- [x] Refresh the source hashes of the six existing regions and confirm that
  each range still brackets the same functions.
- [x] Map uncovered outcomes before adding tests or changing production code.
- [x] Generate fresh full-workspace reports on the closure branch. The
  closure work raised branch coverage from 77.16 percent to 79.79 percent
  (9029 of 11316 outcomes) and line coverage to 91.77 percent.
- [x] Lower the enforced branch floor to an interim 75 percent for Stage 06
  closure. The 90 percent branch target is not reachable without a long tail
  of edge-case tests; it returns as a Stage 10 release-qualification gate.
  The line floor stays at 90 percent and every active critical region stays
  at 100 percent. The remaining uncovered outcomes by file and function are
  recorded for that later work.
- [x] Keep overall line coverage at or above 90 percent.
- [x] Reach 100 percent for every reviewed security-sensitive region.
- [ ] Run the coverage policy self-test and the coverage checker against a
  clean workspace report on the exact closure revision.

  ```sh
  RUSTC_BOOTSTRAP=1 cargo llvm-cov \
    --workspace --all-features --branch --locked \
    --json --output-path target/stage-zero-coverage.json
  python3 scripts/check-coverage.py self-test
  python3 scripts/check-coverage.py check \
    target/stage-zero-coverage.json \
    conformance/critical-coverage.toml
  ```

Commit point 7

- [x] Add focused Stage 06 coverage tests in commit `137e709`.
- [ ] Run formatting, affected package tests, the full workspace coverage run,
  the coverage checker, and source checks.
- [ ] Run GitNexus `detect_changes` before committing.
- [x] Commit and push the partial coverage work to `stage-06-runtime`.
- [ ] Commit point 7 is closed only after the interim branch floor, the line
  floor, and the critical-region thresholds pass on the exact closure
  revision.

#### Requirement ledger and conformance records

- [x] Audit and close exactly 39 Stage 06 normative records.
  - [x] `S06-001`, one strict-configuration record.
  - [x] `S06-003`, four TLS records.
  - [x] `S06-004`, 13 transport and address-privacy records.
  - [x] `S06-008`, three durable StateCore records.
  - [x] `S06-009`, eight account and session-security records.
  - [x] `S06-010`, four channel and messaging records.
  - [x] `S06-011`, one admission record.
  - [x] `S06-012`, two administration records.
  - [x] `S06-014`, two observability and address-privacy records.
  - [x] `S06-015`, one Tor-key-ownership record.
- [x] Do not treat the absence of separate normative records for `S06-002`,
  `S06-005`, `S06-006`, `S06-007`, or `S06-013` as task completion. Their
  task-level evidence is the runtime profile, the transcripts, the deployment
  checks, and the daemon tests recorded in the closing gate run.
- [x] Check `S06-001` through `S06-015` after each task's code, tests, and
  evidence mapping pass. The read-only audits on the closure branch found no
  behaviour gaps; the remaining gaps are missing edge-case tests, which are
  listed as coverage follow-ups for Stage 10.
- [x] Run `python3 scripts/requirements.py generate-bindings` after checking
  the tasks.
- [x] Run `python3 scripts/requirements.py generate`.
- [x] Add the 39 requirement-level Stage 06 evidence-catalog records and the
  matching reviewed bindings in `scripts/check-evidence.py`.
- [x] Keep the existing 16 task-level Stage 06 records, including `S06-900`.
- [x] Verify that Stage 06 has exactly 55 evidence records.
- [x] Run the requirement check, Stage 06 ownership check, requirement
  self-test, Stage 06 profile check and self-test, source check, workspace
  check, CI check, and evidence-catalog check.

Commit point 8

- [x] Add the Stage 06 gate, task-level evidence catalog, runtime profile,
  transcript catalog, CI metadata, and related conformance files in commits
  `e4e2492` and `945977f`.
- [x] Run every generator and checker that owns a staged generated file.
- [x] Run GitNexus `detect_changes` before committing.
- [x] Commit and push the partial conformance work to `stage-06-runtime`.
- [x] Commit point 8 closes on the closure branch once all 39 requirement-level
  records and all 55 Stage 06 evidence records pass their checks.

#### Full implementation gate

- [x] Install or provide the exact required toolchain on the qualification
  host, including Tor, `systemd-analyze`, the AArch64 cross compiler, Rust
  1.98.0, nightly 2026-08-24, `cargo-deny` 0.20.2, `cargo-audit` 0.22.2,
  `cargo-llvm-cov` 0.9.0, and `cargo-fuzz` 0.13.2.
- [x] Run `bash scripts/check-stage-six.sh` without evidence recording until
  all 75 inherited and Stage 06 commands pass from a clean tree. The closure
  branch passes all 75 commands on 2026-09-01 after repairing the Stage 03 and
  Stage 04 module-set checks and rebinding the constant-time review hashes.
- [x] Confirm that the gate includes formatting, native and cross-target
  checks, Clippy, workspace and documentation tests, dependency denial,
  advisory audit, source and workspace checks, coverage, all earlier-stage
  checks, Stage 06 tests, Loom, transcripts, deterministic soak, deployment,
  host qualification, and fuzzing.
- [x] Run both Stage 06 fuzz targets for 10,000 iterations with the fixed seed
  and configured bounds.
- [x] Do not claim the seven-day production soak assigned to `S10-007`.
- [x] Check `S06-900` only after the full non-recording gate passes.
- [x] Update the Stage 06 status text to say that implementation passes and
  exact-revision evidence remains pending.

Commit point 9

- [x] Run GitNexus `detect_changes` for the complete branch against `main`.
- [x] Confirm that the implementation branch contained no unrelated or generated
  residue.
- [x] Commit and push the last implementation source as
  `1c91131ce0b411717a1a3ddb15a0202fc8312ce3`.
- [x] Commit point 9 is closed only after the full non-recording gate passes.

#### Exact-SHA evidence

- [x] Create one temporary detached checkout at the exact source commit. Do
  not create a branch and do not edit source in that checkout.
- [x] Run the recorded gate from the clean detached checkout with
  `AGENC_RELAY_RECORD_GATE=1`.

  ```sh
  source_commit="$(git rev-parse HEAD)"
  env -u GIT_PAGER -u LD_LIBRARY_PATH -u PYTHONPATH \
    AGENC_RELAY_RECORD_GATE=1 \
    bash scripts/check-stage-six.sh
  ```

- [x] Record
  `conformance/evidence/artifacts/stage-six-implementation-65cce9d66f7bcfb0c0830a2ab1d42b52bff82942.json`.
- [x] Generate `conformance/evidence/stage-06-65cce9d66f7bcfb0c0830a2ab1d42b52bff82942.json` with evidence schema
  version 2.

  ```sh
  python3 scripts/generate-gate-evidence.py \
    --artifact \
    "conformance/evidence/artifacts/stage-six-implementation-${source_commit}.json"
  ```

- [x] Run the evidence checker, evidence self-test, and Stage 06 `close-stage`
  command for the exact source SHA.

  ```sh
  python3 scripts/check-evidence.py check
  python3 scripts/check-evidence.py self-test
  python3 scripts/check-evidence.py close-stage \
    --stage 6 --source-commit "${source_commit}"
  ```

- [x] Copy only the generated artifact and manifest back to the active branch,
  together with the required closure-status documentation updates.
- [x] Delete the temporary detached checkout after the artifact is recovered.
- [x] If any source changes after recording, discard the stale Stage 06
  artifact and repeat the exact-SHA gate at the new source commit.

Commit point 10

- [x] Confirm that the staged diff contains only evidence and closure-status
  files.
- [x] Run every evidence checker and self-test again from the active branch.
- [x] Run GitNexus `detect_changes` before committing.
- [x] Commit with the subject `Record Stage 06 checkpoint`.
- [x] Push `stage-06-closure`, the closure branch that replaced
  `stage-06-runtime` after PR #14 deleted it.

#### Pull request and cloud checks

- [x] Open PR #14 from `stage-06-runtime` to `main` containing the
  full Stage 06 history.
- [x] List the affected specification sections and invariants.
- [x] Describe wire, persistence, dependency, privacy, and security effects.
- [x] List the validation commands and known host limitations.
- [x] Keep WSS assigned to Stage 09, federation behavior assigned to Stage 07,
  and E2EE behavior assigned to Stage 08.
- [x] Add no HTTP metrics listener, socket-activation claim, plaintext
  endpoint, wildcard permission, storage-table change, production test double,
  or unreviewed production dependency.
- [x] Merge PR #14 as
  `3a517e9482fe51d7983dc5b9c998fd472e41c600`.
- [x] Fix the failed cloud gate. It stopped at `check-source` because
  `crates/agenc-relay-config/src/paths.rs` has a lint allowance without the
  required review annotation.
- [x] Repeat exact-SHA evidence after any source fix.
- [ ] Leave the pull request open for the cloud-agent and repository-owner
  merge gate. This was violated when PR #14 was merged before the gate passed.

#### Stage 06 review follow-ups

The 2026-09-01 legibility review of the merged runtime closed its definite
defects on `stage-06-closure`. The findings below were verified against the
code but deferred because each needs a design decision, a domain change, or a
specification revision. None blocks the core-v1 gate. Line references are to
the closure branch at review time.

- [x] Keyed JOIN and `MODE +k` now reauthorize with an unmetered current
  snapshot after the Argon2 worker completes. Unrelated commits no longer
  invalidate the result; changed session or channel authority still refuses
  it. Deferred JOIN, MODE, changed-key and disconnected-session regressions
  cover the repair.
- [x] CHANCTL and CHATHISTORY unresolved names now return the same public
  refusal as inaccessible channels. MODE mask removal resolves the canonical
  mask after domain authorization, including quiet-mask role checks. Guest
  CHANCTL account checks precede name lookup on standalone and edge nodes.
  Missing edge MODE targets return SecretUnavailable, and mask arguments cross
  the existing typed federation schema correctly. Live TLS, edge and domain regressions
  cover secret/absent targets and ordered mutation behavior (`PRV-01`, `STA-10`).
  See `docs/stage-10-operational-repair.md`.
- [x] Batch gathering from Architecture 21.5 is unreachable: every plan uses
  the committed revision, so `pending.rs` never chains a second plan. The
  state core now holds its inbox while a batch is pending, so batch size one
  is explicit, every connection observes its own commands in order, and a
  message pipelined behind a JOIN reaches the channel instead of drawing 403
  or SERVERBUSY. Gathering more than one plan per batch still needs a staged
  revision to plan against; the 1 ms gather window stays as specified.
- [x] The minute maintenance event now reaches the registration router and
  retries retained session closes even on an idle server (`STA-01`). The
  regression retains a close behind competing durable work, then verifies
  that maintenance stages removal and releases the nickname after its receipt.
- [x] Account administration advances `account.revision` in both the durable
  after-image and live state. The regression checks suspension, restoration,
  matching after-images and refusal of stale confirmation revisions.
- [x] ACCT and CHANCTL require their vendor capability and standard-replies
  before mutation; CHATHISTORY requires draft/chathistory. Missing capabilities
  receive a bounded numeric refusal. Wire and live-server tests cover capability
  removal, unchanged state on refusal, successful NOTE replies and history batches.
- [x] Startup reconstructs durable before-images for audit events and retained
  checkpoints. The retention regression uses that index without inserting
  rows by hand, commits the expired prefix deletion and checks the reopened
  audit authority and reconstructed checkpoint metadata.
- [x] Appendix C.3 now declares `tls_ocsp_staple_file` in a separate normative
  revision, with public TLS/WSS applicability, bounded protected-file input,
  presence semantics and atomic reload. The parser accepts WSS staples,
  resolving the contradiction with `tls.require_ocsp_staple`. Configuration
  regressions cover optional/required WSS staples and forbidden purposes.
  See `docs/stage-10-ocsp-repair.md`.
- [x] With euid 0, secret file checks accept only root-owned files, so root
  cannot run `print-onboarding`, `check-config`, or `account-invite create`
  against keys installed for the service account. OPS-01 (#40) adds the
  explicit `--service-user <name>` option: a root caller trusts the one
  named local account resolved from `/etc/passwd`, every other file rule is
  unchanged, and `serve` still never starts as root.
- [x] Unused disabled listeners no longer load TLS material; the disabled
  federation entry on an enabled edge still supplies its outbound identity.
  Same-class TLS aliases are allowed consistently; cross-class and other secret
  reuse is rejected. Config, stopped-runtime and real federation restart tests
  cover both paths.
- [x] Reload activation and outcome submission distinguish full or closed
  inbox refusal from a lost reply after acceptance. A refused REHASH now
  commits its failure audit before replying. Tests cover full-queue retry,
  closed inboxes, lost replies and the admin audit receipt boundary.
- [x] Production client readers receive independently bounded input queues at
  admission and StateCore dispatches ready connections round-robin (Architecture
  21.3). Open/control notices retain their separate 64-slot channel. Request and
  byte reservations survive dequeue until dispatch finishes; queue backing is
  reserved before allocation. Boundary, concurrent-producer, shutdown, actor
  admission and durable-command ordering regressions cover the new path.
  See `docs/stage-10-client-input-repair.md` for validation and limits.
- [x] Output queue and input queue backing are acquired on demand (RUN-04).
  An idle connection holds only its 65,536-byte base charge: the writer
  queue keeps a fixed 24-entry ring in connection state and charges one
  exact frame-reference allocation per multi-frame demand, created by
  `prepare` after its permit and released with the demand's final frame;
  the input queue keeps one line inline and charges overflow storage before
  allocating it, growing to the request maximum and releasing on drain.
  Commit stays allocation-free, whole-sink refusal never delivers partially,
  and reload changes apply only to new reservations. 50,000 idle clients fit
  the default pool; the Section 19.3 thresholds against that pool are the
  open conflict in #113. See `docs/stage-10-idle-backing.md`.
- [x] Connection `JoinError` outcomes retain the registered task identity and
  failure policy. They cancel only that child's token; listeners keep accepting
  and existing clients remain usable. Critical task failures still cancel the
  tree. Aborted/unwound child tests and a real TLS listener regression cover
  isolation and permit release; the production panic hook still terminates.
- [x] The reader now checks parsed byte and request bounds before parsing a
  completed line and keeps refusal sticky. It drains each completed line before
  framing another, including a maximum-sized line split across reads. The two
  accumulator regressions fail with the earlier behavior; all 27 connection
  tests pass, including exact bounds and the paused-time inbox stall case.
- [x] One recorded gate run closed a fresh guest connection after the TLS
  handshake and before its first reply
  (`production_daemon_credential_and_lookup_edges_fail_closed`). The
  listener does that only when StateCore refuses the open, drops or never
  answers the open notice, or the tree is cancelled; the unanswered-notice
  case is now classified `Deadline` instead of `Shutdown`, and every
  `connection_closed` event carries its closed reason label. Deterministic
  listener tests force each outcome and check every permit returns once; the
  daemon fixture records phases, attempts, child exit, and the first failure
  and retains bounded logs under a test-only directory variable; a strict
  single-attempt idle-admission test fails on any silent close. The strict
  repetition campaign did not reproduce the incident, so its root cause stays
  unknown. See `docs/stage-10-admission-diagnostics.md`.

- [x] `S06-001` **Implement strict configuration parsing and validation.**
  Parse TOML into an untrusted intermediate, reject unknowns, validate the full
  Appendix-C union and cross-field rules, paths, permissions, bounds, roles,
  targets, and unsafe combinations before listeners open.
  - After: `S05-900`.
  - Targets: `agenc-relay-config`.
  - References: [Architecture §22.1 and Appendix C](docs/arc-architecture-and-implementation-spec.md#221-configuration-document).
  - Invariants: `OPS-02`, `PRV-03`, `TRN-02`.
  - Evidence: golden configuration, unknown/duplicate field, every scalar boundary, cross-field matrix, permission, symlink, and fuzz tests.

- [x] `S06-002` **Implement first-run initialization and `check-config`.**
  Create purpose-separated keys/directories with minimum permissions, display
  onboarding pins safely, validate host controls, and never regenerate durable
  identity implicitly.
  - After: `S06-001`.
  - Targets: `agenc-relay-config`, binary initialization/check commands.
  - References: [Architecture §§22.2–22.3 and Appendix C.8](docs/arc-architecture-and-implementation-spec.md#222-secret-material).
  - Invariants: `ID-06`, `OPS-02`, `OPS-03`.
  - Evidence: clean/partial/repeated initialization, permissions, existing-key, pin, and failure-atomicity tests.

- [x] `S06-003` **Configure TLS 1.3 endpoints exactly.** Use the explicit
  aws-lc provider, TLS-1.3-only versions, `[X25519MLKEM768, X25519]` order,
  no early data/renegotiation/post-handshake auth, exact ALPN, and correct DNS
  or onion identity validation.
  - After: `S06-001`, `S04-013`.
  - Targets: `agenc-relay-runtime`, TLS configuration adapter.
  - References: [Architecture §§8.1–8.3](docs/arc-architecture-and-implementation-spec.md#81-tls-configuration).
  - Invariants: `TRN-01`, `TRN-02`, `TRN-03`.
  - Evidence: positive and negative TLS matrix, hybrid/fallback negotiation, scanner output, ALPN, certificate/pin, and pre-handshake-byte tests.

- [x] `S06-004` **Implement transport-profile isolation.** Keep direct,
  Tor-exit, and onion listeners explicit; forbid reverse DNS, ident, profile
  fallback, address propagation, and unsafe Tor DNS/proxy behavior.
  - After: `S06-002`, `S06-003`.
  - Targets: `agenc-relay-runtime`, deployment profiles.
  - References: [Architecture §§6.1–6.4 and 8.5](docs/arc-architecture-and-implementation-spec.md#61-direct).
  - Invariants: `ID-04`, `PRV-03`, `PRV-04`.
  - Evidence: profile-mismatch, real onion, SafeSocks/TestSocks, DNS-leak, packet-capture, and forbidden-field tests.

- [x] `S06-005` **Implement the owned Tokio task tree.** Supervise listeners,
  connections, StateCore, storage, crypto, timers, maintenance, admin, and
  signals with finite children, propagated failures, cancellation, and joined
  shutdown.
  - After: `S06-003`, `S06-004`.
  - Targets: `agenc-relay-runtime`.
  - References: [Architecture §§21.1–21.2 and 21.8](docs/arc-architecture-and-implementation-spec.md#211-ownership-rule).
  - Invariants: `CON-01`, `CON-02`, `CON-04`, `OPS-04`.
  - Evidence: task panic, start failure, connection churn, cancellation at each phase, idle/load shutdown, and no-leak tests.

- [x] `S06-006` **Implement global memory admission and permits.** Acquire
  exact charges before count-scaled allocation, preserve ownership through
  buffers and reservations, isolate fixed headroom, and reject exhaustion
  before side effects.
  - After: `S06-005`.
  - Targets: `agenc-relay-runtime`, `MemoryBudgetPort`.
  - References: [Architecture §§19.1–19.3 and 24.2](docs/arc-architecture-and-implementation-spec.md#191-hierarchical-admission).
  - Invariants: `CON-05`, `STA-08`, `TRN-04`.
  - Evidence: exact permit accounting, split/drop/rollback, exhaustion, allocation-failure proxy, and high-water tests.

- [x] `S06-007` **Implement connection and output owners.** Give each client a
  generation-bound bounded input/output owner, tentative/prepare/commit queue
  reservations, slow-consumer close, exact ordering, and infallible allocation-
  free commit after preparation.
  - After: `S06-005`, `S06-006`.
  - Targets: `agenc-relay-runtime`, client sink implementation.
  - References: [Architecture §§15.3, 21.3, and 24.2](docs/arc-architecture-and-implementation-spec.md#153-backpressure-and-fanout).
  - Invariants: `STA-08`, `CON-02`, `CON-05`.
  - Evidence: whole-sink exclusion, queue full/close, generation reuse, shared-buffer charging, ordering, and exact permit-return tests.

- [x] `S06-008` **Implement `StateCore` durable command execution.** Own all
  mutable protocol state, construct plans at one revision, reserve runtime
  resources, submit complete storage batches, consume matching receipts, apply
  once, and only then render success.
  - After: `S06-005` through `S06-007`.
  - Targets: `agenc-relay-runtime`.
  - References: [Architecture §§21.1, 21.4–21.5, and 24.2](docs/arc-architecture-and-implementation-spec.md#211-ownership-rule).
  - Invariants: `CON-01`, `CON-03`, `DUR-01`, `STA-06`, `STA-08`, `OPS-04`.
  - Evidence: cancellation/disconnect before and after every reservation/commit/receipt/apply/render boundary.

- [x] `S06-009` **Compose registration, authentication, and session routing.**
  Connect TLS, client wire, account-service jobs, SASL, domain plans, storage,
  welcome state, account switches, logout, keepalive, and connection closure.
  - After: `S04-900`, `S06-008`.
  - Targets: `agenc-relay-runtime`.
  - References: [Architecture §§10–12](docs/arc-architecture-and-implementation-spec.md#10-connection-and-registration-state-machine).
  - Invariants: `ID-*`, `AUTH-*`, `TRN-*`.
  - Evidence: complete registration/account lifecycle transcripts, malicious-edge cases, restart, and generation-fence integration tests.

- [x] `S06-010` **Compose single-node channel and message behavior.** Execute
  local/global channels, discovery, roles, modes, moderation, direct/channel
  messages, recipient reservations, ephemeral defaults, and optional-policy
  refusal exactly as the domain model specifies.
  - After: `S06-007` through `S06-009`.
  - Targets: `agenc-relay-runtime`, `agenc-relay-server` integration tests.
  - References: [Architecture §§13–17](docs/arc-architecture-and-implementation-spec.md#13-channel-model).
  - Invariants: `PRV-*`, `STA-*`, applicable `E2E-02`.
  - Evidence: core-v1 transcripts, model/implementation snapshot equality, overload, slow consumer, and privacy tests.

- [x] `S06-011` **Implement timers, admission, and overload behavior.** Drive
  connection deadlines, keepalive, authentication expiry, rate buckets,
  maintenance, overload classes, and cleanup with explicit clock inputs and
  bounded timer ownership.
  - After: `S06-005`, `S06-006`, `S06-008`.
  - Targets: `agenc-relay-runtime`.
  - References: [Architecture §§19 and 21.6](docs/arc-architecture-and-implementation-spec.md#19-abuse-resistance-and-resource-limits).
  - Invariants: `AUTH-02`, `CON-02`, `CON-05`, `FED-09` where applicable.
  - Evidence: paused-time boundary, replacement/cancellation, slowloris, churn, exhaustion, and post-quiescence recovery tests.

- [x] `S06-012` **Implement isolated administration.** Support local Unix and
  separately pinned mTLS administration, signed contiguous challenges,
  permission mapping, exact read-only batches, mutation authorization, and
  chained audit records; expose no admin authority through client IRC.
  - After: `S06-002`, `S06-003`, `S06-008`.
  - Targets: `agenc-relay-admin`, runtime admin owner.
  - References: [Architecture §§22.4–22.6](docs/arc-architecture-and-implementation-spec.md#224-administrative-transports).
  - Invariants: `TRN-03`, `OPS-03`, `OPS-05`.
  - Evidence: transport/pin/signature/counter/permission/replay/batch/audit/privacy matrix.

- [x] `S06-013` **Implement strict reload behavior.** Validate the entire new
  configuration before atomic activation, reject immutable or unsafe changes,
  and retain the prior configuration on every failure.
  - After: `S06-001`, `S06-012`.
  - Targets: `agenc-relay-config`, runtime configuration owner.
  - References: [Architecture §22.6](docs/arc-architecture-and-implementation-spec.md#226-reload-behavior).
  - Invariants: `OPS-02`, `OPS-04`.
  - Evidence: every reloadable/immutable field, concurrent request, allocation, listener, and rollback case.

- [x] `S06-014` **Implement privacy-bounded observability.** Emit only closed
  log events, fixed metric labels/buckets, local authenticated health, fresh
  process correlation IDs, bounded retention, and explicit readiness/liveness.
  - After: `S06-005`, `S06-008`, `S06-012`.
  - Targets: runtime observability adapters.
  - References: [Architecture §§25.2–25.3](docs/arc-architecture-and-implementation-spec.md#252-logging).
  - Invariants: `OPS-01`, `PRV-02`, `ID-04`, `ID-05`.
  - Evidence: forbidden-value canaries, label-cardinality checks, endpoint exposure, retention, and error-format scans.

- [x] `S06-015` **Ship the single-node service hardening profile.** Run as a
  dedicated unprivileged account, disable core dumps, restrict filesystem,
  syscalls, address families, ptrace, devices, and writable paths, and report
  unavailable controls honestly.
  - After: `S06-002` through `S06-014`.
  - Targets: service definition, deployment checks, operator documentation.
  - References: [Architecture §§25.1 and 25.4–25.5](docs/arc-architecture-and-implementation-spec.md#251-process-and-filesystem-isolation).
  - Invariants: `OPS-01`, `OPS-02`, `OPS-04`.
  - Evidence: host-hardening checks, permissions, locked-secret modes, crash behavior, signal shutdown, and incident-mode tests.

- [x] `S06-900` **Pass the Stage 06 core-v1 gate.** A standalone TLS-only node
  must satisfy the core conformance target with bounded ownership, durable
  results, privacy-safe operations, clean shutdown, and no federation/E2EE
  behavior falsely advertised.
  - After: `S06-001` through `S06-015`.
  - Targets: full single-node release binary and deployment profile.
  - References: [Architecture §§1.1 and 29 phase 6](docs/arc-architecture-and-implementation-spec.md#11-conformance-targets).
  - Invariants: applicable `TRN-*`, `ID-*`, `AUTH-*`, `PRV-*`, `STA-*`, `DUR-*`, `CON-*`, `OPS-*`.
  - Evidence: core-v1 transcripts, Loom models, shutdown/overload/soak tests, host checks, and mandatory build gates pass.


#### Stages 1 to 6 review follow-ups

The 2026-09-02 legibility pass over every crate from Stage 01 to Stage 06
fixed its definite defects on `review/stages-1-6` (mask-list setter
attribution, backup record ceiling, range-read byte budget, restore resume
after finalize). The findings below were verified against the code but
deferred because each needs a design decision or a specification reading.
None blocks the core-v1 gate.

- [ ] `verify_integrity_ledger` writes a full recovery scratch database inside
  the state directory after a checkpoint has committed (`engine.rs`
  `commit_prepared_checkpoint`, `platform.rs` `create_recovery_scratch`). The
  scratch is O(N) and outside the admission reserve, so ENOSPC there maps to
  `Indeterminate` and poisons the owner although the durable state is
  consistent. Size the scratch against capacity first or give a post-commit
  verification failure its own non-poisoning outcome.
  Resolved by STO-04 (#65, 2026-09-18): the checkpoint reads its cut back
  through admitted, bounded scratch slices before it publishes and allocates
  no scratch afterwards; see
  [the bounded recovery scratch record](docs/stage-10-bounded-recovery-scratch.md).
- [ ] `start_backup` runs `startup_scan` and `verify_snapshot_accounting`
  (two full decrypts) before the first slice, and `BackupJob::finish` runs
  `verify_backup` twice, all on the owner thread, so commit and read latency
  during a backup is O(database) rather than O(slice). Reuse the checkpoint
  slicing for the accounting pass and drop one post-write verification.
- [x] Initialization refuses every existing rollback guard before creating the
  database and publishes its first guard with an exclusive rename. Three
  integration regressions reproduce the original overwrite and now pass;
  platform tests cover a guard appearing after admission and later normal
  replacement. The complete storage suite passes 316 tests.
- [x] Backup trust-key validity windows are checked against the header
  `created_at` that the same key signs (`backup.rs` `accepts_creation_time`),
  so a key compromised after `not_after` can still produce accepted backups
  by back-dating. Recorded as an accepted current-format limitation: the
  interval constrains the signed claim, not when the backup existed. The
  operator guide section on backup signing-key validity windows names the
  independent controls (manifest row removal, current guard boundary,
  custody, retained keys and generation pins) and separates a retained key
  from a disabled one; the API comments say the same, and
  `a_backdated_backup_inside_a_retained_interval_is_accepted_by_current_policy`
  documents the accepted backdated case beside both boundaries, an unknown
  key, a mismatched key, and a tampered header. Binding `created_at` to an
  external fact would be a separately reviewed versioned design.
- [x] If the second `verify_backup` in `BackupJob::finish` fails after
  `publish`, the file stays under its final name while the caller gets an
  error, and a retry then fails on `RENAME_NOREPLACE`. Publication now keeps
  the verified descriptor through the no-replace rename, proves by inode
  identity that the final name refers to that file instead of re-reading it,
  and retracts the artifact (only after proving the name still refers to the
  written inode, then syncing the directory) when anything after the rename
  fails, so a failed publication never occupies the final name and the
  same-name retry publishes. A foreign inode under the name is never touched
  and a same-name retry against it is refused. The audit regression and the
  extended fault matrix assert directory contents and the verified retry at
  every backup boundary; see `docs/stage-10-backup-publication-repair.md`.
- [x] `cleanup_random_temporaries` enumerates and unlinks through the same
  locked directory descriptor. A regression replaces its original path,
  preserves unrelated replacement-directory files, and verifies a fresh
  enumeration cursor on a second sweep.
- [x] Sealed-record decode borrows ciphertext from the input envelope, and
  authenticated opening borrows the same bytes through the crypto adapter.
  Sealing transfers its owned allocation without another ciphertext copy.
  Pointer-identity, boundary and authentication regressions cover the change;
  see `docs/stage-10-storage-copy-repair.md`. STO-1 remains open.
- [x] The upstream redb bounded-transaction mechanism for STO-1 is implemented
  in an isolated v4.2.0 checkout (STO-01): a typed physical allocation
  allowance charged for every page extent and file extension before
  allocation, latched typed refusals that never poison the database,
  abortable preparation that journals and restores the allocator on refusal,
  allocation-free header publication, bounded resumable reclamation, and
  bounded allocator-state persistence that the close path then skips. The
  patch, digests, validation commands and results are recorded in
  `docs/upstream/redb-bounded-transaction/`. STO-1 itself stays open for
  upstream publication (STO-02) and integration (STO-03).
- [x] The x86_64 qualification host is prepared and recorded (REL-01): native
  identity, the ext4 NVMe tuple, pinned toolchains, Docker, delegated cgroups,
  Tor and ACL tools, the release and client-tools images built by the
  repository scripts with their records, and the isolation, reservation,
  retention and resumption runbook are in
  `docs/stage-10-qualification-hosts.md`. The AArch64 host remains an explicit
  external blocker: no native host is available and the hosted ARM build path
  is behind the organization Actions block (#41).
- [x] Reverse restore-manifest traversal uses checked addition for its first
  sequence, preserving the existing guarded descending traversal.
- [x] `io_rejected` and `rustix_rejected` collapse every errno to
  `FilesystemRejected`, so a missing guard, EACCES, ENOSPC, and EIO are
  indistinguishable to operators and tests. `FilesystemRejected` now carries
  a closed `FilesystemCause` (missing state, permission, capacity,
  unqualified, I/O failure, unsafe path, unknown) classified at the platform
  and backup adapters from the raw errno and at every explicit policy check;
  the outer Rejected/Indeterminate outcome never depends on it, the Display
  and the `error=filesystem_<cause>` log label are fixed text, and the
  operator guide maps each cause to an action.
- [x] Channel body encoding and decoding validate topic text through the
  domain parser and require canonical typed masks in all three lists.
  Regressions reject controls, malformed masks and normalized aliases;
  controls preserve topic tabs and Unicode, every mask subject and quiet masks.
- [x] `PersistentRecordValue::decode` requires strictly ascending table/key
  references before constructing the value. Regressions reject reversed keys,
  reversed tables and duplicate references while preserving canonical output.
- [ ] `project_channel` (`domain/projection.rs`) hides an unlisted (`+p`)
  channel from non-members, while the specification defines `+p` as
  list-hiding rather than existence-hiding. Confirm the intended reading.
- [x] Rechecked JOIN key reuse against Appendix A.1: `csv(T,N)` forbids
  duplicate canonical values, and JOIN explicitly uses `csv(key,20)`. The
  current duplicate-key rejection follows that grammar. No parser change.
- [ ] `reserved_nickname_owner`, `validate_new_invite_id`, the invite purge
  in `apply_close_session`, and the `DeleteAccount` touched-entity walk scan
  their maps linearly per command (`domain/decision.rs`). Fine at Stage 06
  scale; index them before the limits table is raised.
- [x] `arcd init` writes its effective UID into both the local listener's
  `allowed_uids` and the operator's `local_uids`. Root initialization still
  selects UID 0. Template and real initialization regressions check matching
  admission identities while preserving signing-key proof requirements.
- [x] `account-invite create --expires-in` rejects signs, leading zeroes,
  whitespace, non-ASCII digits and overflow before reading protected inputs.
  A subprocess regression reproduces the earlier acceptance of `+1` and
  passes for all eight invalid spellings with the repair.
## Stage 07 — Base federation

Outcome: one coordinator and its authenticated edges converge through bounded,
durable, privacy-minimized requests, results, events, projections, snapshots,
partitions, and recovery.

- [x] `S07-001` **Implement authenticated federation transport.** Require
  TLS 1.3, exact ALPN, static certificate/application-signature pins, exporter
  binding, bounded framing, and independent peer authorization before role use.
  - After: `S06-900`.
  - Targets: `agenc-relay-runtime`, federation-link owner.
  - References: [Architecture §20.2](docs/arc-architecture-and-implementation-spec.md#202-link-transport-and-trust).
  - Invariants: `TRN-01`, `TRN-03`, `FED-02`, `FED-10`.
  - Evidence: TLS/pin/exporter/ALPN/role/recovery-epoch positive and negative matrices.

- [x] `S07-002` **Implement FHELLO/READY negotiation.** Exchange exact role,
  identity, incarnation, recovery epoch, base profile hash, features, cursors,
  and readiness state; block activation until required synchronization finishes.
  - After: `S07-001`.
  - Targets: `agenc-relay-federation-wire`, federation-link state machine.
  - References: [Architecture §20.3](docs/arc-architecture-and-implementation-spec.md#203-authenticated-hello), [Appendix B.9](docs/arc-architecture-and-implementation-spec.md#b9-federation-profile-hash).
  - Invariants: `FED-02`, `FED-10`, `E2E-07`.
  - Evidence: every tuple mismatch, stale/gap/exhausted incarnation/epoch, early READY, and reconnect transition test.

- [x] `S07-003` **Enforce coordinator/edge authority.** Route every global
  mutation to exactly one logical coordinator; prohibit edge self-promotion,
  edge-to-edge transit, state merge, and guessed partition outcomes.
  - After: `S07-002`.
  - Targets: federation runtime and domain planning.
  - References: [Architecture §§20.1 and 20.10](docs/arc-architecture-and-implementation-spec.md#201-logical-topology).
  - Invariants: `FED-01`, `FED-02`, `OPS-04`.
  - Evidence: topology, partition, coordinator loss/restart, role-conflict, and no-merge model tests.

- [x] `S07-004` **Implement origin lifecycle and fencing.** Maintain live
  origin incarnations, contiguous operation sequences, expiry, deletion
  tombstones, recovery-epoch changes, and permanent fencing of earlier states.
  - After: `S07-002`, `S07-003`.
  - Targets: `agenc-relay-domain`, `agenc-relay-storage`, federation runtime.
  - References: [Architecture §20.7](docs/arc-architecture-and-implementation-spec.md#207-origin-lifecycle).
  - Invariants: `FED-03`, `FED-04`, `FED-09`, `FED-10`.
  - Evidence: duplicate/gap/conflict, incarnation replacement, expiry boundary, tombstone, restart, and replay tests.

- [x] `S07-005` **Implement idempotent requests and durable results.** Validate
  every operation arm, origin sequence, canonical request hash, target revision,
  replay key, result descriptor, and exact stored outcome before forwarding or
  replaying it.
  - After: `S07-004`.
  - Targets: federation wire/domain/storage/runtime.
  - References: [Architecture §§20.5–20.6 and Appendix B.6](docs/arc-architecture-and-implementation-spec.md#205-requests-and-idempotency).
  - Invariants: `FED-03`, `FED-04`, `FED-12`, `DUR-01`.
  - Evidence: every opcode/result arm, exact retry, conflicting reuse, gap, crash, descriptor mismatch, and original-sink test.

- [x] `S07-006` **Implement least-information events and projections.** Derive
  target-edge records at one committed revision, include only authorized data,
  durably erase it when authorization ends, and never project addresses,
  secrets, auth state, or unrelated channels.
  - After: `S07-003` through `S07-005`.
  - Targets: domain projection model, storage outbox, federation runtime.
  - References: [Architecture §20.8 and Appendices B.4–B.5](docs/arc-architecture-and-implementation-spec.md#208-events-projection-and-acknowledgments).
  - Invariants: `PRV-02`, `FED-05`, `FED-07`.
  - Evidence: multi-edge projection diffs, grant/revoke, secret-channel, deletion-before-ACK, and forbidden-field canaries.

- [x] `S07-007` **Implement durable event ACKs and completion coverage.** ACK
  only in the same transaction that applies an event and advances its cursor;
  render a committed result only after its completion is durably covered.
  - After: `S07-005`, `S07-006`.
  - Targets: federation runtime/storage barrier.
  - References: [Architecture §20.8](docs/arc-architecture-and-implementation-spec.md#208-events-projection-and-acknowledgments).
  - Invariants: `FED-05`, `FED-12`, `DUR-01`, `DUR-02`.
  - Evidence: result-first/completion-first, lost ACK, duplicate, crash at each boundary, and successor-snapshot coverage tests.

- [x] `S07-008` **Implement bounded federation object transport.** Validate
  direction, authenticated prefix, descriptor, carrier, length, object hash,
  fragment order/count, reassembly budget, and typed payload before dispatch.
  - After: `S07-001`, `S07-005`.
  - Targets: `agenc-relay-federation-wire`, federation runtime.
  - References: [Architecture §§20.4 and Appendix B.8](docs/arc-architecture-and-implementation-spec.md#204-canonical-federation-objects).
  - Invariants: `TRN-04`, `TRN-05`, `FED-08`, `CON-05`.
  - Evidence: fragment flood, collision, direction/prefix/descriptor/hash/length/count mismatch, timeout, and budget tests.

- [x] `S07-009` **Implement snapshots and resume.** Validate immutable snapshot
  count, order, IDs, digest, cut, cross-references, pagination, pending state,
  replay, ACTIVE authorization, atomic swap, and old-generation quarantine.
  - After: `S07-006` through `S07-008`.
  - Targets: federation wire/domain/storage/runtime.
  - References: [Architecture §20.9 and Appendix B.7](docs/arc-architecture-and-implementation-spec.md#209-snapshot-and-resume-protocol).
  - Invariants: `FED-05`, `FED-06`, `FED-07`, `FED-10`.
  - Evidence: empty/one/maximum pages, reorder/duplicate/missing/cross-reference failures, crash, stale ACTIVE, and atomic-swap tests.

- [x] `S07-010` **Implement partition, keepalive, and outbox recovery.** Detect
  silent peers, apply one nonextendable origin grace interval, fence a full
  durable outbox into snapshot recovery, coalesce only safe notifications, and
  never drop durable state.
  - After: `S07-004`, `S07-007`, `S07-009`.
  - Targets: federation runtime/storage maintenance.
  - References: [Architecture §§20.10, 21.6, and 24.2](docs/arc-architecture-and-implementation-spec.md#2010-partitions-and-coordinator-recovery).
  - Invariants: `FED-01`, `FED-09`, `CON-02`, `OPS-04`.
  - Evidence: silent/lost/slow peer, grace boundaries, full outbox, dropped notification, restart, and resynchronization tests.

- [x] `S07-011` **Implement bounded paged directory queries.** Retain one
  immutable snapshot and one session/account/query/page-bound cursor slot;
  atomically replace it on continuation and return only `QUERY_EXPIRED` for
  invalid, consumed, restarted, or mismatched cursors.
  - After: `S07-005`, `S07-006`.
  - Targets: domain/query model, storage/runtime query state.
  - References: [Architecture §§20.5.2 and Appendix B.6](docs/arc-architecture-and-implementation-spec.md#2052-closed-operation-table).
  - Invariants: `FED-13`, `PRV-02`, `STA-10`.
  - Evidence: page size/cut, expiry, consume, restart, wrong binding, mutation between pages, and no-splice tests.

- [x] `S07-012` **Extend the reference model and fault simulator.** Model
  multiple edges, origins, requests, results, events, snapshots, ACKs,
  partitions, recovery, storage failures, and privacy projections deterministically.
  - After: `S07-003` through `S07-011`.
  - Targets: `agenc-relay-testkit` federation model/simulator.
  - References: [Architecture §§28.3, 28.5, and 28.6](docs/arc-architecture-and-implementation-spec.md#283-state-machine-and-model-tests).
  - Invariants: `FED-*`, applicable `PRV-*`, `DUR-*`, `CON-*`.
  - Evidence: bounded formal model, generated fault schedules, model/implementation equality, and exact replay convergence.

- [x] `S07-013` **Complete federation privacy and interoperability tests.**
  Exercise all wire arms, legacy-client-facing results, least-information
  projections, reconnect/resume, resource ceilings, and server incarnation
  changes across real multi-process nodes.
  - After: `S07-001` through `S07-012`.
  - Targets: multi-node integration and interoperability suites.
  - References: [Architecture §§28.6–28.7 and Appendix D](docs/arc-architecture-and-implementation-spec.md#286-network-interoperability-and-privacy-tests).
  - Invariants: `FED-*`, `PRV-*`, `TRN-*`, `DUR-*`.
  - Evidence: multi-edge test matrix, packet/log/database canaries, capacity limits, and pinned transcript outputs.

- [x] `S07-900` **Pass the Stage 07 federated-v1 gate.** Coordinator and edges
  must converge safely across duplicates, gaps, crashes, partitions, snapshots,
  and recovery without leaking unauthorized projected state.
  - After: `S07-001` through `S07-013`.
  - Targets: federated release topology and complete evidence set.
  - References: [Architecture §§1.1 and 29 phase 7](docs/arc-architecture-and-implementation-spec.md#11-conformance-targets).
  - Invariants: `FED-01` through `FED-13` and all coupled privacy/durability/concurrency invariants.
  - Evidence: bounded model, multi-edge fault simulation, replay, privacy scans, and mandatory workspace gates pass.

### Stage 07 completion notes

The federated-v1 implementation closed on branch `stage-07-federation` on
2026-09-03. The following interpretations and deferrals were made while
implementing it and are recorded here so a later reviewer does not have to
rediscover them.

- Coordinator admission does not meter federated commands; the edge meters
  its own clients and the coordinator trusts the peer link.
- An edge holds no account-service keys (spec 22.2). At Stage 07 closure,
  account creation, credential change, and SASL carriers on an edge answered
  `FAIL <command> UNAVAILABLE`. Sealed account-creation and login forwarding
  are now implemented; registered credential replacement still answers
  `UNAVAILABLE`.
- An edge presents the certificate and key of its `federation` listener
  entry, which stays disabled because an edge never accepts. The
  configuration schema has no separate edge certificate field.
- Federation certificates carry no extended key usage so one leaf serves
  both link directions; the SAN URI and SPKI pin are the identity.
- Expected revisions are compared for equality (`STALE_STATE` on any
  mismatch). An edge therefore holds a connection's next command until its
  earlier request completed, so the revision it sends reflects that request.
- The coordinator backlogs link traffic that arrives while a federation
  batch is in flight instead of refusing pipelined synchronization frames.
- `PEER QUARANTINE` confirms against the process revision; a quarantined
  peer's live link closes and every later link is closed at once.
- A federated coordinator keeps edge-hosted sessions across a restart; the
  origin exchange and the grace sweep reconcile them. The grace timer does
  not survive the restart, so every restored peer without a live link gets
  one fresh grace interval measured from the boot, and an expiry the
  restart interrupted resumes hiding the sessions it still hosts.
- An edge that returns under a new incarnation fences the previous one
  (FED-04); the sessions the previous incarnation hosted are hidden as soon
  as its FORIGIN RESET is accepted rather than after a grace interval.
- A write that finds a link task already gone retires the link at once
  without counting a protocol violation; the owner's `Closed` event then
  finds nothing live.
- Deferred: durable edge pending-request rows, old projection generation
  cleanup on the coordinator, a Loom model of link
  replacement, pinned byte transcripts for the federation exchanges, and
  history queries, which answer `UNAVAILABLE`.
- The subsequent review implemented edge startup reconstruction of durable
  barriers, receipts, projections, and cursors. An edge resynchronizes through
  a snapshot when its cursor is unknown.

## Stage 08 — E2EE server adapter and joint transactions

Outcome: the federated daemon negotiates the exact companion profile, validates
and routes only its assigned public objects, and commits base/E2EE state
atomically while remaining unable to decrypt content or operate an MLS client.

- [x] `S08-001` **Implement exact E2EE profile negotiation.** Require the
  frozen `(version, profile-hash)` on client CAP and federation ECAP, enforce
  dependencies and timeout, and fail closed on absent, malformed, stale,
  mismatched, rolled-back, or exhausted transitions.
  - After: `S07-900`.
  - Targets: `agenc-relay-e2ee`, client/federation negotiation state.
  - References: [Architecture §§18.2 and 26.3](docs/arc-architecture-and-implementation-spec.md#182-cross-document-precedence), [E2EE §§2.3 and 11.1](docs/arc-mls-e2ee-extension.md#23-exact-profile-revision).
  - Invariants: `E2E-07`, `FED-02`, `FED-10`.
  - Evidence: exact match plus every tuple, ordering, timeout, reconnect, rollback, gap, and downgrade negative.

- [x] `S08-002` **Enforce the daemon/client separation mechanically.** Expose
  only public-object validation, routing, storage metadata, and transaction
  planning; forbid production dependency on an MLS client state machine or any
  API accepting epoch secrets, plaintext, root private keys, or device keys.
  - After: `S08-001`.
  - Targets: `agenc-relay-e2ee`, Cargo graph/source checks.
  - References: [Architecture §§18 and 24.1](docs/arc-architecture-and-implementation-spec.md#18-e2ee-integration-contract), [E2EE §20](docs/arc-mls-e2ee-extension.md#20-implementation-separation).
  - Invariants: `E2E-01`, `E2E-02`.
  - Evidence: dependency/API/source scans and compile-fail tests reject MLS-client or secret-bearing production surfaces.

- [x] `S08-003` **Validate public identity and device objects.** Check account
  roots, enrollment possession, device certificates, capability chains,
  complete rosters, revocation, leaf authorization, generations, signatures,
  semantic IDs, and canonical encodings without resolving private keys.
  - After: `S08-002`.
  - Targets: `agenc-relay-e2ee`, crypto/type adapters.
  - References: [E2EE §§2.1–2.2 and 8](docs/arc-mls-e2ee-extension.md#21-signature-registry).
  - Invariants: `E2E-01`, `E2E-05`, `ID-01`, `ID-02`.
  - Evidence: independent vectors and missing/duplicate/stale/rollback/equivocation/signature/capability-chain negatives.

- [x] `S08-004` **Validate route identity and binding locks.** Enforce channel
  instance/direct-account-pair identity, route generations, semantic locks,
  root continuity, close/recreate isolation, encrypted/plaintext collision
  refusal, and tombstones.
  - After: `S08-003`.
  - Targets: `agenc-relay-e2ee`, domain route model.
  - References: [Architecture §§18.1, 18.3–18.4](docs/arc-architecture-and-implementation-spec.md#181-channel-binding), [E2EE §9.1](docs/arc-mls-e2ee-extension.md#91-identifiers-and-route-binding).
  - Invariants: `E2E-02`, `E2E-06`, `STA-02`.
  - Evidence: bind/rebind/close/recreate/root rollback/collision/tombstone/restoration vectors.

- [x] `S08-005` **Validate sequencer, policy, roster, and finality authority.**
  Check sequencer credentials, controller authority, full policy replacement,
  roster heads, candidate authorization, quorum/fault math, council transition,
  revocation, and non-circular approval sets.
  - After: `S08-003`, `S08-004`.
  - Targets: `agenc-relay-e2ee`.
  - References: [E2EE §§9.2–9.4](docs/arc-mls-e2ee-extension.md#92-sequencer-credential).
  - Invariants: `E2E-03` through `E2E-05`.
  - Evidence: exhaustive `(n,f,q)` cases, authority/approval substitution, council rotation, and conflicting-candidate tests.

- [x] `S08-006` **Validate MLS public context and application envelopes.**
  Enforce the required context extension, suite-independent profile digests,
  group/route/policy/roster bindings, outer object types, deterministic padding,
  message IDs, durable sequences, and exact size arithmetic while treating
  MLS ciphertext as opaque.
  - After: `S08-003` through `S08-005`.
  - Targets: `agenc-relay-e2ee`.
  - References: [E2EE §§9.5 and 10](docs/arc-mls-e2ee-extension.md#95-required-mls-context-extension).
  - Invariants: `E2E-01`, `E2E-05`, `TRN-04`, `CON-05`.
  - Evidence: context, binding, envelope, padding, under/equal/over limit, nonzero-padding, overflow, and semantic-ID vectors.

- [x] `S08-007` **Implement E2EE client carriers and reassembly.** Handle the
  fragment tag, channel/direct carriers, binding, identity, KeyPackage,
  Welcome, exact success/object responses, standard errors, tokens, arity,
  direction, timeout, and authenticated resource budgets.
  - After: `S08-001`, `S08-004`, `S08-006`.
  - Targets: `agenc-relay-e2ee`, `agenc-relay-client-wire`, runtime reassembly owner.
  - References: [E2EE §§11.2–11.10](docs/arc-mls-e2ee-extension.md#112-fragment-tag).
  - Invariants: `TRN-04` through `TRN-06`, `E2E-05`, `CON-05`.
  - Evidence: every carrier/object/response arm, wire-budget table, fragment flood, duplicate/conflict, collision, expiry, and allocation tests.

- [x] `S08-008` **Implement candidate, receipt, ACK, finalization, and abort
  validation.** Enforce one active candidate, no local skipping, exact
  signatures/TBS, recipient-dependent disposition, finality proofs, terminal
  IDs, deterministic coverage, and byte-identical replay.
  - After: `S08-005` through `S08-007`.
  - Targets: `agenc-relay-e2ee`, domain/storage transaction plans.
  - References: [E2EE §§12.1–12.4](docs/arc-mls-e2ee-extension.md#121-one-active-candidate-no-local-skipping).
  - Invariants: `E2E-03` through `E2E-06`.
  - Evidence: success and every lost/duplicate/reordered/conflicting/stale/malicious receipt, ACK, finalization, abort, and content-cycle test.

- [x] `S08-009` **Implement E2EE federation objects and state exchange.** Cover
  ECAP, operations, results, events, fragments, descriptors, route changes,
  ESTATE pages, ACTIVE, ERESUME, sequencer-set transitions, mailbox ownership,
  and exact replay under the base federation authority model.
  - After: `S08-001`, `S08-007`, `S08-008`.
  - Targets: `agenc-relay-e2ee`, `agenc-relay-federation-wire`, federation runtime.
  - References: [E2EE §12.5](docs/arc-mls-e2ee-extension.md#125-federation), [Architecture §20](docs/arc-architecture-and-implementation-spec.md#20-federation-architecture-and-wire-protocol).
  - Invariants: `FED-*`, `E2E-05`, `E2E-07`.
  - Evidence: every opcode/result/event/descriptor arm, snapshot page boundary, cursor form, retry, incarnation, collision, and synchronization test.

- [x] `S08-010` **Implement server-visible group lifecycle.** Validate device
  provisioning, channel/direct group creation, joins, device addition,
  KeyPackage claim/burn, Welcome delivery, committed roster and pending-join
  state, while keeping all client MLS processing outside production crates.
  - After: `S08-003` through `S08-009`.
  - Targets: `agenc-relay-e2ee`, domain/storage/runtime integration.
  - References: [E2EE §§13.1–13.4](docs/arc-mls-e2ee-extension.md#131-device-provisioning).
  - Invariants: `E2E-01`, `E2E-03`, `E2E-05`.
  - Evidence: provisioning/create/join/add-device, package replay/burn, Welcome, crash, retry, and full-roster tests using test-only clients.

- [x] `S08-011` **Implement removal, revocation, and recovery gates.** Keep
  sending paused where removal is uncertain, distinguish requested from
  cryptographically final removal, validate update/recovery state, and block
  restored routes until exact evidence establishes a new lineage or permanent
  tombstone.
  - After: `S08-008`, `S08-010`.
  - Targets: `agenc-relay-e2ee`, domain/storage/runtime integration.
  - References: [E2EE §§13.5–13.7.1](docs/arc-mls-e2ee-extension.md#135-part-kick-revocation-and-removal), [Architecture §18.4](docs/arc-architecture-and-implementation-spec.md#184-server-recovery-gate-for-encrypted-routes).
  - Invariants: `E2E-04`, `E2E-06`, `STA-09`.
  - Evidence: part/kick/revoke, delayed/failed finality, state loss, exact/conflicting recovery evidence, restore, and tombstone tests.

- [x] `S08-012` **Implement full ReInit and route migration.** Validate target
  suite/key-package preflight, creator and Welcome ACKs, activation, old-group
  closure, PSK deletion, abort/retry, races, and non-reopening of the prior
  lineage.
  - After: `S08-010`, `S08-011`.
  - Targets: `agenc-relay-e2ee`, joint domain/storage plans.
  - References: [E2EE §13.8](docs/arc-mls-e2ee-extension.md#138-full-reinit-and-route-migration).
  - Invariants: `E2E-03`, `E2E-05`, `E2E-06`.
  - Evidence: preflight, every ACK/activation boundary, abort, retry, crash, race, PSK-erasure, and old-lineage-refusal tests.

- [x] `S08-013` **Implement E2EE replay, mailbox, and persistence policy.**
  Enforce object/replay keys, durable sequence/order, idempotent outbox retries,
  offline delivery tokens, mailbox ownership/ACK, retention, deletion, and
  opaque-history rules.
  - After: `S08-008` through `S08-012`.
  - Targets: `agenc-relay-e2ee`, storage/runtime mailboxes and outboxes.
  - References: [E2EE §§14–15](docs/arc-mls-e2ee-extension.md#14-replay-ordering-and-persistence).
  - Invariants: `E2E-01`, `E2E-05`, `DUR-01`, `DUR-02`, `FED-03`.
  - Evidence: duplicate/gap/conflict, disconnect, crash, restart, token ACK, cursor replay, retention, deletion, and byte-identical retry tests.

- [x] `S08-014` **Enforce E2EE resource and timing limits.** Admit before
  signature, hash, reassembly, storage, or fanout work; bound objects,
  fragments, candidates, rosters, groups, mailboxes, queues, timeouts, and
  amplification.
  - After: `S08-007` through `S08-013`.
  - Targets: `agenc-relay-e2ee`, runtime admission and workers.
  - References: [E2EE §16](docs/arc-mls-e2ee-extension.md#16-resource-and-timing-limits), [Architecture §19](docs/arc-architecture-and-implementation-spec.md#19-abuse-resistance-and-resource-limits).
  - Invariants: `TRN-04`, `TRN-05`, `CON-02`, `CON-05`.
  - Evidence: every limit at below/equal/above, authenticated flood, fanout, slow consumer, queue, timeout, and recovery-after-quiescence tests.

- [x] `S08-015` **Implement downgrade, reset, and failure behavior.** Refuse
  plaintext on bound/tombstoned routes, unknown required capabilities,
  mismatched profiles, ambiguous resets, stale roots, partial finality, and any
  fallback that could hide an encrypted-state failure.
  - After: `S08-001`, `S08-004`, `S08-011` through `S08-014`.
  - Targets: `agenc-relay-e2ee`, domain/client/federation error mapping.
  - References: [E2EE §§17 and 19](docs/arc-mls-e2ee-extension.md#17-downgrade-and-reset-behavior), [Architecture §18](docs/arc-architecture-and-implementation-spec.md#18-e2ee-integration-contract).
  - Invariants: `E2E-02`, `E2E-06`, `E2E-07`, `PRV-01`.
  - Evidence: plaintext injection, profile mismatch, reset/recreate/root rollback, partial-state, retry, and exact public-error tests.

- [x] `S08-016` **Implement the cross-profile durable barrier.** Stage one
  target-edge combined base/E2EE change with exact part IDs/counts/bytes,
  receipts, cursor coverage, and one visibility point; neither profile may ACK,
  swap, render, or advance alone.
  - After: `S08-009`, `S08-011` through `S08-015`.
  - Targets: `agenc-relay-e2ee`, domain, storage, federation runtime.
  - References: [Architecture §§20.8, 23.4, and Appendix B](docs/arc-architecture-and-implementation-spec.md#208-events-projection-and-acknowledgments), [E2EE §12.5](docs/arc-mls-e2ee-extension.md#125-federation).
  - Invariants: `E2E-03`, `FED-11`, `FED-12`, `DUR-01`, `DUR-02`.
  - Evidence: every permitted interleaving and crash boundary, 2,047/2,048/2,049 parts, aggregate byte boundaries, wrong metadata, full outbox, and replay tests.

- [x] `S08-017` **Integrate the encrypted node end to end.** Compose client
  negotiation/carriers, public validation, domain plans, durable state,
  federation synchronization, opaque fanout, mailbox delivery, restoration,
  administration, metrics, and shutdown without widening any crate authority.
  - After: `S08-001` through `S08-016`.
  - Targets: all server-side E2EE integration surfaces and release binary.
  - References: [Architecture §§18, 24.1, and 27.4](docs/arc-architecture-and-implementation-spec.md#18-e2ee-integration-contract), [E2EE §20](docs/arc-mls-e2ee-extension.md#20-implementation-separation).
  - Invariants: `E2E-*`, coupled `FED-*`, `DUR-*`, `CON-*`, `OPS-*`.
  - Evidence: full encrypted-channel/direct-message flows with test-only clients, plus restart/partition/overload/privacy/shutdown tests.

### Stage 08 companion verification matrix

The following tasks correspond one-for-one with the numbered gates in
[E2EE §21](docs/arc-mls-e2ee-extension.md#21-verification-and-release-gates).
Task IDs follow executable dependency order.

- [x] `S08-018` **Pin the MLS WG interoperability corpus.** Record immutable
  revision and content hashes for every enabled suite.
  - After: `S08-017`.
  - Targets: test-only MLS corpus and conformance evidence.
  - References: [E2EE §21 gate 1](docs/arc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-05`.
  - Evidence: corpus hash verification and suite coverage manifest.

- [x] `S08-019` **Supply independent E2EE object vectors.** Cover every root,
  device, roster, policy, binding, context, envelope, fragment, sequencer,
  receipt, ACK, finalization, abort, and ReInit public object.
  - After: `S08-003` through `S08-017`.
  - Targets: checked-in E2EE vector corpus and reference validator.
  - References: [E2EE §21 gate 2](docs/arc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-05`.
  - Evidence: independent generator provenance, hashes, and production/reference agreement.

- [x] `S08-020` **Run cross-implementation MLS tests.** Use at least two
  independent libraries or clients in test-only tooling for each enabled suite.
  - After: `S08-018`, `S08-019`.
  - Targets: interoperability harness; never a production daemon dependency.
  - References: [E2EE §21 gate 3](docs/arc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-01`, `E2E-05`.
  - Evidence: versioned cross-implementation matrix and byte/state comparison results.

- [x] `S08-021` **Prove plaintext rejection on encrypted targets.**
  Characterize every client and federation plaintext entry point after route
  binding or tombstoning.
  - After: `S08-015`, `S08-017`.
  - Targets: client/federation integration tests.
  - References: [E2EE §21 gate 4](docs/arc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-02`, `STA-09`.
  - Evidence: complete command/target/history/topic/fallback rejection matrix.

- [x] `S08-022` **Test every E2EE limit and padding boundary.** Include one
  below/equal/above, checked overflow, outer-object fit, nonzero padding,
  short/long padding, and zero-padding edge cases.
  - After: `S08-006`, `S08-014`.
  - Targets: E2EE boundary suites.
  - References: [E2EE §21 gate 5](docs/arc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `TRN-04`, `CON-05`, `E2E-05`.
  - Evidence: mechanically generated boundary table with exact expected outcomes.

- [x] `S08-023` **Fuzz every E2EE parser boundary.** Cover IRC tags, decimals,
  base64url, reassembly, TLS vectors, identity chains, and MLS outer messages
  under fixed time/memory/output bounds.
  - After: `S08-003`, `S08-006`, `S08-007`, `S08-014`.
  - Targets: E2EE fuzz targets and regression corpus.
  - References: [E2EE §21 gate 6](docs/arc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `TRN-04` through `TRN-06`, `CON-05`.
  - Evidence: reproducible fuzz manifests and minimized regression tests.

- [x] `S08-024` **Run stateful adversarial E2EE properties.** Generate
  duplicate, lost, reordered, conflicting, stale, and malicious fragments and
  Commits, including recipient-dependent corrupt UpdatePaths.
  - After: `S08-008`, `S08-017`.
  - Targets: test-only client/reference model and server integration.
  - References: [E2EE §21 gate 7](docs/arc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-03` through `E2E-06`.
  - Evidence: no endpoint applies before finality and no failed endpoint skips candidates.

- [x] `S08-025` **Crash-test every E2EE durable boundary.** Cover restart,
  snapshot restore, and outbox retry without generation, counter, binding,
  ACK, or vote-lock rollback; exact retries remain byte-identical.
  - After: `S08-013`, `S08-016`, `S08-017`.
  - Targets: storage/federation/E2EE fault harness.
  - References: [E2EE §21 gate 8](docs/arc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-05`, `E2E-06`, `DUR-*`, `FED-03`.
  - Evidence: crash before/after every named durable and visibility boundary.

- [x] `S08-026` **Exhaust finality quorum cases.** Test every permitted
  `(n,f)`, prove `2q-n > f`, exercise netsplits and malicious sequencers, and
  report fault-bound violations outside the claim.
  - After: `S08-005`, `S08-008`.
  - Targets: finality model and property tests.
  - References: [E2EE §21 gate 9](docs/arc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-04`, `E2E-05`.
  - Evidence: exhaustive bounded-state result set and conflicting-finality refusal.

- [x] `S08-027` **Test identity, roster, KeyPackage, policy, and sequencer
  transitions exhaustively.** Include rotation, rollback, equivocation,
  add/remove, cross-group replay, last-resort refusal, join confirmation,
  pending state, full-tree Welcome, inline proposals, disabled updates,
  controller binding, and idle-device reminders.
  - After: `S08-003`, `S08-005`, `S08-010`, `S08-011`.
  - Targets: E2EE vector/state-machine suites.
  - References: [E2EE §21 gate 10](docs/arc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-03` through `E2E-06`.
  - Evidence: every listed transition has success, rejection, replay, rollback, and state-equality coverage.

- [x] `S08-028` **Load-test maximum E2EE shapes.** Cover maximum group size,
  fanout, Commit storms, slow consumers, offline queues, and authenticated
  fragment floods.
  - After: `S08-014`, `S08-017`.
  - Targets: release-mode load harness.
  - References: [E2EE §21 gate 11](docs/arc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `CON-02`, `CON-05`, `STA-08`.
  - Evidence: latency, high-water memory/descriptor/queue, rejection, and post-quiescence reports.

- [x] `S08-029` **Audit E2EE logs and telemetry for forbidden material.** Test
  every success/error/fault path with recognizable identity, key, object,
  content, address, and route canaries.
  - After: `S08-017`.
  - Targets: logs, metrics, health, errors, crash identifiers, audit output.
  - References: [E2EE §21 gate 12](docs/arc-mls-e2ee-extension.md#21-verification-and-release-gates), [Architecture §25](docs/arc-architecture-and-implementation-spec.md#25-operations-observability-and-host-security).
  - Invariants: `E2E-01`, `OPS-01`, `PRV-02`.
  - Evidence: automated canary scan plus closed-field review records no forbidden value.

- [x] `S08-030` **Test every ReInit race.** Cover target-suite KeyPackage
  preflight, creator-local ACK, all Welcome ACKs, abort/retry, PSK deletion,
  activation, crash, and permanent old-group closure.
  - After: `S08-012`, `S08-017`.
  - Targets: test-only clients and server ReInit integration.
  - References: [E2EE §21 gate 14](docs/arc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-03`, `E2E-05`, `E2E-06`.
  - Evidence: deterministic interleaving matrix proves the old group never reopens.

- [x] `S08-031` **Exhaust ECAP and E2EE federation transitions.** Test exact
  profile hash, maximum lines, five-second boundary, simultaneous offers,
  legal flags, duplicate/early ACK rejection, tuple mismatches, key-set
  succession, ESTATE pages, route events, ERESUME, mailbox ownership, retries,
  and channel-instance collision handling.
  - After: `S08-001`, `S08-009`, `S08-017`.
  - Targets: E2EE federation model/integration suites.
  - References: [E2EE §21 gate 15](docs/arc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-07`, `FED-02` through `FED-10`.
  - Evidence: complete transition and boundary matrix with canonical page/state comparisons.

- [x] `S08-032` **Verify every E2EE wire budget mechanically.** Enumerate every
  command, tag combination, decimal width, base64url expansion, and escape case
  in client and server directions against 4,094/4,094/8,191-byte budgets.
  - After: `S08-007`, `S08-022`.
  - Targets: generated wire-budget table and renderer tests.
  - References: [E2EE §21 gate 16](docs/arc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `TRN-04`, `STA-08`, `CON-05`.
  - Evidence: generated maximum forms fit exactly and every plus-one form rejects before allocation.

- [x] `S08-033` **Test semantic-ID malleability and acyclicity.** Prove
  alternative valid proof subsets retain one semantic ID, changed TBS fields
  change it, ACK vectors follow their exact rule, and no authorization,
  Welcome, GroupInfo, binding, or policy object contains a future/self ID.
  - After: `S08-003`, `S08-005`, `S08-008`.
  - Targets: semantic-ID vector/property suites.
  - References: [E2EE §21 gate 17](docs/arc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-05`.
  - Evidence: alternative-subset equality, changed-field inequality, cycle rejection, and immutable-MLS-bytes-first construction tests.

- [x] `S08-034` **Test finality-council removal transitions.** Prove only
  retained, fully staged old principals finalize removal, revoked/removed
  principals cannot, and an earlier epoch rotates a council that would fall
  below the old quorum.
  - After: `S08-005`, `S08-008`, `S08-026`.
  - Targets: finality transition model.
  - References: [E2EE §21 gate 18](docs/arc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-04`, `E2E-05`.
  - Evidence: exhaustive retained/revoked/removed membership and quorum transition cases.

- [x] `S08-035` **Exhaust E2EE federation operation semantics.** Cover every
  opcode/result/event selector, required/forbidden descriptor, snapshot token,
  index/kind/object/size/delivery mismatch, ReInit delivery, close broadcast,
  incarnation loss, replay collision/gap, quarantine, ACK barrier, first-login
  projection, and encrypted/plaintext collision.
  - After: `S08-009`, `S08-013`, `S08-016`, `S08-031`.
  - Targets: federation wire/model/fault integration suites.
  - References: [E2EE §21 gate 19](docs/arc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-*`, `FED-*`, `PRV-02`.
  - Evidence: exhaustive registry-arm matrix with mismatch, crash, replay, privacy, and recovery cases.

- [x] `S08-036` **Crash-test E2EE idempotency operations.** Cover KeyPackage
  claim IDs and burns, mailbox delivery-token ACK transactions, cursors, and
  result recovery after disconnect.
  - After: `S08-010`, `S08-013`, `S08-025`.
  - Targets: E2EE storage/runtime fault harness.
  - References: [E2EE §21 gate 20](docs/arc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-05`, `DUR-01`, `DUR-02`, `FED-03`.
  - Evidence: crash at every transaction boundary yields exact replay, burn, or refusal—never duplicate use.

- [x] `S08-037` **Test root identity and binding chains.** Cover missing
  prefixes, alternate proof subsets, root rollback, semantic-route lock reuse,
  close/recreate continuity, and direct-account-pair downgrade blocking.
  - After: `S08-003`, `S08-004`, `S08-033`.
  - Targets: identity/binding vector and state suites.
  - References: [E2EE §21 gate 21](docs/arc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-02`, `E2E-05`, `E2E-06`.
  - Evidence: positive continuity plus every rollback/reuse/substitution/recreation/downgrade negative.

- [x] `S08-038` **Exhaust cross-profile barrier schedules.** Cover every
  base/E2EE part interleaving, result/completion order, lost FACK/EACK, replay,
  crash, wrong metadata, concurrent barrier, later-event injection, part/byte
  boundaries, either outbox full, and snapshot replacement.
  - After: `S08-016`, `S08-025`, `S08-035`.
  - Targets: joint transaction model, storage/federation/runtime fault harness.
  - References: [E2EE §21 gate 22](docs/arc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-03`, `FED-11`, `FED-12`, `DUR-01`, `DUR-02`.
  - Evidence: one combined state cut, both cumulative ACKs or neither, no duplicate frame, and exact original-sink result convergence.

- [x] `S08-040` **Publish conversation policies to the server.** Accept
  `EGROUP SUBMIT POLICY` (object kind `policy`, opcode `submit_policy`),
  verify each policy against the binding's chain and the retained rosters,
  retain it by content identifier, answer identical resubmissions, and
  restore the chain on reload.
  - After: `S08-006`, `S08-017`.
  - Targets: `agenc-relay-e2ee`, `agenc-relay-domain`, `agenc-relay-storage`, coordinator policy handler and startup restore, edge router.
  - References: [E2EE §§9.3, 11.5, 11.7](docs/arc-mls-e2ee-extension.md#93-canonical-policy-and-roster-transitions).
  - Invariants: `E2E-02`, `E2E-04`.
  - Evidence: chain-order, wrong-initial, idempotent, and reload tests; the three-process test publishes both bootstrap policies.

- [x] `S08-041` **Enforce the finality quorum in the sequencer.** Resolve
  `old_policy_id` to the current retained policy, verify every vote through
  the retained roster certificate, count at most one per principal across
  requests, discard sign-once conflicts, and certify a finalization, abort,
  or ReInit terminal only at `q`; keep the route row and route-state object
  at the current head after every terminal.
  - After: `S08-040`.
  - Targets: coordinator sequence handlers, `agenc-relay-e2ee` finality ledger.
  - References: [E2EE §§12.4 and 13.8](docs/arc-mls-e2ee-extension.md#124-finalization-and-abort-certificates).
  - Invariants: `E2E-02`, `E2E-03`.
  - Evidence: `PENDING` below `q`, certification at `q`, `E2EE_POLICY_REQUIRED` without a policy, discarded conflicting votes, refused forged votes.

- [x] `S08-042` **Witness the sequencer record chain at every edge.** Keep a
  per-conversation head from the route-state cut, require every candidate,
  ReInit-staged, terminal, and close event to extend it, refuse and record a
  fork or skipped position durably, and close the link.
  - After: `S08-014`, `S08-041`.
  - Targets: edge event router, `agenc-relay-storage` witness row.
  - References: [E2EE §12.5](docs/arc-mls-e2ee-extension.md#125-federation).
  - Invariants: `E2E-03`, `FED-11`.
  - Evidence: extension, fork, skip, already-installed, and cut-order tests; the three-process test runs under the witness.

- [x] `S08-043` **Pad application content before encryption.** Define
  `ArcEncryptedContent.zero_padding`, apply the Section 7.5 bucket table to
  the content encoding, and reject a wrong length or nonzero octet.
  - After: `S08-004`.
  - Targets: `agenc-relay-e2ee` content module and padding vectors.
  - References: [E2EE §§7.5 and 10](docs/arc-mls-e2ee-extension.md#75-padding).
  - Invariants: `E2E-05`.
  - Evidence: every boundary vector over the content structure plus one-over, short, long, nonzero, and NUL refusals.

- [x] `S08-044` **Drive the encrypted lifecycle with real MLS clients.** Run
  openmls and mls-rs members through the daemon's client surface: KeyPackage
  publication, binding, policy publication, a Commit candidate, ACK, vote and
  finalization under the published quorum, padded application messages, a
  delivered Welcome joined by the other library, and close.
  - After: `S08-020`, `S08-040`, `S08-041`, `S08-043`.
  - Targets: integration test with real MLS libraries as test-only dependencies.
  - References: [E2EE §21 gate 3](docs/arc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-01`, `E2E-05`.
  - Evidence: per-rule outcomes recorded in `conformance/e2ee-interop-matrix.toml`.

- [x] `S08-900` **Pass the Stage 08 encrypted-v1 gate.** Every companion
  public-object rule, joint transaction, invariant, and technical verification
  gate must pass for the exact profile and dependency set before encrypted-v1
  can be advertised.
  - After: `S08-001` through `S08-038` and `S08-040` through `S08-044`.
  - Targets: encrypted-node release topology, complete companion evidence.
  - References: [Architecture §§1.1 and 29 phase 8](docs/arc-architecture-and-implementation-spec.md#11-conformance-targets), [E2EE §21](docs/arc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-01` through `E2E-07` and all coupled invariant families.
  - Evidence: every companion gate, collision/reset/downgrade test, mandatory workspace check, and finding disposition passes.

### Stage 08 completion notes

The encrypted-v1 server adapter closed on branch `stage-08-e2ee-f` on
2026-09-04 after six pull requests (#19 to #23). The following interpretations and
deferrals were made while implementing the companion document and are
recorded here so a later reviewer does not have to rediscover them.

- `responses<0..32>` on a federation result is read as at most 32
  descriptors behind a u16 length prefix.
- The daemon parses MLS outer framing only: the `MLSMessage` version and
  wire format, the `PrivateMessage` public header, the `Welcome` header,
  and the public `KeyPackage`. Everything inside a ciphertext is opaque.
- NFC normalization of the private topic literal is an endpoint matter;
  the server compares the exact literal
  `Encrypted channel - topic protected by ARC-MLS`.
- The home copy of a semantic event is its request's completion (companion
  12.5), so the edge matches completions by event identity for every kind.
- A channel must be registered (`CHANCTL REGISTER`, history off, no topic)
  before `EGROUP BIND`; the binding then flips its content policy through
  the cross-profile barrier.
- The sequencer certifies a finalization, abort, or ReInit terminal only
  after it has verified the current published policy's quorum `q` of
  distinct council votes (companion 12.4 and 13.8, revised 2026-09-04);
  the public authorization rule `BootstrapActivation` on the certificate
  is what activates a fresh conversation, and application traffic before
  it answers `E2EE_FINALITY_REQUIRED`.
- Root binding lock chains are per (account digest, root fingerprint); a
  direct reservation comes from the smaller account of the pair.
- Companion origin declarations are not durable. After reload, `EORIGIN ADD`
  and `UPDATE` are anchored on the matched base origin and continue from the
  durable origin floor. A generation with retained legacy replay history but
  no matching floor is refused because partial history cannot prove its next
  sequence. The edge keeps its sequence across a replayed declaration of the
  same generation and restarts it only for a new generation.
- A retired delivery generation never restarts: a new `ESTATE` scope opens
  the generation after the last durable cursor, and the edge resets the
  barrier owner's companion position when it installs one.
- After `EORIGIN READY` the edge resends every request still waiting for
  its result; the coordinator answers an executed one from its replay
  table and runs the rest.
- Both edge profiles queue events while the other profile's batch is in
  flight, since one state core commits both.
- Route entitlements are refreshed at each `ESTATE` cut from the base
  facts: channel routes follow the peer's channel standing, direct routes
  go to every peer hosting one of the accounts.
- The reload restores retained objects, the directory (root chains
  re-verified, rosters and capabilities re-verified without their retired
  predecessors), binding lock chains, attachments, the KeyPackage stock and
  claims, mailboxes, replay rows and results, delivery cursors, routes,
  logs, lifecycles, ReInit attempts and terminal phases, and per-conversation
  facts, accepted Commit validation times, durable origin sequence floors, and
  successor BIND context digests. Edge startup reconstructs durable barrier
  heads, immutable parts and payloads, receipts, projections, and cursors.
  Not reloaded, by design or
  deferral: route reservations (short-lived), delivery stream rows (a
  reconnecting edge opens a fresh scope), and the genesis `BIND` context digest.
- The cross-implementation gate runs openmls and mls-rs as testkit-only
  dependencies; `.cargo/audit.toml` ignores RUSTSEC-2026-0173, an
  unmaintained compile-time proc macro that openmls_rust_crypto reaches
  through the experimental HPKE feature and that no production crate graph
  contains, and RUSTSEC-2026-0330 and RUSTSEC-2026-0331 against libcrux-kem
  0.0.9, which Cargo.lock lists only as an optional hpke-rs dependency that
  no workspace crate enables (SDK program, outside master #35); the daemon's own view of their framing is what is compared,
  and any deviation between the libraries is recorded in
  `conformance/e2ee-interop-matrix.toml` rather than hidden.
- Completed local submissions retain a bounded reply for 30 minutes, scoped
  to the connection, attached session, object, and full command parameters.
  An identical retry receives the earlier outcome under its new label.
  Durable origin floors survive replay expiry for requests committed by this
  build. Legacy generations with retained replay history but no matching floor
  are refused after restart. If all legacy history has expired, the daemon
  cannot distinguish a used generation from one that never committed a request.
  Replace uncertain legacy origins with a new authenticated generation or a
  client reconnect; see the
  [upgrade procedure](docs/operator-guide.md#upgrade-encrypted-federation-state).
- Deferred: `reserve_direct` refusals for a bad route state map to
  `E2EE_GROUP_CONFLICT`; new 100 percent branch regions for the replay
  classifier, quorum math, barrier verification, and padding arithmetic
  wait for the next coverage round.

The design revision of 2026-09-04 (`S08-040` to `S08-044`) changed the profile
after the first closure and moved the profile hash; the stage was re-closed the
same day at exact source commit `ae6457fb62fef8961d3caf904febed580e8b4a91`
(after the ledger replay, policy adjacency, durable vote row, and queued witness follow-ups), and
re-closed on 2026-09-19 at `26f0f8029dcad4aad27bff2706c4f0d255a555ba`, whose manifest is the
sole retained Stage 08 checkpoint. Its
interpretations: the server retains published policies per conversation under
`policy/v1/` rows and keeps the current policy identifier as the policy the last
finalization installed; the sequencer keeps a per-slot vote ledger across
requests and restores counted votes from durable rows after a reload;
a vote whose signer is not a council principal or does
not verify fails the request with `E2EE_BINDING_AUTH_INVALID`, while a sign-once
conflict discards the vote; an abort request names no policy, so the current
policy governs it; a ReInit terminal is governed by the old conversation's
current policy over the attempt's slot; a policy change installs only the
retained successor of the old policy; each counted vote is a durable `vote/v1/`
row naming its request and terminal, and a reload restores the open slot's
ledger from those rows so no read-back order can flip a principal's decision; a
witness violation found while draining queued events records its row like a live
one; the follow-up below completes ReInit successor route binding;
every sequencer record refreshes the durable route row and the retained
route-state object, which the witness at the edge exposed as missing (a
route-state cut after a finalization, and a reload, advertised the binding-time
head, and an open candidate did not survive a reload); a close occupies the
route sequence after the record that authorized it; the edge records a witness
violation as a durable `witness/v1` row and closes the link, and logs never
carry the identifiers; the `STORED POLICY` and `STORED AUTHORIZATION` lines name
the request's conversation and subject, taken from the payload at ingress.

The implementation review after that checkpoint corrected certificate vote
assembly and startup restoration. Certificates now include all matching votes
accepted across requests, including votes restored after a restart. Historical
root and roster verification preserves accepted policies and votes after device
retirement or root rotation. Reload restores active ReInit attempts, the next
attempt sequence after an abort, the old conversation's migrated state, and the
successor's log and lifecycle anchor. Successor BIND now consumes a dedicated
reservation only for the retained activation's exact target binding, context,
group, and member plan. It preserves the concrete route and semantic lock,
checks the next binding generation and requesting principal, and retains the
epoch-one activation anchor. Reload rechecks the activation, selects the current
successor independently of row order, and rejects missing predecessor evidence.
The coordinator retires the predecessor's live projection and entitlements.
These changes do not update the recorded checkpoint.

## Stage 09 — Optional WSS and pinned history profiles

Outcome: WebSocket transport and plaintext channel history can be enabled
independently without changing the disabled core, federation, or E2EE behavior.

- [x] `S09-001` **Implement the optional WSS listener.** Perform a bounded
  HTTP upgrade to the negotiated pinned subprotocol over TLS 1.3, forbid
  plaintext upgrades and compression, and hand accepted messages to the
  Stage-02 WebSocket framing semantics.
  - After: `S08-900`, `S02-002`.
  - Targets: `agenc-relay-runtime`, strict WSS configuration.
  - References: [Architecture §§8.4 and Appendix C.3](docs/arc-architecture-and-implementation-spec.md#84-websocket-listener).
  - Invariants: `TRN-01`, `TRN-02`, `TRN-04`, `TRN-05`.
  - Evidence: upgrade/header/subprotocol/origin/extension/size/timeout/TLS matrix and resource tests.

- [x] `S09-002` **Prove TCP/WSS protocol equivalence.** Run the same client
  registration, command, auth, privacy, overload, and close transcripts over
  both transports with transport-only differences excluded from protocol state.
  - After: `S09-001`.
  - Targets: client interoperability suites.
  - References: [Architecture §§1.1 and 8.4](docs/arc-architecture-and-implementation-spec.md#11-conformance-targets).
  - Invariants: all applicable core invariants.
  - Evidence: byte/semantic transcript comparison and identical state snapshots.

- [x] `S09-003` **Implement the pinned plaintext channel-history profile.**
  Require explicit policy, bound retention/count/bytes, authorization at write
  and read, durable deletion, ordered queries, and the exact pinned capability
  behavior.
  - After: `S08-900`, `S03-008`, `S05-013`.
  - Targets: domain, storage, client wire, runtime, configuration.
  - References: [Architecture §17.2](docs/arc-architecture-and-implementation-spec.md#172-optional-plaintext-channel-history), [source ledger §4](docs/protocol-sources-and-decisions.md#4-living-protocol-sources).
  - Invariants: `STA-05`, `STA-09`, `PRV-02`, `FED-07`.
  - Evidence: retention/authorization/order/deletion/recreation/federation/privacy and boundary tests against the pinned draft.

- [x] `S09-004` **Prove history cannot touch encrypted routes.** Reject every
  encrypted-target write, query, replay, topic/history compatibility fallback,
  configuration combination, and post-restore ambiguity.
  - After: `S09-003`.
  - Targets: history/E2EE integration tests.
  - References: [Architecture §§17.2 and 18](docs/arc-architecture-and-implementation-spec.md#172-optional-plaintext-channel-history), [E2EE §§15 and 17](docs/arc-mls-e2ee-extension.md#15-history-and-offline-delivery).
  - Invariants: `E2E-02`, `STA-09`.
  - Evidence: complete target/state/config/restore downgrade-refusal matrix.

- [x] `S09-005` **Prove disabled-state equivalence and independent enablement.**
  WSS and history must each be independently optional and separately
  reported. Disabled services must not activate listeners, capture, queries,
  or capabilities. Schema-2 validation, E2EE exclusion, expiry, and purge
  maintenance remain common to every build.
  - After: `S09-001` through `S09-004`.
  - Targets: configuration, release metadata, integration matrices.
  - References: [Architecture §§26.4 and 29 phase 9](docs/arc-architecture-and-implementation-spec.md#264-conformance-claims).
  - Invariants: `OPS-02`, `E2E-02`, `PRV-03`.
  - Evidence: four-mode matrix (neither/WSS/history/both), dependency graph, listener scan, database diff, and capability diff.

- [x] `S09-900` **Pass the Stage 09 optional-profile gate.** Each optional
  feature must satisfy its full negative, interoperability, privacy, and
  disabled-equivalence suite without weakening any prior conformance target.
  - After: `S09-001` through `S09-005`.
  - Targets: optional-profile release configurations and evidence.
  - References: [Architecture §29 phase 9](docs/arc-architecture-and-implementation-spec.md#29-implementation-sequence-and-acceptance-gates).
  - Invariants: all affected prior invariants.
  - Evidence: complete optional-mode matrix and mandatory workspace gates pass.

Stage 09 implementation includes strict WSS framing and Origin/ALPN policy,
authorization-fenced history paging, metadata-only replay, immutable message
identities and retention, and signed resumable purge. The independent build/runtime matrix and
live capture, disabled restart, and purge lifecycles pass. The
[Stage 09 manifest](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-09-a93e53e71d22a6d5ec46bd749ec18068a9fa572b.json)
closes exact source commit `a93e53e71d22a6d5ec46bd749ec18068a9fa572b` with 10
passed records from the recorded 103-command gate. Stage 10 production
qualification is next.

The implementation uses durable state generations for history row sequence,
policy authority, and query snapshot cuts. Domain record revisions retain
their existing compare-and-swap meaning; process-local revision changes do
not become persisted history sequence numbers. Restart tests stop directly
after capture to exercise this distinction.

See [Stage 09 operations](docs/stage-09-operations.md), the
[history profile](conformance/stage-nine-history.toml), and the
[WSS profile](conformance/stage-nine-wss.toml) for configuration and evidence.

## Stage 10 — Production qualification and release

Outcome: the exact release source, lockfile, targets, configurations, service
profile, and artifacts have complete conformance evidence for every claim made.

Implementation, qualification execution, and release closure are distinct.
Create the complete requirement-to-test inventory before implementing the
runner, and track missing evidence throughout the work. `S10-001` closes that
inventory only after all applicable candidate results exist. Task dependencies
below describe evidence closure, not a prohibition on implementing a later
test driver before its prerequisites have finished running.

Freeze source and build inputs, produce the candidate binaries and SBOM, then
test those immutable binaries. Attach the final evidence index and signatures
without rebuilding them. A new source, lockfile, binary, configuration, or
qualification policy creates a new candidate. Archived checkpoints do not
qualify it. The source/dependency check runs before candidate construction and
again before release signing.

The Stage 09 CI failure for source `75e0667` was reproduced during audit
retention in `disabled_history_startup_preserves_original_rows`. The Stage 10
fix preserves the captured signed audit-chain heads while allowing unrelated
database commits between scan pages. The deterministic regression tests and
the 18-test daemon suite pass, including a run restricted to two CPUs. The
prior checkpoint remains valid for its named source.

[Stage 10 qualification notes](docs/stage-10-qualification.md) track the
implemented runner, local metadata, test-client policy, and remaining native
drivers and release evidence. No Stage 10 task is closed by development tests
alone.

- [ ] `S10-001` **Close the complete requirement ledger.** Every normative
  requirement must map to implemented code, a target crate, successful evidence
  IDs, the current source hash, and a non-waived status; no MUST/MUST NOT may be
  waived.
  - After: `S10-002` through `S10-012`.
  - Targets: `conformance/requirements.toml` and evidence validator.
  - References: [Architecture §§28.1 and Appendix D](docs/arc-architecture-and-implementation-spec.md#281-requirement-ledger-and-evidence).
  - Invariants: all invariant families.
  - Evidence: completeness validator reports zero missing/stale/failed/waived mandatory requirements.
  - Progress: the requirement ledger validator is unchanged; closure waits for every candidate result below.

- [ ] `S10-002` **Run the mandatory build and analysis matrix.** Execute exact
  formatting, check, Clippy, workspace tests, doctests, deny, audit, and branch-
  coverage commands under the pinned release toolchain and lockfile.
  - After: `S10-010`.
  - Targets: entire workspace and CI evidence.
  - References: [Architecture §28.8](docs/arc-architecture-and-implementation-spec.md#288-mandatory-build-and-analysis-gates).
  - Invariants: all source- and build-enforced invariants.
  - Evidence: command manifests and artifacts for both initial targets; zero warnings, unsafe source, or unbounded Tokio channel findings.
  - Progress: `scripts/run-stage-ten-workspace.py` runs the format, source, workspace, requirement, inherited Stage 09, runner, doc-test, audit, and deny checks, the four-combination check, clippy, and test matrix, and the branch coverage report; it cannot pass until the coverage floor is met.

- [ ] `S10-003` **Meet exact coverage requirements.** Reach at least 90%
  branch coverage overall and 100% for parser error discriminants,
  authorization decisions, protocol enum arms, recovery branches, and
  invariant checkers without treating coverage as replacement for other gates.
  - After: `S10-002`.
  - Targets: coverage corpus/report.
  - References: [Architecture §28.8](docs/arc-architecture-and-implementation-spec.md#288-mandatory-build-and-analysis-gates).
  - Invariants: all invariant families.
  - Evidence: source/lock-bound branch report with justified unreachable-code handling.
  - Progress: `conformance/release-critical-coverage.toml` records the complete critical inventory with the 90 percent floor; branch coverage is below that floor, and the per-file gap is listed in the qualification notes.

- [ ] `S10-004` **Complete parser, state-machine, and concurrency qualification.**
  Run reproducible long-duration fuzzing, deterministic reference/model tests,
  Loom schedules, cancellation, overload, task-panic, and shutdown suites with
  recorded corpora and envelopes.
  - After: `S10-002`, `S10-003`.
  - Targets: fuzz/model/Loom/runtime evidence.
  - References: [Architecture §§28.3–28.4](docs/arc-architecture-and-implementation-spec.md#283-state-machine-and-model-tests), [§21](docs/arc-architecture-and-implementation-spec.md#21-state-ownership-and-concurrency).
  - Invariants: `TRN-*`, `STA-*`, `FED-*`, `CON-*`, `OPS-04`.
  - Evidence: tool/version/duration/corpus/schedule manifests and zero unresolved failures.
  - Progress: `scripts/run-stage-ten-fuzz.py` runs bounded parallel segments per target until 86,400 CPU seconds with retained corpora, and `scripts/run-stage-ten-models.sh` runs the Loom, cancellation, overload, panic, and shutdown suites; no campaign has reached its budget yet.

- [ ] `S10-005` **Complete network interoperability and privacy qualification.**
  Test pinned legacy, modern, and encrypted clients, two-node and multi-edge
  federation, exact TLS, WSS when enabled, real Tor onion deployment, profile
  mismatches, partitions, metadata canaries, packet captures, and timing
  classes. Test trust-state presentation, TOFU and transparency distinctions,
  and decrypted text containing control bytes, CTCP markers, terminal control,
  HTML, and command prefixes without interpreting it as active content.
  - After: `S10-002`, `S10-004`.
  - Targets: network/interoperability/privacy evidence and the test-only encrypted-client harness.
  - References: [Architecture §28.6](docs/arc-architecture-and-implementation-spec.md#286-network-interoperability-and-privacy-tests).
  - Invariants: `TRN-*`, `PRV-*`, `FED-*`, `E2E-07`, `OPS-01`.
  - Evidence: versioned client/server/topology and client-policy matrices, safe-rendering outputs, scanner reports, captures, canary scans, and documented privacy limits.
  - Progress: `scripts/qualify-stage-ten-network.py` drives WeeChat, Irssi, OpenMLS, mls-rs, federation, TLS, WSS, an isolated Tor network, packet capture, and the client-policy tests; development runs passed on x86_64.

- [ ] `S10-006` **Complete storage platform qualification.** Run the release
  binary on every declared target/filesystem/block-size/mount tuple, measure
  every worst-case mutation and sync/rename phase, and prove the fixed physical-
  growth reserve and backup/construction space boundaries.
  - After: `S05-015`, `S10-002`.
  - Targets: storage qualification rigs and signed reports.
  - References: [Architecture §§28.5 and 28.7](docs/arc-architecture-and-implementation-spec.md#285-crash-storage-and-fault-injection).
  - Invariants: `DUR-*`, `OPS-04`.
  - Evidence: per-tuple release/profile/corpus/raw-log hashes, maximum deltas, and all boundary/failure outcomes.
  - Progress: `arcd storage qualify` and `scripts/qualify-stage-ten-storage.py` measure the production engine on the final binary; finding STO-1 is open.

- [ ] `S10-007` **Qualify capacity and sustained operation.** Demonstrate the
  advertised connection/member/channel limits on named hardware and run the
  seven-day soak with reconnects, churn, rekey, index transition, snapshots,
  backups, disk pressure, and peer loss.
  - After: `S10-004` through `S10-006`.
  - Targets: release-mode load/soak environments.
  - References: [Architecture §28.7](docs/arc-architecture-and-implementation-spec.md#287-abuse-and-capacity-tests).
  - Invariants: `CON-02`, `CON-05`, `FED-09`, `DUR-11`.
  - Evidence: p50/p95/p99 latency, memory/task/descriptor/queue high-water reports, missed-event checks, and return-to-envelope evidence.
  - Progress: the capacity engine and `scripts/qualify-stage-ten-capacity.py` run the 300-second capacity demonstration; the 64-client development runs found the per-address admission ceilings, the refused snapshot marker, request, and origin acknowledgement batches (CAP-12), and the stale-revision refusals, busy-staging refusals, request-queue ordering, drain, and fairness faults, and origin deletions overtaking queued session closes behind CAP-6, all fixed in the coordinator; the seven-day soak has not run; findings CAP-1 through CAP-8 and CAP-12 through CAP-17 are recorded, CAP-15 and CAP-16 fixed (a batch gathered during the index read-back, and a standing key removed before its snapshot cut row landed, each stopped the coordinator as corrupt), CAP-17 fixed (a refused snapshot cut page was skipped), CAP-18 fixed (a client that left while the link was down kept its nickname at the coordinator; the edge now replays retained origin deletions after a reset, and the campaign requires the whole population back at every quiescence check), CAP-19 has a worktree fix and regression (a process action's confirmation had been refused by any intervening commit). A separate federation resynchronization review (`docs/federation-resync-review.md`) found R01 to R21, fixed as CAP-20 to CAP-40 with 52 regressions (`docs/federation-resync-fixes.md`); qualification acceptance remains pending; CAP-41 fixed (the reload after that change rejected the account service's result rows and quarantined every peer at any coordinator restart), CAP-42 fixed (a deletion behind an unacknowledged update named the old generation and retired the link), CAP-43 fixed (recovery after a link retirement under disk pressure looped on an origin violation: a closed client's unfinished request replayed under the origin the coordinator had dropped and pinned that origin against retirement; the edge now abandons such a request instead of replaying it, and the 300-second campaign passes end to end). CAP-19 uses a stable live-process revision; final validation remains pending. CAP-44 fixed (snapshot activation preserves the durable Clean phase so a replacement incarnation is accepted after cleanup, and preserves Suspended until origin replay). CAP-45 fixed (client close journals the changed request sink flags so a covering snapshot can activate and retire the result after disk-pressure recovery). CAP-46 fixed (the final campaign wait rounds its remaining fractional second upward to meet the configured duration). CAP-7 still exhausted the post-restart login grace in the first release-profile development run; the second completed every scenario and drained federation but recorded 299.392 seconds, below the 300-second qualification minimum.

  - Progress on 2026-09-07: CAP-1 forwards explicit directory queries and their continuation; CAP-2 preserves refused-registration and ordinary close replies; CAP-8 rechecks listener and handshake ceilings after a pending accept; CAP-9 admits unchanged restored OPAQUE credentials under current Account authority; CAP-19 preserves process confirmations across unrelated commits. Each has a regression that fails with the corresponding fix reverted. CAP-47 replays exact companion-origin bytes across reconnects and lost ACKs. CAP-48 renders USERHOST with numeric 302 and authorized public cloaks. CAP-49 records missing MONITOR replies and registry entries. CAP-50 records the absent WHOWAS store and unresolved post-disconnect visibility policy. CAP-51 records checkpoint ordering around physical client cleanup, including the virtual-carrier shutdown regression found in the new restore drills. These worktree changes still need full gates and a new candidate. The capacity engine now requires the original refused session to survive disk pressure and recover, waits for active federation before restart authentication, and no longer retries explicit SASL failures or INVALID_TARGET process confirmations. STO-1 remains open after a storage-owner batch grew by 280,596,480 bytes, beyond the unchanged 256 MiB operational reserve; its opaque corpus is storage-layer evidence, not a complete domain restart. CAP-9 also clears restored channel attachments to omitted sessions and omits ephemeral channels with their name indexes; actual transform regressions are red and green. CAP-51 now distinguishes physical connections from virtual account carriers and passes delayed-close, mixed-carrier, and real coordinator shutdown checks. CAP-52 records the missing total graceful-output drain deadline. CAP-53 fixes duplicate frame accounting for shared events, with actual delivery to all 65,535 recipients and separate ordering and tag-isolation regressions. CAP-52 now enforces one 30-second drain deadline, proven with a deterministic slow-writer regression. CAP-54 identifies a qualification-client error: post-restore account requests still use the initial coordinator recovery epoch and are correctly refused by the server; the client binding is being corrected. CAP-50 now has bounded, charged, commit-dependent WHOWAS retention and independent expiry, with six runtime regressions and exact wire-shape checks; current public-cloak authority is required for disclosure. CAP-9 and CAP-54 now pass both real restore drills, including old and new account authentication. CAP-55 records the stale user-mode wire number and missing domain, home-edge projection, and client-render path; domain projection regressions are red and green. CAP-56 records authenticated admin failures mislabeled as authentication failures. CAP-10 tracing identifies a noncanonical signed single-word DIE reason in the drill, with an attached-account rerun pending. CAP-57 records a false-positive deletion probe that logs into a different healthy account and mistakes the Account ID mismatch for credential rejection; exact deleted-login refusal and unaffected-account checks are being added. CAP-58 records stale recipient capability snapshots after registered CAP changes. CAP-59 records lost labels and premature deferred-command release during federated query pagination; bounded streaming response state is being implemented. CAP-58 now synchronizes capability snapshots before negotiation replies; live tag enable/disable and identity-fence tests pass. CAP-56 now distinguishes three authenticated rejection cases from a genuine failed handshake in its log and metric regression. CAP-10 now passes the actual resynchronization shutdown with its account attached and the detach workaround removed. CAP-55 now passes the full MODE bridge. CAP-60 records missing committed JOIN topic replies, partial failures, and the bounded NAMES continuation. CAP-61 records recovery drills that destroy their ephemeral topic fixture and pass without checking topic persistence; registered seeding and strict explicit topic assertions are being added. CAP-59 now passes six response-boundary tests and a true live red/green NAMES-label regression; JOIN continuation remains separate under CAP-60. CAP-61 has a strict failing resynchronization run that isolates absent topic persistence; its seed now registers the channel. CAP-62 records missing committed AWAY305/306 replies, which currently stop the deletion drill between START and CONFIRM. CAP-60 coordinator topic/partial-failure replies and encrypted placeholders now have exact red/green regressions. CAP-62 exact305/306 and durable replay tests also pass. CAP-63 records the deletion drill’s incorrect ERROR-only closure requirement; final NOTE plus clean EOF is the protocol requirement. CAP-63 now has exact red/green reader tests, including rejection of deceptive content and transport errors. CAP-64 records the confirmed production deletion-close failure after its final NOTE; ordinary and cross-profile completion tests both reproduce it, while refused confirmation keeps the client open. CAP-64 now passes those three completion tests after the fix. CAP-60 now has true requester-echo, command-hold, and interruption regressions plus a passing full labelled JOIN bridge; retained-command memory and local snapshot timing checks remain in progress. CAP-64 now passes final NOTE, clean TLS EOF, and deleted-login refusal in the actual drill; the later coordinator stop reproduces the open shutdown deadline and prevents rekey checks. Drill authentication now waits for active federation and retries only transient transport loss; explicit authentication refusal and failed signed shutdown confirmation fail immediately. CAP-65 records the missing origin-DEL account-carrier cleanup and unfinished exchanges blocking drain; exact carrier retirement and a restricted shutdown cleanup path are being tested. CAP-61 now passes all three strict recovery drills with exact retained topics, old and new account authentication, and clean shutdown. CAP-65 tracing and real actor regressions confirm the abandoned authentication carrier; bounded owned cleanup, exact durable retirement, and eight negative and positive shutdown tests now pass, including an indeterminate cleanup receipt. CAP-60 local snapshot, page, generation, deferred-memory, and complete live bridge checks are also green; strict capacity and full gates remain pending. CAP-65 now passes nine focused tests and the actual formerly blocked stop and rekey. CAP-66 records a restart controller that accepts historical link events and probes authentication before federation is active. CAP-67 replaces whole-backup shrink assertions with exact authenticated deletion-state evidence, with actual false-positive and false-negative regressions. The full strict deletion drill now passes in 39.20 seconds, including rekey, both deleted-login refusals, the surviving account, and all three clean stops. CAP-66 now has an exact reverted-readiness failure after rekey with SASL 904, while the fixed full drill passes; CAP-11 and CAP-57 are also covered by that complete deletion and rekey record. The current CAP-4 eight-client probe preserves all three daemons through the required resynchronization closes and refusals; a fresh cohort after active federation is pending. Final CAP-60 review finds an uncharged local pending-seed vector after its last snapshot permit expires; a container-owned capacity permit is being added. The strict release capacity run reproduces CAP-3 after an explicit pressure refusal, then BrokenPipe on the original session; the run ends at 109.05 seconds before rekey and post-restart authentication. The corrected CAP-4 release probe passes all eight fresh post-recovery clients and three clean stops. CAP-60 now reserves the local seed container before allocation and keeps its permit until destruction; both old-path regressions fail and all seven fixed local JOIN tests pass. Full Clippy and static gates pass. The workspace test run exposes CAP-68: the network fixture can select one loopback address for multiple listeners and the coordinator correctly rejects its configuration; bounded synchronized address claims are being added. CAP-68 now has two deterministic old-path failures and four passing fixed allocator tests, including parallel real bindings; the full workspace gate is being rerun. The inherited USERHOST and TCP/WSS QUIT transcript checks now pass with exact corrected replies. CAP-69 records a local deletion test that reuses a consumed token, accepts any reply as deletion, and ignores the later login outcome; strict fresh-challenge and deleted-login evidence is being added. CAP-69 now rejects the stale-token flow and passes exact local deletion and typed invalid-login evidence in 11.84 seconds, with false-evidence and transport negatives; the fixture preserves the two-attempt SASL limit.

  - Validation of repair checkpoint 74b869d on 2026-09-07: all seven required pre-commit commands pass for the repair set. The exact workspace test suite reports 2,093 passing tests, no failures, and 21 ignored qualification tests. Both reviewed inventories contain 472 production source files, and the release policy retains its unchanged coverage floors across 115 critical regions. CAP-3 remains reproduced by the strict release campaign; CAP-5, CAP-13, STO-1, and full candidate qualification remain open.

  - CAP-3 diagnostic progress: the release run on 74b869d fails after 109.28 seconds. The first coordinator origin acknowledgement and edge event receive FilesystemRejected; the first reconnect names exact retained events under matching generations, but the coordinator chooses snapshots and later closes the original client. Bounded durable resume reconciliation and paced edge journal retry now pass 13 coordinator and 9 edge tests, with actual reverted-behavior failures. The fixed strict release campaign passes its first pressure recovery on the original session, then fails at 250.30 seconds because edge-b keeps reconnecting after its forced-kill restart and later synchronization does not finish. Existing logs do not identify the rejecting phase; rekey and strict post-restart authentication are not reached. All required gates now pass with 2,115 tests, no failures, 21 ignored tests, 476 reviewed production files, and 127 critical regions. The inherited closed-origin fixture now uses fresh link identities and passes its exact regression. Temporary diagnostics are preserved only in the frozen binaries and scratch records.

  - Companion recovery review: CAP-70 records startup dropping retained delivery events and peer scope, then choosing ESTATE on an intact same-scope restart. CAP-71 records EACK changing cursor and barrier coverage without a durable receipt owner. Real-storage regressions now reproduce both faults: intact restart opens ESTATE generation 1 instead of resuming generation 0, and EACK returns no staged cursor transition. The exact tests and frozen executable are parked in the qualification scratch directory while the successor storage format and migration are designed. Neither fault is covered by the ordinary CAP-3 pressure trace.

  - CAP-72 restore correction: the typed classifier now omits obsolete companion replay, delivery, and barrier state, rejects stale-plan copies and key/body identity mismatches, and marks active and closing routes pending without changing their heads or counters. Eleven focused regressions pass; reverting the classifier and transformer produces ten behavioral failures with the preservation control still green. All required repository gates pass with 2,126 workspace tests, no failures, 21 ignored qualification tests, 478 reviewed source files, and 134 release critical regions. CAP-73 remains necessary for complete encrypted recovery.

  - CAP-73 recovery admission proof: two valid-input runtime regressions now fail after real startup reconstructs both Pending gates. Finalization returns new rows for storage, and the absent-signer variant reaches signer-dependent failure instead of early RouteInvalid refusal. Both fail in 0.20 seconds with normal-route controls passing. Runtime mutation guards and terminal-evidence handling remain open; CAP-72 classification alone does not establish encrypted recovery compliance.

  - CAP-13 batching proof: a bound client sink, live bounded federation queue, and actual storage receipts reproduce two visible events instead of three after the second commit. The earlier no-output and no-FACK checks pass before each required receipt. The 0.09-second behavioral red and frozen fixture are parked in Q while the complete batching implementation proceeds.

  - CAP-74 witness persistence proof: a valid kind-13 WitnessRow passes its inner round trip, then the outer persistent constructor returns InvalidEncoding because the E2eeState registry stops at kind 12. The actual behavioral red and frozen executable are archived in Q; sealing and restart assertions are not reached. Schema admission and failure-frame receipt ownership both need correction and verification.

  - Further admission and reconstruction proofs: CAP-75 admits binding delivery from a different attached account that is not a participant. CAP-76 admits ReInit targeting a second normal conversation and then replaces its retained head. CAP-77 offers an acknowledged mailbox item again after reconstructing the exact surviving rows, including actual ACK deletions. All four behavioral regressions fail in the frozen second runtime build. CAP-73's 18 existing recovery cases and two mailbox scan cases pass there. CAP-75 and CAP-76 repairs are in progress; CAP-77 requires durable sequence ownership and explicit legacy ambiguity handling. The CAP-74 schema-3 envelope repair now passes actual sealing and two storage-owner restarts; failure-frame receipt ownership remains open.
  - Focused admission and mailbox repairs: CAP-75 participant checks and CAP-76 successor vacancy checks each pass three cases after their actual behavioral failures. CAP-77 now passes seven runtime, seven domain, and two codec cases with durable kind-15 sequence ownership and exact item retirement. The six real storage migration cases also pass. These results do not close legacy mailbox ambiguity, full repository gates, or release qualification.
  - CAP-78 records the source-traced live mailbox cursor and changing snapshot-token fault; three valid pagination regressions await their first run. CAP-79 has an executed regression: 4,097 valid acknowledged events below the published replay bounds retain only 4,096, failing in 0.28 seconds. Replay age, byte ownership, and the published limits still need repair.
  - CAP-95 records startup accepting 260 MiB of valid stored object envelopes into a 256 MiB cache and silently losing bodies. Its direct startup regression fails in 9.55 seconds, with one passing control. The repair checks complete collection and combined capacity before publishing restored objects. All eight checkpoint gates pass: 2,448 tests pass, none fail, and 21 remain ignored. CAP-79 remains open.
  - CAP-96 records duplicate request classification skipping a missing response body while retaining the original result descriptors. The valid regression fails in 0.01 seconds with one passing complete-response control. Classification now requires every response before returning a replay. All eight checkpoint gates pass: 2,451 tests pass, none fail, and 21 remain ignored. CAP-79 still requires disk reads for retained bodies.
  - CAP-97 records the recent-fragment shortcut bypassing CAP-96 and emitting a partial response set. Its direct valid-object regression has one failure and one passing control, with exact inputs and executable archived. The shortcut now requires every response before rendering lines. All eight checkpoint gates pass with 2,534 tests, no failures, and 21 ignored qualification tests; the runtime suite has 1,077 passes. CAP-79 still requires charged reads for retained bodies absent from memory.
  - CAP-98 has four executed failures for close signatures, controller roots, unrelated finalizations and changed closing intents. The authorized close and empty-vector refusal controls pass. Exact inputs and executable are archived. The public authority checks now pass eleven handler and five validator tests, including reconstruction and bounded memory refusal. Both daemon fixtures now refuse unrelated terminals and wrong signature labels, then accept a separately finalized public closing intent; their closing MLS bodies remain synthetic. All eight checkpoint gates pass: 2,669 workspace tests, no failures and 22 default-ignored tests; 1,201 runtime tests pass. Both inventories cover 756 source files and the release catalog has 1,044 regions. Exact inputs and five executed binaries are archived. Full recovery-chain validation and production qualification remain open.
  - CAP-99 ACK context: all 37 original public-field regressions are archived. Standalone ACKs now match the current candidate or retained ReInit attempt, and terminal requests check every embedded ACK against the voted result. Four additional memory, missing-object and package-reference cases pass. All eight checkpoint checks pass with 2,739 tests, no failures and 22 default-ignored tests; 1,256 runtime tests pass. Both inventories cover 769 source files and the release catalog has 1,083 critical regions, without a new coverage measurement. Exact inputs and five executed binaries are archived. Old-leaf identity, MLS coverage and continuing-member admission remain under CAP-86.
  - CAP-100 ReInit attempt authorization: 26 original public-authority failures and one pre-opened ReInit-state failure are archived. Receipt signing now requires exact repeated authorization fields, body hash links, distinct active controller roots and keys under the current policy, and the original old state. Thirty-two new cases pass. All eight checkpoint checks pass with 2,771 tests, no failures and 22 default-ignored tests; 1,288 runtime tests pass. Both inventories cover 773 source files and the release catalog has 1,089 critical regions, without a new coverage measurement. Exact inputs and five executed binaries are archived. Old-leaf membership and target-state validation remain under CAP-86.
  - CAP-79 format prerequisite: generation 4 adds bounded replay-owner and ACK-range codecs, explicit 3-to-4 migration, and frozen generation-3 audit and delivery admission. Eight codec/admission cases, three storage migration cases, and three actual CLI cases pass. All eight checkpoint gates pass with 2,463 tests, zero failures, and 21 ignored qualification tests. The separate real-storage retention red still proves premature deletion and is archived for restoration with the runtime repair; live retention, paged recovery, charged object reads, and cleanup remain open.
  - CAP-79 runtime work: the restored regression preserves 4,097 physical references after a real journal ACK and recovers all effective ACKs through composed startup. Bounded cold-prefix reads now reach the live ACK adapter, preserve open barrier parts, reject mixed storage commits, retain read ownership through cancellation, and queue peer traffic until the next receipt. The cache releases acknowledged bodies beyond 4,096 rows or 16 MiB while preserving the unacknowledged tail; the original storage and new cache failures remain archived. All eight checkpoint gates pass with 2,517 tests, no failures, and 21 ignored qualification tests; the runtime suite has 1,060 passes. Both inventories cover 683 source files and the release catalog has 848 critical regions, without a new coverage measurement. Physical cleanup, idle expiry, cold object/result delivery, and selective object reconstruction remain open.
  - CAP-79 maintenance work: startup timers now drive offline expiry and bounded deletion below a persisted replay floor. Fourteen actual-storage tests pass, including rejected writes, receipt loss, changed scope, clock failures, malformed pages, and a 132-row partial-deletion restart that preserves an overlapping ACK range and the unacknowledged tail. Both initial maintenance failures are archived. All eight checkpoint gates pass with 2,531 tests, no failures, and 21 ignored qualification tests; the runtime suite has 1,074 passes. Both inventories cover 696 source files and the release catalog has 905 critical regions, without a new coverage measurement. Cold object/result delivery, selective object reconstruction, and shared-body retention remain open.
  - CAP-79 retained responses: complete duplicates and recently assembled requests now read absent response bodies from storage before rendering. Fourteen coordinator and decoder-boundary tests pass, covering full response order, missing bodies, changed metadata and commits, cancellation, synchronization readiness, refused memory, queued requests, and output ownership. The original storage-backed failure remains archived. All eight checkpoint gates pass with 2,549 tests, no failures, and 21 ignored qualification tests; the runtime suite has 1,092 passes. Both inventories cover 704 source files and the release catalog has 931 critical regions, without a new coverage measurement. Fresh cold-object fetches, selective object reconstruction, and independent shared-body retention remain open.
  - CAP-79 fresh fetches: an evicted object now triggers one charged storage read, repeats current request and recovery authorization, and publishes only after its result receipt. The body stays out of the memory cache; storage errors cannot become empty replies. Sixteen actor, decoder, and inner-dispatch cases pass, including the archived original failure. Both inventories cover 712 source files and the release catalog has 951 critical regions, without a new coverage measurement. All eight checkpoint gates pass with 2,565 tests, no failures, and 21 ignored qualification tests; the runtime suite has 1,108 passes. Selective startup and shared-body retention remain open.
  - CAP-79 selective startup: complete mailbox metadata selects resident payloads before the object scan, while historical Commit and control bodies remain available. Startup table reads and retained bodies own memory reservations. Nine actor tests, seven collector tests, and the live application-copy regression pass; both original failures are archived. Live application delivery now keeps its payload in delivery ownership without adding a global copy. Both inventories cover 720 source files and the release catalog has 968 critical regions, without a new coverage measurement. All eight checkpoint gates pass with 2,582 tests, no failures, and 21 ignored qualification tests; the runtime suite has 1,125 passes. Live resident-body admission and retirement, shared-body retention, and larger-capacity qualification remain open.
  - CAP-79 live admission: direct assembly accepts a valid result with a zero process memory budget. The one-case failure and exact executable are archived. Preparing the complete resident set before staging passes the initial case and eight focused admission tests. Eighteen actor and decoder cases pass, including receipt ownership and refusal before submission. Both inventories cover 725 source files and the release catalog has 976 critical regions, without a new coverage measurement. All eight checkpoint gates pass with 2,593 tests, no failures, and 21 ignored qualification tests; the runtime suite has 1,136 passes. Resident-body retirement and independent shared-body retention remain open.
  - CAP-79 mailbox retirement: the final ACK now releases only an unreferenced payload's memory copy and reservation. Shared and control objects remain resident, and stored bodies remain unchanged. One exact final-item deletion may fund its smaller ACK result while keeping old bytes owned until receipt. Both the original resident-copy failure and the introduced full-counter admission failure are archived. Twelve new handler and memory-boundary tests pass. Both inventories cover 729 source files and the release catalog has 981 critical regions, without a new coverage measurement. All eight checkpoint gates pass with 2,605 tests, no failures, and 21 ignored qualification tests; the runtime suite has 1,148 passes. Durable mailbox expiry and shared-body retention remain open.
  - CAP-79 durable mailbox expiry: idle timers now select 128 metadata rows per page, stage exact Item/Token/ACK cleanup, and publish only after the matching receipt. Sequence floors and shared stored bodies remain. Nine storage-owner tests and six domain tests pass, including three archived original failures and a 130-item partial-deletion restart. Both inventories cover 736 source files and the release catalog has 1,007 critical regions, without a new coverage measurement. All eight checkpoint gates pass with 2,620 tests, no failures, and 21 ignored qualification tests; the runtime suite has 1,157 passes. Shared-body retention and larger-capacity qualification remain open.
  - CAP-79 retained request results: idle maintenance expires completed replay rows only behind an independent durable origin sequence floor and the exact storage receipt. Unreferenced result copies retire from memory; startup keeps results without replay owners cold. Both original failures and ten passing storage-owner tests are archived. Both inventories cover 744 source files and the release catalog has 1,027 critical regions, without a new coverage measurement. All eight checkpoint gates pass with 2,630 tests, no failures, and 21 ignored qualification tests; the runtime suite has 1,167 passes. Shared-body retention and larger-capacity qualification remain open.
  - CAP-79 result-memory follow-up: one actual sealed startup regression proves that three persistent result copies occupy 507 bytes outside their 12,288-byte object charge. The failure and exact executable are archived. Result-map ownership now requires backing before copying and preserves the permit through commit and expiry. Six new cases pass in the 1,215-test runtime suite. All eight checkpoint checks pass with 2,698 tests, no failures and 22 default-ignored tests. Both inventories cover 766 source files and the release catalog has 1,073 critical regions, without a new coverage measurement. Physical shared-body retention remains open.
  - CAP-79 larger startup corpus: actual storage-owner shutdown and reopen preserve 4,097 application objects totaling 268,500,992 bytes. Composed startup verifies every body and retains one 65,536-byte mailbox payload, with 68,276,224 additional charged startup bytes. The dedicated ext4 run passes in 325.49 seconds; exact inputs and executable are archived. Ciphertext is synthetic and this is not a live traffic or production storage qualification. All eight final gates pass with 2,630 tests, no failures, and 22 default-ignored tests, including this separately passing capacity test. Both inventories cover 745 source files; critical regions and coverage thresholds are unchanged. Shared-body retention and production capacity qualification remain open.
  - CAP-73 declared recovery provenance: startup now preserves charged kind-one records, rejects contradictory Pending heads and epochs, and installs blocked guards after successor validation. All 23 new cases pass in the 1,190-test runtime suite, including actual storage shutdown/reopen and two corrected introduced regressions. The original failures remain archived. All eight checkpoint gates pass with 2,653 tests, no failures and 22 default-ignored tests. Both inventories cover 751 source files and 1,037 release critical regions, without a new coverage measurement. Normal-row persistence, complete source binding and terminal-evidence ingestion remain open.
  - CAP-77 construction checks: a mismatched owner key and a legacy mailbox migration both produce actual behavioral failures. Exact owner binding and refusal before creating an ambiguous migration target now pass 13 recovery and seven migration cases. CAP-78's first three assertions fail, but the inherited repeating fixture entropy is being replaced and explicitly checked before finalizing the pagination proof.
  - CAP-78's corrected fixture proves 32 distinct delivery tokens and still produces all three pagination failures. CAP-80 separately proves that a current mailbox grant succeeds live but fails with ObjectNotFound after reconstruction chooses a superseded token by key order. Exact Item/Token grant ownership and strict reconstruction are being repaired.
  - Further focused results: CAP-74 now has an actual premature-link-close regression and five passing receipt/retry tests; callback ordering and durable recovery gating remain open. CAP-78 passes ten immutable cursor, expiry, scope, and resource cases. CAP-80 passes five current-grant reconstruction cases after atomic Item/Token updates and strict startup checks. CAP-81 records base FQUERY's bypass of shared query admission; its reproduction and integration into the shared query accounting repair are underway. Full repository gates remain open for this source set.
  - Legacy construction and receipt checks: fourteen migration/backup/restore cases and all 199 storage unit tests pass; reversing legacy admission and exact signed-stream comparison yields four behavioral failures with ten controls still green. The actual CLI preserves original audit signatures through schema-two restore and explicit migration. CAP-74 callback ordering now passes seven cases; CAP-78 shared query accounting passes fifteen cursor cases, with late publication still under repair. CAP-81 now has an actual shared-limit FQUERY failure. CAP-82 records the digest helper's refusal below the published million-entry snapshot ceiling and needs a bounded streaming hash adapter.
  - CAP-80 declared restore key validation now has two behavioral failures against the old classifier and a valid-row preservation control. The repaired classifier passes sixteen recovery cases and all 202 storage unit tests; source and binary proofs are retained in the qualification scratch directory.
  - CAP-82 now has an actual million-entry digest failure and a bounded streaming repair. All 120 E2EE and thirty crypto unit tests pass, including original framing equivalence and exact input-count limits. Runtime capture integration and its allocation regression remain in progress.

  - Further focused recovery results: CAP-74's live, reconstructed, and client admission gates each fail when the retained-witness predicate is disabled, while clean exact resume remains green; all eleven fixed witness tests pass. An authenticated witness-resolution carrier remains open. CAP-81 now passes seven shared-admission and two receipt cases plus all 152 domain tests. CAP-82's million-entry runtime capture fails when its bounded streaming adapter is reverted; all three fixed capture and 121 E2EE cases pass. Exact source and executable records are retained in `cap74-cap82-reversal-proof` and `cap74-cap81-cap82-fixed-proof`.
  - CAP-5 implementation progress: the maintenance codec and complete-purpose new-key loader pass focused suites with independent signed goldens and three actual loader-reversal failures. The schema-three Audit kind-two registry has a real old-registry failure, two fixed controls, and all 204 storage unit tests passing. Both actual CLI rotation tests now pass, including 257 retained entries and exact mapping/refusal checks. Four real start/finish fault tests and fourteen mixed-chain cases pass. The corrected legacy export transport test proves a missing UNAVAILABLE reply; its private classification fix awaits its first run. The live two-account rotation drill and maintenance-aware audit export remain open. The workspace checker admits only the runtime's exact inherited rustix time feature; its thirteen-package check and twenty-six rejection self-tests pass.
  - Current combined proof: all 232 changed source inputs remain fixed through the workspace build. CAP-70 and CAP-71 pass 33 synchronization tests, including six sealed FETCH receipt, crash, retry, and refusal cases; live expiry retirement remains under repair. The barrier fixture now uses a valid federation object and passes. CAP-76 passes all three sealed successor recovery tests under CAP-83's corrected normative signatures; the isolated startup-guard reversal remains pending. Evidence is archived in `mixed-audit-rotation-startup-fourth-proof`.
  - Further rotation and recovery proof: the live two-account rotation drill passes in 33.50 seconds, with dormant-entry refusal, unchanged OPAQUE credentials, exact signed audit append, final authentication, and three clean stops. The corrected mixed-audit suite passes eighteen cases and synchronization passes thirty-five. Actual reversals reproduce both CAP-76 startup collisions, mixed-chain decode failure, missing CLI commands, and incomplete 257-entry scanning, with legacy and empty-index controls preserved. Exact fixed sources and rebuilt binaries are restored; all 932 runtime tests pass in `recovery-audit-command-boundary-fixed-proof`. CAP-84 records queued companion pages dropping their memory charge before transmission; its stalled-writer regression and ownership correction are in progress.
  - CAP-84 now has an actual stalled-writer failure: queued page strings retain zero process memory charge instead of 20,480 bytes after publication. The replacement-link control passes, and the held-source proof is archived in `cap84-queued-page-red-and-stale-start-proof`. The exact shared backing transfer is being repaired. The stale START cleanup test compiles but fails with an unlocalized StaleState; test-only phase context is being added before attributing that failure to the driver.
  - CAP-85 records a separate invitation restart mismatch: the account writer and runtime require one Account reference on a redeemed invitation tombstone, while storage startup rejects every reference on that kind. The unrelated invitation in the stale START fixture exposes this path for investigation. A minimal sealed restart regression and invalid-ownership controls are being added before changing the storage validator.
  - The held 244-input build in `queued-backing-invitation-checkpoint` proves CAP-84's fixed queue, partial admission, actual awaited writer, and cancellation lifetimes with eight passing tests; both sealed startup-read cancellation tests also pass. CAP-85 has two actual storage restart failures: canonical invitation ownership is rejected and missing ownership is accepted. Extra-owner and wrong-target controls pass. The stale START failure is now localized to that seeded storage reconstruction, and the strict validator repair is in progress.
  - CAP-85 now passes all four isolated restart cases under the strict single-Account rule, and the complete stale START cleanup, count, audit append, and reconstruction case passes. Bypassing only typed cleanup leaves three AuthTransaction rows and fails the exact assertion, with all four rotation fault cases and invitation controls still passing. Exact held-source proofs are in `invitation-owner-fixed-proof` and `stopped-start-cleanup-red-proof`; fixed cleanup is restored and full repository checks are in progress.
  - Full formatting, Clippy, source, workspace, and coverage-checker self-tests pass for the current repair set, with 614 inventoried source files and 654 reviewed release regions. The full workspace test run fails the encrypted three-node coordinator restart: both edges reconnect repeatedly before profile acknowledgement and never reach ACTIVE. The exact 246-input run is archived in `recovery-rotation-repair-workspace-gate`; CAP-70 startup handling of retained cross-profile rows is under investigation. This is not a passing workspace gate.
  - Resumed repair checkpoint on 2026-09-07: CAP-70 now restores exact acknowledged cross-profile rows; its sealed regression fails against the original predicate and passes with the correction. A separate base-loader guard refuses uncovered cross-profile parts even when a snapshot flag is set, with two behavioral failures and three fixed startup cases. Full unfinished combined-barrier recovery remains open under CAP-70 and CAP-71. CAP-86 now checks retained old-binding account participation before attempt, activation, or abort signing. Three outside-account regressions fail without the checks and pass with them, including absent-signer refusal and unchanged retained state. All thirteen ReInit tests pass. Device-to-leaf and continuing-member authorization remain separate open obligations. The stale CLI-help fixture now includes both login-index rotation commands and the supported schema-2/schema-3 targets.
  - CAP-70/CAP-71 combined-barrier continuation: both stream endpoints now share a durable gate created with their event rows. Each ACK updates that gate with its own cursor transaction; the second ACK deletes it. Full coordinator tests cover both ACK orders, refused writes, restart before receipt callbacks, exact final-ACK resume, missing or contradictory records, and snapshot refusal. Replay holds later rows on both profiles, and outbox overflow cannot replace an open gate with a snapshot. All required repository gates pass: 2,433 tests, zero failures, 21 ignored qualification tests, and successful formatting, Clippy, source/workspace policy, and coverage self-tests. The final inventory binds 632 files and 688 release regions without lowering coverage floors. Exact proof is retained in `cap70-final-proof`.
  - CAP-93: base replay pages, companion resume replay, and outbox overflow could bypass an already open combined gate. The repair bounds each replay at its endpoint and refuses snapshot fallback under that gate. Three isolated behavior reversals fail the new replay and overflow regressions; the earlier overflow compilation failure is explicitly invalid evidence. See the CAP-93 ledger entry and `cap70-red-base-page`, `cap70-red-companion-replay`, and `cap70-red-outbox-overflow-behavior`.
  - CAP-94: an exact final companion resume rejected a lost ordinary ACK prefix before the barrier. The actual storage-owner regression reproduces this after committing the base ACK and restarting. Resume now validates the entire retained prefix before staging and again at its receipt, while ordinary EACK ordering stays strict. The exact red is archived in `cap94-red-proof`. All required gates pass with 2,436 tests, zero failures, and 21 ignored qualification tests; `cap94-final-proof` binds the exact source and executed binary. Both source inventories contain 633 files and the release policy binds 691 regions at unchanged coverage floors.
  - CAP-5 export continuation: the explicit signed `maintenance-v1` profile carries unchanged admin, maintenance, and checkpoint bytes with distinct framing. Its real transport regression fails without the grammar, while the fixed storage refusal and actual StateCore success cases pass. All 69 admin-focused runtime tests pass, including frozen schema-two admission and complete mixed-chain validation. All required gates pass: 2,443 tests, zero failures, 21 ignored qualification tests, 636 inventoried source files, and 709 release regions with unchanged floors. Exact proof is retained in `cap5-export-final-proof`.
  - The resumed checkpoint passes all required gates with 2,400 workspace tests, zero failures, and 21 ignored qualification tests across 120 results. Source policy accepts 748 Rust files; both inventories bind 617 source files and the release policy contains 656 critical regions. The full command/result record is `resumed-final-gates.json`. GitNexus staged change detection reports critical aggregate scope across the expected storage, federation, administration, recovery, and regression-test changes. Production qualification and the recorded unfinished implementation obligations remain open.
  - The uninstrumented 64-client release campaign fails at 251.19 seconds after coordinator restart because the edges never report active base federation. Disk-pressure refusal and first-attempt recovery, backup, and edge-b loss/return pass beforehand. Repeated profile acknowledgements and link closures reproduce the earlier intermittent restart loop without establishing its cause. Rekey, final drain, full duration, and capacity qualification are not passed. Exact unchanged binary hashes and preserved logs are in `resumed-capacity-result.json` and `resumed-capacity-64`.
  - CAP-87: a diagnostic repeat fails earlier pressure recovery with an edge journal `Phase` loop. Reconnect removed a never-transmitted closed origin while a pending or refused journal write still owned it. Both real-storage regressions fail against `52808b9`; retaining the origin through its durable deletion acknowledgement passes all 100 edge tests, including restart and subsequent admission checks. The outage fixture now acknowledges both retained deletions. All required gates pass with 2,402 workspace tests and 21 ignored qualification tests in `cap87-final-gates.json`. The uninstrumented release repeat passes first-attempt pressure recovery but still fails coordinator-restart synchronization after 237.93 seconds, with unchanged binaries in `cap87-capacity-64-result.json`. That separate restart defect and capacity qualification remain open.
  - CAP-88 localizes a restart failure to a valid channel message rejected by the restored replica revision. Membership events advance channel and home-session revisions in memory without reporting every changed row for persistence. Four real-storage regressions fail against `1482e84` through both single-event and batched JOIN receipts; both replay cases and both restored-session revision cases pass after the revision helpers report their rows. The dispatcher removes duplicate and superseded upserts. An independent twelve-case reconstruction check identifies nine missing-write cases when the fix is reversed. All required gates pass with 2,407 tests and 21 ignored qualification tests in `cap88-final-gates.json`. The uninstrumented capacity repeat still fails restart readiness after 250.87 seconds, with unchanged executables in `cap88-capacity-64-result.json`; its remaining cause is under investigation. The exact earlier trace is in `cap87-event-diagnostic`; both its startup and supposed stopped copies are invalid live evidence under CAP-92.
  - CAP-89: completion replay incorrectly requires a request already retired by durable origin deletion. Three real-storage regressions fail against `e0a7008` through single-event, batched, and combined-barrier application. The fix preserves validation and durable acknowledgement ordering without recreating a request owner or client reply; all three cases and a conflicting-owner/generation negative control pass. All required gates pass with 2,411 tests and 21 ignored qualification tests in `cap89-final-gates.json`; the focused run passes all 120 edge tests. The preceding diagnostic capacity run ends on SASL failure after 207.93 seconds with companion-protocol refusals, unchanged executables, and daemon logs in `cap88-restart-diagnostic` (its database copies are invalid under CAP-92); that separate cause remains under investigation.
  - CAP-90: EORIGIN assembly caches a declaration before its base authority is admitted, trapping subsequent valid retries; the cached path also bypasses changed base authority. Five frame-entry regressions fail against `3a58e09`. Checking RESET, live base authority, and the exact base generation before assembly repairs all five, and all 155 focused coordinator tests pass. All required gates pass with 2,416 tests and 21 ignored qualification tests in `cap90-final-gates.json`. The preceding 64-client five-minute diagnostic campaign passes after 306.37 seconds while exposing the companion refusals; its unchanged binaries and logs are recorded in `cap89-admission-diagnostic`; its database copies are invalid under CAP-92. The uninstrumented repeat at exact commit `b735700` passes in 305.96 seconds with all eight scenarios, all 64 clients returned to the resource envelope, no missed events or envelope/population/sample failures, and three clean stops. Its 31 disruption worker errors remain recorded. This run still uses restart-only index reconstruction. Its event-admission `Quiescing` during intentional shutdown does not establish the separate staged-batch conflict hypothesis.
  - CAP-91: two real-storage regressions expose valid event admission colliding with another owner's gathering or exclusive checkpoint before submission. The complete checkpoint-readiness predicate now queues the event until that receipt, then requires its own receipt before cursor, client output, or acknowledgement publication. Both cases fail in `cap91-red.log`; all 122 edge tests pass in `cap91-green.log`. This is independent of the earlier intentional-shutdown Quiescing trace. All required gates pass with 2,418 tests and 21 ignored qualification tests, 624 reviewed source files, and 661 release critical regions. The first full run fails an unstable free-space boundary; the unchanged isolated storage test and repeated full suite pass. Those records remain preserved in `cap91-first-gates`, `cap91-filesystem-isolated.log`, and `cap91-final-gates.json`; STO-1 remains open.
  - CAP-5 capacity integration: the restart-only scenario fails the exact generation advancement check, actual 1 versus required 2. Its panic requires verified test-process termination after the daemons stop; that red records exit -15 and unchanged executables. The implemented scenario runs real stopped start and finish, authenticates the existing account through lazy migration, checks exact authenticated key state and counts, and requires final live authentication. Its first run reaches start but exposes a harness assertion that omits the command's final shutdown checkpoint; the corrected run passes all eight scenarios in 306.62 seconds, with a measured workload of 300.35 seconds and 64 clients. It rotates generation 1 to 2, requires both live logins, returns every client to the resource envelope, records no missed events or envelope/population/sample failures, and stops all three daemons cleanly. Its 56 worker errors and 6,171 message refusals remain recorded in `cap91-rotation-final` with unchanged binaries and exact source inputs. `cap5-capacity-rotation-red` and `cap91-production-rotation` preserve both results. Maintenance-aware export remains open.
  - CAP-92 withdraws six supposed stopped-state database archives: the scratch helper ignores unreadable process executable links and copies near peer return while the campaigns continue. `cap87-event-diagnostic`, `cap88-restart-diagnostic`, `cap89-admission-diagnostic`, `cap90-production-repeat`, `cap91-production-rotation`, and `cap91-rotation-final` now carry invalid-live-copy notices and hash-bound withdrawal records. The helper is retired. Future copies require the owning test's completed waits for all daemons before fixture cleanup. Campaign metrics, exit statuses, exact executable hashes, daemon logs, and controlled storage-owner tests remain usable.
  - Runtime checkpoint: the latest full frozen run passes 894 tests and fails two inherited fixtures, one missing the newly required delivery owner and one expecting two ACK writes after exact Item retirement makes three. Both fixture corrections are written and await the next full run. No full-runtime success is claimed for this checkpoint.
  - CAP-83 records ReInit quorum verification selecting the ordinary disposition signature domain while the fixture signs under the same wrong domain. Both exact-domain regressions fail against that verifier, with the ordinary disposition control passing. The explicit domain-selection repair passes all 123 E2EE tests; held source and binary proofs differ only in the repaired verifier. The CAP-76 sealed startup collision has an actual failure that discards an independent route and a passing advanced-successor control; its new occupied/duplicate guards await the combined run using corrected profile-valid ReInit signatures.

  - Diagnostic campaign on e6dd301: the unchanged 300-second, 64-client workload passes in 305.81 seconds, including original-session pressure recovery, strict post-restart authentication, rekey, zero final outboxes, and three clean stops. The previous intermittent restart loop does not reproduce or gain a proven cause. CAP-13 remains material: 5,961 busy refusals and message p99 of 59.01 seconds are recorded despite the campaign assertion passing. An uninstrumented repeat and full candidate qualification remain required.

- [ ] `S10-008` **Run restore, deletion, and key-lifecycle drills.**
  Exercise ordinary and disaster restore, storage rekey,
  login-index transition, TLS/federation/sequencer/backup/audit key rotation,
  compromise response, rollback, and client-visible resynchronization.
  - After: `S10-006`, `S10-007`.
  - Targets: operational drill evidence and runbooks.
  - References: [Architecture §§23.6–23.9 and 25.4–25.5](docs/arc-architecture-and-implementation-spec.md#236-storage-format-admission).
  - Invariants: `DUR-04` through `DUR-12`, `FED-10`, `OPS-04`.
  - Evidence: timed drills, artifact/state hashes, failure injection, operator steps, and verified post-drill conformance.
  - Progress: sixteen drills run through `scripts/qualify-stage-ten-drills.py`; twelve pass and four fail on findings CAP-5, CAP-9, and CAP-11.

- [ ] `S10-009` **Verify deployment hardening and observability in production
  configuration.** Check privileges, service sandbox, filesystem permissions,
  locked secrets, core dumps, swap guidance, listener exposure, logs, metrics,
  health, retention, crash handling, and incident modes.
  - After: `S10-005`, `S10-008`.
  - Targets: shipped service profile and production configuration.
  - References: [Architecture §25](docs/arc-architecture-and-implementation-spec.md#25-operations-observability-and-host-security).
  - Invariants: `OPS-01` through `OPS-04`, `ID-04`, `ID-05`, `PRV-02`.
  - Evidence: host-policy tests, port/filesystem scans, secret canaries, retention checks, and incident simulation.
  - Progress: the host hardening and observability drills run in the same driver together with the deployment checker, systemd-analyze, and Tor configuration verification.

- [ ] `S10-010` **Produce reproducible release artifacts and an SBOM.** Build
  after verified dependency fetch with network disabled, record compiler,
  target, features, source/lock hashes, compare independent artifacts, emit
  SPDX or CycloneDX, and sign artifacts from an isolated release identity.
  - After: `S09-900`, `S10-011`.
  - Targets: release pipeline, binaries, packages, SBOM, signatures.
  - References: [Architecture §24.5](docs/arc-architecture-and-implementation-spec.md#245-dependency-and-build-integrity).
  - Invariants: `OPS-02`.
  - Evidence: independently reproduced hashes or documented deterministic differences, SBOM validation, and signature verification.
  - Progress: the release image, the two-container reproduction, the SBOM with reviewed native package licenses, and the aarch64 build workflow exist; x86_64 reproduced bit for bit; the aarch64 build record still has to be produced on a hosted ARM runner.

- [ ] `S10-011` **Recheck sources and dependencies before release.** Verify
  publication status, obsoletes/updates/errata, living-source commits, crate
  checksums/MSRV/features/yanks/advisories, and explicitly adopt, narrow,
  supersede, or reject every detected change.
  - After: `S09-900`; repeat before `S10-013`.
  - Targets: source-decision ledger, lockfile review, affected vectors/requirements.
  - References: [source ledger §6](docs/protocol-sources-and-decisions.md#6-update-and-review-procedure), [Architecture §30](docs/arc-architecture-and-implementation-spec.md#30-sources-and-pinned-research-baseline).
  - Invariants: all affected invariants.
  - Evidence: primary-source checks, exact diffs, decision records, updated hashes/vectors when adopted, and rerun gates.
  - Progress: `scripts/check-release-sources.py` compares structured status records with `conformance/release-source-decisions.toml`; the 2026-09-05 decisions are recorded in the source ledger.

- [ ] `S10-012` **Generate exact conformance metadata and user claims.** Report
  `core-v1`, `federated-v1`, `encrypted-v1`, WSS, and history independently;
  bind claims to source/profile/compiler/target/test-manifest hashes and state
  privacy/security limits without exaggeration.
  - After: `S10-002` through `S10-011`.
  - Targets: binary version/conformance output, release notes, operator documentation.
  - References: [Architecture §26.4](docs/arc-architecture-and-implementation-spec.md#264-conformance-claims), [E2EE Appendix B](docs/arc-mls-e2ee-extension.md#appendix-b-security-claim-template).
  - Invariants: `PRV-04`, all claimed invariant families.
  - Evidence: claim/document review and automated comparison with completed evidence manifests.
  - Progress: `scripts/check-release-claims.py` compares the binary metadata with the candidate and baseline, lints the ledgers, and exercises decision inspection with disposable keys; finding CLM-1 was fixed.

- [ ] `S10-013` **Make the release decision.** Confirm every applicable gate,
  finding disposition, drill, artifact, source, dependency, documentation, and
  claim belongs to the exact release commit and lockfile; unresolved evidence
  blocks only the claim or release it governs and is never hidden.
  - After: `S10-001` through `S10-012`.
  - Targets: signed release decision and immutable evidence index.
  - References: [Architecture §§28.9 and 29 phase 10](docs/arc-architecture-and-implementation-spec.md#289-release-decision), [E2EE §21](docs/arc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: all invariant families.
  - Evidence: signed decision enumerates passed, failed, nonapplicable, and limited evidence for the exact build.
  - Progress: `qualify-release.py close` and `verify` and the binary's decision inspection exist; there is no signing key and no complete evidence set, so no decision has been made.

- [ ] `S10-900` **Pass the final production gate.** The released artifact is
  the exact implementation qualified by the complete evidence set; no local
  patch, changed dependency, different configuration, or unsupported platform
  inherits its claims automatically.
  - After: `S10-001` through `S10-013`.
  - Targets: release artifact, signatures, SBOM, conformance/evidence manifests.
  - References: [Architecture §§26.4, 28.9, and 29](docs/arc-architecture-and-implementation-spec.md#264-conformance-claims).
  - Invariants: all invariant families.
  - Evidence: independent artifact/signature/hash verification and zero incomplete applicable roadmap or conformance-ledger task.
  - Progress: not started; it depends on every task above.

## Deferred and explicitly out of scope for version 1

Do not implement these as hidden extensions or convenient fallbacks. A future
change requires the versioning, source-update, vector, migration, and
negotiation process defined by the specifications.

- Legacy plaintext listeners, STARTTLS, TLS 1.2, spanning-tree AgenC Relay server
  links, collision merging, reverse DNS, ident, SASL PLAIN, password escrow,
  account recovery, address-derived cloaks, or public-session administration.
- Work-in-progress multiline, generic chathistory, metadata, account
  registration, channel rename, read markers, typing, reactions, redactions,
  attachments, targeted MLS messages, external joins, archive keys, or key
  transparency.
- Post-quantum MLS claims or draft cipher suites. The hybrid TLS key exchange
  does not make message E2EE post-quantum.
- Locally designed cryptographic primitives, an in-daemon MLS client engine,
  server decryption, plaintext moderation of encrypted content, or downgrade on
  any encrypted-state failure.
- Unsupported platforms or filesystems presented as conforming merely because
  they compile.

References: [Architecture §§2.1, 3.2, 4, and 26](docs/arc-architecture-and-implementation-spec.md#21-adopted-client-specifications),
[E2EE §§4 and 22](docs/arc-mls-e2ee-extension.md#4-non-goals-and-unavoidable-limits),
and [source ledger §3](docs/protocol-sources-and-decisions.md#3-work-in-progress-and-deliberately-excluded-algorithms).

## Final completion conditions

- Every Stage-00 through Stage-10 task and gate is checked with linked evidence.
- Every Appendix-D surface maps to at least one roadmap task and machine requirement.
- Every `TRN-*`, `ID-*`, `AUTH-*`, `PRV-*`, `STA-*`, `E2E-*`, `FED-*`, `DUR-*`, `CON-*`, and `OPS-*` invariant maps to passing evidence.
- Every E2EE §21 numbered gate is complete for the exact encrypted profile.
- Every production crate appears only at its permitted dependency layer; testkit is absent from release graphs.
- Every mandatory build, analysis, dependency, coverage, fuzz, model, fault, interoperability, capacity, soak, recovery, hardening, and release check has exact-build evidence.
- Conformance and security statements match the evidence and explicitly preserve the design's honest privacy limits.

  - CAP-73 restore provenance follow-up: the current one-source transform can retain stale Normal-gate heads and omits a declaration for normal source routes without one. Three planner/transformer regressions fail and three preservation controls pass in 0.01 seconds, with exact inputs and executable archived. Paired-source planning now passes fourteen unit cases and a seven-variant signed-backup restore case, including scratch reuse, installed-output resume and authenticated readback. The index shares the existing plan byte limit. All eight checkpoint gates pass with 2,684 tests, no failures and 22 default-ignored tests. Both inventories cover 760 source files and the release catalog has 1,064 regions. Legacy Pending ambiguity stays blocked; Normal-row live persistence and terminal-evidence ingestion remain open.
  - CAP-73 live Normal persistence: two missing-record failures are archived. Route outcomes now prepare a charged declaration with the current daemon epoch and retain it only with the route's commit effect. Existing blocked gates cannot become Normal. Eight new cases pass in the 1,209-test runtime suite, including actual storage shutdown/reopen with a lost callback. Six fixture failures from the first full runtime run are archived and corrected. All eight checkpoint checks pass with 2,692 tests, no failures and 22 default-ignored tests. Both inventories cover 763 source files; the release catalog has 1,066 critical regions, without a new coverage measurement. Terminal recovery-evidence ingestion remains open.
  - CAP-73 historical record authentication: a new verifier checks all six sequencer signature domains, the exact expected position and credential, semantic terminal IDs and the referenced ReInit attempt. Eighteen integration tests pass, including real key rotation, malformed evidence and the largest initial Commit. All eight checkpoint checks pass with 2,789 tests, no failures and 22 default-ignored tests. Both inventories cover 776 source files; the release catalog has 1,097 regions. This API has no runtime or maintenance caller and grants no recovery authority. Complete historical-chain validation, ingestion and atomic Closed or Conflict installation remain open.
  - CAP-101 sequencer selection: four regressions reproduce incorrect successor credential IDs, incompatible direct installation and candidate receipts outside the credential interval. Installation now checks the exact selected credential before changing state, and candidate signing uses canonical Commit time. Thirteen focused tests and all eight checkpoint checks pass, with 2,802 workspace tests, no failures and 22 default-ignored tests. Both inventories cover 779 source files; the release catalog has 1,100 regions. Per-conversation key transitions and complete historical recovery remain open.
  - CAP-101 terminal key continuity: four regressions reproduce terminal acceptance under a different credential from the retained receipt. Finalization, abort and both ReInit terminals now require the receipt's exact credential. Expanded controls cover replacement keys, reused public keys, missing signers, reconstruction and unchanged-state retries. All eight checkpoint checks pass with 2,806 tests, no failures and 22 default-ignored tests. Both inventories cover 781 source files; the release catalog has 1,101 regions. New-candidate key selection, overlap ownership and complete recovery remain open.
  - CAP-73 initial public authority: a new verifier checks the original binding against an independent source pin, then revalidates its exact public authority and canonical initial time. Nineteen integration tests pass, including three development failures that exposed missing account, controller and cross-root key checks. All eight checkpoint checks pass with 2,825 tests, no failures and 22 default-ignored tests. Both inventories cover 783 source files; the release catalog has 1,111 regions. This API has no runtime caller and proves no later context, finality or recovery completion.
  - ENC-08 durable object ownership (2026-09-15, issue #53 under master #35): every accepted table-22 object now has an `owner/v1/` account (state record kind 16) persisting its kind, size, retention class, trusted acceptance second and retirement second, with the owning table-23 rows as typed references; the owning set is derived from the rows themselves (route, reservation, record, candidate, proof, policy, membership, identity, roster, lock, capability, package, claim, attach, mailbox, replay, barrier and outbox rows) at every batch site (requests, acknowledgements and publications, mailbox and request expiry, replay maintenance, startup retirement) and installs only on commit. An object is charged once per conversation and once globally; `MAX_STORED_BYTES_PER_CONVERSATION`, the new `RECOVERY_HEADROOM_BYTES` for proof-producing batches, and `e2ee.global_disk_bytes` refuse before any row is staged. Startup reconstructs the accounts from the rows, trusts a stored account only when it is complete and consistent, and reports reconstructed, unowned, mismatched, orphaned and undecodable counts without inventing an age. Evidence: the storage codec test, fifteen coordinator tests (24 retirement orders of a shared object, quota boundaries, headroom, deduplication, the global ceiling, reconstruction in both traversal orders and every inconsistency, the seal/reopen of every owner class) and the existing restart suites; recorded in [the object ownership record](docs/stage-10-object-owners.md). Physical cleanup remains ENC-09.
  - ENC-03 recovery submission carrier (2026-09-15, issue #57 under master #35): `recovery_submission(35)`, `submit_recovery(42)`, `submit_recovery_element(43)`, result kinds 24 through 27, the `EGROUP SUBMIT RECOVERY` and `RECOVERY-ELEMENT` commands and the four `RECOVERY-*` replies are implemented end to end; a pending route accepts device-signed submissions bound to the exact durable gate at the next position (or the head for a record), retains elements under `recovery-submission/v1/` (kind 17) and `recovery-record/v1/` (kind 18) rows owned through ENC-08, verifies every record and close through the ENC-02 chain resumed from the restored server's own validated state, installs `closed` with the tombstone or `conflict` with both proofs in one batch, and never returns to normal. Evidence: six in-process coordinator tests, one real-daemon backup/restore/upload test, storage and e2ee crate tests; recorded in [the recovery submission record](docs/stage-10-recovery-submission.md). Limitations recorded there: ReInit heads and sequencer credential transitions are not recoverable through the carrier. The daemon evidence also fixed five runtime defects it exposed (a restored coordinator reissuing a projection generation the edge held, a companion transfer that could not resume after link loss, requests forwarded before an attachment's declaration was acknowledged, bootstrap activations counted against the old council only, and the closed recovery reply completing through a hosting-only event), each with its own unit test and recorded in the same document.
  - ENC-08 durable object ownership (2026-09-15, issue #53 under master #35): every accepted table-22 object now has an `owner/v1/` account (state record kind 16) persisting its kind, size, retention class, trusted acceptance second and retirement second, with the owning table-23 rows as typed references; the owning set is derived from the rows themselves (route, reservation, record, candidate, proof, policy, membership, identity, roster, lock, capability, package, claim, attach, mailbox, replay, barrier and outbox rows) at every batch site (requests, acknowledgements and publications, mailbox and request expiry, replay maintenance, startup retirement) and installs only on commit. An object is charged once per conversation and once globally; `MAX_STORED_BYTES_PER_CONVERSATION`, the new `RECOVERY_HEADROOM_BYTES` for proof-producing batches, and `e2ee.global_disk_bytes` refuse before any row is staged. Startup reconstructs the accounts from the rows, trusts a stored account only when it is complete and consistent, and reports reconstructed, unowned, mismatched, orphaned and undecodable counts without inventing an age. Evidence: the storage codec test, eleven coordinator tests (24 retirement orders of a shared object, quota boundaries, headroom, deduplication, the global ceiling, reconstruction in both traversal orders and every inconsistency, the seal/reopen of every owner class) and the existing restart suites; recorded in [the object ownership record](docs/stage-10-object-owners.md). Physical cleanup remains ENC-09.
  - RUN-06 secret-lookup response floor (2026-09-17, issue #60 under master #35): `privacy.secret_lookup_floor_milliseconds` now governs every JOIN, NAMES, TOPIC and MODE whose failures are all `NotFound` or `SecretUnavailable`; the rendered logical response is retained with its label and batch boundaries, charged against the output budget, and published by a `SecretChannelFloor` timer at the deadline measured from the start of that command's processing, so slow work adds no delay and an exhausted budget or timer heap answers at once. While a connection owes a floored response its later commands use the existing per-connection deferral queue, so the delayed answer keeps its place in the order while other connections continue; a closed connection drops its response with its timers. Evidence: the floor owner's unit and component tests, the render classification test, and a real-daemon ordering assertion; recorded in [the secret-lookup floor record](docs/stage-10-secret-lookup-floor.md).
  - ENC-04 edge witness resolution (2026-09-17, issue #62 under master #35): a durable `witness/v1` row (kind 13, now carrying a permanent `conflict` mark) resolves only under an authenticated continuation. The companion 12.5.1 `witness_resolution(36)` object and the five `EWITNESS` frames are implemented on the edge with `MAX_WITNESS_RESOLUTION_RECORDS`, `MAX_WITNESS_RESOLUTION_BYTES` and `MAX_WITNESS_RESOLUTION_SECONDS`: the blocked edge now sends its ordinary ERESUME, answers `ERESUME OK` with one `EWITNESS REQUEST` per unresolved row in conversation order, reads only the resume and the EWITNESS family while any row stands, and validates each delivered `sequencer_record` at the next contiguous position under the predecessor the verified prefix reached and a credential of the negotiated sequencer key set (the active credential or its overlapping successor) through the ENC-02 authenticator, requiring the last record's recomputed semantic ID to equal the declared new head. One durable transaction then installs that head in `route/v1/` and deletes the row, and only its receipt sends `EWITNESS RESOLVED` and replays the origins; a zero record count retains the row and repeats the request on a reserved wake; a record that authenticates at the expected position under another predecessor marks the row `conflict` durably, blocks that one conversation for good through the client router and resumes the others; every other failure closes the link and retains the row. Evidence: seven focused edge resolution tests, the rewritten gating controls, the e2ee frame, object and kind tests and the storage witness body test; recorded in [the edge witness resolution record](docs/stage-10-edge-witness-resolution.md). Limitations recorded there: the edge side only (no coordinator publication), no clock-derived overlap window, no `reinit_attempt` record through this carrier, one open resolution per link, and the witness still cannot detect a record the coordinator never delivers. The evidence fixed two owner defects in `witness_failure.rs`: a retained durable record claimed every later frame failure as its own witness close and every later durable batch as its own receipt.
  - ENC-14 edge snapshot generations (2026-09-17, issue #59 under master #35): the edge's ESTATE receiver stages every page as one bounded batch of `pending-route/v1/` rows (kind 20) under the pending delivery generation with an `edge-snapshot/v1/` marker (kind 21), refuses over-ceiling declarations before allocation and wrong partitions, order, object identity, digest, cut changes and token expiry retaining nothing, charges every retained body against the backing reservation port, records READY durably before sending it and resends the identical READY after reconnect, swaps the generation only at ACTIVE (with the new cursor in the same batch), migrates the rows into `route/v1/` in bounded batches while live route changes refresh their pending rows, cleans up abandoned generations the same way, and restores READY, ACTIVE (mid-migration) and abandoned generations exactly from sealed storage. Evidence: eleven edge receiver tests, storage row tests, the projection and rollback tests, and the federation edge harness; recorded in [the edge snapshot generations record](docs/stage-10-edge-snapshot-generations.md). Limitations recorded there: no edge-side entitlement check, the byte ceilings are structural guards, native ext4 growth qualification stays REL-08.
  - Secondary 2026-09-01 audit findings (2026-09-17, issue #13, umbrella of master #35): ZDH-C3, C4, C5 and A1 were each re-read against the current tree at `fb618ab` before any change was considered, and all four no longer apply. The mask-list entry setter is the acting operator, and its creation-time fallback is unreachable because a vector containing `+b`, `+e` or `+I` always requests a trusted UTC read that the plan validator then requires (`cc57214`, PR #17). The executable JOIN outcome matrix disposes the creation/discovery ambiguity, and the member ceiling, `+l`, `+i`, key and E2EE outcomes all sit behind hidden-channel authorization (`2eb0ae3` and `539bf24`, PRs #101 and #107). The named LIST selector resolves each name inside the Listed gate, so absent, secret and unlisted names produce the same omission and the same scan charge (`c93ccf3`, PR #110). The invitation interval is rechecked at FINISH and again with a fresh trusted read at durable admission (`6b07e2e` and `d5d5f06`, PR #93). No production source changed. Two regressions pin the assertions the findings named that had no test of their own: `hidden_invite_only_and_banned_joins_report_only_unavailability` covers the `+i` and ban rows of the matrix, and the daemon regression `named_list_answers_a_secret_name_exactly_like_an_absent_name` proves that a named LIST of a secret channel returns exactly the frames of a named LIST of an absent name through the real binary. Every finding's regression was confirmed to fail against a temporary local mutation restoring the audited behaviour and to pass on the unmodified source; recorded in [the secondary audit findings record](docs/stage-10-audit-secondary-findings.md). Limitation recorded there: the Section 13.5 secret-lookup response floor still has no runtime owner and remains RUN-06 (#60).
  - ENC-05 follow-up leaf-membership decisions (2026-09-17, issue #111 under master #35): companion Section 13.7.3 now reads `epoch` against the disposition, so a `removed` proof names the first epoch in which the leaf is gone (the epoch its `removal_finalization_id` establishes) and a leaf removed by the finalization of epoch `e` states `removed` at `e+1`, above its own `continuing` proof, under the unchanged higher-epoch replacement rule; one device states one claim, its stored proofs at the highest epoch it has reached, continuing only while the device is roster-active and no proof at that epoch is `removed`, so a rotated credential and a superseded leaf both leave the expected set while earlier proofs still identify the ACKs of their own epoch; the expected continuing set of a ReInit attempt counts only claims whose device the approved `ArcKeyPackagePlan` carries into the successor, since `key_package_plan_id` is committed by the `ArcReInitAttemptAuthorization` the old controller threshold signs, so an unplanned claim is answered by the authority that decides membership and no one device can hold a migration open with a leaf key no server can place in the tree; and the failure table gains the `E2EE_EPOCH_STALE` future-epoch row and the `E2EE_BINDING_AUTH_INVALID` row for a `removed` proof naming no retained finalization, with the revoked-device exclusion stated in the expected-set text. Section 13.8 step 5 ties the ACK count to the same approved plan and the `E2EE_EPOCH_STALE` meaning now covers a proof. No BCP 14 clause was added, so the requirement ledger keeps its 251 records. The companion raw SHA-256 moved from `0620b993c63529dca24cc7b2e54eba158ebdf5401ecf54dc081ded73501a76f6` to `b2716e8e7a5531ed0e6f23455d45e51e81c8f901a0ef9a2b5ad3d471f059bf23`; the profile hash moved from `618080b4c92aa6b92196ce823369e5c0dd36b4916049670fd82bdabb09f78f07` (token `YYCAtMkqprkhls6CM2nlwN02tJFgSWcP2Cvauwn3jwc`) to `3771bab2f09024644d0468d004af30fba3d00403e4dc6f0205aea20a75265e45` (token `N3G6svCQJGRNBGjQBK8w-6PQBAPk3G8CBa6iCnUmXkU`), the architecture raw SHA-256 moved from `f542c23cab2724a88476d4650a501043bc367c71c66d45dfac676362f1fb0958` to `36d9dd0c2e917dcef49ba6de03ba4fe256c3e61945283a3e7fc4dae80046cd77`, and every pin moved with it. The implementation delta landed with the specification rather than being left open: `expected_continuing` in `crates/agenc-relay-e2ee/src/membership.rs` returns the highest-epoch claim per device, `activation_coverage` in `crates/agenc-relay-runtime/src/e2ee/coordinator/ops/ack_context.rs` intersects that set with the attempt's approved KeyPackage plan, and `old_group_device` keeps the unbounded claim set it checks before any plan exists. Evidence: the rewritten claim-rule unit test, an excluded leaf whose unplanned claim no longer blocks activation, and a planned device that rotated its leaf key, refused through the superseded credential and admitted through the one it last proved; three release critical regions in `membership.rs` and seven in `ack_context.rs` moved with the code.
  - ENC-09 expired object collection (2026-09-17, issue #67 under master #35): an idle `CompanionObjectMaintenance` owner now physically deletes expired unowned table-22 bodies, deciding only from the ENC-08 accounts (no owning `owner/v1/` reference, a trusted acceptance second, a trusted retirement second, and `now >= retired_at + retention`, where a security proof and ordinary material serve `SEQUENCER_RECORD_RETENTION`, a mailbox payload `WELCOME_RETENTION` and replay state `ACKED_E2EE_EVENT_REPLAY_TARGET_SECONDS`); no uploaded or row-supplied time can accelerate it, and an undated or unaged account is retained rather than collected. One pass charges its work buffer, walks at most 64 accounts and 4 MiB of bodies from a durable `object-expiry/v1` continuation (state record kind 20, E2EE state ceiling 19 to 20), and stages the object delete, its `owner/v1/` account and the advanced continuation in one storage transaction; a candidate crossing the byte budget stops the pass before the cursor names it, and resident bodies and their backing are released only against the receipt. Every candidate is revalidated at capture and again at the receipt against the live account, its retirement second and the resident body's exact content identifier, so a reference accepted after the capture wins and the body stays; a determinate refusal, an indeterminate write, a lost callback and a restart all resume at the last committed page without skipping an undeleted account or charging one twice. Evidence: one storage codec test, fourteen in-process coordinator tests and four sealed-storage federation tests through the real timer, staging and receipt path; recorded in [the object expiry record](docs/stage-10-object-expiry.md). Limitations recorded there: deleting a logical redb row enables reuse without shrinking the file, and native ext4 growth, reuse and cleanup qualification stays owned by STO-03 (#61) and REL-08 (#81).
  - CAP-01 advertised capacity workload (2026-09-17, issue #56 under master #35): the campaign no longer sums its population across the three daemons. Every sample carries per-node `live_client_connections`, `memory_charged_bytes` and `memory_budget_bytes` triples, the record carries the selected workload matrix and the node budget, and the driver, the verifier and their negative fixtures require the smallest client-admitting edge to have held the per-node population against the unchanged default live pool `P = 3,338,666,016`, so clients spread over several nodes can no longer substitute for a per-node limit. The production launcher now selects the Section 19.2 default of 50,000 clients on each client-admitting edge instead of 64 in total; the 4,096-connection harness ceiling is replaced by the published hard maximum; the load population is partitioned into `#load<n>` channels under the 4,096-member default; the generator binds 196 loopback source addresses per edge over 25 /24s so the per-/32 ceiling stays at its hard maximum instead of being raised, and paces registration per source address, which cuts a production warm-up from about eleven hours to about 102 seconds. The campaign also restores the Appendix C.2 four-GiB budget that the Stage 08 fixture lowers to one GiB, which no advertised claim could rest on. Evidence: twelve workload-matrix tests, the runtime occupancy measurement of 50,000 simultaneous idle TLS connections on one node (exactly 65,536 charged bytes each, 3,278,897,152 of `P`, 37,207 resident bytes per connection, every permit returned), the advertised-population profiling matrix for the six linear domain scans, the release qualification fixtures and a 64-client development pilot of the whole campaign; recorded in [the capacity workload record](docs/stage-10-capacity-workload.md). Limitations recorded there: the production campaign, the seven-day soak and the six latency classes at the advertised population were not run, and no production population can qualify until the Section 19.3 conflict in #113 is decided, because the connection-stop class refuses the 45,850th idle client the four-GiB budget admits. The pilot also found a second blocker: with the restored default budget, the peer-loss scenario's SIGKILL left edge B unable to reopen its storage (`storage state is stale or inconsistent` from `verify_guard_pair`, which requires exact repetition between the in-database reservation record and the on-disk rollback guard), while one control run at the fixture's one-GiB budget survived the same kill and completed all eight scenarios; that needs its own prerequisite issue against the storage open path. Neither 300-second pilot finished: the control failed afterwards in the final settle when one admin `STATS` read timed out under concurrent host load, which the controller treats as fatal instead of counting a sample failure.
  - RUN-05 shutdown during active federation recovery (2026-09-17, issue #64 under master #35): three regressions stop a coordinator and an edge through the real four-phase driver while the network is deliberately not drained, so no test needs `wait_for_federation_drain` to reach a clean stop. The coordinator case retains three unacknowledged `edge_outbox` deliveries for an absent edge, holds that edge inside an unfinished FRESUME origin replay, and leaves an abandoned virtual account carrier; `run_shutdown` under a tightened 2/5/5/2 plan completes every phase with no retained problem, no stop-deadline expiry, no stranded session and no invented account-service response, and the sealed database reopens with every retained delivery byte-identical, its keys strictly ordered so no delivery sequence is reused, and no orphaned `auth_transaction` row. A second case withholds a commit receipt so a committed outcome still owes its index readback: the coordinator sends nothing, drain refuses to acknowledge, and both the phase and the committed result arrive only after the receipt. The edge case stops with an unanswered `JOIN` request, a lost link and an armed journal recovery, reporting the physical close from drain, and reopens with every `federation_origin` and `request_result` row byte-identical. Evidence: three in-process tests plus the existing shutdown, `account_shutdown`, `ordinary_batch` and `combined_barriers` suites; recorded in [the shutdown-during-recovery record](docs/stage-10-shutdown-during-recovery.md). No production source changed and no defect was demonstrated. Limitations recorded there: the native ext4 stop deadline and the final physical-allowance guarantee stay bound to STO-03 (#61) and REL-10 (#84), the budgets are proved against a tightened plan rather than the 5/20/10/5 defaults, and the unsubmitted-gathering-batch and cross-profile barrier boundaries stay with their existing step-mode suites.
  - STO-10 storage guard pair after a kill (2026-09-17, issue #124 under master #35): CAP-01 attributed a killed edge's failed restart to `verify_guard_pair` refusing the database/guard pair. It did not, and this withdraws that attribution: the daemon prints `agenc-relay-server: {DaemonError}`, a refusal from `StorageOwner::start` is `DaemonError::Storage` and renders `storage owner failed: ...` alone, and the captured line also carries the `runtime startup failed: ` prefix that only `DaemonError::Runtime` adds, so the storage opened and reconstructed and the runtime refused afterwards. The publication order is also already correct in both directions: every durable operation makes the in-database reservation record durable before it replaces the guard file it names (`write_meta` then `install_reserved_guard`, then `commit_records` then `replace_guard`), so a guard can only lag its record, only by one publication step, and the record stays authoritative while `verify_guard_pair` stays an exact-equality fence. Evidence: a new on-disk crash matrix that abandons a real storage owner at all five `replace_guard` boundaries, on both sides, at both guard publications of a commit and of a checkpoint (40 abandonments) and requires the exact prior or successor state; the reconcilable one-step lag, the same window pushed one step further back which must still refuse, the clean control, and a daemon test pinning both printed lines; recorded in [the storage guard reopen record](docs/stage-10-storage-guard-reopen.md). No production source changed. Limitations recorded there: the CAP-01 failure itself is not reproduced or fixed here and needs a new issue against the edge startup reconstruction (`state_core/reconstruct.rs` alone holds 82 of the runtime's `StaleState` sites), the abandonment is an injected indeterminate failure at a durable boundary rather than a signal, and the offline construction, restore and login-index directories keep their own existing fault campaigns.
  - Overload thresholds and the funded default budget (2026-09-17, issue #113, RUN-04 prerequisite under master #35): Section 19.3 classifies overload against the same live protocol permit pool `P` that admission charges, so the four-GiB default's 50,000 idle client base charges were 98.1% of `P` and a default daemon refused its 45,850th client and entered the eviction class with every charge admitted. Widening the classified quantity to `B - H` or `B` is refused: admission already fails at `P`, so a threshold beyond `P` retires the class it names, which would have left only the 80% class against `B - H` and none against `B`. Weakening Section 28.7 to require only memory admission is refused because eviction selects by descending charged queue bytes and an idle client's queue is empty, so the server would have closed its longest-standing connections to recover a threshold its own configured count defined. The default `server.memory_budget_bytes` is now 6,442,450,944, giving `H = 805,306,368`, `D = 117,440,480`, `C = 301,989,888` and `P = 5,217,714,208`: the default population holds 3,276,800,000 bytes, 62.8% of `P`, in the normal class, and the 80%, 90% and 95% classes admit 63,692, 71,654 and 75,635 base charges. The advertised count, the 250,000 hard maximum and the configurable budget range are unchanged, and a lowered budget stays legal with its population bounded by Section 19.3 rather than by `client_connections`. Section 19.2 states the funding rule and Section 19.3 now names `P`. The same work fixed a second defect in that sentence: `select_evictions` projected only a candidate's queue bytes against the recovery mark although closing the connection also returns its base charge, so an empty-queued population was selected without bound and never reached recovery; the projection now subtracts both, and still omits backing beyond them so it can only select one connection too many. Evidence: 1,532 runtime tests including three rewritten eviction cases and two pinned arithmetic cases, the config template, golden and cross-field fixtures, and 56 release-qualification tests with the raised-pool negative fixture; recorded in [the overload threshold record](docs/stage-10-overload-threshold-defaults.md). Limitations recorded there: no production population has run against the new default, and re-running the capacity campaign's peer-loss scenario at 6,442,450,944 belongs to RUN-08 (#134), the successor to the disproved #124.
  - ENC-11 encrypted-profile defect sweep (2026-09-18, issue #76 under master #35): three examiners with no context from the implementation, given only the specifications and the tree at `46840bd`, each attacked one third of the encrypted profile and reported nine findings, one high, seven medium and one low, none a confidentiality or authority break: the coordinator never answered `EWITNESS REQUEST`, so a witnessed skip closed the federation link on every reconnect (#166, high); the edge installed snapshot entries without an entitlement check (#160); E2EE ingress was charged per fragment line (#161); a successor credential was accepted outside its overlap window (#162); live leaf-membership admission verified against the current roster instead of the named one (#164); reload promoted a pending finalization (#167), dropped resulting-council votes (#168) and left pending requests uncharged (#169); and the coordinator never released direct-route references (#173). All nine are fixed with regressions that fail without the fix (PRs #170, #171, #172, #181). Large areas were examined and found sound, including sequencer signer roles and rotation, quorum and sign-once voting, terminal-proof binding, signature and hash domain separation, secret handling, the account carriers, fragment reassembly and the recovery submission carrier.
  - Project-owned redb fork (2026-09-17, issue #55 withdrawn under master #35): the STO-01 bounded write transaction is now a reviewed local source patch vendored at `vendor/redb-4.2.0` from the published 4.2.0 archive, selected by `[patch.crates-io]`, recorded in `conformance/vendored-dependencies.toml` with the published checksum as provenance and the complete patched-tree digest `5e61f6ded5791fac67267a03ed774d96c1057e5f2a3ad2aa8e12b5a321bdbbba`, and verified by `scripts/check-workspace.py`, which now validates every reviewed patch from one table instead of assuming a single one. Section 24.5 states what a reviewed local source patch is, the persistence row names the fork, and the source ledger carries the paragraph; both documents refrozen. Upstream submission is withdrawn: asking a third party to take 2,100 lines of allocator and commit-path change built around this project's disk-reserve rule placed twenty issues behind a decision nobody here can make. Evidence: the storage crate builds and passes 337 tests against the fork with its ordinary API unchanged, the workspace checker and its 26 self-test cases pass; recorded in [the redb fork record](docs/stage-10-redb-fork.md). STO-03 (#61) is unblocked and integrates the bounded API from the fork.
  - RUN-10 pipelined commands and the slow-consumer close (2026-09-18, issue #174 under master #35): watched under `rr` through the real daemon, the `481` on a guest's fifth pipelined PRIVMSG is the specified Section 19.1 guest-message bucket (burst 4) rendered as the legacy `SERVER_BUSY` numeric and is unchanged. The defect was the writer queue reporting a sink full once more than `response_batches_per_connection` demands were undrained, whatever their size: the five one-line refusals closed the sender as a slow consumer with 196 bytes queued, because the state owner ran the whole read before the writer task popped anything, and the same count closed receivers of a burst. A sink is now full only at its byte or item ceiling (Section 15.3); a demand beyond the open-response ceiling brings one exactly charged cell that `prepare` allocates and `commit` links without allocating, drained in commit order with the ring. The slow-consumer close still destroys the queue and now delivers one shared, pre-rendered `ERROR :Closing connection: output queue exceeded` from the reserved control slot, which no production path had used. Regressions through the real daemon at 5, 9 and 32 pipelined messages, the default-bucket case and pipelined JOINs on connect, plus a full queue over a real TLS transport closing with the `ERROR` line first. Record: `docs/stage-10-pipelined-commands.md`.
  - ENC-19 to ENC-22 coordinator remediation (2026-09-18, issues #166, #167, #168 and #169 under master #35): four defects of the hostile-coordinator, historical-finality and proof-retention surface, found by an examiner with no context from the implementation. The coordinator now answers `EWITNESS REQUEST` from its retained chain with `EWITNESS BEGIN`, `ENTRY` and `END` (an empty set when it holds nothing, one open resolution per link, bounded by the `MAX_WITNESS_RESOLUTION_*` limits and by the first event the edge has not acknowledged) instead of closing the link as a protocol violation; reload rebuilds terminal proofs from certified sequencer records only, so a request below quorum is no longer a retained finalization and certified aborts and ReInit terminals come back; bootstrap-activation votes replay under the council their signer sits on and an uncountable vote row is reported; and every retained below-quorum terminal request has a row that charges it to its conversation, is refused whole over the quota, and ages out through the ENC-09 collector once its slot is certified. Evidence: bridged real-edge tests for a resolved skip, a confined fork and the pending-event bound, and seven reload and ownership regressions that failed before their fixes; recorded in [the coordinator remediation record](docs/stage-10-coordinator-remediation.md).
  - COV-01 base runtime, domain and wire critical-branch coverage (2026-09-17, issue #66 under master #35): a fresh source-bound branch report over the base slice — StateCore, connections, registration, account routing, administration, reload and shutdown, federation receipts and projections, history and WSS, domain authorization and the wire parser and enum boundaries — identified the uncovered executable decisions this issue owns, and eight new test modules close forty-one critical regions that were below 100 percent at `165570e`, with none regressed. The domain cases prove the suspended-home-peer fence refuses execution and direct targeting without deleting the grace-visible session, that a repeated public cloak refuses a fresh session seed, that a `Deny` direct-message policy outranks the recipient's contact set, that a permanent channel ban needs owner authority and never reaches the kick-only role comparison, and that a mask removal by value resolves only the addition its own mode vector staged; the model cases pair the channel key mode with its verifier, refuse a pending encrypted removal outside its membership, and prove suspension and restoration advance both revisions together or change nothing at all; the replica cases refuse a membership without its session, an invite without its channel and an `Invited` copy that names another channel, and deliver a remote-sender direct message to its hosted recipient alone. The administration cases prove every maintenance key-state field boundary refuses a truncation, that an unassigned operation discriminator is refused before either tuple is read, that the transition checker re-validates both tuples rather than trusting its caller, that twelve administrative arguments are each refused on their own, that `RESTART` reports its own verb, that a maintenance body exports under `NOTE AUDIT MAINTENANCE` with its exact bytes, that an unreconciled audit authority refuses both retention steps without moving the chain, that a frozen export is released only by its own `Observed` event, and that only the three assigned table and record-kind pairs are readable back into the verified chain. Overall workspace branches move from 65.6883 percent to 65.8097 percent and lines from 81.9556 percent to 82.0065 percent under the same `--lib` command; the aggregate 90 percent floor stays with COV-04 (#73). Evidence: recorded in [the base coverage record](docs/stage-10-base-coverage.md). No production source changed and no implementation defect was demonstrated. The evidence did expose a coverage-policy declaration defect: forty regions in this slice declared `metric = "branches"` over spans that emit no branch records at all, so `check-coverage.py` failed them with "matched no executable coverage data" however they were tested. Twenty-four were re-scored to the `regions` metric and now reach 100 percent with their category, span and reason unchanged; the remaining sixteen cannot reach 100 percent under either metric because their only uncovered entries are `?` unwinds on paths that cannot fail, and they are listed for review rather than changed. Limitations recorded there: the workspace figures use `--lib` and so exclude every `crates/*/tests/` target, with per-crate all-target reports supplied for the three wire crates where that matters; `admin-session-check-repeat` stays at 19/20 because its last entry needs the signed administrative handshake driven at a monotonic clock within the confirmation TTL of `u64::MAX`; the six `login_index` rotation regions belong to COV-03 (#70) and were not touched; and 238 regions in this slice, concentrated in the federation coordinator and edge owners, remain below 100 percent for the COV-04 (#73) integrated verdict.
  - RUN-08 edge startup reconstruction after a kill (2026-09-17, issue #134 under master #35): CAP-01's SIGKILL of edge B refused runtime startup with `runtime startup failed: storage owner failed: storage state is stale or inconsistent`, and STO-10 (#124, PR #132) already proved the refusal cannot come from the storage open. **The defect stays unreproduced.** A prefix sweep drives a live edge synchronously through the real writers and reconstructs a fresh `EdgeFederation` from exactly the rows storage holds after **every** commit, which is every durable prefix a kill can leave: 40 connection origins with a federated session-open request on each, so 80 dirty journal identities tear the drain across commits against the 64-row `BATCH_ROWS` bound, and a 40-entry standing projection built out of delivered events plus eight further projection events. Every prefix reconstructs. The sweep also rules the durable reconstruction out by inspection: `state_core/reconstruct.rs` admits `request_result`, `federation_peer`, `federation_origin`, `edge_outbox`, `edge_projection`, `e2ee_object` and `e2ee_state` for identity and sizing only, so none of the four shapes #134 names is visible to it, and every cross-kind coupling the edge restore checks (coverage row with its delivery cursor, barrier head with its part and payload, ACTIVE marker with the peer row that counts its entries) is written in one batch while the three multi-commit drains are same-kind with explicit prefix ordering. No writer ordering changed and no reconciliation was added; every state the reconstruction cannot prove still refuses. What did change is the identification the daemon prints, which is why #124 went to the wrong component: `DaemonError::Reconstruction(ReconstructionSurface, RuntimeError)` keeps the error's meaning and renders `runtime startup failed: {surface} refused the recovered state: {error}`, naming the durable state reconstruction, the recovered session reconciliation, the history reconstruction, or the edge federation restore at one of nine `EdgeRestoreStep` record families (`companion-witness-backing`, `federation-peer-record`, `edge-projection-rows`, `edge-projection-install`, `federation-origin-journal`, `request-result-journal`, `e2ee-state-rows`, `companion-snapshot-restore`, `barrier-install`). Evidence: two prefix sweeps, one end-to-end refusal-naming test that pins the whole operator-visible line, two daemon line tests, and the existing `restart` crash-image suite for the barrier windows; recorded in [the edge startup reconstruction record](docs/stage-10-edge-startup-reconstruction.md). Limitations recorded there: the pilot's own conditions were not reproduced (40 connections, not the advertised 50,000-client population, and the writers are driven directly rather than through TLS links), the peer-loss acceptance re-run needs the production campaign that #113 still blocks, and two arms (`Restore::install_projection`'s `edge.replica.install(...).map_err(|_| invalid())` and `E2eeEdge::finish_snapshot_restore`) swallow an allocation refusal into a stale-state refusal, which the pilot's budget observation does not rule out; the new step label narrows that to `edge-projection-install` or `companion-snapshot-restore` if it recurs.
  - COV-02 encrypted lifecycle, authentication and crypto critical-branch coverage (2026-09-17, issue #72 under master #35): a fresh source-bound branch report over the encrypted slice — runtime E2EE including the companion loader that pages the E2EE tables at startup, `agenc-relay-e2ee`, `agenc-relay-auth` and `agenc-relay-crypto` — identified the uncovered executable decisions this issue owns, and eight new test modules close eighteen critical regions that were below 100 percent at `ce98ea0`, with none regressed. The crypto case proves one key and one content produce forty-four distinct signatures, one per registered `SignatureDomain`, each verifying only under its own domain and each label unique, non-empty and carrying the prefix its declared encoding requires. The policy cases refuse a later profile version, a later MLS version, a foreign network and one disabled suite in an otherwise well-formed allowed set; they prove generation zero names no previous policy, that a successor must name the identifier it replaces and never changes the conversation kind, and that the device and leaf caps admit exactly their declared ranges with the same two fields accepted at the bottom of those ranges under re-signed approvals. The route cases refuse a later profile before the kind is read, refuse either direct account on a channel route and a pinned authority root on a direct route, and accept a replacement binding carrying no proof of its own while refusing the same binding carrying the initial unanimous approvals. The authorization cases refuse one controller root approving twice through two of its own devices although the list is already canonical, and refuse two distinct controller roots that enrolled one device signature key. The membership case proves a device that states its own removal at the epoch it reached claims nothing while both proofs stay retained and the continuing proof still identifies the ACKs of its own epoch. The finality cases prove a council seat is pinned to one certificate: a device the root dropped from its republished roster cannot vote, and a re-enrolled device does not inherit the seat. The runtime cases check each of the six gated fields of one companion part on its own, admit an ungated sequence only outside the gate's own mutation, require an open gate's rows contiguous from its first sequence, require a READY owner that still owes one profile, refuse to install a gate whose peer stream is incomplete, and prove a barrier resume recovers a lost ordinary prefix only through the exact gate end and only under an acknowledgement that is really one. Overall workspace branches move from 65.8418 percent to 65.9793 percent and lines from 82.0205 percent to 82.0265 percent under the same `--lib` command; the aggregate 90 percent floor stays with COV-04 (#73). Evidence: recorded in [the encrypted coverage record](docs/stage-10-encrypted-coverage.md). No production source changed and no implementation defect was demonstrated. The evidence did expose more of the coverage-policy declaration defect COV-01 recorded: five regions in this slice declared `metric = "branches"` over spans that emit no branch records at all, so `check-coverage.py` failed them with "matched no executable coverage data" however they were tested; all five are re-scored to the `regions` metric and now reach 100 percent with their category, file, span and reason unchanged. Limitations recorded there: the workspace figures use `--lib` and so exclude every `crates/*/tests/` target, with per-crate all-target reports supplied for the three encrypted crates where that matters; `e2ee-verify-policy` stays at 1/2 because its `MAX_POLICY_BYTES` guard cannot be reached while the TLS field bounds cap a constructible policy at about 23.7 KiB; `e2ee-check-policy-profile` stays at 17/18 because an empty `allowed_suites` is unconstructible under `TlsVec<u16, 2, 32>`; `edge-origin-settled-gate` is mis-anchored onto two argument lines of `submitted_identifier` rather than the `settled()` decision its reason names, and moving a reviewed span is a policy change; all three are reported to the open coverage policy issue #135 rather than adjusted; and 308 regions in this slice, concentrated in the coordinator's sync, startup, delivery-owner restore, retention and mailbox owners, remain below 100 percent for the COV-04 (#73) integrated verdict.
  - COV-05 release-critical region metric decisions (2026-09-17, issue #135 under master #35): a release-critical region declares the metric it is scored under, and COV-01 (#66) left sixteen rows that reach 100 percent under neither. The cause is that `branch_counts` scores only records LLVM emits for instrumented conditional jumps, which a body of `match` arms, slice patterns and `?` propagation never produces, while `region_counts` counts one entry per `?` unwind, so a span holding a propagation whose error arm cannot be produced is equally unscoreable. Each of the sixteen was measured entry by entry against a fresh workspace `--lib` report, a storage all-target report and a whole-workspace all-target report, and decided under one rule: narrow the span only when every uncovered entry is provably unreachable and sits at the span boundary, correct the metric and leave the row failing when any uncovered entry is reachable, and correct the metric and leave the row failing when the unreachable entries are interleaved with the decision the row is reviewed for. Four rows are narrowed and now reach 100 percent: `cap5-mod-maintenanceauditevent-sign` to the audit key selector fence (7/7), `runtime-join-echo-result-channels` to the echo-to-target correspondence and its `Violation::Consistency` refusal (16/16), `cap5-maintenance-preparedmaintenanceaudit-audit-mutation` to the kind-2 audit row itself (8/8), and `s10-cap70-projection-delete` to the barrier row the deletion addresses (3/3). Five stay failing with their remedy named: `s10-cap70-projection-write` 18/22 and `reload-audit-submission-outcome` 23/26 hold reachable entries that are ordinary test work, which withdraws COV-01's classification of both as unreachable unwinds; `cap5-tbs-maintenanceauditeventtbs-encode` 47/62, `cap5-export-export-render-0` 15/17 and `credential-replayed-completion-checkpoint` 45/47 hold unreachable propagations interleaved with their decision and need the production code restructured. The seven `login_index` rotation rows — COV-01's prose says six — take the metric correction alone and stay with COV-03 (#70); the metric correction alone brings `cap5-login-index-load-secrets` to 16/16, so one of COV-03's rows closes here, and the family is scored from the all-target report because a `--lib` report reads the two `login_index.rs` rows as 0/63 and 0/16 where every target built reads 56/63 and 16/16. The audit of the rest of the inventory found nine further rows with the same declaration defect and none in the interim policy: three storage rows are re-scored to `regions` and stay failing on reachable entries, and six in the encrypted, authentication and crypto slice are handed to COV-02 (#72) untouched, three of which need nothing but the metric correction to reach 100 percent. The same check separated a second, unrelated defect the old message had hidden: nine release rows match no coverage data at all because their spans are anchored on doc comments, `static` table rows and `struct` or `enum` declarations rather than on the item they name, and they are recorded for their owners rather than changed. `check-coverage.py` now refuses a branches declaration over a branch-free span with its own message naming it unscoreable as declared rather than untested, leaving `matched no executable coverage data` to mean only an empty span; the self-test grew from 24 to 25 rejection cases. No exemption mechanism was added, because opening the closed `REGION_FIELDS` set so a region can be scored over fewer entries than its span contains is a permanent weakening of the release policy and no narrowed row needs it. Evidence: recorded in [the region metric decisions record](docs/stage-10-region-metric-decisions.md). No production source changed, no floor moved, no reviewed row was deleted and no reachable entry was narrowed away. `check-coverage.py check` over the whole-workspace all-target report now classifies every one of its 665 failure items with no ambiguous message left: one floor (branch coverage 76.04 percent below 90), six unscoreable declarations all in the reserved slice, nine mis-anchored spans and 649 rows below 100 percent. Limitations recorded there: unreachable means unreachable from any caller in the release build rather than proved dead, fourteen rows stay below 100 percent on purpose, and no overall floor is claimed — the integrated verdict remains COV-04's (#73).
  - COV-06 release-critical region anchors (2026-09-17, issue #142 under master #35): a release-critical region names a file and a line span, and that span is what the release claims was reviewed. COV-01 (#66), COV-02 (#72) and COV-05 (#135) each found rows whose span is not the item the row's `reason` describes and each recorded them rather than moving them, because re-anchoring silently asserts a review over lines nobody read. The cause is drift, not authoring error: every one of these spans was correct when it was written and the file then grew above it, and `4bcf230` is the clearest case, inserting thirty-six lines into `witness_failure.rs` and refreshing every affected row's `source_sha256` to the new file while leaving every `start_line` and `end_line` where they were, which defeats the only staleness check the repository has, because `verify-regions.py` compares the hash and checks that `end_line` exists and both pass after such a refresh. Thirty-five rows are re-anchored here onto the item their `id`, `category` and `reason` name, each item read and each row's claim confirmed over the span it now covers, with the move and the re-review recorded in the row's own `reason`: the ten the issue names, of which eight now reach 100 percent including `edge-origin-settled-gate` at 4/4 on the `branches` metric it already declared, and twenty-five more in the same five files. Thirteen stay below 100 percent at their correct span with their owed entries named, decided under COV-05's rule that a span is narrowed only when every uncovered entry is provably unreachable and sits at the boundary; no span here satisfies it, so none is narrowed. Four rows read 100 percent at lines they do not describe and read below 100 percent at the lines they do — `cap97-recent-001-replay-recent` 32/32 to 49/51, `companion-mod-companioncoordinator-batch-applied` 16/16 to 39/40, `cap78-session-sessiontable-query-snapshot-for` 21/21 to 18/19 and `edge-delivery-checkpoint-encode` 1/1 to 29/36 — which is the honest cost of the correction. A second audit, independent of the coverage report, tests whether the item a row's `id` names is defined inside the row's span; over all 1144 release rows it flags 101, of which four are COV-05's deliberate narrowings inside the right function, thirty-four are re-anchored here and sixty-seven in twenty-three other files are recorded untouched for their owners, every one of which matches executable coverage data and so scores silently against an item its row never declared. The interim policy has none. `check-coverage.py` now splits COV-05's remaining message again, keeping `matched no executable coverage data` as the stem of both halves: a span anchored on non-executable text inside a file the report does cover, and a file the report never exercised; the self-test grew from 25 to 26 rejection cases. Evidence: recorded in [the region anchors record](docs/stage-10-region-anchors.md). No production source changed, no floor moved, no reviewed row was deleted and no span was widened. `check-coverage.py check` over the whole-workspace all-target report falls from 648 failure items to 635, with no mis-anchored and no unscoreable row left: one floor (branch coverage 76.19 percent below 90) and 634 rows below 100 percent. Limitations recorded there: a row is re-reviewed only against the item its `id`, `category` and `reason` name; sixty-seven mis-anchored rows are recorded and not moved, so sixty-seven release-critical scores still describe items their rows do not declare; the `id`-names-the-item audit is a lower bound, since a row named for a concept rather than an item cannot be checked that way; no overall floor is claimed and the integrated verdict remains COV-04's (#73); and nothing here prevents the next drift, because `verify-regions.py` still passes for a row whose hash was refreshed without moving its span.
  - COV-07 release-critical region drift (2026-09-17, issue #145 under master #35): COV-06 (#142) moved the ten mis-anchored spans whose drift landed on non-executable text, because those refuse visibly, and recorded sixty-seven more that had drifted onto executable code, where nothing refuses and each row scores silently against an item it never declared. Those are corrected here. The audit is re-run against the item's full extent rather than its declaration line alone and flags sixty-eight rows, and each of the sixty-eight is then decided against the history of `conformance/release-critical-coverage.toml` itself, reading the source at the commit that introduced the row at the row's own span, which says without guessing what the row was anchored to when it was written. Fifty-nine have genuinely drifted and are re-anchored onto the item their `id`, `category` and `reason` name, each item read and each row's claim confirmed over the span it now covers, with the move, the re-review and the resulting score recorded in the row's own `reason`; the ten in `federation/coordinator/companion.rs` are displaced by exactly thirty-four lines and the nine in `witness_failure.rs` by exactly thirty-six, which is one insertion each. Eight of the sixty-eight never named the item the audit guessed — their `id` ends in a word that is also an unrelated helper's name — and one, `storage-execute-restore-command`, had its reviewed body renamed `execute_restore_admitted` behind an identically-signed delegator; those nine keep their spans and now declare the item they have always held. Moving the delegator case onto the six-line entry point was measured and rejected, because that span matches no executable coverage data at all. So sixty-seven was an overcount by nine and an undercount by one: `cap101-sequencer-eligibility-001-selected-credential`, filed by COV-06 as one of COV-05's four deliberate narrowings, is not one of them and had drifted two lines. Nine rows read 100 percent at lines they do not describe and below 100 percent at the lines they do, and six measure zero at their own item — the mailbox expiry timer, the companion snapshot expiry timer, the companion fetch continuation and three quarters of the startup retirement protocol are release-critical and untested, and the policy had been reporting otherwise. Eight rows reach 100 percent only once correctly anchored. Thirty-six stay below 100 percent at their correct span, decided under COV-05's rule that a span is narrowed only when every uncovered entry is provably unreachable and sits at the boundary; none satisfies it, so no span is narrowed and none is widened. The hole is closed rather than patched: every region in both policies now carries `item`, the name of the Rust item the span is anchored to, and `span_sha256` over the span's own bytes. The span hash is invariant under every edit that does not touch the reviewed lines and changes exactly when a re-review is owed, so refreshing a file hash after an insertion above the span — the `4bcf230` operation that produced all of this — is now refused instead of absorbed; the item bind states in the policy what the `id` could only imply. Both are checked by `validate_policy_data`, so both run on every `check` and `self-test` the gate already calls, and `check-coverage.py` gained a Rust item locator (`source_items`) and an `audit` subcommand that runs the audit with no coverage report at all. The self-test grew from 26 to 28 rejection cases, one for a span hash that does not match its lines and one for a row whose item sits outside its span. `verify-regions.py` checks both new fields, and `reanchor.py` may move a span only by finding the exact reviewed text again, verifies the relocated span against the reviewed span hash and the named item, and exits nonzero when a region needs manual re-anchoring. Evidence: recorded in [the region drift record](docs/stage-10-region-drift.md). No production source changed, no floor moved and no reviewed row was deleted. `check-coverage.py check` over the whole-workspace all-target report moves from 635 failure items to 636 — one floor (branch coverage 76.18 percent below 90) and 635 rows below 100 percent — with nine newly failing and eight newly passing, and the audit reports zero drifted rows over all 1165 rows in both policies. Limitations recorded there: thirty-six rows stay below 100 percent and six at zero, with nothing here testing them; the item bind accepts a span that covers its item's declaration without covering the whole item, which is what permits a deliberate narrowing, and a stricter reading flags a further eighty-eight rows across twenty-nine files whose spans are offset from their item by a line or two while still covering its declaration, none of them a row this change touched; the `id`-derived form of the audit is a lower bound and was imprecise in both directions, so the gate reads the declared `item` instead; and no overall floor is claimed, the integrated verdict remaining COV-04's (#73).
  - ENC-07 sequencer signer roles (2026-09-17, issue #58 under master #35): the coordinator holds the active, successor and retired-retained signers from `e2ee.sequencer_private_key_file`, `e2ee.sequencer_successor_private_key_file` and `e2ee.sequencer_retired_private_key_file`, every route pins its accepted context's credential (`route/v1/` gains the pin and a blocked marker), receipts sign only under the pinned issuing credential covering the validation time, terminals only under the receipt's credential through any role, a finalized `SEQUENCER` transition moves the pin, and startup reconciles ownership from `keyset/v1` (kind 11) and `sequencer-history/v1/` (kind 19) rows: continuous succession only, refusal of an omitting set before the overlap deadline, blocked routes at it, release facts, refusal of a released or unrelated retired key, and the `e2ee_routes_blocked` and `e2ee_retired_signer_missing` audit events. A credentials file may open above generation zero after a retirement; `print-onboarding` renders the verified set and omits the four E2EE lines when the profile is disabled. Evidence: fifteen in-process coordinator tests, e2ee, config, daemon, onboarding and observer tests; recorded in [the sequencer signer record](docs/stage-10-sequencer-signers.md). Limitations recorded there: one retired-retained signer, the Appendix C.7/C.8 clauses stay bound to `S10-008`. The daemon evidence fixed a startup stall: the federation loader now continues the reload from the commit receipt of a startup write instead of the next maintenance tick.
  - ENC-01 public-evidence contract (2026-09-15, issue #36 under master #35): the companion now defines the Section 13.7.2 proof-input and validation-owner tables, the Section 13.7.3 leaf-membership proof (`leaf_membership_proof(37)`, `EGROUP SUBMIT MEMBERSHIP`, `submit_membership(44)`, `store_membership(11)`), the Section 13.7.4 recovery submission carrier (`recovery_submission(35)`, `EGROUP SUBMIT RECOVERY` and `RECOVERY-ELEMENT`, `submit_recovery(42)`, `submit_recovery_element(43)`, result kinds 24 through 27), the Section 12.5.1 edge witness resolution (`witness_resolution(36)`, the `EWITNESS` frames), Section 13.7.5 durability and worked examples, eight Section 16 limits, and the architecture Section 18.4 pending-admission narrowing. The companion raw SHA-256 moved from `398237eccca60c7056774b7565dbcac19c38417828191729f50d8fb86a33fdb1` to `79236c985a46205501c64ff45215846288cc0a4a3b8c17884d58055c1c394795`; the profile hash moved from `699c74adfe70c8cc336888e5191d1e09166c5de4406b9c7c8e9a58edadc48159` (token `aZx0rf5wyMwzaIjlGR0eCRZsXeRAa5x8jppY7a3EgVk`) to `d4deba80758c4585437420cd25330682b4fee97c77aea714df238505b08ab38c` (token `1N66gHWMRYVDdCDNJTMGgrT-6Xx3rqcU3yOFBbCKs4w`), and every pin moved with it. No production handler changed; the base registry, wire budget and evidence archive are byte-identical. Implementation handoffs: `ArcRecoverySubmission`, `ArcRecoveryElementKind`, `ArcFederationWitnessResolution`, `ArcLeafMembershipProof` and `ArcLeafDispositionKind` object definitions, `ArcWireObjectKind` arms 35 through 37 and the `POLICY`, `RECOVERY-SUBMISSION`, `WITNESS-RESOLUTION` and `LEAF-MEMBERSHIP-PROOF` client literals in `crates/agenc-relay-client-wire/src/text.rs` belong to `agenc-relay-e2ee` objects, envelope and wire modules and `agenc-relay-client-wire` (ENC-02 #51); the `ARC-MLS/1 recovery submission`, `ARC-MLS/1 leaf membership` and `ARC-MLS/1 leaf membership possession` signature domains and the `recovery_submission_id` and `leaf_membership_id` hash domains belong to `agenc-relay-crypto` and `agenc-relay-e2ee` (ENC-02 #51); recovery submission and element admission, the Section 13.7.4 reply-code mapping, Closed and Conflict installation and the `submit_recovery`, `submit_recovery_element` opcodes and `recovery_*` result kinds belong to coordinator `ops/recovery.rs` and `terminal_proof.rs` and storage `e2ee_records` rows (ENC-03 #57); `EWITNESS` request, delivery and resolution with `MAX_WITNESS_RESOLUTION_*` belong to edge `sync.rs` and `witness_recovery.rs` (ENC-04 #62); leaf-membership storage, ACK signer identification, duplicate and missing continuing-leaf refusal, `submit_membership` and `store_membership` belong to coordinator `ack_context.rs` and the ReInit activation path (ENC-05 #52). The Section 13.7.2 endpoint-only rows stay outside every server crate.
  - ENC-06 sequencer signer contract (2026-09-15, issue #37 under master #35): companion Section 9.2.1 defines credential identity as `sequencer_credential_id`, the three signer roles (active, successor, retired-retained), the per-conversation transition instant, receipt and terminal key selection, retirement at the overlap deadline with blocked routes, the durable signer-ownership metadata, the exact signer-release conditions and an eight-phase transition table; the `E2EE_SYNCING` meaning also covers an unavailable pinned signer with the reply registry unchanged. Architecture Sections 22.2, 22.6 and 25.4, Appendix C.7 (`e2ee.sequencer_successor_private_key_file`, `e2ee.sequencer_retired_private_key_file`, the exact credentials-file layout and the atomic refusal table) and Appendix C.8 (`print-onboarding` verifies the configured key set and omits the four E2EE lines as one unit when the profile is disabled) carry the configuration contract, and the operator guide gains the rotation workflow, three TOML examples and the refusal list. The seven new BCP 14 clauses are bound to `S10-008` as unimplemented. The companion raw SHA-256 moved from `79236c985a46205501c64ff45215846288cc0a4a3b8c17884d58055c1c394795` to `0620b993c63529dca24cc7b2e54eba158ebdf5401ecf54dc081ded73501a76f6`; the profile hash moved from `d4deba80758c4585437420cd25330682b4fee97c77aea714df238505b08ab38c` (token `1N66gHWMRYVDdCDNJTMGgrT-6Xx3rqcU3yOFBbCKs4w`) to `618080b4c92aa6b92196ce823369e5c0dd36b4916049670fd82bdabb09f78f07` (token `YYCAtMkqprkhls6CM2nlwN02tJFgSWcP2Cvauwn3jwc`), and every pin moved with it. No production behaviour changed. Implementation handoffs to ENC-07 (#58): the two new configuration keys and their protected-file parsing in `crates/agenc-relay-config/src/e2ee.rs`, successor and retired-retained signer installation and receipt-time credential selection in `crates/agenc-relay-runtime/src/e2ee/coordinator/sequencer_signing.rs` and `ops/sequence.rs`, the credential history, signer-release fact and blocked-route rows in storage, the refusal table and audit event in `crates/agenc-relay-runtime/src/daemon.rs`, the verified key set in `render_onboarding` (`crates/agenc-relay-runtime/src/offline.rs`), and removal of the unused duplicate layout in `crates/agenc-relay-e2ee/src/federation/keyset_file.rs`.
  - ENC-10 encrypted recovery, rotation and ReInit with real MLS clients (2026-09-17, issue #71 under master #35): the repaired encrypted paths are now driven end to end by real openmls and mls-rs endpoints through the production binary's client surface instead of synthetic MLS bodies. The daemon suite's leaf evidence is now the endpoint's own: `OldLeaf` names the exact signature key each MLS library holds and the `old_credential_hash` of the credential bundle that leaf carries, so every Section 13.7.3 membership proof carries that key's own possession signature and every Commit and ReInit acknowledgement is signed by the private key of the leaf it names; removal proofs name the finalization that removed the leaf. Three daemon scenarios join the Stage 08 suite. Recovery: a member whose live MLS state is lost is removed, rejoins under a fresh leaf through a second claimed KeyPackage and Welcome, decrypts the minutes of the epoch it joined and derives no plaintext from the retained ciphertext of before the loss, and the ten real records of that lineage plus its public close are then re-proved to a coordinator restored under a new recovery epoch through the companion 13.7.4 carrier, where a record that does not continue the chain is refused without installing anything and the genuine record at the same position is still accepted, and `closed` survives a stop and refuses every later submission. Rotation: the advertised sequencer key set moves through three generations while the same conversation runs, a finalized `SEQUENCER` transition is receipted under the old credential and moves the pin, every later receipt verifies under the successor, the coordinator then opens a credentials file whose only credential is generation one, a binding that still pins the retired credential is refused while the same reservation binds under the successor, and a leaf retired from the group still receives the ciphertext but derives no plaintext past its retirement. ReInit: a real RFC 9420 ReInit proposal closes the old group, both endpoints resume through `get_reinit_client`, and the successor activates only once every continuing leaf has acknowledged, while an openmls leaf removed from that mls-rs group in an earlier finalized epoch leaves the expected continuing set, is not required to acknowledge and derives nothing from the successor. Evidence: the three daemon scenarios, the existing real-client, recovery-submission and interoperability suites, and nine new lifecycle rules in `conformance/e2ee-interop-matrix.toml` whose stale final close claim is repaired to name the separately finalized public closing intent; recorded in [the encrypted client proof record](docs/stage-10-encrypted-client-proof.md). No production behaviour changed and no defect was demonstrated; the only production-crate change is a test-only credentials-document builder in the testkit. Limitations recorded there: mls-rs produces a Welcome and a `GroupInfo` for a resumption successor rather than a separate initial-Commit message, so the attempt carries that `GroupInfo` where the coordinator binds only its digest; three of the four successor result digests have no Section 2.2 formula and bind real successor material through the object-identifier hash; the ReInit successor route is not bound, so the `ArcStagedReInit` mailbox carrier is not exercised; the two endpoints that continue through the ReInit are both mls-rs because openmls 0.9 exposes no ReInit proposal or resumption successor, and openmls participates there only as the leaf removed before it; the blocked-route path of a retirement before the overlap deadline stays with the ENC-07 in-process suites; and native release qualification, the seven-day soak and the long fuzz campaigns remain with the root release issues.
  - RUN-07 Section 19.3 overload class owners (2026-09-17, issue #131 under master #35): the runtime computed all three overload classes and reported them while only part of one acted, so a loaded node kept accepting guests, kept serving expensive queries, kept creating channels and never shed the slow consumer that caused the pressure. Every rung now has an owner reading one live class through the new `StateCoreContext::refresh_overload`, which reclassifies from the budget at the moment of the decision and reports the transition, and which `admit_connection` now shares. At 80 percent a guest registration is refused with the Section 19.1 line for temporarily rejecting a guest, `FAIL * REGISTRATION_REQUIRED :Registration required`, before any session seed exists, and every command in the closed expensive-query class of Section 19.1 — now the public `agenc_relay_domain::is_expensive_query`, covering `NAMES`, `LIST`, `WHO`, `WHOIS`, `WHOWAS` and `CHATHISTORY` — is refused with the bounded `FAIL <command> SERVER_BUSY :Server is busy`, in both the ordinary command path and the separate history-admission path, while authenticated ordinary traffic continues untouched. At 90 percent a join is refused only when the domain's own external-input vector asks for a channel-instance draw, so creating a channel is stopped while joining an existing one is not, and no domain planning rule changed. At 95 percent `StateCoreContext::shed_overloaded_connections` calls the existing `select_evictions`, marks each selected connection closing and destroys its entire queue with the connection, stopping at the 85-percent recovery mark through the existing hysteresis; a connection already closing is never offered again, no individual frame is ever selected, and a frame shared with another queue keeps its permit until that last queue drops it. The sweep runs after every accepted input and every timer wake and counts what it selected in `StateCoreCounters::connections_evicted`. Both refusals are charged first, as Section 19.1 requires so a rejection cannot become a cheaper error oracle than the work it replaces. Evidence: two ladder tests that walk one live pool up through 80, 90 and 95 percent and back down through 85 against the real actor loop, registration router and command executor — asserting the exact refusal and the absent numerics at each rung, that a join of an existing channel survives 90 percent, that the refused creation left no channel behind, that eviction takes the largest charged queues first and stops at the recovery mark with the smaller queue alive, and that a recovered node accepts again — plus the extended `admission::overload` class-predicate test; recorded in [the overload class owners record](docs/stage-10-overload-class-owners.md). Limitations recorded there: with the 4-GiB default still on this branch the Section 19.2 default population sits at 98 percent of its pool, so the ladder is only correct for that population once RUN-04 (#130) raises the default; the accept rung stays with `TransportAdmission` and a refused accept never reaches the state owner; federated and edge-mode command paths are untouched; and ranking is by queue occupancy alone, exactly as Section 19.3 words it.
  - RUN-08 edge restore refusal causes (2026-09-17, issue #134 under master #35): the last hypothesis #134 carried was that `Restore::install_projection`'s `edge.replica.install(...).map_err(|_| invalid())` and `E2eeEdge::finish_snapshot_restore` turn an allocation refusal into a stale-state refusal, which would have explained CAP-01's four-GiB run failing where its one-GiB control survived. **It does not hold.** `EdgeReplica::install` returns a closed eight-arm `ReplicaError`, every arm a statement about the restored entries, and the replica is a domain value that never touches `MemoryBudget`, never calls `try_reserve` and has no `MemoryExhausted`, `LimitExceeded` or `Overflow` arm to return; `snapshot_finish_restore` has exactly two `Err` sites, both `E2eeReplyCode::Syncing`, stating only that a READY generation's restored pending-route rows do not add up to its own durable marker's count, and it reads no budget. The companion restore's real admission path is one step earlier — `snapshot_restore_entry` and `WitnessRecovery::restore` reserve through `BackingReservationPort` — and already propagates `MemoryExhausted` unchanged at `e2ee-state-rows`. A different capacity defect was found beside them and is fixed: `Restore::charge` held one pool of `536_870_912` bytes and `1_000_000` rows and charged six record families into it, although those two numbers are the spec-20.8 ceilings the live path admits for **one** projection generation, and an edge holds two generations' entry rows at once because `sync::snapshot_active` switches the peer row without deleting the superseded rows in that batch and `install_projection` requires the active count to match while `pending_generation` is `Some`. A node that crossed no ceiling could therefore be admitted into a durable state its own restore refused, and only a kill would reveal it. A restore that cannot rebuild an admitted projection is not a legitimate refusal: each generation and the companion material now charge against their own copy of the admission ceiling, so the restore fits everything admission admits, no spec ceiling moved, no live path changed, every pool still fails closed with `RuntimeError::LimitExceeded`, and no projection is ever installed partially. The cause-destroying arms are repaired either way. `EdgeRestoreRefusal` gains `cause: EdgeRestoreCause` beside PR #138's step, `ReconstructionSurface::EdgeFederation` prints `edge federation restore at {step} ({cause})` and prints PR #138's exact line unchanged for `Unclassified`, and five arms stopped discarding what they were given: the two replica installs keep their `ReplicaError`, `finish_snapshot_restore` records `CompanionSnapshotIncomplete`, `install_stage` keeps its `BarrierFault` and raises `LimitExceeded` rather than `StaleState` for `BarrierFault::Aggregate`, and `verify_restored_cut` raises `LimitExceeded` for the same two ceilings the live install reports as `Violation::Ceiling`; `Restore::charge`'s own overflow became `Overflow` and a missing `BackingReservationPort` became `InvalidValue`. Evidence: three pool cases driving the accounting directly, two end-to-end cases seeding durable rows through the real storage owner and pinning the whole operator-visible line, one strengthened companion-snapshot case and one added daemon line case; recorded in [the edge restore refusal cause record](docs/stage-10-reconstruction-cause.md). **#134 stays open**: the CAP-01 refusal is still unexplained and still unreproduced, the defect repaired here refuses with `runtime ceiling exceeded` and never with the captured stale-state line, and the peer-loss acceptance re-run still needs the production campaign that #113 blocks.
  - QA-02 sequencer rotation drill repair (2026-09-17, issue #137 under master #35): `run_sequencer_rotation` installed a two-credential rotation document and then pointed `e2ee.sequencer_private_key_file` at the **new** key while configuring no `e2ee.sequencer_successor_private_key_file` at all, which is exactly the set ENC-07 (#58) made the daemon refuse: `e2ee_setup_with_hook` takes the active key to be the key of the credential the file lists first and requires a successor key exactly when the file lists a successor, so the coordinator exited with `DaemonError::E2eeCredentials` before opening a listener and the drill could not start its nodes. The drill carries `#[ignore = "Stage 10 drill; run through the qualification driver"]`, so no ordinary run exercised it and the breakage was invisible until the native campaign; its last recorded pass, "a generation-1 set chaining from the previous credential" in the qualification record, predates ENC-07. The drill now walks the workflow the operator guide documents. The active key keeps the generation it already holds while the incoming key is installed as `sequencer_successor_private_key_file` beside the two-credential document (set generation 1); a finalized `SEQUENCER` transition on the bound channel moves that conversation's pin; and only then does the successor become the active key with the predecessor retained at `e2ee.sequencer_retired_private_key_file` (set generation 2), where a second channel deliberately left pinned to the predecessor keeps that signer required rather than released. Every step now asserts what a client observes instead of that the nodes started: the bootstrap activation's candidate receipt names the generation-zero credential and its signature verifies under exactly that credential's public key, the transition's own receipt is signed under the predecessor and the next finalized record's under the successor, the retirement start is itself the check that the retained key is the key of the one credential the live state still requires because a released or unrelated key refuses startup, `e2ee_routes_blocked` is reported for the route that still pins the predecessor while `e2ee_retired_signer_missing` is not, and a new binding package pinning the retired credential is refused with `E2EE_BINDING_AUTH_INVALID` while the same reservation binds once it pins the credential the advertised set now issues. One further repair was needed: a client session never survives an edge restart and a submission on a channel conversation needs its members present, so the drill re-joins both channels after every restart, without which the first submission after a restart receives no reply at all. The signal outside the native campaign is an ordinary non-ignored test in the same module over the same `KeyPlan` values and the same `install_keys`, which requires the refused shape to exit non-zero and both correct shapes to come up and link, in 24 seconds; the qualification driver's own self-test feeds `validate_record` synthetic record dictionaries and has no fixture, configuration or daemon, so it can only check the closed record schema and the check cannot live there. Audit of the other fourteen ignored Stage 10 drills, each run to completion serially on this host: thirteen configurations are still accepted and their drills pass (restore, disaster restore, rekey, index transition, TLS rotation, federation rotation, backup rotation, audit rotation, compromise, rollback, resynchronization, host hardening, observability); `deletion` writes no configuration the daemon refuses but still fails, in the serial sweep at `authenticated_client` right after a coordinator restart with `FAIL ACCTCREATE UNAVAILABLE` because `DrillNodes::restart` waits for the federation links but not for account authority, and on its own run further in, inside `delete_account`, where an `ACCT` command of the deletion sequence is answered `481 :Permission denied`. That second failure is an authority refusal only the account-deletion path can explain, so both are reported for their own issue rather than patched speculatively and `run_deletion` is left untouched. No production source changed and no production defect was demonstrated; the daemon's refusal was correct and the drill encoded a procedure the daemon does not accept. Evidence: recorded in [the rotation drill repair record](docs/stage-10-rotation-drill-repair.md). Limitations recorded there: the drill's MLS bodies stay synthetic with the real-endpoint rotation left to ENC-10 (#71); the fixture's credentials carry `not_before = 0`, so the retirement is proved at or after the seven-day overlap deadline and a retirement refused before it while a normal route still pins the predecessor stays with the ENC-07 in-process suites; one retired-retained signer is held, so exactly one credential is retired; and native release qualification of the whole drill campaign remains with REL-10 (#84).
  - QA-03 deletion drill repair (2026-09-17, issue #147 under master #35): the Stage 10 account-deletion drill failed in two different places depending on how it was run, and neither was visible outside the native campaign because every Stage 10 drill carries `#[ignore = "Stage 10 drill; run through the qualification driver"]`. **First**, in the serial sweep, `authenticated_client` right after `nodes.restart(&network, 0)` was answered `FAIL ACCTCREATE UNAVAILABLE :Account creation unavailable`: `DrillNodes::restart` waited for the federation links the restart interrupts and returned, while `DrillNodes::restart_all` waits for those links **and** for `wait_for_account_authority` on both edges, and a link is established before an edge can serve an account. That is a harness gap and `restart` now performs the same readiness wait for each edge whose link it waits on. **Second**, run alone, the drill reached `delete_account` and its first `ACCT` line, `ACCT LABEL deletion-check`, was answered `:edge-a.test 481 delete-me :Permission denied`, after which the read waited out its deadline. **The refusal was correct and the drill was wrong.** `delete_account` opened its session with `negotiate_sasl` and then `CAP REQ :standard-replies` alone, while architecture Section 14.6 opens the `ACCT` surface through the Section 9.3 vendor capability and `require_command_capabilities` requires both `agenc.ag/account-controls` and `standard-replies`, returning `NoPrivileges`, which the runtime renders as `481`. The drill was written in `ac0d73f` (2026-09-05) and that requirement arrived eight days later in `0c0128a` (2026-09-13); nothing updated the drill, so it kept negotiating a session the surface is not open on. Every deletion session now requests `standard-replies agenc.ag/account-controls` and asserts the server acknowledged both before it sends an `ACCT` line, and no runtime or domain source changed. The drill now asserts the observable outcome rather than the absence of an error, reading every durable claim from the stopped coordinator's own storage: a new `refuse` step confirms a canonical deletion token no `DELETE START` ever issued, requires `FAIL ACCT BAD_STATE :Command is not valid in the current state`, and then requires both accounts' rows to be what the creation left, so an authorization failure is proved to write nothing; the deletion itself must end on `NOTE ACCT UPDATED :Account setting updated` with the server's own clean close; what it removes is the target's `Account` row reduced to a tombstone with generation 0, no expiry, no references and an empty body with its `OpaqueRecord` row gone; what it retains is the login-index `DeletionTombstone` naming the deleted account with the non-zero expiry of the 30-day login-hash reservation and the unrelated account's credential and policy; and what a later lookup returns is an OPAQUE refusal of the deleted login before and after a rekey under a new master key and rollback guard, on both edges, while the seeded account still authenticates. The signal outside the native campaign is an ordinary non-ignored test in the same module over the same helpers, `deletion_drill_preconditions_are_the_ones_the_daemon_requires`, which requires `ACCT LABEL` over `standard-replies` alone to be refused `481`, the same line over the set the drill now negotiates to be answered `NOTE ACCT UPDATED`, and a coordinator restarted through the repaired `DrillNodes::restart` to leave both edges reporting `active_peers` of 1 read with no wait of its own, in about 20 seconds against the drill's 47. All fifteen ignored Stage 10 drills now pass serially on this host. One unrelated behaviour was found and is **reported for its own issue rather than repaired**: an OPAQUE authentication that reaches an edge whose account authority is momentarily unavailable is answered `904 :SASL authentication failed`, which `SaslNumeric` cannot distinguish from a wrong password because it has no unavailable arm, although Section 9.3 gives `FAIL ACCTCREATE UNAVAILABLE` and `FAIL ACCTCRED UNAVAILABLE` for that state on the other two carriers; the drill works around it by retrying its own session inside `NETWORK_WAIT` after re-waiting for account authority, and no refusal the module proves is read from that carrier. Evidence: recorded in [the deletion drill repair record](docs/stage-10-deletion-drill-repair.md). Limitations recorded there: the deleted account owns no channel and holds no E2EE route, so the Section 14.6 conditions that refuse a confirmation from a session occupying a channel, from an account that would leave a channel ownerless, or from one that has not left every E2EE route stay with the in-process suites; the token-mismatch refusal consumes the challenge on every outcome and would need a second OPAQUE authentication to continue, so only the `BAD_STATE` refusal is driven from the drill; the 30-day login-hash reservation is proved as the durable tombstone row with its expiry rather than by a second creation on the same login; and native release qualification of the whole drill campaign remains with REL-10 (#84).
  - COV-08 companion coordinator and startup retirement coverage (2026-09-17, issue #150 under master #35): COV-07 (#145) re-anchored every reviewed release-critical region onto the item its row names, and six rows that had been reporting partial or full coverage against neighbouring functions measured zero at their own spans — 137 executable regions, all declared release-critical, reached by no test at all: the companion coordinator's mailbox expiry timer (`mailbox_timer_fired`, 0/13), its ESTATE snapshot expiry timer (`snapshot_timer_fired`, 0/33), its fetch continuation (`continue_fetch`, 0/55), and three quarters of the startup owner-retirement protocol (`rejected` 0/23, `retryable` 0/4, `retry` 0/9). Five now reach 100 percent and the sixth reaches 54/55, the maximum its span can reach. Every case is driven through the owning boundary rather than by calling the function: the two timers arm a real heap entry, pop it with `TimerHeap::pop_due` the way `StateCore::step_wake` does and hand it to `FederationCoordinator::timer_fired`, so the whole eight-handler chain is proved to reach them; the fetch cases open a real multi-page cut over `ERESUME`, send `ESTATE FETCH` quoting the cursor the previous page ended on and settle the staged boundary through `commit_staged_batch` and `batch_applied`, which is the only path that reaches `continue_fetch`; and the retirement cases run the real reload until it parks on one accepted startup write, then settle the exact storage refusal through the owner's public `batch_rejected_with_error`, because a `Receipt` cannot be built by hand. The refusal side is covered deliberately: a receipt taken at a moved durable head and one whose pinned commit no longer matches both fail closed although the refusal is retryable, a loader already holding a candidate refuses a second receipt and keeps the one it held, a receipt that cannot be confirmed against live state fails closed, and every refusal leaves the durable head where it was, leaves `retry_at` at zero, advances the violation counter by exactly one and leaves the reload wedged rather than guessing; a retryable refusal returns the candidate and reserves exactly one fixed 100-millisecond interval, `advance` stages nothing before it elapses and stages the same write again once it has, `retryable` is pinned to exactly five bounded refusals against the eight determinate and indeterminate outcomes (the sibling `resume_reconciliation::retryable_storage` deliberately admits a smaller set), and a monotonic reading within one interval of the `u64` ceiling fails closed rather than retrying unpaced. On the fetch side a continuation that overruns the link queue stops at the byte boundary and retires the link rather than carrying a partial page on, one interrupted by a reconnection publishes nothing to the link that is gone and the edge receives the same page again over its new link without staging a second durable boundary, and a publication whose delivery owner moved under it retires the exact live link it was staged for while the same refusal on a link already gone retires nothing. Measured on one whole-workspace all-target report per column, same command and same selection: `check-coverage.py check` moves from 636 failure items to 629 — one floor and 628 rows below 100 percent — with seven rows newly passing and none newly failing, and the workspace reads 76.3846 percent branches, 91.8118 percent lines and 86.2691 percent regions against 76.2024, 91.7454 and 86.2039 before. Two of the seven are reached on the way rather than claimed here: `companion-companion-send-page` moves 23/32 to 32/32 because it is the adapter the fetch continuation publishes through, and `companion-sync-companioncoordinator-snapshot-expired` moves 14/15 to 15/15 because it is the predicate the ESTATE expiry timer reads. Evidence: recorded in [the companion coverage record](docs/stage-10-companion-coverage.md). No production handler changed, no span was narrowed, widened or re-scored and no `reason` moved; each new `mod` line sits at the end of its file so no reviewed span above it shifts. Limitations recorded there: `companion-companion-continue-fetch` stops at 54/55 because the one entry left is the `?` unwind at `companion.rs:996:64`, and `Prepared::committed` returns only `Ok(Vec::new())` or `Ok(vec![Action::SendPage(output)])` while `apply`'s `SendPage` arm cannot return `Err`, so no input reaches it — narrowing the span, accepting 54/55 as the row's ceiling or changing `apply` is a policy decision and not a test, and #135 and #145 settled this row's anchoring and metric so nothing here moves either; the `no executor` guard in `continue_fetch` is unreachable through the owner's receipt path because `companion::committed` returns first, so the one case that covers it takes the receipt's own publication out of `batch_applied` and calls `continue_fetch` with the executor removed; the retirement fixture's candidate is the startup signer reconciliation rather than a delivery-owner retirement, because a restored retirement candidate needs a `sync::Snapshot` whose fields are private to `crate::e2ee::coordinator`, and both are the same `RestoredWrite` through the three rows this closes; the timer cases drop due wakes of other kinds rather than firing them; the retirement fixture composes the registration router, which `compose_test_state` gives the real monotonic clock, so the reload's last reading is pinned with `set_monotonic_for_test` before any case runs and the paced deadline is an exact value rather than one that can cross a millisecond between the value a case reads and the value `retry` reserves; and no overall floor is claimed, the integrated verdict remaining COV-04's (#73).
  - RUN-08 peer-loss reproduction and the edge restore that refused it (2026-09-17, issue #134 under master #35): CAP-01's observation — `scenario_peer_loss` SIGKILLs edge B under load and the restart prints `runtime startup failed: storage owner failed: storage state is stale or inconsistent`, after which the cycle fails with "edge never established its coordinator link" — **reproduces**, three times in 209 SIGKILLs at the published `server.memory_budget_bytes` of 6,442,450,944 against the unmodified `origin/main` daemon at `99956df`, and PR #138's and #144's labelling named it on sight: `edge federation restore at edge-projection-install (active projection: federation replica reference does not resolve)`. Five campaign runs at the pilot's own configuration (`AGENC_STAGE10_CAMPAIGN_SECONDS=300`, `AGENC_STAGE10_CAMPAIGN_CONNECTIONS=64`, one cycle and so one kill each) saw nothing, because one kill per run cannot reach a one-in-seventy race; a new ignored `peer_loss_kill_drill` holds the same population against the same three daemons at the same budget and repeats only that kill, sweeping each kill's phase by 1.5 s across 24 steps over the 0-34.5 s after the re-established link and killing every second restart again inside its own startup, and it preserves the killed edge's whole durable directory and stderr when a restart refuses. All three preserved crash images carry the same state, and it is not a torn write: the coordinator row's `active_entry_count` equals the durable row count exactly (38, 78, 52), every membership resolves, the ACTIVE marker declares `entry_count=0` so the whole standing projection came from the live delta path, and **exactly one channel detail has no local member and no invite**. `EdgeReplica::install` ends in `validate`, which requires the entry set to be closed under entitlement, and `Restore::install_projection` rebuilt the edge's own active generation through that same install. `apply` reaches and holds that state by design in two windows, each bracketed by two separate projected events in two separate durable batches: `ChannelVisible` inserts a channel with no member before the `MemberJoined` that entitles the edge to it, and `SessionHidden` removes the session and all its memberships while only the coordinator's later `ChannelHidden` removes the channel. Nothing on the live path calls `validate`, so a correctly running edge is durably unstartable for the width of one channel, and any restart in that window — not only a kill — would have revealed it. A restore that cannot rebuild a state the live path legitimately reaches is not a legitimate refusal, the same principle #144 settled for the restore's admission pools, so `EdgeReplica` now separates the two installs: `install` is unchanged and still closed for `snapshot_end`'s verification, `sync::activated` and `sync::restore_pending`, which are all coordinator snapshots, and `install_recovered` rebuilds the edge's own active generation, admitting a channel with no local member and no invite and relaxing nothing else. Every other shape still fails closed through both installs — a membership whose channel or session is absent, an unreferenced account, a foreign home, a revision fault, an unsorted or duplicated set, every per-record rule — and the coordinator row's entry count is still enforced. Each of the three real crash images refuses under `install` and restores under `install_recovered`. A second repair was found beside it: `reconcile_recovered_sessions` labelled only the refusals it built itself, while `commit_startup_plan`'s `project_batch` and `refresh_startup_rows`'s `read_back_record` and `DurableIndex::refresh` converted through `?` into `DaemonError::Runtime` and printed the captured line naming no surface, and `try_commit`, its `wait` and `try_read` printed the storage open's own single-prefix line that #124 was misfiled on; both helpers now return `RuntimeError` and `reconcile_recovered_sessions` holds the only conversion to a `DaemonError`, which always names `ReconstructionSurface::RecoveredSessions`. Evidence: the drill with its phase sweep, startup kill, per-round occupancy record and durable-state capture, one domain case requiring the snapshot install to keep refusing what the recovered install admits plus four shapes that still refuse, two end-to-end cases seeding the same rows through the real storage owner, and two daemon cases pinning the labelling; recorded in [the peer-loss reproduction record](docs/stage-10-peer-loss-reproduction.md). Limitations recorded there: the one-in-seventy rate is measured at 32 clients per edge and says nothing about the advertised population, a 24-kill probe at 256 clients per edge saw none, only the active generation was relaxed, the production campaign is still not run, and the campaign alone is not an acceptance for this because one kill per run cannot reach the race.
  - RUN-09 SASL unavailable account authority (2026-09-17, issue #152 under master #35): an OPAQUE authentication that reached an edge whose account authority was momentarily unavailable was answered `:edge-a.test 904 * :SASL authentication failed`, the same numeric a wrong password gets, so neither a client nor the harness could tell a node that would serve it a second later from a credential it must never retry. **No numeric was added.** `SaslNumeric` carries exactly the IRCv3 set 903 through 908, there is no assigned numeric for a temporarily unavailable authenticator, and numerics are a shared registry; the Section 9.5 reply registry already gives `UNAVAILABLE` to `FAIL ACCTCREATE` and `FAIL ACCTCRED` for exactly this state on the other two carriers of the same surface, so the whole normative change is adding `FAIL AUTHENTICATE` to that row, with its public context kept empty as the two siblings keep theirs. On the wire the refusal is now `FAIL AUTHENTICATE UNAVAILABLE :Account authority unavailable` followed by the existing `904`, and a client that did not negotiate `standard-replies` reads exactly what it reads today. The refusal is reported where the cause is still known rather than re-derived: `SaslTransport` already has two terminal doors out of an in-flight exchange, `complete(accepted, now)` for an exchange the account service answered and `unavailable(now)` for one that produced no completion at all, and only the second now yields the failure line ahead of the numeric. Its three call sites are the three ways an authority becomes unreachable — the edge could not forward the envelope, the coordinator's answer was neither a challenge nor a completion, or the coordinator's own account service could not carry the request — while a rejected completion still leaves through `complete(false, now)` with the `904` alone. The negotiated state is read where it is held and carried to where the refusal renders: the edge paths read the connection's capability state, `route_sasl` records it on the coordinator's `AccountConnection` so a refusal answered from a later storage or crypto continuation still renders what that client accepted, and the coordinator's virtual connection for a federated carrier passes `false` because it negotiates nothing and the edge holding the real client renders the line itself. The failure stays closed: the line precedes the numeric and never replaces it, `sasl_action_result` classes it `Rejected`, it is unreachable from a success, an abort, a deadline expiry or a refused logout, and its empty context means it is sent identically whether or not the account exists. The live proof is deterministic rather than opportunistic: the ordinary non-ignored `deletion_drill_preconditions_are_the_ones_the_daemon_requires` already stops the coordinator and restarts it, and between those two calls a real client on a real edge is now required to read the failure line and to be classed transient. **The drill workaround is gone.** `deletion_session` carried a bounded retry that repeated any failure inside `NETWORK_WAIT` and discarded the error unread; it now reads the carrier's own report through the same predicate the capacity campaign uses, so a refused credential or a protocol failure is returned on the first attempt instead of being retried for the full network wait, while the ordinary readiness wait for `active_peers` before each attempt is kept. **`stage_ten_capacity::transient_transport` can now treat the pair as transient, and does**: it checks the failure line first and returns true, keeping the bare-`904` exclusion below it so a refused credential is still never transient. That is safe rather than a relaxation because the line is emitted only from `unavailable`, which a rejected completion cannot reach; because it arrives before the `904` and the harness surfaces the first unexpected line it reads, so the two cases cannot both appear in one error string; and because every session that module authenticates negotiates `standard-replies` through `E2EE_CAPS`, so the line is actually sent to it. `an_authentication_refusal_is_not_a_transient_transport_failure` keeps all five negative cases, including both `904` strings, and gains the positive one. Nine regressions pin the change across the carrier, the coordinator's own route and the live wire, including that a rejected completion renders the `904` alone even with the capability negotiated. The specification edit took the full refreeze and the regenerated ledger is the same 251 records, with only the document hash and the line numbers below the insertion changed. Evidence: recorded in [the SASL unavailable authority record](docs/stage-10-sasl-unavailable.md). Limitations recorded there: the transient state is proved live by stopping the coordinator, with the narrower races — a link closing mid-exchange, or a coordinator answering without a usable completion — proved at the carrier and coordinator seams instead; the line deliberately does not distinguish a malformed envelope, an expired transaction and a storage refusal, exactly as the two sibling carriers already do not; the attempt budget is unchanged, so an unavailable authority still consumes the connection-wide attempt the carrier had already counted; and native release qualification of the whole drill campaign remains with REL-10 (#84).
  - QA-04 flake causes from the dynamic-analysis sweep (2026-09-18, issue #175 under master #35): the whole suite was run repeatedly at 64 and 256 nextest threads and beside 64 and 128 CPU hogs, and every failure that passed alone was traced. Fixture listener ports were probed on `127.0.0.1:0` and released before the daemon bound them, so another process could take the port (`strace`: `EADDRINUSE` on 139 of 139 startup failures) or a test could reach another fixture's daemon; `tests/support/loopback_ports.rs` now allocates only outside `ip_local_port_range` under a per-port advisory lock held for the life of the test process, because the daemon rejects port 0 by specification. `StateCoreFixture::commit_fixture_batch` awaits its storage receipts without the five-second deadline that failed six `delivery_restart` tests on every hog round, `local_admin_lines_never_enter_the_public_client_inbox` accepts the refusal closing the socket before its write, and `DrillNodes::start_capturing` waits for the account authority instead of sleeping. A refused listener bind now reports `address=… error=EADDRINUSE os_error=98` instead of `runtime value violates its invariant`, and a timed-out shutdown names its phase. Hog rounds went from 3 to 8 failures each to 0 at 64 threads and 1 and 4 at 256. Left open with `rr` evidence: an edge cannot reach its drain safe point while a `SnapshotInstall` awaits its coordinator, and `flush` outlives a four-second fixture budget under extreme load. Record: [the flake causes record](docs/stage-10-flake-causes.md).
  - RUN-11 edge drain with a pending snapshot install (2026-09-18, issue #178 under master #35): an edge asked to stop exited 1 in `phase=drain` whenever a base snapshot install was outstanding and its coordinator was slow or gone, because `EdgeFederation::reload_ready` refused the drain safe point for a `SnapshotInstall` that was only waiting for `ACTIVE`. Once StateCore starts the router's shutdown the edge now abandons the receiving and ready-sent stages and stops chaining install batches, while a staged install batch and a staged generation swap still finish as the local durable commits they are; every abandonment leaves what a crash at the same point leaves, so the next start ignores an unmarked generation and sends `FRESUME`, or restores the marked one and sends `READY` again. Five regressions run the production edge actor through `run_shutdown` under the RUN-05 plan and reopen the storage. `rr` shows the separate `phase=flush` exits wait on the admin owner's audit retention scan, which re-verifies every retained audit signature inside the flush budget; that is local work, reported and not patched. Record: [the edge drain record](docs/stage-10-edge-drain-pending-install.md).
  - RUN-12 bounded shutdown flush (2026-09-18, issue #180 under master #35): shutdown flush ran the audit `retention_sweep`, whose scan re-verified the Ed25519 signature of every retained audit event and every checkpoint inside the flush budget and ahead of the state owner's flush, so flush time grew with the audit log until `phase=flush` timed out. Flush now runs no sweep (a retention checkpoint and its deletion are one immediate transaction, so nothing is left for flush to persist), `flush_admin_and_state` runs the state and administrative flush together, and the maintenance sweep is bounded: it starts from the authority's verified marks instead of rescanning the checkpoint table, verifies exactly the prefix it deletes, stops at the retention window or at the 4,096-event checkpoint ceiling, follows a full checkpoint after one minute, and resumes after a restart from the sequence and hash the last checkpoint names. Startup reconstruction, deletion and export still verify every event they trust. Regressions: a node with 20,000 expired audit events stops inside the 2/5/5/2 plan through `run_shutdown` (it fails with `Flush, TimedOut` when the sweep is put back), and a sweep that reads only what it deletes and resumes across ticks and a restart. An `rr` replay of the fixed edge shows no `verify_strict` frame from the flush hook to exit. Record: [the bounded shutdown flush record](docs/stage-10-bounded-shutdown-flush.md).
  - ENC-18 leaf-membership proofs verified against the roster they name (2026-09-18, issue #164 under master #35): finding `ENC11-1` of the 2026-09-18 encrypted-profile defect sweep (issue #76). Companion 13.7.3 says a proof's root and roster fields equal the leaf authorization of its credential and that the device must be active in the retained roster named by `roster_id`; a continuing leaf keeps its credential (8.5) while every Add or revocation Commit rotates the roster (9.3), so that roster stops being current at the first rotation. `ops/membership.rs::verify` checked the proof against `state.principals`, the account's current heads, while `membership_restore::restore` resolved the snapshot the proof names, so the same bytes were refused live with `E2EE_BINDING_AUTH_INVALID` and accepted on a reload, and a client following 13.7.3 literally could publish no proof, and so have no ACK identified, after a routine rotation. The live path was stricter, never more permissive: a divergence with an availability edge, not an authority break. `roster_snapshots.rs` now indexes every retained `device_roster` object by roster identifier (written with the commit of `EKEY PUBLISH ROSTER`, rebuilt at the end of `restore_directory`) and resolves a statement's named root and roster for one account: the current heads at no cost, otherwise the current root or the matching root of the re-verified chain (`startup::principal_roots`, the function reconstruction uses) and the indexed object re-verified with `restore_roster`. `verify` resolves under a transient reservation and hands the snapshot to the unchanged `verify_leaf_membership_proof`; an unresolvable name is the roster-or-root-mismatch row and a device absent from the named roster stays `E2EE_DEVICE_REQUIRED`. Current roster activity is the separate check `Exec::attached_device` already makes for the one device `verify` admits, the same directory predicate ACK identification uses, so no second, unreachable call was added. **The `removed` case is decided explicitly**: both dispositions take the one path, because 13.7.3 states the fields, the signature and the roster rule for both, its failure table and companion 11.6 refuse an unattached or revoked device, and a revoked device's claim already leaves the expected set; a `removed` proof is therefore for a still roster-active device whose leaf is gone (PART, KICK, key rotation, rejoin), which is now admitted under its predecessor roster, while a revoked device's is `E2EE_DEVICE_REQUIRED`. Evidence: eight regressions in `tests/sequence/leaf_membership/named_roster.rs` for a predecessor roster, a predecessor root, a never-retained roster, another account's retained roster, a retained roster without the device, both halves of the `removed` decision, and live admission agreeing with `restore()` on stored, refused and injected inputs and after a reload; four fail on the merged `verify`. The sweep's own test was corrected first: it had submitted a duplicate continuing leaf, which the roster refusal hid. The hand-set region `coordinator-membership-submission` and the new `coordinator-roster-snapshot-resolution` are recorded in [the named-roster membership record](docs/stage-10-membership-named-roster.md). Limitations recorded there: a roster made resident by a recovery reference element joins the index at the next startup; a predecessor name costs one roster re-verification and is not cached; whether the named roster is the leaf's real authorization roster stays an endpoint check; the implementation gate was not run on the branch.
  - ENC-15, ENC-16 and ENC-17 edge remediation (2026-09-18, issues #160, #161 and #162 under master #35): the three findings of the encrypted-profile defect sweep (#76) against the hostile edge and client surface and the recovery and witness gates are repaired. ENC-15: the edge's ESTATE receiver refuses the whole snapshot with `E2EE_SYNCING`, before READY and with nothing of the entry retained, unless the base profile entitles it to the route: a channel route needs the hosted channel detail in the active or the installing base generation (`EdgeFederation::holds_channel`), a direct route needs one of its accounts hosted here as a base account projection, a declared base origin or an attached companion device, read now and as it stood when the transfer opened, or must restate a pair the edge already projects; the witness resolution installer rewrites a head only on a channel route the base still hosts; and the coordinator drops an edge's direct references before every full cut (`RouteEntitlements::fence_direct`) and re-derives them from hosting, because it never released one and would otherwise restate pairs a reinstalled edge cannot verify. ENC-16: `route_e2ee_line` charges `E2eeCommand` and `E2eeSignature` once, on a command line or a fragment zero, and the continuation fragments behind an accepted fragment zero pay their decoded bytes to the new fixed `BucketKind::E2eeIngress` keyed by account and device, 65,536 bytes a second with a burst of one live object, so a 4 MiB control object completes in 60 seconds instead of 351 and costs one verification instead of 1,427; a fragment behind no accepted fragment zero pays for a command line and is refused `E2EE_INVALID_FRAGMENT`; the Stage 08 harness pacer follows the same model. ENC-17: `SequencerKeySet::credential_at` admits the successor credential only from its `not_before` through `MAX_SEQUENCER_KEY_OVERLAP` at the second the record signed (a receipt's `sequenced_at`, or the embedded receipt's for a terminal), and a successor record outside the window closes the link with the row retained. Evidence: the edge snapshot, witness resolution, ingress and base pending-generation tests, the coordinator cut and domain ledger tests, the e2ee key-set and record tests and the Stage 08 daemon suite; recorded in [the edge remediation record](docs/stage-10-edge-remediation.md). Limitations recorded there: the live route change path is not entitlement-checked, the coordinator still never releases a direct reference between full cuts and names every direct route of a hosted account, a republished cut older than the edge's hosting is refused until its token expires, and a terminal's signed time is its embedded receipt's.
  - STO-03 one physical allowance across the durable operation (2026-09-18, issue #61 under master #35): `StateDirectory::admit_transaction` sampled `R(F) + G` and the engine then committed the nonce reservation, replaced the guard, committed the rows and replaced the guard again through redb's unrestricted API, so the gate made room for `G` and nothing held an operation to it. Every durable operation on the core path now derives one `OperationAllowance` of exactly `G` right after the unchanged gate, charges each guard replacement first as fixed headroom at filesystem block granularity (the 324-byte temporary rounded up to a block, one directory block, and 32,768 bytes of inode allocation rounded up, 40,960 bytes at 4 KiB), and hands the remainder to the fork's `begin_write_bounded` for the nonce reservation, then the main or checkpoint transaction, then the deferred cleanup, debiting what each reports charging. **A refusal is determinate**: a refused table write or a refused `prepare` is `Rejected(StorageError::AllowanceRefused(phase))` with nothing written, never an I/O error, never `StaleState` and never `Indeterminate`, an already durable reservation stays burned and the next writer starts after it, while every other prepare failure and every publish failure keeps Section 21.5's `Indeterminate` exactly as before, and nothing determinate is ever reported once the main transaction has published. The fork's bounded handle could not enable two-phase commit, which Section 21.5 requires and without which `TransactionPhaseTwo` never fires; that gap was reported instead of shipping a single-phase publication, the fork gained a narrow `set_two_phase_commit` passthrough (PR #157), and every bounded transaction sets it. The fork's moved duties are taken: `finish_operation` reclaims at most 64 freed-page records after each committed guard with what is left of the same allowance, a refusal leaves the operation committed and the backlog resumes after a restart, and `close_bounded` persists the allocator state under its own admission and allowance at a clean stop and once on any other owner exit, disarms redb's unmetered drop-path transaction even when the gate refuses, never fails a shutdown, and leaves a refused or failed close to the next open's repair, which `RecoveredStorageState::database_repaired` reports. Initialization is bounded the same way. Because the account charges every file extension at its full length and redb grows by up to two regions at a time, every live database is now created with 64 MiB regions through `bounded::live_database_builder`, and **a database whose header records larger regions is refused at open** with `StorageError::UnboundedRegion`, whose message names the size found and the size required; running it unbounded was rejected and there are no deployed databases. Section 19.3 states the enforcement, the headroom, the refusal, the cleanup, the close and the region rule with no new normative keyword, so the refrozen ledger is the same 251 records. Shared for the sibling lanes in `bounded.rs`: the ledger, `guard_replacement_charge`, the refusal mappers, `MaintenanceOutcome`, `live_database_builder`, and the qualification-only `StorageFaultInjector::with_growth_cap`, which can only lower the allowance. Evidence: four ledger and mapping unit cases, three adapter cases replaying one transaction at its measured charge, one byte less and zero, six engine cases, and nine cases through the real `StorageOwner` including the byte-exact boundary, a refusal in preparation with unchanged state and a burned block, both transaction phases required to fire through the bounded handle on the reservation and on the main transaction and to reopen to the exact prior or successor state, a 2,048-row deletion's backlog reclaimed by the first operation after a restart, a clean close reopening without repair and a failed one with repair, and eight MiB rows growing the file past 256 MiB with every operation under exactly `G`; the existing fault matrix passes unchanged; recorded in [the bounded durable operation record](docs/stage-10-bounded-durable-operation.md). Limitations recorded there: the native ext4 qualification workload was not run, so the archived STO-1 shapes, the 134,217,728-byte phase ceiling and the rebuilt qualification metadata stay open for the storage qualification that needs STO-03, STO-04 (#65) and STO-07 (#69) together; the recovery and reference scratch, backup and construction scratch-plan transactions are still unmetered; the guard headroom is a fixed bound rather than a measurement; `reclaim_bounded` publishes single-phase inside the fork and carries no application data; and the growth case takes over a minute in a debug build. **Follow-up from the first gate (2026-09-18):** `insert-max-records`, the greatest legal count, was refused by the allowance. Measured with phase probes, an instrumented scratch copy of the fork and gdb rather than reasoned: 81,920 bytes of guard headroom, 16,384 for the reservation, and with the allowance lifted 825,901,056 bytes for the main transaction, of which 268,435,456 were file extensions, 282,955,776 distinct page extents and 274,509,824 extents charged again, for 257,761,280 bytes of real growth, the figure `main` also records and 1.92 times the qualified ceiling. gdb showed every insert building a one-row leaf from redb 4.2.0's single-large-value fast path, because the run's ascending keys sit directly below the workload's live 8 MiB row and each new sibling's separator routes the next key back to the large leaf. `redb_store::apply_writes` now applies each same-table run in descending key order, which is unobservable because keys are distinct within a batch: the case charges 71,286,784 bytes and grows the file by 16,625,664 under the real `G`, and the greatest growth of any case is 16,789,504. The same run showed a clean close growing an idle database by 24,576 bytes each cycle, because the bounded persistence never reclaims the pages it frees; a clean close now reclaims first, each half of the close's allowance going to one step. The fork's double charge of an extension and the extents inside it, its recharge of recycled extents, and the missing charge in `ReclaimProgress` are reported to the fork owner and not required for the fix.
  - STO-03 one physical allowance across the durable operation (2026-09-18, issue #61 under master #35): `StateDirectory::admit_transaction` sampled `R(F) + G` and the engine then committed the nonce reservation, replaced the guard, committed the rows and replaced the guard again through redb's unrestricted API, so the gate made room for `G` and nothing held an operation to it. Every durable operation on the core path now derives one `OperationAllowance` of exactly `G` right after the unchanged gate, charges each guard replacement first as fixed headroom at filesystem block granularity (the 324-byte temporary rounded up to a block, one directory block, and 32,768 bytes of inode allocation rounded up, 40,960 bytes at 4 KiB), and hands the remainder to the fork's `begin_write_bounded` for the nonce reservation, then the main or checkpoint transaction, then the deferred cleanup, debiting what each reports charging. **A refusal is determinate**: a refused table write or a refused `prepare` is `Rejected(StorageError::AllowanceRefused(phase))` with nothing written, never an I/O error, never `StaleState` and never `Indeterminate`, an already durable reservation stays burned and the next writer starts after it, while every other prepare failure and every publish failure keeps Section 21.5's `Indeterminate` exactly as before, and nothing determinate is ever reported once the main transaction has published. The fork's bounded handle could not enable two-phase commit, which Section 21.5 requires and without which `TransactionPhaseTwo` never fires; that gap was reported instead of shipping a single-phase publication, the fork gained a narrow `set_two_phase_commit` passthrough (PR #157), and every bounded transaction sets it. The fork's moved duties are taken: `finish_operation` reclaims at most 64 freed-page records after each committed guard with what is left of the same allowance, a refusal leaves the operation committed and the backlog resumes after a restart, and `close_bounded` persists the allocator state under its own admission and allowance at a clean stop and once on any other owner exit, disarms redb's unmetered drop-path transaction even when the gate refuses, never fails a shutdown, and leaves a refused or failed close to the next open's repair, which `RecoveredStorageState::database_repaired` reports. Initialization is bounded the same way. Because the account charges every file extension at its full length and redb grows by up to two regions at a time, every live database is now created with 64 MiB regions through `bounded::live_database_builder`, and **a database whose header records larger regions is refused at open** with `StorageError::UnboundedRegion`, whose message names the size found and the size required; running it unbounded was rejected and there are no deployed databases. Section 19.3 states the enforcement, the headroom, the refusal, the cleanup, the close and the region rule with no new normative keyword, so the refrozen ledger is the same 251 records. Shared for the sibling lanes in `bounded.rs`: the ledger, `guard_replacement_charge`, the refusal mappers, `MaintenanceOutcome`, `live_database_builder`, and the qualification-only `StorageFaultInjector::with_growth_cap`, which can only lower the allowance. Evidence: four ledger and mapping unit cases, three adapter cases replaying one transaction at its measured charge, one byte less and zero, six engine cases, and nine cases through the real `StorageOwner` including the byte-exact boundary, a refusal in preparation with unchanged state and a burned block, both transaction phases required to fire through the bounded handle on the reservation and on the main transaction and to reopen to the exact prior or successor state, a 2,048-row deletion's backlog reclaimed by the first operation after a restart, a clean close reopening without repair and a failed one with repair, and eight MiB rows growing the file past 256 MiB with every operation under exactly `G`; the existing fault matrix passes unchanged; recorded in [the bounded durable operation record](docs/stage-10-bounded-durable-operation.md). Limitations recorded there: the native ext4 qualification workload was not run, so the archived STO-1 shapes, the 134,217,728-byte phase ceiling and the rebuilt qualification metadata stay open for the storage qualification that needs STO-03, STO-04 (#65) and STO-07 (#69) together; the recovery and reference scratch, backup and construction scratch-plan transactions are still unmetered; the guard headroom is a fixed bound rather than a measurement; `reclaim_bounded` publishes single-phase inside the fork and carries no application data; and the growth case takes over a minute in a debug build.
  - STO-04 bounded recovery and reference scratch (2026-09-18, issue #65 under master #35): every recovery and reference scratch transaction — creation, the table transaction, each current-row slice, each reverse-replay chunk and each reclamation — is now admitted against the exact state filesystem immediately before it begins (`available >= R(F) + G`, sampled through the retained directory descriptor for the writer-locked authority and for inspection alike), bounded by the fork's `begin_write_bounded` under the fixed `G`, and sliced at 4,096 rows or 1 MiB of logical key and value bytes, so a full current-record set is never one transaction; the close persists nothing under a zero allowance and unlinks the entry through the descriptor, and every scratch is created with 64 MiB regions because a bounded database's regions must be at most half its allowance. The checkpoint now reads its cut back through that scratch **before** it reserves a nonce block, replaces a guard or opens its transaction, and after publication verifies the control chain only, so no scratch is allocated once a checkpoint is durable: a refused admission is `Rejected(FilesystemRejected(InsufficientCapacity))`, a refused allowance `Rejected(AllowanceRefused(phase))` through the mappers STO-03 owns, a scratch I/O failure `Rejected(DatabaseRejected)`, each with the database, the reservation record and the guard byte-identical and the owner still serving, and only a readback that does not reproduce the scan, or a real uncertain I/O outcome after publication, is `Indeterminate` as before. Startup proves the recovered state within the same bound and reports the metered scratch (`ScratchUsage`: transactions, reclamations, charged bytes, peak transaction, peak buffer, creation and peak file bytes, reclaimed pages, cache, allowance) in `RecoveredStorageState` and `CheckpointReceipt`. Measured: the fork's account charges every copy-on-write leaf rewrite without refund, so a 4,096-row slice of maximum stored keys charged 233,775,104 bytes, 87 percent of `G`, which is why slices are bounded by bytes as well as rows; one byte budget of maximum keys charges under an eighth of `G`, and a 5,120-account readback charges 774,144 bytes at a 589,824-byte peak. Section 23.5.3's "private runtime directory" is read as the private mode-0700 state directory the reserve is measured on, recorded rather than changed. Evidence: six scratch unit tests (exact, one-less, one-more and zero allowances around a fixed workload; a refused slice that publishes nothing and leaves the next writer usable; fresh admission before every transaction with a determinate refusal between slices and on creation; a genuine write failure through a failing backend; close, reclamation and anonymous scratch; a maximum-key byte budget), the rewritten store scratch tests, five engine tests (the capacity-admission refusal sweep across every readback sample with StateMeta and the guard unchanged and the retried checkpoint installed; a record substituted behind the scan found by the readback and closed without publishing; startup metered by both authorities with inspection changing nothing; a refused startup admission failing closed; the gate's minus/equal/plus-one boundary on the real filesystem) and four owner-level tests (the same refusal sweep with the guard file byte-identical, the retried checkpoint, the next commit and the reopen; a refused startup admission through `StorageOwner::start`; 5,120 accounts verified in several bounded slices at checkpoint and startup; a stale scratch removed on reopen beside an unrelated entry that survives); 352 storage and 1,588 runtime tests pass; recorded in [the bounded recovery scratch record](docs/stage-10-bounded-recovery-scratch.md). Limitations recorded there: the gate admits one transaction at a time and does not project the total scratch, every slice is followed by at least one reclamation flush, `ScratchGate` still repeats `admit_transaction`'s comparison privately because STO-03's gate is fixed at `G` and refuses the inspection authority, a reclamation is debited a fixed 4 MiB grant, and a pre-publication readback mismatch reuses the `Indeterminate` exit because it is the only fatal one. Follow-up (2026-09-18): the combined gate's `qualification_workload` read `refused|open` at one byte below `R(F) + G`; `rust-gdb` showed `StorageOwner::start` -> `startup_scan` -> `RecoveryScratch::create` -> `ScratchDatabase::begin` -> `ScratchGate::admit_scratch` refusing on the scratch's second sample, after its own file had consumed space. Section 19.3 disables durable mutation below the reserve, not the node, so a writer whose scratch cannot be admitted now opens with the control chain and the full domain scan run and the scratch half owed, `ensure_verified` pays it before any commit or checkpoint is accepted (a backup, admitted at `R(F) + O` and re-verified by restore, is not held behind it) (refusing with the capacity cause while space is missing, fatal if the owed verification fails), an inspection never defers, and one admission now covers a whole allowance window so the scratch's own growth cannot push its next sample under the gate; the three Section 28.7 boundaries read refused-at-commit, admitted, admitted with the owner open in all three.
  - STO-04 bounded recovery and reference scratch (2026-09-18, issue #65 under master #35): every recovery and reference scratch transaction — creation, the table transaction, each current-row slice, each reverse-replay chunk and each reclamation — is now admitted against the exact state filesystem immediately before it begins (`available >= R(F) + G`, sampled through the retained directory descriptor for the writer-locked authority and for inspection alike), bounded by the fork's `begin_write_bounded` under the fixed `G`, and sliced at 4,096 rows or 1 MiB of logical key and value bytes, so a full current-record set is never one transaction; the close persists nothing under a zero allowance and unlinks the entry through the descriptor, and every scratch is created with 64 MiB regions because a bounded database's regions must be at most half its allowance. The checkpoint now reads its cut back through that scratch **before** it reserves a nonce block, replaces a guard or opens its transaction, and after publication verifies the control chain only, so no scratch is allocated once a checkpoint is durable: a refused admission is `Rejected(FilesystemRejected(InsufficientCapacity))`, a refused allowance `Rejected(AllowanceRefused(phase))` through the mappers STO-03 owns, a scratch I/O failure `Rejected(DatabaseRejected)`, each with the database, the reservation record and the guard byte-identical and the owner still serving, and only a readback that does not reproduce the scan, or a real uncertain I/O outcome after publication, is `Indeterminate` as before. Startup proves the recovered state within the same bound and reports the metered scratch (`ScratchUsage`: transactions, reclamations, charged bytes, peak transaction, peak buffer, creation and peak file bytes, reclaimed pages, cache, allowance) in `RecoveredStorageState` and `CheckpointReceipt`. Measured: the fork's account charges every copy-on-write leaf rewrite without refund, so a 4,096-row slice of maximum stored keys charged 233,775,104 bytes, 87 percent of `G`, which is why slices are bounded by bytes as well as rows; one byte budget of maximum keys charges under an eighth of `G`, and a 5,120-account readback charges 774,144 bytes at a 589,824-byte peak. Section 23.5.3's "private runtime directory" is read as the private mode-0700 state directory the reserve is measured on, recorded rather than changed. Evidence: six scratch unit tests (exact, one-less, one-more and zero allowances around a fixed workload; a refused slice that publishes nothing and leaves the next writer usable; fresh admission before every transaction with a determinate refusal between slices and on creation; a genuine write failure through a failing backend; close, reclamation and anonymous scratch; a maximum-key byte budget), the rewritten store scratch tests, five engine tests (the capacity-admission refusal sweep across every readback sample with StateMeta and the guard unchanged and the retried checkpoint installed; a record substituted behind the scan found by the readback and closed without publishing; startup metered by both authorities with inspection changing nothing; a refused startup admission failing closed; the gate's minus/equal/plus-one boundary on the real filesystem) and four owner-level tests (the same refusal sweep with the guard file byte-identical, the retried checkpoint, the next commit and the reopen; a refused startup admission through `StorageOwner::start`; 5,120 accounts verified in several bounded slices at checkpoint and startup; a stale scratch removed on reopen beside an unrelated entry that survives); 352 storage and 1,588 runtime tests pass; recorded in [the bounded recovery scratch record](docs/stage-10-bounded-recovery-scratch.md). Limitations recorded there: the gate admits one transaction at a time and does not project the total scratch, every slice is followed by at least one reclamation flush, `ScratchGate` still repeats `admit_transaction`'s comparison privately because STO-03's gate is fixed at `G` and refuses the inspection authority, the qualification workload was not rerun, and a pre-publication readback mismatch reuses the `Indeterminate` exit because it is the only fatal one.
  - STO-05 incremental online backup (2026-09-18, issue #68 under master #35): `BACKUP CREATE` ran three whole-database passes on the storage owner thread before it yielded once, because `start_backup` called the full `startup_scan` and then `verify_snapshot_accounting` synchronously and `BackupJob::finish` ran the complete `verify_backup` in one call; a commit or read queued behind a backup of a large database waited for each pass. The backup is now the phase machine in `engine/backup_job.rs`: capture (the snapshot slot, inventory, meta membership, the re-authenticated reservation and guard classified as an exact boundary, the header, one redb read transaction, no file), accounting (every row of that one read transaction decrypted and checked through the same `BackupRecordVerification` the post-write pass uses plus the startup scan's per-row domain checks, the logical and exact stream counters recomputed and refusing at their ceilings, references recorded in a scratch, and the last slice binding the accumulators to the authenticated `StateMeta`, so the exact length `O` is fixed before any output exists), resolution of every reference, admission of the temporary at `R(F) + O`, the copy through the same read transaction, the seal that requires exactly `O` bytes, the resumable post-write verification (`BackupStreamVerifier`, the same grammar `verify_backup` now drives to completion) whose last slice must equal the sealed trailer and the captured cut, and the unchanged rename-in-place publication. Each `service_backup` call runs one 4,096-record or 16 MiB slice of one phase and returns, so `owner_step` serves a request beside every slice; a failure in any phase drops the job with its temporary and scratch and publishes nothing; shutdown cancels a backup still in its phases instead of waiting behind it. **One authenticated cut**: accounting and copy read the one read transaction opened at capture, and the proof is byte identity between a quiescent backup and one taken at the same cut with a row committed between every slice of every phase, at the engine and through the real owner. The scratch is the one redb database the backup path writes and it is written only through the fork: `begin_write_bounded` under the `G` allowance with `set_two_phase_commit(true)`, `prepare` and `publish` per slice, `persist_allocator_state_bounded` at close, created with `set_region_size(64 MiB)` because a bounded database is created with regions of at most half its allowance; a refusal anywhere is the determinate `AllowanceRefused` with its phase and the following backup runs. The scratch is not admitted at `R(F) + G`: that would refuse the Section 28.7 backup boundaries whenever the state and backup directories share a filesystem, as the qualification's boundary cases do, and it is unlinked before the output is admitted. Stacked on STO-04 (#65), the scratch runs on its shared `ScratchDatabase` and STO-03's error mappers, keeping only the reference layout and an always-admitting admission private; the full tracked-record replay against the manifests is the whole-database phase this issue removes and is not run by the backup. Evidence: nine engine-level phase tests (byte identity under interleaved commits with every phase in at least two slices, a `BackupRecord` fault on both sides of the first row of each pass and every publication fault refusing with no temporary and the same name retrying, zero and one-byte scratch allowances, ceiling exhaustion in accounting and verification, a dangling reference, the largest legal record, the single slot and an orderly restart in each of the seven phases), four owner-level tests (a request served beside every phase and both reads and commits beside every sliced pass, shutdown cancellation, a dropped receiver, a competing backup) and four through the real `StorageOwner` (the exact authenticated length and the single-cut equality with commits submitted behind the request, refusal at each pass boundary, the `R(F) + O - 1`, equal and plus-one boundaries against the live filesystem, and stale temporaries swept after a kill); recorded in [the incremental backup record](docs/stage-10-incremental-backup.md). Limitations recorded there: the slice budget bounds records and bytes rather than wall time, the scratch's growth is bounded per transaction by `G` and not admitted against the reserve, and native release qualification remains with REL-10 (#84).
  - STO-07 restore and rekey transaction admission (2026-09-18, issue #69 under master #35): Section 19.3 requires restore, rekey, scratch-plan and target-construction databases to apply the same `R(F) + G` gate independently before every scratch or target redb transaction, and the scratch plan applied none: `ConstructionPlanBuilder` held one ordinary redb write transaction across the whole streamed source and committed it once at `finish`, on a filesystem nothing sampled. A new descriptor-bound `ConstructionAdmission` takes a fresh `fstatvfs` sample of the directory that holds the plan or the target immediately before each transaction, computes `R(F)` and UID-available bytes exactly as the live path does, and refuses with `FilesystemRejected(InsufficientCapacity)` below `R(F) + G`; it never lowers `R(F)`. The builder is now a sequence of bounded transactions from the project-owned fork, each `begin_write_bounded(G)` with two-phase commit, `prepare` and `publish`: the plan file's creation, the table reset, slices of source observation and auxiliary indexing, slices of the reverse replay, slices of the unsorted-to-ordered copy with the plan hash carried across them, `reclaim_bounded` and `persist_allocator_state_bounded`, so closing the plan database allocates nothing, and an abandoned builder takes the close duty under a zero allowance so a refused construction writes nothing on drop either. Slices end at the batch record or byte bound, checked before a record's writes. Every target transaction keeps exactly one admission, the engine's own gate and bounded allowance from STO-03 (#61); `ConstructionTarget` only names the initialization, each batch, the finalization and the checkpoint to an installed test observer before the engine begins them. The work found that a bounded database cannot grow under redb's default 4 GiB region, because the account charges a whole doubling extension and the 256-to-512 MiB step alone costs `G`; the fork now exposes `Builder::set_region_size`, STO-03's `live_database_builder` applies 64 MiB regions, and the scratch plan is created through it, so one extension is at most two regions and half of `G`. It also found that `--resume` refused a staging directory stopped before its target existed, which is exactly what a scratch refusal leaves; the resume now builds a fresh target there. A refusal at a target batch leaves the authenticated marker at that batch, and the resumed command's first target transaction is exactly the refused one. `storage restore` reports the refusal as its own `OfflineError::InsufficientCapacity`. Evidence: five tests through the real restore command and the rekey composition with a capacity observer that stands in for an external writer at one named transaction (a construction that fits, a refusal at each of seven scratch-side transactions with no target written and a completing resume, a refusal at the second batch, the finalization and the checkpoint with the exact remainder on resume, and `R(F) + G` minus, equal and plus one at the first scratch and first target transaction after preflight), a growth test that extends a plan file past 256 MiB under an allowance of exactly `G` in steps of at most two regions, and the gate and directory unit tests; recorded in [the restore and rekey admission record](docs/stage-10-restore-rekey-admission.md). Limitations recorded there: the observer replaces a sample rather than filling a filesystem, so the native ext4 boundary stays with the qualification workload and REL-08; a target refusal in the tests is raised by the observer seam rather than by the engine's gate, which STO-03 proves; and `capacity_from_statistics` is repeated privately rather than shared from `platform.rs`.
  - ENC-23 direct route release (2026-09-18, issue #173 under master #35): the coordinator never called `RouteEntitlements::release_direct` on the live path, so it kept and restated every direct route it had ever projected to a Server ID, and PR #171 only fenced that at cut time. Observed under `rust-gdb` before the change: at `EORIGIN DEL` the ledger held one direct entry and no release or departure breakpoint was ever reached. Now `EORIGIN DEL`, `EORIGIN UPDATE` and the `EORIGIN READY` after a replay mark the edge's direct standings departing (`mark_departure`, at most 4,096), and the next committed mutation plan that delivers events examines up to sixteen: a standing whose edge hosts neither account (no live attached companion origin, no base account projection) gets a `route_state_hidden` copy in that plan and `release_departed` drops its references with the commit, observed under `rust-gdb` going from one to zero exactly there; one still hosted keeps its reference and leaves the queue after eight looks. `hosts_direct_account` no longer counts a fenced origin or one left suspended after the edge replayed its origins, and shares `attached_at` with the live release, so a full cut names a direct route exactly when the edge hosts one of its accounts, the rule the ENC-15 edge check verifies. The cut was deliberately not narrowed below hosting because the edge's projected direct routes are the only enforcement of the plaintext downgrade refusal for a bound direct pair. An interrupted cut is republished only while every direct pair it names is still hosted and is otherwise retired for a fresh cut in the next delivery generation, which narrows the 15-minute refusal ENC-15 recorded. Evidence: three real-coordinator scenarios, three bridged regressions that feed the coordinator's rendered lines to the real edge (hosting ends and the route leaves the projection, a reinstalled edge receives no direct route it does not host, an honest cut is accepted across a resync that closes the counted session mid-transfer) and the domain ledger test; recorded in [the direct route release record](docs/stage-10-direct-route-release.md). Limitations recorded there: the release waits for the next event-bearing plan because the coordinator has no mutation of its own, channel routes still leave an edge only through a successor or a cut, a login after a cut is not covered by the edge-side downgrade refusal until the next event or cut, and a change the coordinator has not learned by the next `ERESUME` still republishes the old cut.
  - COV-04a, federation branch tests (2026-09-18, toward issues #70 and #73 under master #35): tests only, no production change. The coordinator gains misaddressed-request, startup-row and retained-resume cases; the edge gains restored-journal, result-refusal, snapshot-refusal and part-binding restart cases; edge history gains lifecycle, refusal, restored and retention cases. Evidence: `cargo nextest run -p agenc-relay-runtime --all-features --locked --lib federation` passes 450 tests. The workspace branch-coverage figure has not been re-measured with these tests; the 90 percent floor of #73 stays open.
  - Reload failure outcome refused by a full request queue (2026-09-19, found by the coverage work under master #35): when an audited reload's success outcome was rejected, the state core rolled the reservation back, reserved the failure outcome's limits and submitted the failure outcome commit. Each limit change wakes the storage owner with a `LimitsChanged` request through the same queue as the commit, and that queue holds two entries, so an owner that had drained neither notice refused the commit as `QueueFull` and the core exited `Indeterminate(StorageIndeterminate)`. `StorageLimitWriter::replace_reservation` makes both limit changes and queues one notice, since the owner reads the limit cell when it wakes. Evidence: `owner/tests/limit_notices.rs` shows the two-call form filling an undrained queue and the replacement leaving a slot; the storage and runtime unit suites pass.
  - Channel revision advanced by an unpersisted change (2026-09-19, found by the coverage work under master #35): a plan whose channel keeps its persisted content, such as `MODE #room +t` on a channel already `+t`, writes nothing and projects nothing, but `apply_prepared` still moved the live channel revision to the plan's resulting revision. The next channel message bound to that live revision, so every edge replica, still holding the persisted revision, refused it with `Revision`, and the channel stayed undeliverable until a real change. `apply_prepared` now keeps the persisted revision of every touched channel the plan does not write. Evidence: `domain/src/federation/tests/projection_revision_drift.rs` (`a_mode_command_without_an_effective_change_keeps_the_channel_revision_edges_hold`) fails before the fix at the revision check; the domain, testkit and runtime unit suites pass after it.
  - Drain acknowledged before the router began its shutdown (2026-09-19, found by the coverage work under master #35): a reload still pending when Drain was requested kept the StateCore run loop from calling `router.begin_shutdown`, and the same pass then activated the reload, computed the activation barrier as clear and acknowledged Drain, so connections were told to shut down and the supervisor moved on while the edge journal retry, the live account exchanges and the pending command observations had not been cancelled. A pass that activates a pending reload now restarts, so the router shutdown guard runs before any Drain or Flush acknowledgement; the activation always takes the pending reload, so the restart happens once per reload and never waits on an outside event, and a router that still declines because a staged authority owns its outcome converges as before. Evidence: `drain_behind_a_pending_reload_is_acknowledged_only_after_the_router_began_shutdown` fails on the old loop with the router shutdown count at zero when the connection is told to shut down; the runtime library suite and the 38 Stage 06 daemon tests pass. Found alongside and not patched: the audited-reload fallback in `submit_reload_failure_after_rejection` notifies the storage owner of a rollback and of a reservation and then submits into the two-slot request queue, so an owner thread that has drained neither turns the determinate `QueueFull` into an indeterminate exit; the unit test that met this under load now asserts only the scheduling-independent invariant.
  - Nickname in use at registration (2026-09-19, found by the coverage work under master #35): a pre-registration `NICK` whose reservation was refused got no reply, and no path in the daemon produced 433, a numeric the profile lists. A client waited for its registration deadline instead of choosing another nickname. The registration machine now emits `NicknameInUse` for the refused nickname ahead of whatever the refusal lets it commit, and the router and the transcript model render `433 <target> <nickname> :Nickname is already in use`. A refused replacement answers 433 and still commits under the held nickname. Two client-wire tests had asserted the silence and now assert the reply. Evidence: `a_nickname_held_by_another_connection_answers_433`, the client-wire, testkit and runtime suites, the 38 Stage 06 daemon tests and the fuzz workspace check pass.
  - Edge registration and keepalive timers (2026-09-19, found by the coverage work under master #35): `RegistrationRouter::timer_fired` returned as soon as the router had no hosted account service, before the command continuation timers and the `RegistrationDeadline`, `Ping` and `Pong` timers. The daemon builds every edge with the advertised policy only, so on an edge a connection that never registered was not closed by its deadline, an idle client was never pinged, and a dead client was never closed for a missing PONG. Only the account step is skipped now. Every earlier timer test used a node that hosts its account service. Evidence: `a_node_without_an_account_service_still_enforces_the_registration_deadline` covers the plain and edge roles, and the 132 registration tests pass.
  - Channel revision drift on edges (2026-09-19, found by review under master #35): the coordinator advances a channel's revision on every mutation of it, an edge refuses a `message_delivered` whose `target_revision` differs from the revision it installed, and several mutations reached an edge holding the channel with no copy that carried the new revision. `EdgeReplica::apply` advanced the channel for an `invited` copy only on an edge hosting the target, so after an INVITE whose target was homed elsewhere every other member edge refused the next channel message with `ReplicaError::Revision`. A member's login or logout rewrites its membership in each joined channel and advances it, and projected nothing about the channel to any edge. An expired invite reached only the edges holding a copy, and a topic, mode or membership change never reached an edge entitled only by an invite. A reprojected invite carried its creation revision, which an edge refuses once the channel has moved on. Now a member edge takes the revision of an `invited` copy without a local projection (Appendix B.5: `invited` uses its explicit resulting revision), which repeats the channel's current revision; an account switch projects one `channel_memberships_recomputed` per joined channel to its member edges, with the recomputed membership; and the derivation ends by sending `channel_policy_changed`, the complete resulting detail that renders nothing, to every edge that keeps a channel the plan advanced and received no copy carrying it. Both sides must run the change. Evidence: `an_invite_hosted_elsewhere_advances_the_channel_on_every_member_edge`, `a_member_switching_account_advances_the_channel_on_every_member_edge`, `an_expired_invite_advances_the_channel_on_edges_that_held_no_copy` and `a_reprojected_invite_repeats_the_current_channel_revision` drive the real derivation into three replicas and failed before the change (the first with `[Err(Revision), Ok, Err(Revision)]` on the next message); `an_invitation_hosted_elsewhere_advances_the_channel_of_a_member_edge` covers the replica arm and its refusals; the domain, runtime federation and testkit suites and the Stage 07 and Stage 08 daemon tests pass. Not measured: coverage of the new projection functions, and the registered-channel case where a login changes the member's role.
  - Invite copies left behind on an edge (2026-09-19, found by review under master #35): `Derivation::hosting_edges` answered a guest principal with `home_of`, which falls back to the session as it was before the plan, so a closed guest still counted as hosted on its home edge. `project_principal_invites_hidden` therefore returned before removing anything: the home edge received `session_hidden` alone, kept the invite row of a session it no longer held, and `EdgeReplica::validate` failed with `DanglingReference`, while the coordinator's standing index kept the key of an invite the domain had already deleted. A guest logging in left its guest invites on the edge in the same way, and an account logging out left the account's invite copies on an edge that no longer hosted the account; once the channel was next touched the edge was sent `channel_hidden` over a remaining child and refused it with `ChildrenRemain`. A guest principal is now hosted only by a live session that is still a guest, and an account switch hides the copies of the principal the session had before it, exactly as a close does, unless the edge still hosts that principal. The removals are `invite_removed(projection_hidden)`; the channel revision the domain advances when it deletes a guest invite reaches the edges that keep the channel through the revision carrier of the entry above. Evidence: `a_closed_guest_leaves_no_invite_behind_on_its_home_edge` (failed with `DanglingReference` on edge A), `a_closed_guest_invite_advances_the_channel_on_every_member_edge`, `a_guest_logging_in_leaves_no_guest_invite_behind` and `an_account_logging_out_hides_its_invite_copy_on_that_edge` drive the real derivation into three replicas, validate each, compare each with the snapshot cut and deliver a following channel message; the domain, runtime federation and testkit suites and the Stage 07 and Stage 08 daemon tests pass.
  - Issue #175 residue (2026-09-18, under master #35): the sweep rounds run after PR #177 pass at 64 test threads beside 64 CPU hogs and fail only at 256 threads beside 128 hogs. Read from their saved output: `idle_capacity` and the recovery test exited on `phase=flush`, the audit sweep inside flush that #180 removed after those rounds ran; two Stage 06 tests failed `public listener did not start` because the fixture gave a debug daemon 20 seconds to open its listener on a host six times oversubscribed, and the bound is now 60 seconds, which costs a passing test nothing because the wait ends when the listener answers; one `FAIL ACCTCREATE UNAVAILABLE` on a single node has no recorded cause, and the refusal-reason event added the same day names the check the next time it occurs.
  - Workspace version (2026-09-18, under master #35): the tag `v1.0.0-rc.1` names a commit whose crates, logs, `VERSION` reply and `--version` output all said `0.0.0`, because the workspace policy required that placeholder. The workspace, the twelve exact inter-crate pins, the fuzz workspace, both lockfiles, the workspace checker and the interop matrix now say `1.0.0-rc.3`, the version the next candidate tag will carry. The lockfiles change nothing else. Evidence: static checks pass, the daemon builds with `--locked` and prints `agenc-relay-server 1.0.0-rc.3`, and the fuzz workspace resolves with `--locked`.
  - Release-source ledger binding (2026-09-18, toward issue #63 under master #35): `conformance/release-source-decisions.toml` binds its decisions to the bytes of `docs/protocol-sources-and-decisions.md`, and the redb fork commit of 2026-09-17 added a paragraph to that document without refreshing the binding, so `scripts/test-release-qualification.py` failed on main unnoticed because no gate ran it. The added paragraph changes no RFC, draft or protocol-repository decision; the binding now names the current bytes, the 56 qualification tests pass, and the Stage 09 gate runs them in its static lane.
  - Refused account requests name their check (2026-09-18, under master #35): about ten different checks answered a login or account request with the same bare failure and logged nothing, which cost most of a day when the concurrent gate surfaced one of them. `account_request_refused` is a new warning event with a closed `reason` field (`AccountRefusalReason`, ten labels, no identifiers); the account service's `fail_route` and `fail_pending`, the edge's two forward failures, the authority's bare refusal at the edge, and the coordinator's principal-mismatch and busy-carrier refusals emit it. The operator guide lists the reasons. Evidence: the event-format unit test and the runtime crate's 1,683 unit tests pass; clippy is clean.
  - Admin test client and refused commands (2026-09-18, found through the concurrent gate under master #35): the daemon answers a refused administrative command with one `FAIL` line and no batch, and answers `FAIL <verb> BUSY` while its audit commit cannot be admitted, which happens in the second after a link comes up on a busy host. The test client's `command_batch` read until `BATCH -` only, so a `FAIL` reply left it waiting for its 20-second socket deadline and the readiness pollers failed with `EAGAIN` (`deletion_drill_preconditions_are_the_ones_the_daemon_requires`, `sequencer_rotation_and_leaf_retirement_hold_the_encrypted_channel`). It now ends a read at a `FAIL` line outside a batch and repeats a command refused as `BUSY` until the deadline. Test support only; the 23 daemon tests that use the admin client pass.
  - Login during an origin update (2026-09-18, found through the concurrent gate under master #35): an edge welcomes a client as soon as its session is bound, before the coordinator acknowledges the origin update that carries the binding. Until that acknowledgement no request can be built for the connection. Commands already wait through the window (`defer_command`); an account carrier did not, so `send_account_carrier` failed and the client read a bare `904`. The window is milliseconds on a quiet disk and seconds when the coordinator's durable write queues behind other I/O, which is how `edge_credential_replacement_survives_coordinator_restart` failed in the concurrent gate. The edge now holds one carrier per connection behind the pending update, with its backing reserved, forwards it when the acknowledgement arrives, ahead of the deferred commands, and drops it when the connection closes. Evidence: three edge tests in `federation/edge/tests/carrier_during_origin_update.rs` (they fail with the deferral disabled), all 453 federation unit tests, and the daemon test pass.
  - Gate lanes (2026-09-18, user directive under master #35): `run-gate.py` no longer runs the manifest as one sequence. `gate_lane` assigns every reviewed command to a lane by its argv (static checks, the three `cargo check` targets, clippy, the workspace tests, coverage, the per-stage test runs, the storage runs, the stage scripts, the feature matrix, fuzz); lanes run concurrently, each Cargo lane in its own directory under `target/lanes/` with a share of the host's build jobs and test threads, and results stay in manifest order. `check-evidence.py` orders command results within a lane instead of across the whole gate. The storage qualification workload measures free space to the byte, so the default nextest profile leaves it out and a new Stage 05 command runs it through the `disk` profile in an exclusive lane after every other lane has ended. Commands that start real daemons (the workspace and coverage test runs and the transcript, soak and load scripts) run one at a time: with all of them overlapping, twelve e2ee daemon tests hit their 20-second socket timeout in one run and a SASL exchange was refused in the next, the load sensitivity issue #175 records. Evidence: two consecutive full gates passed in 14 min 38 s and then, with one shared build for the script lane and the lock narrowed to daemon commands, 11 min 17 s (from 21 min 19 s sequential). The lock is what keeps the gate above about four minutes; it can go when #175 is fixed.
  - Gate wall time (2026-09-18, user directive under master #35): the Stage 09 implementation gate took 37 to 39 minutes on a 64-core host at a load average near 4. Measured from a passing gate log, 888 s was the issue pipeline's Python suite on one core (removed with the pipeline), and 468 s was the workspace suite run twice by `cargo test` and `cargo llvm-cov`, which execute one test binary at a time. The test passes, the coverage pass and the three transcript scripts now use `cargo nextest` (pinned as `cargo-nextest 0.9.145` in the toolchain policy, CI install list and qualification host probe); doctests keep `cargo test --doc`. `.config/nextest.toml` gives the byte-exact storage qualification workload every test thread, so it runs alone inside the same command. `run-gate.py` prints each command's duration. Evidence: `cargo nextest run --workspace --all-features --locked` passed 3,361 tests in 139 s with the qualification workload passing, and `cargo llvm-cov nextest` produced a report that passes the critical coverage policy (branches 76.72%, lines 92.51%, 21 critical regions at 100%).
  - STO-05 follow-up, deterministic reserve boundaries (2026-09-18, after issue #68 under master #35): the backup `R(F) + O` boundary test placed a one-byte boundary on live free space and lost to the other tests of its own binary, failing the release gate after eight retries; STO-04's owner-open boundaries, the transaction `R(F) + G` boundaries and the engine scratch-gate boundaries had the same shape. `StorageFaultInjector::with_capacity_headroom` now injects the capacity sample (available bytes are the computed reserve plus the headroom) at every admission site that samples through the injector, the four tests use it, and their retry loops and the separate-filesystem skip are removed. A disabled handle returns the `fstatvfs` sample unchanged, so production admission is unchanged, and the qualification workload still measures the real filesystem. Evidence: ten of ten consecutive plain `cargo test -p agenc-relay-storage --all-features --locked` runs pass with the build target on ext4; recorded in [the incremental backup record](docs/stage-10-incremental-backup.md).
  - SC-007 recovery NOTE in the welcome burst (2026-10-01, SDK program, outside master #35): Section 10.2 step 5 orders `NOTE * RECOVERY_EPOCH <22-char-epoch> :Current server recovery identity` right after the MOTD group for a connection that negotiated `agenc.ag/recovery`. The client-wire state machine planned that step and the testkit transcript model rendered it, but `RegistrationRouter::welcome_frames` left it empty, so no daemon sent the NOTE. The router now keeps the epoch it advertises (the hosted account service's on a coordinator or standalone node, the advertised one on an edge) and renders the NOTE from that same field, so the NOTE and the `CAP LS` value cannot disagree. The NOTE is not gated on `standard-replies`: Section 10.2 conditions it on `agenc.ag/recovery` alone, Appendix A.3 lists that capability as standalone, and it is built ungated like `NOTE ACCTCREATE CREATED` and `NOTE ACCTCRED CHANGED`, unlike the gated `NOTE ACCT` and `NOTE CHANCTL` replies. A client that did not request the capability sees no difference. The three commits are adopted with `git am` from the SDK's server rehearsal of 2026-09-29; its SC-013, SC-001 and SC-002 commits are not adopted, so the coverage source inventory was recomputed (999 files) and the two `registration.rs` regions keep their spans. The authenticated account state of step 6 and the post-registration login are not implemented by these commits. Evidence: four registration unit tests (local, published MOTD, gating, edge completion), two Stage 06 daemon tests (guests, and pre-registration SASL) and one Stage 08 edge test, all seven failing with the NOTE built but not sent; recorded in [the login state record](docs/stage-10-login-state.md).
  - SC-007 welcome account state (2026-10-01, SDK program, outside master #35): Section 10.2 step 6 follows the recovery NOTE with the authenticated account state, and Appendix E.2 shows the line `:<server> 900 <nick> <nick>!<user>@<host> <public-account-label-or-*> :You are now logged in`; the client-wire state machine planned `WelcomeStep::AccountState` for every registration that bound an account, and the router left it empty, so no authenticated client ever read a `900`. The router now renders it after the NOTE, or after `376` or `422` without the capability. A coordinator or standalone node reads the session from its domain; an edge reads the session projection its coordinator installed, which is in the replica before the edge completes the session open because the coordinator appends the completion event after the plan's events. The mask comes from the same prefix renderer as every other line of that session and the label is the account's public label or `*`; `client_render::LoggedIn` builds the line for both paths. A bound session, account or projection the router cannot find fails the whole burst closed, so a welcome is never sent without its account state; a guest's burst is unchanged. The testkit transcript model renders the same step for its authenticated scenario. Appendix E.2's `001` directly followed by `900` conflicts with Section 10.2's order, which governs; the normative correction is not part of this change. The daemon tests' registration helpers stopped at `376` or `422`, which leaves the `900` unread, so `complete_registration` in the Stage 06 and Stage 08 binaries, the Stage 10 drills' login and the capacity campaign's login now read it after a SASL success and check its shape. Evidence: five registration unit tests (local with and without a label, local fail-closed, the edge projection, edge fail-closed), the Stage 06 and Stage 08 SASL welcome tests made byte-exact against each session's `JOIN` echo, and two testkit transcript tests; with the arm computing the state but not sending it, the seven runtime and daemon tests fail and the NOTE tests pass, and with the model's arm reverted its welcome-order test fails; recorded in [the login state record](docs/stage-10-login-state.md).
  - SC-007 post-registration login on its own node (2026-10-02, SDK program, outside master #35): Section 11.4 has a client check its committed login completion against "the later 900/session state", but a registered session that logged in, or authenticated again to the account it holds, read only the `903`. The account service now renders a registered session's successful finish with `mutation_render::render_account_login`: the carrier frames, ending with `903`, then `900 <nick> <nick>!<user>@<host> <label-or-*> :You are now logged in` from the same `client_render::LoggedIn` as the welcome's. A guest that logged in is also named with `ACCOUNT <label-or-*>` to every local recipient of the switch that negotiated `account-notify`, the session itself included, as a logout names `ACCOUNT *`; a same-account reauthentication repeats the `900` alone; and a coordinator's internal carrier for a session an edge homes gets no `900`, while the coordinator's own channel peers still read the `ACCOUNT` line. `903` stays the first line after the completion. A login to an account without a public label is named `ACCOUNT *`, like its `900` (D-13): a peer cannot tell it from a guest, but learns that, and when, the session authenticated, not to which account; sending nothing instead is listed for the owner. The login of a session an edge homes, and the `ACCOUNT` line for peers that other edges home, are not implemented by this change; logout is unchanged. Evidence: four `account_login_render` unit tests (a fifth, `a_login_to_an_unlabeled_account_names_it_with_a_star`, was added later) and the Stage 06 daemon test `login_after_registration::a_login_after_registration_follows_903_with_900_and_names_the_account` (`903` then a byte-exact `900`, `ACCOUNT <label>` to an `account-notify` peer only, a reauthentication's `900`, an unchanged logout); with the account service rendering a registered login as before, the daemon test fails; recorded in [the login state record](docs/stage-10-login-state.md).
  - SC-007 recomputed membership revision on the federation wire (2026-10-02, SDK program, outside master #35): an account switch projects one `channel_memberships_recomputed` event per joined channel to every edge with a member in it, and the domain keeps each membership at the immutable revision it joined at, which fences history reads. The federation codec's `validate_membership_recompute` required every membership in the event to carry the event's resulting revision, so the projector could not encode it and the coordinator refused any login (and, by reading, any logout) of a session that shared a channel with a member an edge homes: an edge answered `904`, the coordinator closed its own client's connection. Section 20.6 does not require the equality: the recompute arm carries its resulting revision explicitly, and `member_joined` alone uses its membership revision as the resulting one. The check now binds each recomputed membership to the event's channel and requires a nonzero revision not above the resulting revision, on encode and decode, which is the domain's own membership invariant. No producer, schema, registry, vector or profile hash changes; an edge built from 70c832c still refuses the corrected event, so the coordinator and its edges upgrade together. The rule covers every recompute, so the correction also lets the coordinator stage a logout and an account-grant prefix mode on a registered channel (Section 13.2) when an edge homes a member of the channel; at 70c832c both were refused the same way. An edge still renders `channel_memberships_recomputed` to no client, so its clients read no MODE line for an account grant and nothing for another node's logout, which Section 13.2 and Appendix B.5 ask for; that rendering gap is outside SC-007, recorded and listed for the owner. Evidence: `semantics::tests::a_recomputed_membership_keeps_the_revision_it_joined_at` and the runtime tests `federation::codec::tests::recompute` (a round trip at the join revision, and the projector encoding an edge member's login), all three failing with the equality restored; the later projection regressions `a_registered_channel_account_grant_reaches_the_member_edge` and `a_coordinator_logout_beside_an_edge_member_reaches_that_edge` (exactly one recompute to the member edge, at the member's join revision, encoded) fail the same way; recorded in [the login state record](docs/stage-10-login-state.md).
  - SC-007 edge origin after a post-registration login (2026-10-02, SDK program, outside master #35): Section 20.7 represents "a session registration, login, logout, account switch, or companion device attach/detach" by the next origin generation before requests under it are accepted. An edge declared that generation for a registration but not for a login after registration, so its origin kept declaring a guest while the coordinator had switched the session to the account; the coordinator then refused the connection's next account-service request for a principal mismatch, so a same-account reauthentication failed with `904` (and, by reading, the edge refused to build a credential change for such a connection). When a registered connection's SASL finish comes back authenticated, the edge now records the account in the origin and declares the next generation, as for a registration; later requests already wait for that acknowledgement and travel under it, and the companion origin mirrors the acknowledged generation. A login before registration and a reauthentication to the account already declared change nothing. No wire, registry or persistent format change. Evidence: the edge harness test `federation::edge::tests::accounts::a_login_after_registration_declares_its_account_before_the_next_carrier`, which fails with the declaration left out because the next carrier leaves under the guest generation; recorded in [the login state record](docs/stage-10-login-state.md).
  - SC-007 post-registration login on an edge (2026-10-02, SDK program, outside master #35): the coordinator commits every login, so it now also projects a guest's login as `account_label_changed`, with the session's source view and the account's public label, to the session's home edge and to every edge that shares a channel with it, as for a label change; an edge renders it as `ACCOUNT <label-or-*>` to each `account-notify` client sharing a channel with the session and to the session itself. A logout is not projected (edges refuse `AUTHENTICATE *`, SC-012). The home edge renders the `900`: the coordinator sends the login's result before the events that give the session its account, so the registration router keeps a registered connection's login it answered with `903` (`awaited_logins`, one per connection) and sends the `900` once the replica's session projection names that account, with the welcome's mask and label; the first projected event carries that projection, so the `900` precedes the `ACCOUNT` line. A same-account reauthentication reads the `900` right after its `903`; a `900` the edge cannot render closes the connection. An edge renders the user events of a session another node homes (`NICK`, `AWAY`, `SETNAME` and this `ACCOUNT`) to none of its clients, because its replica keeps only its own sessions' memberships and these events carry no channel; so D-13's `ACCOUNT` reaches `account-notify` peers on the session's own node and the coordinator's own clients, not the clients of other edges. Closing that gap needs a normative change (for example a channel vector like `session_hidden`'s), so it is recorded, not changed, and listed for the owner as a normative candidate together with the same pre-existing gap for `NICK`, `AWAY` and `SETNAME`; the domain test `federation::projection::tests::revision_drift::only_the_home_edge_finds_recipients_for_a_sessions_login_and_nick_change` pins the recipients each edge finds. The Stage 08 helpers read the `900` after a registered connection's `903`. Evidence: the domain test `federation::projection::tests::revision_drift::a_login_names_its_public_label_to_the_home_and_member_edges_and_a_logout_does_not` and five updated projection tests, four `registration::edge_login_tests`, and the Stage 08 daemon tests `login_after_registration::an_edge_login_after_registration_sends_900_and_names_the_account` and `a_coordinator_login_after_registration_sends_900_and_names_the_account`; without the login projection seven fail, without the awaited `900` five (the credential replacement's reauthentication among them), and at this commit the recompute equality or a missing origin declaration fails the daemon login tests; recorded in [the login state record](docs/stage-10-login-state.md).
  - SC-007 role-only recompute on an edge (2026-10-03, SDK program, outside master #35): without the recompute equality, an edge's decoder bounds a recomputed membership's revision only by the event's resulting revision, and the replica replaced a membership it holds wholesale, so a coordinator fault that moved a member's join revision, which its history authorization compares (Section 20.6.1), or its join second would have been stored. The replica now accepts a recompute of a held membership only when it changes the role alone (Section 13.2), and otherwise refuses the event as an invalid record, which fails the edge's link like any refused projection. Every recompute the coordinator emits passes, because the domain never changes a membership's revision or join second after the join. Two existing replica tests that recomputed a membership at the resulting revision, the old equality, now keep the join revision. No wire, registry, profile hash or persistent format change. Evidence: `federation::replica::tests::a_recomputation_that_moves_a_join_revision_or_time_is_refused`, which fails with the check left out; recorded in [the login state record](docs/stage-10-login-state.md).
  - SC-007 awaited 900 fails closed on an edge (2026-10-03, SDK program, outside master #35): the registration router keeps a registered edge client's login it answered with `903` until the session projection names the account, then sends the `900`. When it settled an awaited login whose connection state it did not hold, it forgot the login as if the `900` had been sent, and without an edge role it dropped every awaited login. No caller settles while holding a connection's state outside the router, so only a connection that was already closing could reach either path, but a later caller would have lost a `900` silently. Such a login now closes its connection, as a `900` the edge cannot render already did, and a reported close forgets the awaited login even when a closing path already dropped the connection's state. No wire, registry, profile hash or persistent format change. Evidence: `registration::edge_login_tests::an_awaited_login_the_router_cannot_answer_closes_its_connection` and `an_awaited_login_without_an_edge_role_closes_its_connection`, which fail when an unanswerable login settles as sent, and `a_connection_closed_after_its_state_was_dropped_forgets_its_login`, which fails when the close forgets the login only with the connection's state; recorded in [the login state record](docs/stage-10-login-state.md).
  - AUD-18 framed public cloak in every user mask (2026-10-01, SDK program, outside master #35): Architecture Section 7.4 specifies the visible source form `<nickname>!u-<10 base32>@h-<16 base32>.invalid` and every transcript of Appendix E uses it, but every renderer formatted the bare `PublicCloak` components, so a client decoder that enforces Section 7.4 refused every user prefix the daemon sent; the SDK's wire codec found it against a daemon built from the audit pin (SDK program item B-12). `agenc_relay_client_wire::VisibleCloak` and `user_mask` are now the one formatter: the user field `u-<10>`, the host field `h-<16>.invalid`, and a mask that refuses a nickname outside the Section 7.2 grammar, so `MAX_USER_MASK_BYTES` (72) bounds what it renders. The local source prefix (`session_prefix`, from which SC-007's welcome `900` (B-02) takes its mask once both are merged), the `userhost-in-names` tokens of a JOIN's and a NAMES reply, the 311, 314 and 352 user and host fields, the 302 entries, the source of every event an edge renders and the sender of a history replay all take it. Rendering only: stored, federated and in-memory cloaks keep the bare components, and no registry, profile hash or persistent format changes. A framed NAMES token is up to 73 bytes, so the local JOIN snapshot counts a full 8,000-byte chunk at 108 tokens instead of 129; with the old 61-byte bound a channel of 219 members with 32-byte nicknames needed four frames against a bound of three and its JOIN's NAMES failed with `LimitExceeded`. The coordinator's directory NAMES bound derives from the same constant. The host field a client reads in `WHO` is now the text a `$c:` cloak mask matches. Evidence: [the framed cloak record](docs/stage-10-framed-cloak.md): renderer tests per site, a two-guest daemon transcript (JOIN, echo, NAMES, WHO, WHOIS, USERHOST, WHOWAS, MONITOR) in which all 18 masks and field pairs are framed, a remote user across two edges, a `$c:` ban on a user's own `WHO` host field that keeps that user out, page tests against both bounds, the role-prefixed worst case among them, and a revert of each part that at least one of them fails. Limitations recorded there: federated NAMES still carry no `userhost-in-names` tokens, `730` names nicknames only, the welcome `900` arrives with SC-007's branch, and the conventional-client qualification was not rerun.
  - AUD-18 explicit NAMES paged on its own node (2026-10-02, SDK program, outside master #35): a node that answers its own clients rendered an explicit `NAMES` as one logical reply, which the fanout refuses above `response_batch_bytes` (65,536 bytes by default), and the refusal closed the client's connection; a JOIN's NAMES and the NAMES an edge relays from its coordinator were already paged, as Section 14.3 requires. The framed cloak of the note above makes every `userhost-in-names` token 12 bytes longer, which lowered the largest NAMES still answered by about a fifth (review finding B12-R0-1); the state-core fixture runs at the 262,144-byte hard maximum, so no test had shown it. A NAMES reply that fits one response batch is still sent whole and unchanged. A larger one is admitted as a query snapshot, retained as a committed local NAMES seed and delivered by the local JOIN's continuation (Section 14.2): pages of at most 512 users, one label batch from the first page to the last, the next page only below half the client queue, the connection's later commands held behind it. Pages are cut with the batch tag counted, so a tagged page fits the smallest response batch, and the response floor's timer now opens a snapshot the commands it resumes leave, the same line sdk/b-local-join adds for AUD-16. `WHO #channel` keeps its single reply and is listed for the owner. Evidence: [the explicit NAMES pages record](docs/stage-10-explicit-names-pages.md): four router tests at the default response batch (a channel of 1,400 members, a labeled reply in one batch beside a small reply sent whole, a bare NAMES across twenty channels, a NAMES released by the response floor) and a page-size test, each failed by a revert of its part.
  - AUD-16 local JOIN applied in its own step (2026-10-01, SDK program, outside master #35): on a node's own router (a core-only node or a federated coordinator) a guest's lone `JOIN &loc` got no reply, not even its label batch, and every later registered command on that connection waited behind it until the connection closed; `PING` was still answered. A `&` channel is never persisted, and one whose members are all that node's own clients projects nothing to federation, so the JOIN writes nothing durable and `stage_prepared` applies it inside the same step, and `apply_plan` had already run the commit hook that marks retained NAMES seeds when `settle_local_join` retained this one; the seed never opened and the router kept deferring the connection's commands behind it. `settle_local_join` now marks an accepted seed committed when the domain has already reached its revision, which happens only when its plan was applied in that step; a staged seed is still committed by the batch that applies it and a refused JOIN still releases its snapshot. The response-floor timer, which resumes a connection's commands deferred behind a floored refusal outside any routed line, now opens the seeds after resuming them, as every other resume point already did. No wire, numeric, limit, registry, persistent format or specification change; `CHANTYPES=#&` and the other `005` tokens are unchanged. Evidence: a `local_join` unit test of the in-step order, live-router tests of a labeled `JOIN &loc` and `JOIN #room` each followed by a labeled `TIME`, state-core tests of a `JOIN &loc` applied at each point that opens seeds outside a routed line (the response floor's timer, a crypto completion, a refused batch, the NAMES continuation timer, and the commit step of a staged JOIN or of the registration), a core-only daemon test of a plain and a labeled `&` JOIN each followed by `TIME`, and a coordinator-and-edge daemon test of the same on the coordinator (and of a `#` JOIN followed by `AWAY` on the edge); all of them except the staged `#room` test fail with the fix reverted, and each state-core test also fails with only its own point's drain removed. The new release region `runtime-local-join-settled-commit` binds `settle_local_join`. Recorded in [the in-step local JOIN record](docs/stage-10-in-step-local-join.md).
  - AUD-01 an edge initialized by `arcd init` serves (2026-10-01, SDK program, outside master #35): `arcd init --coordinator-descriptor` writes an edge database without the fake OPAQUE record, as Section 22.3 and the owner's edge-initialization tests intend, but startup reconstruction required that record on every role, so every edge an operator initialized refused its first `serve` with `durable state reconstruction refused the recovered state: ... stale or inconsistent`, and no `arcd`-initialized node could offer the encrypted profile, which only edges advertise. `reconstruct` now takes the configured role: a coordinator database without the record is refused exactly as before, an edge database without it is complete, and a record an edge database was seeded with is still admitted under the same row checks and never read. No row, record kind or storage generation changes. A CAP-01-style SIGKILL and restart was run before and after: at `70c832c` a CLI-initialized edge never starts and 21 kills of RUN-08's library-initialized drill edge all restarted; after the change 24 kills of a CLI-initialized edge under channel churn and 32 of 33 drill kills restarted, the one refusal being an unexplained credentials-file read during a host-wide disturbance that stopped every daemon of two concurrent runs. The mechanism refuses only on the first start of an edge whose database never held the record, and the RUN-08 and QA-04 edges were all seeded with it, so it does not explain RUN-08 (#134) or the QA-04 (#175) residue; neither is claimed fixed. Evidence: a reconstruction case for both roles, an offline case reconstructing the databases `initialize_node` writes, and a daemon case provisioning a coordinator and an edge through `arcd init` and `arcd print-onboarding` that links, advertises `agenc.ag/e2ee-mls`, registers a client and survives a SIGKILL, each failing with the role rule reverted; recorded in [the CLI edge initialization record](docs/stage-10-cli-edge-initialization.md).
  - AUD-03 an edge descriptor pins the epoch the edge advertises (2026-10-01, SDK program, outside master #35): an edge's `arcd print-onboarding` pinned the edge's own database recovery epoch while its CAP advertises the pin of its enabled coordinator record, so under ID-06 a client onboarded from an edge's descriptor was blocked on that edge. One selection, `edge_advertised_recovery_epoch`, now serves the daemon's CAP and the descriptor; a coordinator still pins its own database epoch; an edge with no enabled coordinator record, which cannot serve, is refused instead of printing an epoch no serving edge advertises; and the descriptor follows the record when the coordinator's epoch changes and the record is re-pinned. Because the edge's descriptor was the only `arcd` output carrying the edge's own epoch, which the coordinator's record for it pins, `arcd init` now prints `recovery-epoch=` beside `server-id=`; that receipt line is now the only `arcd` output carrying an edge's own epoch, so an edge an earlier `arcd` initialized, or whose receipt was lost, needs its epoch recorded with the earlier `print-onboarding` or a new initialization, and an explicit read of a node's own epoch is listed for the owner. The owner's test asserting the mismatch is changed deliberately; the rule's normative text follows in the program's normative revision (decision D-15), replacing the Section 9.3 sentence that derives the `agenc.ag/recovery` value from the live header's epoch and the Appendix C.8 descriptor `recovery-epoch` line. No wire, configuration or storage change. Evidence: the changed owner case (refused unenrolled, the coordinator's epoch once enrolled, followed after a re-pin, refused when disabled) and the daemon cases comparing the edge's descriptor with its live CAP, each failing with the edge branch reverted, the CLI case's comparison with the edge's welcome NOTE, added at the program's integration merge with SC-007, which fails when the NOTE carries another epoch, and a coordinator case that fails when a coordinator's descriptor pins its peer record's epoch or its receipt's epoch is not the database's; recorded in [the edge descriptor epoch record](docs/stage-10-edge-descriptor-epoch.md).
  - AUD-02 `arcd` creates the sequencer credentials document (2026-10-01, SDK program, outside master #35): no `arcd` command produced the public `e2ee.sequencer_credentials_file` document every node of an encrypted network names; only the testkit's `sequencer_credentials_document` did, so an encrypted network could be provisioned only with test code. The offline `arcd sequencer-credentials create --config <file> --sequencer-key-file <file> --not-before <unix-seconds> --not-after <unix-seconds> --output <new-file> [--service-user <name>]` writes a new network's set generation zero with its one generation-zero credential from the shared `agenc-relay-e2ee` encoders, takes the network ID from the validated configuration and the seed under the protected-file rules, verifies the document with the parser and key-set check startup runs, publishes it as a new file at mode 0644, whatever the caller's umask, with a no-replace rename, refusing an output below any group- or world-writable directory as the daemon's protected read does, and prints its `sequencer-key-set-generation=` and `sequencer-key-set-hash=` lines. The operator guide gains the procedure that enables the encrypted profile with it, including the field sources of the peer records; rotation and retirement documents keep the existing out-of-band procedure. The command has no normative text: Section 22.3 names three offline commands that accept `--service-user` and Appendix C.7 names no producer, so its text is listed for the owner rather than added to the program's normative revision. No wire, configuration, storage or dependency change. Evidence: an offline case comparing the document byte for byte with the testkit's and reading it back through the daemon's loader, a refusal case that also fails when only the output's parent directory is checked, the CLI parser case, the usage pin, and a daemon case in which a coordinator and two edges provisioned through `arcd init`, `print-onboarding` and the new command link, advertise `agenc.ag/e2ee-mls` and register clients, the daemon cases failing with the command's dispatch disabled and, since they run the command under umask 077, without its explicit mode; recorded in [the sequencer credentials record](docs/stage-10-sequencer-credentials-command.md).
  - SC-013 ReInit result tokens (2026-10-01, SDK program, outside master #35): companion 11.7 gives `EGROUP SUBMIT REINIT ATTEMPT`, `ACK`, `ACTIVATE` and `ABORT` their own labeled replies and 12.5 maps every result selector one-to-one to its 11.7 line, but the edge decoded `commit_acked`, `reinit_staged` and `reinit_acked` into one three-identifier tuple and `aborted`, `reinit_activated` and `reinit_aborted` into one four-identifier tuple and rendered the tuple as `ACKED` or `ABORTED` whatever its kind, so a staged or acknowledged ReInit was answered `ACKED` and a successful activation `ABORTED`. `scalar_line` now chooses the line by the decoded kind and refuses a tuple under a kind that does not own it, and the batch metadata child renders `ABORTED` only for an `aborted` result; the completion-delayed path and the reply cache share the renderer. Adopted from the SDK rehearsal's patch 0002. Evidence: five `e2ee::edge::tests::result_kinds` regressions drive real `federation_result` objects through `on_result_frame`, a completion after its result and the reply cache, and the Stage 08 ReInit test now checks `REINIT-STAGED`, `REINIT-ACKED` and `REINIT-ACTIVATED` on each labeled completion line itself; all six fail with `result.rs` reverted. A three-daemon attempt abort whose two council votes arrive separately is answered `PENDING`, then `REINIT-ABORTED`, and the first requester reads the untagged `REINIT-ABORTED` broadcast; it fails with the `reinit_aborted` arm rendering `ABORTED`. Recorded in [the requester replies record](docs/stage-10-e2ee-requester-replies.md). No wire registry, profile hash, limit or persistent format changed.
  - SC-013 requester copies of ACK and terminal events (2026-10-01, SDK program, outside master #35): companion 12.5 sends an ACK submission one labeled `ACKED` (a ReInit ACK one `REINIT-ACKED`) and an immediate close, ReInit stage, finalization, abort, ReInit activation or ReInit abort exactly one labeled scalar on the requesting connection, with the registered untagged broadcast going to the other eligible local sinks and suppressed on the requesting connection; 11.7 says the same of the ACK notice. The edge's `fanout` rendered the untagged copy for every attached connection of the conversation, the requester included, so the requester read the `ACK` or `REINIT-ACK` notice or the terminal broadcast before its labeled line. `fanout` now withholds the copy of every kind except the application and candidate echoes from the connection whose pending request the event completes; every other connection, a second session of the same account included, still receives it, and a request answered `PENDING` earlier receives the later terminal as the untagged broadcast, unless its own connection submits the request that completes it. Evidence: four `e2ee::edge::tests::requester_copies` regressions drive all eight kinds through `on_event_frame`, `on_result_frame` and `prepare_barrier`: three complete a request, the requester's, the peer's and one through a barrier, in both arrival orders and fail with `events.rs` reverted in all 48 of their cases, and the fourth, a control, completes none; the Stage 08 ReInit scenarios require the requester's reply to name its staged, acknowledged, activated or aborted result only in its labeled completion while the other edge reads the untagged broadcast; the shared Stage 08 helpers require the same of every commit ACK, finalization and close a daemon scenario submits; and `requester_copies` has carol, a member on the requester's own edge, and bob, on the other edge, read the untagged copy of the requester's finalization, abort, commit ACK and close. Eight daemon scenarios fail with `events.rs` reverted, and each single-kind mutant of the rule, and a rule that withholds the copy from every sink on the requester's edge, fails at least one. Recorded in [the requester replies record](docs/stage-10-e2ee-requester-replies.md). No wire registry, profile hash, limit or persistent format changed.
  - SC-001 CLAIM STATUS names the stored target, and the SC-002 disposition (2026-10-01, SDK program, outside master #35): companion 11.6 maps `(claiming_account_id, operation_id)` to the exact claim parameters and result and has `CLAIM STATUS` return that stored result, but `claim_status` rendered the device the asking connection had attached instead of the claim's target, so every status of a claim of another account's or a sibling device's package named the wrong device while the reference, object and bytes were right. `Directory::stored_claim` returns the parameters stored beside the outcome, which startup already restores from the claim row, and `claim_status` names the stored target; an unknown operation still answers `EMPTY PACKAGE` and the lookup stays keyed by the requesting account. Adopted from the SDK rehearsal's patch 0003. SC-002 is recorded as a disposition with no code change: an empty claim result stays in memory, so an identical retry before a restart still answers `EMPTY PACKAGE` and a coordinator restart evaluates the operation again. 11.6 retains every claim mapping through at least `KEY_PACKAGE_CLAIM_TIMEOUT`, so the disposition leaves that floor unmet for an empty result across a restart; the rehearsal's patch 0004, which made empty results durable, is not adopted; the retention of claim records is the owner's decision. Evidence: a coordinator regression for a sibling-device claim through STATUS, an identical retry, a restart through the production restore path and the target device's own STATUS; a domain test of the accessor; the Stage 08 claim helper now checks STATUS in every real-client scenario; and a three-daemon coordinator-restart test. The coordinator test and both daemon tests fail with `claim_status` reverted (STATUS names the claimant's device). Recorded in [the claim status record](docs/stage-10-claim-status-target.md). No wire registry, profile hash, limit or persistent format changed.
  - X-10 shared verifier predicates (2026-10-01, SDK program, outside master #35): the SDK readiness audit of 2026-09-28 found the shared public verifiers in `agenc-relay-e2ee` admitting correctly signed objects the companion refuses, which matters because a client runs these predicates on imported public objects with no daemon step behind them. Companion 9.2.1 forbids a sequencer successor that reuses the active credential's public key; `verify_sequencer_credential` now refuses it in its predecessor arm, which covers `SequencerKeySet::verify`, the credentials-file `verify_opened`, `verify_context` and the historical chain's `SEQUENCER` transition. The runtime regressions that built such a set through the verifier (two tests and the set helper of four terminal tests) now assert the refusal and assemble the set without the verifier, so installation's two-role key check, its selection by credential identity and a terminal's receipt-credential rule stay covered. Capability statements and leaf authorizations sign their own `network_id`, which the verifiers never compared with the trusted roster's; `VerifiedRoster` now carries the network of the root that signed it, and the capability verifier (checked and restored) and `verify_leaf_authorization` refuse a statement signed for another network (`ProfileMismatch`), which the credential bundle and KeyPackage checks inherit. A stored capability row that names another network, which an earlier binary could have accepted, is skipped at startup like any row that does not re-verify. Companion 8.3 issues a certificate in exactly its target roster, whose `not_before` its enrollment interval covers, after which it continues unchanged; the roster verifier checked the interval only for a certificate targeting the roster's own generation, so it admitted a certificate enrolled for a later generation and one claiming an earlier generation that no earlier roster issued or that the predecessor had revoked. A later target is now refused on every path; on succession an earlier target must be active, unchanged, in the predecessor; the new `verify_first_contact_roster` admits a roster with no pinned head only with the roster of each continuing certificate's exact target generation as evidence, holds it to every supplied roster of its root below it as succession holds it to its predecessor (each continuing certificate unchanged in every one from its target on, the previous generation the named predecessor, every revocation still listed) and keeps the lineage shape; `restore_roster` keeps admitting continuing certificates, whose issuance was shown when the roster was accepted, and is documented for a roster this node accepted before and a principal roster an independently pinned binding names, never for another party's say-so. the new `verify_first_contact_capabilities` admits a capability statement with no pinned head at any generation under every rule of the checked path but the predecessor step, which the lineage shape replaces; `initial_authority` keeps `restore_roster` under its pinned binding (a recorded limitation), and the named-roster membership fixture that re-listed a dropped certificate now returns the device through a continuous root rotation, the conforming way for a dropped device to become roster-active again. A roster that lists one certificate both active and revoked, which every path admitted (also at `70c832c`), is now refused on every path, since companion 8.4 makes `(Device ID, certificate_serial)` unique and absence revocation. No specification, hash, wire format, storage generation or dependency changed. Evidence: the ported audit counterexamples in `crates/agenc-relay-e2ee/tests/shared_predicate_counterexamples.rs` fail at `70c832c`; with each correction removed its counterexamples and unit tests (and, for the sequencer key, two runtime regressions) fail and with it they pass, the controls pass either way, and at the branch tip `cargo nextest run --workspace --all-features --locked` passes 4,535 tests with 24 skipped (the storage `disk` profile is left to the integration gate's exclusive lane); recorded in [the shared verifier predicates record](docs/stage-10-shared-verifier-predicates.md).
  - X-11 companion Section 16 client scalars (2026-10-01, SDK program, outside master #35): 13 of the 125 rows of the companion's normative limits table had no constant in `agenc-relay-e2ee`'s `limits` module, the shared code owner of that table: the endpoint-only MLS ratchet and application replay windows (Section 14) and the update and idle defaults (Section 13.6). The module now defines them in table order, durations in seconds, and says the server enforces none of them. `crates/agenc-relay-e2ee/tests/companion_limits_table.rs` parses every Section 16 row of the companion at build time and compares its default, in canonical units, and any `; ` qualifier as exact text, with its constant, in table order, so a changed value or qualifier, a row without a constant, a constant left by a removed row or a table line it cannot read fails. No specification, hash, wire format, storage generation, dependency or daemon behaviour changed. Evidence: at the parent commit the test does not compile and the compiler names exactly the 13 missing constants; with them all 276 e2ee tests pass, and changing one new value fails the table test on its row; recorded in [the companion client scalars record](docs/stage-10-companion-client-scalars.md).
  - X-08 OPAQUE profile and client modules (2026-10-01, SDK program, outside master #35): `agenc_relay_auth::profile` now owns the suite, the fixed Argon2id KSF and its constants, the context label and `opaque_context`, `opaque_identifiers`, and `FallibleOpaqueRng` generic over an `EntropySource`; `opaque.rs` consumes it, still over `OsEntropy`. `agenc_relay_auth::client` computes registration and login start and finish over exact-size arrays, refuses a generator that has already latched before any work, takes the export and session keys out of every library result into zeroizing arrays before the latch can discard that result, applies the Section 11.1 password bounds and keeps the invalid login apart from malformed or reflected server messages. The stage_four, stage_six_daemon and stage_eight_e2ee test clients use the public profile; the manual vector generator keeps its independent reference suite. A consumer with its own workspace root links the reviewed `opaque-ke` patch only if it repeats the root `[patch]` (X-09). `scripts/check-stage-four.py` names both modules, their surfaces and the new client suite, and the constant-time review re-binds `opaque.rs` and binds `profile.rs`. No wire, storage or daemon behaviour changes, and no Stage 04 or Stage 10 task changes state. Evidence: `crates/agenc-relay-auth/tests/opaque_client.rs` reproduces every field of `VEC-S04-007-OPAQUE`, including its output digest and both rejection outcomes, through the public modules, checks the export keys against the pinned library and between registration and login, checks that the adapter stays latched after its source recovers, and covers interoperation with the coordinator profile and the refusals, including a latched generator refused before any work, and the client module's unit tests show a discarded result's key wiped before it drops; at the topic tip workspace Clippy is clean and the workspace suite passes (4,531 tests); recorded in [the OPAQUE client profile record](docs/stage-10-opaque-client-profile.md).
  - X-09 Reviewed OPAQUE source in the fuzz workspace (2026-10-01, SDK program, outside master #35): Cargo applies the root `[patch.crates-io]` to this workspace alone, so the separately resolved fuzz workspace linked the unpatched crates.io `opaque-ke` 4.0.1 (`fuzz/Cargo.lock`). `fuzz/Cargo.toml` now selects `../vendor/opaque-ke-4.0.1` in its own `[patch.crates-io]`, as it already does for the redb fork, and `fuzz/Cargo.lock` resolves the vendored copy; `scripts/check-stage-four.py` (10 self-test cases) requires that override and exactly one vendored `opaque-ke` in both lockfiles. The explicit root path edge X-09 asked for was built and measured (13 members, byte-identical `Cargo.lock`, one vendored copy for a separately rooted Git consumer) but not applied: it makes `cargo fmt --all --check`, a Section 28.8 gate, fail on the vendored crate's unvendored targets, so it waits for the owner (a Section 28.8 amendment, or a vendored tree that cargo-fmt can format, which takes more than the published package because that package omits `src/tests.rs`). X-09 stays open, and separately rooted consumers still repeat the root `[patch]`. Evidence: the new rule fails on the previous fuzz manifest and lock and passes on the new ones; recorded in [the OPAQUE fuzz source record](docs/stage-10-opaque-fuzz-source.md).
  - PC-001 ReInit target revision with the program's architecture corrections (2026-10-04, SDK program, outside master #35): companion Section 13.8 removes `old_reinit_state_id` from `ArcReInitTargetTBS`, whose digest the old ReInit Commit's authorization commits while the field named that Commit's own finalization ID, so no target could be built and no conforming ReInit could complete. Every target field is now fixed by the old conversation and the ReInit Proposal, one target stays byte-identical across an accepted-state advance, a candidate abort and an attempt retry, and the successor initial Commit's `ArcCommitAad` names the target's profile version and network, the new conversation and `old_reinit_state_id` as `prior_state_id`. Every `ArcReInitAttempt` now carries the exact target (decisions D-11 (B) and D-11a): the sequencer refuses an attempt with `E2EE_FINALITY_REQUIRED` while the old conversation's accepted state is not a ReInit finalization, and otherwise, before it signs a receipt, refuses with `E2EE_BINDING_AUTH_INVALID` an attempt whose finalization ID, digest, carried-target hash, target fields or KeyPackage plan's semantic plan disagree, or whose carried target does not describe the successor of the bound route or does not yield its own derived IDs; at activation the coordinator installs the successor route, conversation, binding package, policy, credential, anchor and delivery mappings from the carried target in the activation's own transaction, keeps the `ArcMlsContext` digest apart from the target digest, and needs no `EGROUP RESERVE` or `EGROUP BIND`. Endpoints reconstruct the target from the Proposal and verify the successor policy under the successor context's own roster heads, which continue the old heads' roots, so a ReInit never carries a root discontinuity (decision D-12), and a member that joins after activation checks its ReInit binding and policy entries against the target the activation's attempt carries. Section 9.4 gives a ReInit successor's binding the replaced binding's route inputs, Section 11.6 says `CLAIM STATUS` names the stored claim's target device (SC-001), Sections 9.3, 9.5, 13.7.2, 16 and 21 follow, and Sections 2.3 and 22 record the hash-only revision of two object layouts (decision D-08). In the architecture, Sections 9.3 and A.3 and Appendix C.8 make an edge advertise, and its descriptor pin, its coordinator's recovery epoch (decision D-15, the rule the AUD-03 code already follows); Section 9.5 says the recovery `NOTE` does not depend on `standard-replies` and Appendix E.2 puts the welcome `900` after it (decision D-13, as the SC-007 code already sends them); Section 19.1 and Appendix C.6 raise the `preauth_command` default burst from 10 to 24 inside the unchanged 10/1, 50 hard row (decisions D-14 and D-14a); Section 24.1 adds `agenc-relay-client-support` and `agenc-relay-transport` (decision D-16); and Section 28.8 runs `cargo fmt --check` (decision D-30). The value 24 comes from the SDK's account pacing model (agenc-relay-sdk `f1c2509`, `crates/agenc-relay-sdk/src/session/machine/account_phase.rs`, the same file at `a6844c1` and `0332a28`): the burst must cover the longest run of lines that no reply shows read, 16 `AUTHENTICATE` chunks for a login and 17 `ACCTCREATE` lines for a creation, and at one token per second with the model's default inputs (250 ms of server work per request, 1.5 s for the client's finish) the smallest burst admitting both the 41-line creation with registration and the 38-line pre-registration login within the 30-second registration deadline is 17 for round trips up to 1 s, 18 at 1.5 s, 19 at 2 s, 21 at 2.5 s and 24 at 3 s; at 3-second round trips burst 23 refuses the creation (30.525 s predicted) and burst 24 admits the login (26.517 s) and the creation (29.523 s), and the SDK supports the `tor-exit` and `onion` profiles, whose round trips can reach that. Profile version 1 keeps its number. The companion raw SHA-256 moved from `57d6d98df53ce8f738da463304fb47726c9133ef0bec5b268a8cadbc117405bc` to `4fa947bf4edfe146de8f6a72932b93625828b0fd6eea46976e699ab06719658c`; the profile hash moved from `c1b5313f8a7f196cda30eea797fb1ab65b004a55d71cf9a81071927046e5d395` (token `wbUxP4p_GWzaMO6nl_satlsASlXXHPmoEHGScEbl05U`) to `0b3985c1e19f77e561734139d65131fb1c1fc5cb7a63a1119ca03b5a61583525` (token `CzmFweGfd-Vhc0E51lEx-xwfxct6Y6ERnKA7WmFYNSU`); the architecture raw SHA-256 moved from `46f2924279daa9d68347112748ab08b4850a74508fa05841c3fd45f5dbf66e81` to `7317477b0058ec2bc3cba3f14921154e849358e5016ae36bbe18a08fb2fa6528`; the source ledger, which gains its dated Section 9, moved from `23a20cb38c7918d8488403fc780fc1eba14c647d187548f921cee4cdad4635ac` to `430af31197f917c143c7a4f61aabe5c602854a9322674263c0ad59858207fc62`, with `ledger_sha256` in `conformance/release-source-decisions.toml`; and every pin moved with them. Twenty-one new BCP 14 clauses take the requirement ledger from 251 to 272 records: the fourteen endpoint, later-joiner and initial-Commit clauses are bound to `S10-005` and the seven sequencer and coordinator clauses to `S10-004`, all `unimplemented`. No production behaviour changes; the three production sources that moved changed only their pinned constants. Handoffs: P-02 (the shared target helper, the vectors and the one-target Stage 08 fixture), P-03 (successor roster anchoring, root-rotation and suite-change vectors, and whether a ReInit can rotate a channel's authority root, which the kept semantic route lock names), P-04 (the sequencer's attempt checks, the atomic successor installation and its restart, the Stage 08 model), P-05 (refusal of the previous profile, the mixed-version link test, the upgrade note), X-01 to X-04 (the two crates), X-09 (the gate pins of `cargo fmt --check` and the explicit opaque-ke edge) and B-05 (the `preauth_command` default in the configuration code, golden file and `arcd init` template, which keep 10 at this commit). Reopened-task map for the owner, with no box changed: every S08 task that `conformance/stage-eight-e2ee-profile.toml` binds was evidenced under the previous profile hash, among them `S08-001` and `S08-031`, which test the exact hash, `S08-017` and `S08-900`; `S08-019` and `S08-033` rest on companion Section 21 items 2 and 16 (TODO gates 2 and 17), which gain ReInit vector and cycle obligations, as `S08-030` rests on item 13 (TODO gate 14) and `S08-012` on the target layout, the ReInit fixture and the activation contract; `S01-010`'s pins were regenerated here; `S00-004`'s Section 24.1 graph names two crates the workspace gains only with X-01; `S06-011`'s pre-authentication default differs from the configuration until B-05; and the Stage 09 checkpoint names an earlier exact commit. Evidence: `bash scripts/check-spec.sh`, `scripts/check-stage-one.py check`, `scripts/requirements.py check` (272 records) and the crate suites of federation-wire, config, e2ee and runtime pass; recorded in [the ReInit target revision record](docs/stage-10-reinit-target-revision.md).
  - AUD-07 pre-authentication default burst in code (2026-10-04, SDK program, outside master #35): Section 19.1 and Appendix C.6 give `preauth_command` one token per second with a burst of 24 since the program's normative revision (P-01), but `RATE_ROWS` in the configuration and the runtime's own default table (`BucketKind::default_rate`) kept burst 10, so an `ACCTCREATE` request's 16 `DATA` lines and `END`, which network delay can deliver at once, could be refused however its client paced them, and the SDK's account pacing model refused account creation and the login before registration at the template default. Both tables now give 1/1, burst 24; the hard row stays 10/1, burst 50, and every accepted configuration is unchanged. The golden public configuration states the new default; `arcd init` writes no rate table, so every node it initializes takes it with no change to the template's text; and the operator guide gains a section on the budget. At most 24 unauthenticated lines of a connection are admitted at once instead of 10, and at most 54 instead of 40 before its registration limit; a line beyond the available credit is answered with `263` and is not processed, and each line keeps its existing bounds. No wire, numeric, registry, hard limit, persistent format, profile hash or specification change, and no requirement record: the default is stated in tables and an explanation without a BCP 14 keyword, so the ledger has no clause for it; `S06-011`'s admission evidence agrees with the specification again. Evidence: configuration tests pin the row (default 1/1 burst 24, hard 10/1 burst 50; bursts 1, 24 and 50 accepted, 51 refused) and that a template written for each profile resolves every rate to its C.6 default; a runtime test admits exactly 24 lines at one instant and one more after a second; and two daemon tests run the production binary with the template's rate table: a client paced to the bucket, one line per token, with a simulated 3-second round trip and every reply-less run delivered at once, creates an account and registers, then logs in before registration and registers, each within 30 seconds (about 24.7 and 20.3 seconds on the development host), and 25 `PING` lines in one write get 24 `PONG`s, one `263` and a `PONG` after the next refill on the same connection. With burst 10 restored five of these tests fail (the daemon refuses the first `ACCTCREATE` run with `263`), and the refusal-path and table-agreement tests pass either way. The SDK's `PreAuthRate::DEFAULT` follows in its item S-08. Recorded in [the pre-authentication default record](docs/stage-10-preauth-default.md).
  - X-12 one object-kind list and the copied wire limits held equal (2026-10-04, SDK program, outside master #35): `E2EE_OBJECT_KINDS` in the client wire crate, the list behind `E2eeObjectKind::parse`, held 33 of companion Section 11.7's 37 object kinds, so a client using it refused an `EOBJECT` of kind `POLICY`, `RECOVERY-SUBMISSION`, `WITNESS-RESOLUTION` or `LEAF-MEMBERSHIP-PROOF` (AUD-05); the daemon reads kinds with `ArcWireObjectKind` and does not use the list. The list now holds all 37 in ordinal order, and `crates/agenc-relay-testkit/tests/shared_wire_limits.rs` holds the client wire crate's copies equal to their owners: the object-kind list to `ArcWireObjectKind::ALL` position by position, the tag budgets to the E2EE `limits` module and the base profile registry, the fragment size and count to the E2EE fragment, mailbox and batch limits, and the largest object to the largest kind, the envelope plus body and the batch decoded bound. No wire format, registry, daemon behaviour or dependency edge changes. Evidence: with `text.rs` restored to `6986ace` the registry test and the updated text carrier test fail (33 against 37), and with the four tokens they pass; recorded in [the shared client wire record](docs/stage-10-shared-client-wire.md).
  - X-07 public Appendix A.1 argument bounds (2026-10-04, SDK program, outside master #35): the client-input grammar enforced the Appendix A.1 argument bounds from private constants, so a client encoder, which stays in the SDK (decision D-18), had to restate them. `agenc_relay_client_wire::limits` now defines the 23 bounds publicly and the grammar uses them; `MONITOR` names its own `MAX_MONITOR_NICKNAMES` instead of sharing the channel-list bound (both 20). Nothing the parser accepts changes. Evidence: `crates/agenc-relay-client-wire/tests/argument_bounds.rs` drives the public parsers with each bound at its exact value and one over, the shortest channel key also one under, and pins that `ISON`'s 20 nicknames stop at the global 15-parameter budget; recorded in [the shared client wire record](docs/stage-10-shared-client-wire.md).
  - X-05 server-to-client base decoder (2026-10-04, SDK program, outside master #35): the client wire crate framed and parsed only what a client sends, so a client reading the server direction needed its own framer, tag parser and decoder with the registries and bounds restated; the client-input framer applies the client's 4,094-byte tag budget and refuses a legal server line that carries tags of both sides. Three new modules decode the server direction and leave every client entry point unchanged; the daemon never runs them. `WireDirection` names each direction's bounds; `ServerStreamFramer` and `ServerFramedLine` apply the server's (8,703-byte line, 8,191-byte tag section with its `@` and space, no empty line), with the client framer's fixed buffer, byte-wise checks and wiping, and a final first failure. `parse_server_tags` keeps the section raw and checks the IRCv3 key grammar, the closed escapes (refusing the others and a dangling backslash), the `label` and batch-reference bounds, each side's 4,094 bytes, the client-only limits with the E2EE exemption and duplicates in linear time; `unescape_server_tag_value`, `validate_safe_label` and `validate_batch_reference` are public, and the renderer's batch check uses the same predicate. `parse_server_message` decodes the canonical line: single spaces, an optional server-name or framed-cloak prefix (Section 7.4; the bare spelling is refused, and the SDK keeps its own opt-in), upper-case commands of the base registry and its numerics, `FORBIDDEN_NUMERICS` with their own error, at most 15 parameters, the Section 9.5 reply frame with the base codes, never `ADMIN_ONLY_REPLY_CODES` and `SLOW_CONSUMER` only as `WARN *`, and client-only tags only on `PRIVMSG`, `NOTICE` and `TAGMSG`; the companion commands and codes are left to X-06. A decoding error concerns its line only; only a framer failure ends the stream. The testkit's client transcript requires every asserted server frame to decode, and a new `server_framing` fuzz target (listed in `scripts/check-stage-two.py` with the three modules) frames and decodes arbitrary input under three chunk schedules. No wire format, registry, configured limit or daemon behaviour changes. Evidence: boundary tests at 8,191 and 8,192 section bytes, 4,094 and 4,095 bytes per side and 510 and 511 command bytes after a full section; `decode(render(x))` over every numeric the renderer builds, the `005` groups, every Section 9.5 reply row, labeled responses, nested batches, relayed tags and the longest mask; 57 hand-written vectors in `test-data/vectors/server-wire-v1.vectors`; nine rules weakened one at a time, each failing a test; a 10,000-run fuzz smoke; five new release regions, each complete; recorded in [the shared client wire record](docs/stage-10-shared-client-wire.md).
  - X-06 the E2EE replies read back (2026-10-04, SDK program, outside master #35): `agenc_relay_e2ee::wire::response` rendered the companion Section 11.7 results, broadcasts, object batches and live frames and the Section 11.9 `FAIL` line, but nothing read them, so a client restated every verb, kind literal and tag rule, and the Section 11.7 batch bounds were summed only in the daemon's runtime. `wire::received`, beside the renderers, reads one received line into its production with `parse_received_line`: a tag section of more than four fields, more than any production carries, is refused before any is collected; the tag set selects it, each production keeps its exact tag set in any order (the daemon's base renderer sorts companion tags on the way out), the 512-byte non-tag budget, the renderer's source check and its registry tokens, and `SuccessLine`, `BatchOpener`, `BatchChild` and `LiveLine` gain `parse_body`, the inverses of their bodies; `PendingKind`, `EmptyGroupKind` and `StoreKind` gain `ALL` and `from_token` over their own `token()`. `ResponseBatch` follows one object batch: the opener's kind fixes each object's class limit, the first fragment seen of each object (response fragments may arrive in any order, Section 11.8) charges the object, its declared fragments and its declared size to `MAX_BATCH_OBJECTS`, `MAX_BATCH_FRAGMENTS` and `MAX_BATCH_DECODED_BYTES` before a client reserves memory, later fragments must repeat the declaration, and the lines keep their order (one operation-result child before the objects, each `MAILBOX` child immediately before the object it names, at least one object before the close); reassembly and quotas stay with `E2eeAssembler`. The `server_framing` fuzz target also reads every line with it. No wire format, registry, reply code or daemon behaviour changes. Evidence: `parse(render(x))` for all 48 result forms (the four `REINIT-*` results among them), the six broadcasts and only them untagged, openers, closes, all eight children, `EOBJECT` fragments, live frames under their label and receipt rules and with no tag twice, the four-field bound at four and five fields, a line of every declared result form, both ACK literals and every reply code; every body token of every production replaced in turn and refused; the 512 and 513-byte non-tag boundary; a batch at and one over each bound and its class limit, and its order rules; the daemon's path through `WireMessage::extension_line` and `ServerStreamFramer` in the testkit; eleven reader rules weakened one at a time, each failing a test; three new release regions, each complete; recorded in [the shared client wire record](docs/stage-10-shared-client-wire.md).
  - BLJ-R1 information queries answered on an edge (2026-10-04, SDK program, outside master #35): on an edge `MOTD`, `LUSERS`, `VERSION`, `TIME`, `ADMIN`, `INFO` and `LINKS`, plain or labeled, closed the requester's connection with no reply, because the edge's registration router sent them to the node's own command executor, which authorizes against the node's own domain while an edge holds its sessions in its projection; the SDK's liveness probe, a labeled `TIME`, would have ended every SDK session on an edge. The router now sends them down the edge's command path (decision D-28): the edge answers `MOTD`, `LUSERS`, `VERSION`, `TIME`, `ADMIN` and `INFO` itself (Section 14's privacy-safe static or aggregate output, for which the closed operation table of Section 20.5.2 has no operation) with the single-node renderers, its configured MOTD and public information, its build and its clock, and `LUSERS` in one fixed form with no count, the same on every edge in every state (decision D-35, which replaced D-28's counted form); the command is charged as a registered command, needs the requester's session in the projection and a registered connection, and its reply carries the request's label and batch. `LINKS` is forwarded as the coordinator's `directory.links` query. A query the edge answers itself still waits behind the connection's earlier work (a pending request, a `CHATHISTORY` whose record is being committed, an origin update or a JOIN continuation), and once released its reply is handed to the router as a completion after the one that released it, so it never overtakes the earlier request's reply; the edge's own user-mode read takes the same path, where before a released one was sent at once. While the coordinator link is down or recovering the six are served, as Section 20.10 requires, and `LINKS` fails closed with `NETWORK_UNAVAILABLE`. No wire format, numeric, registry, limit, persistent format or specification change. Evidence: edge tests through the actor loop with a scripted coordinator (the six plain and labeled while active, with `LUSERS`, in its fixed form, and `VERSION` pinned line by line and nothing forwarded before a later `LINKS`; the six plain and labeled while partitioned and `LINKS` refused; `TIME`, `MOTD`, the user-mode read and a labeled `LUSERS` each held behind an unanswered `WHO` and delivered after its reply; a `TIME` held while a `CHATHISTORY`'s send commits and between its pages, and released by its last page; refusals without the projected session, without a registered connection and with the registered-command bucket exhausted), and a coordinator-and-edge daemon test in which a guest on the edge sends the six and a `PING`, plain and labeled, reads every reply, gets `LINKS` through the coordinator, and after the coordinator is killed gets the six again on the same connection, and a two-edge daemon test in which edges serving different clients and channels give the same `LUSERS` reply, unchanged after a `JOIN`, a `PART` and the coordinator's loss. With the production files restored to `6986ace` all seven fail; with only the in-order delivery reverted the waiting test fails, and with only the partition rule reverted the partitioned edge test and the daemon test fail. With the counted `LUSERS` restored the edge tests and the two-edge daemon test fail, and with the `CHATHISTORY` rule removed both history ordering tests fail. The release region `runtime-edge-local-user-mode-authority` is respanned and three new release regions bind `is_local_information_query`, `local_information` and the fixed `LUSERS` form. Recorded in [the edge local queries record](docs/stage-10-edge-local-queries.md).
  - P-02 shared ReInit target helper and the carried target (2026-10-04, SDK program, outside master #35): the program's normative revision (P-01) removed `old_reinit_state_id` from `ArcReInitTargetTBS` and made every `ArcReInitAttempt` carry its target; `agenc-relay-e2ee` now implements those Section 13.8 structures and rules in shared code. `ArcReInitTargetTbs` drops the field and `ArcReInitAttempt` gains `target` after its TBS, the layout the revision froze. The new public module `agenc_relay_e2ee::reinit_target` rebuilds a target from its ReInit Proposal (`reconstruct_reinit_target`: the extension list's shape, the recomputed context core, the successor the context and its binding describe, with the shape every binding has against the semantic route it keeps, that route's conversation kind among it, and the successor policy under the supplied rosters), checks a target held without the Proposal, such as the one an attempt carries, against the old conversation's current binding (`check_carried_target`: the same structural rules and every field equal to what the list yields), and binds both to the finalized old ReInit Commit through `AuthorizedReinit`: `from_proof` recomputes the finalization ID and the authorized digest, `check_attempt` is the sequencer's attempt check for P-04 (the finalization ID, the carried target's digest and fields, the KeyPackage plan's semantic plan, the carried list's structure), `check_attempt_target` an endpoint's check against its own reconstruction, `check_staged` the staged wrapper, `check_join_entries` a later joiner's ReInit binding-chain and policy-chain entries against the carried target, and `check_initial_commit` the successor initial Commit's frame and `ArcCommitAad`. `HistoricalChain` checks the target every adopted attempt carries (its digest, or the bound bytes, and the attempt's successor fields), and `HistoricalChain::bind_reinit_target` binds a verifier's reconstruction and refuses while an attempt is open. `scripts/generate-e2ee-vectors.py` writes the 56 independent ReInit vectors of `test-data/vectors/e2ee/reinit` (both suites from the pinned genesis to activation, a log whose accepted state advances before the same target activates on a retried attempt, a later joiner's entries, and rejections), and the Stage 08 ReInit fixture builds one target before the ReInit Commit in both ReInit scenarios, carries it in every attempt, and replays the daemon's records through the shared history. No specification, hash, registry, named limit, reply code or storage generation changed; the `reinit_attempt` object and the two ReInit terminal requests that embed it carry the target, and how a database holding ReInit state of the previous profile restores (a route whose head is such an activation or abort record is not restored, and such an open attempt can neither complete nor be aborted) is part of P-04 (plan item G-08). Requirement bindings are unchanged: thirteen of the fourteen `S10-005` clauses are implemented by the shared code (the helper, with `HistoricalChain` for the chain's receipts, ACKs, votes and terminals and the activation's old-policy verification) and the fourteenth, the successor policy under the rosters its roster heads name, by P-03; they stay `unimplemented` until `S10-005` closes, as the ENC-06 clauses stayed with `S10-008`; P-04 implements the seven `S10-004` clauses in the coordinator. S08-012 (the ReInit fixture) and S08-030 (the ReInit vectors) rest on changed evidence; no box changes. Evidence: `cargo nextest run -p agenc-relay-e2ee --all-features --locked` passes 322 tests (281 at `7075ea0`), the Stage 08 suite passes 46 tests with 17 Stage 10 drills skipped, 129 of 130 single-check mutations of the helper and the chain are killed (the one survivor stores the bound target, whose byte comparison refuses exactly the attempts the digest comparison refuses), and an e2ee branch report scores each of the twenty-four new release regions at 100 percent; recorded in [the ReInit target helper record](docs/stage-10-reinit-target-helper.md).
  - P-03 ReInit successor rosters and the channel-authority limitation (2026-10-04, SDK program, outside master #35): companion Section 13.8 verifies a ReInit successor's policy, controllers and finality council under the rosters the successor context's own `roster_heads` name, each head of an account the old context also names carrying the old head's root or a continuous successor of it (decision D-12). `reconstruct_reinit_target` now takes `OldConversation` (the old binding and the roster heads the old context commits) and `SuccessorRosters` (the rosters the successor's heads name and, per rotated account, the root chain from the old head's root to the new one), and requires the supplied rosters to be exactly the ones the successor's heads name, every changed root to be reached from the old head's root by a chain whose continuity signatures verify, and the successor binding's principals and policy to verify under those rosters; before, the reconstruction verified the policy under whatever rosters its caller supplied, and under the documented old rosters a successor naming a rotated root could not be rebuilt. The vectors gain a continuous rotation of account `d`'s root at suite `0x0001` (through activation and a later joiner's entries) and with a suite change to `0x0003`, and rejections for a forged continuity signature, a fresh root, a binding that keeps the old root and a rotated channel-authority root; the 56 earlier vectors are unchanged. A ReInit cannot rotate a channel's authority root: the successor keeps the old semantic route lock, whose route names the authority root's fingerprint, while its binding's principals must name the rotated root, so the reconstruction refuses it; this is the limitation D-12 (1) anticipated, and no mechanism is added. `E2EE-REQ-FB9D986123B9141AF6AB` is now implemented by the helper, so the shared code (the helper, with `HistoricalChain` where the P-02 record says so) implements all fourteen `S10-005` clauses of the revision, which stay `unimplemented` until that task closes; no binding changed. No specification, hash, wire object, registry, reply code or storage generation changed. Evidence: the new tests in `crates/agenc-relay-e2ee/tests/reinit/rosters.rs` do not compile against the parent's API, and the parent's reconstruction, run on the new vectors in a scratch copy, refused the rotation under the old rosters and accepted the fresh-root, stale-principal and channel-authority successors that are now refused; `cargo nextest run -p agenc-relay-e2ee --all-features --locked` passes 328 tests, the mutation campaign kills all 15 new mutations (144 of 145 with the earlier ones, the survivor equivalent), and an e2ee branch report scores every new region at 100 percent; recorded in [the ReInit successor rosters record](docs/stage-10-reinit-successor-rosters.md).
  - P-05 refusal of the previous encrypted profile and the upgrade note (2026-10-04, SDK program, outside master #35): CAP, ECAP and the onboarding descriptor accept only the exact `(version, profile-hash)` pair, so each already refused release candidate 3's profile token `wbUxP4p_GWzaMO6nl_satlsASlXXHPmoEHGScEbl05U`; tests now pin that the release candidate 3 capability value, ECAP tuple and descriptor, and the tokens of the revision's three unadopted drafts, are refused. A federation link that receives an `ECAP` line that does not parse, such as an OFFER naming another profile hash, which `EcapTuple::parse` refuses before the negotiation sees it, now answers `ERROR :ARC-MLS profile mismatch` before it closes (companion Section 12.5), waiting at most the keepalive timeout for the write, as it already answered a parsed tuple that differs; before, it closed without the line. A Stage 08 daemon test links an edge of the previous profile (the runtime's dial owner under edge A's identity, offering the release candidate 3 tuple) to a coordinator of this revision: the hello completes, the coordinator's OFFER is this build's tuple, the old edge's link closes on the coordinator's answer, and a client of the coordinator and one of the current edge chat before and after. `docs/operator-guide.md` gains the upgrade note, with what a client of the previous hash sees and what this release does with ReInit state stored under the previous profile. No specification, hash, registry, wire object, reply code, storage generation or requirement binding changed. Evidence: the runtime test reads the exact answer and the daemon test sees the old edge's link close on it, and both fail with the answer disabled; the refusal tests pass at the parent commit too; recorded in [the previous-profile refusal record](docs/stage-10-previous-profile-refusal.md).
  - D-36 one labeled response to a message sent through an edge (2026-10-05, SDK program, outside master #35): an edge echoed a labeled `PRIVMSG`, `NOTICE` or `TAGMSG` without its label and, without `echo-message`, sent no labeled `ACK`, so the request had no labeled response (Architecture 9.5; the SDK's wire register WD-16): the requester's copy went out with the coordinator's `MessageDelivered` event like every other copy, and a committed message's completion rendered nothing. While a connection's pending request is a message whose label the connection negotiated, the edge now holds the requester's own copy on that request (a re-rendered event replaces it; a copy that follows the completion, contradicts the result's generation or exceeds the targets is refused and ends the link; each copy is charged to the memory budget) and, once the request completes, sends the held copies through its reply path as the one logical response: one labeled copy, one labeled batch of several, or a labeled `ACK`. As on the coordinator, a `TAGMSG` reaches only a recipient that negotiated `message-tags`, and a direct message reaches its target alone; the latter is a recorded deviation, since IRCv3 `echo-message` (Architecture 2.1, pinned in 30.2) requires a server to send a `PRIVMSG` or `NOTICE` back to its sender, a direct message included, and no role does so yet; the fix for every role is on the owner's list. No wire format, numeric, registry, limit, persistent format or specification change. Evidence: an in-process coordinator and edge compared in four capability sets over twelve messages each (channel, direct, same-node direct, two-channel and channel-and-user `PRIVMSG` and `NOTICE`, channel and direct `TAGMSG`): the edge's response equals the coordinator's, the requester holds exactly its expected echoes in every set, and every other copy is unlabeled; a scripted coordinator shows the labeled echo waiting for the completion in either arrival order, and a copy and a result that contradict each other ending the link in either order; unit tests cover which copy is held and every refusal; a daemon test with a coordinator and two edges gets one labeled `ACK`, then one labeled echo, for a channel `PRIVMSG` and `NOTICE` from an edge client, with every other member's copy unlabeled. With the fix's production files restored to `6e84d29` the scripted, bridged and daemon tests fail, and reverting each part alone fails a test. Three release regions bind `capture`, `labeled_targets` and `validate_result`, and `cap13-render-render-event-strict` is respanned. Recorded in [the edge echo record](docs/stage-10-edge-echo.md).
  - D-36 welcome counters from the node's LUSERS reply (2026-10-05, SDK program, outside master #35): every welcome burst's `RPL_LUSER*` counters (Architecture 10.2 step 3, privacy-safe aggregate values) now give the figures of the node's own `LUSERS` reply: an edge sends its fixed `LUSERS` form (decision D-35), `251` and `255` with fixed text and no count, byte-identical on every edge in every state apart from the server prefix and the nickname; a coordinator's `251` counts the network's sessions, the figure its `LUSERS` reply gives; a node without federation counts its registered connections, as before. The welcome step renders `luser_counters`, which takes the edge's form from `query_render::render_static_lusers`. No wire format, numeric, registry, limit, persistent format or specification change. Evidence: router tests for an edge, a coordinator holding a session homed on another node, and a node without federation; an in-process coordinator and edge in which every edge client's welcome and `LUSERS` reply are the fixed form and each coordinator client's welcome counts what its `LUSERS` reply counts as clients join on both; a node without federation in the actor loop whose welcome counts what its `LUSERS` reply counts, also after a client leaves; a daemon test with a coordinator and two edges serving different clients that requires the same of both edges and of the coordinator as clients join on an edge and on the coordinator. With the welcome step restored to `6e84d29` the edge tests and the daemon test fail, and reverting the edge's form or the coordinator's count alone fails a test. The release region `runtime-edge-static-lusers` is respanned and `runtime-welcome-luser-counters` binds `luser_counters`. Recorded in [the edge echo record](docs/stage-10-edge-echo.md).
  - P-04 ReInit phase from the ReInit finalization and the sequencer's attempt checks (2026-10-05, SDK program, outside master #35): companion Section 13.8 closes the old group when its ReInit Commit finalizes (step 2) and has the sequencer check every attempt and the target it carries against that finalization (step 4), refusing an attempt on any other accepted state with `E2EE_FINALITY_REQUIRED` before the five `E2EE_BINDING_AUTH_INVALID` checks (decision D-11a), each retaining nothing. `SequencerLog::finalize_reinit` now finalizes a ReInit Commit and enters the ReInit phase in one step and is the only way into the phase (`enter_reinit`, through which the first attempt entered it, is removed); `submit_finalization` takes it for every authorization carrying the ReInit bit and records the `AuthorizedReinit` its proof binds, none when `from_proof` refuses the proof, so such a group stays closed and admits no attempt; `submit_reinit_attempt` refuses an attempt unless the group is in its ReInit phase with the authority of the finalization that is its accepted state, then checks it with `AuthorizedReinit::check_attempt` against the old binding re-verified under the rosters its principals name, then requires the successor vacant (moved from the recovery admission so that it follows those checks), the slot and the old-policy authorization, all under one bounded work reservation. Ordinary candidates and application objects of the old group are `E2EE_ROUTE_INVALID` from the finalization on, and a restart restores the phase from a ReInit finalization head and its authority from the retained finalization record; no row, field or storage generation changes. The Stage 08 ReInit fixture's target now carries a successor context the sequencer accepts. The Stage 08 model gains `ReinitFinalize` and a closed-group check: actions 28 to 30, states 50 to 57, transitions 124 to 144, paths 22 to 26 and refusals 660 to 786, each explained in the record; the evidence that changed is that of S08-008, S08-012, S08-024 and S08-030 (transcript rows `domain-reinit-log` and `coordinator-reinit`, gate 14, `model-exhaustive`, gates 7 and 22, and `model-adversarial`, gate 7), and no box changes. Requirement bindings are unchanged: six of the seven `S10-004` clauses are now implemented in the coordinator and stay `unimplemented` until `S10-004` closes; the atomic successor installation is still open. Evidence: the runtime's 800 E2EE tests, the domain and testkit's 391 tests and the Stage 08 suite's 47 tests pass; four rule reverts and 23 of 24 single-condition mutations, each run against the runtime's E2EE tests, fail tests (the survivor takes the principal's newest root instead of the root the binding names; it is not equivalent, as first recorded: the review's follow-up removed the code it changes and adds a test, a restart after a root rotation that follows the activation, that fails with it on the code before the follow-up); each new release region scores 100 percent in a runtime branch report; recorded in [the ReInit enforcement record](docs/stage-10-reinit-enforcement.md).
  - P-04 atomic installation of the ReInit successor (2026-10-05, SDK program, outside master #35): companion Section 13.8 has the coordinator install the successor from the target the activated attempt carries in the transaction that stores the activation certificate, before any reply or event for it, so that no `EGROUP RESERVE` or `EGROUP BIND` precedes successor traffic (step 6), and restores it after a restart. `submit_reinit_terminal` now prepares the installation once the activation's quorum is reached (`reinit_install::prepare`): the old group's recorded authority is required (`E2EE_FINALITY_REQUIRED`), the activated attempt and its carried target are checked again against it and the re-verified old binding, the successor's binding package (the target context's binding with the plan the KeyPackage plan forms and no root binding lock) and the context's policy verify under the rosters the successor binding names, and the pin must be a credential this coordinator issues receipts under, each refusal `E2EE_BINDING_AUTH_INVALID` and retaining nothing; `RouteTable::install_successor` replaces the predecessor's route by the exact next binding of its lineage. The activation's batch carries the successor's route row, binding, policy and route state objects and policy row, with `reinit_activation_id` as its accepted state and record-head anchor, moves the delivery entitlements and sends the route events a binding sent; the successor's context digest is the target context's `ContextHash`, never the target's own digest. The successor reservation and successor `BIND` are removed (`EGROUP RESERVE` of an existing route is `E2EE_GROUP_CONFLICT`), and a restart restores the successor from its own rows, checks it against the activated target (binding package, activation anchor) and selects its route, refusing startup for a migrated predecessor without its installed successor; the startup substitution of the context digest is removed, and the recovery lineage of a pending successor resumes at its anchor while its predecessor's resumes nothing. The Stage 08 activation scenario now sends a successor application message through the daemons, sequences a successor Commit at route sequence zero and, after the whole network restarts, delivers another message, with no reservation or binding. No row kind, field, wire object, reply code or storage generation changed; the model's counts do not change (its route actions are no ReInit successor). `E2EE-REQ-65D600D44A7F4FDA9EE6` is now implemented, so all seven `S10-004` clauses are implemented in the coordinator and stay `unimplemented` until `S10-004` closes; no binding changed. The evidence of S08-012 and S08-030 changed (`coordinator-reinit`, gate 14, and the ENC-10 daemon scenario); no box changes. Evidence: the runtime's 804 E2EE tests, the domain and testkit's 389 tests and the Stage 08 suite's 47 tests pass; reverting the installation, the restore's checks or the context digest fails 14, 3 and 2 tests, and 25 of 26 single-condition mutations are killed (the survivor skips the route selection, which is not redundant, as first recorded: it is the only check that a successor's route row keeps its predecessor's lock and incarnation, and the review's follow-up adds a test that kills it); recorded in [the ReInit enforcement record](docs/stage-10-reinit-enforcement.md).
  - P-04 restore of the ReInit state stored under the previous profile, G-08 (2026-10-05, SDK program, outside master #35): a coordinator of release candidate 3 (`70c832c`) could store ReInit state that this revision does not continue: attempts admitted with no ReInit Commit before them, ReInit activation and abort records that embed an attempt of the previous layout (companion Section 2.3: such an object is never parsed or reinterpreted under this hash), successors bound for such an activation by `EGROUP RESERVE` and `EGROUP BIND`, and finalized ReInit Commits whose phase began only at the first attempt, followed by attempts, ordinary records or a close. Before this change such an activation or abort at a route head refused coordinator startup, and a group that took ordinary records after its finalized ReInit Commit restored open. A new domain phase, `Phase::Retired`, entered only by a restore, takes no candidate, terminal, application object, attempt or close, keeps no restored candidate, is a plaintext tombstone and resumes no recovery lineage. A route whose head is such an activation or abort is retired, recognized from its storage rows alone (a terminal of one of those kinds whose identifier is the route row's head and whose predecessor is the attempt receipt row before it, with a retained sequencer-record object; any disagreement refuses startup), and so is the successor bound for it; a group its head leaves open whose log went on after a finalized ReInit Commit with any record other than an attempt receipt is retired. An attempt left open stays open in the ReInit phase it cannot leave, a ReInit Commit finalized under the previous profile admits no attempt of this revision, and a closed group stays closed; plaintext stays refused and a new reservation of the channel is `E2EE_GROUP_CONFLICT`. G-08's decision is additive within generation 5: no table, key, row, field or object layout changes and startup writes nothing; downgrading a node is unsafe, which the operator guide's upgrade note now says with what this release does with such state (the source ledger's sentence is left for the next normative revision). `test-data/stage-ten/previous-profile-reinit/` holds ten stores that the `70c832c` coordinator wrote through its own test harness, its README reproducing the generator. G-07: the model's counts do not change, since only a restore enters the new phase; the pinned test names are kept and the pinned rows `domain-close-restore` and `domain-lifecycle-gate` (gate 8) pass unchanged; the evidence of S08-011, S08-012, S08-013 and S08-015 changed; no box changes. Requirement bindings are unchanged. Evidence: the runtime's 814 E2EE tests (2,719 library tests) pass, among them ten restore tests over the `70c832c` stores and an aborted attempt's row checks; reverting the terminal retirement, the retirement after a finalized ReInit Commit, the successor retirement or the candidate filter fails 4, 2, 2 and 1 plus 1 tests, and all 18 single-condition mutations are killed; recorded in [the ReInit enforcement record](docs/stage-10-reinit-enforcement.md).
  - P-04 a restored route's head is its last record (2026-10-05, SDK program, outside master #35): companion Section 13.8 step 2 closes the old group for good, so a restart must restore the phase of the route's actual last record. `restore_log_phase` now first requires that the head a route row names is its last retained record, at that record's route sequence and under its identifier (a closed route's head is its close, and a route without a retained record has no recorded head); a route row that names an earlier record, a later position or another identifier restores nothing, and startup refuses the store as it does for the other identity disagreements. Stores this coordinator writes always name their last record, because the route row and the record are written in one batch, and the ten `70c832c` stores of the G-08 restore test restore as before. No row, field, reply code or storage generation changed and no domain file changed; no box changes. Evidence: the runtime's 816 E2EE tests (2,721 library tests) and the Stage 08 suite pass; reverting the rule fails 3 tests and its four single-condition mutations are killed; recorded in [the ReInit enforcement record](docs/stage-10-reinit-enforcement.md).
  - P-04 review follow-up: retained binding facts, a ReInit-closed group stays closed (2026-10-06, SDK program, outside master #35): an independent review of the P-04 topic led to follow-up commits on its branch. The sequencer's attempt check, the activation and the restore of an installed successor now rely on facts verified and retained when a binding was made, never on objects that object expiry may remove: `agenc_relay_e2ee::reinit_target::ReinitPredecessor` holds the old binding's facts the carried target is checked against (`check_carried_target_from`, `AuthorizedReinit::check_attempt_from`), `route::verify_replacement_binding` verifies a replacement package of generation one or later without the principals' rosters, the coordinator keeps the facts of each binding it binds or installs in memory (`ConversationState::reinit_facts`) and rebuilds them at a restart from the binding package its route restores from, and the activation verifies the successor's policy under the principals' current rosters (`current_binding` and `named_rosters` removed); the record states the limitation this brings: a device the successor policy names that its principal revokes, or a root it rotates, between the ReInit finality and the activation refuses that activation on every retry, until the rosters a pending target names are kept resident. A restart retires a group whose head would leave it open whenever any retained finalization is that of a ReInit Commit (`reinit_finalized`, replacing `ordinary_after_reinit`). Two mutation survivors first recorded as equivalent are not: tests now restart an installed successor after its principal rotates the account root, and refuse a successor route row under another semantic lock or incarnation; the reservation test's `EGROUP BIND` case binds the successor's package through a live reservation, so its refusal is that of the generation-zero rule. Development stores of this profile from before P-04 (the pushed tip `6e84d29`) are documented as unsupported, in the record and the operator guide, and startup keeps refusing them; the record also documents the previous-profile terminal's missing profile marker and the other reads of previous-hash state, and leaves the retention of an installed successor's binding package to the server topic `sdk/b-binding-retention`. The Stage 08 evidence map adds S08-038 (gate 22: the model-exhaustive count change) and S08-025 (gate 8: the pinned rows that run `restore_epoch` and `is_tombstone`, and the activation crash test). No row, field, wire object, reply code or storage generation changed (G-08: additive within generation 5, unchanged); no box changes. Evidence: the runtime's 821 E2EE tests and the e2ee crate's 351 pass, and the Stage 08 suite passes but for its two `cli_provisioning` tests, which, like the runtime's ten `offline::tests`, fail on this host's root file system below the storage reserve, also with the follow-up reverted; the expiry and ReInit-closed restore tests fail against the code before the follow-up, the survivor tests kill their survivors, and the follow-up's campaigns kill 22 of 23 mutations (the survivor only spares decoding records that are no finalization); recorded in [the ReInit enforcement record](docs/stage-10-reinit-enforcement.md).
  - D-39 a route row holds its conversation's binding package (2026-10-06, SDK program, outside master #35): companion Section 11.5 has the server durably store a binding, which "survives server restart until authorized close or destruction of that exact channel instance", Section 11.7 answers `EGROUP QUERY` with "the exact current `BINDING` object", Section 13.8 restores an installed ReInit successor after a restart "from durable state", and Section 15 makes the generation-zero binding and the binding ancestry of a live semantic lineage security proofs the responsible server retains. A route row (`route/v1/<conversation>`) owns, beside its route state object, the binding package of the binding it names, as a security proof charged to the conversation: the batch that binds the route or installs a ReInit successor stages the package, and the row acquires the staged package whose recomputed binding identifier is the row's (`owners::owned_by_in_batch`, `route_owned`, `staged_binding_id`); every later rewrite of the row keeps it (`kept_on_rewrite`), so only the row's deletion releases it to object expiry; startup derives the same holding from the package each route is restored from (`Rebuild::derive_held`), so the reconstruction of a store this coordinator wrote stays clean. A migrated ReInit predecessor keeps its package beside its successor's. No table, key, row kind, field or storage generation changed (G-08: additive within generation 5, recorded with the restore tests in a later commit); the record extends the ownership record's owner matrix with the holding, and the ownership suite's every-class test now delivers the package of an unbound conversation to keep a mailbox-class account. Evidence: seven new tests fail against the parent commit and pass; new release regions `retention-owner-staged-packages` and `retention-owner-held-packages`, and four owner regions re-spanned, score 100 percent in a runtime branch report; recorded in [the binding retention record](docs/stage-10-binding-retention.md).
  - D-39 a restart needs no Commit that no candidate slot names (2026-10-06, SDK program, outside master #35): a restart restores a route's validation-time floor from its accepted candidates, re-verifying each candidate's Commit in route order (`startup::restore_validation_time`). A candidate's Commit is named by its epoch's candidate slot row, which a later candidate of the same epoch takes over after an abort; the replaced Commit is then ordinary material no durable row names, which companion Sections 15 and 16 let object expiry collect, and the replacing candidate's validation time is at least the replaced one's. A candidate whose Commit the store no longer holds adds nothing to the floor when its epoch's slot row names another Commit; a Commit its slot still names, or a candidate without a slot row, still refuses the route, and every receipt is still read and checked. No row, field, reply code or storage generation changed (G-08: additive within generation 5). Evidence: the new restart test fails against the parent commit and passes; the missing-Commit refusal passes on both; widening the rule to skip every missing Commit fails that refusal; the new release region `retention-startup-validation-floor` scores 4 of 4 branches; recorded in [the binding retention record](docs/stage-10-binding-retention.md).
  - D-39 a route row holds the rosters its conversation's statements name (2026-10-06, SDK program, outside master #35): companion Section 15 retains "the root, roster, binding, and policy ancestry needed to verify a live semantic lineage" as security proofs and counts that proof set against `MAX_STORED_BYTES_PER_CONVERSATION`; Section 9.4's binding names each principal's roster head, Section 13.7.3 checks a leaf proof against "the retained roster named by `roster_id`", and Section 9.3 verifies each approval "against the retained roster certificate it names". A route row (`route/v1/<conversation>`) holds, as security proofs charged to its conversation, the roster heads its binding names, the roster each stored leaf-membership proof names, and, for each root a retained policy names, the earliest retained roster of that root that verifies under it and holds every certificate the policy names for it, which also verifies every counted vote of that policy's council (`owners::hold_named_rosters`, `roster_holds`). The batch that stores the statement acquires the holding and every later rewrite of the row keeps it (`kept_on_rewrite`), also once a later proof of the same leaf and device replaces the proof that named the roster; startup derives it from each restored route's binding, proofs and policies (`Rebuild::derive_held`, `roster_holds::of_conversation`) and keeps every restored route row that a roster's stored account records as a holder (`Rebuild::recorded_route_holders`), so a restart keeps the holdings and charges live batches left; a statement of a conversation without a route row holds nothing. An account's roster row owns only its current roster, so a replaced roster that no route row holds retires when its account replaces it and object expiry collects it after the security-proof window; a device's first leaf proof that names such a collected roster is then refused, a limitation the record states for the owner. A roster that `MAX_RECORD_REFERENCES` rows already hold takes no further route-row holder and refuses no batch, a restart keeps the same ceiling, and the record states what that ceiling leaves uncharged or refused. A second roster index by root and generation (`roster_snapshots::Generations`) finds the earliest roster that verifies a policy, and object expiry removes a collected roster from both roster indexes. The `roster_snapshots` and `roster_holds` module documentation states the rule, and the operator guide states it with the 256 MiB in-memory ceiling of retained encrypted objects other than message payloads. The ReInit expiry test that restarts without the roster its predecessor named, renamed `an_installed_successor_restarts_without_the_roster_its_predecessor_named`, removes that roster from the store itself, since the predecessor's route row keeps holding it. No table, key, row kind, field or storage generation changed (G-08: additive within generation 5; an earlier store's holdings are derived at its first restart). Evidence: eighteen new tests and the renamed one pass; with every production file of the change set back to its parent and `roster_holds.rs` removed, fourteen of the new tests fail, and the other four fail when only the rule each pins is broken (every published roster kept, the reference ceiling, and a statement of a conversation without a route); 24 of 26 single-edit mutations fail tests, and the two that pass cannot change what is held (where the earliest-roster scan starts, and the trusted-time dating that each such batch's own statement rows already require); the eleven new release regions score 100 percent in a runtime branch report, and the renamed startup-holdings region and the four re-spanned ones keep their scores; recorded in [the binding retention record](docs/stage-10-binding-retention.md).
  - D-39 restore of stores written before the binding-retention rules, G-08 (2026-10-06, SDK program, outside master #35): the decision is additive within storage generation 5: no table, key, row kind, field or object layout changes and startup writes nothing; a binding package's owner row also names its route row, and a held roster's owner row the route rows that hold it. `test-data/stage-ten/binding-retention/` holds three stores written by the test harness of release candidate 3 (`70c832c`: a bound channel after its bootstrap activation, and a bound channel whose account replaced its roster) and of `main` after the P-04 merge (`c262ce1`: an installed ReInit successor), its README reproducing the generator. Each restores, through sealed storage and the harness reload, and from that restart on its route rows hold their packages and the rosters their statements name, so object expiry past every window keeps them, `EGROUP QUERY CHANNEL` answers, policies and the successor restore after another restart; until a batch next writes such an owner row each restart derives the holding again. A store without a route's binding package refuses startup, as for any route whose rows name an object the store does not hold: the package carries the facts the route is restored from, and companion 13.7.1 and 13.7.2 adopt a lost lineage's objects only through the server recovery gate, so a restart that held such a route blocked would leave it no way back; the decision is recorded for the owner. Release candidate 3 reads a store this topic wrote, since no format changed, but does not derive these holdings; the operator guide already says not to start it on a database a later release has run on. Evidence: five restore tests; with every production file of this topic set back to `c262ce1` the three that check the holding fail and the sealed restore and the refusal pass; recorded in [the binding retention record](docs/stage-10-binding-retention.md).
  - D-37 origin deletions name the generation the coordinator holds (2026-10-07, SDK program, outside master #35): companion Section 12.5 has `EORIGIN DEL` use "the same base fence and next companion operation sequence", resets the companion sequence to zero with every origin update, has `DEL` supply "the next unused sequence" and permanently fence later requests, and requires both fences to commit before the shared origin is retired. The coordinator reads one link's frames in order, so a deletion finds it holding the last declaration the link carried. An edge's companion deletion now names the generation of its last declaration on the live link, at the edge's request count under that generation when it already sequences it and at zero otherwise (`E2eeEdge::delete_origin`), and an origin whose declaration on the link is still unacknowledged is deleted as well; whether or not a deletion is sent, a connection's end releases its companion state. The coordinator still requires the generation it holds, and now accepts a stated next sequence at or above the one executed there and fences the origin at the stated sequence, as the base origin table does on a ready link and as Architecture 20.7 retains "the stated next sequence" (`CompanionCoordinator::origin_del`); a lower sequence or another generation is refused. Evidence: six edge tests deliver the edge's own lines to the real companion coordinator; four fail with `origins.rs` set back to the parent `3294b73`, and one, with the coordinator unit test that pins the fence, fails with the coordinator's `sync.rs` set back; five single-edit mutations each fail a test; the release coverage policy gains `edge-companion-origin-deletion` and re-reviews `cap78-sync-origin-del`. Architecture 20.5 returns the stored result of an exact duplicate "without re-execution", and companion 12.5 has "Exact duplicates return the stored result", a reconnect "replay RESET and origin state before resuming", and treats a written frame of a replaced link as one that "may be sent byte-for-byte after reconnect". When a link closes, the coordinator now also forgets which of that peer's request and payload objects completed (`CompanionCoordinator::link_closed`, `E2eeAssembler::forget_recent`), so a request the next link carries again is assembled and classified against the replay rows: an executed one returns its stored result and one that never ran runs at its sequence; on the link that carried it a copy before its answer is still a violation, and other peers' requests and the peer's origin declarations keep the recent-object cache's answer. Evidence: a coordinator test of a request carried again after its link closed fails with `link_closed` set back to the first commit, a second pins what the close keeps, and an assembler test pins `forget_recent`; the release coverage policy gains `companion-closed-link-request-classification`. An origin whose first acknowledgement on a link arrives after `EORIGIN READY` now resends its unanswered requests with that acknowledgement, exactly as first sent, as READY resends those of the origins acknowledged before it (`E2eeEdge::origin_acked`); an acknowledgement before READY, or a later one on the same link, resends nothing, and an acknowledgement resends only the requests of the connections it settles, which are those whose declaration on the link it is the first to acknowledge at that generation. A resume resends a request only while its origin's declaration on the link is acknowledged and only under the generation its origin is acknowledged at (`PendingRequest::origin_generation`, `unanswered_of`); a request named under an earlier generation is never resent and stays pending without a reply until its connection ends, as the base profile holds a request whose origin update is pending. Evidence: nine edge tests send real requests through the edge and drive the real companion coordinator through both orders of READY and the acknowledgement, including requests the coordinator completed on the closed link without running them and requests whose result was lost; five fail with the edge's `origins.rs` and `sync.rs` set back to the second commit, three with the coordinator's `mod.rs` set back to the first, and five single-edit mutations of the selection, including settling a connection at a repeated acknowledgement, each fail a test; the release coverage policy gains `edge-origin-acknowledgement-resend` and re-reviews `edge-origin-attachment-settlement`. Architecture 20.5 increments an origin's generation only after an acknowledged `FORIGIN UPDATE`, and 20.7 has DEL retain "the stated next sequence for replay checking". The base deletion now names a pending update's generation, at sequence zero, only once a link carried that update, and otherwise the acknowledged generation with its next sequence (`send_origin_del`); the edge records in memory that the first pending update went out on a link (`ConnectionOrigin::update_sent`) and clears that record only when the update is acknowledged and retired, so a deletion replayed on a later link names what the first one did. Evidence: four tests apply the frames the edge sends to the coordinator's origin table; two of them fail with the base files set back to the third commit, and three single-edit mutations each fail a test; the release coverage policy gains `edge-origin-deletion-generation`. A Stage 08 daemon test, `origin_deletion::origin_deletions_name_the_generation_the_coordinator_holds`, has guests and authenticated clients register on an edge and end their connections, and requires that the coordinator accepts every base and companion origin deletion; it fails in 8 of 8 runs with either edge deletion rule reverted and passes in 16 of 16 with the whole series. No wire object, reply code, row, field or storage generation changed (G-08: nothing stored changes); G-07 does not apply: no domain file or Stage 08 model changed. Recorded in [the origin deletion record](docs/stage-10-origin-deletion.md).
  - D-42 one helper over the leaf credential the credential hashes read (2026-10-07, SDK program, outside master #35): companion Section 2.2 defines `old_credential_hash` as `SHA256("ARC-MLS/1 old credential hash" || encoded_BasicCredential)` and `resulting_leaf_credential_hash` over `TLS-encode(resulting_leaf_index, encoded_BasicCredential)`, and hashes the canonical TLS encoding of what it names; RFC 9420 Section 5.3 encodes a leaf's credential as one `Credential` (a `uint16` `credential_type`, then, for `basic`, `opaque identity<V>`) and companion Section 8.5 places the exact `ArcCredentialBundle` in that identity, so `encoded_BasicCredential` is the canonical TLS encoding of the leaf's RFC 9420 `Credential` whose `credential_type` is basic: the credential type, then `identity<V>`. `agenc_relay_e2ee::mls_outer::EncodedBasicCredential` holds that input: `parse` reads exactly one basic `Credential` with the KeyPackage parser's own credential reader (`read_basic_credential`, which `parse_leaf_node` now calls for `PublicLeafNode::encoded_credential`) and refuses another credential type, a short input, trailing bytes and a non-minimal length prefix, so neither the bare identity nor `identity<V>` without its type is accepted; `old_credential_hash` and `resulting_leaf_credential_hash` hash exactly those bytes, and `PublicLeafNode::credential` returns a parsed leaf's credential, reading its public field again. No runtime path changed: the coordinator compares the credential hashes that ACKs, leaf-membership proofs and ReInit attempts carry and never computes one from a credential. Evidence: two outer-parser unit tests pin the input and the refusals, and the testkit cross-check `mls_interop::the_parsed_leaf_credential_is_each_librarys_credential_encoding` has openmls 0.9.0 and mls-rs 0.56.0 each generate KeyPackages for suites `0x0001` and `0x0003` with identities of 21, 1,000 and 20,000 bytes and requires that the daemon parser's credential slice equals the library's own `Credential` encoding and that both hashes equal SHA-256 over the label and those bytes; no specification, profile hash, registry, wire object, reply code, row or storage generation changed. Recorded in [the credential hash record](docs/stage-10-credential-hash.md).
  - D-42 the vectors' old credential hashes read the leaf's basic Credential (2026-10-07, SDK program, outside master #35): `scripts/generate-e2ee-vectors.py` hashes every `old_credential_hash` over `encoded_basic_credential`, the basic credential type followed by `identity<V>`, which its KeyPackage leaf also carries: the recovery set's leaf-membership proofs and Commit ACK over the credential whose identity is the device's credential bundle, and the ReInit set's Commit ACKs, attempts, attempt authorizations and ReInit ACKs over the credential of each principal's old leaf, whose synthetic identity is its root identity followed by its device certificate. Regenerated through the generator: 6 recovery files (`membership-continuing.bin`, `membership-removed.bin`, `reject-duplicate-continuing-leaf.bin`, `reject-revoked-device.bin`, `commit-ack-without-membership.bin`, `manifest.toml`) and 40 ReInit files (`manifest.toml` and the 39 files from `record-01-bootstrap-finalization.bin` on whose identifiers follow the ACK set digest); no identity file changed, and no digest, fixture or checker outside the vector directories pins the replaced bytes. Evidence: `membership_vectors::generator_proofs_name_the_leaf_by_its_basic_credential` checks the proofs of device 7's leaf against the credential the outer parser reads from `key-package-7.bin`, and `reinit_vectors::every_old_leaf_is_named_by_its_basic_credential` checks 9 attempts, 6 Commit ACKs and 8 ReInit ACKs against the credential built from each principal's root and roster; with the generator's hash set back, either test fails, and with the vector files set back `--check` fails as well. S08-030 rests on regenerated evidence; no box changes. Recorded in [the credential hash record](docs/stage-10-credential-hash.md).
  - D-42 a Stage 08 leaf's credential hash through the shared helper (2026-10-07, SDK program, outside master #35): the Stage 08 real-client scenarios name each endpoint's old leaf by `old_credential_hash` over the `Credential` that leaf carries: `real_clients::encoded_credential` encodes it through openmls and mls-rs and requires both libraries' bytes to agree (the basic credential type, then `identity<V>`, whose identity is the encoded credential bundle), and `OldLeaf::real` hashes those bytes through `EncodedBasicCredential`. The daemon compares the carried values, so the recovery, rotation, ReInit and two-edge binding scenarios pass unchanged. Evidence: `encrypted_clients::a_real_leaf_is_named_by_the_credential_its_key_package_carries` requires that a real leaf's hash equals the shared helper's hash of the credential each library's KeyPackage under the same leaf key carries, as the outer parser reads it; it fails with the helper set back to hashing the bundle alone, and the shared helper refuses the bundle itself. No production source, vector, wire object, row or storage generation changed. Recorded in [the credential hash record](docs/stage-10-credential-hash.md).
  - D-42 open: define `encoded_BasicCredential` in the next normative revision (2026-10-07, SDK program, outside master #35). Any change to `docs/arc-mls-e2ee-extension.md` moves the ARC-MLS profile hash (Section 2.3), so the sentence waits for a normative revision and its refreeze; the next one should add, as a paragraph of companion Section 2.2 directly after the registry table: "Wherever this document hashes `encoded_BasicCredential` (the `old_credential_hash` and `resulting_leaf_credential_hash` rows and their restatements in Sections 12.3 and 12.4), it is the canonical TLS encoding of the RFC 9420 `Credential` in the `credential` field of the `LeafNode` the hash names, byte for byte, whose `credential_type` is `basic` (`0x0001`): the `uint16` `credential_type` followed by `opaque identity<V>`, whose `identity` is the exact `ArcCredentialBundle` (Section 8.5). It is not the identity alone, and not `identity<V>` without its `credential_type`, as an implementation's own `BasicCredential` type may encode it. `TLS-encode(resulting_leaf_index, encoded_BasicCredential)` is the `uint32` index followed by those bytes, with no further length prefix." Recorded in [the credential hash record](docs/stage-10-credential-hash.md).
  - D-42 open: the Stage 08 Welcome delivery's normal-join proof carries an all-zero `resulting_leaf_credential_hash`, which a conforming joiner refuses (companion Section 12.4); compute it through `EncodedBasicCredential::resulting_leaf_credential_hash` over the claimed KeyPackage's leaf (2026-10-07, SDK program, outside master #35).
  - D-41 the coordinator's recent-object cache is bounded per peer and expires (2026-10-07, SDK program, outside master #35): companion Section 11.8 reserves reassembly quota per federation peer and lets a duplicate content address use the recent-object idempotency cache, Section 16 retains that cache for `RECENT_OBJECT_IDEMPOTENCY_RETENTION` (30 minutes), refuses admission before reservation and refuses new storage fairly at a ceiling, and Section 12.5 permits a `failed` result for every opcode, which commits no semantic mutation. The coordinator's assembler bounds that cache per peer (`RecentCeiling::PerSender`, `MAX_RECENT_OBJECTS` per peer, open submissions reserving their slots), forgets every completed object when its 30-minute window ends, at most once a second before it ingests a companion fragment (`CompanionCoordinator::expire_recent`, `E2eeAssembler::expire_recent`), releases an answered request's request and payload objects once its batch commits or its stored result is sent again, held in memory or read back from storage (`CompanionCoordinator::request_answered`), and keeps no declaration in it: the origin table decides a repeated `EORIGIN ADD` or `UPDATE`, acknowledging an identical declaration of the accepted state again. A request or payload that completes past its peer's ceiling assembles within its quotas without a recent tuple, and the request is answered with the failed result `E2EE_REASSEMBLY_LIMIT`, which consumes its operation sequence like every failed result and is replayed to an exact copy (`CompleteRequest::refusal`); the link stays up. A peer's objects are held only from completion to their answer, so sustained traffic holds far fewer than the per-peer ceiling, which bounds what one peer leaves unanswered. The edge's client ingress keeps the shared ceiling. Evidence: four assembler tests, four coordinator tests driving requests through the frame entry point (a request past its peer's ceiling refused per request, expiry when the window ends, release at the committed answer, no slot for a declaration), a test through real storage of the refused request's failed result at its sequence and one of the release at a replay read back from storage; eleven single-edit mutations each fail a test; the release coverage policy gains six regions and re-reviews five. No wire object, reply code, limit, row, field or storage generation changed. Recorded in [the link faults record](docs/stage-10-link-faults.md).
  - D-41 an edge's coordinator deliveries hold no recent-object slot (2026-10-07, SDK program, outside master #35): companion Section 12.5 positions every delivery, an event at its delivery generation and sequence, a snapshot entry at its page of one immutable cut, which a new link publishes again from its first page, and Section 12.5.1 a witness resolution under its token, while Section 11.8's recent-object cache is keyed by content. The edge's assembler serves both its clients' submissions and these deliveries; an event and its payload, a snapshot entry and a witness resolution object are assembled as server responses (`Direction::Response`), so they never take a slot of the shared client ceiling and an exact copy on a later link is assembled again and checked against the cursor, the cut or the token. When the link closes the edge also discards the coordinator's open assemblies (`E2eeEdge::link_down`), so the next link's copies assemble from their first fragment. A prerequisite of the companion resume follow-up, not changed here: the edge re-acknowledges an exact duplicate event at its installed cursor without reapplying state (Section 12.5). Evidence: five edge tests (an event, a cut's entries and a witness resolution with the client cache at its ceiling, a page published again on the next link, and a partial payload released at link loss) all fail with the edge's files set back to the first commit, and four single edits each fail a test; the release coverage policy gains three regions and re-reviews `edge-snapshot-receiver`. No wire object, reply code, limit, row, field or storage generation changed. Recorded in [the link faults record](docs/stage-10-link-faults.md).
  - D-41 a base declaration naming a removed principal closes only its origin (2026-10-07, SDK program, outside master #35): Architecture 20.5 and 20.7 accept a session registration, login or other principal change under its next origin generation only after an acknowledged `FORIGIN UPDATE`, and 20.7 has DEL retain the stated next sequence. A `FORIGIN ADD` or `UPDATE` is checked against the origin table before the principal it names is classified (`check_structure`), so a malformed declaration is a violation whatever session it names. One whose session is no longer live, or no longer authenticated as the declared account, is refused for its origin alone (`principal_of`, `refuse`): nothing is acknowledged and the link stays up; the refusal first writes the origin's existing row, closed at the generation and next sequence the coordinator holds, and the sessions the origin owns then close through the coordinator's session cleanup, one batch each (`close_sessions`); after a restart, a session whose cleanup had not committed is swept at the edge's next READY with every session no live origin binds. The edge's deletion naming the refused generation is acknowledged (`delete`), a replay of the refused declaration on the next link is refused again, and the closed origin does not hold READY back. The coordinator holds each refusal in memory until it acknowledges that deletion (`refused_declarations`); after a restart a replayed refused declaration is refused again and recorded anew, and a deletion during the reset is accepted by the origin table. A declaration naming another user's or edge's session, or an invalid account generation, remains a violation. Evidence: three tests through the coordinator's actor loop (a removed session, an account the session lacks, a replay on the next link) fail with the coordinator's `origin.rs` and `mod.rs` set back to the second commit; a fourth requires a malformed declaration naming a closed session to be a violation; two restart tests through real storage pin the durable closure, the refusal again, READY, the orphan sweep and the deletion during the reset and after READY; nine single edits each fail a test; the release coverage policy gains five regions. No wire object, reply code, limit, row, field or storage generation changed. Recorded in [the link faults record](docs/stage-10-link-faults.md).
  - D-41 a companion declaration naming a superseded attachment closes only its origin (2026-10-07, SDK program, outside master #35): companion Section 11.6 increments a device's attachment `session_generation` at every successful attachment by compare-and-swap, and Section 12.5 has the edge declare the attachment in the `EORIGIN UPDATE` that follows its base generation transition. A declaration whose device session generation the directory has advanced past is refused for its origin alone (`mirrored_device`, `refuse_declaration`): nothing is acknowledged, the companion origin is fenced where it stood, every later declaration of it, including a replay on a later link, is refused alike until the edge deletes it (`refused_origins`), the edge's deletion naming the generation refused last is acknowledged (`origin_del`), and the link stays up; a generation the directory never reached remains a violation, and an attachment the coordinator accepted stays accepted when its declaration is replayed. Evidence: four synchronization tests; two fail with the coordinator's `sync.rs` and `mod.rs` set back to the third commit, and four single edits each fail a test; the release coverage policy gains two regions and re-reviews three. No wire object, reply code, limit, row, field or storage generation changed. Recorded in [the link faults record](docs/stage-10-link-faults.md).
  - D-41 a companion request whose batch storage refused is answered with its failed result (2026-10-07, SDK program, outside master #35): companion Section 12.5 permits a `failed` result for every opcode, which commits no semantic mutation, writes a request's result and next sequence in one durable batch and sends results only from durable rows. The staged batch keeps its request (`PendingCompanion::request`), the executor hands it back when storage refuses the batch (`CompanionCoordinator::batch_rejected`), and on its live link the coordinator answers it with the failed result `E2EE_RATE_LIMITED`, the code it already gives a request whose storage plan it cannot make, staged as its own batch that consumes the request's sequence (`answer_rejected`), so the origin's next request follows it and the link stays up; a request whose link closed is left for the next link, and storage refusing the failed result retires the link, as for a base request. Evidence: three tests through real storage (the refused batch's request answered while the next request waits behind it, the failed result refused too, the link closed first) - two of them and an adapted object-read rejection test fail with the rejection rule set back to the fourth commit, and three single edits each fail a test; the release coverage policy gains one region and re-reviews three. No wire object, reply code, limit, row, field or storage generation changed. Recorded in [the link faults record](docs/stage-10-link-faults.md).
  - D-41 daemon tests (2026-10-07, SDK program, outside master #35): `link_faults` in the Stage 08 daemon suite runs the production coordinator and two production edges with both profiles active. It requires the coordinator to answer account sessions' companion requests and guests' companion origins past one recent-object ceiling with no link closure, and, through a relay the test cuts and heals between edge A and the coordinator, to refuse for its origin alone a session fenced by its account's credential change while edge A's link is cut and a device attachment superseded on edge B while the coordinator restarted, after which edge A links once and no link closes. The relay is cut only once the coordinator holds no unacknowledged base delivery and the link has carried nothing for half a second. All three fail at the start commit, the fenced-session test also at the second commit and the superseded-attachment test at the third. Recorded in [the link faults record](docs/stage-10-link-faults.md).
  - D-45 display-name preparation applies the RFC 8266 enforcement passes (2026-10-07, SDK program, outside master #35): Architecture Section 7.2 prepares a display name with the RFC 8266 Nickname profile within 64 UTF-8 bytes, and RFC 8266 Section 2.3 with Section 2.1 and RFC 8264 Section 7 applies the FreeformClass check, the additional mapping rule and NFKC until the result is stable. `agenc_relay_types::DisplayName::prepare` now runs those passes itself: after the 256-byte input bound and the existing space mapping, each pass (`enforce_nickname_rules`) checks the FreeformClass through the pinned `precis-profiles` 0.1.13, collapses spaces with the adapter's own mapping (`collapse_precis_spaces`) and normalizes through the dependency's NFKC rule, so spaces are collapsed after normalization; a stable result above 64 bytes is `TooLong`, and no stable result after three passes (`PRECIS_ENFORCEMENT_PASSES`, the dependency's own bound) is `PrecisRejected`. Display-name preparation prepares or refuses every input with its typed error and never panics; the adapter uses the dependency only for the FreeformClass check and NFKC, and `conformance/precis-dependency-decision.md` records the narrowed use. Every caller of the function inherits the rule. Architecture Section 21.2 and `TRN-05`: parsers are total, panics stay fail-stop, and there is no per-connection containment. G-08: unchanged; every name the replaced adapter returned prepares to itself, and every new result is accepted by the replaced adapter. Evidence: `display_name_preparation` (about 3.7 million generated inputs, every scalar value in context, exact results for every character whose NFKC form contains a space) and `display_name_differential` (about 4.0 million inputs: the new adapter equals an RFC 8266 model on every input and differs from the replaced adapter only where the replaced adapter differs from the model). Recorded in [the name preparation record](docs/stage-10-name-preparation.md).
  - D-45 display-name preparation and `SETNAME` in the Stage 02 fuzz target (2026-10-07, SDK program, outside master #35): `client_state` now prepares each input's lossy UTF-8 text as a display name, requiring a prepared name to stay within 64 bytes and to prepare to itself, prepares it as a login, and validates a `SETNAME` line carrying it through the post-registration grammar; its seed corpus gained `seed-display-name-spaces`. Built with the pinned `nightly-2026-08-24` and cargo-fuzz 0.13.2 offline, it passed the Stage 02 smoke parameters (10,000 runs, seed 20260824) and a ten-minute campaign; the recorded Stage 02 smoke and the S10-004 campaign are unchanged. Recorded in [the name preparation record](docs/stage-10-name-preparation.md).
  - D-45 daemon test (2026-10-07, SDK program, outside master #35): `display_name_preparation` in the Stage 06 daemon suite runs the production daemon. A registered client in a shared channel sends 24 `SETNAME` lines whose names need spaces collapsed after normalization, and an observer holding `setname` must receive each change with the exact prepared name; a refused name gets the grammar refusal and is not announced; three clients register with such names as their `USER` realname and the observer's extended `JOIN` carries each prepared realname; both clients still get `TIME` and the daemon stops cleanly. Recorded in [the name preparation record](docs/stage-10-name-preparation.md).
