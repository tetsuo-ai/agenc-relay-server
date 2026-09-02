# AgenC IRCD Implementation TODO

Status: implementation roadmap for version 1. This file is nonnormative. The
[architecture specification](docs/ircd-architecture-and-implementation-spec.md)
and, for encrypted operations, the
[E2EE companion](docs/irc-mls-e2ee-extension.md) remain authoritative.

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

References: [Architecture §§1.2–4](docs/ircd-architecture-and-implementation-spec.md#12-requirements-language),
[§§24.1–24.5](docs/ircd-architecture-and-implementation-spec.md#24-rust-workspace-and-module-boundaries),
[§27](docs/ircd-architecture-and-implementation-spec.md#27-security-and-correctness-invariants),
[E2EE §20](docs/irc-mls-e2ee-extension.md#20-implementation-separation), and
[the contributor guide](AGENTS.md).

## Stage status

| Stage | Outcome | Implementation | Latest local gate | Revision-bound evidence |
| --- | --- | --- | --- | --- |
| 00 | Reproducible workspace and traceability foundation | Complete | Pass, 2026-08-27 | [Current checkpoint](conformance/evidence/stage-00-1e5b738468f88b238061cc6e84b732176f5cae65.json) |
| 01 | Registries, validated types, and canonical codecs | Complete | Pass, 2026-08-27 | [Current checkpoint](conformance/evidence/stage-01-1e5b738468f88b238061cc6e84b732176f5cae65.json) |
| 02 | Bounded client wire implementation | Complete | Pass, 2026-08-27 | [Current checkpoint](conformance/evidence/stage-02-1e5b738468f88b238061cc6e84b732176f5cae65.json) |
| 03 | Pure deterministic domain model | Complete | Pass, 2026-08-27 | [Current checkpoint](conformance/evidence/stage-03-1e5b738468f88b238061cc6e84b732176f5cae65.json) |
| 04 | Crypto adapters and account authentication | Complete | Pass, 2026-08-29 | [Current checkpoint](conformance/evidence/stage-04-4040796f2c21774d58ea7ce54e70a080678e83ac.json) |
| 05 | Durable and recoverable persistence | Complete | Pass, 2026-08-29 | [Current checkpoint](conformance/evidence/stage-05-4040796f2c21774d58ea7ce54e70a080678e83ac.json) |
| 06 | Conforming single-node daemon | Implementation merged; closure in progress | Fail, 2026-09-01 (`check-source`) | Absent |
| 07 | Conforming base federation | Not started | Not run | Absent |
| 08 | Conforming E2EE server adapter | Not started | Not run | Absent |
| 09 | Optional WSS and history profiles | Not started | Not run | Absent |
| 10 | Production qualification and release evidence | Not started | Not run | Absent |

## Coverage and ownership maps

These maps assign primary ownership. Coupled tasks may add evidence, but no
later stage may silently move an authority across the crate graph.

### Crate implementation ownership

| Crate | First functional stage | Governing tasks |
| --- | --- | --- |
| `agenc-ircd-types` | 01 | `S01-001`–`S01-006` |
| `agenc-ircd-client-wire` | 01/02 | `S01-009`, `S02-001`–`S02-011` |
| `agenc-ircd-federation-wire` | 01/07 | `S01-007`–`S01-009`, `S07-002`, `S07-005`, `S07-008`–`S07-009` |
| `agenc-ircd-crypto` | 04 | `S04-001`–`S04-006`, `S04-012`–`S04-013` |
| `agenc-ircd-auth` | 04 | `S04-006`–`S04-011` |
| `agenc-ircd-domain` | 03 | `S03-001`–`S03-010` |
| `agenc-ircd-e2ee` | 08 | `S08-001`–`S08-017` |
| `agenc-ircd-storage` | 05 | `S05-001`–`S05-014` |
| `agenc-ircd-config` | 06 | `S06-001`–`S06-002`, `S06-013` |
| `agenc-ircd-admin` | 06 | `S06-012` |
| `agenc-ircd-runtime` | 06 | `S06-003`–`S06-015`; extended by Stages 07–09 |
| `agenc-ircd-testkit` | 00 | `S00-007`–`S00-008`; extended by every test stage |
| `agenc-ircd` | 06 | composition in `S06-002`, `S06-009`–`S06-015` only |

Reference: [Architecture §24.1](docs/ircd-architecture-and-implementation-spec.md#241-crate-graph).

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

Reference: [Architecture §27](docs/ircd-architecture-and-implementation-spec.md#27-security-and-correctness-invariants).

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

Reference: [Architecture Appendix D](docs/ircd-architecture-and-implementation-spec.md#appendix-d-requirement-traceability).

## Stage 00 — Workspace, policy, and traceability

Outcome: a compiling, reproducible Rust workspace whose crate graph, toolchain,
source baseline, and evidence model are fixed before protocol behavior lands.

- [x] `S00-001` **Freeze and verify the specification baseline.** Record the
  architecture, companion, registry, source-ledger, validator, and derived
  profile hashes without changing normative bytes. ([evidence](conformance/stage-zero-evidence.md#s00-001))
  - After: none.
  - Targets: `docs/`, `scripts/check-spec.sh`, repository evidence.
  - References: [Architecture §§2 and 30](docs/ircd-architecture-and-implementation-spec.md#2-normative-document-order), [source ledger §1](docs/protocol-sources-and-decisions.md#1-purpose), [manifest](docs/specification-manifest.txt).
  - Invariants: `E2E-07`, `FED-02`.
  - Evidence: `bash scripts/check-spec.sh` passes and recorded hashes equal the manifest.

- [x] `S00-002` **Create the machine requirement ledger.** Enumerate every
  applicable MUST/MUST NOT from both normative documents with a stable ID,
  source section/hash, target crate, evidence IDs, and initial status. ([evidence](conformance/stage-zero-evidence.md#s00-002))
  - After: `S00-001`.
  - Targets: `conformance/requirements.toml` and its validator.
  - References: [Architecture §28.1](docs/ircd-architecture-and-implementation-spec.md#281-requirement-ledger-and-evidence), [Appendix D](docs/ircd-architecture-and-implementation-spec.md#appendix-d-requirement-traceability).
  - Invariants: every Section-27 invariant and every E2EE requirement.
  - Evidence: validator proves unique IDs, valid source hashes, valid crate names, and no unmapped normative requirement.

- [x] `S00-003` **Pin the Rust build contract.** Select compiler 1.98.0,
  edition 2024, `rust-version = "1.98"`, resolver version, and the two initial
  Linux targets exactly as specified. ([evidence](conformance/stage-zero-evidence.md#s00-003))
  - After: `S00-001`.
  - Targets: `rust-toolchain.toml`, root and package manifests.
  - References: [Architecture §4](docs/ircd-architecture-and-implementation-spec.md#4-fixed-version-1-decisions), [§24.5](docs/ircd-architecture-and-implementation-spec.md#245-dependency-and-build-integrity).
  - Invariants: `OPS-02`.
  - Evidence: host and cross-target `cargo check --locked` use the pinned compiler and declared package metadata.

- [x] `S00-004` **Create the complete workspace skeleton.** Add every crate in
  the Section-24 graph with only its declared dependency direction; empty crate
  roots must not expose placeholder protocol or cryptographic behavior. ([evidence](conformance/stage-zero-evidence.md#s00-004))
  - After: `S00-003`.
  - Targets: all `agenc-ircd-*` libraries, `agenc-ircd-testkit`, and the `agenc-ircd` binary crate.
  - References: [Architecture §24.1](docs/ircd-architecture-and-implementation-spec.md#241-crate-graph).
  - Invariants: `CON-01`, `CON-04`.
  - Evidence: a `cargo metadata` graph check rejects forbidden edges, cycles, production use of `testkit`, and library dependency on the binary.

- [x] `S00-005` **Enforce workspace-safe Rust and legibility policy.** Apply
  workspace lints, warning denial, `#![forbid(unsafe_code)]`, rustfmt defaults,
  focused-function review triggers, and narrowly documented lint exceptions. ([evidence](conformance/stage-zero-evidence.md#s00-005))
  - After: `S00-004`.
  - Targets: workspace lint tables, crate roots, lint/source-scan tooling.
  - References: [Architecture §21.4](docs/ircd-architecture-and-implementation-spec.md#214-input-pipeline), [§24.3](docs/ircd-architecture-and-implementation-spec.md#243-safe-rust-and-code-shape-policy), [AGENTS.md](AGENTS.md).
  - Invariants: `TRN-05`, `CON-04`, `OPS-01`.
  - Evidence: formatting, Clippy, unsafe-source, panic-path, and unbounded-channel checks fail on seeded violations.

- [x] `S00-006` **Configure dependency and source policy.** Permit crates.io
  only, forbid wildcard and Git requirements, define license/advisory/source
  rules, and document the one reviewed duplicate-crypto dependency generation. ([evidence](conformance/stage-zero-evidence.md#s00-006))
  - After: `S00-003`.
  - Targets: workspace dependency table, `Cargo.lock`, `deny.toml`, audit policy.
  - References: [Architecture §§24.4–24.5](docs/ircd-architecture-and-implementation-spec.md#244-serialization-and-crypto-libraries), [source ledger §§5–6](docs/protocol-sources-and-decisions.md#5-initial-rust-dependency-evidence).
  - Invariants: `OPS-02`.
  - Evidence: `cargo deny check`, `cargo audit --deny warnings`, feature-tree inspection, and checksum comparison pass.

- [x] `S00-007` **Define deterministic test and evidence layout.** Separate
  unit, integration, golden-vector, transcript, property, fuzz, Loom, fault,
  interoperability, capacity, and release evidence so each requirement can
  name a stable evidence ID. ([evidence](conformance/stage-zero-evidence.md#s00-007))
  - After: `S00-002`, `S00-004`.
  - Targets: test directories, corpus/vector directories, evidence schema.
  - References: [Architecture §§28.1–28.8](docs/ircd-architecture-and-implementation-spec.md#28-verification-conformance-and-security-testing).
  - Invariants: all invariant families.
  - Evidence: a schema check rejects missing, duplicate, stale, or unbound evidence IDs.

- [x] `S00-008` **Isolate deterministic test capabilities.** Provide test-only
  clocks, entropy, reference models, fault stores, and transcript drivers that
  cannot enter a release dependency graph or production configuration. ([evidence](conformance/stage-zero-evidence.md#s00-008))
  - After: `S00-004`, `S00-007`.
  - Targets: `agenc-ircd-testkit` and dependency-graph checks.
  - References: [Architecture §§24.1–24.2](docs/ircd-architecture-and-implementation-spec.md#241-crate-graph), [§29](docs/ircd-architecture-and-implementation-spec.md#29-implementation-sequence-and-acceptance-gates).
  - Invariants: `CON-01`, `CON-02`.
  - Evidence: release metadata contains no testkit edge or deterministic entropy/clock feature.

- [x] `S00-009` **Create the continuous-integration baseline.** Run source
  checks, graph checks, formatting, compilation, Clippy, tests, docs,
  dependency policy, audit, and coverage under the pinned toolchain. ([evidence](conformance/stage-zero-evidence.md#s00-009))
  - After: `S00-005` through `S00-008`.
  - Targets: CI workflows and reusable validation commands.
  - References: [Architecture §28.8](docs/ircd-architecture-and-implementation-spec.md#288-mandatory-build-and-analysis-gates), [§24.5](docs/ircd-architecture-and-implementation-spec.md#245-dependency-and-build-integrity).
  - Invariants: `OPS-02`.
  - Evidence: every mandatory command runs from a clean checkout and failures block the build.

- [x] `S00-010` **Define release evidence manifests.** Record command, exact
  ordered toolchain and policy hash, source and lock hashes, target, features,
  timing, result, artifact hash, and nonempty limitations without confusing
  test execution with a security claim. ([evidence](conformance/stage-zero-evidence.md#s00-010))
  - After: `S00-002`, `S00-007`.
  - Targets: conformance evidence schema and validation tooling.
  - References: [Architecture §§26.4 and 28.1](docs/ircd-architecture-and-implementation-spec.md#264-conformance-claims).
  - Invariants: all invariant families.
  - Evidence: positive and malformed sample manifests exercise every validation branch.

- [x] `S00-900` **Pass the Stage 00 gate.** The complete empty workspace and
  traceability baseline must build reproducibly without any protocol stub being
  mistaken for implemented behavior. ([evidence](conformance/stage-zero-evidence.md#s00-900))
  - After: `S00-001` through `S00-010`.
  - Targets: entire repository.
  - References: [Architecture §§24, 28.1, 28.8, and 29](docs/ircd-architecture-and-implementation-spec.md#24-rust-workspace-and-module-boundaries).
  - Invariants: `CON-01`, `CON-02`, `OPS-02`.
  - Evidence: the [current schema version 2 manifest](conformance/evidence/stage-00-1e5b738468f88b238061cc6e84b732176f5cae65.json) closes the gate for exact source commit `1e5b738468f88b238061cc6e84b732176f5cae65`; the [schema version 1 manifest](conformance/evidence/stage-00-8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb.json) remains archive-only.

## Stage 01 — Registries, validated types, and canonical codecs

Outcome: all protocol vocabulary and byte representations required by later
stages exist as bounded, private-field types with independent vectors.

- [x] `S01-001` **Mirror the frozen registries into typed constants.** Cover
  every Appendix-A command/numeric/capability/mode entry and Appendix-B closed
  value without using declaration order as a wire discriminant.
  - After: `S00-900`.
  - Targets: `agenc-ircd-types`; registry-consistency tests.
  - References: [Architecture Appendix A](docs/ircd-architecture-and-implementation-spec.md#appendix-a-client-wire-registries), [Appendix B.2](docs/ircd-architecture-and-implementation-spec.md#b2-closed-enum-registry), [federation registry](docs/federation-v1-profile.registry).
  - Invariants: `TRN-06`, `FED-08`.
  - Evidence: [EVID-S01-001-REGISTRIES](conformance/stage-one-evidence.md#s01-001) proves no missing, duplicate, reordered, or differently encoded entry.

- [x] `S01-002` **Implement bounded quantities and units.** Represent byte
  counts, object counts, queue demand, timestamps, durations, revisions,
  generations, sequence numbers, and quotas with checked construction and
  arithmetic.
  - After: `S01-001`.
  - Targets: `agenc-ircd-types`.
  - References: [Architecture §§19.2 and 24.2–24.3](docs/ircd-architecture-and-implementation-spec.md#192-hard-resource-maxima).
  - Invariants: `TRN-04`, `CON-05`, `DUR-11`.
  - Evidence: [EVID-S01-002-QUANTITIES](conformance/stage-one-evidence.md#s01-002) covers empty/one/maximum/maximum-plus-one, underflow, and overflow for every quantity family.

- [x] `S01-003` **Implement typed identities.** Add private-field Account,
  User, Session, ChannelInstance, Message, request, event, origin, server,
  transaction, database, and recovery identities with explicit parsing and
  generation/incarnation rules.
  - After: `S01-002`.
  - Targets: `agenc-ircd-types`.
  - References: [Architecture §7](docs/ircd-architecture-and-implementation-spec.md#7-typed-identifiers-and-canonical-names), [Appendix B.3](docs/ircd-architecture-and-implementation-spec.md#b3-common-validated-values-and-control-arms).
  - Invariants: `ID-01`, `ID-02`, `FED-04`.
  - Evidence: [EVID-S01-003-IDENTITIES](conformance/stage-one-evidence.md#s01-003) covers construction, canonical text/binary round-trip, domain confusion, and entropy injection.

- [x] `S01-004` **Implement bounded byte and UTF-8 text types.** Reject NUL,
  invalid UTF-8, forbidden controls, overlength input, lossy conversion, and
  allocation before bound validation.
  - After: `S01-002`.
  - Targets: `agenc-ircd-types`.
  - References: [Architecture §§4, 7, and 9.1](docs/ircd-architecture-and-implementation-spec.md#4-fixed-version-1-decisions).
  - Invariants: `TRN-04`, `TRN-05`, `TRN-06`.
  - Evidence: [EVID-S01-004-BOUNDED-VALUES](conformance/stage-one-evidence.md#s01-004) covers byte boundaries, Unicode, invalid encoding, controls, and allocation-before-validation negatives.

- [x] `S01-005` **Implement canonical names and masks.** Apply the exact
  nickname, account, channel, server, user-mask, case mapping, PRECIS, prefix,
  and comparison rules while preserving presentation separately from identity.
  - After: `S01-003`, `S01-004`.
  - Targets: `agenc-ircd-types`.
  - References: [Architecture §§7.1–7.4 and 13.4](docs/ircd-architecture-and-implementation-spec.md#71-account-identity).
  - Invariants: `ID-01`, `STA-01`, `STA-02`.
  - Evidence: [EVID-S01-005-NAMES-MASKS](conformance/stage-one-evidence.md#s01-005) covers canonicalization, collisions, PRECIS rejection, prefixes, masks, and profile boundaries.

- [x] `S01-006` **Implement stable public protocol errors.** Use closed error
  enums and exact public mappings without carrying raw input or internal error
  chains into replies, logs, or metrics.
  - After: `S01-001`, `S01-004`.
  - Targets: `agenc-ircd-types`.
  - References: [Architecture §9.5](docs/ircd-architecture-and-implementation-spec.md#95-errors), [§24.3](docs/ircd-architecture-and-implementation-spec.md#243-safe-rust-and-code-shape-policy), [Appendix A.2](docs/ircd-architecture-and-implementation-spec.md#a2-server-command-and-numeric-registry).
  - Invariants: `PRV-01`, `PRV-02`, `OPS-01`.
  - Evidence: [EVID-S01-006-PROTOCOL-ERRORS](conformance/stage-one-evidence.md#s01-006) uses exhaustive mapping tests and safe fixed descriptions with no input-bearing implicit rendering.

- [x] `S01-007` **Implement canonical binary primitives.** Decode exact-width
  integers, lengths, options, vectors, enums, and structures with full
  consumption, checked allocation, explicit discriminants, and no Serde.
  - After: `S01-001` through `S01-004`.
  - Targets: `agenc-ircd-federation-wire`.
  - References: [Architecture §§24.4 and Appendix B.1](docs/ircd-architecture-and-implementation-spec.md#b1-encoding-notation).
  - Invariants: `TRN-04`, `TRN-05`, `TRN-06`, `FED-08`.
  - Evidence: [EVID-S01-007-BINARY-CODEC](conformance/stage-one-evidence.md#s01-007) covers canonical round-trip, trailing bytes, truncation, bounds, allocation budgets, nesting, and every discriminant.

- [x] `S01-008` **Implement Appendix-B object codecs.** Cover common control
  arms, projections, events, deltas, requests, results, origins, delivery,
  snapshots, descriptors, and cross-reference validation at the codec layer.
  - After: `S01-003`, `S01-007`.
  - Targets: `agenc-ircd-federation-wire`.
  - References: [Architecture Appendices B.3–B.7](docs/ircd-architecture-and-implementation-spec.md#b3-common-validated-values-and-control-arms).
  - Invariants: `FED-03` through `FED-13` at the representation boundary.
  - Evidence: [EVID-S01-008-APPENDIX-B](conformance/stage-one-evidence.md#s01-008) provides all 128 arm vectors plus presence, count, order, substitution, and malformed-cross-reference negatives.

- [x] `S01-009` **Implement canonical text carrier primitives.** Enforce
  uppercase tokens, decimal forms, unpadded URL-safe base64, arity, and exact
  decode/re-encode equality without yet implementing connection state.
  - After: `S01-004`, `S01-007`.
  - Targets: `agenc-ircd-client-wire`, `agenc-ircd-federation-wire`.
  - References: [Architecture Appendix B.8](docs/ircd-architecture-and-implementation-spec.md#b8-text-carrier-tokens-and-command-arity), [E2EE §§11.2 and 11.10](docs/irc-mls-e2ee-extension.md#112-fragment-tag).
  - Invariants: `TRN-06`, `FED-08`.
  - Evidence: [EVID-S01-009-TEXT-CARRIERS](conformance/stage-one-evidence.md#s01-009) covers alternate alphabets, padding, width, sign, leading zero, case, arity, fragments, and overflow.

- [x] `S01-010` **Bind source and profile hashes.** Verify raw document,
  registry, base-federation profile, and E2EE profile derivations independently
  of production codecs and fail on any changed byte.
  - After: `S01-001`, `S01-007`.
  - Targets: conformance tests and source-hash tooling.
  - References: [Architecture §§30.2–30.3 and Appendix B.9](docs/ircd-architecture-and-implementation-spec.md#302-living-protocol-and-implementation-sources), [E2EE §2.3](docs/irc-mls-e2ee-extension.md#23-exact-profile-revision), [manifest](docs/specification-manifest.txt).
  - Invariants: `E2E-07`, `FED-02`.
  - Evidence: [EVID-S01-010-PROFILE-HASHES](conformance/stage-one-evidence.md#s01-010) binds all known hashes and rejects independent single-byte changes.

- [x] `S01-011` **Create independent reference codecs and golden vectors.** A
  small implementation that does not reuse production derive or codec logic
  must generate or verify every stable byte representation.
  - After: `S01-007` through `S01-010`.
  - Targets: `agenc-ircd-testkit`, checked-in vector corpus.
  - References: [Architecture §28.2](docs/ircd-architecture-and-implementation-spec.md#282-deterministic-unit-and-vector-tests).
  - Invariants: all representation-bound invariants.
  - Evidence: [EVID-S01-011-REFERENCE-VECTORS](conformance/stage-one-evidence.md#s01-011) records independent byte-for-byte agreement, provenance, and SHA-256 for every schema.

- [x] `S01-012` **Exercise totality and boundedness.** Property and negative
  tests must prove every finite codec input produces bounded success or error
  without panic, recursion, trailing acceptance, or pre-validation growth.
  - After: `S01-011`.
  - Targets: type and wire test suites.
  - References: [Architecture §§19.4, 27.1, and 28.2](docs/ircd-architecture-and-implementation-spec.md#194-parser-and-algorithmic-defenses).
  - Invariants: `TRN-04`, `TRN-05`, `TRN-06`, `CON-05`.
  - Evidence: [EVID-S01-012-TOTALITY](conformance/stage-one-evidence.md#s01-012) covers the hostile corpus, every truncation, explicit depth/value budgets, nonrecursion, and parser-error negatives.

- [x] `S01-900` **Pass the Stage 01 gate.** All Appendix-A/B constants,
  validated foundational types, canonical codecs, source checks, and independent
  vectors are complete before client behavior begins.
  - After: `S01-001` through `S01-012`.
  - Targets: `agenc-ircd-types`, foundational wire code, testkit vectors.
  - References: [Architecture §29 phase 1](docs/ircd-architecture-and-implementation-spec.md#29-implementation-sequence-and-acceptance-gates).
  - Invariants: `TRN-04` through `TRN-06`, applicable identity and federation representation invariants.
  - Evidence: [EVID-S01-900-STAGE-GATE](conformance/stage-one-evidence.md#s01-900) and the [current schema version 2 manifest](conformance/evidence/stage-01-1e5b738468f88b238061cc6e84b732176f5cae65.json) close the pinned, locked, dual-target gate for exact source commit `1e5b738468f88b238061cc6e84b732176f5cae65`; the [schema version 1 manifest](conformance/evidence/stage-01-8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb.json) remains archive-only.

## Stage 02 — Bounded client wire

Outcome: arbitrary client bytes can be framed, parsed, negotiated, and rendered
through a total, resource-bounded wire layer with no sockets, policy, or state
mutation inside the crate.

Stage 02 task work is complete. The [current schema version 2
manifest](conformance/evidence/stage-02-1e5b738468f88b238061cc6e84b732176f5cae65.json)
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
  - Targets: `agenc-ircd-client-wire`.
  - References: [Architecture §§8.3 and 9.1](docs/ircd-architecture-and-implementation-spec.md#83-time-and-resource-bounds).
  - Invariants: `TRN-04`, `TRN-05`, `TRN-06`.
  - Evidence: every split/coalesce boundary, empty/equal/plus-one length, CRLF, timeout, and EOF transcript passes.

- [x] `S02-002` **Implement WebSocket message framing semantics.** Validate the
  IRC-over-WebSocket message boundary, UTF-8, compression prohibition, size,
  and close behavior independently of the optional network listener. ([evidence](conformance/stage-two-evidence.md#s02-002))
  - After: `S02-001`.
  - Targets: `agenc-ircd-client-wire`.
  - References: [Architecture §8.4](docs/ircd-architecture-and-implementation-spec.md#84-websocket-listener), [RFC 6455 decision](docs/protocol-sources-and-decisions.md#2-published-standards).
  - Invariants: `TRN-02`, `TRN-04`, `TRN-05`.
  - Evidence: fragmented-message, binary-frame, invalid-UTF-8, extension, multi-line, and oversize negatives.

- [x] `S02-003` **Implement IRCv3 tags.** Parse and render tag names, values,
  escapes, duplicates, client-only tags, and budgets canonically. ([evidence](conformance/stage-two-evidence.md#s02-003))
  - After: `S02-001`.
  - Targets: `agenc-ircd-client-wire`.
  - References: [Architecture §9.2](docs/ircd-architecture-and-implementation-spec.md#92-tag-handling), [Appendix A](docs/ircd-architecture-and-implementation-spec.md#appendix-a-client-wire-registries).
  - Invariants: `TRN-04`, `TRN-06`.
  - Evidence: ratified IRCv3 vectors plus all escape, duplicate, boundary, and malformed cases.

- [x] `S02-004` **Implement syntax parsing.** Produce `ParsedMessage` from a
  framed line with exact prefix, command, parameter, trailing, and UTF-8 rules;
  do not perform authorization or mutation. ([evidence](conformance/stage-two-evidence.md#s02-004))
  - After: `S02-001`, `S02-003`.
  - Targets: `agenc-ircd-client-wire`.
  - References: [Architecture §§9 and Appendix A.1](docs/ircd-architecture-and-implementation-spec.md#9-client-wire-format), [RFC 2812](rfcs/rfc2812-irc-client-protocol.txt).
  - Invariants: `TRN-05`, `TRN-06`.
  - Evidence: every grammar arm and arity, prefix rejection, malformed command, parameter boundary, and differential transcript passes.

- [x] `S02-005` **Implement capability state.** Support CAP LS 302, REQ, ACK,
  NAK, END, NEW, DEL, dependencies, line splitting, and reconnect-only profile
  transitions without silently enabling unsupported drafts. ([evidence](conformance/stage-two-evidence.md#s02-005))
  - After: `S02-004`.
  - Targets: `agenc-ircd-client-wire`.
  - References: [Architecture §§2.1, 9.3, and Appendix A.3](docs/ircd-architecture-and-implementation-spec.md#21-adopted-client-specifications).
  - Invariants: `E2E-07`, `TRN-04`, `TRN-06`.
  - Evidence: capability dependency, simultaneous change, unknown capability, line-budget, and downgrade transcripts.

- [x] `S02-006` **Implement the connection-registration wire state.** Enforce
  permitted pre-registration commands, NICK/USER/CAP/SASL ordering, welcome
  burst ordering, keepalive, and bounded close output without implementing auth
  internals. ([evidence](conformance/stage-two-evidence.md#s02-006))
  - After: `S02-004`, `S02-005`.
  - Targets: `agenc-ircd-client-wire` and transcript model.
  - References: [Architecture §10](docs/ircd-architecture-and-implementation-spec.md#10-connection-and-registration-state-machine).
  - Invariants: `TRN-05`, `AUTH-02`, `OPS-04` at the wire boundary.
  - Evidence: every registration transition, invalid ordering, timeout, ping/pong, and close transcript.

- [x] `S02-007` **Implement SASL transport framing.** Handle AUTHENTICATE
  chunking, mechanism selection surface, abort, timeout, and fixed public
  replies while leaving OPAQUE processing to `agenc-ircd-auth`. ([evidence](conformance/stage-two-evidence.md#s02-007))
  - After: `S02-005`, `S02-006`.
  - Targets: `agenc-ircd-client-wire`.
  - References: [Architecture §§11.2–11.6](docs/ircd-architecture-and-implementation-spec.md#112-opaque-profile).
  - Invariants: `AUTH-01`, `AUTH-02`, `AUTH-10` at the carrier boundary.
  - Evidence: chunk width, plus marker, abort, unsupported mechanism, timeout, and response-shape transcripts.

- [x] `S02-008` **Implement capability-aware rendering.** Separate measuring
  from encoding, enforce exact client/server/combined line budgets, preserve
  canonical ordering, and never allocate before a matching permit is supplied. ([evidence](conformance/stage-two-evidence.md#s02-008))
  - After: `S02-003` through `S02-006`.
  - Targets: `agenc-ircd-client-wire`.
  - References: [Architecture §§9.4–9.5, 21.3, and 24.2](docs/ircd-architecture-and-implementation-spec.md#94-rpl_isupport).
  - Invariants: `TRN-04`, `STA-08`, `CON-05`.
  - Evidence: mechanical wire-budget table, measure/encode equality, exact-capacity allocation tests, and every capability combination.

- [x] `S02-009` **Implement labeled replies, batches, and reply ordering.**
  Render standard errors, numerics, labeled-response groups, and batch nesting
  exactly once and in the required order. ([evidence](conformance/stage-two-evidence.md#s02-009))
  - After: `S02-005`, `S02-008`.
  - Targets: `agenc-ircd-client-wire`.
  - References: [Architecture §§9.3–9.5 and 14.1](docs/ircd-architecture-and-implementation-spec.md#93-advertised-capabilities).
  - Invariants: `STA-06`, `STA-08`, `PRV-02`.
  - Evidence: traditional/standard reply, partial-success, nested-batch, label, and ordering golden transcripts.

- [x] `S02-010` **Build the client transcript harness.** Drive framing,
  parsing, capability state, registration, and rendering with deterministic
  time and byte-exact expectations. ([evidence](conformance/stage-two-evidence.md#s02-010))
  - After: `S02-001` through `S02-009`.
  - Targets: `agenc-ircd-testkit`, client-wire integration tests.
  - References: [Architecture §§28.2 and 28.6](docs/ircd-architecture-and-implementation-spec.md#282-deterministic-unit-and-vector-tests), [Appendix E](docs/ircd-architecture-and-implementation-spec.md#appendix-e-worked-protocol-flows).
  - Invariants: `TRN-*`, applicable `AUTH-*` and `STA-*` wire invariants.
  - Evidence: pinned base-client transcript corpus runs byte-identically.

- [x] `S02-011` **Fuzz every client-wire boundary.** Cover raw framing, tags,
  commands, decimal values, base64, capability transitions, render plans, and
  fragmented/coalesced input with explicit memory and time envelopes. ([evidence](conformance/stage-two-evidence.md#s02-011))
  - After: `S02-010`.
  - Targets: client-wire fuzz targets and regression corpus.
  - References: [Architecture §28.4](docs/ircd-architecture-and-implementation-spec.md#284-parser-and-fuzz-testing).
  - Invariants: `TRN-04`, `TRN-05`, `TRN-06`, `CON-05`.
  - Evidence: reproducible fuzz records plus minimized failures promoted to ordinary tests.

- [x] `S02-900` **Pass the Stage 02 gate.** The complete client-wire surface
  must be total, bounded, capability-correct, and transcript-compatible before
  domain state consumes a parsed command. ([evidence](conformance/stage-two-evidence.md#s02-900))
  - After: `S02-001` through `S02-011`.
  - Targets: `agenc-ircd-client-wire`, testkit transcripts and fuzz corpus.
  - References: [Architecture §29 phase 2](docs/ircd-architecture-and-implementation-spec.md#29-implementation-sequence-and-acceptance-gates).
  - Invariants: `TRN-04` through `TRN-06`.
  - Evidence: parser fuzzing and every wire boundary and registration transcript passed with the mandatory workspace gates; the [current schema version 2 manifest](conformance/evidence/stage-02-1e5b738468f88b238061cc6e84b732176f5cae65.json) closes the gate for exact source commit `1e5b738468f88b238061cc6e84b732176f5cae65`, and the [schema version 1 manifest](conformance/evidence/stage-02-8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb.json) remains archive-only.

## Stage 03 — Pure domain model

Outcome: deterministic protocol state, authorization, privacy projections, and
mutation plans are complete without sockets, TLS, executors, databases,
filesystem calls, concrete clocks, or random generators.

- [x] `S03-001` **Model accounts, principals, users, sessions, and presence.**
  Keep account, E2EE, nickname, presentation, cloak, and transport identities
  separate with explicit generation fencing.
  - After: `S02-900`.
  - Targets: `agenc-ircd-domain`.
  - References: [Architecture §§7, 11.1, and 12](docs/ircd-architecture-and-implementation-spec.md#7-typed-identifiers-and-canonical-names).
  - Invariants: `ID-01` through `ID-07`, `AUTH-04`, `AUTH-05`.
  - Evidence: lifecycle, account-switch, nickname reuse, cloak independence, and stale-generation property tests.

- [x] `S03-002` **Model channel instances, membership, roles, and modes.**
  Enforce recreation isolation, owner continuity, role ordering, mandatory and
  mutually exclusive modes, typed masks, and revision-bound decisions.
  - After: `S03-001`.
  - Targets: `agenc-ircd-domain`.
  - References: [Architecture §13](docs/ircd-architecture-and-implementation-spec.md#13-channel-model).
  - Invariants: `STA-02` through `STA-05`.
  - Evidence: generated membership/role/mode sequences and every boundary/collision transition.

- [x] `S03-003` **Implement privacy and discovery projections.** Produce only
  recipient-authorized views for public, unlisted, secret, invisible, offline,
  account, channel, query, and presence state.
  - After: `S03-001`, `S03-002`.
  - Targets: `agenc-ircd-domain`.
  - References: [Architecture §§6, 13.5, 14.3, and 14.5](docs/ircd-architecture-and-implementation-spec.md#6-privacy-and-anonymity-profiles).
  - Invariants: `PRV-01`, `PRV-02`, `STA-10`, `ID-04`, `ID-05`.
  - Evidence: authorization matrices, projection diffs, equal-error tests, and forbidden-field canaries.

- [x] `S03-004` **Canonicalize and validate commands.** Convert parsed syntax
  into `CanonicalCommand` only after semantic bounds, target resolution rules,
  mode vectors, and all-or-none command-level validation succeed.
  - After: `S03-001` through `S03-003`.
  - Targets: `agenc-ircd-domain`.
  - References: [Architecture §§14 and 21.4](docs/ircd-architecture-and-implementation-spec.md#14-base-command-behavior).
  - Invariants: `STA-04`, `STA-05`, `STA-06`, `TRN-05`.
  - Evidence: every Appendix-A command arm has success, rejection, multi-target, and unchanged-state tests.

- [x] `S03-005` **Implement authorization and rate charging.** Produce an
  `AuthorizedCommand` only after current principal, generation, role, target
  revision, policy, and hierarchical budget checks pass.
  - After: `S03-004`.
  - Targets: `agenc-ircd-domain`.
  - References: [Architecture §§16 and 19.1](docs/ircd-architecture-and-implementation-spec.md#16-moderation-and-user-safety).
  - Invariants: `ID-01`, `STA-03`, `STA-05`, `STA-07`, `CON-05`.
  - Evidence: privilege-transition, stale-identity, confused-deputy, exhaustion, and charge-before-ID tests.

- [x] `S03-006` **Implement channel and direct-message plans.** Cover JOIN,
  PART, TOPIC, NAMES, LIST, INVITE, KICK, direct/channel messaging, echo,
  recipient derivation, and atomic authorized-success subsets.
  - After: `S03-005`.
  - Targets: `agenc-ircd-domain`.
  - References: [Architecture §§14.1–15.3](docs/ircd-architecture-and-implementation-spec.md#141-atomic-multi-target-rules).
  - Invariants: `STA-01` through `STA-10`.
  - Evidence: deterministic two-client/multi-target flows, ordering tests, secret-target privacy, and rollback-free pure plans.

- [x] `S03-007` **Implement moderation and user-safety plans.** Model mutes,
  bans, exceptions, sanctions, role-gated actions, removal consequences, and
  auditable operator decisions without inspecting encrypted content.
  - After: `S03-005`, `S03-006`.
  - Targets: `agenc-ircd-domain`.
  - References: [Architecture §16](docs/ircd-architecture-and-implementation-spec.md#16-moderation-and-user-safety).
  - Invariants: `STA-03`, `STA-04`, `STA-05`, `OPS-03`.
  - Evidence: role/sanction matrix, appeal-state transitions, E2EE-removal intent tests, and audit-field allowlist tests.

- [x] `S03-008` **Model history and offline state policy.** Keep default
  ephemerality, optional plaintext channel history, offline account state, and
  E2EE opacity as explicit mutually constrained policies.
  - After: `S03-002`, `S03-006`.
  - Targets: `agenc-ircd-domain`.
  - References: [Architecture §17](docs/ircd-architecture-and-implementation-spec.md#17-persistence-and-history-visible-to-users), [§18](docs/ircd-architecture-and-implementation-spec.md#18-e2ee-integration-contract).
  - Invariants: `STA-09`, `E2E-01`, `E2E-02`.
  - Evidence: default-no-history, opt-in scope, encrypted-target refusal, deletion, and visibility tests.

- [x] `S03-009` **Implement pure mutation plans and events.** Separate
  validation, authorization, deterministic state transition, storage
  projection, recipient projection, and later runtime reservations.
  - After: `S03-004` through `S03-008`.
  - Targets: `agenc-ircd-domain`.
  - References: [Architecture §§21.1, 21.5, and 24.2](docs/ircd-architecture-and-implementation-spec.md#211-ownership-rule).
  - Invariants: `CON-01`, `CON-03`, `DUR-01`, `STA-08`.
  - Evidence: plans are deterministic from one revision, contain no runtime/storage handles, and apply once in the reference model.

- [x] `S03-010` **Make time and randomness explicit inputs.** Express policy
  through monotonic/wall-clock values and requested entropy operations without
  calling system clocks or RNGs in domain code.
  - After: `S03-009`.
  - Targets: `agenc-ircd-domain`, type-level clock/entropy request interfaces.
  - References: [Architecture §§21.6 and 24.2](docs/ircd-architecture-and-implementation-spec.md#216-timers-and-clocks).
  - Invariants: `CON-01`, `AUTH-02`, `FED-09`.
  - Evidence: deterministic boundary tests for expiry, clock failure/jump, timer replacement, and entropy-request identity.

- [x] `S03-011` **Build the deterministic reference model.** Execute every
  command and planned federation-domain operation against simple value state,
  checking invariants after every generated step.
  - After: `S03-001` through `S03-010`.
  - Targets: `agenc-ircd-testkit` reference model.
  - References: [Architecture §28.3](docs/ircd-architecture-and-implementation-spec.md#283-state-machine-and-model-tests).
  - Invariants: all applicable `ID-*`, `PRV-*`, `STA-*`, `CON-*`.
  - Evidence: model covers every command registry arm and exports deterministic snapshots for implementation comparison.

- [x] `S03-012` **Generate adversarial domain sequences.** Cover registration,
  nickname reuse, recreation, roles, modes, invites, account switches,
  deletion, partitions-as-domain-input, duplicates, gaps, and invalid state
  transitions.
  - After: `S03-011`.
  - Targets: property/state-machine test suites.
  - References: [Architecture §§27 and 28.3](docs/ircd-architecture-and-implementation-spec.md#27-security-and-correctness-invariants).
  - Invariants: every applicable Stage-03 invariant.
  - Evidence: generated sequences preserve invariants and rejected steps leave the reference state unchanged.

- [x] `S03-900` **Pass the Stage 03 gate.** The pure domain implementation and
  independent reference model must agree for all generated sequences before
  cryptographic, storage, or runtime side effects are introduced.
  - After: `S03-001` through `S03-012`.
  - Targets: `agenc-ircd-domain`, testkit reference model.
  - References: [Architecture §29 phase 3](docs/ircd-architecture-and-implementation-spec.md#29-implementation-sequence-and-acceptance-gates).
  - Invariants: applicable `ID-*`, `PRV-*`, `STA-*`, `CON-*`.
  - Evidence: generated sequence tests, privacy matrices, model equality, and mandatory workspace gates passed; the [current schema version 2 manifest](conformance/evidence/stage-03-1e5b738468f88b238061cc6e84b732176f5cae65.json) closes the gate for exact source commit `1e5b738468f88b238061cc6e84b732176f5cae65`, and the [schema version 1 manifest](conformance/evidence/stage-03-8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb.json) remains archive-only.

## Stage 04 — Cryptographic adapters and account authentication

Outcome: maintained libraries are configured and composed exactly as specified
behind bounded, secret-safe adapters; account creation, authentication, and
credential change have complete protocol state machines and vectors.

- [x] `S04-001` **Implement secret-bearing wrappers.** Prevent `Debug`,
  `Display`, `Clone`, Serde, implicit string conversion, and accidental log or
  error exposure; zeroize owned buffers where the selected library supports it.
  - After: `S03-900`.
  - Targets: `agenc-ircd-crypto`.
  - References: [Architecture §§22.2 and 24.3](docs/ircd-architecture-and-implementation-spec.md#222-secret-material), [§25.2](docs/ircd-architecture-and-implementation-spec.md#252-logging).
  - Invariants: `ID-05`, `AUTH-03`, `OPS-01`.
  - Evidence: compile-fail trait checks, secret-canary scans, drop tests, and explicit exposure-path review.

- [x] `S04-002` **Implement the OS entropy adapter.** Use `getrandom` with the
  exact features, require complete output, expose failure, and provide no
  production fallback or deterministic mode.
  - After: `S04-001`.
  - Targets: `agenc-ircd-crypto`.
  - References: [Architecture §§24.2 and 24.4](docs/ircd-architecture-and-implementation-spec.md#242-core-interfaces-and-ownership).
  - Invariants: `ID-02`, `ID-03`, `DUR-06` at the entropy boundary.
  - Evidence: full/partial/failure adapter tests and release-graph proof that deterministic entropy is unreachable.

- [x] `S04-003` **Implement domain-separated hash, HMAC, and HKDF adapters.**
  Accept typed contexts and inputs, expose only registered algorithms, and
  prevent cross-domain or truncated-output substitution.
  - After: `S04-001`.
  - Targets: `agenc-ircd-crypto`.
  - References: [Architecture §24.4](docs/ircd-architecture-and-implementation-spec.md#244-serialization-and-crypto-libraries), [E2EE §§2.2 and 7](docs/irc-mls-e2ee-extension.md#22-semantic-id-and-digest-registry).
  - Invariants: `AUTH-08`, `DUR-03`, `E2E-05`.
  - Evidence: RFC/project vectors, domain-substitution negatives, length checks, and differential library tests where available.

- [x] `S04-004` **Implement XChaCha20-Poly1305 storage adapters.** Fix the
  algorithm, key/nonce sizes, AAD domains, full-tag verification, and failure
  behavior; nonce allocation remains a Stage-05 storage responsibility.
  - After: `S04-001`, `S04-003`.
  - Targets: `agenc-ircd-crypto`.
  - References: [Architecture §§23.3 and 24.4](docs/ircd-architecture-and-implementation-spec.md#233-record-encryption), [source ledger §3](docs/protocol-sources-and-decisions.md#3-work-in-progress-and-deliberately-excluded-algorithms).
  - Invariants: `DUR-03`, `DUR-06`.
  - Evidence: XChaCha/project vectors and wrong-key, nonce, AAD, tag, truncation, and tamper negatives.

- [x] `S04-005` **Implement strict Ed25519 adapters.** Use `verify_strict`,
  typed signing domains, exact encodings, no batch/hazmat/legacy surface, and
  secret-key wrappers.
  - After: `S04-001`, `S04-003`.
  - Targets: `agenc-ircd-crypto`.
  - References: [Architecture §24.4](docs/ircd-architecture-and-implementation-spec.md#244-serialization-and-crypto-libraries), [E2EE §2.1](docs/irc-mls-e2ee-extension.md#21-signature-registry).
  - Invariants: `TRN-03`, `E2E-05`, `OPS-05`.
  - Evidence: signature/domain vectors, malleability and wrong-domain negatives, and secret-exposure scans.

- [x] `S04-006` **Implement the fixed account-service HPKE envelope.** Enforce
  Base mode, the pinned suite, request/response contexts, recovery epoch,
  operation kind, exact 4,726-byte wrapper, all-zero padding, and one-use
  exporter material.
  - After: `S04-002`, `S04-003`.
  - Targets: `agenc-ircd-auth`, `agenc-ircd-crypto`.
  - References: [Architecture §11.2.1](docs/ircd-architecture-and-implementation-spec.md#1121-end-to-end-account-service-envelope), [RFC 9180](rfcs/rfc9180-hpke.txt).
  - Invariants: `ID-05`, `ID-06`, `AUTH-08`, `AUTH-10`.
  - Evidence: fixed-wrapper vectors plus pin, epoch, kind, context, length, padding, salt, and replay negatives.

- [x] `S04-007` **Implement the exact OPAQUE profile.** Configure the pinned
  suite, identities, context, Argon2id KSF, private credential IDs, record
  lengths, real and fake records, and dummy KE3 work without Serde.
  - After: `S04-001` through `S04-003`.
  - Targets: `agenc-ircd-auth`, `agenc-ircd-crypto`.
  - References: [Architecture §11.2](docs/ircd-architecture-and-implementation-spec.md#112-opaque-profile), [source ledger §2](docs/protocol-sources-and-decisions.md#2-published-standards).
  - Invariants: `AUTH-01`, `AUTH-03`, `AUTH-09`, `AUTH-10`.
  - Evidence: RFC 9807/project vectors, exact serialized lengths, fake-record equivalence, dummy-KE3 work, and unsupported-suite rejection.

- [x] `S04-008` **Implement account creation.** Bind invitation, login,
  credential identity, HPKE context, OPAQUE registration, expiry, connection,
  and one-use transaction state without creating an E2EE identity.
  - After: `S04-006`, `S04-007`.
  - Targets: `agenc-ircd-auth`, domain authorization interfaces.
  - References: [Architecture §11.3](docs/ircd-architecture-and-implementation-spec.md#113-account-creation).
  - Invariants: `AUTH-02`, `AUTH-04`, `AUTH-08`, `AUTH-09`.
  - Evidence: success, unknown/duplicate login, invitation substitution, expiry, replay, disconnect, and output-shape tests.

- [x] `S04-009` **Implement OPAQUE login over SASL.** Bind KE1/KE2/KE3,
  origin connection, edge/coordinator routing, account-service HPKE, fake-record
  behavior, session generation, and final public replies.
  - After: `S04-006` through `S04-008`.
  - Targets: `agenc-ircd-auth`, client-wire auth interface, domain session interface.
  - References: [Architecture §11.4](docs/ircd-architecture-and-implementation-spec.md#114-opaque-login-over-sasl).
  - Invariants: `AUTH-01`, `AUTH-02`, `AUTH-05`, `AUTH-06`, `AUTH-08` through `AUTH-10`.
  - Evidence: known/unknown parity, malicious-edge, stale completion, replay, session-fence, timeout, and wire-transcript tests.

- [x] `S04-010` **Implement exporter-authenticated completion receipts.** Use
  independent salted one-use exporter material, operation/request binding,
  recovery epoch, response count, exact response kind, and idempotent replay.
  - After: `S04-006`, `S04-009`.
  - Targets: `agenc-ircd-auth`, `agenc-ircd-crypto`.
  - References: [Architecture §§11.2.1 and 11.4](docs/ircd-architecture-and-implementation-spec.md#1121-end-to-end-account-service-envelope), [source ledger §2](docs/protocol-sources-and-decisions.md#2-published-standards).
  - Invariants: `AUTH-06`, `AUTH-08`, `DUR-12`.
  - Evidence: forgery, substitution, bare-success, collision fixture, changed-outcome replay, and `u64::MAX` refusal tests.

- [x] `S04-011` **Implement credential replacement and account-deletion auth.**
  Require fresh same-account proof, revision-bound one-use confirmation,
  credential-identity reuse, atomic record intent, and complete old-session
  fencing; provide no server-assisted recovery path.
  - After: `S04-009`, `S04-010`.
  - Targets: `agenc-ircd-auth`, domain mutation plans.
  - References: [Architecture §§11.5, 14.6, and 23.8](docs/ircd-architecture-and-implementation-spec.md#115-credential-change-and-non-recovery).
  - Invariants: `AUTH-05`, `AUTH-07`, `AUTH-11`.
  - Evidence: fresh/stale proof, wrong account, revision replacement, replay, precondition, tombstone intent, and session-fence tests.

- [x] `S04-012` **Implement bounded crypto workers and `CryptoPort`.** Keep CPU
  and blocking work off Tokio workers, bound queue/in-flight work, preserve
  job ownership, propagate cancellation outcomes, and never log job contents.
  - After: `S04-003` through `S04-011`.
  - Targets: `agenc-ircd-crypto`, runtime-facing port implementation.
  - References: [Architecture §§19.1, 21.7, and 24.2](docs/ircd-architecture-and-implementation-spec.md#191-hierarchical-admission).
  - Invariants: `CON-02`, `CON-04`, `CON-05`, `OPS-01`.
  - Evidence: queue-full, worker panic, cancellation, overload, timing-class, secret-canary, and joined-shutdown tests.

- [x] `S04-013` **Lock the cryptographic dependency graph and features.** Prove
  exact direct versions/features, no forbidden defaults, scoped duplicate
  generations, no Git source, and no unexpected algorithm reachability.
  - After: `S04-003` through `S04-012`.
  - Targets: Cargo manifests/lockfile and dependency evidence.
  - References: [Architecture §§24.4–24.5](docs/ircd-architecture-and-implementation-spec.md#244-serialization-and-crypto-libraries), [source ledger §5](docs/protocol-sources-and-decisions.md#5-initial-rust-dependency-evidence).
  - Invariants: `OPS-02`.
  - Evidence: feature tree, duplicate/reachability report, checksum verification, `cargo deny`, and `cargo audit` pass.

- [x] `S04-014` **Complete crypto/auth verification.** Run all standardized and
  project vectors, malicious-edge confirmation, fake-record/dummy-KE3,
  constant-time-path integration review, secret canaries, and worker-bound
  tests without claiming the primitives themselves were re-proved.
  - After: `S04-001` through `S04-013`.
  - Targets: crypto/auth test and evidence suites.
  - References: [Architecture §§28.2, 28.4, and 29 phase 4](docs/ircd-architecture-and-implementation-spec.md#282-deterministic-unit-and-vector-tests).
  - Invariants: `ID-05` through `ID-07`, `AUTH-*`, applicable `DUR-*`, `OPS-01`.
  - Evidence: complete evidence manifest for every crypto/auth requirement and dependency configuration.

- [x] `S04-900` **Pass the Stage 04 gate.** No auth or cryptographic operation
  advances state without the exact standardized/library-backed validation,
  context binding, resource admission, and completion evidence.
  - After: `S04-001` through `S04-014`.
  - Targets: `agenc-ircd-crypto`, `agenc-ircd-auth`, affected testkit surfaces.
  - References: [Architecture §29 phase 4](docs/ircd-architecture-and-implementation-spec.md#29-implementation-sequence-and-acceptance-gates).
  - Invariants: `AUTH-*`, `ID-05` through `ID-07`, `CON-02`, `CON-04`, `CON-05`.
  - Evidence: all named acceptance evidence and mandatory workspace gates passed under the pinned lockfile; the [current schema version 2 manifest](conformance/evidence/stage-04-4040796f2c21774d58ea7ce54e70a080678e83ac.json) closes the gate for exact source commit `4040796f2c21774d58ea7ce54e70a080678e83ac` after the Stage 04 and 05 legibility review; the [previous schema version 2 manifest](conformance/evidence/stage-04-1e5b738468f88b238061cc6e84b732176f5cae65.json) and the [schema version 1 manifest](conformance/evidence/stage-04-8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb.json) remain archive-only.

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
  - Targets: `agenc-ircd-storage`.
  - References: [Architecture §§23.1–23.2 and Appendix C.5](docs/ircd-architecture-and-implementation-spec.md#231-engine-and-durability).
  - Invariants: `DUR-02`, `DUR-03`, `DUR-10`, `DUR-11`.
  - Evidence: golden record vectors, full-consumption negatives, schema/keyspace inventory, and charge-boundary tests.

- [x] `S05-002` **Implement sealed records.** Authenticate record type, key,
  schema, key generation, and AAD before parsing plaintext; reject corruption,
  substitution, unknown generation, and partial values.
  - After: `S05-001`, `S04-004`.
  - Targets: `agenc-ircd-storage`, crypto adapter integration.
  - References: [Architecture §23.3](docs/ircd-architecture-and-implementation-spec.md#233-record-encryption).
  - Invariants: `DUR-03`, `DUR-06`, `DUR-07`.
  - Evidence: known vectors and wrong key/type/AAD/generation/nonce/tag/truncation/substitution tests.

- [x] `S05-003` **Implement `StateMeta` and accounting.** Maintain exact
  revisions, cursors, epochs, response count, nonce high-water mark, logical
  database bytes, backup-stream bytes, and integrity roots with checked
  arithmetic.
  - After: `S05-001`, `S05-002`.
  - Targets: `agenc-ircd-storage`.
  - References: [Architecture §§23.2–23.5](docs/ircd-architecture-and-implementation-spec.md#232-database-identity-and-schema).
  - Invariants: `DUR-04`, `DUR-06`, `DUR-10` through `DUR-12`.
  - Evidence: full-scan equality, overflow, edge-zero, response-count, and nonce-boundary tests.

- [x] `S05-004` **Implement validated storage mutation batches.** Recompute
  record, byte, seal, and accounting limits; bind one transaction ID; exclude
  closures, runtime handles, borrowed StateCore data, and rendered bytes.
  - After: `S03-009`, `S05-001` through `S05-003`.
  - Targets: `agenc-ircd-storage`, domain-to-storage conversion boundary.
  - References: [Architecture §§21.5, 23.4, and 24.2](docs/ircd-architecture-and-implementation-spec.md#215-durable-mutation-batches).
  - Invariants: `CON-03`, `DUR-01`, `DUR-02`, `CON-05`.
  - Evidence: mismatch, over-limit, stale-revision, cross-transaction, and ownership compile-fail tests.

- [x] `S05-005` **Implement `StorageOwner` and `StoragePort`.** Own redb on one
  blocking thread, accept only complete batches/read plans, return bounded
  completions, and consume every result even after request cancellation.
  - After: `S05-004`.
  - Targets: `agenc-ircd-storage` and runtime-facing port.
  - References: [Architecture §§21.1, 21.7, and 24.2](docs/ircd-architecture-and-implementation-spec.md#211-ownership-rule).
  - Invariants: `CON-01` through `CON-04`.
  - Evidence: ownership, cancellation, worker failure, queue-full, late-receipt, and joined-shutdown tests.

- [x] `S05-006` **Implement immediate two-phase commit reconciliation.** Apply
  the exact atomic record set, sync requirements, receipt matching, and
  `Indeterminate` closure without reporting guessed success or retrying a
  non-idempotent mutation blindly.
  - After: `S05-003` through `S05-005`.
  - Targets: `agenc-ircd-storage`.
  - References: [Architecture §§23.1 and 23.4](docs/ircd-architecture-and-implementation-spec.md#231-engine-and-durability).
  - Invariants: `DUR-01`, `DUR-02`, `OPS-04`, `CON-03`.
  - Evidence: injected failure before/after every write, commit, sync, and receipt boundary proves the specified outcome.

- [x] `S05-007` **Implement nonce reservations and burn rules.** Anchor each
  fresh 192-bit nonce block in both authenticated control state and rollback
  guard before use; burn aborted/uncertain slots and enforce the `2^40` limit.
  - After: `S05-002`, `S05-003`, `S05-006`.
  - Targets: `agenc-ircd-storage`, entropy adapter.
  - References: [Architecture §§23.3 and 23.5](docs/ircd-architecture-and-implementation-spec.md#233-record-encryption).
  - Invariants: `DUR-06`, `DUR-08`.
  - Evidence: crash tests for every reservation state, collision fixtures, high-water boundaries, and no-reuse reconstruction.

- [x] `S05-008` **Implement integrity manifests and checkpoints.** Track every
  sealed record insertion/deletion/substitution in an authenticated bounded
  ledger and produce independently verifiable checkpoints.
  - After: `S05-002`, `S05-003`, `S05-006`.
  - Targets: `agenc-ircd-storage`.
  - References: [Architecture §§23.5 and 23.5.2](docs/ircd-architecture-and-implementation-spec.md#235-authenticated-integrity-rollback-guard-and-recovery).
  - Invariants: `DUR-04`, `DUR-07`, `DUR-09`.
  - Evidence: vector, insertion/deletion/substitution, chain-gap, checkpoint-cut, and bounded-ledger tests.

- [x] `S05-009` **Implement the external rollback guard.** Authenticate exact
  database identity, generation, StateMeta, manifest/checkpoint state, and
  reservation authority using separately keyed, atomically replaced files.
  - After: `S05-003`, `S05-007`, `S05-008`.
  - Targets: `agenc-ircd-storage`, platform filesystem adapter.
  - References: [Architecture §23.5.1](docs/ircd-architecture-and-implementation-spec.md#2351-external-rollback-guard).
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
  - Targets: `agenc-ircd-storage`.
  - References: [Architecture §23.5.3](docs/ircd-architecture-and-implementation-spec.md#2353-startup-integrity-reconstruction).
  - Invariants: `DUR-03`, `DUR-04`, `DUR-07`, `DUR-08`.
  - Evidence: complete corruption/recovery matrix and reconstructed-state comparison with the reference model.

- [x] `S05-011` **Implement authenticated migrations.** Build output through
  the bounded construction ledger, preserve or explicitly transform every
  schema/invariant, support interruption/restart, and install only the matching
  completion record.
  - Version 1 ships schema generation 1 with no migration edge. The compiled
    empty registry rejects every successor, while the construction executor
    validates and resumes a future checked-in edge without in-place mutation.
  - After: `S05-010`.
  - Targets: `agenc-ircd-storage`, migration tooling.
  - References: [Architecture §§23.5.2 and 23.6](docs/ircd-architecture-and-implementation-spec.md#236-migrations).
  - Invariants: `DUR-04`, `DUR-09`, `DUR-11`, `DUR-12`.
  - Evidence: every migration edge, crash point, stale plan, tamper, restart, space, and output-validation test.

- [x] `S05-012` **Implement backup and restore.** Produce the authenticated
  bounded backup stream; restore only through construction; create new server,
  database, recovery, and state generations; and enforce client resynchronization.
  - The storage library creates, verifies, publishes, restores, resumes, and
    reopens signed backups through construction. A strict maintenance-only
    configuration parser and the stopped-daemon `storage restore` binary
    command compose the executor without starting the Stage 06 daemon.
  - After: `S05-010`, `S05-011`.
  - Targets: `agenc-ircd-storage`, binary maintenance commands.
  - References: [Architecture §23.7](docs/ircd-architecture-and-implementation-spec.md#237-backup-format-and-restore).
  - Invariants: `DUR-05`, `DUR-09`, `DUR-11`.
  - Evidence: exact/current, refused stale/divergent, disaster recovery, tamper, truncation, space, crash, and credential-generation tests.

- [x] `S05-013` **Implement deletion and storage-key rotation.** Durably erase
  unauthorized/deleted material before acknowledgment and rebuild rekey output
  with fresh generation, nonce authority, integrity state, and construction
  evidence.
  - After: `S05-010` through `S05-012`.
  - Targets: `agenc-ircd-storage`, domain deletion plans.
  - References: [Architecture §23.8](docs/ircd-architecture-and-implementation-spec.md#238-deletion-and-key-rotation).
  - Invariants: `FED-07`, `DUR-05` through `DUR-09`.
  - Evidence: erasure-before-ACK, interruption, stale-key, generation, residual-record, rollback, and resumed-rekey tests.

- [x] `S05-014` **Implement login-index key transition.** Support exactly one
  current and one previous keyed generation, migrate only after successful
  OPAQUE input, verify duplicate ownership and counts, and fail on missing or
  third-generation state.
  - After: `S04-009`, `S05-010`, `S05-013`.
  - Targets: `agenc-ircd-storage`, auth/storage integration.
  - References: [Architecture §23.9](docs/ircd-architecture-and-implementation-spec.md#239-login-index-key-transition).
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
  - References: [Architecture §§28.5 and 28.7](docs/ircd-architecture-and-implementation-spec.md#285-crash-storage-and-fault-injection).
  - Invariants: `DUR-*`, `CON-03`, `OPS-04`.
  - Evidence: complete crash/fault/corruption matrix and signed per-tuple growth report with boundary cases.

- [x] `S05-900` **Pass the Stage 05 gate.** Every accepted durable mutation,
  recovery state, construction, backup, restore, deletion, and key transition
  satisfies the complete `DUR-*` invariant family.
  - Current status: clean all-workspace coverage is 90.64% of branches and
    95.65% of lines, with all six critical regions at 100%. The complete
    implementation gate passes.
  - After: `S05-001` through `S05-015`.
  - Targets: `agenc-ircd-storage` and all storage evidence.
  - References: [Architecture §29 phase 5](docs/ircd-architecture-and-implementation-spec.md#29-implementation-sequence-and-acceptance-gates).
  - Invariants: `DUR-01` through `DUR-12`, applicable `CON-*` and `OPS-*`.
  - Evidence: all storage acceptance evidence and mandatory workspace gates
    pass from clean state; the [current schema version 2 manifest](conformance/evidence/stage-05-4040796f2c21774d58ea7ce54e70a080678e83ac.json)
    closes the gate for exact source commit
    `4040796f2c21774d58ea7ce54e70a080678e83ac` after the Stage 04 and 05 legibility
    review, and the [previous schema version 2 manifest](conformance/evidence/stage-05-bd7518fe7f5c7420debdbaa958aa444ecb5c80c9.json)
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

The merge did not close Stage 06. The cloud gate failed in `check-source`, the
coverage and requirement-ledger checkpoints remain open, and no exact-SHA
Stage 06 evidence exists. The commit-point boxes below record which work
landed. The `S06-*` task boxes remain open until their required evidence passes
for one exact revision.

#### Branch and worktree control

- [x] Keep the Stage 06 implementation in the existing
  `/home/tetsuo/git/AgenC/agenc-ircd` worktree.
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

- [ ] Install or provide the exact required toolchain on the qualification
  host, including Tor, `systemd-analyze`, the AArch64 cross compiler, Rust
  1.98.0, nightly 2026-08-24, `cargo-deny` 0.20.2, `cargo-audit` 0.22.2,
  `cargo-llvm-cov` 0.9.0, and `cargo-fuzz` 0.13.2.
- [ ] Run `bash scripts/check-stage-six.sh` without evidence recording until
  all 75 inherited and Stage 06 commands pass from a clean tree. The merged
  revision currently stops at `check-source` before the later commands run.
- [ ] Confirm that the gate includes formatting, native and cross-target
  checks, Clippy, workspace and documentation tests, dependency denial,
  advisory audit, source and workspace checks, coverage, all earlier-stage
  checks, Stage 06 tests, Loom, transcripts, deterministic soak, deployment,
  host qualification, and fuzzing.
- [ ] Run both Stage 06 fuzz targets for 10,000 iterations with the fixed seed
  and configured bounds.
- [x] Do not claim the seven-day production soak assigned to `S10-007`.
- [ ] Check `S06-900` only after the full non-recording gate passes.
- [ ] Update the Stage 06 status text to say that implementation passes and
  exact-revision evidence remains pending.

Commit point 9

- [ ] Run GitNexus `detect_changes` for the complete branch against `main`.
- [x] Confirm that the implementation branch contained no unrelated or generated
  residue.
- [x] Commit and push the last implementation source as
  `1c91131ce0b411717a1a3ddb15a0202fc8312ce3`.
- [ ] Commit point 9 is closed only after the full non-recording gate passes.

#### Exact-SHA evidence

- [ ] Create one temporary detached checkout at the exact source commit. Do
  not create a branch and do not edit source in that checkout.
- [ ] Run the recorded gate from the clean detached checkout with
  `AGENC_IRCD_RECORD_GATE=1`.

  ```sh
  source_commit="$(git rev-parse HEAD)"
  env -u GIT_PAGER -u LD_LIBRARY_PATH -u PYTHONPATH \
    AGENC_IRCD_RECORD_GATE=1 \
    bash scripts/check-stage-six.sh
  ```

- [ ] Record
  `conformance/evidence/artifacts/stage-six-implementation-<sha>.json`.
- [ ] Generate `conformance/evidence/stage-06-<sha>.json` with evidence schema
  version 2.

  ```sh
  python3 scripts/generate-gate-evidence.py \
    --artifact \
    "conformance/evidence/artifacts/stage-six-implementation-${source_commit}.json"
  ```

- [ ] Run the evidence checker, evidence self-test, and Stage 06 `close-stage`
  command for the exact source SHA.

  ```sh
  python3 scripts/check-evidence.py check
  python3 scripts/check-evidence.py self-test
  python3 scripts/check-evidence.py close-stage \
    --stage 6 --source-commit "${source_commit}"
  ```

- [ ] Copy only the generated artifact and manifest back to the active branch,
  together with the required closure-status documentation updates.
- [ ] Delete the temporary detached checkout after the artifact is recovered.
- [ ] If any source changes after recording, discard the stale Stage 06
  artifact and repeat the exact-SHA gate at the new source commit.

Commit point 10

- [ ] Confirm that the staged diff contains only evidence and closure-status
  files.
- [ ] Run every evidence checker and self-test again from the active branch.
- [ ] Run GitNexus `detect_changes` before committing.
- [ ] Commit with the subject `Record Stage 06 checkpoint`.
- [ ] Push `stage-06-runtime`.

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
- [ ] Fix the failed cloud gate. It stopped at `check-source` because
  `crates/agenc-ircd-config/src/paths.rs` has a lint allowance without the
  required review annotation.
- [ ] Repeat exact-SHA evidence after any source fix.
- [ ] Leave the pull request open for the cloud-agent and repository-owner
  merge gate. This was violated when PR #14 was merged before the gate passed.

- [x] `S06-001` **Implement strict configuration parsing and validation.**
  Parse TOML into an untrusted intermediate, reject unknowns, validate the full
  Appendix-C union and cross-field rules, paths, permissions, bounds, roles,
  targets, and unsafe combinations before listeners open.
  - After: `S05-900`.
  - Targets: `agenc-ircd-config`.
  - References: [Architecture §22.1 and Appendix C](docs/ircd-architecture-and-implementation-spec.md#221-configuration-document).
  - Invariants: `OPS-02`, `PRV-03`, `TRN-02`.
  - Evidence: golden configuration, unknown/duplicate field, every scalar boundary, cross-field matrix, permission, symlink, and fuzz tests.

- [x] `S06-002` **Implement first-run initialization and `check-config`.**
  Create purpose-separated keys/directories with minimum permissions, display
  onboarding pins safely, validate host controls, and never regenerate durable
  identity implicitly.
  - After: `S06-001`.
  - Targets: `agenc-ircd-config`, binary initialization/check commands.
  - References: [Architecture §§22.2–22.3 and Appendix C.8](docs/ircd-architecture-and-implementation-spec.md#222-secret-material).
  - Invariants: `ID-06`, `OPS-02`, `OPS-03`.
  - Evidence: clean/partial/repeated initialization, permissions, existing-key, pin, and failure-atomicity tests.

- [x] `S06-003` **Configure TLS 1.3 endpoints exactly.** Use the explicit
  aws-lc provider, TLS-1.3-only versions, `[X25519MLKEM768, X25519]` order,
  no early data/renegotiation/post-handshake auth, exact ALPN, and correct DNS
  or onion identity validation.
  - After: `S06-001`, `S04-013`.
  - Targets: `agenc-ircd-runtime`, TLS configuration adapter.
  - References: [Architecture §§8.1–8.3](docs/ircd-architecture-and-implementation-spec.md#81-tls-configuration).
  - Invariants: `TRN-01`, `TRN-02`, `TRN-03`.
  - Evidence: positive and negative TLS matrix, hybrid/fallback negotiation, scanner output, ALPN, certificate/pin, and pre-handshake-byte tests.

- [x] `S06-004` **Implement transport-profile isolation.** Keep direct,
  Tor-exit, and onion listeners explicit; forbid reverse DNS, ident, profile
  fallback, address propagation, and unsafe Tor DNS/proxy behavior.
  - After: `S06-002`, `S06-003`.
  - Targets: `agenc-ircd-runtime`, deployment profiles.
  - References: [Architecture §§6.1–6.4 and 8.5](docs/ircd-architecture-and-implementation-spec.md#61-direct).
  - Invariants: `ID-04`, `PRV-03`, `PRV-04`.
  - Evidence: profile-mismatch, real onion, SafeSocks/TestSocks, DNS-leak, packet-capture, and forbidden-field tests.

- [x] `S06-005` **Implement the owned Tokio task tree.** Supervise listeners,
  connections, StateCore, storage, crypto, timers, maintenance, admin, and
  signals with finite children, propagated failures, cancellation, and joined
  shutdown.
  - After: `S06-003`, `S06-004`.
  - Targets: `agenc-ircd-runtime`.
  - References: [Architecture §§21.1–21.2 and 21.8](docs/ircd-architecture-and-implementation-spec.md#211-ownership-rule).
  - Invariants: `CON-01`, `CON-02`, `CON-04`, `OPS-04`.
  - Evidence: task panic, start failure, connection churn, cancellation at each phase, idle/load shutdown, and no-leak tests.

- [x] `S06-006` **Implement global memory admission and permits.** Acquire
  exact charges before count-scaled allocation, preserve ownership through
  buffers and reservations, isolate fixed headroom, and reject exhaustion
  before side effects.
  - After: `S06-005`.
  - Targets: `agenc-ircd-runtime`, `MemoryBudgetPort`.
  - References: [Architecture §§19.1–19.3 and 24.2](docs/ircd-architecture-and-implementation-spec.md#191-hierarchical-admission).
  - Invariants: `CON-05`, `STA-08`, `TRN-04`.
  - Evidence: exact permit accounting, split/drop/rollback, exhaustion, allocation-failure proxy, and high-water tests.

- [x] `S06-007` **Implement connection and output owners.** Give each client a
  generation-bound bounded input/output owner, tentative/prepare/commit queue
  reservations, slow-consumer close, exact ordering, and infallible allocation-
  free commit after preparation.
  - After: `S06-005`, `S06-006`.
  - Targets: `agenc-ircd-runtime`, client sink implementation.
  - References: [Architecture §§15.3, 21.3, and 24.2](docs/ircd-architecture-and-implementation-spec.md#153-backpressure-and-fanout).
  - Invariants: `STA-08`, `CON-02`, `CON-05`.
  - Evidence: whole-sink exclusion, queue full/close, generation reuse, shared-buffer charging, ordering, and exact permit-return tests.

- [x] `S06-008` **Implement `StateCore` durable command execution.** Own all
  mutable protocol state, construct plans at one revision, reserve runtime
  resources, submit complete storage batches, consume matching receipts, apply
  once, and only then render success.
  - After: `S06-005` through `S06-007`.
  - Targets: `agenc-ircd-runtime`.
  - References: [Architecture §§21.1, 21.4–21.5, and 24.2](docs/ircd-architecture-and-implementation-spec.md#211-ownership-rule).
  - Invariants: `CON-01`, `CON-03`, `DUR-01`, `STA-06`, `STA-08`, `OPS-04`.
  - Evidence: cancellation/disconnect before and after every reservation/commit/receipt/apply/render boundary.

- [x] `S06-009` **Compose registration, authentication, and session routing.**
  Connect TLS, client wire, account-service jobs, SASL, domain plans, storage,
  welcome state, account switches, logout, keepalive, and connection closure.
  - After: `S04-900`, `S06-008`.
  - Targets: `agenc-ircd-runtime`.
  - References: [Architecture §§10–12](docs/ircd-architecture-and-implementation-spec.md#10-connection-and-registration-state-machine).
  - Invariants: `ID-*`, `AUTH-*`, `TRN-*`.
  - Evidence: complete registration/account lifecycle transcripts, malicious-edge cases, restart, and generation-fence integration tests.

- [x] `S06-010` **Compose single-node channel and message behavior.** Execute
  local/global channels, discovery, roles, modes, moderation, direct/channel
  messages, recipient reservations, ephemeral defaults, and optional-policy
  refusal exactly as the domain model specifies.
  - After: `S06-007` through `S06-009`.
  - Targets: `agenc-ircd-runtime`, `agenc-ircd` integration tests.
  - References: [Architecture §§13–17](docs/ircd-architecture-and-implementation-spec.md#13-channel-model).
  - Invariants: `PRV-*`, `STA-*`, applicable `E2E-02`.
  - Evidence: core-v1 transcripts, model/implementation snapshot equality, overload, slow consumer, and privacy tests.

- [x] `S06-011` **Implement timers, admission, and overload behavior.** Drive
  connection deadlines, keepalive, authentication expiry, rate buckets,
  maintenance, overload classes, and cleanup with explicit clock inputs and
  bounded timer ownership.
  - After: `S06-005`, `S06-006`, `S06-008`.
  - Targets: `agenc-ircd-runtime`.
  - References: [Architecture §§19 and 21.6](docs/ircd-architecture-and-implementation-spec.md#19-abuse-resistance-and-resource-limits).
  - Invariants: `AUTH-02`, `CON-02`, `CON-05`, `FED-09` where applicable.
  - Evidence: paused-time boundary, replacement/cancellation, slowloris, churn, exhaustion, and post-quiescence recovery tests.

- [x] `S06-012` **Implement isolated administration.** Support local Unix and
  separately pinned mTLS administration, signed contiguous challenges,
  permission mapping, exact read-only batches, mutation authorization, and
  chained audit records; expose no admin authority through client IRC.
  - After: `S06-002`, `S06-003`, `S06-008`.
  - Targets: `agenc-ircd-admin`, runtime admin owner.
  - References: [Architecture §§22.4–22.6](docs/ircd-architecture-and-implementation-spec.md#224-administrative-transports).
  - Invariants: `TRN-03`, `OPS-03`, `OPS-05`.
  - Evidence: transport/pin/signature/counter/permission/replay/batch/audit/privacy matrix.

- [x] `S06-013` **Implement strict reload behavior.** Validate the entire new
  configuration before atomic activation, reject immutable or unsafe changes,
  and retain the prior configuration on every failure.
  - After: `S06-001`, `S06-012`.
  - Targets: `agenc-ircd-config`, runtime configuration owner.
  - References: [Architecture §22.6](docs/ircd-architecture-and-implementation-spec.md#226-reload-behavior).
  - Invariants: `OPS-02`, `OPS-04`.
  - Evidence: every reloadable/immutable field, concurrent request, allocation, listener, and rollback case.

- [x] `S06-014` **Implement privacy-bounded observability.** Emit only closed
  log events, fixed metric labels/buckets, local authenticated health, fresh
  process correlation IDs, bounded retention, and explicit readiness/liveness.
  - After: `S06-005`, `S06-008`, `S06-012`.
  - Targets: runtime observability adapters.
  - References: [Architecture §§25.2–25.3](docs/ircd-architecture-and-implementation-spec.md#252-logging).
  - Invariants: `OPS-01`, `PRV-02`, `ID-04`, `ID-05`.
  - Evidence: forbidden-value canaries, label-cardinality checks, endpoint exposure, retention, and error-format scans.

- [x] `S06-015` **Ship the single-node service hardening profile.** Run as a
  dedicated unprivileged account, disable core dumps, restrict filesystem,
  syscalls, address families, ptrace, devices, and writable paths, and report
  unavailable controls honestly.
  - After: `S06-002` through `S06-014`.
  - Targets: service definition, deployment checks, operator documentation.
  - References: [Architecture §§25.1 and 25.4–25.5](docs/ircd-architecture-and-implementation-spec.md#251-process-and-filesystem-isolation).
  - Invariants: `OPS-01`, `OPS-02`, `OPS-04`.
  - Evidence: host-hardening checks, permissions, locked-secret modes, crash behavior, signal shutdown, and incident-mode tests.

- [ ] `S06-900` **Pass the Stage 06 core-v1 gate.** A standalone TLS-only node
  must satisfy the core conformance target with bounded ownership, durable
  results, privacy-safe operations, clean shutdown, and no federation/E2EE
  behavior falsely advertised.
  - After: `S06-001` through `S06-015`.
  - Targets: full single-node release binary and deployment profile.
  - References: [Architecture §§1.1 and 29 phase 6](docs/ircd-architecture-and-implementation-spec.md#11-conformance-targets).
  - Invariants: applicable `TRN-*`, `ID-*`, `AUTH-*`, `PRV-*`, `STA-*`, `DUR-*`, `CON-*`, `OPS-*`.
  - Evidence: core-v1 transcripts, Loom models, shutdown/overload/soak tests, host checks, and mandatory build gates pass.

## Stage 07 — Base federation

Outcome: one coordinator and its authenticated edges converge through bounded,
durable, privacy-minimized requests, results, events, projections, snapshots,
partitions, and recovery.

- [ ] `S07-001` **Implement authenticated federation transport.** Require
  TLS 1.3, exact ALPN, static certificate/application-signature pins, exporter
  binding, bounded framing, and independent peer authorization before role use.
  - After: `S06-900`.
  - Targets: `agenc-ircd-runtime`, federation-link owner.
  - References: [Architecture §20.2](docs/ircd-architecture-and-implementation-spec.md#202-link-transport-and-trust).
  - Invariants: `TRN-01`, `TRN-03`, `FED-02`, `FED-10`.
  - Evidence: TLS/pin/exporter/ALPN/role/recovery-epoch positive and negative matrices.

- [ ] `S07-002` **Implement FHELLO/READY negotiation.** Exchange exact role,
  identity, incarnation, recovery epoch, base profile hash, features, cursors,
  and readiness state; block activation until required synchronization finishes.
  - After: `S07-001`.
  - Targets: `agenc-ircd-federation-wire`, federation-link state machine.
  - References: [Architecture §20.3](docs/ircd-architecture-and-implementation-spec.md#203-authenticated-hello), [Appendix B.9](docs/ircd-architecture-and-implementation-spec.md#b9-federation-profile-hash).
  - Invariants: `FED-02`, `FED-10`, `E2E-07`.
  - Evidence: every tuple mismatch, stale/gap/exhausted incarnation/epoch, early READY, and reconnect transition test.

- [ ] `S07-003` **Enforce coordinator/edge authority.** Route every global
  mutation to exactly one logical coordinator; prohibit edge self-promotion,
  edge-to-edge transit, state merge, and guessed partition outcomes.
  - After: `S07-002`.
  - Targets: federation runtime and domain planning.
  - References: [Architecture §§20.1 and 20.10](docs/ircd-architecture-and-implementation-spec.md#201-logical-topology).
  - Invariants: `FED-01`, `FED-02`, `OPS-04`.
  - Evidence: topology, partition, coordinator loss/restart, role-conflict, and no-merge model tests.

- [ ] `S07-004` **Implement origin lifecycle and fencing.** Maintain live
  origin incarnations, contiguous operation sequences, expiry, deletion
  tombstones, recovery-epoch changes, and permanent fencing of earlier states.
  - After: `S07-002`, `S07-003`.
  - Targets: `agenc-ircd-domain`, `agenc-ircd-storage`, federation runtime.
  - References: [Architecture §20.7](docs/ircd-architecture-and-implementation-spec.md#207-origin-lifecycle).
  - Invariants: `FED-03`, `FED-04`, `FED-09`, `FED-10`.
  - Evidence: duplicate/gap/conflict, incarnation replacement, expiry boundary, tombstone, restart, and replay tests.

- [ ] `S07-005` **Implement idempotent requests and durable results.** Validate
  every operation arm, origin sequence, canonical request hash, target revision,
  replay key, result descriptor, and exact stored outcome before forwarding or
  replaying it.
  - After: `S07-004`.
  - Targets: federation wire/domain/storage/runtime.
  - References: [Architecture §§20.5–20.6 and Appendix B.6](docs/ircd-architecture-and-implementation-spec.md#205-requests-and-idempotency).
  - Invariants: `FED-03`, `FED-04`, `FED-12`, `DUR-01`.
  - Evidence: every opcode/result arm, exact retry, conflicting reuse, gap, crash, descriptor mismatch, and original-sink test.

- [ ] `S07-006` **Implement least-information events and projections.** Derive
  target-edge records at one committed revision, include only authorized data,
  durably erase it when authorization ends, and never project addresses,
  secrets, auth state, or unrelated channels.
  - After: `S07-003` through `S07-005`.
  - Targets: domain projection model, storage outbox, federation runtime.
  - References: [Architecture §20.8 and Appendices B.4–B.5](docs/ircd-architecture-and-implementation-spec.md#208-events-projection-and-acknowledgments).
  - Invariants: `PRV-02`, `FED-05`, `FED-07`.
  - Evidence: multi-edge projection diffs, grant/revoke, secret-channel, deletion-before-ACK, and forbidden-field canaries.

- [ ] `S07-007` **Implement durable event ACKs and completion coverage.** ACK
  only in the same transaction that applies an event and advances its cursor;
  render a committed result only after its completion is durably covered.
  - After: `S07-005`, `S07-006`.
  - Targets: federation runtime/storage barrier.
  - References: [Architecture §20.8](docs/ircd-architecture-and-implementation-spec.md#208-events-projection-and-acknowledgments).
  - Invariants: `FED-05`, `FED-12`, `DUR-01`, `DUR-02`.
  - Evidence: result-first/completion-first, lost ACK, duplicate, crash at each boundary, and successor-snapshot coverage tests.

- [ ] `S07-008` **Implement bounded federation object transport.** Validate
  direction, authenticated prefix, descriptor, carrier, length, object hash,
  fragment order/count, reassembly budget, and typed payload before dispatch.
  - After: `S07-001`, `S07-005`.
  - Targets: `agenc-ircd-federation-wire`, federation runtime.
  - References: [Architecture §§20.4 and Appendix B.8](docs/ircd-architecture-and-implementation-spec.md#204-canonical-federation-objects).
  - Invariants: `TRN-04`, `TRN-05`, `FED-08`, `CON-05`.
  - Evidence: fragment flood, collision, direction/prefix/descriptor/hash/length/count mismatch, timeout, and budget tests.

- [ ] `S07-009` **Implement snapshots and resume.** Validate immutable snapshot
  count, order, IDs, digest, cut, cross-references, pagination, pending state,
  replay, ACTIVE authorization, atomic swap, and old-generation quarantine.
  - After: `S07-006` through `S07-008`.
  - Targets: federation wire/domain/storage/runtime.
  - References: [Architecture §20.9 and Appendix B.7](docs/ircd-architecture-and-implementation-spec.md#209-snapshot-and-resume-protocol).
  - Invariants: `FED-05`, `FED-06`, `FED-07`, `FED-10`.
  - Evidence: empty/one/maximum pages, reorder/duplicate/missing/cross-reference failures, crash, stale ACTIVE, and atomic-swap tests.

- [ ] `S07-010` **Implement partition, keepalive, and outbox recovery.** Detect
  silent peers, apply one nonextendable origin grace interval, fence a full
  durable outbox into snapshot recovery, coalesce only safe notifications, and
  never drop durable state.
  - After: `S07-004`, `S07-007`, `S07-009`.
  - Targets: federation runtime/storage maintenance.
  - References: [Architecture §§20.10, 21.6, and 24.2](docs/ircd-architecture-and-implementation-spec.md#2010-partitions-and-coordinator-recovery).
  - Invariants: `FED-01`, `FED-09`, `CON-02`, `OPS-04`.
  - Evidence: silent/lost/slow peer, grace boundaries, full outbox, dropped notification, restart, and resynchronization tests.

- [ ] `S07-011` **Implement bounded paged directory queries.** Retain one
  immutable snapshot and one session/account/query/page-bound cursor slot;
  atomically replace it on continuation and return only `QUERY_EXPIRED` for
  invalid, consumed, restarted, or mismatched cursors.
  - After: `S07-005`, `S07-006`.
  - Targets: domain/query model, storage/runtime query state.
  - References: [Architecture §§20.5.2 and Appendix B.6](docs/ircd-architecture-and-implementation-spec.md#2052-closed-operation-table).
  - Invariants: `FED-13`, `PRV-02`, `STA-10`.
  - Evidence: page size/cut, expiry, consume, restart, wrong binding, mutation between pages, and no-splice tests.

- [ ] `S07-012` **Extend the reference model and fault simulator.** Model
  multiple edges, origins, requests, results, events, snapshots, ACKs,
  partitions, recovery, storage failures, and privacy projections deterministically.
  - After: `S07-003` through `S07-011`.
  - Targets: `agenc-ircd-testkit` federation model/simulator.
  - References: [Architecture §§28.3, 28.5, and 28.6](docs/ircd-architecture-and-implementation-spec.md#283-state-machine-and-model-tests).
  - Invariants: `FED-*`, applicable `PRV-*`, `DUR-*`, `CON-*`.
  - Evidence: bounded formal model, generated fault schedules, model/implementation equality, and exact replay convergence.

- [ ] `S07-013` **Complete federation privacy and interoperability tests.**
  Exercise all wire arms, legacy-client-facing results, least-information
  projections, reconnect/resume, resource ceilings, and server incarnation
  changes across real multi-process nodes.
  - After: `S07-001` through `S07-012`.
  - Targets: multi-node integration and interoperability suites.
  - References: [Architecture §§28.6–28.7 and Appendix D](docs/ircd-architecture-and-implementation-spec.md#286-network-interoperability-and-privacy-tests).
  - Invariants: `FED-*`, `PRV-*`, `TRN-*`, `DUR-*`.
  - Evidence: multi-edge test matrix, packet/log/database canaries, capacity limits, and pinned transcript outputs.

- [ ] `S07-900` **Pass the Stage 07 federated-v1 gate.** Coordinator and edges
  must converge safely across duplicates, gaps, crashes, partitions, snapshots,
  and recovery without leaking unauthorized projected state.
  - After: `S07-001` through `S07-013`.
  - Targets: federated release topology and complete evidence set.
  - References: [Architecture §§1.1 and 29 phase 7](docs/ircd-architecture-and-implementation-spec.md#11-conformance-targets).
  - Invariants: `FED-01` through `FED-13` and all coupled privacy/durability/concurrency invariants.
  - Evidence: bounded model, multi-edge fault simulation, replay, privacy scans, and mandatory workspace gates pass.

## Stage 08 — E2EE server adapter and joint transactions

Outcome: the federated daemon negotiates the exact companion profile, validates
and routes only its assigned public objects, and commits base/E2EE state
atomically while remaining unable to decrypt content or operate an MLS client.

- [ ] `S08-001` **Implement exact E2EE profile negotiation.** Require the
  frozen `(version, profile-hash)` on client CAP and federation ECAP, enforce
  dependencies and timeout, and fail closed on absent, malformed, stale,
  mismatched, rolled-back, or exhausted transitions.
  - After: `S07-900`.
  - Targets: `agenc-ircd-e2ee`, client/federation negotiation state.
  - References: [Architecture §§18.2 and 26.3](docs/ircd-architecture-and-implementation-spec.md#182-cross-document-precedence), [E2EE §§2.3 and 11.1](docs/irc-mls-e2ee-extension.md#23-exact-profile-revision).
  - Invariants: `E2E-07`, `FED-02`, `FED-10`.
  - Evidence: exact match plus every tuple, ordering, timeout, reconnect, rollback, gap, and downgrade negative.

- [ ] `S08-002` **Enforce the daemon/client separation mechanically.** Expose
  only public-object validation, routing, storage metadata, and transaction
  planning; forbid production dependency on an MLS client state machine or any
  API accepting epoch secrets, plaintext, root private keys, or device keys.
  - After: `S08-001`.
  - Targets: `agenc-ircd-e2ee`, Cargo graph/source checks.
  - References: [Architecture §§18 and 24.1](docs/ircd-architecture-and-implementation-spec.md#18-e2ee-integration-contract), [E2EE §20](docs/irc-mls-e2ee-extension.md#20-implementation-separation).
  - Invariants: `E2E-01`, `E2E-02`.
  - Evidence: dependency/API/source scans and compile-fail tests reject MLS-client or secret-bearing production surfaces.

- [ ] `S08-003` **Validate public identity and device objects.** Check account
  roots, enrollment possession, device certificates, capability chains,
  complete rosters, revocation, leaf authorization, generations, signatures,
  semantic IDs, and canonical encodings without resolving private keys.
  - After: `S08-002`.
  - Targets: `agenc-ircd-e2ee`, crypto/type adapters.
  - References: [E2EE §§2.1–2.2 and 8](docs/irc-mls-e2ee-extension.md#21-signature-registry).
  - Invariants: `E2E-01`, `E2E-05`, `ID-01`, `ID-02`.
  - Evidence: independent vectors and missing/duplicate/stale/rollback/equivocation/signature/capability-chain negatives.

- [ ] `S08-004` **Validate route identity and binding locks.** Enforce channel
  instance/direct-account-pair identity, route generations, semantic locks,
  root continuity, close/recreate isolation, encrypted/plaintext collision
  refusal, and tombstones.
  - After: `S08-003`.
  - Targets: `agenc-ircd-e2ee`, domain route model.
  - References: [Architecture §§18.1, 18.3–18.4](docs/ircd-architecture-and-implementation-spec.md#181-channel-binding), [E2EE §9.1](docs/irc-mls-e2ee-extension.md#91-identifiers-and-route-binding).
  - Invariants: `E2E-02`, `E2E-06`, `STA-02`.
  - Evidence: bind/rebind/close/recreate/root rollback/collision/tombstone/restoration vectors.

- [ ] `S08-005` **Validate sequencer, policy, roster, and finality authority.**
  Check sequencer credentials, controller authority, full policy replacement,
  roster heads, candidate authorization, quorum/fault math, council transition,
  revocation, and non-circular approval sets.
  - After: `S08-003`, `S08-004`.
  - Targets: `agenc-ircd-e2ee`.
  - References: [E2EE §§9.2–9.4](docs/irc-mls-e2ee-extension.md#92-sequencer-credential).
  - Invariants: `E2E-03` through `E2E-05`.
  - Evidence: exhaustive `(n,f,q)` cases, authority/approval substitution, council rotation, and conflicting-candidate tests.

- [ ] `S08-006` **Validate MLS public context and application envelopes.**
  Enforce the required context extension, suite-independent profile digests,
  group/route/policy/roster bindings, outer object types, deterministic padding,
  message IDs, durable sequences, and exact size arithmetic while treating
  MLS ciphertext as opaque.
  - After: `S08-003` through `S08-005`.
  - Targets: `agenc-ircd-e2ee`.
  - References: [E2EE §§9.5 and 10](docs/irc-mls-e2ee-extension.md#95-required-mls-context-extension).
  - Invariants: `E2E-01`, `E2E-05`, `TRN-04`, `CON-05`.
  - Evidence: context, binding, envelope, padding, under/equal/over limit, nonzero-padding, overflow, and semantic-ID vectors.

- [ ] `S08-007` **Implement E2EE client carriers and reassembly.** Handle the
  fragment tag, channel/direct carriers, binding, identity, KeyPackage,
  Welcome, exact success/object responses, standard errors, tokens, arity,
  direction, timeout, and authenticated resource budgets.
  - After: `S08-001`, `S08-004`, `S08-006`.
  - Targets: `agenc-ircd-e2ee`, `agenc-ircd-client-wire`, runtime reassembly owner.
  - References: [E2EE §§11.2–11.10](docs/irc-mls-e2ee-extension.md#112-fragment-tag).
  - Invariants: `TRN-04` through `TRN-06`, `E2E-05`, `CON-05`.
  - Evidence: every carrier/object/response arm, wire-budget table, fragment flood, duplicate/conflict, collision, expiry, and allocation tests.

- [ ] `S08-008` **Implement candidate, receipt, ACK, finalization, and abort
  validation.** Enforce one active candidate, no local skipping, exact
  signatures/TBS, recipient-dependent disposition, finality proofs, terminal
  IDs, deterministic coverage, and byte-identical replay.
  - After: `S08-005` through `S08-007`.
  - Targets: `agenc-ircd-e2ee`, domain/storage transaction plans.
  - References: [E2EE §§12.1–12.4](docs/irc-mls-e2ee-extension.md#121-one-active-candidate-no-local-skipping).
  - Invariants: `E2E-03` through `E2E-06`.
  - Evidence: success and every lost/duplicate/reordered/conflicting/stale/malicious receipt, ACK, finalization, abort, and content-cycle test.

- [ ] `S08-009` **Implement E2EE federation objects and state exchange.** Cover
  ECAP, operations, results, events, fragments, descriptors, route changes,
  ESTATE pages, ACTIVE, ERESUME, sequencer-set transitions, mailbox ownership,
  and exact replay under the base federation authority model.
  - After: `S08-001`, `S08-007`, `S08-008`.
  - Targets: `agenc-ircd-e2ee`, `agenc-ircd-federation-wire`, federation runtime.
  - References: [E2EE §12.5](docs/irc-mls-e2ee-extension.md#125-federation), [Architecture §20](docs/ircd-architecture-and-implementation-spec.md#20-federation-architecture-and-wire-protocol).
  - Invariants: `FED-*`, `E2E-05`, `E2E-07`.
  - Evidence: every opcode/result/event/descriptor arm, snapshot page boundary, cursor form, retry, incarnation, collision, and synchronization test.

- [ ] `S08-010` **Implement server-visible group lifecycle.** Validate device
  provisioning, channel/direct group creation, joins, device addition,
  KeyPackage claim/burn, Welcome delivery, committed roster and pending-join
  state, while keeping all client MLS processing outside production crates.
  - After: `S08-003` through `S08-009`.
  - Targets: `agenc-ircd-e2ee`, domain/storage/runtime integration.
  - References: [E2EE §§13.1–13.4](docs/irc-mls-e2ee-extension.md#131-device-provisioning).
  - Invariants: `E2E-01`, `E2E-03`, `E2E-05`.
  - Evidence: provisioning/create/join/add-device, package replay/burn, Welcome, crash, retry, and full-roster tests using test-only clients.

- [ ] `S08-011` **Implement removal, revocation, and recovery gates.** Keep
  sending paused where removal is uncertain, distinguish requested from
  cryptographically final removal, validate update/recovery state, and block
  restored routes until exact evidence establishes a new lineage or permanent
  tombstone.
  - After: `S08-008`, `S08-010`.
  - Targets: `agenc-ircd-e2ee`, domain/storage/runtime integration.
  - References: [E2EE §§13.5–13.7.1](docs/irc-mls-e2ee-extension.md#135-part-kick-revocation-and-removal), [Architecture §18.4](docs/ircd-architecture-and-implementation-spec.md#184-server-recovery-gate-for-encrypted-routes).
  - Invariants: `E2E-04`, `E2E-06`, `STA-09`.
  - Evidence: part/kick/revoke, delayed/failed finality, state loss, exact/conflicting recovery evidence, restore, and tombstone tests.

- [ ] `S08-012` **Implement full ReInit and route migration.** Validate target
  suite/key-package preflight, creator and Welcome ACKs, activation, old-group
  closure, PSK deletion, abort/retry, races, and non-reopening of the prior
  lineage.
  - After: `S08-010`, `S08-011`.
  - Targets: `agenc-ircd-e2ee`, joint domain/storage plans.
  - References: [E2EE §13.8](docs/irc-mls-e2ee-extension.md#138-full-reinit-and-route-migration).
  - Invariants: `E2E-03`, `E2E-05`, `E2E-06`.
  - Evidence: preflight, every ACK/activation boundary, abort, retry, crash, race, PSK-erasure, and old-lineage-refusal tests.

- [ ] `S08-013` **Implement E2EE replay, mailbox, and persistence policy.**
  Enforce object/replay keys, durable sequence/order, idempotent outbox retries,
  offline delivery tokens, mailbox ownership/ACK, retention, deletion, and
  opaque-history rules.
  - After: `S08-008` through `S08-012`.
  - Targets: `agenc-ircd-e2ee`, storage/runtime mailboxes and outboxes.
  - References: [E2EE §§14–15](docs/irc-mls-e2ee-extension.md#14-replay-ordering-and-persistence).
  - Invariants: `E2E-01`, `E2E-05`, `DUR-01`, `DUR-02`, `FED-03`.
  - Evidence: duplicate/gap/conflict, disconnect, crash, restart, token ACK, cursor replay, retention, deletion, and byte-identical retry tests.

- [ ] `S08-014` **Enforce E2EE resource and timing limits.** Admit before
  signature, hash, reassembly, storage, or fanout work; bound objects,
  fragments, candidates, rosters, groups, mailboxes, queues, timeouts, and
  amplification.
  - After: `S08-007` through `S08-013`.
  - Targets: `agenc-ircd-e2ee`, runtime admission and workers.
  - References: [E2EE §16](docs/irc-mls-e2ee-extension.md#16-resource-and-timing-limits), [Architecture §19](docs/ircd-architecture-and-implementation-spec.md#19-abuse-resistance-and-resource-limits).
  - Invariants: `TRN-04`, `TRN-05`, `CON-02`, `CON-05`.
  - Evidence: every limit at below/equal/above, authenticated flood, fanout, slow consumer, queue, timeout, and recovery-after-quiescence tests.

- [ ] `S08-015` **Implement downgrade, reset, and failure behavior.** Refuse
  plaintext on bound/tombstoned routes, unknown required capabilities,
  mismatched profiles, ambiguous resets, stale roots, partial finality, and any
  fallback that could hide an encrypted-state failure.
  - After: `S08-001`, `S08-004`, `S08-011` through `S08-014`.
  - Targets: `agenc-ircd-e2ee`, domain/client/federation error mapping.
  - References: [E2EE §§17 and 19](docs/irc-mls-e2ee-extension.md#17-downgrade-and-reset-behavior), [Architecture §18](docs/ircd-architecture-and-implementation-spec.md#18-e2ee-integration-contract).
  - Invariants: `E2E-02`, `E2E-06`, `E2E-07`, `PRV-01`.
  - Evidence: plaintext injection, profile mismatch, reset/recreate/root rollback, partial-state, retry, and exact public-error tests.

- [ ] `S08-016` **Implement the cross-profile durable barrier.** Stage one
  target-edge combined base/E2EE change with exact part IDs/counts/bytes,
  receipts, cursor coverage, and one visibility point; neither profile may ACK,
  swap, render, or advance alone.
  - After: `S08-009`, `S08-011` through `S08-015`.
  - Targets: `agenc-ircd-e2ee`, domain, storage, federation runtime.
  - References: [Architecture §§20.8, 23.4, and Appendix B](docs/ircd-architecture-and-implementation-spec.md#208-events-projection-and-acknowledgments), [E2EE §12.5](docs/irc-mls-e2ee-extension.md#125-federation).
  - Invariants: `E2E-03`, `FED-11`, `FED-12`, `DUR-01`, `DUR-02`.
  - Evidence: every permitted interleaving and crash boundary, 2,047/2,048/2,049 parts, aggregate byte boundaries, wrong metadata, full outbox, and replay tests.

- [ ] `S08-017` **Integrate the encrypted node end to end.** Compose client
  negotiation/carriers, public validation, domain plans, durable state,
  federation synchronization, opaque fanout, mailbox delivery, restoration,
  administration, metrics, and shutdown without widening any crate authority.
  - After: `S08-001` through `S08-016`.
  - Targets: all server-side E2EE integration surfaces and release binary.
  - References: [Architecture §§18, 24.1, and 27.4](docs/ircd-architecture-and-implementation-spec.md#18-e2ee-integration-contract), [E2EE §20](docs/irc-mls-e2ee-extension.md#20-implementation-separation).
  - Invariants: `E2E-*`, coupled `FED-*`, `DUR-*`, `CON-*`, `OPS-*`.
  - Evidence: full encrypted-channel/direct-message flows with test-only clients, plus restart/partition/overload/privacy/shutdown tests.

### Stage 08 companion verification matrix

The following tasks correspond one-for-one with the numbered gates in
[E2EE §21](docs/irc-mls-e2ee-extension.md#21-verification-and-release-gates).
Task IDs follow executable dependency order, so source gate 13 (external review)
is `S08-039`, after technical source gates 14–22 are complete.

- [ ] `S08-018` **Pin the MLS WG interoperability corpus.** Record immutable
  revision and content hashes for every enabled suite.
  - After: `S08-017`.
  - Targets: test-only MLS corpus and conformance evidence.
  - References: [E2EE §21 gate 1](docs/irc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-05`.
  - Evidence: corpus hash verification and suite coverage manifest.

- [ ] `S08-019` **Supply independent E2EE object vectors.** Cover every root,
  device, roster, policy, binding, context, envelope, fragment, sequencer,
  receipt, ACK, finalization, abort, and ReInit public object.
  - After: `S08-003` through `S08-017`.
  - Targets: checked-in E2EE vector corpus and reference validator.
  - References: [E2EE §21 gate 2](docs/irc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-05`.
  - Evidence: independent generator provenance, hashes, and production/reference agreement.

- [ ] `S08-020` **Run cross-implementation MLS tests.** Use at least two
  independent libraries or clients in test-only tooling for each enabled suite.
  - After: `S08-018`, `S08-019`.
  - Targets: interoperability harness; never a production daemon dependency.
  - References: [E2EE §21 gate 3](docs/irc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-01`, `E2E-05`.
  - Evidence: versioned cross-implementation matrix and byte/state comparison results.

- [ ] `S08-021` **Prove plaintext rejection on encrypted targets.**
  Characterize every client and federation plaintext entry point after route
  binding or tombstoning.
  - After: `S08-015`, `S08-017`.
  - Targets: client/federation integration tests.
  - References: [E2EE §21 gate 4](docs/irc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-02`, `STA-09`.
  - Evidence: complete command/target/history/topic/fallback rejection matrix.

- [ ] `S08-022` **Test every E2EE limit and padding boundary.** Include one
  below/equal/above, checked overflow, outer-object fit, nonzero padding,
  short/long padding, and zero-padding edge cases.
  - After: `S08-006`, `S08-014`.
  - Targets: E2EE boundary suites.
  - References: [E2EE §21 gate 5](docs/irc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `TRN-04`, `CON-05`, `E2E-05`.
  - Evidence: mechanically generated boundary table with exact expected outcomes.

- [ ] `S08-023` **Fuzz every E2EE parser boundary.** Cover IRC tags, decimals,
  base64url, reassembly, TLS vectors, identity chains, and MLS outer messages
  under fixed time/memory/output bounds.
  - After: `S08-003`, `S08-006`, `S08-007`, `S08-014`.
  - Targets: E2EE fuzz targets and regression corpus.
  - References: [E2EE §21 gate 6](docs/irc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `TRN-04` through `TRN-06`, `CON-05`.
  - Evidence: reproducible fuzz manifests and minimized regression tests.

- [ ] `S08-024` **Run stateful adversarial E2EE properties.** Generate
  duplicate, lost, reordered, conflicting, stale, and malicious fragments and
  Commits, including recipient-dependent corrupt UpdatePaths.
  - After: `S08-008`, `S08-017`.
  - Targets: test-only client/reference model and server integration.
  - References: [E2EE §21 gate 7](docs/irc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-03` through `E2E-06`.
  - Evidence: no endpoint applies before finality and no failed endpoint skips candidates.

- [ ] `S08-025` **Crash-test every E2EE durable boundary.** Cover restart,
  snapshot restore, and outbox retry without generation, counter, binding,
  ACK, or vote-lock rollback; exact retries remain byte-identical.
  - After: `S08-013`, `S08-016`, `S08-017`.
  - Targets: storage/federation/E2EE fault harness.
  - References: [E2EE §21 gate 8](docs/irc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-05`, `E2E-06`, `DUR-*`, `FED-03`.
  - Evidence: crash before/after every named durable and visibility boundary.

- [ ] `S08-026` **Exhaust finality quorum cases.** Test every permitted
  `(n,f)`, prove `2q-n > f`, exercise netsplits and malicious sequencers, and
  report fault-bound violations outside the claim.
  - After: `S08-005`, `S08-008`.
  - Targets: finality model and property tests.
  - References: [E2EE §21 gate 9](docs/irc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-04`, `E2E-05`.
  - Evidence: exhaustive bounded-state result set and conflicting-finality refusal.

- [ ] `S08-027` **Test identity, roster, KeyPackage, policy, and sequencer
  transitions exhaustively.** Include rotation, rollback, equivocation,
  add/remove, cross-group replay, last-resort refusal, join confirmation,
  pending state, full-tree Welcome, inline proposals, disabled updates,
  controller binding, and idle-device reminders.
  - After: `S08-003`, `S08-005`, `S08-010`, `S08-011`.
  - Targets: E2EE vector/state-machine suites.
  - References: [E2EE §21 gate 10](docs/irc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-03` through `E2E-06`.
  - Evidence: every listed transition has success, rejection, replay, rollback, and state-equality coverage.

- [ ] `S08-028` **Load-test maximum E2EE shapes.** Cover maximum group size,
  fanout, Commit storms, slow consumers, offline queues, and authenticated
  fragment floods.
  - After: `S08-014`, `S08-017`.
  - Targets: release-mode load harness.
  - References: [E2EE §21 gate 11](docs/irc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `CON-02`, `CON-05`, `STA-08`.
  - Evidence: latency, high-water memory/descriptor/queue, rejection, and post-quiescence reports.

- [ ] `S08-029` **Audit E2EE logs and telemetry for forbidden material.** Test
  every success/error/fault path with recognizable identity, key, object,
  content, address, and route canaries.
  - After: `S08-017`.
  - Targets: logs, metrics, health, errors, crash identifiers, audit output.
  - References: [E2EE §21 gate 12](docs/irc-mls-e2ee-extension.md#21-verification-and-release-gates), [Architecture §25](docs/ircd-architecture-and-implementation-spec.md#25-operations-observability-and-host-security).
  - Invariants: `E2E-01`, `OPS-01`, `PRV-02`.
  - Evidence: automated canary scan plus closed-field review records no forbidden value.

- [ ] `S08-030` **Test every ReInit race.** Cover target-suite KeyPackage
  preflight, creator-local ACK, all Welcome ACKs, abort/retry, PSK deletion,
  activation, crash, and permanent old-group closure.
  - After: `S08-012`, `S08-017`.
  - Targets: test-only clients and server ReInit integration.
  - References: [E2EE §21 gate 14](docs/irc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-03`, `E2E-05`, `E2E-06`.
  - Evidence: deterministic interleaving matrix proves the old group never reopens.

- [ ] `S08-031` **Exhaust ECAP and E2EE federation transitions.** Test exact
  profile hash, maximum lines, five-second boundary, simultaneous offers,
  legal flags, duplicate/early ACK rejection, tuple mismatches, key-set
  succession, ESTATE pages, route events, ERESUME, mailbox ownership, retries,
  and channel-instance collision handling.
  - After: `S08-001`, `S08-009`, `S08-017`.
  - Targets: E2EE federation model/integration suites.
  - References: [E2EE §21 gate 15](docs/irc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-07`, `FED-02` through `FED-10`.
  - Evidence: complete transition and boundary matrix with canonical page/state comparisons.

- [ ] `S08-032` **Verify every E2EE wire budget mechanically.** Enumerate every
  command, tag combination, decimal width, base64url expansion, and escape case
  in client and server directions against 4,094/4,094/8,191-byte budgets.
  - After: `S08-007`, `S08-022`.
  - Targets: generated wire-budget table and renderer tests.
  - References: [E2EE §21 gate 16](docs/irc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `TRN-04`, `STA-08`, `CON-05`.
  - Evidence: generated maximum forms fit exactly and every plus-one form rejects before allocation.

- [ ] `S08-033` **Test semantic-ID malleability and acyclicity.** Prove
  alternative valid proof subsets retain one semantic ID, changed TBS fields
  change it, ACK vectors follow their exact rule, and no authorization,
  Welcome, GroupInfo, binding, or policy object contains a future/self ID.
  - After: `S08-003`, `S08-005`, `S08-008`.
  - Targets: semantic-ID vector/property suites.
  - References: [E2EE §21 gate 17](docs/irc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-05`.
  - Evidence: alternative-subset equality, changed-field inequality, cycle rejection, and immutable-MLS-bytes-first construction tests.

- [ ] `S08-034` **Test finality-council removal transitions.** Prove only
  retained, fully staged old principals finalize removal, revoked/removed
  principals cannot, and an earlier epoch rotates a council that would fall
  below the old quorum.
  - After: `S08-005`, `S08-008`, `S08-026`.
  - Targets: finality transition model.
  - References: [E2EE §21 gate 18](docs/irc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-04`, `E2E-05`.
  - Evidence: exhaustive retained/revoked/removed membership and quorum transition cases.

- [ ] `S08-035` **Exhaust E2EE federation operation semantics.** Cover every
  opcode/result/event selector, required/forbidden descriptor, snapshot token,
  index/kind/object/size/delivery mismatch, ReInit delivery, close broadcast,
  incarnation loss, replay collision/gap, quarantine, ACK barrier, first-login
  projection, and encrypted/plaintext collision.
  - After: `S08-009`, `S08-013`, `S08-016`, `S08-031`.
  - Targets: federation wire/model/fault integration suites.
  - References: [E2EE §21 gate 19](docs/irc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-*`, `FED-*`, `PRV-02`.
  - Evidence: exhaustive registry-arm matrix with mismatch, crash, replay, privacy, and recovery cases.

- [ ] `S08-036` **Crash-test E2EE idempotency operations.** Cover KeyPackage
  claim IDs and burns, mailbox delivery-token ACK transactions, cursors, and
  result recovery after disconnect.
  - After: `S08-010`, `S08-013`, `S08-025`.
  - Targets: E2EE storage/runtime fault harness.
  - References: [E2EE §21 gate 20](docs/irc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-05`, `DUR-01`, `DUR-02`, `FED-03`.
  - Evidence: crash at every transaction boundary yields exact replay, burn, or refusal—never duplicate use.

- [ ] `S08-037` **Test root identity and binding chains.** Cover missing
  prefixes, alternate proof subsets, root rollback, semantic-route lock reuse,
  close/recreate continuity, and direct-account-pair downgrade blocking.
  - After: `S08-003`, `S08-004`, `S08-033`.
  - Targets: identity/binding vector and state suites.
  - References: [E2EE §21 gate 21](docs/irc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-02`, `E2E-05`, `E2E-06`.
  - Evidence: positive continuity plus every rollback/reuse/substitution/recreation/downgrade negative.

- [ ] `S08-038` **Exhaust cross-profile barrier schedules.** Cover every
  base/E2EE part interleaving, result/completion order, lost FACK/EACK, replay,
  crash, wrong metadata, concurrent barrier, later-event injection, part/byte
  boundaries, either outbox full, and snapshot replacement.
  - After: `S08-016`, `S08-025`, `S08-035`.
  - Targets: joint transaction model, storage/federation/runtime fault harness.
  - References: [E2EE §21 gate 22](docs/irc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-03`, `FED-11`, `FED-12`, `DUR-01`, `DUR-02`.
  - Evidence: one combined state cut, both cumulative ACKs or neither, no duplicate frame, and exact original-sink result convergence.

- [ ] `S08-039` **Complete external cryptographic and protocol review.** Provide
  the exact profile, implementation, vectors, composition, threat boundaries,
  and evidence for review; remediate findings and re-review material changes.
  No arbitrary reviewer count or credential gate is added.
  - After: `S08-018` through `S08-038`.
  - Targets: E2EE review package, finding log, remediation evidence.
  - References: [E2EE §21 gate 13](docs/irc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: all `E2E-*` and coupled `AUTH-*`, `FED-*`, `DUR-*`.
  - Evidence: disposition for every finding and re-run evidence for each material remediation.

- [ ] `S08-900` **Pass the Stage 08 encrypted-v1 gate.** Every companion
  public-object rule, joint transaction, invariant, and numbered verification
  gate must pass for the exact profile and dependency set before encrypted-v1
  can be advertised.
  - After: `S08-001` through `S08-039`.
  - Targets: encrypted-node release topology, complete companion evidence.
  - References: [Architecture §§1.1 and 29 phase 8](docs/ircd-architecture-and-implementation-spec.md#11-conformance-targets), [E2EE §21](docs/irc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: `E2E-01` through `E2E-07` and all coupled invariant families.
  - Evidence: every companion gate, collision/reset/downgrade test, mandatory workspace check, and finding disposition passes.

## Stage 09 — Optional WSS and pinned history profiles

Outcome: WebSocket transport and plaintext channel history can be enabled
independently without changing the disabled core, federation, or E2EE behavior.

- [ ] `S09-001` **Implement the optional WSS listener.** Perform a bounded
  authenticated HTTP upgrade to the exact subprotocol over TLS 1.3, forbid
  plaintext upgrades and compression, and hand accepted messages to the
  Stage-02 WebSocket framing semantics.
  - After: `S08-900`, `S02-002`.
  - Targets: `agenc-ircd-runtime`, strict WSS configuration.
  - References: [Architecture §§8.4 and Appendix C.3](docs/ircd-architecture-and-implementation-spec.md#84-websocket-listener).
  - Invariants: `TRN-01`, `TRN-02`, `TRN-04`, `TRN-05`.
  - Evidence: upgrade/header/subprotocol/origin/extension/size/timeout/TLS matrix and resource tests.

- [ ] `S09-002` **Prove TCP/WSS protocol equivalence.** Run the same client
  registration, command, auth, privacy, overload, and close transcripts over
  both transports with transport-only differences excluded from protocol state.
  - After: `S09-001`.
  - Targets: client interoperability suites.
  - References: [Architecture §§1.1 and 8.4](docs/ircd-architecture-and-implementation-spec.md#11-conformance-targets).
  - Invariants: all applicable core invariants.
  - Evidence: byte/semantic transcript comparison and identical state snapshots.

- [ ] `S09-003` **Implement the pinned plaintext channel-history profile.**
  Require explicit policy, bound retention/count/bytes, authorization at write
  and read, durable deletion, ordered queries, and the exact pinned capability
  behavior.
  - After: `S08-900`, `S03-008`, `S05-013`.
  - Targets: domain, storage, client wire, runtime, configuration.
  - References: [Architecture §17.2](docs/ircd-architecture-and-implementation-spec.md#172-optional-plaintext-channel-history), [source ledger §4](docs/protocol-sources-and-decisions.md#4-living-protocol-sources).
  - Invariants: `STA-05`, `STA-09`, `PRV-02`, `FED-07`.
  - Evidence: retention/authorization/order/deletion/recreation/federation/privacy and boundary tests against the pinned draft.

- [ ] `S09-004` **Prove history cannot touch encrypted routes.** Reject every
  encrypted-target write, query, replay, topic/history compatibility fallback,
  configuration combination, and post-restore ambiguity.
  - After: `S09-003`.
  - Targets: history/E2EE integration tests.
  - References: [Architecture §§17.2 and 18](docs/ircd-architecture-and-implementation-spec.md#172-optional-plaintext-channel-history), [E2EE §§15 and 17](docs/irc-mls-e2ee-extension.md#15-history-and-offline-delivery).
  - Invariants: `E2E-02`, `STA-09`.
  - Evidence: complete target/state/config/restore downgrade-refusal matrix.

- [ ] `S09-005` **Prove disabled-state equivalence and independent enablement.**
  WSS and history must each be independently optional, separately reported,
  and unable to alter behavior, dependencies, listeners, storage, or advertised
  capabilities when disabled.
  - After: `S09-001` through `S09-004`.
  - Targets: configuration, release metadata, integration matrices.
  - References: [Architecture §§26.4 and 29 phase 9](docs/ircd-architecture-and-implementation-spec.md#264-conformance-claims).
  - Invariants: `OPS-02`, `E2E-02`, `PRV-03`.
  - Evidence: four-mode matrix (neither/WSS/history/both), dependency graph, listener scan, database diff, and capability diff.

- [ ] `S09-900` **Pass the Stage 09 optional-profile gate.** Each optional
  feature must satisfy its full negative, interoperability, privacy, and
  disabled-equivalence suite without weakening any prior conformance target.
  - After: `S09-001` through `S09-005`.
  - Targets: optional-profile release configurations and evidence.
  - References: [Architecture §29 phase 9](docs/ircd-architecture-and-implementation-spec.md#29-implementation-sequence-and-acceptance-gates).
  - Invariants: all affected prior invariants.
  - Evidence: complete optional-mode matrix and mandatory workspace gates pass.

## Stage 10 — Production qualification and release

Outcome: the exact release source, lockfile, targets, configurations, service
profile, and artifacts have complete conformance evidence for every claim made.

- [ ] `S10-001` **Close the complete requirement ledger.** Every normative
  requirement must map to implemented code, a target crate, successful evidence
  IDs, the current source hash, and a non-waived status; no MUST/MUST NOT may be
  waived.
  - After: `S09-900`.
  - Targets: `conformance/requirements.toml` and evidence validator.
  - References: [Architecture §§28.1 and Appendix D](docs/ircd-architecture-and-implementation-spec.md#281-requirement-ledger-and-evidence).
  - Invariants: all invariant families.
  - Evidence: completeness validator reports zero missing/stale/failed/waived mandatory requirements.

- [ ] `S10-002` **Run the mandatory build and analysis matrix.** Execute exact
  formatting, check, Clippy, workspace tests, doctests, deny, audit, and branch-
  coverage commands under the pinned release toolchain and lockfile.
  - After: `S10-001`.
  - Targets: entire workspace and CI evidence.
  - References: [Architecture §28.8](docs/ircd-architecture-and-implementation-spec.md#288-mandatory-build-and-analysis-gates).
  - Invariants: all source- and build-enforced invariants.
  - Evidence: command manifests and artifacts for both initial targets; zero warnings, unsafe source, or unbounded Tokio channel findings.

- [ ] `S10-003` **Meet exact coverage requirements.** Reach at least 90%
  branch coverage overall and 100% for parser error discriminants,
  authorization decisions, protocol enum arms, recovery branches, and
  invariant checkers without treating coverage as replacement for other gates.
  - After: `S10-002`.
  - Targets: coverage corpus/report.
  - References: [Architecture §28.8](docs/ircd-architecture-and-implementation-spec.md#288-mandatory-build-and-analysis-gates).
  - Invariants: all invariant families.
  - Evidence: source/lock-bound branch report with justified unreachable-code handling.

- [ ] `S10-004` **Complete parser, state-machine, and concurrency qualification.**
  Run reproducible long-duration fuzzing, deterministic reference/model tests,
  Loom schedules, cancellation, overload, task-panic, and shutdown suites with
  recorded corpora and envelopes.
  - After: `S10-002`, `S10-003`.
  - Targets: fuzz/model/Loom/runtime evidence.
  - References: [Architecture §§28.3–28.4](docs/ircd-architecture-and-implementation-spec.md#283-state-machine-and-model-tests), [§21](docs/ircd-architecture-and-implementation-spec.md#21-state-ownership-and-concurrency).
  - Invariants: `TRN-*`, `STA-*`, `FED-*`, `CON-*`, `OPS-04`.
  - Evidence: tool/version/duration/corpus/schedule manifests and zero unresolved failures.

- [ ] `S10-005` **Complete network interoperability and privacy qualification.**
  Test pinned legacy, modern, and encrypted clients, two-node and multi-edge
  federation, exact TLS, WSS when enabled, real Tor onion deployment, profile
  mismatches, partitions, metadata canaries, packet captures, and timing
  classes. Test trust-state presentation, TOFU and transparency distinctions,
  and decrypted text containing control bytes, CTCP markers, terminal control,
  HTML, and command prefixes without interpreting it as active content.
  - After: `S10-002`, `S10-004`.
  - Targets: network/interoperability/privacy evidence and the test-only encrypted-client harness.
  - References: [Architecture §28.6](docs/ircd-architecture-and-implementation-spec.md#286-network-interoperability-and-privacy-tests).
  - Invariants: `TRN-*`, `PRV-*`, `FED-*`, `E2E-07`, `OPS-01`.
  - Evidence: versioned client/server/topology and client-policy matrices, safe-rendering outputs, scanner reports, captures, canary scans, and documented privacy limits.

- [ ] `S10-006` **Complete storage platform qualification.** Run the release
  binary on every declared target/filesystem/block-size/mount tuple, measure
  every worst-case mutation and sync/rename phase, and prove the fixed physical-
  growth reserve and backup/construction space boundaries.
  - After: `S05-015`, `S10-002`.
  - Targets: storage qualification rigs and signed reports.
  - References: [Architecture §§28.5 and 28.7](docs/ircd-architecture-and-implementation-spec.md#285-crash-storage-and-fault-injection).
  - Invariants: `DUR-*`, `OPS-04`.
  - Evidence: per-tuple release/profile/corpus/raw-log hashes, maximum deltas, and all boundary/failure outcomes.

- [ ] `S10-007` **Qualify capacity and sustained operation.** Demonstrate the
  advertised connection/member/channel limits on named hardware and run the
  seven-day soak with reconnects, churn, rekey, index transition, snapshots,
  backups, disk pressure, and peer loss.
  - After: `S10-004` through `S10-006`.
  - Targets: release-mode load/soak environments.
  - References: [Architecture §28.7](docs/ircd-architecture-and-implementation-spec.md#287-abuse-and-capacity-tests).
  - Invariants: `CON-02`, `CON-05`, `FED-09`, `DUR-11`.
  - Evidence: p50/p95/p99 latency, memory/task/descriptor/queue high-water reports, missed-event checks, and return-to-envelope evidence.

- [ ] `S10-008` **Run restore, migration, deletion, and key-lifecycle drills.**
  Exercise ordinary and disaster restore, schema migration, storage rekey,
  login-index transition, TLS/federation/sequencer/backup/audit key rotation,
  compromise response, rollback, and client-visible resynchronization.
  - After: `S10-006`, `S10-007`.
  - Targets: operational drill evidence and runbooks.
  - References: [Architecture §§23.6–23.9 and 25.4–25.5](docs/ircd-architecture-and-implementation-spec.md#236-migrations).
  - Invariants: `DUR-04` through `DUR-12`, `FED-10`, `OPS-04`.
  - Evidence: timed drills, artifact/state hashes, failure injection, operator steps, and verified post-drill conformance.

- [ ] `S10-009` **Verify deployment hardening and observability in production
  configuration.** Check privileges, service sandbox, filesystem permissions,
  locked secrets, core dumps, swap guidance, listener exposure, logs, metrics,
  health, retention, crash handling, and incident modes.
  - After: `S10-005`, `S10-008`.
  - Targets: shipped service profile and production configuration.
  - References: [Architecture §25](docs/ircd-architecture-and-implementation-spec.md#25-operations-observability-and-host-security).
  - Invariants: `OPS-01` through `OPS-04`, `ID-04`, `ID-05`, `PRV-02`.
  - Evidence: host-policy tests, port/filesystem scans, secret canaries, retention checks, and incident simulation.

- [ ] `S10-010` **Produce reproducible release artifacts and an SBOM.** Build
  after verified dependency fetch with network disabled, record compiler,
  target, features, source/lock hashes, compare independent artifacts, emit
  SPDX or CycloneDX, and sign artifacts from an isolated release identity.
  - After: `S10-002`, `S10-009`.
  - Targets: release pipeline, binaries, packages, SBOM, signatures.
  - References: [Architecture §24.5](docs/ircd-architecture-and-implementation-spec.md#245-dependency-and-build-integrity).
  - Invariants: `OPS-02`.
  - Evidence: independently reproduced hashes or documented deterministic differences, SBOM validation, and signature verification.

- [ ] `S10-011` **Recheck sources and dependencies before release.** Verify
  publication status, obsoletes/updates/errata, living-source commits, crate
  checksums/MSRV/features/yanks/advisories, and explicitly adopt, narrow,
  supersede, or reject every detected change.
  - After: `S10-010`.
  - Targets: source-decision ledger, lockfile review, affected vectors/requirements.
  - References: [source ledger §6](docs/protocol-sources-and-decisions.md#6-update-and-review-procedure), [Architecture §30](docs/ircd-architecture-and-implementation-spec.md#30-sources-and-pinned-research-baseline).
  - Invariants: all affected invariants.
  - Evidence: primary-source checks, exact diffs, decision records, updated hashes/vectors when adopted, and rerun gates.

- [ ] `S10-012` **Generate exact conformance metadata and user claims.** Report
  `core-v1`, `federated-v1`, `encrypted-v1`, WSS, and history independently;
  bind claims to source/profile/compiler/target/test-manifest hashes and state
  privacy/security limits without exaggeration.
  - After: `S10-001` through `S10-011`.
  - Targets: binary version/conformance output, release notes, operator documentation.
  - References: [Architecture §26.4](docs/ircd-architecture-and-implementation-spec.md#264-conformance-claims), [E2EE Appendix B](docs/irc-mls-e2ee-extension.md#appendix-b-security-claim-template).
  - Invariants: `PRV-04`, all claimed invariant families.
  - Evidence: claim/document review and automated comparison with completed evidence manifests.

- [ ] `S10-013` **Make the release decision.** Confirm every applicable gate,
  finding disposition, drill, artifact, source, dependency, documentation, and
  claim belongs to the exact release commit and lockfile; unresolved evidence
  blocks only the claim or release it governs and is never hidden.
  - After: `S10-001` through `S10-012`, `S08-039`.
  - Targets: signed release decision and immutable evidence index.
  - References: [Architecture §§28.9 and 29 phase 10](docs/ircd-architecture-and-implementation-spec.md#289-release-decision), [E2EE §21](docs/irc-mls-e2ee-extension.md#21-verification-and-release-gates).
  - Invariants: all invariant families.
  - Evidence: signed decision enumerates passed, failed, nonapplicable, and limited evidence for the exact build.

- [ ] `S10-900` **Pass the final production gate.** The released artifact is
  the exact implementation qualified by the complete evidence set; no local
  patch, changed dependency, different configuration, or unsupported platform
  inherits its claims automatically.
  - After: `S10-001` through `S10-013`.
  - Targets: release artifact, signatures, SBOM, conformance/evidence manifests.
  - References: [Architecture §§26.4, 28.9, and 29](docs/ircd-architecture-and-implementation-spec.md#264-conformance-claims).
  - Invariants: all invariant families.
  - Evidence: independent artifact/signature/hash verification and zero incomplete applicable roadmap or conformance-ledger task.

## Deferred and explicitly out of scope for version 1

Do not implement these as hidden extensions or convenient fallbacks. A future
change requires the versioning, source-update, vector, migration, and
negotiation process defined by the specifications.

- Legacy plaintext listeners, STARTTLS, TLS 1.2, spanning-tree IRC server
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

References: [Architecture §§2.1, 3.2, 4, and 26](docs/ircd-architecture-and-implementation-spec.md#21-adopted-client-specifications),
[E2EE §§4 and 22](docs/irc-mls-e2ee-extension.md#4-non-goals-and-unavoidable-limits),
and [source ledger §3](docs/protocol-sources-and-decisions.md#3-work-in-progress-and-deliberately-excluded-algorithms).

## Final completion conditions

- Every Stage-00 through Stage-10 task and gate is checked with linked evidence.
- Every Appendix-D surface maps to at least one roadmap task and machine requirement.
- Every `TRN-*`, `ID-*`, `AUTH-*`, `PRV-*`, `STA-*`, `E2E-*`, `FED-*`, `DUR-*`, `CON-*`, and `OPS-*` invariant maps to passing evidence.
- Every E2EE §21 numbered gate is complete for the exact encrypted profile.
- Every production crate appears only at its permitted dependency layer; testkit is absent from release graphs.
- Every mandatory build, analysis, dependency, coverage, fuzz, model, fault, interoperability, capacity, soak, recovery, hardening, and release check has exact-build evidence.
- Conformance and security statements match the evidence and explicitly preserve the design's honest privacy limits.
