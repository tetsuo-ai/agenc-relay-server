<p align="center">
  <img src="assets/agenc-ircd-ansi.png" alt="agenc ircd rendered as late-1990s ANSI terminal art">
</p>

<p align="center">
  <strong>Familiar chat. Modern trust boundaries.</strong><br>
  A security-first federated chat daemon being built from scratch in safe Rust.
</p>

<p align="center">
  <a href="https://github.com/tetsuo-ai/agenc-ircd/actions/workflows/ci.yml"><img alt="Stage checks" src="https://img.shields.io/github/actions/workflow/status/tetsuo-ai/agenc-ircd/ci.yml?branch=main&style=flat-square&label=checks"></a>
  <img alt="Status: pre-alpha" src="https://img.shields.io/badge/status-pre--alpha-ff2bd6?style=flat-square">
  <img alt="Rust 1.98" src="https://img.shields.io/badge/Rust-1.98.0-00d9e9?style=flat-square&logo=rust&logoColor=white">
  <img alt="Unsafe Rust forbidden" src="https://img.shields.io/badge/unsafe-forbidden-5234ff?style=flat-square">
</p>

> [!IMPORTANT]
> **This is pre-alpha infrastructure, not a deployable server.** Stages 00
> through 03 are implemented and pass their local gates. The binary stays
> unavailable until the runtime stage is implemented.

## What is being built

The version-1 design keeps nicknames, direct messages, `/join #channel`, topics,
modes, invites, bans, kicks, and public or secret channels while replacing
inherited security assumptions.

| Boundary | Version-1 design |
| --- | --- |
| Transport | TLS 1.3 only; no plaintext listener or STARTTLS downgrade |
| Identity | Pseudonymous accounts separated from nicknames, masks, and network addresses |
| Privacy | Data minimization, no raw-IP logging, direct TLS and Tor onion profiles |
| E2EE | Standard RFC 9420 MLS; servers route opaque ciphertext and never receive epoch secrets |
| Federation | Authenticated coordinator/edge protocol with deterministic recovery semantics |
| Implementation | Safe Rust, bounded queues and parsers, typed state, pinned dependencies, explicit evidence gates |

The project does not invent cryptographic primitives. It defines strict
profiles around maintained implementations of TLS 1.3, OPAQUE, HPKE, MLS,
Ed25519, and authenticated storage.

## Current signal

| Stage | State | Outcome |
| --- | --- | --- |
| 00 | complete | Reproducible workspace, source baseline, policy, and traceability |
| 01 | complete | 53 registry constants, validated types, 128 canonical object codecs, and independent vectors |
| 02 | complete | Incremental framing, client parsing, capability and registration state, bounded rendering, transcripts, and fuzz targets |
| 03 | complete | Pure accounts, sessions, channels, authorization, privacy projections, plans, explicit external inputs, and an independent reference model |
| 04-10 | planned | Cryptographic adapters through production qualification |

The complete dependency-ordered roadmap lives in [TODO.md](TODO.md). The Stage
03 command inherits both declared Linux target checks, dependency and advisory
checks, Clippy with warnings denied, all workspace tests, coverage, and the
Stage 02 deterministic fuzz targets. It adds the pure-domain checks, generated
state-machine cases, privacy tests, and production/reference comparisons. See
the [Stage 03 development record](conformance/stage-three-evidence.md) and the
[latest CI runs](https://github.com/tetsuo-ai/agenc-ircd/actions).

## Trust shape

```text
 client device
      │  TLS 1.3 or TLS 1.3 inside a Tor onion stream
      ▼
 edge / standalone node ═══ authenticated federation ═══ coordinator
      │                                                        │
      └──────── MLS objects remain opaque to every server ─────┘
```

Tor improves network-location privacy; it does not defeat global timing or
volume correlation. MLS protects encrypted conversation content and group
state; it does not conceal every delivery relationship. The normative
[threat model](docs/ircd-architecture-and-implementation-spec.md#5-threat-and-trust-model)
states the exact guarantees and limits.

## Build and verify

The pinned toolchain is Rust 1.98.0. From a clean checkout:

```sh
git clone https://github.com/tetsuo-ai/agenc-ircd.git
cd agenc-ircd
bash scripts/check-stage-three.sh
```

There is no server start command yet. The binary fails closed until its runtime
stage is implemented.

## Find your way around

| Path | Purpose |
| --- | --- |
| [Architecture specification](docs/ircd-architecture-and-implementation-spec.md) | Base behavior, state ownership, federation, storage, concurrency, security, and release requirements |
| [E2EE companion](docs/irc-mls-e2ee-extension.md) | MLS identity, objects, ordering, downgrade resistance, and encrypted routes |
| [Protocol decision ledger](docs/protocol-sources-and-decisions.md) | Adopted, narrowed, superseded, and pinned standards |
| [`crates/`](crates) | Thirteen-crate Rust workspace with enforced dependency boundaries |
| [`conformance/`](conformance) | Requirement ledger, evidence catalog, gates, and source policy |
| [`test-data/`](test-data) | Deterministic vectors, transcripts, fuzz seeds, and planned fault, model, capacity, and interoperability fixtures |

## Participate

Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing code or specification
changes. Security findings belong in the private process described by
[SECURITY.md](SECURITY.md), never in a public issue.

No software license has been selected yet. Until a `LICENSE` file is added,
this repository is not offered under an open-source license.
