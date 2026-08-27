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
> through 04 are implemented. Stage 04 adds cryptographic adapters and private
> account-authentication state machines, but no sockets, storage owner, or
> daemon executor. The binary intentionally exits unsuccessfully until Stage
> 06 composes the runtime.

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
| 00 | implemented; closure reopened | Reproducible workspace, source baseline, policy, and traceability |
| 01 | implemented; closure reopened | 53 registry constants, validated types, 128 canonical object codecs, and independent vectors |
| 02 | implemented; closure reopened | Incremental framing, client parsing, capability and registration state, bounded rendering, transcripts, and fuzz targets |
| 03 | implemented; closure reopened | Pure accounts, sessions, channels, authorization, privacy projections, plans, explicit external inputs, and an independent reference model |
| 04 | implementation complete; closure open | Secret-safe crypto adapters, fixed HPKE and OPAQUE profiles, account authentication, destructive-account proofs, bounded workers, and fuzz coverage |
| 05-10 | planned | Persistence, runtime composition, federation, E2EE routing, optional profiles, and production qualification |

The current highest implemented layer is account authentication.
`agenc-ircd-crypto` owns strict library-backed adapters and bounded blocking
workers. `agenc-ircd-auth` owns the fixed private account-service envelope,
OPAQUE registration and login, authenticated completion receipts, credential
replacement, and account-deletion proof. The domain crate applies the resulting
revision and session-generation fences without doing I/O.

Stage 05 is next. The complete dependency-ordered roadmap lives in
[TODO.md](TODO.md). See the
[Stage 04 evidence record](conformance/stage-four-evidence.md) and the
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

## Verify the current stage

The repository pins Rust 1.98.0 and a separate nightly toolchain for fuzz
targets. Install the exact policy and evidence tool versions listed in the
[CI workflow](.github/workflows/ci.yml), then run the implementation checks
from a clean checkout:

```sh
git clone https://github.com/tetsuo-ai/agenc-ircd.git
cd agenc-ircd
bash scripts/check-stage-four.sh
```

The Stage 04 implementation checks inherit both declared Linux target checks,
dependency and advisory checks, Clippy with warnings denied, workspace tests,
documentation tests, branch coverage, the client-wire fuzz targets, and the
Stage 03 checks. They add exact crypto-profile and lockfile checks, public auth
and crypto tests, domain session-fence tests, and account-envelope fuzzing. The
reviewed command list is in [conformance/gates.toml](conformance/gates.toml).

The reviewed `opaque-ke` patch is vendored, hashed, and checked by workspace
policy. The implementation commands do not close a stage. `S00-900` through
`S04-900` remain open until the inherited checks pass on exact source commits
and the required artifact-backed evidence records are present.

There is no server start command yet. The binary fails closed until its runtime
is composed in Stage 06.

## Find your way around

| Path | Purpose |
| --- | --- |
| [Architecture specification](docs/ircd-architecture-and-implementation-spec.md) | Base behavior, state ownership, federation, storage, concurrency, security, and release requirements |
| [E2EE companion](docs/irc-mls-e2ee-extension.md) | MLS identity, objects, ordering, downgrade resistance, and encrypted routes |
| [Protocol decision ledger](docs/protocol-sources-and-decisions.md) | Adopted, narrowed, superseded, and pinned standards |
| [`crates/`](crates) | Thirteen-crate Rust workspace with enforced dependency boundaries |
| [`agenc-ircd-domain`](crates/agenc-ircd-domain) | Pure Stage 03 state, command, decision, event, and projection model |
| [`agenc-ircd-crypto`](crates/agenc-ircd-crypto) | Stage 04 secret, entropy, hash, AEAD, signature, HPKE, and bounded-worker adapters |
| [`agenc-ircd-auth`](crates/agenc-ircd-auth) | Stage 04 account-service wire, OPAQUE, creation, login, credential, and deletion state machines |
| [`agenc-ircd-testkit`](crates/agenc-ircd-testkit) | Independent models, deterministic inputs, fixtures, and transcript support |
| [`conformance/`](conformance) | Requirement ledger, evidence catalog, gates, and source policy |
| [`test-data/`](test-data) | Deterministic vectors, transcripts, generated property cases, fuzz seeds, and reserved later-stage fixtures |

## Participate

Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing code or specification
changes. Security findings belong in the private process described by
[SECURITY.md](SECURITY.md), never in a public issue.

No software license has been selected yet. Until a `LICENSE` file is added,
this repository is not offered under an open-source license.
