# Repository Guidelines

## Project Structure & Module Organization

`docs/` holds the normative architecture, E2EE extension, federation registry, decision ledger, and integrity manifest. `rfcs/` contains pinned upstream RFC text; preserve these files byte-for-byte. `crates/` contains the 13-crate Section-24 workspace. Stages 00 through 08 are complete. Stage 05 includes sealed records, one storage owner, rollback controls, bounded checkpoints, complete startup reconstruction, signed backup and stopped-daemon restore, rekey construction, login-index transition, and native filesystem qualification. Stage 06 adds strict configuration, initialization, TLS endpoints, transport-profile isolation, the StateCore owner, registration and accounts, channels and messaging, isolated administration, atomic reload, observability, and hardened shutdown. Stage 07 adds base federation: authenticated links, origins, idempotent requests, projections and events, snapshots, partitions, paged queries, and the coordinator and edge roles of the daemon. Stage 08 adds the E2EE server adapter: exact profile negotiation, public object validation, the sequencer with its published-policy quorum guard, KeyPackage and mailbox delivery, route projection with an edge record-chain witness, the cross-profile durable barrier, the coordinator reload, and a lifecycle driven by openmls and mls-rs through the daemon, with the external review task still open. Crates assigned to later stages expose no behavior yet. `conformance/` owns requirement and evidence catalogs, while `test-data/` owns public deterministic fixtures.

Rust implementation must follow Section 24 of `docs/ircd-architecture-and-implementation-spec.md`. Keep the declared `agenc-ircd-*` crate boundaries intact: types and wire codecs remain independent of runtime, storage, and policy; the `agenc-ircd` binary performs composition only. Put crate integration tests in `crates/<crate>/tests/` and shared deterministic fixtures in `agenc-ircd-testkit`.

## Build, Test, and Development Commands

- `bash scripts/check-stage-seven.sh`: run the current Stage 07 implementation checks, including every inherited Stage 00 through Stage 06 check plus the federation profile, transcript catalog, bounded model, three-process daemon test, and federation fuzz targets.
- `bash scripts/check-stage-eight.sh`: run the current Stage 08 implementation checks, including every inherited Stage 00 through Stage 07 check plus the encrypted profile, transcript catalog, bounded route model, MLS corpus, cross-implementation harness, three-process encrypted test, load harness, and E2EE fuzz targets.
- `python3 scripts/requirements.py check`: prove the generated ledger covers the frozen normative sources.
- `python3 scripts/check-source.py check`: reject unsafe, panic-prone, unbounded-channel, and unreviewed code shapes.
- `cargo fmt --all --check`: verify Rust formatting.
- `cargo check --workspace --all-targets --all-features --locked`: compile every supported target surface.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`: enforce the lint policy.
- `cargo test --workspace --all-features --locked`: run unit and integration tests.
- `cargo deny check` and `cargo audit --deny warnings`: check dependencies and advisories.

The `agenc-ircd` binary serves one node through `serve`, prepares one through `init`, `check-config`, and `print-onboarding`, and keeps the stopped-daemon `storage restore` maintenance command; every command fails closed on a configuration, secret, or host-control problem. Implementation checks do not close a stage by themselves. Schema version 2 manifests and artifacts close Stages 00 through 04 for exact source commit `1e5b738468f88b238061cc6e84b732176f5cae65`. The [Stage 05 manifest](conformance/evidence/stage-05-bd7518fe7f5c7420debdbaa958aa444ecb5c80c9.json) closes exact source commit `bd7518fe7f5c7420debdbaa958aa444ecb5c80c9`. The schema version 1 evidence for commit `8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb` remains archive-only. The [Stage 06 manifest](conformance/evidence/stage-06-65cce9d66f7bcfb0c0830a2ab1d42b52bff82942.json) closes exact source commit `65cce9d66f7bcfb0c0830a2ab1d42b52bff82942`. The [Stage 07 manifest](conformance/evidence/stage-07-1093d88d0057c3461a423285e0f86ff3775c1140.json) closes exact source commit `1093d88d0057c3461a423285e0f86ff3775c1140`. The [Stage 08 manifest](conformance/evidence/stage-08-a6e3c54a6a4e4d95436cb43197e66a521ee21315.json) closes exact source commit `a6e3c54a6a4e4d95436cb43197e66a521ee21315`; Stage 09 is the next implementation stage.

## Coding Style & Naming Conventions

Use stable Rust, rustfmt defaults, and four-space indentation. Crates and modules use `snake_case`, types and traits use `UpperCamelCase`, and constants use `SCREAMING_SNAKE_CASE`. Every workspace crate must declare `#![forbid(unsafe_code)]`. Prefer private-field validated types, typed errors, checked arithmetic, named protocol limits, guard clauses, focused functions, and explicit ownership. Never use unbounded channels, hold locks across `.await`, log secrets, or implement cryptographic primitives locally.

## Testing Guidelines

Add golden-vector, round-trip, negative, property, transcript, and fuzz tests at relevant trust boundaries. Name tests by behavior, such as `rejects_oversized_tag_value`. Each implementation stage must satisfy its Section 29 acceptance gate before the next security-sensitive stage begins. Release coverage targets are 90% branch coverage overall and 100% for the critical branches listed in Section 28.8. Until Stage 10 release qualification the enforced branch floor is the interim 75% recorded in `conformance/critical-coverage.toml`.

## Commit & Pull Request Guidelines

Use concise imperative subjects such as `Add bounded client framing`. Keep commits stage-focused. Pull requests must identify affected specification sections and invariants, describe wire, persistence, dependency, or security effects, and list exact validation commands and results. Never combine normative protocol changes with unrelated implementation cleanup.

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **agenc-ircd** (123727 symbols, 305429 relationships, 300 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

> Index stale? Run `node .gitnexus/run.cjs analyze` from the project root — it auto-selects an available runner. No `.gitnexus/run.cjs` yet? `npx gitnexus analyze` (npm 11 crash → `npm i -g gitnexus`; #1939).

## Always Do

- **MUST run impact analysis before editing any symbol.** Before modifying a function, class, or method, run `impact({target: "symbolName", direction: "upstream"})` and report the blast radius (direct callers, affected processes, risk level) to the user. For unified PDG impact, add `mode: "pdg"` with optional `line: <N>` — it returns statement-level `affectedStatements` over CDG + REACHING_DEF and inter-procedural symbols in `interproceduralByDepth`/`byDepth`; no-layer/degraded PDG results are UNKNOWN-risk notes (`--pdg` layer).
- **MUST run `detect_changes()` before committing** to verify your changes only affect expected symbols and execution flows. For regression review, compare against the default branch: `detect_changes({scope: "compare", base_ref: "main"})`.
- **MUST warn the user** if impact analysis returns HIGH or CRITICAL risk before proceeding with edits.
- When exploring unfamiliar code, use `query({search_query: "concept"})` to find execution flows instead of grepping. It returns process-grouped results ranked by relevance.
- When you need full context on a specific symbol — callers, callees, which execution flows it participates in — use `context({name: "symbolName"})`.
- For security review, `explain({target: "fileOrSymbol"})` lists taint findings (source→sink flows; needs `analyze --pdg`).
- For control/data dependence, `pdg_query({mode: "controls", target: "fileOrSymbol"})` answers "under what condition does X run?" (CDG, incl. guard clauses) and `pdg_query({mode: "flows", target, variable})` traces "where does variable Y flow?" (REACHING_DEF). `--pdg` layer.

## Never Do

- NEVER edit a function, class, or method without first running `impact` on it.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis.
- NEVER rename symbols with find-and-replace — use `rename` which understands the call graph.
- NEVER commit changes without running `detect_changes()` to check affected scope.

## Resources

| Resource | Use for |
|----------|---------|
| `gitnexus://repo/agenc-ircd/context` | Codebase overview, check index freshness |
| `gitnexus://repo/agenc-ircd/clusters` | All functional areas |
| `gitnexus://repo/agenc-ircd/processes` | All execution flows |
| `gitnexus://repo/agenc-ircd/process/{name}` | Step-by-step execution trace |

## CLI

| Task | Read this skill file |
|------|---------------------|
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus/gitnexus-cli/SKILL.md` |
| Work in the Tests area (2027 symbols) | `.claude/skills/generated/tests/SKILL.md` |
| Work in the State_core area (597 symbols) | `.claude/skills/generated/state-core/SKILL.md` |
| Work in the Coordinator area (470 symbols) | `.claude/skills/generated/coordinator/SKILL.md` |
| Work in the Federation area (344 symbols) | `.claude/skills/generated/federation/SKILL.md` |
| Work in the Scripts area (308 symbols) | `.claude/skills/generated/scripts/SKILL.md` |
| Work in the Edge area (192 symbols) | `.claude/skills/generated/edge/SKILL.md` |
| Work in the Admission area (142 symbols) | `.claude/skills/generated/admission/SKILL.md` |
| Work in the Cluster_254 area (117 symbols) | `.claude/skills/generated/cluster-254/SKILL.md` |
| Work in the Observe area (113 symbols) | `.claude/skills/generated/observe/SKILL.md` |
| Work in the Ops area (103 symbols) | `.claude/skills/generated/ops/SKILL.md` |
| Work in the E2ee area (93 symbols) | `.claude/skills/generated/e2ee/SKILL.md` |
| Work in the Connection area (84 symbols) | `.claude/skills/generated/connection/SKILL.md` |
| Work in the E2ee_records area (82 symbols) | `.claude/skills/generated/e2ee-records/SKILL.md` |
| Work in the Admin area (82 symbols) | `.claude/skills/generated/admin/SKILL.md` |
| Work in the Supervisor area (76 symbols) | `.claude/skills/generated/supervisor/SKILL.md` |
| Work in the Codec area (73 symbols) | `.claude/skills/generated/codec/SKILL.md` |
| Work in the Wire area (69 symbols) | `.claude/skills/generated/wire/SKILL.md` |
| Work in the Fuzz_targets area (68 symbols) | `.claude/skills/generated/fuzz-targets/SKILL.md` |
| Work in the Tls area (56 symbols) | `.claude/skills/generated/tls/SKILL.md` |
| Work in the Listener area (51 symbols) | `.claude/skills/generated/listener/SKILL.md` |

<!-- gitnexus:end -->
