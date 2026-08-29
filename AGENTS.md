# Repository Guidelines

## Project Structure & Module Organization

`docs/` holds the normative architecture, E2EE extension, federation registry, decision ledger, and integrity manifest. `rfcs/` contains pinned upstream RFC text; preserve these files byte-for-byte. `crates/` contains the 13-crate Section-24 workspace. Stages 00 through 04 are complete. The full Stage 05 persistence implementation and acceptance gate pass; exact-revision evidence is being recorded. Stage 05 includes sealed records, one storage owner, rollback controls, bounded checkpoints, complete startup reconstruction, signed backup and stopped-daemon restore, rekey construction, login-index transition, and native filesystem qualification. Crates assigned to later stages expose no behavior yet. `conformance/` owns requirement and evidence catalogs, while `test-data/` owns public deterministic fixtures.

Rust implementation must follow Section 24 of `docs/ircd-architecture-and-implementation-spec.md`. Keep the declared `agenc-ircd-*` crate boundaries intact: types and wire codecs remain independent of runtime, storage, and policy; the `agenc-ircd` binary performs composition only. Put crate integration tests in `crates/<crate>/tests/` and shared deterministic fixtures in `agenc-ircd-testkit`.

## Build, Test, and Development Commands

- `bash scripts/check-stage-five.sh`: run the current Stage 05 implementation checks, including inherited Stage 00 through Stage 04 checks plus storage policy, integration, dependency, and fuzz checks.
- `python3 scripts/requirements.py check`: prove the generated ledger covers the frozen normative sources.
- `python3 scripts/check-source.py check`: reject unsafe, panic-prone, unbounded-channel, and unreviewed code shapes.
- `cargo fmt --all --check`: verify Rust formatting.
- `cargo check --workspace --all-targets --all-features --locked`: compile every supported target surface.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`: enforce the lint policy.
- `cargo test --workspace --all-features --locked`: run unit and integration tests.
- `cargo deny check` and `cargo audit --deny warnings`: check dependencies and advisories.

The `agenc-ircd` binary still exits unsuccessfully because daemon composition begins in Stage 06; only the stopped-daemon `storage restore` maintenance command is available. This fail-closed behavior prevents the binary from being mistaken for a server. Implementation checks do not close a stage by themselves. Schema version 2 manifests and artifacts close Stages 00 through 04 for exact source commit `1e5b738468f88b238061cc6e84b732176f5cae65`. The schema version 1 evidence for commit `8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb` remains archive-only. Stage 05 implementation checks pass, but Stage 06 must not begin until the Stage 05 exact-SHA artifact and manifest close its checkpoint.

## Coding Style & Naming Conventions

Use stable Rust, rustfmt defaults, and four-space indentation. Crates and modules use `snake_case`, types and traits use `UpperCamelCase`, and constants use `SCREAMING_SNAKE_CASE`. Every workspace crate must declare `#![forbid(unsafe_code)]`. Prefer private-field validated types, typed errors, checked arithmetic, named protocol limits, guard clauses, focused functions, and explicit ownership. Never use unbounded channels, hold locks across `.await`, log secrets, or implement cryptographic primitives locally.

## Testing Guidelines

Add golden-vector, round-trip, negative, property, transcript, and fuzz tests at relevant trust boundaries. Name tests by behavior, such as `rejects_oversized_tag_value`. Each implementation stage must satisfy its Section 29 acceptance gate before the next security-sensitive stage begins. Release coverage targets are 90% branch coverage overall and 100% for the critical branches listed in Section 28.8.

## Commit & Pull Request Guidelines

Use concise imperative subjects such as `Add bounded client framing`. Keep commits stage-focused. Pull requests must identify affected specification sections and invariants, describe wire, persistence, dependency, or security effects, and list exact validation commands and results. Never combine normative protocol changes with unrelated implementation cleanup.

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **agenc-ircd** (44976 symbols, 111969 relationships, 300 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

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
| Work in the Tests area (1153 symbols) | `.claude/skills/generated/tests/SKILL.md` |
| Work in the Scripts area (314 symbols) | `.claude/skills/generated/scripts/SKILL.md` |
| Work in the Cluster_129 area (135 symbols) | `.claude/skills/generated/cluster-129/SKILL.md` |
| Work in the Cluster_173 area (104 symbols) | `.claude/skills/generated/cluster-173/SKILL.md` |
| Work in the Fuzz_targets area (80 symbols) | `.claude/skills/generated/fuzz-targets/SKILL.md` |
| Work in the Cluster_192 area (58 symbols) | `.claude/skills/generated/cluster-192/SKILL.md` |
| Work in the Cluster_36 area (53 symbols) | `.claude/skills/generated/cluster-36/SKILL.md` |
| Work in the Examples area (38 symbols) | `.claude/skills/generated/examples/SKILL.md` |
| Work in the Cluster_7 area (30 symbols) | `.claude/skills/generated/cluster-7/SKILL.md` |
| Work in the Cluster_273 area (29 symbols) | `.claude/skills/generated/cluster-273/SKILL.md` |
| Work in the Cluster_20 area (27 symbols) | `.claude/skills/generated/cluster-20/SKILL.md` |
| Work in the Cluster_214 area (25 symbols) | `.claude/skills/generated/cluster-214/SKILL.md` |
| Work in the Cluster_2 area (22 symbols) | `.claude/skills/generated/cluster-2/SKILL.md` |
| Work in the Cluster_120 area (21 symbols) | `.claude/skills/generated/cluster-120/SKILL.md` |
| Work in the Cluster_140 area (21 symbols) | `.claude/skills/generated/cluster-140/SKILL.md` |
| Work in the Cluster_215 area (21 symbols) | `.claude/skills/generated/cluster-215/SKILL.md` |
| Work in the Cluster_60 area (18 symbols) | `.claude/skills/generated/cluster-60/SKILL.md` |
| Work in the Cluster_203 area (18 symbols) | `.claude/skills/generated/cluster-203/SKILL.md` |
| Work in the Cluster_1 area (17 symbols) | `.claude/skills/generated/cluster-1/SKILL.md` |
| Work in the Cluster_169 area (17 symbols) | `.claude/skills/generated/cluster-169/SKILL.md` |

<!-- gitnexus:end -->
