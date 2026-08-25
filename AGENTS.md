# Repository Guidelines

## Project Structure & Module Organization

`docs/` holds the normative architecture, E2EE extension, federation registry, decision ledger, and integrity manifest. `rfcs/` contains pinned upstream RFC text; preserve these files byte-for-byte. `crates/` contains the 13-crate Section-24 workspace; most production crates intentionally export no behavior until their roadmap stage. `conformance/` owns requirement and evidence catalogs, while `test-data/` owns public deterministic fixtures.

Rust implementation must follow Section 24 of `docs/ircd-architecture-and-implementation-spec.md`. Keep the declared `agenc-ircd-*` crate boundaries intact: types and wire codecs remain independent of runtime, storage, and policy; the `agenc-ircd` binary performs composition only. Put crate integration tests in `crates/<crate>/tests/` and shared deterministic fixtures in `agenc-ircd-testkit`.

## Build, Test, and Development Commands

- `bash scripts/check-stage-zero.sh`: run the complete workspace, policy, conformance, target, audit, and coverage gate.
- `python3 scripts/requirements.py check`: prove the generated ledger covers the frozen normative sources.
- `python3 scripts/check-source.py check`: reject unsafe, panic-prone, unbounded-channel, and unreviewed code shapes.
- `cargo fmt --all --check`: verify Rust formatting once the workspace exists.
- `cargo check --workspace --all-targets --all-features --locked`: compile every supported target surface.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`: enforce the lint policy.
- `cargo test --workspace --all-features --locked`: run unit and integration tests.
- `cargo deny check` and `cargo audit --deny warnings`: check dependencies and advisories.

The `agenc-ircd` binary deliberately exits unsuccessfully during Stage 00 so it cannot be mistaken for a server. Implement phases in `TODO.md` order.

## Coding Style & Naming Conventions

Use stable Rust, rustfmt defaults, and four-space indentation. Crates and modules use `snake_case`, types and traits use `UpperCamelCase`, and constants use `SCREAMING_SNAKE_CASE`. Every workspace crate must declare `#![forbid(unsafe_code)]`. Prefer private-field validated types, typed errors, checked arithmetic, named protocol limits, guard clauses, focused functions, and explicit ownership. Never use unbounded channels, hold locks across `.await`, log secrets, or implement cryptographic primitives locally.

## Testing Guidelines

Add golden-vector, round-trip, negative, property, transcript, and fuzz tests at relevant trust boundaries. Name tests by behavior, such as `rejects_oversized_tag_value`. Each implementation phase must satisfy its Section 29 acceptance gate before the next security-sensitive phase begins. Release coverage targets are 90% branch coverage overall and 100% for the critical branches listed in Section 28.8.

## Commit & Pull Request Guidelines

History currently establishes only `Initial commit`; use concise imperative subjects such as `Add bounded client framing`. Keep commits phase-focused. Pull requests must identify affected specification sections and invariants, describe wire, persistence, dependency, or security effects, and list exact validation commands and results. Never combine normative protocol changes with unrelated implementation cleanup.

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **agenc-ircd** (8904 symbols, 20609 relationships, 236 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

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
| Work in the Scripts area (156 symbols) | `.claude/skills/generated/scripts/SKILL.md` |
| Work in the Tests area (103 symbols) | `.claude/skills/generated/tests/SKILL.md` |
| Work in the Cluster_11 area (75 symbols) | `.claude/skills/generated/cluster-11/SKILL.md` |
| Work in the Validate_ area (23 symbols) | `.claude/skills/generated/validate/SKILL.md` |
| Work in the Cluster_7 area (13 symbols) | `.claude/skills/generated/cluster-7/SKILL.md` |
| Work in the Cluster_0 area (11 symbols) | `.claude/skills/generated/cluster-0/SKILL.md` |
| Work in the Cluster_4 area (9 symbols) | `.claude/skills/generated/cluster-4/SKILL.md` |
| Work in the Cluster_5 area (9 symbols) | `.claude/skills/generated/cluster-5/SKILL.md` |
| Work in the Cluster_14 area (9 symbols) | `.claude/skills/generated/cluster-14/SKILL.md` |
| Work in the Cluster_3 area (8 symbols) | `.claude/skills/generated/cluster-3/SKILL.md` |
| Work in the Cluster_8 area (7 symbols) | `.claude/skills/generated/cluster-8/SKILL.md` |
| Work in the Cluster_10 area (7 symbols) | `.claude/skills/generated/cluster-10/SKILL.md` |
| Work in the Cluster_9 area (6 symbols) | `.claude/skills/generated/cluster-9/SKILL.md` |
| Work in the Cluster_15 area (6 symbols) | `.claude/skills/generated/cluster-15/SKILL.md` |
| Work in the Cluster_18 area (5 symbols) | `.claude/skills/generated/cluster-18/SKILL.md` |
| Work in the Cluster_21 area (5 symbols) | `.claude/skills/generated/cluster-21/SKILL.md` |
| Work in the Cluster_30 area (5 symbols) | `.claude/skills/generated/cluster-30/SKILL.md` |
| Work in the Cluster_16 area (4 symbols) | `.claude/skills/generated/cluster-16/SKILL.md` |
| Work in the Cluster_20 area (4 symbols) | `.claude/skills/generated/cluster-20/SKILL.md` |
| Work in the Cluster_26 area (4 symbols) | `.claude/skills/generated/cluster-26/SKILL.md` |

<!-- gitnexus:end -->
