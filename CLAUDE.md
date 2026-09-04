<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **agenc-ircd** (122688 symbols, 302640 relationships, 300 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

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
| Work in the Tests area (1988 symbols) | `.claude/skills/generated/tests/SKILL.md` |
| Work in the State_core area (712 symbols) | `.claude/skills/generated/state-core/SKILL.md` |
| Work in the Coordinator area (470 symbols) | `.claude/skills/generated/coordinator/SKILL.md` |
| Work in the Scripts area (307 symbols) | `.claude/skills/generated/scripts/SKILL.md` |
| Work in the Federation area (264 symbols) | `.claude/skills/generated/federation/SKILL.md` |
| Work in the Edge area (185 symbols) | `.claude/skills/generated/edge/SKILL.md` |
| Work in the Admission area (139 symbols) | `.claude/skills/generated/admission/SKILL.md` |
| Work in the Observe area (116 symbols) | `.claude/skills/generated/observe/SKILL.md` |
| Work in the Ops area (98 symbols) | `.claude/skills/generated/ops/SKILL.md` |
| Work in the E2ee area (89 symbols) | `.claude/skills/generated/e2ee/SKILL.md` |
| Work in the Supervisor area (86 symbols) | `.claude/skills/generated/supervisor/SKILL.md` |
| Work in the Connection area (84 symbols) | `.claude/skills/generated/connection/SKILL.md` |
| Work in the Admin area (79 symbols) | `.claude/skills/generated/admin/SKILL.md` |
| Work in the Validate_ area (79 symbols) | `.claude/skills/generated/validate/SKILL.md` |
| Work in the E2ee_records area (78 symbols) | `.claude/skills/generated/e2ee-records/SKILL.md` |
| Work in the Wire area (68 symbols) | `.claude/skills/generated/wire/SKILL.md` |
| Work in the Fuzz_targets area (68 symbols) | `.claude/skills/generated/fuzz-targets/SKILL.md` |
| Work in the Codec area (67 symbols) | `.claude/skills/generated/codec/SKILL.md` |
| Work in the Tls area (56 symbols) | `.claude/skills/generated/tls/SKILL.md` |
| Work in the Listener area (47 symbols) | `.claude/skills/generated/listener/SKILL.md` |

<!-- gitnexus:end -->
