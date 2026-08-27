<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **agenc-ircd** (23439 symbols, 55634 relationships, 300 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

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
| Work in the Tests area (561 symbols) | `.claude/skills/generated/tests/SKILL.md` |
| Work in the Scripts area (197 symbols) | `.claude/skills/generated/scripts/SKILL.md` |
| Work in the Cluster_103 area (116 symbols) | `.claude/skills/generated/cluster-103/SKILL.md` |
| Work in the Fuzz_targets area (77 symbols) | `.claude/skills/generated/fuzz-targets/SKILL.md` |
| Work in the Cluster_64 area (61 symbols) | `.claude/skills/generated/cluster-64/SKILL.md` |
| Work in the Cluster_8 area (52 symbols) | `.claude/skills/generated/cluster-8/SKILL.md` |
| Work in the Cluster_124 area (29 symbols) | `.claude/skills/generated/cluster-124/SKILL.md` |
| Work in the Cluster_74 area (23 symbols) | `.claude/skills/generated/cluster-74/SKILL.md` |
| Work in the Cluster_33 area (17 symbols) | `.claude/skills/generated/cluster-33/SKILL.md` |
| Work in the Cluster_47 area (14 symbols) | `.claude/skills/generated/cluster-47/SKILL.md` |
| Work in the Cluster_63 area (11 symbols) | `.claude/skills/generated/cluster-63/SKILL.md` |
| Work in the Cluster_85 area (11 symbols) | `.claude/skills/generated/cluster-85/SKILL.md` |
| Work in the Cluster_92 area (11 symbols) | `.claude/skills/generated/cluster-92/SKILL.md` |
| Work in the Cluster_99 area (11 symbols) | `.claude/skills/generated/cluster-99/SKILL.md` |
| Work in the Cluster_14 area (10 symbols) | `.claude/skills/generated/cluster-14/SKILL.md` |
| Work in the Cluster_25 area (9 symbols) | `.claude/skills/generated/cluster-25/SKILL.md` |
| Work in the Cluster_15 area (8 symbols) | `.claude/skills/generated/cluster-15/SKILL.md` |
| Work in the Cluster_38 area (8 symbols) | `.claude/skills/generated/cluster-38/SKILL.md` |
| Work in the Cluster_80 area (8 symbols) | `.claude/skills/generated/cluster-80/SKILL.md` |
| Work in the Cluster_90 area (8 symbols) | `.claude/skills/generated/cluster-90/SKILL.md` |

<!-- gitnexus:end -->
