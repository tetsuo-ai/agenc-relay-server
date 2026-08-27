<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **agenc-ircd** (32253 symbols, 77865 relationships, 300 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

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
| Work in the Tests area (869 symbols) | `.claude/skills/generated/tests/SKILL.md` |
| Work in the Scripts area (270 symbols) | `.claude/skills/generated/scripts/SKILL.md` |
| Work in the Cluster_110 area (135 symbols) | `.claude/skills/generated/cluster-110/SKILL.md` |
| Work in the Cluster_154 area (104 symbols) | `.claude/skills/generated/cluster-154/SKILL.md` |
| Work in the Fuzz_targets area (82 symbols) | `.claude/skills/generated/fuzz-targets/SKILL.md` |
| Work in the Cluster_41 area (53 symbols) | `.claude/skills/generated/cluster-41/SKILL.md` |
| Work in the Cluster_9 area (30 symbols) | `.claude/skills/generated/cluster-9/SKILL.md` |
| Work in the Cluster_174 area (29 symbols) | `.claude/skills/generated/cluster-174/SKILL.md` |
| Work in the Cluster_121 area (21 symbols) | `.claude/skills/generated/cluster-121/SKILL.md` |
| Work in the Cluster_65 area (18 symbols) | `.claude/skills/generated/cluster-65/SKILL.md` |
| Work in the Cluster_150 area (17 symbols) | `.claude/skills/generated/cluster-150/SKILL.md` |
| Work in the Cluster_5 area (15 symbols) | `.claude/skills/generated/cluster-5/SKILL.md` |
| Work in the Cluster_22 area (15 symbols) | `.claude/skills/generated/cluster-22/SKILL.md` |
| Work in the Cluster_132 area (15 symbols) | `.claude/skills/generated/cluster-132/SKILL.md` |
| Work in the Cluster_152 area (15 symbols) | `.claude/skills/generated/cluster-152/SKILL.md` |
| Work in the Cluster_58 area (13 symbols) | `.claude/skills/generated/cluster-58/SKILL.md` |
| Work in the Cluster_109 area (12 symbols) | `.claude/skills/generated/cluster-109/SKILL.md` |
| Work in the Cluster_78 area (11 symbols) | `.claude/skills/generated/cluster-78/SKILL.md` |
| Work in the Cluster_104 area (11 symbols) | `.claude/skills/generated/cluster-104/SKILL.md` |
| Work in the Cluster_126 area (11 symbols) | `.claude/skills/generated/cluster-126/SKILL.md` |

<!-- gitnexus:end -->
