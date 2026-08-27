<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **agenc-ircd** (33192 symbols, 80948 relationships, 300 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

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
| Work in the Tests area (865 symbols) | `.claude/skills/generated/tests/SKILL.md` |
| Work in the Scripts area (308 symbols) | `.claude/skills/generated/scripts/SKILL.md` |
| Work in the Cluster_112 area (135 symbols) | `.claude/skills/generated/cluster-112/SKILL.md` |
| Work in the Cluster_156 area (106 symbols) | `.claude/skills/generated/cluster-156/SKILL.md` |
| Work in the Fuzz_targets area (78 symbols) | `.claude/skills/generated/fuzz-targets/SKILL.md` |
| Work in the Cluster_41 area (53 symbols) | `.claude/skills/generated/cluster-41/SKILL.md` |
| Work in the Cluster_9 area (30 symbols) | `.claude/skills/generated/cluster-9/SKILL.md` |
| Work in the Cluster_176 area (29 symbols) | `.claude/skills/generated/cluster-176/SKILL.md` |
| Work in the Cluster_123 area (21 symbols) | `.claude/skills/generated/cluster-123/SKILL.md` |
| Work in the Cluster_66 area (18 symbols) | `.claude/skills/generated/cluster-66/SKILL.md` |
| Work in the Cluster_152 area (17 symbols) | `.claude/skills/generated/cluster-152/SKILL.md` |
| Work in the Cluster_5 area (15 symbols) | `.claude/skills/generated/cluster-5/SKILL.md` |
| Work in the Cluster_22 area (15 symbols) | `.claude/skills/generated/cluster-22/SKILL.md` |
| Work in the Cluster_134 area (15 symbols) | `.claude/skills/generated/cluster-134/SKILL.md` |
| Work in the Cluster_154 area (13 symbols) | `.claude/skills/generated/cluster-154/SKILL.md` |
| Work in the Cluster_111 area (12 symbols) | `.claude/skills/generated/cluster-111/SKILL.md` |
| Work in the Cluster_79 area (11 symbols) | `.claude/skills/generated/cluster-79/SKILL.md` |
| Work in the Cluster_106 area (11 symbols) | `.claude/skills/generated/cluster-106/SKILL.md` |
| Work in the Cluster_128 area (11 symbols) | `.claude/skills/generated/cluster-128/SKILL.md` |
| Work in the Cluster_173 area (11 symbols) | `.claude/skills/generated/cluster-173/SKILL.md` |

<!-- gitnexus:end -->
