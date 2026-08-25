---
name: cluster-26
description: "Skill for the Cluster_26 area of agenc-ircd. 4 symbols across 1 files."
---

# Cluster_26

4 symbols | 1 files | Cohesion: 100%

## When to Use

- Working with code in `crates/`
- Understanding how get, insert, remove work
- Modifying cluster_26-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-testkit/src/lib.rs` | get, insert, remove, maybe_fail |

## Entry Points

Start here when exploring this area:

- **`get`** (Function) — `crates/agenc-ircd-testkit/src/lib.rs:320`
- **`insert`** (Function) — `crates/agenc-ircd-testkit/src/lib.rs:326`
- **`remove`** (Function) — `crates/agenc-ircd-testkit/src/lib.rs:362`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `get` | Function | `crates/agenc-ircd-testkit/src/lib.rs` | 320 |
| `insert` | Function | `crates/agenc-ircd-testkit/src/lib.rs` | 326 |
| `remove` | Function | `crates/agenc-ircd-testkit/src/lib.rs` | 362 |
| `maybe_fail` | Function | `crates/agenc-ircd-testkit/src/lib.rs` | 375 |

## How to Explore

1. `context({name: "get"})` — see callers and callees
2. `query({search_query: "cluster_26"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
