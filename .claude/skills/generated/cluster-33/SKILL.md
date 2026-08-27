---
name: cluster-33
description: "Skill for the Cluster_33 area of agenc-ircd. 7 symbols across 1 files."
---

# Cluster_33

7 symbols | 1 files | Cohesion: 92%

## When to Use

- Working with code in `crates/`
- Understanding how first, get work
- Modifying cluster_33-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-client-wire/src/tags.rs` | range, first, get, eq, tag_at (+2) |

## Entry Points

Start here when exploring this area:

- **`first`** (Function) — `crates/agenc-ircd-client-wire/src/tags.rs:188`
- **`get`** (Function) — `crates/agenc-ircd-client-wire/src/tags.rs:194`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `first` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 188 |
| `get` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 194 |
| `range` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 137 |
| `eq` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 235 |
| `tag_at` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 289 |
| `packed_text` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 677 |
| `parsed_tag_ref` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 681 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Eq → Range` | intra_community | 5 |
| `Eq → MessageTagRef` | intra_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_15 | 2 calls |

## How to Explore

1. `context({name: "first"})` — see callers and callees
2. `query({search_query: "cluster_33"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
