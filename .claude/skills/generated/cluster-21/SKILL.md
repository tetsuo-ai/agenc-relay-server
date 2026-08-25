---
name: cluster-21
description: "Skill for the Cluster_21 area of agenc-ircd. 5 symbols across 1 files."
---

# Cluster_21

5 symbols | 1 files | Cohesion: 91%

## When to Use

- Working with code in `crates/`
- Understanding how new work
- Modifying cluster_21-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-federation-wire/src/text.rs` | new, from_parts, validate_fragment_relationships, expected_fragment_length, u32_constant |

## Entry Points

Start here when exploring this area:

- **`new`** (Function) — `crates/agenc-ircd-federation-wire/src/text.rs:294`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `new` | Function | `crates/agenc-ircd-federation-wire/src/text.rs` | 294 |
| `from_parts` | Function | `crates/agenc-ircd-federation-wire/src/text.rs` | 310 |
| `validate_fragment_relationships` | Function | `crates/agenc-ircd-federation-wire/src/text.rs` | 371 |
| `expected_fragment_length` | Function | `crates/agenc-ircd-federation-wire/src/text.rs` | 394 |
| `u32_constant` | Function | `crates/agenc-ircd-federation-wire/src/text.rs` | 412 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `New → U32_constant` | intra_community | 4 |
| `New → Expected_fragment_length` | intra_community | 4 |

## How to Explore

1. `context({name: "new"})` — see callers and callees
2. `query({search_query: "cluster_21"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
