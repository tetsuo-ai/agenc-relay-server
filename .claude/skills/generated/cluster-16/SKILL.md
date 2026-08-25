---
name: cluster-16
description: "Skill for the Cluster_16 area of agenc-ircd. 4 symbols across 2 files."
---

# Cluster_16

4 symbols | 2 files | Cohesion: 55%

## When to Use

- Working with code in `crates/`
- Understanding how prepare work
- Modifying cluster_16-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-types/src/names.rs` | is_space_separator, canonicalize_precis_spaces, prepare |
| `crates/agenc-ircd-federation-wire/src/semantics.rs` | validate_optional_display_name_bytes |

## Entry Points

Start here when exploring this area:

- **`prepare`** (Function) — `crates/agenc-ircd-types/src/names.rs:222`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `prepare` | Function | `crates/agenc-ircd-types/src/names.rs` | 222 |
| `validate_optional_display_name_bytes` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1345 |
| `is_space_separator` | Function | `crates/agenc-ircd-types/src/names.rs` | 186 |
| `canonicalize_precis_spaces` | Function | `crates/agenc-ircd-types/src/names.rs` | 194 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Validate_event_schema → Semantic` | cross_community | 4 |
| `Prepare → New` | cross_community | 3 |
| `Prepare → Is_space_separator` | intra_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 1 calls |
| Cluster_11 | 1 calls |

## How to Explore

1. `context({name: "prepare"})` — see callers and callees
2. `query({search_query: "cluster_16"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
