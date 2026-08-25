---
name: cluster-30
description: "Skill for the Cluster_30 area of agenc-ircd. 5 symbols across 1 files."
---

# Cluster_30

5 symbols | 1 files | Cohesion: 67%

## When to Use

- Working with code in `crates/`
- Understanding how try_from_slice, try_from_vec, len work
- Modifying cluster_30-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-types/src/bounded.rs` | try_from_slice, try_from_vec, len, try_from_bytes, try_from_str |

## Entry Points

Start here when exploring this area:

- **`try_from_slice`** (Function) — `crates/agenc-ircd-types/src/bounded.rs:31`
- **`try_from_vec`** (Function) — `crates/agenc-ircd-types/src/bounded.rs:42`
- **`len`** (Function) — `crates/agenc-ircd-types/src/bounded.rs:55`
- **`try_from_bytes`** (Function) — `crates/agenc-ircd-types/src/bounded.rs:89`
- **`try_from_str`** (Function) — `crates/agenc-ircd-types/src/bounded.rs:96`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `try_from_slice` | Function | `crates/agenc-ircd-types/src/bounded.rs` | 31 |
| `try_from_vec` | Function | `crates/agenc-ircd-types/src/bounded.rs` | 42 |
| `len` | Function | `crates/agenc-ircd-types/src/bounded.rs` | 55 |
| `try_from_bytes` | Function | `crates/agenc-ircd-types/src/bounded.rs` | 89 |
| `try_from_str` | Function | `crates/agenc-ircd-types/src/bounded.rs` | 96 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Validate_mode_change → New` | cross_community | 6 |
| `Validate_mode_change → Len` | cross_community | 6 |
| `Validate_operation_schema → Len` | cross_community | 5 |
| `Validate_event_schema → Len` | cross_community | 5 |
| `Validate_session_hidden → New` | cross_community | 5 |
| `Validate_session_hidden → Len` | cross_community | 5 |
| `Validate_topic_change → New` | cross_community | 5 |
| `Validate_topic_change → Len` | cross_community | 5 |
| `Validate_away_fields → New` | cross_community | 5 |
| `Validate_away_fields → Len` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 2 calls |

## How to Explore

1. `context({name: "try_from_slice"})` — see callers and callees
2. `query({search_query: "cluster_30"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
