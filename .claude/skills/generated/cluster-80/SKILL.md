---
name: cluster-80
description: "Skill for the Cluster_80 area of agenc-ircd. 8 symbols across 3 files."
---

# Cluster_80

8 symbols | 3 files | Cohesion: 92%

## When to Use

- Working with code in `crates/`
- Understanding how is_quiet, is_quiet work
- Modifying cluster_80-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-domain/src/decision.rs` | validate_mode_change, require_role, validate_secret_visibility, validate_mask_add, validate_mask_remove (+1) |
| `crates/agenc-ircd-domain/src/model.rs` | is_quiet |
| `crates/agenc-ircd-types/src/masks.rs` | is_quiet |

## Entry Points

Start here when exploring this area:

- **`is_quiet`** (Function) — `crates/agenc-ircd-domain/src/model.rs:769`
- **`is_quiet`** (Function) — `crates/agenc-ircd-types/src/masks.rs:167`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `is_quiet` | Function | `crates/agenc-ircd-domain/src/model.rs` | 769 |
| `is_quiet` | Function | `crates/agenc-ircd-types/src/masks.rs` | 167 |
| `validate_mode_change` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3348 |
| `require_role` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3379 |
| `validate_secret_visibility` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3386 |
| `validate_mask_add` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3396 |
| `validate_mask_remove` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3421 |
| `mask_list` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3625 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_81 | 1 calls |

## How to Explore

1. `context({name: "is_quiet"})` — see callers and callees
2. `query({search_query: "cluster_80"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
