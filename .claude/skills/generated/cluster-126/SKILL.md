---
name: cluster-126
description: "Skill for the Cluster_126 area of agenc-ircd. 11 symbols across 2 files."
---

# Cluster_126

11 symbols | 2 files | Cohesion: 91%

## When to Use

- Working with code in `crates/`
- Understanding how can_grant work
- Modifying cluster_126-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-domain/src/decision.rs` | validate_and_apply, apply_mask_add, apply_mask_remove, mask_for_entry, mask_is_present (+5) |
| `crates/agenc-ircd-domain/src/model.rs` | can_grant |

## Entry Points

Start here when exploring this area:

- **`can_grant`** (Function) — `crates/agenc-ircd-domain/src/model.rs:645`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `can_grant` | Function | `crates/agenc-ircd-domain/src/model.rs` | 645 |
| `validate_and_apply` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 4069 |
| `apply_mask_add` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 4139 |
| `apply_mask_remove` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 4163 |
| `mask_for_entry` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 4190 |
| `mask_is_present` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 4217 |
| `validate_mode_authority` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 4301 |
| `mask_list_index` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 4413 |
| `require_role` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 4421 |
| `validate_secret_visibility` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 4428 |
| `mask_list` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 4638 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_127 | 1 calls |
| Cluster_110 | 1 calls |

## How to Explore

1. `context({name: "can_grant"})` — see callers and callees
2. `query({search_query: "cluster_126"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
