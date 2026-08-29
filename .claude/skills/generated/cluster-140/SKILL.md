---
name: cluster-140
description: "Skill for the Cluster_140 area of agenc-ircd. 21 symbols across 1 files."
---

# Cluster_140

21 symbols | 1 files | Cohesion: 96%

## When to Use

- Working with code in `crates/`
- Understanding how apply_prepared work
- Modifying cluster_140-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-domain/src/decision.rs` | apply_prepared, apply_mutation, apply_account, apply_session, apply_session_account_switch (+16) |

## Entry Points

Start here when exploring this area:

- **`apply_prepared`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:1470`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `apply_prepared` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1470 |
| `apply_mutation` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3112 |
| `apply_account` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3253 |
| `apply_session` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3258 |
| `apply_session_account_switch` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3268 |
| `apply_account_deletion` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3322 |
| `apply_account_credential_replacement` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3344 |
| `apply_nick` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3360 |
| `apply_away` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3370 |
| `apply_operator_notices` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3377 |
| `apply_monitor` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3384 |
| `apply_display_name` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3400 |
| `apply_join_new` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3412 |
| `apply_join_existing` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3426 |
| `apply_part` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3446 |
| `destroy_channel` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3462 |
| `apply_close_session` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3468 |
| `apply_topic` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3490 |
| `apply_modes` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3502 |
| `recompute_channel_roles` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3560 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Apply_mutation → Destroy_channel` | intra_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_129 | 2 calls |

## How to Explore

1. `context({name: "apply_prepared"})` — see callers and callees
2. `query({search_query: "cluster_140"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
