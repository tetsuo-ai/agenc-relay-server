---
name: cluster-201
description: "Skill for the Cluster_201 area of agenc-ircd. 21 symbols across 1 files."
---

# Cluster_201

21 symbols | 1 files | Cohesion: 94%

## When to Use

- Working with code in `crates/`
- Understanding how apply_prepared work
- Modifying cluster_201-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-domain/src/decision.rs` | apply_prepared, apply_mutation, apply_account, apply_session, apply_session_account_switch (+16) |

## Entry Points

Start here when exploring this area:

- **`apply_prepared`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:1707`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `apply_prepared` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1707 |
| `apply_mutation` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3383 |
| `apply_account` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3524 |
| `apply_session` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3529 |
| `apply_session_account_switch` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3539 |
| `apply_account_deletion` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3593 |
| `apply_account_credential_replacement` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3615 |
| `apply_nick` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3631 |
| `apply_away` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3641 |
| `apply_operator_notices` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3648 |
| `apply_monitor` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3655 |
| `apply_display_name` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3671 |
| `apply_join_new` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3683 |
| `apply_join_existing` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3697 |
| `apply_part` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3717 |
| `destroy_channel` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3733 |
| `apply_close_session` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3739 |
| `apply_topic` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3761 |
| `apply_modes` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3773 |
| `recompute_channel_roles` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 3831 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_206 | 1 calls |
| Cluster_191 | 1 calls |

## How to Explore

1. `context({name: "apply_prepared"})` — see callers and callees
2. `query({search_query: "cluster_201"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
