---
name: cluster-94
description: "Skill for the Cluster_94 area of agenc-ircd. 24 symbols across 1 files."
---

# Cluster_94

24 symbols | 1 files | Cohesion: 96%

## When to Use

- Working with code in `crates/`
- Understanding how apply_prepared work
- Modifying cluster_94-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-domain/src/decision.rs` | apply_prepared, apply_mutation, apply_account, apply_session, apply_session_account_switch (+19) |

## Entry Points

Start here when exploring this area:

- **`apply_prepared`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:1113`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `apply_prepared` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1113 |
| `apply_mutation` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2594 |
| `apply_account` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2698 |
| `apply_session` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2703 |
| `apply_session_account_switch` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2711 |
| `apply_account_deletion` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2757 |
| `apply_account_credential_replacement` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2779 |
| `apply_nick` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2795 |
| `apply_away` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2805 |
| `apply_operator_notices` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2812 |
| `apply_monitor` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2819 |
| `apply_display_name` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2835 |
| `apply_join_new` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2847 |
| `apply_join_existing` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2861 |
| `apply_part` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2881 |
| `destroy_channel` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2896 |
| `apply_close_session` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2902 |
| `apply_topic` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2922 |
| `apply_modes` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2934 |
| `recompute_channel_roles` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2990 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Apply_mutation → Destroy_channel` | intra_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_84 | 1 calls |
| Tests | 1 calls |

## How to Explore

1. `context({name: "apply_prepared"})` — see callers and callees
2. `query({search_query: "cluster_94"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
