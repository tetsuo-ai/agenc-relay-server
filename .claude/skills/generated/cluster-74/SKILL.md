---
name: cluster-74
description: "Skill for the Cluster_74 area of agenc-ircd. 23 symbols across 1 files."
---

# Cluster_74

23 symbols | 1 files | Cohesion: 96%

## When to Use

- Working with code in `crates/`
- Understanding how apply_prepared work
- Modifying cluster_74-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-domain/src/decision.rs` | apply_prepared, apply_mutation, apply_account, apply_session, apply_session_account_switch (+18) |

## Entry Points

Start here when exploring this area:

- **`apply_prepared`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:1034`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `apply_prepared` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1034 |
| `apply_mutation` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2515 |
| `apply_account` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2609 |
| `apply_session` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2614 |
| `apply_session_account_switch` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2622 |
| `apply_account_deletion` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2668 |
| `apply_nick` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2690 |
| `apply_away` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2700 |
| `apply_operator_notices` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2707 |
| `apply_monitor` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2714 |
| `apply_display_name` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2730 |
| `apply_join_new` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2742 |
| `apply_join_existing` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2756 |
| `apply_part` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2776 |
| `destroy_channel` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2791 |
| `apply_close_session` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2797 |
| `apply_topic` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2817 |
| `apply_modes` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2829 |
| `recompute_channel_roles` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2885 |
| `apply_account_setting` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2899 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Apply_prepared → Destroy_channel` | intra_community | 6 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_64 | 1 calls |
| Tests | 1 calls |

## How to Explore

1. `context({name: "apply_prepared"})` — see callers and callees
2. `query({search_query: "cluster_74"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
