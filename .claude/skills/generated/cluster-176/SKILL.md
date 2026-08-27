---
name: cluster-176
description: "Skill for the Cluster_176 area of agenc-ircd. 29 symbols across 1 files."
---

# Cluster_176

29 symbols | 1 files | Cohesion: 92%

## When to Use

- Working with code in `crates/`
- Understanding how apply_inner, create_account, open_session work
- Modifying cluster_176-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-testkit/src/domain_reference.rs` | apply_inner, create_account, open_session, switch_account, rename (+24) |

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `apply_inner` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 765 |
| `create_account` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 846 |
| `open_session` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 864 |
| `switch_account` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 891 |
| `rename` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 926 |
| `close_session` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 941 |
| `join` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 962 |
| `part` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 1025 |
| `part_membership` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 1037 |
| `set_role` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 1053 |
| `set_visibility` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 1081 |
| `delete_account` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 1194 |
| `federation_apply` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 1240 |
| `execute_command` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 1259 |
| `execute_query` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 1313 |
| `set_topic` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 1336 |
| `kick` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 1348 |
| `route_message` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 1375 |
| `set_away` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 1408 |
| `monitor_add` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 1417 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Reference_guard_matrix_covers_limits_roles_and_reverse_indexes → ReferenceAccount` | cross_community | 5 |
| `Reference_guard_matrix_covers_limits_roles_and_reverse_indexes → Validate_name` | cross_community | 5 |
| `Reference_guard_matrix_covers_limits_roles_and_reverse_indexes → Validate_account_fence` | cross_community | 5 |
| `Reference_rejections_cover_identity_membership_role_and_sequence_edges → ReferenceAccount` | cross_community | 5 |
| `Reference_rejections_cover_identity_membership_role_and_sequence_edges → Validate_name` | cross_community | 5 |
| `Reference_rejections_cover_identity_membership_role_and_sequence_edges → Validate_account_fence` | cross_community | 5 |
| `Execute_command → ReferenceChannel` | cross_community | 4 |
| `Execute_command → New` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_173 | 3 calls |
| Cluster_177 | 1 calls |

## How to Explore

1. `context({name: "apply_inner"})` — see callers and callees
2. `query({search_query: "cluster_176"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
