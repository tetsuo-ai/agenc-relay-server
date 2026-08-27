---
name: cluster-144
description: "Skill for the Cluster_144 area of agenc-ircd. 29 symbols across 1 files."
---

# Cluster_144

29 symbols | 1 files | Cohesion: 93%

## When to Use

- Working with code in `crates/`
- Understanding how apply_inner, create_account, open_session work
- Modifying cluster_144-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-testkit/src/domain_reference.rs` | apply_inner, create_account, open_session, switch_account, rename (+24) |

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `apply_inner` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 677 |
| `create_account` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 753 |
| `open_session` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 771 |
| `switch_account` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 793 |
| `rename` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 823 |
| `close_session` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 838 |
| `join` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 857 |
| `part` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 920 |
| `part_membership` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 932 |
| `set_role` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 948 |
| `set_visibility` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 976 |
| `delete_account` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 1024 |
| `federation_apply` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 1049 |
| `execute_command` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 1068 |
| `execute_query` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 1122 |
| `set_topic` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 1145 |
| `kick` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 1157 |
| `route_message` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 1184 |
| `set_away` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 1217 |
| `monitor_add` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 1226 |

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
| `Execute_command → Validate_name` | intra_community | 3 |
| `Execute_command → Part_membership` | intra_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 3 calls |

## How to Explore

1. `context({name: "apply_inner"})` — see callers and callees
2. `query({search_query: "cluster_144"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
