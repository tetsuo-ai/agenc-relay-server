---
name: cluster-173
description: "Skill for the Cluster_173 area of agenc-ircd. 11 symbols across 1 files."
---

# Cluster_173

11 symbols | 1 files | Cohesion: 72%

## When to Use

- Working with code in `crates/`
- Understanding how new, apply work
- Modifying cluster_173-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-testkit/src/domain_reference.rs` | new, apply, insert_channel, open, joined_model (+6) |

## Entry Points

Start here when exploring this area:

- **`new`** (Function) — `crates/agenc-ircd-testkit/src/domain_reference.rs:685`
- **`apply`** (Function) — `crates/agenc-ircd-testkit/src/domain_reference.rs:706`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `new` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 685 |
| `apply` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 706 |
| `insert_channel` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 1000 |
| `open` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 1792 |
| `joined_model` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 1804 |
| `duplicate_live_cloak_is_rejected_without_state_change` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 1837 |
| `duplicate_live_cloak_is_rejected_as_corrupt_reference_state` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 1854 |
| `reference_rejections_cover_identity_membership_role_and_sequence_edges` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 2053 |
| `reference_moderation_invite_and_raw_invariants_fail_closed` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 2238 |
| `reference_guard_matrix_covers_limits_roles_and_reverse_indexes` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 2510 |
| `reference_short_circuits_and_command_indexes_fail_closed` | Function | `crates/agenc-ircd-testkit/src/domain_reference.rs` | 2687 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Reference_guard_matrix_covers_limits_roles_and_reverse_indexes → ReferenceAccount` | cross_community | 5 |
| `Reference_guard_matrix_covers_limits_roles_and_reverse_indexes → Validate_name` | cross_community | 5 |
| `Reference_guard_matrix_covers_limits_roles_and_reverse_indexes → Validate_account_fence` | cross_community | 5 |
| `Reference_guard_matrix_covers_limits_roles_and_reverse_indexes → New` | cross_community | 5 |
| `Reference_rejections_cover_identity_membership_role_and_sequence_edges → ReferenceAccount` | cross_community | 5 |
| `Reference_rejections_cover_identity_membership_role_and_sequence_edges → Validate_name` | cross_community | 5 |
| `Reference_rejections_cover_identity_membership_role_and_sequence_edges → Validate_account_fence` | cross_community | 5 |
| `Reference_rejections_cover_identity_membership_role_and_sequence_edges → New` | cross_community | 5 |
| `Execute_command → ReferenceChannel` | cross_community | 4 |
| `Execute_command → New` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_176 | 1 calls |
| Validate | 1 calls |
| Tests | 1 calls |

## How to Explore

1. `context({name: "new"})` — see callers and callees
2. `query({search_query: "cluster_173"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
