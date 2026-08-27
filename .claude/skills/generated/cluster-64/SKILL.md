---
name: cluster-64
description: "Skill for the Cluster_64 area of agenc-ircd. 61 symbols across 3 files."
---

# Cluster_64

61 symbols | 3 files | Cohesion: 88%

## When to Use

- Working with code in `crates/`
- Understanding how into_name, into_parts, into_data work
- Modifying cluster_64-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-domain/src/decision.rs` | new, insert, channel, user, plan_account_created (+50) |
| `crates/agenc-ircd-domain/src/command.rs` | into_name, into_parts, into_data, from_data |
| `crates/agenc-ircd-domain/src/model.rs` | account_id, next_revision |

## Entry Points

Start here when exploring this area:

- **`into_name`** (Function) — `crates/agenc-ircd-domain/src/command.rs:160`
- **`into_parts`** (Function) — `crates/agenc-ircd-domain/src/command.rs:226`
- **`into_data`** (Function) — `crates/agenc-ircd-domain/src/command.rs:847`
- **`from_data`** (Function) — `crates/agenc-ircd-domain/src/command.rs:851`
- **`new`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:49`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `into_name` | Function | `crates/agenc-ircd-domain/src/command.rs` | 160 |
| `into_parts` | Function | `crates/agenc-ircd-domain/src/command.rs` | 226 |
| `into_data` | Function | `crates/agenc-ircd-domain/src/command.rs` | 847 |
| `from_data` | Function | `crates/agenc-ircd-domain/src/command.rs` | 851 |
| `new` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 49 |
| `channel` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 389 |
| `user` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 398 |
| `plan_account_created` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 832 |
| `plan_session_opened` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 847 |
| `plan_session_account_switch` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 862 |
| `plan_account_deleted` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 928 |
| `plan_sanction` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1058 |
| `account_id` | Function | `crates/agenc-ircd-domain/src/model.rs` | 242 |
| `next_revision` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1347 |
| `insert` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 274 |
| `resolve_switch_account` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 899 |
| `validate_session_seed` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1103 |
| `validate_account_deletion_roles` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1139 |
| `resolve_message_targets` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1455 |
| `plan_with_inputs` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1521 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → New` | cross_community | 5 |
| `Admission_and_authorization_reject_each_fence_and_role_failure → New` | cross_community | 5 |
| `Remaining_mode_and_request_helpers_cover_successful_fallthroughs → New` | cross_community | 5 |
| `Remaining_plan_guards_cover_owner_continuity_part_scope_and_extra_entropy → New` | cross_community | 5 |
| `Mutation_helpers_ignore_missing_targets_without_corrupting_indexes → New` | cross_community | 5 |
| `Mode_validation_and_role_application_cover_every_authority_class → New` | cross_community | 5 |
| `Invitation_planning_covers_collision_expiry_limits_and_quiet_actor → New` | cross_community | 5 |
| `Account_switch_contact_and_invite_short_circuits_are_observable → New` | cross_community | 5 |
| `Plan_session_opened → At_revision` | cross_community | 4 |
| `Lifecycle_planning_rejects_stale_duplicate_and_invalid_authority_state → New` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 5 calls |
| Cluster_81 | 1 calls |
| Cluster_79 | 1 calls |
| Cluster_80 | 1 calls |
| Authorize_ | 1 calls |
| Cluster_78 | 1 calls |

## How to Explore

1. `context({name: "into_name"})` — see callers and callees
2. `query({search_query: "cluster_64"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
