---
name: cluster-112
description: "Skill for the Cluster_112 area of agenc-ircd. 135 symbols across 6 files."
---

# Cluster_112

135 symbols | 6 files | Cohesion: 96%

## When to Use

- Working with code in `crates/`
- Understanding how into_name, into_parts, user_mode_query work
- Modifying cluster_112-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-domain/src/decision.rs` | new, insert, user, message, plan_account_created (+115) |
| `crates/agenc-ircd-domain/src/command.rs` | into_name, into_parts, user_mode_query, information, into_data (+1) |
| `crates/agenc-ircd-domain/src/model.rs` | account_id, principal, default, new_ephemeral, role_of (+1) |
| `crates/agenc-ircd-testkit/src/lib.rs` | now |
| `crates/agenc-ircd-types/src/identifiers.rs` | expose_for_deletion |
| `crates/agenc-ircd-types/src/quantities.rs` | from_ticks |

## Entry Points

Start here when exploring this area:

- **`into_name`** (Function) — `crates/agenc-ircd-domain/src/command.rs:197`
- **`into_parts`** (Function) — `crates/agenc-ircd-domain/src/command.rs:339`
- **`user_mode_query`** (Function) — `crates/agenc-ircd-domain/src/command.rs:783`
- **`information`** (Function) — `crates/agenc-ircd-domain/src/command.rs:865`
- **`into_data`** (Function) — `crates/agenc-ircd-domain/src/command.rs:1006`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `into_name` | Function | `crates/agenc-ircd-domain/src/command.rs` | 197 |
| `into_parts` | Function | `crates/agenc-ircd-domain/src/command.rs` | 339 |
| `user_mode_query` | Function | `crates/agenc-ircd-domain/src/command.rs` | 783 |
| `information` | Function | `crates/agenc-ircd-domain/src/command.rs` | 865 |
| `into_data` | Function | `crates/agenc-ircd-domain/src/command.rs` | 1006 |
| `from_data` | Function | `crates/agenc-ircd-domain/src/command.rs` | 1010 |
| `new` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 52 |
| `user` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 492 |
| `plan_account_created` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 981 |
| `plan_session_opened` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 996 |
| `plan_session_account_switch` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1011 |
| `plan_account_deleted` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1095 |
| `plan_account_deleted_at_revision` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1149 |
| `plan_session_fresh_authentication` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1166 |
| `plan_account_credential_replaced` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1204 |
| `plan_e2ee_binding` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1259 |
| `plan_e2ee_removal_finalized` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1309 |
| `plan_expired_invites` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1343 |
| `plan_sanction` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1494 |
| `account_id` | Function | `crates/agenc-ircd-domain/src/model.rs` | 242 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → Presentation` | cross_community | 8 |
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → Canonical` | cross_community | 8 |
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → Is_global` | cross_community | 8 |
| `Mode_vectors_simulate_client_order_and_check_only_the_final_state → Presentation` | cross_community | 8 |
| `Mode_vectors_simulate_client_order_and_check_only_the_final_state → Canonical` | cross_community | 8 |
| `Remaining_mode_and_request_helpers_cover_successful_fallthroughs → Presentation` | cross_community | 8 |
| `Remaining_mode_and_request_helpers_cover_successful_fallthroughs → Canonical` | cross_community | 8 |
| `Remaining_mode_and_request_helpers_cover_successful_fallthroughs → Is_global` | cross_community | 8 |
| `Mutation_helpers_ignore_missing_targets_without_corrupting_indexes → Presentation` | cross_community | 8 |
| `Mutation_helpers_ignore_missing_targets_without_corrupting_indexes → Canonical` | cross_community | 8 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 27 calls |
| Cluster_106 | 3 calls |
| Cluster_125 | 2 calls |
| Cluster_126 | 2 calls |
| Cluster_134 | 1 calls |
| Cluster_129 | 1 calls |
| Cluster_127 | 1 calls |

## How to Explore

1. `context({name: "into_name"})` — see callers and callees
2. `query({search_query: "cluster_112"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
