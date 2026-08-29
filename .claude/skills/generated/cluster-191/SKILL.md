---
name: cluster-191
description: "Skill for the Cluster_191 area of agenc-ircd. 141 symbols across 6 files."
---

# Cluster_191

141 symbols | 6 files | Cohesion: 95%

## When to Use

- Working with code in `crates/`
- Understanding how into_name, into_parts, user_mode_query work
- Modifying cluster_191-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-domain/src/decision.rs` | new, insert, is_empty, user, message (+121) |
| `crates/agenc-ircd-domain/src/model.rs` | account_id, principal, default, new_ephemeral, role_of (+3) |
| `crates/agenc-ircd-domain/src/command.rs` | into_name, into_parts, user_mode_query, from_data |
| `crates/agenc-ircd-testkit/src/lib.rs` | now |
| `crates/agenc-ircd-types/src/identifiers.rs` | expose_for_deletion |
| `crates/agenc-ircd-types/src/quantities.rs` | from_ticks |

## Entry Points

Start here when exploring this area:

- **`into_name`** (Function) — `crates/agenc-ircd-domain/src/command.rs:197`
- **`into_parts`** (Function) — `crates/agenc-ircd-domain/src/command.rs:339`
- **`user_mode_query`** (Function) — `crates/agenc-ircd-domain/src/command.rs:783`
- **`from_data`** (Function) — `crates/agenc-ircd-domain/src/command.rs:1010`
- **`new`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:55`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `into_name` | Function | `crates/agenc-ircd-domain/src/command.rs` | 197 |
| `into_parts` | Function | `crates/agenc-ircd-domain/src/command.rs` | 339 |
| `user_mode_query` | Function | `crates/agenc-ircd-domain/src/command.rs` | 783 |
| `from_data` | Function | `crates/agenc-ircd-domain/src/command.rs` | 1010 |
| `new` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 55 |
| `is_empty` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 381 |
| `user` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 495 |
| `plan_account_created` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1227 |
| `plan_session_opened` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1242 |
| `plan_session_account_switch` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1257 |
| `plan_account_deleted` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1341 |
| `plan_account_deleted_at_revision` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1395 |
| `plan_session_fresh_authentication` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1412 |
| `plan_account_credential_replaced` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1448 |
| `plan_e2ee_binding` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1501 |
| `plan_e2ee_removal_finalized` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1549 |
| `plan_expired_invites` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1581 |
| `plan_sanction` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1731 |
| `account_id` | Function | `crates/agenc-ircd-domain/src/model.rs` | 243 |
| `principal` | Function | `crates/agenc-ircd-domain/src/model.rs` | 618 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Mode_vectors_simulate_client_order_and_check_only_the_final_state → Presentation` | cross_community | 8 |
| `Mode_vectors_simulate_client_order_and_check_only_the_final_state → Canonical` | cross_community | 8 |
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → Presentation` | cross_community | 8 |
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → Canonical` | cross_community | 8 |
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → Is_global` | cross_community | 8 |
| `Remaining_mode_and_request_helpers_cover_successful_fallthroughs → Presentation` | cross_community | 8 |
| `Remaining_mode_and_request_helpers_cover_successful_fallthroughs → Canonical` | cross_community | 8 |
| `Remaining_mode_and_request_helpers_cover_successful_fallthroughs → Is_global` | cross_community | 8 |
| `Mode_vectors_simulate_client_order_and_check_only_the_final_state → At_revision` | cross_community | 6 |
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → At_revision` | cross_community | 6 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 36 calls |
| Cluster_206 | 4 calls |
| Cluster_181 | 3 calls |
| Cluster_203 | 3 calls |
| Cluster_205 | 2 calls |
| Cluster_198 | 1 calls |
| Cluster_213 | 1 calls |
| Cluster_208 | 1 calls |

## How to Explore

1. `context({name: "into_name"})` — see callers and callees
2. `query({search_query: "cluster_191"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
