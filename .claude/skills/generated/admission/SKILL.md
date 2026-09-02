---
name: admission
description: "Skill for the Admission area of agenc-ircd. 236 symbols across 14 files."
---

# Admission

236 symbols | 14 files | Cohesion: 78%

## When to Use

- Working with code in `crates/`
- Understanding how into_name, into_parts, new work
- Modifying admission-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-domain/src/decision.rs` | new, insert, is_empty, user, message (+105) |
| `crates/agenc-ircd-runtime/src/admission/buckets.rs` | new, default_rate, hard_rate, fixed, defaults (+46) |
| `crates/agenc-ircd-runtime/src/admission/transport.rs` | now, release_direct, erase_idle, admit_direct, admit_onion (+16) |
| `crates/agenc-ircd-runtime/src/admission/prefix.rs` | new, with_ceiling, connection_opened, connection_closed, erase_idle (+14) |
| `crates/agenc-ircd-domain/src/model.rs` | principal, joined, new_ephemeral, role_of, at_revision (+6) |
| `crates/agenc-ircd-runtime/src/admission/overload.rs` | new, classify, default, usage_reaches, select_evictions (+6) |
| `crates/agenc-ircd-runtime/src/state_core/inbox.rs` | host_key, onion_listener, ipv4, prefix_key |
| `crates/agenc-ircd-domain/src/command.rs` | into_name, into_parts |
| `crates/agenc-ircd-runtime/src/state_core/mod.rs` | apply_admin_mutation, record_physical_close |
| `crates/agenc-ircd-testkit/src/lib.rs` | now |

## Entry Points

Start here when exploring this area:

- **`into_name`** (Function) — `crates/agenc-ircd-domain/src/command.rs:197`
- **`into_parts`** (Function) — `crates/agenc-ircd-domain/src/command.rs:339`
- **`new`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:53`
- **`is_empty`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:391`
- **`user`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:505`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `into_name` | Function | `crates/agenc-ircd-domain/src/command.rs` | 197 |
| `into_parts` | Function | `crates/agenc-ircd-domain/src/command.rs` | 339 |
| `new` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 53 |
| `is_empty` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 391 |
| `user` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 505 |
| `plan_account_service_checkpoint` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1489 |
| `plan_account_created` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1502 |
| `plan_session_opened` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1517 |
| `plan_session_account_switch` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1548 |
| `plan_account_deleted` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1632 |
| `plan_account_deleted_at_revision` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1686 |
| `plan_session_fresh_authentication` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1703 |
| `plan_account_credential_replaced` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1739 |
| `plan_e2ee_binding` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1799 |
| `plan_e2ee_removal_finalized` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1847 |
| `plan_expired_invites` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1879 |
| `plan_sanction` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 2036 |
| `principal` | Function | `crates/agenc-ircd-domain/src/model.rs` | 807 |
| `joined` | Function | `crates/agenc-ircd-domain/src/model.rs` | 935 |
| `new_ephemeral` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1128 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Mode_vectors_simulate_client_order_and_check_only_the_final_state → Presentation` | cross_community | 8 |
| `Mode_vectors_simulate_client_order_and_check_only_the_final_state → Canonical` | cross_community | 8 |
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → Presentation` | cross_community | 8 |
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → Canonical` | cross_community | 8 |
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → Is_global` | cross_community | 8 |
| `Mode_vectors_simulate_client_order_and_check_only_the_final_state → At_revision` | cross_community | 6 |
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → At_revision` | cross_community | 6 |
| `Erase_reload_and_domain_mapping_behave_as_specified → Fixed` | cross_community | 5 |
| `Mode_vectors_simulate_client_order_and_check_only_the_final_state → SessionSeed` | intra_community | 5 |
| `Mode_vectors_simulate_client_order_and_check_only_the_final_state → Bytes` | intra_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 45 calls |
| State_core | 16 calls |
| Cluster_243 | 9 calls |
| Listener | 3 calls |
| Bridge | 3 calls |
| Cluster_261 | 2 calls |
| Cluster_251 | 2 calls |
| Cluster_257 | 2 calls |

## How to Explore

1. `context({name: "into_name"})` — see callers and callees
2. `query({search_query: "admission"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
