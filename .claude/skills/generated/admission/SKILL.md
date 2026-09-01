---
name: admission
description: "Skill for the Admission area of agenc-ircd. 185 symbols across 16 files."
---

# Admission

185 symbols | 16 files | Cohesion: 76%

## When to Use

- Working with code in `crates/`
- Understanding how into_name, new, is_empty work
- Modifying admission-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-domain/src/decision.rs` | new, is_empty, user, message, collect (+80) |
| `crates/agenc-ircd-runtime/src/admission/buckets.rs` | new, fixed, defaults, with_ceiling, len (+26) |
| `crates/agenc-ircd-runtime/src/admission/transport.rs` | now, new, admission, admission_with_rates, direct_hosts_obey_the_live_ceiling_and_release_exactly_once (+14) |
| `crates/agenc-ircd-runtime/src/admission/prefix.rs` | new, with_ceiling, connection_opened, connection_closed, erase_idle (+12) |
| `crates/agenc-ircd-runtime/src/admission/overload.rs` | new, classify, default, usage_reaches, select_evictions (+6) |
| `crates/agenc-ircd-domain/src/model.rs` | principal, new_ephemeral, role_of, at_revision, next_revision (+1) |
| `crates/agenc-ircd-runtime/src/state_core/inbox.rs` | ipv4, onion_listener, host_key, prefix_key |
| `crates/agenc-ircd-runtime/src/channels.rs` | guest_prefix_keys_follow_the_transport_profile, guest_prefix_bucket |
| `crates/agenc-ircd-runtime/src/daemon.rs` | configured_rates, config_and_runtime_rate_defaults_match |
| `crates/agenc-ircd-runtime/src/runtime_config.rs` | client_connection_ceiling, tls_handshake_ceiling |

## Entry Points

Start here when exploring this area:

- **`into_name`** (Function) — `crates/agenc-ircd-domain/src/command.rs:197`
- **`new`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:52`
- **`is_empty`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:390`
- **`user`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:504`
- **`plan_account_service_checkpoint`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:1244`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `into_name` | Function | `crates/agenc-ircd-domain/src/command.rs` | 197 |
| `new` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 52 |
| `is_empty` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 390 |
| `user` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 504 |
| `plan_account_service_checkpoint` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1244 |
| `plan_session_fresh_authentication` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1442 |
| `plan_e2ee_binding` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1538 |
| `plan_e2ee_removal_finalized` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1586 |
| `plan_expired_invites` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1618 |
| `plan_sanction` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 1775 |
| `principal` | Function | `crates/agenc-ircd-domain/src/model.rs` | 800 |
| `new_ephemeral` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1096 |
| `role_of` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1233 |
| `at_revision` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1532 |
| `next_revision` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1979 |
| `tests_support_account_id` | Function | `crates/agenc-ircd-domain/src/model.rs` | 2064 |
| `now` | Function | `crates/agenc-ircd-testkit/src/lib.rs` | 102 |
| `from_ticks` | Function | `crates/agenc-ircd-types/src/quantities.rs` | 109 |
| `new` | Function | `crates/agenc-ircd-runtime/src/admission/prefix.rs` | 38 |
| `with_ceiling` | Function | `crates/agenc-ircd-runtime/src/admission/prefix.rs` | 44 |

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
| Tests | 40 calls |
| Cluster_209 | 13 calls |
| State_core | 13 calls |
| Cluster_226 | 2 calls |
| Cluster_225 | 2 calls |
| Cluster_207 | 2 calls |
| Cluster_223 | 2 calls |
| Connection | 2 calls |

## How to Explore

1. `context({name: "into_name"})` — see callers and callees
2. `query({search_query: "admission"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
