---
name: admission
description: "Skill for the Admission area of agenc-ircd. 142 symbols across 14 files."
---

# Admission

142 symbols | 14 files | Cohesion: 60%

## When to Use

- Working with code in `crates/`
- Understanding how iter, registration_committed, charge_all_or_nothing work
- Modifying admission-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/admission/buckets.rs` | charge_all_or_nothing, aggregate, new, defaults, with_ceiling (+47) |
| `crates/agenc-ircd-runtime/src/registration.rs` | route_e2ee_line, drive_e2ee, access_policy, route_message, refresh_deadline (+22) |
| `crates/agenc-ircd-runtime/src/admission/transport.rs` | admission, direct_hosts_obey_the_live_ceiling_and_release_exactly_once, reload_changes_the_direct_host_ceiling_without_resetting_live_counts, prefix_ceiling_eviction_erases_the_coupled_rate_bucket, direct_prefixes_share_the_new_connection_bucket (+15) |
| `crates/agenc-ircd-runtime/src/admission/prefix.rs` | new, with_ceiling, connection_opened, connection_closed, erase_idle (+13) |
| `crates/agenc-ircd-runtime/src/admission/overload.rs` | new, default, usage_reaches, select_evictions, classes_switch_at_exact_thresholds_with_eviction_hysteresis |
| `crates/agenc-ircd-runtime/src/account_service.rs` | registration_committed, charge_opaque_attempt, opaque_attempt_demand, opaque_attempts_stop_at_the_keyed_login_burst_before_lookup |
| `crates/agenc-ircd-runtime/src/state_core/mod.rs` | buckets_mut, record_physical_close, release_connection, apply_runtime_snapshot |
| `crates/agenc-ircd-runtime/src/state_core/inbox.rs` | ipv4, prefix_key, host_key, onion_listener |
| `crates/agenc-ircd-runtime/src/channels.rs` | charge_command, charge_registered_command_only, guest_prefix_keys_follow_the_transport_profile |
| `crates/agenc-ircd-client-wire/src/tags.rs` | iter |

## Entry Points

Start here when exploring this area:

- **`iter`** (Function) — `crates/agenc-ircd-client-wire/src/tags.rs:201`
- **`registration_committed`** (Function) — `crates/agenc-ircd-runtime/src/account_service.rs:1727`
- **`charge_all_or_nothing`** (Function) — `crates/agenc-ircd-runtime/src/admission/buckets.rs:817`
- **`is_e2ee_line`** (Function) — `crates/agenc-ircd-runtime/src/e2ee/edge/router.rs:99`
- **`batch_settled`** (Function) — `crates/agenc-ircd-runtime/src/remote_accounts.rs:115`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `iter` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 201 |
| `registration_committed` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1727 |
| `charge_all_or_nothing` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 817 |
| `is_e2ee_line` | Function | `crates/agenc-ircd-runtime/src/e2ee/edge/router.rs` | 99 |
| `batch_settled` | Function | `crates/agenc-ircd-runtime/src/remote_accounts.rs` | 115 |
| `buckets_mut` | Function | `crates/agenc-ircd-runtime/src/state_core/mod.rs` | 622 |
| `new` | Function | `crates/agenc-ircd-runtime/src/admission/prefix.rs` | 83 |
| `with_ceiling` | Function | `crates/agenc-ircd-runtime/src/admission/prefix.rs` | 89 |
| `connection_opened` | Function | `crates/agenc-ircd-runtime/src/admission/prefix.rs` | 101 |
| `connection_closed` | Function | `crates/agenc-ircd-runtime/src/admission/prefix.rs` | 166 |
| `erase_idle` | Function | `crates/agenc-ircd-runtime/src/admission/prefix.rs` | 195 |
| `new` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 87 |
| `defaults` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 577 |
| `with_ceiling` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 788 |
| `domain_snapshot` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 857 |
| `apply_domain_charges` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 872 |
| `domain_bucket` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 958 |
| `ipv4` | Function | `crates/agenc-ircd-runtime/src/state_core/inbox.rs` | 141 |
| `prefix_key` | Function | `crates/agenc-ircd-runtime/src/state_core/inbox.rs` | 185 |
| `get` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 119 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Run → Try_from` | cross_community | 5 |
| `Run → Iter_mut` | cross_community | 5 |
| `Erase_reload_and_domain_mapping_behave_as_specified → Fixed` | cross_community | 5 |
| `Live_queries_render_lists_names_who_whois_topics_modes_and_information → Prefix_key` | cross_community | 4 |
| `Run → Operational_limits` | cross_community | 4 |
| `Run → Rates` | cross_community | 4 |
| `Erase_reload_and_domain_mapping_behave_as_specified → Retain` | cross_community | 3 |
| `Erase_reload_and_domain_mapping_behave_as_specified → Within` | cross_community | 3 |
| `Erase_reload_and_domain_mapping_behave_as_specified → Iter_mut` | cross_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| State_core | 60 calls |
| Tests | 9 calls |
| Coordinator | 4 calls |
| Cluster_733 | 4 calls |
| Cluster_161 | 3 calls |
| Edge | 3 calls |
| Observe | 3 calls |
| Cluster_822 | 3 calls |

## How to Explore

1. `context({name: "iter"})` — see callers and callees
2. `query({search_query: "admission"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
