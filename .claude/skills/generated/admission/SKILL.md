---
name: admission
description: "Skill for the Admission area of agenc-ircd. 104 symbols across 10 files."
---

# Admission

104 symbols | 10 files | Cohesion: 61%

## When to Use

- Working with code in `crates/`
- Understanding how new, with_ceiling, connection_opened work
- Modifying admission-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/admission/buckets.rs` | new, defaults, with_ceiling, domain_snapshot, apply_domain_charges (+44) |
| `crates/agenc-ircd-runtime/src/admission/transport.rs` | admission, direct_hosts_obey_the_live_ceiling_and_release_exactly_once, reload_changes_the_direct_host_ceiling_without_resetting_live_counts, prefix_ceiling_eviction_erases_the_coupled_rate_bucket, direct_prefixes_share_the_new_connection_bucket (+15) |
| `crates/agenc-ircd-runtime/src/admission/prefix.rs` | new, with_ceiling, connection_opened, connection_closed, erase_idle (+13) |
| `crates/agenc-ircd-runtime/src/admission/overload.rs` | new, default, usage_reaches, select_evictions, classes_switch_at_exact_thresholds_with_eviction_hysteresis |
| `crates/agenc-ircd-runtime/src/state_core/inbox.rs` | ipv4, prefix_key, onion_listener, host_key |
| `crates/agenc-ircd-runtime/src/state_core/mod.rs` | record_physical_close, apply_runtime_snapshot |
| `crates/agenc-ircd-runtime/src/runtime_config.rs` | from_config, runtime_resource_limits |
| `crates/agenc-ircd-runtime/src/account_service.rs` | opaque_attempt_demand, opaque_attempts_stop_at_the_keyed_login_burst_before_lookup |
| `crates/agenc-ircd-runtime/src/channels.rs` | guest_prefix_keys_follow_the_transport_profile |
| `crates/agenc-ircd-runtime/src/daemon.rs` | config_and_runtime_rate_defaults_match |

## Entry Points

Start here when exploring this area:

- **`new`** (Function) — `crates/agenc-ircd-runtime/src/admission/prefix.rs:83`
- **`with_ceiling`** (Function) — `crates/agenc-ircd-runtime/src/admission/prefix.rs:89`
- **`connection_opened`** (Function) — `crates/agenc-ircd-runtime/src/admission/prefix.rs:101`
- **`connection_closed`** (Function) — `crates/agenc-ircd-runtime/src/admission/prefix.rs:166`
- **`erase_idle`** (Function) — `crates/agenc-ircd-runtime/src/admission/prefix.rs:195`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `new` | Function | `crates/agenc-ircd-runtime/src/admission/prefix.rs` | 83 |
| `with_ceiling` | Function | `crates/agenc-ircd-runtime/src/admission/prefix.rs` | 89 |
| `connection_opened` | Function | `crates/agenc-ircd-runtime/src/admission/prefix.rs` | 101 |
| `connection_closed` | Function | `crates/agenc-ircd-runtime/src/admission/prefix.rs` | 166 |
| `erase_idle` | Function | `crates/agenc-ircd-runtime/src/admission/prefix.rs` | 195 |
| `new` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 87 |
| `defaults` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 564 |
| `with_ceiling` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 773 |
| `domain_snapshot` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 842 |
| `apply_domain_charges` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 857 |
| `domain_bucket` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 943 |
| `ipv4` | Function | `crates/agenc-ircd-runtime/src/state_core/inbox.rs` | 141 |
| `prefix_key` | Function | `crates/agenc-ircd-runtime/src/state_core/inbox.rs` | 185 |
| `get` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 119 |
| `rollback` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 161 |
| `begin_connection_open` | Function | `crates/agenc-ircd-runtime/src/admission/prefix.rs` | 111 |
| `try_insert_transaction` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 147 |
| `iter` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 222 |
| `set` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 595 |
| `new` | Function | `crates/agenc-ircd-runtime/src/admission/transport.rs` | 40 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
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
| State_core | 17 calls |
| Tests | 5 calls |
| Cluster_160 | 4 calls |
| Coordinator | 4 calls |
| Observe | 3 calls |
| Budget | 1 calls |

## How to Explore

1. `context({name: "new"})` — see callers and callees
2. `query({search_query: "admission"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
