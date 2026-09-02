---
name: listener
description: "Skill for the Listener area of agenc-ircd. 106 symbols across 22 files."
---

# Listener

106 symbols | 22 files | Cohesion: 64%

## When to Use

- Working with code in `crates/`
- Understanding how admin_lifecycle_channel, admin_transport_channel, empty_for_test work
- Modifying listener-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/listener/mod.rs` | stop_accepting, cancel_connections, new, admit, connection_policy (+22) |
| `crates/agenc-ircd-runtime/src/admin.rs` | start, admin_lifecycle_channel, admin_transport_channel, registry, live_health (+14) |
| `crates/agenc-ircd-testkit/src/tls_fixture.rs` | mint, validate_dns_name, derive_seed, encode_length, tlv (+11) |
| `crates/agenc-ircd-runtime/src/listener/socket.rs` | from, from_metadata, matches, new, drop (+9) |
| `crates/agenc-ircd-runtime/src/runtime_config.rs` | activate_signal, send_activation, commit_outcome, finalize, finish (+1) |
| `crates/agenc-ircd-runtime/src/tls/stream.rs` | export_keying_material, available, acquire |
| `crates/agenc-ircd-runtime/src/state_core/inbox.rs` | try_stop, ipv6, source_keys_mask_to_the_spec_prefixes_and_stay_distinct_per_family |
| `crates/agenc-ircd-storage/src/owner.rs` | try_backup, an_unavailable_helper_retains_and_synchronously_joins_the_owner |
| `crates/agenc-ircd-runtime/src/daemon.rs` | spawn_listener_owner, tracked_shutdown_work_survives_a_dropped_phase_future |
| `crates/agenc-ircd-runtime/src/listener/prefix.rs` | source_key, keys_follow_the_family_and_collapse_mapped_addresses |

## Entry Points

Start here when exploring this area:

- **`admin_lifecycle_channel`** (Function) — `crates/agenc-ircd-runtime/src/admin.rs:444`
- **`admin_transport_channel`** (Function) — `crates/agenc-ircd-runtime/src/admin.rs:602`
- **`empty_for_test`** (Function) — `crates/agenc-ircd-runtime/src/admin/audit.rs:413`
- **`cancel`** (Function) — `crates/agenc-ircd-runtime/src/cancel.rs:64`
- **`stop_accepting`** (Function) — `crates/agenc-ircd-runtime/src/listener/mod.rs:381`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `admin_lifecycle_channel` | Function | `crates/agenc-ircd-runtime/src/admin.rs` | 444 |
| `admin_transport_channel` | Function | `crates/agenc-ircd-runtime/src/admin.rs` | 602 |
| `empty_for_test` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 413 |
| `cancel` | Function | `crates/agenc-ircd-runtime/src/cancel.rs` | 64 |
| `stop_accepting` | Function | `crates/agenc-ircd-runtime/src/listener/mod.rs` | 381 |
| `cancel_connections` | Function | `crates/agenc-ircd-runtime/src/listener/mod.rs` | 386 |
| `admin_core_channel` | Function | `crates/agenc-ircd-runtime/src/state_core/admin.rs` | 425 |
| `spawn` | Function | `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | 161 |
| `try_backup` | Function | `crates/agenc-ircd-storage/src/owner.rs` | 158 |
| `as_bytes` | Function | `crates/agenc-ircd-admin/src/challenge.rs` | 38 |
| `split_exact` | Function | `crates/agenc-ircd-runtime/src/budget/permit.rs` | 56 |
| `backing_charge` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 138 |
| `new` | Function | `crates/agenc-ircd-runtime/src/listener/mod.rs` | 81 |
| `alpn` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 251 |
| `export_keying_material` | Function | `crates/agenc-ircd-runtime/src/tls/stream.rs` | 230 |
| `mint` | Function | `crates/agenc-ircd-testkit/src/tls_fixture.rs` | 89 |
| `bind` | Function | `crates/agenc-ircd-runtime/src/listener/socket.rs` | 183 |
| `channel` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 506 |
| `join` | Function | `crates/agenc-ircd-runtime/src/listener/mod.rs` | 485 |
| `activate_signal` | Function | `crates/agenc-ircd-runtime/src/runtime_config.rs` | 751 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Authenticated_stats_read_the_process_metrics_registry → StorageCompletion` | intra_community | 4 |
| `Start → Lock` | cross_community | 3 |
| `Start → Inner` | cross_community | 3 |
| `Terminal_delivery_failure_keeps_the_committed_intent_terminal → Lock` | cross_community | 3 |
| `Terminal_delivery_failure_keeps_the_committed_intent_terminal → AdminTransportPort` | cross_community | 3 |
| `Terminal_delivery_failure_keeps_the_committed_intent_terminal → AdminOwnerInbox` | cross_community | 3 |
| `Terminal_delivery_failure_keeps_the_committed_intent_terminal → AdminLifecycleControl` | cross_community | 3 |
| `Terminal_delivery_failure_keeps_the_committed_intent_terminal → AdminLifecycleInbox` | cross_community | 3 |
| `Authenticated_stats_read_the_process_metrics_registry → Lock` | cross_community | 3 |
| `Authenticated_stats_read_the_process_metrics_registry → New` | cross_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_320 | 32 calls |
| Tests | 19 calls |
| Admission | 7 calls |
| Admin | 4 calls |
| Cluster_25 | 3 calls |
| Cluster_211 | 1 calls |
| Cluster_429 | 1 calls |
| Bridge | 1 calls |

## How to Explore

1. `context({name: "admin_lifecycle_channel"})` — see callers and callees
2. `query({search_query: "listener"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
