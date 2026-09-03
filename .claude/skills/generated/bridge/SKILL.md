---
name: bridge
description: "Skill for the Bridge area of agenc-ircd. 92 symbols across 19 files."
---

# Bridge

92 symbols | 19 files | Cohesion: 78%

## When to Use

- Working with code in `crates/`
- Understanding how install_observer, prefix_erasure_delay, reload work
- Modifying bridge-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/bridge/storage.rs` | begin, abandon, begin_read, abandon_read, finish_read (+20) |
| `crates/agenc-ircd-runtime/src/channels.rs` | into_runtime, defer, submit, crypto_completed, connection_closed (+8) |
| `crates/agenc-ircd-runtime/src/observe/metrics.rs` | snapshot, is_public, iter, client_admitted, client_closed (+5) |
| `crates/agenc-ircd-runtime/src/bridge/crypto.rs` | try_submit, cancel, in_flight, reap_finished, wait (+4) |
| `crates/agenc-ircd-runtime/src/connection/queue.rs` | rollback, closed_reason, take_warning, is_closed, pop (+3) |
| `crates/agenc-ircd-runtime/src/admission/transport.rs` | install_observer, prefix_erasure_delay, reload, admit, released |
| `crates/agenc-ircd-storage/src/owner.rs` | wait, into_shutdown, shutdown, checkpoint_due, try_checkpoint |
| `crates/agenc-ircd-runtime/src/daemon.rs` | wait_for_prefix_erasure, unwind_live_state_and_log, shutdown_startup_bridges |
| `crates/agenc-ircd-runtime/src/state_core/mod.rs` | complete_command_observation, crypto_mut, start_integrity_checkpoint |
| `crates/agenc-ircd-runtime/src/bridge/mod.rs` | new, job_ids_round_trip_and_the_completion_capacity_is_two |

## Entry Points

Start here when exploring this area:

- **`install_observer`** (Function) — `crates/agenc-ircd-runtime/src/admission/transport.rs:65`
- **`prefix_erasure_delay`** (Function) — `crates/agenc-ircd-runtime/src/admission/transport.rs:78`
- **`reload`** (Function) — `crates/agenc-ircd-runtime/src/admission/transport.rs:95`
- **`begin`** (Function) — `crates/agenc-ircd-runtime/src/bridge/storage.rs:133`
- **`abandon`** (Function) — `crates/agenc-ircd-runtime/src/bridge/storage.rs:146`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `install_observer` | Function | `crates/agenc-ircd-runtime/src/admission/transport.rs` | 65 |
| `prefix_erasure_delay` | Function | `crates/agenc-ircd-runtime/src/admission/transport.rs` | 78 |
| `reload` | Function | `crates/agenc-ircd-runtime/src/admission/transport.rs` | 95 |
| `begin` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 133 |
| `abandon` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 146 |
| `finish` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 217 |
| `fail` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 230 |
| `failure` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 239 |
| `start` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 344 |
| `classify_completion` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 553 |
| `live_children` | Function | `crates/agenc-ircd-runtime/src/cancel.rs` | 92 |
| `closed_reason` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 341 |
| `take_warning` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 347 |
| `is_closed` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 419 |
| `pop` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 426 |
| `next` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 445 |
| `is_public` | Function | `crates/agenc-ircd-runtime/src/observe/metrics.rs` | 205 |
| `iter` | Function | `crates/agenc-ircd-runtime/src/observe/metrics.rs` | 268 |
| `client_admitted` | Function | `crates/agenc-ircd-runtime/src/observe/metrics.rs` | 418 |
| `client_closed` | Function | `crates/agenc-ircd-runtime/src/observe/metrics.rs` | 426 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Route_registered → Compact` | cross_community | 4 |
| `Route_registered → HeapEntry` | cross_community | 4 |
| `Connection_closed → Reap_finished` | cross_community | 4 |
| `Run → Lock` | cross_community | 3 |
| `Start → Lock` | cross_community | 3 |
| `Terminal_delivery_failure_keeps_the_committed_intent_terminal → Lock` | cross_community | 3 |
| `Route_registered → Complete_command_observation` | intra_community | 3 |
| `Route_registered → Now` | cross_community | 3 |
| `Route_registered → Timers_mut` | cross_community | 3 |
| `Authenticated_stats_read_the_process_metrics_registry → Lock` | cross_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| State_core | 13 calls |
| Cluster_620 | 2 calls |
| Observe | 2 calls |
| Tests | 2 calls |
| Cluster_90 | 1 calls |
| Cluster_410 | 1 calls |

## How to Explore

1. `context({name: "install_observer"})` — see callers and callees
2. `query({search_query: "bridge"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
