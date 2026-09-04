---
name: observe
description: "Skill for the Observe area of agenc-ircd. 113 symbols across 11 files."
---

# Observe

113 symbols | 11 files | Cohesion: 64%

## When to Use

- Working with code in `crates/`
- Understanding how listener_lifecycle, command_classified, storage_batch work
- Modifying observe-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/observe/log.rs` | admits, try_emit_outcome, hours, writer, target_failures_are_counted_and_never_block (+35) |
| `crates/agenc-ircd-runtime/src/observe/adapter.rs` | listener_lifecycle, command_classified, storage_batch, reload, admin_action (+21) |
| `crates/agenc-ircd-runtime/src/observe/metrics.rs` | record, increment, default, new, observe_duration (+8) |
| `crates/agenc-ircd-runtime/src/observe/health.rs` | mark, clear, flag, readiness_is_the_conjunction_of_every_stage_and_can_be_cleared, new (+7) |
| `crates/agenc-ircd-runtime/src/observe/events.rs` | from_count, with_error, new, from_os_entropy, next (+3) |
| `crates/agenc-ircd-runtime/src/daemon.rs` | wait_for_prefix_erasure, run_state_owner, reload_preparation_future, wait_for_shutdown, state_completion_failure (+2) |
| `crates/agenc-ircd-runtime/src/connection/queue.rs` | is_closed, pop, prepare |
| `crates/agenc-ircd-runtime/src/admission/transport.rs` | prefix_erasure_delay |
| `crates/agenc-ircd-runtime/src/sync.rs` | lock |
| `crates/agenc-ircd-storage/src/owner.rs` | try_complete |

## Entry Points

Start here when exploring this area:

- **`listener_lifecycle`** (Function) — `crates/agenc-ircd-runtime/src/observe/adapter.rs:98`
- **`command_classified`** (Function) — `crates/agenc-ircd-runtime/src/observe/adapter.rs:220`
- **`storage_batch`** (Function) — `crates/agenc-ircd-runtime/src/observe/adapter.rs:269`
- **`reload`** (Function) — `crates/agenc-ircd-runtime/src/observe/adapter.rs:281`
- **`admin_action`** (Function) — `crates/agenc-ircd-runtime/src/observe/adapter.rs:303`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `listener_lifecycle` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 98 |
| `command_classified` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 220 |
| `storage_batch` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 269 |
| `reload` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 281 |
| `admin_action` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 303 |
| `overload_transition` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 337 |
| `from_count` | Function | `crates/agenc-ircd-runtime/src/observe/events.rs` | 333 |
| `admits` | Function | `crates/agenc-ircd-runtime/src/observe/log.rs` | 91 |
| `try_emit_outcome` | Function | `crates/agenc-ircd-runtime/src/observe/log.rs` | 126 |
| `prefix_erasure_delay` | Function | `crates/agenc-ircd-runtime/src/admission/transport.rs` | 78 |
| `is_closed` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 419 |
| `pop` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 426 |
| `new` | Function | `crates/agenc-ircd-runtime/src/observe/metrics.rs` | 250 |
| `observe_duration` | Function | `crates/agenc-ircd-runtime/src/observe/metrics.rs` | 399 |
| `observe_count` | Function | `crates/agenc-ircd-runtime/src/observe/metrics.rs` | 409 |
| `lock` | Function | `crates/agenc-ircd-runtime/src/sync.rs` | 15 |
| `new` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 36 |
| `record_rate` | Function | `crates/agenc-ircd-runtime/src/observe/metrics.rs` | 441 |
| `with_error` | Function | `crates/agenc-ircd-runtime/src/observe/events.rs` | 448 |
| `hours` | Function | `crates/agenc-ircd-runtime/src/observe/log.rs` | 59 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Run → Lock` | cross_community | 3 |
| `Start → Lock` | cross_community | 3 |
| `Terminal_delivery_failure_keeps_the_committed_intent_terminal → Lock` | cross_community | 3 |
| `Authenticated_stats_read_the_process_metrics_registry → Lock` | cross_community | 3 |
| `Confirmed_die_commits_intent_before_requesting_stop → Lock` | cross_community | 3 |
| `Account_mutation_waits_for_one_atomic_state_core_commit → Lock` | cross_community | 3 |
| `Observed_output_waits_for_the_durable_audit_reply → Lock` | cross_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 5 calls |
| State_core | 4 calls |
| Cluster_542 | 4 calls |
| Coordinator | 3 calls |
| Bridge | 1 calls |
| Cluster_563 | 1 calls |
| Cluster_575 | 1 calls |
| Admission | 1 calls |

## How to Explore

1. `context({name: "listener_lifecycle"})` — see callers and callees
2. `query({search_query: "observe"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
