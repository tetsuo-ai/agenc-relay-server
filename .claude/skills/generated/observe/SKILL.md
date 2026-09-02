---
name: observe
description: "Skill for the Observe area of agenc-ircd. 153 symbols across 9 files."
---

# Observe

153 symbols | 9 files | Cohesion: 75%

## When to Use

- Working with code in `crates/`
- Understanding how process_started, storage_recovered, state_core_ready work
- Modifying observe-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/observe/adapter.rs` | process_started, storage_recovered, state_core_ready, listener_lifecycle, clock_trust_changed (+45) |
| `crates/agenc-ircd-runtime/src/observe/log.rs` | depth, hours, get, new, set_retention (+45) |
| `crates/agenc-ircd-runtime/src/observe/health.rs` | mark, clear, flag, readiness_is_the_conjunction_of_every_stage_and_can_be_cleared, ready (+10) |
| `crates/agenc-ircd-runtime/src/daemon.rs` | stop_deadline_expired, wait_for_blocking_owners, fail_stop_shutdown, unwind_live_storage_and_log, shutdown_blocking_owners (+7) |
| `crates/agenc-ircd-runtime/src/observe/events.rs` | with_count, with_purpose, with_error, new, from_os_entropy (+6) |
| `crates/agenc-ircd-runtime/src/observe/metrics.rs` | record_rate, record, increment, new, key (+6) |
| `crates/agenc-ircd-runtime/src/state_core/mod.rs` | into_bridges, begin_command_observation |
| `crates/agenc-ircd-runtime/src/supervisor/panic.rs` | exit_process |
| `crates/agenc-ircd-storage/src/owner.rs` | try_complete |

## Entry Points

Start here when exploring this area:

- **`process_started`** (Function) — `crates/agenc-ircd-runtime/src/observe/adapter.rs:54`
- **`storage_recovered`** (Function) — `crates/agenc-ircd-runtime/src/observe/adapter.rs:65`
- **`state_core_ready`** (Function) — `crates/agenc-ircd-runtime/src/observe/adapter.rs:87`
- **`listener_lifecycle`** (Function) — `crates/agenc-ircd-runtime/src/observe/adapter.rs:98`
- **`clock_trust_changed`** (Function) — `crates/agenc-ircd-runtime/src/observe/adapter.rs:113`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `process_started` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 54 |
| `storage_recovered` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 65 |
| `state_core_ready` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 87 |
| `listener_lifecycle` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 98 |
| `clock_trust_changed` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 113 |
| `hardening_warning` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 132 |
| `reload` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 258 |
| `admin_action` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 280 |
| `admin_authentication` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 298 |
| `overload_transition` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 314 |
| `shutdown_phase` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 332 |
| `with_count` | Function | `crates/agenc-ircd-runtime/src/observe/events.rs` | 449 |
| `depth` | Function | `crates/agenc-ircd-runtime/src/observe/log.rs` | 148 |
| `set_log_retention` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 273 |
| `with_purpose` | Function | `crates/agenc-ircd-runtime/src/observe/events.rs` | 428 |
| `with_error` | Function | `crates/agenc-ircd-runtime/src/observe/events.rs` | 435 |
| `hours` | Function | `crates/agenc-ircd-runtime/src/observe/log.rs` | 59 |
| `get` | Function | `crates/agenc-ircd-runtime/src/observe/log.rs` | 68 |
| `new` | Function | `crates/agenc-ircd-runtime/src/observe/log.rs` | 82 |
| `set_retention` | Function | `crates/agenc-ircd-runtime/src/observe/log.rs` | 155 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Run → FileLogShutdownWork` | cross_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 8 calls |
| Bridge | 7 calls |
| Cluster_369 | 4 calls |
| State_core | 3 calls |
| Listener | 2 calls |
| Cluster_386 | 2 calls |
| Admission | 2 calls |
| Cluster_529 | 1 calls |

## How to Explore

1. `context({name: "process_started"})` — see callers and callees
2. `query({search_query: "observe"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
