---
name: observe
description: "Skill for the Observe area of agenc-ircd. 154 symbols across 9 files."
---

# Observe

154 symbols | 9 files | Cohesion: 75%

## When to Use

- Working with code in `crates/`
- Understanding how process_started, storage_recovered, state_core_ready work
- Modifying observe-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/observe/adapter.rs` | process_started, storage_recovered, state_core_ready, listener_lifecycle, federation_link (+46) |
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
- **`federation_link`** (Function) — `crates/agenc-ircd-runtime/src/observe/adapter.rs:115`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `process_started` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 54 |
| `storage_recovered` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 65 |
| `state_core_ready` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 87 |
| `listener_lifecycle` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 98 |
| `federation_link` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 115 |
| `clock_trust_changed` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 136 |
| `hardening_warning` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 155 |
| `reload` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 281 |
| `admin_action` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 303 |
| `admin_authentication` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 321 |
| `overload_transition` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 337 |
| `shutdown_phase` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 355 |
| `with_count` | Function | `crates/agenc-ircd-runtime/src/observe/events.rs` | 457 |
| `depth` | Function | `crates/agenc-ircd-runtime/src/observe/log.rs` | 148 |
| `set_log_retention` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 296 |
| `with_purpose` | Function | `crates/agenc-ircd-runtime/src/observe/events.rs` | 436 |
| `with_error` | Function | `crates/agenc-ircd-runtime/src/observe/events.rs` | 443 |
| `hours` | Function | `crates/agenc-ircd-runtime/src/observe/log.rs` | 59 |
| `get` | Function | `crates/agenc-ircd-runtime/src/observe/log.rs` | 68 |
| `new` | Function | `crates/agenc-ircd-runtime/src/observe/log.rs` | 82 |

## Connected Areas

| Area | Connections |
|------|-------------|
| State_core | 7 calls |
| Bridge | 7 calls |
| Tests | 6 calls |
| Cluster_407 | 4 calls |
| Cluster_428 | 2 calls |
| Admission | 2 calls |
| Cluster_610 | 1 calls |
| Examples | 1 calls |

## How to Explore

1. `context({name: "process_started"})` — see callers and callees
2. `query({search_query: "observe"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
