---
name: observe
description: "Skill for the Observe area of agenc-ircd. 120 symbols across 8 files."
---

# Observe

120 symbols | 8 files | Cohesion: 72%

## When to Use

- Working with code in `crates/`
- Understanding how process_started, hardening_warning, command_handled work
- Modifying observe-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/observe/log.rs` | admits, try_emit, depth, hours, get (+33) |
| `crates/agenc-ircd-runtime/src/observe/adapter.rs` | increment, process_started, hardening_warning, command_handled, command_classified (+29) |
| `crates/agenc-ircd-runtime/src/observe/health.rs` | mark, clear, flag, readiness_is_the_conjunction_of_every_stage_and_can_be_cleared, ready (+10) |
| `crates/agenc-ircd-runtime/src/observe/metrics.rs` | is_public, new, iter, increment, observe_duration (+8) |
| `crates/agenc-ircd-runtime/src/observe/events.rs` | with_count, purpose, new, from_os_entropy, next (+6) |
| `crates/agenc-ircd-runtime/src/clock.rs` | start, now, utc_now, monotonic_ticks_never_decrease, wall_clock_reads_a_post_stage_six_utc_second |
| `crates/agenc-ircd-runtime/src/daemon.rs` | wait_for_shutdown, spawn_state_owner, run_state_owner |
| `crates/agenc-ircd-runtime/src/state_core/mod.rs` | into_bridges |

## Entry Points

Start here when exploring this area:

- **`process_started`** (Function) — `crates/agenc-ircd-runtime/src/observe/adapter.rs:158`
- **`hardening_warning`** (Function) — `crates/agenc-ircd-runtime/src/observe/adapter.rs:169`
- **`command_handled`** (Function) — `crates/agenc-ircd-runtime/src/observe/adapter.rs:220`
- **`command_classified`** (Function) — `crates/agenc-ircd-runtime/src/observe/adapter.rs:231`
- **`authentication`** (Function) — `crates/agenc-ircd-runtime/src/observe/adapter.rs:249`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `process_started` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 158 |
| `hardening_warning` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 169 |
| `command_handled` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 220 |
| `command_classified` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 231 |
| `authentication` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 249 |
| `federation_ingress` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 260 |
| `reload` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 291 |
| `admin_action` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 320 |
| `admin_authentication` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 338 |
| `overload_transition` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 354 |
| `shutdown_phase` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 372 |
| `with_count` | Function | `crates/agenc-ircd-runtime/src/observe/events.rs` | 449 |
| `purpose` | Function | `crates/agenc-ircd-runtime/src/observe/events.rs` | 474 |
| `admits` | Function | `crates/agenc-ircd-runtime/src/observe/log.rs` | 89 |
| `try_emit` | Function | `crates/agenc-ircd-runtime/src/observe/log.rs` | 120 |
| `depth` | Function | `crates/agenc-ircd-runtime/src/observe/log.rs` | 141 |
| `is_public` | Function | `crates/agenc-ircd-runtime/src/observe/metrics.rs` | 128 |
| `new` | Function | `crates/agenc-ircd-runtime/src/observe/metrics.rs` | 171 |
| `iter` | Function | `crates/agenc-ircd-runtime/src/observe/metrics.rs` | 189 |
| `increment` | Function | `crates/agenc-ircd-runtime/src/observe/metrics.rs` | 306 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Run → Send_blocking` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 9 calls |
| Connection | 5 calls |
| State_core | 4 calls |
| Admission | 3 calls |
| Listener | 1 calls |
| Examples | 1 calls |

## How to Explore

1. `context({name: "process_started"})` — see callers and callees
2. `query({search_query: "observe"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
