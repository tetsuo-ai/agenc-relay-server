---
name: supervisor
description: "Skill for the Supervisor area of agenc-ircd. 27 symbols across 6 files."
---

# Supervisor

27 symbols | 6 files | Cohesion: 71%

## When to Use

- Working with code in `crates/`
- Understanding how new, crash_event, report_and_exit work
- Modifying supervisor-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | default, new, cancel, join_all, join_all_reports_unfinished_children_after_the_deadline (+3) |
| `crates/agenc-ircd-runtime/src/supervisor/panic.rs` | new, crash_event, report_and_exit, install, server_id (+2) |
| `crates/agenc-ircd-runtime/src/supervisor/signal.rs` | new, classify, run_signal_task, the_first_termination_starts_shutdown_and_later_ones_interrupt, the_signal_task_registers_handlers_and_stops_on_cancel |
| `crates/agenc-ircd-runtime/tests/shutdown.rs` | a_panicking_child_is_contained_and_cancels_the_tree_when_critical, connection_children_churn_without_leaking_registrations, a_second_termination_signal_skips_to_stop |
| `crates/agenc-ircd-runtime/src/supervisor/shutdown.rs` | budget, run_shutdown, run_phase |
| `crates/agenc-ircd-admin/src/session.rs` | terminate |

## Entry Points

Start here when exploring this area:

- **`new`** (Function) — `crates/agenc-ircd-runtime/src/supervisor/panic.rs:27`
- **`crash_event`** (Function) — `crates/agenc-ircd-runtime/src/supervisor/panic.rs:45`
- **`report_and_exit`** (Function) — `crates/agenc-ircd-runtime/src/supervisor/panic.rs:57`
- **`install`** (Function) — `crates/agenc-ircd-runtime/src/supervisor/panic.rs:63`
- **`terminate`** (Function) — `crates/agenc-ircd-admin/src/session.rs:146`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `new` | Function | `crates/agenc-ircd-runtime/src/supervisor/panic.rs` | 27 |
| `crash_event` | Function | `crates/agenc-ircd-runtime/src/supervisor/panic.rs` | 45 |
| `report_and_exit` | Function | `crates/agenc-ircd-runtime/src/supervisor/panic.rs` | 57 |
| `install` | Function | `crates/agenc-ircd-runtime/src/supervisor/panic.rs` | 63 |
| `terminate` | Function | `crates/agenc-ircd-admin/src/session.rs` | 146 |
| `new` | Function | `crates/agenc-ircd-runtime/src/supervisor/signal.rs` | 33 |
| `classify` | Function | `crates/agenc-ircd-runtime/src/supervisor/signal.rs` | 39 |
| `run_signal_task` | Function | `crates/agenc-ircd-runtime/src/supervisor/signal.rs` | 61 |
| `new` | Function | `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | 145 |
| `cancel` | Function | `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | 193 |
| `join_all` | Function | `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | 224 |
| `root_token` | Function | `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | 154 |
| `next_exit` | Function | `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | 199 |
| `budget` | Function | `crates/agenc-ircd-runtime/src/supervisor/shutdown.rs` | 118 |
| `run_shutdown` | Function | `crates/agenc-ircd-runtime/src/supervisor/shutdown.rs` | 178 |
| `server_id` | Function | `crates/agenc-ircd-runtime/src/supervisor/panic.rs` | 87 |
| `the_crash_event_carries_only_closed_fields` | Function | `crates/agenc-ircd-runtime/src/supervisor/panic.rs` | 92 |
| `an_unreadable_clock_blocks_installation_and_a_later_failure_uses_the_fallback` | Function | `crates/agenc-ircd-runtime/src/supervisor/panic.rs` | 113 |
| `the_first_termination_starts_shutdown_and_later_ones_interrupt` | Function | `crates/agenc-ircd-runtime/src/supervisor/signal.rs` | 88 |
| `the_signal_task_registers_handlers_and_stops_on_cancel` | Function | `crates/agenc-ircd-runtime/src/supervisor/signal.rs` | 116 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 16 calls |
| Connection | 3 calls |
| Observe | 2 calls |

## How to Explore

1. `context({name: "new"})` — see callers and callees
2. `query({search_query: "supervisor"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
