---
name: supervisor
description: "Skill for the Supervisor area of agenc-ircd. 34 symbols across 8 files."
---

# Supervisor

34 symbols | 8 files | Cohesion: 72%

## When to Use

- Working with code in `crates/`
- Understanding how lifecycle_channel, new, root_token work
- Modifying supervisor-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | default, new, root_token, cancel, next_exit (+5) |
| `crates/agenc-ircd-runtime/src/daemon.rs` | start_owners, unwind_started_owners, observe, observe_report, all_joined (+2) |
| `crates/agenc-ircd-runtime/src/supervisor/panic.rs` | new, crash_event, report_and_exit, install, server_id (+2) |
| `crates/agenc-ircd-runtime/src/supervisor/signal.rs` | new, classify, run_signal_task, the_first_termination_starts_shutdown_and_later_ones_interrupt |
| `crates/agenc-ircd-runtime/tests/shutdown.rs` | a_panicking_child_is_contained_and_cancels_the_tree_when_critical, connection_children_churn_without_leaking_registrations, forced_abort_joins_every_non_cooperative_owner |
| `crates/agenc-ircd-runtime/src/state_core/inbox.rs` | lifecycle_channel |
| `crates/agenc-ircd-runtime/tests/stage_six_soak.rs` | supervised_connection_batches_join_without_live_owners |
| `crates/agenc-ircd-admin/src/session.rs` | terminate |

## Entry Points

Start here when exploring this area:

- **`lifecycle_channel`** (Function) — `crates/agenc-ircd-runtime/src/state_core/inbox.rs:308`
- **`new`** (Function) — `crates/agenc-ircd-runtime/src/supervisor/mod.rs:145`
- **`root_token`** (Function) — `crates/agenc-ircd-runtime/src/supervisor/mod.rs:154`
- **`cancel`** (Function) — `crates/agenc-ircd-runtime/src/supervisor/mod.rs:193`
- **`next_exit`** (Function) — `crates/agenc-ircd-runtime/src/supervisor/mod.rs:204`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `lifecycle_channel` | Function | `crates/agenc-ircd-runtime/src/state_core/inbox.rs` | 308 |
| `new` | Function | `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | 145 |
| `root_token` | Function | `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | 154 |
| `cancel` | Function | `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | 193 |
| `next_exit` | Function | `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | 204 |
| `join_all` | Function | `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | 229 |
| `live_children` | Function | `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | 188 |
| `abort_all` | Function | `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | 198 |
| `new` | Function | `crates/agenc-ircd-runtime/src/supervisor/panic.rs` | 27 |
| `crash_event` | Function | `crates/agenc-ircd-runtime/src/supervisor/panic.rs` | 45 |
| `report_and_exit` | Function | `crates/agenc-ircd-runtime/src/supervisor/panic.rs` | 57 |
| `install` | Function | `crates/agenc-ircd-runtime/src/supervisor/panic.rs` | 63 |
| `terminate` | Function | `crates/agenc-ircd-admin/src/session.rs` | 146 |
| `new` | Function | `crates/agenc-ircd-runtime/src/supervisor/signal.rs` | 33 |
| `classify` | Function | `crates/agenc-ircd-runtime/src/supervisor/signal.rs` | 39 |
| `run_signal_task` | Function | `crates/agenc-ircd-runtime/src/supervisor/signal.rs` | 61 |
| `start_owners` | Function | `crates/agenc-ircd-runtime/src/daemon.rs` | 2156 |
| `unwind_started_owners` | Function | `crates/agenc-ircd-runtime/src/daemon.rs` | 2289 |
| `default` | Function | `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | 137 |
| `a_critical_failure_cancels_the_tree_and_a_connection_failure_does_not` | Function | `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | 247 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Listener | 21 calls |
| Observe | 3 calls |
| Tests | 3 calls |
| Cluster_325 | 1 calls |
| Bridge | 1 calls |
| Cluster_385 | 1 calls |
| Admin | 1 calls |

## How to Explore

1. `context({name: "lifecycle_channel"})` — see callers and callees
2. `query({search_query: "supervisor"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
