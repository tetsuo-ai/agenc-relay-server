---
name: supervisor
description: "Skill for the Supervisor area of agenc-ircd. 76 symbols across 13 files."
---

# Supervisor

76 symbols | 13 files | Cohesion: 75%

## When to Use

- Working with code in `crates/`
- Understanding how admin_process_channel, new, admin_lifecycle_channel work
- Modifying supervisor-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/admin.rs` | acquire_audit_export_memory, admin_process_channel, new, start, admin_lifecycle_channel (+30) |
| `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | default, new, root_token, spawn, cancel (+6) |
| `crates/agenc-ircd-runtime/src/daemon.rs` | maintenance_completion_triggers_shutdown_without_consuming_the_join_record, observe, observe_report, join_or_abort_supervised_remainder, forced_abort_waits_until_nested_owners_have_joined (+3) |
| `crates/agenc-ircd-runtime/src/supervisor/panic.rs` | new, install, server_id, the_crash_event_carries_only_closed_fields, an_unreadable_clock_blocks_installation_and_a_later_failure_uses_the_fallback (+1) |
| `crates/agenc-ircd-runtime/src/supervisor/signal.rs` | the_signal_task_registers_handlers_and_stops_on_cancel, new, run_signal_task |
| `crates/agenc-ircd-runtime/tests/shutdown.rs` | a_panicking_child_is_contained_and_cancels_the_tree_when_critical, connection_children_churn_without_leaking_registrations, forced_abort_joins_every_non_cooperative_owner |
| `crates/agenc-ircd-runtime/src/state_core/admin.rs` | complete_next_for_test, admin_core_channel |
| `crates/agenc-ircd-runtime/tests/federation_link.rs` | start_link, keepalive_silence_and_unsolicited_pong_close_the_link |
| `crates/agenc-ircd-storage/src/owner.rs` | try_backup, an_unavailable_helper_retains_and_synchronously_joins_the_owner |
| `crates/agenc-ircd-runtime/src/admin/audit.rs` | empty_for_test |

## Entry Points

Start here when exploring this area:

- **`admin_process_channel`** (Function) — `crates/agenc-ircd-runtime/src/admin.rs:138`
- **`new`** (Function) — `crates/agenc-ircd-runtime/src/admin.rs:156`
- **`admin_lifecycle_channel`** (Function) — `crates/agenc-ircd-runtime/src/admin.rs:447`
- **`admin_transport_channel`** (Function) — `crates/agenc-ircd-runtime/src/admin.rs:605`
- **`empty_for_test`** (Function) — `crates/agenc-ircd-runtime/src/admin/audit.rs:413`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `admin_process_channel` | Function | `crates/agenc-ircd-runtime/src/admin.rs` | 138 |
| `new` | Function | `crates/agenc-ircd-runtime/src/admin.rs` | 156 |
| `admin_lifecycle_channel` | Function | `crates/agenc-ircd-runtime/src/admin.rs` | 447 |
| `admin_transport_channel` | Function | `crates/agenc-ircd-runtime/src/admin.rs` | 605 |
| `empty_for_test` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 413 |
| `cancel` | Function | `crates/agenc-ircd-runtime/src/cancel.rs` | 64 |
| `complete_next_for_test` | Function | `crates/agenc-ircd-runtime/src/state_core/admin.rs` | 310 |
| `admin_core_channel` | Function | `crates/agenc-ircd-runtime/src/state_core/admin.rs` | 460 |
| `new` | Function | `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | 148 |
| `root_token` | Function | `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | 157 |
| `spawn` | Function | `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | 164 |
| `cancel` | Function | `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | 196 |
| `abort_all` | Function | `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | 201 |
| `next_exit` | Function | `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | 207 |
| `join_all` | Function | `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | 232 |
| `try_backup` | Function | `crates/agenc-ircd-storage/src/owner.rs` | 158 |
| `live_children` | Function | `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | 191 |
| `new` | Function | `crates/agenc-ircd-runtime/src/supervisor/panic.rs` | 27 |
| `install` | Function | `crates/agenc-ircd-runtime/src/supervisor/panic.rs` | 63 |
| `serve` | Function | `crates/agenc-ircd-runtime/src/daemon.rs` | 290 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Federation_commands_record_intent_and_outcome → Result_class_rank` | cross_community | 6 |
| `Federation_commands_record_intent_and_outcome → Classify_admin_output` | cross_community | 6 |
| `Serve → ConfigIssue` | cross_community | 5 |
| `Serve → Protected_ancestors` | cross_community | 5 |
| `Federation_commands_record_intent_and_outcome → Verb` | cross_community | 5 |
| `Serve → Stage_for` | cross_community | 4 |
| `Serve → ConfigReport` | cross_community | 4 |
| `Serve → HardeningOutcome` | cross_community | 4 |
| `Serve → New` | cross_community | 4 |
| `Serve → Has_duplicates` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 17 calls |
| Listener | 5 calls |
| State_core | 4 calls |
| Federation | 3 calls |
| Cluster_25 | 3 calls |
| Observe | 3 calls |
| Connection | 2 calls |
| Cluster_482 | 2 calls |

## How to Explore

1. `context({name: "admin_process_channel"})` — see callers and callees
2. `query({search_query: "supervisor"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
