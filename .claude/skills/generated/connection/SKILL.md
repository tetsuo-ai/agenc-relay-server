---
name: connection
description: "Skill for the Connection area of agenc-ircd. 101 symbols across 19 files."
---

# Connection

101 symbols | 19 files | Cohesion: 74%

## When to Use

- Working with code in `crates/`
- Understanding how new, new, for_reservation work
- Modifying connection-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/connection/queue.rs` | new, budget, queue, frame, reserve_and_commit (+25) |
| `crates/agenc-ircd-runtime/src/connection/sink.rs` | for_reservation, len, new, next, drop (+21) |
| `crates/agenc-ircd-runtime/src/connection/supervisor.rs` | new, assign_generation, assign_state_permit, arm, assign_line_counter (+8) |
| `crates/agenc-ircd-runtime/src/connection/writer.rs` | handle_pop, write_frame, finish, run_writer, next_or_cancel (+2) |
| `crates/agenc-ircd-runtime/src/connection/reader.rs` | new, accept, run_reader, run_reader_sequenced, feed_and_forward (+1) |
| `crates/agenc-ircd-runtime/src/budget/permit.rs` | drop, new, splits_are_exact_and_every_byte_returns_exactly_once |
| `crates/agenc-ircd-runtime/src/test_support.rs` | take_run_parts, commit |
| `crates/agenc-ircd-client-wire/src/framing.rs` | as_str, feed |
| `crates/agenc-ircd-runtime/src/daemon.rs` | flush_admin_and_state, flush_reacquires_admin_acknowledgements_after_a_dropped_drain |
| `crates/agenc-ircd-runtime/src/admin.rs` | export_memory |

## Entry Points

Start here when exploring this area:

- **`new`** (Function) — `crates/agenc-ircd-runtime/src/budget/permit.rs:41`
- **`new`** (Function) — `crates/agenc-ircd-runtime/src/connection/queue.rs:71`
- **`for_reservation`** (Function) — `crates/agenc-ircd-runtime/src/connection/sink.rs:541`
- **`len`** (Function) — `crates/agenc-ircd-runtime/src/connection/sink.rs:574`
- **`new`** (Function) — `crates/agenc-ircd-runtime/src/connection/supervisor.rs:57`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `new` | Function | `crates/agenc-ircd-runtime/src/budget/permit.rs` | 41 |
| `new` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 71 |
| `for_reservation` | Function | `crates/agenc-ircd-runtime/src/connection/sink.rs` | 541 |
| `len` | Function | `crates/agenc-ircd-runtime/src/connection/sink.rs` | 574 |
| `new` | Function | `crates/agenc-ircd-runtime/src/connection/supervisor.rs` | 57 |
| `assign_generation` | Function | `crates/agenc-ircd-runtime/src/connection/supervisor.rs` | 149 |
| `run_connection` | Function | `crates/agenc-ircd-runtime/src/connection/supervisor.rs` | 207 |
| `connection_close_channel` | Function | `crates/agenc-ircd-runtime/src/state_core/inbox.rs` | 73 |
| `take_run_parts` | Function | `crates/agenc-ircd-runtime/src/test_support.rs` | 560 |
| `as_str` | Function | `crates/agenc-ircd-client-wire/src/framing.rs` | 86 |
| `feed` | Function | `crates/agenc-ircd-client-wire/src/framing.rs` | 116 |
| `new` | Function | `crates/agenc-ircd-runtime/src/connection/reader.rs` | 55 |
| `run_reader` | Function | `crates/agenc-ircd-runtime/src/connection/reader.rs` | 104 |
| `run_reader_sequenced` | Function | `crates/agenc-ircd-runtime/src/connection/reader.rs` | 123 |
| `next_frame` | Function | `crates/agenc-ircd-runtime/src/federation/link.rs` | 116 |
| `new` | Function | `crates/agenc-ircd-runtime/src/connection/sink.rs` | 56 |
| `prepare` | Function | `crates/agenc-ircd-runtime/src/connection/sink.rs` | 413 |
| `as_bytes` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 411 |
| `push_control` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 354 |
| `with_query_usage` | Function | `crates/agenc-ircd-runtime/src/connection/sink.rs` | 68 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Run → With_query_usage` | cross_community | 5 |
| `Run_connection → PhysicalCloseNotice` | intra_community | 4 |
| `Step_admin_request → With_query_usage` | cross_community | 4 |
| `Run_connection → MemoryPermit` | cross_community | 3 |
| `Run_connection → New` | intra_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| State_core | 11 calls |
| Bridge | 8 calls |
| Tests | 6 calls |
| Listener | 4 calls |
| Budget | 4 calls |
| Cluster_86 | 1 calls |
| Cluster_499 | 1 calls |
| Admission | 1 calls |

## How to Explore

1. `context({name: "new"})` — see callers and callees
2. `query({search_query: "connection"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
