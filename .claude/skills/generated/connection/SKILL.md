---
name: connection
description: "Skill for the Connection area of agenc-ircd. 84 symbols across 15 files."
---

# Connection

84 symbols | 15 files | Cohesion: 71%

## When to Use

- Working with code in `crates/`
- Understanding how new, for_reservation, len work
- Modifying connection-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/connection/queue.rs` | new, try_reserve, budget, queue, frame (+27) |
| `crates/agenc-ircd-runtime/src/connection/sink.rs` | for_reservation, len, frame_count, into_transfer, discard (+15) |
| `crates/agenc-ircd-runtime/src/connection/supervisor.rs` | new, assign_generation, assign_state_permit, arm, finish (+7) |
| `crates/agenc-ircd-runtime/src/connection/writer.rs` | handle_pop, write_frame, finish, run_writer, orderly_shutdown_acknowledges_only_after_the_writer_finishes (+1) |
| `crates/agenc-ircd-runtime/src/connection/reader.rs` | new, run_reader, run_reader_sequenced |
| `crates/agenc-ircd-runtime/src/daemon.rs` | flush_reacquires_admin_acknowledgements_after_a_dropped_drain, flush_admin_and_state |
| `crates/agenc-ircd-runtime/src/admin.rs` | export_memory |
| `crates/agenc-ircd-runtime/src/budget/mod.rs` | try_acquire_batch |
| `crates/agenc-ircd-runtime/src/budget/permit.rs` | splits_are_exact_and_every_byte_returns_exactly_once |
| `crates/agenc-ircd-runtime/tests/listener_accept.rs` | enqueue |

## Entry Points

Start here when exploring this area:

- **`new`** (Function) — `crates/agenc-ircd-runtime/src/connection/queue.rs:71`
- **`for_reservation`** (Function) — `crates/agenc-ircd-runtime/src/connection/sink.rs:541`
- **`len`** (Function) — `crates/agenc-ircd-runtime/src/connection/sink.rs:574`
- **`new`** (Function) — `crates/agenc-ircd-runtime/src/connection/supervisor.rs:57`
- **`assign_generation`** (Function) — `crates/agenc-ircd-runtime/src/connection/supervisor.rs:149`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `new` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 71 |
| `for_reservation` | Function | `crates/agenc-ircd-runtime/src/connection/sink.rs` | 541 |
| `len` | Function | `crates/agenc-ircd-runtime/src/connection/sink.rs` | 574 |
| `new` | Function | `crates/agenc-ircd-runtime/src/connection/supervisor.rs` | 57 |
| `assign_generation` | Function | `crates/agenc-ircd-runtime/src/connection/supervisor.rs` | 149 |
| `run_connection` | Function | `crates/agenc-ircd-runtime/src/connection/supervisor.rs` | 207 |
| `frame_count` | Function | `crates/agenc-ircd-runtime/src/connection/sink.rs` | 276 |
| `into_transfer` | Function | `crates/agenc-ircd-runtime/src/connection/sink.rs` | 460 |
| `discard` | Function | `crates/agenc-ircd-runtime/src/connection/sink.rs` | 521 |
| `into_frames` | Function | `crates/agenc-ircd-runtime/src/connection/sink.rs` | 568 |
| `commit` | Function | `crates/agenc-ircd-runtime/src/state_core/fanout.rs` | 233 |
| `new` | Function | `crates/agenc-ircd-runtime/src/connection/sink.rs` | 56 |
| `prepare` | Function | `crates/agenc-ircd-runtime/src/connection/sink.rs` | 413 |
| `close` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 386 |
| `acknowledge_flush` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 409 |
| `new` | Function | `crates/agenc-ircd-runtime/src/connection/reader.rs` | 55 |
| `run_reader` | Function | `crates/agenc-ircd-runtime/src/connection/reader.rs` | 104 |
| `run_reader_sequenced` | Function | `crates/agenc-ircd-runtime/src/connection/reader.rs` | 123 |
| `pending` | Function | `crates/agenc-ircd-runtime/src/connection/sink.rs` | 155 |
| `complete` | Function | `crates/agenc-ircd-runtime/src/connection/sink.rs` | 166 |

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
| Observe | 8 calls |
| Coordinator | 5 calls |
| Budget | 5 calls |
| Tests | 5 calls |
| Supervisor | 4 calls |
| State_core | 3 calls |
| Cluster_529 | 2 calls |
| Listener | 1 calls |

## How to Explore

1. `context({name: "new"})` — see callers and callees
2. `query({search_query: "connection"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
