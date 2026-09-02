---
name: connection
description: "Skill for the Connection area of agenc-ircd. 103 symbols across 17 files."
---

# Connection

103 symbols | 17 files | Cohesion: 73%

## When to Use

- Working with code in `crates/`
- Understanding how new, new, for_reservation work
- Modifying connection-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/connection/queue.rs` | new, budget, queue, frame, reserve_and_commit (+27) |
| `crates/agenc-ircd-runtime/src/connection/sink.rs` | for_reservation, len, new, next, drop (+21) |
| `crates/agenc-ircd-runtime/src/connection/supervisor.rs` | new, assign_generation, assign_state_permit, arm, assign_line_counter (+9) |
| `crates/agenc-ircd-runtime/src/connection/writer.rs` | handle_pop, write_frame, finish, run_writer, next_or_cancel (+2) |
| `crates/agenc-ircd-runtime/src/connection/reader.rs` | new, accept, run_reader, run_reader_sequenced, feed_and_forward (+1) |
| `crates/agenc-ircd-runtime/src/admin.rs` | export_memory, ordinary, writer_acknowledges_after_the_final_admin_frame_and_transport_close |
| `crates/agenc-ircd-runtime/src/budget/permit.rs` | drop, new, splits_are_exact_and_every_byte_returns_exactly_once |
| `crates/agenc-ircd-client-wire/src/framing.rs` | as_str, feed |
| `crates/agenc-ircd-runtime/src/daemon.rs` | flush_admin_and_state, flush_reacquires_admin_acknowledgements_after_a_dropped_drain |
| `crates/agenc-ircd-runtime/src/budget/mod.rs` | try_acquire_batch |

## Entry Points

Start here when exploring this area:

- **`new`** (Function) — `crates/agenc-ircd-runtime/src/budget/permit.rs:41`
- **`new`** (Function) — `crates/agenc-ircd-runtime/src/connection/queue.rs:71`
- **`for_reservation`** (Function) — `crates/agenc-ircd-runtime/src/connection/sink.rs:541`
- **`len`** (Function) — `crates/agenc-ircd-runtime/src/connection/sink.rs:574`
- **`new_live`** (Function) — `crates/agenc-ircd-runtime/src/connection/queue.rs:271`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `new` | Function | `crates/agenc-ircd-runtime/src/budget/permit.rs` | 41 |
| `new` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 71 |
| `for_reservation` | Function | `crates/agenc-ircd-runtime/src/connection/sink.rs` | 541 |
| `len` | Function | `crates/agenc-ircd-runtime/src/connection/sink.rs` | 574 |
| `new_live` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 271 |
| `new` | Function | `crates/agenc-ircd-runtime/src/connection/supervisor.rs` | 57 |
| `assign_generation` | Function | `crates/agenc-ircd-runtime/src/connection/supervisor.rs` | 149 |
| `run_connection` | Function | `crates/agenc-ircd-runtime/src/connection/supervisor.rs` | 207 |
| `connection_close_channel` | Function | `crates/agenc-ircd-runtime/src/state_core/inbox.rs` | 73 |
| `new` | Function | `crates/agenc-ircd-runtime/src/connection/sink.rs` | 56 |
| `prepare` | Function | `crates/agenc-ircd-runtime/src/connection/sink.rs` | 413 |
| `as_str` | Function | `crates/agenc-ircd-client-wire/src/framing.rs` | 86 |
| `feed` | Function | `crates/agenc-ircd-client-wire/src/framing.rs` | 116 |
| `new` | Function | `crates/agenc-ircd-runtime/src/connection/reader.rs` | 55 |
| `run_reader` | Function | `crates/agenc-ircd-runtime/src/connection/reader.rs` | 104 |
| `run_reader_sequenced` | Function | `crates/agenc-ircd-runtime/src/connection/reader.rs` | 123 |
| `as_bytes` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 393 |
| `push_control` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 354 |
| `with_query_usage` | Function | `crates/agenc-ircd-runtime/src/connection/sink.rs` | 68 |
| `queue_snapshot` | Function | `crates/agenc-ircd-runtime/src/state_core/session.rs` | 415 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Registration_committed → Disarm` | cross_community | 6 |
| `Registration_committed → Generation` | cross_community | 6 |
| `Registration_committed → Demand` | cross_community | 6 |
| `Run → With_query_usage` | cross_community | 5 |
| `Registration_committed → Into_frames` | cross_community | 5 |
| `Registration_committed → Discard` | cross_community | 5 |
| `Registration_committed → FanoutCommitReport` | cross_community | 5 |
| `Run_connection → PhysicalCloseNotice` | intra_community | 4 |
| `Step_admin_request → With_query_usage` | cross_community | 4 |
| `Run_connection → MemoryPermit` | cross_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 11 calls |
| Listener | 10 calls |
| Bridge | 8 calls |
| Budget | 4 calls |
| Cluster_320 | 2 calls |
| Cluster_86 | 1 calls |
| Cluster_429 | 1 calls |
| Admission | 1 calls |

## How to Explore

1. `context({name: "new"})` — see callers and callees
2. `query({search_query: "connection"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
