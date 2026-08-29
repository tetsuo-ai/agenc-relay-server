---
name: connection
description: "Skill for the Connection area of agenc-ircd. 75 symbols across 14 files."
---

# Connection

75 symbols | 14 files | Cohesion: 74%

## When to Use

- Working with code in `crates/`
- Understanding how new, new, backing_charge work
- Modifying connection-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/connection/queue.rs` | new, backing_charge, try_reserve, budget, queue (+23) |
| `crates/agenc-ircd-runtime/src/connection/sink.rs` | for_reservation, len, new, next, drop (+12) |
| `crates/agenc-ircd-runtime/src/connection/writer.rs` | handle_pop, write_frame, finish, run_writer, next_or_cancel |
| `crates/agenc-ircd-runtime/src/connection/reader.rs` | new, accept, run_reader, feed_and_forward, forward_pending |
| `crates/agenc-ircd-runtime/tests/listener_accept.rs` | enqueue, next_message, expect_line, expect_closed |
| `crates/agenc-ircd-runtime/src/budget/permit.rs` | drop, new, splits_are_exact_and_every_byte_returns_exactly_once |
| `crates/agenc-ircd-client-wire/src/framing.rs` | timeout, as_str, feed |
| `crates/agenc-ircd-runtime/src/connection/supervisor.rs` | run_connection, supervise_tasks, notify_state_core |
| `crates/agenc-ircd-runtime/src/budget/mod.rs` | try_acquire_batch, try_take |
| `crates/agenc-ircd-client-wire/src/render.rs` | as_bytes |

## Entry Points

Start here when exploring this area:

- **`new`** (Function) — `crates/agenc-ircd-runtime/src/budget/permit.rs:41`
- **`new`** (Function) — `crates/agenc-ircd-runtime/src/connection/queue.rs:66`
- **`backing_charge`** (Function) — `crates/agenc-ircd-runtime/src/connection/queue.rs:125`
- **`for_reservation`** (Function) — `crates/agenc-ircd-runtime/src/connection/sink.rs:348`
- **`len`** (Function) — `crates/agenc-ircd-runtime/src/connection/sink.rs:381`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `new` | Function | `crates/agenc-ircd-runtime/src/budget/permit.rs` | 41 |
| `new` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 66 |
| `backing_charge` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 125 |
| `for_reservation` | Function | `crates/agenc-ircd-runtime/src/connection/sink.rs` | 348 |
| `len` | Function | `crates/agenc-ircd-runtime/src/connection/sink.rs` | 381 |
| `as_bytes` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 393 |
| `failure` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 165 |
| `live_children` | Function | `crates/agenc-ircd-runtime/src/cancel.rs` | 92 |
| `closed_reason` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 266 |
| `take_warning` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 272 |
| `push_control` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 279 |
| `is_closed` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 326 |
| `pop` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 333 |
| `next` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 346 |
| `lock` | Function | `crates/agenc-ircd-runtime/src/sync.rs` | 15 |
| `timeout` | Function | `crates/agenc-ircd-client-wire/src/framing.rs` | 138 |
| `close` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 308 |
| `new` | Function | `crates/agenc-ircd-runtime/src/connection/sink.rs` | 38 |
| `prepare` | Function | `crates/agenc-ircd-runtime/src/connection/sink.rs` | 242 |
| `as_str` | Function | `crates/agenc-ircd-client-wire/src/framing.rs` | 86 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Start → Lock` | cross_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 5 calls |
| Cluster_74 | 2 calls |
| Cluster_266 | 2 calls |
| Budget | 2 calls |
| Fuzz_targets | 1 calls |

## How to Explore

1. `context({name: "new"})` — see callers and callees
2. `query({search_query: "connection"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
