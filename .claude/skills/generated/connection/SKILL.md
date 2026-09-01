---
name: connection
description: "Skill for the Connection area of agenc-ircd. 90 symbols across 18 files."
---

# Connection

90 symbols | 18 files | Cohesion: 73%

## When to Use

- Working with code in `crates/`
- Understanding how as_bytes, install_observer, reload work
- Modifying connection-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/connection/queue.rs` | rollback, closed_reason, take_warning, push_control, is_closed (+28) |
| `crates/agenc-ircd-runtime/src/connection/sink.rs` | for_reservation, len, new, next, frame_count (+17) |
| `crates/agenc-ircd-runtime/src/connection/writer.rs` | handle_pop, write_frame, finish, run_writer, next_or_cancel (+2) |
| `crates/agenc-ircd-runtime/src/connection/reader.rs` | new, accept, run_reader, feed_and_forward, forward_pending |
| `crates/agenc-ircd-runtime/src/admission/transport.rs` | install_observer, reload, admit, released |
| `crates/agenc-ircd-runtime/src/connection/supervisor.rs` | run_connection, supervise_tasks, notify_state_core |
| `crates/agenc-ircd-runtime/src/observe/adapter.rs` | snapshot, rate_values |
| `crates/agenc-ircd-client-wire/src/framing.rs` | as_str, feed |
| `crates/agenc-ircd-runtime/src/state_core/fanout.rs` | commit, close_after_flush |
| `crates/agenc-ircd-runtime/src/admin.rs` | ordinary, writer_acknowledges_after_the_final_admin_frame_and_transport_close |

## Entry Points

Start here when exploring this area:

- **`as_bytes`** (Function) — `crates/agenc-ircd-client-wire/src/render.rs:393`
- **`install_observer`** (Function) — `crates/agenc-ircd-runtime/src/admission/transport.rs:61`
- **`reload`** (Function) — `crates/agenc-ircd-runtime/src/admission/transport.rs:73`
- **`failure`** (Function) — `crates/agenc-ircd-runtime/src/bridge/storage.rs:168`
- **`live_children`** (Function) — `crates/agenc-ircd-runtime/src/cancel.rs:92`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `as_bytes` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 393 |
| `install_observer` | Function | `crates/agenc-ircd-runtime/src/admission/transport.rs` | 61 |
| `reload` | Function | `crates/agenc-ircd-runtime/src/admission/transport.rs` | 73 |
| `failure` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 168 |
| `live_children` | Function | `crates/agenc-ircd-runtime/src/cancel.rs` | 92 |
| `closed_reason` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 269 |
| `take_warning` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 275 |
| `push_control` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 282 |
| `is_closed` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 339 |
| `pop` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 346 |
| `next` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 359 |
| `snapshot` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 97 |
| `rate_values` | Function | `crates/agenc-ircd-runtime/src/observe/adapter.rs` | 196 |
| `lock` | Function | `crates/agenc-ircd-runtime/src/sync.rs` | 15 |
| `new` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 67 |
| `backing_charge` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 126 |
| `for_reservation` | Function | `crates/agenc-ircd-runtime/src/connection/sink.rs` | 435 |
| `len` | Function | `crates/agenc-ircd-runtime/src/connection/sink.rs` | 468 |
| `as_str` | Function | `crates/agenc-ircd-client-wire/src/framing.rs` | 86 |
| `feed` | Function | `crates/agenc-ircd-client-wire/src/framing.rs` | 116 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Start → Lock` | cross_community | 3 |
| `Run → Lock` | cross_community | 3 |
| `Account_mutation_waits_for_one_atomic_state_core_commit → Lock` | cross_community | 3 |
| `Confirmed_die_commits_intent_before_requesting_stop → Lock` | cross_community | 3 |
| `Observed_output_waits_for_the_durable_audit_reply → Lock` | cross_community | 3 |
| `Owner_answers_only_bounded_pre_auth_liveness → Lock` | cross_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 10 calls |
| Budget | 9 calls |
| Listener | 6 calls |
| Cluster_313 | 2 calls |
| Cluster_78 | 1 calls |
| Observe | 1 calls |
| Fuzz_targets | 1 calls |

## How to Explore

1. `context({name: "as_bytes"})` — see callers and callees
2. `query({search_query: "connection"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
