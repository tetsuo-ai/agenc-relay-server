---
name: edge
description: "Skill for the Edge area of agenc-ircd. 193 symbols across 36 files."
---

# Edge

193 symbols | 36 files | Cohesion: 52%

## When to Use

- Working with code in `crates/`
- Understanding how peek, decode_kind, decode work
- Modifying edge-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/federation/edge/mod.rs` | send_frame, batch_applied, companion_active, note_phase, link_established (+28) |
| `crates/agenc-ircd-runtime/src/e2ee/edge/events.rs` | on_event_frame, route_changed, route_entry, record_witness, apply_event (+19) |
| `crates/agenc-ircd-runtime/src/federation/edge/request.rs` | delete_origin, prepare_request, register_request, send_session_open, send_account_carrier (+18) |
| `crates/agenc-ircd-runtime/src/e2ee/edge/router.rs` | subject_of, line, account, cursor, encode_parameters (+8) |
| `crates/agenc-ircd-runtime/src/federation/edge/barrier.rs` | acknowledge, applied, apply, apply_base_events, send_companion_ack (+7) |
| `crates/agenc-ircd-runtime/src/e2ee/edge/sync.rs` | origins_ready, resend_pending, handle_frames, fail_frame, next_sequence (+7) |
| `crates/agenc-ircd-runtime/src/federation/edge/sync.rs` | begin, resume, installed, resume_ok, resume_snapshot (+4) |
| `crates/agenc-ircd-runtime/src/federation/edge/render.rs` | remember_nicknames, event_channel_label, render_event, prefix, channel_name (+2) |
| `crates/agenc-ircd-runtime/src/e2ee/edge/mod.rs` | new, batch_applied_outputs, plaintext_refusal, direct_pair_bound, connection_closed (+2) |
| `crates/agenc-ircd-runtime/src/e2ee/edge/result.rs` | decode_value, decode_result, on_result_frame, assemble_response, record_answer (+1) |

## Entry Points

Start here when exploring this area:

- **`peek`** (Function) — `crates/agenc-ircd-e2ee/src/object.rs:266`
- **`decode_kind`** (Function) — `crates/agenc-ircd-e2ee/src/object.rs:288`
- **`decode`** (Function) — `crates/agenc-ircd-runtime/src/e2ee/coordinator/request.rs:379`
- **`on_event_frame`** (Function) — `crates/agenc-ircd-runtime/src/e2ee/edge/events.rs:160`
- **`route_changed`** (Function) — `crates/agenc-ircd-runtime/src/e2ee/edge/events.rs:558`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `peek` | Function | `crates/agenc-ircd-e2ee/src/object.rs` | 266 |
| `decode_kind` | Function | `crates/agenc-ircd-e2ee/src/object.rs` | 288 |
| `decode` | Function | `crates/agenc-ircd-runtime/src/e2ee/coordinator/request.rs` | 379 |
| `on_event_frame` | Function | `crates/agenc-ircd-runtime/src/e2ee/edge/events.rs` | 160 |
| `route_changed` | Function | `crates/agenc-ircd-runtime/src/e2ee/edge/events.rs` | 558 |
| `decode_value` | Function | `crates/agenc-ircd-runtime/src/e2ee/edge/result.rs` | 103 |
| `decode_result` | Function | `crates/agenc-ircd-runtime/src/e2ee/edge/result.rs` | 166 |
| `applied` | Function | `crates/agenc-ircd-runtime/src/federation/edge/barrier.rs` | 459 |
| `batch_applied` | Function | `crates/agenc-ircd-runtime/src/federation/edge/mod.rs` | 1020 |
| `delete_origin` | Function | `crates/agenc-ircd-runtime/src/federation/edge/request.rs` | 195 |
| `begin` | Function | `crates/agenc-ircd-runtime/src/federation/edge/sync.rs` | 35 |
| `installed` | Function | `crates/agenc-ircd-runtime/src/federation/edge/sync.rs` | 364 |
| `send_session_open` | Function | `crates/agenc-ircd-runtime/src/federation/edge/request.rs` | 332 |
| `send_account_carrier` | Function | `crates/agenc-ircd-runtime/src/federation/edge/request.rs` | 368 |
| `send_session_close` | Function | `crates/agenc-ircd-runtime/src/federation/edge/request.rs` | 409 |
| `send_command` | Function | `crates/agenc-ircd-runtime/src/federation/edge/request.rs` | 428 |
| `completed` | Function | `crates/agenc-ircd-runtime/src/federation/edge/request.rs` | 937 |
| `apply` | Function | `crates/agenc-ircd-runtime/src/federation/edge/barrier.rs` | 328 |
| `stage_rows` | Function | `crates/agenc-ircd-runtime/src/federation/edge/events.rs` | 269 |
| `remember_nicknames` | Function | `crates/agenc-ircd-runtime/src/federation/edge/render.rs` | 19 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Origin_state → Take` | cross_community | 6 |
| `Batch_applied → Len` | cross_community | 5 |
| `Origin_state → Remaining` | cross_community | 5 |
| `Origin_state → Len` | cross_community | 5 |
| `Inbound → Profile_active` | cross_community | 5 |
| `Inbound → CompanionLinkState` | cross_community | 5 |
| `Inbound → New` | cross_community | 5 |
| `Batch_applied → Link_is` | cross_community | 5 |
| `Batch_applied → Link_closed` | cross_community | 5 |
| `Batch_applied → Timers_mut` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 26 calls |
| State_core | 24 calls |
| Coordinator | 17 calls |
| Federation | 15 calls |
| Wire | 7 calls |
| Ops | 7 calls |
| E2ee | 5 calls |
| Codec | 3 calls |

## How to Explore

1. `context({name: "peek"})` — see callers and callees
2. `query({search_query: "edge"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
