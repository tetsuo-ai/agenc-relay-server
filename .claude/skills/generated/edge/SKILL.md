---
name: edge
description: "Skill for the Edge area of agenc-ircd. 185 symbols across 31 files."
---

# Edge

185 symbols | 31 files | Cohesion: 52%

## When to Use

- Working with code in `crates/`
- Understanding how record, entries, projection_kind work
- Modifying edge-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/federation/edge/mod.rs` | send_frame, batch_applied, fail_companion_link, barrier_ready, companion_active (+27) |
| `crates/agenc-ircd-runtime/src/federation/edge/request.rs` | delete_origin, prepare_request, register_request, send_session_open, send_account_carrier (+18) |
| `crates/agenc-ircd-runtime/src/e2ee/edge/events.rs` | apply_event, route_changed, stage, route_entry, cursor_write (+15) |
| `crates/agenc-ircd-runtime/src/federation/edge/barrier.rs` | acknowledge, applied, send_companion_ack, stage_part, barrier_row (+7) |
| `crates/agenc-ircd-runtime/src/e2ee/edge/router.rs` | line, account, cursor, encode_parameters, encode_ekey (+7) |
| `crates/agenc-ircd-runtime/src/federation/edge/sync.rs` | install_rows, install_row, begin, resume, installed (+6) |
| `crates/agenc-ircd-runtime/src/e2ee/edge/sync.rs` | handle_frames, origins_ready, resend_pending, next_sequence, resume_ok (+6) |
| `crates/agenc-ircd-runtime/src/federation/edge/events.rs` | entry_row, apply, removal_write, apply_queued, drain_queued (+2) |
| `crates/agenc-ircd-runtime/src/registration.rs` | welcome_frames, append_motd, welcome_numerics, e2ee_downgrade_refusal, drive_e2ee (+2) |
| `crates/agenc-ircd-runtime/src/federation/edge/render.rs` | prefix, channel_name, frames_for, mode_text, remember_nicknames (+2) |

## Entry Points

Start here when exploring this area:

- **`record`** (Function) — `crates/agenc-ircd-domain/src/federation/replica.rs:180`
- **`entries`** (Function) — `crates/agenc-ircd-domain/src/federation/replica.rs:203`
- **`projection_kind`** (Function) — `crates/agenc-ircd-runtime/src/federation/codec/projection.rs:13`
- **`projection_arm_object`** (Function) — `crates/agenc-ircd-runtime/src/federation/codec/projection.rs:24`
- **`entry_row`** (Function) — `crates/agenc-ircd-runtime/src/federation/edge/events.rs:229`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `record` | Function | `crates/agenc-ircd-domain/src/federation/replica.rs` | 180 |
| `entries` | Function | `crates/agenc-ircd-domain/src/federation/replica.rs` | 203 |
| `projection_kind` | Function | `crates/agenc-ircd-runtime/src/federation/codec/projection.rs` | 13 |
| `projection_arm_object` | Function | `crates/agenc-ircd-runtime/src/federation/codec/projection.rs` | 24 |
| `entry_row` | Function | `crates/agenc-ircd-runtime/src/federation/edge/events.rs` | 229 |
| `applied` | Function | `crates/agenc-ircd-runtime/src/federation/edge/barrier.rs` | 459 |
| `batch_applied` | Function | `crates/agenc-ircd-runtime/src/federation/edge/mod.rs` | 1014 |
| `delete_origin` | Function | `crates/agenc-ircd-runtime/src/federation/edge/request.rs` | 195 |
| `begin` | Function | `crates/agenc-ircd-runtime/src/federation/edge/sync.rs` | 35 |
| `installed` | Function | `crates/agenc-ircd-runtime/src/federation/edge/sync.rs` | 364 |
| `send_session_open` | Function | `crates/agenc-ircd-runtime/src/federation/edge/request.rs` | 332 |
| `send_account_carrier` | Function | `crates/agenc-ircd-runtime/src/federation/edge/request.rs` | 368 |
| `send_session_close` | Function | `crates/agenc-ircd-runtime/src/federation/edge/request.rs` | 409 |
| `send_command` | Function | `crates/agenc-ircd-runtime/src/federation/edge/request.rs` | 428 |
| `completed` | Function | `crates/agenc-ircd-runtime/src/federation/edge/request.rs` | 937 |
| `numeric_reply` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 827 |
| `direct_route` | Function | `crates/agenc-ircd-domain/src/e2ee/route_table.rs` | 231 |
| `new` | Function | `crates/agenc-ircd-runtime/src/e2ee/edge/mod.rs` | 197 |
| `batch_applied_outputs` | Function | `crates/agenc-ircd-runtime/src/e2ee/edge/mod.rs` | 329 |
| `plaintext_refusal` | Function | `crates/agenc-ircd-runtime/src/e2ee/edge/mod.rs` | 344 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Batch_applied → Len` | cross_community | 5 |
| `Project → Channel_detail_object` | cross_community | 5 |
| `Project → Membership_object` | cross_community | 5 |
| `Project → Invite_projection_object` | cross_community | 5 |
| `Inbound → Profile_active` | cross_community | 5 |
| `Inbound → CompanionLinkState` | cross_community | 5 |
| `Inbound → New` | cross_community | 5 |
| `Batch_applied → Link_is` | cross_community | 5 |
| `Batch_applied → Link_closed` | cross_community | 5 |
| `Batch_applied → Timers_mut` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| State_core | 26 calls |
| Tests | 26 calls |
| Coordinator | 20 calls |
| Federation | 9 calls |
| Ops | 9 calls |
| Wire | 7 calls |
| E2ee | 5 calls |
| Codec | 4 calls |

## How to Explore

1. `context({name: "record"})` — see callers and callees
2. `query({search_query: "edge"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
