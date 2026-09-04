---
name: edge
description: "Skill for the Edge area of agenc-ircd. 89 symbols across 12 files."
---

# Edge

89 symbols | 12 files | Cohesion: 56%

## When to Use

- Working with code in `crates/`
- Understanding how session, channel_by_name, note_phase work
- Modifying edge-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/federation/edge/request.rs` | session_revision, channel_of, operation_of, user_by_nickname, mode_operation (+17) |
| `crates/agenc-ircd-runtime/src/federation/edge/mod.rs` | note_phase, link_established, handle_frame, require_self, companion_barrier_part (+17) |
| `crates/agenc-ircd-runtime/src/federation/edge/barrier.rs` | apply, apply_base_events, identity, base_part, companion_part (+8) |
| `crates/agenc-ircd-runtime/src/federation/edge/sync.rs` | resume_ok, resume_snapshot, snapshot_active, write_install_rows, install_rows (+5) |
| `crates/agenc-ircd-runtime/src/federation/edge/render.rs` | remember_nicknames, event_channel_label, render_event, prefix, channel_name (+2) |
| `crates/agenc-ircd-runtime/src/federation/edge/events.rs` | apply, stage_rows, apply_queued, drain_queued, check_header |
| `crates/agenc-ircd-storage/src/e2ee_records/barrier.rs` | receipt_entry, head_key, part_key |
| `crates/agenc-ircd-domain/src/federation/replica.rs` | session, channel_by_name |
| `crates/agenc-ircd-client-wire/src/registration_command.rs` | validate_tagmsg, validate_message_target |
| `crates/agenc-ircd-client-wire/src/tags.rs` | iter |

## Entry Points

Start here when exploring this area:

- **`session`** (Function) — `crates/agenc-ircd-domain/src/federation/replica.rs:121`
- **`channel_by_name`** (Function) — `crates/agenc-ircd-domain/src/federation/replica.rs:172`
- **`note_phase`** (Function) — `crates/agenc-ircd-runtime/src/federation/edge/mod.rs:376`
- **`resend_pending`** (Function) — `crates/agenc-ircd-runtime/src/federation/edge/request.rs:292`
- **`resume_ok`** (Function) — `crates/agenc-ircd-runtime/src/federation/edge/sync.rs:97`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `session` | Function | `crates/agenc-ircd-domain/src/federation/replica.rs` | 121 |
| `channel_by_name` | Function | `crates/agenc-ircd-domain/src/federation/replica.rs` | 172 |
| `note_phase` | Function | `crates/agenc-ircd-runtime/src/federation/edge/mod.rs` | 376 |
| `resend_pending` | Function | `crates/agenc-ircd-runtime/src/federation/edge/request.rs` | 292 |
| `resume_ok` | Function | `crates/agenc-ircd-runtime/src/federation/edge/sync.rs` | 97 |
| `resume_snapshot` | Function | `crates/agenc-ircd-runtime/src/federation/edge/sync.rs` | 124 |
| `snapshot_active` | Function | `crates/agenc-ircd-runtime/src/federation/edge/sync.rs` | 390 |
| `stage_rows` | Function | `crates/agenc-ircd-runtime/src/federation/edge/events.rs` | 267 |
| `remember_nicknames` | Function | `crates/agenc-ircd-runtime/src/federation/edge/render.rs` | 19 |
| `event_channel_label` | Function | `crates/agenc-ircd-runtime/src/federation/edge/render.rs` | 84 |
| `render_event` | Function | `crates/agenc-ircd-runtime/src/federation/edge/render.rs` | 98 |
| `base_part` | Function | `crates/agenc-ircd-runtime/src/federation/edge/barrier.rs` | 76 |
| `companion_part` | Function | `crates/agenc-ircd-runtime/src/federation/edge/barrier.rs` | 101 |
| `drain_queued` | Function | `crates/agenc-ircd-runtime/src/federation/edge/events.rs` | 127 |
| `companion_barrier_part` | Function | `crates/agenc-ircd-runtime/src/federation/edge/mod.rs` | 321 |
| `iter` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 201 |
| `replay_matches` | Function | `crates/agenc-ircd-runtime/src/e2ee/barrier.rs` | 277 |
| `applied` | Function | `crates/agenc-ircd-runtime/src/federation/edge/barrier.rs` | 433 |
| `receipt_entry` | Function | `crates/agenc-ircd-storage/src/e2ee_records/barrier.rs` | 393 |
| `head_key` | Function | `crates/agenc-ircd-storage/src/e2ee_records/barrier.rs` | 124 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Batch_applied → Link_is` | cross_community | 5 |
| `Batch_applied → Link_closed` | cross_community | 5 |
| `Batch_applied → Timers_mut` | cross_community | 5 |
| `Batch_applied → Cancel` | cross_community | 5 |
| `Batch_applied → Session` | cross_community | 5 |
| `Batch_applied → Channel_detail` | cross_community | 5 |
| `Batch_applied → Membership` | cross_community | 5 |
| `Inbound → CompanionLinkState` | cross_community | 5 |
| `Inbound → New` | cross_community | 5 |
| `Inbound → Compact` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Coordinator | 12 calls |
| State_core | 9 calls |
| Tests | 7 calls |
| Federation | 6 calls |
| Codec | 3 calls |
| E2ee | 3 calls |
| E2ee_records | 2 calls |
| Cluster_426 | 1 calls |

## How to Explore

1. `context({name: "session"})` — see callers and callees
2. `query({search_query: "edge"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
