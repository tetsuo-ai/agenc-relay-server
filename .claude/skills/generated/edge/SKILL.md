---
name: edge
description: "Skill for the Edge area of agenc-ircd. 93 symbols across 13 files."
---

# Edge

93 symbols | 13 files | Cohesion: 64%

## When to Use

- Working with code in `crates/`
- Understanding how record, entries, projection_kind work
- Modifying edge-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/federation/edge/request.rs` | session_revision, channel_of, operation_of, user_by_nickname, mode_operation (+21) |
| `crates/agenc-ircd-runtime/src/federation/edge/mod.rs` | fail_link, send_frame, batch_applied, batch_rejected, new (+19) |
| `crates/agenc-ircd-runtime/src/federation/edge/render.rs` | line, prefix, actor_prefix, render_event, enabled (+6) |
| `crates/agenc-ircd-runtime/src/federation/edge/sync.rs` | write_install_rows, install_rows, install_row, begin, resume (+5) |
| `crates/agenc-ircd-domain/src/federation/replica.rs` | record, entries, session, channel_by_name, channels_of (+2) |
| `crates/agenc-ircd-runtime/src/federation/edge/events.rs` | removal_write, entry_row, drain_queued, apply, completion_of (+1) |
| `crates/agenc-ircd-runtime/src/federation/coordinator/snapshot.rs` | encode_entry, cut_row, entry_row |
| `crates/agenc-ircd-runtime/src/federation/codec/projection.rs` | projection_kind |
| `crates/agenc-ircd-runtime/src/state_core/durable.rs` | existing |
| `crates/agenc-ircd-storage/src/federation_records.rs` | projection_entry_key |

## Entry Points

Start here when exploring this area:

- **`record`** (Function) — `crates/agenc-ircd-domain/src/federation/replica.rs:180`
- **`entries`** (Function) — `crates/agenc-ircd-domain/src/federation/replica.rs:203`
- **`projection_kind`** (Function) — `crates/agenc-ircd-runtime/src/federation/codec/projection.rs:13`
- **`existing`** (Function) — `crates/agenc-ircd-runtime/src/state_core/durable.rs:325`
- **`projection_entry_key`** (Function) — `crates/agenc-ircd-storage/src/federation_records.rs:871`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `record` | Function | `crates/agenc-ircd-domain/src/federation/replica.rs` | 180 |
| `entries` | Function | `crates/agenc-ircd-domain/src/federation/replica.rs` | 203 |
| `projection_kind` | Function | `crates/agenc-ircd-runtime/src/federation/codec/projection.rs` | 13 |
| `existing` | Function | `crates/agenc-ircd-runtime/src/state_core/durable.rs` | 325 |
| `projection_entry_key` | Function | `crates/agenc-ircd-storage/src/federation_records.rs` | 871 |
| `iter` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 201 |
| `session` | Function | `crates/agenc-ircd-domain/src/federation/replica.rs` | 121 |
| `channel_by_name` | Function | `crates/agenc-ircd-domain/src/federation/replica.rs` | 172 |
| `channels_of` | Function | `crates/agenc-ircd-domain/src/federation/replica.rs` | 195 |
| `entry_count` | Function | `crates/agenc-ircd-domain/src/federation/replica.rs` | 110 |
| `drain_queued` | Function | `crates/agenc-ircd-runtime/src/federation/edge/events.rs` | 76 |
| `batch_applied` | Function | `crates/agenc-ircd-runtime/src/federation/edge/mod.rs` | 662 |
| `batch_rejected` | Function | `crates/agenc-ircd-runtime/src/federation/edge/mod.rs` | 687 |
| `begin` | Function | `crates/agenc-ircd-runtime/src/federation/edge/sync.rs` | 35 |
| `installed` | Function | `crates/agenc-ircd-runtime/src/federation/edge/sync.rs` | 350 |
| `render_event` | Function | `crates/agenc-ircd-runtime/src/federation/edge/render.rs` | 98 |
| `capabilities_for_user` | Function | `crates/agenc-ircd-runtime/src/state_core/session.rs` | 374 |
| `channel` | Function | `crates/agenc-ircd-domain/src/federation/replica.rs` | 127 |
| `stage_rows` | Function | `crates/agenc-ircd-runtime/src/federation/edge/events.rs` | 216 |
| `remember_nicknames` | Function | `crates/agenc-ircd-runtime/src/federation/edge/render.rs` | 19 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Inbound → Network_available` | cross_community | 4 |
| `Project → Projection_kind` | cross_community | 4 |
| `Inbound → LiveLink` | cross_community | 3 |
| `Inbound → Link_is` | intra_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 15 calls |
| State_core | 10 calls |
| Codec | 4 calls |
| Federation | 3 calls |
| Cluster_325 | 1 calls |
| Cluster_408 | 1 calls |
| Fuzz_targets | 1 calls |

## How to Explore

1. `context({name: "record"})` — see callers and callees
2. `query({search_query: "edge"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
