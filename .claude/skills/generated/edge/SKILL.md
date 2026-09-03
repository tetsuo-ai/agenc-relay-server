---
name: edge
description: "Skill for the Edge area of agenc-ircd. 87 symbols across 10 files."
---

# Edge

87 symbols | 10 files | Cohesion: 63%

## When to Use

- Working with code in `crates/`
- Understanding how iter, session, channel_by_name work
- Modifying edge-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/federation/edge/request.rs` | session_revision, channel_of, operation_of, user_by_nickname, mode_operation (+21) |
| `crates/agenc-ircd-runtime/src/federation/edge/mod.rs` | connection_opened, session_bound, origin_descriptor, link_closed, fail_link (+20) |
| `crates/agenc-ircd-runtime/src/federation/edge/render.rs` | line, prefix, actor_prefix, channel_name, event_channel_label (+6) |
| `crates/agenc-ircd-runtime/src/federation/edge/sync.rs` | write_install_rows, install_rows, install_row, resume_ok, snapshot_active (+5) |
| `crates/agenc-ircd-domain/src/federation/replica.rs` | session, channel_by_name, channels_of, channel, record (+1) |
| `crates/agenc-ircd-runtime/src/federation/edge/events.rs` | apply, completion_of, entry_row, stage_rows, drain_queued |
| `crates/agenc-ircd-client-wire/src/tags.rs` | iter |
| `crates/agenc-ircd-runtime/src/state_core/session.rs` | capabilities_for_user |
| `crates/agenc-ircd-federation-wire/src/objects.rs` | to_object |
| `crates/agenc-ircd-runtime/src/federation/codec/projection.rs` | projection_kind |

## Entry Points

Start here when exploring this area:

- **`iter`** (Function) — `crates/agenc-ircd-client-wire/src/tags.rs:201`
- **`session`** (Function) — `crates/agenc-ircd-domain/src/federation/replica.rs:121`
- **`channel_by_name`** (Function) — `crates/agenc-ircd-domain/src/federation/replica.rs:172`
- **`channels_of`** (Function) — `crates/agenc-ircd-domain/src/federation/replica.rs:195`
- **`channel`** (Function) — `crates/agenc-ircd-domain/src/federation/replica.rs:127`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `iter` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 201 |
| `session` | Function | `crates/agenc-ircd-domain/src/federation/replica.rs` | 121 |
| `channel_by_name` | Function | `crates/agenc-ircd-domain/src/federation/replica.rs` | 172 |
| `channels_of` | Function | `crates/agenc-ircd-domain/src/federation/replica.rs` | 195 |
| `channel` | Function | `crates/agenc-ircd-domain/src/federation/replica.rs` | 127 |
| `event_channel_label` | Function | `crates/agenc-ircd-runtime/src/federation/edge/render.rs` | 84 |
| `render_event` | Function | `crates/agenc-ircd-runtime/src/federation/edge/render.rs` | 98 |
| `capabilities_for_user` | Function | `crates/agenc-ircd-runtime/src/state_core/session.rs` | 374 |
| `record` | Function | `crates/agenc-ircd-domain/src/federation/replica.rs` | 180 |
| `entries` | Function | `crates/agenc-ircd-domain/src/federation/replica.rs` | 203 |
| `remember_nicknames` | Function | `crates/agenc-ircd-runtime/src/federation/edge/render.rs` | 19 |
| `to_object` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 149 |
| `connection_opened` | Function | `crates/agenc-ircd-runtime/src/federation/edge/mod.rs` | 543 |
| `session_bound` | Function | `crates/agenc-ircd-runtime/src/federation/edge/mod.rs` | 659 |
| `declare_origin` | Function | `crates/agenc-ircd-runtime/src/federation/edge/request.rs` | 116 |
| `projection_kind` | Function | `crates/agenc-ircd-runtime/src/federation/codec/projection.rs` | 13 |
| `stage_rows` | Function | `crates/agenc-ircd-runtime/src/federation/edge/events.rs` | 216 |
| `drain_queued` | Function | `crates/agenc-ircd-runtime/src/federation/edge/events.rs` | 76 |
| `batch_rejected` | Function | `crates/agenc-ircd-runtime/src/federation/edge/mod.rs` | 720 |
| `new` | Function | `crates/agenc-ircd-runtime/src/federation/edge/mod.rs` | 181 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Project → Projection_kind` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 13 calls |
| State_core | 8 calls |
| Federation | 3 calls |
| Codec | 3 calls |
| Coordinator | 3 calls |
| Cluster_329 | 1 calls |
| Cluster_415 | 1 calls |
| Fuzz_targets | 1 calls |

## How to Explore

1. `context({name: "iter"})` — see callers and callees
2. `query({search_query: "edge"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
