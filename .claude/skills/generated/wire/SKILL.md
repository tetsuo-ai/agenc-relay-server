---
name: wire
description: "Skill for the Wire area of agenc-ircd. 68 symbols across 15 files."
---

# Wire

68 symbols | 15 files | Cohesion: 71%

## When to Use

- Working with code in `crates/`
- Understanding how parse_companion_frame, canonical_channel_name, parse_id16 work
- Modifying wire-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-e2ee/src/wire/tokens.rs` | parse_id16, parse_hash, parse_account, parse_cursor, parse_decimal (+8) |
| `crates/agenc-ircd-e2ee/src/federation/frames.rs` | correlation, position, fragment, parse_companion_frame, parse_operation (+7) |
| `crates/agenc-ircd-e2ee/src/wire/response.rs` | finish_line, check, render, render_close, render_eobject (+4) |
| `crates/agenc-ircd-e2ee/src/wire/assembly.rs` | release, finish, discard, discard_sender, expire (+3) |
| `crates/agenc-ircd-e2ee/src/wire/command.rs` | channel, parse_egroup, parse_submit, parse_egroup_fetch, parse_ekey (+2) |
| `crates/agenc-ircd-e2ee/src/wire/fragment.rs` | parse, decode_segment, fragment_count, segment_length, check_consistency |
| `crates/agenc-ircd-runtime/src/e2ee/edge/result.rs` | render_batch, batch_id_for, render_answer, scalar_line |
| `crates/agenc-ircd-e2ee/src/wire/carrier.rs` | accepted_kinds, is_live, limit |
| `crates/agenc-ircd-e2ee/src/route.rs` | canonical_channel_name |
| `crates/agenc-ircd-e2ee/src/tests/response.rs` | batches_open_carry_children_and_objects_and_close |

## Entry Points

Start here when exploring this area:

- **`parse_companion_frame`** (Function) — `crates/agenc-ircd-e2ee/src/federation/frames.rs:328`
- **`canonical_channel_name`** (Function) — `crates/agenc-ircd-e2ee/src/route.rs:34`
- **`parse_id16`** (Function) — `crates/agenc-ircd-e2ee/src/wire/tokens.rs:119`
- **`parse_hash`** (Function) — `crates/agenc-ircd-e2ee/src/wire/tokens.rs:124`
- **`parse_account`** (Function) — `crates/agenc-ircd-e2ee/src/wire/tokens.rs:129`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `parse_companion_frame` | Function | `crates/agenc-ircd-e2ee/src/federation/frames.rs` | 328 |
| `canonical_channel_name` | Function | `crates/agenc-ircd-e2ee/src/route.rs` | 34 |
| `parse_id16` | Function | `crates/agenc-ircd-e2ee/src/wire/tokens.rs` | 119 |
| `parse_hash` | Function | `crates/agenc-ircd-e2ee/src/wire/tokens.rs` | 124 |
| `parse_account` | Function | `crates/agenc-ircd-e2ee/src/wire/tokens.rs` | 129 |
| `parse_cursor` | Function | `crates/agenc-ircd-e2ee/src/wire/tokens.rs` | 146 |
| `parse_u16` | Function | `crates/agenc-ircd-e2ee/src/wire/tokens.rs` | 165 |
| `parse_u32` | Function | `crates/agenc-ircd-e2ee/src/wire/tokens.rs` | 170 |
| `parse_u64` | Function | `crates/agenc-ircd-e2ee/src/wire/tokens.rs` | 175 |
| `render` | Function | `crates/agenc-ircd-e2ee/src/wire/response.rs` | 348 |
| `render_close` | Function | `crates/agenc-ircd-e2ee/src/wire/response.rs` | 363 |
| `render_eobject` | Function | `crates/agenc-ircd-e2ee/src/wire/response.rs` | 440 |
| `is_batch_id` | Function | `crates/agenc-ircd-e2ee/src/wire/tokens.rs` | 187 |
| `accepted_kinds` | Function | `crates/agenc-ircd-e2ee/src/wire/carrier.rs` | 103 |
| `is_live` | Function | `crates/agenc-ircd-e2ee/src/wire/carrier.rs` | 138 |
| `limit` | Function | `crates/agenc-ircd-e2ee/src/wire/carrier.rs` | 145 |
| `state_entry` | Function | `crates/agenc-ircd-runtime/src/e2ee/edge/sync.rs` | 160 |
| `body` | Function | `crates/agenc-ircd-e2ee/src/wire/response.rs` | 170 |
| `render_labeled` | Function | `crates/agenc-ircd-e2ee/src/wire/response.rs` | 286 |
| `render_broadcast` | Function | `crates/agenc-ircd-e2ee/src/wire/response.rs` | 294 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Run → Try_from` | cross_community | 5 |
| `Origin_state → Kind_slice` | cross_community | 5 |
| `Origin_state → Is_live` | cross_community | 4 |
| `Origin_state → ObjectLimit` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Coordinator | 8 calls |
| Tests | 6 calls |
| State_core | 2 calls |
| Cluster_823 | 2 calls |
| Budget | 1 calls |
| Admission | 1 calls |
| Cluster_825 | 1 calls |
| Ops | 1 calls |

## How to Explore

1. `context({name: "parse_companion_frame"})` — see callers and callees
2. `query({search_query: "wire"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
