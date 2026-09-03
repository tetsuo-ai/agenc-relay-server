---
name: wire
description: "Skill for the Wire area of agenc-ircd. 61 symbols across 10 files."
---

# Wire

61 symbols | 10 files | Cohesion: 81%

## When to Use

- Working with code in `crates/`
- Understanding how parse_companion_frame, canonical_channel_name, parse_id16 work
- Modifying wire-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-e2ee/src/wire/tokens.rs` | parse_id16, parse_hash, parse_account, parse_cursor, parse_decimal (+8) |
| `crates/agenc-ircd-e2ee/src/federation/frames.rs` | correlation, position, fragment, parse_companion_frame, parse_operation (+7) |
| `crates/agenc-ircd-e2ee/src/wire/response.rs` | body, finish_line, render_labeled, render_broadcast, check (+4) |
| `crates/agenc-ircd-e2ee/src/wire/assembly.rs` | release, finish, discard, discard_sender, expire (+3) |
| `crates/agenc-ircd-e2ee/src/wire/command.rs` | channel, parse_egroup, parse_submit, parse_egroup_fetch, parse_ekey (+2) |
| `crates/agenc-ircd-e2ee/src/wire/fragment.rs` | parse, decode_segment, fragment_count, segment_length, check_consistency |
| `crates/agenc-ircd-e2ee/src/wire/carrier.rs` | accepted_kinds, is_live, limit |
| `crates/agenc-ircd-e2ee/src/tests/response.rs` | batches_open_carry_children_and_objects_and_close, live_lines_order_server_tags_before_the_preserved_client_tag |
| `crates/agenc-ircd-e2ee/src/route.rs` | canonical_channel_name |
| `crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/route.rs` | reservation_tbs |

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
| `body` | Function | `crates/agenc-ircd-e2ee/src/wire/response.rs` | 168 |
| `render_labeled` | Function | `crates/agenc-ircd-e2ee/src/wire/response.rs` | 281 |
| `render_broadcast` | Function | `crates/agenc-ircd-e2ee/src/wire/response.rs` | 289 |
| `render` | Function | `crates/agenc-ircd-e2ee/src/wire/response.rs` | 330 |
| `render_close` | Function | `crates/agenc-ircd-e2ee/src/wire/response.rs` | 345 |
| `render_eobject` | Function | `crates/agenc-ircd-e2ee/src/wire/response.rs` | 422 |
| `render_live` | Function | `crates/agenc-ircd-e2ee/src/wire/response.rs` | 469 |
| `is_safe_label` | Function | `crates/agenc-ircd-e2ee/src/wire/tokens.rs` | 181 |
| `is_batch_id` | Function | `crates/agenc-ircd-e2ee/src/wire/tokens.rs` | 187 |
| `discard` | Function | `crates/agenc-ircd-e2ee/src/wire/assembly.rs` | 504 |
| `discard_sender` | Function | `crates/agenc-ircd-e2ee/src/wire/assembly.rs` | 511 |

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
| Tests | 2 calls |
| Budget | 1 calls |
| Cluster_774 | 1 calls |
| Ops | 1 calls |

## How to Explore

1. `context({name: "parse_companion_frame"})` — see callers and callees
2. `query({search_query: "wire"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
