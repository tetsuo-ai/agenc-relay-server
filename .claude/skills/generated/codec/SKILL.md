---
name: codec
description: "Skill for the Codec area of agenc-ircd. 67 symbols across 10 files."
---

# Codec

67 symbols | 10 files | Cohesion: 83%

## When to Use

- Working with code in `crates/`
- Understanding how expect_schema, field, opaque_field work
- Modifying codec-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/federation/codec/mod.rs` | presence_of, revision_of, generation_of, utc_of, owned_text (+25) |
| `crates/agenc-ircd-federation-wire/src/objects.rs` | replay_key, expect_schema, field, opaque_field, structure (+8) |
| `crates/agenc-ircd-runtime/src/federation/codec/operations.rs` | from_object, session_of, mode_changes_of, join_targets_of, part_of (+3) |
| `crates/agenc-ircd-runtime/src/federation/codec/events.rs` | channel_of, union_of, mode_changes_of, invited_of, topic_of (+2) |
| `crates/agenc-ircd-runtime/src/federation/codec/results.rs` | from_object, reply_parts_of, kind, to_object |
| `crates/agenc-ircd-runtime/src/federation/codec/projection.rs` | projection_record_of |
| `crates/agenc-ircd-runtime/src/federation/coordinator/convert.rs` | nickname_field |
| `crates/agenc-ircd-runtime/src/federation/coordinator/mod.rs` | encode_object |
| `crates/agenc-ircd-runtime/src/federation/coordinator/request.rs` | encode_result |
| `crates/agenc-ircd-runtime/src/federation/codec/tests/round_trip.rs` | every_simple_operation_arm_round_trips |

## Entry Points

Start here when exploring this area:

- **`expect_schema`** (Function) — `crates/agenc-ircd-federation-wire/src/objects.rs:1027`
- **`field`** (Function) — `crates/agenc-ircd-federation-wire/src/objects.rs:1035`
- **`opaque_field`** (Function) — `crates/agenc-ircd-federation-wire/src/objects.rs:1046`
- **`structure`** (Function) — `crates/agenc-ircd-federation-wire/src/objects.rs:1054`
- **`projection_union`** (Function) — `crates/agenc-ircd-federation-wire/src/objects.rs:1062`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `expect_schema` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1027 |
| `field` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1035 |
| `opaque_field` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1046 |
| `structure` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1054 |
| `projection_union` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1062 |
| `unsigned` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1084 |
| `unsigned_u16` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1092 |
| `unsigned_u32` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1097 |
| `fixed` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1102 |
| `optional_fixed` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1112 |
| `projected_event_of` | Function | `crates/agenc-ircd-runtime/src/federation/codec/events.rs` | 443 |
| `nickname_of` | Function | `crates/agenc-ircd-runtime/src/federation/codec/mod.rs` | 118 |
| `source_view_of` | Function | `crates/agenc-ircd-runtime/src/federation/codec/mod.rs` | 176 |
| `session_projection_of` | Function | `crates/agenc-ircd-runtime/src/federation/codec/mod.rs` | 213 |
| `session_event_view_of` | Function | `crates/agenc-ircd-runtime/src/federation/codec/mod.rs` | 256 |
| `channel_detail_of` | Function | `crates/agenc-ircd-runtime/src/federation/codec/mod.rs` | 387 |
| `membership_of` | Function | `crates/agenc-ircd-runtime/src/federation/codec/mod.rs` | 454 |
| `membership_view_of` | Function | `crates/agenc-ircd-runtime/src/federation/codec/mod.rs` | 475 |
| `invite_projection_of` | Function | `crates/agenc-ircd-runtime/src/federation/codec/mod.rs` | 519 |
| `account_projection_of` | Function | `crates/agenc-ircd-runtime/src/federation/codec/mod.rs` | 544 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Projected_event_of → Schema` | intra_community | 6 |
| `Projected_event_of → Field` | intra_community | 5 |
| `From_object → Field` | intra_community | 4 |
| `Projected_event_of → SourceView` | intra_community | 4 |
| `From_object → Schema` | intra_community | 3 |
| `From_object → Schema` | intra_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 11 calls |
| Coordinator | 4 calls |
| Federation | 2 calls |
| State_core | 1 calls |
| Cluster_447 | 1 calls |
| Cluster_954 | 1 calls |

## How to Explore

1. `context({name: "expect_schema"})` — see callers and callees
2. `query({search_query: "codec"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
