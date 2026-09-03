---
name: codec
description: "Skill for the Codec area of agenc-ircd. 109 symbols across 15 files."
---

# Codec

109 symbols | 15 files | Cohesion: 82%

## When to Use

- Working with code in `crates/`
- Understanding how of, projection_schema_name, expect_schema work
- Modifying codec-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/federation/codec/mod.rs` | presence_of, revision_of, generation_of, utc_of, owned_text (+38) |
| `crates/agenc-ircd-federation-wire/src/objects.rs` | of, concat_fixed, projection_schema_name, replay_key, expect_schema (+14) |
| `crates/agenc-ircd-runtime/src/federation/codec/events.rs` | optional_revision, channel_of, union_of, mode_changes_of, invited_of (+6) |
| `crates/agenc-ircd-runtime/src/federation/codec/operations.rs` | from_object, session_of, channel_of, mode_changes_of, join_targets_of (+6) |
| `crates/agenc-ircd-runtime/src/federation/coordinator/convert.rs` | directory_schema, rebuild_query, directory_query, nicknames_of, channel_names_of (+3) |
| `crates/agenc-ircd-runtime/src/federation/codec/results.rs` | from_object, reply_parts_of, reply_object, kind, to_object |
| `crates/agenc-ircd-runtime/src/federation/codec/projection.rs` | projection_record_of, projection_arm_object |
| `crates/agenc-ircd-client-wire/src/render.rs` | measure, combined_tag_section |
| `crates/agenc-ircd-runtime/src/federation/codec/tests/round_trip.rs` | operations, every_simple_operation_arm_round_trips |
| `crates/agenc-ircd-runtime/src/account_service.rs` | encoded |

## Entry Points

Start here when exploring this area:

- **`of`** (Function) — `crates/agenc-ircd-federation-wire/src/objects.rs:758`
- **`projection_schema_name`** (Function) — `crates/agenc-ircd-federation-wire/src/objects.rs:904`
- **`expect_schema`** (Function) — `crates/agenc-ircd-federation-wire/src/objects.rs:1018`
- **`field`** (Function) — `crates/agenc-ircd-federation-wire/src/objects.rs:1026`
- **`opaque_field`** (Function) — `crates/agenc-ircd-federation-wire/src/objects.rs:1037`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `of` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 758 |
| `projection_schema_name` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 904 |
| `expect_schema` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1018 |
| `field` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1026 |
| `opaque_field` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1037 |
| `structure` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1045 |
| `projection_union` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1053 |
| `vector` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1067 |
| `unsigned` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1075 |
| `unsigned_u16` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1083 |
| `unsigned_u32` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1088 |
| `fixed` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1093 |
| `optional_fixed` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1103 |
| `text` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1117 |
| `projected_event_of` | Function | `crates/agenc-ircd-runtime/src/federation/codec/events.rs` | 443 |
| `nickname_of` | Function | `crates/agenc-ircd-runtime/src/federation/codec/mod.rs` | 118 |
| `channel_name_of` | Function | `crates/agenc-ircd-runtime/src/federation/codec/mod.rs` | 127 |
| `source_view_of` | Function | `crates/agenc-ircd-runtime/src/federation/codec/mod.rs` | 176 |
| `session_projection_of` | Function | `crates/agenc-ircd-runtime/src/federation/codec/mod.rs` | 213 |
| `session_event_view_of` | Function | `crates/agenc-ircd-runtime/src/federation/codec/mod.rs` | 256 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `From_object → Unpadded_base64_len` | cross_community | 6 |
| `Projected_event_of → Schema` | intra_community | 6 |
| `Projected_event_of → Field` | intra_community | 5 |
| `Project → Kind` | cross_community | 5 |
| `Project → Membership_view_object` | cross_community | 5 |
| `Project → Channel_detail_object` | cross_community | 5 |
| `From_object → Field` | intra_community | 4 |
| `From_object → Field` | intra_community | 4 |
| `Projected_event_of → SourceView` | intra_community | 4 |
| `From_object → Schema` | intra_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 14 calls |
| State_core | 6 calls |
| Federation | 2 calls |
| Cluster_190 | 1 calls |
| Cluster_103 | 1 calls |
| Cluster_88 | 1 calls |
| Cluster_231 | 1 calls |
| Cluster_36 | 1 calls |

## How to Explore

1. `context({name: "of"})` — see callers and callees
2. `query({search_query: "codec"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
