---
name: codec
description: "Skill for the Codec area of agenc-ircd. 101 symbols across 21 files."
---

# Codec

101 symbols | 21 files | Cohesion: 84%

## When to Use

- Working with code in `crates/`
- Understanding how as_slice, decode_exact, from_object work
- Modifying codec-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/federation/codec/mod.rs` | presence_of, revision_of, generation_of, utc_of, owned_text (+26) |
| `crates/agenc-ircd-federation-wire/src/objects.rs` | from_object, decode, decode_request_operation, decode_result_arm, decode_event_arm (+17) |
| `crates/agenc-ircd-runtime/src/federation/codec/operations.rs` | from_object, session_of, mode_changes_of, join_targets_of, part_of (+3) |
| `crates/agenc-ircd-runtime/src/federation/coordinator/convert.rs` | directory_schema, rebuild_query, directory_query, nicknames_of, channel_names_of (+3) |
| `crates/agenc-ircd-runtime/src/federation/codec/events.rs` | channel_of, union_of, mode_changes_of, invited_of, topic_of (+2) |
| `crates/agenc-ircd-runtime/src/federation/codec/results.rs` | from_object, reply_parts_of, kind, to_object |
| `crates/agenc-ircd-runtime/src/federation/coordinator/startup.rs` | admit, admit_origin, admit_marker, admit_entry |
| `crates/agenc-ircd-runtime/src/federation/codec/projection.rs` | projection_record_of, projection_arm_object |
| `crates/agenc-ircd-runtime/src/federation/coordinator/request.rs` | execute, encode_result |
| `crates/agenc-ircd-runtime/src/federation/edge/request.rs` | receive_result, reply_frame |

## Entry Points

Start here when exploring this area:

- **`as_slice`** (Function) — `crates/agenc-ircd-federation-wire/src/assembly.rs:111`
- **`decode_exact`** (Function) — `crates/agenc-ircd-federation-wire/src/codec.rs:390`
- **`from_object`** (Function) — `crates/agenc-ircd-federation-wire/src/objects.rs:168`
- **`decode`** (Function) — `crates/agenc-ircd-federation-wire/src/objects.rs:233`
- **`decode_request_operation`** (Function) — `crates/agenc-ircd-federation-wire/src/objects.rs:328`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `as_slice` | Function | `crates/agenc-ircd-federation-wire/src/assembly.rs` | 111 |
| `decode_exact` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 390 |
| `from_object` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 168 |
| `decode` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 233 |
| `decode_request_operation` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 328 |
| `decode_result_arm` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 408 |
| `decode_event_arm` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 560 |
| `decode_projection_arm` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 742 |
| `of` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 767 |
| `operation_schema_name` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 836 |
| `result_schema_name` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 868 |
| `projection_schema_name` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 913 |
| `expect_schema` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1027 |
| `field` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1035 |
| `opaque_field` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1046 |
| `structure` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1054 |
| `projection_union` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1062 |
| `unsigned` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1084 |
| `unsigned_u16` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1092 |
| `unsigned_u32` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 1097 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Projected_event_of → Schema` | intra_community | 6 |
| `Projected_event_of → Field` | intra_community | 5 |
| `Project → Channel_detail_object` | cross_community | 5 |
| `Project → Membership_object` | cross_community | 5 |
| `From_object → Field` | intra_community | 4 |
| `Projected_event_of → SourceView` | intra_community | 4 |
| `From_object → Schema` | intra_community | 3 |
| `From_object → Schema` | intra_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 19 calls |
| Coordinator | 15 calls |
| Edge | 6 calls |
| State_core | 4 calls |
| Federation | 3 calls |
| Cluster_835 | 2 calls |
| Cluster_210 | 1 calls |
| Cluster_422 | 1 calls |

## How to Explore

1. `context({name: "as_slice"})` — see callers and callees
2. `query({search_query: "codec"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
