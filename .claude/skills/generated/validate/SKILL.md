---
name: validate
description: "Skill for the Validate_ area of agenc-ircd. 23 symbols across 1 files."
---

# Validate_

23 symbols | 1 files | Cohesion: 49%

## When to Use

- Working with code in `crates/`
- Understanding how validate_operation_schema, validate_invite_projection, validate_membership work
- Modifying validate_-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-federation-wire/src/semantics.rs` | validate_operation_schema, validate_invite_projection, validate_membership, validate_away_operation, validate_channel_mode_operation (+18) |

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `validate_operation_schema` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 108 |
| `validate_invite_projection` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 681 |
| `validate_membership` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 780 |
| `validate_away_operation` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1105 |
| `validate_channel_mode_operation` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1113 |
| `validate_kick_targets` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1121 |
| `validate_nick_change` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1145 |
| `validate_setname_operation` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1158 |
| `validate_topic_operation` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1166 |
| `validate_user_mode_operation` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1174 |
| `validate_fixed_chunks_ordered_unique` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1191 |
| `validate_mode_vector` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1202 |
| `validate_nonzero_field` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1274 |
| `validate_event_schema` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 80 |
| `validate_away_fields` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1006 |
| `validate_member_joined_event` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1031 |
| `validate_kicked_event` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1038 |
| `validate_member_parted_event` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1046 |
| `validate_optional_display_name` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1054 |
| `validate_network_notice` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1062 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `New_schema_frame → Semantic` | cross_community | 7 |
| `New → Semantic` | cross_community | 6 |
| `Validate_mode_change → New` | cross_community | 6 |
| `Validate_mode_change → Len` | cross_community | 6 |
| `Validate_schema_semantics → Field` | cross_community | 5 |
| `Validate_operation_schema → Field` | cross_community | 5 |
| `Validate_operation_schema → Len` | cross_community | 5 |
| `Validate_event_schema → Len` | cross_community | 5 |
| `Validate_session_hidden → New` | cross_community | 5 |
| `Validate_session_hidden → Len` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_11 | 32 calls |
| Cluster_16 | 1 calls |
| Cluster_30 | 1 calls |

## How to Explore

1. `context({name: "validate_operation_schema"})` — see callers and callees
2. `query({search_query: "validate_"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
