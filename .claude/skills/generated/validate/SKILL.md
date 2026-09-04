---
name: validate
description: "Skill for the Validate_ area of agenc-ircd. 79 symbols across 5 files."
---

# Validate_

79 symbols | 5 files | Cohesion: 48%

## When to Use

- Working with code in `crates/`
- Understanding how validate_operation_schema, validate_invite_projection, validate_membership work
- Modifying validate_-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-federation-wire/src/semantics.rs` | validate_operation_schema, validate_invite_projection, validate_membership, validate_query_limit, validate_away_operation (+30) |
| `crates/agenc-ircd-client-wire/src/registration_command.rs` | validate_account_delete, validate_chat_history, validate_single_history_reference, validate_between_history_references, validate_history_reference (+20) |
| `crates/agenc-ircd-runtime/src/offline.rs` | validate_init_paths, validate_lexical_root_separation, validate_edge_descriptor_path, validate_physical_root_separation, validate_existing_file_path (+4) |
| `crates/agenc-ircd-federation-wire/src/codec.rs` | validate_decoded_value, validate_value, validate_bounds, validate_enum, validate_nested_schema (+1) |
| `crates/agenc-ircd-storage/src/construction_runtime.rs` | validate_source_limits, validate_target_limits, validate_work_limits, validate_nonzero_limit |

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `validate_operation_schema` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 133 |
| `validate_invite_projection` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 825 |
| `validate_membership` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 924 |
| `validate_query_limit` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1278 |
| `validate_away_operation` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1282 |
| `validate_channel_mode_operation` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1290 |
| `validate_kick_targets` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1298 |
| `validate_nick_change` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1322 |
| `validate_setname_operation` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1335 |
| `validate_topic_operation` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1343 |
| `validate_user_mode_operation` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1351 |
| `validate_fixed_chunks_ordered_unique` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1368 |
| `validate_nonzero_field` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1453 |
| `validate_event_schema` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 105 |
| `validate_join_target` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 817 |
| `validate_away_fields` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1181 |
| `validate_member_joined_event` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1206 |
| `validate_kicked_event` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1213 |
| `validate_member_parted_event` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1221 |
| `validate_optional_display_name` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1229 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Preview → Validate_bounds` | cross_community | 7 |
| `Internal_restore_scans_reject_duplicate_and_cross_kind_inputs → Validate_nonzero_limit` | cross_community | 6 |
| `Internal_restore_scans_reject_duplicate_and_cross_kind_inputs → Validate_nonzero_usize_limit` | cross_community | 6 |
| `Login_references_and_restore_boundaries_cover_each_exact_arm → Validate_nonzero_limit` | cross_community | 5 |
| `Rebuild_rekey_plan → Validate_nonzero_limit` | cross_community | 4 |
| `Rebuild_rekey_plan → Validate_nonzero_usize_limit` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_422 | 30 calls |
| Federation | 21 calls |
| Cluster_84 | 11 calls |
| Validate_channel | 4 calls |
| Cluster_670 | 3 calls |
| Cluster_100 | 3 calls |
| Cluster_675 | 2 calls |
| Cluster_677 | 1 calls |

## How to Explore

1. `context({name: "validate_operation_schema"})` — see callers and callees
2. `query({search_query: "validate_"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
