---
name: cluster-8
description: "Skill for the Cluster_8 area of agenc-ircd. 7 symbols across 1 files."
---

# Cluster_8

7 symbols | 1 files | Cohesion: 60%

## When to Use

- Working with code in `crates/`
- Understanding how validate_decoded_fields, validate_field_semantics, validate_version_field work
- Modifying cluster_8-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-federation-wire/src/codec.rs` | validate_decoded_fields, validate_field_semantics, validate_version_field, validate_padding_field, validate_collection_semantics (+2) |

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `validate_decoded_fields` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 242 |
| `validate_field_semantics` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 394 |
| `validate_version_field` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 404 |
| `validate_padding_field` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 413 |
| `validate_collection_semantics` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 448 |
| `validate_ordered_unique` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 472 |
| `complete_schema_frame` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 858 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Process_vector_frame → Schema_by_name` | cross_community | 7 |
| `Process_vector_frame → Is_optional_fixed` | cross_community | 7 |
| `Validate_mode_change_embedded → Validate_version_field` | cross_community | 7 |
| `Validate_mode_change_embedded → Validate_padding_field` | cross_community | 7 |
| `Collection_key → Validate_version_field` | cross_community | 6 |
| `Collection_key → Validate_padding_field` | cross_community | 6 |
| `Collection_key → Validate_ordered_unique` | cross_community | 6 |
| `Message_target_key → Schema_by_name` | cross_community | 6 |
| `Message_target_key → Is_optional_fixed` | cross_community | 6 |
| `Process_decode_frame → Validate_nested_schema_name` | cross_community | 6 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_3 | 2 calls |
| Cluster_7 | 1 calls |
| Cluster_11 | 1 calls |
| Cluster_9 | 1 calls |

## How to Explore

1. `context({name: "validate_decoded_fields"})` — see callers and callees
2. `query({search_query: "cluster_8"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
