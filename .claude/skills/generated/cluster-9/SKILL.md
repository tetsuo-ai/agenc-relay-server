---
name: cluster-9
description: "Skill for the Cluster_9 area of agenc-ircd. 6 symbols across 1 files."
---

# Cluster_9

6 symbols | 1 files | Cohesion: 89%

## When to Use

- Working with code in `crates/`
- Understanding how collection_key, object_value, opaque_value work
- Modifying cluster_9-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-federation-wire/src/codec.rs` | collection_key, object_value, opaque_value, structure_value, unsigned_value (+1) |

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `collection_key` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 493 |
| `object_value` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 518 |
| `opaque_value` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 531 |
| `structure_value` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 538 |
| `unsigned_value` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 548 |
| `message_target_key` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 563 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Collection_key → Validate_nested_schema_name` | cross_community | 7 |
| `Collection_key → Validate_bounds` | cross_community | 6 |
| `Collection_key → Validate_enum` | cross_community | 6 |
| `Collection_key → Validate_version_field` | cross_community | 6 |
| `Collection_key → Validate_padding_field` | cross_community | 6 |
| `Collection_key → Validate_ordered_unique` | cross_community | 6 |
| `Message_target_key → Schema_by_name` | cross_community | 6 |
| `Message_target_key → Is_optional_fixed` | cross_community | 6 |
| `Message_target_key → Semantic` | cross_community | 6 |
| `Collection_key → Object_value` | intra_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_3 | 1 calls |

## How to Explore

1. `context({name: "collection_key"})` — see callers and callees
2. `query({search_query: "cluster_9"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
