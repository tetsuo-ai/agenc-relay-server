---
name: cluster-3
description: "Skill for the Cluster_3 area of agenc-ircd. 8 symbols across 2 files."
---

# Cluster_3

8 symbols | 2 files | Cohesion: 45%

## When to Use

- Working with code in `crates/`
- Understanding how new, decode_one_without_embedded, schema_by_name work
- Modifying cluster_3-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-federation-wire/src/codec.rs` | new, base_object_limit, is_optional_fixed, validate_optional_fixed_field, copy_key (+2) |
| `crates/agenc-ircd-federation-wire/src/schema.rs` | schema_by_name |

## Entry Points

Start here when exploring this area:

- **`new`** (Function) — `crates/agenc-ircd-federation-wire/src/codec.rs:92`
- **`decode_one_without_embedded`** (Function) — `crates/agenc-ircd-federation-wire/src/codec.rs:797`
- **`schema_by_name`** (Function) — `crates/agenc-ircd-federation-wire/src/schema.rs:107`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `new` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 92 |
| `decode_one_without_embedded` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 797 |
| `schema_by_name` | Function | `crates/agenc-ircd-federation-wire/src/schema.rs` | 107 |
| `base_object_limit` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 226 |
| `is_optional_fixed` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 376 |
| `validate_optional_fixed_field` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 422 |
| `copy_key` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 555 |
| `remaining` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 732 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Validate_mode_change_embedded → Validate_nested_schema_name` | cross_community | 8 |
| `Collection_key → Validate_nested_schema_name` | cross_community | 7 |
| `Process_vector_frame → Validate_nested_schema_name` | cross_community | 7 |
| `Process_vector_frame → Schema_by_name` | cross_community | 7 |
| `Process_vector_frame → Is_optional_fixed` | cross_community | 7 |
| `Process_vector_frame → Semantic` | cross_community | 7 |
| `Validate_invite_event_embedded → Validate_nested_schema_name` | cross_community | 7 |
| `Validate_projected_mode_embedded → Validate_nested_schema_name` | cross_community | 7 |
| `New_schema_frame → Semantic` | cross_community | 7 |
| `Validate_mode_change_embedded → Validate_bounds` | cross_community | 7 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_7 | 2 calls |
| Tests | 1 calls |
| Cluster_5 | 1 calls |

## How to Explore

1. `context({name: "new"})` — see callers and callees
2. `query({search_query: "cluster_3"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
