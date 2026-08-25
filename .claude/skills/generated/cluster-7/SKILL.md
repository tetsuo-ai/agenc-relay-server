---
name: cluster-7
description: "Skill for the Cluster_7 area of agenc-ircd. 13 symbols across 1 files."
---

# Cluster_7

13 symbols | 1 files | Cohesion: 77%

## When to Use

- Working with code in `crates/`
- Understanding how encoded_len work
- Modifying cluster_7-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-federation-wire/src/codec.rs` | encoded_len, encode_canonical, validate_fields, validate_decoded_value, validate_value (+8) |

## Entry Points

Start here when exploring this area:

- **`encoded_len`** (Function) — `crates/agenc-ircd-federation-wire/src/codec.rs:194`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `encoded_len` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 194 |
| `encode_canonical` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 206 |
| `validate_fields` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 230 |
| `validate_decoded_value` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 257 |
| `validate_value` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 291 |
| `validate_bounds` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 342 |
| `validate_nested_schema` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 364 |
| `validate_nested_schema_name` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 369 |
| `encoded_fields_len` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 576 |
| `encoded_value_len` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 590 |
| `encode_fields` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 621 |
| `encode_value` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 633 |
| `encode_length` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 697 |

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
| Cluster_8 | 2 calls |
| Cluster_3 | 1 calls |
| Cluster_11 | 1 calls |
| Cluster_4 | 1 calls |

## How to Explore

1. `context({name: "encoded_len"})` — see callers and callees
2. `query({search_query: "cluster_7"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
