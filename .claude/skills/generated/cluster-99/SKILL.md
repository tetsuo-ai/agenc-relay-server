---
name: cluster-99
description: "Skill for the Cluster_99 area of agenc-ircd. 11 symbols across 1 files."
---

# Cluster_99

11 symbols | 1 files | Cohesion: 68%

## When to Use

- Working with code in `crates/`
- Understanding how validate_value_storage_capacity, validate_capacity, validate_fields work
- Modifying cluster_99-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-federation-wire/src/codec.rs` | validate_value_storage_capacity, validate_capacity, validate_fields, validate_decoded_value, validate_value (+6) |

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `validate_value_storage_capacity` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 371 |
| `validate_capacity` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 422 |
| `validate_fields` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 466 |
| `validate_decoded_value` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 493 |
| `validate_value` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 527 |
| `validate_bounds` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 578 |
| `validate_nested_schema` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 600 |
| `validate_nested_schema_name` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 605 |
| `encode_fields` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 880 |
| `encode_value` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 892 |
| `encode_length` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 956 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_95 | 1 calls |
| Cluster_101 | 1 calls |
| Cluster_100 | 1 calls |
| Cluster_103 | 1 calls |
| Cluster_92 | 1 calls |

## How to Explore

1. `context({name: "validate_value_storage_capacity"})` — see callers and callees
2. `query({search_query: "cluster_99"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
