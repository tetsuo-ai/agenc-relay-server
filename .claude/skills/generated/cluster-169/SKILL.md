---
name: cluster-169
description: "Skill for the Cluster_169 area of agenc-ircd. 17 symbols across 2 files."
---

# Cluster_169

17 symbols | 2 files | Cohesion: 76%

## When to Use

- Working with code in `crates/`
- Understanding how validate_fields, validate_decoded_fields, validate_decoded_value work
- Modifying cluster_169-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-federation-wire/src/codec.rs` | validate_fields, validate_decoded_fields, validate_decoded_value, validate_value, validate_enum (+11) |
| `crates/agenc-ircd-federation-wire/src/semantics.rs` | validate_schema |

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `validate_fields` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 485 |
| `validate_decoded_fields` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 497 |
| `validate_decoded_value` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 512 |
| `validate_value` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 546 |
| `validate_enum` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 607 |
| `validate_nested_schema` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 619 |
| `validate_nested_schema_name` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 624 |
| `validate_field_semantics` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 649 |
| `validate_version_field` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 659 |
| `validate_padding_field` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 668 |
| `validate_collection_semantics` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 703 |
| `validate_ordered_unique` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 727 |
| `encode_fields` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 899 |
| `encode_value` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 911 |
| `encode_length` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 975 |
| `complete_schema_frame` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 1161 |
| `validate_schema` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 26 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 3 calls |
| Cluster_173 | 1 calls |
| Cluster_170 | 1 calls |
| Cluster_164 | 1 calls |

## How to Explore

1. `context({name: "validate_fields"})` — see callers and callees
2. `query({search_query: "cluster_169"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
