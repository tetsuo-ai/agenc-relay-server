---
name: cluster-5
description: "Skill for the Cluster_5 area of agenc-ircd. 9 symbols across 1 files."
---

# Cluster_5

9 symbols | 1 files | Cohesion: 77%

## When to Use

- Working with code in `crates/`
- Understanding how claim_values, decode_schema_iterative, process_decode_frame work
- Modifying cluster_5-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-federation-wire/src/codec.rs` | claim_values, decode_schema_iterative, process_decode_frame, process_schema_frame, advance_schema_frame (+4) |

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `claim_values` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 119 |
| `decode_schema_iterative` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 815 |
| `process_decode_frame` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 834 |
| `process_schema_frame` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 846 |
| `advance_schema_frame` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 882 |
| `process_vector_frame` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 908 |
| `new_schema_frame` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 928 |
| `push_decode_frame` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 951 |
| `deliver_completed_value` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 959 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Process_vector_frame → Validate_nested_schema_name` | cross_community | 7 |
| `Process_vector_frame → Schema_by_name` | cross_community | 7 |
| `Process_vector_frame → Is_optional_fixed` | cross_community | 7 |
| `Process_vector_frame → Semantic` | cross_community | 7 |
| `New_schema_frame → Semantic` | cross_community | 7 |
| `Process_decode_frame → Validate_nested_schema_name` | cross_community | 6 |
| `Process_decode_frame → Validate_bounds` | cross_community | 6 |
| `Process_decode_frame → Validate_version_field` | cross_community | 6 |
| `Process_vector_frame → Validate_bounds` | cross_community | 6 |
| `Process_vector_frame → Validate_enum` | cross_community | 6 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_3 | 2 calls |
| Cluster_8 | 1 calls |
| Cluster_4 | 1 calls |

## How to Explore

1. `context({name: "claim_values"})` — see callers and callees
2. `query({search_query: "cluster_5"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
