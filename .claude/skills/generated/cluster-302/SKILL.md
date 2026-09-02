---
name: cluster-302
description: "Skill for the Cluster_302 area of agenc-ircd. 107 symbols across 3 files."
---

# Cluster_302

107 symbols | 3 files | Cohesion: 95%

## When to Use

- Working with code in `crates/`
- Understanding how validate_schema_semantics, try_from_slice, len work
- Modifying cluster_302-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-federation-wire/src/semantics.rs` | validate_schema_semantics, validate_event_schema, validate_operation_schema, validate_result_schema, validate_session_event_identity (+95) |
| `crates/agenc-ircd-types/src/identifiers.rs` | unpadded_base64_len, parse_fixed, parse, parse_wire_bytes |
| `crates/agenc-ircd-types/src/bounded.rs` | try_from_slice, len, try_from_bytes |

## Entry Points

Start here when exploring this area:

- **`validate_schema_semantics`** (Function) — `crates/agenc-ircd-federation-wire/src/semantics.rs:41`
- **`try_from_slice`** (Function) — `crates/agenc-ircd-types/src/bounded.rs:31`
- **`len`** (Function) — `crates/agenc-ircd-types/src/bounded.rs:61`
- **`try_from_bytes`** (Function) — `crates/agenc-ircd-types/src/bounded.rs:95`
- **`parse`** (Function) — `crates/agenc-ircd-types/src/identifiers.rs:253`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `validate_schema_semantics` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 41 |
| `try_from_slice` | Function | `crates/agenc-ircd-types/src/bounded.rs` | 31 |
| `len` | Function | `crates/agenc-ircd-types/src/bounded.rs` | 61 |
| `try_from_bytes` | Function | `crates/agenc-ircd-types/src/bounded.rs` | 95 |
| `parse` | Function | `crates/agenc-ircd-types/src/identifiers.rs` | 253 |
| `parse_wire_bytes` | Function | `crates/agenc-ircd-types/src/identifiers.rs` | 305 |
| `validate_event_schema` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 105 |
| `validate_operation_schema` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 133 |
| `validate_result_schema` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 169 |
| `validate_session_event_identity` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 261 |
| `validate_matching_structure_fields` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 282 |
| `validate_event_projection_consistency` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 376 |
| `decode_event_home_projection` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 409 |
| `validate_projected_mode_channels` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 429 |
| `field` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 481 |
| `unsigned_field` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 494 |
| `opaque_field` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 505 |
| `structure_field` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 516 |
| `vector_field` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 527 |
| `semantic` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 538 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_300 | 3 calls |
| Tests | 1 calls |
| Cluster_296 | 1 calls |

## How to Explore

1. `context({name: "validate_schema_semantics"})` — see callers and callees
2. `query({search_query: "cluster_302"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
