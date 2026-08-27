---
name: cluster-123
description: "Skill for the Cluster_123 area of agenc-ircd. 116 symbols across 4 files."
---

# Cluster_123

116 symbols | 4 files | Cohesion: 97%

## When to Use

- Working with code in `crates/`
- Understanding how decode_one_without_embedded, validate_schema_semantics, validate_embedded_semantics work
- Modifying cluster_123-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-federation-wire/src/semantics.rs` | validate_schema_semantics, validate_event_schema, validate_operation_schema, validate_result_schema, validate_embedded_semantics (+104) |
| `crates/agenc-ircd-types/src/identifiers.rs` | unpadded_base64_len, parse_fixed, parse, parse_wire_bytes |
| `crates/agenc-ircd-federation-wire/src/codec.rs` | remaining, decode_one_without_embedded |
| `crates/agenc-ircd-types/src/bounded.rs` | try_from_bytes |

## Entry Points

Start here when exploring this area:

- **`decode_one_without_embedded`** (Function) — `crates/agenc-ircd-federation-wire/src/codec.rs:1081`
- **`validate_schema_semantics`** (Function) — `crates/agenc-ircd-federation-wire/src/semantics.rs:24`
- **`validate_embedded_semantics`** (Function) — `crates/agenc-ircd-federation-wire/src/semantics.rs:168`
- **`try_from_bytes`** (Function) — `crates/agenc-ircd-types/src/bounded.rs:95`
- **`parse`** (Function) — `crates/agenc-ircd-types/src/identifiers.rs:229`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `decode_one_without_embedded` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 1081 |
| `validate_schema_semantics` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 24 |
| `validate_embedded_semantics` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 168 |
| `try_from_bytes` | Function | `crates/agenc-ircd-types/src/bounded.rs` | 95 |
| `parse` | Function | `crates/agenc-ircd-types/src/identifiers.rs` | 229 |
| `parse_wire_bytes` | Function | `crates/agenc-ircd-types/src/identifiers.rs` | 281 |
| `remaining` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 991 |
| `validate_event_schema` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 88 |
| `validate_operation_schema` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 116 |
| `validate_result_schema` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 152 |
| `validate_optional_schema_embedded` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 199 |
| `validate_session_event_embedded` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 225 |
| `validate_session_event_identity` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 244 |
| `validate_matching_structure_fields` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 265 |
| `validate_discriminated_embedded` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 282 |
| `validate_event_target_binding` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 316 |
| `validate_mode_change_embedded` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 356 |
| `field` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 380 |
| `unsigned_field` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 393 |
| `opaque_field` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 404 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 6 calls |
| Cluster_126 | 1 calls |
| Cluster_118 | 1 calls |
| Cluster_121 | 1 calls |

## How to Explore

1. `context({name: "decode_one_without_embedded"})` — see callers and callees
2. `query({search_query: "cluster_123"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
