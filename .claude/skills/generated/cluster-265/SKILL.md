---
name: cluster-265
description: "Skill for the Cluster_265 area of agenc-ircd. 104 symbols across 2 files."
---

# Cluster_265

104 symbols | 2 files | Cohesion: 95%

## When to Use

- Working with code in `crates/`
- Understanding how validate_schema_semantics, parse, parse_wire_bytes work
- Modifying cluster_265-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-federation-wire/src/semantics.rs` | validate_schema_semantics, validate_event_schema, validate_operation_schema, validate_result_schema, validate_session_event_identity (+95) |
| `crates/agenc-ircd-types/src/identifiers.rs` | unpadded_base64_len, parse_fixed, parse, parse_wire_bytes |

## Entry Points

Start here when exploring this area:

- **`validate_schema_semantics`** (Function) — `crates/agenc-ircd-federation-wire/src/semantics.rs:41`
- **`parse`** (Function) — `crates/agenc-ircd-types/src/identifiers.rs:253`
- **`parse_wire_bytes`** (Function) — `crates/agenc-ircd-types/src/identifiers.rs:305`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `validate_schema_semantics` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 41 |
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
| `validate_normalized_login` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 545 |
| `validate_credential_change_start` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 555 |
| `validate_creation_invite` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 562 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_263 | 3 calls |
| Tests | 2 calls |
| Cluster_259 | 1 calls |

## How to Explore

1. `context({name: "validate_schema_semantics"})` — see callers and callees
2. `query({search_query: "cluster_265"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
