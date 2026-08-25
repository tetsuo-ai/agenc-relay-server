---
name: cluster-14
description: "Skill for the Cluster_14 area of agenc-ircd. 9 symbols across 1 files."
---

# Cluster_14

9 symbols | 1 files | Cohesion: 57%

## When to Use

- Working with code in `crates/`
- Understanding how validate_embedded_semantics work
- Modifying cluster_14-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-federation-wire/src/semantics.rs` | validate_embedded_semantics, validate_optional_schema_embedded, validate_session_event_embedded, validate_discriminated_embedded, validate_mode_change_embedded (+4) |

## Entry Points

Start here when exploring this area:

- **`validate_embedded_semantics`** (Function) — `crates/agenc-ircd-federation-wire/src/semantics.rs:160`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `validate_embedded_semantics` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 160 |
| `validate_optional_schema_embedded` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 191 |
| `validate_session_event_embedded` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 217 |
| `validate_discriminated_embedded` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 274 |
| `validate_mode_change_embedded` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 313 |
| `validate_embedded` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1360 |
| `decode_embedded` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1374 |
| `retain_embedded` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1388 |
| `validate_optional_embedded` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1400 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Validate_mode_change_embedded → Validate_nested_schema_name` | cross_community | 8 |
| `Validate_mode_change_embedded → Validate_bounds` | cross_community | 7 |
| `Validate_mode_change_embedded → Validate_enum` | cross_community | 7 |
| `Validate_mode_change_embedded → Validate_version_field` | cross_community | 7 |
| `Validate_mode_change_embedded → Validate_padding_field` | cross_community | 7 |
| `Process_walk_frame → Retain_embedded` | cross_community | 6 |
| `Process_walk_frame → Field` | cross_community | 6 |
| `Process_walk_frame → Directory_arm` | cross_community | 6 |
| `Process_walk_frame → Event_arm` | cross_community | 6 |
| `Process_object_walk → Projection_arm` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_11 | 10 calls |
| Cluster_3 | 3 calls |
| Cluster_15 | 1 calls |

## How to Explore

1. `context({name: "validate_embedded_semantics"})` — see callers and callees
2. `query({search_query: "cluster_14"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
