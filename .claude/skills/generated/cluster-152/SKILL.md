---
name: cluster-152
description: "Skill for the Cluster_152 area of agenc-ircd. 15 symbols across 2 files."
---

# Cluster_152

15 symbols | 2 files | Cohesion: 63%

## When to Use

- Working with code in `crates/`
- Understanding how decode_one_without_embedded, validate_embedded_semantics work
- Modifying cluster_152-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-federation-wire/src/semantics.rs` | validate_embedded_semantics, validate_optional_schema_embedded, validate_session_event_embedded, validate_discriminated_embedded, validate_event_target_binding (+8) |
| `crates/agenc-ircd-federation-wire/src/codec.rs` | remaining, decode_one_without_embedded |

## Entry Points

Start here when exploring this area:

- **`decode_one_without_embedded`** (Function) — `crates/agenc-ircd-federation-wire/src/codec.rs:1100`
- **`validate_embedded_semantics`** (Function) — `crates/agenc-ircd-federation-wire/src/semantics.rs:185`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `decode_one_without_embedded` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 1100 |
| `validate_embedded_semantics` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 185 |
| `remaining` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 1010 |
| `validate_optional_schema_embedded` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 216 |
| `validate_session_event_embedded` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 242 |
| `validate_discriminated_embedded` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 299 |
| `validate_event_target_binding` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 334 |
| `event_projection_home_server` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 349 |
| `validate_mode_change_embedded` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 457 |
| `validate_embedded` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1539 |
| `decode_embedded` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1553 |
| `retain_embedded` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1567 |
| `validate_optional_embedded` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1579 |
| `validate_projected_mode_embedded` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1646 |
| `validate_projected_limit` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 1684 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_154 | 17 calls |
| Tests | 4 calls |
| Cluster_155 | 1 calls |

## How to Explore

1. `context({name: "decode_one_without_embedded"})` — see callers and callees
2. `query({search_query: "cluster_152"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
