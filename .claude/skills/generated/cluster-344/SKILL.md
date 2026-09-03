---
name: cluster-344
description: "Skill for the Cluster_344 area of agenc-ircd. 49 symbols across 1 files."
---

# Cluster_344

49 symbols | 1 files | Cohesion: 62%

## When to Use

- Working with code in `crates/`
- Understanding how validate_schema_semantics work
- Modifying cluster_344-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-federation-wire/src/semantics.rs` | validate_schema_semantics, validate_result_schema, validate_matching_structure_fields, structure_field, semantic (+44) |

## Entry Points

Start here when exploring this area:

- **`validate_schema_semantics`** (Function) — `crates/agenc-ircd-federation-wire/src/semantics.rs:41`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `validate_schema_semantics` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 41 |
| `validate_result_schema` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 169 |
| `validate_matching_structure_fields` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 282 |
| `structure_field` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 516 |
| `semantic` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 538 |
| `validate_normalized_login` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 545 |
| `validate_credential_change_start` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 555 |
| `validate_creation_invite` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 562 |
| `validate_account_challenge` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 575 |
| `validate_account_completion` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 583 |
| `validate_account_projection` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 597 |
| `validate_padding_shape` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 606 |
| `validate_account_setting` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 621 |
| `validate_account_service_operation` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 644 |
| `validate_directory_cursor` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 662 |
| `validate_channel_detail` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 686 |
| `validate_channel_detail_names` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 700 |
| `parsed_channel_name` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 716 |
| `validate_channel_name` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 722 |
| `validate_client_tag` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 732 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_327 | 56 calls |
| Validate_ | 14 calls |
| Federation | 4 calls |

## How to Explore

1. `context({name: "validate_schema_semantics"})` — see callers and callees
2. `query({search_query: "cluster_344"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
