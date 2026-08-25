---
name: cluster-0
description: "Skill for the Cluster_0 area of agenc-ircd. 11 symbols across 1 files."
---

# Cluster_0

11 symbols | 1 files | Cohesion: 92%

## When to Use

- Working with code in `crates/`
- Understanding how parse, as_bytes, parse_u16_decimal work
- Modifying cluster_0-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-client-wire/src/text.rs` | parse, as_bytes, validate_base64_shape, encoded_base64_length, parse_u16_decimal (+6) |

## Entry Points

Start here when exploring this area:

- **`parse`** (Function) — `crates/agenc-ircd-client-wire/src/text.rs:77`
- **`as_bytes`** (Function) — `crates/agenc-ircd-client-wire/src/text.rs:110`
- **`parse_u16_decimal`** (Function) — `crates/agenc-ircd-client-wire/src/text.rs:181`
- **`parse_u32_decimal`** (Function) — `crates/agenc-ircd-client-wire/src/text.rs:187`
- **`parse_u64_decimal`** (Function) — `crates/agenc-ircd-client-wire/src/text.rs:193`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `parse` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 77 |
| `as_bytes` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 110 |
| `parse_u16_decimal` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 181 |
| `parse_u32_decimal` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 187 |
| `parse_u64_decimal` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 193 |
| `validate_base64_shape` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 125 |
| `encoded_base64_length` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 146 |
| `parse_decimal` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 197 |
| `parse_object_id` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 371 |
| `parse_fragment_decimal` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 376 |
| `parse_total_decimal` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 383 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Parse → Parse_decimal` | intra_community | 4 |
| `Parse → Encoded_base64_length` | intra_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 2 calls |

## How to Explore

1. `context({name: "parse"})` — see callers and callees
2. `query({search_query: "cluster_0"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
