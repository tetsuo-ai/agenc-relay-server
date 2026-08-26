---
name: cluster-76
description: "Skill for the Cluster_76 area of agenc-ircd. 8 symbols across 1 files."
---

# Cluster_76

8 symbols | 1 files | Cohesion: 76%

## When to Use

- Working with code in `crates/`
- Understanding how parse, parse_federation_u32, parse_federation_u64 work
- Modifying cluster_76-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-federation-wire/src/text.rs` | parse, parse_federation_u32, parse_federation_u64, parse_decimal, validate_fragment_header (+3) |

## Entry Points

Start here when exploring this area:

- **`parse`** (Function) — `crates/agenc-ircd-federation-wire/src/text.rs:73`
- **`parse_federation_u32`** (Function) — `crates/agenc-ircd-federation-wire/src/text.rs:248`
- **`parse_federation_u64`** (Function) — `crates/agenc-ircd-federation-wire/src/text.rs:254`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `parse` | Function | `crates/agenc-ircd-federation-wire/src/text.rs` | 73 |
| `parse_federation_u32` | Function | `crates/agenc-ircd-federation-wire/src/text.rs` | 248 |
| `parse_federation_u64` | Function | `crates/agenc-ircd-federation-wire/src/text.rs` | 254 |
| `parse_decimal` | Function | `crates/agenc-ircd-federation-wire/src/text.rs` | 258 |
| `validate_fragment_header` | Function | `crates/agenc-ircd-federation-wire/src/text.rs` | 588 |
| `expected_fragment_length` | Function | `crates/agenc-ircd-federation-wire/src/text.rs` | 610 |
| `usize_constant` | Function | `crates/agenc-ircd-federation-wire/src/text.rs` | 624 |
| `u32_constant` | Function | `crates/agenc-ircd-federation-wire/src/text.rs` | 628 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Parse → Encoded_base64_length` | cross_community | 3 |
| `Parse → Validate_base64_alphabet` | cross_community | 3 |
| `Parse → Parse_decimal` | intra_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_78 | 2 calls |
| Cluster_79 | 2 calls |

## How to Explore

1. `context({name: "parse"})` — see callers and callees
2. `query({search_query: "cluster_76"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
