---
name: cluster-18
description: "Skill for the Cluster_18 area of agenc-ircd. 5 symbols across 1 files."
---

# Cluster_18

5 symbols | 1 files | Cohesion: 77%

## When to Use

- Working with code in `crates/`
- Understanding how parse, parse_federation_u32, parse_federation_u64 work
- Modifying cluster_18-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-federation-wire/src/text.rs` | parse, parse_federation_u32, parse_federation_u64, parse_decimal, usize_constant |

## Entry Points

Start here when exploring this area:

- **`parse`** (Function) — `crates/agenc-ircd-federation-wire/src/text.rs:71`
- **`parse_federation_u32`** (Function) — `crates/agenc-ircd-federation-wire/src/text.rs:187`
- **`parse_federation_u64`** (Function) — `crates/agenc-ircd-federation-wire/src/text.rs:193`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `parse` | Function | `crates/agenc-ircd-federation-wire/src/text.rs` | 71 |
| `parse_federation_u32` | Function | `crates/agenc-ircd-federation-wire/src/text.rs` | 187 |
| `parse_federation_u64` | Function | `crates/agenc-ircd-federation-wire/src/text.rs` | 193 |
| `parse_decimal` | Function | `crates/agenc-ircd-federation-wire/src/text.rs` | 197 |
| `usize_constant` | Function | `crates/agenc-ircd-federation-wire/src/text.rs` | 408 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Parse → Encoded_base64_length` | cross_community | 3 |
| `Parse → Validate_base64_alphabet` | cross_community | 3 |
| `Parse → Parse_decimal` | intra_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_20 | 2 calls |
| Cluster_21 | 1 calls |

## How to Explore

1. `context({name: "parse"})` — see callers and callees
2. `query({search_query: "cluster_18"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
