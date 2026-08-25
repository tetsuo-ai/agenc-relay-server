---
name: cluster-20
description: "Skill for the Cluster_20 area of agenc-ircd. 4 symbols across 1 files."
---

# Cluster_20

4 symbols | 1 files | Cohesion: 80%

## When to Use

- Working with code in `crates/`
- Understanding how decode_fixed, decode_variable, encoded_base64_length work
- Modifying cluster_20-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-federation-wire/src/text.rs` | decode_fixed, decode_variable, encoded_base64_length, validate_base64_alphabet |

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `decode_fixed` | Function | `crates/agenc-ircd-federation-wire/src/text.rs` | 123 |
| `decode_variable` | Function | `crates/agenc-ircd-federation-wire/src/text.rs` | 140 |
| `encoded_base64_length` | Function | `crates/agenc-ircd-federation-wire/src/text.rs` | 160 |
| `validate_base64_alphabet` | Function | `crates/agenc-ircd-federation-wire/src/text.rs` | 176 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Parse → Encoded_base64_length` | cross_community | 3 |
| `Parse → Validate_base64_alphabet` | cross_community | 3 |

## How to Explore

1. `context({name: "decode_fixed"})` — see callers and callees
2. `query({search_query: "cluster_20"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
