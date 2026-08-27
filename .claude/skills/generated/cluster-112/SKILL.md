---
name: cluster-112
description: "Skill for the Cluster_112 area of agenc-ircd. 11 symbols across 2 files."
---

# Cluster_112

11 symbols | 2 files | Cohesion: 76%

## When to Use

- Working with code in `crates/`
- Understanding how bytes work
- Modifying cluster_112-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-federation-wire/src/codec.rs` | claim_bytes, claim_values, validate_enum, read, read_unsigned (+5) |
| `crates/agenc-ircd-federation-wire/src/schema.rs` | bytes |

## Entry Points

Start here when exploring this area:

- **`bytes`** (Function) — `crates/agenc-ircd-federation-wire/src/schema.rs:18`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `bytes` | Function | `crates/agenc-ircd-federation-wire/src/schema.rs` | 18 |
| `claim_bytes` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 113 |
| `claim_values` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 121 |
| `validate_enum` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 588 |
| `read` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 995 |
| `read_unsigned` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 1007 |
| `new_schema_frame` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 1209 |
| `begin_decode_value` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 1260 |
| `read_u64` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 1334 |
| `decode_length` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 1343 |
| `decode_opaque` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 1348 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Begin_decode_value → Read` | intra_community | 3 |
| `Begin_decode_value → Bytes` | intra_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 3 calls |
| Cluster_119 | 1 calls |
| Cluster_121 | 1 calls |

## How to Explore

1. `context({name: "bytes"})` — see callers and callees
2. `query({search_query: "cluster_112"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
