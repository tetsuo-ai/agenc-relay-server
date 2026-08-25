---
name: cluster-4
description: "Skill for the Cluster_4 area of agenc-ircd. 9 symbols across 2 files."
---

# Cluster_4

9 symbols | 2 files | Cohesion: 73%

## When to Use

- Working with code in `crates/`
- Understanding how bytes work
- Modifying cluster_4-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-federation-wire/src/codec.rs` | claim_bytes, validate_enum, read, read_unsigned, begin_decode_value (+3) |
| `crates/agenc-ircd-federation-wire/src/schema.rs` | bytes |

## Entry Points

Start here when exploring this area:

- **`bytes`** (Function) — `crates/agenc-ircd-federation-wire/src/schema.rs:18`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `bytes` | Function | `crates/agenc-ircd-federation-wire/src/schema.rs` | 18 |
| `claim_bytes` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 111 |
| `validate_enum` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 352 |
| `read` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 736 |
| `read_unsigned` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 748 |
| `begin_decode_value` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 979 |
| `read_u64` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 1053 |
| `decode_length` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 1062 |
| `decode_opaque` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 1067 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Validate_mode_change_embedded → Validate_enum` | cross_community | 7 |
| `Collection_key → Validate_enum` | cross_community | 6 |
| `Process_vector_frame → Validate_enum` | cross_community | 6 |
| `Validate_invite_event_embedded → Validate_enum` | cross_community | 6 |
| `Validate_projected_mode_embedded → Validate_enum` | cross_community | 6 |
| `Complete_schema_frame → Validate_enum` | cross_community | 5 |
| `Process_schema_frame → Read` | cross_community | 5 |
| `Process_schema_frame → Bytes` | cross_community | 5 |
| `Decode_schema_iterative → Validate_enum` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_3 | 3 calls |
| Cluster_5 | 2 calls |
| Cluster_7 | 1 calls |

## How to Explore

1. `context({name: "bytes"})` — see callers and callees
2. `query({search_query: "cluster_4"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
