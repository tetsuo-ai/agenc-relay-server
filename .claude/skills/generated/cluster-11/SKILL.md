---
name: cluster-11
description: "Skill for the Cluster_11 area of agenc-ircd. 26 symbols across 3 files."
---

# Cluster_11

26 symbols | 3 files | Cohesion: 83%

## When to Use

- Working with code in `crates/`
- Understanding how parse, expose_for_account_parser, from_wire work
- Modifying cluster_11-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-auth/src/wire.rs` | parse, binding, parse_request_plaintext, parse_inner_request, parse_creation_finish (+19) |
| `crates/agenc-ircd-crypto/src/account_hpke.rs` | expose_for_account_parser |
| `crates/agenc-ircd-types/src/generated_registry.rs` | from_wire |

## Entry Points

Start here when exploring this area:

- **`parse`** (Function) — `crates/agenc-ircd-auth/src/wire.rs:72`
- **`expose_for_account_parser`** (Function) — `crates/agenc-ircd-crypto/src/account_hpke.rs:188`
- **`from_wire`** (Function) — `crates/agenc-ircd-types/src/generated_registry.rs:346`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `parse` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 72 |
| `expose_for_account_parser` | Function | `crates/agenc-ircd-crypto/src/account_hpke.rs` | 188 |
| `from_wire` | Function | `crates/agenc-ircd-types/src/generated_registry.rs` | 346 |
| `binding` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 119 |
| `parse_request_plaintext` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 147 |
| `parse_inner_request` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 172 |
| `parse_creation_finish` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 233 |
| `parse_authentication_finish` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 262 |
| `parse_credential_change_start` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 278 |
| `parse_credential_change_finish` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 295 |
| `read_registration_record` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 330 |
| `encode_inner_request` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 397 |
| `encode_vector_u8` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 454 |
| `parse_response_plaintext` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 686 |
| `parse_response_payload` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 710 |
| `parse_challenge` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 783 |
| `parse_completion` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 793 |
| `new` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1011 |
| `read_array` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1015 |
| `read_slice` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1021 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_12 | 5 calls |
| Cluster_123 | 2 calls |

## How to Explore

1. `context({name: "parse"})` — see callers and callees
2. `query({search_query: "cluster_11"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
