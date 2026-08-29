---
name: cluster-20
description: "Skill for the Cluster_20 area of agenc-ircd. 27 symbols across 4 files."
---

# Cluster_20

27 symbols | 4 files | Cohesion: 79%

## When to Use

- Working with code in `crates/`
- Understanding how parse, encode_request_plaintext, encode_response_plaintext work
- Modifying cluster_20-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-auth/src/wire.rs` | parse, parse_request_plaintext, encode_request_plaintext, encode_inner_request, encode_vector_u8 (+18) |
| `crates/agenc-ircd-types/src/identifiers.rs` | encode_fixed, to_text |
| `crates/agenc-ircd-crypto/src/account_hpke.rs` | expose_for_account_parser |
| `crates/agenc-ircd-types/src/generated_registry.rs` | from_wire |

## Entry Points

Start here when exploring this area:

- **`parse`** (Function) — `crates/agenc-ircd-auth/src/wire.rs:218`
- **`encode_request_plaintext`** (Function) — `crates/agenc-ircd-auth/src/wire.rs:569`
- **`encode_response_plaintext`** (Function) — `crates/agenc-ircd-auth/src/wire.rs:889`
- **`expose_for_account_parser`** (Function) — `crates/agenc-ircd-crypto/src/account_hpke.rs:196`
- **`from_wire`** (Function) — `crates/agenc-ircd-types/src/generated_registry.rs:346`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `parse` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 218 |
| `encode_request_plaintext` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 569 |
| `encode_response_plaintext` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 889 |
| `expose_for_account_parser` | Function | `crates/agenc-ircd-crypto/src/account_hpke.rs` | 196 |
| `from_wire` | Function | `crates/agenc-ircd-types/src/generated_registry.rs` | 346 |
| `to_text` | Function | `crates/agenc-ircd-types/src/identifiers.rs` | 263 |
| `parse_request_plaintext` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 340 |
| `encode_inner_request` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 594 |
| `encode_vector_u8` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 648 |
| `encode_optional_invitation` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 655 |
| `parse_response_plaintext` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 934 |
| `parse_response_payload` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 961 |
| `parse_challenge` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1034 |
| `parse_completion` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1044 |
| `encode_response_payload` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1079 |
| `encode_challenge` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1126 |
| `encode_completion` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1151 |
| `new` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1264 |
| `read_slice` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1274 |
| `read_u16` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1292 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Every_start_path_propagates_entropy_failure_without_a_response → New` | cross_community | 6 |
| `Seal → New` | cross_community | 5 |
| `Authentication_finish_entropy_failure_emits_no_completion → New` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_21 | 17 calls |
| Cluster_1 | 1 calls |
| Cluster_98 | 1 calls |
| Tests | 1 calls |
| Cluster_173 | 1 calls |

## How to Explore

1. `context({name: "parse"})` — see callers and callees
2. `query({search_query: "cluster_20"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
