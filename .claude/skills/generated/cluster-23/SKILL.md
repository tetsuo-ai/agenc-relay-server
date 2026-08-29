---
name: cluster-23
description: "Skill for the Cluster_23 area of agenc-ircd. 27 symbols across 4 files."
---

# Cluster_23

27 symbols | 4 files | Cohesion: 79%

## When to Use

- Working with code in `crates/`
- Understanding how parse, encode_request_plaintext, encode_response_plaintext work
- Modifying cluster_23-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-auth/src/wire.rs` | parse, parse_request_plaintext, encode_request_plaintext, encode_inner_request, encode_vector_u8 (+18) |
| `crates/agenc-ircd-types/src/identifiers.rs` | encode_fixed, to_text |
| `crates/agenc-ircd-crypto/src/account_hpke.rs` | expose_for_account_parser |
| `crates/agenc-ircd-types/src/generated_registry.rs` | from_wire |

## Entry Points

Start here when exploring this area:

- **`parse`** (Function) — `crates/agenc-ircd-auth/src/wire.rs:221`
- **`encode_request_plaintext`** (Function) — `crates/agenc-ircd-auth/src/wire.rs:572`
- **`encode_response_plaintext`** (Function) — `crates/agenc-ircd-auth/src/wire.rs:892`
- **`expose_for_account_parser`** (Function) — `crates/agenc-ircd-crypto/src/account_hpke.rs:196`
- **`from_wire`** (Function) — `crates/agenc-ircd-types/src/generated_registry.rs:346`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `parse` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 221 |
| `encode_request_plaintext` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 572 |
| `encode_response_plaintext` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 892 |
| `expose_for_account_parser` | Function | `crates/agenc-ircd-crypto/src/account_hpke.rs` | 196 |
| `from_wire` | Function | `crates/agenc-ircd-types/src/generated_registry.rs` | 346 |
| `to_text` | Function | `crates/agenc-ircd-types/src/identifiers.rs` | 263 |
| `parse_request_plaintext` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 343 |
| `encode_inner_request` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 597 |
| `encode_vector_u8` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 651 |
| `encode_optional_invitation` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 658 |
| `parse_response_plaintext` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 937 |
| `parse_response_payload` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 964 |
| `parse_challenge` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1037 |
| `parse_completion` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1047 |
| `encode_response_payload` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1082 |
| `encode_challenge` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1129 |
| `encode_completion` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1154 |
| `new` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1267 |
| `read_slice` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1277 |
| `read_u16` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1295 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Every_start_path_propagates_entropy_failure_without_a_response → New` | cross_community | 6 |
| `Seal → New` | cross_community | 5 |
| `Authentication_finish_entropy_failure_emits_no_completion → New` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_24 | 17 calls |
| Tests | 3 calls |
| Cluster_174 | 1 calls |

## How to Explore

1. `context({name: "parse"})` — see callers and callees
2. `query({search_query: "cluster_23"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
