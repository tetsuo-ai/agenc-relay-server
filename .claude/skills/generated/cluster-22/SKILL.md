---
name: cluster-22
description: "Skill for the Cluster_22 area of agenc-ircd. 15 symbols across 3 files."
---

# Cluster_22

15 symbols | 3 files | Cohesion: 69%

## When to Use

- Working with code in `crates/`
- Understanding how parse, expose_for_account_parser, from_wire work
- Modifying cluster_22-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-auth/src/wire.rs` | parse, parse_request_plaintext, parse_response_plaintext, parse_response_payload, parse_challenge (+8) |
| `crates/agenc-ircd-crypto/src/account_hpke.rs` | expose_for_account_parser |
| `crates/agenc-ircd-types/src/generated_registry.rs` | from_wire |

## Entry Points

Start here when exploring this area:

- **`parse`** (Function) — `crates/agenc-ircd-auth/src/wire.rs:218`
- **`expose_for_account_parser`** (Function) — `crates/agenc-ircd-crypto/src/account_hpke.rs:196`
- **`from_wire`** (Function) — `crates/agenc-ircd-types/src/generated_registry.rs:346`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `parse` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 218 |
| `expose_for_account_parser` | Function | `crates/agenc-ircd-crypto/src/account_hpke.rs` | 196 |
| `from_wire` | Function | `crates/agenc-ircd-types/src/generated_registry.rs` | 346 |
| `parse_request_plaintext` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 340 |
| `parse_response_plaintext` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 934 |
| `parse_response_payload` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 961 |
| `parse_challenge` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1034 |
| `parse_completion` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1044 |
| `new` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1264 |
| `read_slice` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1274 |
| `read_u16` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1292 |
| `read_vector_u16` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1308 |
| `is_finished` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1320 |
| `cursor_rejects_truncation_invalid_vectors_and_position_overflow` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1389 |
| `writer_rejects_capacity_and_position_overflow_without_partial_output` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 1428 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Every_start_path_propagates_entropy_failure_without_a_response → New` | cross_community | 6 |
| `Credential_generation_overflow_consumes_without_response_authority → New` | cross_community | 6 |
| `Destructive_proofs_and_deletion_confirmations_reject_every_substitution → New` | cross_community | 6 |
| `Authentication_grant_deadlines_fail_closed_on_overflow → New` | cross_community | 6 |
| `Seal → New` | cross_community | 5 |
| `Authentication_finish_entropy_failure_emits_no_completion → New` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_23 | 17 calls |
| Cluster_156 | 1 calls |

## How to Explore

1. `context({name: "parse"})` — see callers and callees
2. `query({search_query: "cluster_22"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
