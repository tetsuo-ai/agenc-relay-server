---
name: cluster-8
description: "Skill for the Cluster_8 area of agenc-ircd. 30 symbols across 1 files."
---

# Cluster_8

30 symbols | 1 files | Cohesion: 81%

## When to Use

- Working with code in `crates/`
- Understanding how new, finish_credential_change, begin_account_deletion work
- Modifying cluster_8-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-auth/src/service.rs` | new, finish_credential_change, begin_account_deletion, rejected_credential_change_response, context (+25) |

## Entry Points

Start here when exploring this area:

- **`new`** (Function) — `crates/agenc-ircd-auth/src/service.rs:42`
- **`finish_credential_change`** (Function) — `crates/agenc-ircd-auth/src/service.rs:1180`
- **`begin_account_deletion`** (Function) — `crates/agenc-ircd-auth/src/service.rs:1399`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `new` | Function | `crates/agenc-ircd-auth/src/service.rs` | 42 |
| `finish_credential_change` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1180 |
| `begin_account_deletion` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1399 |
| `rejected_credential_change_response` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1551 |
| `context` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1645 |
| `context_for_network` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1649 |
| `account` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1669 |
| `fresh_proof` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1677 |
| `inputs` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1722 |
| `decode_nibble` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1848 |
| `vector_bytes` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1856 |
| `open_request` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1885 |
| `open_request_for_network` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1892 |
| `open_request_with_token` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1902 |
| `credential_start_request` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1940 |
| `creation_start_request` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1961 |
| `authentication_start_request` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1978 |
| `authentication_finish_request` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1995 |
| `credential_finish_request` | Function | `crates/agenc-ircd-auth/src/service.rs` | 2016 |
| `assert_rejected_credential_start` | Function | `crates/agenc-ircd-auth/src/service.rs` | 2037 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Every_start_path_propagates_entropy_failure_without_a_response → New` | cross_community | 6 |
| `Every_start_path_propagates_entropy_failure_without_a_response → Transaction_id` | intra_community | 6 |
| `Every_start_path_propagates_entropy_failure_without_a_response → Matches_request_kind` | cross_community | 6 |
| `Credential_generation_overflow_consumes_without_response_authority → New` | cross_community | 6 |
| `Destructive_proofs_and_deletion_confirmations_reject_every_substitution → New` | cross_community | 6 |
| `Every_start_path_propagates_entropy_failure_without_a_response → Message_kind` | intra_community | 5 |
| `Every_start_path_propagates_entropy_failure_without_a_response → From_ticks` | cross_community | 5 |
| `Every_start_path_propagates_entropy_failure_without_a_response → From_unix_seconds` | cross_community | 5 |
| `Authentication_finish_entropy_failure_emits_no_completion → New` | cross_community | 5 |
| `Credential_replacement_reuses_identity_and_fences_generation → Transaction_id` | intra_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_131 | 7 calls |
| Cluster_4 | 5 calls |
| Tests | 5 calls |
| Cluster_10 | 4 calls |
| Cluster_7 | 2 calls |
| Cluster_11 | 1 calls |

## How to Explore

1. `context({name: "new"})` — see callers and callees
2. `query({search_query: "cluster_8"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
