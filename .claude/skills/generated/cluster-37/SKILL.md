---
name: cluster-37
description: "Skill for the Cluster_37 area of agenc-ircd. 30 symbols across 1 files."
---

# Cluster_37

30 symbols | 1 files | Cohesion: 80%

## When to Use

- Working with code in `crates/`
- Understanding how new, finish_credential_change, begin_account_deletion work
- Modifying cluster_37-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-auth/src/service.rs` | new, finish_credential_change, begin_account_deletion, rejected_credential_change_response, context (+25) |

## Entry Points

Start here when exploring this area:

- **`new`** (Function) — `crates/agenc-ircd-auth/src/service.rs:42`
- **`finish_credential_change`** (Function) — `crates/agenc-ircd-auth/src/service.rs:1196`
- **`begin_account_deletion`** (Function) — `crates/agenc-ircd-auth/src/service.rs:1420`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `new` | Function | `crates/agenc-ircd-auth/src/service.rs` | 42 |
| `finish_credential_change` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1196 |
| `begin_account_deletion` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1420 |
| `rejected_credential_change_response` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1572 |
| `context` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1666 |
| `context_for_network` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1670 |
| `account` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1690 |
| `fresh_proof` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1698 |
| `inputs` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1743 |
| `decode_nibble` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1869 |
| `vector_bytes` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1877 |
| `open_request` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1906 |
| `open_request_for_network` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1913 |
| `open_request_with_token` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1923 |
| `credential_start_request` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1961 |
| `creation_start_request` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1982 |
| `authentication_start_request` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1999 |
| `authentication_finish_request` | Function | `crates/agenc-ircd-auth/src/service.rs` | 2016 |
| `credential_finish_request` | Function | `crates/agenc-ircd-auth/src/service.rs` | 2037 |
| `assert_rejected_credential_start` | Function | `crates/agenc-ircd-auth/src/service.rs` | 2058 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Every_start_path_propagates_entropy_failure_without_a_response → New` | cross_community | 6 |
| `Every_start_path_propagates_entropy_failure_without_a_response → Transaction_id` | intra_community | 6 |
| `Every_start_path_propagates_entropy_failure_without_a_response → Matches_request_kind` | cross_community | 6 |
| `Every_start_path_propagates_entropy_failure_without_a_response → Message_kind` | intra_community | 5 |
| `Every_start_path_propagates_entropy_failure_without_a_response → From_ticks` | cross_community | 5 |
| `Every_start_path_propagates_entropy_failure_without_a_response → From_unix_seconds` | cross_community | 5 |
| `Every_start_path_propagates_entropy_failure_without_a_response → Decode_nibble` | intra_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_191 | 7 calls |
| Tests | 6 calls |
| Cluster_27 | 5 calls |
| Cluster_36 | 3 calls |
| Cluster_39 | 3 calls |
| Cluster_40 | 1 calls |

## How to Explore

1. `context({name: "new"})` — see callers and callees
2. `query({search_query: "cluster_37"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
