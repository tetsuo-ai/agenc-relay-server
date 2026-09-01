---
name: cluster-39
description: "Skill for the Cluster_39 area of agenc-ircd. 42 symbols across 3 files."
---

# Cluster_39

42 symbols | 3 files | Cohesion: 76%

## When to Use

- Working with code in `crates/`
- Understanding how authorize_account_transition, new, finish_credential_change work
- Modifying cluster_39-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-auth/src/service.rs` | new, committed, rejected, finish_account_creation_with_entropy, finish_account_authentication_with_entropy (+35) |
| `crates/agenc-ircd-auth/src/opaque.rs` | authorize_account_transition |
| `crates/agenc-ircd-auth/src/transaction.rs` | consume |

## Entry Points

Start here when exploring this area:

- **`authorize_account_transition`** (Function) — `crates/agenc-ircd-auth/src/opaque.rs:588`
- **`new`** (Function) — `crates/agenc-ircd-auth/src/service.rs:44`
- **`finish_credential_change`** (Function) — `crates/agenc-ircd-auth/src/service.rs:2402`
- **`reject_when_unavailable`** (Function) — `crates/agenc-ircd-auth/src/service.rs:2486`
- **`confirm`** (Function) — `crates/agenc-ircd-auth/src/service.rs:2583`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `authorize_account_transition` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 588 |
| `new` | Function | `crates/agenc-ircd-auth/src/service.rs` | 44 |
| `finish_credential_change` | Function | `crates/agenc-ircd-auth/src/service.rs` | 2402 |
| `reject_when_unavailable` | Function | `crates/agenc-ircd-auth/src/service.rs` | 2486 |
| `confirm` | Function | `crates/agenc-ircd-auth/src/service.rs` | 2583 |
| `begin_account_deletion` | Function | `crates/agenc-ircd-auth/src/service.rs` | 2645 |
| `authentication_completion` | Function | `crates/agenc-ircd-auth/src/service.rs` | 2812 |
| `consume` | Function | `crates/agenc-ircd-auth/src/transaction.rs` | 252 |
| `committed` | Function | `crates/agenc-ircd-auth/src/service.rs` | 123 |
| `rejected` | Function | `crates/agenc-ircd-auth/src/service.rs` | 130 |
| `finish_account_creation_with_entropy` | Function | `crates/agenc-ircd-auth/src/service.rs` | 615 |
| `finish_account_authentication_with_entropy` | Function | `crates/agenc-ircd-auth/src/service.rs` | 2028 |
| `evaluate_authentication_finish` | Function | `crates/agenc-ircd-auth/src/service.rs` | 2084 |
| `create_authentication_grant` | Function | `crates/agenc-ircd-auth/src/service.rs` | 2125 |
| `authorize_opaque` | Function | `crates/agenc-ircd-auth/src/service.rs` | 2164 |
| `fresh_account_id` | Function | `crates/agenc-ircd-auth/src/service.rs` | 2739 |
| `validate_finish_lineage` | Function | `crates/agenc-ircd-auth/src/service.rs` | 2745 |
| `rejected_creation_response` | Function | `crates/agenc-ircd-auth/src/service.rs` | 2773 |
| `rejected_authentication_response` | Function | `crates/agenc-ircd-auth/src/service.rs` | 2784 |
| `rejected_credential_change_response` | Function | `crates/agenc-ircd-auth/src/service.rs` | 2797 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Durable_transaction_records_reject_expiry_truncation_and_bad_tags → New` | cross_community | 6 |
| `Creation_transaction_record_round_trips_private_reservations → New` | cross_community | 5 |
| `Authentication_transaction_record_round_trips_without_login_plaintext → New` | cross_community | 5 |
| `Credential_transaction_record_round_trips_consumed_proof_result → New` | cross_community | 5 |
| `Durable_transaction_records_reject_expiry_truncation_and_bad_tags → Transaction_id` | cross_community | 5 |
| `Durable_transaction_records_reject_expiry_truncation_and_bad_tags → Matches_request_kind` | cross_community | 5 |
| `Durable_transaction_records_reject_expiry_truncation_and_bad_tags → Message_kind` | cross_community | 5 |
| `Into_restart_cleanup_metadata → Transaction_id` | cross_community | 4 |
| `Into_restart_cleanup_metadata → Matches_request_kind` | cross_community | 4 |
| `Into_restart_cleanup_metadata → Message_kind` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_37 | 12 calls |
| Cluster_30 | 8 calls |
| Admission | 7 calls |
| Tests | 3 calls |
| Cluster_41 | 1 calls |
| Cluster_32 | 1 calls |
| Cluster_43 | 1 calls |

## How to Explore

1. `context({name: "authorize_account_transition"})` — see callers and callees
2. `query({search_query: "cluster_39"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
