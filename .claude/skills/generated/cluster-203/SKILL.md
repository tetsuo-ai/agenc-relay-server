---
name: cluster-203
description: "Skill for the Cluster_203 area of agenc-ircd. 18 symbols across 3 files."
---

# Cluster_203

18 symbols | 3 files | Cohesion: 50%

## When to Use

- Working with code in `crates/`
- Understanding how login_index_transition_preflight, login_index_transition_preflight, delete work
- Modifying cluster_203-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/src/engine.rs` | login_index_transition_preflight, seal_checkpoint, validate_existing_records, read_login_index_key_state, new (+11) |
| `crates/agenc-ircd-storage/src/construction_runtime.rs` | login_index_transition_preflight |
| `crates/agenc-ircd-storage/src/mutation.rs` | delete |

## Entry Points

Start here when exploring this area:

- **`login_index_transition_preflight`** (Function) — `crates/agenc-ircd-storage/src/construction_runtime.rs:1514`
- **`login_index_transition_preflight`** (Function) — `crates/agenc-ircd-storage/src/engine.rs:463`
- **`delete`** (Function) — `crates/agenc-ircd-storage/src/mutation.rs:113`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `login_index_transition_preflight` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 1514 |
| `login_index_transition_preflight` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 463 |
| `delete` | Function | `crates/agenc-ircd-storage/src/mutation.rs` | 113 |
| `seal_checkpoint` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 1034 |
| `validate_existing_records` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 1403 |
| `read_login_index_key_state` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 2009 |
| `new` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 2670 |
| `database_binding` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 2764 |
| `verify_existing` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 2830 |
| `account_plaintext` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3263 |
| `existing_record` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3268 |
| `batch_with` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3281 |
| `recovered_domain_validation_rejects_cross_table_reference_and_tombstone_errors` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3470 |
| `existing_record_verification_rejects_length_schema_and_identifier_mismatches` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3962 |
| `record_reference_decoder_covers_every_login_arm_and_non_domain_table` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 4158 |
| `prepare_application_covers_replacement_deletion_and_nonce_mismatch` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 4389 |
| `existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 4448 |
| `account_key_for_test` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 4621 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision → Table` | cross_community | 5 |
| `Prepare_application_covers_replacement_deletion_and_nonce_mismatch → Table` | cross_community | 5 |
| `Resume_completed_construction → New` | cross_community | 4 |
| `Existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision → Secret_bytes` | cross_community | 4 |
| `Existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision → StorageEngineLimits` | cross_community | 4 |
| `Existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision → Tbs` | cross_community | 4 |
| `Existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision → StorageMutationHead` | cross_community | 4 |
| `Existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision → StorageAccountingLimits` | cross_community | 4 |
| `Prepare_application_covers_replacement_deletion_and_nonce_mismatch → Secret_bytes` | cross_community | 4 |
| `Prepare_application_covers_replacement_deletion_and_nonce_mismatch → StorageEngineLimits` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 6 calls |
| Cluster_216 | 2 calls |
| Cluster_215 | 2 calls |

## How to Explore

1. `context({name: "login_index_transition_preflight"})` — see callers and callees
2. `query({search_query: "cluster_203"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
