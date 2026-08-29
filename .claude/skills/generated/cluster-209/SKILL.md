---
name: cluster-209
description: "Skill for the Cluster_209 area of agenc-ircd. 20 symbols across 3 files."
---

# Cluster_209

20 symbols | 3 files | Cohesion: 50%

## When to Use

- Working with code in `crates/`
- Understanding how login_index_transition_preflight, login_index_transition_preflight, account_key work
- Modifying cluster_209-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/src/engine.rs` | login_index_transition_preflight, verify_checkpoint_cut, seal_checkpoint, validate_existing_records, read_login_index_key_state (+13) |
| `crates/agenc-ircd-storage/src/construction_runtime.rs` | login_index_transition_preflight |
| `crates/agenc-ircd-storage/src/mutation.rs` | delete |

## Entry Points

Start here when exploring this area:

- **`login_index_transition_preflight`** (Function) — `crates/agenc-ircd-storage/src/construction_runtime.rs:1565`
- **`login_index_transition_preflight`** (Function) — `crates/agenc-ircd-storage/src/engine.rs:465`
- **`account_key`** (Function) — `crates/agenc-ircd-storage/src/engine.rs:3081`
- **`delete`** (Function) — `crates/agenc-ircd-storage/src/mutation.rs:115`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `login_index_transition_preflight` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 1565 |
| `login_index_transition_preflight` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 465 |
| `account_key` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3081 |
| `delete` | Function | `crates/agenc-ircd-storage/src/mutation.rs` | 115 |
| `verify_checkpoint_cut` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 968 |
| `seal_checkpoint` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 1049 |
| `validate_existing_records` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 1417 |
| `read_login_index_key_state` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 2023 |
| `read_manifest` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 2264 |
| `new` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 2743 |
| `verify_existing` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 2903 |
| `account_plaintext` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3385 |
| `existing_record` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3390 |
| `batch_with` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3403 |
| `recovered_domain_validation_rejects_cross_table_reference_and_tombstone_errors` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3592 |
| `existing_record_verification_rejects_length_schema_and_identifier_mismatches` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 4084 |
| `record_reference_decoder_covers_every_login_arm_and_non_domain_table` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 4280 |
| `prepare_application_covers_replacement_deletion_and_nonce_mismatch` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 4511 |
| `existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 4597 |
| `account_key_for_test` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 4770 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision → Secret_bytes` | cross_community | 5 |
| `Existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision → StorageEngineLimits` | cross_community | 5 |
| `Resume_completed_construction → New` | cross_community | 4 |
| `Engine_read_construction_source_and_completion_helpers_cover_live_state → New` | cross_community | 4 |
| `Existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision → Stable` | cross_community | 4 |
| `Existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision → New` | cross_community | 4 |
| `Existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision → Tbs` | cross_community | 4 |
| `Existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision → StorageMutationHead` | cross_community | 4 |
| `Existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision → StorageAccountingLimits` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 6 calls |
| Cluster_224 | 2 calls |
| Cluster_223 | 2 calls |
| Cluster_193 | 1 calls |

## How to Explore

1. `context({name: "login_index_transition_preflight"})` — see callers and callees
2. `query({search_query: "cluster_209"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
