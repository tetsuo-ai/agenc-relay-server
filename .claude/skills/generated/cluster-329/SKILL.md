---
name: cluster-329
description: "Skill for the Cluster_329 area of agenc-ircd. 24 symbols across 5 files."
---

# Cluster_329

24 symbols | 5 files | Cohesion: 51%

## When to Use

- Working with code in `crates/`
- Understanding how login_index_transition_preflight, key_check_plaintext, construction_existing work
- Modifying cluster_329-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/src/engine.rs` | construction_existing, login_index_transition_preflight, verify_checkpoint_cut, seal_checkpoint, validate_existing_records (+15) |
| `crates/agenc-ircd-storage/src/construction_runtime.rs` | login_index_transition_preflight |
| `crates/agenc-ircd-storage/src/control.rs` | key_check_plaintext |
| `crates/agenc-ircd-storage/src/mutation.rs` | delete |
| `crates/agenc-ircd-storage/src/redb_store.rs` | read_record |

## Entry Points

Start here when exploring this area:

- **`login_index_transition_preflight`** (Function) — `crates/agenc-ircd-storage/src/construction_runtime.rs:1565`
- **`key_check_plaintext`** (Function) — `crates/agenc-ircd-storage/src/control.rs:91`
- **`construction_existing`** (Function) — `crates/agenc-ircd-storage/src/engine.rs:396`
- **`login_index_transition_preflight`** (Function) — `crates/agenc-ircd-storage/src/engine.rs:493`
- **`account_key`** (Function) — `crates/agenc-ircd-storage/src/engine.rs:3113`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `login_index_transition_preflight` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 1565 |
| `key_check_plaintext` | Function | `crates/agenc-ircd-storage/src/control.rs` | 91 |
| `construction_existing` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 396 |
| `login_index_transition_preflight` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 493 |
| `account_key` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3113 |
| `delete` | Function | `crates/agenc-ircd-storage/src/mutation.rs` | 115 |
| `read_record` | Function | `crates/agenc-ircd-storage/src/redb_store.rs` | 831 |
| `verify_checkpoint_cut` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 996 |
| `seal_checkpoint` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 1077 |
| `validate_existing_records` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 1445 |
| `read_login_index_key_state` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 2055 |
| `read_manifest` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 2296 |
| `new` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 2775 |
| `verify_key_check` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 2878 |
| `read_state_meta` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 2906 |
| `verify_existing` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 2935 |
| `account_plaintext` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3424 |
| `existing_record` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3437 |
| `batch_with` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3450 |
| `recovered_domain_validation_rejects_cross_table_reference_and_tombstone_errors` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3639 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision → Secret_bytes` | cross_community | 5 |
| `Resume_completed_construction → New` | cross_community | 4 |
| `Engine_read_construction_source_and_completion_helpers_cover_live_state → New` | cross_community | 4 |
| `Existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision → Stable` | cross_community | 4 |
| `Existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision → New` | cross_community | 4 |
| `Existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision → Tbs` | cross_community | 4 |
| `Existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision → StorageMutationHead` | cross_community | 4 |
| `Existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision → StorageAccountingLimits` | cross_community | 4 |
| `Existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision → Try_from` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 12 calls |
| Cluster_368 | 2 calls |
| Cluster_343 | 2 calls |
| Cluster_342 | 2 calls |

## How to Explore

1. `context({name: "login_index_transition_preflight"})` — see callers and callees
2. `query({search_query: "cluster_329"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
