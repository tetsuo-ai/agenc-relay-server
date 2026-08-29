---
name: cluster-215
description: "Skill for the Cluster_215 area of agenc-ircd. 21 symbols across 1 files."
---

# Cluster_215

21 symbols | 1 files | Cohesion: 68%

## When to Use

- Working with code in `crates/`
- Understanding how create, drop, engine_limits work
- Modifying cluster_215-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/src/engine.rs` | create, drop, engine_limits, authenticate_state, active_checkpoint (+16) |

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `create` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 2923 |
| `drop` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 2997 |
| `engine_limits` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3003 |
| `authenticate_state` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3047 |
| `active_checkpoint` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3059 |
| `replace_checkpoint` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3078 |
| `active_manifest` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3117 |
| `replace_manifest` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3152 |
| `reopen_config` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3293 |
| `storage_engine_limits_reject_every_independent_profile_boundary` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3592 |
| `integrity_ledger_rejects_each_genesis_anchor_mismatch` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3648 |
| `integrity_ledger_rejects_each_checkpoint_to_state_anchor_mismatch` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3675 |
| `integrity_ledger_rejects_non_genesis_shape_and_tracked_digest_mismatches` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3708 |
| `integrity_ledger_rejects_installation_sequence_beyond_the_state_head` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3777 |
| `checkpoint_cut_and_accounting_reject_each_independent_mismatch` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3899 |
| `startup_scan_rejects_authenticated_accounting_and_untracked_singleton_corruption` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 4003 |
| `open_rejects_each_expected_server_identity_mismatch` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 4356 |
| `integrity_ledger_rejects_every_manifest_chain_field_independently` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 4559 |
| `active_backup_rejects_competing_backup_and_checkpoint_jobs` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 4630 |
| `checkpoint_retirement_and_ledger_inventory_fail_closed_at_exact_boundaries` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 4660 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Engine_read_construction_source_and_completion_helpers_cover_live_state → Secret_bytes` | cross_community | 4 |
| `Engine_read_construction_source_and_completion_helpers_cover_live_state → StorageEngineLimits` | cross_community | 4 |
| `Existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision → Secret_bytes` | cross_community | 4 |
| `Existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision → StorageEngineLimits` | cross_community | 4 |
| `Prepare_application_covers_replacement_deletion_and_nonce_mismatch → Secret_bytes` | cross_community | 4 |
| `Prepare_application_covers_replacement_deletion_and_nonce_mismatch → StorageEngineLimits` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 9 calls |
| Cluster_203 | 7 calls |
| Cluster_244 | 2 calls |
| Cluster_216 | 2 calls |
| Cluster_220 | 1 calls |

## How to Explore

1. `context({name: "create"})` — see callers and callees
2. `query({search_query: "cluster_215"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
