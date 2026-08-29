---
name: cluster-223
description: "Skill for the Cluster_223 area of agenc-ircd. 18 symbols across 1 files."
---

# Cluster_223

18 symbols | 1 files | Cohesion: 68%

## When to Use

- Working with code in `crates/`
- Understanding how create work
- Modifying cluster_223-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/src/engine.rs` | create, drop, authenticate_state, active_checkpoint, replace_checkpoint (+13) |

## Entry Points

Start here when exploring this area:

- **`create`** (Function) — `crates/agenc-ircd-storage/src/engine.rs:2996`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `create` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 2996 |
| `drop` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3119 |
| `authenticate_state` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3169 |
| `active_checkpoint` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3181 |
| `replace_checkpoint` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3200 |
| `active_manifest` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3239 |
| `replace_manifest` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3274 |
| `integrity_ledger_rejects_each_genesis_anchor_mismatch` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3770 |
| `integrity_ledger_rejects_each_checkpoint_to_state_anchor_mismatch` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3797 |
| `integrity_ledger_rejects_non_genesis_shape_and_tracked_digest_mismatches` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3830 |
| `integrity_ledger_rejects_installation_sequence_beyond_the_state_head` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3899 |
| `checkpoint_cut_and_accounting_reject_each_independent_mismatch` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 4021 |
| `startup_scan_rejects_authenticated_accounting_and_untracked_singleton_corruption` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 4125 |
| `open_rejects_each_expected_server_identity_mismatch` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 4478 |
| `integrity_ledger_rejects_every_manifest_chain_field_independently` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 4708 |
| `active_backup_rejects_competing_backup_and_checkpoint_jobs` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 4779 |
| `checkpoint_retirement_and_ledger_inventory_fail_closed_at_exact_boundaries` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 4809 |
| `open_rejects_manifest_inventory_and_key_check_identifier_corruption` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 4885 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Engine_read_construction_source_and_completion_helpers_cover_live_state → Secret_bytes` | cross_community | 5 |
| `Engine_read_construction_source_and_completion_helpers_cover_live_state → StorageEngineLimits` | cross_community | 5 |
| `Existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision → Secret_bytes` | cross_community | 5 |
| `Existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision → StorageEngineLimits` | cross_community | 5 |
| `Engine_read_construction_source_and_completion_helpers_cover_live_state → Stable` | cross_community | 4 |
| `Engine_read_construction_source_and_completion_helpers_cover_live_state → New` | cross_community | 4 |
| `Existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision → Stable` | cross_community | 4 |
| `Existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision → New` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 6 calls |
| Cluster_209 | 6 calls |
| Cluster_253 | 2 calls |
| Cluster_224 | 2 calls |
| Cluster_216 | 1 calls |

## How to Explore

1. `context({name: "create"})` — see callers and callees
2. `query({search_query: "cluster_223"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
