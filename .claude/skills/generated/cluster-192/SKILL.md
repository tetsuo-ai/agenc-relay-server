---
name: cluster-192
description: "Skill for the Cluster_192 area of agenc-ircd. 58 symbols across 2 files."
---

# Cluster_192

58 symbols | 2 files | Cohesion: 76%

## When to Use

- Working with code in `crates/`
- Understanding how validate, operation_id, start work
- Modifying cluster_192-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/src/construction_runtime.rs` | start, start_streaming, start_inner, new, rebuild_disk (+51) |
| `crates/agenc-ircd-storage/src/construction.rs` | validate, operation_id |

## Entry Points

Start here when exploring this area:

- **`validate`** (Function) — `crates/agenc-ircd-storage/src/construction.rs:60`
- **`operation_id`** (Function) — `crates/agenc-ircd-storage/src/construction.rs:611`
- **`start`** (Function) — `crates/agenc-ircd-storage/src/construction_runtime.rs:145`
- **`start_streaming`** (Function) — `crates/agenc-ircd-storage/src/construction_runtime.rs:155`
- **`new`** (Function) — `crates/agenc-ircd-storage/src/construction_runtime.rs:739`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `validate` | Function | `crates/agenc-ircd-storage/src/construction.rs` | 60 |
| `operation_id` | Function | `crates/agenc-ircd-storage/src/construction.rs` | 611 |
| `start` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 145 |
| `start_streaming` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 155 |
| `new` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 739 |
| `rebuild_disk` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 784 |
| `validate_identity` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 833 |
| `recovery_transform_prefix` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 3242 |
| `start_inner` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 163 |
| `entry` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 847 |
| `preflight_with` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 943 |
| `validate_initial_marker` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 968 |
| `service_batch` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 1047 |
| `prepare_batch` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 1084 |
| `predicted_completion` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 1177 |
| `read_construction_sources` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 1297 |
| `marker_replacement` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 1311 |
| `encoded_existing` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 1324 |
| `initial_construction_accounting` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 1335 |
| `observe` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 1857 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Internal_restore_scans_reject_duplicate_and_cross_kind_inputs → Validate_nonzero_limit` | cross_community | 6 |
| `Internal_restore_scans_reject_duplicate_and_cross_kind_inputs → Validate_nonzero_usize_limit` | cross_community | 6 |
| `Internal_restore_scans_reject_duplicate_and_cross_kind_inputs → Put_fixed` | cross_community | 6 |
| `Disk_plan_and_preflight_accounting_reject_each_independent_internal_mismatch → Validate` | cross_community | 6 |
| `Disk_plan_and_preflight_accounting_reject_each_independent_internal_mismatch → Put_fixed` | cross_community | 6 |
| `Disk_plan_and_preflight_accounting_reject_each_independent_internal_mismatch → New` | cross_community | 6 |
| `Disk_plan_and_preflight_accounting_reject_each_independent_internal_mismatch → Validate_nonzero_limit` | cross_community | 6 |
| `Cursor_successor_and_completion_guards_reject_reachable_internal_mismatches → Validate` | cross_community | 6 |
| `Cursor_successor_and_completion_guards_reject_reachable_internal_mismatches → Put_fixed` | cross_community | 6 |
| `Cursor_successor_and_completion_guards_reject_reachable_internal_mismatches → New` | cross_community | 6 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 40 calls |
| Cluster_204 | 5 calls |
| Validate | 3 calls |
| Cluster_200 | 3 calls |
| Cluster_193 | 3 calls |

## How to Explore

1. `context({name: "validate"})` — see callers and callees
2. `query({search_query: "cluster_192"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
