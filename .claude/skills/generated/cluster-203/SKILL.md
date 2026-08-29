---
name: cluster-203
description: "Skill for the Cluster_203 area of agenc-ircd. 55 symbols across 1 files."
---

# Cluster_203

55 symbols | 1 files | Cohesion: 78%

## When to Use

- Working with code in `crates/`
- Understanding how start, start_streaming, new work
- Modifying cluster_203-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/src/construction_runtime.rs` | start, start_streaming, start_inner, new, rebuild_disk (+50) |

## Entry Points

Start here when exploring this area:

- **`start`** (Function) — `crates/agenc-ircd-storage/src/construction_runtime.rs:162`
- **`start_streaming`** (Function) — `crates/agenc-ircd-storage/src/construction_runtime.rs:172`
- **`new`** (Function) — `crates/agenc-ircd-storage/src/construction_runtime.rs:756`
- **`rebuild_disk`** (Function) — `crates/agenc-ircd-storage/src/construction_runtime.rs:801`
- **`recovery_transform_prefix`** (Function) — `crates/agenc-ircd-storage/src/construction_runtime.rs:3256`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `start` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 162 |
| `start_streaming` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 172 |
| `new` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 756 |
| `rebuild_disk` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 801 |
| `recovery_transform_prefix` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 3256 |
| `start_inner` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 180 |
| `entry` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 864 |
| `preflight_with` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 960 |
| `service_batch` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 1064 |
| `prepare_batch` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 1101 |
| `predicted_completion` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 1167 |
| `read_construction_sources` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 1291 |
| `prepare_construction_batch` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 1308 |
| `marker_replacement` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 1350 |
| `encoded_existing` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 1363 |
| `initial_construction_accounting` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 1374 |
| `observe` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 1888 |
| `service_batch_with` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 2869 |
| `validate_cursor` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 3083 |
| `successor_marker` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 3102 |

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
| Tests | 33 calls |
| Cluster_195 | 7 calls |
| Cluster_210 | 5 calls |
| Validate | 3 calls |
| Cluster_196 | 2 calls |
| Cluster_193 | 2 calls |
| Cluster_192 | 2 calls |
| Cluster_205 | 1 calls |

## How to Explore

1. `context({name: "start"})` — see callers and callees
2. `query({search_query: "cluster_203"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
