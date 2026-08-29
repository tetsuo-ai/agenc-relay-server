---
name: cluster-222
description: "Skill for the Cluster_222 area of agenc-ircd. 25 symbols across 3 files."
---

# Cluster_222

25 symbols | 3 files | Cohesion: 68%

## When to Use

- Working with code in `crates/`
- Understanding how check, new, publish work
- Modifying cluster_222-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/src/platform.rs` | new, create, publish, open, open_with_faults (+16) |
| `crates/agenc-ircd-storage/src/engine.rs` | commit_prepared_checkpoint, verify_integrity_ledger, apply_checkpoint_installation |
| `crates/agenc-ircd-storage/src/fault.rs` | check |

## Entry Points

Start here when exploring this area:

- **`check`** (Function) — `crates/agenc-ircd-storage/src/fault.rs:182`
- **`new`** (Function) — `crates/agenc-ircd-storage/src/platform.rs:120`
- **`publish`** (Function) — `crates/agenc-ircd-storage/src/platform.rs:208`
- **`open`** (Function) — `crates/agenc-ircd-storage/src/platform.rs:282`
- **`open_with_faults`** (Function) — `crates/agenc-ircd-storage/src/platform.rs:290`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `check` | Function | `crates/agenc-ircd-storage/src/fault.rs` | 182 |
| `new` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 120 |
| `publish` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 208 |
| `open` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 282 |
| `open_with_faults` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 290 |
| `open_database_file` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 385 |
| `create_database_file` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 399 |
| `read_guard` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 413 |
| `replace_guard` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 449 |
| `create_recovery_scratch` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 508 |
| `admit_backup_output` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 629 |
| `commit_prepared_checkpoint` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 1196 |
| `verify_integrity_ledger` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 2042 |
| `apply_checkpoint_installation` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 2552 |
| `create` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 158 |
| `random_guard_temporary_name` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 527 |
| `random_temporary_name` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 557 |
| `validate_single_component` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 577 |
| `cleanup_random_temporaries` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 588 |
| `validate_file` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 615 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Construction_scan → StorageSnapshot` | cross_community | 5 |
| `Construction_scan → Name` | cross_community | 5 |
| `Construction_scan → New` | cross_community | 5 |
| `Start_backup → Validate_file` | cross_community | 5 |
| `Startup_scan → StorageSnapshot` | cross_community | 5 |
| `Startup_scan → Name` | cross_community | 5 |
| `Startup_scan → New` | cross_community | 5 |
| `Startup_scan → Fill_from` | cross_community | 5 |
| `Rejected_checkpoint_keeps_the_owner_serving_until_a_commit_lifts_suppression → Check` | cross_community | 5 |
| `Start → Validate_file` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 9 calls |
| Cluster_193 | 3 calls |
| Cluster_209 | 3 calls |
| Cluster_253 | 1 calls |
| Examples | 1 calls |
| Cluster_240 | 1 calls |
| Cluster_223 | 1 calls |

## How to Explore

1. `context({name: "check"})` — see callers and callees
2. `query({search_query: "cluster_222"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
