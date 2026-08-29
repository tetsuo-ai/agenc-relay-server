---
name: cluster-316
description: "Skill for the Cluster_316 area of agenc-ircd. 23 symbols across 3 files."
---

# Cluster_316

23 symbols | 3 files | Cohesion: 70%

## When to Use

- Working with code in `crates/`
- Understanding how validate_migration_profile, check, new work
- Modifying cluster_316-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/src/platform.rs` | new, create, publish, open, open_with_faults (+16) |
| `crates/agenc-ircd-storage/src/construction.rs` | validate_migration_profile |
| `crates/agenc-ircd-storage/src/fault.rs` | check |

## Entry Points

Start here when exploring this area:

- **`validate_migration_profile`** (Function) — `crates/agenc-ircd-storage/src/construction.rs:494`
- **`check`** (Function) — `crates/agenc-ircd-storage/src/fault.rs:182`
- **`new`** (Function) — `crates/agenc-ircd-storage/src/platform.rs:120`
- **`publish`** (Function) — `crates/agenc-ircd-storage/src/platform.rs:208`
- **`open`** (Function) — `crates/agenc-ircd-storage/src/platform.rs:282`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `validate_migration_profile` | Function | `crates/agenc-ircd-storage/src/construction.rs` | 494 |
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
| `create` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 158 |
| `random_guard_temporary_name` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 527 |
| `random_temporary_name` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 557 |
| `validate_single_component` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 577 |
| `cleanup_random_temporaries` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 588 |
| `validate_file` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 615 |
| `require_same_filesystem` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 651 |
| `create_file` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 698 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Rejected_checkpoint_keeps_the_owner_serving_until_a_commit_lifts_suppression → Check` | cross_community | 5 |
| `Start → Validate_file` | cross_community | 5 |
| `Construction_scan → Validate_file` | cross_community | 4 |
| `Construction_scan → Require_same_filesystem` | cross_community | 4 |
| `Start_backup → Validate_file` | cross_community | 4 |
| `Start_backup → Require_same_filesystem` | cross_community | 4 |
| `Startup_scan → Require_same_filesystem` | cross_community | 4 |
| `Start → Require_same_filesystem` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 7 calls |
| Examples | 1 calls |
| Cluster_357 | 1 calls |

## How to Explore

1. `context({name: "validate_migration_profile"})` — see callers and callees
2. `query({search_query: "cluster_316"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
