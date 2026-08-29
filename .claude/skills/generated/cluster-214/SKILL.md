---
name: cluster-214
description: "Skill for the Cluster_214 area of agenc-ircd. 25 symbols across 3 files."
---

# Cluster_214

25 symbols | 3 files | Cohesion: 75%

## When to Use

- Working with code in `crates/`
- Understanding how start_backup, new, create_output work
- Modifying cluster_214-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/src/platform.rs` | new, create_output, create, publish, open (+18) |
| `crates/agenc-ircd-storage/src/engine.rs` | start_backup |
| `crates/agenc-ircd-storage/src/redb_store.rs` | snapshot |

## Entry Points

Start here when exploring this area:

- **`start_backup`** (Function) — `crates/agenc-ircd-storage/src/engine.rs:702`
- **`new`** (Function) — `crates/agenc-ircd-storage/src/platform.rs:114`
- **`create_output`** (Function) — `crates/agenc-ircd-storage/src/platform.rs:122`
- **`publish`** (Function) — `crates/agenc-ircd-storage/src/platform.rs:195`
- **`open`** (Function) — `crates/agenc-ircd-storage/src/platform.rs:269`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `start_backup` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 702 |
| `new` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 114 |
| `create_output` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 122 |
| `publish` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 195 |
| `open` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 269 |
| `open_with_faults` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 277 |
| `open_database_file` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 390 |
| `create_database_file` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 404 |
| `read_guard` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 418 |
| `replace_guard` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 454 |
| `create_recovery_scratch` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 513 |
| `admit_backup_output` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 608 |
| `snapshot` | Function | `crates/agenc-ircd-storage/src/redb_store.rs` | 730 |
| `create` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 152 |
| `random_guard_temporary_name` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 532 |
| `random_temporary_name` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 536 |
| `validate_single_component` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 556 |
| `cleanup_random_temporaries` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 567 |
| `validate_file` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 594 |
| `require_same_filesystem` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 642 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Construction_scan → Fill_from` | cross_community | 6 |
| `Construction_scan → New` | cross_community | 6 |
| `Start_backup → Validate_file` | cross_community | 5 |
| `Startup_scan → Fill_from` | cross_community | 5 |
| `Startup_scan → New` | cross_community | 5 |
| `Construction_scan → Validate_file` | cross_community | 4 |
| `Construction_scan → Require_same_filesystem` | cross_community | 4 |
| `Start_backup → New` | cross_community | 4 |
| `Start_backup → From_u16` | cross_community | 4 |
| `Start_backup → Tbs` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 28 calls |
| Cluster_213 | 1 calls |
| Examples | 1 calls |
| Cluster_231 | 1 calls |
| Cluster_203 | 1 calls |
| Cluster_187 | 1 calls |

## How to Explore

1. `context({name: "start_backup"})` — see callers and callees
2. `query({search_query: "cluster_214"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
