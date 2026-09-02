---
name: cluster-504
description: "Skill for the Cluster_504 area of agenc-ircd. 37 symbols across 4 files."
---

# Cluster_504

37 symbols | 4 files | Cohesion: 82%

## When to Use

- Working with code in `crates/`
- Understanding how validate_migration_profile, check, from_verified_report work
- Modifying cluster_504-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/src/platform.rs` | rustix_rejected, from_verified_report, open, open_candidate, new (+28) |
| `crates/agenc-ircd-storage/src/qualification.rs` | as_str, qualification_for |
| `crates/agenc-ircd-storage/src/construction.rs` | validate_migration_profile |
| `crates/agenc-ircd-storage/src/fault.rs` | check |

## Entry Points

Start here when exploring this area:

- **`validate_migration_profile`** (Function) — `crates/agenc-ircd-storage/src/construction.rs:494`
- **`check`** (Function) — `crates/agenc-ircd-storage/src/fault.rs:182`
- **`from_verified_report`** (Function) — `crates/agenc-ircd-storage/src/platform.rs:64`
- **`open`** (Function) — `crates/agenc-ircd-storage/src/platform.rs:149`
- **`open_candidate`** (Function) — `crates/agenc-ircd-storage/src/platform.rs:192`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `validate_migration_profile` | Function | `crates/agenc-ircd-storage/src/construction.rs` | 494 |
| `check` | Function | `crates/agenc-ircd-storage/src/fault.rs` | 182 |
| `from_verified_report` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 64 |
| `open` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 149 |
| `open_candidate` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 192 |
| `new` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 210 |
| `publish` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 298 |
| `open_with_faults` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 380 |
| `pending_construction` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 449 |
| `open_database_file` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 495 |
| `create_database_file` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 509 |
| `read_guard` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 523 |
| `replace_guard` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 559 |
| `create_recovery_scratch` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 618 |
| `create_anonymous_scratch` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 758 |
| `admit_backup_output` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 893 |
| `as_str` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 63 |
| `qualification_for` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 369 |
| `rustix_rejected` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 39 |
| `create` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 248 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Resume_completed_construction → Check` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 9 calls |
| State_core | 1 calls |
| Examples | 1 calls |

## How to Explore

1. `context({name: "validate_migration_profile"})` — see callers and callees
2. `query({search_query: "cluster_504"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
