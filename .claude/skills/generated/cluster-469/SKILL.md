---
name: cluster-469
description: "Skill for the Cluster_469 area of agenc-ircd. 33 symbols across 2 files."
---

# Cluster_469

33 symbols | 2 files | Cohesion: 85%

## When to Use

- Working with code in `crates/`
- Understanding how from_verified_report, new, publish work
- Modifying cluster_469-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/src/platform.rs` | rustix_rejected, from_verified_report, new, create, publish (+26) |
| `crates/agenc-ircd-storage/src/qualification.rs` | as_str, qualification_for |

## Entry Points

Start here when exploring this area:

- **`from_verified_report`** (Function) — `crates/agenc-ircd-storage/src/platform.rs:64`
- **`new`** (Function) — `crates/agenc-ircd-storage/src/platform.rs:138`
- **`publish`** (Function) — `crates/agenc-ircd-storage/src/platform.rs:226`
- **`open`** (Function) — `crates/agenc-ircd-storage/src/platform.rs:300`
- **`open_with_faults`** (Function) — `crates/agenc-ircd-storage/src/platform.rs:308`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `from_verified_report` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 64 |
| `new` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 138 |
| `publish` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 226 |
| `open` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 300 |
| `open_with_faults` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 308 |
| `pending_construction` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 377 |
| `open_database_file` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 423 |
| `create_database_file` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 437 |
| `read_guard` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 451 |
| `replace_guard` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 487 |
| `create_recovery_scratch` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 546 |
| `create_anonymous_scratch` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 686 |
| `admit_backup_output` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 821 |
| `as_str` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 63 |
| `qualification_for` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 369 |
| `rustix_rejected` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 39 |
| `create` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 176 |
| `drop` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 274 |
| `random_guard_temporary_name` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 704 |
| `construction_sibling` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 708 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_427 | 20 calls |
| Tests | 9 calls |
| Examples | 1 calls |

## How to Explore

1. `context({name: "from_verified_report"})` — see callers and callees
2. `query({search_query: "cluster_469"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
