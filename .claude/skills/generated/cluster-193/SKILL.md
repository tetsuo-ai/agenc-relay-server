---
name: cluster-193
description: "Skill for the Cluster_193 area of agenc-ircd. 22 symbols across 6 files."
---

# Cluster_193

22 symbols | 6 files | Cohesion: 55%

## When to Use

- Working with code in `crates/`
- Understanding how start_backup, startup_scan, construction_scan work
- Modifying cluster_193-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/src/engine.rs` | start_backup, verify_snapshot_accounting, startup_scan, construction_scan, record_references (+2) |
| `crates/agenc-ircd-storage/src/records.rs` | accepts, validate_key, table_schema, validate_record_plaintext, validate_sealed_record (+2) |
| `crates/agenc-ircd-storage/src/redb_store.rs` | visit_table, snapshot, validate_meta_membership, table_usage, validate_inventory |
| `crates/agenc-ircd-storage/src/backup.rs` | meta_logical_bytes |
| `crates/agenc-ircd-storage/src/integrity.rs` | logical_meta_charge |
| `crates/agenc-ircd-storage/src/platform.rs` | create_output |

## Entry Points

Start here when exploring this area:

- **`start_backup`** (Function) — `crates/agenc-ircd-storage/src/engine.rs:704`
- **`startup_scan`** (Function) — `crates/agenc-ircd-storage/src/engine.rs:1689`
- **`construction_scan`** (Function) — `crates/agenc-ircd-storage/src/engine.rs:1913`
- **`logical_meta_charge`** (Function) — `crates/agenc-ircd-storage/src/integrity.rs:615`
- **`create_output`** (Function) — `crates/agenc-ircd-storage/src/platform.rs:128`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `start_backup` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 704 |
| `startup_scan` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 1689 |
| `construction_scan` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 1913 |
| `logical_meta_charge` | Function | `crates/agenc-ircd-storage/src/integrity.rs` | 615 |
| `create_output` | Function | `crates/agenc-ircd-storage/src/platform.rs` | 128 |
| `validate_key` | Function | `crates/agenc-ircd-storage/src/records.rs` | 340 |
| `table_schema` | Function | `crates/agenc-ircd-storage/src/records.rs` | 360 |
| `validate_record_plaintext` | Function | `crates/agenc-ircd-storage/src/records.rs` | 671 |
| `validate_sealed_record` | Function | `crates/agenc-ircd-storage/src/records.rs` | 719 |
| `visit_table` | Function | `crates/agenc-ircd-storage/src/redb_store.rs` | 297 |
| `snapshot` | Function | `crates/agenc-ircd-storage/src/redb_store.rs` | 784 |
| `validate_meta_membership` | Function | `crates/agenc-ircd-storage/src/redb_store.rs` | 805 |
| `table_usage` | Function | `crates/agenc-ircd-storage/src/redb_store.rs` | 892 |
| `validate_inventory` | Function | `crates/agenc-ircd-storage/src/redb_store.rs` | 905 |
| `meta_logical_bytes` | Function | `crates/agenc-ircd-storage/src/backup.rs` | 1030 |
| `verify_snapshot_accounting` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 809 |
| `record_references` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 2283 |
| `validate_recovered_domain_record` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 2324 |
| `reference_is_legal` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 2370 |
| `accepts` | Function | `crates/agenc-ircd-storage/src/records.rs` | 284 |

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
| `Start → Validate_file` | cross_community | 5 |
| `Construction_scan → Validate_file` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 18 calls |
| Cluster_209 | 6 calls |
| Cluster_222 | 5 calls |
| Cluster_192 | 4 calls |
| Cluster_233 | 1 calls |
| Cluster_221 | 1 calls |
| Cluster_253 | 1 calls |
| Cluster_227 | 1 calls |

## How to Explore

1. `context({name: "start_backup"})` — see callers and callees
2. `query({search_query: "cluster_193"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
