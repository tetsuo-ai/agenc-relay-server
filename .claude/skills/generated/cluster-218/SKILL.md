---
name: cluster-218
description: "Skill for the Cluster_218 area of agenc-ircd. 33 symbols across 5 files."
---

# Cluster_218

33 symbols | 5 files | Cohesion: 57%

## When to Use

- Working with code in `crates/`
- Understanding how database_key_check, login_index_transition_preflight, key_check_plaintext work
- Modifying cluster_218-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/src/engine.rs` | new, storage_limit_pair, read_guard, authenticate_open_state, validate_open_accounting (+20) |
| `crates/agenc-ircd-storage/src/redb_store.rs` | read_meta, read_record, read_range, table_usage, validate_row_shape |
| `crates/agenc-ircd-crypto/src/storage_integrity.rs` | database_key_check |
| `crates/agenc-ircd-storage/src/construction_runtime.rs` | login_index_transition_preflight |
| `crates/agenc-ircd-storage/src/control.rs` | key_check_plaintext |

## Entry Points

Start here when exploring this area:

- **`database_key_check`** (Function) — `crates/agenc-ircd-crypto/src/storage_integrity.rs:244`
- **`login_index_transition_preflight`** (Function) — `crates/agenc-ircd-storage/src/construction_runtime.rs:1566`
- **`key_check_plaintext`** (Function) — `crates/agenc-ircd-storage/src/control.rs:91`
- **`new`** (Function) — `crates/agenc-ircd-storage/src/engine.rs:280`
- **`storage_limit_pair`** (Function) — `crates/agenc-ircd-storage/src/engine.rs:365`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `database_key_check` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 244 |
| `login_index_transition_preflight` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 1566 |
| `key_check_plaintext` | Function | `crates/agenc-ircd-storage/src/control.rs` | 91 |
| `new` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 280 |
| `storage_limit_pair` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 365 |
| `read` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 1055 |
| `construction_existing` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 1121 |
| `login_index_transition_preflight` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 1218 |
| `account_key` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3898 |
| `read_meta` | Function | `crates/agenc-ircd-storage/src/redb_store.rs` | 863 |
| `read_record` | Function | `crates/agenc-ircd-storage/src/redb_store.rs` | 901 |
| `read_range` | Function | `crates/agenc-ircd-storage/src/redb_store.rs` | 924 |
| `table_usage` | Function | `crates/agenc-ircd-storage/src/redb_store.rs` | 984 |
| `read_guard` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 725 |
| `authenticate_open_state` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 829 |
| `validate_open_accounting` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 914 |
| `read_login_index_key_state` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 2836 |
| `require_meta` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3648 |
| `database_binding` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3652 |
| `verify_key_check` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3661 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Startup_scan → New` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 11 calls |
| Cluster_519 | 5 calls |
| State_core | 3 calls |
| Cluster_553 | 2 calls |
| Cluster_537 | 1 calls |
| Cluster_525 | 1 calls |
| Cluster_3 | 1 calls |

## How to Explore

1. `context({name: "database_key_check"})` — see callers and callees
2. `query({search_query: "cluster_218"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
