---
name: cluster-185
description: "Skill for the Cluster_185 area of agenc-ircd. 31 symbols across 5 files."
---

# Cluster_185

31 symbols | 5 files | Cohesion: 56%

## When to Use

- Working with code in `crates/`
- Understanding how database_key_check, login_index_transition_preflight, key_check_plaintext work
- Modifying cluster_185-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/src/engine.rs` | read_guard, authenticate_open_state, validate_open_accounting, read, construction_existing (+20) |
| `crates/agenc-ircd-storage/src/redb_store.rs` | read_meta, read_record, table_usage |
| `crates/agenc-ircd-crypto/src/storage_integrity.rs` | database_key_check |
| `crates/agenc-ircd-storage/src/construction_runtime.rs` | login_index_transition_preflight |
| `crates/agenc-ircd-storage/src/control.rs` | key_check_plaintext |

## Entry Points

Start here when exploring this area:

- **`database_key_check`** (Function) — `crates/agenc-ircd-crypto/src/storage_integrity.rs:244`
- **`login_index_transition_preflight`** (Function) — `crates/agenc-ircd-storage/src/construction_runtime.rs:1565`
- **`key_check_plaintext`** (Function) — `crates/agenc-ircd-storage/src/control.rs:91`
- **`read`** (Function) — `crates/agenc-ircd-storage/src/engine.rs:632`
- **`construction_existing`** (Function) — `crates/agenc-ircd-storage/src/engine.rs:694`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `database_key_check` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 244 |
| `login_index_transition_preflight` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 1565 |
| `key_check_plaintext` | Function | `crates/agenc-ircd-storage/src/control.rs` | 91 |
| `read` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 632 |
| `construction_existing` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 694 |
| `login_index_transition_preflight` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 791 |
| `account_key` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3409 |
| `read_meta` | Function | `crates/agenc-ircd-storage/src/redb_store.rs` | 863 |
| `read_record` | Function | `crates/agenc-ircd-storage/src/redb_store.rs` | 901 |
| `table_usage` | Function | `crates/agenc-ircd-storage/src/redb_store.rs` | 962 |
| `read_guard` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 339 |
| `authenticate_open_state` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 442 |
| `validate_open_accounting` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 527 |
| `read_login_index_key_state` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 2351 |
| `new` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3069 |
| `require_meta` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3159 |
| `database_binding` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3163 |
| `verify_key_check` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3172 |
| `read_state_meta` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3200 |
| `directory_fingerprint` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 3514 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Startup_scan → New` | cross_community | 5 |
| `Resume_completed_construction → New` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 13 calls |
| State_core | 3 calls |
| Cluster_480 | 3 calls |
| Cluster_454 | 3 calls |
| Cluster_447 | 3 calls |
| Cluster_427 | 1 calls |
| Cluster_456 | 1 calls |
| Cluster_3 | 1 calls |

## How to Explore

1. `context({name: "database_key_check"})` — see callers and callees
2. `query({search_query: "cluster_185"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
