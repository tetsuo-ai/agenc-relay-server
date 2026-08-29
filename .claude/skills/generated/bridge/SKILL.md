---
name: bridge
description: "Skill for the Bridge area of agenc-ircd. 22 symbols across 7 files."
---

# Bridge

22 symbols | 7 files | Cohesion: 84%

## When to Use

- Working with code in `crates/`
- Understanding how new, begin, abandon work
- Modifying bridge-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/bridge/storage.rs` | new, begin, abandon, finish, fail (+7) |
| `crates/agenc-ircd-runtime/src/bridge/crypto.rs` | new, try_submit, in_flight, reap_finished |
| `crates/agenc-ircd-runtime/src/bridge/mod.rs` | new, job_ids_round_trip_and_the_completion_capacity_is_two |
| `crates/agenc-ircd-runtime/tests/bridge_storage.rs` | the_ledger_and_classification_fail_closed_on_every_loss |
| `crates/agenc-ircd-runtime/tests/loom_models.rs` | completion_sender_loss |
| `crates/agenc-ircd-runtime/tests/bridge_crypto.rs` | verdict |
| `crates/agenc-ircd-storage/src/owner.rs` | try_commit |

## Entry Points

Start here when exploring this area:

- **`new`** (Function) — `crates/agenc-ircd-runtime/src/bridge/storage.rs:115`
- **`begin`** (Function) — `crates/agenc-ircd-runtime/src/bridge/storage.rs:125`
- **`abandon`** (Function) — `crates/agenc-ircd-runtime/src/bridge/storage.rs:138`
- **`finish`** (Function) — `crates/agenc-ircd-runtime/src/bridge/storage.rs:143`
- **`fail`** (Function) — `crates/agenc-ircd-runtime/src/bridge/storage.rs:156`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `new` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 115 |
| `begin` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 125 |
| `abandon` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 138 |
| `finish` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 143 |
| `fail` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 156 |
| `start` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 197 |
| `classify_completion` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 307 |
| `new` | Function | `crates/agenc-ircd-runtime/src/bridge/crypto.rs` | 83 |
| `try_submit` | Function | `crates/agenc-ircd-runtime/src/bridge/crypto.rs` | 532 |
| `in_flight` | Function | `crates/agenc-ircd-runtime/src/bridge/crypto.rs` | 572 |
| `new` | Function | `crates/agenc-ircd-runtime/src/bridge/mod.rs` | 20 |
| `submit` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 224 |
| `try_commit` | Function | `crates/agenc-ircd-storage/src/owner.rs` | 48 |
| `shutdown` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 278 |
| `default` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 177 |
| `bridge_loop` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 319 |
| `the_ledger_and_classification_fail_closed_on_every_loss` | Function | `crates/agenc-ircd-runtime/tests/bridge_storage.rs` | 413 |
| `completion_sender_loss` | Function | `crates/agenc-ircd-runtime/tests/loom_models.rs` | 207 |
| `reap_finished` | Function | `crates/agenc-ircd-runtime/src/bridge/crypto.rs` | 589 |
| `verdict` | Function | `crates/agenc-ircd-runtime/tests/bridge_crypto.rs` | 83 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Connection | 5 calls |
| Tests | 2 calls |

## How to Explore

1. `context({name: "new"})` — see callers and callees
2. `query({search_query: "bridge"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
