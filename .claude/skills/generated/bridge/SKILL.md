---
name: bridge
description: "Skill for the Bridge area of agenc-ircd. 32 symbols across 10 files."
---

# Bridge

32 symbols | 10 files | Cohesion: 78%

## When to Use

- Working with code in `crates/`
- Understanding how new, begin, abandon work
- Modifying bridge-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/bridge/storage.rs` | new, begin, abandon, finish, fail (+9) |
| `crates/agenc-ircd-runtime/src/bridge/crypto.rs` | cancel, try_submit, in_flight, reap_finished, shutdown (+2) |
| `crates/agenc-ircd-runtime/src/channels.rs` | connection_closed, timer_fired, take_pending |
| `crates/agenc-ircd-runtime/src/bridge/mod.rs` | new, job_ids_round_trip_and_the_completion_capacity_is_two |
| `crates/agenc-ircd-runtime/tests/bridge_storage.rs` | the_ledger_and_classification_fail_closed_on_every_loss |
| `crates/agenc-ircd-runtime/tests/loom_models.rs` | completion_sender_loss |
| `crates/agenc-ircd-storage/src/owner.rs` | wait |
| `crates/agenc-ircd-runtime/src/account_service.rs` | cancel_closed_crypto |
| `crates/agenc-ircd-runtime/src/state_core/mod.rs` | crypto_mut |
| `crates/agenc-ircd-runtime/tests/bridge_crypto.rs` | verdict |

## Entry Points

Start here when exploring this area:

- **`new`** (Function) — `crates/agenc-ircd-runtime/src/bridge/storage.rs:118`
- **`begin`** (Function) — `crates/agenc-ircd-runtime/src/bridge/storage.rs:128`
- **`abandon`** (Function) — `crates/agenc-ircd-runtime/src/bridge/storage.rs:141`
- **`finish`** (Function) — `crates/agenc-ircd-runtime/src/bridge/storage.rs:146`
- **`fail`** (Function) — `crates/agenc-ircd-runtime/src/bridge/storage.rs:159`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `new` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 118 |
| `begin` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 128 |
| `abandon` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 141 |
| `finish` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 146 |
| `fail` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 159 |
| `start` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 208 |
| `submit_read` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 283 |
| `classify_completion` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 358 |
| `wait` | Function | `crates/agenc-ircd-storage/src/owner.rs` | 110 |
| `cancel` | Function | `crates/agenc-ircd-runtime/src/bridge/crypto.rs` | 944 |
| `connection_closed` | Function | `crates/agenc-ircd-runtime/src/channels.rs` | 310 |
| `timer_fired` | Function | `crates/agenc-ircd-runtime/src/channels.rs` | 325 |
| `crypto_mut` | Function | `crates/agenc-ircd-runtime/src/state_core/mod.rs` | 473 |
| `try_submit` | Function | `crates/agenc-ircd-runtime/src/bridge/crypto.rs` | 893 |
| `in_flight` | Function | `crates/agenc-ircd-runtime/src/bridge/crypto.rs` | 955 |
| `shutdown` | Function | `crates/agenc-ircd-runtime/src/bridge/crypto.rs` | 975 |
| `new` | Function | `crates/agenc-ircd-runtime/src/bridge/mod.rs` | 22 |
| `shutdown` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 329 |
| `default` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 180 |
| `bridge_loop` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 370 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Route_registered → Reap_finished` | cross_community | 5 |
| `Route_registered → CryptoSubmitRefused` | cross_community | 5 |
| `Route_registered → New` | cross_community | 5 |
| `Route_registered → CryptoCompletionMessage` | cross_community | 5 |
| `Route_registered → Crypto_mut` | cross_community | 4 |
| `Replay_read → Reap_finished` | cross_community | 4 |
| `Replay_read → CryptoSubmitRefused` | cross_community | 4 |
| `Replay_read → New` | cross_community | 4 |
| `Replay_read → CryptoCompletionMessage` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 4 calls |
| Connection | 4 calls |
| Cluster_315 | 2 calls |
| State_core | 1 calls |
| Listener | 1 calls |

## How to Explore

1. `context({name: "new"})` — see callers and callees
2. `query({search_query: "bridge"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
