---
name: listener
description: "Skill for the Listener area of agenc-ircd. 51 symbols across 10 files."
---

# Listener

51 symbols | 10 files | Cohesion: 67%

## When to Use

- Working with code in `crates/`
- Understanding how new, start, bind work
- Modifying listener-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/listener/mod.rs` | new, start, validate_spec, purpose_ceiling, run_listener (+15) |
| `crates/agenc-ircd-runtime/src/listener/socket.rs` | new, drop, bind, adopt_unix, bind_unix (+5) |
| `crates/agenc-ircd-runtime/src/admin.rs` | opened, line, closed, send, run_admin_connection (+1) |
| `crates/agenc-ircd-runtime/src/daemon.rs` | insert_alias, insert_listener_identity, validate_onion_pin, start_owners, spawn_listener_owner (+1) |
| `crates/agenc-ircd-runtime/src/tls/config.rs` | requires_client_certificate, leaf |
| `crates/agenc-ircd-runtime/src/listener/prefix.rs` | source_key, keys_follow_the_family_and_collapse_mapped_addresses |
| `crates/agenc-ircd-runtime/src/state_core/inbox.rs` | ipv6, source_keys_mask_to_the_spec_prefixes_and_stay_distinct_per_family |
| `crates/agenc-ircd-admin/src/challenge.rs` | as_bytes |
| `crates/agenc-ircd-runtime/src/budget/permit.rs` | split_exact |
| `crates/agenc-ircd-runtime/src/listener/spki.rs` | spki_sha256 |

## Entry Points

Start here when exploring this area:

- **`new`** (Function) — `crates/agenc-ircd-runtime/src/listener/mod.rs:82`
- **`start`** (Function) — `crates/agenc-ircd-runtime/src/listener/mod.rs:406`
- **`bind`** (Function) — `crates/agenc-ircd-runtime/src/listener/socket.rs:183`
- **`as_bytes`** (Function) — `crates/agenc-ircd-admin/src/challenge.rs:38`
- **`split_exact`** (Function) — `crates/agenc-ircd-runtime/src/budget/permit.rs:56`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `new` | Function | `crates/agenc-ircd-runtime/src/listener/mod.rs` | 82 |
| `start` | Function | `crates/agenc-ircd-runtime/src/listener/mod.rs` | 406 |
| `bind` | Function | `crates/agenc-ircd-runtime/src/listener/socket.rs` | 183 |
| `as_bytes` | Function | `crates/agenc-ircd-admin/src/challenge.rs` | 38 |
| `split_exact` | Function | `crates/agenc-ircd-runtime/src/budget/permit.rs` | 56 |
| `run_admin_connection` | Function | `crates/agenc-ircd-runtime/src/admin.rs` | 2546 |
| `spki_sha256` | Function | `crates/agenc-ircd-runtime/src/listener/spki.rs` | 25 |
| `requires_client_certificate` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 264 |
| `leaf` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 343 |
| `source_key` | Function | `crates/agenc-ircd-runtime/src/listener/prefix.rs` | 21 |
| `ipv6` | Function | `crates/agenc-ircd-runtime/src/state_core/inbox.rs` | 152 |
| `join` | Function | `crates/agenc-ircd-runtime/src/listener/mod.rs` | 491 |
| `validate_spec` | Function | `crates/agenc-ircd-runtime/src/listener/mod.rs` | 508 |
| `purpose_ceiling` | Function | `crates/agenc-ircd-runtime/src/listener/mod.rs` | 536 |
| `run_listener` | Function | `crates/agenc-ircd-runtime/src/listener/mod.rs` | 564 |
| `admit` | Function | `crates/agenc-ircd-runtime/src/listener/mod.rs` | 703 |
| `hand_off_federation` | Function | `crates/agenc-ircd-runtime/src/listener/mod.rs` | 768 |
| `prepare_admission` | Function | `crates/agenc-ircd-runtime/src/listener/mod.rs` | 828 |
| `acquire_charges` | Function | `crates/agenc-ircd-runtime/src/listener/mod.rs` | 921 |
| `specs_pair_purposes_with_transports_and_ceilings` | Function | `crates/agenc-ircd-runtime/src/listener/mod.rs` | 1283 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Federation_commands_record_intent_and_outcome → Result_class_rank` | cross_community | 6 |
| `Federation_commands_record_intent_and_outcome → Classify_admin_output` | cross_community | 6 |
| `Federation_commands_record_intent_and_outcome → Verb` | cross_community | 5 |
| `Start → Lock` | cross_community | 3 |
| `Start → Inner` | cross_community | 3 |
| `Run_connection → MemoryPermit` | cross_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Supervisor | 10 calls |
| Cluster_528 | 5 calls |
| Admission | 5 calls |
| Tests | 4 calls |
| Cluster_485 | 3 calls |
| Admin | 2 calls |
| Connection | 2 calls |
| State_core | 2 calls |

## How to Explore

1. `context({name: "new"})` — see callers and callees
2. `query({search_query: "listener"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
