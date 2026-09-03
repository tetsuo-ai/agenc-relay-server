---
name: listener
description: "Skill for the Listener area of agenc-ircd. 63 symbols across 11 files."
---

# Listener

63 symbols | 11 files | Cohesion: 71%

## When to Use

- Working with code in `crates/`
- Understanding how backing_charge, new_live, new work
- Modifying listener-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/listener/mod.rs` | new, released, arrived, start, uses_unix_socket (+21) |
| `crates/agenc-ircd-runtime/src/listener/socket.rs` | from, from_metadata, matches, new, drop (+9) |
| `crates/agenc-ircd-runtime/src/tls/stream.rs` | peer_certificates, export_keying_material, available, acquire |
| `crates/agenc-ircd-runtime/src/daemon.rs` | runtime_purpose, insert_listener_identity, build_listener_specs, validate_onion_pin |
| `crates/agenc-ircd-runtime/src/connection/queue.rs` | backing_charge, new_live, new_with_runtime_config |
| `crates/agenc-ircd-runtime/src/tls/config.rs` | alpn, requires_client_certificate, leaf |
| `crates/agenc-ircd-runtime/src/listener/spki.rs` | spki_sha256, read_tlv, sha256 |
| `crates/agenc-ircd-runtime/src/listener/prefix.rs` | source_key, keys_follow_the_family_and_collapse_mapped_addresses |
| `crates/agenc-ircd-runtime/src/state_core/inbox.rs` | ipv6, source_keys_mask_to_the_spec_prefixes_and_stay_distinct_per_family |
| `crates/agenc-ircd-admin/src/challenge.rs` | as_bytes |

## Entry Points

Start here when exploring this area:

- **`backing_charge`** (Function) — `crates/agenc-ircd-runtime/src/connection/queue.rs:138`
- **`new_live`** (Function) — `crates/agenc-ircd-runtime/src/connection/queue.rs:271`
- **`new`** (Function) — `crates/agenc-ircd-runtime/src/listener/mod.rs:82`
- **`start`** (Function) — `crates/agenc-ircd-runtime/src/listener/mod.rs:406`
- **`bind`** (Function) — `crates/agenc-ircd-runtime/src/listener/socket.rs:183`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `backing_charge` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 138 |
| `new_live` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 271 |
| `new` | Function | `crates/agenc-ircd-runtime/src/listener/mod.rs` | 82 |
| `start` | Function | `crates/agenc-ircd-runtime/src/listener/mod.rs` | 406 |
| `bind` | Function | `crates/agenc-ircd-runtime/src/listener/socket.rs` | 183 |
| `as_bytes` | Function | `crates/agenc-ircd-admin/src/challenge.rs` | 38 |
| `split_exact` | Function | `crates/agenc-ircd-runtime/src/budget/permit.rs` | 56 |
| `alpn` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 254 |
| `requires_client_certificate` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 264 |
| `peer_certificates` | Function | `crates/agenc-ircd-runtime/src/tls/stream.rs` | 225 |
| `export_keying_material` | Function | `crates/agenc-ircd-runtime/src/tls/stream.rs` | 230 |
| `spki_sha256` | Function | `crates/agenc-ircd-runtime/src/listener/spki.rs` | 25 |
| `leaf` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 343 |
| `source_key` | Function | `crates/agenc-ircd-runtime/src/listener/prefix.rs` | 21 |
| `ipv6` | Function | `crates/agenc-ircd-runtime/src/state_core/inbox.rs` | 152 |
| `available` | Function | `crates/agenc-ircd-runtime/src/tls/stream.rs` | 107 |
| `acquire` | Function | `crates/agenc-ircd-runtime/src/tls/stream.rs` | 112 |
| `new_with_runtime_config` | Function | `crates/agenc-ircd-runtime/src/connection/queue.rs` | 280 |
| `released` | Function | `crates/agenc-ircd-runtime/src/listener/mod.rs` | 134 |
| `arrived` | Function | `crates/agenc-ircd-runtime/src/listener/mod.rs` | 361 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Start → Lock` | cross_community | 3 |
| `Start → Inner` | cross_community | 3 |
| `Run_connection → MemoryPermit` | cross_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tls | 6 calls |
| State_core | 6 calls |
| Admission | 5 calls |
| Tests | 4 calls |
| Federation | 3 calls |
| Cluster_174 | 2 calls |
| Connection | 2 calls |
| Cluster_32 | 1 calls |

## How to Explore

1. `context({name: "backing_charge"})` — see callers and callees
2. `query({search_query: "listener"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
