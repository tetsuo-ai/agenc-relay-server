---
name: listener
description: "Skill for the Listener area of agenc-ircd. 110 symbols across 19 files."
---

# Listener

110 symbols | 19 files | Cohesion: 72%

## When to Use

- Working with code in `crates/`
- Understanding how admin_process_channel, new, admin_lifecycle_channel work
- Modifying listener-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/admin.rs` | admin_process_channel, new, start, admin_lifecycle_channel, try_export (+25) |
| `crates/agenc-ircd-runtime/src/listener/mod.rs` | stop_accepting, cancel_connections, released, arrived, start (+21) |
| `crates/agenc-ircd-testkit/src/tls_fixture.rs` | mint, validate_dns_name, derive_seed, encode_length, tlv (+11) |
| `crates/agenc-ircd-runtime/src/listener/socket.rs` | from, bind, adopt_tcp, adopt_unix, bind_unix (+3) |
| `crates/agenc-ircd-storage/src/redb_store.rs` | inject, read, set_len, sync_data, write |
| `crates/agenc-ircd-runtime/src/listener/spki.rs` | the_walker_reproduces_the_fixture_spki_digest, spki_sha256, read_tlv, sha256 |
| `crates/agenc-ircd-runtime/src/tls/stream.rs` | peer_certificates, export_keying_material, available, acquire |
| `crates/agenc-ircd-runtime/src/cancel.rs` | cancel, is_cancelled |
| `crates/agenc-ircd-runtime/src/tls/config.rs` | requires_client_certificate, leaf |
| `crates/agenc-ircd/tests/stage_six_daemon.rs` | drop, reserve_loopback_address |

## Entry Points

Start here when exploring this area:

- **`admin_process_channel`** (Function) — `crates/agenc-ircd-runtime/src/admin.rs:105`
- **`new`** (Function) — `crates/agenc-ircd-runtime/src/admin.rs:119`
- **`admin_lifecycle_channel`** (Function) — `crates/agenc-ircd-runtime/src/admin.rs:299`
- **`admin_transport_channel`** (Function) — `crates/agenc-ircd-runtime/src/admin.rs:429`
- **`empty_for_test`** (Function) — `crates/agenc-ircd-runtime/src/admin/audit.rs:273`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `admin_process_channel` | Function | `crates/agenc-ircd-runtime/src/admin.rs` | 105 |
| `new` | Function | `crates/agenc-ircd-runtime/src/admin.rs` | 119 |
| `admin_lifecycle_channel` | Function | `crates/agenc-ircd-runtime/src/admin.rs` | 299 |
| `admin_transport_channel` | Function | `crates/agenc-ircd-runtime/src/admin.rs` | 429 |
| `empty_for_test` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 273 |
| `cancel` | Function | `crates/agenc-ircd-runtime/src/cancel.rs` | 64 |
| `stop_accepting` | Function | `crates/agenc-ircd-runtime/src/listener/mod.rs` | 367 |
| `cancel_connections` | Function | `crates/agenc-ircd-runtime/src/listener/mod.rs` | 372 |
| `admin_core_channel` | Function | `crates/agenc-ircd-runtime/src/state_core/admin.rs` | 425 |
| `spawn` | Function | `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | 161 |
| `try_backup` | Function | `crates/agenc-ircd-storage/src/owner.rs` | 82 |
| `mint` | Function | `crates/agenc-ircd-testkit/src/tls_fixture.rs` | 89 |
| `is_cancelled` | Function | `crates/agenc-ircd-runtime/src/cancel.rs` | 75 |
| `start` | Function | `crates/agenc-ircd-runtime/src/listener/mod.rs` | 387 |
| `spki_sha256` | Function | `crates/agenc-ircd-runtime/src/listener/spki.rs` | 25 |
| `requires_client_certificate` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 86 |
| `leaf` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 159 |
| `peer_certificates` | Function | `crates/agenc-ircd-runtime/src/tls/stream.rs` | 225 |
| `bind` | Function | `crates/agenc-ircd-runtime/src/listener/socket.rs` | 112 |
| `as_bytes` | Function | `crates/agenc-ircd-admin/src/challenge.rs` | 38 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Start → Lock` | cross_community | 3 |
| `Start → Inner` | cross_community | 3 |
| `Account_mutation_waits_for_one_atomic_state_core_commit → Lock` | cross_community | 3 |
| `Account_mutation_waits_for_one_atomic_state_core_commit → AdminTransportPort` | intra_community | 3 |
| `Account_mutation_waits_for_one_atomic_state_core_commit → AdminOwnerInbox` | intra_community | 3 |
| `Account_mutation_waits_for_one_atomic_state_core_commit → AdminSessionBinding` | intra_community | 3 |
| `Account_mutation_waits_for_one_atomic_state_core_commit → AdminLifecycleControl` | intra_community | 3 |
| `Account_mutation_waits_for_one_atomic_state_core_commit → AdminLifecycleInbox` | intra_community | 3 |
| `Confirmed_die_commits_intent_before_requesting_stop → Lock` | cross_community | 3 |
| `Confirmed_die_commits_intent_before_requesting_stop → AdminTransportPort` | intra_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 10 calls |
| Admin | 6 calls |
| Cluster_319 | 6 calls |
| Admission | 6 calls |
| Budget | 2 calls |
| Connection | 2 calls |
| Cluster_22 | 2 calls |
| Cluster_427 | 1 calls |

## How to Explore

1. `context({name: "admin_process_channel"})` — see callers and callees
2. `query({search_query: "listener"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
