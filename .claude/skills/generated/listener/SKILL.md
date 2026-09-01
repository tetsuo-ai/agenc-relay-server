---
name: listener
description: "Skill for the Listener area of agenc-ircd. 106 symbols across 20 files."
---

# Listener

106 symbols | 20 files | Cohesion: 73%

## When to Use

- Working with code in `crates/`
- Understanding how admin_process_channel, new, admin_lifecycle_channel work
- Modifying listener-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/admin.rs` | admin_process_channel, new, start, admin_lifecycle_channel, try_export (+25) |
| `crates/agenc-ircd-runtime/src/listener/mod.rs` | stop_accepting, cancel_connections, serve_inner, negotiate, local_peer_identity (+19) |
| `crates/agenc-ircd-testkit/src/tls_fixture.rs` | mint, validate_dns_name, derive_seed, encode_length, tlv (+11) |
| `crates/agenc-ircd-runtime/src/listener/socket.rs` | from, bind, adopt_tcp, adopt_unix, bind_unix (+3) |
| `crates/agenc-ircd-runtime/src/listener/spki.rs` | the_walker_reproduces_the_fixture_spki_digest, spki_sha256, read_tlv, sha256 |
| `crates/agenc-ircd-runtime/src/tls/stream.rs` | export_keying_material, peer_certificates, available, acquire |
| `crates/agenc-ircd-runtime/src/tls/config.rs` | alpn, requires_client_certificate, leaf |
| `crates/agenc-ircd-runtime/src/cancel.rs` | cancel, is_cancelled |
| `crates/agenc-ircd/tests/stage_six_daemon.rs` | drop, reserve_loopback_address |
| `crates/agenc-ircd-runtime/src/listener/prefix.rs` | source_key, keys_follow_the_family_and_collapse_mapped_addresses |

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
| `stop_accepting` | Function | `crates/agenc-ircd-runtime/src/listener/mod.rs` | 353 |
| `cancel_connections` | Function | `crates/agenc-ircd-runtime/src/listener/mod.rs` | 358 |
| `admin_core_channel` | Function | `crates/agenc-ircd-runtime/src/state_core/admin.rs` | 425 |
| `spawn` | Function | `crates/agenc-ircd-runtime/src/supervisor/mod.rs` | 161 |
| `try_backup` | Function | `crates/agenc-ircd-storage/src/owner.rs` | 82 |
| `mint` | Function | `crates/agenc-ircd-testkit/src/tls_fixture.rs` | 89 |
| `bind` | Function | `crates/agenc-ircd-runtime/src/listener/socket.rs` | 112 |
| `as_bytes` | Function | `crates/agenc-ircd-admin/src/challenge.rs` | 38 |
| `split_exact` | Function | `crates/agenc-ircd-runtime/src/budget/permit.rs` | 56 |
| `alpn` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 76 |
| `export_keying_material` | Function | `crates/agenc-ircd-runtime/src/tls/stream.rs` | 230 |
| `is_cancelled` | Function | `crates/agenc-ircd-runtime/src/cancel.rs` | 75 |
| `start` | Function | `crates/agenc-ircd-runtime/src/listener/mod.rs` | 373 |
| `spki_sha256` | Function | `crates/agenc-ircd-runtime/src/listener/spki.rs` | 25 |

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
| Tests | 12 calls |
| Admin | 6 calls |
| Cluster_313 | 6 calls |
| Admission | 5 calls |
| Connection | 3 calls |
| Cluster_22 | 2 calls |
| Cluster_12 | 1 calls |
| Cluster_3 | 1 calls |

## How to Explore

1. `context({name: "admin_process_channel"})` — see callers and callees
2. `query({search_query: "listener"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
