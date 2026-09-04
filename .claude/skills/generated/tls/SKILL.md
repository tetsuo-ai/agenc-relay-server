---
name: tls
description: "Skill for the Tls area of agenc-ircd. 56 symbols across 9 files."
---

# Tls

56 symbols | 9 files | Cohesion: 66%

## When to Use

- Working with code in `crates/`
- Understanding how read_protected_bytes, tls_private_key, semantic_digest work
- Modifying tls-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/tls/config.rs` | parse, len, is_empty, load_certificate_chain, load_certificate_chain_material (+23) |
| `crates/agenc-ircd-runtime/src/tls/stream.rs` | new, read, is_would_block, poll_read_tls, poll_read (+5) |
| `crates/agenc-ircd-runtime/src/tls/client_stream.rs` | handshake, poll_handshake, close_after_rejection, poll_write_tls, is_would_block (+2) |
| `crates/agenc-ircd-runtime/src/daemon.rs` | edge_dial_plan, insert_ca_identities, build_listener_specs, prepare_restart_material |
| `crates/agenc-ircd-crypto/src/tls_ticket.rs` | open, tls_ticket_key_id, parse_ticket |
| `crates/agenc-ircd-config/src/paths.rs` | read_protected_bytes |
| `crates/agenc-ircd-config/src/secrets.rs` | tls_private_key |
| `crates/agenc-ircd-crypto/src/hash.rs` | semantic_digest |
| `crates/agenc-ircd-runtime/src/tor_client.rs` | prepare |

## Entry Points

Start here when exploring this area:

- **`read_protected_bytes`** (Function) — `crates/agenc-ircd-config/src/paths.rs:81`
- **`tls_private_key`** (Function) — `crates/agenc-ircd-config/src/secrets.rs:365`
- **`semantic_digest`** (Function) — `crates/agenc-ircd-crypto/src/hash.rs:318`
- **`parse`** (Function) — `crates/agenc-ircd-runtime/src/tls/config.rs:321`
- **`len`** (Function) — `crates/agenc-ircd-runtime/src/tls/config.rs:331`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `read_protected_bytes` | Function | `crates/agenc-ircd-config/src/paths.rs` | 81 |
| `tls_private_key` | Function | `crates/agenc-ircd-config/src/secrets.rs` | 365 |
| `semantic_digest` | Function | `crates/agenc-ircd-crypto/src/hash.rs` | 318 |
| `parse` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 321 |
| `len` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 331 |
| `is_empty` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 337 |
| `load_certificate_chain` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 613 |
| `load_certificate_chain_material` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 622 |
| `load_trust_store` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 635 |
| `load_trust_store_material` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 644 |
| `load_ocsp_staple_material` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 662 |
| `new` | Function | `crates/agenc-ircd-runtime/src/tls/stream.rs` | 89 |
| `provider` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 479 |
| `build_client_config_with_group_policy` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 691 |
| `build_pinned_client_config_with_group_policy` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 882 |
| `open` | Function | `crates/agenc-ircd-crypto/src/tls_ticket.rs` | 64 |
| `tls_ticket_key_id` | Function | `crates/agenc-ircd-crypto/src/tls_ticket.rs` | 165 |
| `handshake` | Function | `crates/agenc-ircd-runtime/src/tls/client_stream.rs` | 67 |
| `handshake` | Function | `crates/agenc-ircd-runtime/src/tls/stream.rs` | 182 |
| `encode` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 972 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Policy → Label` | cross_community | 7 |
| `Binding_package → Label` | cross_community | 6 |
| `Serve → Protected_ancestors` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 5 calls |
| Listener | 3 calls |
| Coordinator | 3 calls |
| Cluster_215 | 1 calls |
| Cluster_37 | 1 calls |
| Cluster_571 | 1 calls |
| Cluster_566 | 1 calls |
| Cluster_575 | 1 calls |

## How to Explore

1. `context({name: "read_protected_bytes"})` — see callers and callees
2. `query({search_query: "tls"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
