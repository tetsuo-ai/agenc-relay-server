---
name: tls
description: "Skill for the Tls area of agenc-ircd. 107 symbols across 15 files."
---

# Tls

107 symbols | 15 files | Cohesion: 75%

## When to Use

- Working with code in `crates/`
- Understanding how parse, len, is_empty work
- Modifying tls-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/tls/config.rs` | new, from, parse, len, is_empty (+46) |
| `crates/agenc-ircd-runtime/src/tls/stream.rs` | peer_certificates, new, poll_flush, poll_shutdown, limiter_bounds_and_permits_follow_the_spec_table (+11) |
| `crates/agenc-ircd-runtime/src/tls/client_stream.rs` | read, is_would_block, poll_read_tls, poll_read, handshake (+5) |
| `crates/agenc-ircd-runtime/src/daemon.rs` | insert_alias, insert_listener_identity, insert_ca_identities, build_listener_specs, prepare_restart_material (+1) |
| `crates/agenc-ircd-runtime/tests/tls_endpoint.rs` | client_observing_ocsp, hybrid_required_refuses_a_client_offering_only_x25519, session_tickets_can_be_disabled_completely, enabled_session_tickets_use_the_exact_bounded_lifecycle, required_ocsp_is_fail_closed_and_the_supplied_staple_is_sent |
| `crates/agenc-ircd-testkit/src/tls_fixture.rs` | ca_certificate_der, leaf_certificate_der, leaf_private_key_pkcs8_der |
| `crates/agenc-ircd-runtime/src/listener/spki.rs` | spki_sha256, read_tlv, sha256 |
| `crates/agenc-ircd-crypto/src/hash.rs` | label, semantic_digest, semantic_domains_produce_distinct_results |
| `crates/agenc-ircd-crypto/src/tls_ticket.rs` | open, tls_ticket_key_id, parse_ticket |
| `crates/agenc-ircd/tests/stage_six_daemon.rs` | client_config, admin_tls_client_config |

## Entry Points

Start here when exploring this area:

- **`parse`** (Function) — `crates/agenc-ircd-runtime/src/tls/config.rs:318`
- **`len`** (Function) — `crates/agenc-ircd-runtime/src/tls/config.rs:328`
- **`is_empty`** (Function) — `crates/agenc-ircd-runtime/src/tls/config.rs:334`
- **`build_server_config_blocking`** (Function) — `crates/agenc-ircd-runtime/src/tls/config.rs:500`
- **`build_server_config_with_policy_blocking`** (Function) — `crates/agenc-ircd-runtime/src/tls/config.rs:518`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `parse` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 318 |
| `len` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 328 |
| `is_empty` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 334 |
| `build_server_config_blocking` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 500 |
| `build_server_config_with_policy_blocking` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 518 |
| `build_server_config` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 565 |
| `build_server_config_with_policy` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 583 |
| `load_certificate_chain` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 610 |
| `load_certificate_chain_material` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 619 |
| `load_trust_store` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 632 |
| `build_client_config` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 675 |
| `encode` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 866 |
| `ca_certificate_der` | Function | `crates/agenc-ircd-testkit/src/tls_fixture.rs` | 124 |
| `leaf_certificate_der` | Function | `crates/agenc-ircd-testkit/src/tls_fixture.rs` | 130 |
| `leaf_private_key_pkcs8_der` | Function | `crates/agenc-ircd-testkit/src/tls_fixture.rs` | 136 |
| `tls_private_key` | Function | `crates/agenc-ircd-config/src/secrets.rs` | 365 |
| `spki_sha256` | Function | `crates/agenc-ircd-runtime/src/listener/spki.rs` | 25 |
| `requires_client_certificate` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 261 |
| `leaf` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 340 |
| `spki_identities` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 413 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 17 calls |
| Listener | 3 calls |
| Cluster_172 | 2 calls |
| Admission | 1 calls |
| Cluster_33 | 1 calls |
| Cluster_150 | 1 calls |
| Cluster_381 | 1 calls |
| Cluster_382 | 1 calls |

## How to Explore

1. `context({name: "parse"})` — see callers and callees
2. `query({search_query: "tls"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
