---
name: tls
description: "Skill for the Tls area of agenc-ircd. 99 symbols across 13 files."
---

# Tls

99 symbols | 13 files | Cohesion: 68%

## When to Use

- Working with code in `crates/`
- Understanding how build_server_config_blocking, build_server_config_with_policy_blocking, build_server_config work
- Modifying tls-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/tls/config.rs` | compatibility_default, build_server_config_blocking, build_server_config_with_policy_blocking, build_server_config, build_server_config_with_policy (+44) |
| `crates/agenc-ircd-runtime/src/tls/stream.rs` | new, poll_flush, poll_shutdown, limiter_bounds_and_permits_follow_the_spec_table, acquire_waits_for_a_released_slot (+10) |
| `crates/agenc-ircd-runtime/src/tls/client_stream.rs` | read, is_would_block, poll_read_tls, poll_read, handshake (+5) |
| `crates/agenc-ircd-runtime/tests/tls_endpoint.rs` | client_observing_ocsp, hybrid_required_refuses_a_client_offering_only_x25519, session_tickets_can_be_disabled_completely, enabled_session_tickets_use_the_exact_bounded_lifecycle, required_ocsp_is_fail_closed_and_the_supplied_staple_is_sent |
| `crates/agenc-ircd-runtime/src/daemon.rs` | federation_setup, edge_dial_plan, insert_alias, insert_ca_identities, prepare_restart_material |
| `crates/agenc-ircd-testkit/src/tls_fixture.rs` | ca_certificate_der, leaf_certificate_der, leaf_private_key_pkcs8_der |
| `crates/agenc-ircd-crypto/src/hash.rs` | label, semantic_digest, semantic_domains_produce_distinct_results |
| `crates/agenc-ircd-crypto/src/tls_ticket.rs` | open, tls_ticket_key_id, parse_ticket |
| `crates/agenc-ircd/tests/stage_six_daemon.rs` | client_config, admin_tls_client_config |
| `crates/agenc-ircd-runtime/tests/tor_client.rs` | server_tls |

## Entry Points

Start here when exploring this area:

- **`build_server_config_blocking`** (Function) — `crates/agenc-ircd-runtime/src/tls/config.rs:503`
- **`build_server_config_with_policy_blocking`** (Function) — `crates/agenc-ircd-runtime/src/tls/config.rs:521`
- **`build_server_config`** (Function) — `crates/agenc-ircd-runtime/src/tls/config.rs:568`
- **`build_server_config_with_policy`** (Function) — `crates/agenc-ircd-runtime/src/tls/config.rs:586`
- **`build_client_config`** (Function) — `crates/agenc-ircd-runtime/src/tls/config.rs:678`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `build_server_config_blocking` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 503 |
| `build_server_config_with_policy_blocking` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 521 |
| `build_server_config` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 568 |
| `build_server_config_with_policy` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 586 |
| `build_client_config` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 678 |
| `ca_certificate_der` | Function | `crates/agenc-ircd-testkit/src/tls_fixture.rs` | 165 |
| `leaf_certificate_der` | Function | `crates/agenc-ircd-testkit/src/tls_fixture.rs` | 171 |
| `leaf_private_key_pkcs8_der` | Function | `crates/agenc-ircd-testkit/src/tls_fixture.rs` | 177 |
| `read_protected_bytes` | Function | `crates/agenc-ircd-config/src/paths.rs` | 81 |
| `semantic_digest` | Function | `crates/agenc-ircd-crypto/src/hash.rs` | 318 |
| `load_certificate_chain` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 613 |
| `load_certificate_chain_material` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 622 |
| `load_trust_store` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 635 |
| `load_trust_store_material` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 644 |
| `load_ocsp_staple` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 656 |
| `load_ocsp_staple_material` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 662 |
| `parse` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 321 |
| `len` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 331 |
| `is_empty` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 337 |
| `encode` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 972 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Serve → Try_from` | cross_community | 6 |
| `Serve → Protected_ancestors` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 13 calls |
| Federation | 5 calls |
| State_core | 5 calls |
| Cluster_174 | 2 calls |
| Cluster_197 | 1 calls |
| Listener | 1 calls |
| Admission | 1 calls |
| Cluster_168 | 1 calls |

## How to Explore

1. `context({name: "build_server_config_blocking"})` — see callers and callees
2. `query({search_query: "tls"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
