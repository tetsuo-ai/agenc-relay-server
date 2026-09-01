---
name: tls
description: "Skill for the Tls area of agenc-ircd. 39 symbols across 6 files."
---

# Tls

39 symbols | 6 files | Cohesion: 72%

## When to Use

- Working with code in `crates/`
- Understanding how tls_private_key, parse, len work
- Modifying tls-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/tls/config.rs` | parse, len, is_empty, provider, build_server_config_blocking (+17) |
| `crates/agenc-ircd-runtime/src/tls/stream.rs` | new, poll_flush, poll_shutdown, limiter_bounds_and_permits_follow_the_spec_table, acquire_waits_for_a_released_slot (+6) |
| `crates/agenc-ircd-testkit/src/tls_fixture.rs` | ca_certificate_der, leaf_certificate_der, leaf_private_key_pkcs8_der |
| `crates/agenc-ircd-config/src/secrets.rs` | tls_private_key |
| `crates/agenc-ircd-runtime/src/daemon.rs` | build_listener_specs |
| `crates/agenc-ircd/tests/stage_six_daemon.rs` | client_config |

## Entry Points

Start here when exploring this area:

- **`tls_private_key`** (Function) — `crates/agenc-ircd-config/src/secrets.rs:357`
- **`parse`** (Function) — `crates/agenc-ircd-runtime/src/tls/config.rs:137`
- **`len`** (Function) — `crates/agenc-ircd-runtime/src/tls/config.rs:147`
- **`is_empty`** (Function) — `crates/agenc-ircd-runtime/src/tls/config.rs:153`
- **`provider`** (Function) — `crates/agenc-ircd-runtime/src/tls/config.rs:237`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `tls_private_key` | Function | `crates/agenc-ircd-config/src/secrets.rs` | 357 |
| `parse` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 137 |
| `len` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 147 |
| `is_empty` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 153 |
| `provider` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 237 |
| `build_server_config_blocking` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 253 |
| `build_server_config` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 284 |
| `load_certificate_chain` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 301 |
| `load_certificate_chain_material` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 310 |
| `load_trust_store` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 323 |
| `load_trust_store_material` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 332 |
| `build_client_config` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 345 |
| `ca_certificate_der` | Function | `crates/agenc-ircd-testkit/src/tls_fixture.rs` | 124 |
| `leaf_certificate_der` | Function | `crates/agenc-ircd-testkit/src/tls_fixture.rs` | 130 |
| `leaf_private_key_pkcs8_der` | Function | `crates/agenc-ircd-testkit/src/tls_fixture.rs` | 136 |
| `new` | Function | `crates/agenc-ircd-runtime/src/tls/stream.rs` | 89 |
| `encode` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 423 |
| `build_listener_specs` | Function | `crates/agenc-ircd-runtime/src/daemon.rs` | 769 |
| `parse_certificates` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 367 |
| `read_bounded` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 385 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Listener | 6 calls |
| Tests | 2 calls |
| Cluster_174 | 2 calls |
| Budget | 1 calls |
| Admin | 1 calls |

## How to Explore

1. `context({name: "tls_private_key"})` — see callers and callees
2. `query({search_query: "tls"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
