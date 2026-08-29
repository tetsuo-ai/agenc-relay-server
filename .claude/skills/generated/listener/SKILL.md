---
name: listener
description: "Skill for the Listener area of agenc-ircd. 59 symbols across 11 files."
---

# Listener

59 symbols | 11 files | Cohesion: 79%

## When to Use

- Working with code in `crates/`
- Understanding how mint, source_key, ipv4 work
- Modifying listener-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/listener/mod.rs` | next_accept, released, start, uses_unix_socket, validate_spec (+12) |
| `crates/agenc-ircd-testkit/src/tls_fixture.rs` | mint, validate_dns_name, derive_seed, encode_length, tlv (+11) |
| `crates/agenc-ircd-runtime/src/listener/socket.rs` | from, bind, adopt_tcp, adopt_unix, bind_unix (+3) |
| `crates/agenc-ircd-runtime/src/listener/spki.rs` | the_walker_reproduces_the_fixture_spki_digest, spki_sha256, read_tlv, sha256 |
| `crates/agenc-ircd-runtime/src/state_core/inbox.rs` | ipv4, ipv6, source_keys_mask_to_the_spec_prefixes_and_stay_distinct_per_family, onion_listener |
| `crates/agenc-ircd-runtime/src/tls/config.rs` | for_purpose, requires_client_certificate, alpn |
| `crates/agenc-ircd-runtime/src/listener/prefix.rs` | source_key, keys_follow_the_family_and_collapse_mapped_addresses |
| `crates/agenc-ircd-runtime/src/tls/stream.rs` | acquire, peer_certificates |
| `crates/agenc-ircd-runtime/src/admission/prefix.rs` | prefix |
| `crates/agenc-ircd-runtime/src/cancel.rs` | is_cancelled |

## Entry Points

Start here when exploring this area:

- **`mint`** (Function) — `crates/agenc-ircd-testkit/src/tls_fixture.rs:89`
- **`source_key`** (Function) — `crates/agenc-ircd-runtime/src/listener/prefix.rs:21`
- **`ipv4`** (Function) — `crates/agenc-ircd-runtime/src/state_core/inbox.rs:48`
- **`ipv6`** (Function) — `crates/agenc-ircd-runtime/src/state_core/inbox.rs:59`
- **`acquire`** (Function) — `crates/agenc-ircd-runtime/src/tls/stream.rs:112`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `mint` | Function | `crates/agenc-ircd-testkit/src/tls_fixture.rs` | 89 |
| `source_key` | Function | `crates/agenc-ircd-runtime/src/listener/prefix.rs` | 21 |
| `ipv4` | Function | `crates/agenc-ircd-runtime/src/state_core/inbox.rs` | 48 |
| `ipv6` | Function | `crates/agenc-ircd-runtime/src/state_core/inbox.rs` | 59 |
| `acquire` | Function | `crates/agenc-ircd-runtime/src/tls/stream.rs` | 112 |
| `is_cancelled` | Function | `crates/agenc-ircd-runtime/src/cancel.rs` | 75 |
| `start` | Function | `crates/agenc-ircd-runtime/src/listener/mod.rs` | 223 |
| `onion_listener` | Function | `crates/agenc-ircd-runtime/src/state_core/inbox.rs` | 69 |
| `for_purpose` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 63 |
| `bind` | Function | `crates/agenc-ircd-runtime/src/listener/socket.rs` | 109 |
| `spki_sha256` | Function | `crates/agenc-ircd-runtime/src/listener/spki.rs` | 25 |
| `requires_client_certificate` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 84 |
| `peer_certificates` | Function | `crates/agenc-ircd-runtime/src/tls/stream.rs` | 225 |
| `split_exact` | Function | `crates/agenc-ircd-runtime/src/budget/permit.rs` | 56 |
| `alpn` | Function | `crates/agenc-ircd-runtime/src/tls/config.rs` | 74 |
| `the_walker_reproduces_the_fixture_spki_digest` | Function | `crates/agenc-ircd-runtime/src/listener/spki.rs` | 91 |
| `validate_dns_name` | Function | `crates/agenc-ircd-testkit/src/tls_fixture.rs` | 153 |
| `derive_seed` | Function | `crates/agenc-ircd-testkit/src/tls_fixture.rs` | 167 |
| `encode_length` | Function | `crates/agenc-ircd-testkit/src/tls_fixture.rs` | 174 |
| `tlv` | Function | `crates/agenc-ircd-testkit/src/tls_fixture.rs` | 189 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Start → Lock` | cross_community | 3 |
| `Start → Inner` | cross_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 4 calls |
| Cluster_266 | 3 calls |
| Cluster_165 | 1 calls |
| Connection | 1 calls |
| Cluster_126 | 1 calls |

## How to Explore

1. `context({name: "mint"})` — see callers and callees
2. `query({search_query: "listener"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
