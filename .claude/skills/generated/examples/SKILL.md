---
name: examples
description: "Skill for the Examples area of agenc-ircd. 49 symbols across 9 files."
---

# Examples

49 symbols | 9 files | Cohesion: 74%

## When to Use

- Working with code in `crates/`
- Understanding how fill, generate, generate work
- Modifying examples-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/examples/storage-qualification.rs` | measure_growth, prepare_case, run_case, insert_value, delete_value (+16) |
| `crates/agenc-ircd-crypto/src/tls_ticket.rs` | generate, key_id, seal, generate_with, seal_with (+6) |
| `crates/agenc-ircd-storage/src/qualification.rs` | measure_file, measure_required_corpus, measure_required_file_set, finish, native (+1) |
| `crates/agenc-ircd-storage/examples/storage-qualification-sign.rs` | main, read_private_seed, read_bounded, write_private_file |
| `crates/agenc-ircd-runtime/src/offline.rs` | random_32, unique_suffix |
| `crates/agenc-ircd-storage/tests/stage_five_completion.rs` | signed_growth_report_is_exact_tuple_authority, qualification_required_file_set_measures_every_named_durable_case |
| `crates/agenc-ircd-crypto/src/entropy.rs` | fill |
| `crates/agenc-ircd-crypto/src/signature.rs` | generate |
| `crates/agenc-ircd-storage/examples/storage-qualification-keygen.rs` | main |

## Entry Points

Start here when exploring this area:

- **`fill`** (Function) — `crates/agenc-ircd-crypto/src/entropy.rs:15`
- **`generate`** (Function) — `crates/agenc-ircd-crypto/src/signature.rs:206`
- **`generate`** (Function) — `crates/agenc-ircd-crypto/src/tls_ticket.rs:48`
- **`key_id`** (Function) — `crates/agenc-ircd-crypto/src/tls_ticket.rs:54`
- **`seal`** (Function) — `crates/agenc-ircd-crypto/src/tls_ticket.rs:59`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `fill` | Function | `crates/agenc-ircd-crypto/src/entropy.rs` | 15 |
| `generate` | Function | `crates/agenc-ircd-crypto/src/signature.rs` | 206 |
| `generate` | Function | `crates/agenc-ircd-crypto/src/tls_ticket.rs` | 48 |
| `key_id` | Function | `crates/agenc-ircd-crypto/src/tls_ticket.rs` | 54 |
| `seal` | Function | `crates/agenc-ircd-crypto/src/tls_ticket.rs` | 59 |
| `measure_file` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 416 |
| `measure_required_corpus` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 481 |
| `measure_required_file_set` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 497 |
| `finish` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 509 |
| `native` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 72 |
| `decode_unsigned` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 303 |
| `generate_with` | Function | `crates/agenc-ircd-crypto/src/tls_ticket.rs` | 87 |
| `seal_with` | Function | `crates/agenc-ircd-crypto/src/tls_ticket.rs` | 108 |
| `encode_header` | Function | `crates/agenc-ircd-crypto/src/tls_ticket.rs` | 212 |
| `fixed_key` | Function | `crates/agenc-ircd-crypto/src/tls_ticket.rs` | 240 |
| `versioned_ticket_round_trips_and_random_nonces_change_ciphertext` | Function | `crates/agenc-ircd-crypto/src/tls_ticket.rs` | 255 |
| `exact_ticket_bound_is_enforced_before_network_allocation` | Function | `crates/agenc-ircd-crypto/src/tls_ticket.rs` | 273 |
| `malformed_and_tampered_attacker_tickets_fail_closed` | Function | `crates/agenc-ircd-crypto/src/tls_ticket.rs` | 288 |
| `wrong_generation_and_entropy_failures_return_closed_errors` | Function | `crates/agenc-ircd-crypto/src/tls_ticket.rs` | 312 |
| `random_32` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 1066 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 13 calls |
| Cluster_198 | 2 calls |
| Cluster_201 | 1 calls |
| Cluster_197 | 1 calls |
| State_core | 1 calls |

## How to Explore

1. `context({name: "fill"})` — see callers and callees
2. `query({search_query: "examples"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
