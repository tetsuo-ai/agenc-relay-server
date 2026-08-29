---
name: cluster-95
description: "Skill for the Cluster_95 area of agenc-ircd. 14 symbols across 1 files."
---

# Cluster_95

14 symbols | 1 files | Cohesion: 75%

## When to Use

- Working with code in `crates/`
- Understanding how from_bytes, key_id, generate work
- Modifying cluster_95-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-crypto/src/account_hpke.rs` | from_bytes, key_id, generate, new, seal_response (+9) |

## Entry Points

Start here when exploring this area:

- **`from_bytes`** (Function) — `crates/agenc-ircd-crypto/src/account_hpke.rs:53`
- **`key_id`** (Function) — `crates/agenc-ircd-crypto/src/account_hpke.rs:84`
- **`generate`** (Function) — `crates/agenc-ircd-crypto/src/account_hpke.rs:110`
- **`new`** (Function) — `crates/agenc-ircd-crypto/src/account_hpke.rs:143`
- **`seal_response`** (Function) — `crates/agenc-ircd-crypto/src/account_hpke.rs:430`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `from_bytes` | Function | `crates/agenc-ircd-crypto/src/account_hpke.rs` | 53 |
| `key_id` | Function | `crates/agenc-ircd-crypto/src/account_hpke.rs` | 84 |
| `generate` | Function | `crates/agenc-ircd-crypto/src/account_hpke.rs` | 110 |
| `new` | Function | `crates/agenc-ircd-crypto/src/account_hpke.rs` | 143 |
| `seal_response` | Function | `crates/agenc-ircd-crypto/src/account_hpke.rs` | 430 |
| `open_response` | Function | `crates/agenc-ircd-crypto/src/account_hpke.rs` | 475 |
| `expected_response_kind` | Function | `crates/agenc-ircd-crypto/src/account_hpke.rs` | 511 |
| `export_response_material` | Function | `crates/agenc-ircd-crypto/src/account_hpke.rs` | 576 |
| `export_client_response_material` | Function | `crates/agenc-ircd-crypto/src/account_hpke.rs` | 594 |
| `response_export_context` | Function | `crates/agenc-ircd-crypto/src/account_hpke.rs` | 612 |
| `response_aad` | Function | `crates/agenc-ircd-crypto/src/account_hpke.rs` | 628 |
| `generated_private_key_has_a_stable_public_key` | Function | `crates/agenc-ircd-crypto/src/account_hpke.rs` | 660 |
| `fixed_request_and_exported_response_round_trip` | Function | `crates/agenc-ircd-crypto/src/account_hpke.rs` | 670 |
| `one_shot_rng_and_aad_length_fail_closed` | Function | `crates/agenc-ircd-crypto/src/account_hpke.rs` | 716 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Seal_response → New` | intra_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 4 calls |
| Cluster_96 | 2 calls |

## How to Explore

1. `context({name: "from_bytes"})` — see callers and callees
2. `query({search_query: "cluster_95"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
