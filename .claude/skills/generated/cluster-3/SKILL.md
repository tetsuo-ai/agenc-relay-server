---
name: cluster-3
description: "Skill for the Cluster_3 area of agenc-ircd. 19 symbols across 2 files."
---

# Cluster_3

19 symbols | 2 files | Cohesion: 81%

## When to Use

- Working with code in `crates/`
- Understanding how generate, from_serialized, registration_start work
- Modifying cluster_3-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-auth/src/opaque.rs` | default, hash, new, succeeded, generate (+13) |
| `crates/agenc-ircd-types/src/identifiers.rs` | expose_for_account_service |

## Entry Points

Start here when exploring this area:

- **`generate`** (Function) — `crates/agenc-ircd-auth/src/opaque.rs:139`
- **`from_serialized`** (Function) — `crates/agenc-ircd-auth/src/opaque.rs:164`
- **`registration_start`** (Function) — `crates/agenc-ircd-auth/src/opaque.rs:202`
- **`authentication_start`** (Function) — `crates/agenc-ircd-auth/src/opaque.rs:226`
- **`dummy_finish_work`** (Function) — `crates/agenc-ircd-auth/src/opaque.rs:272`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `generate` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 139 |
| `from_serialized` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 164 |
| `registration_start` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 202 |
| `authentication_start` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 226 |
| `dummy_finish_work` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 272 |
| `finish_authentication` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 361 |
| `from_bytes` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 389 |
| `from_persisted_bytes` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 511 |
| `expose_for_account_service` | Function | `crates/agenc-ircd-types/src/identifiers.rs` | 317 |
| `default` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 55 |
| `hash` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 61 |
| `new` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 89 |
| `succeeded` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 93 |
| `build_fixed_fake_record` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 284 |
| `build_dummy_login_state` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 296 |
| `deserialize_setup` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 324 |
| `deserialize_record` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 331 |
| `opaque_context` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 339 |
| `server_parameters` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 346 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Generate → Fill_from` | cross_community | 6 |
| `Generate → Deserialize_record` | intra_community | 3 |
| `Finish_account_authentication → Opaque_context` | cross_community | 3 |
| `Finish_account_authentication → Server_parameters` | cross_community | 3 |
| `Finish_account_authentication → New` | cross_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 3 calls |
| Cluster_4 | 1 calls |

## How to Explore

1. `context({name: "generate"})` — see callers and callees
2. `query({search_query: "cluster_3"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
