---
name: cluster-2
description: "Skill for the Cluster_2 area of agenc-ircd. 22 symbols across 1 files."
---

# Cluster_2

22 symbols | 1 files | Cohesion: 83%

## When to Use

- Working with code in `crates/`
- Understanding how generate, from_serialized, authentication_start work
- Modifying cluster_2-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-auth/src/opaque.rs` | default, hash, new, succeeded, fill_bytes (+17) |

## Entry Points

Start here when exploring this area:

- **`generate`** (Function) — `crates/agenc-ircd-auth/src/opaque.rs:149`
- **`from_serialized`** (Function) — `crates/agenc-ircd-auth/src/opaque.rs:176`
- **`authentication_start`** (Function) — `crates/agenc-ircd-auth/src/opaque.rs:240`
- **`dummy_finish_work`** (Function) — `crates/agenc-ircd-auth/src/opaque.rs:281`
- **`finish_authentication`** (Function) — `crates/agenc-ircd-auth/src/opaque.rs:407`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `generate` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 149 |
| `from_serialized` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 176 |
| `authentication_start` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 240 |
| `dummy_finish_work` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 281 |
| `finish_authentication` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 407 |
| `from_bytes` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 439 |
| `finish_registration` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 494 |
| `default` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 56 |
| `hash` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 62 |
| `new` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 91 |
| `succeeded` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 95 |
| `fill_bytes` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 128 |
| `build_fixed_fake_record` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 293 |
| `validate_fixed_fake_record` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 314 |
| `build_dummy_login_state` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 327 |
| `opaque_rng_result` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 356 |
| `deserialize_setup` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 363 |
| `deserialize_record` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 370 |
| `opaque_context` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 378 |
| `server_parameters` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 392 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Generate → Fill_from` | cross_community | 6 |
| `Generate → Deserialize_record` | intra_community | 4 |
| `Credential_replacement_reuses_identity_and_fences_generation → Deserialize_setup` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_4 | 2 calls |
| Cluster_3 | 1 calls |

## How to Explore

1. `context({name: "generate"})` — see callers and callees
2. `query({search_query: "cluster_2"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
