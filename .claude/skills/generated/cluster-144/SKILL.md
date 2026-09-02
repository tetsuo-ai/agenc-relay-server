---
name: cluster-144
description: "Skill for the Cluster_144 area of agenc-ircd. 34 symbols across 6 files."
---

# Cluster_144

34 symbols | 6 files | Cohesion: 79%

## When to Use

- Working with code in `crates/`
- Understanding how allocation_charge, enabled_purposes, secret_paths work
- Modifying cluster_144-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-config/src/cross.rs` | validate, listener_union, ocsp_staple_policy, listener_key_reuse, topology (+11) |
| `crates/agenc-ircd-config/src/config.rs` | enabled_purposes, secret_paths, account_secret_paths, public_text_paths, trust_manifest_paths (+2) |
| `crates/agenc-ircd-config/src/paths.rs` | verify_host_paths, check_listener_material_paths, index_u16, check_directory, contained_by_any (+1) |
| `crates/agenc-ircd-config/src/error.rs` | indexed, push |
| `crates/agenc-ircd-config/src/secrets.rs` | tls_keys, secret_paths |
| `crates/agenc-ircd-config/src/bounds.rs` | allocation_charge |

## Entry Points

Start here when exploring this area:

- **`allocation_charge`** (Function) — `crates/agenc-ircd-config/src/bounds.rs:186`
- **`enabled_purposes`** (Function) — `crates/agenc-ircd-config/src/config.rs:117`
- **`secret_paths`** (Function) — `crates/agenc-ircd-config/src/config.rs:130`
- **`public_text_paths`** (Function) — `crates/agenc-ircd-config/src/config.rs:208`
- **`trust_manifest_paths`** (Function) — `crates/agenc-ircd-config/src/config.rs:224`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `allocation_charge` | Function | `crates/agenc-ircd-config/src/bounds.rs` | 186 |
| `enabled_purposes` | Function | `crates/agenc-ircd-config/src/config.rs` | 117 |
| `secret_paths` | Function | `crates/agenc-ircd-config/src/config.rs` | 130 |
| `public_text_paths` | Function | `crates/agenc-ircd-config/src/config.rs` | 208 |
| `trust_manifest_paths` | Function | `crates/agenc-ircd-config/src/config.rs` | 224 |
| `listener_material_paths` | Function | `crates/agenc-ircd-config/src/config.rs` | 238 |
| `validate` | Function | `crates/agenc-ircd-config/src/cross.rs` | 23 |
| `protocol_pool` | Function | `crates/agenc-ircd-config/src/cross.rs` | 632 |
| `working_set` | Function | `crates/agenc-ircd-config/src/cross.rs` | 648 |
| `indexed` | Function | `crates/agenc-ircd-config/src/error.rs` | 119 |
| `push` | Function | `crates/agenc-ircd-config/src/error.rs` | 253 |
| `verify_host_paths` | Function | `crates/agenc-ircd-config/src/paths.rs` | 189 |
| `index_u16` | Function | `crates/agenc-ircd-config/src/paths.rs` | 253 |
| `secret_paths` | Function | `crates/agenc-ircd-config/src/secrets.rs` | 597 |
| `account_secret_paths` | Function | `crates/agenc-ircd-config/src/config.rs` | 186 |
| `push_optional` | Function | `crates/agenc-ircd-config/src/config.rs` | 261 |
| `listener_union` | Function | `crates/agenc-ircd-config/src/cross.rs` | 180 |
| `ocsp_staple_policy` | Function | `crates/agenc-ircd-config/src/cross.rs` | 212 |
| `listener_key_reuse` | Function | `crates/agenc-ircd-config/src/cross.rs` | 253 |
| `topology` | Function | `crates/agenc-ircd-config/src/cross.rs` | 308 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Load → ConfigIssue` | cross_community | 6 |
| `Serve → ConfigIssue` | cross_community | 5 |
| `Verify_host_paths → Try_from` | cross_community | 4 |
| `Load → Try_from` | cross_community | 4 |
| `Verify_host_paths → Account_secret_paths` | intra_community | 3 |
| `Verify_host_paths → Push_optional` | intra_community | 3 |
| `Verify_host_paths → Indexed` | intra_community | 3 |
| `Verify_host_paths → ConfigIssue` | intra_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_172 | 7 calls |
| Cluster_148 | 5 calls |
| Cluster_150 | 3 calls |
| Cluster_182 | 1 calls |
| Admin | 1 calls |
| Cluster_175 | 1 calls |
| Tests | 1 calls |
| Cluster_174 | 1 calls |

## How to Explore

1. `context({name: "allocation_charge"})` — see callers and callees
2. `query({search_query: "cluster_144"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
