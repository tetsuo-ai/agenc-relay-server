---
name: cluster-126
description: "Skill for the Cluster_126 area of agenc-ircd. 31 symbols across 8 files."
---

# Cluster_126

31 symbols | 8 files | Cohesion: 83%

## When to Use

- Working with code in `crates/`
- Understanding how allocation_charge, enabled_purposes, validate work
- Modifying cluster_126-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-config/src/cross.rs` | validate, issue, identity, onboarding_listeners, listener_enabled (+18) |
| `crates/agenc-ircd-config/src/error.rs` | indexed, push |
| `crates/agenc-ircd-config/src/bounds.rs` | allocation_charge |
| `crates/agenc-ircd-config/src/config.rs` | enabled_purposes |
| `crates/agenc-ircd-config/src/limits.rs` | get |
| `crates/agenc-ircd-config/src/paths.rs` | index_u16 |
| `crates/agenc-ircd-config/src/scalar.rs` | as_str |
| `crates/agenc-ircd-config/src/secrets.rs` | tls_keys |

## Entry Points

Start here when exploring this area:

- **`allocation_charge`** (Function) — `crates/agenc-ircd-config/src/bounds.rs:186`
- **`enabled_purposes`** (Function) — `crates/agenc-ircd-config/src/config.rs:117`
- **`validate`** (Function) — `crates/agenc-ircd-config/src/cross.rs:23`
- **`protocol_pool`** (Function) — `crates/agenc-ircd-config/src/cross.rs:581`
- **`working_set`** (Function) — `crates/agenc-ircd-config/src/cross.rs:597`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `allocation_charge` | Function | `crates/agenc-ircd-config/src/bounds.rs` | 186 |
| `enabled_purposes` | Function | `crates/agenc-ircd-config/src/config.rs` | 117 |
| `validate` | Function | `crates/agenc-ircd-config/src/cross.rs` | 23 |
| `protocol_pool` | Function | `crates/agenc-ircd-config/src/cross.rs` | 581 |
| `working_set` | Function | `crates/agenc-ircd-config/src/cross.rs` | 597 |
| `indexed` | Function | `crates/agenc-ircd-config/src/error.rs` | 119 |
| `push` | Function | `crates/agenc-ircd-config/src/error.rs` | 253 |
| `get` | Function | `crates/agenc-ircd-config/src/limits.rs` | 269 |
| `index_u16` | Function | `crates/agenc-ircd-config/src/paths.rs` | 144 |
| `as_str` | Function | `crates/agenc-ircd-config/src/scalar.rs` | 104 |
| `issue` | Function | `crates/agenc-ircd-config/src/cross.rs` | 30 |
| `identity` | Function | `crates/agenc-ircd-config/src/cross.rs` | 35 |
| `onboarding_listeners` | Function | `crates/agenc-ircd-config/src/cross.rs` | 59 |
| `listener_enabled` | Function | `crates/agenc-ircd-config/src/cross.rs` | 77 |
| `onboarding_endpoints` | Function | `crates/agenc-ircd-config/src/cross.rs` | 85 |
| `coordinator_material` | Function | `crates/agenc-ircd-config/src/cross.rs` | 99 |
| `listener_union` | Function | `crates/agenc-ircd-config/src/cross.rs` | 177 |
| `max_connections_bound` | Function | `crates/agenc-ircd-config/src/cross.rs` | 207 |
| `listener_key_reuse` | Function | `crates/agenc-ircd-config/src/cross.rs` | 223 |
| `listener_counts` | Function | `crates/agenc-ircd-config/src/cross.rs` | 251 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Load → ConfigIssue` | cross_community | 6 |
| `Verify_host_paths → Try_from` | cross_community | 4 |
| `Load → Try_from` | cross_community | 4 |
| `Parse → ConfigIssue` | cross_community | 4 |
| `Verify_host_paths → Indexed` | cross_community | 3 |
| `Verify_host_paths → ConfigIssue` | cross_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_149 | 1 calls |
| Tests | 1 calls |
| Cluster_134 | 1 calls |
| Cluster_130 | 1 calls |

## How to Explore

1. `context({name: "allocation_charge"})` — see callers and callees
2. `query({search_query: "cluster_126"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
