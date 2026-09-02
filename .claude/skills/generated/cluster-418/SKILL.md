---
name: cluster-418
description: "Skill for the Cluster_418 area of agenc-ircd. 84 symbols across 2 files."
---

# Cluster_418

84 symbols | 2 files | Cohesion: 87%

## When to Use

- Working with code in `crates/`
- Understanding how initialize_node, verify_database_header, render_onboarding work
- Modifying cluster_418-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/offline.rs` | from, generate, role, imported_network_id, imported_hpke_public_key (+78) |
| `crates/agenc-ircd-storage/src/qualification.rs` | embedded_storage_qualifications |

## Entry Points

Start here when exploring this area:

- **`initialize_node`** (Function) — `crates/agenc-ircd-runtime/src/offline.rs:512`
- **`verify_database_header`** (Function) — `crates/agenc-ircd-runtime/src/offline.rs:1279`
- **`render_onboarding`** (Function) — `crates/agenc-ircd-runtime/src/offline.rs:1338`
- **`create_account_invite`** (Function) — `crates/agenc-ircd-runtime/src/offline.rs:1356`
- **`embedded_storage_qualifications`** (Function) — `crates/agenc-ircd-storage/src/qualification.rs:558`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `initialize_node` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 512 |
| `verify_database_header` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 1279 |
| `render_onboarding` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 1338 |
| `create_account_invite` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 1356 |
| `embedded_storage_qualifications` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 558 |
| `from` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 179 |
| `generate` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 215 |
| `role` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 250 |
| `imported_network_id` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 257 |
| `imported_hpke_public_key` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 274 |
| `create` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 354 |
| `drop` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 502 |
| `prepare_init_mode` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 539 |
| `validate_init_request` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 570 |
| `validate_init_paths` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 589 |
| `valid_init_path_shapes` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 599 |
| `valid_output_path` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 606 |
| `validate_lexical_root_separation` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 610 |
| `validate_edge_descriptor_path` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 639 |
| `safe_absolute_path` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 650 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Init → Safe_absolute_path` | cross_community | 6 |
| `Init → Directory_has_entry` | cross_community | 5 |
| `Init → Validate_descriptor_hpke_pin` | cross_community | 5 |
| `Init → LoadedDescriptor` | cross_community | 5 |
| `Clean_init_reopens_for_onboarding_and_repeated_init_is_refused → Same_directory` | cross_community | 5 |
| `Clean_init_reopens_for_onboarding_and_repeated_init_is_refused → Directory_has_entry` | cross_community | 5 |
| `Init → Require_absent` | cross_community | 4 |
| `Init → Imported_network_id` | cross_community | 4 |
| `Init → Role` | cross_community | 4 |
| `Init → Coordinator_server_id` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 11 calls |
| Cluster_179 | 3 calls |
| Cluster_170 | 3 calls |
| Examples | 2 calls |
| Validate_ | 2 calls |
| Cluster_424 | 2 calls |
| Cluster_420 | 2 calls |
| Cluster_211 | 1 calls |

## How to Explore

1. `context({name: "initialize_node"})` — see callers and callees
2. `query({search_query: "cluster_418"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
