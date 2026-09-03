---
name: cluster-486
description: "Skill for the Cluster_486 area of agenc-ircd. 79 symbols across 2 files."
---

# Cluster_486

79 symbols | 2 files | Cohesion: 87%

## When to Use

- Working with code in `crates/`
- Understanding how initialize_node, verify_database_header, render_onboarding work
- Modifying cluster_486-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/offline.rs` | from, role, imported_hpke_public_key, create, drop (+73) |
| `crates/agenc-ircd-storage/src/qualification.rs` | embedded_storage_qualifications |

## Entry Points

Start here when exploring this area:

- **`initialize_node`** (Function) — `crates/agenc-ircd-runtime/src/offline.rs:512`
- **`verify_database_header`** (Function) — `crates/agenc-ircd-runtime/src/offline.rs:1279`
- **`render_onboarding`** (Function) — `crates/agenc-ircd-runtime/src/offline.rs:1338`
- **`embedded_storage_qualifications`** (Function) — `crates/agenc-ircd-storage/src/qualification.rs:558`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `initialize_node` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 512 |
| `verify_database_header` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 1279 |
| `render_onboarding` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 1338 |
| `embedded_storage_qualifications` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 558 |
| `from` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 179 |
| `role` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 250 |
| `imported_hpke_public_key` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 274 |
| `create` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 354 |
| `drop` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 502 |
| `validate_init_request` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 570 |
| `validate_init_paths` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 589 |
| `valid_init_path_shapes` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 599 |
| `valid_output_path` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 606 |
| `validate_lexical_root_separation` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 610 |
| `validate_edge_descriptor_path` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 639 |
| `safe_absolute_path` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 650 |
| `paths_overlap` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 658 |
| `validate_physical_root_separation` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 662 |
| `open_physical_directory` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 722 |
| `directory_identity` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 744 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Init → Directory_has_entry` | cross_community | 5 |
| `Init → Validate_descriptor_hpke_pin` | cross_community | 5 |
| `Init → LoadedDescriptor` | cross_community | 5 |
| `Init → Require_absent` | cross_community | 4 |
| `Init → Edge` | cross_community | 4 |
| `Init → Imported_network_id` | cross_community | 4 |
| `Init → Role` | cross_community | 4 |
| `Init → Coordinator_server_id` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 10 calls |
| Cluster_172 | 3 calls |
| Cluster_487 | 3 calls |
| Validate_ | 2 calls |
| Cluster_493 | 2 calls |
| Cluster_489 | 2 calls |
| Cluster_162 | 2 calls |
| Examples | 1 calls |

## How to Explore

1. `context({name: "initialize_node"})` — see callers and callees
2. `query({search_query: "cluster_486"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
