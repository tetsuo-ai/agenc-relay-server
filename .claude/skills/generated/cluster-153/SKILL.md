---
name: cluster-153
description: "Skill for the Cluster_153 area of agenc-ircd. 39 symbols across 7 files."
---

# Cluster_153

39 symbols | 7 files | Cohesion: 72%

## When to Use

- Working with code in `crates/`
- Understanding how expose, from_storage, initialize_node work
- Modifying cluster_153-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/offline.rs` | generate, role, imported_network_id, imported_hpke_public_key, initialize_node (+27) |
| `crates/agenc-ircd-runtime/src/daemon.rs` | open, storage_open_config |
| `crates/agenc-ircd-config/src/secrets.rs` | expose |
| `crates/agenc-ircd-runtime/src/lib.rs` | from_storage |
| `crates/agenc-ircd-storage/src/engine.rs` | table_record_count |
| `crates/agenc-ircd-storage/src/owner.rs` | recovered_state |
| `crates/agenc-ircd-storage/src/qualification.rs` | embedded_storage_qualifications |

## Entry Points

Start here when exploring this area:

- **`expose`** (Function) — `crates/agenc-ircd-config/src/secrets.rs:59`
- **`from_storage`** (Function) — `crates/agenc-ircd-runtime/src/lib.rs:48`
- **`initialize_node`** (Function) — `crates/agenc-ircd-runtime/src/offline.rs:379`
- **`verify_database_header`** (Function) — `crates/agenc-ircd-runtime/src/offline.rs:734`
- **`render_onboarding`** (Function) — `crates/agenc-ircd-runtime/src/offline.rs:793`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `expose` | Function | `crates/agenc-ircd-config/src/secrets.rs` | 59 |
| `from_storage` | Function | `crates/agenc-ircd-runtime/src/lib.rs` | 48 |
| `initialize_node` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 379 |
| `verify_database_header` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 734 |
| `render_onboarding` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 793 |
| `create_account_invite` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 811 |
| `table_record_count` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 142 |
| `recovered_state` | Function | `crates/agenc-ircd-storage/src/owner.rs` | 186 |
| `embedded_storage_qualifications` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 558 |
| `open` | Function | `crates/agenc-ircd-runtime/src/daemon.rs` | 321 |
| `storage_open_config` | Function | `crates/agenc-ircd-runtime/src/daemon.rs` | 369 |
| `generate` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 208 |
| `role` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 243 |
| `imported_network_id` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 250 |
| `imported_hpke_public_key` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 267 |
| `prepare_init_mode` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 394 |
| `random_32` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 524 |
| `write_secret` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 530 |
| `write_generated_secrets` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 540 |
| `signing_public` | Function | `crates/agenc-ircd-runtime/src/offline.rs` | 574 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Init → Safe_absolute_path` | cross_community | 5 |
| `Init → Paths_overlap` | cross_community | 5 |
| `Init → Validate_descriptor_hpke_pin` | cross_community | 5 |
| `Init → LoadedDescriptor` | cross_community | 5 |
| `Clean_init_reopens_for_onboarding_and_repeated_init_is_refused → Fill_from` | cross_community | 5 |
| `Edge_init_imports_public_pins_without_creating_coordinator_secrets → Fill_from` | cross_community | 5 |
| `Edge_init_imports_public_pins_without_creating_coordinator_secrets → DnsEndpoint` | cross_community | 5 |
| `Edge_init_imports_public_pins_without_creating_coordinator_secrets → Canonical_u64` | cross_community | 5 |
| `Run → Storage_master` | cross_community | 4 |
| `Init → Imported_network_id` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 11 calls |
| Cluster_370 | 8 calls |
| Cluster_148 | 3 calls |
| State_core | 2 calls |
| Observe | 1 calls |
| Cluster_373 | 1 calls |
| Examples | 1 calls |
| Cluster_178 | 1 calls |

## How to Explore

1. `context({name: "expose"})` — see callers and callees
2. `query({search_query: "cluster_153"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
