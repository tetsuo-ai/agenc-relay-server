---
name: coordinator
description: "Skill for the Coordinator area of agenc-ircd. 473 symbols across 69 files."
---

# Coordinator

473 symbols | 69 files | Cohesion: 50%

## When to Use

- Working with code in `crates/`
- Understanding how derive_storage_index, as_bytes, update work
- Modifying coordinator-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/src/construction_runtime.rs` | validate, start, start_streaming, start_inner, push (+85) |
| `crates/agenc-ircd-runtime/src/e2ee/coordinator/startup.rs` | decode_body, decode_object, route_target, direct_accounts, restore_log (+38) |
| `crates/agenc-ircd-storage/src/e2ee_records.rs` | record_kind_for_key, matches_key, object_body, state_body, structural_body (+37) |
| `crates/agenc-ircd-runtime/src/federation/coordinator/request.rs` | run_operation, run_query, answer_page, finish_query_decision, close_session (+19) |
| `crates/agenc-ircd-runtime/src/e2ee/coordinator/sync.rs` | begin_snapshot, entitled_entries, state_fetch, render_page, snapshot_write (+17) |
| `crates/agenc-ircd-runtime/src/federation/coordinator/convert.rs` | session_seed, directory_schema, rebuild_query, directory_query, nicknames_of (+17) |
| `crates/agenc-ircd-runtime/src/federation/coordinator/mod.rs` | link_is_live, storage_read_completed, companion_timer_fired, fail_link, timer_fired (+16) |
| `crates/agenc-ircd-storage/src/engine.rs` | open_construction_source_record, verify_snapshot_accounting, checkpoint_accounting, checkpoint_retired_charges, prepare_application (+11) |
| `crates/agenc-ircd-runtime/src/federation/coordinator/snapshot.rs` | owns_read, timer_fired, expire, continue_resend, resend_completed (+11) |
| `crates/agenc-ircd-runtime/src/federation/coordinator/companion.rs` | snapshot_timer_fired, companion_acknowledged, try_close_barrier, send_lines, send_to_target (+7) |

## Entry Points

Start here when exploring this area:

- **`derive_storage_index`** (Function) — `crates/agenc-ircd-crypto/src/storage.rs:283`
- **`as_bytes`** (Function) — `crates/agenc-ircd-crypto/src/storage_integrity.rs:120`
- **`update`** (Function) — `crates/agenc-ircd-crypto/src/storage_integrity.rs:336`
- **`offset`** (Function) — `crates/agenc-ircd-e2ee/src/wire/fragment.rs:117`
- **`required_reserve`** (Function) — `crates/agenc-ircd-runtime/src/admission/overload.rs:133`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `derive_storage_index` | Function | `crates/agenc-ircd-crypto/src/storage.rs` | 283 |
| `as_bytes` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 120 |
| `update` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 336 |
| `offset` | Function | `crates/agenc-ircd-e2ee/src/wire/fragment.rs` | 117 |
| `required_reserve` | Function | `crates/agenc-ircd-runtime/src/admission/overload.rs` | 133 |
| `state_fetch` | Function | `crates/agenc-ircd-runtime/src/e2ee/coordinator/sync.rs` | 749 |
| `stats` | Function | `crates/agenc-ircd-runtime/src/e2ee/edge/mod.rs` | 302 |
| `dial` | Function | `crates/agenc-ircd-runtime/src/federation/dial.rs` | 135 |
| `validate` | Function | `crates/agenc-ircd-storage/src/construction.rs` | 60 |
| `construction_plan_hash` | Function | `crates/agenc-ircd-storage/src/construction.rs` | 402 |
| `operation_id` | Function | `crates/agenc-ircd-storage/src/construction.rs` | 611 |
| `validate` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 94 |
| `start` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 163 |
| `start_streaming` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 173 |
| `push` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 251 |
| `finish` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 538 |
| `new` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 757 |
| `rebuild_disk` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 802 |
| `validate_identity` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 851 |
| `preflight` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 938 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Preview → Try_from` | cross_community | 7 |
| `Audit_mutations_rebuild_policy_and_reject_invalid_phase_pairings → As_bytes` | cross_community | 7 |
| `Rebuild_rekey_plan → As_bytes` | cross_community | 6 |
| `Origin_state → Take` | cross_community | 6 |
| `Internal_restore_scans_reject_duplicate_and_cross_kind_inputs → Validate_nonzero_limit` | cross_community | 6 |
| `Internal_restore_scans_reject_duplicate_and_cross_kind_inputs → Validate_nonzero_usize_limit` | cross_community | 6 |
| `Internal_restore_scans_reject_duplicate_and_cross_kind_inputs → Put_fixed` | cross_community | 6 |
| `Run → Try_from` | cross_community | 5 |
| `Construction_scan → Disabled` | cross_community | 5 |
| `Construction_scan → StorageSnapshot` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 98 calls |
| State_core | 38 calls |
| E2ee_records | 18 calls |
| Cluster_823 | 16 calls |
| Ops | 16 calls |
| Cluster_848 | 12 calls |
| Federation | 11 calls |
| Cluster_854 | 10 calls |

## How to Explore

1. `context({name: "derive_storage_index"})` — see callers and callees
2. `query({search_query: "coordinator"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
