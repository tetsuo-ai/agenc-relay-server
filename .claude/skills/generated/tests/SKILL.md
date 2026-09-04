---
name: tests
description: "Skill for the Tests area of agenc-ircd. 1910 symbols across 234 files."
---

# Tests

1910 symbols | 234 files | Cohesion: 70%

## When to Use

- Working with code in `crates/`
- Understanding how derive_storage_index, validate, operation_id work
- Modifying tests-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/src/construction_runtime.rs` | validate, start, start_streaming, start_inner, push (+83) |
| `crates/agenc-ircd-storage/tests/stage_five_completion.rs` | every_table_has_one_closed_schema_and_domain_codec_consumes_fully, read_source, storage_crypto_adapters_cover_every_public_boundary, signed_growth_report_is_exact_tuple_authority, qualification_rejects_every_report_and_measurement_boundary (+71) |
| `crates/agenc-ircd/tests/stage_six_daemon.rs` | client_config, admin_tls_client_config, require_success, failure, opaque_identifiers (+62) |
| `crates/agenc-ircd-runtime/src/federation/coordinator/tests/harness.rs` | entropy_script, peer_identity, new, send, establish (+56) |
| `crates/agenc-ircd-federation-wire/src/tests/semantics.rs` | schema, fields, validate, opaque, unsigned (+52) |
| `crates/agenc-ircd-testkit/tests/domain_reference_model.rs` | apply_production, apply_production_command, apply_production_join, reference_model_executes_every_command_with_real_behavior, reference_command_fixture (+49) |
| `crates/agenc-ircd-auth/tests/stage_four.rs` | new, credential, operation_context, operation_route, operation_context_for_network (+45) |
| `crates/agenc-ircd-runtime/src/federation/edge/tests/harness.rs` | next_frame, pump, start_node, edge_and_coordinator_interoperate_over_a_bridged_link, drive_bridge (+32) |
| `crates/agenc-ircd-domain/src/model.rs` | new, parse, with_policies, from_seed, test_public_cloak (+26) |
| `crates/agenc-ircd-e2ee/src/tests/support.rs` | key, public, sign, account_field, root (+25) |

## Entry Points

Start here when exploring this area:

- **`derive_storage_index`** (Function) — `crates/agenc-ircd-crypto/src/storage.rs:283`
- **`validate`** (Function) — `crates/agenc-ircd-storage/src/construction.rs:60`
- **`operation_id`** (Function) — `crates/agenc-ircd-storage/src/construction.rs:611`
- **`validate`** (Function) — `crates/agenc-ircd-storage/src/construction_runtime.rs:94`
- **`start`** (Function) — `crates/agenc-ircd-storage/src/construction_runtime.rs:163`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `derive_storage_index` | Function | `crates/agenc-ircd-crypto/src/storage.rs` | 283 |
| `validate` | Function | `crates/agenc-ircd-storage/src/construction.rs` | 60 |
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
| `open` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 1455 |
| `rebuild_restore_plan` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 2027 |
| `resume` | Function | `crates/agenc-ircd-storage/src/construction_runtime.rs` | 2819 |
| `record_kind_for_key` | Function | `crates/agenc-ircd-storage/src/e2ee_records.rs` | 174 |
| `matches_key` | Function | `crates/agenc-ircd-storage/src/e2ee_records.rs` | 642 |
| `open_construction_source_record` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 1340 |
| `startup_scan` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 2502 |
| `construction_scan` | Function | `crates/agenc-ircd-storage/src/engine.rs` | 2726 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Audit_mutations_rebuild_policy_and_reject_invalid_phase_pairings → As_bytes` | cross_community | 7 |
| `Preview → Try_from` | cross_community | 7 |
| `Preview → Validate_bounds` | cross_community | 7 |
| `Preview → Validate_version_field` | cross_community | 7 |
| `Preview → Validate_padding_field` | cross_community | 7 |
| `Rebuild_rekey_plan → As_bytes` | cross_community | 6 |
| `Rebuild_rekey_plan → Validate` | cross_community | 6 |
| `Serve → Try_from` | cross_community | 6 |
| `Internal_restore_scans_reject_duplicate_and_cross_kind_inputs → Validate_nonzero_limit` | cross_community | 6 |
| `Internal_restore_scans_reject_duplicate_and_cross_kind_inputs → Validate_nonzero_usize_limit` | cross_community | 6 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Coordinator | 152 calls |
| State_core | 104 calls |
| Federation | 69 calls |
| Supervisor | 39 calls |
| Cluster_890 | 30 calls |
| Codec | 29 calls |
| Ops | 24 calls |
| Cluster_60 | 21 calls |

## How to Explore

1. `context({name: "derive_storage_index"})` — see callers and callees
2. `query({search_query: "tests"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
