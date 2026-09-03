---
name: tests
description: "Skill for the Tests area of agenc-ircd. 2023 symbols across 209 files."
---

# Tests

2023 symbols | 209 files | Cohesion: 75%

## When to Use

- Working with code in `crates/`
- Understanding how parse, allocation_charge, enabled_purposes work
- Modifying tests-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd/tests/stage_six_daemon.rs` | hash, new, require_success, failure, opaque_context (+72) |
| `crates/agenc-ircd-storage/tests/stage_five_completion.rs` | later_protocol_bodies_are_profile_table_and_arm_bound, login_index_codecs_reject_each_short_circuit_boundary, real_successful_login_batch_injects_lazy_migration_boundaries, login_lookup_and_lazy_migration_are_exactly_two_generation, comprehensive_initial_state (+69) |
| `crates/agenc-ircd-testkit/tests/domain_reference_model.rs` | apply_production, production_authority, apply_production_command, apply_production_join, reference_model_executes_every_command_with_real_behavior (+64) |
| `crates/agenc-ircd-federation-wire/src/tests/semantics.rs` | decode_federation_event, schema, fields, validate, opaque (+53) |
| `crates/agenc-ircd-auth/tests/stage_four.rs` | hash, new, credential, operation_context, operation_route (+51) |
| `crates/agenc-ircd-client-wire/src/registration_command.rs` | validate_post_registration_command, validate_join, validate_part, validate_mode, validate_topic (+50) |
| `crates/agenc-ircd-storage/src/domain_records.rs` | decode, validate_session, optional_account_id, decode_channel, validate_channel (+49) |
| `crates/agenc-ircd-runtime/src/federation/coordinator/tests/harness.rs` | entropy_script, peer_identity, new, send, establish (+47) |
| `crates/agenc-ircd-federation-wire/src/codec.rs` | decode_exact, encode_canonical, claim_bytes, validate_bounds, is_optional_fixed (+31) |
| `crates/agenc-ircd-runtime/src/federation/edge/tests/harness.rs` | new, send, establish, frame, object (+30) |

## Entry Points

Start here when exploring this area:

- **`parse`** (Function) — `crates/agenc-ircd-config/src/accounts.rs:123`
- **`allocation_charge`** (Function) — `crates/agenc-ircd-config/src/bounds.rs:186`
- **`enabled_purposes`** (Function) — `crates/agenc-ircd-config/src/config.rs:117`
- **`secret_paths`** (Function) — `crates/agenc-ircd-config/src/config.rs:130`
- **`public_text_paths`** (Function) — `crates/agenc-ircd-config/src/config.rs:208`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `parse` | Function | `crates/agenc-ircd-config/src/accounts.rs` | 123 |
| `allocation_charge` | Function | `crates/agenc-ircd-config/src/bounds.rs` | 186 |
| `enabled_purposes` | Function | `crates/agenc-ircd-config/src/config.rs` | 117 |
| `secret_paths` | Function | `crates/agenc-ircd-config/src/config.rs` | 130 |
| `public_text_paths` | Function | `crates/agenc-ircd-config/src/config.rs` | 208 |
| `trust_manifest_paths` | Function | `crates/agenc-ircd-config/src/config.rs` | 224 |
| `listener_material_paths` | Function | `crates/agenc-ircd-config/src/config.rs` | 238 |
| `validate` | Function | `crates/agenc-ircd-config/src/cross.rs` | 23 |
| `protocol_pool` | Function | `crates/agenc-ircd-config/src/cross.rs` | 632 |
| `working_set` | Function | `crates/agenc-ircd-config/src/cross.rs` | 648 |
| `check_keys` | Function | `crates/agenc-ircd-config/src/document.rs` | 19 |
| `table_array` | Function | `crates/agenc-ircd-config/src/document.rs` | 45 |
| `string` | Function | `crates/agenc-ircd-config/src/document.rs` | 71 |
| `optional_string` | Function | `crates/agenc-ircd-config/src/document.rs` | 76 |
| `unsigned` | Function | `crates/agenc-ircd-config/src/document.rs` | 89 |
| `optional_unsigned` | Function | `crates/agenc-ircd-config/src/document.rs` | 94 |
| `boolean` | Function | `crates/agenc-ircd-config/src/document.rs` | 105 |
| `optional_boolean` | Function | `crates/agenc-ircd-config/src/document.rs` | 110 |
| `string_array` | Function | `crates/agenc-ircd-config/src/document.rs` | 119 |
| `parse` | Function | `crates/agenc-ircd-config/src/e2ee.rs` | 66 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Audit_mutations_rebuild_policy_and_reject_invalid_phase_pairings → As_bytes` | cross_community | 7 |
| `Rebuild_rekey_plan → As_bytes` | cross_community | 6 |
| `Rebuild_rekey_plan → Validate` | cross_community | 6 |
| `Serve → Try_from` | cross_community | 6 |
| `Internal_restore_scans_reject_duplicate_and_cross_kind_inputs → Put_fixed` | cross_community | 6 |
| `Disk_plan_and_preflight_accounting_reject_each_independent_internal_mismatch → Validate` | cross_community | 6 |
| `Disk_plan_and_preflight_accounting_reject_each_independent_internal_mismatch → Put_fixed` | cross_community | 6 |
| `Disk_plan_and_preflight_accounting_reject_each_independent_internal_mismatch → New` | cross_community | 6 |
| `Cursor_successor_and_completion_guards_reject_reachable_internal_mismatches → Validate` | cross_community | 6 |
| `Cursor_successor_and_completion_guards_reject_reachable_internal_mismatches → Put_fixed` | cross_community | 6 |

## Connected Areas

| Area | Connections |
|------|-------------|
| State_core | 218 calls |
| Federation | 68 calls |
| Codec | 37 calls |
| Admission | 36 calls |
| Tls | 32 calls |
| Cluster_668 | 30 calls |
| Coordinator | 19 calls |
| Fuzz_targets | 18 calls |

## How to Explore

1. `context({name: "parse"})` — see callers and callees
2. `query({search_query: "tests"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
