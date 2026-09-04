---
name: tests
description: "Skill for the Tests area of agenc-ircd. 2088 symbols across 247 files."
---

# Tests

2088 symbols | 247 files | Cohesion: 69%

## When to Use

- Working with code in `crates/`
- Understanding how as_slice, decode_exact, to_object work
- Modifying tests-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd/tests/stage_eight_e2ee.rs` | failure, create, write_private, write_trust_manifest, reserve_loopback_address (+84) |
| `crates/agenc-ircd-storage/tests/stage_five_completion.rs` | storage_crypto_adapters_cover_every_public_boundary, signed_growth_report_is_exact_tuple_authority, qualification_rejects_every_report_and_measurement_boundary, qualification_required_file_set_measures_every_named_durable_case, resign_qualification_frame (+67) |
| `crates/agenc-ircd/tests/stage_six_daemon.rs` | client_config, admin_tls_client_config, require_success, failure, opaque_identifiers (+62) |
| `crates/agenc-ircd-runtime/src/federation/coordinator/tests/harness.rs` | entropy_script, peer_identity, new, send, establish (+57) |
| `crates/agenc-ircd-federation-wire/src/tests/semantics.rs` | schema, fields, validate, opaque, unsigned (+52) |
| `crates/agenc-ircd-runtime/src/federation/edge/tests/harness.rs` | start_node, entropy_script, coordinator_identity, new, send (+51) |
| `crates/agenc-ircd-testkit/tests/domain_reference_model.rs` | apply_production, apply_production_command, apply_production_join, reference_model_executes_every_command_with_real_behavior, reference_command_fixture (+49) |
| `crates/agenc-ircd-auth/tests/stage_four.rs` | new, credential, operation_context, operation_route, operation_context_for_network (+45) |
| `crates/agenc-ircd-testkit/src/e2ee_client.rs` | private_message_at_epoch, private_message_with_ciphertext, operational, lock_ids, key (+30) |
| `crates/agenc-ircd-domain/src/model.rs` | new, parse, with_policies, from_seed, test_public_cloak (+26) |

## Entry Points

Start here when exploring this area:

- **`as_slice`** (Function) — `crates/agenc-ircd-federation-wire/src/assembly.rs:111`
- **`decode_exact`** (Function) — `crates/agenc-ircd-federation-wire/src/codec.rs:390`
- **`to_object`** (Function) — `crates/agenc-ircd-federation-wire/src/objects.rs:149`
- **`from_object`** (Function) — `crates/agenc-ircd-federation-wire/src/objects.rs:168`
- **`decode`** (Function) — `crates/agenc-ircd-federation-wire/src/objects.rs:233`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `as_slice` | Function | `crates/agenc-ircd-federation-wire/src/assembly.rs` | 111 |
| `decode_exact` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 390 |
| `to_object` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 149 |
| `from_object` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 168 |
| `decode` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 233 |
| `decode_request_operation` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 328 |
| `decode_result_arm` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 408 |
| `decode_event_arm` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 560 |
| `decode_projection_arm` | Function | `crates/agenc-ircd-federation-wire/src/objects.rs` | 742 |
| `inbound` | Function | `crates/agenc-ircd-runtime/src/federation/coordinator/mod.rs` | 416 |
| `receive` | Function | `crates/agenc-ircd-runtime/src/federation/edge/events.rs` | 22 |
| `receive_result` | Function | `crates/agenc-ircd-runtime/src/federation/edge/request.rs` | 852 |
| `snapshot_entry` | Function | `crates/agenc-ircd-runtime/src/federation/edge/sync.rs` | 176 |
| `link_queue` | Function | `crates/agenc-ircd-runtime/src/federation/link.rs` | 357 |
| `connection_close_channel` | Function | `crates/agenc-ircd-runtime/src/state_core/inbox.rs` | 73 |
| `lifecycle_channel` | Function | `crates/agenc-ircd-runtime/src/state_core/inbox.rs` | 308 |
| `with_registration_router` | Function | `crates/agenc-ircd-runtime/src/test_support.rs` | 505 |
| `with_federation_coordinator` | Function | `crates/agenc-ircd-runtime/src/test_support.rs` | 536 |
| `take_run_parts` | Function | `crates/agenc-ircd-runtime/src/test_support.rs` | 696 |
| `parse_projection_key` | Function | `crates/agenc-ircd-storage/src/federation_records.rs` | 914 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Preview → Try_from` | cross_community | 7 |
| `Preview → Validate_bounds` | cross_community | 7 |
| `Preview → Validate_version_field` | cross_community | 7 |
| `Preview → Validate_padding_field` | cross_community | 7 |
| `Audit_mutations_rebuild_policy_and_reject_invalid_phase_pairings → As_bytes` | cross_community | 7 |
| `Policy → Label` | cross_community | 7 |
| `Rebuild_rekey_plan → As_bytes` | cross_community | 6 |
| `Rebuild_rekey_plan → Validate` | cross_community | 6 |
| `Binding_package → Label` | cross_community | 6 |
| `Preview → Schema_by_name` | cross_community | 6 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Coordinator | 158 calls |
| State_core | 111 calls |
| Federation | 75 calls |
| Supervisor | 37 calls |
| Edge | 35 calls |
| Cluster_940 | 30 calls |
| Codec | 25 calls |
| Examples | 24 calls |

## How to Explore

1. `context({name: "as_slice"})` — see callers and callees
2. `query({search_query: "tests"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
