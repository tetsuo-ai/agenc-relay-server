---
name: tests
description: "Skill for the Tests area of agenc-ircd. 1692 symbols across 164 files."
---

# Tests

1692 symbols | 164 files | Cohesion: 73%

## When to Use

- Working with code in `crates/`
- Understanding how as_u32, from_bytes, new work
- Modifying tests-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd/tests/stage_six_daemon.rs` | hash, new, require_success, failure, opaque_context (+72) |
| `crates/agenc-ircd-storage/tests/stage_five_completion.rs` | later_protocol_bodies_are_profile_table_and_arm_bound, domain_body, account_key_bytes, every_table_has_one_closed_schema_and_domain_codec_consumes_fully, persistent_record_schema_rejects_every_key_kind_and_counter_mismatch (+71) |
| `crates/agenc-ircd-testkit/tests/domain_reference_model.rs` | apply_production, production_authority, apply_production_command, apply_production_join, reference_model_executes_every_command_with_real_behavior (+64) |
| `crates/agenc-ircd-federation-wire/src/tests/semantics.rs` | schema, fields, validate, opaque, unsigned (+53) |
| `crates/agenc-ircd-auth/tests/stage_four.rs` | hash, new, credential, operation_context, operation_route (+51) |
| `crates/agenc-ircd-client-wire/src/registration_command.rs` | validate_post_registration_command, validate_join, validate_part, validate_mode, validate_topic (+50) |
| `crates/agenc-ircd-storage/src/domain_records.rs` | decode, validate_session, optional_account_id, decode_channel, validate_channel (+49) |
| `crates/agenc-ircd-domain/src/model.rs` | new, parse, with_policies, from_seed, test_public_cloak (+32) |
| `crates/agenc-ircd-federation-wire/src/codec.rs` | encode_canonical, claim_bytes, validate_bounds, is_optional_fixed, validate_optional_fixed_field (+31) |
| `crates/agenc-ircd-runtime/tests/listener_accept.rs` | default, fixture, server, client, start (+26) |

## Entry Points

Start here when exploring this area:

- **`as_u32`** (Function) — `crates/agenc-ircd-config/src/scalar.rs:286`
- **`from_bytes`** (Function) — `crates/agenc-ircd-crypto/src/storage_integrity.rs:54`
- **`new`** (Function) — `crates/agenc-ircd-crypto/src/storage_integrity.rs:86`
- **`expose_for_storage`** (Function) — `crates/agenc-ircd-crypto/src/storage_integrity.rs:137`
- **`sealed_record_id`** (Function) — `crates/agenc-ircd-crypto/src/storage_integrity.rs:259`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `as_u32` | Function | `crates/agenc-ircd-config/src/scalar.rs` | 286 |
| `from_bytes` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 54 |
| `new` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 86 |
| `expose_for_storage` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 137 |
| `sealed_record_id` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 259 |
| `tracked_record_commitment` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 274 |
| `tracked_state_digest` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 279 |
| `update` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 315 |
| `update_entry` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 444 |
| `reserved_memory_bytes` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 102 |
| `new` | Function | `crates/agenc-ircd-runtime/src/bridge/crypto.rs` | 108 |
| `start` | Function | `crates/agenc-ircd-runtime/src/bridge/crypto.rs` | 876 |
| `listener_ceiling` | Function | `crates/agenc-ircd-runtime/src/runtime_config.rs` | 373 |
| `refresh` | Function | `crates/agenc-ircd-runtime/src/state_core/durable.rs` | 418 |
| `finish` | Function | `crates/agenc-ircd-runtime/src/state_core/mod.rs` | 495 |
| `backup_stream_bytes` | Function | `crates/agenc-ircd-storage/src/backup.rs` | 1020 |
| `finish` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 52 |
| `take` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 67 |
| `array` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 80 |
| `u16` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 86 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Connection_opened → FixtureIdentity` | cross_community | 8 |
| `Connection_opened → Create` | cross_community | 8 |
| `Mode_vectors_simulate_client_order_and_check_only_the_final_state → Presentation` | cross_community | 8 |
| `Mode_vectors_simulate_client_order_and_check_only_the_final_state → Canonical` | cross_community | 8 |
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → Presentation` | cross_community | 8 |
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → Canonical` | cross_community | 8 |
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → Is_global` | cross_community | 8 |
| `Audit_mutations_rebuild_policy_and_reject_invalid_phase_pairings → As_bytes` | cross_community | 7 |
| `Rebuild_rekey_plan → As_bytes` | cross_community | 6 |
| `Rebuild_rekey_plan → Validate` | cross_community | 6 |

## Connected Areas

| Area | Connections |
|------|-------------|
| State_core | 104 calls |
| Listener | 48 calls |
| Admission | 32 calls |
| Cluster_576 | 30 calls |
| Tls | 23 calls |
| Cluster_218 | 19 calls |
| Fuzz_targets | 19 calls |
| Cluster_64 | 18 calls |

## How to Explore

1. `context({name: "as_u32"})` — see callers and callees
2. `query({search_query: "tests"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
