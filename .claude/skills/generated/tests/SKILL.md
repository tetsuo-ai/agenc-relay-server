---
name: tests
description: "Skill for the Tests area of agenc-ircd. 1541 symbols across 155 files."
---

# Tests

1541 symbols | 155 files | Cohesion: 73%

## When to Use

- Working with code in `crates/`
- Understanding how as_u32, from_bytes, new work
- Modifying tests-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/tests/stage_five_completion.rs` | later_protocol_bodies_are_profile_table_and_arm_bound, login_index_codecs_reject_each_short_circuit_boundary, real_successful_login_batch_injects_lazy_migration_boundaries, login_lookup_and_lazy_migration_are_exactly_two_generation, initialized_lazy_login_fixture (+70) |
| `crates/agenc-ircd-testkit/tests/domain_reference_model.rs` | apply_production_command, apply_production_join, apply_production, production_authority, production_identity (+64) |
| `crates/agenc-ircd-federation-wire/src/tests/semantics.rs` | schema, fields, validate, opaque, unsigned (+53) |
| `crates/agenc-ircd-client-wire/src/registration_command.rs` | validate_post_registration_command, validate_join, validate_part, validate_mode, validate_topic (+50) |
| `crates/agenc-ircd-auth/tests/stage_four.rs` | hash, new, credential, operation_context, operation_route (+50) |
| `crates/agenc-ircd/tests/stage_six_daemon.rs` | hash, new, require_success, failure, opaque_context (+48) |
| `crates/agenc-ircd-domain/src/model.rs` | restore, new, parse, with_policies, from_seed (+33) |
| `crates/agenc-ircd-federation-wire/src/codec.rs` | encode_canonical, claim_bytes, validate_bounds, is_optional_fixed, validate_optional_fixed_field (+31) |
| `crates/agenc-ircd-storage/src/domain_records.rs` | decode, expect_version, byte, text, optional_text (+29) |
| `crates/agenc-ircd-runtime/tests/listener_accept.rs` | snapshot, default, fixture, server, client (+25) |

## Entry Points

Start here when exploring this area:

- **`as_u32`** (Function) — `crates/agenc-ircd-config/src/scalar.rs:286`
- **`from_bytes`** (Function) — `crates/agenc-ircd-crypto/src/storage_integrity.rs:54`
- **`new`** (Function) — `crates/agenc-ircd-crypto/src/storage_integrity.rs:86`
- **`sealed_record_id`** (Function) — `crates/agenc-ircd-crypto/src/storage_integrity.rs:259`
- **`tracked_record_commitment`** (Function) — `crates/agenc-ircd-crypto/src/storage_integrity.rs:274`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `as_u32` | Function | `crates/agenc-ircd-config/src/scalar.rs` | 286 |
| `from_bytes` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 54 |
| `new` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 86 |
| `sealed_record_id` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 259 |
| `tracked_record_commitment` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 274 |
| `tracked_state_digest` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 279 |
| `update` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 315 |
| `finalize` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 328 |
| `update_entry` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 444 |
| `reserved_memory_bytes` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 102 |
| `new` | Function | `crates/agenc-ircd-runtime/src/bridge/crypto.rs` | 105 |
| `start` | Function | `crates/agenc-ircd-runtime/src/bridge/crypto.rs` | 856 |
| `listener_ceiling` | Function | `crates/agenc-ircd-runtime/src/runtime_config.rs` | 280 |
| `backup_stream_bytes` | Function | `crates/agenc-ircd-storage/src/backup.rs` | 1011 |
| `finish` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 52 |
| `take` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 67 |
| `array` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 80 |
| `u16` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 86 |
| `u32` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 90 |
| `u64` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 94 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Mode_vectors_simulate_client_order_and_check_only_the_final_state → Presentation` | cross_community | 8 |
| `Mode_vectors_simulate_client_order_and_check_only_the_final_state → Canonical` | cross_community | 8 |
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → Presentation` | cross_community | 8 |
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → Canonical` | cross_community | 8 |
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → Is_global` | cross_community | 8 |
| `Reconstruct → As_bytes` | cross_community | 7 |
| `Reconstruct → Try_from` | cross_community | 7 |
| `Audit_mutations_rebuild_policy_and_reject_invalid_phase_pairings → As_bytes` | cross_community | 7 |
| `Audit_mutations_rebuild_policy_and_reject_invalid_phase_pairings → Try_from` | cross_community | 7 |
| `Verifies_gapless_events_and_rejects_unmatched_intents → As_bytes` | cross_community | 7 |

## Connected Areas

| Area | Connections |
|------|-------------|
| State_core | 96 calls |
| Listener | 31 calls |
| Cluster_503 | 30 calls |
| Admission | 23 calls |
| Tls | 22 calls |
| Cluster_58 | 18 calls |
| Fuzz_targets | 17 calls |
| Cluster_185 | 16 calls |

## How to Explore

1. `context({name: "as_u32"})` — see callers and callees
2. `query({search_query: "tests"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
