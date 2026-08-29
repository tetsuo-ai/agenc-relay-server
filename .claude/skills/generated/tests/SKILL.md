---
name: tests
description: "Skill for the Tests area of agenc-ircd. 1575 symbols across 147 files."
---

# Tests

1575 symbols | 147 files | Cohesion: 76%

## When to Use

- Working with code in `crates/`
- Understanding how as_u32, from_bytes, new work
- Modifying tests-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/src/construction_runtime.rs` | verify_restore_checkpoint, decode_restore_scratch_key, decode_restore_version, decode_restore_present, validate (+76) |
| `crates/agenc-ircd-storage/tests/stage_five_completion.rs` | every_table_has_one_closed_schema_and_domain_codec_consumes_fully, later_protocol_bodies_are_profile_table_and_arm_bound, restore_transform_preserves_deleted_accounts_and_rejects_creation_reservations, read_source, signed_growth_report_is_exact_tuple_authority (+75) |
| `crates/agenc-ircd-testkit/tests/domain_reference_model.rs` | apply_production, production_authority, apply_production_command, apply_production_join, production_identity (+64) |
| `crates/agenc-ircd-federation-wire/src/tests/semantics.rs` | schema, fields, validate, opaque, unsigned (+53) |
| `crates/agenc-ircd-client-wire/src/registration_command.rs` | validate_post_registration_command, validate_join, validate_part, validate_mode, validate_topic (+50) |
| `crates/agenc-ircd-auth/tests/stage_four.rs` | hash, new, operation_route, encode_request_plaintext, encode_response_plaintext (+49) |
| `crates/agenc-ircd-storage/src/engine.rs` | start_backup, verify_snapshot_accounting, checkpoint_accounting, checkpoint_retired_charges, startup_scan (+31) |
| `crates/agenc-ircd-domain/src/model.rs` | resolve_channel, restore, parse, new, from_seed (+31) |
| `crates/agenc-ircd-federation-wire/src/codec.rs` | encode_canonical, claim_bytes, validate_bounds, is_optional_fixed, validate_optional_fixed_field (+31) |
| `crates/agenc-ircd-testkit/src/domain_reference.rs` | apply_inner, create_account, open_session, switch_account, rename (+30) |

## Entry Points

Start here when exploring this area:

- **`as_u32`** (Function) — `crates/agenc-ircd-config/src/scalar.rs:286`
- **`from_bytes`** (Function) — `crates/agenc-ircd-crypto/src/storage_integrity.rs:54`
- **`new`** (Function) — `crates/agenc-ircd-crypto/src/storage_integrity.rs:86`
- **`tracked_record_commitment`** (Function) — `crates/agenc-ircd-crypto/src/storage_integrity.rs:274`
- **`tracked_state_digest`** (Function) — `crates/agenc-ircd-crypto/src/storage_integrity.rs:279`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `as_u32` | Function | `crates/agenc-ircd-config/src/scalar.rs` | 286 |
| `from_bytes` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 54 |
| `new` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 86 |
| `tracked_record_commitment` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 274 |
| `tracked_state_digest` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 279 |
| `update` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 315 |
| `finalize` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 328 |
| `update_entry` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 444 |
| `reserved_memory_bytes` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 102 |
| `start` | Function | `crates/agenc-ircd-runtime/src/bridge/crypto.rs` | 496 |
| `start` | Function | `crates/agenc-ircd-storage/src/backup.rs` | 287 |
| `backup_stream_bytes` | Function | `crates/agenc-ircd-storage/src/backup.rs` | 1011 |
| `finish` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 52 |
| `take` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 67 |
| `array` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 80 |
| `u16` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 86 |
| `u32` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 90 |
| `u64` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 94 |
| `vector_u32` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 98 |
| `new` | Function | `crates/agenc-ircd-storage/src/control.rs` | 53 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Mode_vectors_simulate_client_order_and_check_only_the_final_state → Presentation` | cross_community | 8 |
| `Mode_vectors_simulate_client_order_and_check_only_the_final_state → Canonical` | cross_community | 8 |
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → Presentation` | cross_community | 8 |
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → Canonical` | cross_community | 8 |
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → Is_global` | cross_community | 8 |
| `Remaining_mode_and_request_helpers_cover_successful_fallthroughs → Presentation` | cross_community | 8 |
| `Remaining_mode_and_request_helpers_cover_successful_fallthroughs → Canonical` | cross_community | 8 |
| `Remaining_mode_and_request_helpers_cover_successful_fallthroughs → Is_global` | cross_community | 8 |
| `Classify_recovery_state → As_bytes` | cross_community | 7 |
| `Classify_recovery_state → Try_from` | cross_community | 7 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Fuzz_targets | 35 calls |
| Cluster_393 | 33 calls |
| Cluster_316 | 24 calls |
| Cluster_329 | 22 calls |
| Cluster_191 | 18 calls |
| Cluster_47 | 17 calls |
| Cluster_163 | 17 calls |
| Cluster_54 | 17 calls |

## How to Explore

1. `context({name: "as_u32"})` — see callers and callees
2. `query({search_query: "tests"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
