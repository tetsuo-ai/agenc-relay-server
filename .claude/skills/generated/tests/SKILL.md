---
name: tests
description: "Skill for the Tests area of agenc-ircd. 2004 symbols across 209 files."
---

# Tests

2004 symbols | 209 files | Cohesion: 75%

## When to Use

- Working with code in `crates/`
- Understanding how nick, quit, part_all work
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
| `crates/agenc-ircd-runtime/src/federation/coordinator/tests/harness.rs` | entropy_script, peer_identity, new, send, establish (+36) |
| `crates/agenc-ircd-federation-wire/src/codec.rs` | decode_exact, encode_canonical, claim_bytes, validate_bounds, is_optional_fixed (+31) |
| `crates/agenc-ircd-domain/src/model.rs` | new, parse, with_policies, from_seed, test_public_cloak (+30) |

## Entry Points

Start here when exploring this area:

- **`nick`** (Function) — `crates/agenc-ircd-domain/src/command.rs:725`
- **`quit`** (Function) — `crates/agenc-ircd-domain/src/command.rs:731`
- **`part_all`** (Function) — `crates/agenc-ircd-domain/src/command.rs:760`
- **`user_operator_notices`** (Function) — `crates/agenc-ircd-domain/src/command.rs:789`
- **`channel_mode_query`** (Function) — `crates/agenc-ircd-domain/src/command.rs:797`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `nick` | Function | `crates/agenc-ircd-domain/src/command.rs` | 725 |
| `quit` | Function | `crates/agenc-ircd-domain/src/command.rs` | 731 |
| `part_all` | Function | `crates/agenc-ircd-domain/src/command.rs` | 760 |
| `user_operator_notices` | Function | `crates/agenc-ircd-domain/src/command.rs` | 789 |
| `channel_mode_query` | Function | `crates/agenc-ircd-domain/src/command.rs` | 797 |
| `topic_set` | Function | `crates/agenc-ircd-domain/src/command.rs` | 819 |
| `apply` | Function | `crates/agenc-ircd-domain/src/federation/projection.rs` | 305 |
| `install_edge` | Function | `crates/agenc-ircd-domain/src/federation/projection.rs` | 333 |
| `close_registered` | Function | `crates/agenc-ircd-runtime/src/channels.rs` | 850 |
| `install_edge` | Function | `crates/agenc-ircd-runtime/src/state_core/projector.rs` | 140 |
| `committed` | Function | `crates/agenc-ircd-runtime/src/state_core/projector.rs` | 338 |
| `bytes` | Function | `crates/agenc-ircd-testkit/src/domain_fixture.rs` | 26 |
| `account_id` | Function | `crates/agenc-ircd-testkit/src/domain_fixture.rs` | 32 |
| `channel_id` | Function | `crates/agenc-ircd-testkit/src/domain_fixture.rs` | 38 |
| `generation` | Function | `crates/agenc-ircd-testkit/src/domain_fixture.rs` | 48 |
| `apply_plan` | Function | `crates/agenc-ircd-testkit/src/domain_fixture.rs` | 53 |
| `create_account` | Function | `crates/agenc-ircd-testkit/src/domain_fixture.rs` | 64 |
| `open_session` | Function | `crates/agenc-ircd-testkit/src/domain_fixture.rs` | 81 |
| `registered_admission` | Function | `crates/agenc-ircd-testkit/src/domain_fixture.rs` | 119 |
| `message_admission` | Function | `crates/agenc-ircd-testkit/src/domain_fixture.rs` | 124 |

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
| State_core | 212 calls |
| Federation | 66 calls |
| Codec | 36 calls |
| Admission | 35 calls |
| Tls | 32 calls |
| Cluster_658 | 30 calls |
| Fuzz_targets | 18 calls |
| Cluster_63 | 18 calls |

## How to Explore

1. `context({name: "nick"})` — see callers and callees
2. `query({search_query: "tests"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
