---
name: tests
description: "Skill for the Tests area of agenc-ircd. 1160 symbols across 103 files."
---

# Tests

1160 symbols | 103 files | Cohesion: 75%

## When to Use

- Working with code in `crates/`
- Understanding how nick, quit, join work
- Modifying tests-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/tests/stage_five_completion.rs` | login_index_codecs_reject_each_short_circuit_boundary, real_successful_login_batch_injects_lazy_migration_boundaries, login_lookup_and_lazy_migration_are_exactly_two_generation, initialized_lazy_login_fixture, later_protocol_bodies_are_profile_table_and_arm_bound (+73) |
| `crates/agenc-ircd-testkit/tests/domain_reference_model.rs` | apply_production, production_authority, apply_production_command, apply_production_join, reference_model_executes_every_command_with_real_behavior (+64) |
| `crates/agenc-ircd-federation-wire/src/tests/semantics.rs` | schema, fields, validate, opaque, unsigned (+53) |
| `crates/agenc-ircd-client-wire/src/registration_command.rs` | validate_post_registration_command, validate_join, validate_part, validate_mode, validate_topic (+50) |
| `crates/agenc-ircd-auth/tests/stage_four.rs` | response_round_trip, parse_authenticated_response, fixed_profile_and_all_wire_arms_reject_substitution, operation_context, operation_context_for_network (+49) |
| `crates/agenc-ircd-federation-wire/src/codec.rs` | encode_canonical, claim_bytes, validate_bounds, is_optional_fixed, validate_optional_fixed_field (+31) |
| `crates/agenc-ircd-domain/src/model.rs` | resolve_channel, parse, new, from_seed, at_revision (+28) |
| `crates/agenc-ircd-client-wire/src/auth_transport.rs` | zeroize_storage, drop, new, client, server_response (+21) |
| `crates/agenc-ircd-client-wire/tests/stage_two_regressions.rs` | in_flight_commit_defers_owned_input_and_resumes_it_after_registration, repeated_commit_defer_resume_cycles_retain_fifo_message_ownership, blind_cap_req_delays_commit_until_end, invalid_pass_does_not_consume_attempt_and_late_events_cannot_reopen_close, pending_ownership_and_auth_failures_are_transactional_and_terminal (+19) |
| `crates/agenc-ircd-crypto/src/account_hpke.rs` | from_bytes, as_bytes, key_id, generate, public_key (+18) |

## Entry Points

Start here when exploring this area:

- **`nick`** (Function) — `crates/agenc-ircd-domain/src/command.rs:725`
- **`quit`** (Function) — `crates/agenc-ircd-domain/src/command.rs:731`
- **`join`** (Function) — `crates/agenc-ircd-domain/src/command.rs:736`
- **`part_all`** (Function) — `crates/agenc-ircd-domain/src/command.rs:760`
- **`user_operator_notices`** (Function) — `crates/agenc-ircd-domain/src/command.rs:789`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `nick` | Function | `crates/agenc-ircd-domain/src/command.rs` | 725 |
| `quit` | Function | `crates/agenc-ircd-domain/src/command.rs` | 731 |
| `join` | Function | `crates/agenc-ircd-domain/src/command.rs` | 736 |
| `part_all` | Function | `crates/agenc-ircd-domain/src/command.rs` | 760 |
| `user_operator_notices` | Function | `crates/agenc-ircd-domain/src/command.rs` | 789 |
| `channel_mode_query` | Function | `crates/agenc-ircd-domain/src/command.rs` | 797 |
| `topic_query` | Function | `crates/agenc-ircd-domain/src/command.rs` | 813 |
| `topic_set` | Function | `crates/agenc-ircd-domain/src/command.rs` | 819 |
| `invite` | Function | `crates/agenc-ircd-domain/src/command.rs` | 837 |
| `message` | Function | `crates/agenc-ircd-domain/src/command.rs` | 859 |
| `presence` | Function | `crates/agenc-ircd-domain/src/command.rs` | 887 |
| `setname` | Function | `crates/agenc-ircd-domain/src/command.rs` | 902 |
| `chathistory` | Function | `crates/agenc-ircd-domain/src/command.rs` | 919 |
| `resolve_channel` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1240 |
| `bytes` | Function | `crates/agenc-ircd-testkit/src/domain_fixture.rs` | 26 |
| `account_id` | Function | `crates/agenc-ircd-testkit/src/domain_fixture.rs` | 32 |
| `channel_id` | Function | `crates/agenc-ircd-testkit/src/domain_fixture.rs` | 38 |
| `revision` | Function | `crates/agenc-ircd-testkit/src/domain_fixture.rs` | 43 |
| `generation` | Function | `crates/agenc-ircd-testkit/src/domain_fixture.rs` | 48 |
| `apply_plan` | Function | `crates/agenc-ircd-testkit/src/domain_fixture.rs` | 53 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → Presentation` | cross_community | 8 |
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → Canonical` | cross_community | 8 |
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → Is_global` | cross_community | 8 |
| `Mode_vectors_simulate_client_order_and_check_only_the_final_state → Presentation` | cross_community | 8 |
| `Mode_vectors_simulate_client_order_and_check_only_the_final_state → Canonical` | cross_community | 8 |
| `Remaining_mode_and_request_helpers_cover_successful_fallthroughs → Presentation` | cross_community | 8 |
| `Remaining_mode_and_request_helpers_cover_successful_fallthroughs → Canonical` | cross_community | 8 |
| `Remaining_mode_and_request_helpers_cover_successful_fallthroughs → Is_global` | cross_community | 8 |
| `Classify_recovery_state → As_bytes` | cross_community | 7 |
| `Rebuild_rekey_plan → As_bytes` | cross_community | 6 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_279 | 30 calls |
| Fuzz_targets | 24 calls |
| Cluster_203 | 23 calls |
| Cluster_23 | 22 calls |
| Cluster_222 | 18 calls |
| Cluster_130 | 15 calls |
| Cluster_2 | 14 calls |
| Cluster_209 | 13 calls |

## How to Explore

1. `context({name: "nick"})` — see callers and callees
2. `query({search_query: "tests"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
