---
name: tests
description: "Skill for the Tests area of agenc-ircd. 1056 symbols across 100 files."
---

# Tests

1056 symbols | 100 files | Cohesion: 78%

## When to Use

- Working with code in `crates/`
- Understanding how nick, quit, join work
- Modifying tests-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-testkit/tests/domain_reference_model.rs` | apply_production, production_authority, apply_production_command, apply_production_join, reference_model_executes_every_command_with_real_behavior (+64) |
| `crates/agenc-ircd-federation-wire/src/tests/semantics.rs` | schema, fields, validate, opaque, unsigned (+53) |
| `crates/agenc-ircd-storage/tests/stage_five_completion.rs` | signed_growth_report_is_exact_tuple_authority, platform_adapter_rejects_each_path_lock_guard_and_capacity_boundary, transaction_capacity_admission_observes_minus_equal_and_plus_one_boundaries, qualification_rejects_every_report_and_measurement_boundary, qualification_required_file_set_measures_every_named_durable_case (+53) |
| `crates/agenc-ircd-auth/tests/stage_four.rs` | hash, new, credential, operation_context, operation_route (+49) |
| `crates/agenc-ircd-client-wire/src/registration_command.rs` | validate_post_registration_command, validate_join, validate_part, validate_mode, validate_topic (+48) |
| `crates/agenc-ircd-storage/src/construction_runtime.rs` | add_final_checkpoint, initial_construction_accounting, add_preflight_record_charge, login_index_transition_preflight, index_restore_channel_source (+38) |
| `crates/agenc-ircd-federation-wire/src/codec.rs` | encode_canonical, claim_bytes, validate_bounds, is_optional_fixed, validate_optional_fixed_field (+31) |
| `crates/agenc-ircd-domain/src/model.rs` | resolve_channel, parse, new, from_seed, at_revision (+28) |
| `crates/agenc-ircd-client-wire/src/auth_transport.rs` | zeroize_storage, drop, new, client, server_response (+21) |
| `crates/agenc-ircd-client-wire/tests/stage_two_regressions.rs` | in_flight_commit_defers_owned_input_and_resumes_it_after_registration, repeated_commit_defer_resume_cycles_retain_fifo_message_ownership, blind_cap_req_delays_commit_until_end, invalid_pass_does_not_consume_attempt_and_late_events_cannot_reopen_close, pending_ownership_and_auth_failures_are_transactional_and_terminal (+19) |

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
| `Mutation_helpers_ignore_missing_targets_without_corrupting_indexes → Presentation` | cross_community | 8 |
| `Mutation_helpers_ignore_missing_targets_without_corrupting_indexes → Canonical` | cross_community | 8 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_245 | 30 calls |
| Fuzz_targets | 29 calls |
| Cluster_75 | 18 calls |
| Cluster_24 | 17 calls |
| Cluster_131 | 15 calls |
| Cluster_2 | 11 calls |
| Cluster_113 | 9 calls |
| Cluster_95 | 9 calls |

## How to Explore

1. `context({name: "nick"})` — see callers and callees
2. `query({search_query: "tests"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
