---
name: tests
description: "Skill for the Tests area of agenc-ircd. 561 symbols across 55 files."
---

# Tests

561 symbols | 55 files | Cohesion: 83%

## When to Use

- Working with code in `crates/`
- Understanding how nick, quit, join work
- Modifying tests-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-client-wire/src/registration_command.rs` | validate_post_registration_command, validate_join, validate_part, validate_mode, validate_topic (+48) |
| `crates/agenc-ircd-federation-wire/src/tests/semantics.rs` | schema, fields, validate, opaque, unsigned (+38) |
| `crates/agenc-ircd-domain/src/decision.rs` | message, apply_mode_change, invite_expiry, mode_events, apply_role_change (+29) |
| `crates/agenc-ircd-client-wire/tests/stage_two_regressions.rs` | in_flight_commit_defers_owned_input_and_resumes_it_after_registration, repeated_commit_defer_resume_cycles_retain_fifo_message_ownership, blind_cap_req_delays_commit_until_end, invalid_pass_does_not_consume_attempt_and_late_events_cannot_reopen_close, pending_ownership_and_auth_failures_are_transactional_and_terminal (+19) |
| `crates/agenc-ircd-domain/src/model.rs` | principal, default, new_ephemeral, parse, new (+18) |
| `crates/agenc-ircd-client-wire/src/auth_transport.rs` | zeroize_storage, drop, new, client, server_response (+17) |
| `crates/agenc-ircd-client-wire/tests/stage_two_branches.rs` | sasl_covers_abort_retry_finish_completion_and_failure_branches, account_carriers_cover_sequence_shape_finish_and_deadlines, feed_sasl_request, feed_account_request, registration_profile_changes_notify_only_opted_in_clients_and_always_reconnect (+16) |
| `crates/agenc-ircd-client-wire/tests/stage_two_wire.rs` | new, stream_framer_handles_every_split_and_coalesced_boundary, stream_framer_enforces_terminators_utf8_nul_eof_and_exact_limits, syntax_parser_canonicalizes_commands_and_preserves_trailing_presence, registration_bounds_pending_input_keepalive_and_close_idempotence (+16) |
| `crates/agenc-ircd-federation-wire/src/codec.rs` | decode_exact, encode_canonical, into_wire, decode_schema_iterative, process_decode_frame (+15) |
| `crates/agenc-ircd-testkit/src/reference_codec.rs` | encode_length_prefix, write_u64, write_fixed, write_opaque, write_length (+15) |

## Entry Points

Start here when exploring this area:

- **`nick`** (Function) — `crates/agenc-ircd-domain/src/command.rs:566`
- **`quit`** (Function) — `crates/agenc-ircd-domain/src/command.rs:572`
- **`join`** (Function) — `crates/agenc-ircd-domain/src/command.rs:577`
- **`part_all`** (Function) — `crates/agenc-ircd-domain/src/command.rs:601`
- **`mode`** (Function) — `crates/agenc-ircd-domain/src/command.rs:606`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `nick` | Function | `crates/agenc-ircd-domain/src/command.rs` | 566 |
| `quit` | Function | `crates/agenc-ircd-domain/src/command.rs` | 572 |
| `join` | Function | `crates/agenc-ircd-domain/src/command.rs` | 577 |
| `part_all` | Function | `crates/agenc-ircd-domain/src/command.rs` | 601 |
| `mode` | Function | `crates/agenc-ircd-domain/src/command.rs` | 606 |
| `user_operator_notices` | Function | `crates/agenc-ircd-domain/src/command.rs` | 630 |
| `channel_mode_query` | Function | `crates/agenc-ircd-domain/src/command.rs` | 638 |
| `topic_query` | Function | `crates/agenc-ircd-domain/src/command.rs` | 654 |
| `invite` | Function | `crates/agenc-ircd-domain/src/command.rs` | 678 |
| `message` | Function | `crates/agenc-ircd-domain/src/command.rs` | 700 |
| `presence` | Function | `crates/agenc-ircd-domain/src/command.rs` | 728 |
| `setname` | Function | `crates/agenc-ircd-domain/src/command.rs` | 743 |
| `chathistory` | Function | `crates/agenc-ircd-domain/src/command.rs` | 760 |
| `bytes` | Function | `crates/agenc-ircd-testkit/src/domain_fixture.rs` | 26 |
| `account_id` | Function | `crates/agenc-ircd-testkit/src/domain_fixture.rs` | 32 |
| `channel_id` | Function | `crates/agenc-ircd-testkit/src/domain_fixture.rs` | 38 |
| `revision` | Function | `crates/agenc-ircd-testkit/src/domain_fixture.rs` | 43 |
| `generation` | Function | `crates/agenc-ircd-testkit/src/domain_fixture.rs` | 48 |
| `apply_plan` | Function | `crates/agenc-ircd-testkit/src/domain_fixture.rs` | 53 |
| `create_account` | Function | `crates/agenc-ircd-testkit/src/domain_fixture.rs` | 64 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → At_revision` | cross_community | 6 |
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → Ascii_lowercase_copy` | cross_community | 6 |
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → Fallible_string_copy` | cross_community | 6 |
| `Remaining_mode_and_request_helpers_cover_successful_fallthroughs → At_revision` | cross_community | 6 |
| `Remaining_mode_and_request_helpers_cover_successful_fallthroughs → Ascii_lowercase_copy` | cross_community | 6 |
| `Remaining_mode_and_request_helpers_cover_successful_fallthroughs → Fallible_string_copy` | cross_community | 6 |
| `Remaining_plan_guards_cover_owner_continuity_part_scope_and_extra_entropy → At_revision` | cross_community | 6 |
| `Remaining_plan_guards_cover_owner_continuity_part_scope_and_extra_entropy → Ascii_lowercase_copy` | cross_community | 6 |
| `Remaining_plan_guards_cover_owner_continuity_part_scope_and_extra_entropy → Fallible_string_copy` | cross_community | 6 |
| `Drive → At` | cross_community | 6 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_64 | 23 calls |
| Fuzz_targets | 21 calls |
| Cluster_6 | 10 calls |
| Cluster_29 | 6 calls |
| Cluster_103 | 6 calls |
| Cluster_99 | 4 calls |
| Cluster_33 | 3 calls |
| Cluster_101 | 3 calls |

## How to Explore

1. `context({name: "nick"})` — see callers and callees
2. `query({search_query: "tests"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
