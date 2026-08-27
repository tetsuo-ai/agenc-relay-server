---
name: tests
description: "Skill for the Tests area of agenc-ircd. 702 symbols across 71 files."
---

# Tests

702 symbols | 71 files | Cohesion: 81%

## When to Use

- Working with code in `crates/`
- Understanding how into_name, information, new work
- Modifying tests-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-client-wire/src/registration_command.rs` | validate_post_registration_command, validate_join, validate_part, validate_mode, validate_topic (+48) |
| `crates/agenc-ircd-domain/src/decision.rs` | new, user, message, resolve_message_targets, plan_join (+42) |
| `crates/agenc-ircd-federation-wire/src/tests/semantics.rs` | schema, fields, validate, opaque, unsigned (+38) |
| `crates/agenc-ircd-auth/tests/stage_four.rs` | request_round_trip, response_round_trip, parse_authenticated_plaintext, parse_authenticated_response, fixed_profile_and_all_wire_arms_reject_substitution (+26) |
| `crates/agenc-ircd-client-wire/src/auth_transport.rs` | zeroize_storage, drop, new, client, server_response (+20) |
| `crates/agenc-ircd-client-wire/tests/stage_two_regressions.rs` | in_flight_commit_defers_owned_input_and_resumes_it_after_registration, repeated_commit_defer_resume_cycles_retain_fifo_message_ownership, blind_cap_req_delays_commit_until_end, invalid_pass_does_not_consume_attempt_and_late_events_cannot_reopen_close, pending_ownership_and_auth_failures_are_transactional_and_terminal (+19) |
| `crates/agenc-ircd-domain/src/model.rs` | principal, default, new_ephemeral, parse, new (+18) |
| `crates/agenc-ircd-crypto/src/account_hpke.rs` | from_bytes, as_bytes, key_id, generate, public_key (+17) |
| `crates/agenc-ircd-client-wire/tests/stage_two_branches.rs` | sasl_covers_abort_retry_finish_completion_and_failure_branches, account_carriers_cover_sequence_shape_finish_and_deadlines, feed_sasl_request, feed_account_request, registration_profile_changes_notify_only_opted_in_clients_and_always_reconnect (+16) |
| `crates/agenc-ircd-client-wire/tests/stage_two_wire.rs` | new, stream_framer_handles_every_split_and_coalesced_boundary, stream_framer_enforces_terminators_utf8_nul_eof_and_exact_limits, syntax_parser_canonicalizes_commands_and_preserves_trailing_presence, registration_bounds_pending_input_keepalive_and_close_idempotence (+16) |

## Entry Points

Start here when exploring this area:

- **`into_name`** (Function) — `crates/agenc-ircd-domain/src/command.rs:160`
- **`information`** (Function) — `crates/agenc-ircd-domain/src/command.rs:706`
- **`new`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:49`
- **`user`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:398`
- **`principal`** (Function) — `crates/agenc-ircd-domain/src/model.rs:604`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `into_name` | Function | `crates/agenc-ircd-domain/src/command.rs` | 160 |
| `information` | Function | `crates/agenc-ircd-domain/src/command.rs` | 706 |
| `new` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 49 |
| `user` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 398 |
| `principal` | Function | `crates/agenc-ircd-domain/src/model.rs` | 604 |
| `new_ephemeral` | Function | `crates/agenc-ircd-domain/src/model.rs` | 819 |
| `now` | Function | `crates/agenc-ircd-testkit/src/lib.rs` | 97 |
| `try_from_str` | Function | `crates/agenc-ircd-types/src/bounded.rs` | 102 |
| `from_ticks` | Function | `crates/agenc-ircd-types/src/quantities.rs` | 109 |
| `from_unix_seconds` | Function | `crates/agenc-ircd-types/src/quantities.rs` | 117 |
| `decode_exact` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 291 |
| `parameter_count` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 63 |
| `validate_post_registration_command` | Function | `crates/agenc-ircd-client-wire/src/registration_command.rs` | 406 |
| `iter` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 201 |
| `seal_account_response` | Function | `crates/agenc-ircd-auth/src/service.rs` | 770 |
| `from_sealed` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 52 |
| `open_and_parse_request` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 131 |
| `response_kind` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 624 |
| `open_and_parse_response` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 667 |
| `from_bytes` | Function | `crates/agenc-ircd-crypto/src/account_hpke.rs` | 53 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Labeled_response → Escaped_len` | cross_community | 7 |
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → At_revision` | cross_community | 6 |
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → Ascii_lowercase_copy` | cross_community | 6 |
| `Mutation_application_covers_optional_cleanup_and_destroy_paths → Fallible_string_copy` | cross_community | 6 |
| `Generate → Fill_from` | cross_community | 6 |
| `Remaining_mode_and_request_helpers_cover_successful_fallthroughs → At_revision` | cross_community | 6 |
| `Remaining_mode_and_request_helpers_cover_successful_fallthroughs → Ascii_lowercase_copy` | cross_community | 6 |
| `Remaining_mode_and_request_helpers_cover_successful_fallthroughs → Fallible_string_copy` | cross_community | 6 |
| `Remaining_plan_guards_cover_owner_continuity_part_scope_and_extra_entropy → At_revision` | cross_community | 6 |
| `Remaining_plan_guards_cover_owner_continuity_part_scope_and_extra_entropy → Ascii_lowercase_copy` | cross_community | 6 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Fuzz_targets | 19 calls |
| Cluster_17 | 15 calls |
| Cluster_84 | 14 calls |
| Cluster_11 | 10 calls |
| Cluster_6 | 9 calls |
| Cluster_80 | 9 calls |
| Cluster_3 | 8 calls |
| Cluster_38 | 7 calls |

## How to Explore

1. `context({name: "into_name"})` — see callers and callees
2. `query({search_query: "tests"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
