---
name: tests
description: "Skill for the Tests area of agenc-ircd. 420 symbols across 44 files."
---

# Tests

420 symbols | 44 files | Cohesion: 82%

## When to Use

- Working with code in `crates/`
- Understanding how decode_exact, parameter_count, validate_post_registration_command work
- Modifying tests-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-client-wire/src/registration_command.rs` | validate_post_registration_command, validate_join, validate_part, validate_mode, validate_topic (+48) |
| `crates/agenc-ircd-federation-wire/src/tests/semantics.rs` | schema, fields, validate, opaque, unsigned (+38) |
| `crates/agenc-ircd-client-wire/tests/stage_two_regressions.rs` | in_flight_commit_defers_owned_input_and_resumes_it_after_registration, repeated_commit_defer_resume_cycles_retain_fifo_message_ownership, blind_cap_req_delays_commit_until_end, invalid_pass_does_not_consume_attempt_and_late_events_cannot_reopen_close, pending_ownership_and_auth_failures_are_transactional_and_terminal (+18) |
| `crates/agenc-ircd-client-wire/src/auth_transport.rs` | zeroize_storage, drop, new, client, server_response (+17) |
| `crates/agenc-ircd-client-wire/tests/stage_two_branches.rs` | sasl_covers_abort_retry_finish_completion_and_failure_branches, account_carriers_cover_sequence_shape_finish_and_deadlines, feed_sasl_request, feed_account_request, registration_profile_changes_notify_only_opted_in_clients_and_always_reconnect (+16) |
| `crates/agenc-ircd-client-wire/tests/stage_two_wire.rs` | new, stream_framer_handles_every_split_and_coalesced_boundary, stream_framer_enforces_terminators_utf8_nul_eof_and_exact_limits, syntax_parser_canonicalizes_commands_and_preserves_trailing_presence, registration_bounds_pending_input_keepalive_and_close_idempotence (+16) |
| `crates/agenc-ircd-federation-wire/src/codec.rs` | decode_exact, encode_canonical, into_wire, decode_schema_iterative, process_decode_frame (+15) |
| `crates/agenc-ircd-testkit/src/reference_codec.rs` | encode_length_prefix, write_u64, write_fixed, write_opaque, write_length (+15) |
| `crates/agenc-ircd-testkit/tests/codec_boundaries.rs` | finite_hostile_corpus_is_total_for_every_schema, encode_part_operation, encode_join_operation, every_vector_rejects_every_truncation_and_trailing_byte, constructors_reject_shape_type_bounds_enum_schema_and_order (+10) |
| `crates/agenc-ircd-client-wire/tests/nickname_reservation_ownership.rs` | new_nick_cancels_pending_before_replacing_and_releases_stale_acceptance, replacement_result_selects_the_exact_lease_transferred_by_commit, latest_nickname_blocks_pass_user_cap_and_token_completion_callers, every_close_entry_cleans_nickname_ownership_once_before_close, transport_close_and_deadline_stale_result_cleanup_are_generation_bound (+10) |

## Entry Points

Start here when exploring this area:

- **`decode_exact`** (Function) — `crates/agenc-ircd-federation-wire/src/codec.rs:291`
- **`parameter_count`** (Function) — `crates/agenc-ircd-client-wire/src/message.rs:63`
- **`validate_post_registration_command`** (Function) — `crates/agenc-ircd-client-wire/src/registration_command.rs:406`
- **`iter`** (Function) — `crates/agenc-ircd-client-wire/src/tags.rs:201`
- **`new`** (Function) — `crates/agenc-ircd-client-wire/src/auth_transport.rs:215`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `decode_exact` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 291 |
| `parameter_count` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 63 |
| `validate_post_registration_command` | Function | `crates/agenc-ircd-client-wire/src/registration_command.rs` | 406 |
| `iter` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 201 |
| `new` | Function | `crates/agenc-ircd-client-wire/src/auth_transport.rs` | 215 |
| `client` | Function | `crates/agenc-ircd-client-wire/src/auth_transport.rs` | 229 |
| `server_response` | Function | `crates/agenc-ircd-client-wire/src/auth_transport.rs` | 251 |
| `complete` | Function | `crates/agenc-ircd-client-wire/src/auth_transport.rs` | 283 |
| `tick` | Function | `crates/agenc-ircd-client-wire/src/auth_transport.rs` | 305 |
| `parse_registration_command` | Function | `crates/agenc-ircd-client-wire/src/registration_command.rs` | 362 |
| `parse_client_transcript` | Function | `crates/agenc-ircd-testkit/src/client_transcript.rs` | 144 |
| `write_u64` | Function | `crates/agenc-ircd-testkit/src/reference_codec.rs` | 156 |
| `write_fixed` | Function | `crates/agenc-ircd-testkit/src/reference_codec.rs` | 163 |
| `write_opaque` | Function | `crates/agenc-ircd-testkit/src/reference_codec.rs` | 170 |
| `write_length` | Function | `crates/agenc-ircd-testkit/src/reference_codec.rs` | 194 |
| `finish` | Function | `crates/agenc-ircd-testkit/src/reference_codec.rs` | 208 |
| `render_tags` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 509 |
| `try_clone` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 77 |
| `encode` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 374 |
| `parse_client_tags` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 386 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Labeled_response → Escaped_len` | cross_community | 7 |
| `Tick → At` | cross_community | 6 |
| `Add_client_only_tag → Validate_parameter_count` | cross_community | 6 |
| `Add_client_only_tag → Command_bytes` | cross_community | 6 |
| `Add_client_only_tag → Validate_prefix` | cross_community | 6 |
| `Add_client_only_tag → Validate_command` | cross_community | 6 |
| `Drive → At` | cross_community | 6 |
| `Drive → Admit_len` | cross_community | 6 |
| `Run → At` | cross_community | 6 |
| `Labeled_response → Validate_parameter_count` | cross_community | 6 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Fuzz_targets | 19 calls |
| Cluster_2 | 14 calls |
| Cluster_72 | 7 calls |
| Cluster_68 | 4 calls |
| Cluster_24 | 4 calls |
| Cluster_85 | 3 calls |
| Cluster_70 | 3 calls |
| Cluster_61 | 3 calls |

## How to Explore

1. `context({name: "decode_exact"})` — see callers and callees
2. `query({search_query: "tests"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
