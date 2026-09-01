---
name: state-core
description: "Skill for the State_core area of agenc-ircd. 672 symbols across 46 files."
---

# State_core

672 symbols | 46 files | Cohesion: 74%

## When to Use

- Working with code in `crates/`
- Understanding how response_intent, into_result_after_commit, into_transaction_after_commit work
- Modifying state_core-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/account_service.rs` | tag, from_tag, binding, encode, decode (+157) |
| `crates/agenc-ircd-runtime/src/state_core/mod.rs` | route, sessions_mut, buckets_mut, timers_mut, submit_storage_read (+80) |
| `crates/agenc-ircd-storage/src/construction_runtime.rs` | validate, start, start_streaming, start_inner, index_restore_channel_source (+73) |
| `crates/agenc-ircd-runtime/src/state_core/durable.rs` | account_key, channel_key, put, delete, revalidate (+51) |
| `crates/agenc-ircd-runtime/src/state_core/reconstruct.rs` | admit_opaque_record, admit_fake_opaque_record, admit_live_opaque_record, finish, validate_login_index_generations (+44) |
| `crates/agenc-ircd-runtime/src/registration.rs` | new, access_policy, route_message, refresh_deadline, apply_action (+39) |
| `crates/agenc-ircd-runtime/src/state_core/session.rs` | unbind_session, connection, generation_for_user, begin_physical_close, accept_line (+20) |
| `crates/agenc-ircd-runtime/src/state_core/timers.rs` | schedule, cancel, compact, wall_trusted, pop_due (+17) |
| `crates/agenc-ircd-runtime/src/channels.rs` | reload_ready, defer, prepare_crypto_jobs, prepare_join_key_jobs, prepare_mode_key_jobs (+11) |
| `crates/agenc-ircd-runtime/src/state_core/pending.rs` | silent, with_rejection_frames, into_rejection, staged_origin_moves_retained_rejection_frames, silent_staged_origin_retains_no_public_failure (+10) |

## Entry Points

Start here when exploring this area:

- **`response_intent`** (Function) — `crates/agenc-ircd-auth/src/service.rs:201`
- **`into_result_after_commit`** (Function) — `crates/agenc-ircd-auth/src/service.rs:210`
- **`into_transaction_after_commit`** (Function) — `crates/agenc-ircd-auth/src/service.rs:295`
- **`invitation_id`** (Function) — `crates/agenc-ircd-auth/src/service.rs:486`
- **`invitation_expires_at`** (Function) — `crates/agenc-ircd-auth/src/service.rs:495`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `response_intent` | Function | `crates/agenc-ircd-auth/src/service.rs` | 201 |
| `into_result_after_commit` | Function | `crates/agenc-ircd-auth/src/service.rs` | 210 |
| `into_transaction_after_commit` | Function | `crates/agenc-ircd-auth/src/service.rs` | 295 |
| `invitation_id` | Function | `crates/agenc-ircd-auth/src/service.rs` | 486 |
| `invitation_expires_at` | Function | `crates/agenc-ircd-auth/src/service.rs` | 495 |
| `as_bytes` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 252 |
| `enabled_names` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 345 |
| `take_parameter` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 72 |
| `has_outstanding_ping` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 578 |
| `enabled_capabilities` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 584 |
| `capability_state` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 592 |
| `as_bytes` | Function | `crates/agenc-ircd-crypto/src/hash.rs` | 23 |
| `from_storage_key` | Function | `crates/agenc-ircd-crypto/src/hash.rs` | 113 |
| `account` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1627 |
| `account_is_suspended` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1699 |
| `nickname_reserved_by` | Function | `crates/agenc-ircd-domain/src/model.rs` | 2055 |
| `reload_ready` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 916 |
| `connection_opened` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 926 |
| `connection_closed` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 975 |
| `timer_fired` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1140 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Audit_retention_deletes_prefix_and_puts_checkpoint_in_one_batch → As_bytes` | cross_community | 7 |
| `Audit_retention_deletes_prefix_and_puts_checkpoint_in_one_batch → Try_from` | cross_community | 7 |
| `Internal_restore_scans_reject_duplicate_and_cross_kind_inputs → Validate_nonzero_limit` | cross_community | 6 |
| `Internal_restore_scans_reject_duplicate_and_cross_kind_inputs → Validate_nonzero_usize_limit` | cross_community | 6 |
| `Internal_restore_scans_reject_duplicate_and_cross_kind_inputs → Put_fixed` | cross_community | 6 |
| `Disk_plan_and_preflight_accounting_reject_each_independent_internal_mismatch → Validate` | cross_community | 6 |
| `Disk_plan_and_preflight_accounting_reject_each_independent_internal_mismatch → Put_fixed` | cross_community | 6 |
| `Disk_plan_and_preflight_accounting_reject_each_independent_internal_mismatch → New` | cross_community | 6 |
| `Disk_plan_and_preflight_accounting_reject_each_independent_internal_mismatch → Validate_nonzero_limit` | cross_community | 6 |
| `Cursor_successor_and_completion_guards_reject_reachable_internal_mismatches → Validate` | cross_community | 6 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 130 calls |
| Admission | 28 calls |
| Cluster_282 | 12 calls |
| Cluster_278 | 9 calls |
| Bridge | 7 calls |
| Cluster_322 | 7 calls |
| Listener | 6 calls |
| Cluster_436 | 5 calls |

## How to Explore

1. `context({name: "response_intent"})` — see callers and callees
2. `query({search_query: "state_core"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
