---
name: state-core
description: "Skill for the State_core area of agenc-ircd. 834 symbols across 47 files."
---

# State_core

834 symbols | 47 files | Cohesion: 78%

## When to Use

- Working with code in `crates/`
- Understanding how response_intent, invitation_id, invitation_expires_at work
- Modifying state_core-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/account_service.rs` | tag, from_tag, binding, encode, decode (+146) |
| `crates/agenc-ircd-runtime/src/state_core/mod.rs` | route, complete_command_observation, sessions_mut, buckets_mut, timers_mut (+116) |
| `crates/agenc-ircd-runtime/src/state_core/reconstruct.rs` | admit_opaque_record, admit_fake_opaque_record, admit_live_opaque_record, finish, reconstruct (+101) |
| `crates/agenc-ircd-storage/src/construction_runtime.rs` | validate, start, start_streaming, start_inner, push (+79) |
| `crates/agenc-ircd-runtime/src/state_core/durable.rs` | account_key, put, delete, revalidate, account_service_table (+59) |
| `crates/agenc-ircd-runtime/src/registration.rs` | new, for_purpose, access_policy, route_message, refresh_deadline (+50) |
| `crates/agenc-ircd-runtime/src/channels.rs` | reload_ready, defer, prepare_crypto_jobs, prepare_join_key_jobs, prepare_mode_key_jobs (+27) |
| `crates/agenc-ircd-runtime/src/query_render.rs` | render_query, render_list_snapshot, render_who_snapshot, snapshot_who_self, snapshot_who_nickname (+21) |
| `crates/agenc-ircd-runtime/src/state_core/session.rs` | begin_physical_close, accept_line, unbind_session, mark_sink_gone, connection (+20) |
| `crates/agenc-ircd-runtime/src/state_core/timers.rs` | schedule, cancel, compact, wall_trusted, pop_due (+17) |

## Entry Points

Start here when exploring this area:

- **`response_intent`** (Function) — `crates/agenc-ircd-auth/src/service.rs:201`
- **`invitation_id`** (Function) — `crates/agenc-ircd-auth/src/service.rs:486`
- **`invitation_expires_at`** (Function) — `crates/agenc-ircd-auth/src/service.rs:495`
- **`as_bytes`** (Function) — `crates/agenc-ircd-auth/src/wire.rs:252`
- **`enabled_names`** (Function) — `crates/agenc-ircd-client-wire/src/capability.rs:345`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `response_intent` | Function | `crates/agenc-ircd-auth/src/service.rs` | 201 |
| `invitation_id` | Function | `crates/agenc-ircd-auth/src/service.rs` | 486 |
| `invitation_expires_at` | Function | `crates/agenc-ircd-auth/src/service.rs` | 495 |
| `as_bytes` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 252 |
| `enabled_names` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 345 |
| `take_parameter` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 72 |
| `has_outstanding_ping` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 578 |
| `enabled_capabilities` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 584 |
| `as_bytes` | Function | `crates/agenc-ircd-crypto/src/hash.rs` | 23 |
| `account` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1685 |
| `account_is_suspended` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1771 |
| `reload_ready` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 958 |
| `connection_opened` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1013 |
| `connection_closed` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1062 |
| `timer_fired` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1227 |
| `startup` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1574 |
| `registration_grant_write` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1602 |
| `begin_registration_grant_consumption` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1626 |
| `registration_rejected` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1736 |
| `begin_account_deletion` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1764 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Connection_opened → FixtureIdentity` | cross_community | 8 |
| `Connection_opened → Create` | cross_community | 8 |
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
| Tests | 162 calls |
| Admission | 33 calls |
| Bridge | 13 calls |
| Cluster_94 | 12 calls |
| Listener | 11 calls |
| Cluster_314 | 9 calls |
| Connection | 9 calls |
| Cluster_46 | 8 calls |

## How to Explore

1. `context({name: "response_intent"})` — see callers and callees
2. `query({search_query: "state_core"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
