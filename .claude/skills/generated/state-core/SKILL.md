---
name: state-core
description: "Skill for the State_core area of agenc-ircd. 1000 symbols across 77 files."
---

# State_core

1000 symbols | 77 files | Cohesion: 67%

## When to Use

- Working with code in `crates/`
- Understanding how response_intent, invitation_id, invitation_expires_at work
- Modifying state_core-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/account_service.rs` | tag, from_tag, binding, encode, decode (+152) |
| `crates/agenc-ircd-runtime/src/state_core/mod.rs` | sessions_mut, buckets_mut, timers_mut, submit_storage_read, entropy_mut (+123) |
| `crates/agenc-ircd-runtime/src/state_core/reconstruct.rs` | admit_opaque_record, admit_fake_opaque_record, admit_live_opaque_record, finish, reconstruct (+100) |
| `crates/agenc-ircd-storage/src/construction_runtime.rs` | validate, start, start_streaming, start_inner, push (+85) |
| `crates/agenc-ircd-runtime/src/registration.rs` | new, for_purpose, access_policy, route_message, refresh_deadline (+71) |
| `crates/agenc-ircd-runtime/src/state_core/durable.rs` | account_key, put, delete, revalidate, account_service_table (+61) |
| `crates/agenc-ircd-runtime/src/admin.rs` | acquire_audit_export_memory, admin_process_channel, new, start, admin_lifecycle_channel (+40) |
| `crates/agenc-ircd-runtime/src/state_core/session.rs` | begin_physical_close, unbind_session, mark_sink_gone, connection, sink_for_generation (+20) |
| `crates/agenc-ircd-runtime/src/state_core/timers.rs` | schedule, cancel, compact, wall_trusted, pop_due (+17) |
| `crates/agenc-ircd-storage/src/engine.rs` | open_construction_source_record, start_backup, verify_snapshot_accounting, checkpoint_accounting, checkpoint_retired_charges (+17) |

## Entry Points

Start here when exploring this area:

- **`response_intent`** (Function) — `crates/agenc-ircd-auth/src/service.rs:201`
- **`invitation_id`** (Function) — `crates/agenc-ircd-auth/src/service.rs:486`
- **`invitation_expires_at`** (Function) — `crates/agenc-ircd-auth/src/service.rs:495`
- **`as_bytes`** (Function) — `crates/agenc-ircd-auth/src/wire.rs:252`
- **`has_outstanding_ping`** (Function) — `crates/agenc-ircd-client-wire/src/registration.rs:578`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `response_intent` | Function | `crates/agenc-ircd-auth/src/service.rs` | 201 |
| `invitation_id` | Function | `crates/agenc-ircd-auth/src/service.rs` | 486 |
| `invitation_expires_at` | Function | `crates/agenc-ircd-auth/src/service.rs` | 495 |
| `as_bytes` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 252 |
| `has_outstanding_ping` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 578 |
| `as_bytes` | Function | `crates/agenc-ircd-crypto/src/hash.rs` | 23 |
| `session` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1679 |
| `account` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1685 |
| `account_is_suspended` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1771 |
| `users_for_account` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1789 |
| `user_for_session` | Function | `crates/agenc-ircd-domain/src/model.rs` | 2186 |
| `reload_ready` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 958 |
| `registered_authority_fenced` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 970 |
| `connection_opened` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1013 |
| `connection_closed` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1062 |
| `timer_fired` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1227 |
| `startup` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1574 |
| `registration_grant_write` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1602 |
| `begin_registration_grant_consumption` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1626 |
| `registration_committed` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1681 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Connection_opened → FixtureIdentity` | cross_community | 9 |
| `Connection_opened → Create` | cross_community | 9 |
| `Registration_committed → New` | cross_community | 8 |
| `Route_sasl → Into_parts` | cross_community | 7 |
| `Route_sasl → CreationReservation` | intra_community | 7 |
| `Route_sasl → AccountServiceConfig` | cross_community | 7 |
| `Route_sasl → Try_from` | cross_community | 7 |
| `Registration_committed → QueuePass` | cross_community | 7 |
| `Registration_committed → Tentative` | cross_community | 7 |
| `Serve → Try_from` | cross_community | 6 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 143 calls |
| Admission | 37 calls |
| Bridge | 35 calls |
| Coordinator | 16 calls |
| Admin | 13 calls |
| Cluster_602 | 12 calls |
| Federation | 11 calls |
| Connection | 9 calls |

## How to Explore

1. `context({name: "response_intent"})` — see callers and callees
2. `query({search_query: "state_core"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
