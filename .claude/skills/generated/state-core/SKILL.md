---
name: state-core
description: "Skill for the State_core area of agenc-ircd. 720 symbols across 52 files."
---

# State_core

720 symbols | 52 files | Cohesion: 72%

## When to Use

- Working with code in `crates/`
- Understanding how response_intent, invitation_id, invitation_expires_at work
- Modifying state_core-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/account_service.rs` | binding, encode, decode, new, authentication (+119) |
| `crates/agenc-ircd-domain/src/decision.rs` | new, insert, user, message, collect (+106) |
| `crates/agenc-ircd-runtime/src/state_core/mod.rs` | sessions_mut, timers_mut, submit_storage_read, now, utc_now (+105) |
| `crates/agenc-ircd-runtime/src/state_core/reconstruct.rs` | finish, reconstruct, session_id_from_key, admit, admit_channel_tombstone (+98) |
| `crates/agenc-ircd-runtime/src/state_core/durable.rs` | account_key, put, delete, revalidate, account_service_table (+60) |
| `crates/agenc-ircd-runtime/src/registration.rs` | edge_sasl_line, stage_authenticated_session, commit_session, reject_pending_registration, connection_opened (+17) |
| `crates/agenc-ircd-runtime/src/state_core/session.rs` | unbind_session, connection, new, with_ceiling, open (+15) |
| `crates/agenc-ircd-runtime/src/state_core/timers.rs` | schedule, cancel, wall_trusted, pop_due, next_deadline (+12) |
| `crates/agenc-ircd-runtime/src/state_core/pending.rs` | silent, with_account_service_writes, start, try_stage, staged (+8) |
| `crates/agenc-ircd-runtime/src/state_core/fanout.rs` | new, reserve_inner, measure_all, reserve_queues, demand_for (+7) |

## Entry Points

Start here when exploring this area:

- **`response_intent`** (Function) — `crates/agenc-ircd-auth/src/service.rs:201`
- **`invitation_id`** (Function) — `crates/agenc-ircd-auth/src/service.rs:486`
- **`invitation_expires_at`** (Function) — `crates/agenc-ircd-auth/src/service.rs:495`
- **`as_bytes`** (Function) — `crates/agenc-ircd-auth/src/wire.rs:252`
- **`as_bytes`** (Function) — `crates/agenc-ircd-crypto/src/hash.rs:23`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `response_intent` | Function | `crates/agenc-ircd-auth/src/service.rs` | 201 |
| `invitation_id` | Function | `crates/agenc-ircd-auth/src/service.rs` | 486 |
| `invitation_expires_at` | Function | `crates/agenc-ircd-auth/src/service.rs` | 495 |
| `as_bytes` | Function | `crates/agenc-ircd-auth/src/wire.rs` | 252 |
| `as_bytes` | Function | `crates/agenc-ircd-crypto/src/hash.rs` | 23 |
| `new` | Function | `crates/agenc-ircd-domain/src/e2ee/route_table.rs` | 32 |
| `account` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1685 |
| `connection_opened` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1022 |
| `timer_fired` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1236 |
| `startup` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1583 |
| `registration_grant_write` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1648 |
| `begin_registration_grant_consumption` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1672 |
| `registration_rejected` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1790 |
| `begin_account_deletion` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1818 |
| `route_sasl` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1978 |
| `crypto_completed` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 2357 |
| `storage_read_completed` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 3255 |
| `batch_rejected` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 5834 |
| `account_created_note` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 6512 |
| `render_sasl_actions` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 6646 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Preview → Try_from` | cross_community | 7 |
| `Preview → Validate_bounds` | cross_community | 7 |
| `Preview → Validate_version_field` | cross_community | 7 |
| `Preview → Validate_padding_field` | cross_community | 7 |
| `Preview → Schema_by_name` | cross_community | 6 |
| `Batch_applied → Into_parts` | cross_community | 5 |
| `Batch_applied → Link_is_live` | cross_community | 5 |
| `Batch_applied → Link_closed` | cross_community | 5 |
| `Batch_applied → Timers_mut` | cross_community | 5 |
| `Batch_applied → Cancel` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 105 calls |
| Coordinator | 69 calls |
| Admission | 30 calls |
| Cluster_50 | 8 calls |
| Bridge | 8 calls |
| Connection | 8 calls |
| Cluster_822 | 8 calls |
| Cluster_733 | 8 calls |

## How to Explore

1. `context({name: "response_intent"})` — see callers and callees
2. `query({search_query: "state_core"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
