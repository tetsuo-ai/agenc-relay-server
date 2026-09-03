---
name: state-core
description: "Skill for the State_core area of agenc-ircd. 756 symbols across 49 files."
---

# State_core

756 symbols | 49 files | Cohesion: 71%

## When to Use

- Working with code in `crates/`
- Understanding how response_intent, invitation_id, invitation_expires_at work
- Modifying state_core-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/account_service.rs` | closed, binding, encode, decode, new (+126) |
| `crates/agenc-ircd-runtime/src/state_core/mod.rs` | timers_mut, submit_storage_read, utc_now, pending_len, fanout_request_to (+107) |
| `crates/agenc-ircd-domain/src/decision.rs` | new, insert, user, message, collect (+106) |
| `crates/agenc-ircd-runtime/src/state_core/reconstruct.rs` | finish, reconstruct, session_id_from_key, admit, admit_channel_tombstone (+97) |
| `crates/agenc-ircd-runtime/src/state_core/durable.rs` | account_key, put, delete, revalidate, account_service_table (+61) |
| `crates/agenc-ircd-runtime/src/registration.rs` | stage_authenticated_session, commit_session, connection_opened, cancel_connection_timers, access_policy (+34) |
| `crates/agenc-ircd-runtime/src/state_core/session.rs` | unbind_session, connection, generation_for_user, new, with_ceiling (+16) |
| `crates/agenc-ircd-runtime/src/state_core/timers.rs` | schedule, cancel, wall_trusted, pop_due, next_deadline (+12) |
| `crates/agenc-ircd-runtime/src/channels.rs` | guest_key_prefix_demand, admit_command, charge_command, charge_registered_command_only, defer (+11) |
| `crates/agenc-ircd-runtime/src/state_core/pending.rs` | silent, with_account_service_writes, start, try_stage, staged (+8) |

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
| `connection_opened` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1013 |
| `connection_closed` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1062 |
| `timer_fired` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1227 |
| `startup` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1574 |
| `registration_grant_write` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1602 |
| `begin_registration_grant_consumption` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1626 |
| `registration_rejected` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1736 |
| `begin_account_deletion` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1764 |
| `route_sasl` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 1924 |
| `crypto_completed` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 2303 |
| `storage_read_completed` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 3201 |
| `batch_rejected` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 5780 |
| `submit_read` | Function | `crates/agenc-ircd-runtime/src/bridge/storage.rs` | 423 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Route_sasl → Into_parts` | intra_community | 7 |
| `Route_sasl → CreationReservation` | intra_community | 7 |
| `Route_sasl → AccountServiceConfig` | cross_community | 7 |
| `Route_sasl → Try_from` | cross_community | 7 |
| `Batch_applied → Into_parts` | cross_community | 5 |
| `Batch_applied → Link_is_live` | cross_community | 5 |
| `Batch_applied → Link_closed` | cross_community | 5 |
| `Batch_applied → Timers_mut` | cross_community | 5 |
| `Batch_applied → Cancel` | cross_community | 5 |
| `Batch_applied → Len` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 122 calls |
| Coordinator | 61 calls |
| Admission | 20 calls |
| Cluster_688 | 10 calls |
| Cluster_456 | 9 calls |
| Cluster_90 | 8 calls |
| Observe | 7 calls |
| Supervisor | 7 calls |

## How to Explore

1. `context({name: "response_intent"})` — see callers and callees
2. `query({search_query: "state_core"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
