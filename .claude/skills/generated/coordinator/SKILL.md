---
name: coordinator
description: "Skill for the Coordinator area of agenc-ircd. 158 symbols across 29 files."
---

# Coordinator

158 symbols | 29 files | Cohesion: 65%

## When to Use

- Working with code in `crates/`
- Understanding how contains, expire, generic_reason work
- Modifying coordinator-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/federation/coordinator/mod.rs` | handle_traffic, link_is_live, link_closed, fail_link, owns_storage_read (+21) |
| `crates/agenc-ircd-runtime/src/federation/coordinator/request.rs` | run_operation, run_query, answer_page, finish_query_decision, open_session (+16) |
| `crates/agenc-ircd-runtime/src/federation/coordinator/snapshot.rs` | owns_read, resend_completed, replay_row, timer_fired, expire (+11) |
| `crates/agenc-ircd-runtime/src/federation/coordinator/convert.rs` | key_for, channel_mode_letter, channel_mode_changes, channel_name, reason (+9) |
| `crates/agenc-ircd-runtime/src/federation/coordinator/query.rs` | expire, new, first_page, next_page, binding (+7) |
| `crates/agenc-ircd-storage/src/federation_records.rs` | origin_key, parse_origin_key, outbox_key, parse_outbox_key, outbox_range (+6) |
| `crates/agenc-ircd-runtime/src/federation/coordinator/startup.rs` | admit_marker, begin, first_key, request_page, finish (+2) |
| `crates/agenc-ircd-domain/src/federation/query_cursor.rs` | contains, expire, draw, install_new, check (+1) |
| `crates/agenc-ircd-runtime/src/federation/coordinator/grace.rs` | hide_next, continue_cleanup, restored, queue_hosted_cleanup, timer_fired |
| `crates/agenc-ircd-runtime/src/state_core/mod.rs` | set_mutation_context, set_request_binding, open_storage_plaintext, take_outbound_events, federation_mut |

## Entry Points

Start here when exploring this area:

- **`contains`** (Function) — `crates/agenc-ircd-domain/src/federation/query_cursor.rs:188`
- **`expire`** (Function) — `crates/agenc-ircd-domain/src/federation/query_cursor.rs:249`
- **`generic_reason`** (Function) — `crates/agenc-ircd-domain/src/federation/record.rs:67`
- **`failure_code`** (Function) — `crates/agenc-ircd-runtime/src/federation/codec/results.rs:251`
- **`key_for`** (Function) — `crates/agenc-ircd-runtime/src/federation/coordinator/convert.rs:615`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `contains` | Function | `crates/agenc-ircd-domain/src/federation/query_cursor.rs` | 188 |
| `expire` | Function | `crates/agenc-ircd-domain/src/federation/query_cursor.rs` | 249 |
| `generic_reason` | Function | `crates/agenc-ircd-domain/src/federation/record.rs` | 67 |
| `failure_code` | Function | `crates/agenc-ircd-runtime/src/federation/codec/results.rs` | 251 |
| `key_for` | Function | `crates/agenc-ircd-runtime/src/federation/coordinator/convert.rs` | 615 |
| `expire` | Function | `crates/agenc-ircd-runtime/src/federation/coordinator/query.rs` | 86 |
| `bound_for` | Function | `crates/agenc-ircd-runtime/src/federation/coordinator/request.rs` | 564 |
| `crypto_completed` | Function | `crates/agenc-ircd-runtime/src/federation/coordinator/request.rs` | 655 |
| `row` | Function | `crates/agenc-ircd-runtime/src/federation/coordinator/request.rs` | 1011 |
| `render_mutation` | Function | `crates/agenc-ircd-runtime/src/mutation_render.rs` | 28 |
| `set_mutation_context` | Function | `crates/agenc-ircd-runtime/src/state_core/mod.rs` | 849 |
| `set_request_binding` | Function | `crates/agenc-ircd-runtime/src/state_core/mod.rs` | 856 |
| `authenticate_query_cursor` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 201 |
| `draw` | Function | `crates/agenc-ircd-domain/src/federation/query_cursor.rs` | 94 |
| `install_new` | Function | `crates/agenc-ircd-domain/src/federation/query_cursor.rs` | 166 |
| `check` | Function | `crates/agenc-ircd-domain/src/federation/query_cursor.rs` | 193 |
| `replace` | Function | `crates/agenc-ircd-domain/src/federation/query_cursor.rs` | 213 |
| `new` | Function | `crates/agenc-ircd-runtime/src/federation/coordinator/query.rs` | 75 |
| `first_page` | Function | `crates/agenc-ircd-runtime/src/federation/coordinator/query.rs` | 106 |
| `next_page` | Function | `crates/agenc-ircd-runtime/src/federation/coordinator/query.rs` | 161 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Batch_applied → Link_is_live` | cross_community | 5 |
| `Batch_applied → Len` | cross_community | 5 |
| `Batch_applied → Try_from` | cross_community | 5 |
| `Batch_applied → LinkOutbound` | cross_community | 5 |
| `Batch_applied → Release_queued` | cross_community | 5 |
| `Next_page → As_bytes` | cross_community | 5 |
| `Batch_applied → Federation_object_id` | cross_community | 4 |
| `Batch_applied → Fragment` | cross_community | 4 |
| `Batch_applied → Kind` | cross_community | 4 |
| `Batch_applied → Command` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| State_core | 47 calls |
| Tests | 33 calls |
| Federation | 7 calls |
| Codec | 4 calls |
| Bridge | 2 calls |
| Cluster_412 | 2 calls |
| Cluster_241 | 1 calls |
| Cluster_190 | 1 calls |

## How to Explore

1. `context({name: "contains"})` — see callers and callees
2. `query({search_query: "coordinator"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
