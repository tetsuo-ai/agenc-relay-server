---
name: observe
description: "Skill for the Observe area of agenc-ircd. 64 symbols across 6 files."
---

# Observe

64 symbols | 6 files | Cohesion: 77%

## When to Use

- Working with code in `crates/`
- Understanding how is_public, new, iter work
- Modifying observe-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/observe/log.rs` | new, event, retention_validates_and_the_filter_never_admits_public_debug, dropped_events_are_counted_and_reported_once_as_a_closed_event, target_failures_are_counted_and_never_block (+18) |
| `crates/agenc-ircd-runtime/src/observe/health.rs` | ready, snapshot, record_supervisor, record_state_core, is_live (+10) |
| `crates/agenc-ircd-runtime/src/observe/metrics.rs` | is_public, new, iter, increment, observe_duration (+8) |
| `crates/agenc-ircd-runtime/src/observe/events.rs` | with_purpose, with_error, new, from_os_entropy, next (+6) |
| `crates/agenc-ircd-config/src/accounts.rs` | parse_flags |
| `crates/agenc-ircd-crypto/tests/stage_four.rs` | dropping_a_pending_completion_future_requests_prestart_cancellation |

## Entry Points

Start here when exploring this area:

- **`is_public`** (Function) — `crates/agenc-ircd-runtime/src/observe/metrics.rs:128`
- **`new`** (Function) — `crates/agenc-ircd-runtime/src/observe/metrics.rs:171`
- **`iter`** (Function) — `crates/agenc-ircd-runtime/src/observe/metrics.rs:189`
- **`increment`** (Function) — `crates/agenc-ircd-runtime/src/observe/metrics.rs:306`
- **`observe_duration`** (Function) — `crates/agenc-ircd-runtime/src/observe/metrics.rs:317`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `is_public` | Function | `crates/agenc-ircd-runtime/src/observe/metrics.rs` | 128 |
| `new` | Function | `crates/agenc-ircd-runtime/src/observe/metrics.rs` | 171 |
| `iter` | Function | `crates/agenc-ircd-runtime/src/observe/metrics.rs` | 189 |
| `increment` | Function | `crates/agenc-ircd-runtime/src/observe/metrics.rs` | 306 |
| `observe_duration` | Function | `crates/agenc-ircd-runtime/src/observe/metrics.rs` | 317 |
| `observe_count` | Function | `crates/agenc-ircd-runtime/src/observe/metrics.rs` | 327 |
| `snapshot` | Function | `crates/agenc-ircd-runtime/src/observe/metrics.rs` | 338 |
| `ready` | Function | `crates/agenc-ircd-runtime/src/observe/health.rs` | 69 |
| `snapshot` | Function | `crates/agenc-ircd-runtime/src/observe/health.rs` | 75 |
| `record_supervisor` | Function | `crates/agenc-ircd-runtime/src/observe/health.rs` | 138 |
| `record_state_core` | Function | `crates/agenc-ircd-runtime/src/observe/health.rs` | 144 |
| `is_live` | Function | `crates/agenc-ircd-runtime/src/observe/health.rs` | 151 |
| `live` | Function | `crates/agenc-ircd-runtime/src/observe/health.rs` | 189 |
| `capture` | Function | `crates/agenc-ircd-runtime/src/observe/health.rs` | 206 |
| `with_purpose` | Function | `crates/agenc-ircd-runtime/src/observe/events.rs` | 404 |
| `with_error` | Function | `crates/agenc-ircd-runtime/src/observe/events.rs` | 411 |
| `new` | Function | `crates/agenc-ircd-runtime/src/observe/log.rs` | 69 |
| `new` | Function | `crates/agenc-ircd-runtime/src/observe/health.rs` | 47 |
| `mark` | Function | `crates/agenc-ircd-runtime/src/observe/health.rs` | 57 |
| `clear` | Function | `crates/agenc-ircd-runtime/src/observe/health.rs` | 63 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Connection | 5 calls |
| Tests | 3 calls |
| Cluster_133 | 1 calls |
| Cluster_191 | 1 calls |
| Examples | 1 calls |

## How to Explore

1. `context({name: "is_public"})` — see callers and callees
2. `query({search_query: "observe"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
