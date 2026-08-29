---
name: cluster-122
description: "Skill for the Cluster_122 area of agenc-ircd. 21 symbols across 2 files."
---

# Cluster_122

21 symbols | 2 files | Cohesion: 96%

## When to Use

- Working with code in `crates/`
- Understanding how new, reserved_memory_bytes, start work
- Modifying cluster_122-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-crypto/src/worker.rs` | try_submit, new, reserved_memory_bytes, physical_queue_capacity, release (+15) |
| `crates/agenc-ircd-domain/src/decision.rs` | channel |

## Entry Points

Start here when exploring this area:

- **`new`** (Function) — `crates/agenc-ircd-crypto/src/worker.rs:74`
- **`reserved_memory_bytes`** (Function) — `crates/agenc-ircd-crypto/src/worker.rs:102`
- **`start`** (Function) — `crates/agenc-ircd-crypto/src/worker.rs:179`
- **`channel`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:483`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `new` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 74 |
| `reserved_memory_bytes` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 102 |
| `start` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 179 |
| `channel` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 483 |
| `try_submit` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 41 |
| `physical_queue_capacity` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 112 |
| `release` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 148 |
| `worker_loop` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 302 |
| `execute_crypto_job` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 334 |
| `drop` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 360 |
| `admission_counters` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 480 |
| `admission_release_rejects_underflow_without_wrapping` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 493 |
| `work_item` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 502 |
| `returns_completion_through_a_bounded_channel` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 521 |
| `class_limit_counts_active_and_queued_work` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 532 |
| `cancellation_before_start_preserves_the_running_job` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 560 |
| `a_panicking_worker_poisons_later_admission` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 591 |
| `submission_reports_shutdown_full_and_disconnected_queues` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 607 |
| `worker_loop_reports_poison_shutdown_and_concurrent_failure` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 671 |
| `empty_and_disconnected_completion_handles_fail_closed` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 745 |

## How to Explore

1. `context({name: "new"})` — see callers and callees
2. `query({search_query: "cluster_122"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
