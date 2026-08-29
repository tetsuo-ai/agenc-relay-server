---
name: cluster-181
description: "Skill for the Cluster_181 area of agenc-ircd. 22 symbols across 2 files."
---

# Cluster_181

22 symbols | 2 files | Cohesion: 93%

## When to Use

- Working with code in `crates/`
- Understanding how new, start, shutdown work
- Modifying cluster_181-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-crypto/src/worker.rs` | try_submit, new, physical_queue_capacity, release, start (+16) |
| `crates/agenc-ircd-domain/src/decision.rs` | channel |

## Entry Points

Start here when exploring this area:

- **`new`** (Function) — `crates/agenc-ircd-crypto/src/worker.rs:74`
- **`start`** (Function) — `crates/agenc-ircd-crypto/src/worker.rs:179`
- **`shutdown`** (Function) — `crates/agenc-ircd-crypto/src/worker.rs:237`
- **`channel`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:486`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `new` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 74 |
| `start` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 179 |
| `shutdown` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 237 |
| `channel` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 486 |
| `try_submit` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 41 |
| `physical_queue_capacity` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 112 |
| `release` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 148 |
| `join_workers` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 241 |
| `worker_loop` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 321 |
| `execute_crypto_job` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 353 |
| `drop` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 380 |
| `admission_counters` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 501 |
| `admission_release_rejects_underflow_without_wrapping` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 514 |
| `work_item` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 523 |
| `returns_completion_through_a_bounded_channel` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 542 |
| `class_limit_counts_active_and_queued_work` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 553 |
| `cancellation_before_start_preserves_the_running_job` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 581 |
| `a_panicking_worker_poisons_later_admission` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 612 |
| `submission_reports_shutdown_full_and_disconnected_queues` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 628 |
| `worker_loop_reports_poison_shutdown_and_concurrent_failure` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 692 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 2 calls |

## How to Explore

1. `context({name: "new"})` — see callers and callees
2. `query({search_query: "cluster_181"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
