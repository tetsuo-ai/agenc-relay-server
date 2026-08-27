---
name: cluster-105
description: "Skill for the Cluster_105 area of agenc-ircd. 11 symbols across 2 files."
---

# Cluster_105

11 symbols | 2 files | Cohesion: 78%

## When to Use

- Working with code in `crates/`
- Understanding how new, channel work
- Modifying cluster_105-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-crypto/src/worker.rs` | try_submit, new, drop, admission_counters, admission_release_rejects_underflow_without_wrapping (+5) |
| `crates/agenc-ircd-domain/src/decision.rs` | channel |

## Entry Points

Start here when exploring this area:

- **`new`** (Function) — `crates/agenc-ircd-crypto/src/worker.rs:74`
- **`channel`** (Function) — `crates/agenc-ircd-domain/src/decision.rs:483`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `new` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 74 |
| `channel` | Function | `crates/agenc-ircd-domain/src/decision.rs` | 483 |
| `try_submit` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 41 |
| `drop` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 360 |
| `admission_counters` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 480 |
| `admission_release_rejects_underflow_without_wrapping` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 493 |
| `work_item` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 502 |
| `submission_reports_shutdown_full_and_disconnected_queues` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 607 |
| `worker_loop_reports_poison_shutdown_and_concurrent_failure` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 671 |
| `empty_and_disconnected_completion_handles_fail_closed` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 745 |
| `unit_configuration_matrix_and_unobserved_handle_are_closed` | Function | `crates/agenc-ircd-crypto/src/worker.rs` | 768 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Begin_account_creation_with_entropy → New` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 1 calls |

## How to Explore

1. `context({name: "new"})` — see callers and callees
2. `query({search_query: "cluster_105"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
