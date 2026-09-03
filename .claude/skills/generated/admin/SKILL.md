---
name: admin
description: "Skill for the Admin area of agenc-ircd. 123 symbols across 9 files."
---

# Admin

123 symbols | 9 files | Cohesion: 79%

## When to Use

- Working with code in `crates/`
- Understanding how verb, render_stats_unavailable, render_stats_storage_unavailable work
- Modifying admin-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/admin/audit.rs` | prepare_event, commit_event, observe, finish_with_observed, new (+59) |
| `crates/agenc-ircd-runtime/src/admin.rs` | opened, line, send, command, audit_export (+36) |
| `crates/agenc-ircd-runtime/src/daemon.rs` | build_live_state, persist_admin_policy_backfills, start, test_observer, clean_maintenance_completion_preserves_indeterminate_state_observation |
| `crates/agenc-ircd-admin/src/audit.rs` | verify, genesis, advance, check_event_order |
| `crates/agenc-ircd-runtime/src/state_core/admin.rs` | commit_audit, target_revision, kill |
| `crates/agenc-ircd-admin/src/command.rs` | verb, contains |
| `crates/agenc-ircd-admin/src/stats.rs` | render_stats_unavailable, render_stats_storage_unavailable |
| `crates/agenc-ircd-crypto/src/storage_integrity.rs` | audit_signing_key_id |
| `crates/agenc-ircd-domain/src/model.rs` | set_operational_limits |

## Entry Points

Start here when exploring this area:

- **`verb`** (Function) — `crates/agenc-ircd-admin/src/command.rs:244`
- **`render_stats_unavailable`** (Function) — `crates/agenc-ircd-admin/src/stats.rs:246`
- **`render_stats_storage_unavailable`** (Function) — `crates/agenc-ircd-admin/src/stats.rs:255`
- **`prepare_event`** (Function) — `crates/agenc-ircd-runtime/src/admin/audit.rs:367`
- **`commit_event`** (Function) — `crates/agenc-ircd-runtime/src/admin/audit.rs:401`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `verb` | Function | `crates/agenc-ircd-admin/src/command.rs` | 244 |
| `render_stats_unavailable` | Function | `crates/agenc-ircd-admin/src/stats.rs` | 246 |
| `render_stats_storage_unavailable` | Function | `crates/agenc-ircd-admin/src/stats.rs` | 255 |
| `prepare_event` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 367 |
| `commit_event` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 401 |
| `commit_audit` | Function | `crates/agenc-ircd-runtime/src/state_core/admin.rs` | 159 |
| `target_revision` | Function | `crates/agenc-ircd-runtime/src/state_core/admin.rs` | 200 |
| `verify` | Function | `crates/agenc-ircd-admin/src/audit.rs` | 238 |
| `genesis` | Function | `crates/agenc-ircd-admin/src/audit.rs` | 456 |
| `advance` | Function | `crates/agenc-ircd-admin/src/audit.rs` | 473 |
| `audit_signing_key_id` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 367 |
| `finish_with_observed` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 497 |
| `reconstruct` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 136 |
| `set_operational_limits` | Function | `crates/agenc-ircd-domain/src/model.rs` | 1609 |
| `into_parts` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 95 |
| `policy_seed` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 281 |
| `contains` | Function | `crates/agenc-ircd-admin/src/command.rs` | 91 |
| `take_pending_startup_action` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 208 |
| `prepare_startup_outcome` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 217 |
| `resolve_committed_startup_action` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 262 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Audit_mutations_rebuild_policy_and_reject_invalid_phase_pairings → As_bytes` | cross_community | 7 |
| `Federation_commands_record_intent_and_outcome → Result_class_rank` | cross_community | 6 |
| `Federation_commands_record_intent_and_outcome → Classify_admin_output` | cross_community | 6 |
| `Federation_commands_record_intent_and_outcome → Verb` | cross_community | 5 |
| `Audit_mutations_rebuild_policy_and_reject_invalid_phase_pairings → TrustedAuditKey` | intra_community | 4 |
| `Audit_mutations_rebuild_policy_and_reject_invalid_phase_pairings → Genesis` | intra_community | 4 |
| `Reconstruct → From_bytes` | cross_community | 3 |
| `Reconstruct → Tbs` | cross_community | 3 |
| `Reconstruct → Canonical_command` | cross_community | 3 |
| `Federation_commands_record_intent_and_outcome → Send` | cross_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| State_core | 18 calls |
| Tests | 14 calls |
| Cluster_201 | 4 calls |
| Cluster_459 | 3 calls |
| Cluster_420 | 3 calls |
| Cluster_4 | 2 calls |
| Coordinator | 2 calls |
| Federation | 2 calls |

## How to Explore

1. `context({name: "verb"})` — see callers and callees
2. `query({search_query: "admin"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
