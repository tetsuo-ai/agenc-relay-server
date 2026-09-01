---
name: admin
description: "Skill for the Admin area of agenc-ircd. 94 symbols across 12 files."
---

# Admin

94 symbols | 12 files | Cohesion: 84%

## When to Use

- Working with code in `crates/`
- Understanding how verb, render_stats_unavailable, render_stats_storage_unavailable work
- Modifying admin-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/admin/audit.rs` | prepare_export, prepare_event, commit_event, reconstruct, freeze (+32) |
| `crates/agenc-ircd-runtime/src/admin.rs` | command, audit_export, issue_confirmation, kill, mutate_account (+31) |
| `crates/agenc-ircd-admin/src/command.rs` | verb, parse, every_registered_command_parses_with_its_permission_and_rules, suspension_and_range_boundaries_are_exact |
| `crates/agenc-ircd-admin/src/canonical.rs` | check, check_parameter_forms, check_trailing, canonical_form_rejects_every_noncanonical_shape |
| `crates/agenc-ircd-runtime/src/state_core/admin.rs` | commit_audit, target_revision, matches_event |
| `crates/agenc-ircd-admin/src/stats.rs` | render_stats_unavailable, render_stats_storage_unavailable |
| `crates/agenc-ircd-admin/src/audit.rs` | genesis, advance |
| `crates/agenc-ircd-runtime/src/daemon.rs` | build_live_state, registered_commands |
| `crates/agenc-ircd-admin/src/operator.rs` | verification_key |
| `crates/agenc-ircd-crypto/src/storage_integrity.rs` | audit_signing_key_id |

## Entry Points

Start here when exploring this area:

- **`verb`** (Function) — `crates/agenc-ircd-admin/src/command.rs:244`
- **`render_stats_unavailable`** (Function) — `crates/agenc-ircd-admin/src/stats.rs:246`
- **`render_stats_storage_unavailable`** (Function) — `crates/agenc-ircd-admin/src/stats.rs:255`
- **`prepare_export`** (Function) — `crates/agenc-ircd-runtime/src/admin/audit.rs:156`
- **`prepare_event`** (Function) — `crates/agenc-ircd-runtime/src/admin/audit.rs:230`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `verb` | Function | `crates/agenc-ircd-admin/src/command.rs` | 244 |
| `render_stats_unavailable` | Function | `crates/agenc-ircd-admin/src/stats.rs` | 246 |
| `render_stats_storage_unavailable` | Function | `crates/agenc-ircd-admin/src/stats.rs` | 255 |
| `prepare_export` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 156 |
| `prepare_event` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 230 |
| `commit_event` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 264 |
| `commit_audit` | Function | `crates/agenc-ircd-runtime/src/state_core/admin.rs` | 154 |
| `target_revision` | Function | `crates/agenc-ircd-runtime/src/state_core/admin.rs` | 195 |
| `genesis` | Function | `crates/agenc-ircd-admin/src/audit.rs` | 456 |
| `advance` | Function | `crates/agenc-ircd-admin/src/audit.rs` | 473 |
| `verification_key` | Function | `crates/agenc-ircd-admin/src/operator.rs` | 155 |
| `audit_signing_key_id` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 346 |
| `reconstruct` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 86 |
| `check` | Function | `crates/agenc-ircd-admin/src/canonical.rs` | 44 |
| `matches_event` | Function | `crates/agenc-ircd-runtime/src/state_core/admin.rs` | 46 |
| `is_reconciled` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 142 |
| `into_parts` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 45 |
| `policy_seed` | Function | `crates/agenc-ircd-runtime/src/admin/audit.rs` | 152 |
| `port` | Function | `crates/agenc-ircd-storage/src/owner.rs` | 178 |
| `command` | Function | `crates/agenc-ircd-runtime/src/admin.rs` | 871 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Reconstruct → As_bytes` | cross_community | 7 |
| `Reconstruct → Try_from` | cross_community | 7 |
| `Audit_mutations_rebuild_policy_and_reject_invalid_phase_pairings → As_bytes` | cross_community | 7 |
| `Audit_mutations_rebuild_policy_and_reject_invalid_phase_pairings → Try_from` | cross_community | 7 |
| `Verifies_gapless_events_and_rejects_unmatched_intents → As_bytes` | cross_community | 7 |
| `Verifies_gapless_events_and_rejects_unmatched_intents → Try_from` | cross_community | 7 |
| `Retention_selection_and_export_coverage_are_total_and_gapless → As_bytes` | cross_community | 7 |
| `Retention_selection_and_export_coverage_are_total_and_gapless → Try_from` | cross_community | 7 |
| `Audit_retention_deletes_prefix_and_puts_checkpoint_in_one_batch → As_bytes` | cross_community | 7 |
| `Audit_retention_deletes_prefix_and_puts_checkpoint_in_one_batch → Try_from` | cross_community | 7 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 11 calls |
| State_core | 8 calls |
| Listener | 5 calls |
| Cluster_178 | 4 calls |
| Cluster_330 | 3 calls |
| Cluster_7 | 2 calls |
| Cluster_12 | 1 calls |
| Cluster_289 | 1 calls |

## How to Explore

1. `context({name: "verb"})` — see callers and callees
2. `query({search_query: "admin"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
