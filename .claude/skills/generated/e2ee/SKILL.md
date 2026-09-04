---
name: e2ee
description: "Skill for the E2ee area of agenc-ircd. 89 symbols across 19 files."
---

# E2ee

89 symbols | 19 files | Cohesion: 72%

## When to Use

- Working with code in `crates/`
- Understanding how genesis, candidate_position, record_candidate work
- Modifying e2ee-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-domain/src/e2ee/sequencer_log.rs` | genesis, next_sequence, candidate_position, record_candidate, close (+10) |
| `crates/agenc-ircd-runtime/src/e2ee/barrier.rs` | open, restore, identity, part, cursor (+7) |
| `crates/agenc-ircd-runtime/src/e2ee/link.rs` | new, link_established, link_closed, ack_frame, an_enabled_node_negotiates_then_queues_admitted_frames (+5) |
| `crates/agenc-ircd-domain/src/e2ee/projection.rs` | new, sort_key, order, plan_barriers, entitled (+4) |
| `crates/agenc-ircd-domain/src/e2ee/lifecycle.rs` | bootstrap, successor, restore, check_mutable, check_application (+1) |
| `crates/agenc-ircd-domain/src/e2ee/tests/sequencer_log.rs` | candidate, an_epoch_permits_a_bounded_number_of_attempts, close_is_the_last_record_and_restore_reproduces_the_head, reinit_attempts_activate_or_abort_and_migrate_the_log, candidates_finalize_and_abort_with_exact_positions |
| `crates/agenc-ircd-domain/src/e2ee/route_table.rs` | channel_route, channel_plaintext_allowed, reserve_direct, target_reserved, insert_reservation |
| `crates/agenc-ircd-domain/src/e2ee/tests/projection.rs` | planned, plans_order_by_phase_conversation_kind_target_and_payload, barriers_cover_only_two_profile_targets_within_bounds, direct_entitlement_is_reference_counted_and_channel_entitlement_follows_base |
| `crates/agenc-ircd-domain/src/e2ee/mailbox.rs` | deliver, fetch, grant_for, expire |
| `crates/agenc-ircd-domain/src/e2ee/tests/lifecycle.rs` | open_log, bootstrap_joins_and_removals_gate_application_traffic, the_recovery_gate_only_moves_forward |

## Entry Points

Start here when exploring this area:

- **`genesis`** (Function) — `crates/agenc-ircd-domain/src/e2ee/sequencer_log.rs:161`
- **`candidate_position`** (Function) — `crates/agenc-ircd-domain/src/e2ee/sequencer_log.rs:290`
- **`record_candidate`** (Function) — `crates/agenc-ircd-domain/src/e2ee/sequencer_log.rs:314`
- **`close`** (Function) — `crates/agenc-ircd-domain/src/e2ee/sequencer_log.rs:525`
- **`new`** (Function) — `crates/agenc-ircd-domain/src/e2ee/projection.rs:611`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `genesis` | Function | `crates/agenc-ircd-domain/src/e2ee/sequencer_log.rs` | 161 |
| `candidate_position` | Function | `crates/agenc-ircd-domain/src/e2ee/sequencer_log.rs` | 290 |
| `record_candidate` | Function | `crates/agenc-ircd-domain/src/e2ee/sequencer_log.rs` | 314 |
| `close` | Function | `crates/agenc-ircd-domain/src/e2ee/sequencer_log.rs` | 525 |
| `new` | Function | `crates/agenc-ircd-domain/src/e2ee/projection.rs` | 611 |
| `order` | Function | `crates/agenc-ircd-domain/src/e2ee/projection.rs` | 752 |
| `plan_barriers` | Function | `crates/agenc-ircd-domain/src/e2ee/projection.rs` | 814 |
| `open` | Function | `crates/agenc-ircd-runtime/src/e2ee/barrier.rs` | 86 |
| `restore` | Function | `crates/agenc-ircd-runtime/src/e2ee/barrier.rs` | 97 |
| `deliver` | Function | `crates/agenc-ircd-domain/src/e2ee/mailbox.rs` | 184 |
| `fetch` | Function | `crates/agenc-ircd-domain/src/e2ee/mailbox.rs` | 218 |
| `expire` | Function | `crates/agenc-ircd-domain/src/e2ee/mailbox.rs` | 346 |
| `entitled` | Function | `crates/agenc-ircd-domain/src/e2ee/projection.rs` | 617 |
| `set_channel` | Function | `crates/agenc-ircd-domain/src/e2ee/projection.rs` | 630 |
| `require_direct` | Function | `crates/agenc-ircd-domain/src/e2ee/projection.rs` | 641 |
| `bootstrap` | Function | `crates/agenc-ircd-domain/src/e2ee/lifecycle.rs` | 90 |
| `successor` | Function | `crates/agenc-ircd-domain/src/e2ee/lifecycle.rs` | 101 |
| `restore` | Function | `crates/agenc-ircd-domain/src/e2ee/lifecycle.rs` | 112 |
| `from_activation` | Function | `crates/agenc-ircd-domain/src/e2ee/sequencer_log.rs` | 167 |
| `attempt_position` | Function | `crates/agenc-ircd-domain/src/e2ee/sequencer_log.rs` | 430 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Batch_applied → Link_closed` | cross_community | 5 |
| `Inbound → CompanionLinkState` | cross_community | 5 |
| `Inbound → New` | cross_community | 5 |
| `Batch_applied → Link_closed` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Edge | 5 calls |
| Coordinator | 5 calls |
| Tests | 2 calls |
| Cluster_817 | 1 calls |
| State_core | 1 calls |
| Ops | 1 calls |

## How to Explore

1. `context({name: "genesis"})` — see callers and callees
2. `query({search_query: "e2ee"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
