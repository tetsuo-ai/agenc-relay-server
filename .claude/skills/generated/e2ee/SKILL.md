---
name: e2ee
description: "Skill for the E2ee area of agenc-ircd. 85 symbols across 16 files."
---

# E2ee

85 symbols | 16 files | Cohesion: 73%

## When to Use

- Working with code in `crates/`
- Understanding how bootstrap, check_application, add_finalized work
- Modifying e2ee-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-domain/src/e2ee/sequencer_log.rs` | genesis, next_sequence, candidate_position, record_candidate, close (+10) |
| `crates/agenc-ircd-runtime/src/e2ee/barrier.rs` | open, restore, identity, part, cursor (+6) |
| `crates/agenc-ircd-domain/src/e2ee/lifecycle.rs` | bootstrap, check_mutable, check_application, add_finalized, join_confirmed (+5) |
| `crates/agenc-ircd-runtime/src/e2ee/link.rs` | new, link_established, link_closed, ack_frame, an_enabled_node_negotiates_then_queues_admitted_frames (+5) |
| `crates/agenc-ircd-domain/src/e2ee/projection.rs` | new, sort_key, order, plan_barriers, has_payload (+4) |
| `crates/agenc-ircd-domain/src/e2ee/tests/sequencer_log.rs` | candidate, an_epoch_permits_a_bounded_number_of_attempts, close_is_the_last_record_and_restore_reproduces_the_head, reinit_attempts_activate_or_abort_and_migrate_the_log, candidates_finalize_and_abort_with_exact_positions |
| `crates/agenc-ircd-domain/src/e2ee/tests/projection.rs` | planned, plans_order_by_phase_conversation_kind_target_and_payload, barriers_cover_only_two_profile_targets_within_bounds, direct_entitlement_is_reference_counted_and_channel_entitlement_follows_base |
| `crates/agenc-ircd-domain/src/e2ee/mailbox.rs` | deliver, fetch, grant_for, expire |
| `crates/agenc-ircd-domain/src/e2ee/tests/lifecycle.rs` | bootstrap_joins_and_removals_gate_application_traffic, open_log, the_recovery_gate_only_moves_forward |
| `crates/agenc-ircd-domain/src/e2ee/tests/mailbox.rs` | tokens, items_are_fetched_with_session_bound_tokens_and_acknowledged_once, pages_are_bounded_detach_invalidates_tokens_and_expiry_frees_items |

## Entry Points

Start here when exploring this area:

- **`bootstrap`** (Function) — `crates/agenc-ircd-domain/src/e2ee/lifecycle.rs:90`
- **`check_application`** (Function) — `crates/agenc-ircd-domain/src/e2ee/lifecycle.rs:159`
- **`add_finalized`** (Function) — `crates/agenc-ircd-domain/src/e2ee/lifecycle.rs:189`
- **`join_confirmed`** (Function) — `crates/agenc-ircd-domain/src/e2ee/lifecycle.rs:212`
- **`pending_leaf_removed`** (Function) — `crates/agenc-ircd-domain/src/e2ee/lifecycle.rs:233`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `bootstrap` | Function | `crates/agenc-ircd-domain/src/e2ee/lifecycle.rs` | 90 |
| `check_application` | Function | `crates/agenc-ircd-domain/src/e2ee/lifecycle.rs` | 159 |
| `add_finalized` | Function | `crates/agenc-ircd-domain/src/e2ee/lifecycle.rs` | 189 |
| `join_confirmed` | Function | `crates/agenc-ircd-domain/src/e2ee/lifecycle.rs` | 212 |
| `pending_leaf_removed` | Function | `crates/agenc-ircd-domain/src/e2ee/lifecycle.rs` | 233 |
| `bootstrap_activated` | Function | `crates/agenc-ircd-domain/src/e2ee/lifecycle.rs` | 238 |
| `removal_requested` | Function | `crates/agenc-ircd-domain/src/e2ee/lifecycle.rs` | 251 |
| `genesis` | Function | `crates/agenc-ircd-domain/src/e2ee/sequencer_log.rs` | 155 |
| `candidate_position` | Function | `crates/agenc-ircd-domain/src/e2ee/sequencer_log.rs` | 266 |
| `record_candidate` | Function | `crates/agenc-ircd-domain/src/e2ee/sequencer_log.rs` | 290 |
| `close` | Function | `crates/agenc-ircd-domain/src/e2ee/sequencer_log.rs` | 501 |
| `new` | Function | `crates/agenc-ircd-domain/src/e2ee/projection.rs` | 611 |
| `order` | Function | `crates/agenc-ircd-domain/src/e2ee/projection.rs` | 752 |
| `plan_barriers` | Function | `crates/agenc-ircd-domain/src/e2ee/projection.rs` | 814 |
| `open` | Function | `crates/agenc-ircd-runtime/src/e2ee/barrier.rs` | 86 |
| `restore` | Function | `crates/agenc-ircd-runtime/src/e2ee/barrier.rs` | 97 |
| `deliver` | Function | `crates/agenc-ircd-domain/src/e2ee/mailbox.rs` | 151 |
| `fetch` | Function | `crates/agenc-ircd-domain/src/e2ee/mailbox.rs` | 185 |
| `expire` | Function | `crates/agenc-ircd-domain/src/e2ee/mailbox.rs` | 313 |
| `from_activation` | Function | `crates/agenc-ircd-domain/src/e2ee/sequencer_log.rs` | 161 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Batch_applied → Link_closed` | cross_community | 5 |
| `Batch_applied → Link_closed` | cross_community | 5 |
| `Inbound → CompanionLinkState` | cross_community | 5 |
| `Inbound → New` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Coordinator | 7 calls |
| Federation | 3 calls |
| Tests | 1 calls |
| Edge | 1 calls |
| Ops | 1 calls |

## How to Explore

1. `context({name: "bootstrap"})` — see callers and callees
2. `query({search_query: "e2ee"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
