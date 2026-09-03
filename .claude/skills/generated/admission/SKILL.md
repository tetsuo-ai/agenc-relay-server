---
name: admission
description: "Skill for the Admission area of agenc-ircd. 133 symbols across 13 files."
---

# Admission

133 symbols | 13 files | Cohesion: 66%

## When to Use

- Working with code in `crates/`
- Understanding how expose_for_persistence, from_persisted_bytes, new work
- Modifying admission-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/admission/buckets.rs` | new, default_rate, hard_rate, fixed, defaults (+50) |
| `crates/agenc-ircd-runtime/src/admission/transport.rs` | now, release_direct, erase_idle, admit_direct, admit_onion (+16) |
| `crates/agenc-ircd-runtime/src/admission/prefix.rs` | new, with_ceiling, connection_opened, connection_closed, erase_idle (+14) |
| `crates/agenc-ircd-auth/src/service.rs` | new, parse, context_for_network, inputs, decode_nibble (+8) |
| `crates/agenc-ircd-runtime/src/admission/overload.rs` | new, classify, default, usage_reaches, select_evictions (+6) |
| `crates/agenc-ircd-runtime/src/state_core/inbox.rs` | host_key, onion_listener, ipv4, prefix_key |
| `crates/agenc-ircd-domain/src/decision.rs` | process_local_arms_project_to_no_write, complete_external_inputs, external_input_validation_covers_every_shape_and_clock_combination |
| `crates/agenc-ircd-auth/src/opaque.rs` | expose_for_persistence, from_persisted_bytes |
| `crates/agenc-ircd-testkit/src/lib.rs` | now |
| `crates/agenc-ircd-types/src/quantities.rs` | from_ticks |

## Entry Points

Start here when exploring this area:

- **`expose_for_persistence`** (Function) — `crates/agenc-ircd-auth/src/opaque.rs:497`
- **`from_persisted_bytes`** (Function) — `crates/agenc-ircd-auth/src/opaque.rs:578`
- **`new`** (Function) — `crates/agenc-ircd-auth/src/service.rs:44`
- **`parse`** (Function) — `crates/agenc-ircd-auth/src/service.rs:814`
- **`now`** (Function) — `crates/agenc-ircd-testkit/src/lib.rs:103`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `expose_for_persistence` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 497 |
| `from_persisted_bytes` | Function | `crates/agenc-ircd-auth/src/opaque.rs` | 578 |
| `new` | Function | `crates/agenc-ircd-auth/src/service.rs` | 44 |
| `parse` | Function | `crates/agenc-ircd-auth/src/service.rs` | 814 |
| `now` | Function | `crates/agenc-ircd-testkit/src/lib.rs` | 103 |
| `from_ticks` | Function | `crates/agenc-ircd-types/src/quantities.rs` | 109 |
| `new` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 87 |
| `default_rate` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 443 |
| `hard_rate` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 465 |
| `defaults` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 564 |
| `with_ceiling` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 773 |
| `domain_snapshot` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 842 |
| `apply_domain_charges` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 857 |
| `domain_bucket` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 943 |
| `contains_key` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 114 |
| `get_mut` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 128 |
| `try_insert` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 137 |
| `remove` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 170 |
| `remove_transaction` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 175 |
| `full` | Function | `crates/agenc-ircd-runtime/src/admission/buckets.rs` | 654 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Run → Iter_mut` | cross_community | 5 |
| `Erase_reload_and_domain_mapping_behave_as_specified → Fixed` | cross_community | 5 |
| `Creation_transaction_record_round_trips_private_reservations → New` | cross_community | 5 |
| `Live_queries_render_lists_names_who_whois_topics_modes_and_information → Prefix_key` | cross_community | 4 |
| `Into_restart_cleanup_metadata → Transaction_id` | cross_community | 4 |
| `Into_restart_cleanup_metadata → Matches_request_kind` | cross_community | 4 |
| `Into_restart_cleanup_metadata → Message_kind` | cross_community | 4 |
| `Creation_transaction_record_round_trips_private_reservations → Transaction_id` | intra_community | 4 |
| `Creation_transaction_record_round_trips_private_reservations → Matches_request_kind` | cross_community | 4 |
| `Creation_transaction_record_round_trips_private_reservations → Message_kind` | intra_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| State_core | 11 calls |
| Tests | 11 calls |
| Cluster_58 | 5 calls |
| Cluster_46 | 5 calls |
| Bridge | 3 calls |
| Coordinator | 2 calls |
| Cluster_146 | 1 calls |
| Cluster_43 | 1 calls |

## How to Explore

1. `context({name: "expose_for_persistence"})` — see callers and callees
2. `query({search_query: "admission"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
