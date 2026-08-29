---
name: cluster-14
description: "Skill for the Cluster_14 area of agenc-ircd. 22 symbols across 2 files."
---

# Cluster_14

22 symbols | 2 files | Cohesion: 92%

## When to Use

- Working with code in `crates/`
- Understanding how needs_confirmation, verb, required_permission work
- Modifying cluster_14-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-admin/src/session.rs` | new, consume_confirmation, accept_line, authenticated_line, dispatch (+14) |
| `crates/agenc-ircd-admin/src/command.rs` | needs_confirmation, verb, required_permission |

## Entry Points

Start here when exploring this area:

- **`needs_confirmation`** (Function) — `crates/agenc-ircd-admin/src/command.rs:49`
- **`verb`** (Function) — `crates/agenc-ircd-admin/src/command.rs:244`
- **`required_permission`** (Function) — `crates/agenc-ircd-admin/src/command.rs:272`
- **`new`** (Function) — `crates/agenc-ircd-admin/src/session.rs:113`
- **`consume_confirmation`** (Function) — `crates/agenc-ircd-admin/src/session.rs:151`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `needs_confirmation` | Function | `crates/agenc-ircd-admin/src/command.rs` | 49 |
| `verb` | Function | `crates/agenc-ircd-admin/src/command.rs` | 244 |
| `required_permission` | Function | `crates/agenc-ircd-admin/src/command.rs` | 272 |
| `new` | Function | `crates/agenc-ircd-admin/src/session.rs` | 113 |
| `consume_confirmation` | Function | `crates/agenc-ircd-admin/src/session.rs` | 151 |
| `accept_line` | Function | `crates/agenc-ircd-admin/src/session.rs` | 179 |
| `authenticated_line` | Function | `crates/agenc-ircd-admin/src/session.rs` | 305 |
| `dispatch` | Function | `crates/agenc-ircd-admin/src/session.rs` | 346 |
| `confirmation_state` | Function | `crates/agenc-ircd-admin/src/session.rs` | 379 |
| `check_repeat` | Function | `crates/agenc-ircd-admin/src/session.rs` | 400 |
| `binding` | Function | `crates/agenc-ircd-admin/src/session.rs` | 449 |
| `challenge` | Function | `crates/agenc-ircd-admin/src/session.rs` | 456 |
| `registry` | Function | `crates/agenc-ircd-admin/src/session.rs` | 469 |
| `peer` | Function | `crates/agenc-ircd-admin/src/session.rs` | 485 |
| `tick` | Function | `crates/agenc-ircd-admin/src/session.rs` | 492 |
| `oper_line` | Function | `crates/agenc-ircd-admin/src/session.rs` | 496 |
| `signed_line` | Function | `crates/agenc-ircd-admin/src/session.rs` | 510 |
| `authenticated` | Function | `crates/agenc-ircd-admin/src/session.rs` | 535 |
| `pre_authentication_allows_only_bounded_liveness_quit_and_one_oper` | Function | `crates/agenc-ircd-admin/src/session.rs` | 547 |
| `oper_requires_matching_record_and_valid_proof_once` | Function | `crates/agenc-ircd-admin/src/session.rs` | 608 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Two_step_confirmation_binds_token_command_permissions_and_time → Len` | cross_community | 6 |
| `Two_step_confirmation_binds_token_command_permissions_and_time → Charge_ping` | cross_community | 5 |
| `Two_step_confirmation_binds_token_command_permissions_and_time → Session_id` | intra_community | 5 |
| `Two_step_confirmation_binds_token_command_permissions_and_time → New` | intra_community | 5 |
| `Two_step_confirmation_binds_token_command_permissions_and_time → Has_duplicates` | cross_community | 5 |
| `Two_step_confirmation_binds_token_command_permissions_and_time → Is_empty` | cross_community | 5 |
| `Two_step_confirmation_binds_token_command_permissions_and_time → Len` | cross_community | 5 |
| `Two_step_confirmation_binds_token_command_permissions_and_time → Authenticated` | intra_community | 4 |
| `Two_step_confirmation_binds_token_command_permissions_and_time → AdminSessionBinding` | intra_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_20 | 2 calls |
| Cluster_418 | 1 calls |
| Cluster_11 | 1 calls |
| Supervisor | 1 calls |
| Cluster_12 | 1 calls |
| Cluster_8 | 1 calls |
| Cluster_9 | 1 calls |

## How to Explore

1. `context({name: "needs_confirmation"})` — see callers and callees
2. `query({search_query: "cluster_14"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
