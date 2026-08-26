---
name: cluster-6
description: "Skill for the Cluster_6 area of agenc-ircd. 52 symbols across 3 files."
---

# Cluster_6

52 symbols | 3 files | Cohesion: 95%

## When to Use

- Working with code in `crates/`
- Understanding how blocks_registration, take_single_parameter, new work
- Modifying cluster_6-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-client-wire/src/registration.rs` | new, drop, from, admit, is_empty (+45) |
| `crates/agenc-ircd-client-wire/src/capability.rs` | blocks_registration |
| `crates/agenc-ircd-client-wire/src/message.rs` | take_single_parameter |

## Entry Points

Start here when exploring this area:

- **`blocks_registration`** (Function) — `crates/agenc-ircd-client-wire/src/capability.rs:331`
- **`take_single_parameter`** (Function) — `crates/agenc-ircd-client-wire/src/message.rs:67`
- **`new`** (Function) — `crates/agenc-ircd-client-wire/src/registration.rs:39`
- **`admit`** (Function) — `crates/agenc-ircd-client-wire/src/registration.rs:438`
- **`is_empty`** (Function) — `crates/agenc-ircd-client-wire/src/registration.rs:458`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `blocks_registration` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 331 |
| `take_single_parameter` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 67 |
| `new` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 39 |
| `admit` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 438 |
| `is_empty` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 458 |
| `apply_capability_profile` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 580 |
| `event` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 663 |
| `tick` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 817 |
| `drop` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 62 |
| `from` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 380 |
| `checked_total` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 468 |
| `push_admitted` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 484 |
| `take_all` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 489 |
| `clear` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 494 |
| `defer_input` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 644 |
| `nickname_reserved` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 708 |
| `access_token_checked` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 738 |
| `registration_committed` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 762 |
| `auth_carrier_finished` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 794 |
| `negotiating_message` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 853 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Tick → At` | cross_community | 6 |
| `Drive → Ignore_event_after_close` | cross_community | 6 |
| `Drive → Owns_nickname_generation` | cross_community | 6 |
| `Registration_committed → At` | cross_community | 6 |
| `Pass_message → At` | cross_community | 6 |
| `User_message → At` | cross_community | 6 |
| `Event → At` | cross_community | 6 |
| `Defer_input → At` | cross_community | 6 |
| `Nickname_reserved → At` | cross_community | 6 |
| `Apply_capability_profile → At` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 3 calls |
| Cluster_2 | 2 calls |
| Fuzz_targets | 2 calls |
| Cluster_9 | 1 calls |

## How to Explore

1. `context({name: "blocks_registration"})` — see callers and callees
2. `query({search_query: "cluster_6"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
