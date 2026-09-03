---
name: cluster-81
description: "Skill for the Cluster_81 area of agenc-ircd. 53 symbols across 3 files."
---

# Cluster_81

53 symbols | 3 files | Cohesion: 96%

## When to Use

- Working with code in `crates/`
- Understanding how blocks_registration, supports_multiline, take_single_parameter work
- Modifying cluster_81-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-client-wire/src/registration.rs` | new, drop, from, admit, is_empty (+45) |
| `crates/agenc-ircd-client-wire/src/capability.rs` | blocks_registration, supports_multiline |
| `crates/agenc-ircd-client-wire/src/message.rs` | take_single_parameter |

## Entry Points

Start here when exploring this area:

- **`blocks_registration`** (Function) — `crates/agenc-ircd-client-wire/src/capability.rs:333`
- **`supports_multiline`** (Function) — `crates/agenc-ircd-client-wire/src/capability.rs:351`
- **`take_single_parameter`** (Function) — `crates/agenc-ircd-client-wire/src/message.rs:81`
- **`new`** (Function) — `crates/agenc-ircd-client-wire/src/registration.rs:46`
- **`admit`** (Function) — `crates/agenc-ircd-client-wire/src/registration.rs:444`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `blocks_registration` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 333 |
| `supports_multiline` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 351 |
| `take_single_parameter` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 81 |
| `new` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 46 |
| `admit` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 444 |
| `is_empty` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 464 |
| `apply_capability_profile` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 601 |
| `event` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 684 |
| `tick` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 838 |
| `drop` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 63 |
| `from` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 386 |
| `checked_total` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 474 |
| `push_admitted` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 490 |
| `take_all` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 495 |
| `clear` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 500 |
| `defer_input` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 665 |
| `nickname_reserved` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 729 |
| `access_token_checked` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 759 |
| `registration_committed` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 783 |
| `auth_carrier_finished` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 815 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Tick → Owns_nickname_generation` | intra_community | 4 |
| `Tick → Push_nickname_cleanup_actions` | intra_community | 4 |
| `Tick → Clear` | intra_community | 4 |
| `Tick → New` | intra_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 4 calls |
| Fuzz_targets | 2 calls |
| Coordinator | 1 calls |

## How to Explore

1. `context({name: "blocks_registration"})` — see callers and callees
2. `query({search_query: "cluster_81"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
