---
name: cluster-83
description: "Skill for the Cluster_83 area of agenc-ircd. 45 symbols across 2 files."
---

# Cluster_83

45 symbols | 2 files | Cohesion: 94%

## When to Use

- Working with code in `crates/`
- Understanding how blocks_registration, new, apply_capability_profile work
- Modifying cluster_83-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-client-wire/src/registration.rs` | new, drop, from, take_all, clear (+39) |
| `crates/agenc-ircd-client-wire/src/capability.rs` | blocks_registration |

## Entry Points

Start here when exploring this area:

- **`blocks_registration`** (Function) — `crates/agenc-ircd-client-wire/src/capability.rs:333`
- **`new`** (Function) — `crates/agenc-ircd-client-wire/src/registration.rs:46`
- **`apply_capability_profile`** (Function) — `crates/agenc-ircd-client-wire/src/registration.rs:601`
- **`event`** (Function) — `crates/agenc-ircd-client-wire/src/registration.rs:684`
- **`tick`** (Function) — `crates/agenc-ircd-client-wire/src/registration.rs:838`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `blocks_registration` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 333 |
| `new` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 46 |
| `apply_capability_profile` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 601 |
| `event` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 684 |
| `tick` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 838 |
| `drop` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 63 |
| `from` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 386 |
| `take_all` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 495 |
| `clear` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 500 |
| `defer_input` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 665 |
| `nickname_reserved` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 729 |
| `access_token_checked` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 759 |
| `registration_committed` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 783 |
| `auth_carrier_finished` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 815 |
| `negotiating_message` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 874 |
| `registered_message` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 906 |
| `expire_before_input` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 943 |
| `auth_message` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 968 |
| `cap_message` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 1007 |
| `cap_ls_message` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 1024 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 5 calls |
| Cluster_96 | 2 calls |
| Fuzz_targets | 1 calls |
| State_core | 1 calls |

## How to Explore

1. `context({name: "blocks_registration"})` — see callers and callees
2. `query({search_query: "cluster_83"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
