---
name: cluster-129
description: "Skill for the Cluster_129 area of agenc-ircd. 63 symbols across 14 files."
---

# Cluster_129

63 symbols | 14 files | Cohesion: 90%

## When to Use

- Working with code in `crates/`
- Understanding how parse, check_keys, table_array work
- Modifying cluster_129-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-config/src/listeners.rs` | uses_tcp, parse, parse, parse_endpoint, parse_raw (+5) |
| `crates/agenc-ircd-config/src/document.rs` | check_keys, table_array, string, optional_string, unsigned (+4) |
| `crates/agenc-ircd-config/src/accounts.rs` | parse, parse_flags, parse_registration, parse_direct_messages, parse_paths (+1) |
| `crates/agenc-ircd-config/src/federation.rs` | parse, optional_path, parse_peers, parse_peer, parse_endpoints |
| `crates/agenc-ircd-config/src/moderation.rs` | parse, parse_operators, parse_operator, parse_label, parse_permissions |
| `crates/agenc-ircd-config/src/network.rs` | parse, parse, parse_network_id, parse_role, parse_onion |
| `crates/agenc-ircd-config/src/e2ee.rs` | parse, parse_coordinator, parse_credentials, parse_ceilings |
| `crates/agenc-ircd-config/src/scalar.rs` | resolve, fixed, ascii_identifier, closed_enum |
| `crates/agenc-ircd-config/src/server.rs` | total_seconds, parse, bounded, parse_shutdown |
| `crates/agenc-ircd-config/src/storage.rs` | parse, u8_value, parse_paths, bounded |

## Entry Points

Start here when exploring this area:

- **`parse`** (Function) — `crates/agenc-ircd-config/src/accounts.rs:123`
- **`check_keys`** (Function) — `crates/agenc-ircd-config/src/document.rs:19`
- **`table_array`** (Function) — `crates/agenc-ircd-config/src/document.rs:45`
- **`string`** (Function) — `crates/agenc-ircd-config/src/document.rs:71`
- **`optional_string`** (Function) — `crates/agenc-ircd-config/src/document.rs:76`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `parse` | Function | `crates/agenc-ircd-config/src/accounts.rs` | 123 |
| `check_keys` | Function | `crates/agenc-ircd-config/src/document.rs` | 19 |
| `table_array` | Function | `crates/agenc-ircd-config/src/document.rs` | 45 |
| `string` | Function | `crates/agenc-ircd-config/src/document.rs` | 71 |
| `optional_string` | Function | `crates/agenc-ircd-config/src/document.rs` | 76 |
| `unsigned` | Function | `crates/agenc-ircd-config/src/document.rs` | 89 |
| `optional_unsigned` | Function | `crates/agenc-ircd-config/src/document.rs` | 94 |
| `boolean` | Function | `crates/agenc-ircd-config/src/document.rs` | 105 |
| `optional_boolean` | Function | `crates/agenc-ircd-config/src/document.rs` | 110 |
| `string_array` | Function | `crates/agenc-ircd-config/src/document.rs` | 119 |
| `parse` | Function | `crates/agenc-ircd-config/src/e2ee.rs` | 66 |
| `parse` | Function | `crates/agenc-ircd-config/src/federation.rs` | 85 |
| `optional_path` | Function | `crates/agenc-ircd-config/src/federation.rs` | 136 |
| `uses_tcp` | Function | `crates/agenc-ircd-config/src/listeners.rs` | 91 |
| `parse` | Function | `crates/agenc-ircd-config/src/listeners.rs` | 115 |
| `parse` | Function | `crates/agenc-ircd-config/src/listeners.rs` | 188 |
| `parse` | Function | `crates/agenc-ircd-config/src/moderation.rs` | 82 |
| `parse` | Function | `crates/agenc-ircd-config/src/network.rs` | 50 |
| `parse` | Function | `crates/agenc-ircd-config/src/network.rs` | 109 |
| `resolve` | Function | `crates/agenc-ircd-config/src/paths.rs` | 41 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_130 | 7 calls |
| Tests | 3 calls |
| Cluster_148 | 3 calls |
| Cluster_140 | 2 calls |
| Cluster_139 | 1 calls |

## How to Explore

1. `context({name: "parse"})` — see callers and callees
2. `query({search_query: "cluster_129"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
