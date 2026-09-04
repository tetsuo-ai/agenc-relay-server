---
name: federation
description: "Skill for the Federation area of agenc-ircd. 344 symbols across 36 files."
---

# Federation

344 symbols | 36 files | Cohesion: 80%

## When to Use

- Working with code in `crates/`
- Understanding how decode_one_without_embedded, validate_schema_semantics, validate_embedded_semantics work
- Modifying federation-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-federation-wire/src/semantics.rs` | validate_schema_semantics, validate_event_schema, validate_operation_schema, validate_result_schema, validate_embedded_semantics (+107) |
| `crates/agenc-ircd-domain/src/federation/projection.rs` | remove, remove_account, empty, new, derive (+78) |
| `crates/agenc-ircd-domain/src/federation/replica.rs` | new, session, membership, account, local_members (+28) |
| `crates/agenc-ircd-runtime/src/federation/link.rs` | write_line, release_queued, on_outbound, send_ping, parse_line (+17) |
| `crates/agenc-ircd-e2ee/src/tls.rs` | new, for_maximum, remaining, finish, take (+14) |
| `crates/agenc-ircd-runtime/src/federation/owner.rs` | squit, is_suspended, wait_until_wanted, register, unregister (+7) |
| `crates/agenc-ircd-runtime/src/federation/certificate.rs` | server_id_from_certificate, tbs_extensions, subject_alt_name_value, parse_single_uri, read_tlv (+3) |
| `crates/agenc-ircd-domain/src/federation/record.rs` | session, channel_detail, membership, invite, key (+1) |
| `crates/agenc-ircd-e2ee/src/federation/frames.rs` | is_companion_command, id, parameters, resume_parameters, origin_parameters (+1) |
| `crates/agenc-ircd-e2ee/src/object.rs` | new, peek, encode_into, decode_from |

## Entry Points

Start here when exploring this area:

- **`decode_one_without_embedded`** (Function) — `crates/agenc-ircd-federation-wire/src/codec.rs:1180`
- **`validate_schema_semantics`** (Function) — `crates/agenc-ircd-federation-wire/src/semantics.rs:41`
- **`validate_embedded_semantics`** (Function) — `crates/agenc-ircd-federation-wire/src/semantics.rs:185`
- **`try_from_bytes`** (Function) — `crates/agenc-ircd-types/src/bounded.rs:95`
- **`parse`** (Function) — `crates/agenc-ircd-types/src/identifiers.rs:253`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `decode_one_without_embedded` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 1180 |
| `validate_schema_semantics` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 41 |
| `validate_embedded_semantics` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 185 |
| `try_from_bytes` | Function | `crates/agenc-ircd-types/src/bounded.rs` | 95 |
| `parse` | Function | `crates/agenc-ircd-types/src/identifiers.rs` | 253 |
| `parse_wire_bytes` | Function | `crates/agenc-ircd-types/src/identifiers.rs` | 305 |
| `new` | Function | `crates/agenc-ircd-domain/src/federation/projection.rs` | 285 |
| `derive` | Function | `crates/agenc-ircd-domain/src/federation/projection.rs` | 343 |
| `encode` | Function | `crates/agenc-ircd-e2ee/src/federation/keyset_file.rs` | 34 |
| `decode` | Function | `crates/agenc-ircd-e2ee/src/federation/keyset_file.rs` | 49 |
| `new` | Function | `crates/agenc-ircd-e2ee/src/object.rs` | 226 |
| `peek` | Function | `crates/agenc-ircd-e2ee/src/object.rs` | 266 |
| `new` | Function | `crates/agenc-ircd-e2ee/src/tls.rs` | 27 |
| `for_maximum` | Function | `crates/agenc-ircd-e2ee/src/tls.rs` | 89 |
| `remaining` | Function | `crates/agenc-ircd-e2ee/src/tls.rs` | 121 |
| `finish` | Function | `crates/agenc-ircd-e2ee/src/tls.rs` | 126 |
| `u8` | Function | `crates/agenc-ircd-e2ee/src/tls.rs` | 148 |
| `u16` | Function | `crates/agenc-ircd-e2ee/src/tls.rs` | 154 |
| `u32` | Function | `crates/agenc-ircd-e2ee/src/tls.rs` | 160 |
| `u64` | Function | `crates/agenc-ircd-e2ee/src/tls.rs` | 166 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Origin_state → Take` | cross_community | 6 |
| `Origin_state → Remaining` | cross_community | 5 |
| `Origin_state → Len` | cross_community | 5 |
| `Binding_package → Len` | cross_community | 5 |
| `Batch_applied → Session` | cross_community | 5 |
| `Batch_applied → Channel_detail` | cross_community | 5 |
| `Batch_applied → Membership` | cross_community | 5 |
| `Batch_applied → Kind` | cross_community | 4 |
| `Batch_applied → Kind` | cross_community | 4 |
| `Batch_applied → New` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 35 calls |
| Coordinator | 14 calls |
| State_core | 3 calls |
| Codec | 3 calls |
| Supervisor | 2 calls |
| Cluster_427 | 2 calls |
| Edge | 2 calls |
| Cluster_970 | 2 calls |

## How to Explore

1. `context({name: "decode_one_without_embedded"})` — see callers and callees
2. `query({search_query: "federation"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
