---
name: federation
description: "Skill for the Federation area of agenc-ircd. 275 symbols across 34 files."
---

# Federation

275 symbols | 34 files | Cohesion: 69%

## When to Use

- Working with code in `crates/`
- Understanding how new, derive, validate_schema_semantics work
- Modifying federation-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-domain/src/federation/projection.rs` | empty, new, derive, home_of, hosts (+78) |
| `crates/agenc-ircd-federation-wire/src/semantics.rs` | validate_schema_semantics, validate_matching_structure_fields, structure_field, semantic, validate_normalized_login (+34) |
| `crates/agenc-ircd-domain/src/federation/replica.rs` | new, membership, account, local_members, apply (+27) |
| `crates/agenc-ircd-runtime/src/federation/link.rs` | new, parse_base_frame, handle_frame, admit_fragment, acquire (+18) |
| `crates/agenc-ircd-e2ee/src/tls.rs` | new, for_maximum, remaining, finish, take (+12) |
| `crates/agenc-ircd-runtime/src/federation/owner.rs` | admit, accept_link, squit, is_suspended, wait_until_wanted (+7) |
| `crates/agenc-ircd-domain/src/federation/origin.rs` | reset, expire, fence_incarnation, add, update (+3) |
| `crates/agenc-ircd-runtime/src/federation/certificate.rs` | verify_peer_certificate, peer, federation_fixture_carries_exactly_one_server_uri, server_id_from_certificate, tbs_extensions (+3) |
| `crates/agenc-ircd-e2ee/src/federation/frames.rs` | is_companion_command, id, parameters, resume_parameters, origin_parameters (+2) |
| `crates/agenc-ircd-domain/src/federation/record.rs` | session, channel_detail, membership, invite, key (+1) |

## Entry Points

Start here when exploring this area:

- **`new`** (Function) — `crates/agenc-ircd-domain/src/federation/projection.rs:285`
- **`derive`** (Function) — `crates/agenc-ircd-domain/src/federation/projection.rs:343`
- **`validate_schema_semantics`** (Function) — `crates/agenc-ircd-federation-wire/src/semantics.rs:41`
- **`parse`** (Function) — `crates/agenc-ircd-types/src/identifiers.rs:253`
- **`parse_wire_bytes`** (Function) — `crates/agenc-ircd-types/src/identifiers.rs:305`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `new` | Function | `crates/agenc-ircd-domain/src/federation/projection.rs` | 285 |
| `derive` | Function | `crates/agenc-ircd-domain/src/federation/projection.rs` | 343 |
| `validate_schema_semantics` | Function | `crates/agenc-ircd-federation-wire/src/semantics.rs` | 41 |
| `parse` | Function | `crates/agenc-ircd-types/src/identifiers.rs` | 253 |
| `parse_wire_bytes` | Function | `crates/agenc-ircd-types/src/identifiers.rs` | 305 |
| `encode` | Function | `crates/agenc-ircd-e2ee/src/federation/keyset_file.rs` | 34 |
| `decode` | Function | `crates/agenc-ircd-e2ee/src/federation/keyset_file.rs` | 49 |
| `new` | Function | `crates/agenc-ircd-e2ee/src/tls.rs` | 27 |
| `for_maximum` | Function | `crates/agenc-ircd-e2ee/src/tls.rs` | 89 |
| `remaining` | Function | `crates/agenc-ircd-e2ee/src/tls.rs` | 121 |
| `finish` | Function | `crates/agenc-ircd-e2ee/src/tls.rs` | 126 |
| `u8` | Function | `crates/agenc-ircd-e2ee/src/tls.rs` | 148 |
| `u16` | Function | `crates/agenc-ircd-e2ee/src/tls.rs` | 154 |
| `u32` | Function | `crates/agenc-ircd-e2ee/src/tls.rs` | 160 |
| `u64` | Function | `crates/agenc-ircd-e2ee/src/tls.rs` | 166 |
| `fixed` | Function | `crates/agenc-ircd-e2ee/src/tls.rs` | 172 |
| `opaque` | Function | `crates/agenc-ircd-e2ee/src/tls.rs` | 194 |
| `vector` | Function | `crates/agenc-ircd-e2ee/src/tls.rs` | 206 |
| `len` | Function | `crates/agenc-ircd-e2ee/src/tls.rs` | 254 |
| `new` | Function | `crates/agenc-ircd-domain/src/federation/replica.rs` | 90 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Origin_state → Take` | cross_community | 6 |
| `Batch_applied → Len` | cross_community | 5 |
| `Origin_state → Remaining` | cross_community | 5 |
| `Origin_state → Len` | cross_community | 5 |
| `Batch_applied → Session` | cross_community | 5 |
| `Batch_applied → Channel_detail` | cross_community | 5 |
| `Batch_applied → Membership` | cross_community | 5 |
| `Batch_applied → Kind` | cross_community | 4 |
| `Batch_applied → Kind` | cross_community | 4 |
| `Batch_applied → New` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_422 | 50 calls |
| Tests | 28 calls |
| Coordinator | 21 calls |
| Validate_ | 13 calls |
| State_core | 5 calls |
| Codec | 5 calls |
| Edge | 4 calls |
| Cluster_913 | 2 calls |

## How to Explore

1. `context({name: "new"})` — see callers and callees
2. `query({search_query: "federation"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
