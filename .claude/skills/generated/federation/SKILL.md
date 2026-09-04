---
name: federation
description: "Skill for the Federation area of agenc-ircd. 264 symbols across 34 files."
---

# Federation

264 symbols | 34 files | Cohesion: 69%

## When to Use

- Working with code in `crates/`
- Understanding how new, derive, validate_schema_semantics work
- Modifying federation-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-domain/src/federation/projection.rs` | empty, new, derive, home_of, hosts (+78) |
| `crates/agenc-ircd-federation-wire/src/semantics.rs` | validate_schema_semantics, structure_field, semantic, validate_normalized_login, validate_creation_invite (+34) |
| `crates/agenc-ircd-domain/src/federation/replica.rs` | new, membership, account, local_members, apply (+26) |
| `crates/agenc-ircd-runtime/src/federation/link.rs` | new, parse_base_frame, handle_frame, admit_fragment, acquire (+17) |
| `crates/agenc-ircd-e2ee/src/tls.rs` | new, for_maximum, remaining, finish, take (+11) |
| `crates/agenc-ircd-runtime/src/federation/owner.rs` | squit, is_suspended, wait_until_wanted, register, unregister (+7) |
| `crates/agenc-ircd-runtime/src/federation/certificate.rs` | server_id_from_certificate, tbs_extensions, subject_alt_name_value, parse_single_uri, read_tlv (+3) |
| `crates/agenc-ircd-domain/src/federation/record.rs` | session, channel_detail, membership, invite, key (+1) |
| `crates/agenc-ircd-e2ee/src/federation/frames.rs` | is_companion_command, id, parameters, resume_parameters, origin_parameters (+1) |
| `crates/agenc-ircd-domain/src/federation/origin.rs` | add, update, require_synchronizing, reset, expire (+1) |

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
| `opaque` | Function | `crates/agenc-ircd-e2ee/src/tls.rs` | 194 |
| `vector` | Function | `crates/agenc-ircd-e2ee/src/tls.rs` | 206 |
| `len` | Function | `crates/agenc-ircd-e2ee/src/tls.rs` | 254 |
| `new` | Function | `crates/agenc-ircd-domain/src/federation/replica.rs` | 90 |
| `membership` | Function | `crates/agenc-ircd-domain/src/federation/replica.rs` | 133 |

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
| Cluster_435 | 49 calls |
| Tests | 30 calls |
| Coordinator | 16 calls |
| Validate_ | 13 calls |
| State_core | 2 calls |
| Cluster_964 | 2 calls |
| Cluster_276 | 2 calls |
| Edge | 2 calls |

## How to Explore

1. `context({name: "new"})` — see callers and callees
2. `query({search_query: "federation"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
