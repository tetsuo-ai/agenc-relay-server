---
name: e2ee-records
description: "Skill for the E2ee_records area of agenc-ircd. 82 symbols across 14 files."
---

# E2ee_records

82 symbols | 14 files | Cohesion: 81%

## When to Use

- Working with code in `crates/`
- Understanding how expose_for_storage, finish, take work
- Modifying e2ee_records-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/src/domain_records.rs` | decode, optional_account_id, decode_channel, expect_version, byte (+19) |
| `crates/agenc-ircd-storage/src/e2ee_records.rs` | decode, unwrap, decoder, take_bool, take_optional_hash (+11) |
| `crates/agenc-ircd-storage/src/e2ee_records/barrier.rs` | from_wire, take, check, decode, validate_body (+8) |
| `crates/agenc-ircd-storage/src/codec.rs` | finish, take, array, u16, u32 (+2) |
| `crates/agenc-ircd-storage/src/federation_records.rs` | decode, unwrap, expect_version, take_bool, take_optional_u64 (+1) |
| `crates/agenc-ircd-storage/src/control.rs` | new, encode, decode, validate, decode_and_verify |
| `crates/agenc-ircd-storage/src/construction.rs` | decode, decode_tbs, decode_fields |
| `crates/agenc-ircd-storage/src/qualification.rs` | decode, decode_and_verify |
| `crates/agenc-ircd-crypto/src/storage_integrity.rs` | expose_for_storage |
| `crates/agenc-ircd-storage/src/backup.rs` | decode |

## Entry Points

Start here when exploring this area:

- **`expose_for_storage`** (Function) — `crates/agenc-ircd-crypto/src/storage_integrity.rs:138`
- **`finish`** (Function) — `crates/agenc-ircd-storage/src/codec.rs:52`
- **`take`** (Function) — `crates/agenc-ircd-storage/src/codec.rs:67`
- **`array`** (Function) — `crates/agenc-ircd-storage/src/codec.rs:80`
- **`u16`** (Function) — `crates/agenc-ircd-storage/src/codec.rs:86`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `expose_for_storage` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 138 |
| `finish` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 52 |
| `take` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 67 |
| `array` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 80 |
| `u16` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 86 |
| `u32` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 90 |
| `u64` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 94 |
| `vector_u32` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 98 |
| `new` | Function | `crates/agenc-ircd-storage/src/control.rs` | 53 |
| `validate` | Function | `crates/agenc-ircd-storage/src/control.rs` | 217 |
| `decode_and_verify` | Function | `crates/agenc-ircd-storage/src/control.rs` | 298 |
| `decode` | Function | `crates/agenc-ircd-storage/src/domain_records.rs` | 178 |
| `decode` | Function | `crates/agenc-ircd-storage/src/e2ee_records.rs` | 298 |
| `validate_state_body` | Function | `crates/agenc-ircd-storage/src/e2ee_records.rs` | 2581 |
| `decode` | Function | `crates/agenc-ircd-storage/src/e2ee_records/barrier.rs` | 371 |
| `validate_body` | Function | `crates/agenc-ircd-storage/src/e2ee_records/barrier.rs` | 577 |
| `decode` | Function | `crates/agenc-ircd-storage/src/federation_records.rs` | 164 |
| `decode` | Function | `crates/agenc-ircd-storage/src/login_index.rs` | 36 |
| `decode_and_verify` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 345 |
| `decode` | Function | `crates/agenc-ircd-storage/src/sealed.rs` | 90 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Rebuild_rekey_plan → As_bytes` | cross_community | 6 |
| `Rebuild_rekey_plan → Validate` | cross_community | 6 |
| `Decode → Take` | intra_community | 5 |
| `Decode → Take` | intra_community | 4 |
| `Write_record → As_bytes` | cross_community | 4 |
| `Write_record → Validate` | cross_community | 4 |
| `Decode → Take` | intra_community | 4 |
| `Decode → Try_from` | cross_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_822 | 31 calls |
| Coordinator | 30 calls |
| Tests | 18 calls |
| Cluster_844 | 4 calls |
| Cluster_847 | 3 calls |
| Cluster_226 | 3 calls |
| Cluster_901 | 2 calls |
| Cluster_846 | 2 calls |

## How to Explore

1. `context({name: "expose_for_storage"})` — see callers and callees
2. `query({search_query: "e2ee_records"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
