---
name: cluster-75
description: "Skill for the Cluster_75 area of agenc-ircd. 30 symbols across 11 files."
---

# Cluster_75

30 symbols | 11 files | Cohesion: 78%

## When to Use

- Working with code in `crates/`
- Understanding how integrity_manifest_hash, integrity_checkpoint_hash, finish work
- Modifying cluster_75-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-storage/src/codec.rs` | finish, take, array, u16, u32 (+2) |
| `crates/agenc-ircd-storage/src/construction.rs` | decode, new, decode_tbs, decode_fields, is_construction_target (+1) |
| `crates/agenc-ircd-storage/src/qualification.rs` | decode, new, validate, decode_and_verify, default |
| `crates/agenc-ircd-storage/src/integrity.rs` | decode, new, validate |
| `crates/agenc-ircd-crypto/src/storage_integrity.rs` | integrity_manifest_hash, integrity_checkpoint_hash |
| `crates/agenc-ircd-storage/src/control.rs` | decode, validate |
| `crates/agenc-ircd-client-wire/src/text.rs` | into_bytes |
| `crates/agenc-ircd-storage/src/backup.rs` | decode |
| `crates/agenc-ircd-storage/src/login_index.rs` | decode |
| `crates/agenc-ircd-storage/src/records.rs` | decode |

## Entry Points

Start here when exploring this area:

- **`integrity_manifest_hash`** (Function) — `crates/agenc-ircd-crypto/src/storage_integrity.rs:252`
- **`integrity_checkpoint_hash`** (Function) — `crates/agenc-ircd-crypto/src/storage_integrity.rs:257`
- **`finish`** (Function) — `crates/agenc-ircd-storage/src/codec.rs:52`
- **`take`** (Function) — `crates/agenc-ircd-storage/src/codec.rs:67`
- **`array`** (Function) — `crates/agenc-ircd-storage/src/codec.rs:80`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `integrity_manifest_hash` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 252 |
| `integrity_checkpoint_hash` | Function | `crates/agenc-ircd-crypto/src/storage_integrity.rs` | 257 |
| `finish` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 52 |
| `take` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 67 |
| `array` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 80 |
| `u16` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 86 |
| `u32` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 90 |
| `u64` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 94 |
| `vector_u32` | Function | `crates/agenc-ircd-storage/src/codec.rs` | 98 |
| `new` | Function | `crates/agenc-ircd-storage/src/construction.rs` | 140 |
| `validate` | Function | `crates/agenc-ircd-storage/src/control.rs` | 212 |
| `new` | Function | `crates/agenc-ircd-storage/src/integrity.rs` | 88 |
| `decode` | Function | `crates/agenc-ircd-storage/src/login_index.rs` | 36 |
| `new` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 78 |
| `validate` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 165 |
| `decode_and_verify` | Function | `crates/agenc-ircd-storage/src/qualification.rs` | 301 |
| `decode` | Function | `crates/agenc-ircd-storage/src/sealed.rs` | 90 |
| `into_bytes` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 138 |
| `decode` | Function | `crates/agenc-ircd-storage/src/backup.rs` | 80 |
| `decode` | Function | `crates/agenc-ircd-storage/src/construction.rs` | 32 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Rebuild_rekey_plan → Validate` | cross_community | 6 |
| `Rebuild_restore_plan → Validate` | cross_community | 6 |
| `Decode → Take` | intra_community | 4 |
| `Write_record → Validate` | cross_community | 4 |
| `Classify_recovery_state → Validate` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 19 calls |
| Cluster_99 | 2 calls |
| Cluster_113 | 2 calls |
| Fuzz_targets | 1 calls |
| Cluster_226 | 1 calls |
| Cluster_175 | 1 calls |
| Cluster_118 | 1 calls |
| Cluster_111 | 1 calls |

## How to Explore

1. `context({name: "integrity_manifest_hash"})` — see callers and callees
2. `query({search_query: "cluster_75"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
