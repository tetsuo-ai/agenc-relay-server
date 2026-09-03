---
name: federation
description: "Skill for the Federation area of agenc-ircd. 292 symbols across 38 files."
---

# Federation

292 symbols | 38 files | Cohesion: 79%

## When to Use

- Working with code in `crates/`
- Understanding how state, iter, absent work
- Modifying federation-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-domain/src/federation/projection.rs` | empty, new, derive, home_of, hosts (+84) |
| `crates/agenc-ircd-domain/src/federation/replica.rs` | new, membership, invite, account, local_members (+26) |
| `crates/agenc-ircd-runtime/src/federation/link.rs` | split, stream_mut, next_deadline, frame_received, run_link (+14) |
| `crates/agenc-ircd-auth/src/service.rs` | durable_expires_at_utc, restore, into_restart_cleanup_metadata, restore_transaction_deadline, read_transaction_record_header (+12) |
| `crates/agenc-ircd-testkit/src/tls_fixture.rs` | mint, mint_federation, validate_dns_name, derive_seed, encode_length (+12) |
| `crates/agenc-ircd-runtime/src/federation/owner.rs` | setup_failed, run_accept_owner, admit, run_dial_owner, history (+11) |
| `crates/agenc-ircd-domain/src/federation/origin.rs` | reset, ready, add, update, delete (+9) |
| `crates/agenc-ircd-domain/src/federation/record.rs` | session, channel_detail, membership, invite, key (+5) |
| `crates/agenc-ircd-runtime/src/federation/certificate.rs` | verify_peer_certificate, peer, federation_fixture_carries_exactly_one_server_uri, server_id_from_certificate, tbs_extensions (+3) |
| `crates/agenc-ircd-domain/src/federation/tests/origin.rs` | binding, add, registered, update, ready_table (+3) |

## Entry Points

Start here when exploring this area:

- **`state`** (Function) — `crates/agenc-ircd-config/src/host.rs:110`
- **`iter`** (Function) — `crates/agenc-ircd-config/src/host.rs:122`
- **`absent`** (Function) — `crates/agenc-ircd-config/src/host.rs:131`
- **`new`** (Function) — `crates/agenc-ircd-domain/src/federation/projection.rs:285`
- **`derive`** (Function) — `crates/agenc-ircd-domain/src/federation/projection.rs:343`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `state` | Function | `crates/agenc-ircd-config/src/host.rs` | 110 |
| `iter` | Function | `crates/agenc-ircd-config/src/host.rs` | 122 |
| `absent` | Function | `crates/agenc-ircd-config/src/host.rs` | 131 |
| `new` | Function | `crates/agenc-ircd-domain/src/federation/projection.rs` | 285 |
| `derive` | Function | `crates/agenc-ircd-domain/src/federation/projection.rs` | 343 |
| `durable_expires_at_utc` | Function | `crates/agenc-ircd-auth/src/service.rs` | 827 |
| `restore` | Function | `crates/agenc-ircd-auth/src/service.rs` | 841 |
| `into_restart_cleanup_metadata` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1015 |
| `into_restart_metadata` | Function | `crates/agenc-ircd-auth/src/service.rs` | 1884 |
| `restore_authentication` | Function | `crates/agenc-ircd-auth/src/transaction.rs` | 193 |
| `parse` | Function | `crates/agenc-ircd-types/src/identifiers.rs` | 253 |
| `parse_wire_bytes` | Function | `crates/agenc-ircd-types/src/identifiers.rs` | 305 |
| `new` | Function | `crates/agenc-ircd-domain/src/federation/replica.rs` | 90 |
| `membership` | Function | `crates/agenc-ircd-domain/src/federation/replica.rs` | 133 |
| `invite` | Function | `crates/agenc-ircd-domain/src/federation/replica.rs` | 143 |
| `account` | Function | `crates/agenc-ircd-domain/src/federation/replica.rs` | 153 |
| `local_members` | Function | `crates/agenc-ircd-domain/src/federation/replica.rs` | 158 |
| `install` | Function | `crates/agenc-ircd-domain/src/federation/replica.rs` | 237 |
| `apply` | Function | `crates/agenc-ircd-domain/src/federation/replica.rs` | 323 |
| `verify_peer_certificate` | Function | `crates/agenc-ircd-runtime/src/federation/certificate.rs` | 150 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `From_object → Unpadded_base64_len` | cross_community | 6 |
| `Batch_applied → Len` | cross_community | 5 |
| `Batch_applied → Try_from` | cross_community | 5 |
| `Batch_applied → LinkOutbound` | cross_community | 5 |
| `Batch_applied → Release_queued` | cross_community | 5 |
| `Batch_applied → Kind` | cross_community | 4 |
| `Into_restart_cleanup_metadata → Read_array` | intra_community | 4 |
| `Into_restart_cleanup_metadata → Transaction_id` | cross_community | 4 |
| `Into_restart_cleanup_metadata → Matches_request_kind` | cross_community | 4 |
| `Into_restart_cleanup_metadata → Message_kind` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 35 calls |
| State_core | 24 calls |
| Admission | 9 calls |
| Tls | 7 calls |
| Edge | 4 calls |
| Coordinator | 3 calls |
| Listener | 3 calls |
| Connection | 1 calls |

## How to Explore

1. `context({name: "state"})` — see callers and callees
2. `query({search_query: "federation"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
