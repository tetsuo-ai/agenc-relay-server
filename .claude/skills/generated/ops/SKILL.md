---
name: ops
description: "Skill for the Ops area of agenc-ircd. 103 symbols across 12 files."
---

# Ops

103 symbols | 12 files | Cohesion: 85%

## When to Use

- Working with code in `crates/`
- Understanding how compute, cursor_row, sequence_copies work
- Modifying ops-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/sequence.rs` | log, record_bytes, decode, sequencer_row, retain (+22) |
| `crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/directory.rs` | digest, decode, single, directory_write, fetch_identity (+15) |
| `crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/route.rs` | conversation_state, expectation_for, expectation, audience, digest (+12) |
| `crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/mod.rs` | from, opcode, params, account_digest, account_id (+7) |
| `crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/mailbox.rs` | row_kind, target_device, deliver, deliver_binding, deliver_welcome (+2) |
| `crates/agenc-ircd-runtime/src/e2ee/coordinator/events.rs` | cursor_row, sequence_copies, encode_event, outbox_write, cursor_write |
| `crates/agenc-ircd-runtime/src/e2ee/coordinator/execute.rs` | assemble, mark_completion, generic_completion |
| `crates/agenc-ircd-runtime/src/e2ee/coordinator/mod.rs` | retain_object, object_write, id_of |
| `crates/agenc-ircd-runtime/src/e2ee/coordinator/request.rs` | scalar, state_row, replay_write |
| `crates/agenc-ircd-storage/src/e2ee_records.rs` | proof_key, package_key, token_key |

## Entry Points

Start here when exploring this area:

- **`compute`** (Function) — `crates/agenc-ircd-e2ee/src/object.rs:26`
- **`cursor_row`** (Function) — `crates/agenc-ircd-runtime/src/e2ee/coordinator/events.rs:126`
- **`sequence_copies`** (Function) — `crates/agenc-ircd-runtime/src/e2ee/coordinator/events.rs:218`
- **`cursor_write`** (Function) — `crates/agenc-ircd-runtime/src/e2ee/coordinator/events.rs:419`
- **`retain_object`** (Function) — `crates/agenc-ircd-runtime/src/e2ee/coordinator/mod.rs:808`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `compute` | Function | `crates/agenc-ircd-e2ee/src/object.rs` | 26 |
| `cursor_row` | Function | `crates/agenc-ircd-runtime/src/e2ee/coordinator/events.rs` | 126 |
| `sequence_copies` | Function | `crates/agenc-ircd-runtime/src/e2ee/coordinator/events.rs` | 218 |
| `cursor_write` | Function | `crates/agenc-ircd-runtime/src/e2ee/coordinator/events.rs` | 419 |
| `retain_object` | Function | `crates/agenc-ircd-runtime/src/e2ee/coordinator/mod.rs` | 808 |
| `object_write` | Function | `crates/agenc-ircd-runtime/src/e2ee/coordinator/mod.rs` | 829 |
| `id_of` | Function | `crates/agenc-ircd-runtime/src/e2ee/coordinator/mod.rs` | 843 |
| `directory_write` | Function | `crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/directory.rs` | 62 |
| `fetch_identity` | Function | `crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/directory.rs` | 77 |
| `fetch_root_chain` | Function | `crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/directory.rs` | 94 |
| `publish_identity` | Function | `crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/directory.rs` | 147 |
| `fetch_roster` | Function | `crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/directory.rs` | 214 |
| `publish_roster` | Function | `crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/directory.rs` | 236 |
| `fetch_capabilities` | Function | `crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/directory.rs` | 306 |
| `publish_capabilities` | Function | `crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/directory.rs` | 351 |
| `fetch_binding_locks` | Function | `crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/directory.rs` | 417 |
| `whoami` | Function | `crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/directory.rs` | 464 |
| `attach_begin` | Function | `crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/directory.rs` | 473 |
| `attach_finish` | Function | `crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/directory.rs` | 558 |
| `claim_package` | Function | `crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/directory.rs` | 685 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Run → Compute` | cross_community | 4 |
| `Execute → Params` | intra_community | 4 |
| `Execute → From` | intra_community | 4 |
| `Execute → Account_digest` | intra_community | 4 |
| `Publish_roster → From` | intra_community | 4 |
| `Publish_identity → From` | intra_community | 4 |
| `Bind → Params` | intra_community | 3 |
| `Bind → From` | intra_community | 3 |
| `Bind → Account_digest` | intra_community | 3 |
| `Reserve → Account_digest` | intra_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Coordinator | 24 calls |
| Tests | 21 calls |
| Edge | 9 calls |
| Cluster_825 | 7 calls |
| E2ee | 6 calls |
| State_core | 5 calls |
| Federation | 4 calls |
| Cluster_348 | 2 calls |

## How to Explore

1. `context({name: "compute"})` — see callers and callees
2. `query({search_query: "ops"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
