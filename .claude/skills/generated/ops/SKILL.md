---
name: ops
description: "Skill for the Ops area of agenc-ircd. 98 symbols across 15 files."
---

# Ops

98 symbols | 15 files | Cohesion: 81%

## When to Use

- Working with code in `crates/`
- Understanding how verify_application_object, verify_commit_object, compute work
- Modifying ops-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/sequence.rs` | log, record_bytes, decode, sequencer_row, retain (+16) |
| `crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/directory.rs` | digest, decode, single, directory_write, fetch_identity (+15) |
| `crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/route.rs` | conversation_state, expectation_for, expectation, audience, digest (+9) |
| `crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/mod.rs` | from, opcode, params, account_digest, account_id (+7) |
| `crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/mailbox.rs` | row_kind, target_device, deliver, deliver_binding, deliver_welcome (+2) |
| `crates/agenc-ircd-e2ee/src/envelope.rs` | private_message, verify_application_object, verify_commit_object |
| `crates/agenc-ircd-runtime/src/e2ee/coordinator/events.rs` | sequence_copies, encode_event, outbox_write |
| `crates/agenc-ircd-runtime/src/e2ee/coordinator/execute.rs` | assemble, mark_completion, generic_completion |
| `crates/agenc-ircd-runtime/src/e2ee/coordinator/mod.rs` | retain_object, object_write, id_of |
| `crates/agenc-ircd-runtime/src/e2ee/coordinator/request.rs` | scalar, state_row, replay_write |

## Entry Points

Start here when exploring this area:

- **`verify_application_object`** (Function) — `crates/agenc-ircd-e2ee/src/envelope.rs:94`
- **`verify_commit_object`** (Function) — `crates/agenc-ircd-e2ee/src/envelope.rs:120`
- **`compute`** (Function) — `crates/agenc-ircd-e2ee/src/object.rs:26`
- **`sequence_copies`** (Function) — `crates/agenc-ircd-runtime/src/e2ee/coordinator/events.rs:218`
- **`retain_object`** (Function) — `crates/agenc-ircd-runtime/src/e2ee/coordinator/mod.rs:771`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `verify_application_object` | Function | `crates/agenc-ircd-e2ee/src/envelope.rs` | 94 |
| `verify_commit_object` | Function | `crates/agenc-ircd-e2ee/src/envelope.rs` | 120 |
| `compute` | Function | `crates/agenc-ircd-e2ee/src/object.rs` | 26 |
| `sequence_copies` | Function | `crates/agenc-ircd-runtime/src/e2ee/coordinator/events.rs` | 218 |
| `retain_object` | Function | `crates/agenc-ircd-runtime/src/e2ee/coordinator/mod.rs` | 771 |
| `object_write` | Function | `crates/agenc-ircd-runtime/src/e2ee/coordinator/mod.rs` | 792 |
| `id_of` | Function | `crates/agenc-ircd-runtime/src/e2ee/coordinator/mod.rs` | 806 |
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
| `Origin_state → Remaining` | cross_community | 5 |
| `Origin_state → Len` | cross_community | 5 |
| `Run → Compute` | cross_community | 4 |
| `Execute → Params` | intra_community | 4 |
| `Execute → From` | intra_community | 4 |
| `Execute → Account_digest` | intra_community | 4 |
| `Publish_roster → From` | intra_community | 4 |
| `Publish_identity → From` | intra_community | 4 |
| `Bind → Params` | intra_community | 3 |
| `Bind → From` | intra_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Coordinator | 27 calls |
| Tests | 21 calls |
| E2ee | 7 calls |
| Federation | 6 calls |
| Cluster_817 | 6 calls |
| State_core | 5 calls |
| Wire | 2 calls |
| Cluster_402 | 2 calls |

## How to Explore

1. `context({name: "verify_application_object"})` — see callers and callees
2. `query({search_query: "ops"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
