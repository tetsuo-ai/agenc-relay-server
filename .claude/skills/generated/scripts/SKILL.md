---
name: scripts
description: "Skill for the Scripts area of agenc-ircd. 308 symbols across 24 files."
---

# Scripts

308 symbols | 24 files | Cohesion: 76%

## When to Use

- Working with code in `scripts/`
- Understanding how externally_blocked_tasks, required_stage_evidence_ids_from_data, required_stage_evidence_ids work
- Modifying scripts-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `scripts/check-evidence.py` | externally_blocked_tasks, required_stage_evidence_ids_from_data, required_stage_evidence_ids, load_json, validate_catalog (+33) |
| `scripts/requirements.py` | quote, task_states, binding_with_current_status, render_bindings, load_bindings (+26) |
| `scripts/check-workspace.py` | load_toml, validate_vendored_patches, validate_toolchain_policy, validate_toolchain, validate_workspace_manifest (+17) |
| `scripts/generate-e2ee-vectors.py` | opaque, vector, irc_signature_input, sign, roster (+17) |
| `scripts/generate-e2ee-fuzz-seeds.py` | opaque, vector, u16, u32, u64 (+16) |
| `scripts/generate-stage-one.py` | rust_string, parse_registry, render_registry_round_trip_tests, render_field_kind, render_schema_registry (+16) |
| `scripts/check-stage-one.py` | digest, checked_sources, profile_digests, reject_single_byte_changes, validate_vectors (+9) |
| `scripts/run-gate.py` | command_environment, git_environment, git_output, bounded_command_runner, rust_host (+8) |
| `scripts/check-coverage.py` | load_policy, load_report, validate, main, production_source_inventory (+7) |
| `scripts/check-stage-four.py` | load_toml, file_sha256, validate_manifests, validate_fuzz, validate_vectors (+6) |

## Entry Points

Start here when exploring this area:

- **`externally_blocked_tasks`** (Function) — `scripts/check-evidence.py:1405`
- **`required_stage_evidence_ids_from_data`** (Function) — `scripts/check-evidence.py:1423`
- **`required_stage_evidence_ids`** (Function) — `scripts/check-evidence.py:1497`
- **`quote`** (Function) — `scripts/requirements.py:771`
- **`task_states`** (Function) — `scripts/requirements.py:793`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `externally_blocked_tasks` | Function | `scripts/check-evidence.py` | 1405 |
| `required_stage_evidence_ids_from_data` | Function | `scripts/check-evidence.py` | 1423 |
| `required_stage_evidence_ids` | Function | `scripts/check-evidence.py` | 1497 |
| `quote` | Function | `scripts/requirements.py` | 771 |
| `task_states` | Function | `scripts/requirements.py` | 793 |
| `binding_with_current_status` | Function | `scripts/requirements.py` | 806 |
| `render_bindings` | Function | `scripts/requirements.py` | 823 |
| `load_bindings` | Function | `scripts/requirements.py` | 846 |
| `validate_bindings` | Function | `scripts/requirements.py` | 854 |
| `merge_bindings` | Function | `scripts/requirements.py` | 925 |
| `render` | Function | `scripts/requirements.py` | 940 |
| `load_ledger` | Function | `scripts/requirements.py` | 986 |
| `validate_data` | Function | `scripts/requirements.py` | 994 |
| `validate` | Function | `scripts/requirements.py` | 1095 |
| `validate_stage_data` | Function | `scripts/requirements.py` | 1110 |
| `validate_stage` | Function | `scripts/requirements.py` | 1136 |
| `expect_rejection` | Function | `scripts/requirements.py` | 1150 |
| `self_test` | Function | `scripts/requirements.py` | 1167 |
| `main` | Function | `scripts/requirements.py` | 1288 |
| `load_toml` | Function | `scripts/check-workspace.py` | 240 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Self_test → Normative_matches` | cross_community | 7 |
| `Main → Section_number` | cross_community | 7 |
| `Self_test → Task_for` | cross_community | 6 |
| `Main → Normative_matches` | cross_community | 6 |
| `Self_test → Flush` | cross_community | 5 |
| `Self_test → Normalize_text` | cross_community | 5 |
| `Self_test → Sha256_bytes` | cross_community | 5 |
| `Main → Width_for` | cross_community | 5 |
| `Main → Task_for` | cross_community | 5 |
| `Self_test → Split_sentences` | cross_community | 4 |

## How to Explore

1. `context({name: "externally_blocked_tasks"})` — see callers and callees
2. `query({search_query: "scripts"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
