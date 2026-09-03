---
name: scripts
description: "Skill for the Scripts area of agenc-ircd. 293 symbols across 23 files."
---

# Scripts

293 symbols | 23 files | Cohesion: 76%

## When to Use

- Working with code in `scripts/`
- Understanding how load_toml, validate_vendored_patches, validate_toolchain_policy work
- Modifying scripts-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `scripts/check-evidence.py` | required_stage_evidence_ids, load_json, validate_catalog, validate_schema, commit_blob_sha256 (+32) |
| `scripts/requirements.py` | quote, task_states, binding_with_current_status, render_bindings, load_bindings (+26) |
| `scripts/generate-e2ee-vectors.py` | opaque, vector, irc_signature_input, sign, roster (+17) |
| `scripts/check-workspace.py` | load_toml, validate_vendored_patches, validate_toolchain_policy, validate_toolchain, validate_workspace_manifest (+16) |
| `scripts/generate-stage-one.py` | rust_string, parse_registry, render_registry_round_trip_tests, render_field_kind, render_schema_registry (+16) |
| `scripts/generate-e2ee-fuzz-seeds.py` | opaque, u8, u16, u32, u64 (+12) |
| `scripts/check-stage-one.py` | digest, checked_sources, profile_digests, reject_single_byte_changes, validate_vectors (+9) |
| `scripts/run-gate.py` | command_environment, git_environment, git_output, bounded_command_runner, rust_host (+8) |
| `scripts/check-coverage.py` | load_policy, load_report, validate, main, production_source_inventory (+7) |
| `scripts/check-stage-four.py` | load_toml, file_sha256, validate_manifests, validate_fuzz, validate_vectors (+6) |

## Entry Points

Start here when exploring this area:

- **`load_toml`** (Function) — `scripts/check-workspace.py:194`
- **`validate_vendored_patches`** (Function) — `scripts/check-workspace.py:226`
- **`validate_toolchain_policy`** (Function) — `scripts/check-workspace.py:254`
- **`validate_toolchain`** (Function) — `scripts/check-workspace.py:279`
- **`validate_workspace_manifest`** (Function) — `scripts/check-workspace.py:297`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `load_toml` | Function | `scripts/check-workspace.py` | 194 |
| `validate_vendored_patches` | Function | `scripts/check-workspace.py` | 226 |
| `validate_toolchain_policy` | Function | `scripts/check-workspace.py` | 254 |
| `validate_toolchain` | Function | `scripts/check-workspace.py` | 279 |
| `validate_workspace_manifest` | Function | `scripts/check-workspace.py` | 297 |
| `validate_dependency_profiles` | Function | `scripts/check-workspace.py` | 334 |
| `is_mls_client_engine` | Function | `scripts/check-workspace.py` | 369 |
| `validate_mls_client_separation` | Function | `scripts/check-workspace.py` | 374 |
| `validate_package_manifest` | Function | `scripts/check-workspace.py` | 414 |
| `validate_package_manifests` | Function | `scripts/check-workspace.py` | 486 |
| `validate_direct_dependency_evidence` | Function | `scripts/check-workspace.py` | 492 |
| `cargo_metadata` | Function | `scripts/check-workspace.py` | 594 |
| `packages_from_metadata` | Function | `scripts/check-workspace.py` | 615 |
| `validate_lockfile` | Function | `scripts/check-workspace.py` | 757 |
| `validate_dependency_exception` | Function | `scripts/check-workspace.py` | 794 |
| `validate` | Function | `scripts/check-workspace.py` | 828 |
| `self_test` | Function | `scripts/check-workspace.py` | 857 |
| `main` | Function | `scripts/check-workspace.py` | 1020 |
| `required_stage_evidence_ids` | Function | `scripts/check-evidence.py` | 1298 |
| `quote` | Function | `scripts/requirements.py` | 770 |

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
| `Main → Task_for` | cross_community | 5 |
| `Main → Width_for` | intra_community | 5 |
| `Self_test → Split_sentences` | cross_community | 4 |

## How to Explore

1. `context({name: "load_toml"})` — see callers and callees
2. `query({search_query: "scripts"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
