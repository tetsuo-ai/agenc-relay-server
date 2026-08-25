---
name: scripts
description: "Skill for the Scripts area of agenc-ircd. 156 symbols across 10 files."
---

# Scripts

156 symbols | 10 files | Cohesion: 90%

## When to Use

- Working with code in `scripts/`
- Understanding how load_toml, validate_toolchain, validate_workspace_manifest work
- Modifying scripts-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `scripts/requirements.py` | quote, render_bindings, load_bindings, validate_bindings, merge_bindings (+26) |
| `scripts/generate-stage-one.py` | lower_snake, upper_camel, parse_registry, render_registry_round_trip_tests, render_federation_text_registry (+23) |
| `scripts/check-stage-one.py` | digest, checked_sources, profile_digests, reject_single_byte_changes, parse_registry (+17) |
| `scripts/check-workspace.py` | load_toml, validate_toolchain, validate_workspace_manifest, validate_dependency_profiles, dependency_tables (+16) |
| `scripts/check-source.py` | load_policy, sanitize_rust, blank, line_number, cfg_test_ranges (+12) |
| `scripts/check-evidence.py` | load_json, load_toml, validate_catalog, validate_schema, canonical_source_sha256 (+10) |
| `scripts/check-ci.py` | validate_workflow, validate_manifest, load_manifest_text, validate, expect_rejection (+3) |
| `scripts/check-baseline.py` | sha256_file, parse_manifest, validate, fail, main |
| `scripts/run-gate.py` | load_gates, resolve_commands, execute, fail, main |
| `scripts/check-coverage.py` | percentage, validate, fail, main |

## Entry Points

Start here when exploring this area:

- **`load_toml`** (Function) — `scripts/check-workspace.py:133`
- **`validate_toolchain`** (Function) — `scripts/check-workspace.py:141`
- **`validate_workspace_manifest`** (Function) — `scripts/check-workspace.py:168`
- **`validate_dependency_profiles`** (Function) — `scripts/check-workspace.py:202`
- **`dependency_tables`** (Function) — `scripts/check-workspace.py:233`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `load_toml` | Function | `scripts/check-workspace.py` | 133 |
| `validate_toolchain` | Function | `scripts/check-workspace.py` | 141 |
| `validate_workspace_manifest` | Function | `scripts/check-workspace.py` | 168 |
| `validate_dependency_profiles` | Function | `scripts/check-workspace.py` | 202 |
| `dependency_tables` | Function | `scripts/check-workspace.py` | 233 |
| `validate_package_manifests` | Function | `scripts/check-workspace.py` | 252 |
| `validate_direct_dependency_evidence` | Function | `scripts/check-workspace.py` | 307 |
| `cargo_metadata` | Function | `scripts/check-workspace.py` | 334 |
| `packages_from_metadata` | Function | `scripts/check-workspace.py` | 355 |
| `graph_from_packages` | Function | `scripts/check-workspace.py` | 373 |
| `validate_graph` | Function | `scripts/check-workspace.py` | 403 |
| `validate_acyclic` | Function | `scripts/check-workspace.py` | 451 |
| `visit` | Function | `scripts/check-workspace.py` | 456 |
| `validate_release_closure` | Function | `scripts/check-workspace.py` | 471 |
| `validate_lockfile` | Function | `scripts/check-workspace.py` | 493 |
| `validate_dependency_exception` | Function | `scripts/check-workspace.py` | 526 |
| `validate` | Function | `scripts/check-workspace.py` | 560 |
| `expect_rejection` | Function | `scripts/check-workspace.py` | 574 |
| `self_test` | Function | `scripts/check-workspace.py` | 587 |
| `fail` | Function | `scripts/check-workspace.py` | 659 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Main → Normative_matches` | cross_community | 6 |
| `Self_test → Normative_matches` | cross_community | 6 |
| `Main → Semantic_opaque` | cross_community | 6 |
| `Main → Length_prefix` | cross_community | 6 |
| `Main → Semantic_enum` | cross_community | 6 |
| `Validate → Normative_matches` | cross_community | 6 |
| `Render_vectors → Length_width` | cross_community | 6 |
| `Validate_stage → Normative_matches` | cross_community | 6 |
| `Main → Require_string` | cross_community | 5 |
| `Main → Blank` | intra_community | 5 |

## How to Explore

1. `context({name: "load_toml"})` — see callers and callees
2. `query({search_query: "scripts"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
