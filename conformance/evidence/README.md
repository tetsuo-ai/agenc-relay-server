# Evidence Artifacts

Machine-readable manifests and their hashed artifacts belong here. Do not add
live user data, production secrets, raw addresses, credentials, ciphertext
captured from users, or unverifiable hand-written success claims.

Archive entries may point to older logs without a path. Schema version 1
manifests and gate-run records remain valid archive material, but they cannot
close a stage. A stage-closing schema version 2 entry must point to one
checked-in JSON gate-run record under `artifacts/`. The record contains only
these top-level fields:

- `schema_version`, `gate`, `gate_manifest_sha256`, `argv`, and `tool`;
- `toolchain_policy_sha256`, the ordered `toolchain`, and `limitations`;
- `source_commit`, `source_sha256`, and `lock_sha256`;
- `target`, `features`, `started_at`, and `ended_at`;
- `result`, `exit_code`, `command_results`, and `evidence`.

`command_results` must match the exact ordered command list resolved from the
committed `conformance/gates.toml`. Every command result records its argument
array, reviewed environment, start and end times, and zero exit status.
`evidence` is the sorted, exact set of required evidence IDs and catalog kinds.
The checker resolves the stage profile from the toolchain policy committed at
the named source revision. It rejects extra or missing tools, a different
version or probe command, policy drift, empty or changed limitations, extra
fields, missing gate commands, a different runner, stale source or lock hashes,
failed results, arbitrary files, and artifacts that do not match the Git index.

Run the unrecorded gate first. After it passes, mark its roadmap gate complete
and commit the source. The recorded gate validates that checked source state;
the resulting manifest closes the stage for that exact commit.

Record a gate only from a clean detached worktree at the exact commit named by
the evidence. Set the output path through the runner's control environment so
the reviewed gate invocation keeps its exact argument vector:

```sh
source_commit="$(git rev-parse HEAD)"
env -u GIT_PAGER -u LD_LIBRARY_PATH -u PYTHONPATH \
  AGENC_IRCD_RECORD_GATE=1 \
  bash scripts/check-stage-nine.sh

python3 scripts/generate-gate-evidence.py \
  --artifact "conformance/evidence/artifacts/stage-nine-implementation-${source_commit}.json"
```

The `env -u` entries remove the three injection variables commonly present in
the development shell. The recorder rejects inherited `GIT_*`, `LD_*`,
`PYTHON*`, Bash startup, and project replay variables before it runs anything.
If it reports another variable, remove that named variable from the recording
invocation. Keep `HOME`, `PATH`, Cargo and Rustup homes, proxy settings, and
certificate settings intact unless the checkpoint policy intentionally changes.

The wrapper performs its normal preflight. The recorder independently probes
the exact ordered toolchain before and after the gate, derives the artifact
name from the gate and full source commit, verifies tracked worktree bytes and
modes directly against `HEAD`, rejects hidden index flags and unexpected
ignored inputs, and strips `AGENC_IRCD_RECORD_GATE` from every child command.
It records real start and end times around each command and writes an artifact
only after the full gate and both probes pass. The manifest generator uses the
checked-in catalog and validator, refuses to overwrite a file, and validates
the run before writing the manifest.

Each stage needs its own gate run. Record every required stage artifact before
generating any manifest. An untracked manifest is intentionally rejected by the
next gate's archive check. After generating all artifacts and manifests, add
them to the Git index before running `check` or `close-stage`; both commands
compare the files with their staged bytes.

This record is exact-source test attestation, not reproducible binary
provenance or a broad security claim. The artifact carries the closed
limitations from `conformance/toolchain-policy.toml`. In particular, command
output is not captured; Bash, external shell utilities, Python, Git, Rustup,
the default native toolchain, advisory database, network state, executable
locations, homes, and ignored caches remain disclosed external inputs. The
recorder strips reviewed Rust, LLVM, Clippy, rustfmt, Cargo, dynamic-loader, and
native-build overrides before every probe and gate command.
