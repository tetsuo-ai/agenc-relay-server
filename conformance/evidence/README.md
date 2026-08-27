# Evidence Artifacts

Machine-readable manifests and their hashed artifacts belong here. Do not add
live user data, production secrets, raw addresses, credentials, ciphertext
captured from users, or unverifiable hand-written success claims.

Archive entries may point to older logs without a path. A stage-closing entry
must point to one checked-in JSON gate-run record under `artifacts/`. The record
uses schema version 1 and contains only these top-level fields:

- `schema_version`, `gate`, `gate_manifest_sha256`, `argv`, and `tool`;
- `source_commit`, `source_sha256`, and `lock_sha256`;
- `target`, `features`, `started_at`, and `ended_at`;
- `result`, `exit_code`, `command_results`, and `evidence`.

`command_results` must match the exact ordered command list resolved from the
committed `conformance/gates.toml`. Every command result records its argument
array, reviewed environment, start and end times, and zero exit status.
`evidence` is the sorted, exact set of required evidence IDs and catalog kinds.
The checker rejects extra fields, missing commands, a different runner, stale
source or lock hashes, failed results, arbitrary files, and artifacts that do
not match the Git index.

Record a gate only from the clean commit named by the evidence. Set the output
path through the runner's control environment so the reviewed gate invocation
keeps its exact argument vector:

```sh
source_commit="$(git rev-parse HEAD)"
AGENC_IRCD_RECORD_GATE=1 \
  python3 scripts/run-gate.py stage-four-implementation

python3 scripts/generate-gate-evidence.py \
  --artifact "conformance/evidence/artifacts/stage-four-implementation-${source_commit}.json"
```

The runner derives the artifact name from the gate and full source commit,
strips `AGENC_IRCD_RECORD_GATE` from every child command, records
real start and end times around each command, and writes an artifact only after
the full gate passes. It does not capture command output. The manifest generator
uses the checked-in catalog and validator, refuses to overwrite a file, and
validates the run before writing the manifest.

Each stage needs its own gate run. Record every required stage artifact before
generating any manifest. An untracked manifest is intentionally rejected by the
next gate's archive check. After generating all artifacts and manifests, add
them to the Git index before running `check` or `close-stage`; both commands
compare the files with their staged bytes.

This record is not a hermetic-build claim. `PATH`, installed tool locations,
Cargo and Rustup homes, and ignored build caches remain external inputs. The
stage wrappers verify pinned tool versions before they invoke the recorder, and
recorded runs reject known shell, Python, Git, and dynamic-loader injection
variables.
