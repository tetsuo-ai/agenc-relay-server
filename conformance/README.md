# Conformance and Evidence

`requirements.toml` is generated from both normative specifications by
`scripts/requirements.py`. Each clause names the task that closes the full
clause. A task that tests only one slice of an invariant does not own that
invariant. Status comes from the matching checkbox in `TODO.md`. Regenerate
after an intentional protocol revision, then review the complete diff.

`evidence-catalog.toml` reserves stable implementation-stage evidence IDs and
records each normative evidence claim after its full closure task is complete.
An unimplemented requirement keeps its reserved evidence ID in
`requirements.toml`, but that ID cannot appear in a closing manifest.
`evidence-manifest.schema.json` defines the release record envelope, while
`scripts/check-evidence.py` enforces cross-record uniqueness, time ordering,
catalog binding, and canonical source-tree and Cargo.lock hashes for each
recorded Git commit. Archive validation accepts passed, failed, and not-run
records. Stage closure accepts only current passed records with a checked-in
artifact path and a digest that matches the artifact bytes. The closing
artifact is a closed JSON gate-run record. It names the exact committed gate
runner and gate manifest, contains one successful result for every resolved
command, binds the committed stage-specific toolchain policy, records every
exact tool probe and disclosed limitation, and lists each required evidence ID
with its catalog kind. All closing entries must refer to that same run. Schema
version 1 records and other historical logs remain valid archive records, but
they cannot close a stage.

`evidence-manifest.example.json` is deliberately non-claiming test data. Real
evidence belongs under `conformance/evidence/` and must identify the exact
source revision on which its command ran. Passing a test records an observed
result; it is not, by itself, a broad security claim. A closing manifest and
each referenced artifact must match their Git index bytes.

LLVM branch instrumentation is still compiler-gated. The stage scripts set
`RUSTC_BOOTSTRAP=1` for that coverage process only while retaining the pinned
Rust compiler; CI policy rejects the variable anywhere else. The detailed
report must meet the 90 percent overall thresholds and 100 percent for every
active range in `critical-coverage.toml`. The policy also hashes the full set of
production Rust sources. Adding, removing, or changing a production source
invalidates the inventory and forces a review for new critical ranges before
the coverage check can pass. Duplicate llvm-cov branch records at the same
source coordinates are combined before the two semantic outcomes are scored.

Run the Stage 04 implementation checks:

```sh
bash scripts/check-stage-four.sh
```

The command inherits every Stage 03 check and adds the exact cryptographic
profile, auth and crypto boundary tests, account-generation fences, and
account-envelope fuzzing. The reviewed `opaque-ke` source patch is pinned by
`conformance/vendored-dependencies.toml` and checked by workspace policy. The
command alone does not close `S04-900`. The five schema version 2 manifests and
artifacts for exact source commit
`1e5b738468f88b238061cc6e84b732176f5cae65` close Stages 00 through 04. They
contain 17 Stage 00 records, 14 Stage 01 records, 12 Stage 02 records, 13 Stage
03 records, and 20 Stage 04 records. Every record passed. Coverage reached
90.01% of branches and 95.59% of lines, with all five critical regions at 100%.
The evidence validator passed 78 rejection cases. The five schema version 1
manifests for source commit `8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb`
remain archive-only.

Run the Stage 05 implementation checks:

```sh
bash scripts/check-stage-five.sh
```

This command inherits the Stage 04 gate and adds the closed storage profile,
storage dependency review, 181 storage tests, persistent-codec and backup-
stream fuzzing, x86_64 and AArch64 checks, the complete fault campaign, signed
native ext4 growth reports, and the Stage 05 requirement set. The
[schema version 2 manifest](evidence/stage-05-bd7518fe7f5c7420debdbaa958aa444ecb5c80c9.json)
contains 39 passed records and closes exact source commit
`bd7518fe7f5c7420debdbaa958aa444ecb5c80c9`. The recorded run reached 90.00%
branch coverage, 95.50% line coverage, and 100% coverage in all six critical
regions.

For an evidence-only check:

```sh
python3 scripts/requirements.py check
python3 scripts/requirements.py self-test
python3 scripts/check-evidence.py check
python3 scripts/check-evidence.py self-test
```

Record an exact-source run with `AGENC_IRCD_RECORD_GATE=1` and generate its
manifest as described in [evidence/README.md](evidence/README.md). Add both JSON
files to the Git index, then test closure with the literal commit ID:

```sh
python3 scripts/check-evidence.py close-stage --stage 4 --source-commit 0123456789abcdef0123456789abcdef01234567
```

The example ID is not evidence and will fail unless that exact commit and its
complete records exist.
