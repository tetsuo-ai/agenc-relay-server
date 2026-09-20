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
report must meet the overall thresholds in `critical-coverage.toml` (90 percent
line coverage, and an interim 75 percent branch floor adopted at Stage 06
closure; the 90 percent branch target returns with Stage 10 release
qualification) and 100 percent for every active range in that file.
`release-critical-coverage.toml` is the Stage 10 policy: the same schema with
the 90 percent branch floor and the complete inventory of parser error
discriminants, authorization decisions, closed protocol enum decoders,
persistence recovery paths, and Section 27 invariant checkers, which the
Stage 10 workspace job validates after the interim policy. The policy also hashes the full set of
production Rust sources. Adding, removing, or changing a production source
invalidates the inventory and forces a review for new critical ranges before
the coverage check can pass. Duplicate llvm-cov branch records at the same
source coordinates are combined before the two semantic outcomes are scored.

Run the current implementation checks:

```sh
bash scripts/check-stage-nine.sh
```

Stage 09 includes every Stage 00 through 08 command. The stage-specific commands
below remain available for narrower development checks. Each checkpoint records
only its named source revision; passing checks on later changes does not update
that checkpoint.

Run the Stage 04 implementation checks:

```sh
bash scripts/check-stage-four.sh
```

The command inherits every Stage 03 check and adds the exact cryptographic
profile, auth and crypto boundary tests, account-generation fences, and
account-envelope fuzzing. The reviewed `opaque-ke` source patch is pinned by
`conformance/vendored-dependencies.toml` and checked by workspace policy. The
command alone does not close `S04-900`. The schema version 2 manifests and
artifacts for exact source commit
`1e5b738468f88b238061cc6e84b732176f5cae65` close Stages 00 through 03. They
contain 17 Stage 00 records, 14 Stage 01 records, 12 Stage 02 records, and 13
Stage 03 records. The
[Stage 04 manifest](evidence/stage-04-4040796f2c21774d58ea7ce54e70a080678e83ac.json)
with 20 passed records closes exact source commit
`4040796f2c21774d58ea7ce54e70a080678e83ac` after the Stage 04 and 05 legibility
review. Its recorded gate ran 50 commands and reached 90.64% of branches and
95.65% of lines, with all six critical regions at 100%. The evidence validator
passed 78 rejection cases. The earlier Stage 04 manifest for
`1e5b738468f88b238061cc6e84b732176f5cae65` and the five schema version 1
manifests for source commit `8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb`
remain archive-only.

Run the Stage 05 implementation checks:

```sh
bash scripts/check-stage-five.sh
```

This command inherits the Stage 04 gate and adds the closed storage profile,
storage dependency review, 191 storage tests, persistent-codec and backup-
stream fuzzing, x86_64 and AArch64 checks, the complete fault campaign, signed
native ext4 growth reports, and the Stage 05 requirement set. The
[schema version 2 manifest](evidence/stage-05-4040796f2c21774d58ea7ce54e70a080678e83ac.json)
contains 39 passed records and closes exact source commit
`4040796f2c21774d58ea7ce54e70a080678e83ac`. The recorded run reached 90.64%
branch coverage, 95.65% line coverage, and 100% coverage in all six critical
regions. The earlier manifest for `bd7518fe7f5c7420debdbaa958aa444ecb5c80c9`
remains archive-only.

Run the Stage 06 implementation checks:

```sh
bash scripts/check-stage-six.sh
```

This command inherits the Stage 05 gate and adds the Stage 06 requirement
set, the runtime profile with 16 transcripts and five host qualification
checks, the config, admin, and runtime package tests, the Stage 06
persistence tests, Loom models, transcripts, the deterministic soak,
deployment checks, controlled-host and Tor qualification, and both Stage 06
fuzz targets. The
[schema version 2 manifest](evidence/stage-06-65cce9d66f7bcfb0c0830a2ab1d42b52bff82942.json)
contains 55 passed records and closes exact source commit
`65cce9d66f7bcfb0c0830a2ab1d42b52bff82942`. The recorded run of 75 commands reached
79.79% branch coverage, 91.79% line coverage, and 100% coverage in all six
critical regions against the interim 75% branch floor.

Run the Stage 07 implementation checks:

```sh
bash scripts/check-stage-seven.sh
```

This command inherits Stage 06 and adds the federation profile, requirement
set, transcript catalog, bounded federation model, three-process daemon test,
and federation fuzz targets. The
[Stage 07 manifest](evidence/stage-07-1093d88d0057c3461a423285e0f86ff3775c1140.json)
contains 38 passed records for exact source commit
`1093d88d0057c3461a423285e0f86ff3775c1140`; its recorded gate ran 85 commands.

Stage 08 adds the encrypted profile, object and wire vectors, durable E2EE
records, bounded route model, transcripts, two-library MLS interoperability,
load checks, and E2EE fuzz targets. The
[Stage 08 manifest](evidence/stage-08-ae6457fb62fef8961d3caf904febed580e8b4a91.json)
contains 160 passed records for exact source commit
`ae6457fb62fef8961d3caf904febed580e8b4a91`; its recorded gate ran 97 commands.
The [review package](review/README.md) records the completed internal review.
No checkpoint claims that Stage 10 production qualification has passed.

Stage 09 adds WSS, plaintext channel history, retained-row maintenance in
disabled builds, metadata-only history replay, and the schema-generation 1-to-2
migration. Its [manifest](evidence/stage-09-a93e53e71d22a6d5ec46bd749ec18068a9fa572b.json)
records 103 commands and 10 passed evidence records for exact source commit
`a93e53e71d22a6d5ec46bd749ec18068a9fa572b`. The reported branch and line
coverage are 75.38% and 90.69%, with nine critical regions at 100%.

Stage 10 has no manifest and no checkpoint. Its evidence is produced by
`scripts/qualify-release.py` against an immutable candidate rather than by
a recorded gate: `stage-ten-qualification.toml` pins the job set,
`release-source-decisions.toml` records the reviewed status of every primary
source, `release-dependency-decisions.toml` records every NOASSERTION the
release SBOM may carry, `release-claims.toml` binds each claim to its jobs and
limit statements, and `release/Dockerfile` defines the build image. The
[Stage 10 qualification notes](../docs/stage-10-qualification.md) describe
each job, the findings the drivers have surfaced, and what remains external.
No release decision has been signed.

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
