# Conformance and Evidence

`requirements.toml` is generated from both normative specifications by
`scripts/requirements.py`. Every record starts as `unimplemented`; only the
implementation stage that supplies its named evidence may change that status.
Regenerate after an intentional protocol revision, then review the complete
diff.

`evidence-catalog.toml` reserves stable implementation-stage evidence IDs.
Requirement evidence IDs live directly in `requirements.toml`.
`evidence-manifest.schema.json` defines the release record envelope, while
`scripts/check-evidence.py` enforces cross-record uniqueness, time ordering,
catalog binding, and canonical source-tree and Cargo.lock hashes for each
recorded Git commit.

`evidence-manifest.example.json` is deliberately non-claiming test data. Real
evidence belongs under `conformance/evidence/` and must identify the exact
source revision on which its command ran. Passing a test records an observed
result; it is not, by itself, a broad security claim.

LLVM branch instrumentation is still compiler-gated. The stage-gate scripts set
`RUSTC_BOOTSTRAP=1` for that coverage process only while retaining the pinned
Rust compiler; CI policy rejects the variable anywhere else.

Run the current local gate:

```sh
bash scripts/check-stage-three.sh
```

The command is the current local verification surface. It inherits every Stage
02 check and adds Stage 03 domain, generated-sequence, privacy, and independent
reference-model checks. Release evidence still requires a manifest tied to the
exact committed revision on which the command ran.

For an evidence-only check:

```sh
python3 scripts/requirements.py check
python3 scripts/requirements.py self-test
python3 scripts/check-evidence.py check
python3 scripts/check-evidence.py self-test
```
