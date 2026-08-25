# Conformance and Evidence

`requirements.toml` is generated from both normative specifications by
`scripts/requirements.py`. Every record starts as `unimplemented`; only the
implementation stage that supplies its named evidence may change that status.
Regenerate after an intentional protocol revision, then review the complete
diff.

`evidence-catalog.toml` reserves stable Stage-00 evidence IDs. Requirement
evidence IDs live directly in `requirements.toml`. `evidence-manifest.schema.json`
defines the release record envelope, while `scripts/check-evidence.py` enforces
cross-record uniqueness, source/lock consistency, time ordering, and binding
to one of those catalogs.

`evidence-manifest.example.json` is deliberately non-claiming test data. Real
evidence belongs under `conformance/evidence/` and must identify the exact
source revision on which its command ran. Passing a test records an observed
result; it is not, by itself, a broad security claim.

LLVM branch instrumentation is still compiler-gated. The Stage-00 script sets
`RUSTC_BOOTSTRAP=1` for that coverage process only while retaining the pinned
Rust compiler; CI policy rejects the variable anywhere else.

Run:

```sh
python3 scripts/requirements.py check
python3 scripts/requirements.py self-test
python3 scripts/check-evidence.py check
python3 scripts/check-evidence.py self-test
```
