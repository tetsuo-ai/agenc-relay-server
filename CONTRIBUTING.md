# Contributing

AgenC Relay (ARCD) is pre-alpha and follows a specification-first, evidence-gated
implementation roadmap. Contributions should make one roadmap stage more
complete without weakening an existing boundary.

## Before changing code

1. Read the relevant task in [TODO.md](TODO.md).
2. Read the cited architecture or E2EE sections and named invariants.
3. Keep work inside the crate that owns the behavior.
4. Add negative and boundary tests with the implementation.
5. Record the evidence required by the task before marking it complete.

Normative protocol changes and implementation changes belong in separate pull
requests. Do not introduce a cryptographic primitive, permissive fallback,
unbounded input path, raw-identifier log field, or new dependency without the
review and evidence required by the specifications.

## Validation

Run the checks a change needs, no more. Re-running checks that already passed
on the same code proves nothing.

- Documentation, `TODO.md` and comments: no test run. Run the static checker
  that reads the file, if one does.
- A checker script or the gate manifest: that script's `check` and `self-test`.
- A Rust change inside one crate: `cargo fmt --all --check`, clippy with
  `-D warnings`, and `cargo nextest run -p <crate> --all-features --locked`;
  add the dependent crates when a public interface changed.
- A change across crates, to the storage engine, to a wire format or to the
  gate runner: the whole suite,
  `cargo nextest run --workspace --all-features --locked`, then
  `cargo nextest run -p agenc-ircd-storage --all-features --locked --profile disk`
  on a quiet machine.
- A release candidate, a stage closure, or a change to the gate itself: the
  full implementation gate, which runs its lanes concurrently:

```sh
bash scripts/check-stage-nine.sh
```

A check does not close a stage by itself.
The [Stage 09 manifest](conformance/evidence/stage-09-a93e53e71d22a6d5ec46bd749ec18068a9fa572b.json)
records the closure for exact source commit
`a93e53e71d22a6d5ec46bd749ec18068a9fa572b`. Checkpoints apply to their named
source revisions; later changes require new artifact-backed evidence to close
a stage at a new revision. See [TODO.md](TODO.md) for every stage's checkpoint
and [conformance/evidence/README.md](conformance/evidence/README.md) for the
recording procedure.

## Pull requests

Use a concise imperative title. In the description, identify:

- roadmap task IDs and specification sections;
- affected security or correctness invariants;
- wire, persistence, privacy, or dependency effects;
- tests and exact validation commands run; and
- any behavior deliberately deferred.

Keep unrelated cleanup out of a protocol change. See [AGENTS.md](AGENTS.md) for
the repository's Rust conventions and module boundaries. Report suspected
vulnerabilities through [SECURITY.md](SECURITY.md), not an issue or ordinary
pull request.
