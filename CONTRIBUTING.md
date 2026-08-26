# Contributing

AgenC IRCD is pre-alpha and follows a specification-first, evidence-gated
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

Run the current complete gate from the repository root:

```sh
bash scripts/check-stage-two.sh
```

For a narrower development loop, use `cargo fmt --all --check`,
`cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`,
and `cargo test --workspace --all-features --locked`. The complete stage gate
must still pass before merge.

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
