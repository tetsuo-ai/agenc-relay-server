# Repository Guidelines

## Project Structure & Module Organization

This repository currently contains the protocol and implementation design, not a runnable daemon. `docs/` holds the normative architecture, E2EE extension, federation registry, decision ledger, and integrity manifest. `rfcs/` contains pinned upstream RFC text; preserve these files byte-for-byte. `scripts/check-spec.sh` validates source hashes, registry structure, and negotiated profile hashes.

Rust implementation must follow Section 24 of `docs/ircd-architecture-and-implementation-spec.md`. Keep the declared `agenc-ircd-*` crate boundaries intact: types and wire codecs remain independent of runtime, storage, and policy; the `agenc-ircd` binary performs composition only. Put crate integration tests in `crates/<crate>/tests/` and shared deterministic fixtures in `agenc-ircd-testkit`.

## Build, Test, and Development Commands

- `bash scripts/check-spec.sh`: validate the current specification baseline; run after any documentation or registry change.
- `cargo fmt --all --check`: verify Rust formatting once the workspace exists.
- `cargo check --workspace --all-targets --all-features --locked`: compile every supported target surface.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`: enforce the lint policy.
- `cargo test --workspace --all-features --locked`: run unit and integration tests.
- `cargo deny check` and `cargo audit --deny warnings`: check dependencies and advisories.

There is no server binary to run yet. Implement phases in the order specified by Section 29.

## Coding Style & Naming Conventions

Use stable Rust, rustfmt defaults, and four-space indentation. Crates and modules use `snake_case`, types and traits use `UpperCamelCase`, and constants use `SCREAMING_SNAKE_CASE`. Every workspace crate must declare `#![forbid(unsafe_code)]`. Prefer private-field validated types, typed errors, checked arithmetic, named protocol limits, guard clauses, focused functions, and explicit ownership. Never use unbounded channels, hold locks across `.await`, log secrets, or implement cryptographic primitives locally.

## Testing Guidelines

Add golden-vector, round-trip, negative, property, transcript, and fuzz tests at relevant trust boundaries. Name tests by behavior, such as `rejects_oversized_tag_value`. Each implementation phase must satisfy its Section 29 acceptance gate before the next security-sensitive phase begins. Release coverage targets are 90% branch coverage overall and 100% for the critical branches listed in Section 28.8.

## Commit & Pull Request Guidelines

History currently establishes only `Initial commit`; use concise imperative subjects such as `Add bounded client framing`. Keep commits phase-focused. Pull requests must identify affected specification sections and invariants, describe wire, persistence, dependency, or security effects, and list exact validation commands and results. Never combine normative protocol changes with unrelated implementation cleanup.
