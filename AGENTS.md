# Repository Guidelines

## Project Structure & Module Organization

AgenC Relay (ARCD) is a safe-Rust federated chat daemon organized as thirteen crates under `crates/`. The sole `arcd` binary composes configuration and runtime. Domain logic, client/federation codecs, authentication, cryptography, E2EE, and storage have separate owning crates. Keep `agenc-relay-domain` free of I/O, clocks, and random generators.

Unit tests live beside modules; integration tests live in each crate's `tests/`. `agenc-relay-testkit` provides shared test support. Deterministic fixtures belong in `test-data/`, fuzz targets in `fuzz/`, and evidence in `conformance/`. `docs/` and `rfcs/` contain specifications; `scripts/` contains validation tools; `deploy/` holds service templates; `assets/` holds artwork.

## Build, Test, and Development Commands

Use the pinned Rust 1.98.0 toolchain. Run commands from the repository root:

- `cargo build --workspace --all-features --locked`: build all crates and optional features.
- `cargo fmt --all --check`: check formatting.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`: enforce lint policy.
- `cargo test --workspace --all-features --locked`: run workspace tests.
- `cargo test -p agenc-relay-client-wire --locked`: test one owning crate.
- `bash scripts/check-stage-nine.sh`: run the full implementation gate used by CI; install prerequisites from `.github/workflows/ci.yml`.
- `cargo run -p agenc-relay-server --bin arcd --locked -- serve --config <file>`: start an initialized node. Follow `docs/operator-guide.md` for initialization, TLS credentials, and `check-config` first.

## Coding Style & Naming Conventions

Use Rust 2024, four-space indentation, and the 100-column rustfmt configuration. Use `snake_case` for modules/functions, `UpperCamelCase` for types, and `SCREAMING_SNAKE_CASE` for constants. Document public APIs. Workspace lints forbid unsafe code and reject `unwrap`, `expect`, panic placeholders, and unchecked indexing. Prefer typed errors and bounded inputs; preserve crate dependency boundaries.

## Testing Guidelines

Use Rust tests, deterministic testkit models, Loom concurrency checks, and cargo-fuzz targets as appropriate. Name tests after observable behavior; integration filenames use descriptive `snake_case.rs`. Add negative and boundary cases. Fixtures must identify their requirement or evidence ID. Coverage policy requires 90% lines, an interim 75% branches, and 100% reviewed critical regions; release qualification requires 90% branches.

## Commit & Pull Request Guidelines

History uses concise imperative subjects, such as “Repair credential replay and startup audit retention.” Follow `.github/PULL_REQUEST_TEMPLATE.md`: identify roadmap tasks from `TODO.md`, specification sections, invariants, compatibility effects, exact validation commands/results, and deferred work. Separate normative protocol changes from implementation PRs. Record evidence before claiming stage completion. Follow `CONTRIBUTING.md`; report vulnerabilities through `SECURITY.md`.
