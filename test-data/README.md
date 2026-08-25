# Deterministic Test Data

Checked-in test material is public, synthetic, bounded, and reproducible.

- `vectors/`: canonical and negative golden vectors.
- `transcripts/`: exact client, federation, E2EE, and admin exchanges.
- `property/`: seeds and minimized state-machine counterexamples.
- `fuzz-corpus/`: structured seeds and minimized fuzz regressions.
- `loom/`: concurrency schedules and model bounds.
- `faults/`: storage, crash, clock, entropy, and queue fault plans.
- `interoperability/`: public fixtures for independent implementations.
- `capacity/`: synthetic load shapes and expected ceilings.
- `release/`: non-secret qualification inputs; results belong in
  `conformance/evidence/`.

Unit tests live beside their owning modules. Black-box and cross-crate tests
live in each crate's `tests/` directory. Fixtures must state their governing
requirement or evidence ID before they can support a conformance claim.
