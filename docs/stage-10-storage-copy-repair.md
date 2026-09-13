# Stage 10 storage copy repair

Decoding a sealed storage envelope previously allocated a copy of its
ciphertext; opening it cloned that copy into the crypto adapter. For a
maximum-sized record, those two temporary copies total 32 MiB, in addition to
the original envelope and authenticated plaintext.

`SealedRecord` now borrows ciphertext from its encoded input. The storage
crypto adapter accepts a bounded borrowed record while preserving the same
table, key-generation, schema, database-key and authentication-tag checks.
An owned record produced by sealing transfers its ciphertext allocation to
the envelope. Rust lifetimes keep borrowed input alive and immutable through
validation and opening. Plaintext remains owned and zeroizes on drop.

The public Rust record types now carry a lifetime; downstream helpers that
name them explicitly use the matching borrow lifetime. Wire bytes, storage
format, key derivation, nonces, algorithm selection and record bounds are
unchanged. Record-ID encoding and plaintext allocation remain; this change
does not claim that all storage reads allocate nothing.

Reverse restore-manifest traversal also checks the addition that computes
its first sequence. The existing upper-bound guard and descending order are
preserved.

## Verification

The pointer-identity regression failed against the original decoder and
passes with borrowed ciphertext. Tests check minimum/maximum ciphertext
bounds, moving an owned allocation, materializing a borrowed value, exact
encoded bytes and record IDs, and refusal of changed bindings and tags.
The complete crypto and storage suites and strict workspace lint pass. The
constant-time integration review was renewed: secret comparisons, key
derivation and authenticated opening are unchanged.

`RUST_TEST_THREADS=1 CARGO_INCREMENTAL=0 bash scripts/check-stage-nine.sh`
passed for `3a0efdf64c7beb3040ef6cf7549f71737ed9629d` in a temporary
memory-backed checkout. Workspace tests passed 2,872 tests with 21 existing
ignored tests. Coverage reached 75.2373% branches and 91.6569% lines, with all
20 interim critical regions at 100%, including the new borrowed input bound.
Feature-matrix, model and fuzz checks passed. The reviewed Rust inventory is
778 files, SHA-256
`2986aad5579cf3fa584520ab596097e41fdc2d2dc24e8a6d331152cff278341a`.
The later prerequisite merge changes only an earlier validation report.
PR #33 merged this repair.

Earlier host attempts refused changing filesystem free-space samples. The
exact boundary checks, five-attempt limit and physical ceilings were retained.
The workload completion test checks measurement and signability; its passing
result does not mean observed growth is within the release ceiling. The full
functional gate on the temporary filesystem is not native ext4 production
qualification or an exact-revision stage closure.

This repairs temporary ciphertext allocation. The redb physical-growth
overrun (STO-1), checkpoint scratch capacity, backup scheduling/publication,
encrypted recovery and production qualification remain open.
