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
The crypto suite passes. Storage, strict workspace lint and full implementation
gate results will be recorded after completion. Coverage thresholds remain
unchanged, with a reviewed critical region for the new borrowed input bound.

This repairs temporary ciphertext allocation. The redb physical-growth
overrun (STO-1), checkpoint scratch capacity, backup scheduling/publication,
encrypted recovery and production qualification remain open.
