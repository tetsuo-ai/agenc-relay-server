# PRECIS Dependency Decision

Phase 01 pins `precis-profiles` 0.1.13 with default features disabled. The
crate remains a private implementation detail of `agenc-ircd-types`; its types
and errors never cross a public API boundary.

The reviewed release contains a byte/character-index mismatch in nickname
space handling when non-ASCII text precedes a disallowed space. Every input is
therefore length-checked and Unicode-space-canonicalized with byte-correct
`char_indices` traversal before the dependency is invoked. Regression and
finite-corpus tests exercise that boundary. The optional networking feature is
forbidden, and the dependency may not perform host or network I/O.
