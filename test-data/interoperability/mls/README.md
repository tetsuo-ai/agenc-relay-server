# MLS WG interoperability corpus subset

The files here are derived from the `mlswg/mls-implementations` repository
at the commit pinned in `conformance/e2ee-mls-corpus.toml`, which also
records the SHA-256 of every upstream source file and of every derived
file below. The daemon never runs an MLS client, so only the outer framing
it parses is kept: KeyPackage, Welcome, PrivateMessage, PublicMessage, and
GroupInfo messages from `test-vectors/messages.json` (the first 24 entries,
one hex line per message), the variable-length integer header vectors from
`test-vectors/deserialization.json` (`header length` per line), and the
seven welcome joins from `test-vectors/welcome.json` (`suite key_package
welcome` per line).

`crates/agenc-ircd-e2ee/tests/mls_corpus.rs` parses every line under the
production outer parser and checks the suite gate: messages of an enabled
suite are accepted with their public fields, messages of any other suite
are refused as a profile mismatch, and no line panics or overruns a budget.
