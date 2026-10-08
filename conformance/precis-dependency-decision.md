# PRECIS Dependency Decision

Stage 01 pins `precis-profiles` 0.1.13 with default features disabled. The
crate remains a private implementation detail of `agenc-relay-types`; its types
and errors never cross a public API boundary.

The display-name adapter applies the RFC 8266 enforcement passes itself until
the result is stable and uses the dependency only for the FreeformClass check
and NFKC; it does not call the dependency's Nickname enforcement or its
additional mapping rule ([the name preparation
record](../docs/stage-10-name-preparation.md)). Every input is length-checked
first. Generated-input and differential tests exercise the adapter. The
optional networking feature is forbidden, and the dependency may not perform
host or network I/O.
