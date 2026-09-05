# Stage 10 production qualification

Stage 10 is in progress. Stage 09 supplies the implemented optional profiles
and its recorded checkpoint. Stage 10 requires evidence from the exact
release binaries on both native targets. No Stage 10 release decision has
been signed.

## Current implementation

The shutdown fix allows unrelated database writes while a signed audit scan
runs. The admin owner serializes audit mutations, and the scan checks its
captured event and checkpoint chain heads. It continues to reject malformed
rows, invalid signatures, gaps, changed audit heads, regressing storage
positions, and truncated pages that make no progress. Shutdown errors now
identify the failed phase and owner using fixed labels.

Local build information is available without starting a node or reading its
secrets.

```sh
agenc-ircd --version
agenc-ircd version --json
agenc-ircd conformance --json
```

The JSON reports the compiler, target, storage schema, compiled optional
features, and source identities supplied by the release builder. Ordinary
development builds report unknown source identities. The conformance command
reports each compiled profile separately and leaves `qualified_claims` empty.
A detached signed release decision supplies completed qualification. The IRC
`VERSION` response retains its existing disclosure limits.

The test client has separate unverified, verified, transparency-observed, and
security-changed states. Unexpected changes block sending until the changed
bindings are authenticated and explicitly reviewed. Decrypted text is
rendered as data, with controls and HTML metacharacters escaped. These tests
do not certify the presentation behavior of third-party clients.

## Candidate and execution records

`scripts/qualify-release.py` defines `check`, `prepare`, `run`, `resume`,
`status`, `close`, and `verify`. Candidate preparation requires a clean detached source
checkout and independently reproduced build records for both native targets.
It copies the binaries and build evidence into a new candidate directory.
Source, lockfile, policy, command, binary, and build-record hashes bind each
attempt to that candidate.

Every attempt has an immutable start record, a bounded combined output log,
measured elapsed and child CPU time, a driver report, and a result record.
The runner allows one active job per candidate directory. Separate native
hosts can execute separate copies, preserving their target-specific attempt
directories when the evidence is collected.

`resume` retains prior attempts. A successful attempt can be reused only when
its evidence still verifies and its host tool identity matches. A failed or
interrupted attempt remains visible and prevents closure. A successful retry
does not dispose of a failure. Fixes that change the source require a new
candidate and new qualification.

The runner rejects duplicate JSON fields, non-finite numbers, path traversal,
symlink artifacts, non-regular inputs, altered logs, modified artifacts,
unknown fields, and mismatched source or target identities. Log exhaustion
and command timeouts produce failures. The CPU accounting includes descendants
that drivers join, so each driver must wait for its workers before exiting.

## Release builds

`scripts/build-release.py build` exports the tracked source, acquires locked
dependencies, and performs two clean native builds inside the same container
image pinned by digest. Each build has a separate output directory, a
read-only source and dependency mount, and networking disabled for the whole
container. Cargo runs with `--frozen`. Compiler and native-library identities
are recorded, and the two binary hashes must match.

An image reference must contain a repository digest or a local `sha256` image
ID. The builder names each container and removes it even if its Docker client
times out. Both runs must reproduce the binary, tool identities, SBOM, and
notice file.

The container image must provide Python 3.11 or later, the pinned Rust 1.98.0
toolchain, Cargo, a native C compiler and linker, and `ldd`. The image must
already be present locally. Cross-compilation or emulation does not count as
the other target's native qualification.

Build output includes a deterministic archive, an SPDX 2.3 dependency report,
available dependency license and notice text, compiler metadata, and both raw
build logs. The dependency report includes build and test dependencies as well
as production dependencies. `NOASSERTION` identifies unavailable license or
native-package information and must be resolved during release review.

The workspace currently uses version `0.0.0`; source-qualified archive names
identify development candidates without inventing a release version or a
license for the project.

## Required campaign lengths

Each fuzz target must accumulate at least 86,400 measured CPU seconds with
the recorded sanitizer and corpus. The driver records bounded segments and
stops at the first failure. Short deterministic fuzz tests remain useful
development checks and cannot satisfy this requirement.

The sustained-operation gate requires at least 604,800 elapsed seconds on
named hardware. It must demonstrate configured capacity, record the required
latency classes and resource limits, exercise every required operational
scenario, and return within its resource limits after load ends. Neither the
existing short soak test nor a report with an asserted duration supplies
that evidence.

Release coverage requires at least 90 percent branches, 90 percent lines,
and 100 percent of all designated critical branches. The inherited coverage
policy retains its 75 percent interim branch floor for development. The
complete Stage 10 critical-branch inventory and its coverage remain open.

## Remaining work

The network driver now compiles integration-test executables into a private
target directory, installs the frozen daemon at their `CARGO_BIN_EXE` path,
and checks its hash before and after each test. It refuses an absent, ignored,
or incomplete selected test. Live WeeChat and Irssi development sessions pass
with the documented ALPN patches. The isolated Tor development test also
passes. Three native client sessions used separate circuits for two contexts,
reused the first context's circuit on reconnect, returned encrypted PONGs, and
shut down cleanly. Packet capture reported zero DNS packets, zero plaintext
canary matches, and zero kernel drops. This evidence covers the local x86_64
development build.

The production-storage, capacity, sustained-operation, and deployment
drill drivers are still being implemented. `check` refuses a policy whose
required driver is absent. Source-status decisions, the complete critical
coverage inventory, native build reproduction, and the long campaigns have
not been completed. The release builder and detached signing path still need
their full integration qualification.

Network evidence must include real WeeChat and Irssi sessions, the native
account protocol, OpenMLS and mls-rs, an isolated Tor v3 network, SOCKS
isolation, packet and DNS-leak capture, privacy canaries, and the client-policy
tests. Configuration parsing alone cannot close the Tor requirement.

Storage evidence must exercise the production storage path on the final
binary, including the required filesystem tuples, growth cases, sync and
rename phases, and reserve boundaries. Earlier redb component measurements
cannot substitute for final release measurements.

Operational evidence must cover restore, migration, deletion, rekey,
login-index transition, each signing and transport key rotation, compromise
response, resynchronization, host hardening, and observability.

## Release claims and limits

The signing command requires an explicit Ed25519 signing key and matching
public key. No signing key is bundled in the daemon. The decision is separate
from the tested binaries, so recording qualification does not rebuild them.
It binds the candidate and all accepted attempt records. Nothing is uploaded
or published by the qualification commands.

Verify a completed decision with a separately trusted public key:

```sh
python3 scripts/qualify-release.py verify --candidate /path/to/candidate \
  --public-key /path/to/trusted-release-public.pem
```

The verifier checks the signature, candidate artifacts, native attempt records,
decision chronology, and the external review when the decision claims the
encrypted profile. It does not trust the public key bundled beside a signature.

An `encrypted-v1` decision also requires the completed external cryptographic
and protocol review recorded by `S08-039`, including remediation verification.
That review remains open. Internal tests and implementation review do not
replace it. Review records must describe work that was performed.

The server observes routing, membership, timing, sizes, and other metadata
described in the specifications. First-contact encryption does not
authenticate an identity out of band. Transparency observation does not
grant Verified status. A compromised client can read its plaintext, and
authorized recipients can disclose messages. Tor testing cannot establish
protection against every traffic-analysis adversary.
