# ARC baseline validation

The ARC baseline is release candidate `1.0.0-rc.3`, storage generation 5,
with `arcd` as the sole executable. The naming decision is in
[the RFC](rfcs/agenc-relay-naming.md).

## Scope

- Thirteen server crates and the fuzz package use `agenc-relay-*` names.
- CLI, service units, setup receipts, runtime replies, logs, and deployment
  paths use ARCD and `arcd`.
- Project-owned MLS labels and canonical object names use ARC. The optional
  WebSocket endpoint is `/arc`; standard IRCv3 subprotocol names are retained.
- Specification hashes, requirement bindings, vectors, authenticated fuzz
  seeds, release fixtures, and coverage references bind the ARC source.
- The server, SDK, and chat repositories are private under `tetsuo-ai`.
  The SDK and chat remain scaffolds; neither is a working chat client yet.
- Previous revision evidence is preserved in Git history. It does not attest
  to this baseline.

## Local implementation checks

`bash scripts/check-stage-nine.sh` passed after the rename. Its workspace
run passed 4,514 selected tests; the separate disk profile passed the isolated
production storage workload. The inherited gate also passed protocol and
source policy, dual-target compile checks, Clippy, documentation tests,
dependency checks, bounded models, daemon transcripts, fuzz smoke campaigns,
and the WSS/history feature matrix.

Implementation coverage measured 84.51% branches and 93.93% lines, with all
21 implementation-critical regions at 100%. The release requires 90% branch
coverage and its complete release-critical inventory; that release threshold
has not been met. All 1,145 release inventory spans have been reanchored to
the source items they identify; this is separate from coverage measurement.

The SDK scaffold passed formatting, Clippy, tests, and its `arc` smoke run.
The release qualification tooling passed its 57 tests. Local Markdown links
and SDK server-source headings were checked. Scans of project-owned source,
fixtures, and filenames found no retired project labels or review gates.

Exact-source gate evidence belongs in `conformance/evidence/` and names its
source commit. These checks do not constitute a production release decision.

## Native qualification still pending

The fresh native x86_64 ext4 growth measurement and its signed report were
produced locally. Its private signing key is stored outside this repository.
Renewal of the pair of embedded native reports is pending a fresh AArch64
measurement. The existing embedded reports have not been relabeled or
re-signed as ARC measurements. They must be replaced together with their
public verification key before the ARC baseline can claim renewed native
storage qualification.

The native workflow was dispatched on the renamed implementation at
`3851938c65167ced7743f9fcf34d6930d0b3bf7b`:
[run 35557628374](https://github.com/tetsuo-ai/agenc-relay-server/actions/runs/35557628374).
GitHub returned `startup_failure` with no jobs. Repository Actions are enabled;
the current token cannot read organization Actions policy (`admin:org` scope
is missing). A native AArch64 Linux host or restored hosted-runner access is
required to complete the measurement. A cross-build or emulated run does not
satisfy this requirement.

Full Stage 10 production qualification remains incomplete. No signed release
decision or production-readiness claim is made by this rename.
