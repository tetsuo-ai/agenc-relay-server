# Credential and runtime repair

This follow-up starts at `fd7d39476302caae385e69bdea126d0a54164233` and implements
registered credential replacement through an edge. It also repairs deferred
channel-key authorization, administrative account revisions and reload refusal
handling. It changes no protocol registry, persistence format, dependency pin
or storage growth limit.

## Credential replacement

The edge forwards both ACCTCRED phases to the coordinator's account-service
owner. The coordinator validates the declared origin against the live session,
home edge, capabilities, account and account generation. Registered SASL
reauthentication uses that same session authority.

Registration retains the one-use fresh-authentication proof. Each internal
carrier holds a conservative client-connection memory reservation until its
origin is deleted, its link closes or the coordinator shuts down. Carrier
admission uses the tracked-connection ceiling and memory budget; exhaustion
returns busy before allocating a new origin mapping. Internal account
connections receive explicit account replies and never enter the local chat
recipient index.

A successful replacement commits the credential mutation, exact sealed outer
response, origin successor and correlated completion event together. The edge
holds the response until its ordinary completion or combined-profile barrier
is durable. It sends the final ACCTCRED result and CHANGED note before closing
the requesting connection. Other affected sessions close after their durable
session-removal events. A refused transaction does not publish a successful
replacement result.

The three-daemon regression creates an account, authenticates two sessions on
separate edges, reauthenticates the registered requester, replaces its password,
checks both connection closures, restarts the coordinator and authenticates
with the replacement password. Additional storage tests compare the exact
response and completion identities, and exercise ordinary and combined-profile
receipt ordering. Edge receipt tests use opaque fixture bodies; account-service
cryptography is exercised by the real OPAQUE daemon test.

## Runtime corrections

- Deferred JOIN and MODE key work reauthorizes against the current revision
  after an unrelated commit. A changed target channel or session still refuses
  the old crypto result, and retrying does not charge command admission twice.
- Account suspension and restoration advance the account revision in both the
  durable after-image and live state. Stale administrative confirmations fail.
- A full or closed reload inbox reports a determinate refusal before submission.
  A lost reply after submission remains indeterminate. The admin owner waits
  for the failure audit record to commit before answering a refused REHASH.

## Validation

The validation commands are:

```sh
cargo fmt --all --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
python3 scripts/requirements.py check
python3 scripts/check-source.py check
python3 scripts/check-source.py self-test
python3 scripts/check-workspace.py check
python3 scripts/check-workspace.py self-test
python3 scripts/check-coverage.py self-test conformance/critical-coverage.toml
python3 scripts/check-coverage.py self-test conformance/release-critical-coverage.toml
```

The locked all-feature workspace run passes 2,828 tests with no failures and
21 ignored tests. Nineteen ignored tests are qualification scenarios; two
generate deterministic fixtures. Both x86_64 and AArch64 all-target compilation,
formatting, Clippy, dependency audit and deny checks pass. The source policy
accepts 915 Rust files; the requirement ledger covers 240 records. Workspace,
source and coverage-policy rejection self-tests pass.

Coverage measures 75.11% branches and 91.54% lines; all eight interim critical
regions reach 100%. The initial instrumented run encountered changing free
disk space during the storage reserve-boundary measurement. The storage suite
passed when rerun serially without concurrent builds, and the remaining crates
completed with the earlier profiles retained. The failed run and its decoded
boundary log are preserved with the validation artifacts. This measurement
passes the 75% development branch floor and remains below the 90% release floor.

The reviewed inventory includes the new authorization, memory, reply-phase and
receipt guards. Updating that inventory does not measure coverage or lower any
coverage floor.

## Remaining completion requirements

STO-1 remains open. The accepted dependency policy requires a published upstream
redb release. The retained allocation prototype is an abort-only probe; it does
not provide bounded preparation, allocation-free publication and bounded
cleanup/close. Integrating it as a maintained fork would violate the accepted
policy. Its engineering contract and experiment are retained in
[the upstream probe directory](upstream/redb-allocation-probe/README.md).

Encrypted recovery remains open under CAP-73 and CAP-74. Pending routes refuse
new authority, but the public initial-authority validator has no runtime or
maintenance caller. Completing recovery requires an evidence-ingestion contract,
authenticated historical transitions and atomic Closed or Conflict installation
bound to the restored source guard and target epoch. Per-conversation signer
ownership, the remaining ReInit leaf checks and complete retained-object cleanup
also remain open under CAP-101, CAP-86 and CAP-79.

The remaining Stage 06 configuration, privacy, queue and shutdown findings stay
listed in `TODO.md`. Production capacity, release coverage, both native-target
qualification sets and the external encrypted-profile review are not closed by
these repairs. The server is not yet fully production-qualified.
