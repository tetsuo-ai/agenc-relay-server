# Operational repair follow-up

This change repairs client commands, channel privacy, TLS configuration and
queue accounting, including federated command conversion. It does not complete
encrypted recovery or STO-1. The storage format,
protocol registry, dependency pins and physical growth limits are unchanged.

## Client-visible behavior

Registered ACCT and CHANCTL commands require their vendor capability and
`standard-replies`; CHATHISTORY requires `draft/chathistory`. Admission checks
the current capability set on every command, including after CAP removal.
Missing capabilities produce numeric 481 before a mutation or history query
reaches the state owner. Successful controls retain their NOTE response.

Channel mask removals carry the canonical mask into domain authorization before
resolving an entry. Quiet-mask removals require operator authority even when the
entry is absent. Ordered mode vectors can add and remove a mask atomically;
a failed later removal preserves the original channel state. Unresolved CHANCTL
and CHATHISTORY names produce the same public refusal as inaccessible channels.
Guest CHANCTL requests require an account before either standalone or edge
conversion resolves the channel. An edge's unresolved MODE target now has the
same SecretUnavailable refusal as a hidden channel at the coordinator.

Federated mask requests previously placed client text in an argument that the
existing schema requires to contain a FederationTypedMask object. The encoder
and decoder now translate that argument in both directions. Ban, exception,
invite-exception and quiet-ban cases retain their list, direction and canonical
mask; invalid masks and quiet flags on other lists remain refused.

The live TLS regressions check refused and successful controls, capability
removal, history batch replies, and equivalent secret/absent channel refusals.
The domain regressions cover ordered mutations, independence of mask lists and
quiet-mask authority. Edge regressions cover guest account checks, missing MODE
targets and actual encoded mask requests. A loader regression refuses changed
key bytes on the same inode while preserving the earlier accepted identity.

## Configuration and queue behavior

Disabled client listeners no longer require TLS files. Enabling them still
requires valid material. A disabled federation listener on an enabled edge
remains an active outbound TLS identity and is loaded and checked. The real
three-daemon credential replacement and coordinator restart test exercises this
exception. Same-class TLS aliases are permitted by both configuration and
runtime; aliases across TLS classes or other secret purposes remain rejected.

Each reader reserves request-count and wire-byte capacity before parsing a
complete command. Its reservation travels with the queued message until
StateCore dispatches it or the message is dropped. A roomy shared inbox cannot
bypass the configured per-connection limits. Exhaustion pauses the reader;
cancellation, inbox closure and the existing 30-second stall deadline terminate
the wait. Maintenance uses an independent bounded channel and observes the
same durable-batch and reload barriers as client dispatch.

The process-wide 64-slot client aggregation channel remains an additional
bound. This repairs per-connection accounting and maintenance isolation; it
does not replace the aggregation channel with independently scheduled
per-connection inboxes or establish a new throughput claim.

## Verification

The all-feature workspace run passes 2,855 tests, with no failures and 21 ignored
qualification or fixture-generation tests. Build, strict Clippy and source
checks pass. The separate documentation run passes 41 tests. Coverage passes at
75.2229% branches and 91.6099% lines, with all 17 interim critical entries at
100%. The new mask-codec entries measure both conversion decision branches;
the federation-wire schema tests continue to own malformed-schema validation.
The source inventories and critical-region locations are updated without
lowering coverage thresholds or changing historical evidence.

All reviewed Stage 09 commands pass across the initial run and continuations:
Loom, daemon transcripts, deterministic soak, federation models, fuzz smoke,
bounded E2EE load and all four WSS/history build combinations. The initial run
stopped on the new codec coverage entries before their metric correction. A
later federation transcript exposed a test that compared two real-clock reads
one millisecond apart. That component fixture now freezes its monotonic clock;
its exact deadline, storage receipt and restart assertions remain intact. The
fixture and complete federation transcript step pass after the change, and the
workspace coverage report is refreshed. Test harnesses ran with
`RUST_TEST_THREADS=1`. These are development checks; no exact-SHA conformance
artifact or release qualification is claimed.

## Work still required

- **CAP-73/74:** The initial-authority verifier authenticates only a pinned
  genesis. Runtime recovery still needs a bounded evidence carrier, complete
  authenticated historical transitions, and an atomic Closed/Conflict result
  tied to the restore source guard and target epoch. Ordinary submissions
  cannot safely clear those gates. The closed upload union has no recovery
  evidence variant, and a retained context-core ID cannot reconstruct the exact
  missing public body. The ingress and its v1 compatibility need an explicit
  protocol contract. Retained edge witnesses need that authenticated ancestry.
- **CAP-86/101/79:** Device-to-leaf and continuing-member authorization,
  per-conversation signing-key selection with restart-safe old-key ownership,
  and complete retained-object references, ages and physical cleanup remain
  open. The current single-secret configuration does not provide old-key
  ownership across restart.
- **STO-1:** The pinned published redb version has no bounded preparation and
  allocation-free publication API. The existing upstream probe cannot commit
  and does not cover physical growth, cleanup or close. The accepted policy
  requires a published upstream release before integration; see the
  [upstream work and remaining contract](upstream/redb-allocation-probe/README.md).
- **Other operations:** OCSP schema reconciliation, service-user ownership
  checks, generated admin access, connection-task failure isolation and the
  remaining capacity and release qualification findings stay open in TODO.md.
