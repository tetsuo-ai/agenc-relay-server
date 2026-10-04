# Stage 10 edge descriptor pins the epoch the edge advertises

This record covers AUD-03 of the SDK readiness audit (2026-10-01, SDK
program, outside master #35). An edge's `arcd print-onboarding` descriptor
pinned a recovery epoch the edge never advertises.

## The defect

`render_onboarding` (`crates/agenc-relay-runtime/src/offline.rs`) wrote the
`recovery-epoch` line from the authenticated database header on every role.
On an edge that is the edge's own database epoch. The edge's CAP, however,
advertises its coordinator's epoch: `registration_config` in
`crates/agenc-relay-runtime/src/daemon.rs` gives an edge
`AccountServiceRole::Advertised` with the `recovery_epoch` of its enabled
coordinator `[[federation.peer]]` record, because the sealed account
envelopes its clients build bind to the account service that opens them, on
the coordinator (Section 22.2). The owner's test
`edge_onboarding_uses_read_only_reconstruction_without_fake_opaque_state`
asserted that the two differ.

Invariant ID-06 and Section 9.3 have a native client compare the
TLS-authenticated `agenc.ag/recovery` value with its onboarding pin before
any account or E2EE use and block on a mismatch. A client onboarded from an
edge's descriptor was therefore blocked on that edge, and a client onboarded
from the coordinator's descriptor dialed a node that offers no encrypted
profile.

## The rule

The program's decision D-15: an edge's descriptor pins the epoch the edge
advertises, which is its coordinator's, carried by its CAP and its welcome
NOTE. After a coordinator epoch change the edge's descriptor follows, and an
old descriptor is an identity transition. Its normative text belongs to the
program's single normative revision (P-01); the current ID-06 already
implies this code, since the only descriptor epoch a client of the edge can
use is the one the edge advertises.

The rule replaces two passages of the frozen architecture text, which this
change leaves untouched:

- Section 9.3: the `agenc.ag/recovery` value is literal `v1.` followed by
  "canonical unpadded base64url for the live header's 16-byte recovery
  epoch". An edge's CAP already departs from it at `70c832c`, advertising
  its coordinator record's pin rather than the edge's own header epoch.
- Appendix C.8: the descriptor line
  `recovery-epoch=<22-char-random-recovery-epoch>`, which on an edge now
  carries that same coordinator pin rather than the edge's own random
  epoch.

## What changed

- `edge_advertised_recovery_epoch` (`daemon.rs`) is the one selection of
  the epoch an edge advertises: the pin of its enabled coordinator record.
  The daemon's CAP and the descriptor both use it, so a printed edge
  descriptor always equals the CAP value. The daemon keeps its existing
  fallback to the edge's own epoch when no enabled coordinator record
  exists, which no serving edge reaches: `validate_profile` refuses an edge
  without federation, the configuration requires exactly one coordinator
  record on a federated edge, and `edge_dial_plan` refuses a disabled one.
- `render_onboarding` pins a coordinator's own database epoch, as before,
  and an edge's advertised epoch. An edge with no enabled coordinator
  record gets no descriptor and the refusal `configuration validation
  failed`. `arcd init` leaves an edge that way, with federation disabled,
  which `check-config` and `serve` already refuse; `serve` also refuses a
  disabled coordinator record.
- `arcd init` prints `recovery-epoch=<22 characters>` after `server-id=`.
  The coordinator's record for an edge pins the epoch the edge's federation
  hello carries, its own database epoch (FED-10), and the edge's descriptor
  was until now the only `arcd` output that carried it. From this change on
  the receipt line is the only `arcd` output that prints an edge's own
  epoch, once, at initialization; `storage restore` prints the new epoch it
  declares. The operator keeps the receipt with the node's other identity
  lines (see Limitations for an edge without one).
- The operator guide states both rules.

No wire byte, configuration key, stored row or protocol identifier changes.
A coordinator's descriptor is byte-identical to before.

## Regressions

- `offline::tests::edge_onboarding_uses_read_only_reconstruction_without_fake_opaque_state`,
  the owner's test, changed deliberately: the edge `arcd init` wrote is
  refused before its coordinator record exists; with an enabled record its
  descriptor pins the coordinator's epoch from the trusted descriptor and
  not the edge's own database epoch, which equals the receipt's
  `recovery_epoch`; after the record is re-pinned to a new coordinator
  epoch the descriptor follows; with the record disabled it is refused
  again. The read-only reconstruction without fake OPAQUE state it names is
  unchanged.
- `offline::tests::coordinator_onboarding_pins_its_own_database_epoch`: a
  federated coordinator with an edge record still pins its own database
  epoch, which its receipt printed. It guards the coordinator branch and the
  receipt, not the edge branch: it fails when a coordinator's descriptor
  pins its enabled peer record's epoch, or when the receipt's epoch is not
  the database's, and passes with the edge branch reverted.
- `stage_eight_e2ee::cli_provisioning::a_cli_initialized_edge_serves_links_and_advertises_e2ee`:
  `print-onboarding` refuses the freshly initialized edge; the coordinator's
  record for the edge pins the epoch the edge's init receipt printed, and the
  link it establishes proves that value; the edge's descriptor printed after
  enrollment pins the coordinator's epoch, and the live edge's CAP
  advertises exactly the descriptor's value. Since the program's integration
  merge with the SC-007 topic, which sends the welcome NOTE, a guest of that
  edge that negotiated `agenc.ag/recovery` must end its welcome with
  `NOTE * RECOVERY_EPOCH` carrying the descriptor's epoch, the coordinator's.

With the edge branch of the descriptor reverted to the database epoch (the
`70c832c` behaviour), the owner's test fails at the refusal and the daemon
cases fail with `print-onboarding was not refused for edge-a.test`. With the
refusal kept but the epoch reverted, the owner's test fails at the epoch
equality and the daemon cases fail with `edge-a.test descriptor does not pin
its coordinator's epoch`. The AUD-02 daemon case, which provisions through
the same steps, fails with the AUD-01 daemon case in both. With the welcome
NOTE rendering another epoch than the router's (the epoch reversed), the
AUD-01 daemon case passes its CAP checks and fails at the NOTE comparison,
the SC-007 edge NOTE cases fail too, and the AUD-02 case, which reads no
NOTE, passes.

## Limitations

- The descriptor follows the configured coordinator pin. When the
  coordinator's epoch changes, the edge's record is updated by the operator
  (a restart-only change, Appendix C.4); nothing re-pins it automatically.
- The architecture text for the rule arrives with P-01 (see The rule).
- Only the init receipt prints an edge's own epoch, which the coordinator's
  record for that edge needs. An edge initialized by an earlier `arcd`,
  whose receipt has no `recovery-epoch=` line, or one whose receipt was
  lost, has no `arcd` read of it: its `print-onboarding` now prints the
  coordinator's epoch, and `check-config` prints only host controls.
  Before upgrading such an edge, record its own epoch with the earlier
  `arcd print-onboarding`, which printed it; otherwise initialize the edge
  again. An edge an earlier `arcd init` created could not start before the
  AUD-01 fix unless its operator seeded the fake OPAQUE record by hand. An
  explicit read of a node's own epoch, for example an additive line in an
  existing offline command, is listed for the owner.
