# Prospective initial-root reservation

This optional profile lets the creator of a new Account ID reserve its first
published ARC-MLS root before the client has generated a root key. The
coordinator holds a commitment to a client-generated bootstrap secret. A
registered client that proves knowledge of that secret can check the
reservation and permanently choose a generation-zero fingerprint. The normal
signed root and its directory chain remain independently verifiable by existing
clients. This document specifies a protocol. Implementation and Linux
interoperability evidence belong to subsequent changes.

## Negotiation and compatibility

The client capability is `agenc.ag/initial-root=v1.<profile>`. The profile
value is unpadded base64url of SHA-256 over the ASCII string
`agenc-chat initial root profile v1`, the 32-byte base federation v1 profile
hash, the 32-byte ARC-MLS v1 profile hash, and SHA-256 of the exact committed
UTF-8 bytes of this document, concatenated in that order. Clients pin the
supported value and explicitly request the capability. An edge offers it only
while its authenticated coordinator link supports this profile. A listening
coordinator may offer it directly. New account creation additionally requires
`agenc.ag/account-create=v1`. A client requesting protected creation stops on
an absent capability, NAK, CAP DEL, descriptor change or uncertain transfer.
It must never retry with unguarded creation.

Federation peers supporting this extension explicitly configure the enhanced
base profile for their link. They use the existing authenticated FHELLO format,
with profile version 2 and the 32-byte profile hash above. The agreed profile
adds exactly the two Appendix-B operations specified below. Existing base
operations, sequence rules, account and origin checks, and the separate
ARCMLS ECAP handshake retain their original encodings. Base v1 links keep
their original FHELLO version, hash, closed registries and traffic. A mismatch
closes the link before origin replay. An enhanced-only operation cannot be
forwarded on a v1 link. Existing account and ARC-MLS clients can operate on
either kind of listener. The coordinator applies the persistent publication
restriction on every originating link and on its own local connections.
[Base compatibility rules](arc-architecture-and-implementation-spec.md#26-compatibility-extension-and-versioning-policy)

## Create the reservation

Before sending the guarded START, the client generates an independent random
32-byte secret and a fresh 16-byte Client Request ID with its operating
system CSPRNG. Under its protected installation owner, it durably records the
secret, original request ID, accepted Network ID, recovery epoch and the
physical profile and local creation operation. It reserves the required
bounded storage before sending. A crash after a possible transmission retains
this exact operation and secret. The secret has no root, enrollment, roster,
MLS, recovery, or ordinary account signing purpose.

The client computes `precommit` with the exact ASCII label and fixed-width
fields below. The first hash is available before an Account ID exists. After
the coordinator allocates the canonical 24-byte account token, the second
hash binds that precommit to the actual account and authenticated transaction.

```text
precommit = SHA256("agenc-chat initial root precommit v1" ||
                   network_id[32] || recovery_epoch[16] ||
                   start_client_request_id[16] || secret[32])
owner = SHA256("agenc-chat initial root owner v1" ||
               network_id[32] || recovery_epoch[16] || account_id[24] ||
               start_client_request_id[16] || precommit[32])
```

`ACCTCREATE CLAIMSTART 4726` and its `READY CLAIMSTART 4726` use the
ACCTCREATE START transfer, budget, OPAQUE challenge and invitation rules.
The new request header has profile version 2 and kind 7
(`claimed_create_start`). Its inner arm has the fields of AccountCreateStart
with inner profile version 2, followed by the exact 32-byte precommit. The
encoded length is 104 through 165 without an invitation and 236 through 297
with an invitation. The response header has version 2 and kind 7
(`claimed_create_challenge`) with the usual AccountServiceChallenge fields
and inner version 2. The original pinned account-service recipient, recovery
epoch, HPKE suite and Section 11.2.1 request/response labels and fixed widths
apply. The actual version and kinds enter the authenticated headers and
request info. The zero-padded wrappers use the original padding version and
exactly `4586 - inner_length` request or `4202 - inner_length` response zero
bytes. Envelopes remain exactly 4,726 or 4,342 bytes. Decoders admit only the
declared arms and bounds under this profile.

The sealed challenge and coordinator's one-use transaction bind the exact
guarded start, recovery epoch, precommit, connection, origin, account-service
key and start request ID. The existing `ACCTCREATE FINISH`, authenticated
completion and terminal remain unchanged. The coordinator accepts this
cross-version pair only for the exact transaction created by the guarded
start. The ordinary start cannot acquire a claim at finish. With a successful
finish, the allocated account marked **Guarded**, credential, private login
index, applicable invitation redemption, claim `Reserved(epoch, start_id, owner)` and committed
completion form **one durable decision**. Rejection, abort, expiry, wrong
binding and a failed commit grant nothing. Duplicate accepted requests follow
the existing exact-result rules. The claim is private, keyed by the Network ID
and Account ID and bounded to one permanent row per guarded account. Account
and directory quotas include all of its terminal states. The authoritative
account record independently identifies its permanent genesis policy,
**Legacy** or **Guarded**. Pre-extension account records decode as Legacy.
Claim absence cannot synthesize Legacy. An absent account has no publication
authority. For a Guarded account, an absent claim or mismatched identity
fences publication and reports a protected storage inconsistency.

## Read or bind the choice

A currently registered session for the exact immutable account sends
`ACCTROOT CLAIM 4726`. The reply is `ACCTROOT READY CLAIM 4726`, 16
request `ACCTROOT DATA` lines and `ACCTROOT END` from the client, followed
by `ACCTROOT COMPLETE 4342`, 15 `ACCTROOT DATA` lines and `ACCTROOT END`
from the server. DATA uses the exact ACCTCREATE chunking. No public result
numeric conveys a disposition. ACCTCRED's per-session transfer, time, memory,
rate and registration bounds apply. The edge forwards the unchanged HPKE
envelope. The request has header version 2, kind 8 (`initial_root_claim`).
The response has header version 2, kind 8 (`initial_root_state`). The
profile-2 HPKE and wrapper rules above apply. Multibyte integers below are
big-endian. Fields shown in brackets have fixed byte lengths and no vector
prefix.

```text
InitialRootClaimRequest (139 bytes)
  uint16 version = 2
  network_id[32]
  account_id[24]
  start_client_request_id[16]
  bootstrap_secret[32]
  uint8 action                       // 1 = read, 2 = choose
  root_fingerprint[32]               // all zero for read

InitialRootState (107 bytes)
  uint16 version = 2
  account_id[24]
  start_client_request_id[16]
  uint8 state                        // 1 = denied, 2 = reserved, 3 = chosen, 4 = published
  root_fingerprint[32]
  initial_object_id[32]
```

The coordinator verifies the authenticated network, original recovery epoch,
currently registered origin's exact account and session generation, start
request ID and constant-time equality of the recomputed bound owner digest
before returning a positive result. The registration must remain current
through durable admission. Treat a missing row, lost right, wrong account,
wrong preimage, differing chosen fingerprint and failed authorization as the
same fixed-size denied state. All four identity and output fields are zero in
a denial. Reserved returns both owner identifiers and zero result fields.
Chosen returns the exact fingerprint and zero object ID. Published returns
the original fingerprint and exact standalone generation-zero object ID,
including after a valid rotation. The state byte controls field presence.
No public logs, audit text, error, counter label, terminal, or federation
plaintext may include the secret, precommit, owner digest or claim status.
The opaque encrypted requests and responses follow the existing retention
and redaction policy. Erase transient cleartext buffers.

A read observes the same serialized authority used for choose and genesis
publication. Only `Reserved -> Chosen(fingerprint)` can select a root.
Choosing the same fingerprint again returns the current Chosen or Published
state. A different choice preserves the existing record. A failure or an
uncertain commit publishes no speculative success. After a disconnect the
client opens a new request for the same account and creation operation, with
a fresh request ID and HPKE exporter, then reconciles the returned state.
An expired federation result cannot reopen a choice.

For the enhanced base federation profile, allocate `claimed_create_start(27)`
and `initial_root_claim(28)`. The former has the parameters and allowed result
kinds of `account_create_start`, using its exact extended HPKE kinds. The
latter has the session ID and envelope parameters of `credential_change_finish`
and returns `failed` on a pre-open transport failure. Its one new result kind
is `initial_root_state(11)`. The result body is exactly the 4,342 bytes of the
sealed response. Its completion event ID and indexed replies are empty. The
edge renders the fixed ACCTROOT response transfer from those bytes. This
same result is used for a protected denial, read or successful choice. Only
these two extended requests and their results use FederationRequest and
FederationResult profile version 2. The binding to the request, exact replay
and finite idempotency quota remain mandatory. The coordinator atomically
records the sealed result, existing one-use response-count increment and any
claim mutation before release.
No auth grant, fresh-auth proof, credential revision change, login or account
creation is produced by a claim read or choose. The registered origin's
current account and generation are independently resolved at the coordinator.

## Directory and recovery

The normal `EKEY PUBLISH IDENTITY` handler validates all original constraints,
including the caller's Account ID, full root signature, predecessor and
canonical object bytes. A guarded account must also be Chosen for the exact
verified generation-zero fingerprint. In one serialized durable decision it
writes the original root object, immutable directory chain, exact initial
object ID, Published claim state and normal committed result. Read, choose and
every origin's publication share this account's synchronization and commit
boundary. A stale precheck cannot enter the directory. An identical transport
retry follows normal result replay. After replay expiry, a claimant can
reconcile Published through a fresh private read and independently verify the
exact public root with the existing root-chain query. A competing root cannot
consume or replace the choice. Later generations use the ordinary verified
continuity path and preserve the initial receipt. Accounts created without a
guard retain their existing directory behavior. No operation can promote a
legacy account to Reserved.

Restore and migration preserve each claim and its permanent publication gate.
Corrupt or absent required data, impossibly mixed directory/claim state, and
a writer that cannot enforce the gate fail closed before serving writes.
Enabling the first guarded account requires an on-disk format fence that an
older coordinator already refuses. Once a change of recovery epoch has been
explicitly accepted, a claim from the previous epoch cannot select a new
fingerprint. Its original Reserved or Chosen restriction continues to block
other roots. An already chosen root can complete ordinary publication of that
same signed object. An already published root remains in its verified
directory lineage. Account deletion and retention follow the existing
deletion controls. They cannot reassign this Account ID to a new claimant.

The SDK must require a positive, freshly authenticated Reserved response
under the exact local pending creation, descriptor, confirmed account,
registered physical profile and private claim before admitting local first
root preparation. Login, an account note, a prior Create receipt or an empty
directory is insufficient. When a creation completion was lost, an explicitly
confirmed login to the same account and the authenticated read can reconcile
the original saved operation and secret. A different or rebound profile
cannot consume it. Prior accepted own-account public authority, an imported
lineage, permanent device choices and the installation account slot continue
to exclude competing setup. The local slot is reserved before root generation.
Fresh reviews, independent protection/reopen, byte-exact possession checks
and storage-owner identity remain client requirements.

Choose follows explicit review of the exact protected descriptor and
successful reopening of its protector. Persist that exact local possible-bind
intent **before** transmission and fence competing setup, cancellation and
key deletion until reconciliation. Reserved after a fresh read permits a retry
of the same intended fingerprint. A fresh read alone cannot prove an earlier
in-flight choose or delayed transmission will never commit. After a possible
choose the SDK conservatively retains the original protected root. A current
Chosen result matching the durable operation permits the separately reviewed
first-root signing workflow. Choosing does not sign, publish or activate any
device. Abandonment before any possible choose or signature follows the
existing protected local retirement rules. The permanent account claim stays
with its creator for a fresh local attempt.

If the only bootstrap secret is lost before choose, the account cannot
automatically establish an initial root. Login, a new installation or
ordinary backup does not replace that right. After choose, possession of
the selected protected root is necessary for its signature. This service
establishes authoritative publication on the named network. It cannot
discover an independently created, unpublished offline identity, establish
freshness after an untrusted rollback or reveal a private root holder.
[ARC-MLS root validation](arc-mls-e2ee-extension.md#82-account-root-and-signatures)

The local caller receives a distinct, actionable outcome when its protected
bootstrap material is unavailable. Retain the account and pending operation
and identify the original installation or previously accepted root as the
recovery dependency. On a changed recovery epoch, report the descriptor
change and the original reservation's suspended status. Even after explicit
descriptor confirmation, a new fingerprint cannot be selected under the old
claim. When the pinned service gives an indistinguishable denial, report an
unavailable reservation. Do not claim to know which private predicate failed.
All three outcomes prohibit issuing fresh authority from this evidence.

## Acceptance

For an encoding control, use homogeneous byte strings `01` for Network ID,
`02` for recovery epoch, `03` for the start request ID, and `04` for the
bootstrap secret, each repeated to its declared width. The Account ID is
`a_BQUFBQUFBQUFBQUFBQUFBQ`, the canonical token for sixteen `05` bytes.
These SHA-256 values cover the exact labeled or encoded inputs above.

| Input | SHA-256 in hexadecimal |
| --- | --- |
| Precommit input | `66294ae222070b29e647d6cc134bbb59166a211f0141bcb0b9c14dcf1f392ad4` |
| Bound owner input | `97998f0500fb162466c3617e9176b3ee6f0440d3bef698fb98b51436cf6ff518` |
| 139-byte read | `42c1b3501ef9c26866e36c336a467207ff974cb93ab669634930213758838b4d` |
| 107-byte reserved state | `95658aafa0ac3735af633e66b690a8b34a023736599e500150524925310b89ba` |

Demonstrate guarded and ordinary creation, both through an authenticated edge
and at the coordinator. Exercise an unmodified legacy client against both
account classes. Show one winner for two choices and for concurrent bare
publication versus choose, including delayed durable admission. Interrupt
creation, confirmation, choose, root publication and replies on both sides
of commit. Reopen both stores, retry from a new origin and recover the same
choice and signed object. Check original-response expiry, wrong network,
recovery epoch, account, profile, secret, operation and fingerprint. Prove
that a present Guarded account with a missing claim fails closed, a missing
account has no genesis authority, a Legacy account still follows its original
path, an older writer refuses protected storage, surviving siblings cannot
issue a second root, and all normal peer lineage and rotation checks still
pass on the real Linux relay. Record independent implementation review and
the actual profile hashes before advertising the capability.
