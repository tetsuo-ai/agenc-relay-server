# ARC-MLS 1.0: End-to-End Encryption for AgenC Relay Chat

Status: design draft 0.5

Date: 2026-08-24
Intended implementation: AgenC Relay Chat clients and AgenC Relay servers

This document is an implementable protocol design, not an RFC, not a claim of
IETF standardization, and not a completed security audit. The cryptographic
core is the standardized Messaging Layer Security protocol. This document
defines the ARC transport, identity, membership, ordering, replay, and
resource policies needed to embed MLS safely in ARC.

Production deployment requires interoperability testing, parser fuzzing,
published test vectors, and the release qualification specified by the
AgenC Relay architecture.

## 1. Abstract

ARC-MLS provides end-to-end encrypted direct conversations and channels over
ARC. An ARC network acts as an untrusted MLS Delivery Service: it routes and
optionally stores ciphertext, but it never receives conversation secrets or
plaintext.

One ARC conversation maps to one MLS group. Each user device is a separate MLS
member. Ordinary messages use one MLS ciphertext regardless of group size;
the server performs normal fanout. Membership changes use MLS TreeKEM updates,
giving forward secrecy and post-compromise recovery without a static shared
channel password.

The design uses:

- MLS 1.0 from RFC 9420 without cryptographic modifications;
- per-account client-owned identity roots and per-device authorization keys;
- distinct MLS signature keys for each device and group;
- IRCv3 capability negotiation, message tags, `TAGMSG`, batches, account tags,
  and standard replies;
- bounded, content-addressed ciphertext fragmentation;
- one active, signed Commit candidate per conversation epoch;
- endpoint-signed Commit processing acknowledgements and Byzantine-quorum
  finality for group-state changes;
- published conversation policies, so the sequencer certifies a terminal only
  after the council quorum has voted for it;
- signed, hash-chained sequencing receipts, witnessed by every edge server,
  for equivocation evidence;
- encrypted-only downgrade protection pinned in MLS group state; and
- strict limits for messages, fragments, reassembly, ratchet advancement,
  skipped keys, KeyPackages, and group operations.

## 2. Conventions and terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and
**OPTIONAL** are to be interpreted as described by BCP 14 when, and only when,
they appear in bold.

The following terms are used throughout:

- **Account**: a stable, authenticated ARC account. It is not a nickname.
- **Account ID**: the immutable, canonical, user-visible identifier for an
account within one ARC network.
- **Device**: one client installation with independent keys and durable MLS
  state.
- **Conversation**: one encrypted ARC channel or one encrypted direct-message
  relationship.
- **Group**: the MLS group protecting one conversation.
- **Delivery Service (DS)**: the ARC network, including federated servers,
  which distributes KeyPackages and ciphertext.
- **Authentication Service (AS)**: the application mechanism that binds
  accounts, devices, and MLS signature keys.
- **Sequencer**: the authoritative server role that orders one active Commit
  candidate at a time for an MLS epoch. It cannot declare that candidate
  cryptographically valid.
- **Root identity key**: a client-generated Ed25519 key that anchors an
  account's cryptographic identity.
- **Device authorization key**: a client-generated Ed25519 key certified by
  the root identity key.
- **Leaf signature key**: a distinct MLS signature key for one device in one
  group.
- **Verified**: the account root and semantic account binding have been
  authenticated out of band. Version 1 does not let an experimental
  key-transparency service confer this state.
- **Unverified**: the root is known only through first-use trust or the relay service.

All multi-byte integers in structures defined by this document use network
byte order. Structures use the TLS presentation language conventions used by
RFC 9420. All hashes named `SHA256` are SHA-256 over the exact encoded bytes
with the stated ASCII domain-separation label. The transport `object-id` is
the sole deliberate exception: it is an ordinary content address over the
complete transported bytes so generic storage can verify it without knowing
the object type.

Every non-MLS signature defined by this document signs the TLS encoding of:

```text
struct {
    opaque label<1..255>;
    opaque content<0..16777215>;
} ArcSignatureInput;
```

`label` is the exact ASCII label stated for that signature, without a trailing
NUL, and `content` is the exact TLS encoding of the named TBS structure.
Signature fields are never part of their own TBS. Root, device-authorization,
and sequencer signatures use Ed25519 and are exactly 64 bytes. Signatures made
with an MLS leaf signature key use the signature scheme and exact encoded
length of the current MLS cipher suite. Native MLS signatures continue to use
RFC 9420 `SignWithLabel`; they are not wrapped in `ArcSignatureInput`.

Ed25519 verification follows RFC 8032 in strict mode: public keys and `R`
values use canonical encodings, `S` is less than the group order, small-order
points are rejected, and permissive legacy verification is not accepted.
Root, device, sequencer, MLS leaf, and TLS keys are independently generated
and never reused across roles. Every value described as random comes from an
operating-system cryptographic random generator; failure to obtain entropy is
fatal, and there is no time-, PID-, or PRNG fallback. A random ID or nonce is
durably reserved before external use when crash replay could duplicate it.

Vectors use the one fixed-width unsigned length prefix implied by their
declared TLS presentation bound (for example, an 8-bit prefix for a maximum
of 255 and a 24-bit prefix for 16,777,215); generic varints and alternate
widths are forbidden. Lists identified as canonical are sorted by the bytewise encoding
of their primary key and reject duplicate keys. A one-byte Boolean accepts
only 0 or 1. Unix times are unsigned seconds. Time values constrain validity
but never choose between competing Commit histories.

### 2.1 Signature registry

The following registry is exhaustive for profile version 1. “Device” means
an Ed25519 device-authorization key; “old leaf” means the MLS signature scheme
of the pre-transition tree. Every row uses `ArcSignatureInput` as specified
above.

| Label | TBS content | Signing key |
| --- | --- | --- |
| `ARC-MLS/1 root identity` | `ArcRootIdentityTBS` | new root |
| `ARC-MLS/1 root continuity` | successor `ArcRootIdentityTBS` | previous root |
| `ARC-MLS/1 device enrollment possession` | `ArcDeviceEnrollmentTBS` | new device |
| `ARC-MLS/1 device enrollment approval` | `ArcDeviceEnrollmentTBS` | root |
| `ARC-MLS/1 device certificate` | `ArcDeviceCertificateTBS` | root |
| `ARC-MLS/1 device roster` | `ArcDeviceRosterTBS` | root |
| `ARC-MLS/1 device capabilities` | `ArcDeviceCapabilitiesTBS` | device |
| `ARC-MLS/1 leaf authorization` | `ArcLeafAuthorizationTBS` | device |
| `ARC-MLS/1 sequencer continuity` | `ArcSequencerCredentialTBS` | previous sequencer |
| `ARC-MLS/1 policy approval` | `ArcPolicyTBS` | device |
| `ARC-MLS/1 conversation binding` | `ArcConversationBindingTBS` | device |
| `ARC-MLS/1 root binding lock` | `ArcRootBindingLockTBS` | root |
| `ARC-MLS/1 commit authorization` | `ArcCommitAuthorizationTBS` | controller device |
| `ARC-MLS/1 reinit attempt authorization` | `ArcReInitAttemptAuthorizationTBS` | controller device |
| `ARC-MLS/1 reservation` | `ArcReservationTBS` | sequencer |
| `ARC-MLS/1 close authorization` | `ArcCloseAuthorizationTBS` | controller device |
| `ARC-MLS/1 device attach challenge` | `ArcDeviceAttachTBS` | sequencer |
| `ARC-MLS/1 device attach possession` | `ArcDeviceAttachTBS` | device |
| `ARC-MLS/1 candidate receipt` | `ArcCandidateReceiptTBS` | sequencer |
| `ARC-MLS/1 commit processed` | `ArcCommitAckTBS` | old leaf |
| `ARC-MLS/1 disposition vote` | `ArcDispositionVoteTBS` | finality device |
| `ARC-MLS/1 commit finalization` | `ArcCommitFinalizationTBS` | sequencer |
| `ARC-MLS/1 candidate abort` | `ArcCommitAbortTBS` | sequencer |
| `ARC-MLS/1 reinit attempt` | `ArcReInitAttemptTBS` | old leaf |
| `ARC-MLS/1 reinit attempt receipt` | `ArcReInitAttemptReceiptTBS` | sequencer |
| `ARC-MLS/1 reinit processed` | `ArcReInitAckTBS` | old leaf |
| `ARC-MLS/1 reinit disposition` | `ArcReInitDispositionVoteTBS` | finality device |
| `ARC-MLS/1 reinit activation` | `ArcReInitActivationTBS` | sequencer |
| `ARC-MLS/1 reinit attempt abort` | `ArcReInitAbortTBS` | sequencer |
| `ARC-MLS/1 recovery submission` | `ArcRecoverySubmissionTBS` | device |
| `ARC-MLS/1 leaf membership` | `ArcLeafMembershipProofTBS` | device |
| `ARC-MLS/1 leaf membership possession` | `ArcLeafMembershipProofTBS` | old leaf |

An implementation **MUST NOT** infer raw-TBS signing for an omitted case. A
future signature adds a new profile version or an explicitly registered label.

### 2.2 Semantic-ID and digest registry

A protocol-state ID is never a hash of a signature, approval vector, vote
vector, proof wrapper, or sequencer certificate. Those bytes are evidence for
an ID, not part of its identity. This prevents two valid quorum subsets for
one decision from creating two successor heads. `object-id` remains the only
transport identifier: it is SHA-256 over the complete encoded `ArcWireObject`
and **MUST NOT** be used as a protocol-state head.

The following registry is exhaustive for every profile-defined in-protocol
semantic ID and security-relevant object/state digest. The transport
`object-id` exception was defined above, and the artifact-level profile digest
is defined separately in Section 2.3; neither is a signed object's semantic
state ID. Every formula hashes the canonical TLS encoding of the named TBS
unless a different input is stated explicitly. In the
Markdown table source, `\|` escapes a column separator and renders as `|`; the
backslash is not part of any hashed input:

| ID or digest | Exact formula |
| --- | --- |
| `root_fingerprint` | `SHA256("ARC-MLS/1 root fingerprint" \|\| encoded_ArcRootDescriptor)` |
| `account_id_digest` | `SHA256("ARC-MLS/1 account id" \|\| TLS-encode(network_id, account_id))` |
| `enrollment_id` | `SHA256("ARC-MLS/1 enrollment id" \|\| encoded_ArcDeviceEnrollmentTBS)` |
| `device_certificate_id` | `SHA256("ARC-MLS/1 device certificate id" \|\| encoded_ArcDeviceCertificateTBS)` |
| `roster_id` | `SHA256("ARC-MLS/1 roster id" \|\| encoded_ArcDeviceRosterTBS)` |
| `capability_id` | `SHA256("ARC-MLS/1 capability id" \|\| encoded_ArcDeviceCapabilitiesTBS)` |
| `leaf_signature_key_digest` | `SHA256("ARC-MLS/1 leaf signature key" \|\| TLS-encode(leaf_signature_scheme, leaf_signature_key))` |
| `leaf_capabilities_digest` | `SHA256("ARC-MLS/1 leaf capabilities" \|\| encoded_LeafNode_capabilities)` |
| `safety_number` | `SHA256("ARC-MLS/1 safety number" \|\| encoded_ArcRootDescriptor)` |
| `conversation_id` | `SHA256("ARC-MLS/1 conversation" \|\| TLS-encode(network_id, group_id))` |
| channel `route_binding` | `SHA256("ARC-MLS/1 channel route" \|\| encoded_ArcChannelRouteTBS)` |
| direct `route_binding` | `SHA256("ARC-MLS/1 direct route" \|\| encoded_ArcDirectRouteTBS)` |
| `policy_id` | `SHA256("ARC-MLS/1 policy id" \|\| encoded_ArcPolicyTBS)` |
| `binding_id` | `SHA256("ARC-MLS/1 binding id" \|\| encoded_ArcConversationBindingTBS)` |
| `root_binding_lock_id` | `SHA256("ARC-MLS/1 root binding lock id" \|\| encoded_ArcRootBindingLockTBS)` |
| `semantic_route_lock_id` | `SHA256("ARC-MLS/1 semantic route lock" \|\| encoded_ArcSemanticRouteTBS)` |
| `sequencer_credential_id` | `SHA256("ARC-MLS/1 sequencer key" \|\| encoded_ArcSequencerCredentialTBS)` |
| `sequencer_key_set_digest` | `SHA256("ARC-MLS/1 sequencer key set" \|\| TLS-encode(credential_ids))` |
| `initial_member_plan_id` | `SHA256("ARC-MLS/1 initial member plan id" \|\| encoded_ArcInitialMemberPlan)` |
| `key_package_plan_id` | `SHA256("ARC-MLS/1 key package plan id" \|\| encoded_ArcKeyPackagePlan)` |
| `context_core_id` | `SHA256("ARC-MLS/1 context core id" \|\| encoded_ArcContextCoreTBS)` |
| `context_digest` | `SHA256("ARC-MLS/1 context hash" \|\| encoded_ArcMlsContext)` |
| `close_intent_id` | `SHA256("ARC-MLS/1 close intent id" \|\| encoded_ArcCloseIntent)` |
| `close_id` | `SHA256("ARC-MLS/1 close authorization id" \|\| encoded_ArcCloseAuthorizationTBS)` |
| `commit_authorization_id` | `SHA256("ARC-MLS/1 commit authorization id" \|\| encoded_ArcCommitAuthorizationTBS)` |
| `genesis_state_id` | `SHA256("ARC-MLS/1 group genesis id" \|\| encoded_ArcGroupGenesisTBS)` |
| `candidate_id` | `SHA256("ARC-MLS/1 candidate id" \|\| encoded_ArcCandidateReceiptTBS)` |
| `group_context_digest` | `SHA256("ARC-MLS/1 group context digest" \|\| encoded_ArcGroupContextDigestTBS)` |
| `ratchet_tree_digest` | `SHA256("ARC-MLS/1 ratchet tree digest" \|\| encoded_ArcRatchetTreeDigestTBS)` |
| `group_info_digest` | `SHA256("ARC-MLS/1 group info digest" \|\| encoded_ArcGroupInfoDigestTBS)` |
| `old_credential_hash` | `SHA256("ARC-MLS/1 old credential hash" \|\| encoded_BasicCredential)` |
| `resulting_leaf_credential_hash` | `SHA256("ARC-MLS/1 resulting leaf credential" \|\| TLS-encode(resulting_leaf_index, encoded_BasicCredential))` |
| `finalization_id` | `SHA256("ARC-MLS/1 finalization id" \|\| encoded_ArcFinalizationCoreTBS)` |
| `abort_id` | `SHA256("ARC-MLS/1 abort id" \|\| encoded_ArcAbortCoreTBS)` |
| `target_context_digest` | `SHA256("ARC-MLS/1 reinit target" \|\| encoded_ArcReInitTargetTBS)` |
| `initial_commit_digest` | `SHA256("ARC-MLS/1 reinit initial commit" \|\| initial_commit_bytes)` |
| `reinit_attempt_authorization_id` | `SHA256("ARC-MLS/1 reinit attempt authorization id" \|\| encoded_ArcReInitAttemptAuthorizationTBS)` |
| `reinit_attempt_id` | `SHA256("ARC-MLS/1 reinit attempt id" \|\| encoded_ArcReInitAttemptTBS)` |
| `reinit_activation_id` | `SHA256("ARC-MLS/1 reinit activation id" \|\| encoded_ArcReInitActivationCoreTBS)` |
| `reinit_abort_id` | `SHA256("ARC-MLS/1 reinit abort id" \|\| encoded_ArcReInitAbortCoreTBS)` |
| `federation_origin_state_id` | `SHA256("ARC-MLS/1 federation origin state" \|\| encoded_ArcFederationOrigin)` |
| `canonical_channel_name_hash` | `SHA256("ARC-MLS/1 canonical channel name" \|\| TLS-encode(canonical_irc_name))` |
| `federation_snapshot_digest` | `SHA256("ARC-MLS/1 federation snapshot" \|\| TLS-encode(state_generation, delivery_generation, ordered_state_object_ids))` |
| `acknowledgement_set_digest` | `SHA256("ARC-MLS/1 commit acknowledgement set" \|\| TLS-encode(canonical_ArcCommitAckTBS_vector))` |
| `reinit_acknowledgement_set_digest` | `SHA256("ARC-MLS/1 reinit acknowledgement set" \|\| TLS-encode(canonical_ArcReInitAckTBS_vector))` |
| `recovery_submission_id` | `SHA256("ARC-MLS/1 recovery submission id" \|\| encoded_ArcRecoverySubmissionTBS)` |
| `leaf_membership_id` | `SHA256("ARC-MLS/1 leaf membership id" \|\| encoded_ArcLeafMembershipProofTBS)` |

Every carried ID is recomputed. Parsed structures consume all input and
re-encode to identical bytes. Two records are the same record exactly when
their kind and semantic ID match; proof wrappers with the same semantic ID are
alternative evidence, not forks. Signatures and thresholds are still checked
independently. A hash collision or two distinct canonical TBS encodings under
one semantic ID is a fatal security error.

For the two proof-set-digest rows, the canonical TBS vectors exclude their
signatures. Each TBS entry has exactly one valid accompanying signature from
its named signer. Duplicate TBS entries or two signatures for one signer are
invalid.

### 2.3 Exact profile revision

The normative version-1 profile document is the exact byte sequence of this
file, `docs/arc-mls-e2ee-extension.md`, in the release source artifact. Those
bytes **MUST** be UTF-8 without a byte-order mark, use LF line endings only,
and end in exactly one LF. Implementations do not normalize Unicode, render
Markdown, rewrite links, add a path, or include archive metadata before
hashing. The negotiated digest is:

```text
arc_mls_profile_hash = SHA256(
    "agenc-chat ARC-MLS specification profile v1\0" ||
    exact_profile_document_bytes
)
```

The `\0` above is one zero byte. On an IRC wire the digest is canonical
unpadded base64url and is therefore exactly 43 characters. A conforming build
embeds the release's computed value as a build-time constant; it does not read
a mutable documentation file at runtime. The raw document SHA-256 and this
domain-separated hash are published in the release manifest and the companion
source-hash table in the daemon architecture specification.

The numeric profile version and `arc_mls_profile_hash` jointly identify the
profile. Any byte change to this document, including an editorial change,
produces a different profile hash and is incompatible until both endpoints
explicitly support that exact revision. References are not recursively hashed.
The hash prevents accidental mixed-revision negotiation; it is not evidence
that a peer implements the document faithfully and does not replace TLS peer
authentication, object validation, or conformance evidence.

The public-evidence revision that added Section 12.5.1 and Sections 13.7.2
through 13.7.5 keeps profile version 1 and changes only this hash. A peer
that presents the previous hash is refused by the exact-match CAP and ECAP
rule of Section 22. Evidence recorded under the previous hash remains valid
historical evidence for that revision; it is never re-admitted or
reinterpreted under this one.

The ReInit-target revision of Section 13.8 also keeps profile version 1 and
changes this hash, although, unlike the revision above, it changes two object
layouts (Section 22). It removes the old-group state ID from
`ArcReInitTargetTBS`: that field named the finalization ID of the very Commit
whose authorization commits the target digest, so no target could be
constructed and no conforming ReInit could complete under the previous hash.
It also carries the target in every `ArcReInitAttempt`, so that the sequencer
checks an attempt against the digest the old ReInit Commit authorized, the
coordinator installs the successor from those bytes at activation, and a later
joiner verifies the same bytes. A ReInit object stored under the previous hash
is never parsed or reinterpreted under this one.

## 3. Goals

ARC-MLS is designed to provide:

1. Message confidentiality and integrity against network observers, IRC
   servers, federation peers, and compromised ciphertext stores.
2. Cryptographic sender authentication to a specific account and device.
3. Forward secrecy when consumed message and epoch secrets are deleted.
4. Post-compromise security after attacker access has ended, compromised
   leaves still controlled by the attacker have been removed, and a Commit
   carrying fresh honest path entropy is finalized and processed.
5. Explicit, reviewable group membership, including every device, bot,
   bridge, logger, or bouncer that can decrypt.
6. Efficient group messaging: one client encryption and one uploaded
   ciphertext, followed by server fanout.
7. Efficient membership changes using the MLS ratchet tree rather than
   encrypting a new channel key separately for every message.
8. Safe operation across ARC federation, reconnects, delayed delivery, and
   netsplits: while the configured finality fault bound and durable-state
   assumptions hold, two conflicting membership histories cannot both obtain
   a valid finality quorum; otherwise clients halt and expose evidence.
9. Compatibility with the IRC message model and the 512-byte non-tag line
   limit.
10. Algorithm agility through MLS version, cipher-suite, and `ReInit`
    mechanisms.

## 4. Non-goals and unavoidable limits

ARC-MLS does not provide:

- availability against a malicious server, which can disconnect, censor,
  delay, or permanently partition users;
- protection after an endpoint is compromised while the attacker retains
  control;
- protection from a legitimate group member copying plaintext;
- anonymity or complete metadata privacy;
- trustworthy first contact when the only identity channel is a malicious
  AgenC Relay server;
- revocation of plaintext or keys already received by an authorized member;
- invisible server-side moderation, search, previews, logging, or bots; or
- post-quantum security in the production version of this profile.

It also does not provide a globally authenticated order or complete censorship
detection for ordinary application messages. Per-sender counters expose some
gaps and replays; the Commit receipt chain authenticates only group-state
sequencing, not the visible chat timeline.

Finality is not magic consensus with no assumptions. Each policy names a
small finality council of `n` device-authorization keys and a Byzantine fault
bound `f`, with `n >= 3f + 1`. For this bound, a key is *faulty* if its holder
is Byzantine or compromised, or if its durable sign-once state can be lost,
rolled back, cloned, or independently restored. Safety requires the total
number of faulty council keys to remain at most `f`; merely retaining one
honest key is not sufficient. Exceeding that bound or compromising the
required policy-controller threshold can authorize a fork. Availability
additionally requires a finality quorum to be online. Version 1 favors a
visible halt over weakening either rule.

AgenC Relay servers continue to observe IP connections, authenticated accounts,
channel and direct-message routing, online membership, public credential and
KeyPackage fields, device counts, directory queries, Welcome references,
group and epoch activity, membership-change timing, ciphertext sizes,
federation paths, and traffic volume. The application finality sidecars also
reveal transition action classes, controller/finality/ACK signer identifiers,
old leaf indices, and result digests. The published policy reveals the
membership policy kind, the suite choice, the controller roots, the finality
council (root fingerprint, Device ID, and certificate ID of every principal),
and the fault bound to every server that retains the conversation. The server
already sees rosters and device attachments, so the added exposure is which
devices hold council and controller roles. Private MLS handshake messages still
hide Proposal bodies, target credentials, path secrets, and the resulting
group secrets, but do not hide ARC channel membership from the IRC
infrastructure. TLS is still required on every client-server and server-server
connection.

## 5. Threat model

The attacker may:

- control the network and any subset of ARC delivery or federation servers;
- read, inject, alter, replay, suppress, delay, and reorder IRC frames;
- provide stale KeyPackages or inconsistent directory answers;
- strip IRC capabilities or falsely claim that encryption is unavailable;
- present different conversation bindings or Commit histories to different
  users;
- control an ARC account database and create arbitrary server-authenticated
  accounts; and
- join an encrypted conversation legitimately and then behave maliciously.

The attacker may also control the sequencer signing key. Sequencer signatures
therefore provide ordering evidence and availability coordination, but global
non-equivocation for group-state transitions comes from intersecting endpoint
quorums, not from trusting that key to sign only once. An honest sequencer
additionally refuses to certify a terminal below the published quorum, and
every edge server witnesses the record chain it projects, so a sequencer that
signs below quorum or forks the chain produces public evidence at the first
honest edge. Endpoints never rely on that refusal for safety.

The attacker initially does not possess:

- private keys of an uncompromised, verified account root;
- private keys of uncompromised device or MLS leaf keys;
- current MLS group secrets held only by uncompromised members; or
- plaintext that a legitimate member has not disclosed.

Once an endpoint is fully compromised, the attacker can read that endpoint's
plaintext and act as it. Recovery requires all of the following: attacker
access to the relevant private state has ended; any leaf or credential still
controlled by the attacker has been removed; an honest member creates a
Commit with a populated UpdatePath containing entropy unavailable to the
attacker; the profile's finalization rule completes; and obsolete secrets are
deleted. An update cannot recover confidentiality while an attacker remains a
legitimate member.

### 5.1 Trust states

Clients **MUST** distinguish these states in their UI and policy:

| State | Meaning |
| --- | --- |
| Unverified encrypted | MLS protects against passive observers and a DS that does not substitute the first identity root. First-contact server impersonation remains possible. |
| Verified encrypted | Every required account, network, and root-key binding has been authenticated out of band. A server cannot silently replace a pinned root. |
| Transparency observed | An experimental transparency deployment supplied currently acceptable proofs. This is distinct from Verified in version 1. |
| Security changed | A root, device set, group binding, required capability, suite, policy, or Commit chain changed unexpectedly. Sending is blocked pending review. |

The UI **MUST NOT** represent unverified encryption with the same assurance as
verified encryption.

## 6. Architecture

The cryptographic endpoint is the client device. The ARCD is not an MLS
member and holds no group secret.

```text
client device ── TLS ── AgenC Relay server/federation ── TLS ── client device
     │                        │                            │
     └──── MLS ciphertext ────┴──── opaque fanout ────────┘

account root
    └── device authorization key
            └── per-group MLS leaf signature key
```

The server has four application roles:

1. Authenticate the IRC connection to an Account ID.
2. Store and atomically dispense one-use MLS KeyPackages.
3. Route complete MLS objects to a channel, direct conversation, or device
   mailbox.
4. Linearize Commit messages for each conversation and issue signed receipts.
5. Retain each conversation's published policy chain and certify a
   finalization, abort, or ReInit terminal only after the old policy's
   finality quorum has voted for it.
6. Witness, at every edge server, that the sequencer record chain of each
   projected conversation extends without forks.

The client has all cryptographic roles:

1. Generate and protect account, device, KeyPackage, and group secrets.
2. Authenticate identity chains and apply local trust policy.
3. Create, join, update, and remove members from MLS groups.
4. Encrypt, decrypt, replay-check, pad, and persist state transactionally.
5. Verify group context, membership policy, sequencer receipts, and downgrade
   state independently of the server.

## 7. Cryptographic profile

### 7.1 Transport security

Every client-server and server-server hop carrying ARC-MLS **MUST** use TLS 1.3
as specified by RFC 9846, with certificate and service-identity validation
under RFC 9525. Deployments
follow RFC 9325, as updated by RFC 9852, for algorithm and operational policy.
Plain IRC and
opportunistic TLS are not valid transports for this profile.

Federation TLS is mutually authenticated: each peer proves a configured
certificate-bound server identity in both directions, and that identity must
match the AgenC Relay server route used by ECAP. A client connection authenticates the
server before account login; its later Account-ID authentication and device
attachment are separate application checks. Anonymous TLS, certificate
warning bypass, and unauthenticated resumption never carry ARC-MLS.

TLS early data **MUST NOT** carry `CAP`, `EGROUP`, `EKEY`, encrypted `TAGMSG`,
`EDIRECT`, or any other state-changing ARC-MLS operation because early data is
replayable. E2EE does not remove the need for authenticated transport: TLS
limits metadata exposure to intermediate networks and protects non-MLS IRC
control traffic.

### 7.2 MLS and HPKE

Clients **MUST** implement MLS 1.0 exactly as specified by RFC 9420 and its
applicable verified errata. HPKE behavior is inherited from RFC 9180. This
profile does not define a new ratchet, KDF, KEM, AEAD, signature scheme, or MLS
cipher suite.

Implementations **MUST** use a maintained MLS library with published
interoperability-vector support. Implementations **MUST NOT** implement the cryptographic primitives
or MLS state machine ad hoc inside the IRC parser.

### 7.3 Cipher suites

| MLS value | Name | ARC-MLS requirement |
| --- | --- | --- |
| `0x0001` | `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` | **MUST** implement; interoperable default |
| `0x0003` | `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` | **MUST** implement; fixed alternative where ChaCha20 is faster than AES-GCM |
| `0x0004` | `MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448` | **MUST NOT** be enabled in version 1 |

Suite `0x0001` is the MLS 1.0 mandatory-to-implement suite. It already targets
approximately 128-bit security and is the correct default for strong,
interoperable, fast chat. Suite `0x0004` has larger keys, signatures, messages,
and CPU cost; it is not automatically safer against the dominant risks of
endpoint compromise or identity substitution.
The version-1 account/device hierarchy is Ed25519, so suite `0x0004` does not
raise the profile's end-to-end authentication strength above that hierarchy;
clients must not market it as a uniform 256-bit security mode.

Suite `0x0001` is the unconditional version-1 creation default. The default
ordered policy vector is exactly `[0x0001, 0x0003]`. A user-approved policy may
instead order `0x0003` first for a measured platform preference, but the vector
is a nonempty duplicate-free subset of exactly those two values and must retain
`0x0001` as an interoperability fallback. Suites `0x0001` and `0x0003` have the
same nominal security level; their ordering is a performance choice, not a
security ranking. A signed conversation policy **MUST** contain that exact
ordered `allowed_suites` vector and the selected suite. Before group initialization, the creator retrieves
non-consuming, device-signed capability documents for every intended initial
device and selects the first policy entry supported by all of them. Directory
withholding causes creation to fail; it never silently changes the selection.

For every later Add, the KeyPackage's top-level MLS version and cipher suite
**MUST** equal the current GroupContext, in addition to satisfying MLS
capability checks. The suite is fixed for the group. Changing it requires the
complete `ReInit` procedure in Section 13.8 and an explicit user-visible
security transition. Moving to a later policy preference or removing a suite
from the signed policy is treated as a downgrade-sensitive transition even
when both suites target the same security level.

Suite `0x0004`, every other registered suite, and custom/private-use cipher
suites **MUST NOT** be enabled in the version-1 production profile. Adding one
requires a new profile version, complete server/client verification support,
new size proofs and vectors; accepting
an opaque unknown suite because the server does not hold MLS secrets is
forbidden.

### 7.4 Handshake privacy

After group creation, Proposals and Commits **MUST** be sent as MLS
`PrivateMessage` objects. The outer MLS header remains visible as required for
routing and sequencing, but the membership proposal contents remain encrypted.

Version 1 Commits **MUST** carry every Proposal inline. Commits containing a
proposal by reference are invalid under this application profile. No
standalone MLS Proposal is sent at all. A UI may exchange an MLS-authenticated
encrypted preview or consent notice as ordinary application data, but that
notice has no MLS semantics or authority; the eventual committer
constructs and signs the inline Proposal independently. Update Proposals are
disabled, so path-secret rotation uses a self-Commit with a populated
UpdatePath.

External senders and external joins are disabled in profile version 1. A new
member is added by an existing authorized member using a one-use KeyPackage
and a normal Add Commit.

### 7.5 Padding

Padding is applied to the application content before MLS encryption, not to
the MLS `PrivateMessageContent`, because no independent MLS implementation
exposes exact control over the RFC 9420 padding field. Every
`ArcEncryptedContent` (Section 10) ends in a `zero_padding` vector. Let `L` be
the complete TLS encoding length of the `ArcEncryptedContent` with an empty
`zero_padding` vector, including that vector's own two length bytes. If
`L <= 4096`, the target is the least multiple of 256 no smaller than `L`;
otherwise it is the least multiple of 1024 no smaller than `L`. The sender
fills `zero_padding` with exactly `target - L` zero octets so that the complete
encoding is exactly `target` bytes. Checked arithmetic is used before
allocation. If the resulting `PrivateMessage` or containing typed object would
exceed its command-specific maximum, the content is too large and is rejected
before encryption; the sender never omits or shortens padding to make it fit.

The receiver decodes the `ArcEncryptedContent`, computes `L` as the encoded
length minus the padding octets, computes the same target with checked
addition and division before comparing lengths, and rejects a padding length
other than `target - L`, any nonzero padding octet, arithmetic overflow,
trailing bytes after the structure, or a complete outer object above its fixed
limit. Zero padding bytes are required when `L` is already on a bucket
boundary; an implementation must not add a second full bucket. MLS-level
padding inside `PrivateMessageContent` is left to the MLS library, is not
constrained by this profile, and is never inspected. These are the mandatory
boundary vectors:

| `L` | target | zero padding bytes |
| ---: | ---: | ---: |
| 1 | 256 | 255 |
| 255 | 256 | 1 |
| 256 | 256 | 0 |
| 257 | 512 | 255 |
| 4,095 | 4,096 | 1 |
| 4,096 | 4,096 | 0 |
| 4,097 | 5,120 | 1,023 |
| 5,119 | 5,120 | 1 |
| 5,120 | 5,120 | 0 |

Handshake messages and Commits are not padded by this profile; their sizes
are bounded public objects. Padding reduces exact-length leakage but does not
hide timing, participant sets, traffic direction, or broad size classes.
Implementations **MUST NOT** describe padding as anonymity.

### 7.6 Compression

Plaintext compression before encryption is forbidden in version 1. It creates
length side channels and complicates decompression bounds. ARC-MLS object and
fragment bytes are not compressed above TLS on client or federation links;
ciphertext is effectively incompressible, and a second decompression parser
adds resource-exhaustion risk without useful bandwidth savings.

### 7.7 Post-quantum position

As of this draft, MLS integration for ML-KEM and hybrid post-quantum suites is
still an IETF Internet-Draft, not an RFC. ARC-MLS 1.0 therefore makes no
post-quantum claim.

Clients **MUST** preserve algorithm agility and `ReInit` support so groups can
migrate once a final RFC and audited implementations exist. Experimental PQ
profiles, if built, **MUST** be separately named, explicitly enabled, pinned
against downgrade, and described only by the precise confidentiality and
authentication properties they actually provide.

## 8. Identity, devices, and credentials

MLS requires the application to authenticate credentials. Server account
authentication alone is insufficient against a malicious operator. The global
signature and canonical-encoding rules in Section 2 apply to every structure
below.

### 8.1 Stable account identity

The Account ID **MUST** be immutable, canonical, and visible during security
verification. In this profile it is exactly the 24 ASCII bytes of the daemon's
`a_` plus 22-character canonical base64url `AccountRandomId`, assigned at
account creation and never recycled or reassigned within that `network_id`,
even after account deletion. The `opaque<1..255>` fields retained in the TLS
structures are encoding envelopes; a version-1 semantic decoder requires
exactly 24 bytes whenever an Account ID is present. Comparison and sorting use
those exact bytes, not IRC case mapping. Alternate encodings are rejected. A
nickname, user/host mask, mutable display label, or current server is not an
Account ID.

The server **MUST** return the same Account ID to all authenticated sessions.
Clients display nicknames only as mutable aliases alongside the authenticated
Account ID.

### 8.2 Account root and signatures

The account owner generates an Ed25519 root identity key locally. The private
key **MUST NOT** be generated, received, escrowed, or recoverable by the relay service, and **SHOULD** remain in dedicated recovery storage rather than on
every chat device.

```text
struct {
    uint16 profile_version;              // 1
    opaque network_id[32];
    opaque account_id<1..255>;
    uint64 root_generation;
    opaque root_public_key[32];
    uint64 not_before;
    uint64 not_after;
    opaque previous_root_fingerprint[32];
} ArcRootIdentityTBS;

struct {
    ArcRootIdentityTBS tbs;
    opaque self_signature[64];
    opaque continuity_signature<0..64>;
} ArcRootIdentity;
```

The self-signature label is `ARC-MLS/1 root identity`. For generation zero,
the previous fingerprint is all zero and the continuity signature is empty.
Every successor increments generation by exactly one. For every later
generation, `continuity_signature` is an old-root signature over the same TBS
with label `ARC-MLS/1 root continuity`, and has length 64.
Any other encoding is invalid.

The semantic descriptor and fingerprint are:

```text
struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque account_id<1..255>;
    uint64 root_generation;
    opaque root_public_key[32];
    uint64 not_before;
    uint64 not_after;
    opaque previous_root_fingerprint[32];
} ArcRootDescriptor;

SHA256("ARC-MLS/1 root fingerprint" || encoded_ArcRootDescriptor)
```

The descriptor repeats every root TBS field, so its fingerprint cannot be
silently moved to a different network or Account ID, assigned another
validity interval, or detached from its predecessor. It contains no signature.
Every root requires `not_before < not_after`; a root used for a candidate must
cover its canonical validation time. A successor's `not_before` lies within
the predecessor's validity interval and never precedes the predecessor's
`not_before`. A new root without valid continuity is an identity discontinuity
and requires a new verification, not routine recovery.

A continuous root rotation issues a new complete roster and new device
certificates under the new root, then uses Section 13.8 to replace credentials
in every group. Version 1 does not mix certificates from two root generations
inside one roster or rotate the application root through an ordinary leaf
Update. Affected conversations show and pin the transition until ReInit
finishes.

### 8.3 Device enrollment and certificates

Each device generates an independent Ed25519 authorization key and random
128-bit Device ID. Only the account root may authorize a version-1 device;
ordinary device keys cannot mint peer devices. Enrollment uses:

```text
struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque account_id<1..255>;
    uint64 root_generation;
    opaque root_fingerprint[32];
    uint64 target_roster_generation;
    opaque enrollment_challenge[32];
    opaque device_id[16];
    opaque device_authorization_key[32];
    uint64 issued_at;
    uint64 expires_at;
} ArcDeviceEnrollmentTBS;

struct {
    ArcDeviceEnrollmentTBS tbs;
    opaque new_device_signature[64];
    opaque root_signature[64];
} ArcDeviceEnrollment;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque account_id<1..255>;
    uint64 root_generation;
    opaque root_fingerprint[32];
    opaque device_id[16];
    opaque device_authorization_key[32];
    uint64 target_roster_generation;
    opaque enrollment_challenge[32];
    opaque enrollment_id[32];
    uint64 certificate_serial;
    uint32 authorization_flags;
    uint64 not_before;
    uint64 not_after;
} ArcDeviceCertificateTBS;

struct {
    ArcDeviceCertificateTBS tbs;
    ArcDeviceEnrollment enrollment_proof;
    opaque root_signature[64];
} ArcDeviceCertificate;
```

The root holder creates the 32-byte enrollment challenge and displays the
exact network, account, target roster generation, Device ID, and device-key
fingerprint for explicit user confirmation. The new device first proves
possession by signing the enrollment TBS with label
`ARC-MLS/1 device enrollment possession`; the root then signs the same TBS
with label `ARC-MLS/1 device enrollment approval`. `enrollment_id` is the
Section 2.2 TBS-only ID. The
certificate copies the root generation, target roster generation, challenge,
Device ID, device key, account, network, and root fingerprint exactly from
`enrollment_proof`, and binds that proof's recomputed TBS-only ID. Its root
signature uses label `ARC-MLS/1 device certificate`.

`issued_at <= expires_at` and
`expires_at - issued_at <= ENROLLMENT_CHALLENGE_TIMEOUT`. The challenge
is consumed exactly once in the named target roster generation. Verifiers
require both embedded enrollment signatures, exact field equality, and the
certificate-to-enrollment ID. The target roster's `not_before` value, rather
than every later Commit validation time, must lie in the enrollment interval;
the enrollment is a short-lived issuance authorization, not the device
certificate's lifetime. The certificate itself requires
`not_before <= roster.not_before <= roster.not_after <= not_after`, and its
`not_after` may not exceed the root identity's `not_after`. Every later use
checks the certificate and roster intervals against the candidate's canonical
validation time. A client rejects a challenge, Device ID, certificate serial,
or target generation already used under that root.
The enrollment root generation and fingerprint must equal the supplied
`ArcRootIdentity`; the certificate repeats both and the target roster repeats
them again. Root generation zero may target initial roster generation zero.
Every later new-device enrollment targets exactly the next roster generation
after the client's pinned head. None of these values is inferred from mutable
directory state.
Threshold or delegated enrollment is a future extension, not an implicit
version-1 option.

In `authorization_flags`, bit 0 authorizes new conversation bindings and bit 1
authorizes policy/controller approvals. All other bits are zero in version 1;
an object setting an unknown bit is invalid. Neither bit authorizes device
enrollment, root rotation, or roster signing.

### 8.4 Complete device roster and revocation

Individual certificates are not sufficient revocation state. Every root
therefore signs a complete, monotonic roster:

```text
struct {
    opaque device_id[16];
    ArcDeviceCertificate certificate;
} ArcActiveDevice;

struct {
    opaque device_id[16];
    uint64 certificate_serial;
    uint64 revoked_in_generation;
    uint16 reason_code;
} ArcDeviceRevocation;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque account_id<1..255>;
    uint64 root_generation;
    opaque root_fingerprint[32];
    uint64 roster_generation;
    uint64 not_before;
    uint64 not_after;
    opaque previous_roster_id[32];
    ArcActiveDevice active_devices<0..65535>;
    ArcDeviceRevocation revocations<0..65535>;
} ArcDeviceRosterTBS;

struct {
    ArcDeviceRosterTBS tbs;
    opaque root_signature[64];
} ArcDeviceRoster;
```

Both vectors are canonical by Device ID; `(Device ID, certificate_serial)` is
unique. The outer Device ID must equal the certificate's Device ID, and every
certificate network, account, root generation, and fingerprint must equal the
roster. No two active entries may contain the same device-authorization public
key, even under different Device IDs. When multiple account rosters are
validated for one binding or group, their active device-authorization keys
must also be pairwise distinct across roots and Account IDs. A repeated key
invalidates the proof and can never count twice toward a controller, binding,
bootstrap, or finality threshold. `active_devices` is the complete active set, not a delta. A device is
authorized only when its exact certificate appears in the highest accepted
roster. Absence means revoked even if an old certificate has not expired.
Revocation entries are append-only within a root generation and are not
silently compacted; approaching the vector bound requires a continuous root
rotation and group ReInit.
The roster signature label is `ARC-MLS/1 device roster`; its `roster_id` is
defined in Section 2.2 over the roster TBS. The root signature is mandatory
evidence but does not change that ID.

Clients persist the highest generation and ID per root. A lower generation
is rollback; two valid different IDs at one generation prove root
equivocation. Roster generation zero uses an all-zero predecessor; every
successor increments by one and names the previous accepted ID. Roster
validity is at most `MAX_ROSTER_LIFETIME` and a roster used for an Add must
have been issued no more than `MAX_ROSTER_AGE_AT_ADD` before the Commit's
canonical validation time.
A server can still suppress a newer root-signed revocation until the pinned
roster expires; out-of-band verification or a future witnessed transparency
profile is required to detect that suppression sooner. Once a newer roster is
known, it **MUST** be carried in the same Commit as all resulting Removes, as
specified in Section 9.3.

An expired roster cannot authorize an Add, policy approval, binding, or new
ordinary Commit ACK. There is one narrow recovery exception: an old leaf whose
certificate is named in the expired roster may authenticate a
`roster_recovery` candidate only when that candidate (a) installs a continuous
unexpired successor roster in the committed context, (b) changes no policy,
binding, suite, sequencer, or membership except removing devices absent from
that successor, (c) performs no Add, and (d) includes a populated UpdatePath.
The old leaf is checked against both the expired predecessor and the resulting
successor; a removed target may authenticate only the public removal path.
Every other authorization check uses the resulting unexpired roster. This
exception cannot extend an old roster or authorize ordinary sending.
Within that one candidate, the unchanged old leaf may produce a processing ACK
and the old policy's unchanged finality device may produce a disposition vote;
neither signature is valid for any other authorization rule or action-bit set.

In Verified mode, application sending pauses after the bounded
`ROSTER_STALE_SEND_GRACE` unless a fresh successor is obtained or the stale
account is removed. This deliberately makes strong revocation freshness cost
periodic root-signed roster renewal; a deployment that relaxes it must narrow
its stale-device claim.

### 8.5 Device capabilities and non-circular leaf authorization

Suite negotiation uses a non-consuming signed object:

```text
struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque account_id<1..255>;
    opaque root_fingerprint[32];
    uint64 roster_generation;
    opaque roster_id[32];
    opaque device_id[16];
    uint64 capability_generation;
    opaque previous_capability_id[32];
    uint64 not_before;
    uint64 not_after;
    ProtocolVersion versions<2..32>;
    CipherSuite cipher_suites<2..64>;
    ExtensionType extensions<0..128>;
    ProposalType proposals<0..128>;
    CredentialType credentials<2..32>;
} ArcDeviceCapabilitiesTBS;

struct {
    ArcDeviceCapabilitiesTBS tbs;
    opaque device_signature[64];
} ArcDeviceCapabilities;
```

Vectors are canonical, duplicate-free numeric sets; policy preference lives in
`ArcPolicy`, not their order. The signature label is
`ARC-MLS/1 device capabilities`. A capability object is valid only for the
same highest roster in which the signing device is active. Its `capability_id`
is defined in Section 2.2.
Generation zero has an all-zero predecessor. Every successor increments by
one, names the previously accepted ID, and has a validity interval no longer
than `MAX_CAPABILITY_LIFETIME`. Clients durably pin the highest generation and ID per
device; rollback, a gap, or two IDs at one generation is a security error.
The exact initial capability-object IDs used for suite selection are bound
into the initial conversation authorization in Section 9.4.

On true first contact a malicious directory can suppress a newer capability
object without detection until another trusted channel reveals it. A policy
that requires a minimum suite therefore names that suite with no fallback;
"prefer strong when advertised" is not a downgrade-resistant first-contact
rule.

Every normal KeyPackage uses a fresh MLS leaf signature key and a fresh random
32-byte `package_nonce`. The device signs this group-independent authorization:

```text
struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque account_id<1..255>;
    uint64 root_generation;
    opaque root_fingerprint[32];
    uint64 roster_generation;
    opaque roster_id[32];
    opaque device_id[16];
    uint64 credential_generation;
    ProtocolVersion mls_version;
    CipherSuite cipher_suite;
    SignatureScheme leaf_signature_scheme;
    opaque leaf_signature_key<1..255>;
    opaque leaf_capabilities_hash[32];
    opaque package_nonce[32];
    uint8 last_resort;                   // MUST be 0 in profile version 1
    uint64 not_before;
    uint64 not_after;
} ArcLeafAuthorizationTBS;

struct {
    ArcLeafAuthorizationTBS tbs;
    opaque device_signature[64];
} ArcLeafAuthorization;

struct {
    ArcRootIdentity root;
    ArcDeviceCertificate device_certificate;
    ArcLeafAuthorization leaf_authorization;
} ArcCredentialBundle;
```

The signature label is `ARC-MLS/1 leaf authorization`.
`BasicCredential.identity` contains the exact `ArcCredentialBundle`. The
authorization deliberately contains neither a future `group_id` nor a hash
of the KeyPackage that contains it; either would make offline publication
impossible or self-referential. The MLS KeyPackage signature already
authenticates the complete KeyPackage, including `init_key` and LeafNode.

Every profile KeyPackage carries the RFC 9420 `lifetime` extension. Its
`not_before` and `not_after` equal the leaf authorization fields exactly,
require `not_before < not_after`, and span at most
`MAX_KEY_PACKAGE_LIFETIME`. `EKEY PUBLISH PACKAGE` repeats that exact
`not_after` as `expires-at`; a mismatch, publication outside the interval, or
an authorization/certificate/roster that does not cover the interval is
rejected. A server never extends these signed times.

Version 1 requires `credential_generation = 0`. Every KeyPackage and ReInit
creator uses a fresh leaf signature key, and a device **MUST NOT** authorize
the same leaf key twice or reuse it in another group. The field is retained for
future profiles that may define in-place credential lineages; inventing a
per-device global counter would make independently published one-use packages
order-dependent and is therefore forbidden here.
Devices keep a durable set of issued Section 2.2 leaf-key digests for the
lifetime of their authorization key; encountering the same digest under two
authorizations is a fatal reuse error.

A receiver validates the embedded root, device certificate, leaf
authorization, the exact root-signed roster proof named by its generation and
ID, lifetime, suite, version, exact LeafNode signature key, and
`SHA256("ARC-MLS/1 leaf capabilities" || encoded_LeafNode_capabilities)`. It also verifies the
normal RFC 9420 KeyPackage signature and `KeyPackageRef`. The KeyPackage
top-level version and suite must equal the authorization and, for an Add, the
current group. Credential bundles larger than `MAX_CREDENTIAL_BUNDLE` are
invalid.

Profile version 1 deliberately forbids reusable MLS last-resort KeyPackages:
`last_resort` **MUST** be zero and the RFC 9420 `last_resort` extension must be
absent. A server may reserve an emergency stock of ordinary packages, but each
such package is still atomically claimed once and then burned. This removes a
cross-group replay exception from the initial profile.

The roster is deliberately not duplicated inside every ratchet-tree leaf. A
KeyPackage claim is used only after fetching that exact roster, every Add
Commit carries it once as the inline roster proposal in Section 9.3, and every
Welcome carries it in `ArcJoinAuthBundle`. Missing roster bytes make a
candidate pending or blocked, never locally skippable. This keeps large group
trees compact without trusting directory delivery.

The device transactionally records `(package_nonce, KeyPackageRef, group_id,
conversation_id)` before accepting a Welcome. Reuse for a different binding
is rejected and reported. A malicious directory can replay bytes but cannot
make the device accept the package into two groups. The Add atomically records
the new leaf in the context's sole `pending_joins` entry until its mandatory
join-confirmation self-Commit finalizes; members never infer successful joining
merely from an Add.

The Add's authenticated Commit transcript, resulting GroupContext, candidate
receipt, finalization certificate, and referenced Welcome together bind the
otherwise group-independent package to this exact group. The Welcome mailbox
metadata includes the finalization ID, and the joiner verifies that complete
binding before recording consumption.

In-group Update Commits retain the same leaf signature key and credential in
version 1. Rotating that key requires remove-and-readd or `ReInit`. Different
Device IDs belonging to one account remain distinct MLS clients.

The initial group creator uses the same authorization format and
transactionally consumes its fresh `package_nonce` locally for the new group,
but does not upload or claim a KeyPackage for itself. Other members validate
its authorization, roster, exact LeafNode key, capabilities hash, version, and
suite from the ratchet tree; KeyPackage-only checks naturally do not apply.

Two MLS credentials represent the same client exactly when validated chains
resolve to the same `(network_id, account_id, continuous root identity,
device_id)`. Credential and leaf-key generations may differ without creating
a new client. A different Device ID is a different client. A root
discontinuity is a different identity. This deterministic equivalence rule is
used for Add validation, duplicate rejection, and ReInit membership checks;
UI trust state and local wall-clock skew never choose a competing Commit.

### 8.6 First use and verification

On first contact, a client may pin a root using trust on first use, but it
**MUST** mark the identity unverified. The safety-number and QR input is:

```text
SHA256("ARC-MLS/1 safety number" || encoded_ArcRootDescriptor)
```

The UI displays the network and Account ID beside the number. A pairwise QR
contains both descriptors sorted by `(network_id, account_id)` so a valid key
cannot be verified under the wrong semantic identity.

An unexpected root change blocks encrypted sending by default, retains the
old pin, displays both descriptors, and requires either a valid continuity
chain or a fresh out-of-band verification. Server-side account recovery never
silently resets trust. A verified direct conversation refuses an unverified
replacement root or device roster without explicit approval.

### 8.7 Key transparency

Key transparency is informative in version 1 because the IETF work remains in
progress. An experimental client records a separate `transparency observed`
state; it **MUST NOT** convert that state to Verified.

A future normative profile must name its log format, inclusion and consistency
proofs, maximum proof age, monitor behavior, persistent tree-head storage,
gossip or independent witnesses, and state-loss recovery. A log operated only
by the same malicious relay service cannot prevent a permanent split view
without those mechanisms.

## 9. Conversation identity, policy, and group binding

### 9.1 Identifiers and route binding

- `network_id` is a random 32-byte value created with the ARC network and
  shared by every federation server. Clients pin it in network configuration;
  it is not derived only from a mutable hostname. It is durable and
  rollback-protected; replacing it creates a visibly new cryptographic network
  that requires verification rather than inheriting old pins.
- `group_id` is exactly 32 fresh random bytes generated for one MLS group. It
  **MUST NOT** be reused; the variable-length RFC 9420 encoding still carries
  those 32 bytes.
- `conversation_id` is
  `SHA256("ARC-MLS/1 conversation" || TLS-encode(network_id, group_id))`.
- `channel_instance_id` is a random 16-byte value allocated when a channel is
  created. Destroying and recreating a name creates a new instance.
- `conversation_nonce` is a random 32-byte value generated by the coordinator
  in a direct reservation and used once. It distinguishes concrete MLS groups
  but is deliberately excluded from the semantic route-lock namespace.

Version 1 deliberately narrows encrypted channel names to a portable ASCII
profile: `#` followed by 1 through 63 ASCII letters, digits, `.`, `_`, `-`, or
`+`. The canonical name maps `A` through `Z` to lowercase and otherwise
preserves the bytes. A server enables the extension only when this canonical
name resolves to the same channel under its network-wide IRC casemapping; all
federation peers use the same rule. Names outside this subset, non-UTF-8 byte
aliases, and alternate spellings are ordinary IRC names but cannot be bound by
profile version 1. `canonical_channel_name` is this 2-to-64-byte result for a
channel and empty for a direct conversation.

For a channel, `route_binding` is:

```text
struct {
    opaque network_id[32];
    opaque channel_instance_id[16];
} ArcChannelRouteTBS;

SHA256("ARC-MLS/1 channel route" || encoded_ArcChannelRouteTBS)
```

The current channel name is display and routing metadata. A supported rename
preserves its instance ID. For a direct conversation it is:

```text
struct {
    opaque network_id[32];
    opaque conversation_nonce[32];
    opaque account_id_a<1..255>;
    opaque account_id_b<1..255>;
} ArcDirectRouteTBS;

SHA256("ARC-MLS/1 direct route" || encoded_ArcDirectRouteTBS)
```

where Account IDs are in canonical bytewise order. Binary IRC parameters use
unpadded base64url. Account IDs use base64url `account-token` parameters so
Unicode, spaces, case mapping, and delimiters cannot alter command parsing.
The semantic anti-fork route is the separately signed
`ArcSemanticRouteTBS` in Section 9.4; neither a server-chosen channel instance
nor this fresh nonce can create another semantic lock slot.

### 9.2 Sequencer credential

The sequencer has a dedicated Ed25519 key, independent of TLS keys:

```text
struct {
    uint16 profile_version;
    opaque network_id[32];
    uint64 key_generation;
    opaque sequencer_public_key[32];
    uint64 not_before;
    uint64 not_after;
    opaque previous_key_id[32];
} ArcSequencerCredentialTBS;

struct {
    ArcSequencerCredentialTBS tbs;
    opaque continuity_signature<0..64>;
} ArcSequencerCredential;
```

Its `sequencer_credential_id` (also called its key ID on the wire) is
`SHA256("ARC-MLS/1 sequencer key" || encoded_ArcSequencerCredentialTBS)`.
Generation zero has an all-zero previous ID and empty signature. Later
credentials increment generation by exactly one, name the exact previous key
ID, and require that previous sequencer key's 64-byte signature with label
`ARC-MLS/1 sequencer continuity`. Every interval has
`not_before < not_after`; the new `not_before` lies within the old interval,
and a receipt key must cover the Commit's canonical validation time.

Version 1 uses one logical sequencer credential per ARC network and separate
logs per conversation. The service may be replicated or sharded internally,
but every shard produces one continuous signed record namespace under that
credential. An individual edge ARCD does not invent a replacement key during
failover.

The federation key set contains at most the current credential and its direct
successor, sorted by generation. Its monotonic set generation and
`SHA256("ARC-MLS/1 sequencer key set" || TLS-encode(credential_ids))` are
the ECAP values. Overlap ends after every live group transitions or
`MAX_SEQUENCER_KEY_OVERLAP`, whichever comes first; a group still pinned to the retired key then
blocks rather than accepting receipts under another key.

Initial trust does not come from the server: the exact credential ID is
covered by the conversation binding approvals below. Rotation requires both a
valid old-key continuity signature and a finalized, old-policy-authorized
GroupContextExtensions transition. Old receipts use the old key through that
transition; later receipts use the new key. The federation may advertise an
overlapping old/new key set during a bounded migration, but each conversation
accepts only the one credential pinned in its current context. Sequencer signatures are evidence
of what one server key said, not proof that its ordering is truthful or
available.

#### 9.2.1 Signer roles, transition, retirement, and release

Credential identity is `sequencer_credential_id`. Two credentials that share
one `sequencer_public_key` are distinct credentials, a successor **MUST NOT**
reuse the active credential's public key, and membership in the advertised
ECAP key set is a separate fact from credential identity: a set that names a
credential neither proves possession of its private key nor changes any
conversation's pin. The per-conversation pin is the `sequencer` credential of
the conversation's current accepted `ArcMlsContext`. The finalized transition
instant of a conversation is the finalization certificate of the
GroupContextExtensions Commit whose resulting context names the successor.
That Commit's candidate receipt, its disposition votes, and its finalization
are signed under the old credential; every later record of the conversation
is signed under the successor.

A coordinator holds at most three private signers, one per role:

- the active signer, whose credential every new binding pins;
- the successor signer, present exactly while the advertised set holds a
  successor credential; and
- the retired-retained signer, the private key of a credential absent from
  the advertised set that a live route still pins or an unfinished receipt
  still names.

A new candidate or ReInit-attempt receipt **MUST** be signed only by the
credential the conversation pins, and only when that credential's interval
covers the Commit's canonical validation time; otherwise the submission is
refused with `E2EE_SYNCING` and no state changes. Finalization, abort, ReInit
activation, and ReInit abort **MUST** use exactly the credential ID carried by
the retained receipt they complete, never a replacement. A retired-retained
signer signs only terminals of receipts issued before its retirement and
never a new receipt.

Retirement is acceptance of a key set that omits a credential; the overlap
deadline of a credential is its successor's `not_before` plus
`MAX_SEQUENCER_KEY_OVERLAP`. Before that deadline a coordinator **MUST**
refuse a set that omits the credential while any `normal` route still pins
it. At or after the deadline it **MUST** accept the set and mark every route
still pinned to the omitted credential blocked. A blocked route accepts no
candidate, ReInit attempt, or policy change; it continues opaque application
delivery on its last accepted epoch; and it leaves the blocked state only by
route close followed by a fresh binding under the current credential, or by
completing an already issued old-credential transition terminal that
finalizes a successor context. An unfinished old-credential receipt remains
completable by the retired-retained signer, and a terminal that finalizes a
successor transition unblocks its route. If the retired private key is
unavailable, the receipt stays unfinished and the route stays blocked; the
coordinator never signs it with another key.

The durable metadata that proves signer ownership after a restart is:

- the highest accepted key set: its set generation, digest, and credential
  IDs;
- a permanent credential history holding every accepted public credential,
  the set generations that introduced and retired it, and its signer-release
  fact;
- every route's current accepted context pin; and
- the `sequencer_key_id` of every unfinished candidate and ReInit-attempt
  receipt.

Startup derives the required signer set from the advertised set plus those
pins and unfinished receipts, counting only `normal` routes; a route whose
Section 13.7.1 gate is `pending`, `conflict`, or `closed` is never live for
signer purposes. Backup restore, a new recovery epoch, and evidence-only
recovery under Section 13.7 never require an old private key and never sign
a missing link. Permanent retention of public credentials for historical
verification is distinct from possession of a private signer. A retired
private key **MAY** be destroyed only when its credential is absent from the
durably accepted set, no `normal` route pins it, no unfinished receipt names
it, and the coordinator has durably recorded the release fact. After release
a configured key for that credential is refused as unrelated, and in-memory
copies are zeroized at release.

The transition below follows two conversations: A stays pinned to the old
credential and B migrates first. Each row states what a restart in that
phase does:

| Phase | Advertised set | Conversation A (pinned old) | Conversation B (migrated) | Unfinished candidate receipt | Unfinished ReInit receipt | Required private signers | Restart behaviour |
| --- | --- | --- | --- | --- | --- | --- | --- |
| steady state | old only | pins old | pins old | none | none | active old | loads old; both routes normal |
| successor published | old and new | pins old | pins old | old-key receipt open | none | active old, successor new | loads both; the open receipt completes under old |
| B transition finalized | old and new | pins old | pins new from its transition certificate | none | old-key attempt open | active old, successor new | B signs under new; A and the open attempt under old |
| all live groups migrated before the deadline | new only, accepted early | pins new | pins new | none | none | active new; old released after the release fact | loads new only; a configured old key is refused as unrelated |
| deadline reached with A still pinned | new only, accepted at the deadline | blocked on old | pins new | none | none | active new; old retired-retained if configured | loads new; A blocked; no old-key receipt is required |
| retirement with unfinished old receipts | new only | blocked on old | pins new | old-key receipt open | old-key attempt open | active new, retired-retained old required | loads both; only terminals of the open records sign under old; new receipts for A are refused |
| retired key unavailable | new only | blocked on old | pins new | old-key receipt open | none | active new; old missing | starts; one audit event and blocked-route telemetry; the receipt stays unfinished and A stays blocked |
| signer released | new only | closed and rebound under new | pins new | none | none | active new | loads new; the release fact is retained and the old key is refused |

### 9.3 Canonical policy and roster transitions

```text
enum { channel(1), direct(2) } ArcConversationKind;
enum { open_visible(1), moderated(2), fixed_direct(3) } ArcMembershipPolicy;

struct {
    opaque root_fingerprint[32];
    opaque device_id[16];
    opaque device_certificate_id[32];
} ArcFinalityPrincipal;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque conversation_id[32];
    uint64 policy_generation;
    opaque previous_policy_id[32];
    ArcConversationKind kind;
    ArcMembershipPolicy membership_policy;
    ProtocolVersion mls_version;
    CipherSuite selected_suite;
    CipherSuite allowed_suites<2..32>;
    opaque controller_root_fingerprints<0..2048>;
    uint16 controller_threshold;
    ArcFinalityPrincipal finality_principals<80..5120>;
    uint16 finality_fault_bound;
    uint8 require_oob_verified_roots;
    uint16 max_devices_per_account;
    uint32 max_group_leaves;
} ArcPolicyTBS;

struct {
    opaque signer_root_fingerprint[32];
    opaque signer_device_id[16];
    opaque signer_device_certificate_id[32];
    opaque device_signature[64];
} ArcPolicyApproval;

struct {
    ArcPolicyTBS tbs;
    ArcPolicyApproval approvals<144..16384>;
} ArcPolicy;
```

The `policy_id` is defined in Section 2.2 over `ArcPolicyTBS`. Its network and
conversation IDs must equal the bound MLS group, so even a byte-identical role
configuration cannot be replayed into another conversation. Controller fingerprints
are concatenated 32-byte values in canonical order. Approvals are canonical
and duplicate-free. A threshold counts distinct controller roots, with at
most one approval counted per root. `allowed_suites` is an
ordered preference vector without duplicates, `selected_suite` must appear in
it, and the vector is never inferred from numeric cipher-suite values.
`max_devices_per_account` and `max_group_leaves` may tighten but never exceed
the hard profile limits in Section 16.
Initial policy generation is zero with an all-zero predecessor. Every
in-group successor increments by one and names the exact prior policy ID.
Before signing a policy, an honest approving device durably locks one exact TBS
per `(network_id, conversation_id, policy_generation,
previous_policy_id)`. That lock supplements, but does not replace, the
candidate-specific authorization and finality proof for the Commit that
installs it.

Every policy kind has a non-empty, duplicate-free controller-root set and
`1 <= controller_threshold <= controller_count`. A `fixed_direct` policy has
exactly the two bound roots and threshold two. An `open_visible` policy uses
its threshold for policy, removal, sequencer, route, and recovery decisions;
only a visible Add is exempt. A `moderated` policy uses it for every
membership or security-state change. There is no separate undefined recovery
threshold.

`finality_principals` is canonical by
`(root_fingerprint, device_id, device_certificate_id)` and contains no
duplicate device, certificate, or device-authorization public key. Every
principal resolves through the context-committed roster heads to an active
device represented by exactly one current MLS leaf and not named in
`pending_joins`. Let `n` be its length and `f` be `finality_fault_bound`. A valid
policy requires `1 <= n <= MAX_FINALITY_PRINCIPALS`, `n >= 3f + 1`, and uses
the derived quorum

```text
q = floor((n + f) / 2) + 1
```

so any two quorums intersect in more than `f` principals. A transition uses
the old policy's council and quorum; the resulting policy may name the next
council. For a one-device bootstrap `n=1`, `f=0`, and `q=1`. Small direct
groups commonly use both parties' devices with `f=0`; tolerating one Byzantine
finalizer requires at least four independently protected council devices.

`signer_device_certificate_id` is the Section 2.2
`device_certificate_id` recomputed from the exact certificate TBS.
Each approval signs `ArcPolicyTBS` with label `ARC-MLS/1 policy approval` and
is made by a device present in the named highest roster whose root-signed
certificate grants policy authority. The initial fixed-direct policy needs one
approval under each of the two bound roots. An initial moderated channel policy needs its declared
controller threshold. A change must be valid under the old policy's threshold
and identify the old policy ID; removing an old controller cannot be used to
validate the transition that removed it. Joiners receive the complete policy
chain in encrypted GroupInfo and its exact finalization references beside the
immutable Welcome. The in-MLS chain is bounded by `MAX_POLICY_CHAIN_BYTES` and
the external reference bundle by
`MAX_JOIN_TRANSITION_PROOF_BUNDLE_BYTES`. ReInit does not erase proof ancestry
merely by resetting the MLS group. When any required root, roster, binding, or
policy proof chain or reference bundle can no longer fit a Welcome, seamless
continuity and new Adds stop;
the safe recovery is an explicitly closed, next semantic incarnation with new
generation-zero root locks and renewed verification, not an unauthenticated
checkpoint.

Policy bytes are never sent as an application message. The complete new
`ArcPolicy` is inside the replacement context extension described below, and
that Commit-bound copy is the one endpoints enforce. The identical canonical
bytes are also published to the server as a public `policy` object with
`EGROUP SUBMIT POLICY` (Section 11.5) so the sequencer can verify finality
quorums (Section 12.4). A client **MUST** publish a policy before it submits
any terminal request whose `old_policy_id` or resulting policy ID names it; the
bootstrap creator publishes the generation-zero policy and the generation-one
operational policy immediately after `EGROUP BIND`. The server accepts a
published policy only when the conversation is bound, the network and
conversation IDs match the route, the recomputed `policy_id` of a
generation-zero policy equals the binding's `initial_policy_id` and its
predecessor is all zero, every later generation names a retained predecessor
and increments its generation by exactly one, and every approval verifies
against the retained roster certificate it names with the threshold counted
per controller root. It retains the object by content ID, answers an identical
resubmission with the same success line, bounds retained policy bytes per
conversation by `MAX_POLICY_CHAIN_BYTES`, and rejects anything else with
`E2EE_POLICY_INVALID`. A published policy is bounded by `MAX_POLICY_OBJECT`;
the reservation advertises no lower policy limit. The server-retained copy is a
witness copy: the policy ID is content-derived, so a context extension and a
published object with the same ID are the same bytes, and a client that finds
a retained policy it did not expect treats it as a `Security changed` event.
A GroupContextExtensions proposal **MUST** contain the complete replacement
extension list, including every unchanged extension and
`required_capabilities`; it is a wholesale replacement, not a merge. Clients
stage and validate the transition under the old policy before acknowledging
the Commit.

Policy approval is not blanket authorization for future Commits. After the
sequencer issues a receipt and endpoints stage the exact Commit, every
candidate gets one candidate-specific authorization:

```text
enum {
    routine_self_update(1), open_visible_add(2), controlled_transition(3),
    roster_recovery(4), join_confirmation(5), bootstrap_activation(6)
} ArcCommitAuthorizationRule;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque conversation_id[32];
    uint64 prior_epoch;
    opaque prior_state_id[32];
    opaque candidate_id[32];
    opaque commit_object_id[32];
    uint64 canonical_validation_time;
    opaque old_policy_id[32];
    ArcCommitAuthorizationRule authorization_rule;
    uint32 action_bits;
    opaque resulting_policy_id[32];
    opaque resulting_group_context_digest[32];
    opaque resulting_ratchet_tree_digest[32];
    opaque transition_target_digest[32];
} ArcCommitAuthorizationTBS;

struct {
    opaque signer_root_fingerprint[32];
    opaque signer_device_id[16];
    opaque signer_device_certificate_id[32];
    opaque device_signature[64];
} ArcCommitApproval;

struct {
    ArcCommitAuthorizationTBS tbs;
    ArcCommitApproval approvals<0..16384>;
} ArcCommitAuthorization;

struct {
    ArcCommitAuthorizationTBS tbs;
    ArcCommitApproval approval;
} ArcCommitApprovalEnvelope;
```

`action_bits` is derived mechanically from the decoded Commit and old and
resulting states. Version 1 assigns:

| Bit | Meaning |
| ---: | --- |
| `0x00000001` | Add leaf |
| `0x00000002` | Remove leaf |
| `0x00000004` | roster proposal or reaffirmation |
| `0x00000008` | policy change |
| `0x00000010` | sequencer change |
| `0x00000020` | binding or route change |
| `0x00000040` | leaf credential change |
| `0x00000080` | ReInit proposal |
| `0x00000100` | pending-join change |
| `0x00000200` | bootstrap-state change |
| `0x00000400` | close-intent change |
| `0x00000800` | private-topic change |

Unknown, missing, or extra bits are fatal. `routine_self_update` has zero
bits. `open_visible_add` has exactly one Add, a roster proposal, and
pending-join creation. `join_confirmation` only clears its named pending join.
`roster_recovery` has a roster proposal and only the Removes required by that
successor. `bootstrap_activation` has exactly policy and bootstrap-state
changes. Every other permitted non-empty combination is a
`controlled_transition`; illegal combinations are rejected rather than
assigned a best-fit label.

The authorization is a separate post-receipt proof object; it is never inside
the MLS Commit or its AAD. Its candidate and Commit object IDs therefore do
not create a content-hash cycle. Each approval signs the authorization TBS with label
`ARC-MLS/1 commit authorization`. The receipt and object ID bind the exact
encrypted Commit; the two result digests bind the fully parsed state that the
approver reviewed. `transition_target_digest` is all zero except that a ReInit
uses its `target_context_digest`, a same-group route migration uses the
resulting `binding_id`, and an active-to-closing transition uses the resulting
`close_intent_id`. Combining those transition classes or adding an unrelated
action bit to any of them is invalid; each carries only its required inline
Proposal, context replacement, and populated UpdatePath. None of these
digests covers an accepted-state or sequencer-record ID: a ReInit target is
fixed by the old conversation and its Proposal alone (Section 13.8), and this
authorization's own `prior_state_id`, `candidate_id`, and `commit_object_id`
bind the digest to one candidate position.
`canonical_validation_time` **MUST** equal
`ArcCommitAad.validation_time`. An approval credential must be active in the
old context-committed roster, represented by an old leaf, and carry policy
authority. Approvals are canonical and count at most one device per controller
root or public key. Before signing, an honest controller device durably locks the
same candidate record slot used by finality and will not authorize a fork until
a quorum abort advances the record head. `moderated`, `fixed_direct`, and every controlled transition use
the old policy's controller threshold. `open_visible_add` under `open_visible`
needs no controller approval, but every endpoint still validates the exact Add
and the finality council attests that validation. A `roster_recovery` uses the
narrow root-signed successor rule in Section 8.4 and the finality quorum;
expired controller credentials do not gain general approval authority.
Every finalization proof carries exactly one `ArcCommitAuthorization`. Its TBS
is derived from the candidate receipt, Commit AAD, decoded Commit, and fully
staged result; every endpoint recomputes every field. The finalization core
commits its semantic ID, so action bits and result digests cannot be swapped
after finality voting. Its approval vector may be empty only for
`routine_self_update`, `open_visible_add`, and `join_confirmation`;
misclassification is fatal.

`bootstrap_activation` is a special policy transition: its resulting policy
ID must equal the binding's `required_operational_policy_id`, its complete
initial member plan must already be active, and its finalization request must
contain separate derived quorums from both the old and resulting councils.
The same vote encoding is used, but resulting-council signers key their durable
lock by `(network_id, binding_id)` so a forked bootstrap history cannot
create a second eligible slot.

Device-roster changes use private-use proposal type `0xF1C2`,
`IRC_DEVICE_ROSTER_UPDATE_PROPOSAL`:

```text
struct {
    ArcDeviceRoster roster;
} ArcDeviceRosterUpdate;
```

The proposal is always inline and doubles as a roster proof. Every Commit with
one or more Adds for an account carries that exact full roster once, even when
its generation is already stored; an identical current roster is a valid
reaffirmation, not an update. A revocation Commit carries the successor roster
and Removes every now-unauthorized leaf for the account atomically. Clients
reject rollback, gaps in `previous_roster_id`, a leaf
whose Device ID and authorization key are not active in the resulting roster,
an Add not issued under that exact current roster, or a roster update without
all required Removes. A retained leaf may keep a credential issued under an
older roster only while the same certificate remains active in every accepted
successor. The custom proposal and context extension are
both listed in MLS `required_capabilities`.

Every roster reaffirmation or update is accompanied by an inline
GroupContextExtensions proposal whose resulting `ArcMlsContext.roster_heads`
names the exact roster generation and ID. The roster Proposal, required
Removes or Adds, and context-head replacement are one atomic candidate. A
roster object carried only in GroupInfo or directory metadata never changes
group authorization state.

Policy meanings are:

- `open_visible`: a member may propose a visible Add, but verified mode still
  requires explicit approval for an unknown root. Automatically committing
  every server-reported JOIN is forbidden.
- `moderated`: the encrypted controller threshold authorizes membership,
  role, policy, route, and recovery changes. This is the default for a group
  claiming resistance to a malicious relay operator.
- `fixed_direct`: leaves resolve to exactly the two bound continuous account
  roots; one valid policy approval from each side is required for membership
  and policy changes.

relay operator status has no cryptographic controller authority. Operators can
still deny service, kick at the IRC layer, or censor ciphertext.

### 9.4 Binding authorization

The server cannot be trusted to bind the same route to the same group for
everyone. Endpoints authorize the initial binding:

```text
struct {
    opaque account_id<1..255>;
    opaque root_fingerprint[32];
    opaque device_id[16];
    opaque capability_id[32];
} ArcInitialMemberPlanEntry;

struct {
    ArcInitialMemberPlanEntry entries<1..1048576>;
} ArcInitialMemberPlan;

struct {
    opaque account_id<1..255>;
    opaque root_fingerprint[32];
    opaque device_id[16];
    opaque capability_id[32];
    opaque key_package_ref<0..255>;       // empty only for the creator
    SignatureScheme leaf_signature_scheme;
    opaque leaf_signature_key_digest[32];
    uint8 creator;
} ArcKeyPackagePlanEntry;

struct {
    ArcKeyPackagePlanEntry entries<1..1048576>;
} ArcKeyPackagePlan;

struct {
    uint16 profile_version;
    opaque network_id[32];
    ArcConversationKind kind;
    opaque direct_account_a<0..24>;
    opaque direct_account_b<0..24>;
    opaque canonical_channel_name<0..255>;
    opaque channel_authority_root_fingerprint[32];
    uint64 semantic_incarnation;
    opaque predecessor_close_id[32];
} ArcSemanticRouteTBS;

struct {
    uint16 profile_version;
    ProtocolVersion mls_version;
    CipherSuite cipher_suite;
    opaque group_id<1..255>;
    opaque network_id[32];
    opaque conversation_id[32];
    ArcConversationKind kind;
    opaque semantic_route_lock_id[32];
    opaque route_binding[32];
    uint64 initial_validation_time;
    opaque initial_policy_id[32];
    opaque required_operational_policy_id[32];
    uint8 initial_bootstrap_pending;
    opaque initial_member_plan_id[32];
    opaque sequencer_credential_id[32];
    opaque encoded_required_capabilities<1..65535>;
} ArcContextCoreTBS;

struct {
    opaque account_id<1..255>;
    opaque root_fingerprint[32];
    uint64 roster_generation;
    opaque roster_id[32];
} ArcBindingPrincipal;

struct {
    uint16 profile_version;
    opaque network_id[32];
    ArcConversationKind kind;
    uint64 binding_generation;
    opaque previous_binding_id[32];
    ArcSemanticRouteTBS semantic_route;
    opaque semantic_route_lock_id[32];
    opaque channel_instance_id<0..16>;
    opaque conversation_nonce<0..32>;
    opaque group_id<1..255>;
    opaque conversation_id[32];
    opaque route_binding[32];
    ProtocolVersion mls_version;
    CipherSuite cipher_suite;
    opaque initial_policy_id[32];
    opaque required_operational_policy_id[32];
    opaque initial_member_plan_id[32];
    opaque context_core_id[32];
    opaque sequencer_credential_id[32];
    ArcBindingPrincipal principals<1..65535>;
} ArcConversationBindingTBS;

struct {
    opaque signer_root_fingerprint[32];
    opaque signer_device_id[16];
    opaque signer_device_certificate_id[32];
    opaque device_signature[64];
} ArcBindingApproval;

struct {
    ArcConversationBindingTBS tbs;
    ArcBindingApproval approvals<0..65535>;
} ArcConversationBinding;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque account_id<1..255>;
    opaque root_fingerprint[32];
    uint64 root_binding_sequence;
    opaque previous_root_binding_lock_id[32];
    opaque semantic_route_lock_id[32];
    opaque binding_id[32];
    uint64 roster_generation;
    opaque roster_id[32];
} ArcRootBindingLockTBS;

struct {
    ArcRootBindingLockTBS tbs;
    opaque root_signature[64];
} ArcRootBindingLock;

struct {
    ArcConversationBinding binding;
    ArcInitialMemberPlan initial_member_plan;
    ArcRootBindingLock root_binding_locks<0..65535>;
} ArcConversationBindingPackage;

enum {
    root_locked_genesis(1), commit_finalized_transition(2),
    reinit_target_transition(3)
} ArcBindingProofKind;

struct {
    ArcConversationBindingPackage package;
    ArcBindingProofKind proof_kind;
} ArcBindingChainEntry;
```

An approval signs the TBS with label `ARC-MLS/1 conversation binding` using a
current device key authorized for bindings. `context_core_id` covers the MLS
version, suite, group ID, complete `required_capabilities`, network, semantic
and concrete routes, initial validation time, bootstrap and required
operational policy IDs, exact initial member plan, and sequencer credential ID
using the Section 2.2 formula. It excludes approvals that would otherwise be
circular. The binding ID is likewise the Section 2.2 TBS-only ID.
The transport always carries `ArcConversationBindingPackage`; verifiers
recompute its plan ID before considering the approvals.
For a channel binding, `channel_instance_id` is exactly 16 bytes and
`conversation_nonce` is empty; for a direct binding, the instance is empty and
the nonce is exactly 32 bytes. These values equal the reservation, or for a
ReInit successor the replaced binding's, and recompute the concrete
`route_binding` under Section 9.1. An ordinary new
group has `initial_bootstrap_pending=1`; a ReInit successor has zero. Any other
value or a mismatch with the initial committed context is invalid.
Principals are canonical by Account ID; approvals are canonical by
`(signer_root_fingerprint, signer_device_id)`; both vectors reject duplicates.
Their entry counts may not exceed `MAX_BINDING_PRINCIPALS` and
`MAX_BINDING_APPROVALS`, even when the TLS byte-vector encoding could hold
more. A root whose unanimity set would exceed the approval bound must reduce
the number of binding-authorized devices in a new roster before creation.
An initial binding has generation zero and an all-zero predecessor. It has the
unanimous approvals and root locks described below. Every replacement
increments by one, names the exact prior binding ID, and has empty approval and
root-lock vectors because its authority is the referenced old-group terminal
record.

The initial plan is a stable semantic device set, canonical by
`(account_id, root_fingerprint, device_id)`, with no duplicate Device ID,
authorization key, or capability ID. Its ID uses Section 2.2. It intentionally
does not bind one-use KeyPackages or leaf keys: every planned invitee proves
acceptance by consuming a fresh KeyPackage and finalizing its mandatory
join-confirmation self-Commit. Bootstrap activation is forbidden until every
planned device is an active, non-pending leaf and no unplanned device exists.
This permits a failed Add to be retried with fresh key material without asking
account roots to sign a different semantic conversation.

An `ArcKeyPackagePlan` is attempt-specific. It is canonical by the same device
tuple, has exactly one `creator=1` entry with an empty KeyPackageRef, and every
other entry has `creator=0` and a fresh, reserved KeyPackageRef. Its device set
and capability IDs must equal the applicable semantic plan. Each leaf-key
digest uses Section 2.2 and must match the resulting LeafNode. A plan is used
only by the ReInit attempt that names its ID; every accepted package is burned
on activation or abort, and a retry constructs a fresh plan.

A direct binding has exactly two principals in Account-ID order. A generation
zero binding requires an approval from **every** active device whose
certificate carries binding authority in each principal's context-named
complete roster. An initial channel binding uses the same unanimity rule for
every root listed as an initial controller, and its principal vector is exactly
that complete controller-root set plus the channel-authority root. The
authority root must issue a root binding lock even when it delegates
controller approval. This deliberately costs
availability at group creation, but closes the split-view attack in which a
server obtains valid signatures from disjoint devices or controller subsets.
On first contact a malicious service can still substitute an entirely
different channel-authority root; that is the identity-substitution limit in
Section 4. Verified mode requires the authority root to be pinned out of band.

It additionally requires one `ArcRootBindingLock` from every principal root.
`semantic_route_lock_id` is
`SHA256("ARC-MLS/1 semantic route lock" || encoded_ArcSemanticRouteTBS)`.
For a direct conversation, the two Account IDs are canonical and non-empty;
the channel name is empty, and the channel-authority fingerprint is all zero.
For a channel, the canonical channel name and a nonzero, locally pinned
channel-authority root fingerprint are present and both account fields are
empty. For either kind, semantic incarnation zero has an all-zero predecessor
close ID. A later incarnation increments by one and names the semantic close
ID of the prior incarnation. Version 1 therefore permits only one live
semantic direct conversation per account pair, and the fresh conversation
nonce cannot manufacture a parallel lock slot. Encrypted-channel rename is
not supported in version 1; it requires a finalized close and newly approved
incarnation. The server-assigned channel instance ID and fresh conversation
nonce remain concrete route inputs inside the locked binding, never the lock
namespace.

Each root maintains one global monotonic binding-lock chain:
sequence zero uses an all-zero predecessor; every later lock increments by one
and names the prior
Section 2.2 `root_binding_lock_id`.
It signs with label
`ARC-MLS/1 root binding lock` and **MUST NOT** sign two binding IDs for
one semantic route lock. For a generation-zero binding the package contains
exactly one canonical lock per principal, and each lock names that principal's
exact roster head. A later binding continued by an old-group-finalized route
migration or ReInit contains an empty lock vector and derives non-forking
continuity from that old finality certificate.

Clients pin the highest root-binding sequence and lock ID per root. A lower
sequence is rollback; a gap requires fetching and verifying intermediate lock
objects, and two IDs at one sequence prove root equivocation. The service
may suppress a newer lock and cause stale-view denial, but it cannot synthesize
the root signature needed for a second semantic-route transcript.

The root lock prevents a malicious directory from exploiting two still-valid,
disjoint roster generations to obtain two apparently unanimous device sets.
It deliberately requires access to the protected root, or a future separately
standardized non-forking account ledger, whenever a generation-zero
conversation is created.

Every such device durably locks one generation-zero transcript per
`semantic_route_lock_id` before emitting its signature and refuses a different
binding ID even after restart or server failover. Because a
valid competing binding needs the same complete device set and root lock, one
honest non-rolled-back signer prevents two valid bindings. A root with no currently
usable binding-authorized device cannot create a new conversation until its
root-signed roster is repaired. An optional future witnessed binding ledger
may replace unanimity; version 1 does not silently do so.

The account with lexicographically smaller Account ID is the only version-1
direct-binding creator; either party may send it an invitation request. A
conflict is a security failure and has no automatic winner. A later route
migration is instead authorized and finalized inside the existing group,
increments the binding generation, and names the exact old binding ID.
Same-name channel instances never imply the same binding.

`ArcBindingChainEntry` makes that continuity available to a later joiner. A
genesis entry validates its approvals and root locks. A same-group entry is
authorized by the exact retained finalization object whose verified result
contains that binding. A ReInit entry is first authorized by the finalized old
ReInit Commit whose authorization commits the stable target digest containing
that binding, and becomes live only when a later matching activation
certificate finalizes one attempt for that target and binding.

Those post-Commit record and object IDs are deliberately absent from
`ArcBindingChainEntry`: the chain is inside GroupInfo and therefore must be
known before the Commit, receipt, finalization, and ReInit activation exist.
The typed Welcome wrapper carries the exact external proof references defined
below. A verifier fetches every referenced object, recomputes its semantic
record ID, validates the result or target transition, and, for ReInit, also
validates the activation record before accepting the entry as live. The chain
is gapless, oldest-to-newest, and ends at the context's current binding.

### 9.5 Required MLS context extension

Every group carries private-use extension `0xF1C1`,
`ARC_MLS_CONTEXT_EXTENSION`, and lists it, join extension `0xF1C3`, and
proposal `0xF1C2` in `required_capabilities`:

```text
struct {
    opaque account_id_digest[32];
    uint64 root_generation;
    opaque root_fingerprint[32];
    uint64 roster_generation;
    opaque roster_id[32];
} ArcRosterHead;

struct {
    uint32 leaf_index;
    opaque key_package_ref<1..255>;
} ArcPendingJoin;

struct {
    uint16 reason_code;
    uint64 validation_time;
} ArcCloseIntent;

enum { active_conversation(1), closing_conversation(2) }
    ArcConversationLifecycleKind;

struct {
    ArcConversationLifecycleKind kind;
    opaque close_intent_id[32];           // zero only while active
} ArcConversationLifecycle;

struct {
    opaque account_id<1..255>;
    ArcRootIdentity roots<1..1048576>;
} ArcAccountRootChain;

enum {
    policy_root_locked_genesis(1), policy_commit_finalized_transition(2),
    policy_reinit_target_transition(3)
} ArcPolicyProofKind;

struct {
    ArcPolicy policy;
    ArcPolicyProofKind proof_kind;
} ArcPolicyChainEntry;

enum { binding_subject(1), policy_subject(2) }
    ArcJoinTransitionSubject;

enum {
    finalized_group_transition(1), reinit_target_authorization(2),
    reinit_activation(3)
} ArcJoinTransitionProofRole;

struct {
    ArcJoinTransitionSubject subject_kind;
    opaque subject_id[32];
    ArcJoinTransitionProofRole proof_role;
    opaque record_conversation_id[32];
    opaque authorizing_record_id[32];
    opaque authorizing_object_id[32];
} ArcJoinTransitionProofReference;

struct {
    ArcJoinTransitionProofReference references<0..262144>;
} ArcJoinTransitionProofBundle;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque conversation_id[32];
    ArcConversationKind kind;
    opaque route_binding[32];
    uint64 initial_validation_time;
    ArcPolicy policy;
    ArcSequencerCredential sequencer;
    ArcConversationBinding current_binding;
    ArcConversationLifecycle lifecycle;
    opaque private_topic<0..4096>;
    uint8 bootstrap_pending;
    ArcRosterHead roster_heads<1..65535>;
    ArcPendingJoin pending_joins<0..65535>;
} ArcMlsContext;

struct {
    ArcAccountRootChain root_chains<1..1048576>;
    ArcBindingChainEntry binding_chain<1..1048576>;
    ArcPolicyChainEntry policy_chain<1..1048576>;
    ArcDeviceRoster roster_chain<1..3145728>;
} ArcJoinAuthBundle;
```

`ArcJoinAuthBundle` is GroupInfo extension `0xF1C3`,
`IRC_JOIN_AUTH_BUNDLE_EXTENSION`. Root chains are canonical and
duplicate-free by Account ID. Each is strictly consecutive, verifies every
root-continuity signature, and ends at the exact root referenced by current
bindings, roster heads, policy principals, finality principals, and leaves. A
chain may begin at a locally pinned generation; otherwise the client fetches
the missing prefix with `EKEY FETCH ROOT-CHAIN` and blocks rather than trusting
a directory jump.

The binding chain follows Section 9.4, includes the complete generation-zero
binding package and semantic member plan, and ends at bytes exactly equal to
`current_binding`. Its concrete route equals `ArcMlsContext.route_binding`.
The policy chain is oldest-to-newest and begins at the original
generation-zero policy authenticated by the root-locked genesis binding. That
entry has `policy_root_locked_genesis`. Within one MLS group it has no
generation gap. Every later in-group entry has
`policy_commit_finalized_transition` and exactly one matching
`finalized_group_transition` proof reference in the Welcome wrapper. The
referenced `ArcCommitFinalizationCertificate` must recompute to the stated
record ID, and its verified authorization and resulting context must name the
entry's exact policy ID.

A reset to generation zero is legal only at a `reinit_target_transition` in
the binding chain. Its policy entry has `policy_reinit_target_transition` and
is the policy inside the exact `ArcReInitTargetTBS`: a continuing member
staging the successor at epoch 1 checks it against the target it
reconstructs, and a later joiner checks it against the target that the
referenced ReInit activation certificate's attempt carries (Section 13.8). The
preceding entry is the old terminal policy used to verify the old ReInit
Commit. The wrapper supplies a `reinit_target_authorization` reference to that
Commit's finalization certificate and, once the successor is live, a
`reinit_activation` reference to the matching activation certificate. A
preactivation `ArcStagedReInit` omits only that not-yet-created activation
reference; the recipient remains staged until it later verifies the
certificate. The chain ends at bytes exactly equal to the policy in
GroupContext.

For both binding and policy chains, the proof bundle is canonical by
`(subject_kind, subject_id, proof_role)`, has no duplicate or extra entry, and
contains exactly the references required by every non-genesis chain entry.
`record_conversation_id` identifies the log used by `EGROUP FETCH OBJECT` and
must equal the conversation ID inside the fetched record; that record's
network ID must equal the wrapper and bound context. The object ID is the hash
of the complete fetched `ArcWireObject`, and the semantic record ID is
recomputed from its TBS. `finalized_group_transition` requires an
`ArcCommitFinalizationCertificate`; `reinit_target_authorization` requires the
old ReInit Commit's `ArcCommitFinalizationCertificate`; and
`reinit_activation` requires an `ArcReInitActivationCertificate`. No other
wire kind satisfies the role.

A genesis entry has no reference. A same-group entry has exactly the
finalized-group reference. A completed ReInit entry has exactly its
target-authorization and activation references, subject to the one
preactivation exception above. One proof object may legitimately authorize
both a binding and policy subject, but each typed subject mapping is explicit.
Missing, mismatched, unavailable, or unverifiable proof blocks the Welcome; a
valid policy signature alone never establishes that the group adopted that
policy.

Each endpoint stores the verified subject-to-proof mapping beside its MLS
state. Applying a finalization or ReInit activation and extending that mapping
is one crash-safe transaction; an endpoint that cannot persist both applies
neither. The map is not a GroupContext field and never feeds a Commit hash.
Any member producing a later Welcome constructs the exact canonical bundle
from this state. Loss of a required mapping blocks Welcome production and
requires refetch and verification, never reconstruction from an untrusted
current-state assertion.

The roster chain contains every signed roster needed to
validate binding and policy approvers and tree credentials, then the current roster for
every represented account; it is canonical by
`(account_id, root_generation, roster_generation)`, begins at each
binding-named head, and has no unexplained gap.
Its last roster for every account must exactly equal the context-committed
`roster_heads` entry; extra or missing heads are invalid. `roster_heads` is
canonical by `(account_id_digest, root_generation, root_fingerprint)` and contains
every account referenced by a leaf, binding principal, controller, or finality
principal. The digest is recomputed from each authenticated root descriptor;
collisions are fatal. A root discontinuity requires ReInit rather than a same-group head
replacement.

The canonical encoding of each `ArcPolicy` is at most `MAX_POLICY_BYTES`, the
binding-chain vector is at most `MAX_BINDING_CHAIN_BYTES`, the policy-chain
vector is at most `MAX_POLICY_CHAIN_BYTES`, and the complete
`ArcMlsContext` extension is at most `MAX_ARC_MLS_CONTEXT_EXTENSION`.
Length-prefix maxima in the presentation structures never override these
smaller profile limits.

`pending_joins` is canonical by leaf index. Profile version 1 permits at most
one entry. The Add Commit creates that entry; until it is cleared, the only
permitted next transition is the named leaf's join-confirmation self-Commit or
its removal after timeout. The confirmation uses GroupContextExtensions to
remove the entry and a populated UpdatePath. This makes activation consensus
state rather than local UI state and prevents an undelivered Welcome from
becoming an ACK dependency in an unrelated transition.

`lifecycle` begins active. The only permitted transition is active to closing,
made by a controlled Commit that sets the close-intent action bit and carries
a populated UpdatePath. `close_intent_id` is
`SHA256("ARC-MLS/1 close intent id" || encoded_ArcCloseIntent)`. Reopening is
forbidden. Once that transition finalizes, endpoints stop all application and
handshake sending and the server may install the corresponding encrypted
tombstone through `EGROUP CLOSE`.

`bootstrap_pending` is 1 only while constructing a generation-zero group and
0 afterward. When it is 0 at ReInit creation, the required operational policy
ID equals the context's current policy ID. While it is 1, application objects are rejected by clients and
the route; only the exact initial-plan Add/confirmation sequence and final
`bootstrap_activation` policy transition are permitted. The initial policy
uses the creator as a one-device `f=0` council. The binding also commits an
exact generation-one `required_operational_policy_id`. After every planned
device is active, the activation candidate installs that policy and clears the
flag atomically. Its finalization needs a quorum from both the old bootstrap
council and the resulting operational council. Resulting-council devices
durably sign at most one bootstrap activation per binding ID, regardless of
candidate history. Quorum intersection therefore prevents two creator-forked
bootstrap histories from both becoming message-bearing conversations. BIND
may reserve/enforce encrypted-only routing earlier, but the ARCD returns
`E2EE_FINALITY_REQUIRED` for application traffic until this certificate.
The private-use values are experiments, not IANA allocations, and must be
replaced if standardized values are assigned.

`private_topic` is empty for a direct conversation. For a channel it is at
most `MAX_PRIVATE_TOPIC_BYTES`, well-formed UTF-8 in NFC, and contains no C0,
DEL, C1, or Unicode bidi-formatting code point U+202A through U+202E or U+2066
through U+2069. It begins empty in an ordinary genesis group. It changes only
through a `controlled_transition` carrying the
private-topic action bit and old-policy controller approval. A ReInit target
commits its exact successor value. Clients display a new topic only after that
transition finalizes, giving every topic one MLS-consensus state instead of an
arrival-order-dependent chat message.

The complete policy is therefore atomic with the MLS GroupContext and its
confirmation tag. A Welcome **MUST** contain the full `ratchet_tree` GroupInfo
extension and the complete `ArcJoinAuthBundle` inside its encrypted GroupInfo.
That bundle contains only trust material known when the Commit and Welcome are
created. Later receipt, finalization, and activation references are carried
beside the immutable Welcome in the typed delivery wrappers from Sections
12.4 and 13.8; they are never inserted retroactively into GroupInfo.
The joiner performs all RFC 9420 tree
hash, parent hash, LeafNode, GroupInfo, and confirmation checks. A Welcome
whose complete wrapper exceeds `MAX_WELCOME_MAILBOX_OBJECT` is rejected; the
group must reduce its membership or proof material before adding that device.

Clients reject a Welcome, Commit, or GroupInfo whose profile, network, group,
route, policy, sequencer, binding, lifecycle, or required capability differs
from the locally expected state. A later context extension changes
`current_binding` only together with the exact gapless binding-chain proof and
authorized transition described above.

## 10. Encrypted application format

Application plaintext carried in MLS `application_data` is:

```text
enum {
    text(1),
    notice(2),
    action(3),
    policy_notice(4),
    security_event(5)
} ArcEncryptedContentType;

struct {
    uint16 profile_version;              // 1
    opaque network_id[32];
    opaque conversation_id[32];
    opaque route_binding[32];
    opaque sender_device_id[16];
    uint64 leaf_credential_generation;
    uint64 sender_sequence;
    opaque message_id[16];
    opaque sequencer_record_chain_head[32];
    ArcEncryptedContentType content_type;
    opaque body<0..32768>;
    opaque zero_padding<0..65535>;
} ArcEncryptedContent;
```

`leaf_credential_generation` must equal the generation in the authenticated
leaf's `ArcLeafAuthorizationTBS`; it is never accepted from message contents
alone and is zero in version 1. `sender_sequence` is a persistent, monotonically increasing counter scoped to
`(group_id, authenticated leaf signature key)`, across
all epochs in which that leaf is retained. The first value is zero and each
subsequent new application ciphertext is exactly one greater. Allocation of
the value, encryption, advancement of the stored next value, and outbox
persistence follow the transaction in Section 14. It resets only after a genuinely
new leaf key is introduced by remove-and-readd or ReInit; an Update Commit or
epoch change does not reset it. `message_id` is a fresh random 128-bit value.

Receivers **MUST**:

- verify profile, network, conversation, route, and Device ID against the MLS
  state and outer route;
- reject a previously accepted message ID;
- reject counter rollback, excess gaps, or a counter outside the distinct
  application forward window;
- compare the sequencer-record chain head with locally observed heads and request any
  missing receipts;
- verify the Section 7.5 padding target and zero octets;
- validate the content type before interpreting the body; and
- treat the MLS credential, not an IRC prefix or nickname, as the sender
  identity.

Only enum values 1 through 5 are valid in version 1; every other value is
rejected. Text, notice, action, policy-notice, and security-event bodies **MUST**
be well-formed UTF-8. A policy notice is explanatory UI text only and has no
authority; a security event is likewise a member-attributed message, not a
trusted protocol alert. The Commit-bound context and verified terminal records
control security state. NUL is forbidden. Clients
**MUST** render control characters safely and **MUST NOT**
interpret decrypted text as CTCP, terminal control, HTML, or a command merely
because it contains a special prefix.

For application messages, MLS `authenticated_data` contains exactly:

```text
struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque conversation_id[32];
    opaque route_binding[32];
    opaque latest_state_id[32];
} ArcApplicationAad;
```

`latest_state_id` is the exact accepted MLS-state anchor: the current
finalization ID, or the binding's genesis/activation anchor before the first
finalization. It is distinct from
`ArcEncryptedContent.sequencer_record_chain_head`, which is the newest ordered
record the sender has observed and may temporarily name a pending candidate or
abort. The AAD route fields equal the decrypted envelope and current context;
any mismatch is fatal.

For Commits it contains exactly:

```text
struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque conversation_id[32];
    opaque route_binding[32];
    uint64 validation_time;
    opaque prior_state_id[32];
} ArcCommitAad;
```

`validation_time` is application consensus input, not trustworthy wall-clock
evidence. It may not precede the last finalized value. Every controller,
processing-ACK signer, and finality voter also requires it within
`MAX_COMMIT_CLOCK_SKEW` of its protected local clock; a clock disagreement withholds finality and
never causes selection of a competing Commit. There is no maximum delta from
the prior value, because an idle group must remain usable after more than one
day. Certificate, roster, and KeyPackage time checks for that candidate all
use this one value.

AAD is visible to the server. No private topic, nickname, reply text, account
roster, or message body belongs in AAD.

## 11. ARC capabilities and IRCv3 wire transport

### 11.1 Dependencies

The vendor capability is:

```text
agenc.ag/e2ee-mls=v1,profile=<profile-hash>,seg=2940,obj=262144,parts=90,welcome=4194304
```

Clients begin with `CAP LS 302`. The value above may appear only in `CAP LS`
or `CAP NEW`; `CAP REQ` and `CAP ACK` use the bare capability name. A
canonical exchange is:

```text
C: CAP LS 302
S: CAP * LS :message-tags batch echo-message labeled-response standard-replies account-tag agenc.ag/e2ee-mls=v1,profile=<profile-hash>,seg=2940,obj=262144,parts=90,welcome=4194304
C: CAP REQ :message-tags batch echo-message labeled-response standard-replies account-tag agenc.ag/e2ee-mls
S: CAP * ACK :message-tags batch echo-message labeled-response standard-replies account-tag agenc.ag/e2ee-mls
```

The value grammar and field order are exact; decimals are canonical and no
unknown field is accepted in profile version 1. `profile-hash` is the exact
Section-2.3 value. Before requesting the capability, a client compares it to
the value compiled into or pinned by that client. A missing, duplicate,
malformed, non-canonical, or unequal value makes the capability unavailable;
a client with an existing encrypted-conversation pin enters the blocked
security state and never falls back to plaintext. `CAP REQ` and `CAP ACK`
continue to carry only the bare capability name. `seg=2940` is network-wide
and immutable, including across federation. Lower deployment object/count
limits never alter segmentation or cause cross-link reframing.

It depends on these IRCv3 capabilities:

- `message-tags` for the extended tag budget and `TAGMSG`;
- `echo-message` so the submitting connection receives its own exact object;
- `batch` for bounded multi-object directory responses;
- `labeled-response` for unambiguous request/response correlation;
- `standard-replies` for structured errors; and
- `account-tag` for the sender's current, mutable services-account routing
  metadata. It is not the immutable Account ID and supplies no cryptographic
  identity proof.

An authenticated account is required. Clients request all dependencies and
`agenc.ag/e2ee-mls` during CAP negotiation. A server **MUST NOT** acknowledge
the vendor capability if any required behavior is unavailable.

CAP negotiation is not downgrade protection because a malicious server
controls it. A client with a pinned encrypted conversation **MUST** abort or
enter a blocked security state if the capability disappears.

### 11.2 Fragment tag

Complete encoded objects are carried in one or more client-only vendor tags:

```text
@+agenc.ag/e2ee=v1.<object-id>.<part>.<count>.<total>.<segment>
```

Client submissions use `+agenc.ag/e2ee`. A server-originated stored-object or
directory response uses `agenc.ag/e2ee` without `+`. A server forwarding or
echoing a client submission preserves the client-only tag name and exact
value. Both names use the identical value grammar below; a frame carrying both
is invalid.

Fields are:

- `v1`: wire profile version;
- `object-id`: unpadded base64url of
  `SHA256(complete_object_bytes)`, exactly 43 ASCII characters;
- `part`: zero-based decimal fragment index;
- `count`: total decimal fragment count;
- `total`: exact decimal byte length of the complete decoded object; and
- `segment`: unpadded base64url of this raw fragment's bytes.

Decimal fields use no leading zero except the value `0`. Base64url is the URL
and filename-safe alphabet from RFC 4648 without `=` padding. A dot never
appears in that alphabet and therefore unambiguously separates fields. Every
base64url field must decode and re-encode to the identical characters;
non-zero unused bits and alternate encodings are invalid.
`part` and `count` contain at most four decimal digits; `total` contains at
most seven. The numeric profile limits are checked before multiplication or
allocation, using overflow-checked arithmetic.

The fixed maximum raw fragment is 2940 bytes, encoding to 3920 base64url
characters. Every extension request that expects a response carries a
negotiated `label`: on fragment zero for a fragmented request, or on the sole
line for a bare request. The raw tag
substring after `label=` **MUST** itself match `[A-Za-z0-9_-]{1,64}`, contain
no backslash escape, and decode to those identical bytes. Arbitrary legal
`label` values are rejected on this path because even unknown IRCv3 escapes
can otherwise expand their wire representation. For a full 2940-byte segment,
the exact client-added sizes are 4064 bytes for a 65,536-byte application
object's fragment zero, 4065 for a 262,144-byte live-control object, and 4068
for a 4,194,304-byte control object's fragment zero, each including a 64-byte
label. The exact server-originated mailbox tag plus a 64-byte `batch` tag is
4070 bytes. All are below IRCv3's independent 4094-byte side budget.

An E2EE-capable server constrains the complete serialized `account` tag to at
most 512 bytes. The fixed-size candidate receipt encodes to 294 bytes, so its
complete receipt tag is exactly 462 bytes. A requester candidate echo with
account, receipt, label, and preserved live fragment therefore uses at most
5041 combined tag bytes, including separators, below 8191. The non-tag portion
of every IRC line remains within the RFC 2812 512-byte limit. A server prefix
used on any extension line serializes to at most
`MAX_E2EE_SERVER_PREFIX_BYTES`, including nick/user/host delimiters when
present; an oversize prefix cannot negotiate this capability.

Before IRCv3 unescaping, the raw substring after `+agenc.ag/e2ee=` or
`agenc.ag/e2ee=` **MUST** match the complete ASCII grammar shown here and
contain no backslash. Duplicate E2EE tag keys are invalid; generic last-value
wins behavior is forbidden on this path.

Fragment zero carries exactly one such label; every other client fragment for
that object carries none. The server retains the label until reassembly and
uses it on the one logical success, echo, batch opening, or error response. A
single-fragment object is therefore labeled normally without repeating one
label across multiple in-flight commands.

A client-submitted E2EE frame may carry only the E2EE tag and, on part zero,
one `label`. A live forwarded or echoed user frame preserves the
client-originated `+agenc.ag/e2ee` tag and may add the server-originated
`account` tag and, only for candidate fragment zero, one receipt tag. A
server-originated directory/fetch frame instead uses unprefixed
`agenc.ag/e2ee` plus one bounded `batch` tag; it never also carries a receipt
tag or `account`. These cases cannot be mixed. Servers **MUST NOT** truncate
tags or ciphertext. The maximum physical client-to-server line is 4608 bytes;
the maximum server-to-client or server-to-server line with the 8191-byte
combined tag budget is 8703 bytes.

On candidate fragment zero the server also uses:

```text
agenc.ag/e2ee-receipt=v1.<candidate-id>.<receipt-bytes>
```

Both variable fields are unpadded base64url; `candidate-id` is exactly 43
characters and names the `candidate_id` defined in Section 12.2, while
`receipt-bytes` is the exact encoded `ArcCandidateReceipt`. It appears only on
live-forwarded candidate part zero and must fit the 4094-byte server-added
budget independently of the preserved client tags. Stored and fetched
receipts are separate `SEQUENCER-RECORD` objects and never use this tag. A client
rejects a duplicate, malformed, hash-mismatched, or differently encoded
receipt tag.

### 11.3 Channel carrier

Live encrypted application objects use normal `TAGMSG` routing and profile
version 1 restricts federated encrypted channels to ordinary global `#`
channels:

```text
@+agenc.ag/e2ee=<fragment-value> TAGMSG #channel
```

The server applies normal channel membership, bans, mute, flood, and routing
policy. It reassembles and validates the complete object before fanout. On
delivery, it supplies the authenticated IRC source and account tag, but those
remain routing metadata rather than cryptographic identity.

On a bound channel, the server rejects every user-originated `TAGMSG` that is
not exactly this E2EE application-frame production, including a frame with an
unrelated client-only tag. It also rejects plaintext `PRIVMSG` and `NOTICE`.
The public IRC topic is fixed to the literal UTF-8 text
`Encrypted channel - topic protected by ARC-MLS`; user `TOPIC` changes are
rejected, and the authenticated private topic exists only in the committed
`ArcMlsContext`. User-supplied `PART`, `KICK`, and `QUIT` reasons are never
forwarded onto a bound route: the server omits them or substitutes the fixed
public text `encrypted conversation event`. Clients do not render either
placeholder as authenticated conversation content.
`&`, `+`, and `!` channel namespaces are outside the federated version-1
profile because their scope and lifetime rules differ materially.

Only one plain channel target is allowed. Comma-separated target lists,
server/host masks, and status-message targets such as `@#channel` are rejected
because they make the cryptographic audience ambiguous.

If the capability or a dependency is removed with `CAP DEL`, disabled by the
client, or lost through services logout/account switch, the server immediately
stops E2EE submission and removes that session from bound-channel delivery.
It does not turn the target into plaintext. Authorized `CLOSE` leaves an
encrypted-only tombstone until that exact channel instance is destroyed; the
last-member transition durably records the tombstone before ordinary channel
delay/lifetime cleanup begins.

### 11.4 Direct carrier

Direct groups use the alphabetic extension command:

```text
@+agenc.ag/e2ee=<fragment-value> EDIRECT <conversation-id>
```

`EDIRECT` routes to every current device session belonging to the two accounts
bound to the conversation, including the submitting connection and the
sender's other devices. An ARCD may
queue complete opaque objects for offline delivery under a bounded retention
policy.

The server **MUST** reject a sender whose authenticated Account ID and
attached, roster-active Device ID are not bound to the direct conversation.
While a live encrypted direct binding exists for an Account-ID pair, the
server resolves nickname targets to Account IDs and rejects plaintext
`PRIVMSG` or `NOTICE` between that pair with `E2EE_REQUIRED`. Nick changes,
multiple sessions, and routing through another edge do not bypass this rule;
unrelated account pairs are unaffected. A closed direct binding remains an
encrypted tombstone until an explicitly approved new semantic generation is
created and never silently falls back to plaintext.

Every reassembled byte string is a typed envelope, never an untyped MLS blob:

```text
enum {
    application_mls(1), commit_mls(2), commit_approval(3), commit_ack(4),
    finalization_request(5), finalization_certificate(6),
    abort_request(7), abort_certificate(8), welcome_mls(9),
    root_identity(10), root_identity_chain(11), device_roster(12),
    device_capabilities(13), key_package_mls(14),
    conversation_binding(15), close_authorization(16), reservation(17),
    reinit_attempt(18), staged_reinit(19), reinit_ack(20),
    reinit_activation_request(21), reinit_activation_certificate(22),
    reinit_abort_request(23), reinit_abort_certificate(24),
    sequencer_record(25), device_attach_challenge(26), device_attach(27),
    root_binding_lock(28), federation_state(29), federation_origin(30),
    federation_request(31), federation_result(32), federation_event(33),
    policy(34), recovery_submission(35), witness_resolution(36),
    leaf_membership_proof(37)
} ArcWireObjectKind;

struct {
    uint16 profile_version;
    ArcWireObjectKind kind;
    opaque body<1..4194298>;
} ArcWireObject;
```

`body` is exactly one TLS encoding of the type named in the matrix below, with
no trailing byte. `object-id` hashes the complete encoded `ArcWireObject`.
Cheap envelope kind and length validation occurs before storage or MLS
processing. An object on any other carrier is rejected; in particular, a
Commit sent as ordinary channel `TAGMSG` or `EDIRECT` application traffic
never reaches fanout or sequencing.

| Command or carrier | Required kind and exact body | Hard complete-object maximum | Ingress authorization | Success path |
| --- | --- | ---: | --- | --- |
| bound-channel `TAGMSG` / `EDIRECT` | `application_mls`: one MLS `PrivateMessage` with `application` content | `MAX_APPLICATION_MLS_OBJECT` | attached, roster-active bound device; endpoint leaf auth | exact live echo/fanout |
| `EGROUP SUBMIT CANDIDATE` | `commit_mls`: one MLS `PrivateMessage` with `commit` content | `MAX_LIVE_OBJECT` | attached, roster-active bound device; endpoint leaf auth | candidate echo plus receipt |
| `EGROUP SUBMIT AUTHORIZATION` | `commit_approval`: `ArcCommitApprovalEnvelope` | `MAX_COMMIT_APPROVAL_OBJECT` | attached device matching approval signer | `STORED` |
| `EGROUP SUBMIT ACK` | `commit_ack`: `ArcCommitAck` | `MAX_COMMIT_ACK_OBJECT` | attached device matching signer | `ACKED` |
| `EGROUP SUBMIT FINALIZATION` | `finalization_request`: `ArcFinalizationRequest` | `MAX_FINALIZATION_OBJECT` | attached roster-active device; the server certifies only at the retained old policy's quorum, and endpoint quorum checks remain authoritative | `FINALIZED` or `PENDING` |
| `EGROUP SUBMIT ABORT` | `abort_request`: `ArcAbortRequest` | `MAX_ABORT_OBJECT` | attached roster-active device; the server certifies only at the retained old policy's quorum, and endpoint quorum checks remain authoritative | `ABORTED` or `PENDING` |
| `EGROUP SUBMIT REINIT ATTEMPT` | `reinit_attempt`: `ArcReInitAttempt` | `MAX_REINIT_OBJECT` | attached old-group device | `REINIT-STAGED` or `PENDING` |
| `EGROUP SUBMIT REINIT ACK` | `reinit_ack`: `ArcReInitAck` | `MAX_REINIT_ACK_OBJECT` | attached device matching signer | `REINIT-ACKED` |
| `EGROUP SUBMIT REINIT ACTIVATE` | `reinit_activation_request`: `ArcReInitActivationRequest` | `MAX_REINIT_OBJECT` | attached continuing old-group device | `REINIT-ACTIVATED` or `PENDING` |
| `EGROUP SUBMIT REINIT ABORT` | `reinit_abort_request`: `ArcReInitAbortRequest` | `MAX_REINIT_OBJECT` | attached old-group device | `REINIT-ABORTED` or `PENDING` |
| `EGROUP SUBMIT POLICY` | `policy`: `ArcPolicy` | `MAX_POLICY_OBJECT` | attached, roster-active bound device; approvals verified against retained rosters and the binding's policy chain | `STORED POLICY` |
| `EGROUP SUBMIT MEMBERSHIP` | `leaf_membership_proof`: `ArcLeafMembershipProof` | `MAX_LEAF_MEMBERSHIP_OBJECT` | attached device whose Device ID equals the proof's and whose account is a principal of the current binding | `STORED MEMBERSHIP` |
| `EGROUP SUBMIT RECOVERY` | `recovery_submission`: `ArcRecoverySubmission` | `MAX_RECOVERY_SUBMISSION_OBJECT` | attached device of a binding-principal account while the Section 13.7.1 gate is `pending` | `RECOVERY-ACCEPTED` |
| `EGROUP SUBMIT RECOVERY-ELEMENT` | the kind named by the accepted submission: `sequencer_record`, `close_authorization`, or the referenced object's existing kind | that kind's existing limit | the submitting device of the named open submission | `RECOVERY-EXTENDED`, `RECOVERY-CLOSED`, or `RECOVERY-CONFLICT` |
| `EGROUP BIND` | `conversation_binding`: `ArcConversationBindingPackage` | `MAX_BINDING_OBJECT` | reservation owner and complete binding approvals | `BOUND` |
| `EGROUP CLOSE` | `close_authorization`: `ArcCloseAuthorization` | `MAX_CLOSE_OBJECT` | old-policy authorization and finality reference | `CLOSED` |
| `EKEY PUBLISH IDENTITY` | `root_identity`: `ArcRootIdentity` | `MAX_IDENTITY_OBJECT` | same authenticated Account ID | `STORED` |
| `EKEY PUBLISH ROSTER` | `device_roster`: `ArcDeviceRoster` | `MAX_ROSTER_OBJECT` | same authenticated Account ID | `STORED` |
| `EKEY PUBLISH CAPABILITIES` | `device_capabilities`: `ArcDeviceCapabilities` | `MAX_CAPABILITY_OBJECT` | attached matching Device ID | `STORED` |
| `EKEY PUBLISH PACKAGE` | `key_package_mls`: one MLS `KeyPackage` | `MAX_KEY_PACKAGE_OBJECT` | attached matching Device ID | `STORED` |
| `EKEY REVOKE PACKAGE` | no object; exact KeyPackageRef parameter | none | attached matching publishing Device ID | `REVOKED` |
| `EKEY DELIVER BINDING` | `conversation_binding`: `ArcConversationBindingPackage` | `MAX_BINDING_OBJECT` | approved binding participant | `STORED` |
| `EKEY DELIVER WELCOME` | `welcome_mls`: `ArcDeliveredWelcome`, or `staged_reinit`: `ArcStagedReInit` | `MAX_WELCOME_MAILBOX_OBJECT` | finalized conversation member | `STORED` |
| `EKEY ATTACH FINISH` | `device_attach`: `ArcDeviceAttach` | `MAX_DEVICE_ATTACH_OBJECT` | same authenticated Account ID and challenge | `ATTACHED` |
| `EKEY ACK MAILBOX` | no object; exact delivery token and object ID | none | attached target Device ID | `ACKED` |

Response-only kinds have these one-to-one bodies: `reservation` is
`ArcReservation`; `finalization_certificate` is
`ArcCommitFinalizationCertificate`; `abort_certificate` is
`ArcCommitAbortCertificate`; `root_identity_chain` is `ArcAccountRootChain`;
`reinit_activation_certificate` and `reinit_abort_certificate` are their
exact named certificate types; `sequencer_record` is `ArcSequencerRecord`;
`device_attach_challenge` is `ArcDeviceAttachChallenge`; and
`root_binding_lock` is `ArcRootBindingLock`. S2S-only kinds map exactly to
`ArcFederationRouteState`, `ArcFederationOrigin`, `ArcFederationRequest`,
`ArcFederationResult`, `ArcFederationEvent`, and, for `witness_resolution`,
the Section 12.5.1 `ArcFederationWitnessResolution`. No other type-to-kind
mapping is legal; each S2S control envelope is bounded by
`MAX_FEDERATION_CONTROL_OBJECT` and transports any larger payload as its
separately bounded referenced object. `reservation` uses
`MAX_RESERVATION_OBJECT`; root chains use `MAX_ROOT_CHAIN_OBJECT`; device
attach kinds use `MAX_DEVICE_ATTACH_OBJECT`; root locks use
`MAX_IDENTITY_OBJECT`; terminal certificate kinds use their matching
finalization, abort, or ReInit limit; and `sequencer_record` uses
`MAX_SEQUENCER_RECORD_OBJECT`. The smaller 4,190,000-byte terminal bound leaves
space for the tagged-union record wrapper inside the 4,194,304-byte record
limit. Every `MAX_*_OBJECT` in this document measures the complete encoded
`ArcWireObject`, including its six-byte version/kind/vector envelope, never
only `body`.

Profile version 1 accepts no standalone MLS Proposal object. A standalone
proposal received elsewhere is only an unauthenticated advisory preview and
is never converted into an inline proposal. Update Proposals are disabled;
devices rotate path secrets with a self-Commit and populated UpdatePath.

### 11.5 Group binding command

`EGROUP` establishes the untrusted server route that is independently bound
inside MLS:

```text
EGROUP RESERVE CHANNEL <channel>
EGROUP RESERVE DIRECT <peer-account-token>
EGROUP BIND <reservation-id> <conversation-id> <context-digest>
EGROUP QUERY CHANNEL <channel>
EGROUP QUERY DIRECT <peer-account-token>
EGROUP CLOSE <conversation-id> <reason-code>
EGROUP SUBMIT CANDIDATE <conversation-id>
EGROUP SUBMIT AUTHORIZATION <conversation-id>
EGROUP SUBMIT ACK <conversation-id>
EGROUP SUBMIT FINALIZATION <conversation-id>
EGROUP SUBMIT ABORT <conversation-id>
EGROUP SUBMIT REINIT ATTEMPT <conversation-id>
EGROUP SUBMIT REINIT ACK <conversation-id>
EGROUP SUBMIT REINIT ACTIVATE <conversation-id>
EGROUP SUBMIT REINIT ABORT <conversation-id>
EGROUP SUBMIT POLICY <conversation-id>
EGROUP SUBMIT MEMBERSHIP <conversation-id>
EGROUP SUBMIT RECOVERY <conversation-id>
EGROUP SUBMIT RECOVERY-ELEMENT <conversation-id> <submission-id>
EGROUP FETCH OBJECT <conversation-id> <object-id>
EGROUP FETCH AUTHORIZATIONS <conversation-id> <candidate-id> <cursor-or-star>
EGROUP FETCH ACKS <conversation-id> <candidate-or-reinit-attempt-id> <cursor-or-star>
EGROUP FETCH RECEIPTS <conversation-id> <first-route-sequence> <cursor-or-star>
```

`FETCH ACKS` resolves its 32-byte selector against exactly one retained Commit
candidate ID or ReInit attempt ID in the named conversation. A candidate page
contains only `commit_ack` objects; an attempt page contains only `reinit_ack`
objects. It never mixes the two kinds. An unknown selector returns
`EMPTY ACKS`; a selector matching both namespaces or a returned object whose
signed parent differs is a fatal semantic-ID collision, not an ambiguous page.

`SUBMIT MEMBERSHIP` stores one Section 13.7.3 leaf-membership proof.
`SUBMIT RECOVERY` and `SUBMIT RECOVERY-ELEMENT` carry the Section 13.7.4
recovery evidence for a route whose Section 13.7.1 gate is `pending`; every
other `EGROUP` mutation of such a route is refused with `E2EE_ROUTE_INVALID`.

The reservation and close objects are:

```text
struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque reservation_id[16];
    ArcConversationKind kind;
    opaque route_binding[32];
    opaque channel_instance_id<0..16>;
    opaque conversation_nonce<0..32>;
    ArcSequencerCredential sequencer;
    uint32 application_object_limit;
    uint32 live_object_limit;
    uint32 key_package_object_limit;
    uint32 identity_object_limit;
    uint32 root_chain_object_limit;
    uint32 roster_object_limit;
    uint32 capability_object_limit;
    uint32 binding_object_limit;
    uint32 commit_approval_object_limit;
    uint32 commit_ack_object_limit;
    uint32 finalization_object_limit;
    uint32 abort_object_limit;
    uint32 reinit_object_limit;
    uint32 close_object_limit;
    uint32 welcome_object_limit;
    uint16 live_part_limit;
    uint16 mailbox_part_limit;
    uint64 expires_at;
} ArcReservationTBS;

struct {
    ArcReservationTBS tbs;
    opaque sequencer_signature[64];
} ArcReservation;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque conversation_id[32];
    opaque binding_id[32];
    opaque authorizing_terminal_id[32];
    ArcCloseIntent close_intent;
    opaque close_intent_id[32];
} ArcCloseAuthorizationTBS;

struct {
    ArcCloseAuthorizationTBS tbs;
    ArcCommitApproval approvals<144..16384>;
} ArcCloseAuthorization;
```

`channel_instance_id` has length 16 only for a channel and
`conversation_nonce` has length 32 only for a direct reservation; the other
field is empty. The sequencer signs a reservation with label
`ARC-MLS/1 reservation`. Close approvals sign with label
`ARC-MLS/1 close authorization`, satisfy the last finalized policy's
controller rule, and reference the finalization ID of the exact in-group
active-to-closing transition. The close intent and its ID must equal the
resulting committed lifecycle value. The semantic close ID is
`SHA256("ARC-MLS/1 close authorization id" ||
encoded_ArcCloseAuthorizationTBS)`; approval subsets do not alter it.
Closing does not make a live channel plaintext-capable.

A reservation returns the exact signed/typed `ArcReservation` object.
`context-digest` is
`SHA256("ARC-MLS/1 context hash" || encoded_ArcMlsContext)`; the BIND line also
carries the independently verifiable signed binding as a tagged object. The
creator constructs both before the reservation expires.

Channel reservation requires membership and channel permission. Direct
reservation binds the authenticated sender and named peer. Binding is atomic;
only one binding may win for the same channel instance or direct-conversation
generation.

`BIND`, `CLOSE`, and route-changing operations carry the matrix-required
typed object in the fragment tag. A bare reason string never closes a binding.
Closing or replacing a binding is a security reset. Clients with a pinned
binding **MUST NOT** accept a replacement solely because the server reports
one. They require an authorized encrypted transition or explicit user reset.

A reservation expires after `RESERVATION_TIMEOUT` and has no security effect. Successful
BIND is the atomic activation barrier: the server durably stores the binding,
rejects plaintext `PRIVMSG` and `NOTICE`, removes or rejects sessions that lack
the complete E2EE capability set, and echoes `BOUND` before accepting encrypted
application traffic. Version 1 does not upgrade a live plaintext channel in
place; it requires a fresh channel instance or an explicit freeze-and-recreate
operation whose old transcript stays visibly separate. A binding survives
server restart until authorized close or destruction of that exact channel
instance. Legacy clients receive `FAIL ... E2EE_CAP_REQUIRED` and never join
as apparent encrypted members.

### 11.6 Identity, KeyPackage, and Welcome command

`EKEY` is an authenticated directory and device-mailbox command:

```text
EKEY FETCH IDENTITY <account-token>
EKEY FETCH ROOT-CHAIN <account-token> <first-generation> <cursor-or-star>
EKEY PUBLISH IDENTITY
EKEY FETCH ROSTER <account-token>
EKEY PUBLISH ROSTER
EKEY FETCH CAPABILITIES <account-token> <cursor-or-star>
EKEY PUBLISH CAPABILITIES <device-id>
EKEY FETCH BINDING-LOCKS <account-token> <root-fingerprint> <first-sequence> <cursor-or-star>

EKEY WHOAMI
EKEY ATTACH BEGIN <device-id>
EKEY ATTACH FINISH <device-id>

EKEY CLAIM PACKAGE <account-token> <device-id> <mls-suite> <operation-id>
EKEY CLAIM STATUS <operation-id>
EKEY PUBLISH PACKAGE <device-id> <mls-suite> NORMAL <expires-at>
EKEY REVOKE PACKAGE <key-package-ref>

EKEY DELIVER BINDING <account-token> <device-id>
EKEY DELIVER WELCOME <account-token> <device-id> <conversation-id> <authorization-id>
EKEY FETCH MAILBOX <APPLICATION|BINDING|WELCOME|STAGED-REINIT> <cursor-or-star>
EKEY ACK MAILBOX <delivery-token> <object-id>
```

Device attachment is connection-bound proof of possession:

```text
struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque account_id<1..255>;
    opaque device_id[16];
    opaque connection_nonce[32];
    opaque server_challenge[32];
    uint64 session_generation;
    uint64 issued_at;
    uint64 expires_at;
} ArcDeviceAttachTBS;

struct {
    ArcDeviceAttachTBS tbs;
    opaque sequencer_signature[64];
} ArcDeviceAttachChallenge;

struct {
    ArcDeviceAttachChallenge challenge;
    opaque device_signature[64];
} ArcDeviceAttach;
```

The edge creates a fresh 32-byte `connection_nonce` when TLS authentication
completes and registers it with the coordinator's origin state. The
coordinator creates an independent 32-byte `server_challenge` for each
`BEGIN`; neither value is client-selected or reusable.

`BEGIN` returns a typed `ArcDeviceAttachChallenge` whose sequencer signature uses label
`ARC-MLS/1 device attach challenge`. The device adds a signature over the same
TBS with label `ARC-MLS/1 device attach possession` and returns the exact
challenge inside `ArcDeviceAttach` with
`FINISH` within `ATTACH_CHALLENGE_TIMEOUT`. The server checks the immutable authenticated
Account ID, current context-independent root roster, active certificate, exact
connection nonce, and unused challenge, then binds that Device ID and the next
session generation to the connection. `session_generation` is a durable
nonzero uint64 counter scoped to the Account ID and Device ID. Its first value
is one, every successful attachment increments it exactly once in the same
transaction, it never wraps or reuses a value after restart, and zero means no
attached device. `BEGIN` reserves that next value and invalidates any earlier
outstanding challenge for the same connection and device; `FINISH` succeeds
only by compare-and-swap against the durable prior value. Reconnect, logout,
account switch, or TLS termination invalidates the attachment.

`WHOAMI` returns the immutable Account ID and current session generation; it
is distinct from the mutable IRCv3 `account` tag. Mailbox delivery creates a
random 32-byte `delivery-token` disclosed only to a currently attached target
device. Fetch, acknowledgement, and deletion require both the attached Device
ID and token, so another same-account session cannot consume its mailbox.

A token expires after `MAILBOX_DELIVERY_TOKEN_TIMEOUT` and is bound to the mailbox snapshot,
object ID, target Device ID, attachment session generation, and delivery
attempt. Reconnect or detachment invalidates the token but does not consume the
object; the next fetch atomically issues a fresh token. ACK is an idempotent
transaction: the server durably records `(device_id, delivery-token,
object-id) -> acknowledged` before making the object unavailable, retains that
result for `MAILBOX_ACK_RETENTION`, and returns the same `ACKED` outcome to an
identical retry. Different parameters under a used token are rejected. A
crash can therefore cause redelivery, never silent deletion.

Client `PUBLISH` and `DELIVER` lines carry a `+agenc.ag/e2ee` fragment tag. `FETCH`
and `CLAIM` responses use server-initiated vendor batches and the same fragment
format. The command context states whether the object is a root identity,
roster, device capability statement, binding request, MLS KeyPackage, or MLS
Welcome. A capability statement is signed by the named device authorization
key and binds its supported MLS versions, suites, credential types,
extensions, proposal types, generation, and roster ID. Fetching it never
consumes a KeyPackage.

For a normal `ArcDeliveredWelcome`, the command Account ID, Device ID,
conversation ID, and authorization ID match the wrapper target, conversation,
and finalization ID exactly. For `ArcStagedReInit`, they match the wrapper
target, new conversation, and ReInit attempt ID. A mismatch is rejected before
mailbox insertion.

`FETCH ROOT-CHAIN` returns a contiguous, immutable-snapshot page beginning at
the requested generation. Every page repeats the same snapshot token and
continues with no generation gap; the final root must match the requested
account and every continuity signature. A missing generation blocks identity
advancement. `FETCH IDENTITY` remains a current-head convenience and never
licenses skipping this chain.

`FETCH BINDING-LOCKS` is likewise an immutable, contiguous page for the exact
Account ID and root fingerprint. Sequence zero starts that root's chain; a
request never merges lock sequences from two root generations.

`FETCH CAPABILITIES` pages the exact current-roster device set in canonical
Device-ID order under one immutable snapshot. Every active device appears
exactly once, no inactive device appears, and each returned capability object
is the highest accepted generation for that device and named roster.

`operation-id` is 16 random client bytes. The coordinator transactionally maps
`(claiming_account_id, operation_id)` to the exact claim parameters and result
before consuming a package. `CLAIM STATUS` returns that stored result: its
`EKEY CLAIMED` line names the target device, KeyPackageRef, and object that
the claim's own `CLAIM PACKAGE` answer named, never the device attached to the
connection that asks. An identical retry is idempotent; reuse with different
parameters is rejected. The mapping survives reconnect and is retained through
at least the later of the claimed package lifetime and
`KEY_PACKAGE_CLAIM_TIMEOUT`.

The server **MUST**:

- allow publishing only for the authenticated Account ID;
- validate object type and declared bounds before storage;
- atomically dispense a normal KeyPackage at most once;
- claim only a package with at least `MIN_KEY_PACKAGE_CLAIM_VALIDITY`
  remaining at the authenticated server time;
- rate-limit claims so an attacker cannot exhaust another account's stock;
- require the signed leaf authorization's `last_resort` bit to be zero;
- deliver bindings and Welcomes only to the exact Account ID and Device ID in
  the validated target roster, and require sender authorization for the named
  conversation;
- delete or make unavailable an acknowledged Welcome according to retention
  policy; and
- avoid logging tag values or serialized key material at normal log levels.

Every application, candidate, ACK, authorization, finality, abort, ReInit,
Welcome-delivery, and mailbox operation requires a connection-bound attached
Device ID that is active in the highest accepted roster. Submission and
delivery stop atomically on detach, logout, account switch, CAP loss, or TLS
termination. Servers perform only this visible envelope/session check;
decrypted leaf, policy, controller, ACK-coverage, and quorum validation is
authoritative at endpoints.

The client still authenticates every returned object cryptographically. Server
directory authorization is not identity proof.

### 11.7 Exact success and object-response grammar

Extension success responses are server-prefixed and use these fixed forms:

```text
@label=<label> :server EGROUP BOUND <conversation-id> <binding-id>
@label=<label> :server EGROUP CLOSED <conversation-id> <close-id>
@label=<label> :server EGROUP STORED AUTHORIZATION <conversation-id> <candidate-id> <approval-object-id>
@label=<label> :server EGROUP STORED POLICY <conversation-id> <policy-id> <policy-object-id>
@label=<label> :server EGROUP STORED MEMBERSHIP <conversation-id> <leaf-membership-id> <membership-object-id>
@label=<label> :server EGROUP RECOVERY-ACCEPTED <conversation-id> <submission-id>
@label=<label> :server EGROUP RECOVERY-EXTENDED <conversation-id> <route-sequence> <record-id>
@label=<label> :server EGROUP RECOVERY-CLOSED <conversation-id> <close-id>
@label=<label> :server EGROUP RECOVERY-CONFLICT <conversation-id> <route-sequence> <first-record-id> <second-record-id>
@label=<label> :server EGROUP ACKED <conversation-id> <candidate-id> <ack-object-id>
@label=<label> :server EGROUP PENDING <conversation-id> <FINALIZATION|ABORT|REINIT-ATTEMPT|REINIT-ACTIVATE|REINIT-ABORT> <object-id>
@label=<label> :server EGROUP FINALIZED <conversation-id> <resulting-epoch> <finalization-id> <certificate-object-id>
@label=<label> :server EGROUP ABORTED <conversation-id> <candidate-id> <abort-id> <certificate-object-id>
@label=<label> :server EGROUP REINIT-STAGED <old-conversation-id> <reinit-attempt-id> <attempt-object-id>
@label=<label> :server EGROUP REINIT-ACKED <old-conversation-id> <reinit-attempt-id> <ack-object-id>
@label=<label> :server EGROUP REINIT-ACTIVATED <old-conversation-id> <new-conversation-id> <activation-id> <certificate-object-id>
@label=<label> :server EGROUP REINIT-ABORTED <old-conversation-id> <reinit-attempt-id> <abort-id> <certificate-object-id>
@label=<label> :server EGROUP EMPTY <AUTHORIZATIONS|ACKS|RECEIPTS|OBJECTS>

@label=<label> :server EKEY ACCOUNT <account-token> <session-generation>
@label=<label> :server EKEY ATTACHED <device-id> <session-generation>
@label=<label> :server EKEY STORED <IDENTITY|ROSTER|CAPABILITIES|PACKAGE|APPLICATION|BINDING|WELCOME|STAGED-REINIT> <object-id>
@label=<label> :server EKEY REVOKED <key-package-ref>
@label=<label> :server EKEY ACKED <delivery-token> <object-id>
@label=<label> :server EKEY EMPTY <IDENTITY|ROOT-CHAIN|ROSTER|CAPABILITIES|PACKAGE|APPLICATION|BINDING|BINDING-LOCK|WELCOME|STAGED-REINIT>

:server EGROUP FINALIZED <conversation-id> <resulting-epoch> <finalization-id> <certificate-object-id>
:server EGROUP ABORTED <conversation-id> <candidate-id> <abort-id> <certificate-object-id>
:server EGROUP CLOSED <conversation-id> <close-id>
:server EGROUP REINIT-STAGED <old-conversation-id> <reinit-attempt-id> <attempt-object-id>
:server EGROUP REINIT-ACTIVATED <old-conversation-id> <new-conversation-id> <activation-id> <certificate-object-id>
:server EGROUP REINIT-ABORTED <old-conversation-id> <reinit-attempt-id> <abort-id> <certificate-object-id>
```

The shown `@label` appears only on the response copy sent to the requesting
connection. The six untagged forms are the only asynchronous server state
broadcasts. A requesting connection receives either its one labeled terminal
line or an earlier labeled `PENDING` followed later by the untagged broadcast,
never two labeled completions.

`reservation-id` is 16 random bytes in unpadded base64url. Its fetched object
contains the profile and network IDs, conversation kind, canonical route
inputs, route binding, full sequencer credential, expiry, and every advertised
limit. Unknown extra parameters are not permitted in version 1.

The longest client command form is `EKEY FETCH BINDING-LOCKS` with its exact
32-character Account token, 43-character root fingerprint, maximum 20-digit
sequence, and 43-character cursor. It is 168 non-tag bytes including CRLF. An
extension server prefix is at most
`MAX_E2EE_SERVER_PREFIX_BYTES`; every production above and below must remain
at most 512 non-tag bytes including that prefix and CRLF. An implementation
generates and tests each exact bound rather than truncating a parameter. The
longest recovery command, `EGROUP SUBMIT RECOVERY-ELEMENT` with its
conversation ID and submission ID, is 99 non-tag bytes including CRLF, and the
longest recovery success body, `RECOVERY-CONFLICT` with its conversation ID,
20-digit sequence, and two record IDs, is 177 bytes before the prefix and
CRLF; neither exceeds the existing maxima, so the published wire-budget table
is unchanged by them.

`key-package-ref` is unpadded base64url of the exact RFC 9420 `KeyPackageRef`;
its decoded length is the selected suite's hash length and is not assumed to
be 32 bytes.

Every directory, mailbox, or fetch response containing one or more objects
uses exactly one batch. Live `TAGMSG`/`EDIRECT` echo and candidate echo remain
their original command with the preserved client tag and are never wrapped in
this response batch:

```text
@label=<label> :server BATCH +<batch-id> agenc.ag/e2ee-objects <request-command> <object-kind> <scope-token> <snapshot-token> <next-cursor-or-star>
@batch=<batch-id> :server EGROUP RESERVED <reservation-id> <reservation-object-id>
@batch=<batch-id> :server EGROUP BOUND <conversation-id> <binding-id> <binding-object-id>
@batch=<batch-id> :server EGROUP CANDIDATE <conversation-id> <candidate-object-id> <candidate-id>
@batch=<batch-id> :server EGROUP FINALIZED <conversation-id> <resulting-epoch> <finalization-id> <certificate-object-id>
@batch=<batch-id> :server EGROUP ABORTED <conversation-id> <candidate-id> <abort-id> <certificate-object-id>
@batch=<batch-id> :server EKEY ATTACH-CHALLENGE <device-id> <challenge-object-id>
@batch=<batch-id> :server EKEY CLAIMED <device-id> NORMAL <key-package-ref> <object-id>
@batch=<batch-id> :server EKEY MAILBOX <delivery-token> <device-id> <object-id>
@batch=<batch-id>;agenc.ag/e2ee=<fragment-value> :server EOBJECT <object-kind> <scope-token> <object-id>
... zero or more additional fragments for at least one EOBJECT ...
:server BATCH -<batch-id>
```

Exactly one operation-result metadata child appears when applicable. A
mailbox FETCH has one `MAILBOX` child immediately before each object's first
EOBJECT fragment; an ordinary FETCH has none. Other success forms never share
the response label with a second logical response.

Successful `EGROUP BIND` uses the scalar labeled `BOUND` form because the
requester supplied and retained the exact binding package. Successful
`EGROUP QUERY CHANNEL` or `QUERY DIRECT` instead uses one object batch with the
`BOUND` metadata child and the exact current `BINDING` object; its metadata
object ID equals the EOBJECT ID. A query never returns only semantic binding
IDs that the client cannot resolve to authenticated bytes.

`object-kind` is exactly one of `APPLICATION`, `COMMIT`, `AUTHORIZATION`,
`ACK`, `FINALIZATION-REQUEST`, `FINALIZATION-CERTIFICATE`, `ABORT-REQUEST`,
`ABORT-CERTIFICATE`, `WELCOME`, `IDENTITY`, `ROOT-CHAIN`, `ROSTER`,
`CAPABILITIES`, `PACKAGE`, `BINDING`, `CLOSE`, `RESERVATION`,
`REINIT-ATTEMPT`, `STAGED-REINIT`, `REINIT-ACK`,
`REINIT-ACTIVATION-REQUEST`, `REINIT-ACTIVATION-CERTIFICATE`,
`REINIT-ABORT-REQUEST`, `REINIT-ABORT-CERTIFICATE`, `SEQUENCER-RECORD`,
`DEVICE-ATTACH-CHALLENGE`, `DEVICE-ATTACH`, `BINDING-LOCK`,
`FEDERATION-STATE`, `FEDERATION-ORIGIN`, `FEDERATION-REQUEST`,
`FEDERATION-RESULT`, `FEDERATION-EVENT`, `POLICY`, `RECOVERY-SUBMISSION`,
`WITNESS-RESOLUTION`, or `LEAF-MEMBERSHIP-PROOF`; these map by ordinal to the
registry in Section 11.4. `scope-token` is a fresh 16-byte response-scope ID in
unpadded base64url, not a repeated Account ID. The explicit object ID must equal the
tag's object ID on every fragment. All fragments for an object stay in one
batch; a batch does not mix request labels or scopes. The server echoes the
request's canonical safe `label` on the opening response under IRCv3 labeled
response rules. Errors use Section 11.9 instead of a partial success batch.
`request-command` is exactly `EGROUP` or `EKEY` and matches the original
top-level command; the label, object kind, and server-bound snapshot state
identify its exact subcommand.

`batch-id` is unique among open batches on the connection and matches
`1*64(ALPHA / DIGIT / "-")`. `snapshot-token`, continuation cursors, and
delivery tokens are 32 random bytes in unpadded base64url. A cursor is valid
only with its original attached device or authenticated Account ID, request
kind, scope, and immutable snapshot; it expires after
`DIRECTORY_CURSOR_TIMEOUT`. One batch
contains at most `MAX_BATCH_OBJECTS`, `MAX_BATCH_FRAGMENTS`, and
`MAX_BATCH_DECODED_BYTES`. The opener names the next cursor or `*` when the
snapshot is exhausted. Empty pages use the fixed `EMPTY` response and do not
open a batch.

The server echoes every accepted candidate and application object to the
submitting connection as exact bytes. A creator therefore never depends on a
locally assumed echo when deciding whether its Commit was sequenced.

Live forwarding uses only these exact productions. The first three are
fragment-zero requester echoes and are the operation's sole labeled success;
the rest are unlabeled recipient copies or later fragments:

```text
@label=<label>;account=<mutable-account>;+agenc.ag/e2ee=<fragment-zero> :source TAGMSG #channel
@label=<label>;account=<mutable-account>;+agenc.ag/e2ee=<fragment-zero> :source EDIRECT <conversation-id>
@label=<label>;account=<mutable-account>;agenc.ag/e2ee-receipt=<receipt>;+agenc.ag/e2ee=<fragment-zero> :source EGROUP CANDIDATE <conversation-id> <object-id> <candidate-id>
@account=<mutable-account>;+agenc.ag/e2ee=<fragment> :source TAGMSG #channel
@account=<mutable-account>;+agenc.ag/e2ee=<fragment> :source EDIRECT <conversation-id>
@account=<mutable-account>;agenc.ag/e2ee-receipt=<receipt>;+agenc.ag/e2ee=<fragment-zero> :source EGROUP CANDIDATE <conversation-id> <object-id> <candidate-id>
@account=<mutable-account>;+agenc.ag/e2ee=<later-fragment> :source EGROUP CANDIDATE <conversation-id> <object-id> <candidate-id>
:source EGROUP ACK <conversation-id> <candidate-id> <ack-object-id>
:source EGROUP REINIT-ACK <old-conversation-id> <reinit-attempt-id> <ack-object-id>
```

`fragment-zero` has index zero; `later-fragment` has a nonzero index; plain
`fragment` may be either. A candidate fragment zero always carries the receipt
tag and a later fragment never does. ACK submission
gets only the labeled `ACKED` scalar; the final unlabeled line merely notifies
other sessions to fetch its object. ReInit ACK uses the same rule and its
distinct `REINIT-ACK` literal prevents a candidate/attempt ID substitution.
Finalization and abort proofs may be too large for live
fanout; their submission receives `PENDING`, and other endpoints receive only
the fixed untagged `FINALIZED`/`ABORTED` metadata line before fetching the
typed record in a bounded batch. An ordinary application echo remains
`TAGMSG` or `EDIRECT`, never `EOBJECT`.

### 11.8 Fragment processing

The receiver keys an in-progress object by the exact tuple

```text
(direction,
 authenticated connection and session generation or canonical S2S Origin ID,
 command, subcommand, normalized route,
 response scope and batch ID, object ID)
```

The first accepted fragment pins that tuple, every repeated command parameter,
`count`, and `total`;
any later disagreement invalidates and discards that one assembly. Attacker-
chosen alternate counts or totals never create parallel allocations for the
same object ID.

It **MUST** reject before significant allocation when:

- the version, field count, decimal syntax, base64url syntax, or tag escaping
  is invalid;
- `count` is zero or exceeds the fragment limit;
- `part >= count`;
- `total` exceeds the command-specific object limit;
- `total` is zero;
- `count != ceil(total / 2940)`;
- a non-final decoded segment is not exactly 2940 bytes;
- decoded segment lengths cannot total the declared size;
- duplicate indexes carry different bytes;
- the reassembly timeout, connection quota, account quota, or route quota is
  exceeded; or
- the final SHA-256 digest does not equal `object-id`.

Identical duplicate fragments may be ignored and do not refresh an idle or
absolute deadline. Remote/federated and response fragments may arrive out of
order. No fragment is delivered onward until the whole object passes transport
validation and minimal bounded type parsing.

For local client ingress, fragment zero is mandatory first and later fragments
are strictly contiguous in ascending order. The ingress server permits only
one such in-progress object per local sender,
which allows streaming validation without sparse attacker-controlled
allocation. Federated and recipient-side code still keys assembly by object ID
and tolerates bounded interleaving between different senders.

Before accepting the first fragment seen for an assembly - fragment zero for
local client ingress, or any index for an out-of-order remote/response path -
the receiver atomically reserves declared `total` bytes and one object against
the connection, Account ID, route, federation peer, and process-global
reassembly quotas. No sparse state or segment bytes are retained before that
reservation succeeds. Every quota is released
on completion or discard. Reconnects do not release account-charged abuse
history, and duplicate content addresses use the recent-object idempotency
cache rather than consuming a second reservation or causing repeat fanout.

Transport hashing detects corruption and chunk-mixing. MLS authentication,
not the transport hash, supplies cryptographic message authenticity.

### 11.9 Standard replies

Servers use IRCv3 `FAIL`, `WARN`, and `NOTE`, not new private numerics, except
where IRC already mandates a numeric. In particular, client tag data over
4094 bytes produces `417 ERR_INPUTTOOLONG` before extension parsing; it is not
replaced by `FAIL`. Existing RFC routing numerics likewise retain their normal
meaning. At minimum the following reply codes are defined for the associated
command:

```text
:server FAIL <actual-command|*> <code> [context-token] :description
```

The optional context is one already supplied by the requester, such as a
conversation or reservation ID. It never contains object bytes or newly
disclosed identity material.

| Code | Meaning |
| --- | --- |
| `E2EE_CAP_REQUIRED` | Required capability was not negotiated |
| `E2EE_ACCOUNT_REQUIRED` | Connection lacks an authenticated account |
| `E2EE_DEVICE_REQUIRED` | Connection lacks a current roster-active device attachment |
| `E2EE_INVALID_FRAGMENT` | Fragment grammar, encoding, or consistency failed |
| `E2EE_OBJECT_TOO_LARGE` | Declared or decoded object exceeds its limit |
| `E2EE_REASSEMBLY_LIMIT` | Memory, object-count, or timeout limit reached |
| `E2EE_HASH_MISMATCH` | Reassembled bytes do not match the object ID |
| `E2EE_ROUTE_INVALID` | Route is unknown or does not match the sender |
| `E2EE_GROUP_CONFLICT` | A binding already exists |
| `E2EE_BINDING_AUTH_INVALID` | Binding or transition authorization is missing or malformed |
| `E2EE_CANDIDATE_ACTIVE` | The epoch already has an unfinalized candidate |
| `E2EE_FINALITY_REQUIRED` | Operation named a candidate without a valid finalization |
| `E2EE_POLICY_INVALID` | A published policy failed route, chain, or approval validation |
| `E2EE_POLICY_REQUIRED` | A terminal request named a policy the server has not retained |
| `E2EE_EPOCH_STALE` | A Commit or proof references an epoch outside the bounded window |
| `E2EE_OBJECT_NOT_FOUND` | Requested retained object or record is unavailable |
| `E2EE_RATE_LIMITED` | Operation exceeded an authenticated quota |
| `E2EE_KEY_UNAVAILABLE` | No acceptable KeyPackage is available |
| `E2EE_OPERATION_CONFLICT` | A stable operation ID was reused with different parameters |
| `E2EE_DELIVERY_UNCERTAIN` | Coordinator accepted the request but ingress lost its correlated result |
| `E2EE_SYNCING` | Federation route state has not crossed the READY/ACTIVE barrier, or the pinned sequencer credential cannot sign at this time |
| `E2EE_REQUIRED` | Plaintext is forbidden for the target |

Descriptions contain no ciphertext, key material, credentials, or sensitive
identity document contents.

The command parameter is the actual triggering command, including `JOIN`,
`PRIVMSG`, or `NOTICE`; `*` is used only when parsing or session state fails
before a command is available. A legacy client that lacks `standard-replies`
is rejected with the command's normal numeric/error path before it becomes a
channel member. It is never briefly admitted and later removed merely to show
an E2EE error.

### 11.10 Canonical wire tokens

Command and subcommand literals in this document are uppercase and
case-sensitive. Each production has exactly the shown parameter count; no
optional trailing parameter exists in version 1. The remaining token grammar
is:

```text
b64char       = ALPHA / DIGIT / "-" / "_"
b64url        = 1*b64char
id16-token    = 22b64char              ; exactly 16 decoded bytes
hash-token    = 43b64char              ; exactly 32 decoded bytes
profile-hash  = hash-token             ; Section 2.3 profile digest
device-id     = id16-token
operation-id  = id16-token
request-id    = id16-token
event-id      = id16-token
origin-id     = id16-token
reservation-id = id16-token
server-id     = id16-token
server-incarnation = id16-token
scope-token   = id16-token
conversation-id = hash-token
object-id     = hash-token
candidate-id  = hash-token
terminal-id   = hash-token
binding-id    = hash-token
policy-id     = hash-token
delivery-token = hash-token
snapshot-token = hash-token
account-token = 32b64char              ; exactly 24 decoded Account ID bytes
key-package-ref = 1*340b64char         ; 1..255 decoded bytes
batch-id      = 1*64(ALPHA / DIGIT / "-")
safe-label    = 1*64b64char
uint16-dec    = "0" / (%x31-39 *4DIGIT)
uint32-dec    = "0" / (%x31-39 *9DIGIT)
uint64-dec    = "0" / (%x31-39 *19DIGIT)
cursor        = "*" / hash-token
reason-code   = uint16-dec
mls-suite     = uint16-dec
expires-at    = uint64-dec
route-sequence = uint64-dec
resulting-epoch = uint64-dec
root-generation = uint64-dec
session-generation = uint64-dec
page-sequence = uint32-dec
response-index = uint16-dec
state-generation = uint64-dec
delivery-generation = uint64-dec
delivery-sequence = uint64-dec
star-delivery-sequence = "*" / uint64-dec
star-event-id = "*" / event-id
entry-count = uint32-dec
snapshot-cursor = hash-token
next-snapshot-cursor = "*" / snapshot-cursor
submission-id = hash-token
record-id     = hash-token
first-record-id = hash-token
second-record-id = hash-token
leaf-membership-id = hash-token
membership-object-id = hash-token
resolution-token = id16-token
resolution-object-id = hash-token
record-object-id = hash-token
expected-head-id = hash-token
new-head-id   = hash-token
expected-sequence = uint64-dec
new-head-sequence = uint64-dec
entry-sequence = uint32-dec
record-count  = uint32-dec
mailbox-kind  = "APPLICATION" / "BINDING" / "WELCOME" / "STAGED-REINIT"
```

Every decimal is range-checked after rejecting a leading zero. Every base64url
token is unpadded, has canonical unused bits, and re-encodes identically. The
allowed request-command values are exactly `EGROUP` and `EKEY`, and the
object-kind values are the literals listed in Section 11.7; result,
pending-operation, mailbox, and store kind tokens are likewise closed
registries from their exact productions.
Every angle-bracket field whose semantic type is a 16- or 32-byte ID uses the
matching production above. Server-added tags are serialized before the
preserved client-only `+agenc.ag/e2ee` tag for reproducible wire-budget tests;
receivers do not assign security meaning to tag order.

## 12. Commit ordering, acknowledgement, and federation

### 12.1 One active candidate; no local skipping

Ordering alone cannot make Commit validity global. RFC 9420 Section 16.12
allows a malicious insider to create an UpdatePath that some recipients can
process and others cannot. This profile therefore separates *sequenced* from
*finalized* and never asks clients to select their own first-valid candidate.

For prior epoch `N`, an honest sequencer exposes exactly one active candidate.
A malicious sequencer may expose forks, so endpoint finality, not that
promise, supplies the security invariant:

1. The server reassembles the typed `commit_mls` object and performs only
   visible, bounded checks: outer MLS group ID, epoch, content type, AAD route,
   authenticated Account ID, object limits, and rate limits. A PrivateMessage
   hides the sender leaf, Commit, Proposals, and UpdatePath; the server cannot
   inspect them, enforce inline-only proposals, derive copath coverage, or
   charge a leaf-level quota. It charges the authenticated account and attached
   device instead.
2. The sequencer assigns a route sequence and signs a `CandidateReceipt`, then
   broadcasts the unchanged object and receipt. This does not advance accepted
   epoch state or release a Welcome.
3. Each old endpoint durably locks that record position, decrypts the Commit,
   requires every Proposal to be inline, and validates MLS plus the complete
   application policy. A continuing endpoint stages epoch `N+1` separately
   and independently derives the exact authorization TBS; a removal target
   follows the public-only path in Section 12.3.
4. Continuing endpoints report `VALID`, `DEFINITIVELY_INVALID`, or
   `LOCAL_STATE_MISSING`. The last result triggers fetch/resynchronization and
   never permits local skipping. An irreconcilable client halts and rejoins.
5. Required controllers publish candidate-specific approval envelopes. Valid
   continuing endpoints produce processing ACKs. An endpoint assembles a
   bounded `ArcFinalizationRequest`; finality principals independently
   validate its authorization, approvals, and ACKs and issue durable sign-once
   disposition votes.
6. The staged state becomes live only after a finalization certificate carries
   the old policy's controller authorization when required, complete processing
   evidence, and an intersecting finality quorum. Abandonment similarly needs
   a quorum abort certificate before the next candidate receipt may extend it.

A timeout pauses the conversation and exposes recovery controls; it never
automatically advances. A finality voter that has signed `FINALIZE` cannot
later vote `ABORT`, even if the sequencer withholds the certificate. This may
deny service, but under the stated fault bound it prevents two partitions from
obtaining conflicting terminal quorums.

### 12.2 Candidate receipt

```text
struct {
    opaque network_id[32];
    opaque conversation_id[32];
    opaque group_id<1..255>;
    opaque binding_id[32];
    opaque context_core_id[32];
} ArcGroupGenesisTBS;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque conversation_id[32];
    uint64 route_sequence;
    uint64 prior_epoch;
    uint64 resulting_epoch;
    uint32 candidate_sequence;
    opaque commit_object_id[32];
    opaque prior_state_id[32];
    opaque predecessor_record_id[32];
    uint64 sequenced_at;
    opaque sequencer_key_id[32];
} ArcCandidateReceiptTBS;

struct {
    ArcCandidateReceiptTBS tbs;
    opaque sequencer_signature[64];
} ArcCandidateReceipt;
```

`genesis_state_id` is
`SHA256("ARC-MLS/1 group genesis id" || encoded_ArcGroupGenesisTBS)`. A new
binding uses it as both its accepted state ID and external record-head anchor.
A ReInit successor instead uses the verified `reinit_activation_id` as both
anchors.

The sequencer signs the TBS with label `ARC-MLS/1 candidate receipt`.
`candidate_id` is the Section 2.2 hash of the receipt TBS, excluding the
signature. For a fresh epoch, `candidate_sequence` is zero and
`predecessor_record_id` equals `prior_state_id`; its route sequence is zero for
a new conversation log. After an abort, the next candidate increments
`candidate_sequence`, names that `abort_id` as predecessor, and uses the next
route sequence. After finalization the next epoch resets the candidate
sequence to zero and uses that `finalization_id` for both `prior_state_id` and
predecessor. A ReInit successor has its own route sequence zero and names the
activation ID as its external predecessor. `sequenced_at` is informational
and is never certificate time.

Every sequencer record after route sequence zero has sequence exactly one
greater than its predecessor record and names that record's semantic ID.
Sequence zero names only the genesis or ReInit external anchor. No counter
wraps. Proof variants for one semantic record reuse the same sequence and
predecessor and never advance the log twice.

The receipt is attached to fragment zero with server tag
`agenc.ag/e2ee-receipt`. Clients verify its exact signature, key generation,
semantic ID, chain, object hash, route sequence, and outer MLS fields. A gap blocks staging
until the missing complete records are fetched. The receipt asserts ordering
only.

Fetch and federation encode record history with an exact tagged union:

```text
enum {
    candidate_record(1), finalization_record(2), abort_record(3),
    reinit_attempt_record(4), reinit_activation_record(5),
    reinit_abort_record(6)
} ArcSequencerRecordKind;

struct {
    ArcSequencerRecordKind kind;
    select (kind) {
        case candidate_record: ArcCandidateReceipt candidate;
        case finalization_record: ArcCommitFinalizationCertificate finalization;
        case abort_record: ArcCommitAbortCertificate abort;
        case reinit_attempt_record: ArcReInitAttemptReceipt reinit_attempt;
        case reinit_activation_record: ArcReInitActivationCertificate reinit;
        case reinit_abort_record: ArcReInitAbortCertificate reinit_abort;
    } record;
} ArcSequencerRecord;
```

Unknown union arms and trailing bytes are rejected in profile version 1.
The record ID, sequence, and predecessor are read as follows:

| Kind | Semantic record ID | Sequence/predecessor source |
| --- | --- | --- |
| candidate | `candidate_id` | `ArcCandidateReceiptTBS` |
| finalization | `finalization_id` | `ArcCommitFinalizationTBS` |
| abort | `abort_id` | `ArcCommitAbortTBS` |
| ReInit attempt | `reinit_attempt_id` | `ArcReInitAttemptReceiptTBS` |
| ReInit activation | `reinit_activation_id` | `ArcReInitActivationTBS` |
| ReInit abort | `reinit_abort_id` | `ArcReInitAbortTBS` |

For every row the asserted ID is recomputed, the sequencer key ID equals the
credential committed for that log position, and exact predecessor equality is
mandatory. Alternative proof snapshots for one ID occupy one route sequence.

### 12.3 Commit processing acknowledgements

Profile result digests are always independent 32-byte SHA-256 values, even
when the selected MLS suite uses a 64-byte hash:

```text
struct {
    CipherSuite cipher_suite;
    opaque encoded_group_context<1..1048576>;
} ArcGroupContextDigestTBS;

struct {
    CipherSuite cipher_suite;
    opaque encoded_ratchet_tree<1..4194304>;
} ArcRatchetTreeDigestTBS;

struct {
    CipherSuite cipher_suite;
    opaque encoded_group_info<1..4194304>;
} ArcGroupInfoDigestTBS;
```

The formulas are respectively SHA-256 with labels
`ARC-MLS/1 group context digest`, `ARC-MLS/1 ratchet tree digest`, and
`ARC-MLS/1 group info digest` over the exact TBS encoding. GroupContext and
GroupInfo use their RFC 9420 TLS encodings. `encoded_ratchet_tree` is the exact
canonical TLS encoding of the complete RatchetTree value, not an MLS
suite-hash output. Implementations reject a non-canonical re-encoding.

A member that completely stages the same next state signs:

```text
struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque conversation_id[32];
    uint64 prior_epoch;
    opaque candidate_id[32];
    opaque commit_object_id[32];
    uint32 old_leaf_index;
    opaque old_credential_hash[32];
    uint64 resulting_epoch;
    opaque resulting_group_context_digest[32];
    opaque resulting_ratchet_tree_digest[32];
    opaque finalization_authenticator[32];
} ArcCommitAckTBS;

struct {
    ArcCommitAckTBS tbs;
    opaque old_leaf_signature<1..255>;
} ArcCommitAck;
```

The ACK signs the Section 2 `ArcSignatureInput` with label
`ARC-MLS/1 commit processed` and the encoded ACK TBS as content. The signature uses the ACKing
member's signature key in the old, still-live tree and the signature length
must match that MLS suite. `old_credential_hash` is
`SHA256("ARC-MLS/1 old credential hash" || encoded_BasicCredential)`. The
32-byte `finalization_authenticator` is exported from
the staged new state using the MLS exporter label
`ARC-MLS/1 commit finalization`, the candidate ID as exporter
context, and output length 32. This purpose-scoped value may be exposed to the
sequencer; the underlying epoch authenticator and other MLS secrets may not.

All accepted ACKs agree exactly on network, conversation, prior and resulting
epochs, candidate receipt, Commit object ID, both result digests, and exporter
authenticator. `old_leaf_index`, `old_credential_hash`, and signature are
signer-specific and deliberately differ. The required set contains:

- the Commit sender; and
- one active, retained, pre-existing member from every non-empty subtree rooted at the
  copath node corresponding to each node in the UpdatePath, considering only
  old members that receive that path encryption.

The verifier derives coverage from the old tree and staged Commit; an ACK
cannot claim its own coverage. Removed leaves, newly added leaves, and a
context-marked pending join cannot satisfy ordinary coverage; a pending join
may ACK only its own mandatory confirmation Commit as the sender. A singleton
group needs only the sender ACK. Version 1 requires a
populated UpdatePath on every membership, policy, roster, sequencer, and
recovery Commit.

Before signing, an endpoint durably records the receipt and exact record
position. It never signs ACKs for two forked candidates at that position. A
valid quorum abort advances the record head and permits the next candidate;
local timeout does not.

A removal target is not a failed continuing endpoint. It decrypts and
authenticates the old-epoch Commit framing, verifies its own Remove,
candidate-specific policy authorization, Proposal syntax, public tree update,
receipt, ACK signatures, and finality quorum using old public state. It cannot
derive the new epoch, verify the confirmation tag or exporter, produce a
processing ACK, or compare a staged secret state. It never reports
`LOCAL_STATE_MISSING` for that expected condition. After valid finalization it
purges the group under Section 13.5; an invalid certificate leaves it blocked
on the old state.

This is the application acknowledgement mechanism recommended by RFC 9420
Section 16.12. A dishonest ACK signer can lie, and offline coverage can stop
liveness. Even then, a client whose staged result differs from the certificate
halts instead of selecting another candidate, turning attempted fragmentation
into a visible lockout rather than two automatically advancing honest
histories.

### 12.4 Finalization and abort certificates

```text
struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque conversation_id[32];
    uint64 prior_epoch;
    opaque prior_state_id[32];
    opaque candidate_id[32];
    opaque commit_object_id[32];
    uint64 resulting_epoch;
    opaque old_policy_id[32];
    opaque commit_authorization_id[32];
    opaque acknowledgement_set_digest[32];
    opaque resulting_group_context_digest[32];
    opaque resulting_ratchet_tree_digest[32];
    opaque finalization_authenticator[32];
} ArcFinalizationCoreTBS;

struct {
    ArcFinalizationCoreTBS core;
    ArcCandidateReceipt receipt;
    ArcCommitAuthorization authorization;
    ArcCommitAck acknowledgements<1..262144>;
} ArcFinalizationProof;

enum { finalize(1), abort(2) } ArcDisposition;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque conversation_id[32];
    uint64 prior_epoch;
    opaque prior_state_id[32];
    uint32 candidate_sequence;
    opaque slot_predecessor_record_id[32];
    opaque candidate_id[32];
    ArcDisposition disposition;
    opaque terminal_id[32];
    uint16 reason_code;                  // zero for FINALIZE
} ArcDispositionVoteTBS;

struct {
    opaque signer_root_fingerprint[32];
    opaque signer_device_id[16];
    opaque signer_device_certificate_id[32];
    opaque device_signature[64];
} ArcFinalityVote;

struct {
    ArcFinalizationProof proof;
    ArcFinalityVote votes<0..16384>;
} ArcFinalizationRequest;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque conversation_id[32];
    uint64 route_sequence;
    opaque predecessor_record_id[32];
    opaque finalization_id[32];
    opaque sequencer_key_id[32];
    ArcFinalizationRequest request;
} ArcCommitFinalizationTBS;

struct {
    ArcCommitFinalizationTBS tbs;
    opaque sequencer_signature[64];
} ArcCommitFinalizationCertificate;

struct {
    opaque finalization_id[32];
    opaque finalization_object_id[32];
    opaque added_key_package_ref<1..255>;
    uint32 resulting_leaf_index;
    opaque resulting_leaf_credential_hash[32];
} ArcNormalJoinAuthorizationProof;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque conversation_id[32];
    opaque target_account_id_digest[32];
    opaque target_device_id[16];
    ArcNormalJoinAuthorizationProof authorization;
    ArcJoinTransitionProofBundle transition_proofs;
    opaque welcome_bytes<1..4190000>;
} ArcDeliveredWelcome;
```

`commit_authorization_id` is the Section 2.2 ID over the authorization TBS.
Its proof always appears; only its approval vector may be empty under the
rules in Section 9.3. `acknowledgement_set_digest` uses the Section 2.2
canonical ACK-TBS formula. ACKs are canonical by old leaf index,
duplicate-free, individually verified, and must match that digest.
`finalization_id` is the Section 2.2 ID over `ArcFinalizationCoreTBS`.

Each finality principal independently verifies the exact receipt and Commit,
required controller authorization, inline proposals, roster/context
atomicity, processing ACK signatures and copath coverage, common results, and
its own staged result. A `FINALIZE` vote counts only if the old-policy
principal's exact old leaf remains an active, non-pending MLS member in the
resulting state, its certificate remains active in the resulting committed
roster, and that device personally staged the common context, tree, and
exporter result. A removed or newly revoked principal may perform the
public-only checks in Section 12.3 and vote `ABORT`, but **MUST NOT** vote
`FINALIZE`. It then signs `ArcDispositionVoteTBS` with label
`ARC-MLS/1 disposition vote` using its device-authorization key. All FINALIZE
votes use `finalization_id` as `terminal_id` and reason zero.

The quorum `q` is still derived from the complete old council. Therefore a
candidate is incapable of finalization unless at least `q` old principals are
eligible retained voters. To remove more, first finalize a policy-only council
handoff while those old principals remain MLS members, then remove them in a
later epoch under the new council. The expired-roster recovery path obeys the
same rule. If the handoff quorum is unavailable, the group halts rather than
weakening finality.

The candidate sender is the deterministic request assembler. After coverage
exists, it selects the sender ACK and then, in copath order, the valid covering
ACK with the lowest old leaf index, de-duplicates that vector, persists the
exact proof, and publishes it once. Anyone may retransmit those exact bytes;
creating an alternative proof for the same receipt is invalid. This choice
can sacrifice liveness if the sender disappears, in which case the council
must abort rather than invent another finalization transcript.

Controller devices submit individual `ArcCommitApprovalEnvelope` objects keyed
by the identical authorization TBS ID. Endpoints fetch and verify them; the
deterministic assembler takes at most one valid approval per root, ordered by
root fingerprint and then Device ID, until the required threshold is met.
The server only bounds, stores, and groups identical TBS bytes. It does not
assemble approvals or declare controller validity; controller authorization
remains an endpoint check under the policy.

The finality request may be submitted repeatedly with additional canonical
votes over one fixed proof and core. The sequencer resolves `old_policy_id` to
the retained published policy (Section 9.3); a request naming an unretained
policy, or whose authorization names a resulting policy that is not retained,
fails with `E2EE_POLICY_REQUIRED` and is not retained. `old_policy_id` must be
the conversation's current policy, the one its last finalization installed
and the binding's initial policy before the first; a retained policy that is
not current fails with `E2EE_EPOCH_STALE`, and the authorization's
`old_policy_id` must match. A resulting policy other than the old one must be
the retained policy whose `previous_policy_id` is the old policy at the next
generation; an older or skipped generation fails with
`E2EE_BINDING_AUTH_INVALID`. The sequencer reconstructs the exact
`ArcDispositionVoteTBS` for the slot from its own receipt and verifies each
vote's device signature with the device-authorization key of the retained
roster certificate named by `signer_device_certificate_id`. A vote vector that
is not canonical fails with `E2EE_INVALID_FRAGMENT`; a vote whose signer is
not a finality principal of that policy, names another certificate, or does
not verify fails the request with `E2EE_BINDING_AUTH_INVALID`; a vote from a
principal the sequencer already counted for the other terminal of the same
slot is discarded as a sign-once violation. It counts at most one vote per
principal, keeps the count for the slot across requests so a later request
need only add the missing votes (each counted vote is recorded durably per
principal, and a reloaded coordinator rebuilds the count from those records
and the retained requests they name), and signs the bounded proof snapshot
with
label `ARC-MLS/1 commit finalization` only when at least `q` distinct valid
FINALIZE votes stand. A request below `q` is retained and returns `PENDING`.
Certification makes the authorization's resulting policy the current policy.
The sequencer does not know the old tree, ACK coverage, or staged result, so
its certificate is public evidence that the quorum voted, never a substitute
for the endpoint verification below.
`route_sequence` is exactly the candidate receipt's sequence plus one,
`predecessor_record_id` exactly equals `candidate_id`, and the asserted
`finalization_id` is recomputed from the core. An invalid or under-quorum
sequencer wrapper is ignored and does not consume the endpoint state slot.
Different valid vote subsets may create different transport object IDs, but
they are evidence for the same `finalization_id`, use the same route sequence,
and cannot create different next-state heads. The finalization ID becomes the
next epoch's `prior_state_id`.

For one semantic terminal ID the coordinator keeps a monotonic canonical
proof accumulator, adding at most one validly encoded entry per signer key.
`FETCH RECEIPTS` returns only its latest snapshot at that route sequence;
older snapshots remain fetchable by their content object ID through retention.
Growing this evidence does not append another sequencer record.

An endpoint applies its staged state only after it verifies the candidate,
authorization, every selected ACK, complete copath coverage, the old-policy
finality quorum, identical result values, sequencer chain, and its own staged
result. New-epoch application traffic and ordinary Add
Welcomes are forbidden before this point. If a recipient first sees
new-epoch traffic, it fetches the certificate and does not speculate.

A new Add recipient cannot decrypt the predecessor Commit or verify old-tree
copath coverage. Its `ArcDeliveredWelcome` therefore carries the immutable
MLS Welcome beside the exact post-finalization
`ArcNormalJoinAuthorizationProof` and the external transition-proof bundle
required by Section 9.5. Before consuming the Welcome it verifies
the wrapper's profile, network, conversation, target account digest, and
Device ID, fetches the referenced finalization object, verifies that its
recomputed ID matches, and then validates its KeyPackageRef and leaf index
against the context's sole `pending_joins` entry, validates the resulting
context/tree/credential digests, and verifies the old policy, controller
authorization, and device-key finality quorum from the policy and roster proof
chains. Copath verification remains a continuing-member duty; under the
declared `f` bound, the joiner relies on at least one honest finality voter
having performed it. A delivery wrapper without this exact proof is rejected.
`resulting_leaf_credential_hash` is
`SHA256("ARC-MLS/1 resulting leaf credential" ||
TLS-encode(resulting_leaf_index, encoded_BasicCredential))` and must equal the
credential at that exact leaf in the authenticated resulting ratchet tree;
that credential must resolve to the wrapper's target account digest and Device
ID.
The join bundle's generation-zero binding package and gapless binding/root
chains are mandatory, so the joiner can recompute the initial member-plan ID
and current-binding continuity rather than trusting the Welcome alone.

Abort encoding is:

```text
enum {
    sender_withdrawn(1),
    policy_recovery(2),
    definitively_invalid(3),
    local_state_unavailable(4),
    staging_timeout(5)
} ArcCommitAbortReason;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque conversation_id[32];
    opaque prior_state_id[32];
    opaque candidate_id[32];
    uint64 prior_epoch;
    ArcCommitAbortReason reason;
    opaque evidence_digest[32];
} ArcAbortCoreTBS;

struct {
    ArcAbortCoreTBS core;
    ArcCandidateReceipt receipt;
    ArcFinalityVote votes<0..16384>;
} ArcAbortRequest;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque conversation_id[32];
    uint64 route_sequence;
    opaque predecessor_record_id[32];
    opaque abort_id[32];
    opaque sequencer_key_id[32];
    ArcAbortRequest request;
} ArcCommitAbortTBS;

struct {
    ArcCommitAbortTBS tbs;
    opaque sequencer_signature[64];
} ArcCommitAbortCertificate;
```

`abort_id` is the Section 2.2 ID over `ArcAbortCoreTBS`.
Each council signer uses the same `ArcDispositionVoteTBS`, with disposition
ABORT, that abort ID as `terminal_id`, and the matching non-zero reason. Votes are canonical
by finality principal. Sender withdrawal is a request, not unilateral power;
every abort requires the same derived old-policy quorum `q`. The sequencer
verifies ABORT votes exactly as it verifies FINALIZE votes and signs the abort
TBS with label `ARC-MLS/1 candidate abort` only at `q` or more distinct valid
votes; a request below `q` returns `PENDING`. No valid
finalization and valid abort can coexist under the fault bound because their
quorums intersect in an honest sign-once device. The wrapper's route sequence
is the candidate receipt's `route_sequence` plus one, its predecessor exactly
equals `candidate_id`, and its asserted abort ID is recomputed.

For every candidate receipt, an honest finality device durably records at most
one exact encoded disposition-vote TBS for the slot
`(network_id, conversation_id, prior_epoch, prior_state_id,
candidate_sequence, receipt.predecessor_record_id)`. Forked receipts share
that slot. It never signs a second TBS for that slot, even with the same
disposition. Only a quorum-certified abort advances the local record head and
allows a receipt whose candidate sequence is one greater and whose
predecessor is that abort ID. A FINALIZE vote is permanent even if the
sequencer withholds its wrapper. This is the quorum-intersection rule that
prevents a malicious sequencer from finalizing two partitions; receipt gossip
alone would provide only after-the-fact evidence.

Because the MLS epoch never advanced, a valid abort discards only provisional
next-epoch state. Encoding or decrypting old-epoch PrivateMessages may already
have consumed old handshake-ratchet keys; that progress and every RFC 9420
Section 9.2 deletion remain durably committed and are never rolled back. A
valid abort permits the next candidate. Malicious refusal to ACK or vote can
deny service; it cannot force a fallback or alternate epoch.

The Commit creator follows the same rule as everyone else: generation does
not mutate live state. It persists old and staged states separately, waits for
the returned candidate and finalization, and releases its Welcome material
only after finality. Exact staged bytes are deleted on abort or expiry after an
explicit recovery decision.

Each encrypted application object gossips the latest sequencer record-head ID
and accepted state ID observed by its sender. Different heads can reflect normal
delay, so clients fetch and compare missing signed records first. Two valid
sequencer signatures for different records at the same chain position prove
equivocation. These receipts do not detect selective omission or cross-sender
reordering of application messages, and no receipt scheme defeats permanent
censorship or partitioning. Every edge server additionally witnesses the chain
it projects (Section 12.5): a candidate or terminal event that does not extend
the edge's last head is refused, recorded durably, and closes the federation
link, so a fork is visible at the first honest edge without decrypting
anything.

### 12.5 Federation

All servers in one ARC network share the network ID and route each encrypted
operation to one logical E2EE coordinator named by `coordinator-server-id`.
That service owns the sequencer, directory, device mailboxes, and authoritative
E2EE state/event log; it may use replicated consensus internally, but exposes one
history and one configured 16-byte server ID. Edge servers proxy typed objects
and fanout events. Federation peers never decrypt, normalize, translate,
refragment, or re-encrypt complete object bytes.

Every link carrying encrypted conversations **MUST** negotiate the exact
ARC-MLS link profile and limits immediately after server registration and
before an E2EE route is introduced:

```text
:<server-name> ECAP ARCMLS OFFER 1 <profile-hash> <network-id> <coordinator-server-id> 2940 262144 4194304 4094 4094 8191 <key-set-generation> <key-set-hash>
:<server-name> ECAP ARCMLS ACK 1 <profile-hash> <network-id> <coordinator-server-id> 2940 262144 4194304 4094 4094 8191 <key-set-generation> <key-set-hash>
```

Both lines are untagged, have exactly the shown 14 parameters after `ECAP`,
have no trailing parameter, and carry the authenticated server-name prefix for
that link direction. `profile-hash` is the Section-2.3 value. The six fixed
decimal fields are, in order, maximum raw fragment, live object, Welcome
object, client-originated tag data, server-added tag data, and combined tag
section. Every decimal is canonical; key-set generation is a `uint64-dec`, and
the network, profile, and key-set hashes are `hash-token` values. Under the
127-byte serialized server-prefix ceiling, maximum generation width, and
CRLF, the OFFER is exactly at most 360 bytes and the ACK at most 358 bytes.

After both directions have completed base FREADY, each endpoint enters
`PROFILE_NEGOTIATING`, starts one nonextendable five-second monotonic deadline,
and immediately sends exactly one OFFER constructed from its immutable local
profile constant and fully parsed sequencer-credential file. Per link, the
endpoint owns these four initially false flags: `peer_offer_received`,
`peer_ack_sent`, `peer_ack_received`, and `profile_active`. The only legal
transitions are:

1. The first peer OFFER must have the authenticated prefix and byte-for-byte
   equal tuple of version, profile hash, network, coordinator, six limits,
   key-set generation, and key-set hash. The receiver sets
   `peer_offer_received`, sends exactly one ACK echoing that complete tuple,
   and sets `peer_ack_sent`.
2. The first peer ACK is legal only after the peer OFFER, must have that same
   authenticated prefix, and must echo the receiver's complete local OFFER
   tuple. The receiver sets `peer_ack_received`. An ACK never receives an ACK.
3. `profile_active` becomes true exactly when the peer OFFER has validated,
   the matching ACK has been sent, and the matching peer ACK has validated.
   Only then may either direction send an E2EE origin, state, request, result,
   event, payload, ACK, resume, or snapshot frame.

TCP ordering means an honest ACK cannot arrive before the OFFER that caused
it. A duplicate OFFER or ACK, ACK-before-OFFER, unknown subcommand, wrong
arity, tag, prefix mismatch, field mismatch, timeout at or after the deadline,
or any E2EE frame before `profile_active` sends at most
`ERROR :ARC-MLS profile mismatch` and closes the link. No differing field is
reported, no partial state is retained, and negotiation is never downgraded.
Simultaneous OFFERs follow the same transitions and cannot loop.

`key-set-hash` covers the canonical active network sequencer credentials,
including a bounded rotation overlap. The endpoint verifies every credential,
continuity link, interval, ordering rule, set generation, and computed hash
before it sends OFFER. It durably retains the highest accepted network-wide
set generation and hash. The first configured set initializes that record;
later sets increment generation by exactly one and prove the Section-9.2
credential continuity. A lower generation, a gap, a same-generation different
hash, counter exhaustion, or a locally configured hash mismatch is fatal
before E2EE activation.

The negotiated tuple is immutable for one TLS connection. Sequencer-set
rotation is a coordinated reconnect transition rather than an in-band ECAP
mutation: both endpoints first provision and validate the direct successor,
then stop admitting new E2EE work and close the old link without draining its
outbox. Every previously accepted but not cumulatively acknowledged operation,
result, event, or payload remains in its ordinary durable replay record; a
partially or completely written frame is treated as unacknowledged and may be
sent byte-for-byte after reconnect. The replacement connection repeats
FHELLO/FREADY and this ECAP exchange; neither endpoint relays a receipt under
the new generation until the replacement link is profile-active and its
normal state/resume gate has completed. A file change observed on an active
link triggers this same fail-closed reconnect and never changes the accepted
tuple in place.

Federation never serializes a client command as free-form IRC tokens. It uses
typed request, result, and event objects. All S2S object-bearing lines use the
unprefixed server tag and no `label`, `batch`, `account`, receipt, or preserved
client tag:

```text
@agenc.ag/e2ee=<fragment> :<home-sid> EREQUEST <coordinator-server-id> <server-incarnation> <origin-id> <origin-generation> <operation-sequence> <request-id> <request-object-id>
@agenc.ag/e2ee=<fragment> :<home-sid> EPAYLOAD <coordinator-server-id> <server-incarnation> <origin-id> <origin-generation> <operation-sequence> <request-id> <payload-object-id>
@agenc.ag/e2ee=<fragment> :<coordinator-sid> ERESULT <home-server-id> <server-incarnation> <origin-id> <origin-generation> <operation-sequence> <request-id> <result-object-id>
@agenc.ag/e2ee=<fragment> :<coordinator-sid> ERESPONSE <home-server-id> <server-incarnation> <origin-id> <origin-generation> <operation-sequence> <request-id> <response-index> <object-id>
@agenc.ag/e2ee=<fragment> :<coordinator-sid> EEVENT <target-server-id> <delivery-generation> <delivery-sequence> <event-id> <event-object-id>
@agenc.ag/e2ee=<fragment> :<coordinator-sid> EDATA <target-server-id> <delivery-generation> <delivery-sequence> <event-id> <payload-object-id>
:<edge-sid> EACK <coordinator-server-id> <delivery-generation> <delivery-sequence> <event-id>
:<edge-sid> ERESUME <coordinator-server-id> <server-incarnation> <delivery-generation> <last-delivery-sequence-or-star> <last-event-id-or-star>
:<coordinator-sid> ERESUME OK <target-server-id> <server-incarnation> <delivery-generation> <next-delivery-sequence>
```

Every prefix is the standard authenticated AgenC Relay server identity. Home-origin
commands are accepted only from the named home route; coordinator results,
events, and state are accepted only from the configured coordinator route;
target and coordinator IDs must equal link configuration. A direction or
identity mismatch closes the link as a profile violation.

The explicit object ID equals the fragment tag ID on every object-bearing
line, and every repeated incarnation/origin/generation/sequence/request or
delivery field equals the decoded object. `EACK`, `ERESUME`, and `ERESUME OK`
are untagged and have exactly the shown arity. Their Server Incarnation and
Event ID fields use `server-incarnation` and `event-id`; delivery generation,
delivery sequence, and next sequence use the corresponding canonical decimal
productions in Section 11.10. ERESUME's last-sequence/last-ID fields are either
both `*` or both concrete `star-delivery-sequence`/`star-event-id` values. No
line has a trailing parameter. The complete non-tag portion is at most 512
bytes under the 127-byte server-prefix ceiling, the maximum S2S tag is 3999
bytes, and the complete physical line is therefore below the 8,703-byte S2S
ceiling. Fragment zero is transmitted first and all fragments are contiguous,
although the receiver still reserves quota before the first accepted fragment
of any index. A request completes before its optional payload; a result
completes before its indexed responses; an event completes before its optional
data. Payload-before-descriptor, missing data, duplicate index, index gap,
wrong kind, wrong ID, or extra object is fatal to that transaction. Execution,
result rendering, event application, or fanout begins only after every
required object has validated.

```text
enum {
    application_channel(1), application_direct(2),
    reserve_channel(3), reserve_direct(4), bind_group(5),
    query_channel(6), query_direct(7), close_group(8),
    submit_candidate(9), submit_authorization(10), submit_commit_ack(11),
    submit_finalization(12), submit_abort(13),
    submit_reinit_attempt(14), submit_reinit_ack(15),
    submit_reinit_activate(16), submit_reinit_abort(17),
    fetch_object(18), fetch_authorizations(19), fetch_acks(20),
    fetch_receipts(21), fetch_identity(22), fetch_root_chain(23),
    publish_identity(24), fetch_roster(25), publish_roster(26),
    fetch_capabilities(27), publish_capabilities(28),
    fetch_binding_locks(29), whoami(30), attach_begin(31),
    attach_finish(32), claim_package(33), claim_status(34),
    publish_package(35), revoke_package(36), deliver_binding(37),
    deliver_welcome(38), fetch_mailbox(39), acknowledge_mailbox(40),
    submit_policy(41), submit_recovery(42), submit_recovery_element(43),
    submit_membership(44)
} ArcFederationOpcode;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque home_server_id[16];
    opaque server_incarnation[16];
    opaque origin_id[16];
    uint64 origin_generation;
    uint64 operation_sequence;
    opaque request_id[16];
    ArcFederationOpcode opcode;
    opaque encoded_parameters<0..1024>;
    opaque payload_object_id<0..32>;
} ArcFederationRequest;
```

`encoded_parameters` is exactly one canonical TLS encoding from this table;
it is not a string, map, or extensible list. Account fields use their declared
`opaque<1..255>` envelope but are semantically exactly 24 bytes under Section
8.1; channel-name fields are `opaque<1..255>`, cursors are `opaque<0..32>` with
empty meaning first page, IDs have their fixed sizes, and an unlisted field is
forbidden:

| Opcode | Parameter fields in exact order | Required payload kind |
| --- | --- | --- |
| `application_channel` | conversation ID, channel-instance ID | `application_mls` |
| `application_direct` | conversation ID | `application_mls` |
| `reserve_channel` | channel-instance ID, canonical channel name | none |
| `reserve_direct` | peer Account ID | none |
| `bind_group` | reservation ID, conversation ID, context digest | `conversation_binding` |
| `query_channel` | channel-instance ID, canonical channel name | none |
| `query_direct` | peer Account ID | none |
| `close_group` | conversation ID, reason code | `close_authorization` |
| `submit_candidate` | conversation ID | `commit_mls` |
| `submit_authorization` | conversation ID | `commit_approval` |
| `submit_commit_ack` | conversation ID | `commit_ack` |
| `submit_finalization` | conversation ID | `finalization_request` |
| `submit_abort` | conversation ID | `abort_request` |
| `submit_reinit_attempt` | old conversation ID | `reinit_attempt` |
| `submit_reinit_ack` | old conversation ID | `reinit_ack` |
| `submit_reinit_activate` | old conversation ID | `reinit_activation_request` |
| `submit_reinit_abort` | old conversation ID | `reinit_abort_request` |
| `submit_policy` | conversation ID | `policy` |
| `submit_recovery` | conversation ID | `recovery_submission` |
| `submit_recovery_element` | conversation ID, submission ID | `sequencer_record`, `close_authorization`, or the referenced object's existing kind, exactly as the accepted submission names |
| `submit_membership` | conversation ID | `leaf_membership_proof` |
| `fetch_object` | conversation ID, object ID | none |
| `fetch_authorizations` | conversation ID, candidate ID, cursor | none |
| `fetch_acks` | conversation ID, candidate-or-ReInit-attempt ID, cursor | none |
| `fetch_receipts` | conversation ID, first route sequence, cursor | none |
| `fetch_identity` | Account ID | none |
| `fetch_root_chain` | Account ID, first root generation, cursor | none |
| `publish_identity` | none | `root_identity` |
| `fetch_roster` | Account ID | none |
| `publish_roster` | none | `device_roster` |
| `fetch_capabilities` | Account ID, cursor | none |
| `publish_capabilities` | Device ID | `device_capabilities` |
| `fetch_binding_locks` | Account ID, root fingerprint, first sequence, cursor | none |
| `whoami` | none | none |
| `attach_begin` | Device ID | none |
| `attach_finish` | Device ID | `device_attach` |
| `claim_package` | Account ID, Device ID, suite, operation ID | none |
| `claim_status` | operation ID | none |
| `publish_package` | Device ID, suite, expiry | `key_package_mls` |
| `revoke_package` | KeyPackageRef | none |
| `deliver_binding` | Account ID, Device ID | `conversation_binding` |
| `deliver_welcome` | Account ID, Device ID, conversation ID, authorization ID | `welcome_mls` or `staged_reinit` |
| `fetch_mailbox` | `ArcFederationMailboxKind`, cursor | none |
| `acknowledge_mailbox` | delivery token, object ID | none |

An empty payload ID is legal only for a `none` row; otherwise it is 32 bytes
and names the exact following `EPAYLOAD` object.

```text
enum {
    store_authorization(1), store_identity(2), store_roster(3),
    store_capabilities(4), store_package(5), store_application(6),
    store_binding(7), store_welcome(8), store_staged_reinit(9),
    store_policy(10), store_membership(11)
} ArcFederationStoreKind;

enum {
    pending_finalization(1), pending_abort(2),
    pending_reinit_attempt(3), pending_reinit_activate(4),
    pending_reinit_abort(5)
} ArcFederationPendingKind;

enum {
    empty_authorizations(1), empty_acks(2), empty_receipts(3),
    empty_objects(4), empty_identity(5), empty_root_chain(6),
    empty_roster(7), empty_capabilities(8), empty_package(9),
    empty_application(10), empty_binding(11), empty_binding_lock(12),
    empty_welcome(13), empty_staged_reinit(14)
} ArcFederationEmptyKind;

enum { normal_package(1) } ArcFederationPackageKind;

enum {
    mailbox_application(1), mailbox_binding(2), mailbox_welcome(3),
    mailbox_staged_reinit(4)
} ArcFederationMailboxKind;

enum {
    failed(1), accepted_event(2), bound(3), closed(4), stored(5),
    commit_acked(6), pending(7), empty(8), account(9), attached(10),
    attach_challenge(11), revoked(12), reserved(13), finalized(14),
    aborted(15), claimed(16), object_page(17), mailbox_page(18),
    reinit_staged(19), reinit_acked(20), reinit_activated(21),
    reinit_aborted(22), mailbox_acked(23), recovery_accepted(24),
    recovery_extended(25), recovery_closed(26), recovery_conflict(27)
} ArcFederationResultKind;

struct {
    uint16 response_index;
    ArcWireObjectKind wire_kind;
    opaque object_id[32];
    uint32 total_size;
    opaque delivery_token<0..32>;
    opaque target_device_id<0..16>;
} ArcFederationResponseDescriptor;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque home_server_id[16];
    opaque server_incarnation[16];
    opaque origin_id[16];
    uint64 origin_generation;
    uint64 operation_sequence;
    opaque request_id[16];
    opaque request_object_id[32];
    uint64 coordinator_state_generation;
    opaque completion_event_id<0..16>;
    ArcFederationResultKind result_kind;
    opaque encoded_result<0..1024>;
    opaque snapshot_token<0..32>;
    opaque next_cursor<0..32>;
    ArcFederationResponseDescriptor responses<0..32>;
} ArcFederationResult;
```

The home Server ID, incarnation, Origin ID, origin generation, operation
sequence, request ID, and request-object ID must equal one exact retained
request tuple. A result from an older or newer origin generation is never
attached to the current connection even when its request ID matches. An exact
duplicate reuses the complete result object and response descriptors; any
field conflict is a fatal peer violation.

`encoded_result` is the exact TLS tuple in this closed table:

| Result kind | Exact fields in order |
| --- | --- |
| `failed` | registered reply-code `opaque<1..64>`, copied request context `opaque<0..255>` |
| `accepted_event` | event ID |
| `bound` | conversation ID, binding ID, binding-package object ID |
| `closed` | conversation ID, close ID |
| `stored` | `ArcFederationStoreKind`, object ID |
| `commit_acked` | conversation ID, candidate ID, ACK object ID |
| `pending` | conversation ID, `ArcFederationPendingKind`, request object ID |
| `empty` | `ArcFederationEmptyKind` |
| `account` | Account ID, session generation |
| `attached` | Device ID, session generation |
| `attach_challenge` | Device ID, challenge object ID |
| `revoked` | KeyPackageRef |
| `reserved` | reservation ID, reservation object ID |
| `finalized` | conversation ID, resulting epoch, finalization ID, certificate object ID |
| `aborted` | conversation ID, candidate ID, abort ID, certificate object ID |
| `claimed` | Device ID, `ArcFederationPackageKind`, KeyPackageRef, object ID |
| `object_page` / `mailbox_page` | empty tuple |
| `reinit_staged` | old conversation ID, ReInit attempt ID, ReInit-attempt object ID |
| `reinit_acked` | old conversation ID, ReInit attempt ID, ACK object ID |
| `reinit_activated` | old conversation ID, new conversation ID, activation ID, certificate object ID |
| `reinit_aborted` | old conversation ID, ReInit attempt ID, abort ID, certificate object ID |
| `mailbox_acked` | delivery token, object ID |
| `recovery_accepted` | conversation ID, submission ID |
| `recovery_extended` | conversation ID, route sequence, record ID |
| `recovery_closed` | conversation ID, close ID |
| `recovery_conflict` | conversation ID, route sequence, first record ID, second record ID |

Every opcode permits `failed`. A failed result has
`coordinator_state_generation=0`, an empty completion Event ID, empty snapshot
token and next cursor, and zero response descriptors; it never consumes or
partially commits the requested semantic mutation. Rate-accounting and audit
work outside the requested semantic mutation may still commit under the base
architecture, but those records cannot alter this result. Its successful
result and completion form are otherwise closed by this table. A parenthesized
value is the required enum selector. `semantic:<kind>` means the named event's
home copy is the completion event; `generic` means a separate home-only
`request_completed`; `none` means both completion fields are empty/zero.

| Opcode | Permitted success result | Completion |
| --- | --- | --- |
| `application_channel`, `application_direct` | `accepted_event` | `semantic:channel_application` or `semantic:direct_application` respectively |
| `reserve_channel`, `reserve_direct` | `reserved` | generic |
| `bind_group` | `bound` | `semantic:route_state_changed` |
| `query_channel`, `query_direct` | `bound` or `empty(empty_binding)` | none |
| `close_group` | `closed` | `semantic:closed_event` |
| `submit_candidate` | `accepted_event` | `semantic:candidate_event` |
| `submit_authorization` | `stored(store_authorization)` | generic |
| `submit_policy` | `stored(store_policy)` | generic |
| `submit_commit_ack` | `commit_acked` | `semantic:commit_ack_event` |
| `submit_finalization` | `pending(pending_finalization)` or `finalized` | generic or `semantic:finalized_event`, matching the result |
| `submit_abort` | `pending(pending_abort)` or `aborted` | generic or `semantic:aborted_event`, matching the result |
| `submit_reinit_attempt` | `pending(pending_reinit_attempt)` or `reinit_staged` | generic or `semantic:reinit_staged_event`, matching the result |
| `submit_reinit_ack` | `reinit_acked` | `semantic:reinit_ack_event` |
| `submit_reinit_activate` | `pending(pending_reinit_activate)` or `reinit_activated` | generic or `semantic:reinit_activated_event`, matching the result |
| `submit_reinit_abort` | `pending(pending_reinit_abort)` or `reinit_aborted` | generic or `semantic:reinit_aborted_event`, matching the result |
| `fetch_object` | `object_page` or `empty(empty_objects)` | none |
| `fetch_authorizations` | `object_page` or `empty(empty_authorizations)` | none |
| `fetch_acks` | `object_page` or `empty(empty_acks)` | none |
| `fetch_receipts` | `object_page` or `empty(empty_receipts)` | none |
| `fetch_identity` | `object_page` or `empty(empty_identity)` | none |
| `fetch_root_chain` | `object_page` or `empty(empty_root_chain)` | none |
| `publish_identity` | `stored(store_identity)` | generic |
| `fetch_roster` | `object_page` or `empty(empty_roster)` | none |
| `publish_roster` | `stored(store_roster)` | generic |
| `fetch_capabilities` | `object_page` or `empty(empty_capabilities)` | none |
| `publish_capabilities` | `stored(store_capabilities)` | generic |
| `fetch_binding_locks` | `object_page` or `empty(empty_binding_lock)` | none |
| `whoami` | `account` | none |
| `attach_begin` | `attach_challenge` | none |
| `attach_finish` | `attached` | generic |
| `claim_package` | `claimed` or `empty(empty_package)` | generic for `claimed`, none for `empty` |
| `claim_status` | `claimed` or `empty(empty_package)` | none |
| `publish_package` | `stored(store_package)` | generic |
| `revoke_package` | `revoked` | generic |
| `deliver_binding` | `stored(store_binding)` | generic |
| `deliver_welcome` | `stored(store_welcome)` or `stored(store_staged_reinit)` matching its payload | generic |
| `fetch_mailbox` | `mailbox_page` or exactly one selected `empty(empty_application)`, `empty(empty_binding)`, `empty(empty_welcome)`, or `empty(empty_staged_reinit)` | generic for `mailbox_page`, none for `empty` |
| `acknowledge_mailbox` | `mailbox_acked` | generic |
| `submit_recovery` | `recovery_accepted` | generic |
| `submit_recovery_element` | `recovery_extended`, `recovery_closed`, or `recovery_conflict` | generic for `recovery_extended` and `recovery_conflict`; `semantic:route_state_changed` for `recovery_closed` |
| `submit_membership` | `stored(store_membership)` | generic |

For `accepted_event`, the encoded event ID equals the top-level
`completion_event_id`. A generic completion's event arm repeats
`coordinator_state_generation`. A semantic completion's event generation,
request-correlation tuple, and kind equal this table. Any other opcode/result,
selector, completion presence, or semantic-event combination is a fatal
federation violation, even if every individual field decodes.

For `bind_group`, the `bound` result's binding-package object ID equals the
request payload-object ID and no response descriptor is sent. For either query,
that ID names the coordinator's current complete binding package and the exact
descriptor required below; the semantic binding ID is recomputed from its body.
Thus bind echoes no bytes the requester already supplied, while query cannot
return an unverifiable semantic ID.

For `reinit_staged`, the encoded ReInit-attempt object ID equals the request's
nonempty payload-object ID and the matching event's encoded object ID. For
`reinit_acked`, the result ACK object ID, request payload-object ID, and event
payload-object ID are identical, and the signed ACK names the result/event
attempt ID. The equivalent object-ID equality applies to `commit_acked` and
its Commit-ACK event. A pending result creates no semantic completion event;
if that operation later reaches a terminal/staged state, the later event is an
uncorrelated asynchronous notification because the earlier generic completion
already covered the request.

`none` requires `coordinator_state_generation=0` and an empty completion ID.
Every semantic or generic completion requires a nonzero generation and an
exact 16-byte ID. One accepted E2EE mutation advances the composed daemon's
single coordinator global state generation exactly once and atomically writes
its request result, every
semantic/route event and referenced payload, the completion event, every
target outbox entry, and all authoritative directory/mailbox/route changes.
A retry returns those exact IDs and bytes without advancing state or consuming
a package twice. The edge may receive ERESULT and every ERESPONSE before the
completion event; it durably retains them as pending and renders no labeled
success until the complete response set and exact completion event have been
applied in delivery order. A disconnected or replaced origin becomes
`sink_gone`; later coverage permits cleanup but never transfers its label or
result to another connection.

Each selector maps one-to-one to the corresponding uppercase client result in
Section 11.7; profile version 1 adds no unknown arm. The
`ArcFederationMailboxKind` is the exact `fetch_mailbox` parameter selector. A
failed code is from Section 11.9 and the context is
empty or copied byte-for-byte from the request. Unknown result kinds, reply
codes, extra fields, or trailing bytes are invalid. Descriptors are canonical
by contiguous `response_index` starting at zero and obey all batch object,
byte, and fragment limits. Their closed presence/type registry is:

| Request and result | Exact response descriptors |
| --- | --- |
| `reserve_channel` / `reserve_direct` + `reserved` | exactly one `reservation`; object ID equals the result reservation-object ID |
| `query_channel` / `query_direct` + `bound` | exactly one `conversation_binding`; object ID equals the result binding-package object ID |
| `attach_begin` + `attach_challenge` | exactly one `device_attach_challenge`; object ID equals the result challenge-object ID |
| `claim_package` / `claim_status` + `claimed` | exactly one `key_package_mls`; KeyPackageRef and object ID equal the result |
| `fetch_object` + `object_page` | exactly one object with the request's object ID and its stored legal non-S2S kind |
| `fetch_authorizations` + `object_page` | 1..`MAX_BATCH_OBJECTS` `commit_approval` objects for the named candidate |
| `fetch_acks` + `object_page` | 1..`MAX_BATCH_OBJECTS` homogeneous `commit_ack` or `reinit_ack` objects selected by the named parent ID |
| `fetch_receipts` + `object_page` | 1..`MAX_BATCH_OBJECTS` contiguous `sequencer_record` objects beginning at the requested route sequence |
| `fetch_identity` + `object_page` | exactly one `root_identity` current head for the named account |
| `fetch_root_chain` + `object_page` | exactly one `root_identity_chain` containing the contiguous requested page |
| `fetch_roster` + `object_page` | exactly one `device_roster` current head for the named account |
| `fetch_capabilities` + `object_page` | 1..`MAX_BATCH_OBJECTS` `device_capabilities` objects in Device-ID order |
| `fetch_binding_locks` + `object_page` | 1..`MAX_BATCH_OBJECTS` contiguous `root_binding_lock` objects for the named root |
| `fetch_mailbox` + `mailbox_page` | 1..`MAX_BATCH_OBJECTS` objects of exactly the selected application/binding/Welcome/staged-ReInit kind |

Every descriptor outside `mailbox_page` has empty delivery token and target
Device ID. A mailbox descriptor has a 32-byte delivery token, 16-byte target
Device ID, and kind respectively `application_mls`, `conversation_binding`,
`welcome_mls`, or `staged_reinit`; every descriptor in one page uses the
requested mailbox selector but has its own token. `object_page` and
`mailbox_page` have a 32-byte snapshot token and an empty or 32-byte next
cursor. Each singleton generated-object response also has a fresh 32-byte
response snapshot token and an empty next cursor so the edge can render the
required one-batch client grammar; that token is bound to the exact stored
result and creates no continuation. Every other result has zero descriptors
and empty snapshot/cursor. `ERESPONSE` index, wire kind, object ID, total size, delivery fields,
fragment metadata, and complete decoded object must all match its descriptor;
a forbidden descriptor or missing required response is fatal.

```text
enum {
    channel_application(1), direct_application(2), candidate_event(3),
    commit_ack_event(4), finalized_event(5), aborted_event(6),
    reinit_activated_event(7), reinit_aborted_event(8), closed_event(9),
    route_state_changed(10), request_completed(11), route_state_hidden(12),
    reinit_staged_event(13), reinit_ack_event(14)
} ArcFederationEventKind;

struct {
    opaque user_id[16];
    opaque nickname<1..32>;
    opaque public_user_component[10];
    opaque public_host_component[16];
    opaque account_label<0..32>;
} ArcFederationSourceView;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque target_server_id[16];
    uint64 delivery_generation;
    uint64 coordinator_state_generation;
    uint64 delivery_sequence;
    opaque event_id[16];
    ArcFederationEventKind event_kind;
    opaque cross_profile_mutation_id<0..16>;
    uint16 cross_profile_part_index;
    uint16 cross_profile_part_count;
    opaque conversation_id<0..32>;
    uint64 route_sequence;
    opaque origin_id<0..16>;
    uint64 origin_generation;
    opaque source_view<0..108>;
    opaque request_home_server_id<0..16>;
    opaque request_server_incarnation<0..16>;
    opaque request_origin_id<0..16>;
    uint64 request_origin_generation;
    uint64 request_operation_sequence;
    opaque request_id<0..16>;
    opaque payload_object_id<0..32>;
    opaque encoded_event_result<0..1024>;
} ArcFederationEvent;
```

The three cross-profile fields use the base specification's Section-20.8
barrier without variation. Empty ID requires zero index/count. Otherwise the
ID is exactly 16 bytes, count is `2..2048`, and index is less than count. A
coordinator mutation that emits both profiles to one target includes every
base event first and every companion event second in the common contiguous
index space; its ID is fresh and target-specific, all parts have the same
nonzero coordinator state generation, and their complete event-plus-required-
payload aggregate is at most 16,777,216 bytes. A one-profile target uses the
empty tuple. The coordinator and edge apply, ACK, replay, receipt, capacity,
failure, and snapshot rules are exactly those in that section; this extension
does not define a weaker independent path.

The four variable request-correlation IDs are either all empty or all present;
the two request-correlation integers are zero exactly in the empty case. They
are present exactly on the home-edge event copy selected as the completion by
the opcode/result table above; ordinary recipient copies leave them empty.
The tuple equals the complete retained request, and the event's coordinator
state generation and ID equal its result. Channel application, direct
application, candidate, Commit-ACK, and ReInit-ACK events require a 16-byte `origin_id`
and its currently ACKed generation plus the exact 45..108-byte TLS encoding of
one `ArcFederationSourceView`. Its encoding and semantic fields are byte-for-
byte identical to the base specification's Appendix-B
`FederationSourceView`. The view is captured from the coordinator's matching
base session at acceptance. Its nickname and public-cloak components obey the
base profile, and its account label is empty or the exact public label then in
force. It contains no Account ID, address, transport, home-server name, device
identity, or authority. The target edge uses it only to render the
pseudonymous source and does not persist it after the event/replay window.
Finalized, aborted, ReInit-staged, ReInit-terminal, and close events have an empty origin,
`origin_generation=0`, and empty source view because they are server-originated
state notifications. Route-state, route-hidden, and request-completion events also have an
empty origin/source. Any other presence combination is invalid.

For an application event, `route_sequence` is the numeric sequence of the
coordinator's current sequencer-record head and may repeat across messages. A
candidate event uses its receipt sequence; a Commit ACK uses its candidate's receipt sequence; a
finalization, abort, or ReInit terminal event uses its certificate sequence;
a ReInit-staged event uses its attempt-receipt sequence, a ReInit ACK uses its
attempt's receipt sequence, and a close event uses the route sequence its close
occupies, one after the record that authorized it.
Route-state changes use the state object's
`sequencer_record_head_sequence`; route-hidden uses that value from the last
projected state and names that exact state object. A generic
request completion uses the named conversation's current head, or zero when
the request has no conversation. Conversation ID is exactly 32 bytes for every
semantic/route event, is the request's conversation when one exists for a
generic completion, and is empty only for a non-conversation generic
completion. Any other value or presence is invalid. Event selector arms are
exact:

| Event kind | Required data object | `encoded_event_result` |
| --- | --- | --- |
| `channel_application` / `direct_application` | `application_mls` | empty tuple |
| `candidate_event` | `commit_mls` | exact `ArcCandidateReceipt` |
| `commit_ack_event` | `commit_ack` | candidate ID |
| `finalized_event` | none | resulting epoch, finalization ID, certificate object ID |
| `aborted_event` | none | candidate ID, abort ID, certificate object ID |
| `reinit_activated_event` | none | new conversation ID, activation ID, certificate object ID |
| `reinit_aborted_event` | none | ReInit attempt ID, abort ID, certificate object ID |
| `closed_event` | none | close ID |
| `route_state_changed` | `federation_state` | empty tuple |
| `request_completed` | none | coordinator state generation `uint64` |
| `route_state_hidden` | none | prior federation-state object ID `[32]` |
| `reinit_staged_event` | none | ReInit attempt ID, ReInit-attempt object ID |
| `reinit_ack_event` | `reinit_ack` | ReInit attempt ID |

`payload_object_id` is empty exactly for a `none` row. A request-completion arm
value equals the event/result generation. No other event-result encoding is
legal.

The coordinator derives event recipients from one immutable state cut before
allocating Event IDs. For a channel conversation, a semantic event targets
exactly the Server IDs that host at least one current base membership in the
bound ChannelInstanceId; the edge fans out only to those local member sessions
whose ACKed companion origin has an attached roster-active Device ID. For a
direct conversation, it targets exactly the Server IDs that host at least one
ACKed companion origin whose Account ID is either bound direct account and
whose Device ID is attached and roster-active; the edge fans out only to those
matching origins. A disconnected/offline device receives no invented live
event and recovers retained objects through the authenticated fetch/mailbox
path. The requesting home edge is unioned into the target set only when it must
receive the completion copy; a gone sink still receives durable coverage but
no client output.

`route_state_changed` targets every edge newly or currently entitled to the
resulting route view. `route_state_hidden` targets every edge losing its last
standing entitlement. `request_completed` is home-only. No other event is
sent to an edge merely because it federates, hosts an unrelated account, or
once saw the conversation. For one logical semantic event there is at most one
copy per target Server ID. Copies reference the same immutable payload but use
distinct fresh Event IDs and delivery sequences; only the home completion copy
has request correlation. The edge derives its local sinks from the same
generation-bound base projection and companion origins, never from nickname or
an event-supplied recipient list.

One mutation constructs companion copies in this exact order before assigning
delivery sequences: phase 1 `route_state_changed`; phase 2 channel/direct
application, candidate, Commit-ACK, and ReInit-ACK events; phase 3 ReInit-staged,
finalized, aborted, ReInit-terminal, and closed events; phase 4
`route_state_hidden`; phase 5 a
generic `request_completed`. Within one phase, copies sort by conversation ID
bytes, event-kind discriminant, target Server ID bytes, then payload-object ID
bytes with empty sorting first. A semantic completion stays in its semantic
phase and carries the correlation on its home copy; no extra generic completion
is created. Event IDs are sampled only after this order is fixed. The
target-specific subsequence is the companion order used by a cross-profile
barrier. Unknown phases, duplicate logical copies, or a different order are
fatal.

The coordinator owns one durable contiguous E2EE delivery stream per target
edge. `delivery_generation` is scoped by the authenticated coordinator
recovery epoch, target Server ID, and target Server Incarnation; it starts at
zero for a newly admitted scope and increments without wrap only for an
explicit full state reset of that same scope. Delivery sequence starts at zero
in each generation and increments by one. Event IDs are fresh 16 random bytes.
Every event copy produced by one mutation carries the same nonzero coordinator
state generation used by the base coordinator; there is no companion-only
global counter. Values in one delivery stream are nondecreasing. The text
carrier, object fields, target, IDs, and referenced payload must all agree.

The coordinator transaction that accepts a mutation also writes every exact
event object, referenced immutable payload, target outbox row, request result,
and next sequence. It sends ERESULT/ERESPONSE and semantic events only from
those durable rows. The edge admits the complete event and payload, validates
the next exact cursor and all route/origin/source constraints, and obtains the
complete bounded client-fanout reservation before opening its apply
transaction. That one transaction applies any route/projection change, stores
either the matching result-covered marker or a durable completion-coverage
tombstone, advances the event cursor, and records any locally required
pending fanout. Only after commit does it make frames visible and send EACK.
Storage, allocation, or reservation failure produces neither ACK nor client
output. EACK is cumulative through its named sequence and is accepted only
when its Event ID matches that delivered row; outside a cross-profile barrier
it advances by exactly one. An exact duplicate at the installed cursor is re-ACKed without
reapplying state or rerendering; a gap, conflicting ID/object, decreased state
generation, or other generation blocks E2EE processing and closes the link.

The edge also witnesses the sequencer record chain of every conversation it
projects. It keeps the head `(sequencer_record_head_sequence,
sequencer_record_head_id)` installed from the route-state cut and advances it
from semantic events. The head is the external anchor until a record occupies
it, and the next position is the head sequence at the anchor and one greater
afterwards. A `candidate_event` receipt must carry `route_sequence` equal to
the next position and `predecessor_record_id` exactly equal to the head ID,
and its candidate ID then becomes the head. A `reinit_staged_event`,
`finalized_event`, `aborted_event`, `reinit_activated_event`,
`reinit_aborted_event`, or `closed_event` must arrive at the next position,
and its attempt, terminal, or close ID becomes the head. An event that names
the installed head again, as after a route-state cut that already carried it,
leaves the head. Application, ACK, and completion events never move the head.
A route-state change installs the cut's head when it is the first state for
the conversation or when it names the witnessed head or a later one; a cut
whose head is older than, or forks from, the witnessed head is a violation. A
semantic event that does not extend the head is a witness violation: the edge
produces no client output and no EACK, records a durable `witness/v1` row
naming the conversation ID, the expected next position and head ID, and the
observed sequence, identifier, and asserted predecessor, and nothing else,
then closes the link so the route reads `E2EE_SYNCING` until the Section
12.5.1 witness resolution installs a delivered chain that extends the
witnessed head; a route-state snapshot alone never resolves the row. Logs
carry only the closure, never an identifier. The witness cannot detect a record the coordinator never
delivers; it detects every fork and every skipped position.
Cross-profile parts instead stage and commit under the base Section-20.8
combined transaction; no individual part advances this cursor or emits EACK.

A completion event may precede its ERESULT after reconnect. Its coverage
tombstone is keyed by the complete replay tuple, request ID/object ID,
completion Event ID, and state generation and is retained for at least
`S2S_IDEMPOTENCY_RETENTION`. Arrival of the exact result atomically consumes or
links that tombstone and permits rendering when every indexed response object
is also complete. A mismatch is fatal. Result-first arrival remains pending
until the event. `sink_gone` suppresses rendering in both orders.

After a same-incarnation link reconnect and profile negotiation, the edge sends
ERESUME with its durable cursor. Both star fields are present together only
before sequence zero. Otherwise both are concrete and identify the exact last
ACK. The coordinator's peer record retains that cursor even after deleting the
corresponding event body. It returns ERESUME OK with zero or the next sequence
and retransmits every unacknowledged row byte-for-byte. A generation,
incarnation, cursor, or event-ID mismatch is fatal and cannot be repaired by
guessing a later cursor. A genuinely new recovery epoch/incarnation uses the
full ESTATE reset below and cannot resume old origins or delivery state.

Unacknowledged event rows are never evicted or replaced by a route snapshot.
One edge may hold at most `MAX_UNACKED_E2EE_EVENTS_PER_EDGE` rows and
`MAX_UNACKED_E2EE_EVENT_BYTES_PER_EDGE` complete event-plus-required-payload
bytes. Before an append would cross either ceiling, the coordinator marks that
target `EVENT_BLOCKED`, suspends its origins, closes a live link, and rejects
the complete mutation with `E2EE_SYNCING`; it does not commit a partial target
set or discard an application/security event. Unrelated mutations needing no
event for that target may continue. ACKed rows target 24 hours of replay and
are trimmed at the first of `MAX_ACKED_E2EE_EVENT_REPLAY_ROWS_PER_EDGE` or
`MAX_ACKED_E2EE_EVENT_REPLAY_BYTES_PER_EDGE`, while the last-ACK cursor remains.
Referenced cryptographic objects and security proofs keep their longer
normative retention. All these bytes also count against the composed daemon's
global E2EE disk ceiling.

When this extension is composed with the daemon architecture specification,
it creates no second Server Incarnation, Origin ID, or account principal. The
fields below are exact mirrors of the currently ACKed base
`FederationOrigin`; E2EE origin state adds only device attachment. Losing base
origin/request continuity changes the shared Server Incarnation and fences
both profiles. Origin synchronization uses:

```text
:<home-sid> EORIGIN RESET <coordinator-server-id> <server-incarnation>
:<coordinator-sid> EORIGIN READY <home-server-id> <server-incarnation>
@agenc.ag/e2ee=<fragment> :<home-sid> EORIGIN ADD <coordinator-server-id> <server-incarnation> <origin-id> <origin-generation> <origin-state-object-id>
@agenc.ag/e2ee=<fragment> :<home-sid> EORIGIN UPDATE <coordinator-server-id> <server-incarnation> <origin-id> <origin-generation> <origin-state-object-id>
:<home-sid> EORIGIN DEL <coordinator-server-id> <server-incarnation> <origin-id> <origin-generation> <next-operation-sequence>
:<coordinator-sid> EORIGIN ACK <home-server-id> <server-incarnation> <origin-id> <origin-generation> <state-object-id-or-star>
```

```text
struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque home_server_id[16];
    opaque server_incarnation[16];
    opaque origin_id[16];
    uint64 origin_generation;
    opaque previous_origin_state_id[32];
    opaque connection_id[16];
    opaque session_id<0..16>;
    opaque user_id<0..16>;
    opaque account_id<0..24>;
    uint64 account_session_generation;
    opaque connection_nonce[32];
    opaque attached_device_id<0..16>;
    uint64 device_session_generation;
} ArcFederationOrigin;
```

`ADD` requires the same generation-zero base origin and an all-zero
predecessor. It is accepted only after the corresponding base FORIGIN ADD is
ACKed. `UPDATE` increments by one, is accepted only after the corresponding
base FORIGIN UPDATE is ACKed, and names
`SHA256("ARC-MLS/1 federation origin state" ||
encoded_ArcFederationOrigin)` for the accepted predecessor. Network, home
server, incarnation, Origin ID, Connection ID, and connection nonce equal the
base object byte-for-byte. Session/User IDs are both empty or both 16 bytes.
Account ID is empty exactly for an unauthenticated/guest origin and then
account-session generation is zero; otherwise it is exactly 24 bytes and the
generation is nonzero. An attached device requires an authenticated account,
has a 16-byte Device ID and nonzero device-session generation; absence requires
both fields empty/zero.

Registration, login, logout, account switch, session replacement, and device
attach/detach advance the one shared base origin generation before either
profile accepts a request under it. Device attachment is stored only in this
companion object, but still forces the matching base generation transition.
Nickname, display-name, cloak, account-label, and other presentation changes
do not create a security-principal generation. DEL uses the same base fence
and next companion operation sequence; a reconnect creates a new base Origin
ID rather than an E2EE-only identity. EORIGIN RESET/READY never completes
before the matching base origin set is ready.

Within each ACKed Origin ID/generation, the first request operation sequence is
zero and each new logical request increments it by one. An origin update resets
the companion operation sequence to zero exactly as the base profile resets its
own counter. The base and companion counters are independent contiguous
namespaces, domain-separated in storage by profile (`base-v1` versus
`arc-mls-v1`); a request in one neither consumes nor fills a gap in the other.
FORIGIN DEL carries the next base value and EORIGIN DEL the next companion
value, and both fences must commit before the shared origin is fully retired.
The coordinator's companion replay key is exactly
`(arc-mls-v1, home_server_id, server_incarnation, origin_id,
origin_generation, operation_sequence)`, mapped
to one request ID and request-object hash. Exact duplicates return the stored
result; different bytes at that key, a reused request ID, or a sequence gap are
protocol violations. Object ID is not part of the replay key. `DEL` supplies
the next unused sequence and permanently fences later requests. Link loss
immediately fences execution from that link; reconnect must replay RESET and
origin state before resuming. A new server incarnation permanently fences all
older incarnations for that home server. Tombstones and results survive at
least `S2S_IDEMPOTENCY_RETENTION`; a security-state mutation remains replayable
for at least seven days, and any referenced proof keeps its longer normative
retention.

Authoritative route state is encoded as:

```text
enum { active_route(1), encrypted_tombstone(2) } ArcRouteStateKind;

struct {
    uint16 profile_version;
    opaque network_id[32];
    uint64 state_generation;
    opaque conversation_id[32];
    ArcConversationKind conversation_kind;
    opaque route_binding[32];
    opaque semantic_route_lock_id[32];
    opaque channel_instance_id<0..16>;
    opaque canonical_channel_name_hash[32];
    opaque direct_account_a<0..24>;
    opaque direct_account_b<0..24>;
    opaque binding_id[32];
    uint64 finalized_epoch;
    opaque accepted_state_id[32];
    uint64 sequencer_record_head_sequence;
    opaque sequencer_record_head_id[32];
    ArcRouteStateKind state;
} ArcFederationRouteState;
```

After the first sequencer record,
`sequencer_record_head_sequence` is that retained record's exact
`route_sequence` and `sequencer_record_head_id` is its recomputed semantic ID;
both belong to this conversation and are the coordinator's current head at the
route-state cut. The coordinator refreshes the retained route-state object and
its durable route row at every sequencer record (candidate, ReInit attempt,
terminal, and close), so a cut and a reloaded coordinator name the head the
edges have witnessed. Before the first record,
the sequence is zero and the ID is
the exact external genesis or ReInit-activation anchor required by Section
12.2. An ID/sequence mismatch, missing required security record, invalid
external anchor, or head older than the accepted state's authorizing record is
fatal. The numeric field exists so an edge can validate and order events
without guessing a sequence from a 32-byte semantic ID.

For a channel, the instance field is 16 bytes and the name hash is
`SHA256("ARC-MLS/1 canonical channel name" || TLS-encode(canonical_irc_name))`;
the direct-account fields are empty. For a direct route the instance is empty,
the name hash is all zero, and the two Account IDs are non-empty and canonical.
Edges use those authenticated route-state accounts for plaintext downgrade
rejection; nicknames never become the stored identity.

Standing route projection is least-information and follows the base
projection entitlement at the same state cut. A channel route/tombstone is
present only while the edge has a base channel-detail entitlement. A direct
route is never projected merely because the edge hosts a session for either
Account ID: login cannot enumerate or bulk-copy that account's direct
conversations. It is present only while required by an unacknowledged event or
operation for a matching local attached origin, or by a still-live mailbox item
for an exact local target Device ID. The coordinator remains authoritative for
every lookup not already entitled and for every base direct-message downgrade
check, so absence from this cache never authorizes plaintext.

When a direct semantic event targets an edge with no standing entry, its plan
sends `route_state_changed` immediately before the semantic event. If no
operation, unacknowledged event, or mailbox item still requires the view, the
same plan sends `route_state_hidden` immediately afterward. Thus one live
event may create a short-lived correct projection but cannot leave historical
direct pairs behind. A mailbox/operation-backed entry is hidden as soon as its
last exact reason is ACKed, consumed, expired, or fenced. These reasons and
their per-edge entry/byte totals are transactionally reference-counted; an
underflow, orphan, or entry not represented in ESTATE is fatal. The edge never
receives unrelated secret-channel routes, directory identities, direct-account
pairs, or a global encrypted-channel index.

The first entitlement sends `route_state_changed` before any application or
security event requiring that route. A later route transition replaces the
exact prior state. Every change to a serialized `ArcFederationRouteState`
field, including accepted-state or sequencer-record head, emits that changed
object to each then-entitled edge; an authoritative route transition sets its
`state_generation` to the event's coordinator state generation. A first or
renewed entitlement may instead project the unchanged current object, whose
nonzero state generation is no greater than the event generation and whose
object ID equals the coordinator's current route record. Losing the last
entitlement sends
`route_state_hidden` with
the prior object ID after every earlier event for that route; the edge deletes
that one projection entry before EACK. A changed/hidden event and the matching
base channel/account projection delta are one cross-profile mutation plan and
must reach compatible active states before client rendering. The ESTATE
snapshot contains exactly this entitled set and no orphan route.

State synchronization uses these exact lines:

```text
:<coordinator-sid> ESTATE BEGIN <target-server-id> <snapshot-token> <state-generation> <delivery-generation> <page-sequence> <total-entry-count> <page-entry-count> <snapshot-digest>
@agenc.ag/e2ee=<fragment> :<coordinator-sid> ESTATE ENTRY <target-server-id> <snapshot-token> <page-sequence> <conversation-id> <state-object-id>
:<coordinator-sid> ESTATE END <target-server-id> <snapshot-token> <page-sequence> <next-cursor-or-star>
:<edge-sid> ESTATE FETCH <coordinator-server-id> <snapshot-token> <next-page-sequence> <cursor>
:<edge-sid> ESTATE READY <coordinator-server-id> <snapshot-token> <state-generation> <delivery-generation> <snapshot-digest>
:<coordinator-sid> ESTATE ACTIVE <target-server-id> <snapshot-token> <state-generation> <delivery-generation> <snapshot-digest>
```

Every ENTRY object is exactly one `federation_state` envelope. Entries
are canonical by conversation ID; page sequences start at zero and all counts
must match. Each page is exactly one BEGIN, the declared number of complete
ENTRY objects in order with every object's fragments contiguous, and one END.
Every nonfinal nonempty page contains exactly `MAX_BATCH_OBJECTS` entries; the
final nonempty page contains the remaining 1..`MAX_BATCH_OBJECTS`. An empty
snapshot is exactly page zero with total/page counts both zero, no ENTRY, and a
final `*` END. Thus a nonempty snapshot has exactly
`ceil(total_entry_count / MAX_BATCH_OBJECTS)` pages and no implementation may
choose a different partition. (There is no UPDATE command after this revision;
live changes use the ACKed `route_state_changed` event.) One page's sum of
complete objects is at most `MAX_BATCH_DECODED_BYTES`. The complete
snapshot has at most `MAX_FEDERATION_STATE_ENTRIES_PER_EDGE` entries and
`MAX_FEDERATION_STATE_SNAPSHOT_BYTES_PER_EDGE` encoded object bytes.
`snapshot-digest` is
`SHA256("ARC-MLS/1 federation snapshot" ||
TLS-encode(state_generation, delivery_generation,
ordered_state_object_ids))`.

The token is 32 random bytes, has a nonextendable 15-minute monotonic lifetime,
and identifies one immutable cut and one target/incarnation. Each nonfinal END
contains a fresh 32-byte cursor bound to the next page; FETCH repeats that next
page number and cursor. The final END uses `*`. An exact FETCH retry returns
the byte-identical page. Wrong order/count/cursor, duplicate/missing
conversation, object mismatch, expiry, or a second live token discards the
pending generation and closes the link.

The Section-11.10 productions are exact here: both counts are canonical
`entry-count` values, every page value is `page-sequence`, FETCH requires a
concrete `snapshot-cursor`, and only END accepts `next-snapshot-cursor` with
`*`. BEGIN repeats the same target, token, state generation, delivery
generation, total count, and digest on every page; only page sequence and page
entry count change. ENTRY repeats that page sequence and its decoded route's
conversation ID and complete object ID. FETCH names exactly the next sequence,
READY/ACTIVE repeat the BEGIN cut fields, and all six commands have exactly the
shown arity with no trailing parameter. Their non-tag portions are below 512
bytes under `MAX_E2EE_SERVER_PREFIX_BYTES`; tagged ENTRY lines remain below the
composed daemon's 8,703-byte S2S physical ceiling.

The edge stages the complete snapshot in a new storage generation and verifies
count, byte total, order, object IDs, digest, route semantics, base
channel/account entitlement, and recovery-gate consistency before atomically
marking it pending and sending READY. The coordinator durably records that
exact READY before sending ACTIVE. ACTIVE is the only authorization to swap the
pending generation into use. If the link fails after READY, the edge resends
the identical READY after authenticated reconnect and the coordinator returns
the byte-identical ACTIVE; a conflicting token/cut is fatal. State changes
after the immutable cut are queued as delivery events beginning at sequence
zero of the named new generation and replay only after ACTIVE.

A full ESTATE transfer is legal only for initial peer admission, a new base
recovery epoch/incarnation, or an explicit paired base FSNAPSHOT that durably
advanced the edge's `client_resync_epoch`. A reset in the same authenticated
coordinator/target scope increments delivery generation; a new scope starts at
zero. The paired base transition has already marked old origins/results
`sink_gone` and closed global client sessions, so ESTATE never claims to cover
or render an old labeled E2EE result.
After ACTIVE the edge establishes the new event cursor, completes EORIGIN
RESET/READY, and only then enters `STATE_ACTIVE`. A same-incarnation ordinary
reconnect uses ERESUME and never substitutes a state image for missing events.
A state/event gap blocks affected routes rather than triggering an implicit
cursor jump.

Until `STATE_ACTIVE`, no ARC-MLS request or event crosses that edge; global-channel
netburst state is quarantined from client-visible merge or fanout; and affected
JOIN, TOPIC, PRIVMSG, NOTICE, TAGMSG, and collision processing pauses or fails
with `E2EE_SYNCING`. Plaintext is never accepted merely because the encrypted
route table is incomplete. A live route change becomes usable on one target
edge only in the transaction that applies its ordered `route_state_changed`
event; EACK proves that edge reached the new state but is not endpoint MLS
acceptance.

On netjoin, a global `#` name with two channel-instance bindings has one
deterministic IRC-namespace winner: the smaller bytewise
`(channel_instance_id, binding_id)`. The losing route is placed in an
encrypted tombstone and its local users are force-parted with an explicit
security-collision error. Their clients remain pinned and send-blocked; they
do not join or merge into the winner automatically. This resolves the single
IRC namespace without merging MLS groups. If only one side is encrypted or an
encrypted tombstone, the encrypted namespace entry wins and the plaintext or
unbound side is force-parted; none of its members are injected into the MLS
route. A tombstone remains blocked until an explicit authenticated state update
proves that exact instance destroyed.

Labels never cross federation. The ingress server retains
`(home_server_id, server_incarnation, origin_id, origin_generation,
operation_sequence,
request_id, connection, device_session_generation, label)`. Application and
candidate success is the matching event echo, with the label only on the
requester's fragment zero after durable completion coverage. ACK submission
gets one labeled `ACKED`; ReInit ACK submission gets one labeled
`REINIT-ACKED`; other matching ACK event copies are unlabeled. An immediate
close, ReInit-stage, finalization, abort, ReInit activation, or ReInit abort
uses its semantic completion to send exactly one labeled scalar to the
requesting connection and the registered untagged broadcast to other eligible
local sinks; it suppresses that broadcast on the requesting connection. An object-returning
operation gets one labeled batch only after every descriptor object is present
and any required completion is covered, and a scalar operation gets one
labeled line under the same rule. A pending terminal request gets one labeled
`PENDING` after its generic request completion and later one untagged terminal
event. Failure gets one labeled `FAIL`. A late result for a disconnected
connection is retained for stable-ID reconciliation and never attached to a
new connection or reused label.

An incompatible link never strips tags, converts ciphertext to `PRIVMSG`, or
silently partitions an encrypted channel across a legacy link.

Application messages may be delivered out of order within configured MLS and
application windows. Group-state objects, ACKs, aborts, and finalizations use
the total sequencer order.

During a netsplit, a partition without the coordinator cannot obtain the
sequencer wrapper and therefore cannot complete a membership change. Even a
malicious coordinator cannot create two endpoint disposition quorums within
the configured fault bound. Failover is allowed only when replicated service
consensus preserves the exact record log, key, request-id table, and mailbox
transactions. Pending removals pause sending. Existing-epoch application
traffic may continue only when no removal, compromise, or membership
uncertainty is pending. Ordinary IRC collision rules never merge encrypted
membership or inject old ciphertext into a new instance.

#### 12.5.1 Edge witness resolution

A durable `witness/v1` row blocks a conversation until the coordinator proves
how the retained chain continues from the witnessed head. That proof travels
in the only frame family a blocked edge accepts for that conversation:

```text
struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque coordinator_server_id[16];
    opaque target_server_id[16];
    opaque conversation_id[32];
    opaque resolution_token[16];
    uint64 expected_sequence;
    opaque expected_head_id[32];
    uint32 record_count;
    uint64 new_head_sequence;
    opaque new_head_id[32];
    opaque record_object_ids<0..32768>;
} ArcFederationWitnessResolution;
```

`record_object_ids` is exactly `record_count` concatenated 32-byte object IDs
of `sequencer_record` objects in chain order, and `record_count` is at most
`MAX_WITNESS_RESOLUTION_RECORDS`, so the vector fits the control envelope. The
wire kind is `witness_resolution`; like every S2S control envelope the object
is bounded by `MAX_FEDERATION_CONTROL_OBJECT`. The S2S lines are:

```text
:<edge-sid> EWITNESS REQUEST <coordinator-server-id> <conversation-id> <expected-sequence> <expected-head-id>
@agenc.ag/e2ee=<fragment> :<coordinator-sid> EWITNESS BEGIN <target-server-id> <conversation-id> <resolution-token> <resolution-object-id>
@agenc.ag/e2ee=<fragment> :<coordinator-sid> EWITNESS ENTRY <target-server-id> <resolution-token> <entry-sequence> <record-object-id>
:<coordinator-sid> EWITNESS END <target-server-id> <resolution-token> <record-count>
:<edge-sid> EWITNESS RESOLVED <coordinator-server-id> <conversation-id> <resolution-token> <new-head-sequence> <new-head-id>
```

After profile activation and `ERESUME OK` on a same-incarnation link, the edge
sends one `EWITNESS REQUEST` for every durable `witness/v1` row, naming the
row's expected next position and head ID. `EWITNESS BEGIN` carries exactly one
`witness_resolution` object whose coordinator, target, conversation, token,
expected sequence, expected head, and record count equal the line and the
request. `resolution_token` is fresh per link incarnation and identifies one
open resolution; at most one resolution is open per conversation per link,
and a token from an earlier incarnation is refused. Each `EWITNESS ENTRY`
carries one `sequencer_record` object whose object ID equals the
`record_object_ids` entry at `entry-sequence`, counted from zero and
contiguous. `EWITNESS END` completes the set and its count equals
`record_count`. The edge answers `EWITNESS RESOLVED` only after the durable
installation below; a repeated `RESOLVED` for an installed token is
idempotent. Every line fits the 512-byte non-tag ceiling under
`MAX_E2EE_SERVER_PREFIX_BYTES`, and one resolution set is at most
`MAX_WITNESS_RESOLUTION_BYTES` of complete `sequencer_record` objects.

The edge validates the delivered records exactly as Section 12.2 and the
witness rules above require:

1. While any `witness/v1` row is unresolved, the edge accepts only `EWITNESS`
   frames for conversations that have a durable row and refuses every other
   companion frame exactly as before; the route continues to read
   `E2EE_SYNCING`.
2. The first record occupies `expected_sequence` and, for a candidate record,
   names `expected_head_id` as its predecessor; every later record has
   sequence one greater than the previous record and names that record's
   semantic ID as its predecessor.
3. Every record verifies under a sequencer credential of the key set
   negotiated on the current link, including the overlapping successor during
   `MAX_SEQUENCER_KEY_OVERLAP`; a record under any other key is a violation.
4. The last record's recomputed semantic ID equals `new_head_id` and its
   sequence equals `new_head_sequence`.

When every check passes, one durable edge transaction deletes the row and
installs `(new_head_sequence, new_head_id)` as the witnessed head; only then
is `RESOLVED` sent, and a later route-state cut naming that head or a later
one is accepted under the ordinary rules. A `record_count` of zero means the
coordinator holds no record beyond the expected position: the row is retained
unchanged and the edge repeats its request after
`MAX_WITNESS_RESOLUTION_SECONDS`. A record that verifies at the expected
position but names a predecessor other than `expected_head_id` is an
unresolvable fork: the edge durably marks the row `conflict`, keeps that
conversation reading `E2EE_SYNCING` permanently with no head change, resumes
every other conversation, and offers no administrator or maintenance command
that clears that mark. Any other failure closes the link as a profile
violation and retains the row. The witness still cannot detect a record the
coordinator never delivers; a resolution proves continuity of what was
delivered, never completeness.

## 13. Group lifecycle

### 13.1 Device provisioning

On provisioning, a device:

1. creates its independent device authorization key;
2. completes the root-authorized, challenge-bound enrollment in Section 8.3;
3. receives the new root-signed complete roster and verifies its predecessor;
4. publishes a device-signed capability statement for that roster generation;
5. creates fresh per-suite MLS KeyPackages with non-circular credential
   bundles; and
6. uploads normal one-use packages and replenishes them before exhaustion.

KeyPackages **MUST** expire no later than `MAX_KEY_PACKAGE_LIFETIME` after
creation. For a normal package, the corresponding private `init_key` is
deleted after the first Welcome is transactionally accepted; an unclaimed
package also deletes it on expiry or revocation.

Version 1 sends no target-visible package-claim notification: pre-binding claim
intent is not exposed to the target account or its current edges. The directory
burns the claimed normal package atomically and never dispenses it again. The
publishing device retains its private `init_key` until it transactionally
accepts the one Welcome naming that KeyPackageRef, or until the package's
signed expiry, local revocation, or account/device destruction, whichever
comes first; it then deletes the key and never republishes the same bytes.
`KEY_PACKAGE_CLAIM_TIMEOUT` bounds the claimant's stable operation mapping and
expected Welcome workflow, not target-side key deletion.

An operator or client may describe some locally maintained inventory as
emergency stock, but this is not a wire or server-side package class. Those
packages are ordinary one-use packages with `last_resort=0`, enter through the
same publish/claim quotas, and receive no priority or hidden reserve. The
server never dispenses the same KeyPackage twice or extends its lifetime.

### 13.2 Creating a channel group

1. An authorized channel member reserves the channel route.
2. Before consuming any package or initializing MLS, it fetches and validates
   roots, current rosters, and signed capabilities for every intended initial
   device, then applies the exact suite preference in Section 7.3.
3. It constructs the exact semantic initial member plan from those device and
   capability IDs. It does not put a KeyPackageRef or leaf key in that
   root-locked plan.
4. It creates the creator-only bootstrap policy and the exact generation-one
   operational policy/finality council, fresh group ID, sequencer pin, binding
   TBS with the locally pinned channel-authority root, and complete context. Every active
   binding-authorized device under every initial controller root signs the
   exact binding and member plan.
5. It initializes the one-member MLS group with its own device as the initial
   leaf and atomically binds the exact context, plan, and signed binding to the
   reservation. Every Add Proposal is inline. It then publishes the
   generation-zero and generation-one policies with `EGROUP SUBMIT POLICY`
   before its first Commit.
6. For the next planned device only, it claims and validates one fresh
   KeyPackage, submits one Add Commit, stages it, collects required ACKs,
   controller authorization and finality votes, and waits for an
   `ArcCommitFinalizationCertificate`.
7. Only then is `ArcDeliveredWelcome` sent: its immutable encrypted Welcome
   contains the full ratchet tree and policy/roster chains, while its outer
   sidecar contains the now-known finalization proof. The added leaf remains
   context-marked `pending` until Section 13.4 completes; initial devices are
   added and confirmed serially.
8. After the exact plan is active, it finalizes the dual-council
   `bootstrap_activation`, installs the binding-committed operational policy,
   and clears `bootstrap_pending`. Only then may a controlled transition set
   the private topic. Policy, topic, and rosters are Commit-bound; the policy
   is additionally published to the server as a public object and is never an
   application message.

The channel becomes encrypted-only when the binding is active. The server
rejects plaintext `PRIVMSG` and `NOTICE` to the bound channel. Clients without
the required capability cannot join the encrypted membership and receive a
structured failure instead of a plaintext fallback.

JOIN, PART, KICK, MODE, NAMES, and presence remain IRC metadata. The private
topic lives inside MLS, the policy is Commit-bound and also published to the
server, and any ordinary server topic is a non-secret placeholder.

### 13.3 Creating a direct group

1. Both parties verify or explicitly accept the other's semantic root
   descriptor and current device roster.
2. The lexicographically smaller Account ID acts as binding creator, even if
   the other party initiated the invitation. It reserves the route, gathers
   signed capabilities, and chooses the suite before MLS initialization.
3. It creates the exact semantic initial member plan, creator-only bootstrap policy,
   required fixed-direct operational policy/finality council, and binding transcript containing both roots and roster
   IDs. Every active binding-authorized device in both complete rosters
   signs the exact transcript and plan.
4. It initializes itself as the one-member group. It never Adds its
   already-present creator credential.
5. It claims one fresh package, commits, finalizes, delivers, and confirms each inline Add serially.
   Each `ArcDeliveredWelcome` carries the immutable Welcome and exact
   post-finalization sidecar.
6. All planned devices must be active and non-pending before the dual-council
   bootstrap activation; only the exact old and resulting policy councils
   vote. Direct-message application data remains forbidden before it
   finalizes.

MLS is used even when only two devices exist, keeping direct and group code
paths consistent. Adding later devices is an ordinary visible membership
change.

### 13.4 Joining and adding devices

IRC JOIN does not itself reveal group secrets. An existing authorized member
must:

1. observe the account's route authorization;
2. retrieve and validate its root, complete current roster, and signed
   capabilities against locally pinned high-water marks;
3. claim one fresh KeyPackage matching the current version and suite;
4. apply the encrypted membership policy;
5. create one inline Add proposal, including a full roster-update proposal when
   required;
6. submit, stage, and finalize the Commit; and
7. deliver the exact `ArcDeliveredWelcome` tied to that finalization ID.

The new device validates the full Welcome, tree, committed roster heads,
old-policy finality quorum, its pending leaf entry, and package reference;
then it transactionally consumes its package nonce for this binding and sends
an MLS-authenticated join-confirmation self-Commit with a populated UpdatePath
and context replacement that clears its pending entry. That confirmation is
implicitly authorized by the exact finalized Add and needs no fresh controller
approval, but still needs processing evidence and old-council finality.
Existing members do not display it as active or rely on it for ordinary ACK
coverage until finalization. No other transition is accepted meanwhile.
Failure to confirm within `JOIN_CONFIRMATION_TIMEOUT` permits only a quorum-
finalized removal of that pending leaf. This prevents a withheld or
undecryptable Welcome from being mistaken for a successful join.

Unknown or changed roots remain unverified and trigger the configured policy.
All leaf additions are shown in the security event log.
If an Add candidate aborts, every claimed normal KeyPackage remains burned;
the committer deletes its staged Welcome and the target replenishes stock.
Returning a package to the directory would permit ambiguous cross-group reuse.

### 13.5 Part, kick, revocation, and removal

An intentional PART, KICK, device revocation, account-root discontinuity, or
compromise report creates a pending removal. Authorized members remove every
affected leaf in one Commit where possible.

A removal candidate must still retain the old policy's full derived quorum of
eligible finality principals as active leaves that can stage it. If it would
not, members first finalize a policy-only council handoff while the old quorum
remains present, then remove those leaves in a later epoch. There is no
emergency lower quorum.

Clients **MUST** pause application sending while a required removal is pending.
Security against the removed member begins only after the removal Commit is
finalized and processed.

On applying a removal, a client immediately deletes every retained past-epoch
receive key and skipped-key branch for each removed leaf and rejects all later
old-epoch traffic from it. This intentionally drops legitimately delayed
messages that cannot be distinguished from post-removal messages created with
the old leaf. Other retained-leaf receive windows remain subject to Section
16.

A transport disconnect or QUIT does not reliably express permanent departure.
The encrypted roster is account/device membership, distinct from live socket
presence. Abruptly offline devices remain until explicit removal or the idle
eviction policy. This behavior must be visible to users.

### 13.6 Updates and post-compromise recovery

An active device **SHOULD** send and finalize its own Commit with a populated
UpdatePath at least once per `DEFAULT_ACTIVE_UPDATE_PERIOD` or
`DEFAULT_ACTIVE_UPDATE_MESSAGES` sent application messages, whichever occurs
first. Profile version 1 disables Update Proposals and
forbids standalone MLS Proposals; a separate application preview has no
authorization. A
fresh self-Commit with an UpdatePath is also required after suspected
compromise, authorization change, emergency-package use, and a
security-sensitive policy transition.

Post-compromise recovery is claimed only after attacker access to the old
private state has ended, every still-controlled leaf is removed, a required
honest Commit contributes fresh path entropy unknown to the attacker, all
required members process the finalized transition, and old secrets are
deleted. A member still controlled by the attacker legitimately receives the
new epoch and defeats that claim.

A client **SHOULD** warn its user when one of that account's devices has
produced no locally observed, valid MLS-authenticated application or handshake
message for `DEFAULT_IDLE_DEVICE_EVICTION`. This is a local reminder, not a
shared liveness fact: a server can suppress traffic, clients can be offline,
and profile version 1 has no signed idle-period policy field. No server or
client automatically removes a leaf from elapsed time alone. A controller may
respond to the warning only through the ordinary authorized removal and
finality flow. A client may offer an earlier local reminder, but it does not
advertise that preference as conversation policy or claim another member is
cryptographically inactive.

### 13.7 State loss and restoration

A device that loses or rolls back live MLS state **MUST NOT** continue with the
old leaf. It generates new device/group state, rejoins as a new leaf, and has
the old leaf removed.

Live MLS ratchets, generation counters, and group secrets **MUST NOT** be cloned
between devices or restored from an ordinary backup. Stale restoration risks
state forks and key/nonce reuse.

Normal crash safety uses a durable transaction containing the next MLS state,
application counter, monotonic `state_generation`, exact pending ciphertext,
binding locks, ACK locks, and every Commit/ReInit disposition vote lock. A
signature is emitted only after its lock transaction is synced. A retry sends
identical bytes rather than signing or encrypting again. Where the platform provides a
non-restorable monotonic secure counter, the client reserves its next value
before committing the database and requires exact equality on startup. A
counter ahead of the database or a database behind the counter makes the leaf
unusable and triggers rejoin.

A remote high-water mark controlled only by the malicious relay service is not
an anti-rollback anchor. When no reliable OS or hardware anchor exists, the
live MLS database **MUST** be excluded from restore/import workflows. After a
filesystem or device-image restore, every group state is discarded and the
device rejoins. Implementations without an anchor scope their rollback claim
accordingly.

The root private key remains in dedicated recovery storage and is not copied
into routine device installations. A root backup uses a high-entropy recovery
secret, authenticated encryption, explicit versioning, and rollback
protection; a human password alone is not an adequate encryption key. The
root-binding-lock head is inseparable anti-fork state for that signer and must
share its rollback protection. If the signer cannot prove that head current
after restoration, it rotates through a new continuous root before signing
another generation-zero binding.

#### 13.7.1 Server-side backup-restore gate

Endpoint recovery above does not authorize a restored delivery service to
resume an old route. In the composed daemon profile, every server-side route
also carries the exact daemon architecture specification Section-18.4
recovery record:

```text
enum {
    e2ee_recovery_normal(1), e2ee_recovery_pending(2),
    e2ee_recovery_conflict(3), e2ee_recovery_closed(4)
} E2eeServerRecoveryKind;

struct {
    uint16 recovery_gate_version;           // 1
    opaque conversation_id[32];
    E2eeServerRecoveryKind state;
    opaque recovery_epoch[16];
    opaque restored_binding_id[32];
    opaque restored_accepted_state_id[32];
    opaque restored_sequencer_head_id[32];
    opaque source_rollback_guard_hash[32];
} E2eeServerRecoveryGate;
```

An ordinary live route is `normal`. Restoring any nonterminal route writes
`pending` under the new daemon recovery epoch with the exact authenticated
source heads and source guard hash. Pending rejects application ciphertext,
new receipts/sequencer records, membership, policy, route, and security-state
mutation. It accepts only reads of already-known public objects,
byte-identical re-upload of previously signed evidence whose complete chain
extends a stored head, the Section 13.7.4 recovery submission that carries
such evidence, and the Section 12.5.1 witness resolution that delivers it to
a blocked edge. `EGROUP SUBMIT MEMBERSHIP` and every other companion mutation
of a `pending` route are refused with `E2EE_ROUTE_INVALID`, and the restored
server never signs a missing link.

A complete companion-valid chain to an already finalized terminal close may
atomically install the evidence and set `closed`; it never returns the old
lineage to `normal`. Two valid successors for one chain position set
`conflict` and permanently preserve/block both proofs. Without one continuous
terminal chain, users create a fresh semantic lineage with new sequencer
confirmation and renewed out-of-band verification. No administrator override
clears, rewrites, or downgrades this gate. These rules narrow every ordinary
recovery path in this document and never relax its signature, finality, or
client state-loss requirements.

#### 13.7.2 Public proof inputs and validation owners

Every transition a restored server may adopt is proved by public objects it
can fetch or receive, authorized by prior state it already holds. Publication
of an object, or of a matching digest, never implies adoption:

| Transition | Public proof inputs | Authorizing prior state |
| --- | --- | --- |
| initial authority at the pinned genesis binding | the `conversation_binding` package, its exact context-core bytes named by `context_core_id`, the generation-zero `policy` object, the exact `ArcSequencerCredential` bytes, and one `root_identity` plus `device_roster` object per binding principal | the independently pinned source binding of the restore: `restored_binding_id` and `source_rollback_guard_hash` of the durable gate, never the objects themselves |
| bootstrap activation | the genesis-epoch `candidate_record` and `finalization_record` at route sequences zero and one with the finalization's complete ACK-set digest | the initial-authority row: the receipt and certificate verify under the pinned sequencer credential at exactly the next position |
| policy transition | the `policy` object with its approvals and the `candidate_record` and `finalization_record` that commit it | the retained finalized policy chain head and the roster heads at the record's validation time |
| roster transition | the `device_roster` object and the finalized record committing the roster head | the previous root-signed roster and the retained root identity chain |
| root continuity transition | the successor `root_identity` in the account root chain and the finalized record | the previous root's continuity signature over the successor |
| binding transition | the successor `conversation_binding` package and the finalized record | the retained current binding and its approvals under the current policy |
| sequencer credential transition | the successor `ArcSequencerCredential` and the finalized GroupContextExtensions record | the previous credential's continuity signature and the old-policy-authorized finalization |
| ReInit target authorization | the `reinit_attempt_record` and the authorizing old-group finalization | the retained old finalized state and the `reinit_attempt_authorization_id` it names |
| ReInit activation | the `reinit_activation_record` with its complete ReInit ACK set and disposition votes | the retained ReInit attempt receipt and the old-policy finality council |
| terminal close | the `close_authorization` object | the finalized record named by `authorizing_terminal_id` and the last finalized policy's controller rule |

The restored server derives every authorizing prior state from the durable
`E2eeServerRecoveryGate`, its retained finalized records, and the credentials
pinned by them. Each row's inputs are adopted only when they verify under
that state at exactly the next chain position.

Every field of the carriers defined below has one validation owner and one
evidence class. Cryptographic finality means a signature or chain that the
owner verifies under a credential it already trusts. A server-visible
attestation is a check the owner performs against retained public state and
that can be wrong only if that retained state is wrong. An endpoint-only MLS
check is one no server can perform and none claims:

| Requirement | Carrier field or object | Validation owner | Evidence class |
| --- | --- | --- | --- |
| submission names this network and conversation | `ArcRecoverySubmissionTBS` `profile_version`, `network_id`, `conversation_id` | coordinator | server-visible attestation |
| submission targets the exact restored route | `ArcRecoverySubmissionTBS` `recovery_epoch`, `restored_binding_id`, `restored_accepted_state_id`, `restored_sequencer_head_id`, `source_rollback_guard_hash` equal the durable gate | coordinator | server-visible attestation |
| submission extends the stored head | `ArcRecoverySubmissionTBS` `route_sequence`, `predecessor_record_id` | coordinator | server-visible attestation |
| submission names one element | `ArcRecoverySubmissionTBS` `element_kind`, `element_object_kind`, `element_object_id`; the element hashes to that ID | coordinator | server-visible attestation |
| submitter is an authorized principal device | `ArcRecoverySubmissionTBS` `account_id`, `device_id`, and `ArcRecoverySubmission` `device_signature` under the retained roster | coordinator | server-visible attestation |
| record element continues the chain | `record_element`: the `sequencer_record` verifies under the credential committed for its position | coordinator | cryptographic finality |
| close element closes the chain | `close_element`: the `close_authorization` approvals satisfy the retained old policy and name the head finalization | coordinator | cryptographic finality |
| referenced object supports a record | `reference_element`: the object hashes to the ID the referencing record names | coordinator | server-visible attestation |
| resolution is addressed to this link | `ArcFederationWitnessResolution` `coordinator_server_id`, `target_server_id`, `conversation_id`, `resolution_token` | edge | server-visible attestation |
| resolution starts at the witnessed head | `ArcFederationWitnessResolution` `expected_sequence`, `expected_head_id` equal the durable row | edge | server-visible attestation |
| delivered records continue the chain | `ArcFederationWitnessResolution` `record_count`, `record_object_ids` and each delivered `sequencer_record` under the negotiated key set | edge | cryptographic finality |
| resolution ends at the claimed head | `ArcFederationWitnessResolution` `new_head_sequence`, `new_head_id` equal the last verified record | edge | cryptographic finality |
| proof names this network and conversation | `ArcLeafMembershipProofTBS` `profile_version`, `network_id`, `conversation_id` | coordinator | server-visible attestation |
| proof identifies one old leaf | `ArcLeafMembershipProofTBS` `epoch`, `leaf_index`, `old_credential_hash`, `leaf_signature_scheme`, `leaf_signature_key` | coordinator against the ACK TBS and the possession signature | server-visible attestation |
| proof binds an active device | `ArcLeafMembershipProofTBS` `account_id`, `device_id`, `root_generation`, `root_fingerprint`, `roster_generation`, `roster_id`, `credential_generation` and `ArcLeafMembershipProof` `device_signature` | coordinator against the retained roster and root chain | server-visible attestation |
| proof states a disposition | `ArcLeafMembershipProofTBS` `disposition`, `removal_finalization_id` and `ArcLeafMembershipProof` `possession_signature` | coordinator against retained finalized records | server-visible attestation |
| attempt names the old ReInit finalization | `ArcReInitAttemptTBS` `old_reinit_state_id` | coordinator against the retained finalized record that is the old conversation's accepted state | server-visible attestation |
| attempt carries the authorized target | `ArcReInitAttempt` `target` hashes to `ArcReInitAttemptTBS` `target_context_digest`, which equals the finalized authorization's `transition_target_digest`, and the attempt's group, version, suite, conversation, binding, and plan fields equal the target's | coordinator against the retained old ReInit finalization | server-visible attestation |
| carried target describes the successor of the bound route | the context extension in `ArcReInitTargetTBS` `encoded_target_extensions` | coordinator against the retained current binding | server-visible attestation |
| attempt's KeyPackage plan forms the target's semantic plan | `ArcReInitAttempt` `key_package_plan` and `ArcReInitTargetTBS` `initial_member_plan_id` | coordinator | server-visible attestation |
| leaf is actually in the tree at that epoch | the MLS ratchet tree | endpoint | endpoint-only MLS check |
| ACK set covers every UpdatePath copath | the old tree and staged Commit | endpoint | endpoint-only MLS check |
| exact continuing set of a ReInit | the old tree, the successor tree, and the Welcome set | endpoint | endpoint-only MLS check |
| ReInit target equals the reconstruction from its Proposal | the old ReInit Proposal or the successor's epoch-1 GroupContext, and the rosters its roster heads name | endpoint | endpoint-only MLS check |
| later joiner's ReInit binding and policy entries match the activated target | the join bundle's ReInit entries and the target that the referenced ReInit activation certificate's attempt carries | endpoint | endpoint-only MLS check |

The expected recovery epoch, source rollback guard hash, restored binding,
state, and head IDs, and the sequencer key set are taken only from the
durable `E2eeServerRecoveryGate`, the retained route state, and the
ECAP-negotiated key set, never from uploaded evidence.

#### 13.7.3 Leaf-membership proofs

An ordinary Commit ACK or ReInit ACK is signed by an old MLS leaf key the
server does not otherwise know. A leaf-membership proof gives the server a
public, device-attested mapping from an attached device to that leaf so the
ACK signer can be identified without any private MLS state:

```text
enum { continuing(1), removed(2) } ArcLeafDispositionKind;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque conversation_id[32];
    uint64 epoch;
    uint32 leaf_index;
    opaque old_credential_hash[32];
    SignatureScheme leaf_signature_scheme;
    opaque leaf_signature_key<1..255>;
    opaque account_id<1..255>;
    opaque device_id[16];
    uint64 root_generation;
    opaque root_fingerprint[32];
    uint64 roster_generation;
    opaque roster_id[32];
    uint64 credential_generation;
    ArcLeafDispositionKind disposition;
    opaque removal_finalization_id[32];
} ArcLeafMembershipProofTBS;

struct {
    ArcLeafMembershipProofTBS tbs;
    opaque device_signature[64];
    opaque possession_signature<0..255>;
} ArcLeafMembershipProof;
```

`epoch` is read against the disposition. A `continuing` proof names the MLS
epoch in which the leaf at `leaf_index` holds the credential whose
`old_credential_hash` and raw public `leaf_signature_key` the proof carries.
A `removed` proof names the first MLS epoch in which that leaf is gone: the
epoch established by the finalized record its `removal_finalization_id`
names, one later than the last epoch in which the leaf held that credential.
A leaf removed by the finalization of epoch `e` therefore states `removed`
at epoch `e+1`, above its own `continuing` proof at epoch `e`, so the
replacement rule below always admits a member's own removal and no removal
is lost because the leaf does not survive into the epoch it would otherwise
have to name. In both dispositions the account, device, root, roster, and
credential generation fields equal the leaf authorization of that
credential. The device signs with label `ARC-MLS/1 leaf membership`. A
`continuing` proof also carries a nonempty `possession_signature` by the old
leaf key with label `ARC-MLS/1 leaf membership possession`, verifiable under
the carried public key, and has an all-zero `removal_finalization_id`. A
`removed` proof carries an empty possession field and names the retained
finalized record after which the leaf is gone. `leaf_membership_id` is the
Section 2.2 hash of the TBS. The wire kind is `leaf_membership_proof`, the
object is at most `MAX_LEAF_MEMBERSHIP_OBJECT`, and it carries only a public
leaf key and digests: no ratchet tree, epoch secret, private key, or
decrypted GroupContext appears in it.

The server applies these rules:

- A proof is durably stored before any ACK it authenticates. A `commit_ack`
  or `reinit_ack` signer is identified by the stored `continuing` proof whose
  `(leaf_index, old_credential_hash)` equals the ACK TBS values and whose
  `epoch` is not later than the ACK's prior epoch; the server verifies the
  ACK's `old_leaf_signature` under that proof's public key and classifies the
  result as a server-visible attestation. An ACK with no such stored proof is
  refused with `E2EE_BINDING_AUTH_INVALID` and consumes no state.
- The proof's device must be active in the retained roster named by
  `roster_id` at the record's validation time, so a proof or ACK from a
  revoked device is refused. A stored proof whose device is no longer
  roster-active identifies no ACK and states no expectation: it leaves the
  expected continuing set when the device is revoked and returns to it only
  if that device becomes roster-active again.
- A proof whose `epoch` is later than the epoch the conversation has
  accepted attests to an old state that does not exist yet and is refused
  with `E2EE_EPOCH_STALE`. A `removed` proof whose `removal_finalization_id`
  names no finalization this conversation retains is refused with
  `E2EE_BINDING_AUTH_INVALID`; because that finalization is retained before
  the removal is admitted, the epoch a `removed` proof names is one the
  conversation has already accepted.
- Two `continuing` proofs for one `(leaf_index, old_credential_hash)` from
  different devices, or one device holding `continuing` proofs for two leaf
  indexes at one epoch, are a duplicate continuing leaf and are refused with
  `E2EE_OPERATION_CONFLICT`; the earlier stored proof is unchanged.
- A later proof for the same leaf and device with a higher `epoch` replaces
  the earlier one; a byte-identical resubmission returns the same
  `STORED MEMBERSHIP` reply without state change; a differing proof at the
  same epoch is refused with `E2EE_OPERATION_CONFLICT`.
- One device states one claim: its stored proofs at the highest `epoch` it
  has reached. Every earlier proof of that device stays retained and keeps
  identifying the ACKs of its own epoch but states nothing about the
  present, so a credential the device has rotated away from and a leaf it
  has since stated `removed` both stop being expected. The claim continues,
  naming that one `continuing` proof, only while the device is roster-active
  and no proof it holds at that epoch is `removed`; a duplicate continuing
  leaf is already refused, so at most one such proof exists.
- The expected continuing set of one ReInit attempt is every continuing
  claim whose device the attempt's `ArcKeyPackagePlan` carries into the
  successor. A `reinit_activation_request` that lacks a proof-backed ACK for
  a member of that set is refused as a missing continuing leaf with
  `E2EE_BINDING_AUTH_INVALID`, so a planned device acknowledges through the
  exact leaf it last proved and an attempt cannot quietly substitute another.
- A continuing claim the plan does not carry is outside that set and never
  blocks an activation. `key_package_plan_id` is committed by the
  `ArcReInitAttemptAuthorization` the old controller threshold signs, so the
  authority that decides membership has already answered that claim, and no
  one device holds the conversation's migration open with a leaf key no
  server can place in the ratchet tree. The claim stays stored and readable
  as that device's public statement, and revocation is not the only way to
  clear it.
- A `reinit_attempt` or `reinit_abort_request` submitter is an old-group
  device: one whose claim continues. No plan exists before an attempt, so
  that is the whole check. An activation submitter is additionally a device
  the attempt's plan carries into the successor.
- The server relies on `continuing` proofs only to identify ACK signers and
  to bound the expected ReInit continuing set, and on `removed` proofs only
  to shrink it. The exact continuing set, copath coverage, and removal
  outcomes remain endpoint-only MLS checks; the server check is a filter,
  never authority.

Proofs are stored under the conversation and fetched only through
`EGROUP FETCH OBJECT` by attached devices of binding-principal accounts. A
proof is durably stored before its ACK is admitted, so an ACK never waits on
a proof that is still in flight. Because Section 22 exact-match negotiation
refuses the previous profile hash, there is no mixed-mode admission: ACK
objects retained under the previous revision are historical evidence that
this revision never re-admits.

| Membership failure | Reply code |
| --- | --- |
| unattached or revoked device | `E2EE_DEVICE_REQUIRED` |
| account is not a binding principal | `E2EE_BINDING_AUTH_INVALID` |
| malformed object | `E2EE_INVALID_FRAGMENT` |
| invalid device or possession signature | `E2EE_BINDING_AUTH_INVALID` |
| roster or root mismatch | `E2EE_BINDING_AUTH_INVALID` |
| epoch later than the accepted epoch | `E2EE_EPOCH_STALE` |
| `removed` proof names no retained finalization | `E2EE_BINDING_AUTH_INVALID` |
| duplicate or conflicting continuing leaf | `E2EE_OPERATION_CONFLICT` |
| object exceeds `MAX_LEAF_MEMBERSHIP_OBJECT` | `E2EE_OBJECT_TOO_LARGE` |
| authenticated quota exceeded | `E2EE_RATE_LIMITED` |

#### 13.7.4 Recovery submission carrier

A route whose gate is `pending` accepts evidence only through a signed
submission that names exactly one element and binds it to the restored
route:

```text
enum {
    record_element(1), close_element(2), reference_element(3)
} ArcRecoveryElementKind;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque conversation_id[32];
    opaque recovery_epoch[16];
    opaque restored_binding_id[32];
    opaque restored_accepted_state_id[32];
    opaque restored_sequencer_head_id[32];
    opaque source_rollback_guard_hash[32];
    uint64 route_sequence;
    opaque predecessor_record_id[32];
    ArcRecoveryElementKind element_kind;
    ArcWireObjectKind element_object_kind;
    opaque element_object_id[32];
    opaque account_id<1..255>;
    opaque device_id[16];
} ArcRecoverySubmissionTBS;

struct {
    ArcRecoverySubmissionTBS tbs;
    opaque device_signature[64];
} ArcRecoverySubmission;
```

The device signs with label `ARC-MLS/1 recovery submission`;
`recovery_submission_id` is the Section 2.2 hash of the TBS. The wire kind is
`recovery_submission` and the object is at most
`MAX_RECOVERY_SUBMISSION_OBJECT`. A `record_element` names a
`sequencer_record`; a `close_element` names a `close_authorization`, because
`ArcSequencerRecordKind` has no close arm and the Section 12.5 rule makes the
close ID the head at the route sequence after its authorizing record; a
`reference_element` names an object of its existing kind that a submitted
record references. The element is uploaded under
`EGROUP SUBMIT RECOVERY-ELEMENT` in its existing wire kind with its existing
limit and must hash to `element_object_id`.

The submitter is an attached device whose account is a principal of the
binding named by `restored_binding_id` and whose certificate is active in
that account's retained roster at the element's validation time. A
submission is accepted, and answered `RECOVERY-ACCEPTED`, only when the gate
is `pending`, `recovery_epoch`, `source_rollback_guard_hash`, and the three
restored IDs equal the durable gate, and `route_sequence` equals the stored
head sequence plus one with `predecessor_record_id` equal to the stored head
ID, except that a byte-identical re-upload of the record already at the
restored head is idempotent. An exact duplicate returns the prior reply
without state change. When the element arrives, a record valid under the
credential committed for its position extends the head and is answered
`RECOVERY-EXTENDED`; a valid close element that names the head finalization
installs `closed` and is answered `RECOVERY-CLOSED`; a second record valid
under the position's committed credential at an already installed position
installs `conflict` and is answered `RECOVERY-CONFLICT` naming both record
IDs; an invalid second record is refused and installs nothing.

Incomplete evidence is bounded. A conversation holds at most
`MAX_OPEN_RECOVERY_SUBMISSIONS` accepted submissions whose element has not
arrived, and the complete accepted chain, elements included, is at most
`MAX_RECOVERY_CHAIN_BYTES`. An accepted submission whose element has not
arrived after `MAX_RECOVERY_SUBMISSION_SECONDS` is discarded with the gate,
head, and every other submission unchanged; a later element for it, or a
new submission beyond either ceiling, is refused with the code below, and
expiry never installs `closed` or `conflict`. Every byte counts against the
global E2EE disk ceiling and the per-conversation stored-byte quota.

| Recovery failure | Reply code |
| --- | --- |
| gate is not `pending`, wrong recovery epoch, guard, head, or binding | `E2EE_ROUTE_INVALID` |
| unrelated network, conversation, or context | `E2EE_ROUTE_INVALID` |
| unattached or revoked submitting device | `E2EE_DEVICE_REQUIRED` |
| account is not a principal of the restored binding | `E2EE_BINDING_AUTH_INVALID` |
| malformed submission or element | `E2EE_INVALID_FRAGMENT` |
| invalid submission signature or invalid record, close, or reference | `E2EE_BINDING_AUTH_INVALID` |
| element does not hash to `element_object_id` | `E2EE_HASH_MISMATCH` |
| unknown or expired submission for an element | `E2EE_OBJECT_NOT_FOUND` |
| object exceeds its limit | `E2EE_OBJECT_TOO_LARGE` |
| open-submission, chain-byte, or rate ceiling exceeded | `E2EE_RATE_LIMITED` |

Submissions and elements are retained under the recovery gate and are never
fanned out while the gate is `pending`. After installation they are fetched
through `EGROUP FETCH OBJECT` only by binding participants; on `closed` they
are installed together with the encrypted tombstone, and on `conflict` both
proofs are preserved permanently. Recovery submissions produce no new
semantic event kind: `recovery_closed` completes through the existing
`route_state_changed` event and every other result completes generically.

#### 13.7.5 Durability, irreversibility, and worked examples

Pending gates, accepted recovery submissions, stored membership proofs, and
`witness/v1` rows are durable and survive restart unchanged. A refused or
indeterminate storage write installs nothing and leaves the gate, head,
submission set, and witness row exactly as they were; the client receives
`E2EE_DELIVERY_UNCERTAIN` or a retryable failure, never a success. `closed`
and `conflict` are installed in one joint transaction and never transition
again; the old lineage never returns to `normal`. A fresh semantic lineage is
a new conversation, a ReInit successor or a new binding, under new sequencer
confirmation and renewed out-of-band verification. There is deliberately no
administrator or maintenance command that clears, rewrites, or downgrades the
gate or a `conflict` witness row; both this document and the daemon
architecture specification record that decision.

A complete recovery from an empty head at the external anchor to a valid
terminal close proceeds as follows. The restored head is the ReInit
activation anchor at route sequence zero:

| Step | Route sequence | Predecessor | Element | Reply | Gate after |
| --- | ---: | --- | --- | --- | --- |
| 1 | 1 | activation anchor | `record_element`: candidate receipt | `RECOVERY-EXTENDED` | `pending` |
| 2 | 2 | candidate ID | `record_element`: finalization certificate | `RECOVERY-EXTENDED` | `pending` |
| 3 | 2 | candidate ID | `record_element`: byte-identical finalization re-upload | prior reply, no change | `pending` |
| 4 | 3 | finalization ID | `close_element`: close authorization naming that finalization | `RECOVERY-CLOSED` | `closed` |
| 5 | 4 | close ID | any submission | `E2EE_ROUTE_INVALID` | `closed` |

Two valid successors at one position end in `conflict`:

| Step | Route sequence | Predecessor | Element | Reply | Gate after |
| --- | ---: | --- | --- | --- | --- |
| 1 | 1 | activation anchor | `record_element`: candidate receipt A | `RECOVERY-EXTENDED` | `pending` |
| 2 | 1 | activation anchor | `record_element`: candidate receipt B, valid under the same committed credential | `RECOVERY-CONFLICT` naming A and B | `conflict` |
| 3 | 2 | candidate A | `record_element`: finalization of A | `E2EE_ROUTE_INVALID` | `conflict` |

### 13.8 Full ReInit and route migration

`ReInit` is not shorthand for changing a context field. It closes the old MLS
group as specified by RFC 9420, then creates and quorum-activates one exact
successor. The preparation order is security-critical:

1. Before the old ReInit Commit, controllers precompute the exact immutable
   `ArcReInitTargetTBS`: target version, suite, group ID, complete extension
   bytes, generation-zero policy, roster heads, new binding, finality council,
   and semantic initial member plan. The old candidate authorization commits
   its target digest. The target covers no accepted-state or record ID of the
   old group, so it exists before the old Commit, receipt, authorization, and
   finalization and depends on none of their IDs. It does not commit one-use
   KeyPackages. Offline leaves and enough old finality principals to leave
   fewer than `q` continuing staged voters are removed or handed off in
   earlier finalized epochs, not omitted afterward.
   A ReInit successor sets `bootstrap_pending=0`; its separate activation
   certificate is already the all-member barrier, so it does not repeat the
   generation-zero bootstrap protocol.
2. The authorized old-group candidate carries exactly one inline ReInit
   Proposal containing those already-approved version, suite, group ID, and
   extension bytes. The old finality protocol certifies it. After finalization,
   the old group is permanently closed to application and handshake messages;
   it can never be reactivated. The post-Commit `reinit` resumption PSK is
   retained only for bounded successor attempts.
3. For one attempt, controllers choose the creator and approve an exact fresh
   `ArcKeyPackagePlan`. The creator initializes itself with its fresh target-suite leaf,
   constructs the exact initial Commit, Adds every other continuing leaf using
   the reserved KeyPackages, and injects the `reinit` resumption PSK. The new
   GroupContext exactly matches the ReInit parameters and reaches epoch 1.
   The creator is not a Welcome recipient.
4. The sequencer checks the attempt and the target it carries against the
   finalized old ReInit Commit and accepts one active attempt receipt. Every
   other continuing leaf receives a full-tree Welcome in `ArcStagedReInit`;
   the creator stages its locally constructed state. No staged endpoint sends
   new-group traffic.
5. The creator issues a `creator_state` ACK; every other continuing leaf
   validates and consumes its one-use Welcome and issues a `welcome_join` ACK.
   Version 1 requires exactly one ACK for every continuing old leaf. The
   server counts that set against the approved `ArcKeyPackagePlan` and
   against the Section 13.7.3 expected continuing set the same plan bounds,
   so a published continuing claim the approved plan does not carry is a
   disagreement the controllers settled in step 1, never a reason to refuse
   the activation.
6. Old-policy finality principals verify the exact attempt and complete ACK
   set, then issue sign-once ReInit disposition votes. A quorum activation
   certificate atomically remaps the route and activates new epoch 1: the
   coordinator installs the successor from the target the attempt carries in
   the transaction that stores the certificate, so no `EGROUP RESERVE` or
   `EGROUP BIND` precedes successor traffic.
7. On success, endpoints delete the resumption PSK, staged Welcomes, attempt
   state, and obsolete old-group secrets. An activation timeout leaves the old
   group closed and permits only a quorum abort of that successor attempt,
   followed by another attempt with a new creator if needed, a new controller
   authorization, fresh leaf keys, and fresh KeyPackages while the PSK is still
   retained. Every package in the aborted attempt is permanently burned.

The exact structures are:

```text
enum { creator_state(1), welcome_join(2) } ArcReInitAckKind;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque old_conversation_id[32];
    opaque new_conversation_id[32];
    opaque target_group_id<1..255>;
    ProtocolVersion target_version;
    CipherSuite target_suite;
    opaque target_context_core_id[32];
    opaque target_binding_id[32];
    opaque initial_member_plan_id[32];
    opaque encoded_target_extensions<1..1048576>;
} ArcReInitTargetTBS;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque old_conversation_id[32];
    opaque new_conversation_id[32];
    opaque old_reinit_state_id[32];
    uint32 attempt_sequence;
    uint32 creator_old_leaf_index;
    opaque creator_old_credential_hash[32];
    opaque target_group_id<1..255>;
    ProtocolVersion target_version;
    CipherSuite target_suite;
    opaque target_context_digest[32];
    opaque target_binding_id[32];
    opaque initial_member_plan_id[32];
    opaque key_package_plan_id[32];
    opaque initial_commit_digest[32];
    opaque attempt_authorization_id[32];
    opaque new_group_info_digest[32];
    opaque new_group_context_digest[32];
    opaque new_ratchet_tree_digest[32];
    opaque new_exporter_authenticator[32];
} ArcReInitAttemptTBS;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque old_conversation_id[32];
    opaque old_reinit_state_id[32];
    uint32 attempt_sequence;
    uint32 creator_old_leaf_index;
    opaque creator_old_credential_hash[32];
    opaque new_conversation_id[32];
    opaque target_context_digest[32];
    opaque target_binding_id[32];
    opaque initial_member_plan_id[32];
    opaque key_package_plan_id[32];
    opaque initial_commit_digest[32];
    opaque new_group_info_digest[32];
    opaque new_group_context_digest[32];
    opaque new_ratchet_tree_digest[32];
    opaque new_exporter_authenticator[32];
} ArcReInitAttemptAuthorizationTBS;

struct {
    ArcReInitAttemptAuthorizationTBS tbs;
    ArcCommitApproval approvals<144..16384>;
} ArcReInitAttemptAuthorization;

struct {
    ArcReInitAttemptTBS tbs;
    ArcReInitTargetTBS target;
    ArcKeyPackagePlan key_package_plan;
    opaque initial_commit_bytes<1..3145728>;
    ArcReInitAttemptAuthorization authorization;
    opaque creator_old_leaf_signature<1..255>;
} ArcReInitAttempt;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque old_conversation_id[32];
    opaque old_reinit_state_id[32];
    uint64 route_sequence;
    uint32 attempt_sequence;
    opaque predecessor_record_id[32];
    opaque reinit_attempt_id[32];
    opaque attempt_object_id[32];
    uint64 sequenced_at;
    opaque sequencer_key_id[32];
} ArcReInitAttemptReceiptTBS;

struct {
    ArcReInitAttemptReceiptTBS tbs;
    opaque sequencer_signature[64];
} ArcReInitAttemptReceipt;

struct {
    opaque old_reinit_state_id[32];
    opaque old_reinit_finalization_object_id[32];
    ArcReInitAttemptReceipt receipt;
    opaque new_conversation_id[32];
    opaque target_account_id_digest[32];
    opaque target_device_id[16];
    ArcJoinTransitionProofBundle transition_proofs;
    opaque welcome_bytes<1..4190000>;
} ArcStagedReInit;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque old_conversation_id[32];
    opaque new_conversation_id[32];
    opaque old_reinit_state_id[32];
    opaque reinit_attempt_id[32];
    ArcReInitAckKind ack_kind;
    opaque new_group_info_digest[32];
    opaque new_group_context_digest[32];
    opaque new_ratchet_tree_digest[32];
    opaque new_exporter_authenticator[32];
    uint32 old_leaf_index;
    opaque old_credential_hash[32];
    uint32 new_leaf_index;
    opaque key_package_ref<0..255>;       // empty only for creator_state
} ArcReInitAckTBS;

struct {
    ArcReInitAckTBS tbs;
    opaque old_leaf_signature<1..255>;
} ArcReInitAck;

enum { activate_reinit(1), abort_reinit_attempt(2) } ArcReInitDisposition;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque old_conversation_id[32];
    opaque old_reinit_state_id[32];
    uint32 attempt_sequence;
    opaque slot_predecessor_record_id[32];
    opaque reinit_attempt_id[32];
    ArcReInitDisposition disposition;
    opaque terminal_id[32];
    uint16 reason_code;
} ArcReInitDispositionVoteTBS;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque old_conversation_id[32];
    opaque new_conversation_id[32];
    opaque old_reinit_state_id[32];
    uint32 attempt_sequence;
    opaque reinit_attempt_id[32];
    opaque new_group_info_digest[32];
    opaque new_group_context_digest[32];
    opaque new_ratchet_tree_digest[32];
    opaque new_exporter_authenticator[32];
    opaque acknowledgement_set_digest[32];
} ArcReInitActivationCoreTBS;

struct {
    ArcReInitActivationCoreTBS core;
    ArcReInitAttemptReceipt receipt;
    ArcReInitAttempt attempt;
    ArcReInitAck acknowledgements<1..1048576>;
    ArcFinalityVote votes<0..16384>;
} ArcReInitActivationRequest;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque old_conversation_id[32];
    uint64 route_sequence;
    opaque predecessor_record_id[32];
    opaque reinit_activation_id[32];
    opaque sequencer_key_id[32];
    ArcReInitActivationRequest request;
} ArcReInitActivationTBS;

struct {
    ArcReInitActivationTBS tbs;
    opaque sequencer_signature[64];
} ArcReInitActivationCertificate;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque old_conversation_id[32];
    opaque old_reinit_state_id[32];
    uint32 attempt_sequence;
    opaque slot_predecessor_record_id[32];
    opaque reinit_attempt_id[32];
    uint16 reason_code;
    opaque evidence_digest[32];
} ArcReInitAbortCoreTBS;

struct {
    ArcReInitAbortCoreTBS core;
    ArcReInitAttemptReceipt receipt;
    ArcReInitAttempt attempt;
    ArcFinalityVote votes<0..16384>;
} ArcReInitAbortRequest;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque old_conversation_id[32];
    uint64 route_sequence;
    opaque predecessor_record_id[32];
    opaque reinit_abort_id[32];
    opaque sequencer_key_id[32];
    ArcReInitAbortRequest request;
} ArcReInitAbortTBS;

struct {
    ArcReInitAbortTBS tbs;
    opaque sequencer_signature[64];
} ArcReInitAbortCertificate;
```

`target_context_digest` is
`SHA256("ARC-MLS/1 reinit target" || encoded_ArcReInitTargetTBS)`. The target
covers no accepted-state or record ID of the old group; every field is fixed
by the old conversation and the ReInit Proposal. `target_group_id`,
`target_version`, `target_suite`, and `encoded_target_extensions` are the
Proposal's group ID, version, cipher suite, and exact encoded extension list,
and `new_conversation_id` is the Section 2.2 conversation ID of that group ID.
The list carries exactly one `ARC_MLS_CONTEXT_EXTENSION` and exactly one
`required_capabilities` extension. `target_binding_id` is the Section 2.2
`binding_id` of that context's `current_binding`, `initial_member_plan_id` is
that binding's plan ID, and `target_context_core_id` is that binding's
`context_core_id`, which equals the Section 2.2 ID of the `ArcContextCoreTBS`
recomputed from the target version, suite, and group ID, the
`required_capabilities` extension data, the context's initial validation
time, and the binding's network, conversation, kind, route lock, route,
initial and operational policy, plan, and sequencer IDs, with
`initial_bootstrap_pending` zero.

That context describes the successor as it is once activated: it names the
target's profile version, network, and new conversation ID; its lifecycle is
active with a zero `close_intent_id`; its `bootstrap_pending` is zero; and it
names no pending join, because the activation certificate, not a
join-confirmation self-Commit, completes every continuing leaf's join. Its
`policy` is the successor's generation-zero policy: it names the target's
network and new conversation ID and the context's kind, selects the
Proposal's suite, has an all-zero `previous_policy_id`, and its Section 2.2 ID
is both the binding's `initial_policy_id` and its
`required_operational_policy_id` (Section 9.5). Its `sequencer` credential has
the Section 2.2 ID the binding names. Its `current_binding` is a Section 9.4
replacement of the old conversation's current binding: its generation is one
greater than that binding's, its `previous_binding_id` is that binding's ID,
and it has no approvals. The binding names the target's profile version,
network, group ID, and new conversation ID, the Proposal's version and suite,
the context's kind and concrete route, and the old binding's semantic route
lock and concrete route, which the activation remaps to the successor
(step 6). The successor's policy, with its controllers and finality council,
is verified under the rosters that the context's `roster_heads` name, not
under the old conversation's rosters, and each of those heads for an account
that the old context's `roster_heads` also name carries either the old head's
root or a continuous successor of it (Section 8.2), so a ReInit never carries
a root discontinuity. Like every context extension, the context also meets the
policy, binding, roster-head, and private-topic rules of Sections 9.3 to 9.5.

Because no target field depends on the accepted state, the target's bytes and
digest do not change when the accepted state advances between freezing the
target and sequencing its candidate, for example through a finalized
self-update or another member's Commit after a candidate abort. A later
candidate carrying the same Proposal needs only its own candidate-specific
authorization, whose `prior_state_id`, `candidate_id`, and `commit_object_id`
bind the unchanged digest to the new position. Controllers freeze a new target
only when its content has to change, for example because an embedded roster
head, policy, or sequencer credential is no longer valid. One target
therefore stays byte-identical from preparation through old finality, every
attempt and attempt abort, activation, and later join ancestry.

Every `ArcReInitAttempt` carries in `target` the exact target whose digest is
its `target_context_digest`: the creator copies, byte for byte, the target
that the old candidate authorization committed. The attempt TBS, the attempt
authorization, and that old authorization commit the target through its
digest, the receipt commits the attempt object that holds it through
`attempt_object_id`, and the activation and abort requests embed that
attempt, so the sequencer, the controllers, every continuing leaf, and a later
joiner check the same bytes, including those that never see the Proposal. The
carried target counts toward `MAX_REINIT_OBJECT` in the attempt and in each
request that embeds it (Section 16).

An endpoint reconstructs the target from the ReInit Proposal it verifies: an
old-group member from the staged old Commit before it approves,
acknowledges, or votes, and a continuing member from the successor
GroupContext at epoch 1 before it acknowledges an attempt. That epoch-1
GroupContext carries exactly the Proposal's extension list (step 3). A later
GroupContext does not: it names the joining member's own pending join and may
name later roster heads and policies, so a member that joins the successor
after activation verifies its join bundle's ReInit entries against the
carried target as stated below instead. An endpoint verifying a ReInit
**MUST** reject it when:

- the Proposal's extension list does not carry exactly one context extension
  and one `required_capabilities` extension, or the context core recomputed
  from them differs from their binding's `context_core_id`;
- the context in that list, or its `current_binding`, does not describe the
  successor as stated above: it names another profile version, network,
  conversation, group ID, kind, route, version, or suite, is not active with
  a zero `close_intent_id`, has a nonzero `bootstrap_pending` or a pending
  join, carries a policy or sequencer credential other than the one its
  binding names, or the binding is not a replacement of the old
  conversation's current binding with the next generation, that binding's ID
  as `previous_binding_id`, and no approvals;
- the context's policy does not verify under the rosters its `roster_heads`
  name, or one of those heads, for an account that the old context's
  `roster_heads` also name, carries a root that is neither the old head's
  root nor a continuous successor of it;
- a presented target, or its binding, context core, plan, or extension bytes,
  differs from that reconstruction, including a target replaced after the old
  ReInit Commit finalized and the target an attempt carries;
- the old candidate authorization has action bits other than the ReInit bit
  alone, commits a `transition_target_digest` other than the reconstructed
  digest, or names a `prior_state_id` other than the accepted state that the
  candidate receipt and finalization core name;
- the finalization core does not commit the recomputed ID of that
  authorization;
- an attempt, attempt authorization, receipt, `ArcStagedReInit`, ACK, vote,
  activation, or abort names an `old_reinit_state_id` other than the
  recomputed finalization ID of the old ReInit Commit; or
- an attempt's `target_context_digest` differs from the authorized digest or
  from the digest of the target it carries, or its group ID, version, suite,
  new conversation ID, target binding ID, or initial member plan ID differs
  from that target.

The sequencer holds the old ReInit finalization and the target each attempt
carries, but not the Proposal. The sequencer **MUST** refuse an attempt for a
conversation whose accepted state is not the finalization of a ReInit Commit
with `E2EE_FINALITY_REQUIRED`, retaining nothing.

For an attempt on a conversation whose accepted state is the finalization of
a ReInit Commit, before it signs an attempt receipt, the sequencer **MUST**
refuse the attempt with `E2EE_BINDING_AUTH_INVALID`, retaining nothing, when:

- its `old_reinit_state_id` is not the ID of the finalization that is the old
  conversation's accepted state;
- the target it carries does not hash to its `target_context_digest`, or that
  digest differs from the `transition_target_digest` of the authorization
  that finalization commits;
- its group ID, version, suite, new conversation ID, target binding ID, or
  initial member plan ID differs from the target it carries;
- the device tuples and capability IDs of its `ArcKeyPackagePlan`, in that
  plan's canonical order, do not form the `ArcInitialMemberPlan` whose
  Section 2.2 ID is the target's `initial_member_plan_id`; or
- the extension list of the target it carries fails the first two endpoint
  rules above, with that target in place of the Proposal, or that target's
  `new_conversation_id`, `target_context_core_id`, `target_binding_id`, or
  `initial_member_plan_id` is not the value this section derives from that
  list.

A member that joins the successor after activation holds neither the
Proposal nor the epoch-1 GroupContext. Its Welcome wrapper references the old
ReInit Commit's finalization certificate as `reinit_target_authorization` and
the activation certificate as `reinit_activation` (Section 9.5), and the
attempt inside that activation certificate carries the target. The
activation certificate is the old-policy quorum's statement that every
continuing leaf acknowledged that attempt after reconstructing the target, so
the joiner checks the ReInit entries against the carried target and relies on
that quorum for the checks that need the old group's state, such as the old
context's roster heads. Such a joiner **MUST** reject the ReInit binding-chain
or policy-chain entry when:

- the finalization certificate fails the old-authorization and finalization
  rules above, with the digest of the target the activation's attempt carries
  in place of the reconstructed digest, or the activation certificate does not
  verify under the old policy;
- the activation's attempt names an `old_reinit_state_id` other than that
  finalization's recomputed ID or a `target_context_digest` other than its
  authorized digest, or the target the attempt carries does not hash to that
  digest;
- the extension list of the carried target fails the first two endpoint rules
  above, with that target in place of the Proposal and the binding-chain
  entry that precedes the ReInit entry as the old conversation's current
  binding, the carried target's `new_conversation_id`,
  `target_context_core_id`, `target_binding_id`, or `initial_member_plan_id`
  is not the value this section derives from that list, or the attempt's
  group ID, version, suite, new conversation ID, target binding ID, or initial
  member plan ID differs from the carried target;
- the binding-chain entry's binding differs from the binding in the carried
  target's context, or its package carries a root binding lock; or
- the policy-chain entry's policy differs from the policy in the carried
  target's context.

The `initial_commit_digest` is
`SHA256("ARC-MLS/1 reinit initial commit" || initial_commit_bytes)`; the bytes
are the complete canonical MLS message containing the successor initial
Commit, not an IRC wire wrapper. Like every Commit after group creation
(Section 7.4), it is a `PrivateMessage` whose public header names the target
group ID, epoch zero, and the `commit` content type, so only its creator,
which alone holds the successor's epoch-zero secrets, can parse its content.
Its group, Add set, KeyPackageRefs, leaf keys, resumption PSK usage,
GroupContext, tree, and GroupInfo must match the target and key-package plans
and every result digest: the creator checks them on the Commit it constructs,
and every Welcome recipient checks the same facts from its Welcome, the
GroupSecrets it decrypts, the full ratchet tree, and the GroupInfo before it
acknowledges. Every other verifier checks the public header, the
authenticated data, and the digests.
The successor initial Commit's `authenticated_data` **MUST** be the Section 10
`ArcCommitAad` that names the target's profile version and network, the new
conversation ID, the target context's `route_binding`, a `validation_time` no
earlier than the old ReInit Commit's, and `old_reinit_state_id` as
`prior_state_id`. The successor has no accepted state before activation, and
its `reinit_activation_id` depends on this Commit through the attempt's
`initial_commit_digest`, so naming that activation ID, or any other successor
state, would make the digests circular.

The attempt authorization TBS repeats every attempt field a controller must
review. Its fields must equal the attempt TBS exactly, and its Section 2.2 ID
must equal `attempt_authorization_id`. Its approvals use label
`ARC-MLS/1 reinit attempt authorization`, are canonical, come from active old
policy-authority devices, and meet the old controller threshold. A different
attempt sequence, creator, leaf key, KeyPackageRef, initial Commit, or staged
result requires a new authorization. The attempt creator then signs
`ArcReInitAttemptTBS` with label `ARC-MLS/1 reinit attempt` using its old leaf
key. `reinit_attempt_id` is recomputed from that TBS, while
`attempt_object_id` addresses the complete proof-bearing wire object.

The sequencer receipt is signed with label
`ARC-MLS/1 reinit attempt receipt`. The first attempt has sequence zero,
predecessor equal to `old_reinit_state_id`, and route sequence exactly one
after the finalized old ReInit record. After a valid attempt abort, the next
attempt increments its sequence, names that `reinit_abort_id` as predecessor,
and uses the next route sequence. In the attempt, attempt authorization,
receipt, `ArcStagedReInit`, ACK, vote, activation, and abort,
`old_reinit_state_id` is the semantic finalization ID of the old ReInit
Commit; the target, which precedes that finalization, does not carry it. A
staged recipient fetches and verifies both object IDs in `ArcStagedReInit`
and every required transition proof reference before consuming its Welcome.
The wrapper's new conversation ID equals the fetched attempt, and its target
account digest and Device ID equal exactly one non-creator key-package-plan
entry and the resulting leaf credential. A creator never receives this
wrapper. For the new ReInit target's binding and policy entries, the wrapper
contains the old finalization's `reinit_target_authorization` references but
not the future activation references; every older ReInit entry has both. Both
normal and ReInit wrapper `welcome_bytes` fields are at most
`MAX_EMBEDDED_MLS_WELCOME_BYTES`, their transition-proof bundle is at most
`MAX_JOIN_TRANSITION_PROOF_BUNDLE_BYTES`, and the complete wire object must
still fit `MAX_WELCOME_MAILBOX_OBJECT`.

Each old leaf signs its ACK with label `ARC-MLS/1 reinit processed`. ACKs are
canonical by old leaf index and match the exact old-to-new credential and
key-package-plan entry. The creator ACK has an empty KeyPackageRef; every
Welcome ACK names its reserved ref. Exactly one ACK is required for every plan
entry. The exporter uses label `ARC-MLS/1 reinit activation`, the old ReInit
state ID as context, and a 32-byte output.

The ACK-set digest uses the Section 2.2 ReInit ACK-TBS formula.
`reinit_activation_id` and `reinit_abort_id` use the Section 2.2 core-TBS
formulas. Finality devices sign the reconstructed
`ArcReInitDispositionVoteTBS` with label `ARC-MLS/1 reinit disposition`.
An activation vote counts only from an old-policy finality principal that has
an equivalent successor leaf, supplied the matching ACK, and personally
staged the exact successor state. At least the unchanged old-policy quorum
must be eligible; an omitted or unstaged principal may vote only to abort.

The ReInit vote slot is `(network_id, old_conversation_id,
old_reinit_state_id, attempt_sequence,
receipt.predecessor_record_id)`. A device durably signs at most one exact vote
TBS in that slot. The activation or abort wrapper has route sequence exactly
one after the attempt receipt, `predecessor_record_id` exactly equal to
`reinit_attempt_id`, the current sequencer key ID, and a recomputed semantic
terminal ID. Variable valid vote subsets are alternative evidence for that
same ID. The sequencer signs activation with label
`ARC-MLS/1 reinit activation` or abort with
`ARC-MLS/1 reinit attempt abort` only after it has verified at least `q`
distinct valid votes under the old conversation's current policy over the
attempt's slot, exactly as in Section 12.4; endpoints still validate the
quorum and the staged result themselves.
Activation makes
`reinit_activation_id` the successor's initial accepted state and external
record-head anchor. The activation and abort quorums cannot both exist within
the fault bound.

The coordinator **MUST** install the successor from the target the activated
attempt carries in the same durable transaction that stores the activation
certificate, and before it sends any reply or event for that activation: the
remap of the old route to the new conversation ID; the successor conversation,
whose binding is the `current_binding` of the target's context, whose current
`BINDING` object (Section 11.7) is the `ArcConversationBindingPackage` of that
binding with the `ArcInitialMemberPlan` the attempt's `ArcKeyPackagePlan`
forms and no root binding lock, whose current and retained published policy
(Section 9.3) is that context's `policy`, and whose pinned credential is that
context's `sequencer`; `reinit_activation_id` as its accepted state and
record-head anchor; and the delivery mappings that send the route's encrypted
traffic and mailbox objects to the successor. The successor's context digest
is the Section 2.2 `context_digest` of the `ArcMlsContext` in the target, the
value an `EGROUP BIND` would carry, never the attempt's
`target_context_digest`, which hashes a different structure under a different
label. A ReInit successor is therefore never bound with `EGROUP RESERVE` and
`EGROUP BIND`: once its activation is durable it accepts ordinary candidates,
from its own route sequence zero (Section 12.2), and application objects, also
after a coordinator restart, which restores the installed successor from
durable state. A crash leaves either the old route closed with its attempt
pending or the complete installed successor, never part of it.

An attempt abort never rolls back or reopens the old MLS group. It only
permits a different successor creator as contemplated by RFC 9750 while the
same resumption PSK remains retained. If the PSK is deleted or its
`REINIT_RESUMPTION_PSK_RETENTION` hard lifetime expires, continuity recovery is unavailable: users must create
a fresh security context with generation-zero binding unanimity and renewed
out-of-band verification. No server-only route remap repairs it.

## 14. Replay, ordering, and persistence

MLS sender generations handle network reordering but do not prevent every
replay by a malicious insider. The encrypted `sender_sequence` and
`message_id` provide the application replay layer.

All state-advancing profile generation and sequence counters have one exact
scope and advancement rule:

| Value | Scope | Initial value | Advancement |
| --- | --- | ---: | --- |
| `root_generation` | Account ID root lineage | 0 | exactly +1 |
| `roster_generation` | root fingerprint | 0 | exactly +1 |
| `capability_generation` | root fingerprint and Device ID | 0 | exactly +1 |
| `credential_generation` | one fresh leaf signature key | 0 | fixed at zero in version 1 |
| sequencer `key_generation` | ARC network sequencer lineage | 0 | exactly +1 per continuous key rotation |
| federation key-set generation | ARC network link profile | 0 | exactly +1 per accepted active-key-set change |
| `policy_generation` | MLS group | 0 | exactly +1 |
| `binding_generation` | semantic conversation lineage | 0 | exactly +1 |
| `root_binding_sequence` | root fingerprint, globally | 0 | exactly +1 per lock object |
| `route_sequence` | one conversation sequencer log | 0 | exactly +1 per semantic record |
| `candidate_sequence` | one prior MLS epoch | 0 | exactly +1 only after certified abort |
| `attempt_sequence` | one finalized ReInit transition | 0 | exactly +1 only after certified attempt abort |
| `operation_sequence` | federation origin incarnation | 0 | exactly +1 per logical request |
| `origin_generation` | federation Origin ID | 0 | exactly +1 per ACKed origin update |
| `device_session_generation` | Account ID and Device ID | 1; zero is unattached | exactly +1 per successful attach |
| federation `state_generation` | Network ID, recovery epoch, and coordinator incarnation; shared with the base profile | 0 | exactly +1 per accepted coordinator `MutationPlan` in either or both profiles |
| federation `delivery_generation` | coordinator recovery epoch, target Server ID/incarnation | 0 | exactly +1 only for an explicit full ESTATE reset in the same scope |
| federation `delivery_sequence` | target and delivery generation | 0 | exactly +1 per durable event copy |
| `sender_sequence` | group ID and leaf key | 0 | exactly +1 per new application ciphertext |
| local `state_generation` | one durable device database | 0 | exactly +1 per state-advancing transaction |

No counter wraps; exhaustion blocks and requires the corresponding fresh key,
identity, ReInit, or conversation. An ordinary group begins with
`genesis_state_id`; a ReInit successor begins with `reinit_activation_id`.
Aborts advance only the record head, not accepted MLS state. Finalizations
advance both. Every predecessor is exact equality, never merely an older
known ancestor.

Clients maintain, per `(group_id, leaf signature key)` for the entire lifetime
of that leaf:

- the highest accepted application sequence;
- a bounded bitmap/window for out-of-order sequences;
- bounded outstanding gaps and recent message IDs; and
- after removal, a tombstone high-water mark for at least the ciphertext
  retention interval.

MLS sender-generation windows are separate state with separate limits. An
application sequence beyond `MAX_APPLICATION_SEQUENCE_FORWARD_JUMP` or an
attempt to create more than `MAX_APPLICATION_SEQUENCE_GAPS` is rejected
without advancing either window. Update Commits and epoch changes preserve the
application state; only a new leaf key and scope starts at zero. When the
conversation-wide replay-state byte ceiling is reached, clients reject new
gaps rather than evicting accepted high-water marks or opening a replay path.

Outbound state advancement, application counter advancement, exact ciphertext
creation, durable outbox insertion, and `state_generation` advancement **MUST**
be one crash-safe transaction completed before emission. A retry sends the
identical stored ciphertext. The implementation never emits bytes if a crash
could restore a state that reuses an MLS generation, nonce, message ID, or
application sequence.

Inbound MLS-ratchet advancement, skipped-key consumption, application replay
windows, accepted message IDs, accepted transition-proof mappings,
local-history insertion, and
`state_generation` advancement are likewise one durable transaction completed
before rendering plaintext or triggering notifications, bots, or other side
effects. A persistence failure renders nothing. Crash recovery may redeliver
ciphertext to the parser but cannot redisplay or re-execute an already
committed message.

Past-epoch retention means only bounded, unconsumed receive key/nonce pairs and
the minimum unconsumed ratchet branches permitted by RFC 9420. Implementations
never retain `epoch_secret`, `commit_secret`, `joiner_secret`, consumed
`encryption_secret` material, consumed ratchet secrets, or obsolete tree
private keys. All are deleted on the RFC 9420 schedule. Retaining them for
convenience invalidates the corresponding forward-secrecy claim. Removal adds
the stricter immediate purge in Section 13.5.

Per-sender state detects replays and some omissions. It does not establish a
single cross-sender display order: two honest recipients may receive ordinary
messages in different orders, and the server may selectively omit them.

## 15. History and offline delivery

The server may store complete opaque MLS objects and receipts for bounded
idempotent retry and direct-device offline delivery. It never stores decrypting
keys. Profile version 1 deliberately defines no discoverable server-side
channel application-history cursor: channel application objects are live
fanout only, apart from a fetch by already-known object ID. A deployment must
not advertise generic IRC history as encrypted history.

Direct offline objects use the attached-device, delivery-token, paged mailbox
protocol in Section 11.6. A ciphertext-only bouncer may provide additional
history only through a separately specified client relationship; a decrypting
bouncer is an explicit MLS leaf.

An existing device can process delayed traffic only within its retained epoch
and skipped-key windows. A newly added, restored, or rejoined device receives
no pre-join history. This is a deliberate forward-secrecy property.

Clients may store already-decrypted local history encrypted at rest under
device storage protections. Server-side full-text search, previews, or content
indexing are impossible without adding a visible decrypting endpoint.

A future archive-key extension may intentionally trade forward secrecy for
cross-device history. It is outside version 1 and must be labeled as a weaker
security profile rather than silently exporting live MLS secrets.

Terminal records referenced by an `ArcJoinTransitionProofBundle`, every
root-binding lock, and the root, roster, binding, and policy ancestry needed
to verify a live semantic lineage are security proofs, not ordinary message
history. The responsible servers retain those exact objects for
`SECURITY_PROOF_RETENTION`; the ordinary `SEQUENCER_RECORD_RETENTION` applies
only to records not referenced by a live proof chain. A server never frees
space by deleting a proof still needed to validate a live lineage.

At terminal-record acceptance, the coordinator conservatively marks every
certificate whose authorization action bits contain policy, binding/route, or
ReInit change as a security proof; it does not wait for a later Welcome to
reference it. ReInit activation certificates and generation-zero binding and
root-lock objects are marked on acceptance as well. Parsing this retention
class grants no cryptographic authority: endpoints still perform every proof
check.

The proof set counts against `MAX_STORED_BYTES_PER_CONVERSATION`. Before that
quota is exhausted, the route stops accepting new proof-producing transitions
and Adds. Recovery is an explicitly finalized close followed by a new semantic
incarnation with fresh root locks and renewed verification; silently
checkpointing or truncating ancestry is forbidden. Proofs for the closed
lineage remain available through `WELCOME_RETENTION`, after which that lineage
cannot accept another join or transition.

## 16. Resource and timing limits

The profile limits and operational defaults are:

| Named limit | Default |
| --- | ---: |
| `MAX_APPLICATION_PLAINTEXT` | 32,768 bytes |
| `MAX_PRIVATE_TOPIC_BYTES` | 4,096 bytes |
| `MAX_APPLICATION_MLS_OBJECT` | 65,536 bytes |
| `MAX_KEY_PACKAGE_OBJECT` | 65,536 bytes |
| `MAX_IDENTITY_OBJECT` | 65,536 bytes |
| `MAX_ROOT_CHAIN_OBJECT` | 1,048,576 bytes |
| `MAX_ROSTER_OBJECT` | 65,536 bytes |
| `MAX_CAPABILITY_OBJECT` | 65,536 bytes |
| `MAX_CREDENTIAL_BUNDLE` | 8,192 bytes |
| `MAX_POLICY_BYTES` | 32,768 bytes |
| `MAX_POLICY_OBJECT` | 32,774 bytes |
| `MAX_BINDING_OBJECT` | 262,144 bytes |
| `MAX_BINDING_CHAIN_BYTES` | 1,048,576 bytes |
| `MAX_ARC_MLS_CONTEXT_EXTENSION` | 196,608 bytes |
| `MAX_POLICY_CHAIN_BYTES` | 1,048,576 bytes |
| `MAX_LIVE_OBJECT` | 262,144 bytes |
| `MAX_COMMIT_APPROVAL_OBJECT` | 65,536 bytes |
| `MAX_COMMIT_ACK_OBJECT` | 65,536 bytes |
| `MAX_REINIT_ACK_OBJECT` | 65,536 bytes |
| `MAX_FINALIZATION_OBJECT` | 4,190,000 bytes |
| `MAX_ABORT_OBJECT` | 1,048,576 bytes |
| `MAX_REINIT_OBJECT` | 4,190,000 bytes |
| `MAX_REINIT_INITIAL_COMMIT_BYTES` | 3,145,728 bytes |
| `MAX_RESERVATION_OBJECT` | 65,536 bytes |
| `MAX_SEQUENCER_RECORD_OBJECT` | 4,194,304 bytes |
| `MAX_CLOSE_OBJECT` | 32,768 bytes |
| `MAX_DEVICE_ATTACH_OBJECT` | 4,096 bytes |
| `MAX_FEDERATION_CONTROL_OBJECT` | 65,536 bytes |
| `MAX_FEDERATION_STATE_ENTRIES_PER_EDGE` | 1,000,000 |
| `MAX_FEDERATION_STATE_SNAPSHOT_BYTES_PER_EDGE` | 536,870,912 bytes |
| `FEDERATION_STATE_SNAPSHOT_TIMEOUT` | 15 minutes absolute |
| `MAX_UNACKED_E2EE_EVENTS_PER_EDGE` | 262,144 |
| `MAX_UNACKED_E2EE_EVENT_BYTES_PER_EDGE` | 1,073,741,824 bytes |
| `MAX_CROSS_PROFILE_EVENT_PARTS_PER_EDGE` | 2,048 |
| `MAX_CROSS_PROFILE_EVENT_BYTES_PER_EDGE` | 16,777,216 bytes |
| `ACKED_E2EE_EVENT_REPLAY_TARGET` | 24 hours |
| `MAX_ACKED_E2EE_EVENT_REPLAY_ROWS_PER_EDGE` | 1,000,000 |
| `MAX_ACKED_E2EE_EVENT_REPLAY_BYTES_PER_EDGE` | 1,073,741,824 bytes |
| `MAX_WELCOME_MAILBOX_OBJECT` | 4,194,304 bytes |
| `MAX_EMBEDDED_MLS_WELCOME_BYTES` | 4,190,000 bytes |
| `MAX_JOIN_TRANSITION_PROOF_BUNDLE_BYTES` | 262,147 bytes |
| `MAX_E2EE_SERVER_PREFIX_BYTES` | 127 serialized bytes |
| `MAX_SERIALIZED_ACCOUNT_TAG` | 512 bytes |
| `MAX_CANDIDATE_RECEIPT_TAG` | 462 bytes |
| `MAX_FRAGMENT_RAW` | 2,940 bytes |
| `MAX_LIVE_FRAGMENT_COUNT` | 90 |
| `MAX_MAILBOX_FRAGMENT_COUNT` | 1,427 |
| `MAX_OPEN_REASSEMBLIES_PER_LOCAL_SENDER` | 1 |
| `MAX_OPEN_REMOTE_OBJECTS_PER_SENDER` | 8 |
| `MAX_OPEN_REMOTE_OBJECTS_PER_CONNECTION` | 32 |
| `MAX_LIVE_REASSEMBLY_BYTES_PER_CONNECTION` | 2,097,152 bytes |
| `MAX_OPEN_REASSEMBLIES_PER_ACCOUNT` | 16 |
| `MAX_REASSEMBLY_BYTES_PER_ACCOUNT` | 8,388,608 bytes |
| `MAX_OPEN_REASSEMBLIES_PER_ROUTE` | 64 |
| `MAX_REASSEMBLY_BYTES_PER_ROUTE` | 16,777,216 bytes |
| `MAX_OPEN_REASSEMBLIES_PER_FEDERATION_PEER` | 256 |
| `MAX_REASSEMBLY_BYTES_PER_FEDERATION_PEER` | 67,108,864 bytes |
| `MAX_OPEN_REASSEMBLIES_GLOBAL` | 1,024 |
| `MAX_REASSEMBLY_BYTES_GLOBAL` | 268,435,456 bytes |
| `LIVE_REASSEMBLY_TIMEOUT` | 2 minutes absolute, 15 seconds idle |
| `MAILBOX_REASSEMBLY_TIMEOUT` | 10 minutes absolute, 30 seconds idle |
| `MIN_ADMITTED_E2EE_INGRESS_RATE` | 65,536 bytes/second |
| `MAX_RECIPIENT_E2EE_SENDQ` | 8,388,608 bytes |
| `MAX_BATCH_OBJECTS` | 32 |
| `MAX_BATCH_FRAGMENTS` | 1,427 |
| `MAX_BATCH_DECODED_BYTES` | 4,194,304 bytes |
| `RECENT_OBJECT_IDEMPOTENCY_RETENTION` | 30 minutes |
| `S2S_IDEMPOTENCY_RETENTION` | 24 hours |
| `MAX_ACTIVE_COMMIT_CANDIDATES` | 1 |
| `MAX_FINALITY_PRINCIPALS` | 64 |
| `MAX_BINDING_PRINCIPALS` | 64 |
| `MAX_BINDING_APPROVALS` | 256 |
| `MAX_CANDIDATE_ATTEMPTS_PER_EPOCH` | 8 |
| `ENROLLMENT_CHALLENGE_TIMEOUT` | 10 minutes |
| `RESERVATION_TIMEOUT` | 60 seconds |
| `ATTACH_CHALLENGE_TIMEOUT` | 60 seconds |
| `MAILBOX_DELIVERY_TOKEN_TIMEOUT` | 10 minutes |
| `DIRECTORY_CURSOR_TIMEOUT` | 10 minutes |
| `MAX_COMMIT_CLOCK_SKEW` | 10 minutes |
| `COMMIT_STAGING_TIMEOUT` | 10 minutes; pause only, never auto-skip |
| `JOIN_CONFIRMATION_TIMEOUT` | 1 hour |
| `KEY_PACKAGE_CLAIM_TIMEOUT` | 7 days |
| `MAILBOX_ACK_RETENTION` | 30 minutes |
| `REINIT_STAGING_TIMEOUT` | 1 hour |
| `MAX_COMMIT_SUBMISSIONS_PER_LEAF_PER_MINUTE` | 2 |
| `MAX_COMMIT_SUBMISSIONS_PER_CONVERSATION_PER_MINUTE` | 16 |
| `MAX_RATCHET_FORWARD_JUMP` | 1,024 generations |
| `MAX_SKIPPED_KEYS_PER_SENDER` | 1,024 |
| `MAX_SKIPPED_KEY_BYTES_PER_CONVERSATION` | 67,108,864 bytes |
| `SKIPPED_KEY_RETENTION` | 5 minutes |
| `MAX_RETAINED_PAST_EPOCHS` | 2 |
| `PAST_EPOCH_RECEIVE_RETENTION` | 5 minutes; zero for removed leaves |
| `MAX_APPLICATION_SEQUENCE_FORWARD_JUMP` | 4,096 |
| `MAX_APPLICATION_SEQUENCE_GAPS` | 1,024 |
| `MAX_RECENT_MESSAGE_IDS_PER_LEAF` | 8,192 |
| `MAX_REPLAY_GAP_STATE_BYTES_PER_CONVERSATION` | 16,777,216 bytes |
| `MAX_PROPOSALS_PER_COMMIT` | 512 |
| `MAX_GROUP_LEAVES` | 512 |
| `MAX_ACTIVE_DEVICES_PER_ACCOUNT` | 64 |
| `MAX_KEY_PACKAGE_LIFETIME` | 7 days |
| `MAX_CAPABILITY_LIFETIME` | 7 days |
| `MIN_KEY_PACKAGE_CLAIM_VALIDITY` | 1 hour |
| `MAX_ROSTER_AGE_AT_ADD` | 24 hours |
| `MAX_ROSTER_LIFETIME` | 7 days |
| `ROSTER_STALE_SEND_GRACE` | 24 hours |
| `MAX_MAILBOX_BYTES_PER_ACCOUNT` | 67,108,864 bytes |
| `MAX_DIRECTORY_BYTES_PER_ACCOUNT` | 8,388,608 bytes |
| `MAX_STORED_BYTES_PER_CONVERSATION` | 268,435,456 bytes |
| `WELCOME_RETENTION` | 7 days |
| `SEQUENCER_RECORD_RETENTION` | 30 days |
| `SECURITY_PROOF_RETENTION` | live semantic lineage plus `WELCOME_RETENTION` after final close |
| `MAX_SEQUENCER_KEY_OVERLAP` | 7 days |
| `MAX_LEAF_MEMBERSHIP_OBJECT` | 8,192 bytes |
| `MAX_RECOVERY_SUBMISSION_OBJECT` | 4,096 bytes |
| `MAX_OPEN_RECOVERY_SUBMISSIONS` | 8 per conversation |
| `MAX_RECOVERY_CHAIN_BYTES` | 268,435,456 bytes |
| `MAX_RECOVERY_SUBMISSION_SECONDS` | 600 seconds |
| `MAX_WITNESS_RESOLUTION_RECORDS` | 1,024 |
| `MAX_WITNESS_RESOLUTION_BYTES` | 268,435,456 bytes |
| `MAX_WITNESS_RESOLUTION_SECONDS` | 300 seconds |
| `REINIT_RESUMPTION_PSK_RETENTION` | 24 hours |
| `MAX_SIGNATURE_VERIFICATIONS_PER_ACCOUNT_PER_MINUTE` | 1,024 |
| `DEFAULT_ACTIVE_UPDATE_PERIOD` | 24 hours |
| `DEFAULT_ACTIVE_UPDATE_MESSAGES` | 10,000 |
| `DEFAULT_IDLE_DEVICE_EVICTION` | 30 days |

Every `MAX_*` value is a hard profile ceiling; a signed reservation or local
policy may lower it but cannot raise it. In particular, a decoded Commit has
at most `MAX_PROPOSALS_PER_COMMIT` inline proposals, a roster has at most
`MAX_ACTIVE_DEVICES_PER_ACCOUNT` active entries, and a group has at most
`MAX_GROUP_LEAVES` non-blank leaves. Candidate sequence 0 through
`MAX_CANDIDATE_ATTEMPTS_PER_EPOCH - 1` are the only permitted attempts for one
epoch. Exhaustion blocks that group for explicit security recovery or fresh
generation-zero recreation; it never wraps or opens an unsequenced bypass.

For an E2EE edge-event quota, one row charges the complete encoded
`ArcFederationEvent` plus the declared complete payload-object length when
present, even when immutable payload storage is physically shared by several
outbox references. The process-global disk counter charges the actual sealed
object once and each sealed outbox/reference row once; the conservative
per-edge charge is a separate admission limit, not permission to double-count
free space. ACK moves a row from the unacknowledged to acknowledged replay
class atomically. Trimming an ACKed row never trims an object or proof whose
independent retention has not expired. ESTATE counts the sum of complete
encoded `ArcFederationRouteState` wire objects, and both snapshot maxima are
verified before staging disk extents or allocating page state.

Live objects use at most `MAX_LIVE_FRAGMENT_COUNT` fragments and mailbox/control
objects at most `MAX_MAILBOX_FRAGMENT_COUNT`, always with the exact ceiling
implied by `ceil(total / MAX_FRAGMENT_RAW)`. Exceeding
`MAX_RECIPIENT_E2EE_SENDQ` disconnects or blocks the slow recipient without
truncating an accepted object or weakening other recipients' delivery.
Signature-verification and ingress-rate limits are charged before expensive
cryptography and fail closed when their authenticated bucket is exhausted.

`MAX_GROUP_LEAVES` is a structural ceiling, not a promise that every
maximum-sized credential set fits. Before accepting an Add, clients must prove
that the resulting membership can still form a full ReInit successor whose
initial Commit is at most `MAX_REINIT_INITIAL_COMMIT_BYTES`, whose attempt,
with the target it carries, and terminal records fit `MAX_REINIT_OBJECT`, and
whose per-recipient full-tree Welcome fits `MAX_WELCOME_MAILBOX_OBJECT`. The
calculation uses exact current credential and policy proofs plus fresh
size-bounded KeyPackages from every continuing device. If recovery headroom
is unavailable, the Add is invalid; members reduce membership or proof sizes
without discarding ancestry before the group becomes cryptographically
unmigratable.

Every `MAX_*_OBJECT` above applies to the complete encoded `ArcWireObject`,
including its six-byte envelope. Fragment `total` and capability/reservation
limits use that same measure. `MAX_CREDENTIAL_BUNDLE`, `MAX_POLICY_BYTES`,
`MAX_BINDING_CHAIN_BYTES`, `MAX_ARC_MLS_CONTEXT_EXTENSION`,
`MAX_POLICY_CHAIN_BYTES`, and `MAX_EMBEDDED_MLS_WELCOME_BYTES` instead bound
the canonical encoded embedded value named by the constant, without an IRC
wire envelope. `MAX_JOIN_TRANSITION_PROOF_BUNDLE_BYTES` includes the bundle's
three-byte TLS vector length; its `references` payload is therefore at most
262,144 bytes. The embedded Welcome and proof bundle maxima are independent
field ceilings, not additive permission: every complete typed Welcome wrapper
still fits `MAX_WELCOME_MAILBOX_OBJECT`. `ArcWireObject.body` is capped at
4,194,298 bytes even before the smaller per-kind limit is applied.

Large Welcome, ReInit staging, finalization-proof, and policy-chain objects use
only authenticated, separately quota-controlled control/mailbox paths. They are
spooled with the per-account and per-conversation hard quotas rather than held
as live per-connection memory. Live channel,
direct, Commit, and application objects never inherit the 4 MiB
mailbox allowance.

In the composed daemon, the account/route/peer/global reassembly-byte maxima
are decoded admission ceilings across memory plus authenticated spool, not
permission to reserve each maximum in heap. A connection may hold at most
`MAX_LIVE_REASSEMBLY_BYTES_PER_CONNECTION` of companion live assembly, and all
base fragments, live companion fragments, decoder scratch, and complete
in-memory objects awaiting dispatch share the architecture's 16-MiB per-link
ingress budget. Larger allowed control/mailbox objects stream to charged spool
extents after transport authentication and validation of their bounded
descriptor; semantic processing still waits for complete object-ID/type
validation. Every heap backing
allocation owns a process-global `MemoryPermit`; moving a completed buffer to
the reader queue transfers that permit rather than cloning the bytes.

Each server also **MUST** configure an explicit global E2EE disk ceiling and
per-federation-peer byte rate; there is no safe universal value. These values
are dynamic operational controls reported in administrative metrics, not
invented fields in the signed reservation. Client-visible lower object and
part limits are the exact reservation fields in Section 11.5. At the hard
ceiling, new storage is refused fairly rather than evicting unexpired objects
from a selected account. Candidate quotas are charged to the authenticated
Account ID and attached Device ID; the server does not pretend to know
the encrypted sender leaf. Version 1 uses the same candidate-rate buckets for
policy-authorized recovery operations; there is no hidden recovery bucket,
candidate slot, or bypass of object, memory, or global disk ceilings.

The composed daemon profile fulfills that requirement with the mandatory
`e2ee.global_disk_bytes`, `e2ee.federation_peer_bytes_per_second`, and
`e2ee.federation_peer_burst_bytes` fields in architecture Appendix C.7. Its
checked logical-disk accounting includes sealed records and authenticated spool
extents, and its peer buckets charge each direction before expensive or
storage work. Those deployment defaults are not new wire maxima and do not
relax any nested ceiling in this section.

The CAP and ECAP version, profile-hash, field order, and maxima are fixed.
Servers advertise any lower deployment limits only in the signed group
reservation, which contains every lowerable object and part limit. Clients
apply the lower of their safe local limit and that reservation. A version-1 policy requires
`1 <= max_group_leaves <= MAX_GROUP_LEAVES` and
`1 <= max_devices_per_account <= MAX_ACTIVE_DEVICES_PER_ACCOUNT`.
Implementations do not exceed hard profile maxima through configuration; doing
so requires a new negotiated profile.

Before decoding vectors or allocating payload-sized buffers, parsers validate
the declared limit, fragment count, and remaining connection/account quota.
Expensive operations occur only after ARC account authentication and cheap
syntax checks. Servers rate-limit group reservations, KeyPackage claims,
identity publication, Commits, ACKs, Welcomes, signature-verification work,
and failed reassemblies separately by connection, Account ID, attached device,
conversation, and federation peer. Expiry of an ordinary unreferenced receipt
can force a stale client to rejoin. A referenced security proof instead obeys
`SECURITY_PROOF_RETENTION`; no expiry licenses an unverifiable chain jump.

Traditional line-count flood penalties **MUST NOT** make an already admitted
maximum-size object impossible to complete before its wall-clock deadline.
After cheap fragment-zero checks and atomic quota reservation, E2EE ingress is
charged by decoded bytes through a dedicated authenticated token bucket that
provides at least `MIN_ADMITTED_E2EE_INGRESS_RATE`; idle and absolute deadlines
still apply. Admission may be refused before reservation. Fanout is charged by
decoded bytes times recipient count, uses fair per-route scheduling, and drops
or disconnects a slow recipient before its bounded E2EE send queue can consume
global memory. A byte-identical retry found in the idempotency cache returns
the prior outcome without repeated fanout, KeyPackage consumption, or
sequencing.

## 17. Downgrade and reset behavior

An encrypted channel or direct conversation is pinned locally by network ID,
conversation and group IDs, current binding ID and chain, profile version,
suite, ordered allowed-suite policy, route binding, required MLS capabilities,
policy generation/ID, highest root, roster, and capability generations/IDs,
sequencer credential generation/key ID, finality principals/fault bound,
pending-join and lifecycle state, root binding-lock IDs, the verified
transition-proof mapping, accepted semantic state ID, and sequencer record-head
ID.

Clients **MUST NOT** send plaintext automatically when:

- the IRC capability is missing;
- decryption or group-state loading fails;
- a group binding disappears or changes;
- the server reports that encryption is unavailable;
- some recipient lacks support; or
- a suite, profile, policy, or required extension changes.

These conditions enter a blocked security state. A user may explicitly start a
new unencrypted conversation, but the client must present it as a distinct
security context and must not silently reuse the encrypted transcript UI.

Reinitialization, group replacement, account-root replacement, and sequencer
key replacement are conspicuous security events. They follow their complete
old-state-authorized procedures. An operation lacking that authorization is a
fresh security context requiring explicit re-verification, never a repair of
the pinned conversation.

## 18. Bots, bouncers, bridges, moderation, and abuse

Any bot, bouncer, logger, bridge, moderation agent, search indexer, or preview
service that reads plaintext is an MLS leaf and appears in the device roster.
Removing it advances the epoch. A ciphertext-only bouncer may store and relay
without group membership.

A gateway from ARC-MLS to plaintext IRC terminates E2EE. Clients must display
that gateway as a decrypting member and security boundary.

The server can enforce metadata-level policy: authentication, channel access,
bans, flood limits, object limits, and routing. It cannot inspect encrypted
content. Content abuse reporting requires an explicit client-side disclosure
flow and is outside version 1. MLS makes no general deniability claim, and a
recipient can always copy plaintext.

Attachments are outside version 1. A future attachment profile must use a
fresh client-generated file key, independently authenticated bounded chunks,
an encrypted manifest, server-side ciphertext quotas, and an MLS-encrypted
capability. Plaintext filenames, MIME types, thumbnails, and file hashes must
not leak through the server API.

## 19. Failure handling

The following failures never trigger plaintext fallback:

- invalid identity chain;
- root change or missing verification required by policy;
- malformed MLS object;
- unsupported required extension or suite;
- invalid Add, Remove, policy, or GroupContext transition;
- stale or conflicting Commit;
- receipt-chain mismatch;
- replay or counter rollback;
- route/context mismatch;
- resource ceiling violation; or
- lost, rolled-back, or irreconcilably forked local state.

For recoverable delivery gaps, clients request missing complete objects by
object ID or route sequence within retention. They do not request raw ratchet
keys. For an irreconcilable group, clients stop sending and perform an explicit
finality-council quorum abort followed by MLS `ReInit`, or a fresh-group reset
authorized and finalized under the old state when possible. They do not layer
a reset on top of an unresolved active candidate.

Failures shown to users distinguish:

- delivery unavailable;
- security verification required;
- member/device changed;
- message delayed outside the key window;
- group fork or receipt inconsistency; and
- local cryptographic state lost.

## 20. Implementation separation

The ARCD implementation should keep these surfaces separate:

- bounded IRC line and tag parsing;
- fragment validation and reassembly;
- directory and opaque mailbox storage;
- route authorization and fanout;
- Commit sequencing and receipt signing;
- published-policy retention and finality-vote verification;
- sequencer record-chain witnessing at the edge;
- recovery-submission admission and edge witness resolution; and
- bounded MLS outer-header inspection, without MLS secret state.

The client or client SDK owns:

- identity and trust storage;
- MLS state and cryptographic operations;
- application envelope parsing;
- replay windows and transactional counters;
- policy validation; and
- security UI.

No ARC-MLS server code path should accept decrypted application content or an
MLS epoch secret; ordinary unbound IRC remains a separate plaintext feature.
No production API or carrier in this document, including the recovery
submission, witness resolution, and leaf-membership proof of Sections 12.5.1
and 13.7, carries application plaintext, an MLS epoch secret, a private key,
or a decrypted GroupContext. A leaf-membership proof carries only a public
leaf signature key and digests, and `finalization_authenticator` remains the
only exported MLS value a server ever sees.
Logs, metrics, traces, panic reports, and error descriptions must not record
fragment tags, identity documents, KeyPackages, Welcome objects, ciphertexts,
or decrypted content by default.

## 21. Verification and release gates

Before production use, an implementation requires:

1. The MLS WG interoperability vector corpus and harness pinned by repository
   revision and content hash for every enabled suite. RFC 9420 itself does not
   contain an official test-vector section.
2. Independent vectors for roots, enrollment possession, device certificates,
   rosters, capability chains, leaf authorizations, policies, root binding
   locks, bindings, committed roster heads, contexts,
   application envelopes, object fragments, sequencer credentials, candidate
   receipts, ACKs, finalizations, aborts, ReInit targets reconstructed from
   their Proposals and the targets attempts carry, the ReInit binding-chain
   and policy-chain entries a later joiner verifies against the activated
   target, and ReInit activation.
3. Cross-implementation tests in which at least two independent MLS
   libraries each, through the daemon's client surface and not only a framing
   comparison, publish KeyPackages, bind a conversation, publish its policies,
   submit a Commit candidate, acknowledge it, vote and receive a finalization
   under the published quorum, send Section 7.5 padded application messages,
   add a member of the other library through a delivered Welcome, and close;
   every outcome is recorded per rule.
4. Characterization tests proving plaintext IRC behavior is rejected for a
   bound encrypted target.
5. Boundary tests at every named resource limit and one unit over it. The
   application-padding suite includes every Section-7.5 vector over
   `ArcEncryptedContent`, checked-arithmetic overflow, exact outer-object limit
   fit/overflow, nonzero padding, one byte too little/much padding, and the
   zero-padding boundary case.
6. Parser fuzzing for IRC tags, decimal fields, base64url, reassembly, TLS
   vectors, identity chains, and MLS outer messages.
7. Stateful property tests for duplicate, lost, reordered, conflicting, stale,
   and malicious fragments and Commits, including recipient-dependent corrupt
   UpdatePaths from RFC 9420 Section 16.12. Tests prove no endpoint applies
   before finality and no failed endpoint skips to a competing candidate.
8. Crash, restart, snapshot-restore, and outbox-retry tests at every durable
   boundary, proving no sender generation, application counter, binding lock,
   ACK lock, or disposition-vote lock can roll back and every retry is
   byte-identical.
9. Exhaustive quorum tests for every permitted `(n,f)`, proving
   `2q-n > f`, plus netsplit and malicious-sequencer tests proving two
   conflicting membership changes cannot both certify while at most `f`
   finality principals are Byzantine. The sequencer refuses to certify a
   finalization, abort, or ReInit terminal below `q` for every permitted
   `(n,f)` and certifies at exactly `q`. Fault-bound violations are tested and
   reported as outside the claim rather than silently passing.
10. Tests for root and sequencer rotation, roster rollback/equivocation,
    device addition/removal, KeyPackage cross-group replay, rejection of
    reusable last-resort packages,
    mandatory serialized join confirmation, pending removal, committed roster
    and pending-join state, full-tree Welcome and join-proof checks,
    inline-only proposals, disabled Update Proposals, controller-bound
    candidate authorization, policy wholesale replacement, removal-target
    processing, the idle-device reminder without timer-driven removal,
    suite-independent profile digests, published-policy chain validation,
    quorum refusal without a retained policy, edge witness refusal of a
    non-extending candidate or terminal event, and server equivocation.
11. Load tests for maximum group size, fanout, Commit storms, slow consumers,
    offline queues, and authenticated fragment floods.
12. A review that server logs and telemetry contain no forbidden material.
13. ReInit race tests covering target-suite KeyPackage preflight, creator-local
    ACK, all Welcome ACKs, attempt abort/retry, PSK deletion, one target that
    stays byte-identical across an accepted-state advance, a candidate abort,
    and an attempt retry, the sequencer's refusal of an attempt whose
    finalization ID, digest, or carried target differs, a successor that takes
    traffic after activation and after a coordinator restart with no
    `EGROUP BIND`, a crash on either side of the activation transaction, and
    the invariant that the old group never reopens.
14. Federation tests for ECAP's exact profile-document hash, 360/358-byte
    maximum lines, five-second boundary, simultaneous OFFERs, each legal flag
    transition, duplicate and ACK-before-OFFER rejection, every mismatched
    tuple field, reconnect-only key-set succession/rollback/gap/exhaustion,
    non-looping state machine, origin attachment, ESTATE snapshot/ACTIVE
    recovery at 0/1/31/32/33/maximum entries, canonical page partition,
    concrete/nonfinal and star/final cursor presence, every repeated cut field
    and exact arity, route changed/hidden events, ERESUME, mailbox ownership,
    idempotent retry, and deterministic channel-instance collision handling.
15. A mechanically checked wire-budget table for every command, tag
    combination, maximum decimal width, base64url expansion, and IRCv3 escape
    case in both client and server directions, separately enforcing 4094-byte
    client-added, 4094-byte server-added, and 8191-byte combined budgets.
16. Semantic-ID malleability tests proving that alternative valid signature,
    approval, and vote subsets retain one state ID, while any changed semantic
    TBS field changes it. ACK signatures over the identical mandated ACK-TBS
    vector retain one ID; a different ACK-TBS vector changes the terminal ID
    and is rejected unless it is the exact deterministic coverage vector.
    Tests also reject an authorization embedded in its own Commit, a GroupInfo
    or Welcome that embeds any future receipt/finalization/activation ID, an
    in-MLS binding or policy-chain entry containing post-Commit proof IDs, a
    ReInit target that names the finalization committing it, a successor
    initial Commit that names the activation committing it, or any other
    content-address cycle. Wrapper construction tests prove that
    immutable MLS Welcome bytes exist first and are only then paired with the
    exact typed external proof references.
17. Finality-council transition tests proving only retained, fully staged old
    principals can finalize a removal, removed or revoked principals cannot,
    and a council is rotated in an earlier epoch when a proposed removal would
    leave fewer than the old quorum.
18. Federation tests covering every opcode/result/event selector arm, every
    required and forbidden response descriptor, singleton snapshot-token
    presence, response index/kind/object/size/delivery mismatch, ReInit staged
    and ACK live/fetch/offline delivery, terminal close broadcast, origin
    incarnation loss, replay-key collisions and gaps, snapshot quarantine,
    event ACK barriers, first login with arbitrarily many historical direct
    routes but no bulk route projection, and encrypted/plaintext route
    collisions.
19. Crash-idempotency tests for KeyPackage claim operation IDs, package burns,
    mailbox delivery-token ACK transactions, cursor replay, and response
    recovery after disconnect.
20. Root-identity and binding-chain tests covering missing prefixes, alternate
    proof subsets for one semantic binding, root rollback, semantic-route lock
    reuse, close/recreate incarnation continuity, and direct-account-pair
    downgrade blocking.
21. Cross-profile barrier tests covering every permitted base/E2EE part
    interleaving, result-first and completion-first delivery, lost final FACK
    and EACK, complete replay, a crash before and after each staging/apply/
    fanout-visibility boundary, wrong ID/count/index/profile partition/state
    generation, a second open barrier, later-event injection,
    2,047/2,048/2,049 parts,
    aggregate bytes one below/equal/above the ceiling, either outbox full, and
    attempted same-incarnation snapshot replacement. The oracle requires one
    combined state cut, both cumulative ACKs or neither, no duplicated frame,
    and eventual exact result rendering only to its original live sink.

No release may claim “secure,” “forward secret,” “post-compromise secure,”
“post-quantum,” or “production ready” without evidence for that exact build,
configuration, dependency set, and operational profile.

## 22. Versioning and standardization path

Profile version 1 depends only on finalized RFC 9420 behavior for the
cryptographic core. Work-in-progress MLS extensions, PQ suites, targeted
messages, key transparency, archive keys, attachments, and external joins are
not silently incorporated.

A future incompatible wire or application change uses a new vendor capability
version and new context profile version. Every changed document byte also
changes the Section-2.3 profile hash, even when the numeric major remains 1;
CAP and ECAP accept only an explicitly supported `(version, profile-hash)`
pair. A bridge supporting two revisions implements and tests two complete
profiles and never parses one revision under the other's rules. A
cryptographic suite or MLS protocol upgrade uses `ReInit`. Unknown required
capabilities cause fail-closed rejection. The revision that added the
public-evidence carriers of Section 12.5.1 and Sections 13.7.2 through 13.7.5
is such a hash change under an unchanged numeric version: peers presenting
the previous profile hash are refused by exact-match negotiation, and no
implementation parses that revision's objects under this one. The
ReInit-target revision of Section 13.8 is also a hash change under an
unchanged numeric version, although it changes the layout of two structures,
the target whose digest signed authorizations commit and the attempt that now
carries it, which the first rule of this section would otherwise give a new
version: under the previous hash no target could be constructed, so no
conforming ReInit exists to keep interoperable, and exact-match negotiation
already refuses every peer that presents that hash.

Before interoperability outside this implementation family:

- submit the capability, tag, commands, batch types, and reply codes to the
  IRCv3 process;
- replace the private MLS extension value with an assigned value if available;
- publish complete encodings and test vectors.

## 23. Normative references

- [RFC 2119, Key words for use in RFCs](https://www.rfc-editor.org/rfc/rfc2119.html)
- [RFC 2812, Internet Relay Chat: Client Protocol](../rfcs/rfc2812-irc-client-protocol.txt)
- [RFC 2813, Internet Relay Chat: Server Protocol](../rfcs/rfc2813-irc-server-protocol.txt)
- [RFC 4648, Base-N Encodings](https://www.rfc-editor.org/rfc/rfc4648.html)
- [RFC 8032, Edwards-Curve Digital Signature Algorithm](https://www.rfc-editor.org/rfc/rfc8032.html)
- [RFC 8174, Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words](https://www.rfc-editor.org/rfc/rfc8174.html)
- [RFC 9846, TLS 1.3](https://www.rfc-editor.org/rfc/rfc9846.html)
- [RFC 9180, Hybrid Public Key Encryption](../rfcs/rfc9180-hpke.txt)
- [RFC 9325, Recommendations for Secure Use of TLS and DTLS](../rfcs/rfc9325-secure-tls-recommendations.txt)
- [RFC 9852, New Protocols Using TLS Must Require TLS 1.3](https://www.rfc-editor.org/rfc/rfc9852.html)
- [RFC 9420, The Messaging Layer Security Protocol](../rfcs/rfc9420-mls-protocol.txt)
- [RFC 9525, Service Identity in TLS](../rfcs/rfc9525-tls-service-identity.txt)
- [RFC 9750, The Messaging Layer Security Architecture](../rfcs/rfc9750-mls-architecture.txt)
- [IRCv3 Capability Negotiation](https://ircv3.net/specs/extensions/capability-negotiation.html)
- [IRCv3 Message Tags](https://ircv3.net/specs/extensions/message-tags.html)
- [IRCv3 Batch](https://ircv3.net/specs/extensions/batch)
- [IRCv3 Echo Message](https://ircv3.net/specs/extensions/echo-message)
- [IRCv3 Labeled Response](https://ircv3.net/specs/extensions/labeled-response)
- [IRCv3 Standard Replies](https://ircv3.net/specs/extensions/standard-replies)
- [IRCv3 Account Tag](https://ircv3.net/specs/extensions/account-tag)

## 24. Informative references

- [RFC 1459, Internet Relay Chat Protocol](../rfcs/rfc1459-irc-protocol.txt)
- [RFC 2810, Internet Relay Chat Architecture](../rfcs/rfc2810-irc-architecture.txt)
- [RFC 2811, Internet Relay Chat Channel Management](../rfcs/rfc2811-irc-channel-management.txt)
- [RFC 7194, IRC over TLS](../rfcs/rfc7194-irc-over-tls.txt)
- [IETF MLS active documents](https://datatracker.ietf.org/wg/mls/documents/)
- [MLS WG implementation and test-vector workspace](https://github.com/mlswg/mls-implementations)
- [ML-KEM and Hybrid Cipher Suites for MLS, work in progress](https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites/)
- [Key Transparency Architecture, work in progress](https://datatracker.ietf.org/doc/draft-ietf-keytrans-architecture/)
- [Project protocol source and decision ledger](protocol-sources-and-decisions.md)

## Appendix A. Fast path summary

For an ordinary encrypted channel message:

1. The client creates `ArcEncryptedContent` with a durable sequence and random
   message ID.
2. It derives one padded MLS PrivateMessage and the next sender state without
   exposing either to the network.
3. It transactionally persists that next state and the exact ciphertext in its
   durable outbox, then syncs the transaction.
4. It computes the SHA-256 object ID and transmits the stored bytes; retries
   reuse them unchanged.
5. Usually one or a small number of 2940-byte fragments are sent as tagged
   `TAGMSG` lines.
6. The ARCD performs bounded reassembly and one opaque fanout.
7. Each recipient validates, decrypts, replay-checks, and renders locally.

There is no per-recipient application encryption, no server decryption, no
shared static channel password, and no plaintext content processing in the
ARCD.

## Appendix B. Security claim template

An implementation may accurately state:

> ARC-MLS uses standardized MLS 1.0 to provide authenticated end-to-end
> encryption for messages among the devices shown in the encrypted roster.
> It provides forward secrecy when old secrets are deleted and
> post-compromise recovery after attacker access ends, controlled leaves are
> removed, and an honest fresh-path Commit is finalized. Conflicting group
> histories cannot both finalize while the configured endpoint finality fault
> bound and durable sign-once state hold. AgenC Relay servers still observe routing
> metadata and can deny service. In version 1, identity is resistant to server
> substitution only after users verify account keys out of band; experimental
> transparency supplies observation and evidence, not Verified status. The
> production profile is not post-quantum secure.

It must not shorten that statement to “military-grade encryption,” “anonymous
IRC,” “server-proof identity,” or “post-quantum secure.”
