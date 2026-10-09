# A client's attachment and its share of an edge stay its own (D-44)

This record covers part 2 of decision D-44 of the SDK server program
(2026-10-07, outside master #35), which follows [the link faults
record](stage-10-link-faults.md) and [the link resume
record](stage-10-link-resume.md): a client's ordinary actions, and its share
of an edge's companion resources, affect only that client, never its
federation link and never other clients. The first commit has the base and
companion declarations of a generation name one principal, ends a device
attachment with the principal it was made under, and retires a deleted
origin only at the generation its deletion named. The second has the
coordinator mirror an attachment another attachment of its device superseded
as it stands, count only a device's current attachment as attached, refuse
any other disagreement of a well-formed declaration for its origin alone,
close an origin for a mismatched companion deletion, drop requests under
fenced or refused origins, and acknowledge a base deletion of a fenced
origin. The third gives each connection its own share of the edge's
client-ingress recent-object cache, keeps each connection's and each
account's replies within their own quotas, charged to the process memory
budget, bounds outstanding requests per connection, per account and for the
edge, counting a closed connection's unanswered requests until the
coordinator answers or drops them, and releases a submission's recent tuple
once it is answered or refused. The fourth answers a fresh companion request
the coordinator cannot run or stage for a local reason with its failed
result, `E2EE_SYNCING` for a target's route state, refuses at the edge's
ingress a payload that is no wire object of its command's kind, and bounds
requests waiting for their payloads per peer. The fifth keeps a commit
landing during a companion storage read from failing the link: a read stays
current across other routers' commits, its completion waits while a batch is
open, a read across one of the coordinator's own commits is planned again,
and a snapshot page read counts as companion work, one companion read at a
time. The sixth holds a snapshot page, ACTIVE or a witness resolution of the
E2EE edge's that finds a batch open until none is, refuses one that finds an
event queued, closes the link for a refused batch of the E2EE edge's, keeps
the base edge's snapshot install and a complete barrier waiting for a free
slot, and records the audit of the edge's other paths and a limitation. The
seventh scores the record's regions and closes what that found. The eighth
adds daemon tests of a session's own actions after a device attach, of two
sessions of one account at their reply quotas, and of a payload that is no
wire object, and lists what stays open. No specification, profile hash,
registry entry, named limit, reply code, wire object, table, key, row kind,
field or storage generation changed.

## A generation's declarations name one principal, and an attachment ends with its principal (first commit)

The text these rules implement:

- Companion Section 11.6: "Reconnect, logout, account switch, or TLS
  termination invalidates the attachment", and "Submission and delivery stop
  atomically on detach, logout, account switch, CAP loss, or TLS
  termination."
- Companion Section 12.5: the companion origin's "Network, home server,
  incarnation, Origin ID, Connection ID, and connection nonce equal the base
  object byte-for-byte"; "Registration, login, logout, account switch,
  session replacement, and device attach/detach advance the one shared base
  origin generation before either profile accepts a request under it"; and
  "An attached device requires an authenticated account".
- Architecture Section 20.7: "`UPDATE` increments by one and names the exact
  previous object", and DEL "retains the stated next sequence for replay
  checking".

The rules, in `crates/agenc-relay-runtime/src/federation/edge/mod.rs` and
`crates/agenc-relay-runtime/src/e2ee/edge/origins.rs`:

- **The companion declaration mirrors the held principal.** The base facts a
  companion declaration is built from (`EdgeFederation::origin_facts`) name
  the session and account of the held generation's acknowledged declaration
  (`ConnectionOrigin::held_principal`), not the connection's next principal,
  which moves as soon as it is known and before its update is queued. The
  base and companion declarations of a generation therefore name one
  session and account, as the base journal row and the base declaration of
  the held generation already do ([the origin journal
  record](stage-10-origin-journal.md), third commit).
- **An attachment ends with its principal.** A device attachment records the
  user and account it was made under (`LocalOrigin::device_principal`, set
  by `device_attached`). A declaration whose base principal names another
  user or account, that is a logout, an account switch or a replaced
  session, carries no device (`attachment`), and the connection holds none
  from then on, so its device-requiring lines are refused locally with
  `E2EE_DEVICE_REQUIRED`; its in-progress submission under the attachment is
  discarded, and the retry it answered from its replies ends
  (`attachment_ended`). A later declaration naming the first
  principal again does not bring the attachment back: the device attaches
  again. A reauthentication to the same account keeps the attachment.
- **A deletion is retired at the generation it named.** The edge retires a
  closed origin only at an acknowledgement naming the generation its
  deletion named (`ConnectionOrigin::deletion_acknowledged_at`, through
  `deletion_point`), which the coordinator's acknowledgement repeats;
  another generation, or an acknowledgement for an origin the edge did not
  delete, is a violation.

| Test | What it pins |
| --- | --- |
| `federation::edge::tests::origin_deletion::held_declaration::the_companion_facts_of_the_held_generation_name_its_acknowledged_principal` | Generation zero is acknowledged and the connection's session and account become known while its update is not queued: the companion facts of generation zero name no session or account. Once the update is carried and acknowledged, generation one's facts name both. |
| `federation::edge::tests::origin_deletion::a_deletion_acknowledgement_names_the_generation_the_deletion_named` | With the update not carried, the deletion names generation zero; with it carried, generation one. In both, an acknowledgement before the deletion and one naming the other generation are violations and retire nothing, and the one naming the deletion's generation retires the origin. |
| `e2ee::edge::origins::tests::a_principal_change_ends_the_attachment_its_declarations_carried` | A device attached under an account and session; the next declaration after a logout, an account switch or a replaced session names no device, the connection holds none, its in-progress submission is discarded and its retry ends, and a later declaration naming the first principal names no device either. After a reauthentication to the same account the declaration still names the device, and the submission and the retry stay. |

With the federation edge's `mod.rs` set back to the start commit, the first
two tests fail. Single edits fail tests as well: building the facts from the
connection's current session and account fails the first; retiring a
deletion at either the held generation or the pending update's fails the
second; carrying the device whatever the principal, keeping the in-progress
submission or the retry, or recording no principal at the attachment each
fails the third.

The release coverage policy gains `edge-origin-deletion-acknowledgement`
(branches), `edge-companion-origin-facts`,
`edge-companion-attachment-principal` and `edge-companion-attachment-ended`
(regions); the other regions of the changed files move with unchanged spans.
Both source inventories are refreshed.

## The coordinator answers every remaining mismatch for its origin alone (second commit)

The text these rules implement:

- Companion Section 11.6: "`session_generation` is a durable nonzero uint64
  counter scoped to the Account ID and Device ID", "every successful
  attachment increments it exactly once", and "Reconnect, logout, account
  switch, or TLS termination invalidates the attachment"; Section 11.9:
  `E2EE_DEVICE_REQUIRED` is "Connection lacks a current roster-active device
  attachment".
- Companion Section 12.5: "Session/User IDs are both empty or both 16
  bytes. Account ID is empty exactly for an unauthenticated/guest origin and
  then account-session generation is zero; otherwise it is exactly 24 bytes
  and the generation is nonzero. An attached device requires an
  authenticated account, has a 16-byte Device ID and nonzero device-session
  generation; absence requires both fields empty/zero"; "`DEL` supplies the
  next unused sequence and permanently fences later requests"; "Exact
  duplicates return the stored result".
- Architecture Section 20.7: "DEL is durable, permanently rejects later
  requests, and retains the stated next sequence for replay checking."

### Decision: one outcome for a superseded attachment

A declaration naming an attachment another attachment of its device
superseded is mirrored as it stands, whether the coordinator meets it on a
live link or replayed on a later one, and that attachment holds no device
authority:

- On a live link the coordinator already kept an accepted attachment
  mirrored after the device attached elsewhere. A declaration replayed after
  a coordinator restart, which lost the companion origins it held in
  memory, now gets the same outcome instead of a refusal of its origin
  ([the link faults record](stage-10-link-faults.md), fourth commit).
- Only a device's current attachment counts as attached
  (`CompanionState::current_attachment`: the directory holds the
  attachment's session generation for the origin's account, and the device
  is roster-active). A device-requiring operation needs it
  (`ops::Exec::attached_device`), so under a superseded attachment every
  such operation fails with `E2EE_DEVICE_REQUIRED`, the code Section 11.9
  gives a connection that "lacks a current roster-active device
  attachment", on a live link and after a replay alike. Operations that
  need no device are still served, and `EKEY WHOAMI` reports the session
  generation zero, which Section 11.6 gives no attached device. Delivery
  follows the same rule: an edge whose only origin of an account holds a
  superseded attachment is not targeted with that account's direct events
  and holds no direct standing for it (`execute::attached_origin_edges`,
  `direct_release::attached_at`), as Section 12.5 targets only an edge
  hosting an origin "whose Device ID is attached and roster-active", and a
  mailbox cut of such an origin is released at the next publication
  (`mailbox_snapshot::Store::publish`). The device attaches again on the
  connection to regain its authority.
- A refusal of the origin would instead leave the connection answered
  `E2EE_SYNCING` until it ends, since no wire signal tells the edge of the
  refusal, and closing the base session would end a connection whose
  principal is valid. A wire change is outside this topic.

### The rules

In `crates/agenc-relay-runtime/src/e2ee/coordinator/sync.rs`, `mod.rs`,
`ops/mod.rs`, `ops/directory.rs`, `ops/mailbox_snapshot.rs`,
`direct_release.rs`, `request.rs` and `execute.rs`, and
`crates/agenc-relay-runtime/src/federation/coordinator/companion.rs` and
`origin.rs`:

- **A malformed declaration is a violation; a disagreeing one is refused
  for its origin.** A declaration whose fields are malformed by Section
  12.5's shape rules (a session without its user, an account without a
  nonzero account session generation or the reverse, a device without a
  nonzero device session generation or the reverse) is still a violation. A
  well-formed declaration whose session or account the base origin does not
  hold at the declared generation (`mirrored_principal`), or whose device
  is named without an account or at a session generation the directory
  never reached for the declared account (`mirrored_device`), is refused for
  its origin alone, as a superseded attachment was: nothing is
  acknowledged, the origin is fenced where it stands, every later
  declaration of it is refused alike, and its deletion is acknowledged
  (`refuse_declaration`, `MirrorFault::Disagrees`). Such a declaration comes
  from an edge that kept an attachment across a logout or an account switch.
- **A mismatched companion deletion closes its origin alone.** A deletion
  naming another generation than the one the coordinator holds, or a
  sequence below the one executed there, fences the origin at the
  generation and next sequence the coordinator holds, releases its mailbox
  cuts and is acknowledged (`origin_del`); the connection behind it ended.
  A deletion at the held generation and a sequence at or above the executed
  one fences at the stated sequence, as before, and any deletion of an
  origin a refused declaration fenced is acknowledged without changing it.
- **A request under a fenced or refused origin is dropped.** A request
  without a replay row under an origin its deletion or a refused
  declaration fenced (`Classified::Fenced`), including one whose first
  declaration was the one refused and which so holds no state, is refused
  for good: nothing runs, nothing is answered or written, its objects leave
  the recent-object cache (`Staged::Dropped`), and the link stays up. An
  exact copy of a request that ran is still answered from its replay row. A
  request under a suspended origin, another generation or another sequence
  is still a violation.
- **A base deletion of a fenced origin is acknowledged.** The base origin
  table refuses a deletion of a fenced origin; the coordinator now
  acknowledges it for that origin alone, whatever generation and sequence
  it names, and changes nothing, since the fence already rejects every
  later request for good, and the sessions the origin owns close
  (`federation::coordinator::origin::delete`). The edge's deletion of an
  origin fenced after an expired replay is therefore acknowledged for its
  origin alone.

The audit of the origin journal topic's review is recorded here: a reset
that takes a deletion naming the generation the coordinator holds records
the larger of the stated and the executed next sequence, which is the
stated one, since an origin's journal row is durable before any of its
requests is sent; a deletion naming another generation can only take the
next-generation form, since the first pending update always follows the
held generation, and the origin journal topic's rule covers its replay. No
other mismatch between a reset's deletion and the coordinator's origin is
reachable.

| Test | What it pins |
| --- | --- |
| `e2ee::coordinator::tests::sync::superseded_attachments::a_declaration_naming_a_superseded_attachment_is_mirrored_as_it_stands` | The directory is at generation two; the declaration naming generation one is acknowledged and the origin holds that attachment. |
| `e2ee::coordinator::tests::sync::superseded_attachments::a_superseded_attachment_holds_no_device_authority` | A device-requiring fetch is served under the current attachment, and `WHOAMI` reports its generation; once the device attaches on another connection the fetch fails with `E2EE_DEVICE_REQUIRED`, and `WHOAMI` is still served and reports zero. |
| `e2ee::coordinator::tests::sync::superseded_attachments::a_superseded_attachment_is_neither_targeted_nor_standing` | Under the current attachment the edge is targeted with the account's direct events and holds the pair's direct standing; once the device attaches on another connection it is neither. |
| `e2ee::coordinator::tests::direct_release::a_standing_needs_a_live_origin_of_the_edge_with_a_current_attachment` | The edge's live origin with the current attachment of a device of the pair holds the direct standing; another edge, a fenced origin and one still suspended once the edge replayed its origins hold none. |
| `e2ee::coordinator::tests::sequence::recovery_pending::mailbox::mailbox_cursor::boundaries::query_usage::publication::mailbox_publication_drops_the_cut_of_a_superseded_attachment` | Another connection attaches the device and fetches the mailbox: at that cut's publication the superseded origin's cut is released and only the current attachment's remains. |
| `e2ee::coordinator::tests::sync::superseded_attachments::an_attachment_the_directory_never_reached_closes_only_its_origin` | A declaration naming a generation above the directory's is not acknowledged, fences the origin where it stood, and its deletion is acknowledged. |
| `e2ee::coordinator::tests::sync::superseded_attachments::a_principal_change_that_still_names_the_device_closes_only_its_origin` | After a logout, and after a switch to another account, a declaration still naming the device is refused for its origin, a later declaration is refused alike, and the deletion is acknowledged. |
| `e2ee::coordinator::tests::sync::superseded_attachments::a_refused_declaration_replayed_on_the_next_link_is_refused_again` | After the link is replaced, READY follows the RESET, the replayed declaration is refused again, and the deletion is acknowledged. |
| `e2ee::coordinator::tests::sync::origin_refusals::*` | Another session, no session where the base holds one, an account the base lacks or omits, another account or account session generation, a device without an account and a device the directory does not know are each refused for the origin, and its deletion is acknowledged; a session without its user, an account generation without an account or the reverse, and a device or generation alone are violations (`an_origin_object_whose_session_differs_from_the_base_is_refused`, `an_origin_object_claiming_an_account_the_base_lacks_is_refused`, `an_authenticated_origin_mirrors_the_base_account_and_generation_exactly`, `an_origin_object_omitting_the_base_account_is_refused`, `an_attached_device_needs_an_account_and_a_nonzero_generation`, `an_attached_device_the_directory_does_not_know_is_refused`). |
| `e2ee::coordinator::tests::sync::origin_refusals::a_delete_fences_the_accepted_generation_at_the_stated_sequence` | The deletion fences at the stated sequence, and a later deletion at a lower one is acknowledged without undercutting it. |
| `e2ee::coordinator::tests::sync::origin_refusals::a_mismatched_delete_closes_only_its_origin_where_it_stands` | Deletions naming another generation, or a sequence below the executed one, are acknowledged and fence the origin at the generation and sequence the coordinator holds. |
| `e2ee::coordinator::execute::origin_replay::a_fenced_origin_classifies_a_request_without_a_replay_row_as_fenced` | A fresh request is classified fresh, one under a suspended origin is a violation, and requests under the fenced origin at any generation or sequence are classified as fenced. |
| `federation::coordinator::tests::companion_refusals::a_request_under_a_fenced_origin_is_dropped_and_the_link_kept` | Through real storage: after the edge's deletion, a request it counted before the deletion is neither staged nor answered, twice, and the executed request's copy is answered from its replay row; the link stays up. |
| `federation::coordinator::tests::companion_refusals::a_request_under_a_refused_origin_is_dropped_and_the_link_kept` | A request under an origin whose first declaration was refused is neither staged nor answered, and the link stays up. |
| `federation::coordinator::tests::origin_refusals::a_deletion_of_a_fenced_origin_is_acknowledged_and_changes_nothing` | A base origin fenced after its declaration: deletions naming its generation, another one and a higher sequence are each acknowledged at the generation they name, nothing is staged, the origin stays fenced, the session the origin registered is queued to close, and the link stays up. |

Existing tests changed with the rules:
`e2ee::coordinator::tests::request_envelope::a_request_from_a_fenced_suspended_or_regenerated_origin_is_a_violation`
now classifies the fenced origin's request as fenced;
`e2ee::coordinator::tests::sync::origins_mirror_the_acked_base_declaration`
no longer asserts the principal, attachment and deletion mismatches, which
the refusal tests above pin;
`e2ee::coordinator::tests::sequence::recovery_pending::mailbox::mailbox_cursor::boundaries::query_usage::mailbox_query_origin_close_releases_only_after_the_exact_descriptor_passes`
now requires that another origin's deletion releases nothing, and that a
deletion naming another generation, or a sequence below the one executed,
releases the origin's cut as the exact deletion does, since a mismatched
deletion closes its origin; the recovery tests' second device attaches
through the directory, as a real attachment does, since an attachment the
directory does not hold has no device authority; and the direct release
tests' second connection holds its device's current attachment in the
directory. The link faults record's daemon test of a superseded
attachment, now
`link_faults::a_superseded_attachment_declared_to_a_restarted_coordinator_holds_no_device_authority`,
requires that edge A's session, whose attachment edge B's superseded while
the coordinator restarted, is served after its replay and that its
device-requiring `EKEY FETCH MAILBOX` gets `E2EE_DEVICE_REQUIRED`.

With the coordinator's `sync.rs` set back to the first commit, the twelve
mirror, refusal and deletion tests above fail, and so does the mailbox
query test; with `ops/mod.rs` set back,
the device authority test fails; and with the federation coordinator's
`origin.rs` set back, the fenced deletion test fails. Single edits fail tests
as well, one for each part of the rules: refusing a superseded attachment
fails the mirror test; a violation for an unreached generation fails five
tests; a violation for a device without an account fails two; a violation
for a disagreeing principal fails four; dropping the account shape check
fails one; a violation for a fenced origin's request fails three;
answering a refused origin's request as a violation fails the refused origin
test; keeping a dropped request's objects fails the fenced origin test; a
violation for a mismatched deletion fails three; fencing only a matching
deletion fails the mismatched deletion test; keeping a mismatched
deletion's mailbox cuts fails the mailbox query test; refusing a base
deletion of a fenced origin fails the fenced deletion test, and so does
closing none of its sessions; counting a mirrored device as the current
attachment fails six tests, the authority, targeting and publication tests
among them; `WHOAMI` reporting the mirrored generation fails the authority
test; targeting or a direct standing by the mirrored device fails the
targeting test; and keeping a mailbox cut by it fails the publication
test.

The release coverage policy gains `companion-mirrored-principal`,
`companion-current-attachment` (on `CompanionState::current_attachment`)
and `companion-direct-standing-current-attachment` (branches), and
`companion-fenced-request-classification` and
`companion-whoami-current-attachment` (regions). It re-reviews and
respans `companion-superseded-attachment`,
`cap90-current-base-origin-admission`, `cap78-sync-origin-del`,
`cap96-replay-response-completeness`,
`cap79-fresh-object-006-run-with-object`,
`cap79-fresh-object-010-attached-origin-edges`,
`cap78-mailbox-snapshot-store-publish` and
`coordinator-refused-declaration-deletion`; the other regions of the changed
files move with unchanged spans. Both source inventories are refreshed.

## Each connection holds its own share of the edge's companion resources (third commit)

The text these rules implement:

- Companion Section 16: "At the hard ceiling, new storage is refused
  fairly rather than evicting unexpired objects from a selected account";
  "Admission may be refused before reservation"; and "A byte-identical
  retry found in the idempotency cache returns the prior outcome without
  repeated fanout, KeyPackage consumption, or sequencing".
- Companion Section 11.8: a receiver reserves quota "against the
  connection, Account ID, route, federation peer, and process-global
  reassembly quotas", and "duplicate content addresses use the
  recent-object idempotency cache rather than consuming a second
  reservation or causing repeat fanout".
- Architecture Section 19.2: "All count-scaled or peer-influenced heap
  storage is allocated through one process-wide `MemoryBudget` authority",
  and "A configured connection count is therefore a strict upper bound, not
  a promise that every connection can simultaneously consume every other
  configured maximum."

The edge keeps two caches of its clients' submissions: the recent-object
cache of its assembler, which answers a copy of a submission still in
flight, and its reply cache (`e2ee/edge/retry.rs`), which answers a retry of
an answered submission from the lines its answer rendered. Both were one
pool for the whole edge.

### Decision: quotas for each connection and each account

A share of one pool for the whole edge would not keep the other clients
served: a few connections, of one account or more, could hold every
share. The reply cache therefore has no pool for the whole edge. Each
connection and each account has a fixed quota, which no other connection
changes, and the bound for all of them together is the memory the daemon
admits its connections against, as for every other count-scaled
allocation (architecture 19.2). Both quotas apply: one per account alone
would let one connection hold its account's whole share, and one per
connection alone would let an account multiply it by its sessions. At its
quota a connection or account is refused, never evicted: evicting a reply
would answer a retry of its submission with a second execution instead of
the prior outcome (Sections 11.8 and 16).

### The rules

In `crates/agenc-relay-e2ee/src/wire/assembly.rs`,
`crates/agenc-relay-runtime/src/e2ee/edge/` and
`crates/agenc-relay-runtime/src/state_core/mod.rs`:

- **A recent-object ceiling per connection.** The edge's assembler bounds
  its recent-object cache per sender (`RecentCeiling::PerSenderRefused`),
  and a client submission's sender is its connection and attachment
  session, so each connection has its own `MAX_RECENT_OBJECTS` tuples,
  counting the slots its open submissions reserve. A connection past its
  ceiling is refused `E2EE_REASSEMBLY_LIMIT` before any reservation, as the
  shared ceiling refused before; every other connection keeps its own
  ceiling. Unlike the coordinator's per-peer ceiling
  (`RecentCeiling::PerSender`), which assembles past the ceiling without a
  tuple and answers from the replay rows, the edge refuses: it keeps no
  durable record of its clients' submissions.
- **A submission's tuple is released once it is answered or refused.** When
  a submission's answer is published, its reply answers every retry
  (`retry::Replies::replay`, checked first at fragment zero), so its tuple
  leaves the recent-object cache (`completion::publish_reply`). A completed
  submission refused before it went out (a quota, the memory budget or the
  origin) keeps no tuple either, so its retry is admitted again
  (`router::accept_line`). A closed connection's tuples and open submission
  leave with it (`E2eeEdge::connection_closed`). The recent-object cache
  therefore holds only submissions in flight.
- **Each connection and each account keeps its replies within its own
  quota.** A reply kept for a submission's retries counts against its
  connection's quota, 512 replies charged at most 4 MiB, and against its
  account's over all the account's connections on the edge, 1,024 replies
  charged at most 8 MiB, each with the reservations of its submissions
  still outstanding (`Replies::admits`, `CONNECTION_REPLIES`,
  `ACCOUNT_REPLIES`). A connection or account at its quota is refused
  `E2EE_RATE_LIMITED` for its next submission, which only it sees, and
  nothing it keeps is evicted, so a retry of its own submission is still
  answered from its reply. What one connection or account keeps never
  refuses another account's connection, and a request whose reply is not
  kept, such as `EKEY WHOAMI` or a fetch, reserves nothing and is not
  refused for replies.
- **Kept replies are charged to the memory budget.** A submission reserves
  its command's largest reply from the process memory budget when it goes
  out (`reply_reservation`, `StateCoreContext::reserve_kept_output`): a
  live carrier's echo, one line per fragment of its object, or any other
  submission's one line (Section 11.7), each at most one physical client
  line, with its entry. Its kept reply keeps only its own charge and the
  rest returns to the budget (`Replies::remember`); a kept reply's charge
  returns at the end of the 30-minute retention or of its connection. A
  submission the budget cannot reserve for is refused `E2EE_RATE_LIMITED`
  before it goes out.
- **Outstanding requests are bounded per connection, per account and for
  the edge.** A connection has at most 4 requests outstanding, an account at
  most 8 over its connections, and the edge at most 32, half of the
  coordinator's per-peer bounds on queued requests and on requests waiting
  for their payloads, so a conforming edge stays clear of both
  (`E2eeEdge::admits_request`). A request past a bound is refused
  `E2EE_RATE_LIMITED`; an outstanding request holds its place only until
  the coordinator answers it.
- **A closed connection's requests keep their places until the coordinator
  is done with them.** A connection that closes with requests unanswered
  deletes its origin behind them, and the coordinator runs or drops them
  before it acknowledges the deletion, holding them queued meanwhile. Each
  keeps its place in its account's and the edge's bounds until a frame of
  its result arrives, the deletion is acknowledged, or the link ends, when
  the coordinator drops the link's queued requests
  (`E2eeEdge::delete_origin`, `closed_requests`). A request already
  answered keeps none, and so does every request of a connection whose
  origin no declaration on the live link names: no deletion goes out, and
  the coordinator holds none of them.

Sizing. A connection's tuples are its submissions in flight, at most its
four outstanding requests, so the per-connection recent-object ceiling never
limits a conforming client. A connection's 512 replies allow one answered
submission every 3.5 seconds over the 30-minute retention, and an account
twice that over its connections. A short one-line reply is charged 4 KiB and
the longest 12 KiB, which every outstanding submission other than a live
carrier reserves, and a live carrier's echo at most 768 KiB, its reservation
while outstanding. The quotas hold for each connection and each account
alone, and the memory budget, which an operator sizes to the connections the
edge admits, bounds all connections together.

| Test | What it pins |
| --- | --- |
| `wire::assembly::tests::a_refusing_per_sender_ceiling_refuses_only_the_sender_past_it` (`agenc-relay-e2ee`) | A sender at its ceiling is refused before any reservation, its recent object is still answered from the cache, another sender is admitted, and a forgotten object frees its sender's slot. |
| `e2ee::edge::tests::ingress::a_connection_past_its_recent_share_leaves_the_others_admitted` | One connection holds its ceiling of tuples: its next submission is refused `E2EE_REASSEMBLY_LIMIT` with nothing reserved, and another connection's submission completes. |
| `e2ee::edge::tests::retry::an_answered_submission_releases_its_recent_object_tuple` | Publishing a submission's answer releases its tuple, and its reply answers a retry. |
| `e2ee::edge::tests::ingress::a_submission_refused_before_it_is_sent_releases_its_recent_tuple` | A three-fragment submission whose connection's reply quota fills while it assembles is refused `E2EE_RATE_LIMITED` when it completes, nothing is outstanding, and it keeps no tuple. |
| `e2ee::edge::tests::ingress::a_closed_connection_forgets_its_recent_submissions` | A closed connection's tuples and its open submission leave the cache, and another connection's tuple stays. |
| `e2ee::edge::tests::retry::replies_are_kept_within_each_connection_and_account_quota` | A connection keeping 511 replies is admitted, and refused with one submission outstanding; keeping 512 it is refused and nothing it keeps is evicted. The account's second connection is admitted until the account keeps 1,024, then every connection of the account is refused while another account's is admitted; a disconnect releases the account's share of that connection's replies. |
| `e2ee::edge::tests::retry::a_connection_byte_quota_bounds_its_kept_replies` | A connection whose kept and reserved charges reach 4 MiB is admitted, and refused one byte past it. |
| `e2ee::edge::tests::retry::an_account_byte_quota_bounds_its_kept_replies_over_its_connections` | An account whose kept and reserved charges over two connections reach 8 MiB is admitted on a third, and refused one byte past it. |
| `e2ee::edge::tests::retry::an_account_outstanding_reservations_count_against_its_quota` | An account keeping 1,023 replies over two connections is admitted on a third, and refused with one submission outstanding. |
| `e2ee::edge::tests::ingress::outstanding_reservations_count_against_the_reply_quotas_at_fragment_zero` | A connection keeping 511 replies is refused at fragment zero while a submission of its whose reply is kept is outstanding, and admitted once none is; so is a third connection of an account keeping 1,023 replies over two connections while a submission of the account is outstanding. |
| `e2ee::edge::tests::retry::expired_and_disconnected_replies_give_their_quota_back` | A connection keeping 512 replies is refused, and admitted again once they expire; neither expiry nor a disconnect leaves a usage of the connection or its account behind. |
| `e2ee::edge::tests::retry::a_kept_reply_lasts_the_retention_and_is_charged_its_size` | A kept reply keeps only its own charge out of its reservation and the rest returns to the budget; it answers a retry until the retention ends, when its charge returns; a reply its reservation cannot hold is refused. |
| `e2ee::edge::tests::retry::a_submission_reserves_the_largest_reply_of_its_command` | A live carrier reserves 90 physical lines, another submission one, and a command without an object nothing. |
| `e2ee::edge::tests::ingress::outstanding_requests_are_bounded_per_connection_account_and_edge` | A connection with four outstanding requests is refused `E2EE_RATE_LIMITED`; the account's second connection is admitted until the account holds eight, then refused; another account's connection is admitted until the edge holds 32, and then refused. |
| `e2ee::edge::tests::ingress::a_closed_connections_requests_count_against_the_outstanding_bounds` | Eight unanswered requests of an account's closed connection refuse the account on another connection; another account's connection is admitted until the edge holds 32 with them, and then refused. |
| `e2ee::edge::origins::tests::a_closed_connection_keeps_its_unanswered_requests_until_answered` | Of a closed connection's three requests, the two unanswered ones keep their places, and the answered one and another connection's request keep none; a frame of one's result releases it and the deletion's acknowledgement the other, and a link loss releases the other connection's once it closed. |
| `e2ee::edge::tests::ingress::a_connection_at_its_reply_quota_is_served_a_request_it_keeps_no_reply_for` | A connection keeping 512 replies is refused its next submission and is still served `EKEY WHOAMI`. |
| `e2ee::edge::tests::ingress::a_submission_the_memory_budget_cannot_reserve_for_is_refused` | With the memory budget held, a submission is refused `E2EE_RATE_LIMITED` with nothing outstanding; with the memory back it goes out. |

The edge tests' requests name an account for each connection, and a test
whose request keeps its reply reserves its memory as sending does
(`reserve_reply`); `fill_client_cache` fills one connection's share to its
ceiling, and `keep` keeps one connection's replies.
`e2ee::edge::origins::tests::an_ended_connection_releases_its_requests_without_a_live_declaration`
now also requires that the ended connection's request keeps no place.

The new and changed signatures of the reply cache and the assembler mean the
start files do not compile with these tests, so single edits stand in for
the revert proof, each failing a test: a shared ceiling at the edge fails
the per-connection test; a refusing per-sender ceiling that counts every
sender's tuples, or that assembles past the ceiling, fails the assembler
test; keeping the tuple of an answered or a closed connection's submission
fails its test, and of a refused one two tests; no account quota fails four
tests, and no byte quota for an account the account byte test; no connection
quota fails six, and no byte quota for it the connection byte test; not
counting the outstanding reservations of a connection in the reply cache
fails three, and those of an account three; at the edge, counting no kept
reply's reservation, or none for the connection or for the account, each
fails the fragment zero test; no outstanding bound for a connection fails
the outstanding request test, and none for an account or for the edge two
tests each; a reservation for every request fails the test of a connection
at its reply quota; ignoring a refused memory reservation fails the memory
test; a kept reply holding its whole reservation fails the charge test;
keeping replies past the retention fails two; reserving one line for a live
carrier fails the reservation test; keeping a connection's usage when its
reply leaves fails the expiry test; keeping replies past their connection
fails three; and for a closed connection's requests, keeping no place for
the unanswered ones, keeping one for an answered request or for a connection
whose deletion did not go out, keeping it past a frame of its result, past
the deletion's acknowledgement or past a link loss, or not counting it
against the account's bound or against the edge's each fails one test.

The release coverage policy gains `edge-reply-quotas` and
`edge-reply-reservation` (branches) and `edge-request-admission`,
`edge-closed-connection-submissions`, `edge-reply-kept`,
`edge-reply-release` and `edge-kept-output-reservation` (regions), and
re-reviews and respans `e2ee-assembly-recent-ceiling`,
`e2ee-assembly-recent-admission`, `cap74-router-accept-line`,
`edge-companion-origin-deletion`, `edge-link-down-partial-objects` and
`edge-origin-acknowledgement-resend`; the other regions of the changed files
move with unchanged spans. Both source inventories are refreshed.

## A request's own failure is answered with its failed result (fourth commit)

The text these rules implement:

- Companion Section 12.5: "Every opcode permits `failed`. A failed result
  has `coordinator_state_generation=0`, an empty completion Event ID, empty
  snapshot token and next cursor, and zero response descriptors; it never
  consumes or partially commits the requested semantic mutation."
- Companion Section 12.5: before an append would cross an edge's
  unacknowledged-event ceiling, the coordinator "rejects the complete
  mutation with `E2EE_SYNCING`"; Architecture Section 20.8: "Insufficient
  capacity rejects the whole mutation with the initiating profile's
  overload result".
- Companion Section 11.9: `E2EE_INVALID_FRAGMENT` answers a malformed
  object, `E2EE_RATE_LIMITED` is "Operation exceeded an authenticated
  quota", and `E2EE_SYNCING` is "Federation route state has not crossed the
  READY/ACTIVE barrier"; Section 16 refuses storage at the global E2EE disk
  ceiling.
- Companion Section 11.8: "No fragment is delivered onward until the whole
  object passes transport validation and minimal bounded type parsing",
  and a receiver reserves quota per "federation peer"; Section 11.4 names
  the object kinds each command carries.

The rules, in `crates/agenc-relay-runtime/src/e2ee/coordinator/execute.rs`,
`request.rs` and `mod.rs`, `crates/agenc-relay-runtime/src/e2ee/edge/router.rs`
and `crates/agenc-relay-e2ee/src/wire/carrier.rs`:

- **A local failure of a fresh request is answered.** Once a request is
  classified fresh against the replay rows and its origin, its operation is
  run and its batch staged (`Fresh::stage`). When that fails for a reason of
  this coordinator's own, the request is staged again as its failed result
  (`run_with_object`), which consumes the request's operation sequence and
  commits no semantic mutation; the next request follows it, and the link
  stays up. A target whose route state cannot take the request's events, a
  delivery stream not past READY/ACTIVE, one at the unacknowledged-event
  ceiling, one with a barrier open or a full base outbox, refuses the
  mutation with `E2EE_SYNCING`, and that is the failed result's code. Any
  other local reason, its clock, a checkpoint plan, entropy, a timer or
  memory reservation, a storage quota such as the global E2EE disk ceiling,
  or the staging itself, gives `E2EE_RATE_LIMITED`, the code the link faults
  record gives a request whose batch storage refused, as the companion's
  overload result. Only when even the failed result cannot be made, as with
  a failed clock or plan, does the error stand and retire the link, as
  before. A malformed request object, a descriptor that contradicts it, an
  unknown origin, a request under a suspended origin, another generation, or
  a sequence other than the next remain violations.
- **A payload that is no wire object of its command's kind is refused at
  ingress.** The edge sends a client's complete object onward only once it
  is a wire object of a kind its command carries (`ArcWireObject::peek`,
  `CarrierCommand::accepts`); otherwise the submission is refused
  `E2EE_INVALID_FRAGMENT` at ingress, nothing is outstanding, and it keeps
  no recent-object tuple (`router::accept_line`). The recovery element
  carrier accepts every kind an element of a recovery submission may name,
  a root identity chain among them, as the coordinator's check of the
  submission does (`CarrierCommand::SubmitRecoveryElement`,
  `recovery::REFERENCE_ELEMENT_KINDS`, companion 13.7.4); its largest
  object is unchanged.
- **A malformed payload that still arrives is the request's failure.** A
  payload that is not a well-formed wire object, which a conforming edge no
  longer relays, leaves the request without a decoded payload
  (`request::decode`), and the operation that reads it answers with its
  failed result `E2EE_INVALID_FRAGMENT` (`ops::Exec::payload`), instead of
  failing the edge's link. A payload whose hash does not match the
  request's declaration, which only a faulty edge produces, is still a
  violation.
- **Payload waits are bounded per peer.** A request that names a payload
  waits for it in its peer's own bound of `MAX_QUEUED_COMPANION_REQUESTS`;
  one peer at its bound never refuses another peer's request
  (`on_request_fragment`). A peer past its own bound is still a violation of
  that peer's link: a conforming edge keeps at most 32 requests
  outstanding, a closed connection's unanswered ones among them (the third
  commit), so it never reaches it, nor the per-peer queue bound of the same
  size, which is unchanged.

| Test | What it pins |
| --- | --- |
| `federation::coordinator::tests::companion_refusals::a_request_its_storage_quota_refuses_is_answered_with_its_failed_result` | Through real storage, with the global E2EE disk ceiling set to admit one more failed result and not an account result: the `WHOAMI` is answered `E2EE_RATE_LIMITED` at its sequence, the sequence advances, and the link stays up; with no room left the request's error stands and nothing is staged. |
| `federation::coordinator::tests::companion_refusals::a_payload_that_is_no_wire_object_is_answered_with_its_failed_result` | A `PUBLISH IDENTITY` whose payload is not a wire object is answered `E2EE_INVALID_FRAGMENT` at its sequence, the next request runs at the following one, and the link stays up. |
| `e2ee::coordinator::tests::sync::recent_objects::payload_waits_are_bounded_per_peer` | A peer with 64 requests waiting for their payloads is refused its next, and another peer still opens 64. |
| `e2ee::coordinator::tests::sync::local_failures::a_completion_target_not_past_ready_answers_e2ee_syncing` | A `PUBLISH IDENTITY` whose completion targets an edge with no stream past READY is answered with its failed result `E2EE_SYNCING`. |
| `e2ee::coordinator::tests::sync::local_failures::a_completion_target_at_its_event_ceiling_answers_e2ee_syncing` | The same request whose target's stream is blocked at its unacknowledged-event ceiling is answered `E2EE_SYNCING`. |
| `e2ee::coordinator::execute::origin_replay::a_target_without_room_for_a_barrier_refuses_the_mutation_with_syncing` | A mutation whose target has base parts and no room for its barrier, an open barrier or a full base outbox, is refused `E2EE_SYNCING` before any copy is sequenced, which `run_with_object` answers with that failed result. |
| `e2ee::edge::tests::ingress::a_payload_that_is_no_object_of_its_kind_is_refused_at_ingress` | A payload that is no wire object, and a device roster on `PUBLISH IDENTITY`, are refused `E2EE_INVALID_FRAGMENT` at the edge with nothing outstanding and no tuple kept; an identity object goes out. |
| `e2ee::edge::tests::ingress::a_recovery_element_goes_out_in_each_kind_an_element_names` | An MLS application object on `EGROUP SUBMIT RECOVERY-ELEMENT` is refused `E2EE_INVALID_FRAGMENT`, and an element in each kind an element may name, a root identity chain among them, goes out. |
| `wire::carrier::tests::the_recovery_element_carrier_accepts_exactly_the_kinds_an_element_names` (`agenc-relay-e2ee`) | The recovery element carrier accepts a kind exactly when an element of a recovery submission may name it. |

With `execute.rs` set back to the third commit, the quota test and both
route state tests fail; with `request.rs` or the coordinator's `mod.rs` set
back, the payload test or the payload wait test fails, in turn. Single edits
fail tests as well: answering only a request that carries a payload fails
the quota test, and so does staging the retry without its refusal; refusing
a malformed payload as a violation fails the payload test; counting every
peer's payload waits fails the wait test; answering a target's route state
`E2EE_RATE_LIMITED` fails both route state tests, and answering every local
failure `E2EE_SYNCING` the quota test; relaying a payload without its type
parsing, or without its kind check, fails the ingress parsing test and the
recovery element test, and keeping the tuple of a payload refused at ingress
the ingress parsing test; and leaving the root identity chain out of the
recovery element carrier fails the recovery element test and the E2EE
crate's carrier test. The ingress tests that complete a submission send an
identity object, and the recovery element test an object of each kind an
element names.

Two lines of the failed result's staging are guards no test can fail. The
staging clears the cross-profile assignment of the first attempt, which
only an `at_revision` failure after the assignment leaves in place, since a
refused staging takes or clears it (`project_next`,
`clear_projection_intent`), and an assignment needs a base plan the unit
tests do not build. It also stages the failed result without the object the
first attempt read, whose exclusion from the resident objects matches no
row a failed result writes.

The release coverage policy gains `companion-fresh-request-staging`
(regions), re-reviews and sets `cap79-fresh-object-006-run-with-object` to
the new extent of `run_with_object`, whose staging moved into
`Fresh::stage`, and re-reviews and respans `cap74-router-accept-line`; the
other regions of the changed files move with unchanged spans. Both source
inventories are refreshed.

## A commit landing during a companion read never fails the link (fifth commit)

The third commit of [the link resume
record](stage-10-link-resume.md) keeps link traffic and companion batches
waiting while any batch is open, so local write contention never fails a
link. This commit carries that rule to the coordinator's companion storage
reads: a fresh request's object read, a stored reply's body reads, an
acknowledgement's retention prefix read and a snapshot page read. A commit
that lands while one of them is in flight never fails its link, whether
another router made it or the coordinator's own batch did, which
timer-driven base work (a grace fence, a resume reconciliation retry) and a
base request whose signature check completed can stage at any time.

The rules, in `crates/agenc-relay-runtime/src/federation/coordinator/`:

- **A companion read stays current across other routers' commits.** No
  other router writes companion rows. A node runs either the coordinator
  role or the edge role (`daemon::attach_federation_role`), and on a
  coordinator node only the coordinator's own batches write the
  `E2eeObject` and `E2eeState` tables; the projector writes a barrier row
  there only for the cross-profile assignment of a companion batch. The
  coordinator counts its own batches as they commit (`own_commits`, at
  `take_pending_for_receipt`), and each companion read is pinned to that
  count instead of the storage commit sequence (`object_read::validate`,
  `response_read::submit`, `companion::ack_read::submit`): a commit another
  router makes while a read is in flight, or between two of its pages,
  leaves it current, and a completion read at a later storage commit than
  the one at submission is no longer malformed.
- **A completion waits while a batch is open.** A companion read whose
  completion finds a batch open, the coordinator's own or one another
  router staged, waits (`parks_read`, `parked_read`) and continues once no
  batch is open, at that batch's receipt or refusal (`resume_parked_read`,
  from `continue_after_commit` and `batch_rejected_with_error`). Its
  continuation, a fresh request's batch, an acknowledgement or a page's
  `FETCH` advance, then finds the batch slot free. A completion that
  arrives while the coordinator quiesces is settled at once, as before.
- **A read across one of the coordinator's own commits is planned again.**
  A batch of the coordinator's own that committed while a read was in
  flight or waiting may have changed the rows the read describes. The
  fresh request then runs again from its start and reads its object again
  (`companion::run`); a stored reply is read again from its first body, and
  an acknowledgement's prefix from its first page (`ReadStep::Stale`). A
  batch that storage refused changed nothing, and the read continues with
  what it has read.
- **A page read is companion work.** A snapshot page read counts with the
  other companion reads (`replay_io_busy`): link traffic, queued requests,
  background work and expiry maintenance wait for it, and at most one
  companion read is in flight, so a second companion batch can no longer
  find the held batch's slot taken. When a companion read completes with no
  other in flight, the queued base and companion requests and the backlog
  that waited for it run (`companion_read_settled`), at a page read's
  completion as at the others'.
- **Companion reads run one at a time.** A page read or an
  acknowledgement's prefix read is refused while another companion read is
  in flight, and its link fails, as the object and reply reads already were
  (`page_read::submit`, `ack_read::submit`). Link traffic and queued
  requests wait while a read is in flight, so a conforming link never meets
  the refusal, and the one completion that waits (`parked_read`) never
  meets a second.

| Test | What it pins |
| --- | --- |
| `federation::coordinator::tests::object_reads::contention::a_commit_of_another_router_during_an_object_read_leaves_it_current` | Through real storage, another router commits while a fresh request's object read is in flight: the read completes, and the request is answered at its sequence with the object it read, with no second read and the link up. Replaces `a_new_storage_commit_invalidates_a_pending_object_read`. |
| `federation::coordinator::tests::object_reads::contention::an_object_read_completing_while_another_router_has_a_batch_open_waits_for_it` | The completion finds another router's batch open: it waits, nothing is staged or sent, and that batch's receipt runs the request with the object it read. |
| `federation::coordinator::tests::object_reads::contention::an_own_commit_during_an_object_read_runs_its_request_again` | A batch of the coordinator's own opens while the read is in flight: the completion waits, and at that batch's receipt the request runs again, reads its object again and is answered at its sequence. |
| `federation::coordinator::tests::object_reads::contention::an_object_read_behind_a_refused_batch_of_its_own_keeps_its_object` | Storage refuses that batch: the request runs with the object it read. |
| `federation::coordinator::tests::response_reads::contention::a_commit_of_another_router_between_response_bodies_keeps_the_reply` | Another router commits between two of a stored reply's three bodies: the whole reply goes out once and the link stays up. Replaces `unrelated_storage_commit_between_response_pages_refuses_the_entire_reply`. |
| `federation::coordinator::tests::response_reads::contention::an_own_commit_between_response_bodies_reads_the_reply_again` | A batch of the coordinator's own commits between two bodies: the completion waits, the reply is read again from its first body, and it goes out once. |
| `federation::coordinator::tests::combined_barriers::ack_read::an_ack_read_keeps_its_pages_across_a_commit_of_another_router` | A prefix page completes while another router's batch is open: it waits, that batch commits, the read continues with its two remaining pages, and the acknowledgement commits with the link up. Replaces `an_unrelated_commit_between_ack_pages_refuses_mixed_inventory_without_advancing_coverage`. |
| `federation::coordinator::tests::combined_barriers::ack_read::an_ack_read_completing_behind_a_batch_of_its_own_reads_again` | A batch of the coordinator's own opens while the prefix read is in flight: the page waits, at that batch's receipt the prefix is read again from its first page, and the acknowledgement commits with the link up. Replaces `an_ack_read_completing_behind_a_staged_batch_fails_its_link`. |
| `federation::coordinator::tests::combined_barriers::ack_read::an_ack_read_completing_behind_a_refused_batch_of_its_own_continues` | Storage refuses that batch: the waiting page is admitted and the read continues with its remaining pages. |
| `federation::coordinator::tests::combined_barriers::page_read::link_traffic_waits_for_a_page_read_and_runs_at_its_completion` | A base `FACK` that arrives while a page read is in flight waits in the backlog, and the read's completion runs it. |
| `federation::coordinator::tests::combined_barriers::page_read::a_page_read_completion_waits_for_an_open_batch` | A page read's completion waits while another router's batch is open and settles at that batch's receipt. |
| `federation::coordinator::tests::combined_barriers::page_read::the_base_request_queue_waits_for_a_page_read_and_drains_at_its_completion` | The base request queue is not visited while a page read is in flight, and is at its completion. |
| `federation::coordinator::tests::object_reads::contention::a_completion_while_quiescing_settles_at_once_behind_another_batch` | A completion that arrives while the coordinator quiesces is settled at once although another router's batch is open: nothing waits, and the read's reservation is released. |
| `federation::coordinator::tests::combined_barriers::ack_read::a_companion_read_is_refused_while_another_is_in_flight` | A snapshot page read is refused while an acknowledgement's prefix read is in flight, and the prefix read while a page read is. |

`object_reads::failures::malformed_raw_reads_never_stage_a_response` and
`response_reads::failures::malformed_raw_completions_fail_before_any_response_is_queued`
no longer count a completion at another storage commit among their
malformed completions.

Single edits fail tests, each run on the coordinator's combined barrier,
object read and response read tests: settling every completion at once fails
eight; letting a completion wait while the coordinator quiesces fails the
quiescing test; waiting only for the coordinator's own batch fails three;
resuming a waiting read at no receipt fails six, and at no refusal two; not
counting the coordinator's own commits fails three; keeping an object read,
a reply's bodies or a prefix's pages across one of the coordinator's own
commits fails one test each; leaving page reads out of companion work fails
three, and settling nothing at a page read's completion two; visiting no
base request at that completion fails one; letting a page read, or a prefix
read, start while another companion read is in flight fails the
one-at-a-time test; and refusing a completion read at an earlier storage
commit than the current one, the former pin, fails two object read tests,
one response read test and one acknowledgement test.

The release coverage policy gains `coordinator-parked-read`,
`coordinator-parked-read-resume` and `coordinator-companion-read-settled`
(regions). It re-reviews and re-spans the fresh object read's regions
`cap79-fresh-object-014-submit` through `-017-admit`, the response read's
`cap79-response-018-submit`, `-021-advance` and `-023-prepare` through
`-025-admit`, the acknowledgement read's `cap79-replay-089-submit`,
`-090-prepare` and `-093-completed` through `-095-advance`, and
`companion-page-read-completed`, whose reasons now name the coordinator's
own commits; `companion-page-read-submit`, whose reason now names one
companion read at a time, as the prefix read's `cap79-replay-089-submit`
does; `cap79-maintenance-055-replay-io-busy`, which now counts page reads;
`cap79-maintenance-056-reject-pending-batch` and
`cap81-mod-federationcoordinator-batch-rejected-with-error`, which resume a
waiting read at a refusal; `cap79-request-expiry-022-apply-pending-receipt`,
which counts the coordinator's own commits; and `cap79-fresh-object-018-run`
and `-019-run-with-object`, for `companion::run`, which the object read now
calls. The other regions of the changed files move with unchanged spans.
Both source inventories are refreshed.

## The edge's own batches wait for a free slot, and a refused one closes the link (sixth commit)

The text these rules implement, companion Section 12.5:

- "The edge admits the complete event and payload, validates the next exact
  cursor [...] before opening its apply transaction"; "Only after commit
  does it make frames visible and send EACK".
- "After a same-incarnation link reconnect and profile negotiation, the edge
  sends ERESUME with its durable cursor"; the coordinator "retransmits every
  unacknowledged row byte-for-byte". An `ERESUME` begins a link's companion
  synchronization, and an event that a refused batch undid is retransmitted
  only on the next link.

This commit carries the second commit of [the link resume
record](stage-10-link-resume.md), under which an event waits while the state
core cannot take its batch, to the edge's other batches, and closes the link
for a batch of the E2EE router's that storage refused. The rules, in
`crates/agenc-relay-runtime/src/e2ee/edge/`,
`crates/agenc-relay-runtime/src/federation/edge/` and
`crates/agenc-relay-runtime/src/registration.rs`:

- **A batch of the E2EE edge's waits for a free slot.** A snapshot page's
  `ESTATE END`, `ESTATE ACTIVE` and a witness resolution's `EWITNESS END`
  stage a batch. The state core hands the E2EE router a companion frame in
  the step that reads it from the link, while no batch is open, so such a
  frame meets an open batch only when a role staged earlier in that step;
  its batch then waits, as an event's does, instead of failing the link. A
  batch that finds a batch open, the edge's own, one in flight, or one
  another router gathers, is held (`stage_or_hold`, `HeldBatch`) and
  staged once no batch is open, at the next receipt or after a refusal
  (`stage_held`, from `batch_applied` and `drain_waiting_events`). While it
  is held, events queue behind it (`holds_events`). At most one batch is
  held: the coordinator sends the frame that stages the next one only after
  this one's receipt, a page after `EFETCH`, ACTIVE after READY, and a
  resolution answer after the request it answers; a second one is refused
  as before. A held batch belongs to its link, and a link loss drops it
  (`link_down`): the next link carries its frame again.
- **No event queues ahead of a held batch.** A held batch is staged before
  the events queued behind a batch (`stage_held` before `drain_queued`),
  which reorders nothing, since no event is queued when a batch is held. A
  snapshot page or ACTIVE arrives only on a link whose resume the
  coordinator answered with a snapshot transfer (a transfer opens only
  while resuming), and that link carries the new generation's events only
  after the origin replay that follows ACTIVE's commit; an event that
  arrives before is refused for its generation and closes the link. A
  witness resolution is read only while every frame outside the resolution
  family is dropped. A link loss empties the event queue. A batch that
  finds an event queued is refused, and the link closes (`stage_or_hold`),
  so no batch goes ahead of a queued event even if a frame arrives out of
  that order.
- **A refused batch of the E2EE edge's closes the link.** When storage
  refuses a batch the E2EE router staged, an event, a snapshot page, READY,
  ACTIVE, a migration step or a witness resolution, the event or step is
  undone as before, and the edge closes its federation link
  (`E2eeEdge::batch_rejected`, `EdgeFederation::fail_companion_storage`), as
  the base edge closes it for its own refused batches. The next link's
  `ERESUME` names the durable cursor, and the coordinator retransmits from
  there; no `ERESUME` goes out on the link that carried the refused work.
- **The base edge's snapshot install waits for a free slot.** At an install
  batch's receipt, roles that settle the receipt before the base edge, such
  as the registration router retrying a session close, can stage their own
  batch first. The next batch of an install is staged only while no batch
  is open (`installed`, `continue_install`); otherwise it waits and is
  staged at the next receipt (`continue_storage_work`) or at the refusal of
  the batch it waited for (`batch_rejected_with_error`).
- **A complete barrier waits for a free slot.** A cross-profile barrier is
  applied at a receipt, after the other roles settled it. Its transaction
  is prepared and staged only while no batch is open
  (`registration::apply_ready_barrier`); it applies at the next receipt or
  the next frame of the link.

The audit of the edge's other paths for the same pattern:

- **Snapshot.** The base edge's snapshot frames, among them ACTIVE, are
  handled only from the state core's inbox, which it reads only while no
  batch is open, and the base edge handles each before any other role of
  that step. The E2EE edge's migration and stray cleanup steps stage only
  while no batch is open (`continue_snapshot`).
- **Witness.** A durable witness violation row is staged by its retry
  timer only while no batch is open, and waits for the next one otherwise
  (`try_witness_stage`); a resolution's batch waits as above.
- **Origin.** The base edge's origin journal stages only while no batch is
  open and otherwise retries (`journal::continue_write`,
  `storage_occupied`). The E2EE edge's origin frames stage nothing.

A limitation is recorded, not changed. The edge acknowledges an exact
duplicate at its installed cursor again ([the link resume
record](stage-10-link-resume.md)), and two repeats are still refused and
close the link: a cross-profile part whose position repeats the installed
cursor, and a duplicate of an event whose commit is still in flight.
Neither is reachable under the coordinator's resend rules. It retransmits
only on a new link, and only the rows after the cursor that link's
`ERESUME` names, which it takes as acknowledged (the link resume record's
first commit); and the edge sends `ERESUME` only after the receipt of an
event commit in flight (`link_active`).

| Test | What it pins |
| --- | --- |
| `e2ee::edge::tests::snapshot::a_page_end_waits_while_another_router_gathers_a_batch` | A page's END that arrives while another router's batch gathers holds the page's batch; at that batch's receipt, or after storage refuses it, the batch stages, READY becomes durable and the edge awaits ACTIVE. |
| `e2ee::edge::tests::snapshot::active_waits_while_another_router_gathers_a_batch` | ACTIVE that arrives while another router's batch gathers is held and stages at that batch's receipt, and the cut activates. |
| `e2ee::edge::tests::projection::witness_persistence::resolution::a_resolution_end_waits_while_another_router_gathers_a_batch` | A witness resolution's END that arrives while another router's batch gathers is held with the link up, and an event that arrives then is dropped, not queued; the resolution stages at that batch's receipt, the head installs and `EWITNESS RESOLVED` follows its own receipt. |
| `e2ee::edge::tests::snapshot::no_event_queues_while_active_waits_for_a_slot` | An event of the new generation that arrives while ACTIVE is held is refused, not queued, and the link closes. |
| `e2ee::edge::tests::projection::event_admission::a_link_loss_drops_the_held_batch` | A batch held behind another router's batch is dropped at a link loss: that batch's receipt stages nothing of the edge's, and nothing waits. |
| `e2ee::edge::tests::projection::event_admission::an_event_waits_behind_a_held_batch` | An event that arrives while a batch of the edge's is held queues behind it; the held batch stages first and the event applies at its receipt. |
| `e2ee::edge::tests::projection::event_admission::a_second_batch_is_refused_while_one_is_held` | A second batch while one is held is refused, and nothing stages the held one while the other router's batch is still open. |
| `e2ee::edge::tests::projection::event_admission::a_batch_that_finds_an_event_queued_is_refused` | A batch of the edge's that arrives while an event waits behind another router's batch is refused and not held, and the event applies at that batch's receipt. |
| `e2ee::edge::tests::projection::event_admission::a_held_batch_the_state_core_refuses_closes_the_link` | A held batch the state core refuses once no batch is open closes the link. |
| `e2ee::edge::tests::projection::event_admission::a_refused_event_batch_closes_the_link` | Storage refuses an event's batch: the event is undone, the federation link closes, the cursor stays at the installed position, and nothing goes out on that link. |
| `federation::edge::sync::sync_stages::an_install_batch_waits_while_another_router_has_a_batch_open` | At an install batch's receipt where another router's batch gathers, and at a journal receipt then, the next install batch waits with the link up; it stages at that batch's receipt or after storage refuses it. |
| `federation::edge::tests::restart::rollback::a_ready_barrier_waits_while_another_router_has_a_batch_open` | A complete barrier waits while another router's batch is open: nothing is staged, the link stays up and the route stays unbound; once that batch settles, the barrier applies. |

`E2eeEdge::batch_rejected` now takes the state core and the base edge, and
its two existing callers among the tests pass them.

Single edits fail tests, each run on the E2EE edge, base edge or
registration tests: holding a batch only behind the edge's own commit fails
eight; staging the held batch at no receipt fails five, and at no refusal
one; letting events pass a held batch fails one, and so does staging or
holding a batch while an event is queued; letting a second batch replace the
held one fails one, and so does dropping a held batch the state core refuses
without closing the link; staging a page's or a resolution's batch at once
fails one test each, and ACTIVE's two; keeping the link up for a refused
batch fails one; keeping a held batch across a link loss fails two; staging
an install batch at a receipt, or continuing one, while another router's
batch gathers fails one test each, and so does continuing none at a receipt
or at a refusal; and applying a complete barrier while a batch is open fails
one. With `federation/edge/sync.rs` set back to the fifth commit, the
install test fails.

The release coverage policy gains `edge-companion-held-batch` and
`edge-companion-held-staging` (branches) and
`edge-companion-refused-batch`, `edge-companion-storage-refusal` and
`edge-storage-continuation` (regions). It re-reviews and re-spans
`edge-event-hold`, `edge-link-down-partial-objects`,
`edge-snapshot-receiver`, `cap13-mod-batch-applied` and
`cap13-mod-batch-rejected-with-error`, whose reasons now name the held
batch and the waiting install; the other regions of the changed files move
with unchanged spans. Both source inventories are refreshed.

## The coverage of this record's regions (seventh commit)

A runtime and E2EE library branch report at this commit
(`RUSTC_BOOTSTRAP=1 cargo llvm-cov nextest -p agenc-relay-runtime -p
agenc-relay-e2ee --lib --all-features --branch --locked --no-fail-fast`, in
the program's test environment, 3,100 of 3,100 pass), compared with the
same report at the start commit (3,038 of 3,038 pass), scores the regions
the first six commits added or re-reviewed. This commit closes what that
report found on lines the record's commits wrote, without changing a rule:

- `EdgeFederation::origin_facts` builds the account text without an early
  return that cannot be taken, and a test asks it for a connection without
  a base origin.
- `attachment_ended` clears the attachment through the origin's map entry,
  and the principal-change test gains a logout with no submission in
  progress.
- The fresh object read's validation no longer checks for an open batch,
  since its completion waits while one is open (fifth commit).
- The base edge continues a waiting install after the other refusal checks
  of `batch_rejected_with_error`, where another router's refused batch
  falls through as before, instead of returning before them.
- The quota test adds a request that already carries its failed result and
  still cannot be staged, and a new acknowledgement read test answers its
  first page without the replay owner it expects
  (`federation::coordinator::tests::combined_barriers::ack_read::an_ack_page_missing_its_inventory_fails_its_link_without_staging`).

With these, every region the record added scores in full except five,
which keep their spans and name their scores in their reasons under the
rule of [the region drift record](stage-10-region-drift.md): none of their
uncovered entries both is provably unreachable and sits at its span's
boundary.

- `companion-fenced-request-classification`, 42 of 43 regions: the
  uncovered one is the unchanged violation for a replay row without a
  stored result.
- `companion-fresh-request-staging`, 106 of 146 regions: of the 40
  uncovered, 10 are error returns of the planning and staging steps
  `Fresh::stage` took over from `run_with_object`, and 30 lie on two
  success paths the library tests do not build, a fresh request whose
  outcome carries a mailbox expiry deadline, and one with a base plan,
  whose projection preview, mutation context and cross-profile assignment
  the staging sets. The start commit's report leaves all of them uncovered
  in `run_with_object` as well: `cap79-fresh-object-006-run-with-object`
  scored 157 of 204 there, and it and the new region together score 227 of
  274 here.
- `edge-companion-held-staging`, 8 of 10 branches: `stage_held` runs at a
  receipt, after the router's commit was taken, or after a refusal, when
  nothing is in flight, so the outcomes of its open-batch check for the
  edge's own commit and for a batch in flight are not reached. The check
  stays as written, the condition `stage_or_hold` holds under.
- `edge-reply-kept`, 57 of 58 regions: the uncovered one refuses a charge
  that cannot be computed, which no reply's length reaches.
- `edge-kept-output-reservation`, 7 of 8 regions: the uncovered one refuses
  a charge list that is empty or too long, which one charge never is.

No re-reviewed region holds more uncovered regions than at the start commit:
`companion-superseded-attachment` rises from 3 of 4 to 6 of 6 branches,
`cap90-current-base-origin-admission` from 22 to 23 of 24,
`cap79-fresh-object-010-attached-origin-edges` from 0 of 18 to 22 of 22
regions, and `cap74-router-accept-line` from 22 uncovered regions to 17, and
the others keep their uncovered count. In each row's declared metric, the
uncovered entries that fall on lines the record's commits changed are,
besides the five above, an error return on reserving the next
acknowledgement page, in `cap79-replay-089-submit` and
`cap79-replay-095-advance`, whose lines gained an argument, and the closure
on an object submission sent in `cap74-router-accept-line`, which the
library tests do not reach. Counted by regions, eleven more uncovered
entries fall on changed lines in rows scored by branches or in no row: error
returns and branches the library tests do not reach, in
`current_attachment`, `mirrored_device`, `ops::Exec::attached_device`, the
edge's answer publication, the reply cache's charge and release and the
coordinator's handling of a dropped request, and the install write at a
receipt in `federation/edge/sync.rs`, which the start commit's report leaves
uncovered as well.

Single edits fail tests: continuing no install at another router's refused
batch fails the install test, keeping the device when an attachment ends
fails the principal-change test, and changing the account generation of the
companion facts fails the held-principal test. The release coverage policy
re-reviews and re-spans `edge-companion-origin-facts`,
`edge-companion-attachment-ended`, `cap13-mod-batch-rejected-with-error` and
`cap79-fresh-object-015-validate`, and names the scores of
`edge-companion-held-staging`, `companion-fenced-request-classification`,
`companion-fresh-request-staging`, `edge-reply-kept` and
`edge-kept-output-reservation` in their reasons; both source inventories
are refreshed.

## Daemon tests (eighth commit)

`link_faults` in the Stage 08 daemon suite runs the production coordinator
and two production edges with both profiles active, edge A's link through a
relay. Three tests are added; each requires that edge A's link neither
closes nor links again while it runs.

| Test | What it pins |
| --- | --- |
| `link_faults::an_attachment_stands_through_the_principal_actions_of_its_session` | A session on edge A authenticates as an account and attaches a device, and its device-requiring `EKEY FETCH MAILBOX BINDING *` is served. Its logout is refused with 904 on the edge, and its login to another account is refused with 904, since the coordinator does not move a session that holds an account to another; after each, the fetch is served again. A second session of the account attaches the device and reauthenticates to the same account, and its fetch is served. |
| `link_faults::two_sessions_of_one_account_at_their_reply_quota_leave_another_account_served` | Two sessions of one account on edge A submit identity objects whose bodies are no identity in turn, each answered `E2EE_INVALID_FRAGMENT` and kept by the edge, until each is refused `E2EE_RATE_LIMITED`: each was answered exactly 512 times, its connection's quota and half its account's. A session of another account on edge A is then answered for a submission and for `EKEY WHOAMI`. Its duration, about 145 seconds, follows the per-session command pacing. |
| `link_faults::a_payload_that_is_no_wire_object_is_answered_for_its_request_alone` | A session's `EKEY PUBLISH IDENTITY` whose payload is not a wire object is refused `E2EE_INVALID_FRAGMENT` at edge A's ingress, and the session's next request is answered. |

At the start commit, with this test file, the payload and quota tests fail
and the attachment test passes. All seven `link_faults` tests pass at this
commit.

The attachment test settles how the first commit's case arises on an edge.
A session's own actions do not change the principal of a connection that
attached a device: an edge refuses a logout, the coordinator refuses a
login to another account for a session that holds an account, a connection
has two authentication attempts, and a reauthentication to the same account
keeps the account and the attachment. A declaration naming a device under
another principal therefore does not arise from these actions; the first
commit ends an attachment whenever a declaration names another principal,
and the coordinator refuses any remaining mismatch for its origin alone.

## What stays open

These belong to later topics and change nothing here:

- **A companion origin is not fenced with its base origin.** When the
  coordinator closes or fences a base origin or session, for a credential
  change or a refused base declaration, the companion origin of the same
  connection is not fenced with it, and companion requests on the link
  still run under it until the edge's `EORIGIN DEL` arrives. Companion
  Section 12.5 has losing base continuity fence both profiles.
- **Back-to-back base updates and the companion's generation.** The base
  edge advances its acknowledged generation only when no further update is
  pending, and the companion declares only at that generation, so two base
  updates sent back to back would have the companion skip a generation,
  which the coordinator refuses (Section 12.5: an update increments by
  one). On an edge, authentication runs only before registration and an
  attach needs the companion generation acknowledged first, so two such
  updates do not arise today; a test pinning that, or a companion
  declaration of every acknowledged generation, is open.
- **Two intermittent runtime tests.**
  `registration::explicit_names_tests::a_bare_names_across_joined_channels_arrives_in_pages`
  fails intermittently when the whole runtime library runs in one `cargo
  test` process and passes under `cargo nextest`, which runs each test in
  its own process;
  `state_core::tests::a_guest_session_registers_and_commands_flow_through_the_router`
  fails intermittently under either runner.
