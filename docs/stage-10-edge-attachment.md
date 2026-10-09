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
once it is answered or refused. No specification, profile hash, registry
entry, named limit, reply code, wire object, table, key, row kind, field or
storage generation changed.

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
