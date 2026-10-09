# A client's attachment and its share of an edge stay its own (D-44)

This record covers part 2 of decision D-44 of the SDK server program
(2026-10-07, outside master #35), which follows [the link faults
record](stage-10-link-faults.md) and [the link resume
record](stage-10-link-resume.md): a client's ordinary actions, and its share
of an edge's companion resources, affect only that client, never its
federation link and never other clients. The first commit has the base and
companion declarations of a generation name one principal, ends a device
attachment with the principal it was made under, and retires a deleted
origin only at the generation its deletion named. No specification, profile
hash, registry entry, named limit, reply code, wire object, table, key, row
kind, field or storage generation changed.

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
