# Requester replies of ReInit results (SC-013)

This record covers SC-013 of the SDK server program (2026-10-01, outside
master #35): the labeled result a requesting connection receives for the four
ReInit submissions. No wire object, registry, profile hash, limit,
persistent format or normative text changed.

## Each ReInit result keeps its own token

Companion Section 11.7 gives `EGROUP SUBMIT REINIT ATTEMPT`, `ACK`, `ACTIVATE`
and `ABORT` their own labeled replies, `REINIT-STAGED`, `REINIT-ACKED`,
`REINIT-ACTIVATED` and `REINIT-ABORTED` (the Section 11 command table and the
fixed success forms), and Section 12.5 maps each result selector one-to-one to
the corresponding Section 11.7 result. The edge decodes `commit_acked`,
`reinit_staged` and `reinit_acked` into one three-identifier tuple and
`aborted`, `reinit_activated` and `reinit_aborted` into one four-identifier
tuple, and its scalar renderer ignored the kind it had retained beside the
tuple: a staged or acknowledged ReInit was answered `ACKED`, and a successful
activation `ABORTED`. The coordinator already sends the exact result kind, and
the shared renderer in `agenc-relay-e2ee` already has all four forms, so the
defect was confined to the edge.

`scalar_line` (`crates/agenc-relay-runtime/src/e2ee/edge/result.rs`) now
takes the decoded result and chooses the line of a shared tuple by its kind
(`triple_line`, `quad_line`). A tuple under a kind that does not own it is
refused as `E2EE_INVALID_FRAGMENT` instead of being rendered as another kind;
the decoder builds each tuple from its kind, so that arm is defensive and
unreachable from the wire. The batch metadata child renders `ABORTED` only
for an `aborted` result. The completion-delayed path and the retry cache
render through the same function, so a completion that arrives after its
result and a retried submission answered from the cache carry the same token.

This adopts the SDK rehearsal's patch 0002 (rehearsal commit `6babf95c`)
unchanged; only the coverage source inventories were recomputed for this
tree.

### Regressions

`crates/agenc-relay-runtime/src/e2ee/edge/tests/result_kinds.rs` drives real
`federation_result` objects of the six kinds that share the two tuples
(`commit_acked`, `aborted` and the four ReInit kinds) through the edge's own
entry points and checks the byte-exact labeled line:

- `a_result_whose_completion_was_applied_renders_its_own_kind`: through
  `on_result_frame` with the completion event already applied;
- `a_completion_after_the_result_renders_its_own_kind`: the result first,
  then `prepare_completion` and `commit_completion`;
- `a_retried_submission_replays_its_own_kind`: a retried submission answered
  from the reply cache under a new label;
- `a_tuple_under_a_kind_that_does_not_own_it_is_refused`: mismatched kind and
  tuple pairs are refused with `InvalidFragment`;
- `only_an_aborted_tuple_names_an_aborted_batch_child`.

The three-daemon Stage 08 test
`encrypted_clients::reinit::a_reinit_activates_only_with_every_continuing_leaf_acknowledged`
asserted `" EGROUP ACKED "` for `SUBMIT REINIT ACK`; it now asserts
`REINIT-ACKED`. It also checks `REINIT-STAGED`, `REINIT-ACKED` and
`REINIT-ACTIVATED` and their identifiers on the labeled completion line
itself: its earlier `contains` checks were satisfied by the correct untagged
broadcast that arrived before the wrong labeled line.

With `result.rs` alone reverted to `70c832c`, the five unit tests fail (the
labeled token is `ACKED` where `REINIT-STAGED` is required, a mismatched tuple
renders instead of being refused, and a ReInit activation batch names an
`ABORTED` child), and the daemon test fails at its first labeled completion:
`@label=l35 :edge-a.test EGROUP ACKED …` where `REINIT-STAGED` is required.
With the fix restored, all six pass.

### An attempt abort through the daemons

The rehearsal checked `REINIT-ABORTED` at the unit level only.
`encrypted_clients::reinit::a_reinit_attempt_aborts_when_its_second_vote_arrives`
stages a real two-leaf ReInit attempt through the production coordinator and
both edges, then aborts it with the two council votes in separate requests
(companion 13.8: an abort is certified at the derived old-policy quorum,
which is two for this two-principal council):

- alice's vote alone is below the quorum and is answered
  `PENDING <conversation-id> REINIT-ABORT <request-object-id>`;
- bob's vote completes the abort and is answered
  `REINIT-ABORTED <old-conversation-id> <reinit-attempt-id> <abort-id> <certificate-object-id>`,
  whose abort ID equals the one recomputed from the abort core;
- alice then reads the untagged `REINIT-ABORTED` broadcast naming the same
  abort, as Section 11.7 gives a requester answered `PENDING`.

With only the `reinit_aborted` arm of `quad_line` rendering `ABORTED`, the
test fails at bob's completion (`@label=l6 :edge-b.test EGROUP ABORTED …`
where `REINIT-ABORTED` is required); with the whole of `result.rs` reverted
it fails earlier, at the staged attempt's `ACKED`.

### Wire effect

Only the requester's labeled completion of the four ReInit submissions changes
token: `ACKED` becomes `REINIT-STAGED` or `REINIT-ACKED`, and `ABORTED`
becomes `REINIT-ACTIVATED` or `REINIT-ABORTED`. The identifiers, the untagged
broadcasts and the ordinary `ACKED` and `ABORTED` replies are unchanged.

## Limitations

- The meaning of the last identifier of `REINIT-ACTIVATED` and
  `REINIT-ABORTED` (`<certificate-object-id>`) is unchanged; the SDK
  program tracks that reading separately (its cross-check row SC-010).
- ReInit's own target-commitment correction (the SDK program's PC-001) is a
  separate change; this one only makes the edge render the result kind the
  coordinator already sends.
- Through the daemons the results are checked on the ordinary path, where the
  completion event is applied before the labeled result. A completion that
  arrives after its result and a retry answered from the reply cache are
  checked at the unit level only, and no daemon test restarts an edge between
  a ReInit result and its completion.
