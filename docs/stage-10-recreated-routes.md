# Recreated routes at a later semantic incarnation (B-14)

This record covers the server topic `sdk/b-routes` of the SDK server
program (item B-14, 2026-10-09, outside master #35). The first commit lets
the shared verifiers accept the generation-zero binding of an ordinary group
at a later semantic incarnation, anchored at the verified close of the
incarnation before it. No specification, profile hash, registry entry, named
limit, reply code, wire object, table, key, row kind, field or storage
generation changed.

## A recreated route's genesis follows the close before it (first commit)

The companion text this rule implements:

- Section 9.4: "For either kind, semantic incarnation zero has an all-zero
  predecessor close ID. A later incarnation increments by one and names the
  semantic close ID of the prior incarnation." An initial binding "has
  generation zero and an all-zero predecessor. It has the unanimous
  approvals and root locks described below", and "An ordinary new group has
  `initial_bootstrap_pending=1`; a ReInit successor has zero. Any other
  value or a mismatch with the initial committed context is invalid."
- Section 9.3: when proof material no longer fits a Welcome, "the safe
  recovery is an explicitly closed, next semantic incarnation with new
  generation-zero root locks and renewed verification".
- Section 9.5: "`bootstrap_pending` is 1 only while constructing a
  generation-zero group and 0 afterward."
- Section 11.5: "Close approvals sign with label `ARC-MLS/1 close
  authorization`, satisfy the last finalized policy's controller rule, and
  reference the finalization ID of the exact in-group active-to-closing
  transition. The close intent and its ID must equal the resulting
  committed lifecycle value. The semantic close ID is `SHA256("ARC-MLS/1
  close authorization id" || encoded_ArcCloseAuthorizationTBS)`; approval
  subsets do not alter it."

The rule, in the shared crate:

- The context core of a binding is bootstrap-pending exactly when the
  binding has generation zero, at every semantic incarnation
  (`context::verify_context_core`); a binding of generation one or later, a
  ReInit successor, is never bootstrap-pending.
- `initial_authority::PriorTerminal` is the terminal of one closed
  incarnation: the close that ended it, the binding and conversation it
  closed, and that binding's semantic route. Only
  `HistoricalChain::prior_terminal` produces one, from a validated chain
  whose lineage a close ended; a chain that is open, closing, or ended by a
  ReInit activation has none. A chain adopts a close only through
  `HistoricalChain::close`, which requires the close to name the chain's
  network, conversation and binding, to reference the finalization of the
  exact active-to-closing transition at the chain's head, to carry the
  committed close intent, and to carry approvals that satisfy the last
  finalized policy's controller rule. A holder of retained state resumes
  the chain at its closing state (`HistoricalChain::resume`, which trusts
  that state as it trusts every resumed anchor) and adopts the exact
  retained close the same way. There is no other constructor: a close
  that no chain adopted, however well formed, yields no terminal.
- `authenticate_initial_authority` keeps accepting only incarnation zero.
  `authenticate_recreated_authority` takes the generation-zero binding of a
  later incarnation with a `PriorTerminal`, and admits it only when the
  binding's semantic route has the terminal's route key, the incarnation
  after the terminal's, and the terminal's close ID, on the same network, in
  another conversation (`PriorTerminal::precedes`). Every other check of a
  genesis binding applies unchanged: unanimous approvals, root locks, the
  pinned roots and rosters, the context core, the bootstrap policy and the
  sequencer credential. The returned authority carries the terminal.
- `HistoricalChain::open` opens a binding at incarnation zero without a
  terminal, and a binding at a later incarnation only when its authority
  carries the terminal of the incarnation before it on this network. The
  recreated chain starts bootstrap-pending at its genesis anchor, like any
  genesis.

So no next incarnation opens while the one before it is live or closing,
or after a close its controllers never approved: the recreated route's
own binding, signed by every binding-authorized device of its principals
and root-locked, pins the close ID, and the terminal it is checked against
comes only from a chain that verified that close.

### Tests

`crates/agenc-relay-e2ee/tests/history/recreation.rs`, with real
signatures, closing a channel lineage after its bootstrap:

| Test | What it pins |
| --- | --- |
| `a_closed_route_reopens_at_its_next_incarnation_and_operates` | The closed chain's terminal and the one a chain resumed at the retained closing state yields after adopting the exact retained close agree; the next incarnation's authority carries it; the chain opens bootstrap-pending at its genesis anchor, under this network only, activates its bootstrap, finalizes a routine Commit, closes in turn, and its terminal opens incarnation two. |
| `a_recreated_route_needs_the_exact_close_of_the_incarnation_before_it` | Refused: a later incarnation without a terminal, with the close of another lineage of the same route key, a skipped incarnation, a repeated incarnation zero naming the close, a terminal given for an incarnation-zero genesis, and the closed conversation as its own next incarnation. |
| `only_a_closed_lineage_yields_a_prior_terminal` | A chain at its genesis anchor, one after its bootstrap activation and one after its closing transition have no terminal; a closed one has. |
| `an_unapproved_close_yields_no_terminal_for_a_next_incarnation` | A close that names no closing finalization and that no controller approved is refused by the live chain. It, the same close naming the head finalization, the controller's approval without its signature, and a close naming another binding are refused by the closing chain and by the chain resumed at its retained closing state, neither of which then yields a terminal; the exact close then yields the terminal that opens incarnation one. |

Also `tests::context::an_ordinary_group_bootstraps_at_every_incarnation_and_a_successor_does_not`:
at incarnation one, a generation-zero binding's core verifies only
bootstrap-pending and a generation-one binding's only not pending.

Revert proofs, each run over the whole e2ee crate (380 tests):

- the three start-commit gates restored together (the context core's
  incarnation-zero predicate, the genesis anchor's and `open`'s): 4 tests
  fail;
- each gate alone: 4, 3 and 1 tests fail;
- single edits: the anchor accepting any terminal (1), accepting a later
  incarnation without one (1), `open` accepting any terminal (1),
  `precedes` accepting the closed conversation (1), any network (1) or any
  later incarnation of the key (1), `prior_terminal` answering an unclosed
  lineage (2) or a closing one (2), and `HistoricalChain::close` adopting
  a close without checking its approvals (2).
- `open` accepting a later incarnation without a terminal passes: an
  authority without a terminal is refused at a later incarnation by its
  anchor check before `open` sees it, so that check of `open` is defence in
  depth, as its generation check is.
