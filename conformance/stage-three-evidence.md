# Stage 03 Evidence

Stage 03 implements pure domain behavior. The domain crate has no sockets,
filesystem access, executor, database handle, concrete clock, random generator,
or cryptographic implementation.

## Identity and channel state

`EVID-S03-001-IDENTITIES` covers separate account, session, user, nickname,
display-name, cloak, capability, and connection identities. Tests cover account
switches, account deletion, nickname reuse, session generation, account
generation, and stale revisions.

`EVID-S03-002-CHANNELS` covers immutable channel instances, recreation,
memberships, ordered roles, registered ownership, simple modes, typed mask
lists, invitations, and revision checks.

## Privacy, commands, and authorization

`EVID-S03-003-PROJECTIONS` covers public, unlisted, secret, account, session,
presence, channel, member, topic, and LIST projections. Hidden and absent users
or channels return the same public result.

`EVID-S03-004-COMMANDS` binds all 31 registered command families to closed
domain command kinds. Multi-target constructors reject duplicates, mixed
authority, invalid bodies, invalid mode vectors, and bound violations before
state planning. Query constructors enforce the NAMES, LIST, WHOWAS, ISON,
USERHOST, MONITOR, and CHATHISTORY limits. MODE includes user queries, `+w`
changes, channel queries, and typed list queries.

`EVID-S03-005-AUTHORIZATION` covers session and account generations, current
roles, direct-message policy, state revisions, and hierarchical rate charges.
Charges are returned on policy rejection, and NOTICE failures remain silent.

## Plans and policy

`EVID-S03-006-DELIVERY-PLANS` covers JOIN, PART, TOPIC, NAMES, LIST, INVITE,
KICK, channel messages, direct messages, recipients, and atomic multi-target
successful subsets. It also covers keyed joins, silent NOTICE rejection,
per-target failures, immutable message batches, and deterministic route and
message identifiers. Accepted KICK users and resolved message routes use
immutable identity order. Secret and absent channel lookups return the same
error class.

`EVID-S03-007-MODERATION` covers typed sanctions, closed reason codes, role
checks, typed ban and quiet entries, and E2EE removal-pending events without
content inspection.

`EVID-S03-008-HISTORY-E2EE` covers default-off history, registered plaintext
history constraints, encrypted-route refusal, fixed encrypted topic output,
and tag-only encrypted delivery.

`EVID-S03-009-MUTATION-PLANS` covers revision-bound plans, explicit storage
classes, logical recipients, semantic events, stale-plan rejection, and
single-consumption prepared plans.

`EVID-S03-010-EXPLICIT-INPUTS` covers stable request sequence numbers,
purpose-bound identifier requests, monotonic time, UTC values, wall-clock
failure, mismatched input vectors, and unchanged state on failure.

## Independent model and gate

`EVID-S03-011-REFERENCE-MODEL` is the testkit value-state model. It does not
import or call the production domain crate. It applies an executable operation
for every registered command family, checks its own invariants after accepted
changes, and exports stable snapshots.

`EVID-S03-012-SEQUENCES` is the generated case and rejection matrix in
`test-data/property/domain-stage-three-v1.steps`. Its 12 cases cross listed,
unlisted, and secret visibility with membership and role changes, nickname
reuse and channel recreation, invitation cleanup during account switches, and
channel registration, account deletion, and federation sequencing. Production
and reference revisions and selected state snapshots agree at each comparison
point. The test dispatches every generated rejection record and proves that the
full reference snapshot stays unchanged.

`EVID-S03-900-STAGE-GATE` is `bash scripts/check-stage-three.sh`. It inherits
the complete Stage 02 gate and adds requirement closure, generated-artifact
checks, independent domain checks, targeted model comparisons, and the full
Stage 03 behavior matrix.
