# Stage 03 Evidence

Status: closed on 2026-08-27 for source commit
`8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb`. The [current
manifest](evidence/stage-03-8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb.json)
binds every required record to one clean gate run and its checked-in
[artifact](evidence/artifacts/stage-three-implementation-8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb.json).

Stage 03 implements pure domain behavior. The domain crate has no sockets,
filesystem access, executor, database handle, concrete clock, random generator,
or cryptographic implementation.

## Identity and channel state

`EVID-S03-001-IDENTITIES` covers separate account, session, user, nickname,
display-name, cloak, capability, and connection identities. Tests cover account
login and logout, account deletion, nickname reuse, session generation, account
generation, and stale revisions. Direct account replacement requires logout,
while same-account reauthentication changes only the process-local fresh-auth
deadline. E2EE-bound sessions reject identity replacement.

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
message identifiers. CTCP `ACTION` and IRC formatting controls remain ordinary
text, while plaintext CTCP DCC commands return the closed `UnsafeCtcp` domain
error. Accepted KICK users and resolved message routes use immutable identity
order. Secret and absent channel lookups return the same error class.

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
changes and rejected inputs, and exports stable snapshots. The comparison test
normalizes every exported account, session, channel, invitation, generation,
display-name, presence, monitor, topic, registration, sequence, and command
coverage field into one ordered snapshot. Invitation comparisons include the
target principal, inviter, accepted creation revision, and expiry tick.

`EVID-S03-012-SEQUENCES` is the executable seed manifest in
`test-data/property/domain-stage-three-v1.steps`. The default test expands 256
reviewed seeds to 64 operations each, for 16,384 ordered step checks. Every seed
interleaves accepted and rejected account creation, session registration,
nickname reuse, channel recreation, role and visibility changes, invitations,
account switches, session closure, and account deletion. Duplicate, stale, and
forbidden operations are included in each generated round. Separate reference
tests retain federation duplicate and gap inputs. Each round also sends `p`
and `s` discovery changes and paired role additions and removals in one MODE
command. The independent model applies those changes in client order, including
inactive-letter removal and exact-role lowering.

After every operation, the test validates both state machines, compares their
complete canonical snapshots, and proves that rejection changed neither
snapshot. A failure reports the seed, operation index, minimal failing prefix,
stable fingerprint, exact replay command, and a regression record ready for
promotion. Two minimized prefixes retain the invitation-metadata and
multi-session account-deletion mismatches found during model comparison. Their
fingerprints are checked and their prefixes replay before the full seed range,
so a later generator change cannot silently replace either operation sequence.

`EVID-S03-900-STAGE-GATE` names `bash scripts/check-stage-three.sh`. The command
inherits the Stage 02 implementation checks and adds requirement ownership,
generated-artifact checks, independent domain checks, targeted model
comparisons, and the full Stage 03 behavior matrix. The current manifest binds
that passed run to exact source commit
`8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb` and closes `S03-900` for that
revision.
