# Secret-lookup response floor

This record closes RUN-06 (issue #60): the configured
`privacy.secret_lookup_floor_milliseconds` now governs the answer to a
JOIN, NAMES, TOPIC, or MODE whose target is missing or concealed, so that
the time an answer takes does not separate "no such channel" from "a
channel you may not see". The floor is a best-effort response minimum, not
a constant-time or network-anonymity guarantee, and no wire format, reply
code, or resource ceiling changed.

## What is floored

`client_render::floored` selects exactly the outcomes whose timing would
otherwise be an existence oracle: a request whose command is JOIN, NAMES,
TOPIC, or MODE and whose every failure is `NotFound` or
`SecretUnavailable`, which the renderer already answers identically (a
concealed channel reports the same 403 as a missing one). A multi-target
request is floored only when every one of its failures is such an outcome,
so an ordinary refusal (`Forbidden`, `LimitExceeded`, an invalid argument,
a busy server) is never delayed and no other reply class changes.

## The owner

`state_core::secret_floor` holds the configured floor, the instant the
current registered command's processing began, and at most one rendered
response per connection. `RegisteredCommandExecutor::route_registered`
records the start of every admitted command, so the floor is measured from
the beginning of that command's work; a failure that already took longer
than the floor is answered at once and adds no delay.

When a floored failure is rendered, its complete logical response (label
and batch boundaries included, because the hold happens after
`logical_frames`) is retained, charged against the output budget at the
physical line ceiling per frame, and a `SecretChannelFloor` timer is
scheduled for the connection at the deadline. The state owner's timer heap
publishes it: the registration router's timer dispatch releases the
response and then resumes the commands that connection deferred. An
exhausted budget or a full timer heap answers immediately instead of
dropping or losing the response.

## Order and lifetime

While a connection owes a floored response, its later registered commands
go to the existing per-connection deferral queue that an open JOIN or NAMES
continuation already uses, and they resume only after the response goes
out. A delayed answer therefore keeps its place in the connection's order,
and unrelated connections, control traffic and maintenance continue
untouched. Nothing sleeps and no task is created per request: one timer
entry per waiting connection.

A closed or replaced connection drops its retained response and its charge
with its other timers, so a stale reply can never reach a new generation.
The configured value is restart-only under the existing reload diff, so a
running floor never changes underneath a waiting response.

## Limitations

- The floor covers the four commands the architecture names. A concealed
  target reached through another command keeps its existing timing.
- The floor is measured from the start of the command's processing inside
  the state owner, not from the byte arrival, so transport and parsing time
  is not included.
- One connection holds one floored response; a second concealment for the
  same connection cannot arrive while the first waits, because its command
  is deferred.

## Evidence

- `crates/agenc-ircd-runtime/src/state_core/tests/secret_floor.rs`: the
  deadline follows the command's start at floors of 1, 5 and 50
  milliseconds and disappears at and beyond it, a zero floor holds nothing,
  one connection holds one response, a held response reaches its connection
  only after the deadline and exactly once with its timer naming that exact
  connection, work that already exceeded the floor is answered at once, and
  a closed connection's response is dropped rather than published.
- `crates/agenc-ircd-runtime/src/client_render.rs`: the classification test
  covers the four commands against the concealment outcomes and every other
  failure class, mixed multi-target outcomes, and other commands.
- `crates/agenc-ircd/tests/stage_six_daemon.rs`: through the real daemon
  over TLS, a concealed TOPIC refusal precedes the next command's reply on
  the same connection.
