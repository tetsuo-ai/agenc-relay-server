# Stage 10 overload thresholds and the funded default budget

This record closes the RUN-04 prerequisite (issue #113). RUN-04 (#46) made an
idle client charge exactly its 65,536-byte base, which let the four-GiB
default admit 50,000 of them; the campaign work of CAP-01 (#56) then showed
that admitting them is not the same as holding them. Section 19.3 classifies
overload against the same live protocol permit pool `P` that admission charges
against, and 50,000 base charges were 98.1% of the four-GiB `P`. A default
daemon therefore refused its 45,850th idle client and entered the eviction
class with every charge admitted. Section 28.7 required the population;
Section 19.2 and 19.3 refused it.

## Why the pool is not widened

Three of the four resolutions the issue listed take the classes against a
larger quantity. They are refused because a class above the admission ceiling
is not a class at all: admission already fails at `P`, so a threshold beyond
`P` can never be entered and the graceful degradation it names never happens.

| Classified against | 80% | 90% | 95% | Entered before admission fails at `P` |
| --- | ---: | ---: | ---: | --- |
| `P` = 3,338,666,016 | 2,670,932,812 | 3,004,799,414 | 3,171,732,715 | all three |
| `B - H` = 3,758,096,384 | 3,006,477,107 | 3,382,286,745 | 3,570,191,564 | only 80% |
| `B` = 4,294,967,296 | 3,435,973,836 | 3,865,470,566 | 4,080,218,931 | none |

Keeping the arithmetic and weakening Section 28.7 to require only memory
admission is refused for the same reason it was worth filing: a population the
95% class evicts is not a population the configuration holds. Selection is by
descending charged queue bytes, and an idle client's queue is empty, so the
server would have closed its longest-standing connections to recover a
threshold its own configured count defined.

## What changed

The default `server.memory_budget_bytes` is now 6,442,450,944. With four
crypto workers that gives `H = 805,306,368`, `D = 117,440,480`,
`C = 301,989,888` and `P = 5,217,714,208`. The default 50,000 client base
charges hold 3,276,800,000 bytes, 62.8% of `P`, in the normal class, and the
80%, 90% and 95% classes admit 63,692, 71,654 and 75,635 base charges. The
advertised default count, the hard maximum of 250,000 and the configurable
budget range are unchanged; only the default budget moved, and an operator who
lowers it keeps a legal configuration whose population is then bounded by
Section 19.3 rather than by `client_connections`. Section 19.2 now says so,
and Section 19.3 now names `P` explicitly so the same ambiguity cannot return.

## The eviction projection

Proving the eviction class reachable exposed a second defect in the same
sentence. `select_evictions` projected only `candidate.charged_bytes`, the
connection's queue backing, against the recovery mark, although closing the
connection also returns its base charge. With empty queues the projection
never moved, so the loop selected every candidate and still never reached
recovery: a whole population closed to recover a pool its base charges held.
The projection now subtracts the queue bytes and the base charge together.
Backing beyond those two is still not projected, which can only select one
connection too many, never one too few, so the fail-safe direction is kept.

## Evidence

- `cargo test -p agenc-ircd-runtime --all-features --lib`: 1,532 passed.
  `the_full_default_population_stays_in_the_normal_overload_class` pins the new
  arithmetic and the normal class;
  `the_former_default_budget_left_the_population_above_every_class` keeps the
  rejected four-GiB arithmetic legible;
  `eviction_of_an_idle_population_stops_at_the_recovery_mark` fails against the
  previous projection, which selected all ten candidates instead of two.
- `cargo test -p agenc-ircd-config --all-features`: the template, the golden
  public configuration and the cross-field fixtures carry the new default.
- `python3 scripts/test-release-qualification.py`: 56 passed, including the
  negative fixture that refuses a node reporting a raised or overdrawn pool.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`.

## Limitations

The Stage 08 fixture still lowers the budget to one GiB, and every fixture
leaves `client_connections` at its default, so those daemons remain bounded by
Section 19.3 well below their configured count; no fixture opens enough
connections to reach it. The stage-ten capacity campaign now pins the new
default node budget, but no production population has been run against it: the
campaign's own blocker is STO-10 (#124), where a SIGKILL at the published
budget left an edge unable to reopen its storage. Re-running the peer-loss
scenario at 6,442,450,944 is that issue's acceptance, not this one's.
