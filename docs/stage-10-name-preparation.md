# Display-name preparation (D-45)

This record covers decision D-45 of the SDK server program (2026-10-07,
outside master #35). Architecture Section 7.2 prepares a display name with
the RFC 8266 Nickname profile, limits it to 64 UTF-8 bytes and never uses it
for routing or authorization; Appendix A.1 gives `SETNAME` one trailing
display name of 0 to 64 prepared bytes. RFC 8266 Section 2.3 enforces a
nickname by preparing it as Section 2.2 requires (FreeformClass code points
only), then applying the Section 2.1 additional mapping rule (every `Zs`
space becomes SPACE, leading and trailing spaces are removed, interior runs
become one SPACE) and the normalization rule (NFKC), and then refusing an
empty result. Section 2.1 and RFC 8264 Section 7 apply those rules again
until the result is stable, refusing a string that has not stabilized.

The rule this topic makes hold for every input: display-name preparation
prepares or refuses every input with its typed error and never panics, and
spaces are collapsed after normalization.

## The adapter applies the enforcement passes (first commit)

`agenc_relay_types::DisplayName::prepare` keeps its signature, its
256-byte hostile-input bound (`MAX_PRECIS_INPUT_BYTES`), its 64-byte result
bound (`MAX_DISPLAY_NAME_BYTES`) and its errors (`TooLong`, `PrecisRejected`
and `AllocationFailed`). It now runs the enforcement passes itself:

1. The input is length-checked and its spaces are mapped as before
   (`canonicalize_precis_spaces`).
2. Each pass (`enforce_nickname_rules`) checks the FreeformClass through the
   pinned dependency's preparation, applies the additional mapping rule
   (`collapse_precis_spaces`), applies NFKC through the dependency's
   normalization rule and refuses an empty result, so spaces are collapsed
   after normalization.
3. A pass whose output equals its input ends preparation: the result is
   refused with `TooLong` above 64 bytes and returned otherwise. After
   `PRECIS_ENFORCEMENT_PASSES` (three) passes without a stable result the
   input is refused with `PrecisRejected`.

The pinned dependency (`precis-profiles` 0.1.13) now supplies only the
FreeformClass check and NFKC; the adapter does not call its Nickname
enforcement or its additional mapping rule. Three passes is the bound the
dependency applies to its own profile, so results that stabilized before
still stabilize at the same pass. RFC 8266 allows a fourth application; the
differential test's model uses four and agrees with the adapter on every
generated input. `conformance/precis-dependency-decision.md` records the
narrowed use of the dependency.

Every caller of `DisplayName::prepare` inherits the rule.
`NormalizedLogin::prepare` (UsernameCaseMapped) is unchanged, and the
generated-input test below runs it over the same inputs.

Compatibility (G-08: unchanged). No table, key, row kind, field or storage
generation changed, and no specification text, profile hash, registry
entry, wire object, reply code or limit changed. The differential test
requires that every display name the replaced adapter returned prepares to
itself under the new adapter, so stored and relayed names restore and
validate unchanged, and that every name the new adapter returns is accepted
unchanged by the replaced adapter, so a federation of mixed revisions
accepts each other's names.

## Panic policy

Architecture Section 21.2 and `TRN-05`: parsers are total, panics stay
fail-stop, and there is no per-connection containment. No `catch_unwind`
was added, and the panic hook and the supervisor are unchanged.

## Tests

- `crates/agenc-relay-types/tests/display_name_preparation.rs`:
  - `every_generated_display_name_is_prepared_or_refused` prepares about
    3.7 million generated inputs (below) and requires a typed result for
    each. A prepared name must be non-empty, at most 64 bytes, without a
    leading, trailing or repeated space or an unmapped `Zs` space, in NFKC,
    and must prepare to itself. `NormalizedLogin::prepare` must return a
    typed result for each input too.
  - `spaces_from_normalization_are_collapsed` takes every character whose
    NFKC form contains a space, places it among context characters and
    spaces, and requires the exact prepared name.
  - `every_scalar_value_in_context_is_prepared_or_refused` places every
    Unicode scalar value after context text and a space, alone and doubled,
    and checks each prepared name as above.
  - `the_hostile_input_bound_is_checked_before_preparation` keeps the
    256-byte bound ahead of preparation.
- `crates/agenc-relay-types/tests/display_name_differential.rs`,
  `preparation_equals_the_model_and_changes_only_results_the_model_differs_from`,
  compares the new adapter, a copy of the replaced adapter and an RFC 8266
  model over about 4.0 million generated inputs. The model maps spaces by
  splitting on the `Zs` characters, uses the dependency's FreeformClass
  check and NFKC, and applies the rules at most four times. The new adapter
  must equal the model on every input; a result may differ from the
  replaced adapter's only where the replaced adapter's differs from the
  model; and the two cross-revision checks above must hold.
- The generated inputs (`tests/support/name_inputs.rs`): every Unicode
  scalar value alone and after context text; every character whose NFKC
  form differs from it and contains a space, computed from the dependency's
  normalization rather than listed, in eight short patterns with every pair
  of twenty context characters (characters from several scripts and planes,
  combining marks, `Zs` spaces, conjoining jamo, a default-ignorable and a
  control character); every string of up to four characters over a
  sixteen-character alphabet; and seeded random strings.
