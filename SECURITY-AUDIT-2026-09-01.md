# Security Audit Report — 2026-09-01

**Status: PRIVATE — coordinated disclosure per `SECURITY.md`. Do not publish.**

- **Audited commit:** `99dd907` (post Stage-05 close; merge of #9)
- **Scope:** all workspace source implementing Stages 00–05 (`agenc-ircd-domain`,
  `agenc-ircd-client-wire`, `agenc-ircd-federation-wire`, `agenc-ircd-auth`,
  `agenc-ircd-crypto`, `agenc-ircd-storage`, `agenc-ircd-types`,
  `agenc-ircd-testkit`), 79k LoC. CI scripts and RFC texts excluded.
- **Method:** exploit-first adversarial campaign — invariant extraction against
  the normative specification, per-slice audits with adversarial-reasoning
  protocols (invariant-first, spec-vs-implementation diff, negative-space,
  backward search, reference-differential), attacker-persona rotation, and
  deterministic proof construction with negative controls. Every candidate was
  falsified before promotion; two candidate findings were rejected during
  verification (recorded in Appendix B).
- **Reproduction:** `cargo test --test zdh_poc_domain -p agenc-ircd-testkit
  --all-features --locked` and `cargo test --test zdh_poc_codec -p
  agenc-ircd-federation-wire --all-features --locked`. Both files are included
  on this branch and pass against the vulnerable code; a fix should flip the
  marked assertions.

## Summary

| ID | Severity | Title | CWE |
| --- | --- | --- | --- |
| ZDH-C1 | **High** | Authenticated non-member JOIN of a Secret/Unlisted channel succeeds | CWE-862 / CWE-200 |
| ZDH-C2 | Medium | HalfOperator can set `+l` (Operator-only), enabling founder lockout | CWE-284 |
| ZDH-D1 | Low (latent) | Five zero-field federation schemas share the empty canonical encoding | CWE-346 |
| ZDH-C3 | Low | Ban/exception entries are attributed to the channel creator, not the actor | CWE-778 |
| ZDH-C4 | Low | Secret-vs-nonexistent JOIN outcome divergence enables an enumeration oracle | CWE-204 |
| ZDH-C5 | Low | Named-LIST queries carry no privacy gate in the domain layer | CWE-200 |
| ZDH-A1 | Low | Invitation time-validity is frozen at START; FINISH commits stale invitations | CWE-294 |

---

## ZDH-C1 — Authenticated non-member JOIN of a Secret/Unlisted channel succeeds

- **Severity:** High
- **Affected:** `crates/agenc-ircd-domain/src/decision.rs` — `check_join_existing`
  (~line 2269–2285), `validate_guest_join` (~3900–3912),
  `validate_join_admission` (~3926–3955)
- **Specification:** Section 13.5 — "For an unauthenticated or unauthorized
  user, nonexistent and secret channel JOIN/NAMES/TOPIC/MODE requests take the
  same logical path and return `FAIL <command> SECRET_UNAVAILABLE`".
- **Expected behavior:** a JOIN by a non-member who holds no invite, matches no
  `+I` entry, and supplies no key must return `SECRET_UNAVAILABLE` for
  `Visibility::Secret` and `Visibility::Unlisted` channels — for guests and
  authenticated users alike.
- **Observed behavior:** the visibility admission gate exists only for guests.
  `validate_guest_join` rejects principals with `account_id == None` on
  non-Listed channels, and `validate_join_admission` never reads
  `channel.visibility`. Any registered account that knows or guesses a secret
  channel's name joins it normally and becomes a member.
- **Impact:** complete break of the Section 13.5 secrecy model. The joining
  attacker receives the member roster (JOIN recipients and the Section 14.2
  NAMES burst), can message the channel, and unlocks every co-member's
  `SessionProjection` through the shared-channel visibility rule (nickname,
  display name, cloak, account label, away text). Plaintext (non-E2EE-bound)
  secret channels additionally disclose full content. The existing
  contrast with `project_channel` — which correctly hides non-Listed channels
  from non-members on NAMES/TOPIC/MODE — confirms the omission is in the JOIN
  path only. The repository's existing test covers only the guest case
  (`decision.rs` test fixture `outsider = session(3, None)`).
- **Minimal reproduction:** `zdh_c1_authenticated_non_member_joins_secret_channel`
  in `crates/agenc-ircd-testkit/tests/zdh_poc_domain.rs` (included on this
  branch): owner creates `#hidden`, sets `+s`; a guest is refused with
  `SecretUnavailable` (negative control); an authenticated non-member without
  invite/key/`+I` joins and reaches `Role::Member`.
- **Suggested mitigation:** in `check_join_existing`, when
  `channel.visibility != Visibility::Listed` and the principal is not a member,
  require a matching invite, a matching `+I` entry, or a verified key before
  admission; otherwise return `DomainError::SecretUnavailable`. Add the
  authenticated-non-member case as a regression test alongside the guest case.

## ZDH-C2 — HalfOperator can set the member limit (`+l`)

- **Severity:** Medium
- **Affected:** `crates/agenc-ircd-domain/src/decision.rs` —
  `validate_mode_authority` (~4316–4319)
- **Specification:** Section 13.2 role matrix — "operator: modes, topic,
  invites, bans, kicks…; halfop: topic, voice, routine kick, and non-owner ban
  management". Channel modes are Operator authority; HalfOperator authority
  does not include them.
- **Expected behavior:** `MODE #channel +l N` requires `Role::Operator`.
- **Observed behavior:** `ModeChange::MemberLimit(_)` is grouped with
  `TopicProtected(_)` under `require_role(Role::HalfOperator)`.
- **Impact:** a HalfOperator can set `+l` to the current member count after the
  owner parts, permanently locking the founder out of their own channel (the
  durable owner grant persists but rejoin is rejected `LimitExceeded`) until a
  remaining halfop-or-higher raises the limit. Deterministic sequence in the
  reproduction test.
- **Minimal reproduction:** `zdh_c2_halfop_member_limit_locks_out_founder` in
  the same test file: a plain Member is refused (`Forbidden`, negative
  control); after `+h`, the halfop installs `+l 1` once alone in the channel
  and the founder's rejoin is rejected `LimitExceeded`.
- **Suggested mitigation:** move `ModeChange::MemberLimit(_)` to
  `require_role(Role::Operator)`; add the halfop-forbidden regression test.

## ZDH-D1 — Zero-field schemas share the empty canonical encoding

- **Severity:** Low today (no signing or transcript hashing exists yet); latent
  type-confusion/replay primitive for Stage 07 federation.
- **Affected:** `crates/agenc-ircd-federation-wire/src/generated_schema.rs`
  (`directory.links`, `directory.monitor_clear`, `directory.monitor_list`,
  `directory.monitor_status`, `result.no_content`) and
  `SchemaObject::encode_canonical` / `decode_exact` in `codec.rs`.
- **Expected behavior:** distinct logical message types must have distinct
  canonical bytes, or every future signature/transcript construction must bind
  schema identity explicitly.
- **Observed behavior:** all five schemas `decode_exact(b"")` successfully and
  `encode_canonical()` to `b""` — canonical bytes carry no schema identity.
- **Impact:** if the Stage 07 signer or transcript hash operates on bare
  canonical bytes, a signed `result.no_content` is indistinguishable from four
  directory query arms (message-type substitution). Not exploitable against any
  current code path.
- **Minimal reproduction:** `zdh_d1_zero_field_schemas_share_the_empty_canonical_encoding`
  in `crates/agenc-ircd-federation-wire/tests/zdh_poc_codec.rs`.
- **Suggested mitigation:** require every signed/hashed construction to prefix a
  domain string that includes the schema name (mirroring `SignatureDomain` in
  `agenc-ircd-crypto`), or assert encoding uniqueness for zero-field schemas.

## Secondary findings (confirmed by code reading)

- **ZDH-C3 (CWE-778):** `apply_mode_change` (~`decision.rs:3544`) constructs
  every `+b/+e/+I` `ListEntry` with `setter: channel.creator` instead of the
  acting operator, and falls back to channel creation time when UTC is absent.
  The moderation audit trail attributes any halfop's bans to the founder.
  Fix: pass the acting principal through `apply_mode_change`.
- **ZDH-C4 (CWE-204):** Section 13.5 requires nonexistent and secret channels
  to be indistinguishable; the domain returns materially different outcomes
  (guest JOIN of a free name creates the channel; of a held secret name returns
  `SecretUnavailable`; authenticated JOIN of a secret `+i` channel returns
  `Forbidden`). Unless the future renderer collapses these — the domain API
  gives it no instruction to — clients can enumerate hidden channel names.
- **ZDH-C5 (CWE-200):** `authorize_command` has no arm for
  `CanonicalCommandData::List`, and `project_channel_list` cannot filter by the
  command's name vector. The privacy decision for named LIST queries exists
  nowhere yet; a daemon resolving names directly will confirm secret-channel
  existence.
- **ZDH-A1 (CWE-294):** `evaluate_creation_invitation` runs once inside
  `begin_account_creation` (`crates/agenc-ircd-auth/src/service.rs:456–491`);
  `finish_account_creation` (503–557) never re-validates the window against the
  FINISH-time clock, so a transaction straddling `expires_at`/`not_before`
  commits an account under an invitation that is invalid at commit time
  (spec 11.3). Fix: re-check `not_before <= now < expires_at` at FINISH.

## Appendix A — Surfaces audited with no findings

- `agenc-ircd-storage` engine (login-index transitions, rollback classifier,
  owner thread, redb commit path, initialize/genesis, filesystem platform):
  CAS-plus-MAC chains verified end-to-end into redb 4.2.0; uncertainty is never
  reported as rejection; fail-closed throughout. Two delegated invariants
  (both-generation absence on login-index creation; `previous_entry_count`
  consistency outside audited constructors) are contract hazards for the
  Stage 06 caller, not exploitable bugs today.
- `agenc-ircd-auth` / `agenc-ircd-crypto`: no auth bypass, key confusion, nonce
  reuse, or secret-exposure path found. Sixteen near-miss classes ruled out
  with code evidence (OPAQUE replay/transplant, dummy-path confusion, HPKE
  two-time pad, RNG failure fallback, Debug/Display leakage, invitation
  forwarding is by-design bearer semantics per spec 11.3).
- `agenc-ircd-client-wire` parsers: no panic, unbounded allocation, or
  amplification beyond the documented ~3.4× parsed-backing factor; render path
  is fail-closed with a measure==encode proof.

## Appendix B — Candidates rejected during verification

- *Part-vector casefold dedup:* reported against `operation.part`, but that
  vector carries `FederationChannelId` 16-byte instance IDs, not names;
  raw-byte dedup is correct there. Residual informational inconsistency:
  `message_target_key` dedups nicknames/channel names by raw bytes while join
  dedups casefolded keys (duplicate-delivery only). The real invariant (exact
  duplicate part IDs rejected) is pinned in the codec test file.
- *CAP REQ over-budget error instead of NAK:* the repository already asserts
  this exact behavior in
  `capability_reply_budget.rs::req_accepts_exact_ack_and_rejects_plus_one_before_mutation`;
  it is intended design. Residual Stage 06 hazard: the daemon must map
  `CapError::LineBudget` to a bounded error reply, not a disconnect.
