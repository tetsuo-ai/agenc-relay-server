# ReInit state stored under the previous encrypted profile

These files are the restore evidence of plan item G-08 for P-04 (SDK
program, outside master #35), recorded in
[the ReInit enforcement record](../../../docs/stage-10-reinit-enforcement.md).
Governing evidence: G-08 and decision D-06 (storage generation 5); the rules
they exercise are companion Section 2.3, which forbids reinterpreting an
object of the previous profile hash under this one, and Section 13.8 step 2.
They support no conformance claim by themselves.

Each `.rows` file holds the durable rows that the coordinator of commit
`70c832c487e5590b892336f538d97769d867513e` (release candidate 3, the
previous profile hash) stored for one ReInit state, as its test harness's
logical store held them: one row per line, `<table id> <key hex> <value
hex>`, the value being the plaintext persistent record before sealing. The
tests in
`crates/agenc-relay-runtime/src/e2ee/coordinator/tests/sequence/reinit/successor/previous_profile.rs`
seal them into a storage fixture of this tree and restore them through the
storage reads a restart uses, and reload them into the coordinator harness
for the requests that follow.

| File | State |
| --- | --- |
| `open-attempt-at-genesis.rows` | a ReInit attempt admitted at the genesis anchor of the bound `#room` route, with no ReInit Commit, left open, with its successor reservation |
| `open-attempt-after-finalization.rows` | the same after the bootstrap activation, an ordinary finalization |
| `aborted-attempt.rows` | that attempt aborted: the head is a ReInit abort certificate of the previous layout |
| `activated.rows` | that attempt activated: the head is a ReInit activation certificate of the previous layout, and no successor is bound |
| `activated-and-bound.rows` | the same with the successor reserved and bound by `EGROUP RESERVE` and `EGROUP BIND` |
| `reinit-finalization.rows` | a finalized ReInit Commit at the head; its authorization's `transition_target_digest` is 32 bytes of `0x5a` |
| `reinit-finalization-then-attempt.rows` | a finalized ReInit Commit followed by an attempt left open |
| `reinit-finalization-then-candidate.rows` | a finalized ReInit Commit followed by an ordinary candidate left open |
| `reinit-finalization-then-candidate.finalization` | one hex line: the finalization request that would have completed that candidate |
| `reinit-finalization-then-ordinary.rows` | a finalized ReInit Commit followed by an ordinary candidate and its finalization |
| `reinit-finalization-then-close.rows` | a finalized ReInit Commit followed by a finalized closing intent and the authorized close |

## How the files were written

`git archive 70c832c` was extracted into a scratch directory (not a
checkout), where three test-only edits were made: the module below was added
as `crates/agenc-relay-runtime/src/e2ee/coordinator/tests/sequence/reinit/successor/g08_fixtures.rs`,
`successor.rs` declares it (`mod g08_fixtures;`), and `finalization_with` in
`crates/agenc-relay-runtime/src/e2ee/coordinator/tests/close_authorization.rs`
became `pub(in crate::e2ee::coordinator::tests)`. No production source of
that commit changed. The module ran with that tree's own lockfile and
toolchain:

```sh
G08_OUT=<directory> cargo nextest run -p agenc-relay-runtime --lib \
  --all-features --locked --run-ignored only -E 'test(write_g08_fixtures)'
```

The output is deterministic: separate runs wrote byte-identical files. The
module:

```rust
//! Test-only generator of the G-08 restore fixtures of P-04: writes the
//! durable rows this (70c832c) coordinator holds after each ReInit state of
//! its profile. Each file holds one row per line,
//! `<table> <key hex> <value hex>`, in the harness's store order.

use super::*;
use crate::e2ee::coordinator::tests::sequence::recovery_pending::close_authorization::{
    finalization_bytes, finalization_with, open_finalization,
};
use crate::state_core::durable::AccountServiceDurableWrite as Write;
use agenc_relay_e2ee::objects::conversation::{
    ArcCloseAuthorization, ArcCloseAuthorizationTbs, ArcCloseIntent, ArcCommitAuthorizationRule,
    action_bits,
};
use std::fmt::Write as _;

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn dump(harness: &Harness, name: &str) -> TestResult {
    let dir = std::env::var("G08_OUT")?;
    let mut text = String::new();
    for write in &harness.writes {
        let Write::Put {
            table,
            key,
            plaintext,
        } = write
        else {
            return Err("a delete in the logical store".into());
        };
        let _ = writeln!(
            text,
            "{} {} {}",
            *table as u16,
            hex(key.as_bytes()),
            hex(plaintext)
        );
    }
    std::fs::write(format!("{dir}/{name}.rows"), text)?;
    Ok(())
}

/// The bootstrap activation of a bound conversation (epoch zero).
fn activate_bootstrap(harness: &mut Harness, conversation: [u8; 32]) -> TestResult<[u8; 32]> {
    let opened = open_finalization(harness, conversation, 0)?;
    let (bytes, terminal) = finalization_bytes(harness, &opened, None, &[DEVICE])?;
    ok(harness.run(Op::SubmitFinalization, &conversation, Some(&bytes))?)?;
    Ok(terminal)
}

/// Finalizes one candidate at `epoch` whose authorization carries `bits`.
fn finalize_with_bits(
    harness: &mut Harness,
    conversation: [u8; 32],
    epoch: u64,
    reinit: bool,
) -> TestResult<[u8; 32]> {
    let opened = open_finalization(harness, conversation, epoch)?;
    let (bytes, terminal) = finalization_with(harness, &opened, &[DEVICE], |authorization| {
        if reinit {
            authorization.authorization_rule = ArcCommitAuthorizationRule::ControlledTransition;
            authorization.action_bits = action_bits::REINIT;
            authorization.transition_target_digest = [0x5a; 32];
        }
    })?;
    ok(harness.run(Op::SubmitFinalization, &conversation, Some(&bytes))?)?;
    Ok(terminal)
}

/// The abort of the staged attempt of `fixture`, completed by one vote.
fn abort(fixture: &mut Fixture) -> TestResult {
    let old_state = *fixture
        .harness
        .coordinator
        .state
        .logs
        .get(&fixture.old)
        .ok_or("old log")?
        .accepted_state_id();
    let receipt = staged_receipt(&fixture.harness, fixture.old)?;
    let mut budget = DecodeBudget::new(1 << 20, 1 << 16);
    let attempt_object = fixture
        .harness
        .coordinator
        .state
        .objects
        .get(&receipt.tbs.attempt_object_id)
        .ok_or("attempt object")?
        .clone();
    let object = ArcWireObject::decode_kind(
        &attempt_object,
        Some(ArcWireObjectKind::ReinitAttempt),
        &mut budget,
    )?;
    let attempt = ArcReInitAttempt::decode_exact(object.body(), &mut budget)?;
    let core = ArcReInitAbortCoreTbs {
        profile_version: 1,
        network_id: NETWORK,
        old_conversation_id: fixture.old,
        old_reinit_state_id: old_state,
        attempt_sequence: 0,
        slot_predecessor_record_id: receipt.tbs.predecessor_record_id,
        reinit_attempt_id: receipt.tbs.reinit_attempt_id,
        reason_code: 1,
        evidence_digest: [0; 32],
    };
    let abort_id = semantic_id_of(SemanticHashDomain::ReinitAbortId, &core)?;
    let vote = reinit_vote(
        &fixture.harness,
        DEVICE,
        &receipt,
        old_state,
        receipt.tbs.reinit_attempt_id,
        Terminal::abort(abort_id, 1)?,
    )?;
    let request = ArcReInitAbortRequest {
        core,
        receipt,
        attempt,
        votes: TlsVec::new(vec![vote])?,
    };
    let bytes = wire(ArcWireObjectKind::ReinitAbortRequest, &request)?;
    let outcome = ok(fixture
        .harness
        .run(Op::SubmitReinitAbort, &fixture.old, Some(&bytes))?)?;
    assert!(matches!(outcome.result, ResultBody::ReinitAborted(..)));
    Ok(())
}

#[test]
#[ignore = "lane scratch: writes the G-08 fixtures to G08_OUT"]
fn write_g08_fixtures() -> TestResult {
    // An attempt admitted at the genesis anchor, with no finalization.
    let fixture = Fixture::prepare()?;
    dump(&fixture.harness, "open-attempt-at-genesis")?;
    // An attempt admitted after an ordinary finalization.
    let mut harness = Harness::new()?;
    let old = harness.bind_channel()?;
    activate_bootstrap(&mut harness, old)?;
    let finalized = Fixture::prepare_bound(harness, old)?;
    dump(&finalized.harness, "open-attempt-after-finalization")?;
    // The attempt aborted.
    let mut aborted = Fixture::prepare()?;
    abort(&mut aborted)?;
    dump(&aborted.harness, "aborted-attempt")?;
    // The attempt activated, with no successor bound yet.
    let mut activated = Fixture::prepare()?;
    activated.activate()?;
    dump(&activated.harness, "activated")?;
    // The activated successor bound with RESERVE and BIND.
    let package = activated.package.clone();
    ok(activated.bind(&package, CONTEXT)?)?;
    dump(&activated.harness, "activated-and-bound")?;
    // A finalized ReInit Commit whose phase the previous profile never
    // entered, and the same group after a later ordinary finalization.
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    activate_bootstrap(&mut harness, conversation)?;
    finalize_with_bits(&mut harness, conversation, 1, true)?;
    dump(&harness, "reinit-finalization")?;
    finalize_with_bits(&mut harness, conversation, 2, false)?;
    dump(&harness, "reinit-finalization-then-ordinary")?;
    // A finalized ReInit Commit followed by an ordinary candidate still
    // open, with the finalization request that would complete it.
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    activate_bootstrap(&mut harness, conversation)?;
    finalize_with_bits(&mut harness, conversation, 1, true)?;
    let opened = open_finalization(&mut harness, conversation, 2)?;
    let (bytes, _) = finalization_bytes(&harness, &opened, None, &[DEVICE])?;
    dump(&harness, "reinit-finalization-then-candidate")?;
    std::fs::write(
        format!(
            "{}/reinit-finalization-then-candidate.finalization",
            std::env::var("G08_OUT")?
        ),
        hex(&bytes),
    )?;
    // A finalized ReInit Commit followed by an attempt, left open: the
    // previous profile's own ReInit flow.
    let mut harness = Harness::new()?;
    let old = harness.bind_channel()?;
    activate_bootstrap(&mut harness, old)?;
    finalize_with_bits(&mut harness, old, 1, true)?;
    let attempted = Fixture::prepare_bound(harness, old)?;
    dump(&attempted.harness, "reinit-finalization-then-attempt")?;
    // A finalized ReInit Commit followed by a finalized closing intent and
    // the authorized close.
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    activate_bootstrap(&mut harness, conversation)?;
    finalize_with_bits(&mut harness, conversation, 1, true)?;
    let intent = ArcCloseIntent {
        reason_code: 1,
        validation_time: 30,
    };
    let intent_id = semantic_id_of(SemanticHashDomain::CloseIntentId, &intent)?;
    let opened = open_finalization(&mut harness, conversation, 2)?;
    let (bytes, terminal) = finalization_bytes(&harness, &opened, Some(intent_id), &[DEVICE])?;
    ok(harness.run(Op::SubmitFinalization, &conversation, Some(&bytes))?)?;
    let binding = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("conversation")?
        .binding;
    let tbs = ArcCloseAuthorizationTbs {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        binding_id: binding,
        authorizing_terminal_id: terminal,
        close_intent: intent,
        close_intent_id: intent_id,
    };
    let close = ArcCloseAuthorization {
        approvals: TlsVec::new(vec![crate::e2ee::coordinator::tests::support::commit_approval(
            &harness.principal,
            DEVICE,
            &tbs,
            SignatureDomain::CloseAuthorization,
        )?])?,
        tbs,
    };
    let bytes = wire(ArcWireObjectKind::CloseAuthorization, &close)?;
    let mut parameters = conversation.to_vec();
    parameters.extend_from_slice(&close.tbs.close_intent.reason_code.to_be_bytes());
    ok(harness.run(Op::CloseGroup, &parameters, Some(&bytes))?)?;
    dump(&harness, "reinit-finalization-then-close")?;
    Ok(())
}
```
