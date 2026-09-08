//! Terminal certificates continue the credential on the exact retained receipt.
#![forbid(unsafe_code)]
use super::*;
use agenc_ircd_e2ee::objects::sequencing::IrcSequencerRecord;
mod staged;

type Prepared = (Harness, [u8; 32], Vec<u8>);

fn bound() -> TestResult<(Harness, [u8; 32])> {
    let mut harness = Harness::new()?;
    let id = harness.coordinator.signer().ok_or("signer")?.credential_id;
    let conversation = bind_pinned(&mut harness, id)?;
    let initial = harness.initial_policy.clone();
    let operational = harness.operational_policy.clone();
    harness.publish_policy(conversation, &initial)?;
    harness.publish_policy(conversation, &operational)?;
    Ok((harness, conversation))
}

fn select(harness: &mut Harness, successor: bool, reuse_key: bool) -> TestResult {
    let old = sequencer_credential(&key(90), 0, (0, 2_000_000), None)?;
    let next_seed = if reuse_key { 90 } else { 91 };
    let next = sequencer_credential(&key(next_seed), 1, (100, 3_000_000), Some((&key(90), &old)))?;
    let set = SequencerKeySet::verify(&NETWORK, &[old.clone(), next.clone()], 1, None)?;
    let (seed, credential) = if successor {
        (next_seed, next)
    } else {
        (90, old)
    };
    harness
        .coordinator
        .install_sequencer(key(seed), set, credential)?;
    Ok(())
}

fn ordinary(abort: bool) -> TestResult<Prepared> {
    let (mut harness, conversation) = bound()?;
    let (receipt, commit, candidate) = submit_candidate(&mut harness, conversation, 0, 500)?;
    let request = if abort {
        let core = IrcAbortCoreTbs {
            profile_version: 1,
            network_id: NETWORK,
            conversation_id: conversation,
            prior_state_id: receipt.tbs.prior_state_id,
            candidate_id: candidate,
            prior_epoch: 0,
            reason: IrcCommitAbortReason::SenderWithdrawn,
            evidence_digest: [0; 32],
        };
        let id = semantic_id_of(SemanticHashDomain::AbortId, &core)?;
        let signed = vote(
            &harness,
            DEVICE,
            &receipt,
            candidate,
            Terminal::abort(id, 1)?,
        )?;
        wire(
            IrcWireObjectKind::AbortRequest,
            &IrcAbortRequest {
                core,
                receipt,
                votes: TlsVec::new(vec![signed])?,
            },
        )?
    } else {
        let ack = acknowledge(&mut harness, conversation, candidate, commit)?;
        finalization_request(
            &harness,
            conversation,
            &receipt,
            commit,
            candidate,
            &ack,
            &[DEVICE],
        )?
    };
    Ok((harness, conversation, request))
}

fn verify_terminal(harness: &Harness, result: &ResultBody) -> TestResult {
    let (ResultBody::Finalized(_, _, _, id)
    | ResultBody::Aborted(_, _, _, id)
    | ResultBody::ReinitActivated(_, _, _, id)
    | ResultBody::ReinitAborted(_, _, _, id)) = result
    else {
        return Err("terminal result".into());
    };
    let bytes = harness
        .coordinator
        .state
        .objects
        .get(id)
        .ok_or("record object")?;
    let mut budget = DecodeBudget::new(1 << 22, 1 << 16);
    let object = agenc_ircd_e2ee::object::IrcWireObject::decode_kind(
        bytes,
        Some(IrcWireObjectKind::SequencerRecord),
        &mut budget,
    )?;
    let record = IrcSequencerRecord::decode_exact(object.body(), &mut budget)?;
    let (domain, credential_id, tbs, signature) = match record {
        IrcSequencerRecord::Finalization(value) => (
            SignatureDomain::CommitFinalization,
            value.tbs.sequencer_key_id,
            value.tbs.encode()?,
            value.sequencer_signature,
        ),
        IrcSequencerRecord::Abort(value) => (
            SignatureDomain::CandidateAbort,
            value.tbs.sequencer_key_id,
            value.tbs.encode()?,
            value.sequencer_signature,
        ),
        IrcSequencerRecord::ReinitActivation(value) => (
            SignatureDomain::ReinitActivation,
            value.tbs.sequencer_key_id,
            value.tbs.encode()?,
            value.sequencer_signature,
        ),
        IrcSequencerRecord::ReinitAbort(value) => (
            SignatureDomain::ReinitAttemptAbort,
            value.tbs.sequencer_key_id,
            value.tbs.encode()?,
            value.sequencer_signature,
        ),
        _ => return Err("terminal record".into()),
    };
    let old = sequencer_credential(&key(90), 0, (0, 2_000_000), None)?;
    let old = agenc_ircd_e2ee::sequencer::verify_sequencer_credential(&NETWORK, &old, None)?;
    assert_eq!(credential_id, old.credential_id);
    old.key.verify(domain, &tbs, &signature)?;
    Ok(())
}

fn boundary(prepare: impl Fn() -> TestResult<Prepared>, opcode: Op) -> TestResult {
    let (mut control, conversation, request) = prepare()?;
    let result = ok(control.run(opcode, &conversation, Some(&request))?)?;
    verify_terminal(&control, &result.result)?;
    for (restart, reuse_key, absent) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (true, true, false),
        (false, false, true),
        (true, false, true),
    ] {
        let (mut harness, conversation, request) = prepare()?;
        if restart {
            harness = harness.reloaded()?;
        }
        select(&mut harness, true, reuse_key)?;
        if absent {
            harness.coordinator.signer = None;
        }
        let logs = harness.coordinator.state.logs.clone();
        let states = harness.coordinator.state.conversations.clone();
        let writes = harness.writes.len();
        assert_eq!(
            code(harness.run(opcode, &conversation, Some(&request))?),
            Some(E2eeReplyCode::Syncing)
        );
        assert_eq!(harness.coordinator.state.logs, logs);
        assert_eq!(harness.coordinator.state.conversations, states);
        assert_eq!(harness.writes.len(), writes);
        select(&mut harness, false, reuse_key)?;
        let result = ok(harness.run(opcode, &conversation, Some(&request))?)?;
        verify_terminal(&harness, &result.result)?;
    }
    Ok(())
}

#[test]
fn finalization_waits_for_the_candidate_receipt_key() -> TestResult {
    boundary(|| ordinary(false), Op::SubmitFinalization)
}

#[test]
fn abort_waits_for_the_candidate_receipt_key() -> TestResult {
    boundary(|| ordinary(true), Op::SubmitAbort)
}

#[test]
fn activation_waits_for_the_attempt_receipt_key() -> TestResult {
    boundary(|| staged::prepare(true), Op::SubmitReinitActivate)
}

#[test]
fn reinit_abort_waits_for_the_attempt_receipt_key() -> TestResult {
    boundary(|| staged::prepare(false), Op::SubmitReinitAbort)
}
