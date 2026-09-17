//! Real sequencer keys and binding approvals; MLS ciphertext remains a public-envelope fixture.
#![forbid(unsafe_code)]

use agenc_ircd_e2ee::objects::conversation::IrcConversationBindingPackage;
use agenc_ircd_e2ee::sequencer::SequencerKeySet;

use super::super::support::sequencer_credential;

mod installation;
mod rotation;
mod terminal;
use super::*;

fn install_interval(harness: &mut Harness, interval: (u64, u64)) -> TestResult<[u8; 32]> {
    let credential = sequencer_credential(&key(90), 0, interval, None)?;
    let set = SequencerKeySet::verify(&NETWORK, std::slice::from_ref(&credential), 0, None)?;
    let id = set.current().ok_or("current credential")?.credential_id;
    harness
        .coordinator
        .install_sequencer(key(90), set, credential)?;
    Ok(id)
}

fn signed_binding(harness: &Harness, credential: [u8; 32]) -> TestResult<Vec<u8>> {
    let bytes = harness.binding_bytes()?;
    let mut budget = DecodeBudget::new(1 << 20, 1 << 12);
    let object = agenc_ircd_e2ee::object::IrcWireObject::decode_kind(
        &bytes,
        Some(IrcWireObjectKind::ConversationBinding),
        &mut budget,
    )?;
    let mut package = IrcConversationBindingPackage::decode_exact(object.body(), &mut budget)?;
    package.binding.tbs.sequencer_credential_id = credential;
    let binding_id = semantic_id_of(SemanticHashDomain::BindingId, &package.binding.tbs)?;
    let mut approvals = package.binding.approvals.as_slice().to_vec();
    for approval in &mut approvals {
        approval.device_signature = sign(
            &key(DEVICE),
            SignatureDomain::ConversationBinding,
            &package.binding.tbs,
        )?;
    }
    package.binding.approvals = TlsVec::new(approvals)?;
    let mut locks = package.root_binding_locks.as_slice().to_vec();
    for lock in &mut locks {
        lock.tbs.binding_id = binding_id;
        lock.root_signature = sign(
            &harness.principal.root_secret,
            SignatureDomain::RootBindingLock,
            &lock.tbs,
        )?;
    }
    package.root_binding_locks = TlsVec::new(locks)?;
    wire(IrcWireObjectKind::ConversationBinding, &package)
}

fn bind_pinned(harness: &mut Harness, credential: [u8; 32]) -> TestResult<[u8; 32]> {
    harness.publish_identity_and_roster()?;
    harness.attach()?;
    let mut reserve = INSTANCE.to_vec();
    reserve.push(5);
    reserve.extend_from_slice(b"#room");
    let result = ok(harness.run(Op::ReserveChannel, &reserve, None)?)?;
    let ResultBody::Reserved(reservation, _) = result.result else {
        return Err("reservation".into());
    };
    let conversation = agenc_ircd_e2ee::ids::conversation_id(&NETWORK, &GROUP)?;
    let binding = signed_binding(harness, credential)?;
    let mut params = reservation.to_vec();
    params.extend_from_slice(&conversation);
    params.extend_from_slice(&[44; 32]);
    assert!(matches!(
        ok(harness.run(Op::BindGroup, &params, Some(&binding))?)?.result,
        ResultBody::Bound { .. }
    ));
    Ok(conversation)
}

fn candidate_time(time: u64, interval: (u64, u64), accepted: bool) -> TestResult {
    let mut harness = Harness::new()?;
    let credential = install_interval(&mut harness, interval)?;
    let conversation = bind_pinned(&mut harness, credential)?;
    let before = harness
        .coordinator
        .state
        .logs
        .get(&conversation)
        .ok_or("log")?
        .clone();
    let writes = harness.writes.len();
    let bytes = commit_bytes(&harness, conversation, 0, time)?;
    let outcome = harness.run(Op::SubmitCandidate, &conversation, Some(&bytes))?;
    if accepted {
        let outcome = ok(outcome)?;
        let event = outcome.events.first().ok_or("candidate event")?;
        let mut budget = DecodeBudget::new(1 << 16, 1 << 10);
        let receipt = IrcCandidateReceipt::decode_exact(&event.encoded_result, &mut budget)?;
        assert_eq!(receipt.tbs.sequencer_key_id, credential);
        assert_eq!(receipt.tbs.sequenced_at, super::super::NOW);
        harness
            .coordinator
            .key_set()
            .and_then(|set| set.credential(&credential))
            .ok_or("credential")?
            .key
            .verify(
                SignatureDomain::CandidateReceipt,
                &receipt.tbs.encode()?,
                &receipt.sequencer_signature,
            )?;
    } else {
        assert_eq!(code(outcome), Some(E2eeReplyCode::Syncing));
        assert_eq!(
            harness.coordinator.state.logs.get(&conversation),
            Some(&before)
        );
        assert_eq!(harness.writes.len(), writes);
    }
    Ok(())
}

#[test]
fn candidate_refuses_time_before_credential_interval() -> TestResult {
    candidate_time(99, (100, 1_000), false)
}

#[test]
fn candidate_refuses_time_after_credential_interval() -> TestResult {
    candidate_time(1_001, (100, 1_000), false)
}

#[test]
fn candidate_uses_canonical_time_and_inclusive_interval_ends() -> TestResult {
    for (time, interval) in [
        (100, (100, 1_000)),
        (1_000, (100, 1_000)),
        (10, (0, 20)),
        (2_000, (1_500, 2_500)),
    ] {
        candidate_time(time, interval, true)?;
    }
    Ok(())
}

#[test]
fn installed_successor_names_the_key_that_actually_signs() -> TestResult {
    let mut harness = Harness::new()?;
    let old = sequencer_credential(&key(90), 0, (0, 2_000_000), None)?;
    let next = sequencer_credential(&key(91), 1, (100, 3_000_000), Some((&key(90), &old)))?;
    let set = SequencerKeySet::verify(&NETWORK, &[old, next.clone()], 1, None)?;
    let expected = semantic_id_of(SemanticHashDomain::SequencerKey, &next.tbs)?;
    harness.coordinator.install_sequencer(key(91), set, next)?;
    let conversation = bind_pinned(&mut harness, expected)?;
    let (receipt, _, _) = submit_candidate(&mut harness, conversation, 0, 500)?;
    assert_eq!(receipt.tbs.sequencer_key_id, expected);
    let verified = harness
        .coordinator
        .key_set()
        .and_then(|set| set.credential(&expected))
        .ok_or("successor")?;
    verified.key.verify(
        SignatureDomain::CandidateReceipt,
        &receipt.tbs.encode()?,
        &receipt.sequencer_signature,
    )?;
    Ok(())
}

#[test]
fn failed_installation_preserves_existing_signer_and_advertisement() -> TestResult {
    for variant in 0..4 {
        let mut harness = Harness::new()?;
        let old_id = harness.coordinator.signer().ok_or("signer")?.credential_id;
        let old_set = harness.coordinator.key_set().ok_or("set")?.clone();
        let old_raw = harness
            .coordinator
            .current_credential()
            .ok_or("credential")?
            .clone();
        let mut raw = old_raw.clone();
        let mut set = old_set.clone();
        let mut seed = 90;
        match variant {
            0 => seed = 91,
            1 => raw.tbs.not_after += 1,
            2 => {
                raw.tbs.network_id = [99; 32];
            }
            3 => set.credentials.clear(),
            _ => return Err("variant".into()),
        }
        let _installed = harness.coordinator.install_sequencer(key(seed), set, raw);
        assert_eq!(
            harness.coordinator.signer().ok_or("signer")?.credential_id,
            old_id,
            "variant {variant}"
        );
        assert_eq!(
            harness
                .coordinator
                .signer()
                .ok_or("signer")?
                .key
                .public_key()
                .as_bytes(),
            key(90).public_key().as_bytes(),
            "variant {variant}"
        );
        assert_eq!(
            harness.coordinator.key_set(),
            Some(&old_set),
            "variant {variant}"
        );
        assert_eq!(
            harness.coordinator.current_credential(),
            Some(&old_raw),
            "variant {variant}"
        );
    }
    Ok(())
}
