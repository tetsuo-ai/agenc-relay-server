#![forbid(unsafe_code)]

//! Independent ReInit vectors (companion 13.8): one conversation from its
//! pinned genesis to a ReInit activation for successor suites 0x0001 and
//! 0x0003, written by `scripts/generate-e2ee-vectors.py`. Every record is
//! adopted by the shared historical chain; the target is rebuilt from the
//! Proposal's extension list byte for byte; the old finalization, the attempt
//! and the successor initial Commit are checked against that one target; and
//! every rejection vector is refused.

#[path = "reinit/support.rs"]
mod support;
use support::*;

#[path = "reinit/rules.rs"]
mod rules;

#[path = "reinit/successor.rs"]
mod successor;

#[path = "reinit/join.rs"]
mod join;

#[path = "reinit/rosters.rs"]
mod rosters;

use agenc_relay_crypto::SemanticHashDomain;
use agenc_relay_e2ee::E2eeError;
use agenc_relay_e2ee::history::{ChainStep, Lifecycle};
use agenc_relay_e2ee::ids::semantic_id_of;
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::reinit::ArcReInitTargetTbs;
use agenc_relay_e2ee::reinit_target::{
    AuthorizedReinit, ReinitPredecessor, check_carried_target, check_carried_target_from,
};
use agenc_relay_e2ee::{TlsDecode, TlsEncode};

/// Every decoded record, attempt and target re-encodes to its exact bytes.
fn assert_round_trip(file: &str) -> TestResult {
    let bytes = read(file)?;
    let mut budget = budget();
    let (kind, _) = ArcWireObject::peek(&bytes)?;
    let object = ArcWireObject::decode_kind(&bytes, Some(kind), &mut budget)?;
    let body = match kind {
        ArcWireObjectKind::SequencerRecord => {
            agenc_relay_e2ee::objects::sequencing::ArcSequencerRecord::decode_exact(
                object.body(),
                &mut budget,
            )?
            .encode()?
        }
        ArcWireObjectKind::ReinitAttempt => {
            agenc_relay_e2ee::objects::reinit::ArcReInitAttempt::decode_exact(
                object.body(),
                &mut budget,
            )?
            .encode()?
        }
        other => return Err(format!("{file} has unexpected kind {other:?}").into()),
    };
    assert_eq!(ArcWireObject::new(kind, body)?.encode()?, bytes, "{file}");
    Ok(())
}

#[test]
fn both_suites_rebuild_one_target_and_activate_it_through_the_shared_history() -> TestResult {
    let chain = activated_chain()?;
    for suite in [1_u16, 3] {
        let prefix = format!("suite-{suite:04x}");
        let file = |name: &str| format!("{prefix}-{name}");
        let digest = id(&file("target.bin"), "target_context_digest")?;

        // The target, decoded, re-encodes to its bytes and hashes to the
        // recorded digest; the Proposal's extension list rebuilds it exactly.
        let target_bytes = read(&file("target.bin"))?;
        let decoded = ArcReInitTargetTbs::decode_exact(&target_bytes, &mut budget())?;
        assert_eq!(decoded.encode()?, target_bytes, "{prefix}");
        let proposal = Proposal::of(suite)?;
        let target = proposal.reconstruct()?;
        assert_eq!(target.tbs().encode()?, target_bytes, "{prefix}");
        assert_eq!(target.tbs(), &decoded, "{prefix}");
        assert_eq!(target.digest(), &digest, "{prefix}");
        assert_eq!(
            semantic_id_of(SemanticHashDomain::ReinitTarget, &decoded)?,
            digest
        );
        assert_eq!(
            target.tbs().target_binding_id,
            id(&file("target.bin"), "target_binding_id")?
        );
        assert_eq!(
            target.tbs().target_context_core_id,
            id(&file("target.bin"), "target_context_core_id")?
        );
        assert_eq!(
            target.tbs().initial_member_plan_id,
            id(&file("target.bin"), "initial_member_plan_id")?
        );
        assert_eq!(
            target.route_binding(),
            &id(&file("target.bin"), "route_binding")?
        );
        assert_eq!(
            target.tbs().new_conversation_id,
            id(&file("extensions.bin"), "new_conversation_id")?
        );

        // The old ReInit candidate and its finalization, which commits the
        // digest; the chain enters its ReInit lifecycle at that finalization.
        let mut chain = chain.clone();
        let candidate = file("record-02-reinit-candidate.bin");
        assert!(matches!(
            advance(&mut chain, &candidate)?,
            ChainStep::Candidate(open) if open.candidate_id == id(&candidate, "semantic_id")?
        ));
        let finalization = file("record-03-reinit-finalization.bin");
        let finalization_id = id(&finalization, "semantic_id")?;
        let step = advance(&mut chain, &finalization)?;
        let ChainStep::Finalized {
            finalization_id: adopted,
            transitions,
            ..
        } = step
        else {
            return Err(format!("{finalization} did not finalize").into());
        };
        assert_eq!(adopted, finalization_id);
        assert_eq!(transitions.reinit_target_digest, Some(digest));
        assert!(matches!(
            chain.lifecycle(),
            Lifecycle::Reinit(state)
                if state.old_reinit_state_id == finalization_id && state.target_context_digest == digest
        ));

        // The authorization's links, independently of the chain.
        let authorized = AuthorizedReinit::from_proof(&finalization_proof(&finalization)?)?;
        assert_eq!(authorized.finalization_id(), &finalization_id);
        assert_eq!(authorized.target_context_digest(), &digest);
        assert_eq!(
            authorized.prior_state_id(),
            &id(&candidate, "prior_state_id")?
        );
        assert_eq!(
            id(&finalization, "transition_target_digest")?,
            digest,
            "{prefix}"
        );
        authorized.check_target(target.tbs())?;

        // The attempt names that finalization and carries the one target byte
        // for byte; the sequencer's checks rebuild the same target from the
        // carried bytes alone, and the initial Commit names the finalization
        // as its prior state.
        let attempt = attempt(&file("attempt-0.bin"))?;
        assert_eq!(attempt.target.encode()?, target_bytes, "{prefix}");
        let (old_binding, _) = old_authority()?;
        let carried = authorized.check_attempt(&attempt, &old_binding, &mut budget())?;
        assert_eq!(carried.tbs(), target.tbs(), "{prefix}");
        assert_eq!(carried.digest(), target.digest(), "{prefix}");
        assert_eq!(&carried, target.carried(), "{prefix}");
        assert_eq!(
            check_carried_target(&network()?, &old_binding, &attempt.target, &mut budget())?,
            carried
        );
        // The same checks against the facts the sequencer retained when it
        // verified the old binding.
        let facts = retained_facts()?;
        assert_eq!(
            authorized.check_attempt_from(&attempt, &facts, &mut budget())?,
            carried
        );
        assert_eq!(
            check_carried_target_from(&network()?, &facts, &attempt.target, &mut budget())?,
            carried
        );
        authorized.check_attempt_target(&attempt, &target)?;
        let initial_commit = read(&file("initial-commit-0.bin"))?;
        assert_eq!(attempt.initial_commit_bytes.as_slice(), initial_commit);
        authorized.check_initial_commit(&initial_commit, target.carried(), &mut budget())?;

        // The chain binds the target, adopts the attempt and the activation.
        chain.bind_reinit_target(target.tbs())?;
        let receipt = file("record-04-attempt-0-receipt.bin");
        assert!(matches!(
            advance_attempt(&mut chain, &receipt, &file("attempt-0.bin"))?,
            ChainStep::ReinitAttempted(open)
                if open.attempt_id == id(&receipt, "semantic_id")?
                    && open.new_conversation_id == target.tbs().new_conversation_id
        ));
        let activation = file("record-05-activation.bin");
        assert!(matches!(
            advance(&mut chain, &activation)?,
            ChainStep::ReinitActivated { reinit_activation_id, new_conversation_id, quorum_votes }
                if reinit_activation_id == id(&activation, "semantic_id")?
                    && new_conversation_id == target.tbs().new_conversation_id
                    && quorum_votes == 2
        ));
        assert!(chain.is_terminal());
        for name in [
            &candidate,
            &finalization,
            &receipt,
            &file("attempt-0.bin"),
            &activation,
        ] {
            assert_round_trip(name)?;
        }
    }
    Ok(())
}

#[test]
fn the_suites_differ_only_where_the_suite_enters_the_target() -> TestResult {
    let one = Proposal::of(1)?.reconstruct()?;
    let three = Proposal::of(3)?.reconstruct()?;
    assert_eq!(one.tbs().target_suite, 1);
    assert_eq!(three.tbs().target_suite, 3);
    assert_ne!(one.digest(), three.digest());
    assert_ne!(
        one.tbs().target_context_core_id,
        three.tbs().target_context_core_id
    );
    assert_ne!(one.tbs().target_binding_id, three.tbs().target_binding_id);
    assert_eq!(
        one.tbs().old_conversation_id,
        three.tbs().old_conversation_id
    );
    assert_eq!(one.route_binding(), three.route_binding());
    Ok(())
}

#[test]
fn one_target_survives_a_state_advance_a_candidate_abort_and_an_attempt_retry() -> TestResult {
    let target = Proposal::of(1)?.reconstruct()?;
    let direct_finalization = id(
        "suite-0001-record-03-reinit-finalization.bin",
        "semantic_id",
    )?;
    let mut chain = activated_chain()?;
    advance(&mut chain, "advanced-record-02-routine-candidate.bin")?;
    let routine = id("advanced-record-03-routine-finalization.bin", "semantic_id")?;
    assert!(matches!(
        advance(&mut chain, "advanced-record-03-routine-finalization.bin")?,
        ChainStep::Finalized { finalization_id, .. } if finalization_id == routine
    ));
    advance(
        &mut chain,
        "advanced-record-04-reinit-candidate-aborted.bin",
    )?;
    assert!(matches!(
        advance(&mut chain, "advanced-record-05-candidate-abort.bin")?,
        ChainStep::Aborted { .. }
    ));
    advance(&mut chain, "advanced-record-06-reinit-candidate.bin")?;
    let finalization = "advanced-record-07-reinit-finalization.bin";
    let finalization_id = id(finalization, "semantic_id")?;
    advance(&mut chain, finalization)?;

    // A later position and another finalization authorize the same digest.
    let authorized = AuthorizedReinit::from_proof(&finalization_proof(finalization)?)?;
    assert_eq!(authorized.prior_state_id(), &routine);
    assert_eq!(authorized.finalization_id(), &finalization_id);
    assert_ne!(finalization_id, direct_finalization);
    assert_eq!(authorized.target_context_digest(), target.digest());
    assert_eq!(
        id(finalization, "transition_target_digest")?,
        id("suite-0001-target.bin", "target_context_digest")?
    );
    chain.bind_reinit_target(target.tbs())?;

    // The first attempt aborts; the retry carries the same target.
    for (sequence, receipt) in [
        (0, "advanced-record-08-attempt-0-receipt.bin"),
        (1, "advanced-record-10-attempt-1-receipt.bin"),
    ] {
        let object = format!("advanced-attempt-{sequence}.bin");
        let attempt = attempt(&object)?;
        assert_eq!(&attempt.target, target.tbs());
        authorized.check_attempt_target(&attempt, &target)?;
        let (old_binding, _) = old_authority()?;
        authorized.check_attempt(&attempt, &old_binding, &mut budget())?;
        authorized.check_initial_commit(
            &read(&format!("advanced-initial-commit-{sequence}.bin"))?,
            target.carried(),
            &mut budget(),
        )?;
        advance_attempt(&mut chain, receipt, &object)?;
        // No target binds while an attempt is open, even the same target.
        let open = chain.head().record_id;
        assert_eq!(
            chain.bind_reinit_target(target.tbs()),
            Err(E2eeError::InvalidValue)
        );
        assert_eq!(chain.head().record_id, open);
        if sequence == 0 {
            assert!(matches!(
                advance(&mut chain, "advanced-record-09-attempt-abort.bin")?,
                ChainStep::ReinitAborted { .. }
            ));
            // After the abort it binds again, before the retry opens.
            chain.bind_reinit_target(target.tbs())?;
        }
    }
    assert!(matches!(
        advance(&mut chain, "advanced-record-11-activation.bin")?,
        ChainStep::ReinitActivated { reinit_activation_id, .. }
            if reinit_activation_id == id("advanced-record-11-activation.bin", "semantic_id")?
    ));
    Ok(())
}

#[test]
fn malformed_or_mismatched_extension_lists_rebuild_no_target() -> TestResult {
    let proposal = Proposal::of(1)?;
    for (file, expected) in [
        (
            "reject-extensions-duplicate-context.bin",
            E2eeError::NonCanonical,
        ),
        (
            "reject-extensions-missing-required-capabilities.bin",
            E2eeError::InvalidValue,
        ),
        (
            "reject-extensions-context-core-mismatch.bin",
            E2eeError::InvalidValue,
        ),
        (
            "reject-extensions-later-joiner-context.bin",
            E2eeError::InvalidValue,
        ),
    ] {
        let extensions = read(file)?;
        let mut fields = proposal.fields();
        fields.encoded_extensions = &extensions;
        let refused = reconstruct(&fields)?;
        assert_eq!(refused, Err(expected), "{file}");
        assert_eq!(entry(file, "expected")?, format!("E2eeError::{expected:?}"));
    }
    Ok(())
}

#[test]
fn the_pinned_target_layout_names_no_authorized_target() -> TestResult {
    let file = "reject-target-pinned-layout.bin";
    let finalization_id = id(file, "finalization_id")?;
    assert_eq!(
        finalization_id,
        id(
            "suite-0001-record-03-reinit-finalization.bin",
            "semantic_id"
        )?
    );
    let authorized = AuthorizedReinit::from_proof(&finalization_proof(
        "suite-0001-record-03-reinit-finalization.bin",
    )?)?;
    // The old layout carried the very finalization ID its own authorization
    // commits: it does not decode as the corrected target, and no decoding of
    // it hashes to the authorized digest.
    let bytes = read(file)?;
    match ArcReInitTargetTbs::decode_exact(&bytes, &mut budget()) {
        Err(_) => {}
        Ok(decoded) => assert!(authorized.check_target(&decoded).is_err()),
    }
    Ok(())
}

#[test]
fn a_successor_initial_commit_naming_its_activation_is_refused() -> TestResult {
    let target = Proposal::of(1)?.reconstruct()?;
    let authorized = AuthorizedReinit::from_proof(&finalization_proof(
        "suite-0001-record-03-reinit-finalization.bin",
    )?)?;
    let file = "reject-initial-commit-names-activation.bin";
    assert_eq!(
        id(file, "prior_state_id")?,
        id("suite-0001-record-05-activation.bin", "semantic_id")?
    );
    assert_eq!(
        authorized.check_initial_commit(&read(file)?, target.carried(), &mut budget()),
        Err(E2eeError::InvalidValue)
    );
    Ok(())
}

#[test]
fn an_attempt_carrying_another_targets_digest_is_refused() -> TestResult {
    let mut chain = activated_chain()?;
    advance(&mut chain, "suite-0001-record-02-reinit-candidate.bin")?;
    advance(&mut chain, "suite-0001-record-03-reinit-finalization.bin")?;
    let receipt = "reject-other-digest-record-04-attempt-0-receipt.bin";
    let object = "reject-other-digest-attempt-0.bin";
    let attempt = attempt(object)?;
    assert_eq!(
        attempt.tbs.target_context_digest,
        id("suite-0003-target.bin", "target_context_digest")?
    );
    let authorized = AuthorizedReinit::from_proof(&finalization_proof(
        "suite-0001-record-03-reinit-finalization.bin",
    )?)?;
    // The attempt carries the target its digest names, but not the
    // authorized one: the sequencer, the endpoint and the chain refuse it.
    assert_eq!(attempt.target.encode()?, read("suite-0003-target.bin")?);
    let (old_binding, _) = old_authority()?;
    assert_eq!(
        authorized.check_attempt(&attempt, &old_binding, &mut budget()),
        Err(E2eeError::InvalidValue)
    );
    let target = Proposal::of(1)?.reconstruct()?;
    assert_eq!(
        authorized.check_attempt_target(&attempt, &target),
        Err(E2eeError::InvalidValue)
    );
    let head = *chain.head();
    assert!(advance_attempt(&mut chain, receipt, object).is_err());
    assert_eq!(chain.head(), &head);
    Ok(())
}

#[test]
fn an_attempt_carrying_another_target_than_the_authorized_one_is_refused() -> TestResult {
    let mut chain = activated_chain()?;
    advance(&mut chain, "suite-0001-record-02-reinit-candidate.bin")?;
    advance(&mut chain, "suite-0001-record-03-reinit-finalization.bin")?;
    let receipt = "reject-carried-target-record-04-attempt-0-receipt.bin";
    let object = "reject-carried-target-attempt-0.bin";
    let attempt = attempt(object)?;
    // The attempt names the authorized digest and the suite-1 target's
    // fields, but the target it carries is the suite-3 one.
    assert_eq!(
        attempt.tbs.target_context_digest,
        id("suite-0001-target.bin", "target_context_digest")?
    );
    assert_eq!(attempt.target.encode()?, read("suite-0003-target.bin")?);
    let authorized = AuthorizedReinit::from_proof(&finalization_proof(
        "suite-0001-record-03-reinit-finalization.bin",
    )?)?;
    let (old_binding, _) = old_authority()?;
    assert_eq!(
        authorized.check_attempt(&attempt, &old_binding, &mut budget()),
        Err(E2eeError::InvalidValue)
    );
    let target = Proposal::of(1)?.reconstruct()?;
    assert_eq!(
        authorized.check_attempt_target(&attempt, &target),
        Err(E2eeError::InvalidValue)
    );
    // A chain without a bound target refuses it because the carried bytes
    // do not hash to the digest; one that bound the target, because they
    // are not the bound bytes.
    let head = *chain.head();
    assert!(advance_attempt(&mut chain.clone(), receipt, object).is_err());
    chain.bind_reinit_target(target.tbs())?;
    assert!(advance_attempt(&mut chain, receipt, object).is_err());
    assert_eq!(chain.head(), &head);
    Ok(())
}

/// The facts of the old conversation's genesis binding, read from its
/// retained package without the rosters that verified it.
fn retained_facts() -> TestResult<ReinitPredecessor> {
    let bytes = read("genesis-binding.bin")?;
    let mut budget = budget();
    let object = ArcWireObject::decode_kind(
        &bytes,
        Some(ArcWireObjectKind::ConversationBinding),
        &mut budget,
    )?;
    let package =
        agenc_relay_e2ee::objects::conversation::ArcConversationBindingPackage::decode_exact(
            object.body(),
            &mut budget,
        )?;
    Ok(ReinitPredecessor::of_binding_tbs(&package.binding.tbs)?)
}

#[test]
fn the_facts_of_a_retained_binding_are_those_of_the_verified_binding() -> TestResult {
    let (binding, _) = old_authority()?;
    let facts = retained_facts()?;
    assert_eq!(facts, ReinitPredecessor::of_binding(&binding));
    // The facts of another binding of the conversation describe another
    // predecessor, which no successor in the vectors replaces.
    let target = Proposal::of(1)?.reconstruct()?;
    check_carried_target_from(&network()?, &facts, target.tbs(), &mut budget())?;
    let bytes = read("genesis-binding.bin")?;
    let mut budget = budget();
    let object = ArcWireObject::decode_kind(
        &bytes,
        Some(ArcWireObjectKind::ConversationBinding),
        &mut budget,
    )?;
    let package =
        agenc_relay_e2ee::objects::conversation::ArcConversationBindingPackage::decode_exact(
            object.body(),
            &mut budget,
        )?;
    let mut later = package.binding.tbs.clone();
    later.binding_generation += 1;
    let mut renamed = package.binding.tbs.clone();
    renamed.previous_binding_id = [9; 32];
    // A channel instance or a conversation nonce of another length names no
    // concrete route.
    for (name, edit) in [("instance", (true, false)), ("nonce", (false, true))] {
        let mut odd = package.binding.tbs.clone();
        if edit.0 {
            odd.channel_instance_id = agenc_relay_e2ee::Opaque::from_slice(&[1; 5])?;
        }
        if edit.1 {
            odd.conversation_nonce = agenc_relay_e2ee::Opaque::from_slice(&[1; 5])?;
        }
        assert!(ReinitPredecessor::of_binding_tbs(&odd).is_err(), "{name}");
    }
    for (name, tbs) in [("generation", &later), ("binding", &renamed)] {
        let other = ReinitPredecessor::of_binding_tbs(tbs)?;
        assert_ne!(other, facts, "{name}");
        assert!(
            check_carried_target_from(&network()?, &other, target.tbs(), &mut self::budget())
                .is_err(),
            "{name}"
        );
    }
    Ok(())
}
