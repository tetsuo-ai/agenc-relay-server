#![forbid(unsafe_code)]

//! Historical verification with supplied leaf-membership facts (companion
//! 13.7.3): the same validated proofs that identify ACK signers on the
//! server authenticate every ACK a finalization or ReInit activation
//! embeds, without any MLS processing.

use super::*;

const CREATOR_LEAF: Leaf = (0, 7, CREATOR_LEAF_SEED, 0, [55; 32]);
const JOINER_LEAF: Leaf = (1, 9, JOINER_LEAF_SEED, 1, [66; 32]);

#[test]
fn supplied_membership_facts_authenticate_every_embedded_commit_ack() -> TestResult {
    let genesis = Genesis::new()?;
    let (mut chain, mut log) = activated(&genesis)?;
    let council = operational_council(&genesis);
    let (candidate, finalization) = log.routine_step([2; 32], &council)?;
    adopt(&mut chain, &candidate)?;
    let head = *chain.head();
    let empty = memberships(&genesis, &[])?;
    let wrong_key = memberships(&genesis, &[(0, 7, 152, 0, [55; 32])])?;
    let other_credential = memberships(&genesis, &[(0, 7, CREATOR_LEAF_SEED, 0, [54; 32])])?;
    for (name, facts) in [
        ("no stored proof", &empty),
        ("a proof under another leaf key", &wrong_key),
        ("a proof for another credential", &other_credential),
    ] {
        let references = RecordReferences {
            memberships: Some(facts),
            ..RecordReferences::default()
        };
        assert!(
            chain
                .advance(&finalization.bytes, &references, &mut budget())
                .is_err(),
            "{name}"
        );
        assert_eq!(*chain.head(), head, "{name}");
    }
    let facts = memberships(&genesis, &[CREATOR_LEAF])?;
    let step = chain.advance(
        &finalization.bytes,
        &RecordReferences {
            memberships: Some(&facts),
            ..RecordReferences::default()
        },
        &mut budget(),
    )?;
    assert!(matches!(step, ChainStep::Finalized { .. }));
    Ok(())
}

#[test]
fn supplied_membership_facts_bind_reinit_acks_to_their_plan_entries() -> TestResult {
    let genesis = Genesis::new()?;
    let (mut chain, mut log) = activated(&genesis)?;
    let council = operational_council(&genesis);
    let target = [72; 32];
    let (candidate_record, candidate) = log.candidate([2; 32])?;
    adopt(&mut chain, &candidate_record)?;
    let tbs = log.authorization_tbs(
        &candidate,
        IrcCommitAuthorizationRule::ControlledTransition,
        action_bits::REINIT,
        log.policy_id,
        target,
    );
    let (request, id) =
        log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
    let policy_id = log.policy_id;
    let record = log.finalization(request, id, policy_id)?;
    adopt(&mut chain, &record)?;
    let (attempt_bytes, receipt_record, receipt, attempt) =
        log.reinit_attempt(record.id, 0, target, &council)?;
    chain.advance(
        &receipt_record.bytes,
        &RecordReferences {
            attempt_object: Some(&attempt_bytes),
            ..RecordReferences::default()
        },
        &mut budget(),
    )?;
    let activation = log.reinit_activation(&receipt, &attempt, &council)?;
    let head = *chain.head();
    let missing_joiner = memberships(&genesis, &[CREATOR_LEAF])?;
    // Device 8 of the creator's account holds the joiner's leaf key, but the
    // plan's joiner entry names device 9 of the other account.
    let wrong_device = memberships(
        &genesis,
        &[CREATOR_LEAF, (0, 8, JOINER_LEAF_SEED, 1, [66; 32])],
    )?;
    for (name, facts) in [
        ("an omitted joiner proof", &missing_joiner),
        ("a joiner leaf held by another device", &wrong_device),
    ] {
        let references = RecordReferences {
            memberships: Some(facts),
            ..RecordReferences::default()
        };
        assert!(
            chain
                .advance(&activation.bytes, &references, &mut budget())
                .is_err(),
            "{name}"
        );
        assert_eq!(*chain.head(), head, "{name}");
    }
    let facts = memberships(&genesis, &[CREATOR_LEAF, JOINER_LEAF])?;
    let step = chain.advance(
        &activation.bytes,
        &RecordReferences {
            memberships: Some(&facts),
            ..RecordReferences::default()
        },
        &mut budget(),
    )?;
    assert!(matches!(step, ChainStep::ReinitActivated { .. }));
    Ok(())
}
