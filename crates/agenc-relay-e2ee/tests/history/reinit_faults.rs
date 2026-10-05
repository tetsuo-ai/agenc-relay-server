#![forbid(unsafe_code)]

//! A ReInit attempt must take the exact next slot of the reinit state and name a real
//! successor; an activation or abort must name the attempt that is open, and an abort needs
//! the council's quorum.

use super::*;
use agenc_relay_e2ee::ids::conversation_id;
use agenc_relay_e2ee::objects::reinit::{
    ArcReInitAbortCoreTbs, ArcReInitActivationCoreTbs, ArcReInitAttempt, ArcReInitAttemptReceipt,
    ArcReInitTargetTbs,
};

/// The digest of the target every harness attempt carries.
fn target() -> Result<[u8; 32], E2eeError> {
    let target = harness_target(conversation_id(&NETWORK, &GROUP)?, &[71; 32])?;
    semantic_id_of(SemanticHashDomain::ReinitTarget, &target)
}

/// The pending chain with attempt zero open, and the receipt and attempt that opened it.
type OpenAttempt = (
    Genesis,
    HistoricalChain,
    Log,
    [u8; 32],
    ArcReInitAttemptReceipt,
    ArcReInitAttempt,
);

/// One edit of an abort core.
type CoreEdit = (&'static str, fn(&mut ArcReInitAbortCoreTbs));

/// One edit of an activation core.
type ActivationEdit = (&'static str, fn(&mut ArcReInitActivationCoreTbs));

/// An activated chain moved into its ReInit lifecycle, with the reinit state id.
fn reinit_pending() -> Result<(Genesis, HistoricalChain, Log, [u8; 32]), E2eeError> {
    reinit_pending_with(target()?)
}

/// [`reinit_pending`] whose finalized authorization commits `target`.
fn reinit_pending_with(
    target: [u8; 32],
) -> Result<(Genesis, HistoricalChain, Log, [u8; 32]), E2eeError> {
    let genesis = Genesis::new()?;
    let (mut chain, mut log) = activated(&genesis)?;
    let council = operational_council(&genesis);
    let (candidate_record, candidate) = log.candidate([2; 32])?;
    adopt(&mut chain, &candidate_record)?;
    let tbs = log.authorization_tbs(
        &candidate,
        ArcCommitAuthorizationRule::ControlledTransition,
        action_bits::REINIT,
        log.policy_id,
        target,
    );
    let (request, id) =
        log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
    let policy_id = log.policy_id;
    let record = log.finalization(request, id, policy_id)?;
    adopt(&mut chain, &record)?;
    Ok((genesis, chain, log, record.id))
}

fn attempt_refused(chain: &HistoricalChain, attempt_bytes: &[u8], record: &Built) -> bool {
    let mut probe = chain.clone();
    let refused = probe
        .advance(
            &record.bytes,
            &RecordReferences {
                attempt_object: Some(attempt_bytes),
                ..RecordReferences::default()
            },
            &mut budget(),
        )
        .is_err();
    refused && probe.head() == chain.head()
}

#[test]
fn an_attempt_must_take_the_next_slot_and_name_a_real_successor() -> TestResult {
    let (genesis, chain, log, old_reinit_state_id) = reinit_pending()?;
    let council = operational_council(&genesis);
    let (bytes, record, _, _) =
        log.clone_for_fork()
            .reinit_attempt([9; 32], 0, target()?, &council)?;
    assert!(
        attempt_refused(&chain, &bytes, &record),
        "another reinit state"
    );
    let (bytes, record, _, _) =
        log.clone_for_fork()
            .reinit_attempt(old_reinit_state_id, 1, target()?, &council)?;
    assert!(
        attempt_refused(&chain, &bytes, &record),
        "a skipped attempt sequence"
    );
    let mut other_predecessor = log.clone_for_fork();
    other_predecessor.head = [9; 32];
    let (bytes, record, _, _) =
        other_predecessor.reinit_attempt(old_reinit_state_id, 0, target()?, &council)?;
    assert!(
        attempt_refused(&chain, &bytes, &record),
        "the first attempt must follow the reinit state itself"
    );
    let mut same_conversation = log.clone_for_fork();
    same_conversation.target = harness_target(log.conversation, &GROUP)?;
    let (bytes, record, _, _) =
        same_conversation.reinit_attempt(old_reinit_state_id, 0, target()?, &council)?;
    assert!(
        attempt_refused(&chain, &bytes, &record),
        "the successor cannot be the old conversation"
    );
    let mut log = log;
    let mut chain = chain;
    let (bytes, record, _, _) = log.reinit_attempt(old_reinit_state_id, 0, target()?, &council)?;
    chain.advance(
        &record.bytes,
        &RecordReferences {
            attempt_object: Some(&bytes),
            ..RecordReferences::default()
        },
        &mut budget(),
    )?;
    let (bytes, record, _, _) =
        log.clone_for_fork()
            .reinit_attempt(old_reinit_state_id, 1, target()?, &council)?;
    assert!(
        attempt_refused(&chain, &bytes, &record),
        "no second attempt while one is open"
    );
    Ok(())
}

fn open_attempt() -> Result<OpenAttempt, E2eeError> {
    let (genesis, mut chain, mut log, old_reinit_state_id) = reinit_pending()?;
    let council = operational_council(&genesis);
    let (bytes, record, receipt, attempt) =
        log.reinit_attempt(old_reinit_state_id, 0, target()?, &council)?;
    chain.advance(
        &record.bytes,
        &RecordReferences {
            attempt_object: Some(&bytes),
            ..RecordReferences::default()
        },
        &mut budget(),
    )?;
    Ok((genesis, chain, log, old_reinit_state_id, receipt, attempt))
}

#[test]
fn an_activation_for_an_attempt_that_is_not_open_is_refused() -> TestResult {
    let (genesis, chain, log, old_reinit_state_id, _, _) = open_attempt()?;
    let council = operational_council(&genesis);
    let mut fork = log.clone_for_fork();
    let (_, _, other_receipt, other_attempt) =
        fork.reinit_attempt(old_reinit_state_id, 1, target()?, &council)?;
    let activation =
        log.clone_for_fork()
            .reinit_activation(&other_receipt, &other_attempt, &council)?;
    let mut probe = chain.clone();
    assert!(adopt(&mut probe, &activation).is_err());
    assert!(!probe.is_terminal());
    Ok(())
}

#[test]
fn an_abort_core_must_name_the_open_attempt_and_reach_the_quorum() -> TestResult {
    let (genesis, chain, log, _, receipt, attempt) = open_attempt()?;
    let council = operational_council(&genesis);
    let edits: [CoreEdit; 5] = [
        ("old conversation", |core| {
            core.old_conversation_id = [9; 32]
        }),
        ("reinit state", |core| core.old_reinit_state_id = [9; 32]),
        ("attempt sequence", |core| core.attempt_sequence = 1),
        ("slot predecessor", |core| {
            core.slot_predecessor_record_id = [9; 32]
        }),
        ("attempt id", |core| core.reinit_attempt_id = [9; 32]),
    ];
    for (name, edit) in edits {
        let abort = log
            .clone_for_fork()
            .reinit_abort_with(&receipt, &attempt, 5, &council, edit)?;
        let mut probe = chain.clone();
        assert!(adopt(&mut probe, &abort).is_err(), "{name}");
        assert_eq!(probe.head(), chain.head(), "{name}");
    }
    let alone = Council {
        genesis: &genesis,
        approvers: vec![(0, 7)],
        voters: vec![(0, 7)],
    };
    let abort = log
        .clone_for_fork()
        .reinit_abort(&receipt, &attempt, 5, &alone)?;
    let mut probe = chain.clone();
    assert!(adopt(&mut probe, &abort).is_err(), "one vote is no quorum");
    let abort = log
        .clone_for_fork()
        .reinit_abort(&receipt, &attempt, 5, &council)?;
    let mut probe = chain.clone();
    assert!(matches!(
        adopt(&mut probe, &abort)?,
        ChainStep::ReinitAborted { .. }
    ));
    Ok(())
}

#[test]
fn an_activation_core_must_repeat_the_open_attempt_and_its_acknowledgements() -> TestResult {
    let (genesis, chain, log, _, receipt, attempt) = open_attempt()?;
    let council = operational_council(&genesis);
    let edits: [ActivationEdit; 3] = [
        ("new conversation", |core| {
            core.new_conversation_id = [9; 32]
        }),
        ("group info digest", |core| {
            core.new_group_info_digest = [9; 32]
        }),
        ("acknowledgement set", |core| {
            core.acknowledgement_set_digest = [9; 32]
        }),
    ];
    for (name, edit) in edits {
        let activation = log
            .clone_for_fork()
            .reinit_activation_with(&receipt, &attempt, &council, edit)?;
        let mut probe = chain.clone();
        assert!(adopt(&mut probe, &activation).is_err(), "{name}");
        assert_eq!(probe.head(), chain.head(), "{name}");
        assert!(!probe.is_terminal(), "{name}");
    }
    let activation = log
        .clone_for_fork()
        .reinit_activation(&receipt, &attempt, &council)?;
    let mut probe = chain.clone();
    assert!(matches!(
        adopt(&mut probe, &activation)?,
        ChainStep::ReinitActivated { .. }
    ));
    Ok(())
}

#[test]
fn an_attempt_must_carry_the_authorized_target_and_repeat_its_fields() -> TestResult {
    let (genesis, chain, log, old_reinit_state_id) = reinit_pending()?;
    let council = operational_council(&genesis);
    let authorized = target()?;
    let other = ArcReInitTargetTbs {
        target_binding_id: [9; 32],
        ..log.target.clone()
    };
    // The attempt names the authorized digest but carries another target.
    let (bytes, record, _, _) = log.clone_for_fork().reinit_attempt_carrying(
        old_reinit_state_id,
        0,
        authorized,
        &other,
        &council,
    )?;
    assert!(attempt_refused(&chain, &bytes, &record), "another target");
    // An attempt whose carried target is the authorized one but whose own
    // fields name another binding, under an authorization of that target.
    let digest = semantic_id_of(SemanticHashDomain::ReinitTarget, &other)?;
    let (genesis, chain, log, old_reinit_state_id) = reinit_pending_with(digest)?;
    let council = operational_council(&genesis);
    let (bytes, record, _, _) = log.clone_for_fork().reinit_attempt_carrying(
        old_reinit_state_id,
        0,
        digest,
        &other,
        &council,
    )?;
    assert!(attempt_refused(&chain, &bytes, &record), "other fields");
    Ok(())
}

#[test]
fn a_bound_target_must_name_its_own_successor_conversation() -> TestResult {
    let (genesis, chain, log, old_reinit_state_id) = reinit_pending()?;
    let council = operational_council(&genesis);
    // A chain that bound the authorized target adopts the attempt carrying
    // it, and refuses one carrying any other bytes, even bytes the
    // authorization does not name.
    let mut bound = chain.clone();
    bound.bind_reinit_target(&log.target)?;
    let (bytes, record, _, _) =
        log.clone_for_fork()
            .reinit_attempt(old_reinit_state_id, 0, target()?, &council)?;
    assert!(matches!(
        bound.clone().advance(
            &record.bytes,
            &RecordReferences {
                attempt_object: Some(&bytes),
                ..RecordReferences::default()
            },
            &mut budget(),
        )?,
        ChainStep::ReinitAttempted(_)
    ));
    let other = ArcReInitTargetTbs {
        target_context_core_id: [9; 32],
        ..log.target.clone()
    };
    let (bytes, record, _, _) = log.clone_for_fork().reinit_attempt_carrying(
        old_reinit_state_id,
        0,
        target()?,
        &other,
        &council,
    )?;
    assert!(attempt_refused(&bound, &bytes, &record));

    // A target whose successor conversation is not its group's, is the old
    // conversation, or whose group ID is not 32 bytes never binds, although
    // the finalized authorization committed exactly its digest.
    let conversation = conversation_id(&NETWORK, &GROUP)?;
    let target = log.target.clone();
    let cases = [
        (
            "not its group's conversation",
            ArcReInitTargetTbs {
                new_conversation_id: [70; 32],
                ..target.clone()
            },
        ),
        (
            "the old conversation",
            harness_target(conversation, &GROUP)?,
        ),
        (
            "a short group ID",
            ArcReInitTargetTbs {
                target_group_id: agenc_relay_e2ee::Opaque::new(vec![71; 31])?,
                ..target.clone()
            },
        ),
    ];
    for (name, bad) in cases {
        let digest = semantic_id_of(SemanticHashDomain::ReinitTarget, &bad)?;
        let (_, mut chain, _, _) = reinit_pending_with(digest)?;
        assert_eq!(
            chain.bind_reinit_target(&bad),
            Err(E2eeError::InvalidValue),
            "{name}"
        );
    }
    Ok(())
}
