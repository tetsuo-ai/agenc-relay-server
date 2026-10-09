#![forbid(unsafe_code)]

//! A closed route's next semantic incarnation (companion 9.4: "A later
//! incarnation increments by one and names the semantic close ID of the
//! prior incarnation"; companion 9.5: an ordinary new group bootstraps): the
//! generation-zero binding of a recreated route opens a chain only with the
//! terminal of the incarnation before it, which only a chain that adopted a
//! valid close yields (companion 11.5), then bootstraps and operates like
//! any genesis, and closes in turn for the incarnation after it.

use super::*;
use agenc_relay_e2ee::initial_authority::PriorTerminal;

const SECOND_GROUP: [u8; 32] = [26; 32];
const THIRD_GROUP: [u8; 32] = [27; 32];

/// The close intent every lineage here commits.
fn close_intent() -> ArcCloseIntent {
    ArcCloseIntent {
        reason_code: 1,
        validation_time: VALIDATION_TIME,
    }
}

/// Drives `genesis` from its bootstrap through its finalized closing
/// transition: the closing chain, and the log whose head is that
/// finalization.
fn closing(genesis: &Genesis) -> Result<(HistoricalChain, Log), E2eeError> {
    let (mut chain, mut log) = activated(genesis)?;
    let council = operational_council(genesis);
    let intent_id = semantic_id_of(SemanticHashDomain::CloseIntentId, &close_intent())?;
    let (candidate_record, candidate) = log.candidate([2; 32])?;
    adopt(&mut chain, &candidate_record)?;
    let tbs = log.authorization_tbs(
        &candidate,
        ArcCommitAuthorizationRule::ControlledTransition,
        action_bits::CLOSE_INTENT,
        log.policy_id,
        intent_id,
    );
    let (request, id) =
        log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
    let policy_id = log.policy_id;
    let record = log.finalization(request, id, policy_id)?;
    adopt(&mut chain, &record)?;
    Ok((chain, log))
}

/// The exact close of `genesis` after its closing transition: it names
/// the head finalization of `log` and carries the controller's approval
/// under the operational policy.
fn exact_close(genesis: &Genesis, log: &Log) -> Result<(Vec<u8>, [u8; 32]), E2eeError> {
    log.close(
        genesis.expected.binding_id,
        close_intent(),
        &operational_council(genesis),
    )
}

/// Drives `genesis` to its exact close and returns the closed chain, the
/// chain just before the close, and the close's complete wire object.
fn closed(genesis: &Genesis) -> Result<(HistoricalChain, HistoricalChain, Vec<u8>), E2eeError> {
    let (closing_chain, log) = closing(genesis)?;
    let (close, close_id) = exact_close(genesis, &log)?;
    let mut chain = closing_chain.clone();
    assert_eq!(chain.close(&close, &mut budget())?, close_id);
    Ok((chain, closing_chain, close))
}

/// The chain resumed at the retained state of `closing_chain`, as a
/// restored holder of that state resumes it (companion 13.7.2).
fn resumed_at(
    genesis: &Genesis,
    closing_chain: &HistoricalChain,
) -> Result<HistoricalChain, E2eeError> {
    HistoricalChain::resume(
        &NETWORK,
        &genesis.conversation,
        resumed_from(genesis, closing_chain)?,
        ChainLimits::DEFAULT,
    )
}

/// The terminal the retained closing state of `closing_chain` yields once
/// it adopts the exact retained `close`.
fn retained(
    genesis: &Genesis,
    closing_chain: &HistoricalChain,
    close: &[u8],
) -> Result<PriorTerminal, E2eeError> {
    let mut resumed = resumed_at(genesis, closing_chain)?;
    resumed.close(close, &mut budget())?;
    resumed.prior_terminal()
}

#[test]
fn a_closed_route_reopens_at_its_next_incarnation_and_operates() -> TestResult {
    let first = Genesis::new()?;
    let (closed_chain, closing_chain, close) = closed(&first)?;
    let prior = closed_chain.prior_terminal()?;
    let Lifecycle::Closed { close_id } = *closed_chain.lifecycle() else {
        return Err("the first lineage is closed".into());
    };
    assert_eq!(prior.close_id(), &close_id);
    assert_eq!(prior.conversation_id(), &first.conversation);
    assert_eq!(prior.binding_id(), &first.expected.binding_id);
    assert_eq!(prior.route().incarnation, 0);
    // The retained closing state, resumed, adopts the exact retained close
    // and yields the same terminal.
    assert_eq!(retained(&first, &closing_chain, &close)?, prior);

    let second = Genesis::recreated(SECOND_GROUP, &first, &prior)?;
    let authority = second.authority()?;
    assert_eq!(authority.prior_terminal(), Some(&prior));
    assert_eq!(authority.binding().route.incarnation, 1);
    assert_eq!(authority.binding().route.predecessor_close_id, close_id);
    // The recreated genesis bootstraps and operates like any genesis.
    // The terminal belongs to this network: the chain opens under it only.
    assert_eq!(
        HistoricalChain::open(
            &[9; 32],
            &second.conversation,
            &authority,
            ChainLimits::DEFAULT
        )
        .err(),
        Some(E2eeError::InvalidValue)
    );
    let mut chain = second.chain()?;
    assert!(chain.bootstrap_pending());
    assert_eq!(chain.lifecycle(), &Lifecycle::Active);
    assert_eq!(chain.head().record_id, second.genesis_id()?);
    let (activated_chain, mut log) = activated(&second)?;
    chain = activated_chain;
    assert!(!chain.bootstrap_pending());
    assert_eq!(chain.epoch(), 1);
    let council = operational_council(&second);
    let (candidate, finalization) = log.routine_step([3; 32], &council)?;
    adopt(&mut chain, &candidate)?;
    adopt(&mut chain, &finalization)?;
    assert_eq!(chain.epoch(), 2);
    assert_eq!(chain.accepted_state_id(), &finalization.id);

    // The recreated route closes in turn and opens incarnation two.
    let (closed_second, closing_second, second_close) = closed(&second)?;
    let second_prior = closed_second.prior_terminal()?;
    assert_eq!(
        retained(&second, &closing_second, &second_close)?,
        second_prior
    );
    assert_eq!(second_prior.route().incarnation, 1);
    let third = Genesis::recreated(THIRD_GROUP, &second, &second_prior)?;
    let third_authority = third.authority()?;
    assert_eq!(third_authority.binding().route.incarnation, 2);
    let (third_chain, _) = activated(&third)?;
    assert!(!third_chain.bootstrap_pending());
    Ok(())
}

#[test]
fn a_recreated_route_needs_the_exact_close_of_the_incarnation_before_it() -> TestResult {
    let first = Genesis::new()?;
    let (closed_chain, _, _) = closed(&first)?;
    let prior = closed_chain.prior_terminal()?;
    let second = Genesis::recreated(SECOND_GROUP, &first, &prior)?;
    // Missing: the genesis entry point refuses a later incarnation.
    let mut missing = Genesis::recreated(SECOND_GROUP, &first, &prior)?;
    missing.prior = None;
    assert_eq!(missing.authority().err(), Some(E2eeError::InvalidValue));

    // Wrong: the close of another lineage of the same route key.
    let other = Genesis::with_group([28; 32])?;
    let (other_chain, _, _) = closed(&other)?;
    let mut wrong = Genesis::recreated(SECOND_GROUP, &first, &prior)?;
    wrong.prior = Some(other_chain.prior_terminal()?);
    assert_eq!(wrong.authority().err(), Some(E2eeError::InvalidValue));

    // Skipped: incarnation two after the close of incarnation zero, and a
    // repeated incarnation zero naming that close.
    let recreated_once = second.authority()?;
    for incarnation in [2, 0] {
        let skipped = Genesis::recreated_at(THIRD_GROUP, &second, &prior, incarnation)?;
        assert_eq!(
            skipped.authority().err(),
            Some(E2eeError::InvalidValue),
            "incarnation {incarnation}"
        );
    }

    // A prior terminal is never an anchor for an incarnation-zero genesis.
    let mut genesis_with_prior = Genesis::with_group(SECOND_GROUP)?;
    genesis_with_prior.prior = Some(prior.clone());
    assert_eq!(
        genesis_with_prior.authority().err(),
        Some(E2eeError::InvalidValue)
    );

    // The closed conversation cannot be its own next incarnation.
    let same_group = Genesis::recreated(GROUP, &first, &prior)?;
    assert_eq!(same_group.authority().err(), Some(E2eeError::InvalidValue));
    assert_eq!(recreated_once.prior_terminal(), Some(&prior));
    Ok(())
}

#[test]
fn only_a_closed_lineage_yields_a_prior_terminal() -> TestResult {
    let genesis = Genesis::new()?;
    let chain = genesis.chain()?;
    assert_eq!(chain.prior_terminal().err(), Some(E2eeError::InvalidValue));
    let (activated_chain, _) = activated(&genesis)?;
    assert_eq!(
        activated_chain.prior_terminal().err(),
        Some(E2eeError::InvalidValue)
    );
    // A finalized closing transition is not yet a close.
    let (closing_chain, _) = closing(&genesis)?;
    assert_eq!(
        closing_chain.prior_terminal().err(),
        Some(E2eeError::InvalidValue)
    );
    let (closed_chain, _, _) = closed(&genesis)?;
    assert!(closed_chain.prior_terminal().is_ok());
    Ok(())
}

/// A close that names no finalization of a closing transition and that no
/// controller approved, beside one whose controller signature does not
/// verify and one naming another binding: none ends the lineage, so none
/// yields the terminal a next incarnation needs, whether the lineage is
/// still live, closing, or resumed from its retained closing state
/// (companion 11.5: close approvals "satisfy the last finalized policy's
/// controller rule, and reference the finalization ID of the exact in-group
/// active-to-closing transition").
#[test]
fn an_unapproved_close_yields_no_terminal_for_a_next_incarnation() -> TestResult {
    let first = Genesis::new()?;
    let intent_id = semantic_id_of(SemanticHashDomain::CloseIntentId, &close_intent())?;
    let tbs = |authorizing_terminal_id: [u8; 32]| ArcCloseAuthorizationTbs {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: first.conversation,
        binding_id: first.expected.binding_id,
        authorizing_terminal_id,
        close_intent: close_intent(),
        close_intent_id: intent_id,
    };
    let close_of = |tbs: ArcCloseAuthorizationTbs, approvals: Vec<ArcCommitApproval>| {
        object(
            ArcWireObjectKind::CloseAuthorization,
            &ArcCloseAuthorization {
                tbs,
                approvals: agenc_relay_e2ee::TlsVec::new(approvals)?,
            },
        )
    };
    // Signed by no device: a root that is not a controller, an unknown
    // device and certificate, and an empty signature.
    let unapproved = |authorizing_terminal_id: [u8; 32]| {
        close_of(
            tbs(authorizing_terminal_id),
            vec![ArcCommitApproval {
                signer_root_fingerprint: [1; 32],
                signer_device_id: [2; 16],
                signer_device_certificate_id: [3; 32],
                device_signature: [0; 64],
            }],
        )
    };
    // The live lineage: only its bootstrap finalized.
    let (mut live, _) = activated(&first)?;
    assert_eq!(
        live.close(&unapproved([0x5a; 32])?, &mut budget()).err(),
        Some(E2eeError::InvalidValue)
    );
    assert_eq!(live.lifecycle(), &Lifecycle::Active);
    assert_eq!(live.prior_terminal().err(), Some(E2eeError::InvalidValue));

    // The closing lineage, as opened and as resumed from its retained
    // closing state.
    let (closing_chain, log) = closing(&first)?;
    let head = closing_chain.head().record_id;
    let mut forged = operational_council(&first).approvals(
        &tbs(head),
        agenc_relay_crypto::SignatureDomain::CloseAuthorization,
    )?;
    for approval in &mut forged {
        approval.device_signature = [0; 64];
    }
    let refused = [
        (
            "no finalization, no approval",
            unapproved([0x5a; 32])?,
            E2eeError::InvalidValue,
        ),
        (
            "the head finalization, no approval",
            unapproved(head)?,
            E2eeError::InvalidValue,
        ),
        (
            "the controller's device without its signature",
            close_of(tbs(head), forged)?,
            E2eeError::SignatureInvalid,
        ),
        (
            "another binding",
            log.close([9; 32], close_intent(), &operational_council(&first))?
                .0,
            E2eeError::InvalidValue,
        ),
    ];
    for mut chain in [closing_chain.clone(), resumed_at(&first, &closing_chain)?] {
        for (name, close, error) in &refused {
            assert_eq!(
                chain.close(close, &mut budget()).err(),
                Some(*error),
                "{name}"
            );
            assert!(matches!(chain.lifecycle(), Lifecycle::Closing { .. }));
            assert_eq!(chain.prior_terminal().err(), Some(E2eeError::InvalidValue));
        }
        // Only the exact close ends the lineage, and its terminal opens the
        // next incarnation.
        let (close, close_id) = exact_close(&first, &log)?;
        assert_eq!(chain.close(&close, &mut budget())?, close_id);
        let prior = chain.prior_terminal()?;
        let second = Genesis::recreated(SECOND_GROUP, &first, &prior)?;
        assert_eq!(second.authority()?.binding().route.incarnation, 1);
    }
    Ok(())
}
