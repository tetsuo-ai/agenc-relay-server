#![forbid(unsafe_code)]

//! A chain opens only for the conversation its authority was pinned to, and
//! a close authorization must name this network and conversation.

use super::*;
use agenc_ircd_e2ee::TlsVec;

#[test]
fn a_chain_opens_only_for_the_conversation_its_authority_names() -> TestResult {
    let genesis = Genesis::new()?;
    let authority = genesis.authority()?;
    assert_eq!(
        HistoricalChain::open(&NETWORK, &[9; 32], &authority, ChainLimits::DEFAULT)
            .map(|_| ())
            .err(),
        Some(E2eeError::InvalidValue)
    );
    assert!(
        HistoricalChain::open(
            &NETWORK,
            &genesis.conversation,
            &authority,
            ChainLimits::DEFAULT
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn a_close_authorization_must_name_this_network_and_conversation() -> TestResult {
    let genesis = Genesis::new()?;
    let (mut chain, mut log) = activated(&genesis)?;
    let council = operational_council(&genesis);
    let intent = IrcCloseIntent {
        reason_code: 1,
        validation_time: VALIDATION_TIME,
    };
    let intent_id = semantic_id_of(SemanticHashDomain::CloseIntentId, &intent)?;
    let (candidate_record, candidate) = log.candidate([2; 32])?;
    adopt(&mut chain, &candidate_record)?;
    let tbs = log.authorization_tbs(
        &candidate,
        IrcCommitAuthorizationRule::ControlledTransition,
        action_bits::CLOSE_INTENT,
        log.policy_id,
        intent_id,
    );
    let (request, id) =
        log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
    let policy_id = log.policy_id;
    let record = log.finalization(request, id, policy_id)?;
    adopt(&mut chain, &record)?;
    assert!(matches!(chain.lifecycle(), Lifecycle::Closing { .. }));
    let head = *chain.head();
    let close = |network: [u8; 32], conversation: [u8; 32]| -> Result<Vec<u8>, E2eeError> {
        let tbs = IrcCloseAuthorizationTbs {
            profile_version: 1,
            network_id: network,
            conversation_id: conversation,
            binding_id: genesis.expected.binding_id,
            authorizing_terminal_id: head.record_id,
            close_intent: intent.clone(),
            close_intent_id: intent_id,
        };
        let approvals =
            council.approvals(&tbs, agenc_ircd_crypto::SignatureDomain::CloseAuthorization)?;
        object(
            IrcWireObjectKind::CloseAuthorization,
            &IrcCloseAuthorization {
                tbs,
                approvals: TlsVec::new(approvals)?,
            },
        )
    };
    for (name, bytes) in [
        ("another network", close([2; 32], genesis.conversation)?),
        ("another conversation", close(NETWORK, [9; 32])?),
    ] {
        assert!(chain.close(&bytes, &mut budget()).is_err(), "{name}");
        assert_eq!(*chain.head(), head, "{name}");
        assert!(
            matches!(chain.lifecycle(), Lifecycle::Closing { .. }),
            "{name}"
        );
    }
    let (honest, close_id) = log.close(genesis.expected.binding_id, intent, &council)?;
    assert_eq!(chain.close(&honest, &mut budget())?, close_id);
    Ok(())
}

#[test]
fn a_finalization_cannot_close_and_reinitialize_in_one_step() -> TestResult {
    let genesis = Genesis::new()?;
    let (mut chain, mut log) = activated(&genesis)?;
    let council = operational_council(&genesis);
    let (candidate_record, candidate) = log.candidate([2; 32])?;
    adopt(&mut chain, &candidate_record)?;
    let tbs = log.authorization_tbs(
        &candidate,
        IrcCommitAuthorizationRule::ControlledTransition,
        action_bits::CLOSE_INTENT | action_bits::REINIT,
        log.policy_id,
        [5; 32],
    );
    let (request, id) =
        log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
    let policy_id = log.policy_id;
    let record = log.finalization(request, id, policy_id)?;
    let head = *chain.head();
    assert!(adopt(&mut chain, &record).is_err());
    assert_eq!(*chain.head(), head);
    assert_eq!(chain.lifecycle(), &Lifecycle::Active);
    Ok(())
}

#[test]
fn a_finalization_core_must_repeat_the_authorized_result_digests() -> TestResult {
    let genesis = Genesis::new()?;
    let (mut chain, mut log) = activated(&genesis)?;
    let council = operational_council(&genesis);
    let (candidate_record, candidate) = log.candidate([2; 32])?;
    adopt(&mut chain, &candidate_record)?;
    let head = *chain.head();
    let policy_id = log.policy_id;
    for (name, context, tree) in [
        ("group context digest", true, false),
        ("ratchet tree digest", false, true),
    ] {
        let tbs = log.authorization_tbs(
            &candidate,
            IrcCommitAuthorizationRule::RoutineSelfUpdate,
            0,
            policy_id,
            [0; 32],
        );
        let (mut request, id) =
            log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
        if context {
            request.proof.core.resulting_group_context_digest = [7; 32];
        }
        if tree {
            request.proof.core.resulting_ratchet_tree_digest = [7; 32];
        }
        let record = log.clone_for_fork().finalization(request, id, policy_id)?;
        assert!(adopt(&mut chain, &record).is_err(), "{name}");
        assert_eq!(*chain.head(), head, "{name}");
    }
    Ok(())
}
