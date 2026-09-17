//! Reload, retained-proof faults and resource refusal for public close admission.
#![forbid(unsafe_code)]
use super::*;
use crate::budget::{BackingReservationPort, MemoryBudget};
use crate::e2ee::coordinator::CompanionCoordinator;
use crate::e2ee::coordinator::tests::support::sequencer_credential;
use crate::sync::Arc;
use agenc_ircd_e2ee::sequencer::SequencerKeySet;

#[test]
fn a_valid_close_survives_reconstruction_and_its_tombstone_survives_another_reload() -> TestResult {
    let mut fixture = Fixture::ready(true)?;
    fixture.source = fixture.source.reloaded()?;
    let bytes = wire(IrcWireObjectKind::CloseAuthorization, &fixture.close)?;
    let mut parameters = fixture.conversation.to_vec();
    parameters.extend_from_slice(&fixture.close.tbs.close_intent.reason_code.to_be_bytes());
    let outcome = ok(fixture
        .source
        .run(Op::CloseGroup, &parameters, Some(&bytes))?)?;
    assert!(matches!(outcome.result, ResultBody::Closed { .. }));
    let expected = fixture
        .source
        .coordinator
        .state
        .logs
        .get(&fixture.conversation)
        .ok_or("closed log")?;
    assert!(matches!(
        expected.phase(),
        agenc_ircd_domain::e2ee::sequencer_log::Phase::Closed { .. }
    ));
    let restored = fixture.source.reloaded()?;
    assert_eq!(
        restored.coordinator.state.logs.get(&fixture.conversation),
        Some(expected)
    );
    assert!(
        !restored
            .coordinator
            .state
            .routes
            .route(&ConversationId(fixture.conversation))
            .ok_or("route")?
            .accepts_traffic()
    );
    Ok(())
}

#[test]
fn correctly_signed_close_context_substitutions_are_refused_before_effects() -> TestResult {
    for change in 0..4 {
        let mut fixture = Fixture::ready(true)?;
        let before = fixture
            .source
            .coordinator
            .state
            .logs
            .get(&fixture.conversation)
            .cloned()
            .ok_or("log")?;
        let writes = fixture.source.writes.len();
        match change {
            0 => fixture.close.tbs.network_id = [91; 32],
            1 => fixture.close.tbs.binding_id = [92; 32],
            2 => fixture.close.tbs.conversation_id = [93; 32],
            _ => fixture.close.tbs.authorizing_terminal_id = [94; 32],
        }
        fixture.sign_close()?;
        assert_eq!(
            code(fixture.evaluate()?),
            Some(E2eeReplyCode::BindingAuthInvalid)
        );
        assert_eq!(
            fixture
                .source
                .coordinator
                .state
                .logs
                .get(&fixture.conversation),
            Some(&before)
        );
        assert_eq!(fixture.source.writes.len(), writes);
    }
    Ok(())
}

#[test]
fn command_reason_must_match_the_signed_close_intent() -> TestResult {
    let mut fixture = Fixture::ready(true)?;
    let bytes = wire(IrcWireObjectKind::CloseAuthorization, &fixture.close)?;
    let mut parameters = fixture.conversation.to_vec();
    parameters.extend_from_slice(&2_u16.to_be_bytes());
    assert_eq!(
        code(evaluate_request(
            &mut fixture.source,
            Op::CloseGroup,
            &parameters,
            Some(&bytes)
        )?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    Ok(())
}

#[test]
fn missing_or_changed_retained_proof_owners_cannot_authorize_a_close() -> TestResult {
    for fault in 0..5 {
        let mut fixture = Fixture::ready(true)?;
        let state = &mut fixture.source.coordinator.state;
        let conversation = state
            .conversations
            .get_mut(&fixture.conversation)
            .ok_or("conversation")?;
        let terminal = fixture.close.tbs.authorizing_terminal_id;
        let proof = *conversation.proofs.get(&terminal).ok_or("proof")?;
        match fault {
            0 => {
                conversation.proofs.remove(&terminal);
            }
            1 => {
                state.objects.remove(&proof);
            }
            2 => {
                *state
                    .objects
                    .get_mut(&proof)
                    .ok_or("body")?
                    .first_mut()
                    .ok_or("byte")? ^= 1;
            }
            3 => {
                conversation
                    .policies
                    .remove(&conversation.current_policy_id);
            }
            _ => {
                let object = conversation
                    .policies
                    .get(&conversation.current_policy_id)
                    .ok_or("policy")?
                    .object_id;
                conversation.proofs.insert(terminal, object);
            }
        }
        assert_eq!(
            code(fixture.evaluate()?),
            Some(E2eeReplyCode::BindingAuthInvalid)
        );
    }
    Ok(())
}

#[test]
fn close_verification_refuses_memory_and_releases_its_temporary_reservation() -> TestResult {
    for capacity in [0, 2 * 1024 * 1024] {
        let mut fixture = Fixture::ready(true)?;
        let budget = Arc::new(MemoryBudget::new(capacity));
        fixture.source.backing = BackingReservationPort::new(budget.clone());
        let outcome = fixture.evaluate()?;
        if capacity == 0 {
            assert_eq!(code(outcome), Some(E2eeReplyCode::RateLimited));
        } else {
            assert!(matches!(ok(outcome)?.result, ResultBody::Closed { .. }));
        }
        assert_eq!(budget.charged(), 0);
    }
    Ok(())
}

/// A closed route is never live for signer purposes: its pin requires no
/// private signer and never blocks (companion 9.2.1).
#[test]
fn a_closed_route_pins_no_signer_at_startup() -> TestResult {
    let install_rotated = |coordinator: &mut CompanionCoordinator| -> TestResult {
        let old = sequencer_credential(&key(90), 0, (0, 2_000_000), None)?;
        let next = sequencer_credential(&key(91), 1, (100, 3_000_000), Some((&key(90), &old)))?;
        let head = agenc_ircd_e2ee::sequencer::verify_sequencer_credential(&NETWORK, &old, None)?;
        let set = SequencerKeySet::verify(&NETWORK, std::slice::from_ref(&next), 1, Some(&head))?;
        coordinator.install_sequencer(key(91), set, next)?;
        Ok(())
    };
    let mut fixture = Fixture::ready(true)?;
    // While the route is normal, a first startup under a set that omits its
    // pinned credential blocks the route and requires the retired signer.
    let mut open = fixture.source.reloaded_with(install_rotated)?;
    open.coordinator
        .next_restored_write(0)?
        .ok_or("the reconciliation")?
        .apply(&mut open.coordinator)?;
    assert_eq!(open.coordinator.blocked_routes(), 1);
    assert!(open.coordinator.signer_report().retired_missing);
    // Once closed, the same startup counts no pin for the route.
    let bytes = wire(IrcWireObjectKind::CloseAuthorization, &fixture.close)?;
    let mut parameters = fixture.conversation.to_vec();
    parameters.extend_from_slice(&fixture.close.tbs.close_intent.reason_code.to_be_bytes());
    let outcome = ok(fixture
        .source
        .run(Op::CloseGroup, &parameters, Some(&bytes))?)?;
    assert!(matches!(outcome.result, ResultBody::Closed { .. }));
    let mut closed = fixture.source.reloaded_with(install_rotated)?;
    closed
        .coordinator
        .next_restored_write(0)?
        .ok_or("the reconciliation")?
        .apply(&mut closed.coordinator)?;
    assert_eq!(closed.coordinator.blocked_routes(), 0);
    assert_eq!(
        closed.coordinator.signer_report(),
        crate::e2ee::coordinator::SignerReport::default()
    );
    Ok(())
}
