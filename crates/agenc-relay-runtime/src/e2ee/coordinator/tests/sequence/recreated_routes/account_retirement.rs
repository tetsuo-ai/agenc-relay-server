#![forbid(unsafe_code)]

//! A verified initial binding and an account retirement are ordered by the same state core.
use super::*;
use crate::e2ee::coordinator::execute::{BaseView, OriginFacts, Staged};
use crate::e2ee::coordinator::sync::PendingWork;
use crate::e2ee::coordinator::tests::sync::initial_ready_peer;
use crate::e2ee::coordinator::tests::{HOME, NOW};
use crate::federation::LinkId;
use agenc_relay_e2ee::objects::federation::{ArcFederationResult, ArcFederationResultKind};

fn stage_first_binding(peer_exists: bool) -> TestResult {
    let mut harness = Harness::new()?;
    let home = agenc_relay_types::ServerId::from_bytes(HOME);
    initial_ready_peer(&mut harness.coordinator, home)?;
    harness.publish_identity_and_roster()?;
    harness.attach()?;
    let peer = direct_peer(&mut harness)?;
    let peer_id: [u8; 24] = peer.root.tbs.account_id.as_slice().try_into()?;
    let (grant, nonce) = ok_reservation(reserve_direct(&mut harness, &peer_id)?)?;
    let group = direct_group(&harness, &peer, (0, [0; 32]), nonce, DIRECT_GROUP)?;
    let mut parameters = grant.to_vec();
    parameters.extend_from_slice(&group.conversation);
    parameters.extend_from_slice(&[44; 32]);
    let complete = harness.request(Op::BindGroup, &parameters, Some(&group.bytes))?;

    let creator = AccountId::parse_wire_bytes(&harness.account)?;
    let participant = AccountId::parse_wire_bytes(&peer_id)?;
    let mut fixture = crate::test_support::StateCoreFixture::new(vec![0; 65_536])?;
    let context = fixture.context_mut()?;
    context.set_wall_for_test(NOW);
    let generation = agenc_relay_types::Generation::new(1)?;
    for account in [Some(creator), peer_exists.then_some(participant)]
        .into_iter()
        .flatten()
    {
        let plan = context
            .domain()
            .plan_account_created(agenc_relay_domain::AccountState::new(
                account,
                generation,
                context.domain().revision(),
            ))?;
        crate::test_support::apply_live_plan(context, plan)?;
    }
    let mut registered = crate::test_support::remote_session_seed(context, home, "creator")?;
    registered.account_id = Some(creator);
    registered.account_session_generation = generation;
    let user = registered.user_id;
    let plan = context.domain().plan_session_opened(registered)?;
    crate::test_support::apply_live_plan(context, plan)?;
    let view = BaseView {
        terminal_root_profile: false,
        context,
        peers: vec![home],
        base_capacity: Box::new(|_, _, _| true),
    };
    let staged = crate::e2ee::coordinator::execute::run(
        &mut harness.coordinator,
        view,
        LinkId::new(1),
        home,
        complete,
        &|_| OriginFacts {
            user_id: Some(user),
        },
    )
    .map_err(|code| format!("binding could not be staged: {code:?}"))?;
    assert!(matches!(staged, Staged::Batch));

    let Some(PendingWork::Request(pending)) = harness.coordinator.pending.as_ref() else {
        return Err("no original binding receipt was staged".into());
    };
    let mut budget = DecodeBudget::new(1 << 16, 4_096);
    let object = agenc_relay_e2ee::object::ArcWireObject::decode_kind(
        &pending.result,
        Some(ArcWireObjectKind::FederationResult),
        &mut budget,
    )?;
    let result = ArcFederationResult::decode_exact(object.body(), &mut budget)?;
    if peer_exists {
        assert_eq!(result.result_kind, ArcFederationResultKind::Bound);
        assert_eq!(
            pending.new_direct_binding,
            Some(DirectPair::new(creator, participant)?)
        );
    } else {
        assert_eq!(result.result_kind, ArcFederationResultKind::Failed);
        let encoded = result.encoded_result.as_slice();
        let length = usize::from(*encoded.first().ok_or("missing reply code")?);
        assert_eq!(
            encoded.get(1..=length),
            Some(b"E2EE_BINDING_AUTH_INVALID".as_slice())
        );
        assert_eq!(pending.new_direct_binding, None);
    }
    assert!(
        !harness
            .coordinator
            .state
            .routes
            .has_unclosed_direct(participant)
    );
    assert_eq!(
        harness
            .coordinator
            .blocks_account_deletion(fixture.context_mut()?, participant),
        peer_exists
    );
    assert!(
        harness
            .coordinator
            .blocks_account_deletion(fixture.context_mut()?, creator)
    );
    let unrelated = AccountId::parse_wire_bytes(&account_bytes(17)?)?;
    assert!(
        !harness
            .coordinator
            .blocks_account_deletion(fixture.context_mut()?, unrelated)
    );
    Ok(())
}

#[test]
fn staged_direct_binding_holds_its_confirmed_peer_before_the_route_is_published() -> TestResult {
    stage_first_binding(true)
}

#[test]
fn a_committed_peer_retirement_refuses_the_previously_reviewed_pair() -> TestResult {
    stage_first_binding(false)
}
