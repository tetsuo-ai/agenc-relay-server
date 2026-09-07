//! BIND consumes a reservation only for the exact activated successor.

#![forbid(unsafe_code)]

mod reconstruction;

use super::*;
use agenc_ircd_domain::e2ee::ConversationId;
use agenc_ircd_e2ee::objects::conversation::IrcConversationBindingPackage;
use agenc_ircd_e2ee::tls::TlsEncode;

use super::super::super::INSTANCE;

const SUCCESSOR_GROUP: [u8; 32] = [11; 32];
const CONTEXT: [u8; 32] = [2; 32];

struct Fixture {
    harness: Harness,
    old: [u8; 32],
    new: [u8; 32],
    reservation: [u8; 16],
    package: IrcConversationBindingPackage,
    activation: Vec<u8>,
    activation_id: [u8; 32],
}

fn reserve(harness: &mut Harness) -> TestResult<[u8; 16]> {
    let mut params = INSTANCE.to_vec();
    params.push(5);
    params.extend_from_slice(b"#room");
    let ResultBody::Reserved(id, _) = ok(harness.run(Op::ReserveChannel, &params, None)?)?.result
    else {
        return Err("expected successor reservation".into());
    };
    Ok(id)
}

impl Fixture {
    fn prepare() -> TestResult<Self> {
        let mut harness = Harness::new()?;
        let old = harness.bind_channel()?;
        Self::prepare_bound(harness, old)
    }

    fn prepare_bound(mut harness: Harness, old: [u8; 32]) -> TestResult<Self> {
        let reservation = reserve(&mut harness)?;
        let old_state = *harness
            .coordinator
            .state
            .logs
            .get(&old)
            .ok_or("old log")?
            .accepted_state_id();
        let mut package = crate::e2ee::coordinator::ops::route_successor::binding(
            &harness.coordinator.state,
            &old,
        )?;
        let previous = semantic_id_of(SemanticHashDomain::BindingId, &package.binding.tbs)?;
        let new = agenc_ircd_e2ee::ids::conversation_id(&NETWORK, &SUCCESSOR_GROUP)?;
        package.binding.tbs.binding_generation = 1;
        package.binding.tbs.previous_binding_id = previous;
        package.binding.tbs.group_id = Opaque::from_slice(&SUCCESSOR_GROUP)?;
        package.binding.tbs.conversation_id = new;
        package.binding.approvals = TlsVec::new(Vec::new())?;
        package.root_binding_locks = TlsVec::new(Vec::new())?;
        let binding_id = semantic_id_of(SemanticHashDomain::BindingId, &package.binding.tbs)?;
        let (mut attempt, _) = attempt(&harness, old, old_state, 0)?;
        attempt.tbs.new_conversation_id = new;
        attempt.tbs.target_binding_id = binding_id;
        attempt.tbs.initial_member_plan_id = package.binding.tbs.initial_member_plan_id;
        attempt.authorization.tbs.new_conversation_id = new;
        attempt.authorization.tbs.target_binding_id = binding_id;
        attempt.authorization.tbs.initial_member_plan_id =
            package.binding.tbs.initial_member_plan_id;
        attempt.authorization.approvals = TlsVec::new(vec![commit_approval(
            &harness.principal,
            DEVICE,
            &attempt.authorization.tbs,
            SignatureDomain::CommitAuthorization,
        )?])?;
        attempt.tbs.attempt_authorization_id = semantic_id_of(
            SemanticHashDomain::ReinitAttemptAuthorizationId,
            &attempt.authorization.tbs,
        )?;
        let bytes = wire(IrcWireObjectKind::ReinitAttempt, &attempt)?;
        ok(harness.run(Op::SubmitReinitAttempt, &old, Some(&bytes))?)?;
        let receipt = staged_receipt(&harness, old)?;
        let (mut ack, _) = ack(old, old_state, receipt.tbs.reinit_attempt_id)?;
        ack.tbs.new_conversation_id = new;
        let core = IrcReInitActivationCoreTbs {
            profile_version: 1,
            network_id: NETWORK,
            old_conversation_id: old,
            new_conversation_id: new,
            old_reinit_state_id: old_state,
            attempt_sequence: 0,
            reinit_attempt_id: receipt.tbs.reinit_attempt_id,
            new_group_info_digest: [7; 32],
            new_group_context_digest: [8; 32],
            new_ratchet_tree_digest: [9; 32],
            new_exporter_authenticator: [10; 32],
            acknowledgement_set_digest: agenc_ircd_e2ee::ids::proof_set_digest(
                SemanticHashDomain::ReinitAcknowledgementSet,
                std::slice::from_ref(&ack.tbs),
            )?,
        };
        let activation_id = semantic_id_of(SemanticHashDomain::ReinitActivationId, &core)?;
        let vote = reinit_vote(
            &harness,
            DEVICE,
            &receipt,
            old_state,
            receipt.tbs.reinit_attempt_id,
            Terminal::finalize(activation_id),
        )?;
        let activation = wire(
            IrcWireObjectKind::ReinitActivationRequest,
            &IrcReInitActivationRequest {
                core,
                receipt,
                attempt,
                acknowledgements: TlsVec::new(vec![ack])?,
                votes: TlsVec::new(vec![vote])?,
            },
        )?;
        Ok(Self {
            harness,
            old,
            new,
            reservation,
            package,
            activation,
            activation_id,
        })
    }

    fn activate(&mut self) -> TestResult {
        ok(self
            .harness
            .run(Op::SubmitReinitActivate, &self.old, Some(&self.activation))?)?;
        Ok(())
    }

    fn bind(
        &mut self,
        package: &IrcConversationBindingPackage,
        context: [u8; 32],
    ) -> TestResult<
        Result<crate::e2ee::coordinator::request::Outcome, crate::e2ee::coordinator::ops::Fail>,
    > {
        let mut params = self.reservation.to_vec();
        params.extend_from_slice(&self.new);
        params.extend_from_slice(&context);
        let bytes = wire(IrcWireObjectKind::ConversationBinding, package)?;
        self.harness.run(Op::BindGroup, &params, Some(&bytes))
    }
}

#[test]
fn successor_bind_requires_activation_and_preserves_epoch_one_after_restart() -> TestResult {
    let mut fixture = Fixture::prepare()?;
    let package = fixture.package.clone();
    assert_eq!(
        code(fixture.bind(&package, CONTEXT)?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    fixture.activate()?;
    let bound = ok(fixture.bind(&package, CONTEXT)?)?;
    assert!(
        bound
            .events
            .iter()
            .any(|event| event.planned.kind == EventKind::RouteStateHidden
                && event.planned.conversation_id == Some(fixture.old))
    );
    let home = agenc_ircd_types::ServerId::from_bytes(super::super::super::HOME);
    assert!(
        !fixture
            .harness
            .coordinator
            .state
            .entitlements
            .entitled(home, &fixture.old)
    );
    assert!(
        fixture
            .harness
            .coordinator
            .state
            .entitlements
            .entitled(home, &fixture.new)
    );
    for reload in [false, true] {
        if reload {
            fixture.harness = fixture.harness.reloaded()?;
        }
        let state = &fixture.harness.coordinator.state;
        assert_eq!(
            state
                .routes
                .channel_route(&agenc_ircd_types::ChannelInstanceId::from_bytes(INSTANCE))
                .map(|route| route.conversation_id),
            Some(ConversationId(fixture.new))
        );
        let log = state.logs.get(&fixture.new).ok_or("successor log")?;
        assert_eq!(log.accepted_epoch(), 1);
        assert_eq!(log.accepted_state_id(), &fixture.activation_id);
        assert_eq!(log.head().record_id, fixture.activation_id);
        assert!(
            !state
                .lifecycles
                .get(&fixture.new)
                .ok_or("successor lifecycle")?
                .bootstrap_pending()
        );
        assert!(matches!(
            state.logs.get(&fixture.old).map(|log| log.phase()),
            Some(Phase::Migrated { .. })
        ));
    }
    let aad = agenc_ircd_e2ee::objects::aad::IrcCommitAad {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: fixture.new,
        route_binding: package.binding.tbs.route_binding,
        validation_time: 20,
        prior_state_id: fixture.activation_id,
    }
    .encode()?;
    let bytes = super::super::super::wire_raw(
        IrcWireObjectKind::CommitMls,
        super::super::super::support::private_message_at_epoch(&SUCCESSOR_GROUP, 1, 3, &aad)?,
    )?;
    ok(fixture
        .harness
        .run(Op::SubmitCandidate, &fixture.new, Some(&bytes))?)?;
    let prior = fixture
        .harness
        .coordinator
        .state
        .logs
        .get(&fixture.new)
        .cloned();
    fixture.harness = fixture.harness.reloaded()?;
    let state = &fixture.harness.coordinator.state;
    assert_eq!(state.logs.get(&fixture.new), prior.as_ref());
    assert_eq!(
        state
            .conversations
            .get(&fixture.new)
            .map(|value| value.context_digest),
        Some(CONTEXT)
    );
    assert!(
        !state
            .lifecycles
            .get(&fixture.new)
            .ok_or("successor lifecycle after candidate reload")?
            .bootstrap_pending()
    );
    Ok(())
}

#[test]
fn successor_bind_rejects_changed_target_and_keeps_the_reservation() -> TestResult {
    let mut fixture = Fixture::prepare()?;
    fixture.activate()?;
    let original = fixture.package.clone();
    assert_eq!(
        code(fixture.bind(&original, [99; 32])?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    for change in 0..5 {
        let mut package = original.clone();
        match change {
            0 => package.binding.tbs.group_id = Opaque::from_slice(&[91; 32])?,
            1 => package.binding.tbs.context_core_id = [92; 32],
            2 => package.binding.tbs.binding_generation = 2,
            3 => package.binding.tbs.previous_binding_id = [93; 32],
            _ => {
                package
                    .binding
                    .tbs
                    .semantic_route
                    .channel_authority_root_fingerprint = [94; 32]
            }
        }
        assert_eq!(
            code(fixture.bind(&package, CONTEXT)?),
            Some(E2eeReplyCode::BindingAuthInvalid)
        );
    }
    ok(fixture.bind(&original, CONTEXT)?)?;
    Ok(())
}

#[test]
fn successor_bind_rejects_a_different_reservation_owner() -> TestResult {
    let mut fixture = Fixture::prepare()?;
    fixture.activate()?;
    let original = fixture.harness.coordinator.state.routes.clone();
    let other = agenc_ircd_types::AccountId::from_random(
        agenc_ircd_types::AccountRandomId::from_bytes([99; 16]),
    );
    let mut routes = agenc_ircd_domain::e2ee::RouteTable::new();
    for route in original.routes() {
        routes.restore_entry(*route);
    }
    routes.reserve_successor(
        agenc_ircd_domain::e2ee::ReservationId(fixture.reservation),
        ConversationId(fixture.old),
        other,
        None,
        super::super::super::NOW + 60,
    )?;
    fixture.harness.coordinator.state.routes = routes;
    let package = fixture.package.clone();
    assert_eq!(
        code(fixture.bind(&package, CONTEXT)?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    fixture.harness.coordinator.state.routes = original;
    ok(fixture.bind(&package, CONTEXT)?)?;
    Ok(())
}

#[test]
fn successor_reservation_can_be_renewed_after_activation_and_restart() -> TestResult {
    let mut fixture = Fixture::prepare()?;
    fixture.activate()?;
    fixture.harness = fixture.harness.reloaded()?;
    fixture.reservation = reserve(&mut fixture.harness)?;
    let package = fixture.package.clone();
    ok(fixture.bind(&package, CONTEXT)?)?;
    Ok(())
}

#[test]
fn successor_reload_rejects_missing_activation_evidence() -> TestResult {
    use crate::state_core::durable::AccountServiceDurableWrite as Write;
    let mut fixture = Fixture::prepare()?;
    fixture.activate()?;
    let package = fixture.package.clone();
    ok(fixture.bind(&package, CONTEXT)?)?;
    let object = fixture
        .harness
        .coordinator
        .state
        .conversations
        .get(&fixture.old)
        .and_then(|state| state.records.last_key_value())
        .map(|(_, id)| *id)
        .ok_or("activation record")?;
    let key = agenc_ircd_storage::e2ee_records::object_key(&object)?;
    fixture.harness.writes.retain(|write| !matches!(write,
        Write::Put { table: agenc_ircd_storage::TableId::E2eeObject, key: present, .. } if *present == key));
    let restored = fixture.harness.reloaded()?;
    assert!(
        !restored
            .coordinator
            .state
            .conversations
            .contains_key(&fixture.new)
    );
    assert!(
        restored
            .coordinator
            .state
            .routes
            .route(&ConversationId(fixture.new))
            .is_none()
    );
    Ok(())
}
