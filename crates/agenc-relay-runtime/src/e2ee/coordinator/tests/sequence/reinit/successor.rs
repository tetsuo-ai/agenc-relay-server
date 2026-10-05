//! BIND consumes a reservation only for the exact activated successor.

#![forbid(unsafe_code)]

mod declared_recovery;
pub(in crate::e2ee::coordinator::tests::sequence) mod reconstruction;
mod row_mismatch;
mod target_mismatch;

use super::*;
use agenc_relay_domain::e2ee::ConversationId;
use agenc_relay_e2ee::objects::conversation::ArcConversationBindingPackage;
use agenc_relay_e2ee::tls::TlsEncode;

use super::super::super::INSTANCE;

use super::super::reinit_successor::SUCCESSOR_GROUP;

struct Fixture {
    harness: Harness,
    old: [u8; 32],
    new: [u8; 32],
    reservation: [u8; 16],
    package: ArcConversationBindingPackage,
    activation: Vec<u8>,
    activation_id: [u8; 32],
    /// The context digest a successor BIND names: the authorized target's.
    context: [u8; 32],
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

    fn prepare_bound(harness: Harness, old: [u8; 32]) -> TestResult<Self> {
        Self::prepare_bound_with(harness, old, |_, _| Ok(()))
    }

    /// [`Self::prepare_bound`] with `edit` applied to the successor package the
    /// BIND carries; the activated attempt targets the authorized successor.
    fn prepare_bound_with(
        mut harness: Harness,
        old: [u8; 32],
        edit: fn(&mut ArcConversationBindingPackage, [u8; 32]) -> TestResult,
    ) -> TestResult<Self> {
        let reservation = reserve(&mut harness)?;
        harness.finalize_reinit(old)?;
        let successor = harness.reinit.clone().ok_or("the authorized successor")?;
        let old_state = *harness
            .coordinator
            .state
            .logs
            .get(&old)
            .ok_or("old log")?
            .accepted_state_id();
        let mut package = successor.package()?;
        edit(&mut package, old)?;
        let new = successor.conversation;
        let (attempt, bytes) = attempt(&harness, old, old_state, 0)?;
        ok(harness.run(Op::SubmitReinitAttempt, &old, Some(&bytes))?)?;
        let receipt = staged_receipt(&harness, old)?;
        let (mut ack, _) = ack(old, old_state, receipt.tbs.reinit_attempt_id)?;
        ack.tbs.new_conversation_id = new;
        let ack = signed_reinit_ack(ack, crate::e2ee::coordinator::tests::LEAF_SEED)?;
        let core = ArcReInitActivationCoreTbs {
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
            acknowledgement_set_digest: agenc_relay_e2ee::ids::proof_set_digest(
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
            ArcWireObjectKind::ReinitActivationRequest,
            &ArcReInitActivationRequest {
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
            context: successor.digest,
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
        package: &ArcConversationBindingPackage,
        context: [u8; 32],
    ) -> TestResult<
        Result<crate::e2ee::coordinator::request::Outcome, crate::e2ee::coordinator::ops::Fail>,
    > {
        let mut params = self.reservation.to_vec();
        params.extend_from_slice(&self.new);
        params.extend_from_slice(&context);
        let bytes = wire(ArcWireObjectKind::ConversationBinding, package)?;
        self.harness.run(Op::BindGroup, &params, Some(&bytes))
    }
}

#[test]
fn successor_bind_requires_activation_and_preserves_epoch_one_after_restart() -> TestResult {
    let mut fixture = Fixture::prepare()?;
    let package = fixture.package.clone();
    assert_eq!(
        code(fixture.bind(&package, fixture.context)?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    fixture.activate()?;
    let bound = ok(fixture.bind(&package, fixture.context)?)?;
    assert!(
        bound
            .events
            .iter()
            .any(|event| event.planned.kind == EventKind::RouteStateHidden
                && event.planned.conversation_id == Some(fixture.old))
    );
    let home = agenc_relay_types::ServerId::from_bytes(super::super::super::HOME);
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
                .channel_route(&agenc_relay_types::ChannelInstanceId::from_bytes(INSTANCE))
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
    let aad = agenc_relay_e2ee::objects::aad::ArcCommitAad {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: fixture.new,
        route_binding: package.binding.tbs.route_binding,
        validation_time: 20,
        prior_state_id: fixture.activation_id,
    }
    .encode()?;
    let bytes = super::super::super::wire_raw(
        ArcWireObjectKind::CommitMls,
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
        Some(fixture.context)
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
fn an_activation_ends_the_reinit_phase_and_its_authorized_target() -> TestResult {
    let mut fixture = Fixture::prepare()?;
    let authorized = fixture
        .harness
        .coordinator
        .state
        .conversations
        .get(&fixture.old)
        .ok_or("old state")?
        .reinit;
    assert!(authorized.is_some());
    fixture.activate()?;
    let old_state = *fixture
        .harness
        .coordinator
        .state
        .logs
        .get(&fixture.old)
        .ok_or("old log")?
        .accepted_state_id();
    let (_, bytes) = attempt(&fixture.harness, fixture.old, old_state, 1)?;
    for reload in [false, true] {
        if reload {
            fixture.harness = fixture.harness.reloaded()?;
        }
        // The migrated group keeps no authority, live and after a restart.
        let state = &mut fixture.harness.coordinator.state;
        let old = state.conversations.get_mut(&fixture.old).ok_or("old")?;
        assert_eq!(old.reinit, None, "reload {reload}");
        // An attempt on it is refused as finality required, even with the
        // authorized target of its ReInit put back.
        old.reinit = authorized;
        assert_eq!(
            code(
                fixture
                    .harness
                    .run(Op::SubmitReinitAttempt, &fixture.old, Some(&bytes))?
            ),
            Some(E2eeReplyCode::FinalityRequired),
            "reload {reload}"
        );
    }
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
            code(fixture.bind(&package, fixture.context)?),
            Some(E2eeReplyCode::BindingAuthInvalid)
        );
    }
    ok(fixture.bind(&original, fixture.context)?)?;
    Ok(())
}

#[test]
fn successor_bind_rejects_a_different_reservation_owner() -> TestResult {
    let mut fixture = Fixture::prepare()?;
    fixture.activate()?;
    let original = fixture.harness.coordinator.state.routes.clone();
    let other = agenc_relay_types::AccountId::from_random(
        agenc_relay_types::AccountRandomId::from_bytes([99; 16]),
    );
    let mut routes = agenc_relay_domain::e2ee::RouteTable::new();
    for route in original.routes() {
        routes.restore_entry(*route);
    }
    routes.reserve_successor(
        agenc_relay_domain::e2ee::ReservationId(fixture.reservation),
        ConversationId(fixture.old),
        other,
        None,
        super::super::super::NOW + 60,
    )?;
    fixture.harness.coordinator.state.routes = routes;
    let package = fixture.package.clone();
    assert_eq!(
        code(fixture.bind(&package, fixture.context)?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    fixture.harness.coordinator.state.routes = original;
    ok(fixture.bind(&package, fixture.context)?)?;
    Ok(())
}

#[test]
fn successor_reservation_can_be_renewed_after_activation_and_restart() -> TestResult {
    let mut fixture = Fixture::prepare()?;
    fixture.activate()?;
    fixture.harness = fixture.harness.reloaded()?;
    fixture.reservation = reserve(&mut fixture.harness)?;
    let package = fixture.package.clone();
    ok(fixture.bind(&package, fixture.context)?)?;
    Ok(())
}

#[test]
fn successor_reload_rejects_missing_activation_evidence() -> TestResult {
    use crate::state_core::durable::AccountServiceDurableWrite as Write;
    let mut fixture = Fixture::prepare()?;
    fixture.activate()?;
    let package = fixture.package.clone();
    ok(fixture.bind(&package, fixture.context)?)?;
    let object = fixture
        .harness
        .coordinator
        .state
        .conversations
        .get(&fixture.old)
        .and_then(|state| state.records.last_key_value())
        .map(|(_, id)| *id)
        .ok_or("activation record")?;
    let key = agenc_relay_storage::e2ee_records::object_key(&object)?;
    fixture.harness.writes.retain(|write| !matches!(write,
        Write::Put { table: agenc_relay_storage::TableId::E2eeObject, key: present, .. } if *present == key));
    // Both bound routes now declare their recovery epoch; missing activation
    // evidence refuses the whole reconstruction before either gate is installed.
    assert!(fixture.harness.reloaded().is_err());
    Ok(())
}

/// One edit of the successor package before the attempt targets it.
type PackageEdit = (
    &'static str,
    fn(&mut ArcConversationBindingPackage, [u8; 32]) -> TestResult,
);

#[test]
fn successor_bind_rejects_a_targeted_package_that_does_not_continue_the_lineage() -> TestResult {
    let edits: [PackageEdit; 6] = [
        ("a skipped generation", |package, _| {
            package.binding.tbs.binding_generation = 2;
            Ok(())
        }),
        ("another predecessor", |package, _| {
            package.binding.tbs.previous_binding_id = [93; 32];
            Ok(())
        }),
        ("another route binding", |package, _| {
            package.binding.tbs.route_binding = [95; 32];
            Ok(())
        }),
        ("another channel instance", |package, _| {
            package.binding.tbs.channel_instance_id = Opaque::from_slice(&[96; 16])?;
            Ok(())
        }),
        ("another conversation nonce", |package, _| {
            package.binding.tbs.conversation_nonce = Opaque::from_slice(&[97; 32])?;
            Ok(())
        }),
        ("the old conversation itself", |package, old| {
            package.binding.tbs.conversation_id = old;
            Ok(())
        }),
    ];
    let mut reached = 0;
    for (name, edit) in edits {
        let mut harness = Harness::new()?;
        let old = harness.bind_channel()?;
        let Ok(mut fixture) = Fixture::prepare_bound_with(harness, old, edit) else {
            // The attempt itself refused the target; the bind is never reached.
            continue;
        };
        if fixture.activate().is_err() {
            continue;
        }
        reached += 1;
        let package = fixture.package.clone();
        assert_eq!(
            code(fixture.bind(&package, fixture.context)?),
            Some(E2eeReplyCode::BindingAuthInvalid),
            "{name}"
        );
    }
    assert!(
        reached >= 5,
        "every lineage field but the old conversation reaches the bind"
    );
    Ok(())
}
