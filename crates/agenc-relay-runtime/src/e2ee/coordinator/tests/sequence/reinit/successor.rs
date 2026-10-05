//! A quorum-activated ReInit installs its successor in the activation's own
//! batch (companion 13.8): the old route remaps to the successor, whose
//! binding, published policy and pin are the target's, and which takes
//! candidates and application objects with no `EGROUP RESERVE` or
//! `EGROUP BIND`, also after a restart. A crash on either side of the
//! activation leaves the old route closed with its attempt pending or the
//! complete successor.

#![forbid(unsafe_code)]

mod declared_recovery;
mod previous_profile;
pub(in crate::e2ee::coordinator::tests::sequence) mod reconstruction;
mod row_mismatch;
mod target_mismatch;

use super::*;
use crate::e2ee::coordinator::ConversationState;
use agenc_relay_domain::e2ee::ConversationId;
use agenc_relay_domain::e2ee::lifecycle::Lifecycle;
use agenc_relay_domain::e2ee::sequencer_log::SequencerLog;
use agenc_relay_e2ee::tls::TlsEncode;
use agenc_relay_storage::e2ee_records::{RouteRow, SequencerRow, object_key};

use super::super::super::INSTANCE;

use super::super::reinit_successor::{SUCCESSOR_GROUP, Successor};
use crate::e2ee::coordinator::tests::object_id;

struct Fixture {
    harness: Harness,
    old: [u8; 32],
    new: [u8; 32],
    successor: Successor,
    activation: Vec<u8>,
    activation_id: [u8; 32],
}

impl Fixture {
    fn prepare() -> TestResult<Self> {
        let mut harness = Harness::new()?;
        let old = harness.bind_channel()?;
        Self::prepare_bound(harness, old)
    }

    /// Finalizes the ReInit Commit of the bound `old` and stages its attempt
    /// ([`Self::prepare_staged`]).
    fn prepare_bound(mut harness: Harness, old: [u8; 32]) -> TestResult<Self> {
        harness.finalize_reinit(old)?;
        Self::prepare_staged(harness, old)
    }

    /// Stages the attempt for the successor the finalized ReInit Commit of
    /// `old` authorized, with the attached device's creator ACK, and builds
    /// the activation request that completes it.
    fn prepare_staged(mut harness: Harness, old: [u8; 32]) -> TestResult<Self> {
        let successor = harness.reinit.clone().ok_or("the authorized successor")?;
        let old_state = *harness
            .coordinator
            .state
            .logs
            .get(&old)
            .ok_or("old log")?
            .accepted_state_id();
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
            successor,
            activation,
            activation_id,
        })
    }

    fn activate(&mut self) -> TestResult<crate::e2ee::coordinator::request::Outcome> {
        ok(self
            .harness
            .run(Op::SubmitReinitActivate, &self.old, Some(&self.activation))?)
    }

    /// The complete wire object of the binding package the activation
    /// installs.
    fn package_bytes(&self) -> TestResult<Vec<u8>> {
        wire(
            ArcWireObjectKind::ConversationBinding,
            &self.successor.package()?,
        )
    }

    /// The successor's context digest: the Section 2.2 hash of the context
    /// the target carries.
    fn context_digest(&self) -> TestResult<[u8; 32]> {
        Ok(semantic_id_of(
            SemanticHashDomain::ContextHash,
            &self.successor.context,
        )?)
    }

    /// A Commit candidate of the successor at its epoch one.
    fn successor_commit(&self, validation_time: u64) -> TestResult<Vec<u8>> {
        let aad = agenc_relay_e2ee::objects::aad::ArcCommitAad {
            profile_version: 1,
            network_id: NETWORK,
            conversation_id: self.new,
            route_binding: self.successor.context.route_binding,
            validation_time,
            prior_state_id: self.activation_id,
        }
        .encode()?;
        super::super::super::wire_raw(
            ArcWireObjectKind::CommitMls,
            super::super::super::support::private_message_at_epoch(&SUCCESSOR_GROUP, 1, 3, &aad)?,
        )
    }

    /// An application object of the successor, sent on the channel route.
    fn successor_application(&self) -> TestResult<(Vec<u8>, Vec<u8>)> {
        let aad = agenc_relay_e2ee::objects::aad::ArcApplicationAad {
            profile_version: 1,
            network_id: NETWORK,
            conversation_id: self.new,
            route_binding: self.successor.context.route_binding,
            latest_state_id: self.activation_id,
        }
        .encode()?;
        let message = super::super::super::wire_raw(
            ArcWireObjectKind::ApplicationMls,
            super::super::super::support::private_message_bytes(&SUCCESSOR_GROUP, 1, &aad)?,
        )?;
        let mut send = self.new.to_vec();
        send.extend_from_slice(&INSTANCE);
        Ok((send, message))
    }
}

/// The parts of the companion state an activation changes.
struct Snapshot {
    routes: agenc_relay_domain::e2ee::RouteTable,
    logs: std::collections::BTreeMap<[u8; 32], SequencerLog>,
    lifecycles: std::collections::BTreeMap<[u8; 32], Lifecycle>,
    conversations: std::collections::BTreeMap<[u8; 32], ConversationState>,
}

fn snapshot(harness: &Harness) -> Snapshot {
    let state = &harness.coordinator.state;
    Snapshot {
        routes: state.routes.clone(),
        logs: state.logs.clone(),
        lifecycles: state.lifecycles.clone(),
        conversations: state.conversations.clone(),
    }
}

/// The installed facts of a conversation a restart must reproduce. A
/// conversation bound with `EGROUP BIND` keeps the context digest that
/// command carried only in memory, so `bound` leaves it out.
fn installed(state: &ConversationState, bound: bool) -> impl PartialEq + std::fmt::Debug {
    (
        (
            state.binding_object_id,
            state.binding,
            state.context_core_id,
            (!bound).then_some(state.context_digest),
            state.cipher_suite,
            state.group_id.clone(),
        ),
        (
            state.route_binding,
            state.lock_id,
            state.channel_name_hash,
            state.direct_accounts,
            state.sequencer_credential_id,
            state.principal_accounts.clone(),
        ),
        (
            state.initial_policy_id,
            state.required_operational_policy_id,
            state.current_policy_id,
            state.policies.clone(),
            state.predecessor_close_id,
            state.route_object_id,
            state.reinit,
        ),
    )
}

#[test]
fn an_activation_installs_its_successor_which_takes_traffic_without_bind() -> TestResult {
    let mut fixture = Fixture::prepare()?;
    let outcome = fixture.activate()?;
    let keys: Vec<_> = outcome
        .writes
        .iter()
        .filter_map(|write| {
            write
                .encoded_record()
                .map(|(table, key, _)| (table, key.clone()))
        })
        .collect();
    let package = fixture.package_bytes()?;
    let policy = wire(ArcWireObjectKind::Policy, &fixture.successor.context.policy)?;
    let policy_id = semantic_id_of(
        SemanticHashDomain::PolicyId,
        &fixture.successor.context.policy.tbs,
    )?;
    // The activation's own batch carries every successor row.
    for (table, key) in [
        (
            agenc_relay_storage::TableId::E2eeState,
            RouteRow::key(&fixture.new)?,
        ),
        (
            agenc_relay_storage::TableId::E2eeState,
            SequencerRow::policy_key(&fixture.new, &policy_id)?,
        ),
        (
            agenc_relay_storage::TableId::E2eeObject,
            object_key(&object_id(&package))?,
        ),
        (
            agenc_relay_storage::TableId::E2eeObject,
            object_key(&object_id(&policy))?,
        ),
    ] {
        assert!(keys.contains(&(table, key)));
    }
    let event = |kind, conversation| {
        outcome.events.iter().any(|event| {
            event.planned.kind == kind && event.planned.conversation_id == Some(conversation)
        })
    };
    assert!(event(EventKind::RouteStateHidden, fixture.old));
    assert!(event(EventKind::RouteStateChanged, fixture.new));
    let live = snapshot(&fixture.harness);
    let home = agenc_relay_types::ServerId::from_bytes(super::super::super::HOME);
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
            Some(ConversationId(fixture.new)),
            "reload {reload}"
        );
        if !reload {
            // The delivery entitlements move to the successor (a restart
            // rebuilds them as the edges declare again).
            assert!(!state.entitlements.entitled(home, &fixture.old));
            assert!(state.entitlements.entitled(home, &fixture.new));
        }
        assert_eq!(
            state.logs.get(&fixture.new),
            Some(&SequencerLog::from_activation(
                fixture.new,
                fixture.activation_id
            ))
        );
        assert_eq!(
            state.lifecycles.get(&fixture.new),
            live.lifecycles.get(&fixture.new)
        );
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
        let successor = state
            .conversations
            .get(&fixture.new)
            .ok_or("successor state")?;
        assert_eq!(successor.binding_object_id, object_id(&package));
        assert_eq!(successor.binding, fixture.successor.binding_id);
        // The context digest is the hash of the target's context, never
        // the digest of the target itself.
        assert_eq!(successor.context_digest, fixture.context_digest()?);
        assert_ne!(successor.context_digest, fixture.successor.digest);
        assert!(successor.policies.contains_key(&policy_id));
        assert_eq!(successor.current_policy_id, policy_id);
        assert_eq!(
            successor.sequencer_credential_id,
            fixture.harness.pinned_credential()
        );
        // A restart restores what the activation installed.
        for (conversation, bound) in [(fixture.old, true), (fixture.new, false)] {
            assert_eq!(
                state
                    .conversations
                    .get(&conversation)
                    .map(|state| installed(state, bound)),
                live.conversations
                    .get(&conversation)
                    .map(|state| installed(state, bound)),
                "conversation {conversation:?}, reload {reload}"
            );
        }
        assert_eq!(state.routes, live.routes, "reload {reload}");
    }
    // Ordinary traffic, with no reservation or binding.
    let (send, message) = fixture.successor_application()?;
    assert_eq!(
        ok(fixture
            .harness
            .run(Op::ApplicationChannel, &send, Some(&message))?)?
        .result,
        ResultBody::AcceptedEvent
    );
    let commit = fixture.successor_commit(70)?;
    ok(fixture
        .harness
        .run(Op::SubmitCandidate, &fixture.new, Some(&commit))?)?;
    let prior = fixture
        .harness
        .coordinator
        .state
        .logs
        .get(&fixture.new)
        .cloned();
    fixture.harness = fixture.harness.reloaded()?;
    assert_eq!(
        fixture.harness.coordinator.state.logs.get(&fixture.new),
        prior.as_ref()
    );
    Ok(())
}

#[test]
fn a_crash_on_either_side_of_the_activation_leaves_the_attempt_pending_or_the_successor()
-> TestResult {
    let mut fixture = Fixture::prepare()?;
    // The activation is decided but its batch never commits: a restart
    // finds the old route closed with its attempt pending and no part of
    // the successor.
    let staged = super::super::recovery_pending::evaluate_request(
        &mut fixture.harness,
        Op::SubmitReinitActivate,
        &fixture.old,
        Some(&fixture.activation),
    )?;
    assert!(matches!(
        staged.map(|outcome| outcome.result),
        Ok(ResultBody::ReinitActivated(..))
    ));
    let mut crashed = fixture.harness.reloaded()?;
    let state = &crashed.coordinator.state;
    let log = state.logs.get(&fixture.old).ok_or("old log")?;
    assert!(matches!(log.phase(), Phase::Reinit { .. }));
    assert!(log.reinit_attempt().is_some());
    assert!(!state.conversations.contains_key(&fixture.new));
    assert!(!state.logs.contains_key(&fixture.new));
    assert!(!state.lifecycles.contains_key(&fixture.new));
    assert!(state.routes.route(&ConversationId(fixture.new)).is_none());
    assert_eq!(
        state
            .routes
            .channel_route(&agenc_relay_types::ChannelInstanceId::from_bytes(INSTANCE))
            .map(|route| route.conversation_id),
        Some(ConversationId(fixture.old))
    );
    // The same activation then completes, and after its batch commits a
    // restart finds the whole successor.
    ok(crashed.run(
        Op::SubmitReinitActivate,
        &fixture.old,
        Some(&fixture.activation),
    )?)?;
    let live = snapshot(&crashed);
    let restarted = crashed.reloaded()?;
    let state = &restarted.coordinator.state;
    assert_eq!(state.routes, live.routes);
    assert_eq!(state.logs.get(&fixture.new), live.logs.get(&fixture.new));
    assert_eq!(
        state
            .conversations
            .get(&fixture.new)
            .map(|state| installed(state, false)),
        live.conversations
            .get(&fixture.new)
            .map(|state| installed(state, false))
    );
    Ok(())
}

#[test]
fn the_successor_is_never_reserved_or_bound() -> TestResult {
    let mut fixture = Fixture::prepare()?;
    fixture.activate()?;
    let mut reserve = INSTANCE.to_vec();
    reserve.push(5);
    reserve.extend_from_slice(b"#room");
    assert_eq!(
        code(fixture.harness.run(Op::ReserveChannel, &reserve, None)?),
        Some(E2eeReplyCode::GroupConflict)
    );
    let mut bind = [7; 16].to_vec();
    bind.extend_from_slice(&fixture.new);
    bind.extend_from_slice(&fixture.context_digest()?);
    let package = fixture.package_bytes()?;
    let before = fixture.harness.coordinator.state.conversations.clone();
    assert_eq!(
        code(fixture.harness.run(Op::BindGroup, &bind, Some(&package))?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    assert_eq!(fixture.harness.coordinator.state.conversations, before);
    Ok(())
}

#[test]
fn an_activation_that_cannot_install_its_successor_retains_nothing() -> TestResult {
    // Without the recorded authority of its ReInit, the activation is
    // refused as finality required.
    let mut fixture = Fixture::prepare()?;
    if let Some(old) = fixture
        .harness
        .coordinator
        .state
        .conversations
        .get_mut(&fixture.old)
    {
        old.reinit = None;
    }
    let before = snapshot(&fixture.harness);
    assert_eq!(
        code(fixture.harness.run(
            Op::SubmitReinitActivate,
            &fixture.old,
            Some(&fixture.activation)
        )?),
        Some(E2eeReplyCode::FinalityRequired)
    );
    assert_eq!(fixture.harness.coordinator.state.logs, before.logs);
    assert_eq!(fixture.harness.coordinator.state.routes, before.routes);
    // A successor pinned to a credential this coordinator does not issue
    // receipts under is not installed.
    let mut harness = Harness::new()?;
    let old = harness.bind_channel()?;
    let foreign = super::super::super::support::sequencer_credential(
        &super::super::super::support::key(77),
        0,
        (0, 4_000_000_000),
        None,
    )?;
    let plan = super::super::reinit_successor::creator_plan(&harness)?;
    let successor = super::super::reinit_successor::successor_pinned(
        &harness,
        old,
        plan,
        SUCCESSOR_GROUP,
        foreign,
    )?;
    harness.finalize_commit(
        old,
        super::super::reinit_successor::Authorized::reinit(successor.digest),
        &[super::super::reinit_successor::LEAF_ZERO],
    )?;
    harness.reinit = Some(successor);
    let mut fixture = Fixture::prepare_staged(harness, old)?;
    let before = snapshot(&fixture.harness);
    let writes = fixture.harness.writes.len();
    assert_eq!(
        code(fixture.harness.run(
            Op::SubmitReinitActivate,
            &fixture.old,
            Some(&fixture.activation)
        )?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    assert_eq!(fixture.harness.coordinator.state.logs, before.logs);
    assert_eq!(fixture.harness.coordinator.state.routes, before.routes);
    assert_eq!(
        fixture.harness.coordinator.state.conversations,
        before.conversations
    );
    assert_eq!(fixture.harness.writes.len(), writes);
    Ok(())
}

#[test]
fn an_activation_whose_successor_does_not_verify_retains_nothing() -> TestResult {
    // The successor policy's approval does not verify: the sequencer's
    // attempt check, which does not verify the policy (an endpoint does),
    // admits the attempt, and the activation installs nothing.
    let mut harness = Harness::new()?;
    let old = harness.bind_channel()?;
    let sequencer = harness
        .coordinator
        .current_credential()
        .cloned()
        .ok_or("the harness sequencer credential")?;
    let plan = super::super::reinit_successor::creator_plan(&harness)?;
    let successor = super::super::reinit_successor::successor_edited(
        &harness,
        old,
        plan,
        SUCCESSOR_GROUP,
        sequencer,
        |policy| {
            let mut approvals = policy.approvals.as_slice().to_vec();
            let approval = approvals.first_mut().ok_or("a policy approval")?;
            approval.device_signature[0] ^= 1;
            policy.approvals = TlsVec::new(approvals)?;
            Ok(())
        },
    )?;
    harness.finalize_commit(
        old,
        super::super::reinit_successor::Authorized::reinit(successor.digest),
        &[super::super::reinit_successor::LEAF_ZERO],
    )?;
    harness.reinit = Some(successor);
    let mut fixture = Fixture::prepare_staged(harness, old)?;
    refused_activation(&mut fixture, E2eeReplyCode::BindingAuthInvalid)
}

/// Publishes a roster that continues the harness principal's and returns
/// the identifier of the roster the bindings name.
fn move_roster_on(fixture: &mut Fixture) -> TestResult<[u8; 32]> {
    let principal = &fixture.harness.principal;
    let named = super::super::super::support::roster_id(&principal.roster)?;
    let certificates = principal
        .roster
        .tbs
        .active_devices
        .as_slice()
        .iter()
        .map(|entry| entry.certificate.clone())
        .collect();
    let next = super::super::super::support::roster(
        &principal.root_secret,
        &principal.root,
        1,
        named,
        (100, 100 + 6 * 24 * 3600),
        certificates,
        Vec::new(),
    )?;
    let bytes = wire(ArcWireObjectKind::DeviceRoster, &next)?;
    ok(fixture.harness.run(Op::PublishRoster, &[], Some(&bytes))?)?;
    Ok(named)
}

#[test]
fn an_activation_checks_the_bindings_under_the_rosters_they_name() -> TestResult {
    // The principal's roster moves on after the attempt: the old and the
    // successor binding still name the original roster, whose retained
    // snapshot verifies them, and the activation installs the successor.
    let mut fixture = Fixture::prepare()?;
    move_roster_on(&mut fixture)?;
    let outcome = fixture.activate()?;
    assert!(matches!(outcome.result, ResultBody::ReinitActivated(..)));
    assert!(
        fixture
            .harness
            .coordinator
            .state
            .conversations
            .contains_key(&fixture.new)
    );
    // Without that snapshot the old binding cannot be checked again, and
    // nothing is installed.
    let mut fixture = Fixture::prepare()?;
    let named = move_roster_on(&mut fixture)?;
    let object = fixture
        .harness
        .coordinator
        .state
        .roster_snapshots
        .get(&named)
        .copied()
        .ok_or("the named roster snapshot")?;
    assert!(
        fixture
            .harness
            .coordinator
            .state
            .objects
            .remove(&object)
            .is_some()
    );
    refused_activation(&mut fixture, E2eeReplyCode::BindingAuthInvalid)
}

#[test]
fn an_activation_rechecks_its_attempt_under_bounded_work() -> TestResult {
    // An authority of another finalization recorded for the old group: the
    // activation checks its attempt against the recorded authority again
    // and installs nothing.
    let mut fixture = Fixture::prepare()?;
    let mut other = Harness::new()?;
    let elsewhere = other.bind_channel()?;
    other.activate_bootstrap(elsewhere)?;
    other.finalize_reinit(elsewhere)?;
    let foreign = other
        .coordinator
        .state
        .conversations
        .get(&elsewhere)
        .ok_or("other state")?
        .reinit;
    if let Some(old) = fixture
        .harness
        .coordinator
        .state
        .conversations
        .get_mut(&fixture.old)
    {
        old.reinit = foreign;
    }
    refused_activation(&mut fixture, E2eeReplyCode::BindingAuthInvalid)?;
    // An exhausted work memory budget is refused before any check.
    let mut fixture = Fixture::prepare()?;
    let budget = std::sync::Arc::new(crate::budget::MemoryBudget::new(0));
    fixture.harness.backing = crate::budget::BackingReservationPort::new(budget.clone());
    refused_activation(&mut fixture, E2eeReplyCode::RateLimited)?;
    assert_eq!(budget.charged(), 0);
    Ok(())
}

/// Submits the fixture's activation, requires the refusal `expected`, and
/// requires that nothing was retained.
fn refused_activation(fixture: &mut Fixture, expected: E2eeReplyCode) -> TestResult {
    let before = snapshot(&fixture.harness);
    let writes = fixture.harness.writes.len();
    assert_eq!(
        code(fixture.harness.run(
            Op::SubmitReinitActivate,
            &fixture.old,
            Some(&fixture.activation)
        )?),
        Some(expected)
    );
    let after = snapshot(&fixture.harness);
    assert_eq!(after.logs, before.logs);
    assert_eq!(after.routes, before.routes);
    assert_eq!(after.conversations, before.conversations);
    assert_eq!(fixture.harness.writes.len(), writes);
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
fn successor_reload_rejects_missing_activation_evidence() -> TestResult {
    use crate::state_core::durable::AccountServiceDurableWrite as Write;
    let mut fixture = Fixture::prepare()?;
    fixture.activate()?;
    let object = fixture
        .harness
        .coordinator
        .state
        .conversations
        .get(&fixture.old)
        .and_then(|state| state.records.last_key_value())
        .map(|(_, id)| *id)
        .ok_or("activation record")?;
    let key = object_key(&object)?;
    fixture.harness.writes.retain(|write| !matches!(write,
        Write::Put { table: agenc_relay_storage::TableId::E2eeObject, key: present, .. } if *present == key));
    // Both routes declare their recovery epoch; missing activation evidence
    // refuses the whole reconstruction before either gate is installed.
    assert!(fixture.harness.reloaded().is_err());
    Ok(())
}

#[test]
fn a_restored_successor_keeps_no_bootstrap_whatever_the_read_order() -> TestResult {
    let mut fixture = Fixture::prepare()?;
    fixture.activate()?;
    fixture.harness.writes.reverse();
    let restored = fixture.harness.reloaded()?;
    let state = &restored.coordinator.state;
    assert_eq!(
        state
            .routes
            .channel_route(&agenc_relay_types::ChannelInstanceId::from_bytes(INSTANCE))
            .map(|route| route.conversation_id),
        Some(ConversationId(fixture.new))
    );
    assert_eq!(
        state.lifecycles.get(&fixture.new),
        Some(&Lifecycle::restore(
            agenc_relay_domain::e2ee::lifecycle::RecoveryGate::Normal,
            false,
            false
        ))
    );
    Ok(())
}
