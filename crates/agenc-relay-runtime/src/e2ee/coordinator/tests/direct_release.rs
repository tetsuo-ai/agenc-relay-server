#![forbid(unsafe_code)]

//! Live release of a direct route projection and the cut that names only
//! hosted direct routes (companion 12.5, ENC-23). The scenarios run the
//! real coordinator and hand its rendered lines to the edge-side bridged
//! tests in `e2ee::edge::tests::direct_release_bridged`.

use std::collections::BTreeMap;

use agenc_relay_domain::e2ee::projection::{EntitlementReason, EventPlan};
use agenc_relay_domain::e2ee::{
    ConversationId, DirectPair, RecoveryState, RouteEntry, RouteLifecycle, RouteTarget,
    SemanticLockId,
};
use agenc_relay_e2ee::federation::frames::CompanionFrame;
use agenc_relay_e2ee::objects::conversation::ArcConversationKind;
use agenc_relay_e2ee::objects::federation::{ArcFederationRouteState, ArcRouteStateKind};
use agenc_relay_types::{AccountId, AccountRandomId};

use super::super::events::{render_copy, sequence_copies};
use super::super::sync::Action;
use super::super::{CompanionOrigin, CompanionOriginKey, ConversationState};
use super::sync::FakeHost;
use super::*;
use crate::federation::LinkId;

/// The direct conversation between two accounts other than the harness's.
pub(crate) const DIRECT: [u8; 32] = [0xd1; 32];
const REMOTE_ORIGIN: [u8; 16] = [21; 16];
const SERVER_NAME: &str = "coordinator.example";

/// What the coordinator sent to the home edge, as rendered text.
pub(crate) struct Bridged {
    /// The lines in the order they were sent.
    pub lines: Vec<String>,
    /// The `federation_state` object of [`DIRECT`].
    pub route: Vec<u8>,
    /// The hosted account of the pair, in wire form.
    pub hosted: [u8; 24],
}

fn account(seed: u8) -> TestResult<[u8; 24]> {
    let id = AccountId::from_random(AccountRandomId::from_bytes([seed; 16]));
    Ok(id.to_text().as_bytes().try_into()?)
}

fn pair() -> TestResult<([u8; 24], [u8; 24])> {
    let (first, second) = (account(60)?, account(61)?);
    Ok(if first <= second {
        (first, second)
    } else {
        (second, first)
    })
}

fn direct_route() -> TestResult<Vec<u8>> {
    let (first, second) = pair()?;
    let state = ArcFederationRouteState {
        profile_version: 1,
        network_id: NETWORK,
        state_generation: 4,
        conversation_id: DIRECT,
        conversation_kind: ArcConversationKind::Direct,
        route_binding: [26; 32],
        semantic_route_lock_id: [23; 32],
        channel_instance_id: Opaque::new(Vec::new())?,
        canonical_channel_name_hash: [0; 32],
        direct_account_a: Opaque::new(first.to_vec())?,
        direct_account_b: Opaque::new(second.to_vec())?,
        binding_id: [34; 32],
        finalized_epoch: 1,
        accepted_state_id: [58; 32],
        sequencer_record_head_sequence: 0,
        sequencer_record_head_id: [58; 32],
        state: ArcRouteStateKind::ActiveRoute,
    };
    wire(ArcWireObjectKind::FederationState, &state)
}

/// Retains [`DIRECT`] as a current direct route between the pair.
fn retain_direct(harness: &mut Harness) -> TestResult<Vec<u8>> {
    let route = direct_route()?;
    let (first, second) = pair()?;
    let state = &mut harness.coordinator.state;
    state.conversations.insert(
        DIRECT,
        ConversationState {
            direct_accounts: Some((first, second)),
            route_object_id: object_id(&route),
            ..ConversationState::default()
        },
    );
    state.objects.insert(object_id(&route), route.clone());
    state.routes.restore_entry(RouteEntry {
        conversation_id: ConversationId(DIRECT),
        target: RouteTarget::Direct(DirectPair::new(
            AccountId::parse_wire_bytes(&first)?,
            AccountId::parse_wire_bytes(&second)?,
        )?),
        lock: SemanticLockId([23; 32]),
        incarnation: 0,
        binding_id: [34; 32],
        binding_generation: 0,
        lifecycle: RouteLifecycle::Active,
        recovery: RecoveryState::Normal,
    });
    Ok(route)
}

fn remote_key() -> CompanionOriginKey {
    CompanionOriginKey {
        home_server_id: HOME,
        server_incarnation: INCARNATION,
        origin_id: REMOTE_ORIGIN,
    }
}

/// A second connection on the home edge: the first account of the pair
/// with an attached device.
fn host_remote(harness: &mut Harness) -> TestResult {
    let hosted = pair()?.0;
    let digest = agenc_relay_e2ee::ids::account_id_digest(&NETWORK, &hosted)?;
    harness.coordinator.state.origins.insert(
        remote_key(),
        CompanionOrigin {
            home_server_id: HOME,
            server_incarnation: INCARNATION,
            origin_id: REMOTE_ORIGIN,
            generation: 1,
            next_sequence: 0,
            account_id: Some(hosted),
            account_digest: Some(digest),
            device: Some(([9; 16], 1)),
            connection_nonce: [6; 32],
            connection_id: [13; 16],
            object_id: [0; 32],
            state_id: [0; 32],
            previous_state_id: [0; 32],
            suspended: false,
            fenced: false,
        },
    );
    Ok(())
}

fn host() -> FakeHost {
    let mut host = FakeHost::default();
    host.revision = STATE_GENERATION;
    host
}

/// The real `EORIGIN DEL` of the remote connection.
fn delete_remote(harness: &mut Harness) -> TestResult {
    let mut entropy = Counter(90);
    let _ack = harness
        .coordinator
        .on_frame(
            LinkId::new(1),
            ServerId::from_bytes(HOME),
            CompanionFrame::OriginDel {
                coordinator_server_id: COORDINATOR,
                server_incarnation: INCARNATION,
                origin_id: REMOTE_ORIGIN,
                origin_generation: 1,
                next_operation_sequence: 0,
            },
            5_000_000,
            &host(),
            &mut entropy,
        )
        .map_err(|fault| format!("EORIGIN DEL refused: {fault:?}"))?;
    Ok(())
}

/// One channel application by the harness's own attached origin: the
/// mutation plan a departing standing rides.
fn application(harness: &mut Harness, channel: [u8; 32], generation: u8) -> TestResult<Outcome> {
    let aad = ArcApplicationAad {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: channel,
        route_binding: channel_route_binding(&NETWORK, &INSTANCE)?,
        latest_state_id: [generation; 32],
    }
    .encode()?;
    let message = wire_raw(
        ArcWireObjectKind::ApplicationMls,
        private_message_bytes(&GROUP, 1, &aad)?,
    )?;
    let mut send = channel.to_vec();
    send.extend_from_slice(&INSTANCE);
    ok(harness.run(Op::ApplicationChannel, &send, Some(&message))?)
}

/// A harness with a bound, activated channel, a ready home edge, and the
/// direct route retained and hosted by the remote connection.
fn hosted() -> TestResult<(Harness, [u8; 32], Vec<u8>)> {
    let mut harness = Harness::new()?;
    let channel = harness.bind_channel()?;
    harness
        .coordinator
        .state
        .lifecycles
        .get_mut(&channel)
        .ok_or("the bound lifecycle")?
        .bootstrap_activated()?;
    let route = retain_direct(&mut harness)?;
    host_remote(&mut harness)?;
    Ok((harness, channel, route))
}

fn hidden(outcome: &Outcome) -> Vec<(ServerId, Option<[u8; 32]>)> {
    outcome
        .events
        .iter()
        .filter(|content| content.planned.kind == EventKind::RouteStateHidden)
        .map(|content| (content.planned.target, content.planned.conversation_id))
        .collect()
}

/// The rendered copies of `outcome` for the home edge, in delivery order.
fn home_lines(harness: &Harness, mut outcome: Outcome) -> TestResult<Vec<String>> {
    let plan = EventPlan::order(
        outcome
            .events
            .iter()
            .map(|content| content.planned.clone())
            .collect(),
    )?;
    outcome.events.sort_by_key(|content| {
        plan.events()
            .iter()
            .position(|planned| *planned == content.planned)
    });
    let mut entropy = Counter(120);
    let sequenced = sequence_copies(
        &harness.coordinator,
        &plan,
        &outcome.events,
        STATE_GENERATION,
        &mut entropy,
        &BTreeMap::new(),
        &harness.backing,
    )
    .map_err(|code| format!("{code:?}"))?;
    let mut lines = Vec::new();
    for copy in sequenced
        .copies
        .iter()
        .filter(|copy| copy.target == ServerId::from_bytes(HOME))
    {
        for line in render_copy(SERVER_NAME, copy).map_err(|code| format!("{code:?}"))? {
            lines.push(line.as_str().to_owned());
        }
    }
    Ok(lines)
}

/// Hosting ends on the live path: the remote connection is deleted and the
/// next mutation plan hides the route from the home edge and drops its
/// references. Returns what crossed the link.
pub(crate) fn hosting_ends_over_the_bridge() -> TestResult<Bridged> {
    let home = ServerId::from_bytes(HOME);
    let (mut harness, channel, route) = hosted()?;
    super::sync::initial_ready_peer(&mut harness.coordinator, home)?;
    harness.coordinator.state.entitlements.require_direct(
        home,
        DIRECT,
        EntitlementReason::Event,
    )?;
    // While the pair is hosted a plan leaves the standing alone.
    let quiet = application(&mut harness, channel, 1)?;
    assert!(hidden(&quiet).is_empty());
    assert!(
        harness
            .coordinator
            .state
            .entitlements
            .entitled(home, &DIRECT)
    );
    assert!(
        harness
            .coordinator
            .state
            .entitlements
            .departing(16)
            .is_empty()
    );
    // The real EORIGIN DEL marks the standing; nothing is released yet.
    delete_remote(&mut harness)?;
    assert_eq!(
        harness.coordinator.state.entitlements.departing(16),
        vec![(home, DIRECT)]
    );
    assert!(
        harness
            .coordinator
            .state
            .entitlements
            .entitled(home, &DIRECT)
    );
    // The next committed plan carries the removal and drops the references.
    let carrying = application(&mut harness, channel, 2)?;
    assert_eq!(hidden(&carrying), vec![(home, Some(DIRECT))]);
    assert!(
        !harness
            .coordinator
            .state
            .entitlements
            .entitled(home, &DIRECT)
    );
    assert!(
        harness
            .coordinator
            .state
            .entitlements
            .departing(16)
            .is_empty()
    );
    // A later plan has nothing more to hide.
    let lines = home_lines(&harness, carrying)?;
    let later = application(&mut harness, channel, 3)?;
    assert!(hidden(&later).is_empty());
    Ok(Bridged {
        lines,
        route,
        hosted: pair()?.0,
    })
}

/// Commits each staged page or owner of a cut until its first page goes out.
fn published(harness: &mut Harness, mut actions: Vec<Action>) -> TestResult<Vec<Action>> {
    use super::super::sync::{Committed, PendingWork};
    for _ in 0..agenc_relay_storage::e2ee_records::delivery_recovery::MAX_SNAPSHOT_PAGES + 2 {
        let staged = matches!(
            actions.as_slice(),
            [Action::Stage {
                work: PendingWork::Snapshot(_),
                ..
            }]
        );
        if !staged {
            break;
        }
        let Some(Action::Stage { work, .. }) = actions.into_iter().next() else {
            return Err("a staged page or owner".into());
        };
        harness.coordinator.set_pending(work);
        let Some(Committed::Snapshot(publication)) = harness.coordinator.batch_applied(Some(0))?
        else {
            return Err("the page or owner receipt".into());
        };
        actions =
            harness
                .coordinator
                .continue_snapshot_publication(*publication, 5_000_000, &host())?;
    }
    Ok(actions)
}

/// The first page of the cut a new scope receives, as rendered text.
fn cut_lines(harness: &mut Harness) -> TestResult<Vec<String>> {
    let mut entropy = Counter(60);
    let actions = harness
        .coordinator
        .on_frame(
            LinkId::new(1),
            ServerId::from_bytes(HOME),
            CompanionFrame::Resume {
                coordinator_server_id: COORDINATOR,
                server_incarnation: INCARNATION,
                delivery_generation: 0,
                last: None,
            },
            5_000_000,
            &host(),
            &mut entropy,
        )
        .map_err(|fault| format!("ERESUME refused: {fault:?}"))?;
    let actions = published(harness, actions)?;
    let mut lines = Vec::new();
    for action in &actions {
        let sent = match action {
            Action::Send(lines) => lines.as_slice(),
            Action::SendPage(output) => output.lines(),
            _ => continue,
        };
        lines.extend(sent.iter().map(|line| line.as_str().to_owned()));
    }
    Ok(lines)
}

/// An honest cut for an edge that hosts the first account of the pair: it
/// names the direct route, which the edge must accept.
pub(crate) fn hosted_cut_over_the_bridge() -> TestResult<Bridged> {
    let (mut harness, _channel, route) = hosted()?;
    let lines = cut_lines(&mut harness)?;
    assert!(
        harness
            .coordinator
            .state
            .entitlements
            .entitled(ServerId::from_bytes(HOME), &DIRECT)
    );
    Ok(Bridged {
        lines,
        route,
        hosted: pair()?.0,
    })
}

/// A reinstalled edge: the coordinator still holds a direct reference for
/// its Server ID, and the connection that hosted the pair is gone. The cut
/// of the new scope names no direct route.
pub(crate) fn reinstalled_cut_over_the_bridge() -> TestResult<Bridged> {
    let home = ServerId::from_bytes(HOME);
    let (mut harness, _channel, route) = hosted()?;
    harness.coordinator.state.entitlements.require_direct(
        home,
        DIRECT,
        EntitlementReason::Event,
    )?;
    harness.coordinator.state.origins.remove(&remote_key());
    let lines = cut_lines(&mut harness)?;
    assert!(
        !harness
            .coordinator
            .state
            .entitlements
            .entitled(home, &DIRECT)
    );
    Ok(Bridged {
        lines,
        route,
        hosted: pair()?.0,
    })
}

#[test]
fn a_departed_standing_is_hidden_by_the_next_plan_and_released_with_it() -> TestResult {
    let bridged = hosting_ends_over_the_bridge()?;
    assert!(bridged.lines.iter().any(|line| line.contains(" EEVENT ")));
    Ok(())
}

#[test]
fn a_standing_still_hosted_keeps_its_reference_and_leaves_the_queue() -> TestResult {
    let home = ServerId::from_bytes(HOME);
    let (mut harness, channel, _route) = hosted()?;
    super::sync::initial_ready_peer(&mut harness.coordinator, home)?;
    let entitlements = &mut harness.coordinator.state.entitlements;
    entitlements.require_direct(home, DIRECT, EntitlementReason::Event)?;
    entitlements.mark_departure(home);
    for generation in 1..=agenc_relay_domain::e2ee::projection::DEPARTING_DIRECT_LOOKS {
        assert_eq!(
            harness.coordinator.state.entitlements.departing(16).len(),
            1
        );
        let outcome = application(&mut harness, channel, generation)?;
        assert!(hidden(&outcome).is_empty());
    }
    assert!(
        harness
            .coordinator
            .state
            .entitlements
            .departing(16)
            .is_empty()
    );
    assert!(
        harness
            .coordinator
            .state
            .entitlements
            .entitled(home, &DIRECT)
    );
    Ok(())
}

#[test]
fn an_interrupted_cut_the_edge_no_longer_hosts_is_retired_not_republished() -> TestResult {
    let home = ServerId::from_bytes(HOME);
    let (mut harness, _channel, _route) = hosted()?;
    let first = cut_lines(&mut harness)?;
    assert!(first.iter().any(|line| line.contains(" ESTATE ENTRY ")));
    // The link drops; a resume while the pair is still hosted publishes the
    // same cut again.
    harness.coordinator.link_closed(home);
    let again = cut_lines(&mut harness)?;
    assert_eq!(again, first);
    // The hosting connection ends during the next outage: the cut that
    // names the pair is retired and a fresh one names no direct route.
    harness.coordinator.link_closed(home);
    if let Some(origin) = harness.coordinator.state.origins.get_mut(&remote_key()) {
        origin.fenced = true;
    }
    let fresh = cut_lines(&mut harness)?;
    assert!(fresh.iter().any(|line| line.contains(" ESTATE BEGIN ")));
    assert!(fresh.iter().all(|line| !line.contains(" ESTATE ENTRY ")));
    assert_ne!(fresh.first(), first.first());
    Ok(())
}
