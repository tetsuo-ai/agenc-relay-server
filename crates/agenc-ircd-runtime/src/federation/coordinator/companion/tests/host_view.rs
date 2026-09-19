//! The base facts the companion executor mirrors, the gates it may adopt, and the
//! link writes it may make, each checked against the owner's own tables.
#![forbid(unsafe_code)]

use agenc_ircd_domain::federation::{OriginBinding, OriginEntry, OriginPrincipal};
use agenc_ircd_storage::e2ee_records::delivery_recovery::{
    BarrierEndpoint, DeliveryBarrier, DeliveryBarrierFields, DeliveryScope, DeliveryScopeFields,
};
use agenc_ircd_types::{
    AccountId, AccountRandomId, ConnectionId, EventId, Generation, SessionId, UserId,
};

use super::*;
use crate::bridge::crypto::ChannelKeyVerifierRecord;
use crate::e2ee::coordinator::CompanionCoordinator;
use crate::federation::coordinator::{CoordinatorConfig, LiveLink};
use crate::federation::link::{LinkQueue, link_queue};
use crate::test_support::{StateCoreFixture, TestResult};
use agenc_ircd_e2ee::federation::frames::Correlation;

const NAME: &str = "coordinator.example";
const PEER: ServerId = ServerId::from_bytes([50; 16]);
const STRANGER: ServerId = ServerId::from_bytes([99; 16]);
const LINK: LinkId = LinkId::new(11);
const INCARNATION: ServerIncarnation = ServerIncarnation::from_bytes([51; 16]);

fn owner(core: &StateCoreFixture, executor: bool) -> TestResult<FederationCoordinator> {
    let identity = &core.identity;
    let mut coordinator = FederationCoordinator::new(
        CoordinatorConfig {
            network_id: identity.network_id,
            server_id: identity.server_id,
            server_name: NAME.into(),
            recovery_epoch: identity.recovery_epoch,
            query_cursor_key: [21; 32],
            process_nonce: [22; 16],
            outbox_bytes_per_edge: 1 << 20,
            outbox_objects_per_edge: 64,
        },
        vec![crate::federation::PeerIdentity::new(
            PEER,
            "edge.example",
            agenc_ircd_types::FederationRole::Edge,
            identity.recovery_epoch,
            agenc_ircd_crypto::Ed25519SecretKey::from_bytes([9; 32]).public_key(),
            [8; 32],
        )],
        std::sync::Arc::new(crate::test_support::TestChannelKeyVerifier),
        ChannelKeyVerifierRecord::new([7; 16], [1; 32]),
    );
    if executor {
        coordinator.install_companion_executor(
            CompanionCoordinator::new(
                *identity.network_id.as_bytes(),
                identity.server_id,
                NAME.into(),
            ),
            identity.server_incarnation,
        )?;
    }
    Ok(coordinator)
}

fn go_live(coordinator: &mut FederationCoordinator, capacity: u64) -> TestResult<LinkQueue> {
    let (handle, queue) = link_queue(capacity);
    let state = coordinator.peers.get_mut(&PEER).ok_or("peer")?;
    state.live = Some(LiveLink {
        link: LINK,
        handle,
        incarnation: INCARNATION,
    });
    Ok(queue)
}

fn account(seed: u8) -> AccountId {
    AccountId::from_random(AccountRandomId::from_bytes([seed; 16]))
}

fn account_text(account: AccountId) -> TestResult<[u8; 24]> {
    Ok(account.to_text().as_bytes().try_into()?)
}

fn origin_key(seed: u8) -> OriginKey {
    OriginKey {
        home_server_id: PEER,
        server_incarnation: INCARNATION,
        origin_id: OriginId::from_bytes([seed; 16]),
    }
}

fn companion_key(key: &OriginKey) -> CompanionOriginKey {
    CompanionOriginKey {
        home_server_id: *key.home_server_id.as_bytes(),
        server_incarnation: *key.server_incarnation.as_bytes(),
        origin_id: *key.origin_id.as_bytes(),
    }
}

fn declare(
    coordinator: &mut FederationCoordinator,
    seed: u8,
    status: OriginStatus,
    held: Option<AccountId>,
) -> TestResult<OriginKey> {
    let key = origin_key(seed);
    let account = match held {
        Some(account) => Some((account, Generation::new(3)?)),
        None => None,
    };
    coordinator.origins.restore_origin(
        key,
        OriginEntry {
            generation: 2,
            next_sequence: 5,
            object_id: [1; 32],
            binding: OriginBinding {
                connection_id: ConnectionId::from_bytes([seed; 16]),
                connection_nonce: [seed; 32],
            },
            principal: OriginPrincipal {
                session: Some((
                    SessionId::from_bytes([seed; 16]),
                    UserId::from_bytes([seed; 16]),
                )),
                account,
            },
            status,
            deleted_after: None,
        },
    );
    Ok(key)
}

fn host<'a>(
    coordinator: &'a FederationCoordinator,
    context: &StateCoreContext,
    peer: ServerId,
) -> HostView<'a> {
    HostView {
        trusted_ack_unix_seconds: None,
        backing: context.backing_reservations(),
        origins: &coordinator.origins,
        peers: &coordinator.peers,
        revision: 12,
        peer,
        held_channels: BTreeSet::from([[30; 16]]),
    }
}

#[tokio::test]
async fn only_a_live_base_origin_is_mirrored_with_its_exact_principal() -> TestResult {
    let mut core = StateCoreFixture::new(vec![1; 256])?;
    let mut coordinator = owner(&core, false)?;
    let held = account(40);
    let live = declare(&mut coordinator, 60, OriginStatus::Live, Some(held))?;
    let anonymous = declare(&mut coordinator, 61, OriginStatus::Live, None)?;
    let fenced = declare(&mut coordinator, 62, OriginStatus::Fenced, Some(held))?;
    let suspended = declare(&mut coordinator, 63, OriginStatus::Suspended, None)?;
    let view = host(&coordinator, core.context_mut()?, PEER);
    let mirrored = view
        .base_origin(&companion_key(&live))
        .ok_or("live origin")?;
    assert_eq!(mirrored.generation, 2);
    assert_eq!(mirrored.connection_id, [60; 16]);
    assert_eq!(mirrored.connection_nonce, [60; 32]);
    assert_eq!(mirrored.session, Some(([60; 16], [60; 16])));
    assert_eq!(mirrored.account, Some((account_text(held)?, 3)));
    let mirrored = view
        .base_origin(&companion_key(&anonymous))
        .ok_or("anonymous")?;
    assert_eq!(mirrored.account, None);
    assert!(view.base_origin(&companion_key(&fenced)).is_none());
    assert!(view.base_origin(&companion_key(&suspended)).is_none());
    assert!(view.base_origin(&companion_key(&origin_key(64))).is_none());
    Ok(())
}

#[tokio::test]
async fn an_account_is_hosted_only_through_a_live_origin_of_the_live_incarnation() -> TestResult {
    let mut core = StateCoreFixture::new(vec![1; 256])?;
    let mut coordinator = owner(&core, false)?;
    let (hosted, fenced, absent) = (account(40), account(41), account(42));
    declare(&mut coordinator, 60, OriginStatus::Live, Some(hosted))?;
    declare(&mut coordinator, 61, OriginStatus::Fenced, Some(fenced))?;
    declare(&mut coordinator, 62, OriginStatus::Live, None)?;
    let offline = host(&coordinator, core.context_mut()?, PEER);
    assert!(!offline.hosts_account(&account_text(hosted)?));
    assert_eq!(offline.live_incarnation(PEER), None);
    let _queue = go_live(&mut coordinator, 1 << 20)?;
    let view = host(&coordinator, core.context_mut()?, PEER);
    assert!(view.hosts_account(&account_text(hosted)?));
    assert!(!view.hosts_account(&account_text(fenced)?));
    assert!(!view.hosts_account(&account_text(absent)?));
    assert_eq!(view.live_incarnation(PEER), Some(*INCARNATION.as_bytes()));
    let foreign = host(&coordinator, core.context_mut()?, STRANGER);
    assert!(!foreign.hosts_account(&account_text(hosted)?));
    Ok(())
}

#[tokio::test]
async fn peer_facts_default_closed_for_an_unconfigured_peer() -> TestResult {
    let mut core = StateCoreFixture::new(vec![1; 256])?;
    let mut coordinator = owner(&core, false)?;
    let state = coordinator.peers.get_mut(&PEER).ok_or("peer")?;
    state.phase = PeerPhase::Ready;
    state.client_resync_epoch = 4;
    let context = core.context_mut()?;
    let view = host(&coordinator, context, PEER);
    assert!(view.base_origins_ready(PEER));
    assert!(!view.base_origins_ready(STRANGER));
    assert_eq!(view.base_resync_epoch(PEER), 4);
    assert_eq!(view.base_resync_epoch(STRANGER), 0);
    assert_eq!(view.state_generation(), 12);
    assert_eq!(view.trusted_ack_unix_seconds(), None);
    assert!(view.holds_channel([30; 16]));
    assert!(!view.holds_channel([31; 16]));
    assert!(held_channels(&coordinator, context, PEER).is_empty());
    Ok(())
}

fn scope(target: ServerId) -> TestResult<DeliveryScope> {
    Ok(DeliveryScope::new(DeliveryScopeFields {
        network_id: [31; 32],
        coordinator_server_id: [32; 16],
        coordinator_incarnation: [33; 16],
        coordinator_recovery_epoch: [34; 16],
        target_server_id: *target.as_bytes(),
        target_incarnation: *INCARNATION.as_bytes(),
        covered_base_client_resync_epoch: 0,
    })?)
}

fn planned() -> TestResult<BarrierPlanned> {
    Ok(BarrierPlanned {
        target: PEER,
        mutation_id: [63; 16],
        base_parts: 2,
        part_count: 3,
        state_generation: 9,
        companion_scope: scope(PEER)?,
        companion: BarrierEndpoint::new(1, 4, 4, [64; 16])?,
    })
}

fn gate_fields() -> TestResult<DeliveryBarrierFields> {
    Ok(DeliveryBarrierFields {
        scope: scope(PEER)?,
        mutation_id: [63; 16],
        state_generation: 9,
        part_count: 3,
        base: BarrierEndpoint::new(1, 0, 1, [65; 16])?,
        companion: BarrierEndpoint::new(1, 4, 4, [64; 16])?,
        base_acked: false,
        companion_acked: false,
    })
}

fn carrying(target: ServerId, gate: Option<DeliveryBarrier>) -> OutboundEvent {
    OutboundEvent {
        target,
        projection_generation: 1,
        delivery_sequence: 1,
        event_id: EventId::from_bytes([65; 16]),
        object_id: agenc_ircd_federation_wire::FederationHash32::from_bytes([66; 32]),
        encoded: vec![1; 16],
        combined_barrier: gate.map(Box::new),
    }
}

type GateDefect = fn(&mut DeliveryBarrierFields) -> TestResult;

#[test]
fn a_gate_is_adopted_only_when_it_is_exactly_the_planned_one() -> TestResult {
    let planned = planned()?;
    assert!(matches_planned(
        &DeliveryBarrier::new(gate_fields()?)?,
        &planned
    ));
    let defects: [GateDefect; 6] = [
        |fields| {
            fields.scope = scope(STRANGER)?;
            Ok(())
        },
        |fields| {
            fields.companion = BarrierEndpoint::new(1, 4, 4, [99; 16])?;
            Ok(())
        },
        |fields| {
            fields.state_generation = 10;
            Ok(())
        },
        |fields| {
            fields.base = BarrierEndpoint::new(1, 0, 2, [65; 16])?;
            fields.part_count = 4;
            Ok(())
        },
        |fields| {
            fields.base_acked = true;
            Ok(())
        },
        |fields| {
            fields.companion_acked = true;
            Ok(())
        },
    ];
    for defect in defects {
        let mut fields = gate_fields()?;
        defect(&mut fields)?;
        assert!(!matches_planned(&DeliveryBarrier::new(fields)?, &planned));
    }
    let mut wider = gate_fields()?;
    wider.base = BarrierEndpoint::new(1, 0, 0, [65; 16])?;
    wider.companion = BarrierEndpoint::new(1, 4, 5, [64; 16])?;
    let mut replanned = planned;
    replanned.companion = wider.companion;
    assert!(
        !matches_planned(&DeliveryBarrier::new(wider)?, &replanned),
        "the base slice must hold exactly the planned base parts"
    );
    Ok(())
}

#[tokio::test]
async fn a_committed_request_cannot_open_a_missing_duplicate_or_second_gate() -> TestResult {
    let core = StateCoreFixture::new(vec![1; 256])?;
    let planned = [planned()?];
    let gate = || -> TestResult<DeliveryBarrier> { Ok(DeliveryBarrier::new(gate_fields()?)?) };
    let mut other = gate_fields()?;
    other.mutation_id = [77; 16];
    let cases = [
        vec![carrying(PEER, None)],
        vec![carrying(STRANGER, Some(gate()?))],
        vec![carrying(PEER, Some(DeliveryBarrier::new(other)?))],
        vec![carrying(PEER, Some(gate()?)), carrying(PEER, Some(gate()?))],
    ];
    for events in cases {
        let mut coordinator = owner(&core, true)?;
        assert_eq!(
            open_barriers(&mut coordinator, &planned, &events),
            Err(CompanionFault::Storage)
        );
        assert!(coordinator.barriers.is_empty());
    }
    let mut coordinator = owner(&core, true)?;
    let events = [carrying(PEER, Some(gate()?))];
    assert_eq!(
        open_barriers(&mut coordinator, &planned, &events),
        Err(CompanionFault::Storage),
        "the target has no companion stream to hold"
    );
    coordinator.barriers.insert(PEER, gate()?);
    assert_eq!(
        open_barriers(&mut coordinator, &planned, &events),
        Err(CompanionFault::Storage),
        "one gate per target"
    );
    assert_eq!(open_barriers(&mut coordinator, &[], &events), Ok(()));
    Ok(())
}

#[tokio::test]
async fn a_barrier_closes_only_after_both_streams_acknowledged_it() -> TestResult {
    let mut core = StateCoreFixture::new(vec![1; 256])?;
    let mut coordinator = owner(&core, false)?;
    let context = core.context_mut()?;
    try_close_barrier(&mut coordinator, context, PEER);
    for (base_acked, companion_acked) in [(false, false), (true, false), (false, true)] {
        let mut fields = gate_fields()?;
        fields.base_acked = base_acked;
        fields.companion_acked = companion_acked;
        coordinator
            .barriers
            .insert(PEER, DeliveryBarrier::new(fields)?);
        try_close_barrier(&mut coordinator, context, PEER);
        assert!(coordinator.barriers.contains_key(&PEER));
    }
    let mut fields = gate_fields()?;
    fields.base_acked = true;
    fields.companion_acked = true;
    coordinator
        .barriers
        .insert(PEER, DeliveryBarrier::new(fields)?);
    try_close_barrier(&mut coordinator, context, PEER);
    assert!(coordinator.barriers.is_empty());
    let _queue = go_live(&mut coordinator, 1 << 20)?;
    coordinator
        .barriers
        .insert(PEER, DeliveryBarrier::new(fields)?);
    try_close_barrier(&mut coordinator, context, PEER);
    assert!(coordinator.barriers.is_empty());
    assert!(coordinator.link_is_live(LINK, PEER));
    assert!(coordinator.pending.is_none());
    Ok(())
}

fn line(text: &str) -> TestResult<FederationLineText> {
    Ok(FederationLineText::from_rendered(format!(
        ":{NAME} {text}\r\n"
    ))?)
}

async fn quiet(queue: &mut LinkQueue) -> bool {
    tokio::time::timeout(std::time::Duration::from_millis(50), queue.recv())
        .await
        .is_err()
}

#[tokio::test]
async fn lines_for_a_superseded_or_absent_link_are_dropped() -> TestResult {
    let mut core = StateCoreFixture::new(vec![1; 256])?;
    let mut coordinator = owner(&core, false)?;
    let context = core.context_mut()?;
    send_lines(&mut coordinator, context, LINK, PEER, vec![line("EACK")?]);
    let mut queue = go_live(&mut coordinator, 1 << 20)?;
    send_lines(
        &mut coordinator,
        context,
        LinkId::new(12),
        PEER,
        vec![line("EACK")?],
    );
    assert!(quiet(&mut queue).await);
    send_lines(&mut coordinator, context, LINK, PEER, vec![line("EACK")?]);
    let sent = tokio::time::timeout(std::time::Duration::from_secs(5), queue.recv())
        .await?
        .ok_or("line")?;
    assert_eq!(sent.as_str(), line("EACK")?.as_str());
    assert_eq!(coordinator.counters.violations, 0);
    Ok(())
}

#[tokio::test]
async fn a_line_the_writer_cannot_queue_retires_the_link_and_stops_the_burst() -> TestResult {
    let mut core = StateCoreFixture::new(vec![1; 256])?;
    let mut coordinator = owner(&core, false)?;
    let context = core.context_mut()?;
    let first = line("EACK")?;
    let mut queue = go_live(&mut coordinator, u64::try_from(first.len())?)?;
    send_lines(
        &mut coordinator,
        context,
        LINK,
        PEER,
        vec![first, line("EACK")?, line("EACK")?],
    );
    assert_eq!(coordinator.counters.violations, 1);
    assert!(!coordinator.link_is_live(LINK, PEER));
    let delivered = tokio::time::timeout(std::time::Duration::from_secs(5), queue.recv()).await?;
    assert!(delivered.is_some(), "the line that fit was queued");
    let closed = tokio::time::timeout(std::time::Duration::from_secs(5), queue.recv()).await?;
    assert!(closed.is_none(), "then the close request");
    Ok(())
}

#[tokio::test]
async fn an_event_copy_is_sent_only_to_a_delivering_target_outside_a_barrier() -> TestResult {
    let mut core = StateCoreFixture::new(vec![1; 256])?;
    let mut coordinator = owner(&core, true)?;
    let context = core.context_mut()?;
    send_to_target(&mut coordinator, context, PEER, Some(5), line("EEVENT")?);
    let mut queue = go_live(&mut coordinator, 1 << 20)?;
    send_to_target(&mut coordinator, context, PEER, Some(5), line("EEVENT")?);
    assert!(quiet(&mut queue).await, "the target is not delivering");
    coordinator
        .barriers
        .insert(PEER, DeliveryBarrier::new(gate_fields()?)?);
    send_to_target(&mut coordinator, context, PEER, Some(5), line("EEVENT")?);
    send_to_target(&mut coordinator, context, PEER, Some(4), line("EEVENT")?);
    send_to_target(&mut coordinator, context, PEER, None, line("EEVENT")?);
    assert!(quiet(&mut queue).await);
    assert_eq!(coordinator.counters.events_sent, 0);
    Ok(())
}

fn request() -> CompleteRequest {
    CompleteRequest {
        correlation: Correlation {
            peer_server_id: [32; 16],
            server_incarnation: *INCARNATION.as_bytes(),
            origin_id: [60; 16],
            origin_generation: 0,
            operation_sequence: 0,
            request_id: [61; 16],
        },
        request: vec![1],
        payload: None,
    }
}

#[tokio::test]
async fn companion_work_without_an_executor_is_unsupported() -> TestResult {
    let mut core = StateCoreFixture::new(vec![1; 256])?;
    let mut coordinator = owner(&core, false)?;
    let context = core.context_mut()?;
    let unsupported = Err(Violation::Companion(CompanionViolation::Unsupported));
    assert_eq!(
        execute_or_queue(&mut coordinator, context, LINK, PEER, request()),
        unsupported
    );
    let reset = CompanionFrame::OriginReset {
        coordinator_server_id: [32; 16],
        server_incarnation: *INCARNATION.as_bytes(),
    };
    assert_eq!(
        admitted(&mut coordinator, context, LINK, PEER, reset),
        unsupported
    );
    assert_eq!(
        run(&mut coordinator, context, LINK, PEER, request()),
        unsupported
    );
    committed(&mut coordinator, context, LINK, PEER, &[], None, false);
    base_ready(&mut coordinator, context, PEER, INCARNATION);
    drain_queued(&mut coordinator, context);
    assert!(coordinator.pending.is_none());
    assert_eq!(coordinator.counters.violations, 0);
    Ok(())
}

#[tokio::test]
async fn a_request_from_a_peer_that_is_not_delivering_is_a_request_violation() -> TestResult {
    let mut core = StateCoreFixture::new(vec![1; 256])?;
    let mut coordinator = owner(&core, true)?;
    let context = core.context_mut()?;
    assert_eq!(
        execute_or_queue(&mut coordinator, context, LINK, PEER, request()),
        Err(Violation::Companion(CompanionViolation::Request))
    );
    assert!(coordinator.pending.is_none());
    committed(&mut coordinator, context, LINK, PEER, &[], None, false);
    assert_eq!(coordinator.counters.violations, 0, "nothing was pending");
    Ok(())
}

#[tokio::test]
async fn a_committed_request_whose_lines_cannot_render_fails_its_link() -> TestResult {
    let mut core = StateCoreFixture::new(vec![1; 256])?;
    let mut coordinator = owner(&core, true)?;
    let context = core.context_mut()?;
    let _queue = go_live(&mut coordinator, 1 << 20)?;
    request_committed(
        &mut coordinator,
        context,
        LINK,
        PEER,
        Err(E2eeReplyCode::RateLimited),
    );
    assert_eq!(coordinator.counters.requests_committed, 1);
    assert_eq!(coordinator.counters.violations, 1);
    assert!(!coordinator.link_is_live(LINK, PEER));
    Ok(())
}

#[tokio::test]
async fn companion_timers_are_claimed_by_kind_and_fail_only_an_expired_live_cut() -> TestResult {
    let mut core = StateCoreFixture::new(vec![1; 256])?;
    let mut coordinator = owner(&core, true)?;
    let context = core.context_mut()?;
    let _queue = go_live(&mut coordinator, 1 << 20)?;
    let now = context.now();
    let mut entry_of = |kind, id| -> TestResult<TimerEntry> {
        context.timers_mut().schedule(now, kind, id)?;
        Ok(context.timers_mut().pop_due(now).ok_or("timer")?)
    };
    let snapshot = entry_of(TimerKind::CompanionSnapshotExpiry, TimedId::Peer(PEER))?;
    let mailbox = entry_of(TimerKind::MailboxSnapshotExpiry, TimedId::Global)?;
    assert!(!snapshot_timer_fired(&mut coordinator, context, mailbox));
    assert!(!mailbox_timer_fired(&mut coordinator, context, snapshot));
    assert!(snapshot_timer_fired(&mut coordinator, context, snapshot));
    assert!(mailbox_timer_fired(&mut coordinator, context, mailbox));
    assert!(coordinator.link_is_live(LINK, PEER), "no cut had expired");
    assert_eq!(coordinator.counters.violations, 0);
    assert!(context.timers_mut().is_empty());
    Ok(())
}
