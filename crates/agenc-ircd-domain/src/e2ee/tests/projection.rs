#![forbid(unsafe_code)]

//! Companion event projection.

use super::*;

const EDGE_A: ServerId = ServerId::from_bytes([1; 16]);
const EDGE_B: ServerId = ServerId::from_bytes([2; 16]);
const HOME: ServerId = ServerId::from_bytes([3; 16]);

#[test]
fn the_completion_table_is_closed() -> Result<(), PlanError> {
    for opcode in Opcode::all() {
        assert_eq!(
            completion_for(opcode, ResultKind::Failed)?,
            Completion::None
        );
        assert_eq!(
            descriptor_rule(opcode, ResultKind::Failed)?,
            DescriptorRule::None
        );
    }
    assert_eq!(
        completion_for(Opcode(0), ResultKind::Failed),
        Err(PlanError::UnknownOpcode)
    );
    assert_eq!(
        completion_for(Opcode(42), ResultKind::Bound),
        Err(PlanError::ResultNotPermitted)
    );
    assert_eq!(
        completion_for(Opcode::SUBMIT_RECOVERY, ResultKind::RecoveryAccepted)?,
        Completion::Generic
    );
    assert_eq!(
        completion_for(Opcode::SUBMIT_RECOVERY_ELEMENT, ResultKind::RecoveryClosed)?,
        Completion::Generic
    );
    assert_eq!(
        completion_for(
            Opcode::SUBMIT_RECOVERY_ELEMENT,
            ResultKind::RecoveryConflict
        )?,
        Completion::Generic
    );
    assert_eq!(
        completion_for(Opcode(43), ResultKind::Failed)?,
        Completion::None
    );
    assert_eq!(
        completion_for(Opcode(45), ResultKind::Failed),
        Err(PlanError::UnknownOpcode)
    );
    assert!(Opcode::all().any(|opcode| opcode == Opcode::SUBMIT_MEMBERSHIP));
    let semantic = [
        (
            Opcode::APPLICATION_CHANNEL,
            ResultKind::AcceptedEvent,
            EventKind::ChannelApplication,
        ),
        (
            Opcode::APPLICATION_DIRECT,
            ResultKind::AcceptedEvent,
            EventKind::DirectApplication,
        ),
        (
            Opcode::BIND_GROUP,
            ResultKind::Bound,
            EventKind::RouteStateChanged,
        ),
        (Opcode::CLOSE_GROUP, ResultKind::Closed, EventKind::Closed),
        (
            Opcode::SUBMIT_CANDIDATE,
            ResultKind::AcceptedEvent,
            EventKind::Candidate,
        ),
        (
            Opcode::SUBMIT_COMMIT_ACK,
            ResultKind::CommitAcked,
            EventKind::CommitAck,
        ),
        (
            Opcode::SUBMIT_FINALIZATION,
            ResultKind::Finalized,
            EventKind::Finalized,
        ),
        (
            Opcode::SUBMIT_ABORT,
            ResultKind::Aborted,
            EventKind::Aborted,
        ),
        (
            Opcode::SUBMIT_REINIT_ATTEMPT,
            ResultKind::ReinitStaged,
            EventKind::ReinitStaged,
        ),
        (
            Opcode::SUBMIT_REINIT_ACK,
            ResultKind::ReinitAcked,
            EventKind::ReinitAck,
        ),
        (
            Opcode::SUBMIT_REINIT_ACTIVATE,
            ResultKind::ReinitActivated,
            EventKind::ReinitActivated,
        ),
        (
            Opcode::SUBMIT_REINIT_ABORT,
            ResultKind::ReinitAborted,
            EventKind::ReinitAborted,
        ),
    ];
    for (opcode, result, kind) in semantic {
        assert_eq!(completion_for(opcode, result)?, Completion::Semantic(kind));
    }
    let generic = [
        (Opcode::RESERVE_CHANNEL, ResultKind::Reserved),
        (
            Opcode::SUBMIT_AUTHORIZATION,
            ResultKind::Stored(StoreKind::Authorization),
        ),
        (Opcode::SUBMIT_POLICY, ResultKind::Stored(StoreKind::Policy)),
        (
            Opcode::SUBMIT_MEMBERSHIP,
            ResultKind::Stored(StoreKind::Membership),
        ),
        (
            Opcode::SUBMIT_FINALIZATION,
            ResultKind::Pending(PendingKind::Finalization),
        ),
        (
            Opcode::SUBMIT_ABORT,
            ResultKind::Pending(PendingKind::Abort),
        ),
        (
            Opcode::SUBMIT_REINIT_ATTEMPT,
            ResultKind::Pending(PendingKind::ReinitAttempt),
        ),
        (
            Opcode::SUBMIT_REINIT_ACTIVATE,
            ResultKind::Pending(PendingKind::ReinitActivate),
        ),
        (
            Opcode::SUBMIT_REINIT_ABORT,
            ResultKind::Pending(PendingKind::ReinitAbort),
        ),
        (
            Opcode::PUBLISH_IDENTITY,
            ResultKind::Stored(StoreKind::Identity),
        ),
        (
            Opcode::PUBLISH_ROSTER,
            ResultKind::Stored(StoreKind::Roster),
        ),
        (
            Opcode::PUBLISH_CAPABILITIES,
            ResultKind::Stored(StoreKind::Capabilities),
        ),
        (Opcode::ATTACH_FINISH, ResultKind::Attached),
        (Opcode::CLAIM_PACKAGE, ResultKind::Claimed),
        (
            Opcode::PUBLISH_PACKAGE,
            ResultKind::Stored(StoreKind::Package),
        ),
        (Opcode::REVOKE_PACKAGE, ResultKind::Revoked),
        (
            Opcode::DELIVER_BINDING,
            ResultKind::Stored(StoreKind::Binding),
        ),
        (
            Opcode::DELIVER_WELCOME,
            ResultKind::Stored(StoreKind::Welcome),
        ),
        (
            Opcode::DELIVER_WELCOME,
            ResultKind::Stored(StoreKind::StagedReinit),
        ),
        (Opcode::FETCH_MAILBOX, ResultKind::MailboxPage),
        (Opcode::ACKNOWLEDGE_MAILBOX, ResultKind::MailboxAcked),
    ];
    for (opcode, result) in generic {
        assert_eq!(
            completion_for(opcode, result)?,
            Completion::Generic,
            "{opcode:?}"
        );
    }
    let none = [
        (Opcode::QUERY_CHANNEL, ResultKind::Bound),
        (Opcode::QUERY_DIRECT, ResultKind::Empty(EmptyKind::Binding)),
        (Opcode::FETCH_OBJECT, ResultKind::ObjectPage),
        (Opcode::FETCH_ACKS, ResultKind::Empty(EmptyKind::Acks)),
        (
            Opcode::FETCH_BINDING_LOCKS,
            ResultKind::Empty(EmptyKind::BindingLock),
        ),
        (Opcode::WHOAMI, ResultKind::Account),
        (Opcode::ATTACH_BEGIN, ResultKind::AttachChallenge),
        (Opcode::CLAIM_STATUS, ResultKind::Claimed),
        (Opcode::CLAIM_PACKAGE, ResultKind::Empty(EmptyKind::Package)),
        (
            Opcode::FETCH_MAILBOX,
            ResultKind::Empty(EmptyKind::StagedReinit),
        ),
    ];
    for (opcode, result) in none {
        assert_eq!(
            completion_for(opcode, result)?,
            Completion::None,
            "{opcode:?}"
        );
    }
    let refused = [
        (Opcode::APPLICATION_CHANNEL, ResultKind::Bound),
        (Opcode::BIND_GROUP, ResultKind::Empty(EmptyKind::Binding)),
        (
            Opcode::SUBMIT_FINALIZATION,
            ResultKind::Pending(PendingKind::Abort),
        ),
        (Opcode::FETCH_MAILBOX, ResultKind::Empty(EmptyKind::Objects)),
        (
            Opcode::DELIVER_WELCOME,
            ResultKind::Stored(StoreKind::Binding),
        ),
        (Opcode::WHOAMI, ResultKind::Attached),
        (Opcode::FETCH_OBJECT, ResultKind::MailboxPage),
    ];
    for (opcode, result) in refused {
        assert_eq!(
            completion_for(opcode, result),
            Err(PlanError::ResultNotPermitted),
            "{opcode:?}"
        );
    }
    Ok(())
}

#[test]
fn descriptor_rules_follow_the_registry() -> Result<(), PlanError> {
    assert_eq!(
        descriptor_rule(Opcode::RESERVE_DIRECT, ResultKind::Reserved)?,
        DescriptorRule::ExactlyOne(17)
    );
    assert_eq!(
        descriptor_rule(Opcode::QUERY_CHANNEL, ResultKind::Bound)?,
        DescriptorRule::ExactlyOne(15)
    );
    assert_eq!(
        descriptor_rule(Opcode::BIND_GROUP, ResultKind::Bound)?,
        DescriptorRule::None,
        "bind echoes nothing"
    );
    assert_eq!(
        descriptor_rule(Opcode::CLAIM_STATUS, ResultKind::Claimed)?,
        DescriptorRule::ExactlyOne(14)
    );
    assert_eq!(
        descriptor_rule(Opcode::FETCH_ACKS, ResultKind::ObjectPage)?,
        DescriptorRule::Page(&[4, 20])
    );
    assert_eq!(
        descriptor_rule(Opcode::FETCH_ROOT_CHAIN, ResultKind::ObjectPage)?,
        DescriptorRule::ExactlyOne(11)
    );
    assert_eq!(
        descriptor_rule(Opcode::FETCH_MAILBOX, ResultKind::MailboxPage)?,
        DescriptorRule::MailboxPage
    );
    assert_eq!(
        descriptor_rule(Opcode::FETCH_OBJECT, ResultKind::ObjectPage)?,
        DescriptorRule::Page(&CLIENT_KINDS)
    );
    assert!(matches!(
        descriptor_rule(Opcode::FETCH_OBJECT, ResultKind::ObjectPage)?,
        DescriptorRule::Page(kinds) if !kinds.contains(&29)
    ));
    assert_eq!(
        descriptor_rule(Opcode::WHOAMI, ResultKind::Bound),
        Err(PlanError::ResultNotPermitted)
    );
    assert_eq!(
        mailbox_wire_kind(super::super::mailbox::MailboxKind::Welcome),
        9
    );
    assert_eq!(
        mailbox_wire_kind(super::super::mailbox::MailboxKind::StagedReinit),
        19
    );
    assert_eq!(
        mailbox_wire_kind(super::super::mailbox::MailboxKind::Binding),
        15
    );
    assert_eq!(
        mailbox_wire_kind(super::super::mailbox::MailboxKind::Application),
        1
    );
    Ok(())
}

#[test]
fn event_kinds_have_consistent_phases_and_presence_rules() {
    let all = [
        EventKind::ChannelApplication,
        EventKind::DirectApplication,
        EventKind::Candidate,
        EventKind::CommitAck,
        EventKind::Finalized,
        EventKind::Aborted,
        EventKind::ReinitActivated,
        EventKind::ReinitAborted,
        EventKind::Closed,
        EventKind::RouteStateChanged,
        EventKind::RequestCompleted,
        EventKind::RouteStateHidden,
        EventKind::ReinitStaged,
        EventKind::ReinitAck,
    ];
    let discriminants: BTreeSet<u8> = all.iter().map(|kind| kind.discriminant()).collect();
    assert_eq!(discriminants, (1..=14).collect());
    for kind in all {
        assert!((1..=5).contains(&kind.phase()));
        if kind.has_source() {
            assert_eq!(kind.phase(), 2);
            assert!(kind.has_payload());
        }
        assert_eq!(kind.has_conversation(), kind != EventKind::RequestCompleted);
    }
    assert_eq!(EventKind::RouteStateChanged.phase(), 1);
    assert_eq!(EventKind::RouteStateHidden.phase(), 4);
    assert_eq!(EventKind::RequestCompleted.phase(), 5);
    assert!(!EventKind::Finalized.has_payload());
    assert!(EventKind::RouteStateChanged.has_payload());
}

#[test]
fn direct_entitlement_is_reference_counted_and_channel_entitlement_follows_base()
-> Result<(), PlanError> {
    let mut entitlements = RouteEntitlements::new();
    let direct = [7; 32];
    assert!(!entitlements.entitled(EDGE_A, &direct));
    assert!(entitlements.require_direct(EDGE_A, direct, EntitlementReason::Event)?);
    assert!(!entitlements.require_direct(EDGE_A, direct, EntitlementReason::Mailbox)?);
    assert!(entitlements.entitled(EDGE_A, &direct));
    assert!(!entitlements.release_direct(EDGE_A, direct, EntitlementReason::Event)?);
    assert!(entitlements.release_direct(EDGE_A, direct, EntitlementReason::Mailbox)?);
    assert!(!entitlements.entitled(EDGE_A, &direct));
    assert_eq!(
        entitlements.release_direct(EDGE_A, direct, EntitlementReason::Operation),
        Err(PlanError::ReferenceUnderflow)
    );
    entitlements.require_direct(EDGE_A, direct, EntitlementReason::Operation)?;
    assert_eq!(
        entitlements.release_direct(EDGE_A, direct, EntitlementReason::Event),
        Err(PlanError::ReferenceUnderflow)
    );
    let channel = [8; 32];
    assert!(entitlements.set_channel(EDGE_A, channel, true));
    assert!(!entitlements.set_channel(EDGE_A, channel, true));
    assert_eq!(
        entitlements.snapshot(EDGE_A),
        [channel, direct].into_iter().collect()
    );
    assert!(entitlements.snapshot(EDGE_B).is_empty());
    assert!(entitlements.set_channel(EDGE_A, channel, false));
    assert!(!entitlements.set_channel(EDGE_A, channel, false));
    entitlements.require_direct(EDGE_B, direct, EntitlementReason::Event)?;
    // A full cut fences one edge's direct references and nothing else.
    assert!(entitlements.set_channel(EDGE_A, channel, true));
    entitlements.fence_direct(EDGE_A);
    assert!(!entitlements.entitled(EDGE_A, &direct));
    assert!(entitlements.entitled(EDGE_A, &channel));
    assert!(entitlements.entitled(EDGE_B, &direct));
    assert!(entitlements.require_direct(EDGE_A, direct, EntitlementReason::Operation)?);
    // A departure queues the edge's direct standings; a plan that finds one
    // hosted spends a look, and the last look settles it with its reference.
    entitlements.mark_departure(EDGE_A);
    assert_eq!(entitlements.departing(16), vec![(EDGE_A, direct)]);
    assert!(entitlements.departing(0).is_empty());
    for _ in 0..DEPARTING_DIRECT_LOOKS {
        assert_eq!(entitlements.departing(16).len(), 1);
        entitlements.still_hosted(EDGE_A, direct);
    }
    assert!(entitlements.departing(16).is_empty());
    assert!(entitlements.entitled(EDGE_A, &direct));
    entitlements.still_hosted(EDGE_A, direct);
    // An unhosted one is released with every reference it held.
    entitlements.mark_departure(EDGE_A);
    assert!(entitlements.release_departed(EDGE_A, direct));
    assert!(!entitlements.release_departed(EDGE_A, direct));
    assert!(!entitlements.entitled(EDGE_A, &direct));
    assert!(entitlements.departing(16).is_empty());
    assert!(entitlements.entitled(EDGE_B, &direct));
    // Every fence clears the queue with the standings.
    entitlements.require_direct(EDGE_A, direct, EntitlementReason::Event)?;
    entitlements.mark_departure(EDGE_A);
    entitlements.fence_direct(EDGE_A);
    assert!(entitlements.departing(16).is_empty());
    entitlements.require_direct(EDGE_A, direct, EntitlementReason::Event)?;
    entitlements.mark_departure(EDGE_A);
    entitlements.fence(EDGE_A);
    assert!(!entitlements.entitled(EDGE_A, &direct));
    assert!(entitlements.entitled(EDGE_B, &direct));
    Ok(())
}

fn planned(
    kind: EventKind,
    conversation: u8,
    target: ServerId,
    payload: Option<u8>,
) -> PlannedEvent {
    PlannedEvent {
        kind,
        conversation_id: (kind != EventKind::RequestCompleted).then_some([conversation; 32]),
        target,
        payload_object_id: payload.map(|byte| [byte; 32]),
        completion: false,
        route_sequence: 0,
        bytes: 100,
    }
}

#[test]
fn plans_order_by_phase_conversation_kind_target_and_payload() -> Result<(), PlanError> {
    let events = vec![
        planned(EventKind::RequestCompleted, 0, HOME, None),
        planned(EventKind::Finalized, 2, EDGE_B, None),
        planned(EventKind::ChannelApplication, 2, EDGE_B, Some(9)),
        planned(EventKind::ChannelApplication, 2, EDGE_A, Some(9)),
        planned(EventKind::RouteStateHidden, 1, EDGE_A, None),
        planned(EventKind::RouteStateChanged, 2, EDGE_A, Some(5)),
        planned(EventKind::Candidate, 1, EDGE_A, Some(3)),
    ];
    let plan = EventPlan::order(events)?;
    let kinds: Vec<(EventKind, u8, ServerId)> = plan
        .events()
        .iter()
        .map(|event| {
            (
                event.kind,
                event.conversation_id.map_or(0, |id| id[0]),
                event.target,
            )
        })
        .collect();
    assert_eq!(
        kinds,
        vec![
            (EventKind::RouteStateChanged, 2, EDGE_A),
            (EventKind::Candidate, 1, EDGE_A),
            (EventKind::ChannelApplication, 2, EDGE_A),
            (EventKind::ChannelApplication, 2, EDGE_B),
            (EventKind::Finalized, 2, EDGE_B),
            (EventKind::RouteStateHidden, 1, EDGE_A),
            (EventKind::RequestCompleted, 0, HOME),
        ]
    );
    assert_eq!(plan.for_target(EDGE_A).len(), 4);
    assert_eq!(plan.targets(), [EDGE_A, EDGE_B, HOME].into_iter().collect());
    let duplicate = vec![
        planned(EventKind::Candidate, 1, EDGE_A, Some(3)),
        planned(EventKind::Candidate, 1, EDGE_A, Some(3)),
    ];
    assert_eq!(EventPlan::order(duplicate), Err(PlanError::InvalidPlan));
    let mut first = planned(EventKind::Candidate, 1, EDGE_A, Some(3));
    first.completion = true;
    let mut second = planned(EventKind::Candidate, 1, EDGE_B, Some(3));
    second.completion = true;
    assert_eq!(
        EventPlan::order(vec![first, second]),
        Err(PlanError::InvalidPlan)
    );
    assert_eq!(
        EventPlan::order(vec![planned(EventKind::Candidate, 1, EDGE_A, None)]),
        Err(PlanError::InvalidPlan),
        "a candidate needs its payload"
    );
    assert_eq!(
        EventPlan::order(vec![planned(EventKind::Finalized, 1, EDGE_A, Some(1))]),
        Err(PlanError::InvalidPlan),
        "a finalized event has no payload"
    );
    let mut hidden = planned(EventKind::RouteStateHidden, 1, EDGE_A, None);
    hidden.completion = true;
    assert_eq!(EventPlan::order(vec![hidden]), Err(PlanError::InvalidPlan));
    let mut orphan = planned(EventKind::Closed, 1, EDGE_A, None);
    orphan.conversation_id = None;
    assert_eq!(EventPlan::order(vec![orphan]), Err(PlanError::InvalidPlan));
    Ok(())
}

#[test]
fn barriers_cover_only_two_profile_targets_within_bounds() -> Result<(), PlanError> {
    let plan = EventPlan::order(vec![
        planned(EventKind::RouteStateChanged, 1, EDGE_A, Some(1)),
        planned(EventKind::Closed, 1, EDGE_A, None),
        planned(EventKind::Closed, 1, EDGE_B, None),
    ])?;
    let mut base = BTreeMap::new();
    base.insert(EDGE_A, (2_usize, 500_u64));
    base.insert(HOME, (1_usize, 10_u64));
    let plans = plan_barriers(&base, &plan)?;
    assert_eq!(
        plans,
        vec![BarrierPlan {
            target: EDGE_A,
            base_parts: 2,
            companion_parts: 2,
            aggregate_bytes: 700,
        }]
    );
    assert_eq!(plans.first().map(BarrierPlan::part_count), Some(4));
    base.insert(EDGE_B, (0, 0));
    assert_eq!(
        plan_barriers(&base, &plan)?.len(),
        1,
        "zero base parts is one-profile"
    );
    base.insert(EDGE_B, (1, MAX_CROSS_PROFILE_AGGREGATE_BYTES));
    assert_eq!(plan_barriers(&base, &plan), Err(PlanError::InvalidPlan));
    base.insert(EDGE_B, (2_047, 1));
    assert_eq!(plan_barriers(&base, &plan)?.len(), 2);
    base.insert(EDGE_B, (2_048, 1));
    assert_eq!(plan_barriers(&base, &plan), Err(PlanError::InvalidPlan));
    let hosting: BTreeSet<ServerId> = [EDGE_A, EDGE_B].into_iter().collect();
    assert_eq!(
        recipients(&Audience::Channel { hosting: &hosting }, Some(HOME)),
        [EDGE_A, EDGE_B, HOME].into_iter().collect()
    );
    assert_eq!(
        recipients(&Audience::Direct { attached: &hosting }, None),
        hosting
    );
    assert!(!PlanError::Overflow.to_string().is_empty());
    Ok(())
}

#[test]
fn snapshot_iteration_merges_live_reasons_in_order_without_duplicate_conversations()
-> Result<(), PlanError> {
    let mut entitlements = RouteEntitlements::new();
    for conversation in [[0; 32], [3; 32], [0xff; 32]] {
        entitlements.set_channel(EDGE_A, conversation, true);
    }
    for conversation in [[1; 32], [3; 32], [4; 32]] {
        entitlements.require_direct(EDGE_A, conversation, EntitlementReason::Event)?;
    }
    entitlements.release_direct(EDGE_A, [4; 32], EntitlementReason::Event)?;
    entitlements.set_channel(EDGE_A, [2; 32], false);
    entitlements.set_channel(EDGE_B, [2; 32], true);
    assert_eq!(
        entitlements.snapshot_iter(EDGE_A).collect::<Vec<_>>(),
        vec![[0; 32], [1; 32], [3; 32], [0xff; 32]]
    );
    assert_eq!(
        entitlements.snapshot_iter(EDGE_B).collect::<Vec<_>>(),
        vec![[2; 32]]
    );
    entitlements.fence(EDGE_A);
    assert_eq!(entitlements.snapshot_iter(EDGE_A).next(), None);
    Ok(())
}
