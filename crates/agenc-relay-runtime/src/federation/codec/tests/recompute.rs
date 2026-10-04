#![forbid(unsafe_code)]
//! A recompute carries its resulting revision explicitly, and every
//! membership the coordinator recomputes keeps the revision it joined at
//! (architecture 20.6). Such an event encodes, decodes back unchanged, and
//! the projector stages every recompute a member edge receives: the one a
//! login or a logout of a channel member sends, and the one a role MODE on
//! an account-holding member of a registered channel (an account grant)
//! sends.

use std::error::Error;

use agenc_relay_domain::federation::{
    ActorView, CoordinatorProjection, MembershipRecord, MembershipView, MutationContext,
    ProjectedEvent, SourceView,
};
use agenc_relay_domain::{
    CanonicalCommand, ChannelCommand, ChannelNameValue, ChannelTarget, ModeChange, ModeOperation,
    MutationPlan, NicknameValue, PlanDecision, Role,
};
use agenc_relay_federation_wire::{CodecError, DecodeBudget};
use agenc_relay_testkit::DomainTestIdentity;
use agenc_relay_types::{
    ChannelInstanceId, FederationEventKind, NetworkId, Revision, ServerId, UserId, UtcSecond,
};

use crate::federation::codec::events::{event_arm_object, projected_event_of};
use crate::state_core::StateCoreContext;
use crate::state_core::projector::{EdgeDelivery, FederationProjector};
use crate::test_support::{
    StateCoreFixture, apply_live_plan, plan_live, remote_session_seed, seed_account, seed_session,
};

type TestResult = Result<(), Box<dyn Error>>;

const CHANNEL: ChannelInstanceId = ChannelInstanceId::from_bytes([4; 16]);
const NETWORK: NetworkId = NetworkId::from_bytes([1; 32]);
const COORDINATOR: ServerId = ServerId::from_bytes([2; 16]);
const EDGE: ServerId = ServerId::from_bytes([50; 16]);

/// A recompute of one membership that joined at `joined` and is recomputed
/// at `resulting`.
fn recompute(joined: u64, resulting: u64) -> Result<ProjectedEvent, Box<dyn Error>> {
    let user_id = UserId::from_bytes([5; 16]);
    Ok(ProjectedEvent::ChannelMembershipsRecomputed {
        channel_id: CHANNEL,
        resulting_revision: Revision::new(resulting)?,
        actor: ActorView(None),
        memberships: vec![MembershipView {
            membership: MembershipRecord {
                channel_id: CHANNEL,
                user_id,
                role: Role::Operator,
                membership_revision: Revision::new(joined)?,
                joined_at: UtcSecond::from_unix_seconds(1_700_000_000),
            },
            source: SourceView {
                user_id,
                nickname: agenc_relay_domain::NicknameValue::parse("member")?,
                public_cloak: agenc_relay_testkit::deterministic_cloak(5)?,
                account_label: None,
            },
        }],
    })
}

#[test]
fn a_recomputed_membership_round_trips_at_the_revision_it_joined_at() -> TestResult {
    let event = recompute(3, 7)?;
    let object = event_arm_object(&event)?;
    let decoded = projected_event_of(
        FederationEventKind::ChannelMembershipsRecomputed,
        &object,
        &mut DecodeBudget::new(1 << 16, 256),
    )?;
    assert!(decoded == event, "the recompute changed on the wire");
    // A membership can never have joined after the revision recomputing it.
    assert!(matches!(
        event_arm_object(&recompute(8, 7)?),
        Err(CodecError::CrossReference)
    ));
    Ok(())
}

#[test]
fn a_member_edge_receives_the_recompute_of_its_member_login() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let context = fixture.context_mut()?;
    let account = seed_account(context, 7, 1)?;
    // A guest the edge homes, alone in a channel.
    let seed = remote_session_seed(context, EDGE, "Remote")?;
    let member = DomainTestIdentity {
        session_id: seed.session_id,
        user_id: seed.user_id,
        generation: seed.generation,
        account_id: None,
    };
    let opened = context.domain().plan_session_opened(seed)?;
    apply_live_plan(context, opened)?;
    let name = ChannelNameValue::parse("#room")?;
    let PlanDecision::Mutation(joined) = plan_live(context, member, &|| {
        agenc_relay_domain::CanonicalCommand::join(vec![ChannelTarget::new(name.clone(), false)])
    })?
    else {
        return Err("JOIN was not planned as a mutation".into());
    };
    apply_live_plan(context, joined)?;
    let mut projector = FederationProjector::new(NETWORK, COORDINATOR);
    projector.set_edge(
        EDGE,
        EdgeDelivery {
            projection_generation: 1,
            next_delivery_sequence: 0,
        },
    );
    context.install_federation_projector(projector);

    // The login recomputes the membership at a later channel revision.
    let session = context
        .domain()
        .session(member.user_id)
        .ok_or("no session")?;
    let login = context.domain().plan_session_account_switch(
        member.user_id,
        session.generation(),
        Some(account),
    )?;
    let projected = context.preview_projection(&login)?;
    let (events, _bytes) = projected.get(&EDGE).ok_or("nothing projects to the edge")?;
    assert!(*events > 0, "the login projects nothing to its member edge");
    Ok(())
}

fn mutation(decision: PlanDecision) -> Result<MutationPlan, Box<dyn Error>> {
    match decision {
        PlanDecision::Mutation(plan) => Ok(plan),
        _ => Err("the command was not planned as a mutation".into()),
    }
}

fn join(context: &mut StateCoreContext, member: DomainTestIdentity) -> TestResult {
    let name = ChannelNameValue::parse("#room")?;
    let joined = mutation(plan_live(context, member, &|| {
        CanonicalCommand::join(vec![ChannelTarget::new(name.clone(), false)])
    })?)?;
    apply_live_plan(context, joined)
}

/// Opens `nickname` as a session the edge homes, holding `account` if any.
fn edge_session(
    context: &mut StateCoreContext,
    nickname: &str,
    account: Option<(agenc_relay_types::AccountId, agenc_relay_types::Generation)>,
) -> Result<DomainTestIdentity, Box<dyn Error>> {
    let mut seed = remote_session_seed(context, EDGE, nickname)?;
    if let Some((account_id, generation)) = account {
        seed.account_id = Some(account_id);
        seed.account_session_generation = generation;
    }
    let member = DomainTestIdentity {
        session_id: seed.session_id,
        user_id: seed.user_id,
        generation: seed.generation,
        account_id: seed.account_id,
    };
    let opened = context.domain().plan_session_opened(seed)?;
    apply_live_plan(context, opened)?;
    Ok(member)
}

/// Installs a coordinator projector whose index holds exactly the edge's
/// current standing, and returns the events `plan` projects to that edge.
fn projected_to_edge(
    context: &mut StateCoreContext,
    plan: &MutationPlan,
) -> Result<Vec<ProjectedEvent>, Box<dyn Error>> {
    let standing = CoordinatorProjection::standing_of(context.domain(), EDGE);
    let mut index = CoordinatorProjection::new(COORDINATOR);
    index.install_edge(EDGE, &standing);
    let projection = index.derive(context.domain(), plan, &MutationContext::default())?;
    let mut projector = FederationProjector::new(NETWORK, COORDINATOR);
    projector.set_edge(
        EDGE,
        EdgeDelivery {
            projection_generation: 1,
            next_delivery_sequence: 0,
        },
    );
    projector.install_edge(EDGE, &standing);
    context.install_federation_projector(projector);
    Ok(projection
        .edges
        .into_iter()
        .filter(|delta| delta.target == EDGE)
        .flat_map(|delta| delta.events)
        .collect())
}

/// The recomputed membership of the one recompute in `events`, after
/// checking that it kept the revision it joined at, below the recompute's
/// resulting revision.
fn recomputed_member(events: &[ProjectedEvent]) -> Result<MembershipRecord, Box<dyn Error>> {
    let [
        ProjectedEvent::ChannelMembershipsRecomputed {
            resulting_revision,
            memberships,
            ..
        },
    ] = events
    else {
        let kinds: Vec<FederationEventKind> = events.iter().map(ProjectedEvent::kind).collect();
        return Err(format!("expected exactly one recompute, got {kinds:?}").into());
    };
    let [view] = memberships.as_slice() else {
        return Err("expected exactly one recomputed membership".into());
    };
    assert!(
        view.membership.membership_revision < *resulting_revision,
        "the recompute moved the revision its member joined at"
    );
    Ok(view.membership)
}

/// A role MODE on a registered channel whose target holds an account is an
/// account grant: the coordinator recomputes that account's memberships and
/// projects the recompute, alone, to every member edge. Under the equality
/// the codec used to require, the projector could not encode it, so the
/// coordinator refused such a MODE whenever an edge homed a member of the
/// channel.
#[test]
fn a_registered_channel_account_grant_reaches_the_member_edge() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let context = fixture.context_mut()?;
    let owner_account = seed_account(context, 7, 1)?;
    let member_account = seed_account(context, 8, 1)?;
    let owner = seed_session(context, 5, "Owner", Some(owner_account))?;
    let member = edge_session(context, "Remote", Some(member_account))?;
    join(context, owner)?;
    join(context, member)?;
    let channel = context
        .domain()
        .session(owner.user_id)
        .ok_or("no owner session")?
        .joined_channels()
        .next()
        .ok_or("the owner joined no channel")?;
    let registered = mutation(plan_live(context, owner, &|| {
        Ok(CanonicalCommand::channel(ChannelCommand::Register(channel)))
    })?)?;
    apply_live_plan(context, registered)?;

    let name = ChannelNameValue::parse("#room")?;
    let grant = mutation(plan_live(context, owner, &|| {
        CanonicalCommand::mode(
            name.clone(),
            vec![ModeChange::Role {
                operation: ModeOperation::Add,
                target: NicknameValue::parse("Remote")?,
                role: Role::Voice,
            }],
        )
    })?)?;
    let events = projected_to_edge(context, &grant)?;
    let recomputed = recomputed_member(&events)?;
    assert_eq!(recomputed.user_id, member.user_id);
    assert_eq!(recomputed.role, Role::Voice);
    let projected = context.preview_projection(&grant)?;
    assert_eq!(projected.get(&EDGE).map(|(events, _)| *events), Some(1));
    Ok(())
}

/// A coordinator session that logs out recomputes its membership in every
/// channel it joined, and an edge with a member there receives that
/// recompute alone: a logout is not projected as `account_label_changed`.
/// Under the equality the codec used to require, the coordinator refused
/// such a logout.
#[test]
fn a_coordinator_logout_beside_an_edge_member_reaches_that_edge() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let context = fixture.context_mut()?;
    let account = seed_account(context, 7, 1)?;
    let local = seed_session(context, 5, "Local", Some(account))?;
    let member = edge_session(context, "Remote", None)?;
    join(context, local)?;
    join(context, member)?;

    let session = context
        .domain()
        .session(local.user_id)
        .ok_or("no local session")?;
    let logout =
        context
            .domain()
            .plan_session_account_switch(local.user_id, session.generation(), None)?;
    let events = projected_to_edge(context, &logout)?;
    let recomputed = recomputed_member(&events)?;
    assert_eq!(recomputed.user_id, local.user_id);
    let projected = context.preview_projection(&logout)?;
    assert_eq!(projected.get(&EDGE).map(|(events, _)| *events), Some(1));
    Ok(())
}
