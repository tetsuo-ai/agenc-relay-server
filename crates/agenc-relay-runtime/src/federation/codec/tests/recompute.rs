#![forbid(unsafe_code)]
//! A recompute carries its resulting revision explicitly, and every
//! membership the coordinator recomputes keeps the revision it joined at
//! (architecture 20.6). Such an event encodes, decodes back unchanged, and
//! the projector stages the one an account switch sends to a member edge.

use std::error::Error;

use agenc_relay_domain::federation::{
    ActorView, MembershipRecord, MembershipView, ProjectedEvent, SourceView,
};
use agenc_relay_domain::{ChannelNameValue, ChannelTarget, PlanDecision, Role};
use agenc_relay_federation_wire::{CodecError, DecodeBudget};
use agenc_relay_testkit::DomainTestIdentity;
use agenc_relay_types::{
    ChannelInstanceId, FederationEventKind, NetworkId, Revision, ServerId, UserId, UtcSecond,
};

use crate::federation::codec::events::{event_arm_object, projected_event_of};
use crate::state_core::projector::{EdgeDelivery, FederationProjector};
use crate::test_support::{
    StateCoreFixture, apply_live_plan, plan_live, remote_session_seed, seed_account,
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
