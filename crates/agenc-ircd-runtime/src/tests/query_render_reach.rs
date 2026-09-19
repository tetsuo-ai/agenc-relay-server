//! A query renders only for the requester it was planned for and at the
//! domain revision it was planned against.
#![forbid(unsafe_code)]

use agenc_ircd_client_wire::{FramedLine, parse_message};
use agenc_ircd_domain::{CanonicalCommand, ChannelNameValue, ChannelTarget, PlanDecision};

use super::{ReplyInput, federated_query_frames, render_query};
use crate::connection::ConnectionGeneration;
use crate::test_support::{
    StateCoreFixture, TestResult, apply_live_plan, negotiated_capabilities, plan_live, seed_session,
};

#[test]
fn a_query_plan_renders_only_for_its_requester_at_its_revision() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let context = fixture.context_mut()?;
    let owner = seed_session(context, 1, "Asker", None)?;
    let other = seed_session(context, 2, "Other", None)?;
    let list = || CanonicalCommand::list(Vec::new());
    let PlanDecision::Query(plan) = plan_live(context, owner, &list)? else {
        return Err("LIST was not planned as a query".into());
    };
    let capabilities = negotiated_capabilities(&[])?;
    let request = parse_message(FramedLine::new("LIST")?)?.ok_or("empty request")?;
    let reply = ReplyInput {
        requester: other.user_id,
        generation: ConnectionGeneration::new(2),
        capabilities: &capabilities,
        request: &request,
    };
    assert!(
        render_query(context, reply, &plan).is_err(),
        "another requester cannot render the plan"
    );
    assert!(federated_query_frames(context, other.user_id, false, &plan).is_err());

    // A mutation advances the revision the plan was bound to.
    let room = ChannelNameValue::parse("#advance")?;
    let join = || CanonicalCommand::join(vec![ChannelTarget::new(room.clone(), false)]);
    let PlanDecision::Mutation(mutation) = plan_live(context, owner, &join)? else {
        return Err("JOIN was not a mutation".into());
    };
    apply_live_plan(context, mutation)?;
    let reply = ReplyInput {
        requester: owner.user_id,
        generation: ConnectionGeneration::new(1),
        capabilities: &capabilities,
        request: &request,
    };
    assert!(
        render_query(context, reply, &plan).is_err(),
        "a stale plan cannot render"
    );
    assert!(federated_query_frames(context, owner.user_id, false, &plan).is_err());
    Ok(())
}
