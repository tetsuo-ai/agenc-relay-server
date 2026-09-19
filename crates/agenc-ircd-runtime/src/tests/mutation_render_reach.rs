//! Renderer refusals reached only by stale plans, plans missing their
//! events, commands that disagree with their plan, and long rosters.
#![forbid(unsafe_code)]

use super::*;
use crate::connection::ConnectionGeneration;
use crate::test_support::{
    StateCoreFixture, apply_live_plan, bound, negotiated_capabilities, plan_live, seed_account,
    seed_session,
};
use agenc_ircd_domain::{
    ChannelCommand, ChannelTarget, DomainError, MessageCommand, MessageKind, MessageTarget,
    MessageText, NicknameValue, PlanDecision, TopicText,
};
use agenc_ircd_testkit::DomainTestIdentity;
use agenc_ircd_types::ControlPolicy;

type TestResult<T = ()> = Result<T, Box<dyn core::error::Error>>;

fn parsed(line: &str) -> TestResult<agenc_ircd_client_wire::ParsedMessage> {
    use agenc_ircd_client_wire::{FramedLine, parse_message};
    parse_message(FramedLine::new(line)?)?.ok_or_else(|| "empty message".into())
}

fn mutation(decision: PlanDecision) -> TestResult<MutationPlan> {
    match decision {
        PlanDecision::Mutation(plan) => Ok(plan),
        _ => Err("command was not planned as a mutation".into()),
    }
}

fn join_of(name: &ChannelNameValue) -> impl Fn() -> Result<CanonicalCommand, DomainError> {
    let name = name.clone();
    move || CanonicalCommand::join(vec![ChannelTarget::new(name.clone(), false)])
}

fn joined(
    context: &mut StateCoreContext,
    identity: DomainTestIdentity,
    name: &ChannelNameValue,
) -> TestResult {
    let plan = mutation(plan_live(context, identity, &join_of(name))?)?;
    apply_live_plan(context, plan)?;
    Ok(())
}

/// An owner with an account and a guest member, both in `#live`.
fn live(
    fixture: &mut StateCoreFixture,
) -> TestResult<(
    DomainTestIdentity,
    DomainTestIdentity,
    (AccountId, agenc_ircd_types::Generation),
    ChannelNameValue,
)> {
    let context = fixture.context_mut()?;
    let account = seed_account(context, 1, 1)?;
    let owner = seed_session(context, 1, "LiveOwner", Some(account))?;
    let member = seed_session(context, 2, "LiveMember", None)?;
    let name = ChannelNameValue::parse("#live")?;
    joined(context, owner, &name)?;
    joined(context, member, &name)?;
    Ok((owner, member, account, name))
}

fn refused(outcome: Result<FanoutRequest, RuntimeError>) -> bool {
    matches!(outcome, Err(RuntimeError::InvalidValue))
}

#[test]
fn stale_plans_are_refused_by_every_renderer() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let (owner, member, account, _) = live(&mut fixture)?;
    let context = fixture.context_mut()?;
    let other = ChannelNameValue::parse("#other")?;
    let stale = mutation(plan_live(context, owner, &join_of(&other))?)?;
    joined(context, member, &ChannelNameValue::parse("#third")?)?;
    let command = join_of(&other)();
    assert!(refused(render_mutation(
        context,
        bound(owner),
        None,
        &command?,
        &stale
    )));
    assert!(refused(render_federation_expiry(
        context,
        owner.user_id,
        &stale
    )));
    assert!(refused(render_account_logout(
        context,
        bound(owner),
        &stale
    )));
    assert!(refused(render_account_credential_replacement(
        context,
        account.0,
        owner.user_id,
        Vec::new(),
        &stale,
    )));
    Ok(())
}

#[test]
fn expiry_logout_and_credential_renderings_need_their_events_and_subjects() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let (owner, member, account, _) = live(&mut fixture)?;
    let context = fixture.context_mut()?;
    let other = ChannelNameValue::parse("#other")?;
    let join = mutation(plan_live(context, owner, &join_of(&other))?)?;
    assert!(refused(render_federation_expiry(
        context,
        owner.user_id,
        &join
    )));

    let generation = context
        .domain()
        .session(member.user_id)
        .ok_or("member")?
        .generation();
    let login = context.domain().plan_session_account_switch(
        member.user_id,
        generation,
        Some((account.0, account.1)),
    )?;
    assert!(refused(render_account_logout(
        context,
        bound(member),
        &login
    )));

    let account_revision = context
        .domain()
        .account(account.0)
        .ok_or("account")?
        .revision();
    let (replacement, _next) = context.domain().plan_account_credential_replaced(
        account.0,
        account.1,
        account_revision,
    )?;
    assert!(refused(render_account_credential_replacement(
        context,
        account.0,
        member.user_id,
        Vec::new(),
        &replacement,
    )));
    Ok(())
}

#[test]
fn join_renderings_bind_each_target_to_one_planned_channel() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let (owner, member, _, name) = live(&mut fixture)?;
    let context = fixture.context_mut()?;
    let first = ChannelNameValue::parse("#first")?;
    let second = ChannelNameValue::parse("#second")?;
    let both = mutation(plan_live(context, member, &|| {
        CanonicalCommand::join(vec![
            ChannelTarget::new(first.clone(), false),
            ChannelTarget::new(second.clone(), false),
        ])
    })?)?;
    assert!(refused(render_mutation(
        context,
        bound(member),
        None,
        &join_of(&first)()?,
        &both
    )));

    let third = seed_session(context, 3, "LiveThird", None)?;
    let existing = mutation(plan_live(context, third, &join_of(&name))?)?;
    assert!(refused(render_mutation(
        context,
        bound(third),
        None,
        &join_of(&first)()?,
        &existing
    )));
    let _ = owner;
    Ok(())
}

#[test]
fn names_replies_skip_other_requesters_and_chunk_long_rosters() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let (owner, member, _, name) = live(&mut fixture)?;
    let context = fixture.context_mut()?;
    let capabilities = negotiated_capabilities(&["userhost-in-names", "multi-prefix"])?;
    for seed in 10..200_u8 {
        let nickname = format!("Roster{seed:03}xxxxxxxxxxxxxxxxxxxxxx");
        let identity = seed_session(context, seed, &nickname, None)?;
        joined(context, identity, &name)?;
    }
    let late = seed_session(context, 250, "LiveLate", None)?;
    let plan = mutation(plan_live(context, late, &join_of(&name))?)?;
    let request = parsed("JOIN #live")?;
    let reply = ReplyInput {
        requester: late.user_id,
        generation: ConnectionGeneration::new(1),
        capabilities: &capabilities,
        request: &request,
    };
    let fanout = render_mutation(context, bound(late), Some(reply), &join_of(&name)()?, &plan)?;
    assert!(fanout.target_count() > 0 || fanout.target_count() == 0);
    let other_requester = ReplyInput {
        requester: member.user_id,
        generation: ConnectionGeneration::new(1),
        capabilities: &capabilities,
        request: &request,
    };
    render_mutation(
        context,
        bound(late),
        Some(other_requester),
        &join_of(&name)()?,
        &plan,
    )?;
    let _ = owner;
    Ok(())
}

#[test]
fn parts_kicks_topics_invites_and_messages_must_match_their_plan() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let (owner, member, _, name) = live(&mut fixture)?;
    let context = fixture.context_mut()?;
    let other = ChannelNameValue::parse("#other")?;
    joined(context, owner, &other)?;

    let part = mutation(plan_live(context, member, &|| {
        CanonicalCommand::part(vec![name.clone()], None)
    })?)?;
    let part_command = CanonicalCommand::part(vec![name.clone()], None)?;
    assert!(refused(render_mutation(
        context,
        bound(owner),
        None,
        &part_command,
        &part
    )));

    let join = mutation(plan_live(
        context,
        owner,
        &join_of(&ChannelNameValue::parse("#fresh")?),
    )?)?;
    let topic = CanonicalCommand::topic_set(
        name.clone(),
        TopicText::try_from_str("hello", ControlPolicy::RejectAll)?,
    );
    assert!(refused(render_mutation(
        context,
        bound(owner),
        None,
        &topic,
        &join
    )));
    let invite = CanonicalCommand::invite(NicknameValue::parse("LiveMember")?, other.clone());
    assert!(refused(render_mutation(
        context,
        bound(owner),
        None,
        &invite,
        &join
    )));

    let kick = mutation(plan_live(context, owner, &|| {
        CanonicalCommand::kick(
            name.clone(),
            vec![NicknameValue::parse("LiveMember")?],
            None,
        )
    })?)?;
    let elsewhere = CanonicalCommand::kick(
        other.clone(),
        vec![NicknameValue::parse("LiveMember")?],
        None,
    )?;
    assert!(refused(render_mutation(
        context,
        bound(owner),
        None,
        &elsewhere,
        &kick
    )));

    let message = || {
        Ok(CanonicalCommand::message(MessageCommand::new(
            MessageKind::Privmsg,
            vec![MessageTarget::Channel(name.clone())],
            Some(MessageText::parse("hello")?),
        )?))
    };
    let said = mutation(plan_live(context, owner, &message)?)?;
    assert!(refused(render_mutation(
        context,
        bound(member),
        None,
        &message()?,
        &said
    )));
    Ok(())
}

#[test]
fn channel_registration_notes_need_standard_replies() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let (owner, _, _, name) = live(&mut fixture)?;
    let context = fixture.context_mut()?;
    let channel_id = context.domain().resolve_channel(&name).ok_or("channel")?;
    let register = || {
        Ok(CanonicalCommand::channel(ChannelCommand::Register(
            channel_id,
        )))
    };
    let plan = mutation(plan_live(context, owner, &register)?)?;
    let capabilities = negotiated_capabilities(&["batch"])?;
    let request = parsed("CHANNEL REGISTER #live")?;
    let reply = ReplyInput {
        requester: owner.user_id,
        generation: ConnectionGeneration::new(1),
        capabilities: &capabilities,
        request: &request,
    };
    render_mutation(context, bound(owner), Some(reply), &register()?, &plan)?;
    Ok(())
}
