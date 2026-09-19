//! Refusals and boundaries of registered-command planning, channel-key job
//! preparation, and the executor's continuation indexes.
#![forbid(unsafe_code)]

use agenc_ircd_client_wire::{
    ChannelControlCommand, FramedLine, PostRegistrationCommandKind, parse_message,
};
use agenc_ircd_domain::{ChannelNameValue, ChannelTarget, ModeChange, ModeOperation};

use super::*;
use crate::test_support::{
    StateCoreFixture, TestResult, apply_live_plan, bind_live_session, bound, seed_account,
    seed_session,
};

const SECRET: &str = "correct-horse-battery";

fn key() -> ChannelKeyVerifierRecord {
    ChannelKeyVerifierRecord::new([17; 16], [18; 32])
}

fn verifier() -> Arc<dyn ChannelKeyVerifier> {
    Arc::new(TestVerifier)
}

fn executor() -> RegisteredCommandExecutor {
    RegisteredCommandExecutor::new(verifier(), key())
}

fn parsed(line: &str) -> TestResult<ParsedMessage> {
    Ok(parse_message(FramedLine::new(line)?)?.ok_or("empty line")?)
}

fn channel() -> Result<ChannelNameValue, RuntimeError> {
    ChannelNameValue::parse("#locked").map_err(|_| RuntimeError::InvalidValue)
}

fn join(keyed: bool) -> Result<CanonicalCommand, RuntimeError> {
    CanonicalCommand::join(vec![ChannelTarget::new(channel()?, keyed)])
        .map_err(|_| RuntimeError::InvalidValue)
}

fn keyed_join() -> Result<CanonicalCommand, RuntimeError> {
    join(true)
}

fn plain_join() -> Result<CanonicalCommand, RuntimeError> {
    join(false)
}

fn set_key() -> Result<CanonicalCommand, RuntimeError> {
    CanonicalCommand::mode(channel()?, vec![ModeChange::JoinKey(true)])
        .map_err(|_| RuntimeError::InvalidValue)
}

fn make_secret() -> Result<CanonicalCommand, RuntimeError> {
    let change = ModeChange::Visibility {
        operation: ModeOperation::Add,
        mode: agenc_ircd_domain::VisibilityMode::Secret,
    };
    CanonicalCommand::mode(channel()?, vec![change]).map_err(|_| RuntimeError::InvalidValue)
}

fn federated(
    context: &mut StateCoreContext,
    actor: BoundSession,
    command: fn() -> Result<CanonicalCommand, RuntimeError>,
) -> TestResult<FederatedPlan> {
    plan_federated_command(
        context,
        actor,
        &|_| command(),
        &|_| Some(Zeroizing::new(SECRET.as_bytes().to_vec())),
        &verifier(),
        key(),
    )
    .map_err(|_| "planning was refused".into())
}

fn apply_ready(
    context: &mut StateCoreContext,
    actor: BoundSession,
    command: fn() -> Result<CanonicalCommand, RuntimeError>,
) -> TestResult {
    let FederatedPlan::Ready(PlanDecision::Mutation(mutation)) =
        federated(context, actor, command)?
    else {
        return Err("expected a ready mutation".into());
    };
    apply_live_plan(context, mutation)
}

/// Creates `#locked` with a key and returns its account-holding owner.
fn locked_channel(context: &mut StateCoreContext) -> TestResult<BoundSession> {
    let account = seed_account(context, 31, 1)?;
    let owner = bound(seed_session(context, 33, "Owner", Some(account))?);
    apply_ready(context, owner, plain_join)?;
    let FederatedPlan::Crypto(mut pending) = federated(context, owner, set_key)? else {
        return Err("expected channel-key work".into());
    };
    pending
        .complete(Ok(CryptoJobOutput::ChannelKeyConstruct(Ok(key()))))
        .map_err(|_| "key construction")?;
    let PlanDecision::Mutation(mutation) = pending.finish(context).map_err(|_| "finish")? else {
        return Err("expected the key mutation".into());
    };
    apply_live_plan(context, mutation)?;
    Ok(owner)
}

fn guest(context: &mut StateCoreContext) -> TestResult<BoundSession> {
    Ok(bound(seed_session(context, 35, "Guest", None)?))
}

fn deadline(
    context: &mut StateCoreContext,
    kind: TimerKind,
    id: TimedId,
) -> Result<TimerEntry, RuntimeError> {
    let deadline = context.now();
    let generation = context.timers_mut().schedule(deadline, kind, id)?;
    Ok(TimerEntry {
        deadline,
        kind,
        id,
        generation,
    })
}

#[tokio::test]
async fn a_timer_owned_elsewhere_is_not_claimed() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![41; 4096])?;
    let context = fixture.context_mut()?;
    let mut executor = executor();
    let connection = TimedId::Connection(ConnectionGeneration::new(5));
    let other_owner = deadline(context, TimerKind::CommandDeadline, connection)?;
    assert!(matches!(
        executor.timer_fired(context, other_owner),
        Ok(false)
    ));
    let other_kind = deadline(context, TimerKind::Ping, TimedId::Sequence(5))?;
    assert!(matches!(
        executor.timer_fired(context, other_kind),
        Ok(false)
    ));
    Ok(())
}

#[tokio::test]
async fn a_command_deadline_without_a_continuation_is_consumed() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![41; 4096])?;
    let context = fixture.context_mut()?;
    let mut executor = executor();
    let unknown = deadline(context, TimerKind::CommandDeadline, TimedId::Sequence(77))?;
    assert!(matches!(executor.timer_fired(context, unknown), Ok(true)));

    executor.by_sequence.insert(78, CryptoJobId::new(9));
    let orphaned = deadline(context, TimerKind::CommandDeadline, TimedId::Sequence(78))?;
    assert!(matches!(executor.timer_fired(context, orphaned), Ok(true)));
    assert!(executor.pending.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_completion_for_an_unowned_job_is_ignored() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![41; 4096])?;
    let context = fixture.context_mut()?;
    let mut executor = executor();
    let message = CryptoCompletionMessage {
        job_id: CryptoJobId::new(404),
        output: Ok(CryptoJobOutput::ChannelKey(ChannelKeyVerdict::for_test(
            true,
        ))),
    };
    assert!(executor.crypto_completed(context, message).is_ok());
    assert!(executor.reload_ready());
    Ok(())
}

#[tokio::test]
async fn closing_a_connection_without_a_continuation_cancels_nothing() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![41; 4096])?;
    let context = fixture.context_mut()?;
    let mut executor = executor();
    executor.connection_closed(context, ConnectionGeneration::new(6));
    assert!(executor.reload_ready());

    let generation = ConnectionGeneration::new(7);
    executor
        .by_connection
        .insert(generation, CryptoJobId::new(9));
    executor.connection_closed(context, generation);
    assert!(executor.pending.is_empty());
    assert!(executor.by_sequence.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_refusal_with_no_reply_path_is_an_internal_error() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![41; 4096])?;
    let context = fixture.context_mut()?;
    let actor = guest(context)?;
    let memory = EphemeralRefused::Fanout(FanoutRefused::MemoryExhausted);
    assert_eq!(
        render_ephemeral_refusal(context, actor, None, memory).err(),
        Some(RuntimeError::MemoryExhausted)
    );
    let domain = EphemeralRefused::Domain(DomainError::Forbidden);
    assert_eq!(
        render_ephemeral_refusal(context, actor, None, domain).err(),
        Some(RuntimeError::InvalidValue)
    );
    assert_eq!(
        render_durable_stage_refusal(context, actor, None, StageRefused::Busy).err(),
        Some(RuntimeError::LimitExceeded)
    );
    Ok(())
}

#[tokio::test]
async fn a_refused_command_is_answered_busy_unless_it_is_a_notice() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![41; 4096])?;
    let context = fixture.context_mut()?;
    let identity = seed_session(context, 35, "Guest", None)?;
    let actor = bound(identity);
    let capabilities = CapabilityState::default();
    let sink = bind_live_session(context, 8, identity, CapabilityState::default(), true)?;
    let cases = [
        ("PRIVMSG Owner :hello", 1_usize),
        ("NOTICE Owner :hello", 0),
    ];
    for (line, answered) in cases {
        let message = parsed(line)?;
        let reply = ClientReply {
            generation: ConnectionGeneration::new(8),
            capabilities: &capabilities,
            request: RetryCommand {
                kind: RegisteredCommandKind::Public(PostRegistrationCommandKind::Privmsg),
                message: &message,
            },
        };
        let before = sink.lines().len();
        let memory = EphemeralRefused::Fanout(FanoutRefused::MemoryExhausted);
        let result = render_ephemeral_refusal(context, actor, Some(reply), memory)?;
        assert_eq!(result, ResultClass::Busy);
        let staged = render_durable_stage_refusal(context, actor, Some(reply), StageRefused::Busy)?;
        assert_eq!(staged, ResultClass::Busy);
        assert_eq!(sink.lines().len() - before, answered * 2, "{line}");
    }
    Ok(())
}

#[tokio::test]
async fn a_rejected_plan_without_a_reply_path_is_still_classified() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![41; 4096])?;
    let context = fixture.context_mut()?;
    let owner = locked_channel(context)?;
    let stranger = guest(context)?;
    let FederatedPlan::Ready(rejected) = federated(context, stranger, plain_join)? else {
        return Err("expected a ready rejection".into());
    };
    assert!(matches!(rejected, PlanDecision::Rejected(_)));
    assert_eq!(
        complete_nonmutation(context, stranger, None, rejected)?,
        ResultClass::Rejected
    );

    let FederatedPlan::Ready(mutation) = federated(context, owner, make_secret)? else {
        return Err("expected a ready mutation".into());
    };
    assert_eq!(
        complete_nonmutation(context, owner, None, mutation).err(),
        Some(RuntimeError::InvalidValue)
    );
    Ok(())
}

#[tokio::test]
async fn only_a_connected_guest_supplying_a_key_is_charged_by_prefix() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![41; 4096])?;
    let context = fixture.context_mut()?;
    let owner = locked_channel(context)?;
    let identity = seed_session(context, 35, "Guest", None)?;
    let visitor = bound(identity);
    assert!(guest_key_prefix_demand(context, visitor, &plain_join()?)?.is_none());
    assert!(guest_key_prefix_demand(context, owner, &keyed_join()?)?.is_none());
    assert!(guest_key_prefix_demand(context, visitor, &set_key()?)?.is_none());
    assert_eq!(
        guest_key_prefix_demand(context, visitor, &keyed_join()?).err(),
        Some(RuntimeError::InvalidValue)
    );
    let _sink = bind_live_session(context, 9, identity, CapabilityState::default(), true)?;
    assert!(guest_key_prefix_demand(context, visitor, &keyed_join()?)?.is_some());
    Ok(())
}

#[tokio::test]
async fn an_unmetered_keyed_join_is_deferred_to_one_verification() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![41; 4096])?;
    let context = fixture.context_mut()?;
    let _owner = locked_channel(context)?;
    let account = seed_account(context, 51, 1)?;
    let joiner = bound(seed_session(context, 52, "Joiner", Some(account))?);
    let message = parsed(&format!("JOIN #locked {SECRET}"))?;
    let retry = RetryCommand {
        kind: RegisteredCommandKind::Public(PostRegistrationCommandKind::JoinChannels),
        message: &message,
    };
    let planned = plan_session_command(context, joiner, keyed_join()?, Some(retry), false);
    let Ok(PlannedCommand::Crypto(plan)) = planned else {
        return Err("expected deferred channel-key work".into());
    };
    assert_eq!(plan.requests.len(), 1);

    let missing = plan_session_command(context, joiner, keyed_join()?, None, false);
    assert!(matches!(
        missing,
        Err(SessionCommandError::Internal(RuntimeError::InvalidValue))
    ));
    Ok(())
}

#[tokio::test]
async fn an_unmetered_channel_creation_is_planned_without_crypto() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![41; 4096])?;
    let context = fixture.context_mut()?;
    let account = seed_account(context, 51, 1)?;
    let creator = bound(seed_session(context, 52, "Creator", Some(account))?);
    let message = parsed("JOIN #locked")?;
    let retry = RetryCommand {
        kind: RegisteredCommandKind::Public(PostRegistrationCommandKind::JoinChannels),
        message: &message,
    };
    let planned = plan_session_command(context, creator, plain_join()?, Some(retry), false);
    assert!(matches!(
        planned,
        Ok(PlannedCommand::Ready(PlanDecision::Mutation(_)))
    ));
    Ok(())
}

#[tokio::test]
async fn external_entropy_is_refused_at_any_other_width_or_when_exhausted() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![41; 8])?;
    let context = fixture.context_mut()?;
    let mut inputs = ExternalInputs::default();
    let narrow = ExternalInputRequest::Entropy {
        request_sequence: 0,
        purpose: EntropyPurpose::Invite,
        bytes: 8,
    };
    assert_eq!(
        satisfy_one(context, &mut inputs, narrow).err(),
        Some(RuntimeError::InvalidValue)
    );
    let exhausted = ExternalInputRequest::Entropy {
        request_sequence: 1,
        purpose: EntropyPurpose::Invite,
        bytes: 16,
    };
    assert_eq!(
        satisfy_external(context, &[exhausted]).err(),
        Some(RuntimeError::InvalidValue)
    );
    assert!(inputs.invite_ids.is_empty());
    Ok(())
}

#[tokio::test]
async fn key_jobs_refuse_a_request_of_the_other_kind() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![41; 4096])?;
    let context = fixture.context_mut()?;
    let actor = locked_channel(context)?;
    let construction = ExternalInputRequest::ChannelKeyConstruction {
        request_sequence: 0,
        change_index: 0,
    };
    let verification = ExternalInputRequest::ChannelKeyVerification {
        request_sequence: 0,
        target_index: 0,
    };
    let mut join_message = parsed(&format!("JOIN #locked {SECRET}"))?;
    let joined = prepare_crypto_jobs(
        context,
        actor,
        &mut join_message,
        &keyed_join()?,
        &[construction],
        &verifier(),
        key(),
    );
    assert_eq!(joined.err(), Some(RuntimeError::InvalidValue));

    let mut mode_message = parsed(&format!("MODE #locked +k {SECRET}"))?;
    let changed = prepare_crypto_jobs(
        context,
        actor,
        &mut mode_message,
        &set_key()?,
        &[verification],
        &verifier(),
        key(),
    );
    assert_eq!(changed.err(), Some(RuntimeError::InvalidValue));
    Ok(())
}

#[tokio::test]
async fn key_jobs_need_a_key_bearing_command_and_a_supplied_key() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![41; 4096])?;
    let context = fixture.context_mut()?;
    let actor = locked_channel(context)?;
    let verification = ExternalInputRequest::ChannelKeyVerification {
        request_sequence: 0,
        target_index: 0,
    };
    let mut quit = parsed("QUIT")?;
    let unkeyed = prepare_crypto_jobs(
        context,
        actor,
        &mut quit,
        &CanonicalCommand::quit(None),
        &[verification],
        &verifier(),
        key(),
    );
    assert_eq!(unkeyed.err(), Some(RuntimeError::InvalidValue));

    let mut keyless = parsed("JOIN #locked")?;
    let missing = prepare_crypto_jobs(
        context,
        actor,
        &mut keyless,
        &keyed_join()?,
        &[verification],
        &verifier(),
        key(),
    );
    assert_eq!(missing.err(), Some(RuntimeError::InvalidValue));

    let mut keyed = parsed(&format!("JOIN #locked {SECRET}"))?;
    let jobs = prepare_crypto_jobs(
        context,
        actor,
        &mut keyed,
        &keyed_join()?,
        &[verification],
        &verifier(),
        key(),
    )?;
    assert_eq!(jobs.len(), 1);
    Ok(())
}

#[tokio::test]
async fn a_guest_verifies_against_the_stored_key_only_on_an_open_channel() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![41; 4096])?;
    let context = fixture.context_mut()?;
    let owner = locked_channel(context)?;
    let visitor = guest(context)?;
    let target = ChannelTarget::new(channel()?, true);
    assert!(matches!(
        channel_key_target(context, visitor, &target, key()),
        ChannelKeyTarget::Stored(_)
    ));
    let absent = ChannelTarget::new(
        ChannelNameValue::parse("#absent").map_err(|_| "name")?,
        true,
    );
    assert!(matches!(
        channel_key_target(context, visitor, &absent, key()),
        ChannelKeyTarget::Dummy(_)
    ));

    apply_ready(context, owner, make_secret)?;
    assert!(matches!(
        channel_key_target(context, visitor, &target, key()),
        ChannelKeyTarget::Dummy(_)
    ));
    assert!(matches!(
        channel_key_target(context, owner, &target, key()),
        ChannelKeyTarget::Stored(_)
    ));
    Ok(())
}

#[tokio::test]
async fn an_unconvertible_command_is_rejected_until_the_session_bucket_is_empty() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![41; 4096])?;
    let context = fixture.context_mut()?;
    let identity = seed_session(context, 35, "Guest", None)?;
    let actor = bound(identity);
    let capabilities = CapabilityState::default();
    let sink = bind_live_session(context, 10, identity, CapabilityState::default(), true)?;
    let kind = RegisteredCommandKind::Public(PostRegistrationCommandKind::ChannelControl(
        ChannelControlCommand::Register,
    ));
    let message = parsed("CHANNEL REGISTER #locked")?;
    let reply = ClientReply {
        generation: ConnectionGeneration::new(10),
        capabilities: &capabilities,
        request: RetryCommand {
            kind,
            message: &message,
        },
    };
    let first = convert_registered_command(context, actor, reply, kind, &message)?;
    assert!(matches!(
        first,
        ConvertedCommand::Rejected(ResultClass::Rejected)
    ));
    assert_eq!(sink.lines().len(), 1);

    let mut last = ResultClass::Rejected;
    for _ in 0..4_096_u16 {
        let ConvertedCommand::Rejected(result) =
            convert_registered_command(context, actor, reply, kind, &message)?
        else {
            return Err("a guest channel registration was converted".into());
        };
        last = result;
        if result == ResultClass::Busy {
            break;
        }
    }
    assert_eq!(last, ResultClass::Busy);
    Ok(())
}

#[tokio::test]
async fn federated_key_work_needs_a_key_and_submits_each_job_once() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![41; 4096])?;
    let context = fixture.context_mut()?;
    let _owner = locked_channel(context)?;
    let account = seed_account(context, 51, 1)?;
    let joiner = bound(seed_session(context, 52, "Joiner", Some(account))?);
    let keyless = plan_federated_command(
        context,
        joiner,
        &|_| keyed_join(),
        &|_| None,
        &verifier(),
        key(),
    );
    assert!(matches!(
        keyless,
        Err(FederatedRefusal::Internal(RuntimeError::InvalidValue))
    ));

    let FederatedPlan::Crypto(mut pending) = federated(context, joiner, keyed_join)? else {
        return Err("expected channel-key work".into());
    };
    assert!(pending.submit_next(context)?.is_some());
    assert!(pending.submit_next(context)?.is_none());
    assert!(matches!(
        pending.complete(Err(CryptoWorkerError::QueueFull)),
        Err(FederatedRefusal::Public(DomainError::ServerBusy))
    ));
    Ok(())
}
