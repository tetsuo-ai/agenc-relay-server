//! Deferred key results survive unrelated commits and reject changed authority.
#![forbid(unsafe_code)]

use super::*;
use crate::test_support::{
    StateCoreFixture, TestResult, apply_live_plan, bound, seed_account, seed_session,
};
use agenc_ircd_domain::{ChannelNameValue, ChannelTarget, ModeChange};

fn key() -> ChannelKeyVerifierRecord {
    ChannelKeyVerifierRecord::new([17; 16], [18; 32])
}

fn join() -> Result<CanonicalCommand, RuntimeError> {
    CanonicalCommand::join(vec![ChannelTarget::new(
        ChannelNameValue::parse("#locked").map_err(|_| RuntimeError::InvalidValue)?,
        true,
    )])
    .map_err(|_| RuntimeError::InvalidValue)
}

fn mode() -> Result<CanonicalCommand, RuntimeError> {
    CanonicalCommand::mode(
        ChannelNameValue::parse("#locked").map_err(|_| RuntimeError::InvalidValue)?,
        vec![ModeChange::JoinKey(true)],
    )
    .map_err(|_| RuntimeError::InvalidValue)
}

fn plan(
    context: &mut StateCoreContext,
    bound: BoundSession,
    command: fn() -> Result<CanonicalCommand, RuntimeError>,
) -> TestResult<FederatedPlan> {
    let verifier: Arc<dyn ChannelKeyVerifier> = Arc::new(TestVerifier);
    plan_federated_command(
        context,
        bound,
        &|_| command(),
        &|_| Some(Zeroizing::new(vec![19; 16])),
        &verifier,
        key(),
    )
    .map_err(|error| match error {
        FederatedRefusal::Public(error) => format!("public planning error: {error:?}").into(),
        FederatedRefusal::Internal(error) => format!("internal planning error: {error:?}").into(),
    })
}

fn deferred(
    context: &mut StateCoreContext,
    bound: BoundSession,
    command: fn() -> Result<CanonicalCommand, RuntimeError>,
) -> TestResult<Box<FederatedDeferred>> {
    match plan(context, bound, command)? {
        FederatedPlan::Crypto(pending) => Ok(pending),
        FederatedPlan::Ready(_) => Err("expected channel-key work".into()),
    }
}

fn completed(
    mut pending: Box<FederatedDeferred>,
    context: &StateCoreContext,
) -> Result<PlanDecision, FederatedRefusal> {
    let output = match pending.current {
        PendingCryptoKind::Verify => CryptoJobOutput::ChannelKey(ChannelKeyVerdict::for_test(true)),
        PendingCryptoKind::Construct => CryptoJobOutput::ChannelKeyConstruct(Ok(key())),
    };
    pending.complete(Ok(output))?;
    pending.finish(context)
}

fn apply(
    context: &mut StateCoreContext,
    result: Result<PlanDecision, FederatedRefusal>,
) -> TestResult {
    let result = result.map_err(|error| match error {
        FederatedRefusal::Public(error) => format!("public completion error: {error:?}"),
        FederatedRefusal::Internal(error) => format!("internal completion error: {error:?}"),
    })?;
    let PlanDecision::Mutation(mutation) = result else {
        return Err("expected mutation".into());
    };
    apply_live_plan(context, mutation)
}

fn setup(context: &mut StateCoreContext) -> TestResult<(BoundSession, BoundSession)> {
    let account = seed_account(context, 31, 1)?;
    let owner = bound(seed_session(context, 33, "Owner", Some(account))?);
    let joiner = bound(seed_session(context, 34, "Joiner", Some(account))?);
    fn create() -> Result<CanonicalCommand, RuntimeError> {
        CanonicalCommand::join(vec![ChannelTarget::new(
            ChannelNameValue::parse("#locked").map_err(|_| RuntimeError::InvalidValue)?,
            false,
        )])
        .map_err(|_| RuntimeError::InvalidValue)
    }
    let FederatedPlan::Ready(created) = plan(context, owner, create)? else {
        return Err("unexpected crypto creating channel".into());
    };
    apply(context, Ok(created))?;
    let pending = deferred(context, owner, mode)?;
    let result = completed(pending, context);
    apply(context, result)?;
    Ok((owner, joiner))
}

#[tokio::test]
async fn deferred_join_and_mode_survive_unrelated_commits() -> TestResult {
    for joining in [true, false] {
        let mut fixture = StateCoreFixture::new(vec![41; 4096])?;
        let context = fixture.context_mut()?;
        let (owner, joiner) = setup(context)?;
        let actor = if joining { joiner } else { owner };
        let command: fn() -> Result<CanonicalCommand, RuntimeError> =
            if joining { join } else { mode };
        let pending = deferred(context, actor, command)?;
        seed_account(context, 55, 1)?;
        let result = completed(pending, context);
        apply(context, result)?;
    }
    Ok(())
}

#[tokio::test]
async fn deferred_join_rejects_a_changed_key() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![41; 4096])?;
    let context = fixture.context_mut()?;
    let (owner, joiner) = setup(context)?;
    let join = deferred(context, joiner, join)?;
    let mut replacement = deferred(context, owner, mode)?;
    replacement
        .complete(Ok(CryptoJobOutput::ChannelKeyConstruct(Ok(
            ChannelKeyVerifierRecord::new([51; 16], [52; 32]),
        ))))
        .map_err(|_| "replace key")?;
    let result = replacement.finish(context);
    apply(context, result)?;
    assert!(matches!(
        completed(join, context),
        Err(FederatedRefusal::Public(DomainError::StaleRevision))
    ));
    Ok(())
}

#[tokio::test]
async fn deferred_key_work_rejects_a_disconnected_session() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![41; 4096])?;
    let context = fixture.context_mut()?;
    let (_, joiner) = setup(context)?;
    let pending = deferred(context, joiner, join)?;
    let disconnected = context.domain().plan_session_disconnected(joiner.user_id)?;
    apply_live_plan(context, disconnected)?;
    assert!(matches!(
        completed(pending, context),
        Err(FederatedRefusal::Public(DomainError::NotFound))
    ));
    Ok(())
}
