//! A real StateCore barrier for a current registered base account and its stored private grant.
#![forbid(unsafe_code)]

use agenc_relay_crypto::InitialRootClaimOwner;
use agenc_relay_domain::AccountState;
use agenc_relay_types::{AccountRandomId, RequestId};

use super::*;
use crate::state_core::fanout::FanoutRequest;
use crate::test_support::{StateCoreFixture, TestResult, seed_account};

fn stage(
    context: &mut StateCoreContext,
    plan: MutationPlan,
    writes: Vec<AccountServiceDurableWrite>,
) -> TestResult {
    context
        .stage_durable_with_account_service(
            plan,
            FanoutRequest::new(Vec::new(), Vec::new())?,
            None,
            0,
            writes,
        )
        .map_err(|_| "could not stage root test batch")?;
    Ok(())
}

#[tokio::test]
async fn initial_root_read_and_competing_choice_use_one_private_revision_fence() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![5; 16_384])?;
    let account = AccountRandomId::from_bytes([0x62; 16]).to_account_id();
    let generation = Generation::new(1)?;
    let network = fixture.identity.network_id;
    let epoch = fixture.identity.recovery_epoch;
    let row = RootClaimOwner {
        network,
        account,
        epoch,
        start: RequestId::from_bytes([7; 16]),
        owner: InitialRootClaimOwner::from_protected_bytes([8; 32]),
        state: RootClaimState::Reserved,
    };
    let context = fixture.context_mut()?;
    let missing = context.plan_signed_root(account, generation, 0, [6; 32], [4; 32]);
    assert!(matches!(missing, Err(E2eeReplyCode::AccountRequired)));
    let plan = context.domain().plan_account_created(
        AccountState::new(account, generation, context.domain().revision())
            .with_initial_root_claim(),
    )?;
    let revision = plan.resulting_revision();
    let writes = vec![
        initial_root_write(
            revision.get(),
            StoredKey::new(FORMAT_KEY.to_vec())?,
            InitialRootRow::format()?,
        )?,
        owned_write(revision.get(), &row)?,
    ];
    stage(context, plan, writes)?;
    assert!(context.initial_root_claim(account)?.is_none());
    fixture.commit_staged_batch().await?;
    let context = fixture.context_mut()?;
    assert!(matches!(
        context.plan_signed_root(account, generation, 0, [6; 32], [4; 32]),
        Err(E2eeReplyCode::BindingAuthInvalid)
    ));
    let (a, reserved) = context.initial_root_admission(account, generation)?;
    assert!(reserved.is_some_and(|c| c.state == ClaimState::Reserved
        && c.creation_request == row.start
        && c.owner.matches(&row.owner)));
    let (b, _) = context.initial_root_admission(account, generation)?;
    let (old_read, _) = context.initial_root_admission(account, generation)?;
    let mut writes = Vec::new();
    let plan = context.plan_initial_root_choice(a, Some([6; 32]), &mut writes)?;
    assert_eq!(writes.len(), 1);
    assert!(plan.events().is_empty() && plan.durable_writes().is_empty());
    stage(context, plan, writes)?;
    assert!(context.initial_root_admission(account, generation).is_err());
    assert!(matches!(
        context.plan_signed_root(account, generation, 0, [6; 32], [4; 32]),
        Err(E2eeReplyCode::AccountRequired)
    ));
    fixture.commit_staged_batch().await?;
    let context = fixture.context_mut()?;
    let mut writes = Vec::new();
    assert!(
        context
            .plan_initial_root_choice(b, Some([9; 32]), &mut writes)
            .is_err()
    );
    assert!(
        context
            .plan_initial_root_choice(old_read, None, &mut writes)
            .is_err()
    );
    assert!(writes.is_empty());
    assert!(
        context
            .initial_root_claim(account)?
            .is_some_and(|c| c.state == ClaimState::Chosen([6; 32]))
    );
    assert_eq!(
        context
            .domain()
            .account(account)
            .ok_or("account")?
            .revision(),
        revision
    );
    assert!(matches!(
        context.plan_signed_root(account, generation, 0, [9; 32], [4; 32]),
        Err(E2eeReplyCode::BindingAuthInvalid)
    ));
    assert!(
        context
            .plan_signed_root(account, generation, 0, [6; 32], [4; 32])
            .ok()
            .flatten()
            .is_some()
    );
    let (legacy, generation) = seed_account(context, 4, 1)?;
    assert!(context.initial_root_claim(legacy)?.is_none());
    assert!(matches!(
        context.plan_signed_root(legacy, generation, 0, [1; 32], [3; 32]),
        Ok(None)
    ));
    Ok(())
}
