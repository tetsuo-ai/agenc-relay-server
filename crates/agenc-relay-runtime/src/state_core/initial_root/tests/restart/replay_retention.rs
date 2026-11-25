//! The actual closed/open redb journal retains the first root through private result expiry.
use super::*;
use crate::account_service::{AccountServiceCoordinator, test_registered_receipt};
use crate::state_core::durable::claim_replays::CLAIM_REPLAY_SECONDS;
use crate::test_support::account_service_config;
use agenc_relay_auth::initial_root::{ClaimAction, open_claim, seal_claim};
use agenc_relay_crypto::{
    AccountHpkePrivateKey, AccountRequestBinding, InitialRootExchange, InitialRootSecret,
};

#[tokio::test]
async fn expiry_only_retires_the_exact_response_after_a_trusted_cut_and_reopen() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![48; 32_768])?;
    let network = fixture.identity.network_id;
    let epoch = fixture.identity.recovery_epoch;
    let account = AccountRandomId::from_bytes([11; 16]).to_account_id();
    let start = RequestId::from_bytes([21; 16]);
    let id = RequestId::from_bytes([31; 16]);
    let secret = InitialRootSecret::generate()?;
    let original = RootClaimOwner {
        account,
        network,
        epoch,
        start,
        owner: secret
            .precommit(network, epoch, start)
            .bind(network, epoch, account, start),
        state: RootClaimState::Reserved,
    };
    reserved_database(&mut fixture, &original).await?;
    let service = AccountServiceCoordinator::new(account_service_config(
        &fixture.identity,
        &fixture.opaque,
        fixture.key_state,
    )?)?;
    let private = AccountHpkePrivateKey::generate()?;
    let public = private.public_key()?;
    let pick = [42; 32];
    let (request, _opener) = seal_claim(
        public,
        AccountRequestBinding::new(
            network,
            epoch,
            public.key_id(),
            id,
            InitialRootExchange::Claim,
        ),
        account,
        start,
        &secret,
        ClaimAction::Choose(pick),
    )?;
    let now = 1_000_000;
    let expires = now + CLAIM_REPLAY_SECONDS;
    let context = fixture.context_mut()?;
    context.set_wall_for_test(now);
    let (cut, before) = context.initial_root_admission(account, Generation::new(1)?)?;
    let prepared = open_claim(&private, network, epoch, &request)?.prepare(
        Some(account),
        before.as_ref(),
        context.head().account_service_response_count,
    )?;
    assert_eq!(prepared.new_choice(), Some(pick));
    let mut writes = Vec::new();
    let plan = context.plan_initial_root_choice(cut, prepared.new_choice(), &mut writes)?;
    writes.push(test_registered_receipt(
        account,
        plan.resulting_revision().get(),
        expires,
        &request,
        prepared.bytes_for_commit(),
    )?);
    context
        .stage_durable_with_account_service(
            plan,
            FanoutRequest::new(Vec::new(), Vec::new())?,
            None,
            1,
            writes,
        )
        .map_err(|_| "could not stage exact registered result")?;
    fixture.commit_staged_batch().await?;
    let key = StoredKey::new(id.as_bytes().to_vec())?;
    fixture.restart_registration_storage(vec![49; 32_768])?;
    let context = fixture.context_mut()?;
    assert!(context.index().holds(TableId::RequestResult, &key));
    assert_eq!(
        context
            .index()
            .expired_claim_replays(expires, 32)
            .collect::<Vec<_>>(),
        [id]
    );
    context.set_wall_for_test(expires - 1);
    AccountServiceCoordinator::require_live_claim_result(context, Some(expires))?;
    assert!(AccountServiceCoordinator::require_live_claim_result(context, None).is_err());
    service.retire_claim_results(context)?;
    assert_eq!(context.pending_len(), 0);
    context.set_untrusted_wall_for_test(Some(expires + 86_400));
    assert!(AccountServiceCoordinator::require_live_claim_result(context, Some(expires)).is_err());
    service.retire_claim_results(context)?;
    assert_eq!(context.pending_len(), 0);
    context.set_wall_for_test(expires);
    assert!(AccountServiceCoordinator::require_live_claim_result(context, Some(expires)).is_err());
    service.retire_claim_results(context)?;
    assert!(context.index().holds(TableId::RequestResult, &key));
    fixture.commit_staged_batch().await?;
    assert!(!fixture.stored_row_exists(TableId::RequestResult, key.clone())?);
    fixture.restart_registration_storage(vec![50; 32_768])?;
    let context = fixture.context_mut()?;
    assert_eq!(context.head().account_service_response_count, 1);
    assert!(!context.index().holds(TableId::RequestResult, &key));
    assert_eq!(
        context.index().expired_claim_replays(expires, 32).count(),
        0
    );
    assert!(
        context
            .initial_root_claim(account)?
            .is_some_and(|r| r.state == ClaimState::Chosen(pick))
    );
    Ok(())
}
