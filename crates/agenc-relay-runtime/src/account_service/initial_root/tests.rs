#![forbid(unsafe_code)]

use super::*;
use crate::state_core::fanout::FanoutRequest;
use crate::test_support::{StateCoreFixture, TestResult, account_service_config};
use agenc_relay_auth::initial_root::{ClaimAction, open_claim, seal_claim};
use agenc_relay_crypto::{AccountHpkePrivateKey, AccountRequestBinding, InitialRootSecret};
use agenc_relay_types::AccountRandomId;

#[tokio::test]
async fn a_registered_seal_waits_in_its_bounded_queue_for_an_unrelated_writer() -> TestResult {
    let mut core = StateCoreFixture::new(vec![9; 16_384])?;
    let mut service = AccountServiceCoordinator::new(account_service_config(
        &core.identity,
        &core.opaque,
        core.key_state,
    )?)?;
    let network = core.identity.network_id;
    let epoch = core.identity.recovery_epoch;
    let account = AccountRandomId::from_bytes([61; 16]).to_account_id();
    let generation = Generation::new(1)?;
    let private = AccountHpkePrivateKey::generate()?;
    let public = private.public_key()?;
    let binding = AccountRequestBinding::new(
        network,
        epoch,
        public.key_id(),
        RequestId::from_bytes([2; 16]),
        InitialRootExchange::Claim,
    );
    let (sealed, _) = seal_claim(
        public,
        binding,
        account,
        RequestId::from_bytes([3; 16]),
        &InitialRootSecret::generate()?,
        ClaimAction::Read,
    )?;
    let opened = open_claim(&private, network, epoch, &sealed)?;
    let connection = ConnectionGeneration::new(19);
    service.push_ready_seal(ReadySeal::Claim {
        request: RequestContext {
            generation: connection,
            carrier_generation: 1,
            target: "guarded-test".into(),
            route: ConnectionRoute {
                origin_id: OriginId::from_bytes([4; 16]),
                origin_generation: generation,
                connection_id: ConnectionId::from_bytes([5; 16]),
                connection_nonce: [6; 32],
            },
            envelope: RoutedEnvelope::InitialRoot(sealed),
            carrier: RequestCarrier::InitialRoot(InitialRootCarrier::Claim),
            phase: AccountCarrierPhase::Start,
        },
        scope: RegisteredClaim {
            account,
            generation,
            session: SessionId::from_bytes([7; 16]),
        },
        opened,
    })?;
    let context = core.context_mut()?;
    let plan = context.domain().plan_account_created(AccountState::new(
        AccountRandomId::from_bytes([62; 16]).to_account_id(),
        generation,
        context.domain().revision(),
    ))?;
    context
        .stage_durable_with_account_service(
            plan,
            FanoutRequest::new(Vec::new(), Vec::new())?,
            None,
            0,
            Vec::new(),
        )
        .map_err(|_| "unrelated account write was refused")?;
    assert_eq!(context.pending_len(), 1);
    assert!(service.progress_ready_seal(context).is_none());
    assert_eq!(service.ready_seals.len(), 1);
    assert!(service.crypto.is_empty());
    core.commit_staged_batch().await?;
    // This caller has no live registration when the unrelated commit completes.
    let refusal = service
        .progress_ready_seal(core.context_mut()?)
        .ok_or("stale registration accepted")?;
    assert_eq!(refusal.generation, connection);
    assert!(refusal.close);
    assert!(service.ready_seals.is_empty() && service.crypto.is_empty());
    Ok(())
}
