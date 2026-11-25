//! Actual root rotation, named object ownership and sealed directory costs at the operator minimum.
#![forbid(unsafe_code)]

use super::*;
use crate::state_core::BatchStep;

#[tokio::test]
async fn guarded_directory_refuses_another_signed_rotation_at_one_mib_and_reopens_the_same_receipt()
-> TestResult {
    const LIMIT: u64 = 1024 * 1024;
    let mut fixture = StateCoreFixture::new(vec![51; 1024 * 1024])?;
    let network = fixture.identity.network_id;
    let account = AccountRandomId::from_bytes([20; 16]).to_account_id();
    let original = RootClaimOwner {
        network,
        account,
        epoch: fixture.identity.recovery_epoch,
        start: RequestId::from_bytes([23; 16]),
        owner: InitialRootClaimOwner::from_protected_bytes([24; 32]),
        state: RootClaimState::Reserved,
    };
    fixture
        .context_mut()?
        .index
        .guarded_directory
        .set_limit(LIMIT);
    reserved_database(&mut fixture, &original).await?;
    let mut root = signed_identity(network, account, 1, None)?;
    let chosen = root_fingerprint(&root)?;
    let context = fixture.context_mut()?;
    let (cut, _) = context.initial_root_admission(account, Generation::new(1)?)?;
    let mut writes = vec![];
    let plan = context.plan_initial_root_choice(cut, Some(chosen), &mut writes)?;
    stage(context, plan, writes)?;
    fixture.commit_staged_batch().await?;
    let mut coordinator = CompanionCoordinator::new(
        *network.as_bytes(),
        fixture.identity.server_id,
        "coord.test".into(),
    );
    let mut chain = vec![];
    let initial = publish(&mut fixture, &mut coordinator, &root, &mut chain).await?;
    for seed in 2..=126 {
        root = signed_identity(network, account, seed, Some((seed - 1, &root)))?;
        publish(&mut fixture, &mut coordinator, &root, &mut chain).await?;
    }
    assert_eq!(chain.len(), 126);
    assert_eq!(saved_directory_bytes(&mut fixture, account)?, LIMIT);
    let excess = signed_identity(network, account, 127, Some((126, &root)))?;
    let budget = crate::sync::Arc::new(crate::budget::MemoryBudget::new(512 * 1024 * 1024));
    assert_eq!(fixture.recover_with_directory_limit(&budget, LIMIT)?, 0);
    let Err(error) = fixture.recover_with_directory_limit(&budget, LIMIT - 1) else {
        return Err("a one-byte-short startup accepted the sealed directory".into());
    };
    assert!(matches!(
        error.downcast_ref::<RuntimeError>(),
        Some(RuntimeError::Storage(StorageError::LimitExceeded))
    ));
    for _ in 0..2 {
        let before = fixture.context_mut()?.head().storage_commit_sequence;
        let (object, pending) = stage_publication(&mut fixture, &coordinator, &excess, &chain)?;
        let result = fixture
            .context_mut()?
            .submit_batch()
            .map_err(|_| "quota rejection stopped the coordinator")?;
        let BatchStep::Rejected(rejections) = result else {
            return Err("over-limit rotation was admitted".into());
        };
        assert!(matches!(rejections.as_slice(), [r] if r.error == StorageError::LimitExceeded));
        drop(pending);
        assert_eq!(
            fixture.context_mut()?.head().storage_commit_sequence,
            before
        );
        assert!(!fixture.stored_row_exists(TableId::E2eeObject, StoredKey::new(object.to_vec())?)?);
        fixture.restart_registration_storage(vec![52; 1024 * 1024])?;
        fixture
            .context_mut()?
            .index
            .guarded_directory
            .set_limit(LIMIT);
        assert_eq!(saved_directory_bytes(&mut fixture, account)?, LIMIT);
        assert!(
            fixture
                .context_mut()?
                .initial_root_claim(account)?
                .is_some_and(|row| row.state
                    == ClaimState::Published {
                        fingerprint: chosen,
                        object_id: initial
                    })
        );
    }
    Ok(())
}
