//! Two independently guarded accounts retain exact shares of one signed package through restart.
#![forbid(unsafe_code)]

use super::*;
use agenc_relay_storage::e2ee_records::{ClaimOutcome, PACKAGE_ROW_KIND, PackageRow, PackageState};
use agenc_relay_testkit::e2ee_client::{KeyPackageSpec, default_capabilities, key_package};

type Write = AccountServiceDurableWrite;

fn package_row(key: StoredKey, row: &PackageRow, revision: u64) -> TestResult<Write> {
    let value = PersistentRecordValue::new(
        TableId::E2eeState,
        PACKAGE_ROW_KIND,
        revision,
        0,
        None,
        Vec::new(),
        row.encode()?,
    )?;
    Ok(Write::put(TableId::E2eeState, key, value.encode()?)?)
}

async fn commit_owners(
    fixture: &mut StateCoreFixture,
    coordinator: &mut CompanionCoordinator,
    make: impl FnOnce(u64) -> TestResult<Vec<Write>>,
) -> TestResult {
    let context = fixture.context_mut()?;
    let plan = context.domain().plan_account_service_checkpoint()?;
    let revision = plan.resulting_revision().get();
    let mut writes = make(revision)?;
    let owners = coordinator
        .stage_owners(&mut writes, 1000, false, revision)
        .map_err(|_| "stage package owners")?;
    stage(context, plan, writes)?;
    fixture.commit_staged_batch().await?;
    owners.apply(&mut coordinator.state);
    Ok(())
}

async fn new_guarded(fixture: &mut StateCoreFixture, seed: u8) -> TestResult<AccountId> {
    let account = AccountRandomId::from_bytes([seed; 16]).to_account_id();
    let owner = RootClaimOwner {
        network: fixture.identity.network_id,
        account,
        epoch: fixture.identity.recovery_epoch,
        start: RequestId::from_bytes([seed; 16]),
        owner: InitialRootClaimOwner::from_protected_bytes([seed; 32]),
        state: RootClaimState::Reserved,
    };
    reserved_database(fixture, &owner).await?;
    Ok(account)
}

fn confirm(
    fixture: &mut StateCoreFixture,
    accounts: [AccountId; 2],
    blocks: [u64; 2],
) -> TestResult {
    for (account, count) in accounts.into_iter().zip(blocks) {
        assert_eq!(saved_directory_bytes(fixture, account)?, count * 4096);
    }
    fixture.restart_registration_storage(vec![57; 65_536])?;
    for (account, count) in accounts.into_iter().zip(blocks) {
        assert_eq!(saved_directory_bytes(fixture, account)?, count * 4096);
    }
    Ok(())
}

#[tokio::test]
async fn guarded_stock_and_distinct_claim_owners_charge_and_retire_independently() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![55; 65_536])?;
    let network = fixture.identity.network_id;
    let publisher = new_guarded(&mut fixture, 61).await?;
    let claimant = new_guarded(&mut fixture, 62).await?;
    let ids = [publisher, claimant];
    let publishing = account_id_digest(network.as_bytes(), publisher.to_text().as_bytes())?;
    let claiming = account_id_digest(network.as_bytes(), claimant.to_text().as_bytes())?;
    let mut coordinator = CompanionCoordinator::new(
        *network.as_bytes(),
        fixture.identity.server_id,
        "coord.test".into(),
    );
    let mls = key_package(&KeyPackageSpec {
        identity: publisher.to_text().as_bytes(),
        leaf_seed: 17,
        suite: 1,
        lifetime: (100, 2000),
        capabilities: default_capabilities(),
        leaf_extensions: Vec::new(),
    })?;
    let mut budget = agenc_relay_e2ee::tls::DecodeBudget::new(1 << 16, 1 << 14);
    let agenc_relay_e2ee::mls_outer::MlsOuterMessage::KeyPackage(package) =
        agenc_relay_e2ee::mls_outer::parse_mls_message(&mls, &mut budget)?
    else {
        return Err("expected MLS KeyPackage".into());
    };
    agenc_relay_e2ee::mls_outer::verify_key_package_signatures(&package)?;
    let reference = package.key_package_ref.to_vec();
    let bytes = ArcWireObject::new(ArcWireObjectKind::KeyPackageMls, mls)?.encode()?;
    let stock = PackageRow::package_key(&reference)?;
    let object = *agenc_relay_e2ee::ObjectId::compute(&bytes).as_bytes();
    let claim = PackageRow::claim_key(&claiming, &[4; 16])?;
    let stock_row = PackageRow::Package {
        account_digest: publishing,
        device_id: [5; 16],
        suite: 1,
        expires_at: 2000,
        object_id: object,
        state: PackageState::Published,
        claimed_by: None,
    };
    commit_owners(&mut fixture, &mut coordinator, |rev| {
        Ok(vec![
            CompanionCoordinator::object_write(&bytes)
                .map_err(|_| "package object")?
                .at_revision(rev)?,
            package_row(stock.clone(), &stock_row, rev)?,
        ])
    })
    .await?;
    confirm(&mut fixture, ids, [5, 2])?;
    // A retained older layout can have both a stock reference and a successful claim.
    // The two references share the immutable object but must pay and release independently.
    let row = PackageRow::Claim {
        target_account_digest: publishing,
        target_device_id: [5; 16],
        suite: 1,
        outcome: ClaimOutcome::Claimed,
        key_package_ref: reference,
        object_id: Some(object),
        retain_until: 2000,
    };
    commit_owners(&mut fixture, &mut coordinator, |rev| {
        Ok(vec![package_row(claim.clone(), &row, rev)?])
    })
    .await?;
    confirm(&mut fixture, ids, [5, 5])?;
    commit_owners(&mut fixture, &mut coordinator, |_| {
        Ok(vec![Write::delete(TableId::E2eeState, stock)?])
    })
    .await?;
    confirm(&mut fixture, ids, [2, 5])?;
    commit_owners(&mut fixture, &mut coordinator, |_| {
        Ok(vec![Write::delete(TableId::E2eeState, claim)?])
    })
    .await?;
    confirm(&mut fixture, ids, [2, 2])?;
    assert!(fixture.stored_row_exists(TableId::E2eeObject, StoredKey::new(object.to_vec())?)?);
    Ok(())
}
