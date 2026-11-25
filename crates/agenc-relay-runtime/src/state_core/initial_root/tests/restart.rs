//! Cross-check the retained disposition against actual signed public roots on a reopened database.
#![forbid(unsafe_code)]

use super::*;
use crate::e2ee::coordinator::CompanionCoordinator;
use agenc_relay_crypto::{LoginIndexDigest, SignatureDomain};
use agenc_relay_e2ee::ids::account_id_digest;
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::identity::{ArcRootIdentity, ArcRootIdentityTbs};
use agenc_relay_e2ee::tls::{Opaque, TlsEncode};
use agenc_relay_storage::e2ee_records::{DIRECTORY_ROW_KIND, DirectoryRow};
use agenc_relay_storage::{
    LIVE_RECORD_KIND, LoginIndexStoredKey, LoginIndexValue, LoginIndexValueKind, RecordReference,
};
use agenc_relay_testkit::e2ee_client::{account_field, key, public, root_fingerprint, sign};
use agenc_relay_types::{NetworkId, OpaqueCredentialId};

fn registered_rows(
    fixture: &StateCoreFixture,
    account: AccountId,
    revision: u64,
) -> TestResult<Vec<AccountServiceDurableWrite>> {
    let digest = account_id_digest(
        fixture.identity.network_id.as_bytes(),
        account.to_text().as_bytes(),
    )?;
    let key = LoginIndexStoredKey::new(
        fixture.key_state.current_generation(),
        LoginIndexDigest::from_storage_key(digest),
    )?;
    let login = LoginIndexValue::new(
        &key,
        LoginIndexValueKind::Live {
            account_id: account,
            opaque_credential_id: OpaqueCredentialId::from_bytes(digest),
        },
    )?;
    let account_key = crate::state_core::durable::KeyDeriver::account_key(account)?;
    // A valid synthetic registration record supplies the startup credential shape; no login is claimed here.
    let opaque = PersistentRecordValue::new(
        TableId::OpaqueRecord,
        LIVE_RECORD_KIND,
        revision,
        1,
        None,
        vec![RecordReference::new(TableId::Account, account_key.clone())?],
        fixture.opaque.expose_fake_record_for_persistence().to_vec(),
    )?;
    Ok(vec![
        AccountServiceDurableWrite::put(TableId::LoginIndex, key.encode()?, login.encode()?)?,
        AccountServiceDurableWrite::put(TableId::OpaqueRecord, account_key, opaque.encode()?)?,
    ])
}

async fn reserved_database(fixture: &mut StateCoreFixture, who: &RootClaimOwner) -> TestResult {
    let account = who.account;
    let context = fixture.context_mut()?;
    let account = AccountState::new(account, Generation::new(1)?, context.domain().revision())
        .with_initial_root_claim();
    let plan = context.domain().plan_account_created(account)?;
    let revision = plan.resulting_revision().get();
    let mut writes = registered_rows(fixture, who.account, revision)?;
    let fence = StoredKey::new(FORMAT_KEY.to_vec())?;
    if !fixture
        .context_mut()?
        .index
        .holds(TableId::E2eeState, &fence)
    {
        writes.push(initial_root_write(
            revision,
            fence,
            InitialRootRow::format()?,
        )?);
    }
    writes.push(owned_write(revision, who)?);
    stage(fixture.context_mut()?, plan, writes)?;
    fixture
        .commit_staged_batch()
        .await
        .map_err(|error| format!("seed guarded account: {error}"))?;
    Ok(())
}

fn signed_identity(
    network: NetworkId,
    account: AccountId,
    seed: u8,
    previous: Option<(u8, &ArcRootIdentity)>,
) -> TestResult<ArcRootIdentity> {
    let identity = key(seed);
    let tbs = ArcRootIdentityTbs {
        profile_version: 1,
        network_id: *network.as_bytes(),
        account_id: account_field(account.to_text().as_bytes().try_into()?)?,
        root_generation: previous.map_or(0, |(_, old)| old.tbs.root_generation + 1),
        root_public_key: public(&identity),
        not_before: 10,
        not_after: 999_999,
        previous_root_fingerprint: previous
            .map(|(_, root)| root_fingerprint(root))
            .transpose()?
            .unwrap_or_default(),
    };
    let self_signature = sign(&identity, SignatureDomain::RootIdentity, &tbs)?;
    let continuity = previous
        .map(|(old, _)| sign(&key(old), SignatureDomain::RootContinuity, &tbs))
        .transpose()?
        .map_or_else(Vec::new, |sig| sig.to_vec());
    Ok(ArcRootIdentity {
        tbs,
        self_signature,
        continuity_signature: Opaque::new(continuity)?,
    })
}

fn stage_publication(
    fixture: &mut StateCoreFixture,
    coordinator: &CompanionCoordinator,
    root: &ArcRootIdentity,
    chain: &[[u8; 32]],
) -> TestResult<([u8; 32], crate::e2ee::coordinator::owners::Staged)> {
    let bytes = ArcWireObject::new(ArcWireObjectKind::RootIdentity, root.encode()?)?.encode()?;
    let object = *agenc_relay_e2ee::ObjectId::compute(&bytes).as_bytes();
    let fingerprint = root_fingerprint(root)?;
    let account = AccountId::parse_wire_bytes(root.tbs.account_id.as_slice())?;
    let network = fixture.identity.network_id;
    let digest = account_id_digest(network.as_bytes(), &root.tbs.account_id.exactly::<24>()?)?;
    let context = fixture.context_mut()?;
    let plan = context.domain().plan_account_service_checkpoint()?;
    let mut writes = Vec::new();
    writes.extend(
        context
            .plan_signed_root(
                account,
                Generation::new(1)?,
                root.tbs.root_generation,
                fingerprint,
                object,
            )
            .map_err(|_| "signed root admission")?,
    );
    writes.push(
        CompanionCoordinator::object_write(&bytes)
            .map_err(|_| "signed object")?
            .at_revision(plan.resulting_revision().get())?,
    );
    let row = DirectoryRow::Identity {
        root_generation: root.tbs.root_generation,
        root_fingerprint: fingerprint,
        object_id: object,
        chain_object_ids: chain.iter().copied().chain([object]).collect(),
    };
    let directory = PersistentRecordValue::new(
        TableId::E2eeState,
        DIRECTORY_ROW_KIND,
        plan.resulting_revision().get(),
        0,
        None,
        vec![],
        row.encode()?,
    )?;
    writes.push(AccountServiceDurableWrite::put(
        TableId::E2eeState,
        DirectoryRow::identity_key(&digest)?,
        directory.encode()?,
    )?);
    let owners = coordinator
        .stage_owners(&mut writes, 1_000, false, plan.resulting_revision().get())
        .map_err(|_| "signed directory and object owners")?;
    stage(context, plan, writes)?;
    Ok((object, owners))
}

async fn publish(
    fixture: &mut StateCoreFixture,
    coordinator: &mut CompanionCoordinator,
    root: &ArcRootIdentity,
    chain: &mut Vec<[u8; 32]>,
) -> TestResult<[u8; 32]> {
    let (object, owners) = stage_publication(fixture, coordinator, root, chain)?;
    fixture
        .commit_staged_batch()
        .await
        .map_err(|error| format!("publish generation {}: {error}", root.tbs.root_generation))?;
    owners.apply(&mut coordinator.state);
    chain.push(object);
    Ok(object)
}

fn saved_directory_bytes(fixture: &mut StateCoreFixture, account: AccountId) -> TestResult<u64> {
    use agenc_relay_storage::e2ee_records::initial_root::directory::Subtotal;
    use agenc_relay_storage::{ReadPlan, SealedRecord};
    let digest = account_id_digest(
        fixture.identity.network_id.as_bytes(),
        account.to_text().as_bytes(),
    )?;
    let key = Subtotal {
        account: digest,
        bytes: 4096,
    }
    .key()?;
    let result = fixture.read_rows(ReadPlan::exact(TableId::E2eeState, key.clone()))?;
    let [row] = result.records.as_slice() else {
        return Err("scoped directory receipt missing".into());
    };
    let plain = fixture.context_mut()?.keys.open(
        TableId::E2eeState,
        &key,
        &SealedRecord::decode(&row.sealed_record)?,
    )?;
    let value =
        PersistentRecordValue::decode(TableId::E2eeState, plain.expose_for_storage_codec())?;
    let InitialRootRow::Directory(total) = InitialRootRow::check_record(&key, &value)? else {
        return Err("expected directory subtotal".into());
    };
    Ok(total.bytes)
}

#[tokio::test]
async fn guarded_initial_root_survives_four_reopens_and_a_signed_rotation_with_original_receipt()
-> TestResult {
    let mut fixture = StateCoreFixture::new(vec![47; 32_768])?;
    let network = fixture.identity.network_id;
    let account = AccountRandomId::from_bytes([27; 16]).to_account_id();
    let original = RootClaimOwner {
        network,
        account,
        epoch: fixture.identity.recovery_epoch,
        start: RequestId::from_bytes([28; 16]),
        owner: InitialRootClaimOwner::from_protected_bytes([29; 32]),
        state: RootClaimState::Reserved,
    };
    reserved_database(&mut fixture, &original).await?;
    assert_eq!(saved_directory_bytes(&mut fixture, account)?, 2 * 4096);
    let none = crate::sync::Arc::new(crate::budget::MemoryBudget::new(0));
    let Err(error) = fixture.recover_with_account_budget(&none) else {
        return Err("fresh startup must reserve the private owner".into());
    };
    assert!(matches!(
        error.downcast_ref::<RuntimeError>(),
        Some(RuntimeError::MemoryExhausted)
    ));
    assert_eq!(none.charged(), 0);
    assert_eq!(fixture.recovered_startup_cleanup_count()?, 0);
    fixture.restart_registration_storage(vec![48; 32_768])?;
    let generation = Generation::new(1)?;
    let first = signed_identity(network, account, 41, None)?;
    let alternate = signed_identity(network, account, 42, None)?;
    let chosen = root_fingerprint(&first)?;
    let foreign = root_fingerprint(&alternate)?;
    let context = fixture.context_mut()?;
    let (cut, saved) = context.initial_root_admission(account, generation)?;
    assert!(
        saved.is_some_and(|s| s.state == ClaimState::Reserved && original.owner.matches(s.owner))
    );
    let mut writes = vec![];
    let plan = context.plan_initial_root_choice(cut, Some(chosen), &mut writes)?;
    stage(context, plan, writes)?;
    fixture.commit_staged_batch().await?;
    fixture.restart_registration_storage(vec![49; 32_768])?;
    assert_eq!(saved_directory_bytes(&mut fixture, account)?, 2 * 4096);
    let context = fixture.context_mut()?;
    assert!(
        context
            .initial_root_claim(account)?
            .is_some_and(|s| s.state == ClaimState::Chosen(chosen))
    );
    assert!(matches!(
        context.plan_signed_root(account, generation, 0, foreign, [50; 32]),
        Err(E2eeReplyCode::BindingAuthInvalid)
    ));
    let mut chain = vec![];
    let mut coordinator = CompanionCoordinator::new(
        *network.as_bytes(),
        fixture.identity.server_id,
        "coord.test".into(),
    );
    let id = publish(&mut fixture, &mut coordinator, &first, &mut chain).await?;
    fixture.restart_registration_storage(vec![51; 32_768])?;
    assert_eq!(saved_directory_bytes(&mut fixture, account)?, 5 * 4096);
    let second = signed_identity(network, account, 43, Some((41, &first)))?;
    let next = publish(&mut fixture, &mut coordinator, &second, &mut chain).await?;
    assert_ne!(next, id);
    fixture.restart_registration_storage(vec![52; 32_768])?;
    assert_eq!(saved_directory_bytes(&mut fixture, account)?, 7 * 4096);
    assert!(
        fixture
            .context_mut()?
            .initial_root_claim(account)?
            .is_some_and(|s| s.state
                == ClaimState::Published {
                    fingerprint: chosen,
                    object_id: id
                }
                && s.creation_request == original.start)
    );
    Ok(())
}

mod quota;
mod stock;
