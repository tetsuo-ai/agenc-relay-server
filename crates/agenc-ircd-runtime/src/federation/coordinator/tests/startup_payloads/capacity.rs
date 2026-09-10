//! Actual sealed storage exceeds the former global body limit while one mailbox stays resident.
#![forbid(unsafe_code)]
use super::*;
use crate::e2ee::coordinator::tests::support::opaque_v;
use crate::state_core::durable::AccountServiceDurableWrite as Write;
use agenc_ircd_e2ee::limits::{MAX_APPLICATION_MLS_OBJECT, WIRE_OBJECT_ENVELOPE_BYTES};
use agenc_ircd_storage::e2ee_records::{
    MAILBOX_ROW_KIND, MAILBOX_SEQUENCE_ROW_KIND, MailboxKind, MailboxRow, MailboxSequenceRow,
    ObjectRow,
};
use std::collections::{BTreeMap, BTreeSet};

const OBJECTS: u64 = 4097;
const BATCH_OBJECTS: usize = 64;
const FORMER_LIMIT: usize = 256 * 1024 * 1024;

#[tokio::test]
#[ignore = "CAP-79 capacity corpus; run explicitly on the qualification filesystem"]
async fn selective_startup_recovers_more_than_256_mib_from_reopened_storage() -> TestResult {
    let mut core = StateCoreFixture::with_registration_router(entropy_script())?;
    let network = *core.identity.network_id.as_bytes();
    let expected = seed(&mut core, network).await?;
    let total = usize::try_from(OBJECTS)?
        .checked_mul(MAX_APPLICATION_MLS_OBJECT)
        .ok_or("size")?;
    assert!(total > FORMER_LIMIT);
    let before = core.context_mut()?.head().storage_commit_sequence;
    core.restart_registration_storage(entropy_script())?;
    assert!(core.context_mut()?.head().storage_commit_sequence >= before);
    let budget = core.context_mut()?.backing_budget_for_test();
    let baseline = budget.charged();
    let mut coordinator = empty_coordinator(&core)?;
    coordinator.startup(core.context_mut()?);
    let mut peak = budget.charged();
    let mut seen = BTreeSet::new();
    for _ in 0..256 {
        if coordinator.loaded() || coordinator.counters().violations != 0 {
            break;
        }
        let message = helpers::next(&mut core).await?;
        verify_page(&mut core, &message, &expected, &mut seen, network)?;
        assert!(coordinator.owns_storage_read(message.read_id));
        coordinator.storage_read_completed(core.context_mut()?, message);
        peak = peak.max(budget.charged());
    }
    assert!(coordinator.loaded());
    assert_eq!(coordinator.counters().violations, 0);
    assert_eq!(seen.len(), usize::try_from(OBJECTS)?);
    let resident = payload(network, 0)?;
    let id = *ObjectId::compute(&resident).as_bytes();
    let executor = coordinator.companion_executor().ok_or("executor")?;
    assert_eq!(executor.state.mailboxes.item_count(), 1);
    assert_eq!(executor.state.objects.len(), 1);
    assert_eq!(executor.state.objects.get(&id), Some(&resident));
    assert_eq!(executor.state.object_bytes, MAX_APPLICATION_MLS_OBJECT);
    assert_eq!(executor.state.object_memory.len(), 1);
    let startup_charge = peak.checked_sub(baseline).ok_or("charge")?;
    assert!(startup_charge < u64::try_from(FORMER_LIMIT)?);
    eprintln!(
        "selective startup: {total} stored object bytes, {} verified objects, {} resident bytes, {startup_charge} peak additional charged bytes",
        seen.len(),
        executor.state.object_bytes
    );
    drop(coordinator);
    assert_eq!(budget.charged(), baseline);
    Ok(())
}

async fn seed(
    core: &mut StateCoreFixture,
    network: [u8; 32],
) -> TestResult<BTreeMap<[u8; 32], u64>> {
    let mut expected = BTreeMap::new();
    let mut writes = Vec::with_capacity(BATCH_OBJECTS);
    for index in 0..OBJECTS {
        let bytes = payload(network, index)?;
        let id = *ObjectId::compute(&bytes).as_bytes();
        assert!(expected.insert(id, index).is_none());
        writes.push(
            CompanionCoordinator::object_write(&bytes).map_err(|e| format!("object: {e:?}"))?,
        );
        if writes.len() == BATCH_OBJECTS {
            helpers::commit(core, std::mem::take(&mut writes)).await?;
        }
    }
    if !writes.is_empty() {
        helpers::commit(core, writes).await?;
    }
    helpers::commit(core, mailbox_owner(network)?).await?;
    Ok(expected)
}

fn payload(network: [u8; 32], index: u64) -> TestResult<Vec<u8>> {
    let mut group = [33; 32];
    group[24..].copy_from_slice(&index.to_be_bytes());
    let conversation = agenc_ircd_e2ee::ids::conversation_id(&network, &group)?;
    let route = agenc_ircd_e2ee::route::channel_route_binding(&network, &[8; 16])?;
    let aad = IrcApplicationAad {
        profile_version: 1,
        network_id: network,
        conversation_id: conversation,
        route_binding: route,
        latest_state_id: [22; 32],
    }
    .encode()?;
    let mut body = vec![0, 1, 0, 2];
    opaque_v(&mut body, &group)?;
    body.extend_from_slice(&9_u64.to_be_bytes());
    body.push(1);
    opaque_v(&mut body, &aad)?;
    opaque_v(&mut body, &[1; 40])?;
    // The final opaque ciphertext uses a four-byte canonical MLS length.
    let ciphertext = MAX_APPLICATION_MLS_OBJECT
        .checked_sub(WIRE_OBJECT_ENVELOPE_BYTES + body.len() + 4)
        .ok_or("body size")?;
    opaque_v(&mut body, &vec![2; ciphertext])?;
    let object = IrcWireObject::new(IrcWireObjectKind::ApplicationMls, body)?;
    let expected = RouteExpectation {
        network_id: network,
        conversation_id: conversation,
        route_binding: route,
        group_id: group,
    };
    let mut budget = agenc_ircd_e2ee::tls::DecodeBudget::new(MAX_APPLICATION_MLS_OBJECT, 4096);
    verify_application_object(&object, &expected, &mut budget)?;
    let bytes = object.encode()?;
    assert_eq!(bytes.len(), MAX_APPLICATION_MLS_OBJECT);
    Ok(bytes)
}

fn mailbox_owner(network: [u8; 32]) -> TestResult<Vec<Write>> {
    let bytes = payload(network, 0)?;
    let mut group = [33; 32];
    group[24..].copy_from_slice(&0_u64.to_be_bytes());
    let owner = MailboxSequenceRow::new([1; 32], [2; 16], MailboxKind::Application, 1)?;
    let item = MailboxRow::Item {
        object_id: *ObjectId::compute(&bytes).as_bytes(),
        conversation_id: agenc_ircd_e2ee::ids::conversation_id(&network, &group)?,
        inserted_at: 1000,
        expires_at: 87400,
        grant: None,
    };
    [
        (owner.key()?, MAILBOX_SEQUENCE_ROW_KIND, owner.encode()?),
        (
            MailboxRow::item_key(&[1; 32], &[2; 16], MailboxKind::Application, 0)?,
            MAILBOX_ROW_KIND,
            item.encode()?,
        ),
    ]
    .into_iter()
    .map(|(key, kind, body)| {
        let value =
            PersistentRecordValue::new(TableId::E2eeState, kind, 1, 0, None, Vec::new(), body)?;
        Ok(Write::put(TableId::E2eeState, key, value.encode()?)?)
    })
    .collect()
}

fn verify_page(
    core: &mut StateCoreFixture,
    message: &crate::bridge::StorageReadCompletionMessage,
    expected: &BTreeMap<[u8; 32], u64>,
    seen: &mut BTreeSet<[u8; 32]>,
    network: [u8; 32],
) -> TestResult {
    let result = message
        .result
        .as_ref()
        .map_err(|e| format!("read: {e:?}"))?;
    assert_eq!(
        result.storage_commit_sequence,
        core.context_mut()?.head().storage_commit_sequence
    );
    for row in &result.records {
        if row.table != TableId::E2eeObject {
            continue;
        }
        let id: [u8; 32] = row.key.as_bytes().try_into()?;
        let index = *expected.get(&id).ok_or("unexpected object")?;
        assert!(seen.insert(id));
        let plain =
            core.context_mut()?
                .open_storage_plaintext(row.table, &row.key, &row.sealed_record)?;
        let value = PersistentRecordValue::decode(row.table, plain.expose_for_storage_codec())?;
        let stored = ObjectRow::decode(value.body())?;
        assert_eq!(stored.bytes, payload(network, index)?);
        assert_eq!(*ObjectId::compute(&stored.bytes).as_bytes(), id);
    }
    Ok(())
}
