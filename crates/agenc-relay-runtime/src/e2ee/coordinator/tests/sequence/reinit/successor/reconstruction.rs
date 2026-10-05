//! Authenticated retained successors must have one compatible activation lineage.

#![forbid(unsafe_code)]

use super::*;
use crate::e2ee::coordinator::tests::support::{
    BindingSpec, PolicySpec, binding_package, channel_route, policy, policy_id_of, sign,
};
use crate::e2ee::coordinator::tests::{account_id_digest, wire_raw};
use crate::e2ee::coordinator::{CompanionCoordinator, CompanionFault};
use crate::state_core::durable::AccountServiceDurableWrite as Write;
use crate::state_core::fanout::FanoutRequest;
use crate::test_support::StateCoreFixture;
use agenc_relay_e2ee::objects::conversation::{ArcConversationKind, ArcPolicy};
use agenc_relay_storage::{PersistentRecordValue, ReadPlan, StoredKey, TableId};

const INDEPENDENT_INSTANCE: [u8; 16] = [98; 16];

#[tokio::test]
async fn sealed_reconstruction_rejects_an_independent_route_at_an_activation_target() -> TestResult
{
    let mut migrated = Fixture::prepare()?;
    migrated.activate()?;
    let independent = independent_root(migrated.new)?;
    let mut rows = copy_rows(&independent.writes)?;
    let normal = Box::pin(reconstruct(&rows)).await?;
    assert!(normal.1.is_ok());
    let expected = normal
        .0
        .state
        .logs
        .get(&migrated.new)
        .cloned()
        .ok_or("independent log")?;
    assert_eq!(expected.accepted_epoch(), 0);
    // Keep the migrated predecessor's final rows and add only distinct keys
    // from the independently valid history. No row body or signature is forged.
    rows = copy_rows(&migrated.harness.writes)?;
    append_missing(&mut rows, &independent.writes)?;
    let (restored, result) = Box::pin(reconstruct(&rows)).await?;
    assert!(
        result.is_err(),
        "incompatible signed histories must refuse startup; independent route survived: {}",
        restored.state.logs.get(&migrated.new) == Some(&expected)
    );
    Ok(())
}

#[tokio::test]
async fn sealed_reconstruction_preserves_a_bound_successors_later_head() -> TestResult {
    let mut fixture = Fixture::prepare()?;
    fixture.activate()?;
    let package = fixture.package.clone();
    ok(fixture.bind(&package, fixture.context)?)?;
    let aad = agenc_relay_e2ee::objects::aad::ArcCommitAad {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: fixture.new,
        route_binding: package.binding.tbs.route_binding,
        validation_time: 20,
        prior_state_id: fixture.activation_id,
    }
    .encode()?;
    let candidate = wire_raw(
        ArcWireObjectKind::CommitMls,
        crate::e2ee::coordinator::tests::support::private_message_at_epoch(
            &SUCCESSOR_GROUP,
            1,
            3,
            &aad,
        )?,
    )?;
    ok(fixture
        .harness
        .run(Op::SubmitCandidate, &fixture.new, Some(&candidate))?)?;
    let before = &fixture.harness.coordinator.state;
    let expected = before
        .logs
        .get(&fixture.new)
        .cloned()
        .ok_or("successor log")?;
    let lifecycle = before
        .lifecycles
        .get(&fixture.new)
        .cloned()
        .ok_or("successor lifecycle")?;
    let (restored, result) = Box::pin(reconstruct(&fixture.harness.writes)).await?;
    result?;
    assert_eq!(restored.state.logs.get(&fixture.new), Some(&expected));
    assert_eq!(
        restored.state.lifecycles.get(&fixture.new),
        Some(&lifecycle)
    );
    assert_eq!(
        restored
            .state
            .conversations
            .get(&fixture.new)
            .map(|state| state.context_digest),
        Some(fixture.context)
    );
    assert_eq!(
        restored
            .state
            .routes
            .channel_route(&agenc_relay_types::ChannelInstanceId::from_bytes(INSTANCE))
            .map(|route| route.conversation_id),
        Some(ConversationId(fixture.new))
    );
    Ok(())
}

fn independent_root(conversation: [u8; 32]) -> TestResult<Harness> {
    independent_root_with_group(conversation, SUCCESSOR_GROUP)
}

/// A harness with `#room` and an independent `#other` conversation of
/// `group`, both bound with their policies and leaf-zero proofs.
pub(in crate::e2ee::coordinator::tests::sequence) fn independent_root_with_group(
    conversation: [u8; 32],
    group: [u8; 32],
) -> TestResult<Harness> {
    let mut harness = Harness::new()?;
    harness.bind_channel()?;
    let (package, initial, operational) = independent_package(&harness, conversation, group)?;
    let mut reserve = INDEPENDENT_INSTANCE.to_vec();
    reserve.push(6);
    reserve.extend_from_slice(b"#other");
    let ResultBody::Reserved(reservation, _) =
        ok(harness.run(Op::ReserveChannel, &reserve, None)?)?.result
    else {
        return Err("independent reservation".into());
    };
    let mut parameters = reservation.to_vec();
    parameters.extend_from_slice(&conversation);
    parameters.extend_from_slice(&[44; 32]);
    let bytes = wire(ArcWireObjectKind::ConversationBinding, &package)?;
    ok(harness.run(Op::BindGroup, &parameters, Some(&bytes))?)?;
    harness.publish_policy(conversation, &initial)?;
    harness.publish_policy(conversation, &operational)?;
    harness.publish_leaf_zero(conversation)?;
    Ok(harness)
}

fn independent_package(
    harness: &Harness,
    conversation: [u8; 32],
    group: [u8; 32],
) -> TestResult<(ArcConversationBindingPackage, ArcPolicy, ArcPolicy)> {
    let principals = std::slice::from_ref(&harness.principal);
    let bootstrap = PolicySpec::bootstrap(principals, conversation, ArcConversationKind::Channel);
    let initial = policy(&bootstrap)?;
    let operational = policy(&bootstrap.successor(policy_id_of(&initial)?))?;
    let fingerprint = root_fingerprint(&harness.principal.root)?;
    let mut package = binding_package(&BindingSpec {
        principals,
        route: channel_route(b"#other", fingerprint)?,
        channel_instance_id: Some(INDEPENDENT_INSTANCE),
        conversation_nonce: None,
        group_id: group,
        generation: 0,
        previous_binding_id: [0; 32],
        lock_sequence: 1,
        plan_devices: vec![(&harness.account, fingerprint, DEVICE)],
        initial_policy_id: policy_id_of(&initial)?,
        required_operational_policy_id: policy_id_of(&operational)?,
        sequencer_credential_id: harness.pinned_credential(),
    })?;
    let digest = account_id_digest(&NETWORK, &harness.account)?;
    let (sequence, prior) = harness
        .coordinator
        .state
        .binding_locks
        .get(&(digest, fingerprint))
        .and_then(|locks| locks.last_key_value())
        .ok_or("prior lock")?;
    let mut locks = package.root_binding_locks.as_slice().to_vec();
    let lock = locks.first_mut().ok_or("root lock")?;
    lock.tbs.root_binding_sequence = sequence.checked_add(1).ok_or("lock sequence overflow")?;
    lock.tbs.previous_root_binding_lock_id = prior.lock_id;
    lock.root_signature = sign(
        &harness.principal.root_secret,
        SignatureDomain::RootBindingLock,
        &lock.tbs,
    )?;
    package.root_binding_locks = TlsVec::new(locks)?;
    Ok((package, initial, operational))
}

#[tokio::test]
async fn sealed_reconstruction_rejects_duplicate_predecessor_ownership() -> TestResult {
    let mut first = Fixture::prepare()?;
    first.activate()?;
    let second_group = [12; 32];
    let second_old = agenc_relay_e2ee::ids::conversation_id(&NETWORK, &second_group)?;
    let second_root = independent_root_with_group(second_old, second_group)?;
    let mut second = Fixture::prepare_bound(second_root, second_old)?;
    second.activate()?;
    assert_ne!(first.old, second.old);
    assert_eq!(first.new, second.new);
    assert_ne!(first.activation_id, second.activation_id);
    // Each complete source reconstructs independently before their distinct
    // predecessor rows are combined into a contradictory retained image.
    for fixture in [&first, &second] {
        let (_, result) = Box::pin(reconstruct(&fixture.harness.writes)).await?;
        result?;
    }
    let mut rows = copy_rows(&first.harness.writes)?;
    append_missing(&mut rows, &second.harness.writes)?;
    for _ in 0..2 {
        let (restored, result) = Box::pin(reconstruct(&rows)).await?;
        assert!(result.is_err(), "two predecessors cannot own one successor");
        assert!(
            !restored.state.logs.contains_key(&first.new),
            "duplicate ownership must refuse before choosing an activation anchor"
        );
        rows.reverse();
    }
    Ok(())
}

fn copy_rows(source: &[Write]) -> TestResult<Vec<Write>> {
    let mut rows = Vec::new();
    append_missing(&mut rows, source)?;
    Ok(rows)
}

fn append_missing(rows: &mut Vec<Write>, source: &[Write]) -> TestResult {
    for write in source {
        let Write::Put {
            table,
            key,
            plaintext,
        } = write
        else {
            return Err("final logical fixture image must contain only surviving rows".into());
        };
        if rows.iter().any(|row| {
            matches!(row, Write::Put { table: present_table, key: present_key, .. }
            if present_table == table && present_key == key)
        }) {
            continue;
        }
        rows.push(Write::put(*table, key.clone(), plaintext.to_vec())?);
    }
    Ok(())
}

async fn reconstruct(
    rows: &[Write],
) -> TestResult<(CompanionCoordinator, Result<(), CompanionFault>)> {
    let mut storage = StateCoreFixture::new(vec![44; 65_536])?;
    let keys = Box::pin(seal_rows(&mut storage, rows)).await?;
    let mut fresh = Harness::new()?;
    for (table, key) in keys {
        let read = storage
            .context_mut()?
            .submit_storage_read(ReadPlan::exact(table, key))?;
        let message = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            storage.next_storage_read(),
        )
        .await??;
        assert_eq!(message.read_id, read);
        let result = message.result?;
        assert_eq!(result.records.len(), 1);
        for record in result.records {
            let plaintext = storage.context_mut()?.open_storage_plaintext(
                table,
                &record.key,
                &record.sealed_record,
            )?;
            let value = PersistentRecordValue::decode(table, plaintext.expose_for_storage_codec())?;
            fresh.coordinator.admit_restored_with_backing(
                table,
                &record.key,
                &value,
                &storage.context_mut()?.backing_reservations(),
            );
        }
    }
    let result = fresh
        .coordinator
        .finish_restore_with_backing(storage.context_mut()?.backing_reservations());
    Ok((fresh.coordinator, result))
}

async fn seal_rows(
    storage: &mut StateCoreFixture,
    rows: &[Write],
) -> TestResult<Vec<(TableId, StoredKey)>> {
    let context = storage.context_mut()?;
    let plan = context.domain().plan_account_service_checkpoint()?;
    let revision = plan.resulting_revision().get();
    let writes = copy_rows(rows)?
        .into_iter()
        .map(|row| row.at_revision(revision))
        .collect::<Result<Vec<_>, _>>()?;
    let keys = writes
        .iter()
        .filter_map(|write| match write {
            Write::Put { table, key, .. } => Some((*table, key.clone())),
            Write::Delete { .. } => None,
        })
        .collect();
    context
        .stage_durable_with_account_service(
            plan,
            FanoutRequest::new(Vec::new(), Vec::new())?,
            None,
            0,
            writes,
        )
        .map_err(|error| format!("sealed reconstruction stage: {error:?}"))?;
    storage.commit_staged_batch().await?;
    Ok(keys)
}
