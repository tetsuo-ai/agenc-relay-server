//! Stored application ciphertext needs no global memory copy when no mailbox retains it.
#![forbid(unsafe_code)]
mod capacity;
mod expiry;
mod helpers;
mod io;
mod recovery_gates;
mod request_expiry;
mod selection;
use super::*;
use crate::e2ee::coordinator::CompanionCoordinator;
use crate::e2ee::coordinator::tests::support::private_message_bytes;
use agenc_ircd_e2ee::ObjectId;
use agenc_ircd_e2ee::envelope::{RouteExpectation, verify_application_object};
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::aad::IrcApplicationAad;
use agenc_ircd_e2ee::tls::TlsEncode;

#[tokio::test]
async fn startup_keeps_unreferenced_application_only_in_storage() -> TestResult {
    let mut core = StateCoreFixture::with_registration_router(entropy_script())?;
    let bytes = application(*core.identity.network_id.as_bytes())?;
    let id = *ObjectId::compute(&bytes).as_bytes();
    let context = core.context_mut()?;
    let plan = context.domain().plan_account_service_checkpoint()?;
    let write = CompanionCoordinator::object_write(&bytes)
        .map_err(|e| format!("object: {e:?}"))?
        .at_revision(plan.resulting_revision().get())?;
    context
        .stage_durable_with_account_service(
            plan,
            crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())?,
            None,
            0,
            vec![write],
        )
        .map_err(|e| format!("stage: {e:?}"))?;
    core.commit_staged_batch().await?;
    let commit = core.context_mut()?.head().storage_commit_sequence;
    let mut coordinator = empty_coordinator(&core)?;
    coordinator.startup(core.context_mut()?);
    let mut stored_body_seen = false;
    for _ in 0..32 {
        if coordinator.loaded() || coordinator.counters().violations != 0 {
            break;
        }
        let completion =
            tokio::time::timeout(std::time::Duration::from_secs(5), core.next_storage_read())
                .await??;
        for row in &completion
            .result
            .as_ref()
            .map_err(|e| format!("read: {e:?}"))?
            .records
        {
            if row.table == TableId::E2eeObject && row.key.as_bytes() == id {
                let plain = core.context_mut()?.open_storage_plaintext(
                    row.table,
                    &row.key,
                    &row.sealed_record,
                )?;
                let value =
                    PersistentRecordValue::decode(row.table, plain.expose_for_storage_codec())?;
                assert_eq!(
                    agenc_ircd_storage::e2ee_records::ObjectRow::decode(value.body())?.bytes,
                    bytes
                );
                stored_body_seen = true;
            }
        }
        assert!(coordinator.owns_storage_read(completion.read_id));
        coordinator.storage_read_completed(core.context_mut()?, completion);
    }
    assert!(stored_body_seen);
    assert!(coordinator.loaded());
    assert_eq!(coordinator.counters().violations, 0);
    assert_eq!(core.context_mut()?.head().storage_commit_sequence, commit);
    let executor = coordinator.companion_executor().ok_or("executor")?;
    assert!(
        !executor.state.objects.contains_key(&id),
        "startup copied an unreferenced application body into the global object cache"
    );
    assert_eq!(executor.state.object_bytes, 0);
    Ok(())
}

fn empty_coordinator(core: &StateCoreFixture) -> TestResult<FederationCoordinator> {
    let identity = &core.identity;
    let mut coordinator = FederationCoordinator::new(
        CoordinatorConfig {
            network_id: identity.network_id,
            server_id: identity.server_id,
            server_name: COORDINATOR_NAME.into(),
            recovery_epoch: identity.recovery_epoch,
            query_cursor_key: [21; 32],
            process_nonce: [22; 16],
            outbox_bytes_per_edge: 1 << 20,
            outbox_objects_per_edge: 64,
        },
        Vec::new(),
        std::sync::Arc::new(crate::test_support::TestChannelKeyVerifier),
        ChannelKeyVerifierRecord::new([7; 16], [1; 32]),
    );
    coordinator.install_companion_executor(
        CompanionCoordinator::new(
            *identity.network_id.as_bytes(),
            identity.server_id,
            COORDINATOR_NAME.into(),
        ),
        identity.server_incarnation,
    )?;
    Ok(coordinator)
}

fn application(network: [u8; 32]) -> TestResult<Vec<u8>> {
    let group = [33; 32];
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
    let object = IrcWireObject::new(
        IrcWireObjectKind::ApplicationMls,
        private_message_bytes(&group, 1, &aad)?,
    )?;
    let expected = RouteExpectation {
        network_id: network,
        conversation_id: conversation,
        route_binding: route,
        group_id: group,
    };
    let mut budget = agenc_ircd_e2ee::tls::DecodeBudget::new(65_536, 4096);
    verify_application_object(&object, &expected, &mut budget)?;
    Ok(object.encode()?)
}
