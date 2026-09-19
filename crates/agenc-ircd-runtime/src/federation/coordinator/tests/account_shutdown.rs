//! Cancellation of unfinished remote account exchanges at durable lifecycle boundaries.
#![forbid(unsafe_code)]

use super::*;
use agenc_ircd_storage::{ReadPlan, StoredKey, TableId};
use std::time::Duration;

async fn unfinished_authentication(edge: &mut Edge, origin: &mut Origin) -> TestResult {
    edge.establish().await?;
    synchronize_ok(edge, &mut [origin]).await?;
    let envelope = crate::test_support::sealed_authentication_start(
        NETWORK,
        RecoveryEpoch::from_bytes([34; 16]),
        "absent-account",
        171,
    )?;
    let mut budget = DecodeBudget::new(8_192, 64);
    let envelope = SchemaObject::decode_exact("AccountServiceEnvelope", &envelope, &mut budget)?;
    request(
        edge,
        origin,
        &FederatedOperation::AccountService {
            opcode: agenc_ircd_types::FederationOpcode::OpaqueAuthStart,
            session_id: None,
            envelope,
        },
    )
    .await?;
    let challenge = answer(edge, &mut Vec::new()).await?;
    assert!(matches!(challenge.arm, ResultArm::AuthChallenge(_)));
    origin.sequence += 1;
    Ok(())
}

async fn delete_authentication_origin(edge: &mut Edge, origin: &Origin) -> TestResult {
    edge.frame(FederationFrame::OriginDel {
        coordinator_server_id: COORDINATOR,
        server_incarnation: edge.incarnation,
        origin_id: origin.id,
        generation: origin.generation,
        next_operation_sequence: origin.sequence,
    })
    .await?;
    assert!(matches!(
        edge.next_wire_frame().await?,
        FederationFrame::OriginAck {
            object_id: None,
            ..
        }
    ));
    // The next committed declaration cannot overtake account cleanup staged
    // by the preceding DEL receipt.
    let mut barrier = Origin::new(172);
    let _ready = declare(edge, &mut barrier, false).await?;
    Ok(())
}

async fn remote_authentication_lifecycle(
    delete_origin: bool,
) -> TestResult<(bool, usize, usize, u64)> {
    let peer = peer_identity(ServerId::from_bytes([44; 16]), "edge.example");
    let mut fixture = StateCoreFixture::with_federation_coordinator(entropy_script(), vec![peer])?;
    let mut parts = fixture.take_run_parts()?;
    let (inbox, inbox_receiver) = mpsc::channel(8);
    let (federation, federation_receiver) = mpsc::channel(64);
    parts.state.install_federation_inbox(federation_receiver)?;
    let (_close_port, close_inbox) = connection_close_channel();
    let (lifecycle, lifecycle_receiver) = lifecycle_channel();
    let driven = async move {
        let mut edge = Edge::new(federation, 44);
        let mut origin = Origin::new(164);
        let result: TestResult<bool> = async {
            unfinished_authentication(&mut edge, &mut origin).await?;
            if delete_origin {
                delete_authentication_origin(&mut edge, &origin).await?;
                return Ok(true);
            }
            for phase in [
                LifecyclePhase::Quiesce,
                LifecyclePhase::Drain,
                LifecyclePhase::Flush,
            ] {
                if !matches!(
                    tokio::time::timeout(Duration::from_secs(2), lifecycle.request(phase)).await,
                    Ok(Ok(()))
                ) {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        .await;
        let _stopped = lifecycle.request(LifecyclePhase::Stop).await;
        drop(inbox);
        result
    };
    let run = parts.state.run(
        inbox_receiver,
        close_inbox,
        lifecycle_receiver,
        parts.storage,
        parts.storage_reads,
        parts.checkpoints,
        parts.crypto,
        CancellationToken::root(),
    );
    let (exit, completed) = tokio::join!(run, driven);
    assert!(matches!(exit, StateCoreExit::Stopped), "{exit:?}");
    let virtual_connections = parts.state.context().sessions().len();
    let response_count = parts.state.context().head().account_service_response_count;
    let (storage, _crypto) = parts.state.into_bridges();
    let transactions = crate::bridge::storage::read_blocking(
        storage.port(),
        ReadPlan::range(
            TableId::AuthTransaction,
            StoredKey::new(vec![0; 16])?,
            StoredKey::new(vec![255; 16])?,
            10,
        )?,
    )?;
    Ok((
        completed?,
        virtual_connections,
        transactions.records.len(),
        response_count,
    ))
}

#[tokio::test]
async fn deleting_an_origin_cancels_its_unfinished_opaque_exchange() -> TestResult {
    let (completed, carriers, transactions, responses) =
        remote_authentication_lifecycle(true).await?;
    assert!(completed);
    assert_eq!(
        carriers, 0,
        "durable origin DEL must close its virtual account carrier"
    );
    assert_eq!(
        responses, 1,
        "cleanup cannot invent account-service responses"
    );
    assert_eq!(
        transactions, 0,
        "durable transaction cleanup must finish behind DEL"
    );
    Ok(())
}

#[tokio::test]
async fn shutdown_cancels_a_live_remote_opaque_exchange_before_drain() -> TestResult {
    let (completed, carriers, transactions, responses) =
        remote_authentication_lifecycle(false).await?;
    assert!(
        completed,
        "Drain must cancel unfinished exchanges before their ordinary timeout"
    );
    assert_eq!(carriers, 0);
    assert_eq!(
        responses, 1,
        "cleanup cannot invent account-service responses"
    );
    assert_eq!(
        transactions, 0,
        "Flush must cover durable authentication cleanup"
    );
    Ok(())
}

#[tokio::test]
async fn an_origin_del_closes_only_the_carrier_captured_by_its_durable_receipt() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let peer = ServerId::from_bytes([50; 16]);
    let mut coordinator = standalone_coordinator(peer);
    let context = fixture.context_mut()?;
    let (mut fresh, edge) = remote_account_staging_request(&mut coordinator, context)?;
    let key = fresh.key.origin;
    fresh.header.opcode = agenc_ircd_types::FederationOpcode::OpaqueAuthStart;
    fresh.command = None;
    coordinator
        .queue_remote_carrier(context, edge.link, peer, fresh, Vec::new())
        .map_err(|error| format!("carrier fixture: {error:?}"))?;
    let owner = coordinator
        .remote_carrier_for_origin(peer, *key.origin_id.as_bytes())
        .ok_or("carrier")?;
    let stale = OriginKey {
        server_incarnation: ServerIncarnation::from_bytes([50; 16]),
        ..key
    };
    assert!(
        super::super::origin::delete(&mut coordinator, context, edge.link, peer, stale, 0, 0)
            .is_err()
    );
    assert!(coordinator.take_closed_remote_carriers().is_empty());
    assert!(coordinator.remote_carrier_peer(owner).is_some());
    assert!(
        super::super::origin::delete(&mut coordinator, context, edge.link, peer, key, 1, 0)
            .is_err()
    );
    assert!(coordinator.take_closed_remote_carriers().is_empty());
    super::super::origin::delete(&mut coordinator, context, edge.link, peer, key, 0, 0)
        .map_err(|error| format!("DEL: {error:?}"))?;
    assert!(
        coordinator.take_closed_remote_carriers().is_empty(),
        "staging cannot publish carrier closure"
    );
    assert!(coordinator.remote_carrier_peer(owner).is_some());
    fixture.commit_staged_batch().await?;
    coordinator.batch_applied(fixture.context_mut()?);
    assert_eq!(coordinator.take_closed_remote_carriers(), vec![owner]);
    coordinator.batch_applied(fixture.context_mut()?);
    assert!(
        coordinator.take_closed_remote_carriers().is_empty(),
        "the receipt closes its captured generation only once"
    );
    Ok(())
}

#[tokio::test]
async fn quiescence_refuses_new_remote_authentication_before_carrier_admission() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let peer = ServerId::from_bytes([50; 16]);
    let mut coordinator = standalone_coordinator(peer);
    let (mut fresh, mut edge) =
        remote_account_staging_request(&mut coordinator, fixture.context_mut()?)?;
    fresh.header.opcode = agenc_ircd_types::FederationOpcode::OpaqueAuthStart;
    let envelope = crate::test_support::sealed_authentication_start(
        NETWORK,
        RecoveryEpoch::from_bytes([34; 16]),
        "absent-account",
        191,
    )?;
    let mut budget = DecodeBudget::new(8_192, 64);
    let operation = FederatedOperation::AccountService {
        opcode: fresh.header.opcode,
        session_id: None,
        envelope: SchemaObject::decode_exact("AccountServiceEnvelope", &envelope, &mut budget)?,
    };
    let bytes = fresh
        .header
        .build(&operation.to_object()?)?
        .encode_canonical()?
        .as_slice()
        .to_vec();
    let descriptor = OperationDescriptor {
        object_id: federation_object_id(&bytes),
        ..fresh.descriptor
    };
    let (carrier, object) = edge.assemble(&bytes, |fragment| FederationFrame::Request {
        descriptor,
        fragment,
    })?;
    let _exit =
        fixture
            .state_mut()?
            .step_message(crate::state_core::inbox::StateCoreMessage::Signal(
                crate::state_core::inbox::SignalEvent::Terminate,
            ));
    let context = fixture.context_mut()?;
    assert!(context.is_quiescing());
    coordinator.inbound(
        context,
        FederationInbound {
            link: edge.link,
            peer,
            event: LinkEvent::Object { carrier, object },
            charge: None,
        },
    );
    assert!(
        coordinator.take_remote_account_work().is_empty(),
        "quiescence must refuse before allocating account work"
    );
    assert!(
        coordinator
            .remote_carrier_for_origin(peer, *fresh.key.origin.origin_id.as_bytes())
            .is_none()
    );
    assert_eq!(context.sessions().len(), 0);
    assert_eq!(context.head().account_service_response_count, 0);
    let read = context.submit_storage_read(ReadPlan::range(
        TableId::AuthTransaction,
        StoredKey::new(vec![0; 16])?,
        StoredKey::new(vec![255; 16])?,
        10,
    )?)?;
    let completion = fixture.next_storage_read().await?;
    assert_eq!(completion.read_id, read);
    assert!(completion.result?.records.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_second_carrier_request_is_refused_while_the_first_is_in_flight() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let peer = ServerId::from_bytes([50; 16]);
    let mut coordinator = standalone_coordinator(peer);
    let context = fixture.context_mut()?;
    // Durable origin rows carry the domain revision, which a fresh core has
    // not advanced yet.
    crate::test_support::seed_account(context, 31, 1)?;
    let (mut fresh, edge) = remote_account_staging_request(&mut coordinator, context)?;
    fresh.header.opcode = agenc_ircd_types::FederationOpcode::OpaqueAuthStart;
    fresh.command = None;
    let mut next_key = fresh.key;
    next_key.sequence = 1;
    let mut next_header = fresh.header;
    next_header.replay_key.operation_sequence = 1;
    next_header.request_id = RequestId::from_bytes([76; 16]);
    let mut next_descriptor = fresh.descriptor;
    next_descriptor.operation_sequence = 1;
    next_descriptor.request_id = next_header.request_id;
    next_descriptor.object_id = FederationHash32::from_bytes([77; 32]);
    let second = crate::federation::coordinator::FreshRequest {
        key: next_key,
        header: next_header,
        descriptor: next_descriptor,
        request_object_id: FederationHash32::from_bytes([77; 32]),
        bound: None,
        command: None,
        mutation: agenc_ircd_domain::federation::MutationContext::default(),
        charge: None,
    };
    coordinator
        .queue_remote_carrier(context, edge.link, peer, fresh, Vec::new())
        .map_err(|error| format!("first carrier: {error:?}"))?;
    let mut work = coordinator.take_remote_account_work();
    let Some(super::super::accounts::RemoteAccountWork::Carrier {
        generation,
        in_flight,
        ..
    }) = work.pop()
    else {
        return Err("expected a queued carrier".into());
    };
    assert!(work.is_empty(), "one queued carrier");
    coordinator
        .remote_carrier_started(context, generation, in_flight)
        .map_err(|error| format!("carrier start: {error:?}"))?;
    assert!(matches!(
        coordinator.queue_remote_carrier(context, edge.link, peer, second, Vec::new()),
        Err(Violation::Ceiling)
    ));
    assert!(coordinator.take_remote_account_work().is_empty());
    Ok(())
}
