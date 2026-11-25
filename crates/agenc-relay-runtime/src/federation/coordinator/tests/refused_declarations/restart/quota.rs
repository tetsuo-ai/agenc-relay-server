//! A full origin's reply, FORIGIN DEL acknowledgement and session cleanup require its committed row.
#![forbid(unsafe_code)]

use super::*;
use agenc_relay_auth::{
    CreationStart, OpaqueRegistrationRequest, claimed_creation, client, profile::FallibleOpaqueRng,
};
use agenc_relay_crypto::{
    AccountHpkePrivateKey, AccountRequestBinding, InitialRootExchange, InitialRootSecret, OsEntropy,
};
use agenc_relay_federation_wire::{FederationProfile, InitialRootOperation, InitialRootRequest};
use agenc_relay_storage::federation_records::{
    FederationOriginRecord, OriginRowStatus, origin_key,
};
use agenc_relay_storage::{ReadPlan, StorageError};
use agenc_relay_types::NormalizedLogin;

struct Request {
    header: RequestHeader,
    descriptor: OperationDescriptor,
    bytes: Vec<u8>,
}

impl Request {
    fn guarded(f: &Restartable, origin: &Origin) -> TestResult<Self> {
        let operation = InitialRootOperation::ClaimedCreateStart;
        let header = RequestHeader {
            network_id: NETWORK,
            replay_key: origin.replay_key(&f.edge),
            request_id: RequestId::from_bytes([88; 16]),
            opcode: operation.base_layout(),
        };
        let public = AccountHpkePrivateKey::generate()?.public_key()?;
        let started = client::registration_start(
            &mut FallibleOpaqueRng::new(OsEntropy),
            "test account password",
        )?;
        let (sealed, _reply) = claimed_creation::seal_start(
            public,
            AccountRequestBinding::new(
                NETWORK,
                f.coordinator.config.recovery_epoch,
                public.key_id(),
                header.request_id,
                InitialRootExchange::ClaimedCreateStart,
            ),
            &CreationStart {
                network_id: NETWORK,
                login: NormalizedLogin::prepare("quota-receipt")?,
                registration_request: OpaqueRegistrationRequest::from_bytes(started.request)?,
                invitation: None,
            },
            &InitialRootSecret::generate()?,
        )?;
        let bytes = InitialRootRequest {
            layout: header,
            operation,
            session: None,
            envelope: sealed.as_bytes(),
        }
        .encode(FederationProfile::InitialRoot)?;
        let descriptor = OperationDescriptor {
            addressed_server_id: COORDINATOR,
            server_incarnation: f.edge.incarnation,
            origin_id: origin.id,
            origin_generation: origin.generation,
            operation_sequence: origin.sequence,
            request_id: header.request_id,
            object_id: federation_object_id(&bytes),
        };
        Ok(Self {
            header,
            descriptor,
            bytes,
        })
    }

    async fn expect_terminal(&self, f: &mut Restartable) -> TestResult {
        use agenc_relay_federation_wire::InitialRootResult;
        let mut completed = 0;
        for frame in f.frames().await? {
            let FederationFrame::Result { descriptor, .. } = &frame else {
                return Err("a terminal request produced an unrelated frame".into());
            };
            assert_eq!(descriptor.request_id, self.header.request_id);
            let (_, key) = carrier_of(&frame).map_err(|error| error.to_string())?;
            let fragment = frame.fragment().ok_or("missing result fragment")?;
            if let AssemblyProgress::Complete(object) = f.edge.assembler.admit(key, fragment, 0)? {
                let mut budget = DecodeBudget::new(16_384, 128);
                let result = InitialRootResult::decode(
                    FederationProfile::InitialRoot,
                    object.as_slice(),
                    &mut budget,
                )?;
                assert_eq!(result.layout.replay_key, self.header.replay_key);
                assert_eq!(result.layout.request_object_id, self.descriptor.object_id);
                assert!(result.layout.completion_event_id.is_none());
                assert!(result.sealed.is_none());
                assert!(result.indexed_replies()?.is_empty());
                let reason = ResultArm::from_object(
                    FederationResultKind::Failed,
                    &result.failed_arm(&mut budget)?,
                )?;
                assert!(
                    matches!(reason, ResultArm::Failed { code, context } if code == "ORIGIN_EXPIRED" && context.is_empty())
                );
                completed += 1;
            }
        }
        assert_eq!(completed, 1);
        Ok(())
    }

    fn submit(&self, f: &mut Restartable) -> TestResult {
        inbound_object(
            &mut f.coordinator,
            f.core.context_mut()?,
            &mut f.edge,
            &self.bytes,
            |fragment| FederationFrame::Request {
                descriptor: self.descriptor,
                fragment,
            },
        )
    }
}

async fn connect(f: &mut Restartable, link: u64, first: &Origin, sibling: &Origin) -> TestResult {
    f.link_with_profile(link, FederationProfile::InitialRoot)?;
    f.settle().await?;
    for origin in [first, sibling] {
        f.declare(origin, false, None)?;
        f.settle().await?;
    }
    let frames = f.frames().await?;
    assert!(acknowledges(&frames, sibling, sibling.generation));
    Ok(())
}

fn stored_status(f: &mut Restartable, origin: &Origin) -> TestResult<OriginRowStatus> {
    let raw = origin_key(
        f.edge.server_id,
        f.edge.incarnation,
        *origin.id.as_bytes(),
        origin.generation,
    )?;
    let page = f
        .core
        .read_rows(ReadPlan::exact(TableId::FederationOrigin, raw))?;
    let row = page.records.first().ok_or("missing durable origin")?;
    let opened = f.core.context_mut()?.open_storage_plaintext(
        TableId::FederationOrigin,
        &row.key,
        &row.sealed_record,
    )?;
    let value = PersistentRecordValue::decode(
        TableId::FederationOrigin,
        opened.expose_for_storage_codec(),
    )?;
    Ok(FederationOriginRecord::decode(value.body())?.status)
}

fn reject_writer(f: &mut Restartable) -> TestResult {
    assert_eq!(f.core.context_mut()?.pending_len(), 1);
    f.core
        .state_mut()?
        .reject_fixture_batch_before_submission(StorageError::QueueFull)?;
    f.coordinator
        .batch_rejected_with_error(f.core.context_mut()?, StorageError::QueueFull);
    Ok(())
}

#[tokio::test]
async fn a_full_origins_refusal_and_del_wait_for_their_own_storage_receipt_across_reconnects()
-> TestResult {
    let mut f = Box::new(Restartable::new()?);
    let (inbox, _) = mpsc::channel(1);
    let mut other = Edge::new(inbox, 59);
    f.coordinator = standalone_coordinator_pair(f.edge.server_id, other.server_id);
    std::mem::swap(&mut f.edge, &mut other);
    f.link(15)?;
    f.settle().await?;
    f.frames().await?;
    std::mem::swap(&mut f.edge, &mut other);
    let affected = Origin::new(97);
    let sibling = Origin::new(98);
    connect(&mut f, 1, &affected, &sibling).await?;
    let key = f.key(&affected);
    let request = Request::guarded(&f, &affected)?;
    f.core.context_mut()?.set_wall_for_test(1_000_000);
    let mut slots = Vec::new();
    for seq in 1..=128 {
        let header = RequestHeader {
            replay_key: ReplayKey {
                operation_sequence: seq,
                ..request.header.replay_key
            },
            ..request.header
        };
        slots.push(
            f.coordinator
                .admit_initial_root(f.core.context_mut()?, &header)
                .map_err(|_| "pending intake")?
                .ok_or("early per-origin refusal")?,
        );
    }
    request.submit(&mut f)?;
    f.coordinator.batch_applied(f.core.context_mut()?);
    assert_eq!(
        f.coordinator
            .origins
            .origin(&key)
            .ok_or("live origin")?
            .status,
        OriginStatus::Live
    );
    assert!(!f.coordinator.refused_declarations.contains_key(&key));
    assert!(f.frames().await?.is_empty());
    assert_eq!(stored_status(&mut f, &affected)?, OriginRowStatus::Live);
    reject_writer(&mut f)?;
    assert!(!f.coordinator.link_is_live(f.edge.link, f.edge.server_id));
    assert!(!f.coordinator.refused_declarations.contains_key(&key));
    assert_eq!(stored_status(&mut f, &affected)?, OriginRowStatus::Live);

    // A separately authenticated peer still receives its own durable declaration ACK.
    std::mem::swap(&mut f.edge, &mut other);
    let independent = Origin::new(99);
    f.declare(&independent, false, None)?;
    f.settle().await?;
    assert!(acknowledges(
        &f.frames().await?,
        &independent,
        independent.generation
    ));
    assert_eq!(stored_status(&mut f, &independent)?, OriginRowStatus::Live);
    std::mem::swap(&mut f.edge, &mut other);

    // The same coordinator reopens the original peer connection without a process restart.
    connect(&mut f, 2, &affected, &sibling).await?;
    f.delete(&affected, affected.generation)?;
    assert!(
        f.frames().await?.is_empty(),
        "an uncommitted refusal authorized DEL"
    );
    assert_eq!(
        f.coordinator
            .origins
            .origin(&key)
            .ok_or("live origin")?
            .status,
        OriginStatus::Live
    );
    reject_writer(&mut f)?;
    assert_eq!(stored_status(&mut f, &affected)?, OriginRowStatus::Live);

    connect(&mut f, 3, &affected, &sibling).await?;
    request.submit(&mut f)?;
    assert!(
        f.frames().await?.is_empty(),
        "a duplicate answered before the retry committed"
    );
    f.core.commit_staged_batch().await?;
    assert_eq!(stored_status(&mut f, &affected)?, OriginRowStatus::Deleted);
    assert_eq!(
        f.coordinator
            .origins
            .origin(&key)
            .ok_or("publication")?
            .status,
        OriginStatus::Live
    );
    f.coordinator.batch_applied(f.core.context_mut()?);
    assert_eq!(
        f.coordinator.refused_declarations.get(&key),
        Some(&affected.generation)
    );
    request.expect_terminal(&mut f).await?;
    let epoch = f.core.context_mut()?.head().storage_commit_sequence;
    request.submit(&mut f)?;
    request.expect_terminal(&mut f).await?;
    assert_eq!(f.core.context_mut()?.pending_len(), 0);
    assert_eq!(f.core.context_mut()?.head().storage_commit_sequence, epoch);
    f.delete(&affected, affected.generation)?;
    assert!(acknowledges(
        &f.frames().await?,
        &affected,
        affected.generation
    ));
    drop(slots);
    let coordinator = Box::new(standalone_coordinator_pair(
        f.edge.server_id,
        other.server_id,
    ));
    f.restart_with(coordinator).await?;
    assert_eq!(
        f.coordinator
            .origins
            .origin(&key)
            .ok_or("reopened tombstone")?
            .deleted_after,
        Some(0)
    );
    assert_eq!(stored_status(&mut f, &sibling)?, OriginRowStatus::Live);
    Ok(())
}
