//! Decoder-boundary failures remain private even after other response bodies were admitted.
#![forbid(unsafe_code)]

use super::*;
use crate::e2ee::coordinator::response_read::{Candidate, Identity};
use agenc_ircd_e2ee::objects::federation::IrcFederationResult;
use agenc_ircd_e2ee::tls::{DecodeBudget as E2eeDecodeBudget, TlsDecode, TlsVec};

fn identity(fixture: &Fixture) -> Identity {
    let request = &fixture.decoded.request;
    Identity {
        peer: PEER,
        request_object_id: fixture.decoded.request_object_id,
        correlation: Correlation {
            peer_server_id: *PEER.as_bytes(),
            server_incarnation: request.server_incarnation,
            origin_id: request.origin_id,
            origin_generation: request.origin_generation,
            operation_sequence: request.operation_sequence,
            request_id: request.request_id,
        },
    }
}

fn rewrite_result(
    fixture: &mut Fixture,
    change: impl FnOnce(&mut IrcFederationResult),
) -> TestResult {
    let executor = fixture
        .coordinator
        .companion_exec
        .as_mut()
        .ok_or("executor")?;
    let stored = executor
        .state
        .results
        .get_mut(&fixture.decoded.request_object_id)
        .ok_or("stored result")?;
    let object = IrcWireObject::decode_kind(
        &stored.result,
        Some(IrcWireObjectKind::FederationResult),
        &mut E2eeDecodeBudget::new(8192, 512),
    )?;
    let mut result =
        IrcFederationResult::decode_exact(object.body(), &mut E2eeDecodeBudget::new(8192, 512))?;
    change(&mut result);
    stored.result =
        IrcWireObject::new(IrcWireObjectKind::FederationResult, result.encode()?)?.encode()?;
    executor
        .state
        .replays
        .get_mut(&fixture.key)
        .ok_or("replay row")?
        .result_object_id = Some(*ObjectId::compute(&stored.result).as_bytes());
    Ok(())
}

#[tokio::test]
async fn original_result_identity_and_descriptor_order_are_bound_before_read_submission()
-> TestResult {
    for change in 0..9 {
        let mut fixture = Box::pin(Fixture::new(None)).await?;
        let empty = TlsVec::new(Vec::new())?;
        rewrite_result(&mut fixture, |result| match change {
            0 => result.network_id = [98; 32],
            1 => result.home_server_id = [98; 16],
            2 => result.server_incarnation = [98; 16],
            3 => result.origin_id = [98; 16],
            4 => result.origin_generation += 1,
            5 => result.operation_sequence += 1,
            6 => result.request_id = [98; 16],
            7 => result.request_object_id = [98; 32],
            _ => {
                result.responses = empty;
            }
        })?;
        assert!(fixture.submit().is_err());
        assert!(fixture.coordinator.companion_response_read.is_none());
        assert_eq!(fixture.handle.queued_bytes(), 0);
    }
    Ok(())
}

#[tokio::test]
async fn duplicate_object_ids_keep_separate_response_positions() -> TestResult {
    let mut fixture = Box::pin(Fixture::new(None)).await?;
    let stored = &fixture
        .executor()?
        .state
        .results
        .get(&fixture.decoded.request_object_id)
        .ok_or("result")?
        .result;
    let object = IrcWireObject::decode_kind(
        stored,
        Some(IrcWireObjectKind::FederationResult),
        &mut E2eeDecodeBudget::new(8192, 512),
    )?;
    let mut result =
        IrcFederationResult::decode_exact(object.body(), &mut E2eeDecodeBudget::new(8192, 512))?;
    let mut descriptors = result.responses.into_items();
    let mut duplicate = descriptors.first().ok_or("descriptor")?.clone();
    duplicate.response_index = 1;
    *descriptors.get_mut(1).ok_or("second descriptor")? = duplicate;
    result.responses = TlsVec::new(descriptors)?;
    rewrite_result(&mut fixture, |original| *original = result)?;
    let first = fixture.responses.first().ok_or("first body")?.clone();
    let id = *ObjectId::compute(&first).as_bytes();
    *fixture.responses.get_mut(1).ok_or("second body")? = first;
    let executor = fixture
        .coordinator
        .companion_exec
        .as_mut()
        .ok_or("executor")?;
    *executor
        .state
        .replays
        .get_mut(&fixture.key)
        .ok_or("row")?
        .response_object_ids
        .get_mut(1)
        .ok_or("row descriptor")? = id;
    *executor
        .state
        .results
        .get_mut(&fixture.decoded.request_object_id)
        .ok_or("stored")?
        .responses
        .get_mut(1)
        .ok_or("stored descriptor")? = id;
    fixture.submit()?;
    assert_eq!(fixture.finish_reads().await?, 3);
    fixture.expect_complete_output().await?;
    Ok(())
}

#[tokio::test]
async fn response_reader_rejects_wrong_body_and_stays_failed() -> TestResult {
    let mut fixture = Box::pin(Fixture::new(None)).await?;
    let backing = fixture.core.context_mut()?.backing_reservations();
    let candidate = Candidate::capture(fixture.executor()?, identity(&fixture), &backing)?;
    let mut job = candidate.begin(9, &backing)?;
    assert!(job.next()?.is_some());
    let bytes = fixture.responses.get(1).ok_or("second response")?;
    let write =
        CompanionCoordinator::object_write(bytes).map_err(|e| format!("object write: {e:?}"))?;
    let crate::state_core::durable::AccountServiceDurableWrite::Put {
        table,
        key,
        plaintext,
    } = write
    else {
        return Err("object write was not a Put".into());
    };
    let value = PersistentRecordValue::decode(table, &plaintext)?;
    assert!(job.admit(9, false, vec![(key, value)]).is_err());
    assert!(job.next().is_err());
    assert!(job.finish(fixture.executor()?).is_err());
    Ok(())
}

#[tokio::test]
async fn mismatched_response_kind_and_size_refuse_after_loading_the_expected_object() -> TestResult
{
    for wrong_kind in [false, true] {
        let mut fixture = Box::pin(Fixture::new(None)).await?;
        let stored = &fixture
            .executor()?
            .state
            .results
            .get(&fixture.decoded.request_object_id)
            .ok_or("result")?
            .result;
        let object = IrcWireObject::decode_kind(
            stored,
            Some(IrcWireObjectKind::FederationResult),
            &mut E2eeDecodeBudget::new(8192, 512),
        )?;
        let mut result = IrcFederationResult::decode_exact(
            object.body(),
            &mut E2eeDecodeBudget::new(8192, 512),
        )?;
        let mut descriptors = result.responses.into_items();
        let first = descriptors.first_mut().ok_or("descriptor")?;
        if wrong_kind {
            first.wire_kind = IrcWireObjectKind::DeviceRoster;
        } else {
            first.total_size += 1;
        }
        result.responses = TlsVec::new(descriptors)?;
        rewrite_result(&mut fixture, |original| *original = result)?;
        fixture.submit()?;
        assert_eq!(fixture.finish_reads().await?, 1);
        assert_eq!(fixture.handle.queued_bytes(), 0);
        assert_eq!(fixture.coordinator.counters.violations, 1);
    }
    Ok(())
}

#[tokio::test]
async fn a_response_read_is_refused_for_another_peer_or_behind_a_pending_batch() -> TestResult {
    let mut fixture = Box::pin(Fixture::new(None)).await?;
    let foreign = identity(&fixture);
    let context = fixture.core.context_mut()?;
    assert!(matches!(
        crate::federation::coordinator::response_read::submit(
            &mut fixture.coordinator,
            context,
            LinkId::new(1),
            ServerId::from_bytes([7; 16]),
            foreign,
        ),
        Err(Violation::Ceiling)
    ));
    assert!(fixture.coordinator.companion_response_read.is_none());
    let queued = identity(&fixture);
    fixture.coordinator.pending = Some(PendingCommit::Acknowledged);
    let context = fixture.core.context_mut()?;
    assert!(matches!(
        crate::federation::coordinator::response_read::submit(
            &mut fixture.coordinator,
            context,
            LinkId::new(1),
            PEER,
            queued,
        ),
        Err(Violation::Ceiling)
    ));
    assert!(fixture.coordinator.companion_response_read.is_none());
    fixture.coordinator.pending = None;
    fixture.submit()?;
    assert!(fixture.coordinator.companion_response_read.is_some());
    Ok(())
}
