//! Retained result descriptors cannot outlive their required response bytes.
#![forbid(unsafe_code)]

use super::*;
use crate::e2ee::coordinator::request::{Classified, ResponseObject, ResultBody};
use crate::e2ee::coordinator::tests::support::{capabilities, principal};

fn retained_page() -> TestResult<(CompanionCoordinator, Decoded, Vec<Vec<u8>>)> {
    let mut coordinator = coordinator();
    declare(&mut coordinator, 0)?;
    let mut decoded = decoded(0, 0)?;
    let account = agenc_relay_types::AccountId::from_random(
        agenc_relay_types::AccountRandomId::from_bytes([30; 16]),
    )
    .to_text();
    let identity = principal(30, &account.as_bytes().try_into()?, &[31, 32, 33])?;
    let mut parameters = vec![24];
    parameters.extend_from_slice(account.as_bytes());
    parameters.push(0);
    decoded.request.opcode = ArcFederationOpcode::FetchCapabilities;
    decoded.request.encoded_parameters = Opaque::new(parameters)?;
    let request_bytes = ArcWireObject::new(
        ArcWireObjectKind::FederationRequest,
        decoded.request.encode()?,
    )?
    .encode()?;
    decoded.request_object_id = *agenc_relay_e2ee::ObjectId::compute(&request_bytes).as_bytes();
    let mut outcome = Outcome::scalar(ResultBody::ObjectPage);
    outcome.snapshot_token = Some([19; 32]);
    let mut responses = Vec::new();
    for seed in [31, 32, 33] {
        let capability = capabilities(seed, &identity.roster, 0, [0; 32], (100, 1000), vec![1])?;
        let bytes =
            ArcWireObject::new(ArcWireObjectKind::DeviceCapabilities, capability.encode()?)?
                .encode()?;
        responses.push(bytes.clone());
        outcome.responses.push(ResponseObject {
            bytes,
            delivery_token: None,
            target_device_id: None,
        });
    }
    let staged = assemble(
        &coordinator,
        HOME,
        ServerId::from_bytes(HOME),
        &decoded,
        outcome,
        1,
        500,
        None,
        BarrierInputs {
            backing: backing(),
            base_counts: None,
            base_capacity: &|_, _, _| true,
            entropy: &mut Entropy,
        },
    )
    .map_err(|code| format!("assemble: {code:?}"))?;
    for effect in staged.effects {
        effect(&mut coordinator.state);
    }
    Ok((coordinator, decoded, responses))
}

#[test]
fn replay_refuses_any_missing_response_without_renumbering_the_rest() -> TestResult {
    for missing in 0..3 {
        let (mut coordinator, decoded, responses) = retained_page()?;
        let bytes = responses.get(missing).ok_or("missing fixture response")?;
        let id = *agenc_relay_e2ee::ObjectId::compute(bytes).as_bytes();
        assert!(coordinator.state.objects.remove(&id).is_some());
        assert!(
            matches!(
                request::classify(&coordinator.state, HOME, &decoded),
                Classified::Violation
            ),
            "replay accepted a retained result with response {missing} absent"
        );
    }
    Ok(())
}

#[test]
fn complete_replay_preserves_original_response_order_and_bytes() -> TestResult {
    let (coordinator, decoded, responses) = retained_page()?;
    let Classified::Replay(result, replayed) =
        request::classify(&coordinator.state, HOME, &decoded)
    else {
        return Err("complete replay was refused".into());
    };
    assert_eq!(replayed, responses);
    assert_eq!(
        result,
        coordinator
            .state
            .results
            .get(&decoded.request_object_id)
            .ok_or("result")?
            .result
    );
    Ok(())
}

#[test]
fn empty_replay_has_no_required_response_objects() -> TestResult {
    let mut coordinator = coordinator();
    declare(&mut coordinator, 0)?;
    let decoded = decoded(0, 0)?;
    let staged = batch(&coordinator, &decoded)?;
    for effect in staged.effects {
        effect(&mut coordinator.state);
    }
    let Classified::Replay(_, responses) = request::classify(&coordinator.state, HOME, &decoded)
    else {
        return Err("empty result replay was refused".into());
    };
    assert!(responses.is_empty());
    Ok(())
}

fn recent_correlation(decoded: &Decoded) -> Correlation {
    Correlation {
        peer_server_id: COORDINATOR,
        server_incarnation: decoded.request.server_incarnation,
        origin_id: decoded.request.origin_id,
        origin_generation: decoded.request.origin_generation,
        operation_sequence: decoded.request.operation_sequence,
        request_id: decoded.request.request_id,
    }
}

#[test]
fn recent_fragment_replay_refuses_every_missing_response_before_emitting_lines() -> TestResult {
    for missing in 0..3 {
        let (mut coordinator, decoded, responses) = retained_page()?;
        let bytes = responses.get(missing).ok_or("response")?;
        let id = *agenc_relay_e2ee::ObjectId::compute(bytes).as_bytes();
        assert!(coordinator.state.objects.remove(&id).is_some());
        let result = coordinator.replay_recent(
            ServerId::from_bytes(HOME),
            &recent_correlation(&decoded),
            decoded.request_object_id,
        );
        let actions = result?;
        assert!(
            matches!(
                actions.as_slice(),
                [super::super::super::sync::Action::ReadResponses(_)]
            ),
            "recent-fragment replay emitted lines before retrieving response {missing}"
        );
    }
    Ok(())
}

#[test]
fn recent_fragment_replay_preserves_all_three_response_indices_and_object_ids() -> TestResult {
    use crate::federation::link::{ParsedLine, parse_line};
    let (coordinator, decoded, responses) = retained_page()?;
    let actions = coordinator.replay_recent(
        ServerId::from_bytes(HOME),
        &recent_correlation(&decoded),
        decoded.request_object_id,
    )?;
    let [super::super::super::sync::Action::Send(lines)] = actions.as_slice() else {
        return Err("recent replay did not return lines".into());
    };
    let mut returned = BTreeMap::new();
    for line in lines {
        if let ParsedLine::Companion(CompanionFrame::Response {
            response_index,
            object_id,
            ..
        }) = parse_line(
            line.as_str().strip_suffix("\r\n").ok_or("line ending")?,
            "coordinator.example",
        )
        .map_err(|e| format!("line: {e:?}"))?
        {
            assert!(
                returned
                    .insert(response_index, object_id)
                    .is_none_or(|previous| previous == object_id)
            );
        }
    }
    assert_eq!(returned.len(), 3);
    for (index, response) in responses.iter().enumerate() {
        assert_eq!(
            returned.get(&u16::try_from(index)?),
            Some(agenc_relay_e2ee::ObjectId::compute(response).as_bytes())
        );
    }
    Ok(())
}

#[test]
fn recent_fragment_replay_accepts_a_result_with_no_required_response_objects() -> TestResult {
    let mut coordinator = coordinator();
    declare(&mut coordinator, 0)?;
    let decoded = decoded(0, 0)?;
    for effect in batch(&coordinator, &decoded)?.effects {
        effect(&mut coordinator.state);
    }
    let actions = coordinator.replay_recent(
        ServerId::from_bytes(HOME),
        &recent_correlation(&decoded),
        decoded.request_object_id,
    )?;
    let [super::super::super::sync::Action::Send(lines)] = actions.as_slice() else {
        return Err("empty-result replay did not return lines".into());
    };
    assert!(!lines.is_empty());
    assert!(lines.iter().all(|line| line.as_str().contains(" ERESULT ")));
    Ok(())
}

#[tokio::test]
async fn a_retained_response_on_disk_remains_replayable_after_its_memory_copy_is_evicted()
-> TestResult {
    let (mut coordinator, decoded, responses) = retained_page()?;
    let mut storage = crate::test_support::StateCoreFixture::new(vec![44; 65_536])?;
    let context = storage.context_mut()?;
    let plan = context.domain().plan_account_service_checkpoint()?;
    let revision = plan.resulting_revision().get();
    let writes = responses
        .iter()
        .map(|bytes| {
            CompanionCoordinator::object_write(bytes)
                .map_err(|e| format!("object: {e:?}"))?
                .at_revision(revision)
                .map_err(|e| format!("revision: {e:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    context
        .stage_durable_with_account_service(
            plan,
            crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())?,
            None,
            0,
            writes,
        )
        .map_err(|e| format!("stage responses: {e:?}"))?;
    storage.commit_staged_batch().await?;
    let id = *agenc_relay_e2ee::ObjectId::compute(responses.first().ok_or("response")?).as_bytes();
    assert!(coordinator.state.objects.remove(&id).is_some());
    let candidate = crate::e2ee::coordinator::response_read::Candidate::capture(
        &coordinator,
        crate::e2ee::coordinator::response_read::Identity {
            peer: ServerId::from_bytes(HOME),
            correlation: recent_correlation(&decoded),
            request_object_id: decoded.request_object_id,
        },
        &storage.context_mut()?.backing_reservations(),
    )?;
    let mut job = candidate.begin(
        storage.context_mut()?.head().storage_commit_sequence,
        &storage.context_mut()?.backing_reservations(),
    )?;
    assert_eq!(
        job.candidate().identity().request_object_id,
        decoded.request_object_id
    );
    let mut count = 0;
    while let Some(plan) = job.next()? {
        let _raw = storage
            .context_mut()?
            .reserve_output_backing(agenc_relay_storage::MAX_SEALED_RECORD_BYTES + 8192)?;
        let _decode = storage
            .context_mut()?
            .reserve_output_backing(16 * 1024 * 1024)?;
        let read = storage.context_mut()?.submit_storage_read(plan)?;
        let message = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            storage.next_storage_read(),
        )
        .await??;
        assert_eq!(message.read_id, read);
        let result = message.result?;
        let mut records = Vec::new();
        for row in &result.records {
            let plain = storage.context_mut()?.open_storage_plaintext(
                row.table,
                &row.key,
                &row.sealed_record,
            )?;
            records.push((
                row.key.clone(),
                PersistentRecordValue::decode(row.table, plain.expose_for_storage_codec())?,
            ));
        }
        job.admit(result.storage_commit_sequence, result.truncated, records)?;
        count += 1;
    }
    assert_eq!(count, 3);
    let mut output = job.finish(&coordinator)?;
    let _backing = output.backing();
    let lines: Vec<_> = output.drain().collect();
    let expected = replay_lines(
        &coordinator,
        &recent_correlation(&decoded),
        HOME,
        &coordinator
            .state
            .results
            .get(&decoded.request_object_id)
            .ok_or("result")?
            .result,
        &responses,
    )
    .map_err(|e| format!("expected replay: {e:?}"))?;
    assert_eq!(
        lines.iter().map(|line| line.as_str()).collect::<Vec<_>>(),
        expected
            .iter()
            .map(|line| line.as_str())
            .collect::<Vec<_>>()
    );
    Ok(())
}

/// The read job of the retained page's reply, with the sealed object rows it must be fed.
fn read_job(
    coordinator: &CompanionCoordinator,
    decoded: &Decoded,
    responses: &[Vec<u8>],
) -> TestResult<(
    crate::e2ee::coordinator::response_read::Job,
    Vec<(agenc_relay_storage::StoredKey, PersistentRecordValue)>,
)> {
    let identity = crate::e2ee::coordinator::response_read::Identity {
        peer: ServerId::from_bytes(HOME),
        correlation: recent_correlation(decoded),
        request_object_id: decoded.request_object_id,
    };
    let candidate = crate::e2ee::coordinator::response_read::Candidate::capture(
        coordinator,
        identity,
        &backing(),
    )
    .map_err(|fault| format!("capture: {fault:?}"))?;
    let job = candidate
        .begin(7, &backing())
        .map_err(|fault| format!("begin: {fault:?}"))?;
    let mut rows = Vec::new();
    for bytes in responses {
        let crate::state_core::durable::AccountServiceDurableWrite::Put { key, plaintext, .. } =
            CompanionCoordinator::object_write(bytes).map_err(|code| format!("{code:?}"))?
        else {
            return Err("object write".into());
        };
        rows.push((
            key,
            PersistentRecordValue::decode(agenc_relay_storage::TableId::E2eeObject, &plaintext)?,
        ));
    }
    Ok((job, rows))
}

type Row = (agenc_relay_storage::StoredKey, PersistentRecordValue);

/// Selects the page one fault feeds the job: its commit, truncation and rows.
type Fault = fn(Vec<Row>) -> (u64, bool, Vec<Row>);

#[test]
fn a_reply_read_job_binds_every_body_before_it_renders() -> TestResult {
    let (coordinator, decoded, responses) = retained_page()?;
    let (mut job, rows) = read_job(&coordinator, &decoded, &responses)?;
    assert_eq!(
        job.admit(7, false, rows).err(),
        Some(CompanionFault::Storage),
        "a page nobody asked for"
    );
    assert_eq!(
        job.next().err(),
        Some(CompanionFault::Storage),
        "a failed job reads nothing"
    );
    let (job, _) = read_job(&coordinator, &decoded, &responses)?;
    assert_eq!(
        job.finish(&coordinator).err(),
        Some(CompanionFault::Storage),
        "no body was bound"
    );
    let faults: [(&str, Fault); 5] = [
        ("another commit", |rows| {
            (8, false, rows.into_iter().take(1).collect())
        }),
        ("a truncated page", |rows| {
            (7, true, rows.into_iter().take(1).collect())
        }),
        ("no row", |_| (7, false, Vec::new())),
        ("two rows", |rows| {
            (7, false, rows.into_iter().take(2).collect())
        }),
        ("another object", |rows| {
            (7, false, rows.into_iter().skip(1).take(1).collect())
        }),
    ];
    for (name, fault) in faults {
        let (mut job, rows) = read_job(&coordinator, &decoded, &responses)?;
        assert!(job.next()?.is_some(), "{name}");
        let (commit, truncated, records) = fault(rows);
        assert_eq!(
            job.admit(commit, truncated, records).err(),
            Some(CompanionFault::Storage),
            "{name}"
        );
        assert_eq!(job.next().err(), Some(CompanionFault::Storage), "{name}");
    }
    let (mut job, rows) = read_job(&coordinator, &decoded, &responses)?;
    assert!(job.next()?.is_some());
    let (key, _) = rows.into_iter().next().ok_or("first row")?;
    let foreign = PersistentRecordValue::new(
        agenc_relay_storage::TableId::E2eeObject,
        2,
        1,
        0,
        None,
        Vec::new(),
        agenc_relay_storage::ProtocolRecordBody::new(
            agenc_relay_storage::TableId::E2eeObject,
            2,
            1,
            vec![1, 2, 3],
        )?
        .encode()?,
    );
    if let Ok(foreign) = foreign {
        assert_eq!(
            job.admit(7, false, vec![(key, foreign)]).err(),
            Some(CompanionFault::Storage),
            "another record kind"
        );
    }
    let (mut job, rows) = read_job(&coordinator, &decoded, &responses)?;
    for row in rows {
        assert!(job.next()?.is_some());
        job.admit(7, false, vec![row])
            .map_err(|fault| format!("honest body: {fault:?}"))?;
    }
    assert!(job.next()?.is_none());
    let _output = job
        .finish(&coordinator)
        .map_err(|fault| format!("finish: {fault:?}"))?;
    Ok(())
}
