//! A persisted history receipt whose identity disagrees with its row or this edge stops the reload.
#![forbid(unsafe_code)]

use super::*;

type Tamper = fn(&mut HistoryEdgeRequestRecord, &mut super::super::super::EdgeConfig) -> TestResult;

fn reencoded(record: &mut HistoryEdgeRequestRecord, opcode: FederationOpcode) -> TestResult {
    let mut budget = agenc_relay_federation_wire::DecodeBudget::new(2048, 64);
    let object = agenc_relay_federation_wire::SchemaObject::decode_exact(
        "FederationRequest",
        &record.request.request_object,
        &mut budget,
    )?;
    let mut header = RequestHeader::from_object(&object)?;
    header.opcode = opcode;
    let operation = FederatedOperation::SessionClose {
        session_id: agenc_relay_types::SessionId::from_bytes([3; 16]),
        reason_code: 1,
    };
    let bytes = header
        .build(&operation.to_object()?)?
        .encode_canonical()?
        .as_slice()
        .to_vec();
    record.request.request_object_id = *federation_object_id(&bytes).as_bytes();
    record.request.request_object = bytes;
    Ok(())
}

fn tampers() -> [Tamper; 5] {
    [
        |_, config| {
            config.network_id = NetworkId::from_bytes([77; 32]);
            Ok(())
        },
        |_, config| {
            config.server_id = ServerId::from_bytes([77; 16]);
            Ok(())
        },
        |record, _| {
            record.request.request_id = [77; 16];
            Ok(())
        },
        |record, _| reencoded(record, FederationOpcode::SessionClose),
        |record, _| {
            record.request.request_object_id = [77; 32];
            Ok(())
        },
    ]
}

fn image(
    fixture: &mut StateCoreFixture,
    record: &HistoryEdgeRequestRecord,
    key: agenc_relay_storage::StoredKey,
) -> TestResult<AccountServiceDurableWrite> {
    let revision = fixture
        .context_mut()?
        .domain()
        .revision()
        .get()
        .checked_add(1)
        .ok_or("revision")?;
    let plaintext = PersistentRecordValue::new(
        TableId::RequestResult,
        HISTORY_EDGE_REQUEST_KIND,
        revision,
        0,
        None,
        Vec::new(),
        record.encode()?,
    )?
    .encode()?;
    Ok(AccountServiceDurableWrite::put(
        TableId::RequestResult,
        key,
        plaintext,
    )?)
}

#[tokio::test]
async fn a_receipt_that_disagrees_with_this_edge_or_its_request_refuses_the_reload() -> TestResult {
    for tamper in tampers() {
        let (mut fixture, edge, sink, _) = fixture()?;
        let mut record = edge.history.records.get(&ID).ok_or("record")?.clone();
        let mut config = edge.config;
        tamper(&mut record, &mut config)?;
        let key =
            agenc_relay_storage::federation_records::request_result_key(record.request.replay_key)?;
        let write = image(&mut fixture, &record, key)?;
        let mut restarted = EdgeFederation::new(config);
        let outcome = fixture.commit_and_restore_edge(vec![write], &mut restarted, None);
        assert!(outcome.is_err_and(|error| format!("{error:?}").contains("StaleState")));
        assert!(restarted.pending.is_empty());
        assert!(restarted.history.records.is_empty());
        assert!(sink.lines().is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn a_receipt_rekeyed_away_from_its_request_header_refuses_the_reload() -> TestResult {
    let (mut fixture, edge, _, _) = fixture()?;
    let mut record = edge.history.records.get(&ID).ok_or("record")?.clone();
    *record.request.replay_key.get_mut(40).ok_or("origin byte")? ^= 1;
    let key =
        agenc_relay_storage::federation_records::request_result_key(record.request.replay_key)?;
    let write = image(&mut fixture, &record, key)?;
    let mut restarted = EdgeFederation::new(edge.config);
    let outcome = fixture.commit_and_restore_edge(vec![write], &mut restarted, None);
    assert!(outcome.is_err_and(|error| format!("{error:?}").contains("StaleState")));
    assert!(restarted.history.records.is_empty());
    Ok(())
}
