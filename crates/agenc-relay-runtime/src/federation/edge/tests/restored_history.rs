#![forbid(unsafe_code)]

//! A restored history request row must agree with the request it retains: same replay key,
//! this network and this edge, the recorded request id and the exact object hash. An honest
//! row restores unattached, and a row of another kind is not this validator's business.

use agenc_relay_domain::HistorySelector;
use agenc_relay_federation_wire::ReplayKey;
use agenc_relay_storage::federation_records::request_result_key;
use agenc_relay_storage::history_records::{
    HISTORY_EDGE_REQUEST_KIND, HistoryEdgePhase, HistoryEdgeRequestRecord, HistoryRequestIdentity,
};
use agenc_relay_storage::{InitialStorageRecord, PersistentRecordValue, StoredKey, TableId};
use agenc_relay_types::{ChannelInstanceId, FederationOpcode, OriginId, RequestId, SessionId};

use super::*;
use crate::federation::edge::startup::EdgeRestoreStep;

fn header(network: NetworkId) -> RequestHeader {
    RequestHeader {
        network_id: network,
        replay_key: ReplayKey {
            home_server_id: EDGE,
            server_incarnation: EDGE_INCARNATION,
            origin_id: OriginId::from_bytes([71; 16]),
            origin_generation: 0,
            operation_sequence: 0,
        },
        request_id: RequestId::from_bytes([73; 16]),
        opcode: FederationOpcode::HistoryQuery,
    }
}

fn request_bytes(header: &RequestHeader) -> TestResult<Vec<u8>> {
    let operation = FederatedOperation::HistoryQuery {
        session_id: SessionId::from_bytes([21; 16]),
        channel_id: ChannelInstanceId::from_bytes([22; 16]),
        selector: crate::federation::codec::history::selector_object(HistorySelector::Latest(
            None,
        ))?,
        limit: 10,
        cursor: None,
    };
    Ok(header
        .build(&operation.to_object()?)?
        .encode_canonical()?
        .as_slice()
        .to_vec())
}

fn record(
    header: &RequestHeader,
    object_id: Option<[u8; 32]>,
) -> TestResult<HistoryEdgeRequestRecord> {
    let request_object = request_bytes(header)?;
    Ok(HistoryEdgeRequestRecord {
        request: HistoryRequestIdentity {
            replay_key: header.replay_key.to_bytes(),
            request_id: *header.request_id.as_bytes(),
            request_object_id: object_id
                .unwrap_or(*federation_object_id(&request_object).as_bytes()),
            request_object,
        },
        original_result_object_id: None,
        expired_result_object_id: None,
        authorization: None,
        deadline_unix_milliseconds: 1,
        phase: HistoryEdgePhase::Pending,
        sink_gone: false,
    })
}

fn row(key: StoredKey, record: &HistoryEdgeRequestRecord) -> TestResult<InitialStorageRecord> {
    let value = PersistentRecordValue::new(
        TableId::RequestResult,
        HISTORY_EDGE_REQUEST_KIND,
        1,
        0,
        None,
        Vec::new(),
        record.encode()?,
    )?;
    Ok(InitialStorageRecord::new(
        TableId::RequestResult,
        key,
        1,
        value.encode()?,
    )?)
}

fn restored(
    rows: Vec<InitialStorageRecord>,
) -> TestResult<(Option<EdgeRestoreStep>, EdgeFederation)> {
    let fixture = StateCoreFixture::with_registration_router_and_records(entropy_script(), rows)?;
    let mut edge = resync_edge();
    let step = fixture
        .restore_edge_refusal(&mut edge, None)?
        .err()
        .map(|refusal| refusal.step);
    Ok((step, edge))
}

#[tokio::test]
async fn a_history_request_row_that_disagrees_with_its_request_refuses() -> TestResult {
    let honest = header(NETWORK);
    let key = request_result_key(honest.replay_key.to_bytes())?;
    let rows = [
        ("replay key", {
            let mut header = honest;
            header.replay_key.operation_sequence = 5;
            let mut record = record(&header, None)?;
            record.request.replay_key = honest.replay_key.to_bytes();
            row(key.clone(), &record)?
        }),
        ("request id", {
            let mut record = record(&honest, None)?;
            record.request.request_id = [1; 16];
            row(key.clone(), &record)?
        }),
        ("home server", {
            let mut header = honest;
            header.replay_key.home_server_id = ServerId::from_bytes([98; 16]);
            let mut record = record(&header, None)?;
            record.request.replay_key = honest.replay_key.to_bytes();
            row(key.clone(), &record)?
        }),
        (
            "network",
            row(
                key.clone(),
                &record(&header(NetworkId::from_bytes([99; 32])), None)?,
            )?,
        ),
        (
            "object",
            row(key.clone(), &record(&honest, Some([9; 32]))?)?,
        ),
    ];
    for (name, tampered) in rows {
        let (step, edge) = restored(vec![tampered])?;
        assert_eq!(step, Some(EdgeRestoreStep::RequestJournal), "{name}");
        assert!(edge.pending.is_empty(), "{name}");
    }
    let (step, edge) = restored(vec![row(key, &record(&honest, None)?)?])?;
    assert_eq!(step, None, "an honest row restores");
    assert!(
        edge.pending.is_empty(),
        "restored history requests stay unattached"
    );
    Ok(())
}
