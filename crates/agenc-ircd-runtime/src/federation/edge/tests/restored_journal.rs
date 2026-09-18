#![forbid(unsafe_code)]

//! A journal image that disagrees with this edge, its keys or its own hashes refuses the reload
//! at the step that owns the row, and restores nothing.

use agenc_ircd_federation_wire::FederationHash32;
use agenc_ircd_storage::federation_records::{
    CompletionCoverageRecord, EDGE_REQUEST_KIND, EdgeRequestPhase, EdgeRequestRecord,
    FederationOriginRecord, ORIGIN_RECORD_KIND, OriginRowStatus, origin_key, request_result_key,
};
use agenc_ircd_storage::{InitialStorageRecord, PersistentRecordValue, StoredKey, TableId};
use agenc_ircd_types::{ConnectionId, FederationOpcode, FederationResultKind, OriginId, RequestId};

use super::*;
use crate::federation::edge::startup::EdgeRestoreStep;

const ORIGIN: OriginId = OriginId::from_bytes([71; 16]);
const REQUEST: RequestId = RequestId::from_bytes([73; 16]);

/// One origin row and one request row, each editable before it is sealed into storage.
struct Image {
    origin: agenc_ircd_federation_wire::OriginRecord,
    origin_row: FederationOriginRecord,
    origin_key: Option<StoredKey>,
    header: RequestHeader,
    request_row: EdgeRequestRecord,
}

type Tamper = fn(&mut Image) -> TestResult;

fn replay_key() -> agenc_ircd_federation_wire::ReplayKey {
    agenc_ircd_federation_wire::ReplayKey {
        home_server_id: EDGE,
        server_incarnation: EDGE_INCARNATION,
        origin_id: ORIGIN,
        origin_generation: 0,
        operation_sequence: 0,
    }
}

fn request_bytes(header: &RequestHeader) -> TestResult<Vec<u8>> {
    let operation = FederatedOperation::SessionOpen {
        connection_id: ConnectionId::from_bytes([72; 16]),
        auth_grant_id: None,
        nickname: "durable".to_owned(),
        realname: "Durable".to_owned(),
        capability_hash: [1; 32],
        connection_nonce: [74; 32],
    };
    Ok(header
        .build(&operation.to_object()?)?
        .encode_canonical()?
        .as_slice()
        .to_vec())
}

fn image() -> TestResult<Image> {
    let header = RequestHeader {
        network_id: NETWORK,
        replay_key: replay_key(),
        request_id: REQUEST,
        opcode: FederationOpcode::SessionOpen,
    };
    let bytes = request_bytes(&header)?;
    Ok(Image {
        origin: agenc_ircd_federation_wire::OriginRecord {
            network_id: NETWORK,
            home_server_id: EDGE,
            server_incarnation: EDGE_INCARNATION,
            origin_id: ORIGIN,
            generation: 0,
            previous_origin_object_id: [0; 32],
            connection_id: ConnectionId::from_bytes([72; 16]),
            session: None,
            account: None,
            connection_nonce: [74; 32],
        },
        origin_row: FederationOriginRecord {
            origin_object_id: [0; 32],
            origin_object: Vec::new(),
            next_sequence: 1,
            status: OriginRowStatus::Live,
            flags: 0,
        },
        origin_key: None,
        header,
        request_row: EdgeRequestRecord {
            completion_coverage: None,
            request_id: *REQUEST.as_bytes(),
            request_object_id: *federation_object_id(&bytes).as_bytes(),
            request_object: bytes,
            phase: EdgeRequestPhase::Sent,
            sink_gone: false,
            result_object_id: None,
            result_object: Vec::new(),
            completion_event_id: None,
            resulting_state_generation: 0,
        },
    })
}

impl Image {
    /// Rebuilds the request object after a header edit, keeping its hash honest.
    fn rebuild_request(&mut self) -> TestResult {
        let bytes = request_bytes(&self.header)?;
        self.request_row.request_object_id = *federation_object_id(&bytes).as_bytes();
        self.request_row.request_object = bytes;
        Ok(())
    }

    /// Stores a registered result whose header is edited before encoding.
    fn with_result(&mut self, edit: fn(&mut ResultHeader)) -> TestResult {
        let mut header = ResultHeader {
            network_id: NETWORK,
            replay_key: self.header.replay_key,
            request_id: REQUEST,
            request_object_id: FederationHash32::from_bytes(self.request_row.request_object_id),
            completion_event_id: Some(EventId::from_bytes([76; 16])),
            result_kind: FederationResultKind::SessionRegistered,
        };
        edit(&mut header);
        let arm = ResultArm::SessionRegistered(SessionRegistered {
            session_id: SessionId::from_bytes([77; 16]),
            user_id: UserId::from_bytes([78; 16]),
            session_revision: 9,
            account: None,
            resulting_state_generation: 9,
        });
        let bytes = header
            .build(&arm.to_object()?, Vec::new())?
            .encode_canonical()?
            .as_slice()
            .to_vec();
        self.request_row.phase = EdgeRequestPhase::ResultPending;
        self.request_row.result_object_id = Some(*federation_object_id(&bytes).as_bytes());
        self.request_row.result_object = bytes;
        self.request_row.completion_event_id = Some([76; 16]);
        self.request_row.resulting_state_generation = 9;
        Ok(())
    }

    fn rows(mut self) -> TestResult<Vec<InitialStorageRecord>> {
        if self.origin_row.origin_object.is_empty() {
            let bytes = self.origin.to_object()?.encode_canonical()?;
            self.origin_row.origin_object = bytes.as_slice().to_vec();
            self.origin_row.origin_object_id =
                *federation_object_id(&self.origin_row.origin_object).as_bytes();
        }
        let origin_key = match self.origin_key.take() {
            Some(key) => key,
            None => origin_key(
                self.origin.home_server_id,
                self.origin.server_incarnation,
                *ORIGIN.as_bytes(),
                self.origin.generation,
            )?,
        };
        let sealed = [
            (
                TableId::FederationOrigin,
                ORIGIN_RECORD_KIND,
                origin_key,
                self.origin_row.encode()?,
            ),
            (
                TableId::RequestResult,
                EDGE_REQUEST_KIND,
                request_result_key(self.header.replay_key.to_bytes())?,
                self.request_row.encode()?,
            ),
        ];
        let mut rows = Vec::new();
        for (table, kind, key, body) in sealed {
            let value = PersistentRecordValue::new(table, kind, 1, 0, None, Vec::new(), body)?;
            rows.push(InitialStorageRecord::new(table, key, 1, value.encode()?)?);
        }
        Ok(rows)
    }
}

fn refusal_of(image: Image) -> TestResult<(Option<EdgeRestoreStep>, EdgeFederation)> {
    let fixture =
        StateCoreFixture::with_registration_router_and_records(entropy_script(), image.rows()?)?;
    let mut restarted = resync_edge();
    let step = fixture
        .restore_edge_refusal(&mut restarted, None)?
        .err()
        .map(|refusal| refusal.step);
    Ok((step, restarted))
}

fn origin_tampers() -> [Tamper; 4] {
    [
        |image| {
            image.origin.network_id = NetworkId::from_bytes([99; 32]);
            Ok(())
        },
        |image| {
            image.origin.home_server_id = ServerId::from_bytes([99; 16]);
            image.origin_key = Some(origin_key(EDGE, EDGE_INCARNATION, *ORIGIN.as_bytes(), 0)?);
            Ok(())
        },
        |image| {
            image.origin_key = Some(origin_key(EDGE, EDGE_INCARNATION, *ORIGIN.as_bytes(), 5)?);
            Ok(())
        },
        |image| {
            let bytes = image.origin.to_object()?.encode_canonical()?;
            image.origin_row.origin_object = bytes.as_slice().to_vec();
            image.origin_row.origin_object_id = [99; 32];
            Ok(())
        },
    ]
}

fn request_tampers() -> [Tamper; 6] {
    [
        |image| {
            image.header.replay_key.home_server_id = ServerId::from_bytes([99; 16]);
            image.rebuild_request()
        },
        |image| {
            image.with_result(|_| {})?;
            image.request_row.phase = EdgeRequestPhase::SnapshotCovered;
            Ok(())
        },
        |image| {
            image.header.network_id = NetworkId::from_bytes([99; 32]);
            image.rebuild_request()
        },
        |image| {
            image.request_row.request_id = [99; 16];
            Ok(())
        },
        |image| {
            image.request_row.request_object_id = [99; 32];
            Ok(())
        },
        |image| {
            image.request_row.phase = EdgeRequestPhase::EventCovered;
            Ok(())
        },
    ]
}

fn result_tampers() -> [Tamper; 5] {
    [
        |image| image.with_result(|header| header.replay_key.operation_sequence = 4),
        |image| image.with_result(|header| header.request_id = RequestId::from_bytes([99; 16])),
        |image| {
            image.with_result(|header| {
                header.request_object_id = FederationHash32::from_bytes([99; 32]);
            })
        },
        |image| {
            image.with_result(|_| {})?;
            image.request_row.result_object_id = Some([99; 32]);
            Ok(())
        },
        |image| {
            image.with_result(|_| {})?;
            image.request_row.completion_event_id = Some([99; 16]);
            Ok(())
        },
    ]
}

fn coverage_tampers() -> [Tamper; 4] {
    [
        |image| covered(image, |coverage| coverage.request_object_id = [99; 32]),
        |image| covered(image, |coverage| coverage.completion_event_id = [99; 16]),
        |image| covered(image, |coverage| coverage.coordinator_state_generation = 8),
        |image| covered(image, |coverage| coverage.projection_generation = 50),
    ]
}

fn covered(image: &mut Image, edit: fn(&mut CompletionCoverageRecord)) -> TestResult {
    image.with_result(|_| {})?;
    let mut coverage = CompletionCoverageRecord {
        request_object_id: image.request_row.request_object_id,
        completion_event_id: [76; 16],
        completion_object_id: [75; 32],
        projection_generation: 0,
        delivery_sequence: 0,
        coordinator_state_generation: 9,
    };
    edit(&mut coverage);
    image.request_row.completion_coverage = Some(coverage);
    Ok(())
}

fn assert_refused(tampers: &[Tamper], step: EdgeRestoreStep) -> TestResult {
    for tamper in tampers {
        let mut image = image()?;
        tamper(&mut image)?;
        let (refused, restarted) = refusal_of(image)?;
        assert_eq!(refused, Some(step));
        assert!(restarted.pending.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn an_origin_row_that_disagrees_with_this_edge_refuses_at_the_origin_journal() -> TestResult {
    assert_refused(&origin_tampers(), EdgeRestoreStep::OriginJournal)
}

#[tokio::test]
async fn a_request_row_that_disagrees_with_its_object_refuses_at_the_request_journal() -> TestResult
{
    assert_refused(&request_tampers(), EdgeRestoreStep::RequestJournal)?;
    assert_refused(&result_tampers(), EdgeRestoreStep::RequestJournal)?;
    assert_refused(&coverage_tampers(), EdgeRestoreStep::RequestJournal)
}

#[tokio::test]
async fn an_honest_image_restores_and_a_previous_incarnations_image_is_left_alone() -> TestResult {
    let mut honest = image()?;
    honest.with_result(|_| {})?;
    let (refused, restarted) = refusal_of(honest)?;
    assert_eq!(refused, None);
    assert!(restarted.pending.contains_key(&REQUEST));

    let mut previous = image()?;
    let incarnation = ServerIncarnation::from_bytes([98; 16]);
    previous.origin.server_incarnation = incarnation;
    previous.header.replay_key.server_incarnation = incarnation;
    previous.rebuild_request()?;
    let (refused, restarted) = refusal_of(previous)?;
    assert_eq!(refused, None);
    assert!(restarted.pending.is_empty());
    assert!(restarted.origins.is_empty());
    Ok(())
}
