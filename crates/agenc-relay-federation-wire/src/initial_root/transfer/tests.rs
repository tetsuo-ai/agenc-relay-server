//! The base link and fixed-width profile are independent on both directions.
#![forbid(unsafe_code)]

use super::*;
use crate::{FederationHash32, federation_object_id};
use agenc_relay_types::{NetworkId, OriginId, RequestId, ServerId, ServerIncarnation};

fn layout(operation: InitialRootOperation) -> RequestHeader {
    RequestHeader {
        network_id: NetworkId::from_bytes([1; 32]),
        replay_key: ReplayKey {
            home_server_id: ServerId::from_bytes([2; 16]),
            server_incarnation: ServerIncarnation::from_bytes([3; 16]),
            origin_id: OriginId::from_bytes([4; 16]),
            origin_generation: 5,
            operation_sequence: 6,
        },
        request_id: RequestId::from_bytes([7; 16]),
        opcode: operation.base_layout(),
    }
}

fn hpke(operation: InitialRootOperation, size: u64) -> Result<Vec<u8>, CodecError> {
    let mut bytes = vec![0x2d; usize::try_from(size).map_err(|_| CodecError::Overflow)?];
    bytes
        .get_mut(..2)
        .ok_or(CodecError::UnexpectedEof)?
        .copy_from_slice(&V2.to_be_bytes());
    bytes
        .get_mut(HPKE_KIND..HPKE_KIND + 2)
        .ok_or(CodecError::UnexpectedEof)?
        .copy_from_slice(&operation.hpke().to_be_bytes());
    let length = HPKE_KIND + 2 + 32;
    let cipher_len = u16::try_from(bytes.len() - length - 2).map_err(|_| CodecError::Overflow)?;
    bytes
        .get_mut(length..length + 2)
        .ok_or(CodecError::UnexpectedEof)?
        .copy_from_slice(&cipher_len.to_be_bytes());
    Ok(bytes)
}
fn budget() -> DecodeBudget {
    DecodeBudget::new(128 * 1024, 1024)
}
fn check_request(
    kind: InitialRootOperation,
) -> Result<(RequestHeader, FederationHash32), CodecError> {
    let layout = layout(kind);
    let session = (kind == InitialRootOperation::Claim).then_some(SessionId::from_bytes([8; 16]));
    let envelope = hpke(kind, ACCOUNT_SERVICE_ENVELOPE_BYTES)?;
    let request = InitialRootRequest {
        operation: kind,
        layout,
        session,
        envelope: &envelope,
    };
    let wire = request.encode(FederationProfile::InitialRoot)?;
    assert!(request.encode(FederationProfile::Base).is_err());
    assert!(SchemaObject::decode_exact("FederationRequest", &wire, &mut budget()).is_err());
    assert!(InitialRootRequest::decode(FederationProfile::Base, &wire, &mut budget()).is_err());
    let got = InitialRootRequest::decode(FederationProfile::InitialRoot, &wire, &mut budget())?;
    assert_eq!(
        (got.layout, got.operation, got.session),
        (layout, kind, session)
    );
    assert!(got.envelope == envelope);
    assert!(
        InitialRootRequest::decode(
            FederationProfile::InitialRoot,
            &wire,
            &mut DecodeBudget::new(wire.len() - 1, 1024)
        )
        .is_err()
    );
    let mut wrong = wire.clone();
    replace_tag(
        &mut wrong,
        REQUEST_ARM + kind.session_width() + HPKE_KIND,
        kind.hpke(),
        1,
    )?;
    assert!(
        InitialRootRequest::decode(FederationProfile::InitialRoot, &wrong, &mut budget()).is_err()
    );
    Ok((layout, federation_object_id(&wire)))
}
#[test]
fn both_opted_in_operations_and_sealed_results_retain_the_original_envelopes()
-> Result<(), CodecError> {
    for operation in [
        InitialRootOperation::ClaimedCreateStart,
        InitialRootOperation::Claim,
    ] {
        let (request, id) = check_request(operation)?;
        let layout = ResultHeader {
            network_id: request.network_id,
            replay_key: request.replay_key,
            request_id: request.request_id,
            request_object_id: id,
            completion_event_id: None,
            result_kind: FederationResultKind::AuthChallenge,
        };
        let sealed = hpke(operation, ACCOUNT_SERVICE_RESPONSE_BYTES)?;
        let wire = InitialRootResult::encode_sealed(
            FederationProfile::InitialRoot,
            &layout,
            operation,
            &sealed,
        )?;
        let got = InitialRootResult::decode(FederationProfile::InitialRoot, &wire, &mut budget())?;
        assert_eq!(got.layout, layout);
        assert!(got.sealed == Some((operation, sealed.as_slice())));
        assert!(SchemaObject::decode_exact("FederationResult", &wire, &mut budget()).is_err());
        assert!(InitialRootResult::decode(FederationProfile::Base, &wire, &mut budget()).is_err());
        let mut wrong = wire.clone();
        replace_tag(
            &mut wrong,
            RESULT_KIND,
            operation.result(),
            FederationResultKind::Committed.wire_value(),
        )?;
        assert!(
            InitialRootResult::decode(FederationProfile::InitialRoot, &wrong, &mut budget())
                .is_err()
        );
        let failure = SchemaObject::new(
            "result.failed",
            vec![access::opaque(b"SERVER_BUSY")?, access::opaque(b"")?],
        )?;
        let failed_header = ResultHeader {
            result_kind: FederationResultKind::Failed,
            ..layout
        };
        let failed = InitialRootResult::encode_failed(
            FederationProfile::InitialRoot,
            &failed_header,
            &failure,
            vec![],
        )?;
        let got =
            InitialRootResult::decode(FederationProfile::InitialRoot, &failed, &mut budget())?;
        assert!(got.sealed.is_none());
        assert_eq!(got.layout, failed_header);
    }
    Ok(())
}
