#![forbid(unsafe_code)]
//! History pages enforce immutable row facts and exclude mutation-completion semantics.

use agenc_ircd_federation_wire::access::opaque;
use agenc_ircd_federation_wire::{
    CanonicalEncode, CodecError, DecodeBudget, FederationHash32, HistoryPage, ReplayKey,
    ResultHeader, SchemaObject, WireValue,
};
use agenc_ircd_types::{
    EventId, FederationResultKind, NetworkId, OriginId, RequestId, ServerId, ServerIncarnation,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn auth(
    session: u8,
    generation: u64,
    account: &[u8],
    account_generation: u64,
) -> Result<SchemaObject, CodecError> {
    SchemaObject::new(
        "FederationHistoryAuthorization",
        vec![
            opaque(&[session; 16])?,
            opaque(&[2; 16])?,
            WireValue::Unsigned(generation),
            opaque(account)?,
            WireValue::Unsigned(account_generation),
            WireValue::Unsigned(1),
            WireValue::Unsigned(1),
        ],
    )
}

fn message(
    sequence: u64,
    kind: u64,
    received: u64,
    expires: u64,
    body: &[u8],
) -> Result<SchemaObject, CodecError> {
    let nickname = SchemaObject::new("FederationNickname", vec![opaque(b"sam")?])?;
    let cloak = SchemaObject::new(
        "FederationPublicCloak",
        vec![opaque(b"aaaaaaaaaa")?, opaque(b"bbbbbbbbbbbbbbbb")?],
    )?;
    let source = SchemaObject::new(
        "FederationSourceView",
        vec![
            opaque(&[2; 16])?,
            WireValue::Structure(nickname),
            WireValue::Structure(cloak),
            opaque(b"")?,
        ],
    )?;
    SchemaObject::new(
        "FederationHistoryMessage",
        vec![
            opaque(&[3; 16])?,
            WireValue::Unsigned(sequence),
            WireValue::Unsigned(received),
            WireValue::Unsigned(expires),
            WireValue::Unsigned(kind),
            WireValue::Structure(source),
            WireValue::Vector(Vec::new()),
            opaque(body)?,
        ],
    )
}

fn page(
    session: u8,
    cut: u64,
    rows: Vec<SchemaObject>,
    cursor: &[u8],
) -> Result<HistoryPage, CodecError> {
    let channel = SchemaObject::new("FederationChannelName", vec![opaque(b"#room")?])?;
    HistoryPage::new(SchemaObject::new(
        "result.history_page",
        vec![
            opaque(&[session; 16])?,
            opaque(&[4; 16])?,
            WireValue::Structure(channel),
            WireValue::Structure(auth(1, 1, b"", 0)?),
            opaque(&[5; 32])?,
            WireValue::Unsigned(cut),
            WireValue::Unsigned(0),
            opaque(cursor)?,
            WireValue::Vector(rows),
        ],
    )?)
}

fn header(kind: FederationResultKind, completion: Option<EventId>) -> ResultHeader {
    ResultHeader {
        network_id: NetworkId::from_bytes([1; 32]),
        replay_key: ReplayKey {
            home_server_id: ServerId::from_bytes([2; 16]),
            server_incarnation: ServerIncarnation::from_bytes([3; 16]),
            origin_id: OriginId::from_bytes([4; 16]),
            origin_generation: 1,
            operation_sequence: 1,
        },
        request_id: RequestId::from_bytes([5; 16]),
        request_object_id: FederationHash32::from_bytes([6; 32]),
        completion_event_id: completion,
        result_kind: kind,
    }
}

#[test]
fn history_messages_reject_wrong_kind_body_and_expiry() -> TestResult {
    assert!(message(1, 1, 1, 2, b"hello").is_ok());
    assert!(message(1, 2, 1, 2, b"").is_ok());
    for (sequence, kind, received, expires, body) in [
        (0, 1, 1, 2, &b"hello"[..]),
        (1, 3, 1, 2, b"hello"),
        (1, 1, 0, 2, b"hello"),
        (1, 1, 2, 2, b"hello"),
        (1, 1, 1, 2, b""),
        (1, 1, 1, 2, b"a\nb"),
    ] {
        assert!(message(sequence, kind, received, expires, body).is_err());
    }
    Ok(())
}

#[test]
fn authorization_and_page_correlation_fail_closed() -> TestResult {
    assert!(auth(1, 0, b"", 0).is_err());
    assert!(auth(1, 1, b"", 1).is_err());
    assert!(auth(1, 1, b"a_AAECAwQFBgcICQoLDA0ODw", 1).is_ok());
    assert!(page(2, 1, Vec::new(), b"").is_err());
    assert!(page(1, 0, Vec::new(), b"").is_err());
    assert!(page(1, 1, Vec::new(), &[1; 32]).is_err());
    assert!(page(1, 1, vec![message(2, 1, 1, 2, b"hello")?], b"").is_err());
    assert!(
        page(
            1,
            3,
            vec![
                message(2, 1, 1, 2, b"hello")?,
                message(1, 1, 1, 2, b"hello")?
            ],
            b""
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn empty_and_populated_history_pages_round_trip_without_completion() -> TestResult {
    for rows in [Vec::new(), vec![message(1, 1, 1, 3_600_001, b"hello")?]] {
        let page = page(1, 1, rows, b"")?;
        let object =
            header(FederationResultKind::HistoryPage, None).build(page.as_object(), Vec::new())?;
        let bytes = object.encode_canonical()?;
        let decoded = SchemaObject::decode_exact(
            "FederationResult",
            bytes.as_slice(),
            &mut DecodeBudget::new(1 << 20, 4096),
        )?;
        assert!(decoded == object);
        assert!(
            header(
                FederationResultKind::HistoryPage,
                Some(EventId::from_bytes([1; 16]))
            )
            .build(page.as_object(), Vec::new())
            .is_err()
        );
    }
    let expired = SchemaObject::new("result.history_expired", vec![opaque(&[9; 32])?])?;
    assert!(
        header(FederationResultKind::HistoryExpired, None)
            .build(&expired, Vec::new())
            .is_ok()
    );
    assert!(
        header(
            FederationResultKind::HistoryExpired,
            Some(EventId::from_bytes([1; 16]))
        )
        .build(&expired, Vec::new())
        .is_err()
    );
    Ok(())
}
