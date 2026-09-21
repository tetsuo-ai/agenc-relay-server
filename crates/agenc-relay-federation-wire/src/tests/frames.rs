#![forbid(unsafe_code)]

//! Frame parse and render: round trips, prefix and tag policy, cursors, and
//! the proof that every form fits its line ceiling.

use std::error::Error;

use agenc_relay_types::{
    CLIENT_PHYSICAL_LINE_BYTES, EventId, FederationRole, NetworkId, OriginId, RecoveryEpoch,
    RequestId, ServerId, ServerIncarnation,
};

use super::*;
use crate::objects::{FederationHello, HelloTbs};
use crate::text::{FederationCommandTag, FederationFragment, FederationHash32};

type TestResult = Result<(), Box<dyn Error>>;

const PEER: &str = "core.example";
const MAX_NAME: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn hello() -> FederationHello {
    FederationHello {
        tbs: HelloTbs {
            network_id: NetworkId::from_bytes([1; 32]),
            sender_server_id: ServerId::from_bytes([2; 16]),
            expected_peer_server_id: ServerId::from_bytes([3; 16]),
            server_incarnation: ServerIncarnation::from_bytes([4; 16]),
            recovery_epoch: RecoveryEpoch::from_bytes([5; 16]),
            role: FederationRole::Edge,
            hello_nonce: [6; 32],
            profile_hash: [7; 32],
            tls_exporter: [8; 32],
        },
        signature: [9; 64],
    }
}

fn max_fragment() -> Result<FederationFragment, Box<dyn Error>> {
    Ok(FederationFragment::new(
        FederationHash32::from_bytes([0xff; 32]),
        u32::MAX / 3 - 1,
        u32::MAX / 3,
        u32::MAX / 3 * 2,
        &[0xff; 2940],
    )
    .or_else(|_| {
        FederationFragment::new(
            FederationHash32::from_bytes([0xff; 32]),
            88,
            90,
            262_144,
            &[0xff; 2940],
        )
    })?)
}

fn fragment_for(object_id: FederationHash32) -> Result<FederationFragment, Box<dyn Error>> {
    Ok(FederationFragment::new(object_id, 0, 1, 3, b"abc")?)
}

fn operation_descriptor(object_id: FederationHash32) -> OperationDescriptor {
    OperationDescriptor {
        addressed_server_id: ServerId::from_bytes([u8::MAX; 16]),
        server_incarnation: ServerIncarnation::from_bytes([u8::MAX; 16]),
        origin_id: OriginId::from_bytes([u8::MAX; 16]),
        origin_generation: u64::MAX,
        operation_sequence: u64::MAX,
        request_id: RequestId::from_bytes([u8::MAX; 16]),
        object_id,
    }
}

fn identity() -> SnapshotIdentity {
    SnapshotIdentity {
        snapshot_token: FederationHash32::from_bytes([u8::MAX; 32]),
        recovery_epoch: RecoveryEpoch::from_bytes([u8::MAX; 16]),
        projection_generation: u64::MAX,
        state_generation: u64::MAX,
        snapshot_digest: FederationHash32::from_bytes([u8::MAX; 32]),
    }
}

/// Every form at its widest legal parameter values.
fn widest_frames() -> Result<Vec<FederationFrame>, Box<dyn Error>> {
    let wide_id = ServerId::from_bytes([u8::MAX; 16]);
    let wide_incarnation = ServerIncarnation::from_bytes([u8::MAX; 16]);
    let wide_hash = FederationHash32::from_bytes([u8::MAX; 32]);
    let cursor = DeliveryCursor::At {
        delivery_sequence: u64::MAX,
        event_id: EventId::from_bytes([u8::MAX; 16]),
    };
    let fragment = max_fragment()?;
    let object_id = fragment.object_id();
    Ok(vec![
        FederationFrame::Hello {
            peer_server_id: wide_id,
            hello: hello(),
        },
        FederationFrame::Ready {
            peer_server_id: wide_id,
            hello_nonce: [u8::MAX; 32],
        },
        FederationFrame::Ping {
            peer_server_id: wide_id,
            nonce: [u8::MAX; 32],
        },
        FederationFrame::Pong {
            peer_server_id: wide_id,
            nonce: [u8::MAX; 32],
        },
        FederationFrame::Request {
            descriptor: operation_descriptor(object_id),
            fragment: max_fragment()?,
        },
        FederationFrame::Result {
            descriptor: operation_descriptor(object_id),
            fragment: max_fragment()?,
        },
        FederationFrame::Event {
            descriptor: EventDescriptor {
                target_server_id: wide_id,
                delivery_sequence: u64::MAX,
                event_id: EventId::from_bytes([u8::MAX; 16]),
                object_id,
            },
            fragment: max_fragment()?,
        },
        FederationFrame::Ack {
            coordinator_server_id: wide_id,
            delivery_sequence: u64::MAX,
            event_id: EventId::from_bytes([u8::MAX; 16]),
        },
        FederationFrame::OriginReset {
            coordinator_server_id: wide_id,
            server_incarnation: wide_incarnation,
        },
        FederationFrame::OriginAdd {
            descriptor: OriginDescriptor {
                coordinator_server_id: wide_id,
                server_incarnation: wide_incarnation,
                origin_id: OriginId::from_bytes([u8::MAX; 16]),
                generation: u64::MAX,
                object_id,
            },
            fragment: max_fragment()?,
        },
        FederationFrame::OriginUpdate {
            descriptor: OriginDescriptor {
                coordinator_server_id: wide_id,
                server_incarnation: wide_incarnation,
                origin_id: OriginId::from_bytes([u8::MAX; 16]),
                generation: u64::MAX,
                object_id,
            },
            fragment: max_fragment()?,
        },
        FederationFrame::OriginDel {
            coordinator_server_id: wide_id,
            server_incarnation: wide_incarnation,
            origin_id: OriginId::from_bytes([u8::MAX; 16]),
            generation: u64::MAX,
            next_operation_sequence: u64::MAX,
        },
        FederationFrame::OriginAck {
            edge_server_id: wide_id,
            server_incarnation: wide_incarnation,
            origin_id: OriginId::from_bytes([u8::MAX; 16]),
            generation: u64::MAX,
            object_id: Some(wide_hash),
        },
        FederationFrame::OriginAck {
            edge_server_id: wide_id,
            server_incarnation: wide_incarnation,
            origin_id: OriginId::from_bytes([u8::MAX; 16]),
            generation: u64::MAX,
            object_id: None,
        },
        FederationFrame::OriginReady {
            edge_server_id: wide_id,
            server_incarnation: wide_incarnation,
        },
        FederationFrame::Resume {
            coordinator_server_id: wide_id,
            projection_generation: u64::MAX,
            cursor,
        },
        FederationFrame::Resume {
            coordinator_server_id: wide_id,
            projection_generation: 0,
            cursor: DeliveryCursor::Empty,
        },
        FederationFrame::ResumeOk {
            edge_server_id: wide_id,
            projection_generation: u64::MAX,
            next_delivery_sequence: u64::MAX,
        },
        FederationFrame::ResumeSnapshot {
            edge_server_id: wide_id,
        },
        FederationFrame::SnapshotBegin {
            edge_server_id: wide_id,
            identity: identity(),
            entry_count: u64::MAX,
        },
        FederationFrame::SnapshotEntry {
            edge_server_id: wide_id,
            snapshot_token: wide_hash,
            entry_index: u32::MAX,
            object_id,
            fragment: max_fragment()?,
        },
        FederationFrame::SnapshotEnd {
            edge_server_id: wide_id,
            snapshot_token: wide_hash,
            cursor,
        },
        FederationFrame::SnapshotEnd {
            edge_server_id: wide_id,
            snapshot_token: wide_hash,
            cursor: DeliveryCursor::Empty,
        },
        FederationFrame::SnapshotReady {
            coordinator_server_id: wide_id,
            identity: identity(),
        },
        FederationFrame::SnapshotActive {
            edge_server_id: wide_id,
            identity: identity(),
        },
    ])
}

/// Splits a rendered line back into the parts a message parser would supply.
struct SplitLine {
    tag: Option<(String, String)>,
    prefix: Option<String>,
    command: String,
    parameters: Vec<String>,
}

fn split(line: &str) -> Result<SplitLine, Box<dyn Error>> {
    let body = line.strip_suffix("\r\n").ok_or("missing CRLF")?;
    let mut tokens = body.split(' ');
    let mut first = tokens.next().ok_or("empty line")?;
    let mut tag = None;
    if let Some(tag_text) = first.strip_prefix('@') {
        let (name, value) = tag_text.split_once('=').ok_or("tag without value")?;
        tag = Some((name.to_owned(), value.to_owned()));
        first = tokens.next().ok_or("missing prefix")?;
    }
    let prefix = first.strip_prefix(':').map(str::to_owned);
    let command = if prefix.is_some() {
        tokens.next().ok_or("missing command")?.to_owned()
    } else {
        first.to_owned()
    };
    Ok(SplitLine {
        tag,
        prefix,
        command,
        parameters: tokens.map(str::to_owned).collect(),
    })
}

fn reparse(line: &str, expected_prefix: &str) -> Result<FederationFrame, Box<dyn Error>> {
    let parts = split(line)?;
    let tags: Vec<FederationCommandTag<'_>> = parts
        .tag
        .iter()
        .map(|(name, value)| FederationCommandTag::new(name, Some(value)))
        .collect();
    let parameters: Vec<&str> = parts.parameters.iter().map(String::as_str).collect();
    Ok(FederationFrame::parse(
        FederationLine::new(parts.prefix.as_deref(), &tags, &parts.command, &parameters),
        expected_prefix,
    )?)
}

#[test]
fn every_form_round_trips_and_fits_its_ceiling() -> TestResult {
    let ceiling = usize::try_from(CLIENT_PHYSICAL_LINE_BYTES)?;
    let mut seen = std::collections::BTreeSet::new();
    for frame in widest_frames()? {
        let rendered = frame.render(MAX_NAME)?;
        assert!(!rendered.is_empty());
        let limit = if frame.kind() == FederationFrameKind::Hello {
            FHELLO_LINE_BYTES
        } else {
            ceiling
        };
        assert!(
            rendered.len() <= limit,
            "{} rendered {} bytes",
            frame.kind().form(),
            rendered.len()
        );
        let parsed = reparse(rendered.as_str(), MAX_NAME)?;
        assert_eq!(parsed.kind(), frame.kind());
        let again = parsed.render(MAX_NAME)?;
        assert_eq!(again.as_str(), rendered.as_str());
        assert_eq!(parsed.fragment().is_some(), frame.fragment().is_some());
        seen.insert(frame.kind().form());
    }
    assert_eq!(seen.len(), 22);
    Ok(())
}

#[test]
fn parsed_values_match_the_rendered_frame() -> TestResult {
    let frame = FederationFrame::Ack {
        coordinator_server_id: ServerId::from_bytes([1; 16]),
        delivery_sequence: 77,
        event_id: EventId::from_bytes([2; 16]),
    };
    let rendered = frame.render(PEER)?;
    assert_eq!(
        rendered.as_str(),
        ":core.example FACK AQEBAQEBAQEBAQEBAQEBAQ 77 AgICAgICAgICAgICAgICAg\r\n"
    );
    match reparse(rendered.as_str(), PEER)? {
        FederationFrame::Ack {
            coordinator_server_id,
            delivery_sequence,
            event_id,
        } => {
            assert_eq!(coordinator_server_id, ServerId::from_bytes([1; 16]));
            assert_eq!(delivery_sequence, 77);
            assert_eq!(event_id, EventId::from_bytes([2; 16]));
        }
        _ => return Err("wrong frame".into()),
    }

    let hello_frame = FederationFrame::Hello {
        peer_server_id: ServerId::from_bytes([3; 16]),
        hello: hello(),
    };
    let rendered = hello_frame.render(PEER)?;
    match reparse(rendered.as_str(), PEER)? {
        FederationFrame::Hello {
            peer_server_id,
            hello: parsed,
        } => {
            assert_eq!(peer_server_id, ServerId::from_bytes([3; 16]));
            assert_eq!(parsed, hello());
        }
        _ => return Err("wrong frame".into()),
    }

    let request = FederationFrame::Request {
        descriptor: operation_descriptor(FederationHash32::from_bytes([4; 32])),
        fragment: fragment_for(FederationHash32::from_bytes([4; 32]))?,
    };
    let rendered = request.render(PEER)?;
    assert!(rendered.as_str().starts_with("@agenc.ag/fed=v1."));
    match reparse(rendered.as_str(), PEER)? {
        FederationFrame::Request {
            descriptor,
            fragment,
        } => {
            assert_eq!(
                descriptor,
                operation_descriptor(FederationHash32::from_bytes([4; 32]))
            );
            assert_eq!(fragment.segment(), b"abc");
        }
        _ => return Err("wrong frame".into()),
    }
    Ok(())
}

#[test]
fn prefix_tag_arity_and_identity_violations_are_rejected() -> TestResult {
    let ack = ":core.example FACK AQEBAQEBAQEBAQEBAQEBAQ 77 AgICAgICAgICAgICAgICAg\r\n";
    assert_eq!(
        reparse(ack, "other.example").err().map(|e| e.to_string()),
        Some(FrameError::WrongPrefix.to_string())
    );
    let no_prefix = "FACK AQEBAQEBAQEBAQEBAQEBAQ 77 AgICAgICAgICAgICAgICAg\r\n";
    assert_eq!(
        reparse(no_prefix, PEER).err().map(|e| e.to_string()),
        Some(FrameError::MissingPrefix.to_string())
    );
    let extra = ":core.example FACK AQEBAQEBAQEBAQEBAQEBAQ 77 AgICAgICAgICAgICAgICAg extra\r\n";
    assert!(reparse(extra, PEER).is_err());
    let unknown = ":core.example FNOPE a\r\n";
    assert!(reparse(unknown, PEER).is_err());
    let lowercase = ":core.example fack a b c\r\n";
    assert!(reparse(lowercase, PEER).is_err());

    let request = FederationFrame::Request {
        descriptor: operation_descriptor(FederationHash32::from_bytes([4; 32])),
        fragment: fragment_for(FederationHash32::from_bytes([5; 32]))?,
    };
    let rendered = request.render(PEER)?;
    assert_eq!(
        reparse(rendered.as_str(), PEER)
            .err()
            .map(|e| e.to_string()),
        Some(FrameError::ObjectIdMismatch.to_string())
    );

    let tagged_ack = format!("@agenc.ag/fed=v1.x {ack}");
    assert!(reparse(&tagged_ack, PEER).is_err());

    let resume_half = ":core.example FRESUME AQEBAQEBAQEBAQEBAQEBAQ 1 * AgICAgICAgICAgICAgICAg\r\n";
    assert_eq!(
        reparse(resume_half, PEER).err().map(|e| e.to_string()),
        Some(FrameError::CursorShape.to_string())
    );
    let resume_other_half = ":core.example FRESUME AQEBAQEBAQEBAQEBAQEBAQ 1 5 *\r\n";
    assert_eq!(
        reparse(resume_other_half, PEER)
            .err()
            .map(|e| e.to_string()),
        Some(FrameError::CursorShape.to_string())
    );

    let bad_hello = ":core.example FHELLO AQEBAQEBAQEBAQEBAQEBAQ AAAA\r\n";
    assert!(reparse(bad_hello, PEER).is_err());
    let mut hello_line = FederationFrame::Hello {
        peer_server_id: ServerId::from_bytes([3; 16]),
        hello: hello(),
    }
    .render(PEER)?
    .as_str()
    .to_owned();
    hello_line.truncate(hello_line.len() - 2);
    hello_line.pop();
    hello_line.push_str("=\r\n");
    assert!(reparse(&hello_line, PEER).is_err());
    Ok(())
}

#[test]
fn render_rejects_invalid_server_names() -> TestResult {
    let frame = FederationFrame::ResumeSnapshot {
        edge_server_id: ServerId::from_bytes([1; 16]),
    };
    for name in ["", "nodot", "Upper.example", "a b.example", "-bad.example"] {
        assert_eq!(
            frame.render(name).err(),
            Some(FrameError::InvalidServerName),
            "{name}"
        );
    }
    let too_long = format!("{}.example", "a".repeat(120));
    assert_eq!(
        frame.render(&too_long).err(),
        Some(FrameError::InvalidServerName)
    );
    assert_eq!(frame.render(MAX_NAME)?.len(), MAX_NAME.len() + 43);
    Ok(())
}

#[test]
fn errors_display_and_convert() {
    assert!(!FrameError::MissingPrefix.to_string().is_empty());
    assert!(!FrameError::WrongPrefix.to_string().is_empty());
    assert!(!FrameError::ObjectIdMismatch.to_string().is_empty());
    assert!(!FrameError::CursorShape.to_string().is_empty());
    assert!(!FrameError::InvalidServerName.to_string().is_empty());
    assert!(!FrameError::Overflow.to_string().is_empty());
    assert!(!FrameError::AllocationFailed.to_string().is_empty());
    assert!(
        !FrameError::from(FederationTextError::Empty)
            .to_string()
            .is_empty()
    );
    assert!(
        !FrameError::from(CodecError::TrailingBytes)
            .to_string()
            .is_empty()
    );
    for kind in [
        FederationFrameKind::Hello,
        FederationFrameKind::SnapshotActive,
    ] {
        assert!(!kind.form().is_empty());
    }
}
