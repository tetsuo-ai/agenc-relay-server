#![forbid(unsafe_code)]

//! Companion federation frames.

use std::error::Error;

use super::*;
use crate::wire::fragment::fragment_object;
use crate::wire::tokens::base64url_encode;

type TestResult = Result<(), Box<dyn Error>>;

const PREFIX: &str = "coord.example.test";

fn tuple() -> Result<EcapTuple, E2eeError> {
    EcapTuple::local(
        &base64url_encode(&[1; 32]),
        &base64url_encode(&[2; 16]),
        3,
        &base64url_encode(&[4; 32]),
    )
}

fn correlation() -> Correlation {
    Correlation {
        peer_server_id: [1; 16],
        server_incarnation: [2; 16],
        origin_id: [3; 16],
        origin_generation: 4,
        operation_sequence: 5,
        request_id: [6; 16],
    }
}

fn position() -> DeliveryPosition {
    DeliveryPosition {
        server_id: [1; 16],
        delivery_generation: 2,
        delivery_sequence: 3,
        event_id: [4; 16],
    }
}

fn object() -> Result<(FragmentTag, [u8; 32]), Box<dyn Error>> {
    let bytes: Vec<u8> = (0..500_u16).map(|index| (index % 251) as u8).collect();
    let fragment = fragment_object(&bytes)?
        .into_iter()
        .next()
        .ok_or("fragment")?;
    let object_id = *fragment.object_id.as_bytes();
    Ok((fragment, object_id))
}

/// A rendered line split back into its tag, prefix, command, and parameters.
type SplitLine = (Option<String>, String, String, Vec<String>);

/// Splits a rendered line back into its tag, prefix, command, and parameters.
fn split(line: &str) -> Result<SplitLine, Box<dyn Error>> {
    let line = line.strip_suffix("\r\n").ok_or("crlf")?;
    let mut words = line.split(' ');
    let mut first = words.next().ok_or("empty")?;
    let mut tag = None;
    if let Some(rest) = first.strip_prefix('@') {
        let (_, value) = rest.split_once('=').ok_or("tag")?;
        tag = Some(value.to_owned());
        first = words.next().ok_or("prefix")?;
    }
    let prefix = first.strip_prefix(':').ok_or("colon")?.to_owned();
    let command = words.next().ok_or("command")?.to_owned();
    Ok((tag, prefix, command, words.map(str::to_owned).collect()))
}

fn every_frame() -> Result<Vec<CompanionFrame>, Box<dyn Error>> {
    let (fragment, object_id) = object()?;
    Ok(vec![
        CompanionFrame::EcapOffer(tuple()?),
        CompanionFrame::EcapAck(tuple()?),
        CompanionFrame::Request {
            correlation: correlation(),
            object_id,
            fragment: fragment.clone(),
        },
        CompanionFrame::Payload {
            correlation: correlation(),
            object_id,
            fragment: fragment.clone(),
        },
        CompanionFrame::Result {
            correlation: correlation(),
            object_id,
            fragment: fragment.clone(),
        },
        CompanionFrame::Response {
            correlation: correlation(),
            response_index: 7,
            object_id,
            fragment: fragment.clone(),
        },
        CompanionFrame::Event {
            position: position(),
            object_id,
            fragment: fragment.clone(),
        },
        CompanionFrame::Data {
            position: position(),
            object_id,
            fragment: fragment.clone(),
        },
        CompanionFrame::Ack(position()),
        CompanionFrame::Resume {
            coordinator_server_id: [1; 16],
            server_incarnation: [2; 16],
            delivery_generation: 3,
            last: None,
        },
        CompanionFrame::Resume {
            coordinator_server_id: [1; 16],
            server_incarnation: [2; 16],
            delivery_generation: 3,
            last: Some((9, [5; 16])),
        },
        CompanionFrame::ResumeOk {
            target_server_id: [1; 16],
            server_incarnation: [2; 16],
            delivery_generation: 3,
            next_delivery_sequence: 10,
        },
        CompanionFrame::OriginReset {
            coordinator_server_id: [1; 16],
            server_incarnation: [2; 16],
        },
        CompanionFrame::OriginReady {
            home_server_id: [1; 16],
            server_incarnation: [2; 16],
        },
        CompanionFrame::OriginState {
            update: false,
            coordinator_server_id: [1; 16],
            server_incarnation: [2; 16],
            origin_id: [3; 16],
            origin_generation: 0,
            object_id,
            fragment: fragment.clone(),
        },
        CompanionFrame::OriginState {
            update: true,
            coordinator_server_id: [1; 16],
            server_incarnation: [2; 16],
            origin_id: [3; 16],
            origin_generation: 1,
            object_id,
            fragment: fragment.clone(),
        },
        CompanionFrame::OriginDel {
            coordinator_server_id: [1; 16],
            server_incarnation: [2; 16],
            origin_id: [3; 16],
            origin_generation: 1,
            next_operation_sequence: 4,
        },
        CompanionFrame::OriginAck {
            home_server_id: [1; 16],
            server_incarnation: [2; 16],
            origin_id: [3; 16],
            origin_generation: 1,
            object_id: Some([8; 32]),
        },
        CompanionFrame::OriginAck {
            home_server_id: [1; 16],
            server_incarnation: [2; 16],
            origin_id: [3; 16],
            origin_generation: 1,
            object_id: None,
        },
        CompanionFrame::StateBegin {
            target_server_id: [1; 16],
            snapshot_token: [2; 32],
            state_generation: 3,
            delivery_generation: 4,
            page_sequence: 0,
            total_entry_count: 33,
            page_entry_count: 32,
            snapshot_digest: [5; 32],
        },
        CompanionFrame::StateEntry {
            target_server_id: [1; 16],
            snapshot_token: [2; 32],
            page_sequence: 0,
            conversation_id: [6; 32],
            object_id,
            fragment,
        },
        CompanionFrame::StateEnd {
            target_server_id: [1; 16],
            snapshot_token: [2; 32],
            page_sequence: 0,
            next_cursor: Some([7; 32]),
        },
        CompanionFrame::StateEnd {
            target_server_id: [1; 16],
            snapshot_token: [2; 32],
            page_sequence: 1,
            next_cursor: None,
        },
        CompanionFrame::StateFetch {
            coordinator_server_id: [1; 16],
            snapshot_token: [2; 32],
            next_page_sequence: 1,
            cursor: [7; 32],
        },
        CompanionFrame::StateCut {
            active: false,
            server_id: [1; 16],
            snapshot_token: [2; 32],
            state_generation: 3,
            delivery_generation: 4,
            snapshot_digest: [5; 32],
        },
        CompanionFrame::StateCut {
            active: true,
            server_id: [1; 16],
            snapshot_token: [2; 32],
            state_generation: 3,
            delivery_generation: 4,
            snapshot_digest: [5; 32],
        },
    ])
}

#[test]
fn every_frame_renders_and_parses_back() -> TestResult {
    for frame in every_frame()? {
        let line = frame.render(PREFIX)?;
        let (tag, prefix, command, params) = split(&line)?;
        assert_eq!(prefix, PREFIX);
        assert!(is_companion_command(&command));
        assert_eq!(command, frame.command());
        assert_eq!(tag.is_some(), frame.carries_object(), "{command}");
        let params: Vec<&str> = params.iter().map(String::as_str).collect();
        let parsed = parse_companion_frame(&command, &params, tag.as_deref())?;
        assert_eq!(parsed, frame, "{command}");
        let non_tag = line.rsplit_once(" :").map_or(line.len(), |_| {
            line.len() - line.find(" :").unwrap_or(0) - 1
        });
        assert!(non_tag <= 512);
    }
    assert!(!is_companion_command("FREQUEST"));
    assert!(!is_companion_command("EGROUP"));
    Ok(())
}

#[test]
fn coordinator_and_home_frames_are_classified() -> TestResult {
    for frame in every_frame()? {
        let expected = matches!(
            frame,
            CompanionFrame::Result { .. }
                | CompanionFrame::Response { .. }
                | CompanionFrame::Event { .. }
                | CompanionFrame::Data { .. }
                | CompanionFrame::ResumeOk { .. }
                | CompanionFrame::OriginReady { .. }
                | CompanionFrame::OriginAck { .. }
                | CompanionFrame::StateBegin { .. }
                | CompanionFrame::StateEntry { .. }
                | CompanionFrame::StateEnd { .. }
                | CompanionFrame::StateCut { active: true, .. }
        );
        assert_eq!(frame.from_coordinator(), expected, "{}", frame.command());
    }
    Ok(())
}

#[test]
fn ecap_lines_fit_their_stated_maxima() -> TestResult {
    let widest = EcapTuple::local(
        &base64url_encode(&[1; 32]),
        &base64url_encode(&[2; 16]),
        u64::MAX,
        &base64url_encode(&[4; 32]),
    )?;
    let prefix = "p".repeat(126);
    let offer = CompanionFrame::EcapOffer(widest.clone()).render(&prefix)?;
    let ack = CompanionFrame::EcapAck(widest).render(&prefix)?;
    assert_eq!(offer.len(), 360);
    assert_eq!(ack.len(), 358);
    assert!(
        CompanionFrame::EcapAck(tuple()?)
            .render(&"p".repeat(127))
            .is_err()
    );
    assert!(CompanionFrame::EcapAck(tuple()?).render("").is_err());
    assert!(CompanionFrame::EcapAck(tuple()?).render("a b").is_err());
    Ok(())
}

#[test]
fn grammar_violations_are_refused() -> TestResult {
    let (fragment, object_id) = object()?;
    let raw = fragment.render();
    let id = base64url_encode(&object_id);
    let sid = base64url_encode(&[1; 16]);
    let good: Vec<&str> = vec![&sid, &sid, &sid, "4", "5", &sid, &id];
    assert!(parse_companion_frame("EREQUEST", &good, Some(&raw)).is_ok());
    assert_eq!(
        parse_companion_frame("EREQUEST", &good, None),
        Err(E2eeError::InvalidValue),
        "an object frame needs its tag"
    );
    let other = base64url_encode(&[9; 32]);
    let mismatched: Vec<&str> = vec![&sid, &sid, &sid, "4", "5", &sid, &other];
    assert_eq!(
        parse_companion_frame("EREQUEST", &mismatched, Some(&raw)),
        Err(E2eeError::ObjectIdMismatch)
    );
    let short: Vec<&str> = vec![&sid, &sid, &sid, "4", "5", &sid];
    assert!(parse_companion_frame("EREQUEST", &short, Some(&raw)).is_err());
    let long: Vec<&str> = vec![&sid, &sid, &sid, "4", "5", &sid, &id, "x"];
    assert!(parse_companion_frame("EREQUEST", &long, Some(&raw)).is_err());
    let ack: Vec<&str> = vec![&sid, "2", "3", &sid];
    assert!(parse_companion_frame("EACK", &ack, None).is_ok());
    assert_eq!(
        parse_companion_frame("EACK", &ack, Some(&raw)),
        Err(E2eeError::InvalidValue),
        "a tag on an untagged frame"
    );
    assert_eq!(
        parse_companion_frame("EACK", &[&sid, "02", "3", &sid], None),
        Err(E2eeError::NonCanonical)
    );
    assert_eq!(
        parse_companion_frame("FACK", &ack, None),
        Err(E2eeError::UnknownDiscriminant)
    );
    assert!(parse_companion_frame("ECAP", &["IRCMLS", "NAK"], None).is_err());
    assert!(parse_companion_frame("ERESUME", &[&sid, &sid, "3", "*", &sid], None).is_err());
    assert!(parse_companion_frame("ERESUME", &[&sid, &sid, "3", "9", "*"], None).is_err());
    assert!(parse_companion_frame("EORIGIN", &["PURGE", &sid, &sid], None).is_err());
    assert!(parse_companion_frame("ESTATE", &["UPDATE", &sid], None).is_err());
    assert!(
        parse_companion_frame("ESTATE", &["FETCH", &sid, &id, "1", "*"], None).is_err(),
        "FETCH needs a concrete cursor"
    );
    assert!(!PROFILE_MISMATCH_LINE.is_empty());
    Ok(())
}
