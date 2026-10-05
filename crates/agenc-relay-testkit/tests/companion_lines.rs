#![forbid(unsafe_code)]

//! X-05 and X-06 together, as a client reads the daemon: every companion
//! line goes through `WireMessage::extension_line`, which sorts its tags,
//! before it is sent. Each such line frames as one server line, the E2EE
//! crate's reader reads it back to what was rendered, and the base decoder
//! accepts exactly the lines whose command is in the base registry.

use std::error::Error;

use agenc_relay_client_wire::{
    OutputBudget, RenderError, ServerFramedLine, ServerMessageError, ServerStreamFramer,
    WireMessage, parse_server_message,
};
use agenc_relay_e2ee::object::ArcWireObjectKind;
use agenc_relay_e2ee::wire::fragment::{ReceiptTag, fragment_object};
use agenc_relay_e2ee::wire::received::{ReceivedLine, ResponseBatch, parse_received_line};
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;
use agenc_relay_e2ee::wire::response::{
    BatchChild, BatchOpener, LiveLine, LiveTags, SuccessLine, render_eobject, render_fail,
    render_labeled, render_live,
};

type TestResult = Result<(), Box<dyn Error>>;

const SERVER: &str = "server.example";
const USER: &str = "alice!u-abcdefgh23@h-ijklmnopqrstuv67.invalid";

struct AnyBudget;

impl OutputBudget for AnyBudget {
    type Permit = ();

    fn try_reserve_exact(&mut self, _bytes: usize) -> Result<Self::Permit, RenderError> {
        Ok(())
    }
}

/// The bytes the daemon sends for one rendered companion line, framed back
/// into the one line a client reads.
fn as_sent(rendered: &str) -> Result<String, Box<dyn Error>> {
    let message = WireMessage::extension_line(rendered)?;
    let bytes = message
        .measure()?
        .encode(&mut AnyBudget)?
        .as_bytes()
        .to_vec();
    let mut framer = ServerStreamFramer::new()?;
    let mut lines = Vec::new();
    framer.feed(&bytes, |line| lines.push(line.as_str().to_owned()))?;
    framer.finish()?;
    match lines.as_slice() {
        [line] => Ok(line.clone()),
        _ => Err("not one line".into()),
    }
}

fn base_decode(line: &str) -> Result<Result<(), ServerMessageError>, Box<dyn Error>> {
    Ok(parse_server_message(ServerFramedLine::new(line)?).map(|_| ()))
}

#[test]
fn a_batch_as_sent_reads_back_and_charges_its_objects() -> TestResult {
    let opener = BatchOpener {
        label: "req-1".to_owned(),
        batch_id: "q-7".to_owned(),
        request_command: "EKEY",
        object_kind: ArcWireObjectKind::WelcomeMls,
        scope: [4; 16],
        snapshot: [5; 32],
        next_cursor: None,
    };
    let objects = [vec![0x11; 5_000], vec![0x22; 10]];
    let mut lines = vec![as_sent(&opener.render(SERVER)?)?];
    for (index, object) in objects.iter().enumerate() {
        let fill = u8::try_from(index)?;
        let mailbox = BatchChild::Mailbox(
            [fill; 32],
            [9; 16],
            *fragment_object(object)?
                .first()
                .ok_or("no fragment")?
                .object_id
                .as_bytes(),
        );
        lines.push(as_sent(&mailbox.render(SERVER, "q-7")?)?);
        for fragment in fragment_object(object)?.iter().rev() {
            let rendered = render_eobject(
                SERVER,
                "q-7",
                fragment,
                ArcWireObjectKind::WelcomeMls,
                &[4; 16],
            )?;
            lines.push(as_sent(&rendered)?);
        }
    }
    lines.push(as_sent(&opener.render_close(SERVER)?)?);

    let mut batch = None;
    for line in &lines {
        // BATCH is a base command; EGROUP, EKEY and EOBJECT are not.
        let expected = if line.contains(" BATCH ") {
            None
        } else {
            Some(ServerMessageError::UnregisteredCommand)
        };
        assert_eq!(base_decode(line)?.err(), expected, "{line}");
        match parse_received_line(line)?.line {
            ReceivedLine::BatchOpen(read) => {
                assert_eq!(read, opener);
                batch = Some(ResponseBatch::open(read));
            }
            ReceivedLine::BatchChild { batch_id, child } => {
                batch.as_mut().ok_or("no batch")?.child(&batch_id, &child)?;
            }
            ReceivedLine::Object(fragment) => {
                batch.as_mut().ok_or("no batch")?.charge(&fragment)?;
            }
            ReceivedLine::BatchClose { batch_id } => {
                batch.as_ref().ok_or("no batch")?.close(&batch_id)?;
            }
            other => return Err(format!("unexpected {other:?}").into()),
        }
    }
    let batch = batch.ok_or("no batch")?;
    assert_eq!(batch.object_count(), 2);
    assert_eq!(batch.fragment_count(), 3);
    assert_eq!(batch.decoded_bytes(), 5_010);
    // The tags of an object fragment were sorted on the way out.
    let object_line = lines
        .iter()
        .find(|line| line.contains("EOBJECT"))
        .ok_or("no EOBJECT")?;
    assert!(object_line.starts_with("@agenc.ag/e2ee="));
    Ok(())
}

#[test]
fn results_failures_and_live_frames_as_sent_read_back() -> TestResult {
    let success = SuccessLine::ReinitActivated([1; 32], [2; 32], [3; 32], [4; 32]);
    let line = as_sent(&render_labeled("req-2", SERVER, &success)?)?;
    assert_eq!(
        base_decode(&line)?,
        Err(ServerMessageError::UnregisteredCommand)
    );
    assert_eq!(
        parse_received_line(&line)?.line,
        ReceivedLine::Labeled {
            label: "req-2".to_owned(),
            success
        }
    );

    let body = E2eeReplyCode::RouteInvalid.render_fail("EGROUP", None);
    let line = as_sent(&render_fail(SERVER, &body)?)?;
    assert_eq!(
        base_decode(&line)?,
        Err(ServerMessageError::UnregisteredReplyCode)
    );
    assert!(matches!(
        parse_received_line(&line)?.line,
        ReceivedLine::Fail(fail) if fail.code == E2eeReplyCode::RouteInvalid
    ));
    // The two companion codes the base registry also holds pass both readers.
    let body = E2eeReplyCode::Syncing.render_fail("EGROUP", None);
    let line = as_sent(&render_fail(SERVER, &body)?)?;
    assert_eq!(base_decode(&line)?, Ok(()));
    assert!(parse_received_line(&line).is_ok());

    let fragment = fragment_object(&[0x44; 100])?
        .into_iter()
        .next()
        .ok_or("no fragment")?;
    let receipt = ReceiptTag {
        candidate_id: [3; 32],
        receipt: vec![6; 40],
    };
    let tags = LiveTags {
        label: Some("req-3"),
        account: Some("heron"),
        receipt: Some(&receipt),
    };
    let candidate = LiveLine::Candidate([1; 32], [2; 32], [3; 32]);
    let line = as_sent(&render_live(USER, &tags, &fragment, &candidate)?)?;
    assert!(line.starts_with("@account=heron;agenc.ag/e2ee-receipt="));
    assert_eq!(
        base_decode(&line)?,
        Err(ServerMessageError::UnregisteredCommand)
    );
    let ReceivedLine::Live(frame) = parse_received_line(&line)?.line else {
        return Err("not a live frame".into());
    };
    assert_eq!(frame.line, candidate);
    assert_eq!(frame.receipt, Some(receipt));

    let channel = LiveLine::Tagmsg(b"#garden".to_vec());
    let tags = LiveTags {
        label: None,
        account: Some("heron"),
        receipt: None,
    };
    let line = as_sent(&render_live(USER, &tags, &fragment, &channel)?)?;
    assert_eq!(base_decode(&line)?, Ok(()));
    assert!(matches!(
        parse_received_line(&line)?.line,
        ReceivedLine::Live(frame) if frame.line == channel
    ));
    Ok(())
}
