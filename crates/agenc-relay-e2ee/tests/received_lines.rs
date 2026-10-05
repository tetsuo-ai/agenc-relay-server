#![forbid(unsafe_code)]

//! X-06: the companion Section 11.7 productions and the Section 11.9 `FAIL`
//! line read back as a client receives them, `parse(render(x))` for every
//! form, and an object batch charged to its class and batch bounds.

use std::collections::BTreeSet;
use std::error::Error;

use agenc_relay_e2ee::E2eeError;
use agenc_relay_e2ee::limits::{
    MAX_BATCH_DECODED_BYTES, MAX_BATCH_FRAGMENTS, MAX_BATCH_OBJECTS, MAX_FRAGMENT_RAW,
};
use agenc_relay_e2ee::object::{ArcWireObjectKind, ObjectId};
use agenc_relay_e2ee::wire::fragment::{FragmentTag, ReceiptTag, fragment_object};
use agenc_relay_e2ee::wire::received::{
    AckNotice, FailLine, FragmentCharge, LiveFrame, ObjectFragment, Received, ReceivedLine,
    ResponseBatch, parse_received_line,
};
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;
use agenc_relay_e2ee::wire::response::{
    BatchChild, BatchOpener, EmptyGroupKind, LiveLine, LiveTags, PendingKind, StoreKind,
    SuccessLine, render_ack_notice, render_broadcast, render_eobject, render_fail, render_labeled,
    render_labeled_fail, render_live,
};
use agenc_relay_e2ee::wire::tokens::base64url_encode;

type TestResult = Result<(), Box<dyn Error>>;

const SERVER: &str = "irc.example.test";
const USER: &str = "alice!u-abcdefgh23@h-ijklmnopqrstuv67.invalid";

/// A rendered line without its CRLF, as a client's framer yields it.
fn line(rendered: &str) -> Result<&str, Box<dyn Error>> {
    Ok(rendered.strip_suffix("\r\n").ok_or("no CRLF")?)
}

fn read(rendered: &str) -> Result<Received, Box<dyn Error>> {
    Ok(parse_received_line(line(rendered)?)?)
}

fn refused(text: &str) -> Result<E2eeError, Box<dyn Error>> {
    match parse_received_line(text) {
        Ok(received) => Err(format!("accepted {text:?} as {received:?}").into()),
        Err(error) => Ok(error),
    }
}

fn h(fill: u8) -> String {
    base64url_encode(&[fill; 32])
}

/// Every result form of companion 11.7, the four ReInit results among them.
fn every_success() -> Vec<SuccessLine> {
    let mut lines = vec![
        SuccessLine::Bound([1; 32], [2; 32]),
        SuccessLine::Closed([1; 32], [2; 32]),
        SuccessLine::StoredAuthorization([1; 32], [2; 32], [3; 32]),
        SuccessLine::StoredPolicy([1; 32], [2; 32], [3; 32]),
        SuccessLine::StoredMembership([1; 32], [2; 32], [3; 32]),
        SuccessLine::RecoveryAccepted([1; 32], [2; 32]),
        SuccessLine::RecoveryExtended([1; 32], u64::MAX, [3; 32]),
        SuccessLine::RecoveryClosed([1; 32], [2; 32]),
        SuccessLine::RecoveryConflict([1; 32], 0, [3; 32], [4; 32]),
        SuccessLine::Acked([1; 32], [2; 32], [3; 32]),
        SuccessLine::Finalized([1; 32], 7, [3; 32], [4; 32]),
        SuccessLine::Aborted([1; 32], [2; 32], [3; 32], [4; 32]),
        SuccessLine::ReinitStaged([1; 32], [2; 32], [3; 32]),
        SuccessLine::ReinitAcked([1; 32], [2; 32], [3; 32]),
        SuccessLine::ReinitActivated([1; 32], [2; 32], [3; 32], [4; 32]),
        SuccessLine::ReinitAborted([1; 32], [2; 32], [3; 32], [4; 32]),
        SuccessLine::Account([5; 24], 3),
        SuccessLine::Attached([6; 16], 4),
        SuccessLine::Revoked(vec![7; 32]),
        SuccessLine::Revoked(vec![7; 255]),
        SuccessLine::MailboxAcked([8; 32], [9; 32]),
    ];
    lines.extend(
        PendingKind::ALL
            .into_iter()
            .map(|kind| SuccessLine::Pending([1; 32], kind, [3; 32])),
    );
    lines.extend(EmptyGroupKind::ALL.into_iter().map(SuccessLine::EmptyGroup));
    lines.extend(StoreKind::ALL.into_iter().map(SuccessLine::EmptyKey));
    lines.extend(
        StoreKind::ALL
            .into_iter()
            .filter(|kind| kind.storable())
            .map(|kind| SuccessLine::Stored(kind, [9; 32])),
    );
    lines
}

/// The variant name of a result form. The match has no wildcard arm, so a
/// new `SuccessLine` variant does not compile until it is named here, and
/// `every_success_holds_every_declared_result_form` then fails until
/// `every_success` holds a line of it.
fn form_name(success: &SuccessLine) -> &'static str {
    match success {
        SuccessLine::Bound(..) => "Bound",
        SuccessLine::Closed(..) => "Closed",
        SuccessLine::StoredAuthorization(..) => "StoredAuthorization",
        SuccessLine::StoredPolicy(..) => "StoredPolicy",
        SuccessLine::StoredMembership(..) => "StoredMembership",
        SuccessLine::RecoveryAccepted(..) => "RecoveryAccepted",
        SuccessLine::RecoveryExtended(..) => "RecoveryExtended",
        SuccessLine::RecoveryClosed(..) => "RecoveryClosed",
        SuccessLine::RecoveryConflict(..) => "RecoveryConflict",
        SuccessLine::Acked(..) => "Acked",
        SuccessLine::Pending(..) => "Pending",
        SuccessLine::Finalized(..) => "Finalized",
        SuccessLine::Aborted(..) => "Aborted",
        SuccessLine::ReinitStaged(..) => "ReinitStaged",
        SuccessLine::ReinitAcked(..) => "ReinitAcked",
        SuccessLine::ReinitActivated(..) => "ReinitActivated",
        SuccessLine::ReinitAborted(..) => "ReinitAborted",
        SuccessLine::EmptyGroup(..) => "EmptyGroup",
        SuccessLine::Account(..) => "Account",
        SuccessLine::Attached(..) => "Attached",
        SuccessLine::Stored(..) => "Stored",
        SuccessLine::Revoked(..) => "Revoked",
        SuccessLine::MailboxAcked(..) => "MailboxAcked",
        SuccessLine::EmptyKey(..) => "EmptyKey",
    }
}

/// The variants `SuccessLine` declares, read from its definition.
fn declared_forms() -> Result<BTreeSet<&'static str>, Box<dyn Error>> {
    const SOURCE: &str = include_str!("../src/wire/response.rs");
    let start = SOURCE
        .find("pub enum SuccessLine {")
        .ok_or("no SuccessLine")?;
    let body = SOURCE.get(start..).ok_or("no SuccessLine body")?;
    let end = body.find("\n}\n").ok_or("no end of SuccessLine")?;
    let mut forms = BTreeSet::new();
    for line in body
        .get(..end)
        .ok_or("no SuccessLine body")?
        .lines()
        .skip(1)
    {
        let line = line.trim();
        if line.is_empty() || line.starts_with("///") {
            continue;
        }
        let name = line
            .split(|character: char| !character.is_ascii_alphanumeric())
            .next()
            .ok_or("no variant name")?;
        forms.insert(name);
    }
    Ok(forms)
}

#[test]
fn every_success_holds_every_declared_result_form() -> TestResult {
    let named: BTreeSet<&str> = every_success().iter().map(form_name).collect();
    assert_eq!(named, declared_forms()?);
    Ok(())
}

#[test]
fn every_result_form_reads_back_labeled_and_from_its_body() -> TestResult {
    let lines = every_success();
    assert_eq!(lines.len(), 21 + 5 + 4 + 10 + 8);
    for success in lines {
        let received = read(&render_labeled("req-1_a", SERVER, &success)?)?;
        assert_eq!(received.source, SERVER);
        assert_eq!(
            received.line,
            ReceivedLine::Labeled {
                label: "req-1_a".to_owned(),
                success: success.clone(),
            }
        );
        assert_eq!(SuccessLine::parse_body(&success.body()?)?, success);
    }
    Ok(())
}

#[test]
fn only_the_six_state_broadcasts_read_back_untagged() -> TestResult {
    let mut broadcasts = 0_usize;
    for success in every_success() {
        let untagged = format!(":{SERVER} {}", success.body()?);
        if success.is_broadcast() {
            broadcasts += 1;
            let received = read(&render_broadcast(SERVER, &success)?)?;
            assert_eq!(received.line, ReceivedLine::Broadcast(success));
            assert!(parse_received_line(&untagged).is_ok());
        } else {
            assert_eq!(refused(&untagged)?, E2eeError::InvalidValue, "{untagged}");
        }
    }
    assert_eq!(broadcasts, 6);
    Ok(())
}

fn opener(command: &'static str, cursor: Option<[u8; 32]>) -> BatchOpener {
    BatchOpener {
        label: "req-2".to_owned(),
        batch_id: "b-1".to_owned(),
        request_command: command,
        object_kind: ArcWireObjectKind::WelcomeMls,
        scope: [4; 16],
        snapshot: [5; 32],
        next_cursor: cursor,
    }
}

#[test]
fn batch_lines_read_back_from_every_renderer() -> TestResult {
    for opener in [opener("EGROUP", None), opener("EKEY", Some([6; 32]))] {
        let received = read(&opener.render(SERVER)?)?;
        assert_eq!(received.line, ReceivedLine::BatchOpen(opener.clone()));
        assert_eq!(
            read(&opener.render_close(SERVER)?)?.line,
            ReceivedLine::BatchClose {
                batch_id: "b-1".to_owned()
            }
        );
    }
    // The runtime opens an unlabeled request's batch under `-`.
    let unlabeled = BatchOpener {
        label: "-".to_owned(),
        ..opener("EKEY", None)
    };
    assert_eq!(
        read(&unlabeled.render(SERVER)?)?.line,
        ReceivedLine::BatchOpen(unlabeled.clone())
    );
    let children = [
        BatchChild::Reserved([1; 16], [2; 32]),
        BatchChild::Bound([1; 32], [2; 32], [3; 32]),
        BatchChild::Candidate([1; 32], [2; 32], [3; 32]),
        BatchChild::Finalized([1; 32], u64::MAX, [3; 32], [4; 32]),
        BatchChild::Aborted([1; 32], [2; 32], [3; 32], [4; 32]),
        BatchChild::AttachChallenge([1; 16], [2; 32]),
        BatchChild::Claimed([1; 16], vec![3; 48], [4; 32]),
        BatchChild::Mailbox([1; 32], [2; 16], [3; 32]),
    ];
    for child in children {
        let received = read(&child.render(SERVER, "b-1")?)?;
        assert_eq!(
            received.line,
            ReceivedLine::BatchChild {
                batch_id: "b-1".to_owned(),
                child
            }
        );
    }
    let object = vec![0x5a; MAX_FRAGMENT_RAW + 100];
    for fragment in fragment_object(&object)? {
        let rendered = render_eobject(
            SERVER,
            "b-1",
            &fragment,
            ArcWireObjectKind::WelcomeMls,
            &[4; 16],
        )?;
        let received = read(&rendered)?;
        assert_eq!(
            received.line,
            ReceivedLine::Object(ObjectFragment {
                batch_id: "b-1".to_owned(),
                kind: ArcWireObjectKind::WelcomeMls,
                scope: [4; 16],
                fragment,
            })
        );
    }
    Ok(())
}

fn fragment_of(part: u32) -> Result<FragmentTag, Box<dyn Error>> {
    let object = vec![0x33; MAX_FRAGMENT_RAW * 2];
    fragment_object(&object)?
        .into_iter()
        .find(|fragment| fragment.part == part)
        .ok_or_else(|| "no such fragment".into())
}

#[test]
fn live_frames_read_back_with_their_tag_rules() -> TestResult {
    let receipt = ReceiptTag {
        candidate_id: [3; 32],
        receipt: vec![4; 40],
    };
    let zero = fragment_of(0)?;
    let later = fragment_of(1)?;
    let channel = LiveLine::Tagmsg(b"#Garden".to_vec());
    let direct = LiveLine::Edirect([1; 32]);
    let candidate = LiveLine::Candidate([1; 32], [2; 32], [3; 32]);
    let cases = [
        (Some("req-3"), Some("heron"), None, &zero, &channel),
        (None, Some("heron"), None, &later, &channel),
        (Some("req-3"), None, None, &zero, &direct),
        (None, None, None, &later, &direct),
        (
            Some("req-3"),
            Some("heron"),
            Some(&receipt),
            &zero,
            &candidate,
        ),
        (None, Some("heron"), Some(&receipt), &zero, &candidate),
        (None, Some("heron"), None, &later, &candidate),
    ];
    for (label, account, receipt, fragment, live) in cases {
        let tags = LiveTags {
            label,
            account,
            receipt,
        };
        let received = read(&render_live(USER, &tags, fragment, live)?)?;
        assert_eq!(received.source, USER);
        assert_eq!(
            received.line,
            ReceivedLine::Live(LiveFrame {
                label: label.map(str::to_owned),
                account: account.map(str::to_owned),
                receipt: receipt.cloned(),
                fragment: fragment.clone(),
                line: live.clone(),
            })
        );
    }
    let fragment = |tag: &FragmentTag| tag.render();
    for (tags, body, why) in [
        (
            format!("label=req-3;+agenc.ag/e2ee={}", fragment(&later)),
            "TAGMSG #garden".to_owned(),
            "a label on a later fragment",
        ),
        (
            format!("+agenc.ag/e2ee={}", fragment(&zero)),
            format!("EGROUP CANDIDATE {} {} {}", h(1), h(2), h(3)),
            "a candidate's fragment zero without its receipt",
        ),
        (
            format!(
                "agenc.ag/e2ee-receipt={};+agenc.ag/e2ee={}",
                receipt.render(),
                fragment(&later)
            ),
            format!("EGROUP CANDIDATE {} {} {}", h(1), h(2), h(3)),
            "a receipt on a later fragment",
        ),
        (
            format!(
                "agenc.ag/e2ee-receipt={};+agenc.ag/e2ee={}",
                receipt.render(),
                fragment(&zero)
            ),
            "TAGMSG #garden".to_owned(),
            "a receipt on a channel frame",
        ),
        (
            format!("msgid=x;+agenc.ag/e2ee={}", fragment(&zero)),
            "TAGMSG #garden".to_owned(),
            "a tag the production does not carry",
        ),
        (
            format!("+agenc.ag/e2ee={}", fragment(&zero)),
            "TAGMSG &local".to_owned(),
            "a channel outside the encrypted channel profile",
        ),
        (
            format!("label=req_\\s;+agenc.ag/e2ee={}", fragment(&zero)),
            "TAGMSG #garden".to_owned(),
            "an escaped label",
        ),
    ] {
        assert!(
            parse_received_line(&format!("@{tags} :{USER} {body}")).is_err(),
            "{why}"
        );
    }
    // No tag twice. The live production asks only whether a tag is present,
    // so the tag split's own rule is what refuses a repeated one.
    for (tags, why) in [
        (
            format!(
                "account=heron;account=heron;+agenc.ag/e2ee={}",
                fragment(&zero)
            ),
            "a repeated account",
        ),
        (
            format!("label=req-3;label=req-4;+agenc.ag/e2ee={}", fragment(&zero)),
            "a repeated label",
        ),
        (
            format!("+agenc.ag/e2ee={0};+agenc.ag/e2ee={0}", fragment(&zero)),
            "a repeated fragment tag",
        ),
    ] {
        assert_eq!(
            refused(&format!("@{tags} :{USER} TAGMSG #garden"))?,
            E2eeError::InvalidValue,
            "{why}"
        );
    }
    Ok(())
}

#[test]
fn the_tag_split_holds_four_fields_and_refuses_a_fifth() -> TestResult {
    let receipt = ReceiptTag {
        candidate_id: [3; 32],
        receipt: vec![4; 40],
    };
    let tags = LiveTags {
        label: Some("req-3"),
        account: Some("heron"),
        receipt: Some(&receipt),
    };
    let candidate = LiveLine::Candidate([1; 32], [2; 32], [3; 32]);
    let rendered = render_live(USER, &tags, &fragment_of(0)?, &candidate)?;
    // Four fields, the most a production carries: a live candidate frame.
    let four = line(&rendered)?;
    let tagged = four.strip_prefix('@').ok_or("no tags")?;
    let (section, _) = tagged.split_once(' ').ok_or("no tag section")?;
    assert_eq!(section.split(';').count(), 4);
    assert!(matches!(
        parse_received_line(four)?.line,
        ReceivedLine::Live(_)
    ));
    // A fifth field is refused for the count, before the production would
    // refuse the tag it does not carry.
    assert_eq!(
        refused(&format!("@msgid=x;{tagged}"))?,
        E2eeError::LimitExceeded
    );
    // So is any longer section, whatever its fields.
    let long = vec!["a=1"; 2_048].join(";");
    let bound = format!("EGROUP BOUND {} {}", h(1), h(2));
    assert_eq!(
        refused(&format!("@{long} :{SERVER} {bound}"))?,
        E2eeError::LimitExceeded
    );
    // Four fields outside every production's tag set are refused by the
    // productions.
    assert_eq!(
        refused(&format!("@a=1;b=2;c=3;d=4 :{SERVER} {bound}"))?,
        E2eeError::InvalidValue
    );
    Ok(())
}

#[test]
fn ack_notices_read_back_with_their_distinct_literals() -> TestResult {
    for reinit in [false, true] {
        let received = read(&render_ack_notice(
            USER, reinit, &[1; 32], &[2; 32], &[3; 32],
        )?)?;
        assert_eq!(
            received.line,
            ReceivedLine::AckNotice(AckNotice {
                reinit,
                conversation_id: [1; 32],
                selector: [2; 32],
                ack_object_id: [3; 32],
            })
        );
    }
    Ok(())
}

#[test]
fn fail_lines_read_back_for_every_code() -> TestResult {
    for code in E2eeReplyCode::ALL {
        for (command, context) in [("EGROUP", Some(h(1))), ("*", None), ("PRIVMSG", None)] {
            let body = code.render_fail(command, context.as_deref());
            let expected = FailLine {
                label: None,
                command: command.to_owned(),
                code,
                context: context.clone(),
                description: code.description().to_owned(),
            };
            let received = read(&render_fail(SERVER, &body)?)?;
            assert_eq!(received.line, ReceivedLine::Fail(expected.clone()));
            let labeled = read(&render_labeled_fail("req-4", SERVER, &body)?)?;
            assert_eq!(
                labeled.line,
                ReceivedLine::Fail(FailLine {
                    label: Some("req-4".to_owned()),
                    ..expected
                })
            );
        }
    }
    for (line, error) in [
        (
            format!(":{SERVER} FAIL EGROUP E2EE_MADE_UP :x"),
            E2eeError::UnknownDiscriminant,
        ),
        (
            format!(":{SERVER} FAIL egroup E2EE_SYNCING :x"),
            E2eeError::InvalidValue,
        ),
        (
            format!(":{SERVER} FAIL EGROUP E2EE_SYNCING a b :x"),
            E2eeError::InvalidValue,
        ),
        (
            format!(":{SERVER} FAIL EGROUP E2EE_SYNCING"),
            E2eeError::InvalidValue,
        ),
        (
            format!("@batch=b-1 :{SERVER} FAIL EGROUP E2EE_SYNCING :x"),
            E2eeError::InvalidValue,
        ),
    ] {
        assert_eq!(refused(&line)?, error, "{line}");
    }
    Ok(())
}

#[test]
fn tags_may_come_in_the_order_the_base_renderer_sorts_them() -> TestResult {
    let fragment = fragment_of(1)?;
    let sorted = format!(
        "@agenc.ag/e2ee={};batch=b-1 :{SERVER} EOBJECT WELCOME {} {}",
        fragment.render(),
        base64url_encode(&[4; 16]),
        base64url_encode(fragment.object_id.as_bytes())
    );
    let ReceivedLine::Object(object) = parse_received_line(&sorted)?.line else {
        return Err("not an object fragment".into());
    };
    assert_eq!(object.fragment, fragment);
    let zero = fragment_of(0)?;
    let receipt = ReceiptTag {
        candidate_id: [3; 32],
        receipt: vec![4; 40],
    };
    let live = format!(
        "@account=heron;agenc.ag/e2ee-receipt={};label=req-3;+agenc.ag/e2ee={} :{USER} EGROUP CANDIDATE {} {} {}",
        receipt.render(),
        zero.render(),
        h(1),
        h(2),
        h(3)
    );
    assert!(matches!(
        parse_received_line(&live)?.line,
        ReceivedLine::Live(_)
    ));
    Ok(())
}

#[test]
fn malformed_lines_are_refused() -> TestResult {
    let bound = format!("EGROUP BOUND {} {}", h(1), h(2));
    for (line, error) in [
        (
            format!("@label=a;label=b :{SERVER} {bound}"),
            E2eeError::InvalidValue,
        ),
        (format!("@label :{SERVER} {bound}"), E2eeError::InvalidValue),
        (
            format!("@label=a\\sb :{SERVER} {bound}"),
            E2eeError::InvalidValue,
        ),
        (
            format!("@label=a;msgid=x :{SERVER} {bound}"),
            E2eeError::InvalidValue,
        ),
        (
            format!("@label=a {SERVER} {bound}"),
            E2eeError::InvalidValue,
        ),
        (format!("@label=a :{SERVER}"), E2eeError::InvalidValue),
        (format!("@label=a : {bound}"), E2eeError::LimitExceeded),
        (
            format!("@label=a :{SERVER} EGROUP BOUND {}", h(1)),
            E2eeError::InvalidValue,
        ),
        (
            format!("@label=a :{SERVER} EGROUP BOUND {} {} {}", h(1), h(2), h(3)),
            E2eeError::InvalidValue,
        ),
        (
            format!("@label=a :{SERVER} EGROUP UNBOUND {} {}", h(1), h(2)),
            E2eeError::InvalidValue,
        ),
        (
            format!("@label=a :{SERVER} EGROUP BOUND {} {}x", h(1), h(2)),
            E2eeError::LengthOutOfRange,
        ),
        (
            format!("@label=a :{SERVER} EGROUP PENDING {} REINIT {}", h(1), h(3)),
            E2eeError::UnknownDiscriminant,
        ),
        (
            format!("@label=a :{SERVER} EGROUP EMPTY RECORDS"),
            E2eeError::UnknownDiscriminant,
        ),
        (
            format!("@label=a :{SERVER} EKEY STORED ROOT-CHAIN {}", h(1)),
            E2eeError::UnknownDiscriminant,
        ),
        (
            format!("@label=a :{SERVER} EKEY STORED BINDING-LOCK {}", h(1)),
            E2eeError::UnknownDiscriminant,
        ),
        (
            format!(
                "@label=a :{SERVER} EGROUP FINALIZED {} 07 {} {}",
                h(1),
                h(2),
                h(3)
            ),
            E2eeError::NonCanonical,
        ),
        (
            format!("@label=a :{SERVER} EGROUP  BOUND {} {}", h(1), h(2)),
            E2eeError::InvalidValue,
        ),
        (
            format!(
                "@batch=b_1 :{SERVER} EGROUP RESERVED {} {}",
                base64url_encode(&[1; 16]),
                h(2)
            ),
            E2eeError::InvalidValue,
        ),
        (format!(":{SERVER} BATCH -b_1"), E2eeError::InvalidValue),
        (format!(":{SERVER} BATCH +b-1"), E2eeError::InvalidValue),
        (
            format!(":{SERVER} EGROUP NOTICE {} {} {}", h(1), h(2), h(3)),
            E2eeError::InvalidValue,
        ),
    ] {
        assert_eq!(refused(&line)?, error, "{line}");
    }
    // The EOBJECT line names the fragment's object.
    let fragment = fragment_of(0)?;
    let mismatch = format!(
        "@batch=b-1;agenc.ag/e2ee={} :{SERVER} EOBJECT WELCOME {} {}",
        fragment.render(),
        base64url_encode(&[4; 16]),
        h(9)
    );
    assert_eq!(refused(&mismatch)?, E2eeError::ObjectIdMismatch);
    let unknown_kind = format!(
        "@batch=b-1;agenc.ag/e2ee={} :{SERVER} EOBJECT FUTURE {} {}",
        fragment.render(),
        base64url_encode(&[4; 16]),
        base64url_encode(fragment.object_id.as_bytes())
    );
    assert!(parse_received_line(&unknown_kind).is_err());
    Ok(())
}

#[test]
fn the_non_tag_budget_holds_512_bytes_with_the_crlf() -> TestResult {
    let head = format!(":{SERVER} FAIL EGROUP E2EE_SYNCING :");
    let at = format!("{head}{}", "d".repeat(512 - 2 - head.len()));
    assert_eq!(at.len() + 2, 512);
    let body = at.strip_prefix(&format!(":{SERVER} ")).ok_or("no body")?;
    assert_eq!(render_fail(SERVER, body)?.len(), 512);
    assert!(parse_received_line(&format!("@label=a {at}")).is_ok());
    let over = format!("{at}d");
    assert_eq!(refused(&over)?, E2eeError::LimitExceeded);
    assert!(render_fail(SERVER, &format!("{body}d")).is_err());
    Ok(())
}

fn welcome_opener() -> BatchOpener {
    opener("EKEY", None)
}

/// A fragment of an object of `total` bytes with only its declared shape:
/// the batch charge reads the declaration, not the segment.
fn declared(object: u8, part: u32, total: u32) -> ObjectFragment {
    let raw = u32::try_from(MAX_FRAGMENT_RAW).unwrap_or(u32::MAX);
    ObjectFragment {
        batch_id: "b-1".to_owned(),
        kind: ArcWireObjectKind::WelcomeMls,
        scope: [4; 16],
        fragment: FragmentTag {
            object_id: ObjectId::from_bytes([object; 32]),
            part,
            count: total.div_ceil(raw),
            total,
            segment: Vec::new(),
        },
    }
}

#[test]
fn a_mailbox_batch_charges_each_object_once_in_any_fragment_order() -> TestResult {
    let mut batch = ResponseBatch::open(welcome_opener());
    let first = declared(1, 0, 6_000);
    batch.child("b-1", &BatchChild::Mailbox([7; 32], [8; 16], [1; 32]))?;
    assert_eq!(
        batch.charge(&declared(1, 2, 6_000))?,
        FragmentCharge::NewObject
    );
    assert_eq!(batch.charge(&first)?, FragmentCharge::KnownObject);
    assert_eq!(
        batch.charge(&declared(1, 1, 6_000))?,
        FragmentCharge::KnownObject
    );
    batch.child("b-1", &BatchChild::Mailbox([7; 32], [8; 16], [2; 32]))?;
    assert_eq!(
        batch.charge(&declared(2, 0, 10))?,
        FragmentCharge::NewObject
    );
    assert_eq!(batch.object_count(), 2);
    assert_eq!(batch.fragment_count(), 4);
    assert_eq!(batch.decoded_bytes(), 6_010);
    assert_eq!(batch.opener().batch_id, "b-1");
    batch.close("b-1")?;
    assert_eq!(batch.close("b-2"), Err(E2eeError::InvalidValue));
    Ok(())
}

#[test]
fn a_batch_keeps_its_object_fragment_and_byte_bounds() -> TestResult {
    let raw = u32::try_from(MAX_FRAGMENT_RAW)?;
    // 32 objects fit; a 33rd does not.
    let mut objects = ResponseBatch::open(welcome_opener());
    for object in 0..u8::try_from(MAX_BATCH_OBJECTS)? {
        objects.charge(&declared(object, 0, 1))?;
    }
    assert_eq!(
        objects.charge(&declared(200, 0, 1)),
        Err(E2eeError::LimitExceeded)
    );
    // 1,426 + 1 fragments fit; one more does not.
    let mut fragments = ResponseBatch::open(welcome_opener());
    fragments.charge(&declared(1, 0, raw * 1_426))?;
    fragments.charge(&declared(2, 0, 1))?;
    assert_eq!(fragments.fragment_count(), MAX_BATCH_FRAGMENTS);
    assert_eq!(
        fragments.charge(&declared(3, 0, 1)),
        Err(E2eeError::LimitExceeded)
    );
    // 4,194,304 declared bytes fit within 1,427 fragments; one more does not.
    let rest = u32::try_from(MAX_BATCH_DECODED_BYTES)? - raw * 1_426;
    let mut bytes = ResponseBatch::open(welcome_opener());
    bytes.charge(&declared(1, 0, raw * 1_426))?;
    bytes.charge(&declared(2, 0, rest))?;
    assert_eq!(bytes.decoded_bytes(), MAX_BATCH_DECODED_BYTES);
    let mut over = ResponseBatch::open(welcome_opener());
    over.charge(&declared(1, 0, raw * 1_426))?;
    assert_eq!(
        over.charge(&declared(2, 0, rest + 1)),
        Err(E2eeError::LimitExceeded)
    );
    // The class: an application object over its kind's maximum.
    let application = BatchOpener {
        object_kind: ArcWireObjectKind::ApplicationMls,
        ..welcome_opener()
    };
    let mut class = ResponseBatch::open(application);
    let largest = u32::try_from(ArcWireObjectKind::ApplicationMls.maximum_object_bytes())?;
    let mut fragment = declared(1, 0, largest);
    fragment.kind = ArcWireObjectKind::ApplicationMls;
    class.charge(&fragment)?;
    let mut fragment = declared(2, 0, largest + 1);
    fragment.kind = ArcWireObjectKind::ApplicationMls;
    assert_eq!(class.charge(&fragment), Err(E2eeError::LimitExceeded));
    Ok(())
}

#[test]
fn a_batch_keeps_its_opener_and_production_order() -> TestResult {
    let open = || ResponseBatch::open(welcome_opener());
    let mut batch = open();
    let mut other_batch = declared(1, 0, 10);
    other_batch.batch_id = "b-2".to_owned();
    assert_eq!(batch.charge(&other_batch), Err(E2eeError::InvalidValue));
    let mut other_kind = declared(1, 0, 10);
    other_kind.kind = ArcWireObjectKind::ApplicationMls;
    assert_eq!(batch.charge(&other_kind), Err(E2eeError::WrongKind));
    let mut other_scope = declared(1, 0, 10);
    other_scope.scope = [9; 16];
    assert_eq!(batch.charge(&other_scope), Err(E2eeError::InvalidValue));
    batch.charge(&declared(1, 0, 6_000))?;
    assert_eq!(
        batch.charge(&declared(1, 1, 6_001)),
        Err(E2eeError::InvalidValue),
        "a later fragment changed the declared size"
    );
    // One operation-result child, before the first object.
    let result = BatchChild::Reserved([1; 16], [2; 32]);
    let mut children = open();
    assert_eq!(children.child("b-2", &result), Err(E2eeError::InvalidValue));
    children.child("b-1", &result)?;
    assert_eq!(children.child("b-1", &result), Err(E2eeError::InvalidValue));
    let mut late = open();
    late.charge(&declared(1, 0, 10))?;
    assert_eq!(late.child("b-1", &result), Err(E2eeError::InvalidValue));
    // Mailbox children: each names the next object, and a fetch is all one
    // kind or the other.
    let mailbox = |object: u8| BatchChild::Mailbox([7; 32], [8; 16], [object; 32]);
    let mut wrong_object = open();
    wrong_object.child("b-1", &mailbox(2))?;
    assert_eq!(
        wrong_object.charge(&declared(1, 0, 10)),
        Err(E2eeError::InvalidValue)
    );
    let mut twice = open();
    twice.child("b-1", &mailbox(1))?;
    assert_eq!(
        twice.child("b-1", &mailbox(1)),
        Err(E2eeError::InvalidValue)
    );
    let mut mixed = open();
    mixed.child("b-1", &mailbox(1))?;
    mixed.charge(&declared(1, 0, 10))?;
    assert_eq!(
        mixed.charge(&declared(2, 0, 10)),
        Err(E2eeError::InvalidValue)
    );
    let mut ordinary = open();
    ordinary.charge(&declared(1, 0, 10))?;
    assert_eq!(
        ordinary.child("b-1", &mailbox(2)),
        Err(E2eeError::InvalidValue)
    );
    // The close: at least one object, and no mailbox child left unpaired.
    assert_eq!(open().close("b-1"), Err(E2eeError::InvalidValue));
    let mut dangling = open();
    dangling.child("b-1", &mailbox(1))?;
    dangling.charge(&declared(1, 0, 10))?;
    dangling.child("b-1", &mailbox(2))?;
    assert_eq!(dangling.close("b-1"), Err(E2eeError::InvalidValue));
    assert_eq!(
        dangling.charge(&declared(1, 0, 10)),
        Err(E2eeError::InvalidValue),
        "a mailbox child must precede a new object"
    );
    Ok(())
}

/// Replacing any one body token of any production with a token no position
/// takes refuses the line: every token of every production is checked.
#[test]
fn every_token_of_every_production_is_checked() -> TestResult {
    let mut rendered = Vec::new();
    for success in every_success() {
        rendered.push(render_labeled("req-1", SERVER, &success)?);
    }
    for child in [
        BatchChild::Reserved([1; 16], [2; 32]),
        BatchChild::Bound([1; 32], [2; 32], [3; 32]),
        BatchChild::Candidate([1; 32], [2; 32], [3; 32]),
        BatchChild::Finalized([1; 32], 4, [3; 32], [4; 32]),
        BatchChild::Aborted([1; 32], [2; 32], [3; 32], [4; 32]),
        BatchChild::AttachChallenge([1; 16], [2; 32]),
        BatchChild::Claimed([1; 16], vec![3; 48], [4; 32]),
        BatchChild::Mailbox([1; 32], [2; 16], [3; 32]),
    ] {
        rendered.push(child.render(SERVER, "b-1")?);
    }
    rendered.push(opener("EKEY", Some([6; 32])).render(SERVER)?);
    rendered.push(opener("EGROUP", None).render_close(SERVER)?);
    for reinit in [false, true] {
        rendered.push(render_ack_notice(
            SERVER, reinit, &[1; 32], &[2; 32], &[3; 32],
        )?);
    }
    let fragment = fragment_of(0)?;
    rendered.push(render_eobject(
        SERVER,
        "b-1",
        &fragment,
        ArcWireObjectKind::WelcomeMls,
        &[4; 16],
    )?);
    let tags = LiveTags {
        label: None,
        account: None,
        receipt: None,
    };
    for live in [
        LiveLine::Tagmsg(b"#garden".to_vec()),
        LiveLine::Edirect([1; 32]),
        LiveLine::Candidate([1; 32], [2; 32], [3; 32]),
    ] {
        rendered.push(render_live(USER, &tags, &fragment_of(1)?, &live)?);
    }
    let mut mutated = 0_usize;
    for rendered in &rendered {
        let text = line(rendered)?;
        assert!(parse_received_line(text).is_ok(), "{text}");
        let (head, body) = split_body(text)?;
        let words: Vec<&str> = body.split(' ').collect();
        for position in 0..words.len() {
            let mut changed = words.clone();
            if let Some(word) = changed.get_mut(position) {
                *word = "x";
            }
            let candidate = format!("{head}{}", changed.join(" "));
            assert!(parse_received_line(&candidate).is_err(), "{candidate}");
            mutated += 1;
        }
    }
    assert!(mutated > 250, "{mutated} mutations");
    Ok(())
}

/// Splits a line after its source into the head (tags and source, with the
/// space) and the body.
fn split_body(text: &str) -> Result<(&str, &str), Box<dyn Error>> {
    let source_start = if text.starts_with('@') {
        text.find(" :").ok_or("no source")? + 1
    } else {
        0
    };
    let body_start = text
        .get(source_start..)
        .and_then(|rest| rest.find(' '))
        .ok_or("no body")?
        + source_start
        + 1;
    Ok((
        text.get(..body_start).ok_or("head")?,
        text.get(body_start..).ok_or("body")?,
    ))
}

#[test]
fn tag_sets_and_frames_outside_a_production_are_refused() -> TestResult {
    let fragment = fragment_of(0)?.render();
    let object = format!(
        "EOBJECT WELCOME {} {}",
        base64url_encode(&[4; 16]),
        base64url_encode(fragment_of(0)?.object_id.as_bytes())
    );
    let reserved = format!("EGROUP RESERVED {} {}", base64url_encode(&[1; 16]), h(2));
    let finalized = format!("EGROUP FINALIZED {} 7 {} {}", h(1), h(2), h(3));
    for line in [
        "@label=req-1".to_owned(),
        format!("@=x :{SERVER} {finalized}"),
        format!("@label= :{SERVER} {finalized}"),
        format!("@msgid=x :{SERVER} {finalized}"),
        format!("@batch=b-1;label=req-1 :{SERVER} {reserved}"),
        format!("@agenc.ag/e2ee={fragment} :{SERVER} {object}"),
        format!("@agenc.ag/e2ee={fragment};batch=b-1;label=req-1 :{SERVER} {object}"),
        format!("@agenc.ag/e2ee={fragment};batch=b_1 :{SERVER} {object}"),
        format!("@agenc.ag/e2ee={fragment};batch=b-1 :{SERVER} {reserved}"),
        format!("@agenc.ag/e2ee=v2.{fragment};batch=b-1 :{SERVER} {object}"),
        format!("@+agenc.ag/e2ee=v2.{fragment} :{USER} TAGMSG #garden"),
        format!("@+agenc.ag/e2ee={fragment} :{USER} EDIRECT x"),
        format!(":{SERVER} FAIL EGROUP E2EE_SYNCING  :x"),
        format!(":{SERVER} FAIL  E2EE_SYNCING :x"),
        format!(":{SERVER} FAIL E2EE_SYNCING :x"),
        format!("@label=req_\\s :{SERVER} FAIL EGROUP E2EE_SYNCING :x"),
        format!(
            "@agenc.ag/e2ee-receipt=v2.x;+agenc.ag/e2ee={fragment} :{USER} EGROUP CANDIDATE {} {} {}",
            h(1),
            h(2),
            h(3)
        ),
    ] {
        assert!(parse_received_line(&line).is_err(), "{line}");
    }
    Ok(())
}

#[test]
fn a_fragment_declaring_more_than_its_class_allows_is_not_charged() -> TestResult {
    let mut batch = ResponseBatch::open(welcome_opener());
    let mut fragment = declared(1, 0, 10);
    fragment.fragment.count = u32::try_from(MAX_BATCH_FRAGMENTS)? + 1;
    assert_eq!(batch.charge(&fragment), Err(E2eeError::LimitExceeded));
    assert_eq!(batch.object_count(), 0);
    Ok(())
}

#[test]
fn the_production_readers_check_what_their_lines_cannot_carry() -> TestResult {
    let body = opener("EKEY", None).render(SERVER)?;
    let body = line(&body)?
        .split_once(&format!(":{SERVER} "))
        .ok_or("no body")?
        .1
        .to_owned();
    assert!(BatchOpener::parse_body("req-2", &body).is_ok());
    assert_eq!(
        BatchOpener::parse_body("req 2", &body),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(
        BatchOpener::parse_body("req-2", &body.replace("+b-1", "+b_1")),
        Err(E2eeError::InvalidValue)
    );
    // A later fragment that changes the declared count alone.
    let mut batch = ResponseBatch::open(welcome_opener());
    batch.charge(&declared(1, 0, 6_000))?;
    let mut recount = declared(1, 1, 6_000);
    recount.fragment.count += 1;
    assert_eq!(batch.charge(&recount), Err(E2eeError::InvalidValue));
    Ok(())
}
