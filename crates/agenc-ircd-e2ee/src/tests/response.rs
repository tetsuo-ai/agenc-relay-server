#![forbid(unsafe_code)]

//! Response productions.

use std::error::Error;

use super::*;
use crate::wire::fragment::fragment_object;
use crate::wire::tokens::base64url_encode;

type TestResult = Result<(), Box<dyn Error>>;

const SERVER: &str = "irc.example.test";

fn h(fill: u8) -> String {
    base64url_encode(&[fill; 32])
}

#[test]
fn scalar_success_lines_render_exactly() -> TestResult {
    let bound = SuccessLine::Bound([1; 32], [2; 32]);
    assert_eq!(
        render_labeled("req-1", SERVER, &bound)?,
        format!("@label=req-1 :{SERVER} EGROUP BOUND {} {}\r\n", h(1), h(2))
    );
    assert_eq!(
        render_labeled(
            "x",
            SERVER,
            &SuccessLine::Pending([1; 32], PendingKind::ReinitAbort, [3; 32])
        )?,
        format!(
            "@label=x :{SERVER} EGROUP PENDING {} REINIT-ABORT {}\r\n",
            h(1),
            h(3)
        )
    );
    assert_eq!(
        render_labeled(
            "x",
            SERVER,
            &SuccessLine::Finalized([1; 32], 9, [2; 32], [3; 32])
        )?,
        format!(
            "@label=x :{SERVER} EGROUP FINALIZED {} 9 {} {}\r\n",
            h(1),
            h(2),
            h(3)
        )
    );
    assert_eq!(
        render_labeled(
            "x",
            SERVER,
            &SuccessLine::StoredAuthorization([1; 32], [2; 32], [3; 32])
        )?,
        format!(
            "@label=x :{SERVER} EGROUP STORED AUTHORIZATION {} {} {}\r\n",
            h(1),
            h(2),
            h(3)
        )
    );
    assert_eq!(
        render_labeled(
            "x",
            SERVER,
            &SuccessLine::EmptyGroup(EmptyGroupKind::Receipts)
        )?,
        format!("@label=x :{SERVER} EGROUP EMPTY RECEIPTS\r\n")
    );
    assert_eq!(
        render_labeled("x", SERVER, &SuccessLine::Account([b'a'; 24], 1))?,
        format!(
            "@label=x :{SERVER} EKEY ACCOUNT {} 1\r\n",
            base64url_encode(&[b'a'; 24])
        )
    );
    assert_eq!(
        render_labeled("x", SERVER, &SuccessLine::Attached([1; 16], 2))?,
        format!(
            "@label=x :{SERVER} EKEY ATTACHED {} 2\r\n",
            base64url_encode(&[1; 16])
        )
    );
    assert_eq!(
        render_labeled(
            "x",
            SERVER,
            &SuccessLine::Stored(StoreKind::StagedReinit, [4; 32])
        )?,
        format!("@label=x :{SERVER} EKEY STORED STAGED-REINIT {}\r\n", h(4))
    );
    assert_eq!(
        render_labeled("x", SERVER, &SuccessLine::Revoked(vec![5; 32]))?,
        format!("@label=x :{SERVER} EKEY REVOKED {}\r\n", h(5))
    );
    assert_eq!(
        render_labeled("x", SERVER, &SuccessLine::MailboxAcked([6; 32], [7; 32]))?,
        format!("@label=x :{SERVER} EKEY ACKED {} {}\r\n", h(6), h(7))
    );
    assert_eq!(
        render_labeled("x", SERVER, &SuccessLine::EmptyKey(StoreKind::BindingLock))?,
        format!("@label=x :{SERVER} EKEY EMPTY BINDING-LOCK\r\n")
    );
    let all = [
        SuccessLine::Closed([1; 32], [2; 32]),
        SuccessLine::Acked([1; 32], [2; 32], [3; 32]),
        SuccessLine::Aborted([1; 32], [2; 32], [3; 32], [4; 32]),
        SuccessLine::ReinitStaged([1; 32], [2; 32], [3; 32]),
        SuccessLine::ReinitAcked([1; 32], [2; 32], [3; 32]),
        SuccessLine::ReinitActivated([1; 32], [2; 32], [3; 32], [4; 32]),
        SuccessLine::ReinitAborted([1; 32], [2; 32], [3; 32], [4; 32]),
    ];
    for line in &all {
        let rendered = render_labeled("x", &"s".repeat(127), line)?;
        assert!(rendered.len() - "@label=x ".len() <= MAX_NON_TAG_LINE_BYTES);
    }
    assert_eq!(
        render_labeled(
            "x",
            SERVER,
            &SuccessLine::Stored(StoreKind::RootChain, [4; 32])
        ),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(
        render_labeled("bad label", SERVER, &bound),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(
        render_labeled("x", &"s".repeat(128), &bound),
        Err(E2eeError::LimitExceeded)
    );
    assert_eq!(
        render_labeled("x", "with space", &bound),
        Err(E2eeError::LimitExceeded)
    );
    Ok(())
}

#[test]
fn only_the_six_state_forms_broadcast() -> TestResult {
    let closed = SuccessLine::Closed([1; 32], [2; 32]);
    assert_eq!(
        render_broadcast(SERVER, &closed)?,
        format!(":{SERVER} EGROUP CLOSED {} {}\r\n", h(1), h(2))
    );
    assert!(SuccessLine::Finalized([1; 32], 0, [2; 32], [3; 32]).is_broadcast());
    assert!(SuccessLine::ReinitStaged([1; 32], [2; 32], [3; 32]).is_broadcast());
    assert!(!SuccessLine::Bound([1; 32], [2; 32]).is_broadcast());
    assert!(!SuccessLine::ReinitAcked([1; 32], [2; 32], [3; 32]).is_broadcast());
    assert_eq!(
        render_broadcast(SERVER, &SuccessLine::Bound([1; 32], [2; 32])),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(
        render_fail(SERVER, "FAIL EGROUP E2EE_ROUTE_INVALID :x")?,
        format!(":{SERVER} FAIL EGROUP E2EE_ROUTE_INVALID :x\r\n")
    );
    Ok(())
}

#[test]
fn batches_open_carry_children_and_objects_and_close() -> TestResult {
    let opener = BatchOpener {
        label: "req".to_owned(),
        batch_id: "b-1".to_owned(),
        request_command: "EKEY",
        object_kind: IrcWireObjectKind::WelcomeMls,
        scope: [1; 16],
        snapshot: [2; 32],
        next_cursor: None,
    };
    assert_eq!(
        opener.render(SERVER)?,
        format!(
            "@label=req :{SERVER} BATCH +b-1 agenc.ag/e2ee-objects EKEY WELCOME {} {} *\r\n",
            base64url_encode(&[1; 16]),
            h(2)
        )
    );
    assert_eq!(
        opener.render_close(SERVER)?,
        format!(":{SERVER} BATCH -b-1\r\n")
    );
    let child = BatchChild::Mailbox([3; 32], [4; 16], [5; 32]);
    assert_eq!(
        child.render(SERVER, "b-1")?,
        format!(
            "@batch=b-1 :{SERVER} EKEY MAILBOX {} {} {}\r\n",
            h(3),
            base64url_encode(&[4; 16]),
            h(5)
        )
    );
    let children = [
        BatchChild::Reserved([1; 16], [2; 32]),
        BatchChild::Bound([1; 32], [2; 32], [3; 32]),
        BatchChild::Candidate([1; 32], [2; 32], [3; 32]),
        BatchChild::Finalized([1; 32], 4, [2; 32], [3; 32]),
        BatchChild::Aborted([1; 32], [2; 32], [3; 32], [4; 32]),
        BatchChild::AttachChallenge([1; 16], [2; 32]),
        BatchChild::Claimed([1; 16], vec![9; 32], [2; 32]),
    ];
    for child in &children {
        let rendered = child.render(&"s".repeat(127), "b")?;
        assert!(
            rendered.len() - "@batch=b ".len() <= MAX_NON_TAG_LINE_BYTES,
            "{child:?}"
        );
    }
    assert_eq!(
        BatchChild::Claimed([1; 16], vec![9; 255], [2; 32]).render(SERVER, "b_1"),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(
        BatchChild::Claimed([1; 16], vec![9; 255], [2; 32]).render(&"s".repeat(127), "b"),
        Err(E2eeError::LimitExceeded),
        "a 255-byte reference cannot fit behind a maximal prefix; enabled suites use 32"
    );
    let fragments = fragment_object(&[7; 100])?;
    let fragment = fragments.first().ok_or("fragment")?;
    let line = render_eobject(
        SERVER,
        "b-1",
        fragment,
        IrcWireObjectKind::WelcomeMls,
        &[1; 16],
    )?;
    assert_eq!(
        line,
        format!(
            "@batch=b-1;agenc.ag/e2ee={} :{SERVER} EOBJECT WELCOME {} {}\r\n",
            fragment.render(),
            base64url_encode(&[1; 16]),
            base64url_encode(fragment.object_id.as_bytes())
        )
    );
    let mut bad = opener.clone();
    bad.request_command = "EDIRECT";
    assert_eq!(bad.render(SERVER), Err(E2eeError::InvalidValue));
    let mut bad = opener;
    bad.label = String::new();
    assert_eq!(bad.render(SERVER), Err(E2eeError::InvalidValue));
    Ok(())
}

#[test]
fn live_lines_order_server_tags_before_the_preserved_client_tag() -> TestResult {
    let fragments = fragment_object(&vec![7; 6_000])?;
    let zero = fragments.first().ok_or("fragment")?;
    let later = fragments.get(1).ok_or("fragment")?;
    let receipt = ReceiptTag {
        candidate_id: [8; 32],
        receipt: vec![1; 294],
    };
    let echo = render_live(
        "nick!user@host",
        &LiveTags {
            label: Some("req"),
            account: Some("alice"),
            receipt: Some(&receipt),
        },
        zero,
        &LiveLine::Candidate([1; 32], [2; 32], [8; 32]),
    )?;
    assert_eq!(
        echo,
        format!(
            "@label=req;account=alice;{RECEIPT_TAG}={};{CLIENT_FRAGMENT_TAG}={} :nick!user@host EGROUP CANDIDATE {} {} {}\r\n",
            receipt.render(),
            zero.render(),
            h(1),
            h(2),
            h(8)
        )
    );
    let tagmsg = render_live(
        "nick!user@host",
        &LiveTags {
            account: Some("alice"),
            ..LiveTags::default()
        },
        later,
        &LiveLine::Tagmsg(b"#room".to_vec()),
    )?;
    assert!(tagmsg.starts_with(&format!("@account=alice;{CLIENT_FRAGMENT_TAG}=")));
    assert!(tagmsg.ends_with(" :nick!user@host TAGMSG #room\r\n"));
    let direct = render_live(
        "nick!user@host",
        &LiveTags::default(),
        zero,
        &LiveLine::Edirect([1; 32]),
    )?;
    assert!(direct.ends_with(&format!(" :nick!user@host EDIRECT {}\r\n", h(1))));
    assert_eq!(
        render_live(
            "s",
            &LiveTags {
                label: Some("req"),
                ..LiveTags::default()
            },
            later,
            &LiveLine::Edirect([1; 32])
        ),
        Err(E2eeError::InvalidValue),
        "a label only on fragment zero"
    );
    assert_eq!(
        render_live(
            "s",
            &LiveTags::default(),
            zero,
            &LiveLine::Candidate([1; 32], [2; 32], [8; 32])
        ),
        Err(E2eeError::InvalidValue),
        "candidate fragment zero needs its receipt"
    );
    assert_eq!(
        render_live(
            "s",
            &LiveTags {
                receipt: Some(&receipt),
                ..LiveTags::default()
            },
            later,
            &LiveLine::Candidate([1; 32], [2; 32], [8; 32])
        ),
        Err(E2eeError::InvalidValue),
        "a later candidate fragment never carries a receipt"
    );
    assert_eq!(
        render_live(
            "s",
            &LiveTags {
                receipt: Some(&receipt),
                ..LiveTags::default()
            },
            zero,
            &LiveLine::Tagmsg(b"#room".to_vec())
        ),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(
        render_ack_notice("s", false, &[1; 32], &[2; 32], &[3; 32])?,
        format!(":s EGROUP ACK {} {} {}\r\n", h(1), h(2), h(3))
    );
    assert_eq!(
        render_ack_notice("s", true, &[1; 32], &[2; 32], &[3; 32])?,
        format!(":s EGROUP REINIT-ACK {} {} {}\r\n", h(1), h(2), h(3))
    );
    Ok(())
}
