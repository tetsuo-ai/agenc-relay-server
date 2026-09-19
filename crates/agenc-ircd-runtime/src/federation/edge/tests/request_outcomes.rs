#![forbid(unsafe_code)]

//! The reply classifiers behind account deletion and carrier outcomes.

use agenc_ircd_client_wire::{FramedLine, WireMessage, parse_message};

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn parsed(line: &str) -> TestResult<ParsedMessage> {
    Ok(parse_message(FramedLine::new(line)?)?.ok_or("empty line")?)
}

fn reply(command: &str, middle: &[&str], trailing: Option<&str>) -> TestResult<WireMessage> {
    Ok(WireMessage::new("edge.example", command, middle, trailing)?)
}

#[test]
fn only_the_exact_confirmed_deletion_reply_counts_as_an_account_deletion() -> TestResult {
    let updated = || {
        reply(
            "NOTE",
            &["ACCT", "UPDATED"],
            Some("Account setting updated"),
        )
    };
    let other_note = reply("NOTE", &["ACCT", "UPDATED"], Some("Something else"))?;
    let failure = reply(
        "FAIL",
        &["ACCT", "UPDATED"],
        Some("Account setting updated"),
    )?;
    let cases: [(&str, Vec<WireMessage>, bool); 7] = [
        ("ACCT DELETE CONFIRM", vec![updated()?], true),
        ("ACCT delete confirm", vec![updated()?], true),
        ("WHO DELETE CONFIRM", vec![updated()?], false),
        ("ACCT DELETE", vec![updated()?], false),
        ("ACCT DELETE LATER", vec![updated()?], false),
        ("ACCT DELETE CONFIRM", vec![updated()?, updated()?], false),
        ("ACCT DELETE CONFIRM", vec![other_note], false),
    ];
    for (line, replies, deleted) in cases {
        assert_eq!(
            is_committed_account_deletion(&parsed(line)?, &replies),
            deleted,
            "{line}"
        );
    }
    assert!(!is_committed_account_deletion(
        &parsed("ACCT DELETE CONFIRM")?,
        &[failure]
    ));
    Ok(())
}

#[test]
fn carrier_outcomes_keep_only_their_own_payload_chunks() -> TestResult {
    let replies = [
        reply("AUTHENTICATE", &["c2FzbA"], None)?,
        reply("ACCTCREATE", &["DATA", "Y3JlYXRl"], None)?,
        reply("ACCTCREATE", &["DONE"], None)?,
        reply("ACCTCRED", &["DATA", "Y3JlZA"], None)?,
        reply("ACCTCRED", &["DONE"], None)?,
    ];
    let failed = || ResultArm::Failed {
        code: "NOT_ALLOWED".to_owned(),
        context: String::new(),
    };
    assert!(matches!(
        carrier_outcome(failed(), &replies, true),
        RemoteCarrierOutcome::Failed { chunks } if chunks == ["c2FzbA"]
    ));
    assert!(matches!(
        carrier_outcome(failed(), &replies, false),
        RemoteCarrierOutcome::Failed { chunks } if chunks == ["Y3JlYXRl"]
    ));
    assert!(matches!(
        credential_outcome(failed(), &replies),
        RemoteCarrierOutcome::Failed { chunks } if chunks == ["Y3JlZA"]
    ));
    let committed = ResultArm::Committed {
        resulting_state_generation: 4,
    };
    assert!(matches!(
        credential_outcome(committed, &replies),
        RemoteCarrierOutcome::CredentialChanged { chunks } if chunks == ["Y3JlZA"]
    ));
    Ok(())
}
