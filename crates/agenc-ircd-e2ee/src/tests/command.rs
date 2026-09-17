#![forbid(unsafe_code)]

//! Client command productions.

use std::error::Error;

use super::*;
use crate::wire::tokens::base64url_encode;

type TestResult = Result<(), Box<dyn Error>>;

fn id16() -> String {
    base64url_encode(&[1; 16])
}

fn hash(fill: u8) -> String {
    base64url_encode(&[fill; 32])
}

fn account() -> String {
    base64url_encode(&[b'a'; 24])
}

#[test]
fn every_egroup_production_parses_with_its_exact_arity() -> TestResult {
    use EgroupCommand::*;
    let h1 = hash(1);
    let h2 = hash(2);
    let account = account();
    let id16 = id16();
    let cases: Vec<(Vec<&str>, EgroupCommand)> = vec![
        (
            vec!["RESERVE", "CHANNEL", "#Room"],
            ReserveChannel(b"#room".to_vec()),
        ),
        (
            vec!["RESERVE", "DIRECT", &account],
            ReserveDirect([b'a'; 24]),
        ),
        (
            vec!["BIND", &id16, &h1, &h2],
            Bind {
                reservation_id: [1; 16],
                conversation_id: [1; 32],
                context_digest: [2; 32],
            },
        ),
        (
            vec!["QUERY", "CHANNEL", "#room"],
            QueryChannel(b"#room".to_vec()),
        ),
        (vec!["QUERY", "DIRECT", &account], QueryDirect([b'a'; 24])),
        (
            vec!["CLOSE", &h1, "7"],
            Close {
                conversation_id: [1; 32],
                reason_code: 7,
            },
        ),
        (
            vec!["FETCH", "OBJECT", &h1, &h2],
            FetchObject {
                conversation_id: [1; 32],
                object_id: [2; 32],
            },
        ),
        (
            vec!["FETCH", "AUTHORIZATIONS", &h1, &h2, "*"],
            FetchAuthorizations {
                conversation_id: [1; 32],
                candidate_id: [2; 32],
                cursor: None,
            },
        ),
        (
            vec!["FETCH", "ACKS", &h1, &h2, &h1],
            FetchAcks {
                conversation_id: [1; 32],
                selector: [2; 32],
                cursor: Some([1; 32]),
            },
        ),
        (
            vec!["FETCH", "RECEIPTS", &h1, "0", "*"],
            FetchReceipts {
                conversation_id: [1; 32],
                first_route_sequence: 0,
                cursor: None,
            },
        ),
    ];
    for (params, expected) in cases {
        assert_eq!(
            parse_command("EGROUP", &params)?,
            ClientCommand::Egroup(expected),
            "{params:?}"
        );
    }
    let submits = [
        (
            vec!["CANDIDATE"],
            SubmitKind::Candidate,
            CarrierCommand::SubmitCandidate,
        ),
        (
            vec!["AUTHORIZATION"],
            SubmitKind::Authorization,
            CarrierCommand::SubmitAuthorization,
        ),
        (vec!["ACK"], SubmitKind::Ack, CarrierCommand::SubmitAck),
        (
            vec!["FINALIZATION"],
            SubmitKind::Finalization,
            CarrierCommand::SubmitFinalization,
        ),
        (
            vec!["ABORT"],
            SubmitKind::Abort,
            CarrierCommand::SubmitAbort,
        ),
        (
            vec!["REINIT", "ATTEMPT"],
            SubmitKind::ReinitAttempt,
            CarrierCommand::SubmitReinitAttempt,
        ),
        (
            vec!["REINIT", "ACK"],
            SubmitKind::ReinitAck,
            CarrierCommand::SubmitReinitAck,
        ),
        (
            vec!["REINIT", "ACTIVATE"],
            SubmitKind::ReinitActivate,
            CarrierCommand::SubmitReinitActivate,
        ),
        (
            vec!["REINIT", "ABORT"],
            SubmitKind::ReinitAbort,
            CarrierCommand::SubmitReinitAbort,
        ),
        (
            vec!["POLICY"],
            SubmitKind::Policy,
            CarrierCommand::SubmitPolicy,
        ),
        (
            vec!["MEMBERSHIP"],
            SubmitKind::Membership,
            CarrierCommand::SubmitMembership,
        ),
        (
            vec!["RECOVERY"],
            SubmitKind::Recovery,
            CarrierCommand::SubmitRecovery,
        ),
    ];
    for (words, kind, carrier) in submits {
        let mut params = vec!["SUBMIT"];
        params.extend(words);
        params.push(&h1);
        let command = parse_command("EGROUP", &params)?;
        assert_eq!(
            command,
            ClientCommand::Egroup(Submit {
                kind,
                conversation_id: [1; 32]
            })
        );
        assert_eq!(command.carrier(), Some(carrier));
        assert_eq!(command.request_command(), "EGROUP");
    }
    let h2 = hash(2);
    let command = parse_command("EGROUP", &["SUBMIT", "RECOVERY-ELEMENT", &h1, &h2])?;
    assert_eq!(
        command,
        ClientCommand::Egroup(SubmitRecoveryElement {
            conversation_id: [1; 32],
            submission_id: [2; 32],
        })
    );
    assert_eq!(
        command.carrier(),
        Some(CarrierCommand::SubmitRecoveryElement)
    );
    assert!(parse_command("EGROUP", &["SUBMIT", "RECOVERY-ELEMENT", &h1]).is_err());
    Ok(())
}

#[test]
fn every_ekey_production_parses_with_its_exact_arity() -> TestResult {
    use EkeyCommand::*;
    let h1 = hash(1);
    let h2 = hash(2);
    let reference = base64url_encode(&[3; 32]);
    let account = account();
    let id16 = id16();
    let cases: Vec<(Vec<&str>, EkeyCommand, Option<CarrierCommand>)> = vec![
        (
            vec!["FETCH", "IDENTITY", &account],
            FetchIdentity([b'a'; 24]),
            None,
        ),
        (
            vec!["FETCH", "ROOT-CHAIN", &account, "3", "*"],
            FetchRootChain {
                account: [b'a'; 24],
                first_generation: 3,
                cursor: None,
            },
            None,
        ),
        (
            vec!["PUBLISH", "IDENTITY"],
            PublishIdentity,
            Some(CarrierCommand::PublishIdentity),
        ),
        (
            vec!["FETCH", "ROSTER", &account],
            FetchRoster([b'a'; 24]),
            None,
        ),
        (
            vec!["PUBLISH", "ROSTER"],
            PublishRoster,
            Some(CarrierCommand::PublishRoster),
        ),
        (
            vec!["FETCH", "CAPABILITIES", &account, &h1],
            FetchCapabilities {
                account: [b'a'; 24],
                cursor: Some([1; 32]),
            },
            None,
        ),
        (
            vec!["PUBLISH", "CAPABILITIES", &id16],
            PublishCapabilities([1; 16]),
            Some(CarrierCommand::PublishCapabilities),
        ),
        (
            vec![
                "FETCH",
                "BINDING-LOCKS",
                &account,
                &h1,
                "18446744073709551615",
                &h2,
            ],
            FetchBindingLocks {
                account: [b'a'; 24],
                root_fingerprint: [1; 32],
                first_sequence: u64::MAX,
                cursor: Some([2; 32]),
            },
            None,
        ),
        (vec!["WHOAMI"], Whoami, None),
        (vec!["ATTACH", "BEGIN", &id16], AttachBegin([1; 16]), None),
        (
            vec!["ATTACH", "FINISH", &id16],
            AttachFinish([1; 16]),
            Some(CarrierCommand::AttachFinish),
        ),
        (
            vec!["CLAIM", "PACKAGE", &account, &id16, "1", &id16],
            ClaimPackage {
                account: [b'a'; 24],
                device_id: [1; 16],
                suite: 1,
                operation_id: [1; 16],
            },
            None,
        ),
        (vec!["CLAIM", "STATUS", &id16], ClaimStatus([1; 16]), None),
        (
            vec!["PUBLISH", "PACKAGE", &id16, "3", "NORMAL", "1000"],
            PublishPackage {
                device_id: [1; 16],
                suite: 3,
                expires_at: 1_000,
            },
            Some(CarrierCommand::PublishPackage),
        ),
        (
            vec!["REVOKE", "PACKAGE", &reference],
            RevokePackage(vec![3; 32]),
            None,
        ),
        (
            vec!["DELIVER", "BINDING", &account, &id16],
            DeliverBinding {
                account: [b'a'; 24],
                device_id: [1; 16],
            },
            Some(CarrierCommand::DeliverBinding),
        ),
        (
            vec!["DELIVER", "WELCOME", &account, &id16, &h1, &h2],
            DeliverWelcome {
                account: [b'a'; 24],
                device_id: [1; 16],
                conversation_id: [1; 32],
                authorization_id: [2; 32],
            },
            Some(CarrierCommand::DeliverWelcome),
        ),
        (
            vec!["FETCH", "MAILBOX", "STAGED-REINIT", "*"],
            FetchMailbox {
                kind: MailboxKind::StagedReinit,
                cursor: None,
            },
            None,
        ),
        (
            vec!["ACK", "MAILBOX", &h1, &h2],
            AckMailbox {
                delivery_token: [1; 32],
                object_id: [2; 32],
            },
            None,
        ),
    ];
    for (params, expected, carrier) in cases {
        let command = parse_command("EKEY", &params)?;
        assert_eq!(command, ClientCommand::Ekey(expected), "{params:?}");
        assert_eq!(command.carrier(), carrier, "{params:?}");
        assert_eq!(command.request_command(), "EKEY");
    }
    assert_eq!(MailboxKind::Application.token(), "APPLICATION");
    assert_eq!(MailboxKind::Binding.token(), "BINDING");
    assert_eq!(MailboxKind::Welcome.token(), "WELCOME");
    let longest = format!(
        "EKEY FETCH BINDING-LOCKS {} {} 18446744073709551615 {}\r\n",
        account, h1, h2
    );
    assert_eq!(longest.len(), 168, "the longest client command form");
    Ok(())
}

#[test]
fn edirect_and_rejections() -> TestResult {
    let h1 = hash(1);
    let account = account();
    let id16 = id16();
    let command = parse_command("EDIRECT", &[&h1])?;
    assert_eq!(command, ClientCommand::Edirect([1; 32]));
    assert_eq!(command.carrier(), Some(CarrierCommand::Edirect));
    assert_eq!(command.request_command(), "EDIRECT");
    assert!(is_extension_command("EGROUP"));
    assert!(!is_extension_command("PRIVMSG"));
    let rejected: Vec<(&str, Vec<&str>)> = vec![
        ("EDIRECT", vec![]),
        ("EDIRECT", vec![&h1, &h1]),
        ("PRIVMSG", vec!["#room"]),
        ("EGROUP", vec!["RESERVE", "CHANNEL", "room"]),
        ("EGROUP", vec!["RESERVE", "CHANNEL", "#room", "extra"]),
        ("EGROUP", vec!["reserve", "CHANNEL", "#room"]),
        ("EGROUP", vec!["BIND", &h1, &h1, &h1]),
        ("EGROUP", vec!["CLOSE", &h1, "65536"]),
        ("EGROUP", vec!["CLOSE", &h1, "07"]),
        ("EGROUP", vec!["SUBMIT", "PROPOSAL", &h1]),
        ("EGROUP", vec!["SUBMIT", "REINIT", &h1]),
        ("EGROUP", vec!["FETCH", "OBJECT", &h1]),
        ("EGROUP", vec!["FETCH", "RECEIPTS", &h1, "x", "*"]),
        ("EKEY", vec![]),
        ("EKEY", vec!["WHOAMI", "x"]),
        (
            "EKEY",
            vec!["PUBLISH", "PACKAGE", &id16, "1", "LAST-RESORT", "1000"],
        ),
        ("EKEY", vec!["FETCH", "MAILBOX", "OTHER", "*"]),
        ("EKEY", vec!["FETCH", "IDENTITY", &h1]),
        ("EKEY", vec!["REVOKE", "PACKAGE", ""]),
        ("EKEY", vec!["CLAIM", "PACKAGE", &account, &id16, "1"]),
    ];
    for (command, params) in rejected {
        assert!(
            parse_command(command, &params).is_err(),
            "{command} {params:?}"
        );
    }
    Ok(())
}
