#![forbid(unsafe_code)]

//! Companion-profile lines enter the client wire through one constructor
//! that admits only the closed extension command set.

use agenc_ircd_client_wire::{RenderError, WireMessage};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn extension_lines_parse_tags_prefix_command_and_parameters() -> TestResult {
    let line = "@label=abc;batch=b1;+agenc.ag/e2ee=v1.x.0.1.3.YWJj :server.example EGROUP CANDIDATE a b c\r\n";
    let message = WireMessage::extension_line(line)?;
    assert_eq!(message.command(), "EGROUP");
    assert_eq!(message.middle(), ["CANDIDATE", "a", "b", "c"]);
    assert_eq!(message.trailing(), None);
    let fail = WireMessage::extension_line(
        ":server.example FAIL EGROUP E2EE_ROUTE_INVALID ctx :Route is unknown",
    )?;
    assert_eq!(fail.command(), "FAIL");
    assert_eq!(fail.trailing(), Some("Route is unknown"));
    let batch = WireMessage::extension_line(
        ":server.example BATCH +b1 agenc.ag/e2ee-objects EKEY ROSTER s t *",
    )?;
    assert_eq!(batch.middle().len(), 7);
    Ok(())
}

#[test]
fn extension_lines_refuse_other_commands_and_broken_syntax() {
    assert_eq!(
        WireMessage::extension_line(":server.example PRIVMSG #a :hi")
            .err()
            .map(|error| error.to_string()),
        Some(RenderError::UnknownRegistryValue.to_string())
    );
    for line in [
        "server.example EGROUP BOUND a b",
        "@=x :server.example EGROUP BOUND a b",
        ":server.example",
        ":server.example EGROUP  BOUND",
    ] {
        assert!(WireMessage::extension_line(line).is_err(), "{line}");
    }
    let long = format!(":server.example EGROUP {}", "x".repeat(9_000));
    assert!(WireMessage::extension_line(&long).is_err());
}
