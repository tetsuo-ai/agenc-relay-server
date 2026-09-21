//! Additional malformed-input combinations at parser short-circuit boundaries.

#![forbid(unsafe_code)]

use std::error::Error;
use std::io;

use agenc_relay_client_wire::{
    AccessTokenPolicy, FramedLine, ParsedMessage, RegistrationGrammarError, parse_message,
    parse_registration_command, validate_post_registration_command,
};

#[test]
fn post_registration_validation_reaches_each_distinct_shape_guard() -> Result<(), Box<dyn Error>> {
    for line in [
        "JOIN #room",
        "PART #room",
        "MODE #room",
        "NAMES #room",
        "LIST #room",
        "NOTICE #room :",
        "MONITOR - Nick",
        "ACCT PRESENCE PRIVATE",
        "CHANCTL UNREGISTER #room",
        "CHATHISTORY BEFORE #room timestamp=2024-04-30T23:59:60.000Z 1",
    ] {
        assert!(validate(line).is_ok(), "{line}");
    }

    for (line, expected) in [
        (
            "PART #room reason",
            RegistrationGrammarError::InvalidArgument,
        ),
        ("MODE", RegistrationGrammarError::NeedMoreParameters),
        ("MODE :#room", RegistrationGrammarError::InvalidArgument),
        (
            "MODE #room :missing-mode",
            RegistrationGrammarError::InvalidArgument,
        ),
        ("MODE #room +1", RegistrationGrammarError::InvalidArgument),
        (
            "PRIVMSG #room body",
            RegistrationGrammarError::InvalidArgument,
        ),
        (
            "NOTICE #room body",
            RegistrationGrammarError::InvalidArgument,
        ),
        ("JOIN ,", RegistrationGrammarError::InvalidArgument),
        ("JOIN Nick", RegistrationGrammarError::InvalidArgument),
        ("JOIN #bad!", RegistrationGrammarError::InvalidArgument),
        (
            "JOIN #room 1234\t678",
            RegistrationGrammarError::InvalidArgument,
        ),
        ("MOTD localhost", RegistrationGrammarError::InvalidArgument),
        (
            "MOTD IRC.example",
            RegistrationGrammarError::InvalidArgument,
        ),
        (
            "MOTD -irc.example",
            RegistrationGrammarError::InvalidArgument,
        ),
        (
            "MOTD irc-.example",
            RegistrationGrammarError::InvalidArgument,
        ),
        ("MOTD .example", RegistrationGrammarError::InvalidArgument),
        (
            "CHATHISTORY BEFORE #room reference=unknown 1",
            RegistrationGrammarError::InvalidArgument,
        ),
        (
            "CHATHISTORY BEFORE #room timestamp=2024-01-01T00:00:00.00AZ 1",
            RegistrationGrammarError::InvalidArgument,
        ),
        (
            "ACCT DELETE CONFIRM AAAAAAAAAAAAAAAAAAAA",
            RegistrationGrammarError::InvalidArgument,
        ),
    ] {
        assert_eq!(validate(line).err(), Some(expected), "{line:?}");
    }

    let non_post = parsed("PING token")?;
    assert_eq!(
        validate_post_registration_command(&non_post).err(),
        Some(RegistrationGrammarError::UnknownCommand)
    );
    Ok(())
}

#[test]
fn registration_dispatch_rejects_control_and_noncanonical_carriers() -> Result<(), Box<dyn Error>> {
    for line in [
        "CAP REQ :bad\u{7f}",
        "AUTHENTICATE AA===",
        "ACCTCREATE DATA :",
        "NICK :",
        "USER @ 0 * :real name",
    ] {
        assert_eq!(
            classify(line).err(),
            Some(RegistrationGrammarError::InvalidArgument),
            "{line:?}"
        );
    }
    Ok(())
}

fn parsed(line: &str) -> Result<ParsedMessage, Box<dyn Error>> {
    parse_message(FramedLine::new(line)?)?
        .ok_or_else(|| io::Error::other("fixture did not contain a message").into())
}

fn validate(line: &str) -> Result<(), RegistrationGrammarError> {
    let message = parsed(line).map_err(|_| RegistrationGrammarError::InvalidArgument)?;
    validate_post_registration_command(&message).map(|_| ())
}

fn classify(line: &str) -> Result<(), RegistrationGrammarError> {
    let message = parsed(line).map_err(|_| RegistrationGrammarError::InvalidArgument)?;
    parse_registration_command(&message, AccessTokenPolicy::IgnoreCompatibilityPass).map(|_| ())
}
