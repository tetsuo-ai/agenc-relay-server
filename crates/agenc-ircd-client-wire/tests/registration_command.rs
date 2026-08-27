//! Registration-only Appendix-A grammar and public-listener classification.

#![forbid(unsafe_code)]

use std::error::Error;
use std::io;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

use agenc_ircd_client_wire::{
    AccessTokenPolicy, AccountControlCommand, ChannelControlCommand, ChatHistoryCommand,
    FramedLine, LocalInformationCommand, MonitorCommand, POST_REGISTRATION_COMMANDS, ParsedMessage,
    PostRegistrationCommandKind, RegistrationAccountCommand, RegistrationCapCommand,
    RegistrationCommand, RegistrationGrammarError, parse_message, parse_registration_command,
    validate_post_registration_command,
};
use agenc_ircd_types::CLIENT_COMMANDS;

#[test]
fn cap_accepts_only_the_four_exact_stage_two_productions() -> Result<(), Box<dyn Error>> {
    for (line, expected) in [
        ("CAP LS", RegistrationCapCommand::ListSupported),
        ("CAP LS 302", RegistrationCapCommand::ListSupported),
        ("CAP LIST", RegistrationCapCommand::ListEnabled),
        (
            "CAP REQ :batch labeled-response",
            RegistrationCapCommand::Request,
        ),
        ("CAP REQ :-batch", RegistrationCapCommand::Request),
        ("CAP END", RegistrationCapCommand::End),
    ] {
        assert_eq!(classify(line)?, RegistrationCommand::Cap(expected));
    }

    for (line, expected) in [
        ("CAP", RegistrationGrammarError::NeedMoreParameters),
        ("CAP LS 301", RegistrationGrammarError::InvalidArgument),
        (
            "CAP LS 302 extra",
            RegistrationGrammarError::InvalidArgument,
        ),
        ("CAP list", RegistrationGrammarError::InvalidArgument),
        ("CAP REQ", RegistrationGrammarError::NeedMoreParameters),
        ("CAP REQ :", RegistrationGrammarError::NeedMoreParameters),
        (
            "CAP REQ :batch  sasl",
            RegistrationGrammarError::InvalidArgument,
        ),
        (
            "CAP REQ :name=value",
            RegistrationGrammarError::InvalidArgument,
        ),
        ("CAP END :extra", RegistrationGrammarError::InvalidArgument),
    ] {
        assert_eq!(classify(line).err(), Some(expected), "{line}");
    }
    Ok(())
}

#[test]
fn authenticate_validates_one_bounded_mechanism_marker_or_chunk() -> Result<(), Box<dyn Error>> {
    let chunk = STANDARD.encode([0_u8; 300]);
    for line in [
        "AUTHENTICATE AGENC-OPAQUE".to_owned(),
        "AUTHENTICATE PLAIN".to_owned(),
        "AUTHENTICATE *".to_owned(),
        "AUTHENTICATE +".to_owned(),
        format!("AUTHENTICATE {chunk}"),
    ] {
        assert_eq!(classify(&line)?, RegistrationCommand::Authenticate);
    }

    for (line, expected) in [
        ("AUTHENTICATE", RegistrationGrammarError::NeedMoreParameters),
        (
            "AUTHENTICATE :AGENC-OPAQUE",
            RegistrationGrammarError::InvalidArgument,
        ),
        (
            "AUTHENTICATE bad-mechanism",
            RegistrationGrammarError::InvalidArgument,
        ),
        (
            "AUTHENTICATE AGENC-OPAQUE extra",
            RegistrationGrammarError::InvalidArgument,
        ),
    ] {
        assert_eq!(classify(line).err(), Some(expected), "{line}");
    }
    let too_long = format!("AUTHENTICATE {}", "A".repeat(401));
    assert_eq!(classify(&too_long)?, RegistrationCommand::Authenticate);
    Ok(())
}

#[test]
fn pass_enforces_the_selected_listener_shape_at_exact_boundaries() -> Result<(), Box<dyn Error>> {
    let configured = URL_SAFE_NO_PAD.encode([0_u8; 32]);
    assert_eq!(configured.len(), 43);
    assert_eq!(
        classify_with_policy(
            &format!("PASS {configured}"),
            AccessTokenPolicy::RequireConfiguredToken,
        )?,
        RegistrationCommand::Pass
    );
    let mut noncanonical = configured.clone();
    noncanonical.replace_range(42.., "B");
    assert_eq!(
        classify_with_policy(
            &format!("PASS {noncanonical}"),
            AccessTokenPolicy::RequireConfiguredToken,
        )
        .err(),
        Some(RegistrationGrammarError::InvalidArgument)
    );
    assert_eq!(
        classify_with_policy("PASS short", AccessTokenPolicy::RequireConfiguredToken).err(),
        Some(RegistrationGrammarError::InvalidArgument)
    );

    assert_eq!(
        classify_with_policy("PASS x", AccessTokenPolicy::IgnoreCompatibilityPass)?,
        RegistrationCommand::Pass
    );
    assert_eq!(
        classify_with_policy(
            &format!("PASS {}", "x".repeat(256)),
            AccessTokenPolicy::IgnoreCompatibilityPass,
        )?,
        RegistrationCommand::Pass
    );
    assert_eq!(
        classify_with_policy(
            &format!("PASS {}", "x".repeat(257)),
            AccessTokenPolicy::IgnoreCompatibilityPass,
        )
        .err(),
        Some(RegistrationGrammarError::InputTooLong)
    );
    for line in ["PASS", "PASS :token", "PASS one two"] {
        assert!(classify_with_policy(line, AccessTokenPolicy::IgnoreCompatibilityPass).is_err());
    }
    Ok(())
}

#[test]
fn account_carriers_validate_only_context_independent_shapes() -> Result<(), Box<dyn Error>> {
    for (command, wrapper) in [
        (
            "ACCTCREATE",
            RegistrationCommand::AccountCreate as fn(_) -> _,
        ),
        (
            "ACCTCRED",
            RegistrationCommand::AccountCredentials as fn(_) -> _,
        ),
    ] {
        let chunk = URL_SAFE_NO_PAD.encode([0_u8; 300]);
        for (tail, operation) in [
            ("START 4726".to_owned(), RegistrationAccountCommand::Start),
            ("FINISH 4726".to_owned(), RegistrationAccountCommand::Finish),
            (format!("DATA {chunk}"), RegistrationAccountCommand::Data),
            ("DATA AA".to_owned(), RegistrationAccountCommand::Data),
            ("END".to_owned(), RegistrationAccountCommand::End),
        ] {
            assert_eq!(classify(&format!("{command} {tail}"))?, wrapper(operation));
        }

        for tail in [
            "",
            "START",
            "START 04726",
            "START 4342",
            "DATA",
            "DATA AB",
            "DATA AA==",
            "END extra",
        ] {
            assert!(
                classify(&format!("{command} {tail}")).is_err(),
                "{command} {tail}"
            );
        }
        assert_eq!(
            classify(&format!("{command} DATA {}", "A".repeat(401))).err(),
            Some(RegistrationGrammarError::InputTooLong)
        );
        assert_eq!(
            classify(&format!("@+trace=x {command} END")).err(),
            Some(RegistrationGrammarError::InvalidArgument)
        );
    }
    Ok(())
}

#[test]
fn nick_and_user_enforce_exact_shape_and_prepared_byte_limits() -> Result<(), Box<dyn Error>> {
    for nick in ["a", "_", "Nick-32"] {
        assert_eq!(
            classify(&format!("NICK {nick}"))?,
            RegistrationCommand::Nick
        );
    }
    for line in [
        "NICK",
        "NICK :nick",
        "NICK 9nick",
        "NICK bad.nick",
        "NICK one two",
    ] {
        assert!(classify(line).is_err(), "{line}");
    }
    assert_eq!(
        classify(&format!("NICK A{}", "a".repeat(32))).err(),
        Some(RegistrationGrammarError::InputTooLong)
    );

    for line in [
        "USER ignored 0 * :",
        "USER ignored anything unused :Real Name",
        "USER visible:unicode-é 0 * :Real Name",
        "USER ignored 0 * :ab\u{0007}cd",
        &format!("USER ignored 0 * :{}", "é".repeat(32)),
        &format!("USER {} 0 * :bounded by the line", "u".repeat(400)),
    ] {
        assert_eq!(classify(line)?, RegistrationCommand::User);
    }
    for line in [
        "USER",
        "USER ignored 0 *",
        "USER ignored 0 * realname",
        "USER a b c d :e",
        "USER bad@user 0 * :Real Name",
        "USER bad\tuser 0 * :Real Name",
        "USER bad\u{0007}user 0 * :Real Name",
    ] {
        assert!(classify(line).is_err(), "{line}");
    }
    assert_eq!(
        classify(&format!("USER ignored 0 * :{}", "é".repeat(33))).err(),
        Some(RegistrationGrammarError::InputTooLong)
    );
    Ok(())
}

#[test]
fn ping_pong_and_quit_preserve_empty_and_exact_byte_boundaries() -> Result<(), Box<dyn Error>> {
    for command in ["PING", "PONG"] {
        for parameter in [
            "token".to_owned(),
            ":".to_owned(),
            format!(":{}", "é".repeat(32)),
        ] {
            let expected = if command == "PING" {
                RegistrationCommand::Ping
            } else {
                RegistrationCommand::Pong
            };
            assert_eq!(classify(&format!("{command} {parameter}"))?, expected);
        }
        assert_eq!(
            classify(&format!("{command} :{}", "x".repeat(65))).err(),
            Some(RegistrationGrammarError::InputTooLong)
        );
        assert_eq!(
            classify(command).err(),
            Some(RegistrationGrammarError::NeedMoreParameters)
        );
        assert_eq!(
            classify(&format!("{command} one two")).err(),
            Some(RegistrationGrammarError::InvalidArgument)
        );
    }

    for line in [
        "QUIT".to_owned(),
        "QUIT :".to_owned(),
        format!("QUIT :{}", "x".repeat(256)),
    ] {
        assert_eq!(classify(&line)?, RegistrationCommand::Quit);
    }
    assert_eq!(
        classify(&format!("QUIT :{}", "x".repeat(257))).err(),
        Some(RegistrationGrammarError::InputTooLong)
    );
    for line in ["QUIT reason", "QUIT one :reason"] {
        assert_eq!(
            classify(line).err(),
            Some(RegistrationGrammarError::InvalidArgument)
        );
    }
    Ok(())
}

#[test]
fn post_registration_registry_is_exhaustive_and_public_classification_is_closed()
-> Result<(), Box<dyn Error>> {
    let registration = [
        "CAP",
        "AUTHENTICATE",
        "PASS",
        "ACCTCREATE",
        "ACCTCRED",
        "NICK",
        "USER",
        "PING",
        "PONG",
        "QUIT",
    ];
    assert!(
        CLIENT_COMMANDS.iter().copied().eq(registration
            .into_iter()
            .chain(POST_REGISTRATION_COMMANDS.iter().copied()))
    );

    for (line, expected) in valid_post_registration_examples() {
        assert_eq!(
            classify(line)?,
            RegistrationCommand::PostRegistration(expected),
            "{line}"
        );
        assert_eq!(validate(line)?, expected, "{line}");
    }

    for command in [
        "ACCOUNT", "ACK", "BATCH", "ERROR", "FAIL", "NOTE", "WARN", "SERVLIST", "SQUERY", "SUMMON",
        "USERS", "WHATEVER",
    ] {
        assert_eq!(
            classify(command).err(),
            Some(RegistrationGrammarError::UnknownCommand),
            "{command}"
        );
    }
    for command in [
        "AUDIT", "BACKUP", "CHANNEL", "CONNECT", "DIE", "KILL", "OPER", "PEER", "REHASH",
        "RESTART", "SQUIT", "STATS", "TRACE",
    ] {
        assert_eq!(
            classify(command).err(),
            Some(RegistrationGrammarError::NoPrivileges),
            "{command}"
        );
    }
    assert_eq!(
        classify("OPER :credentials are not parsed").err(),
        Some(RegistrationGrammarError::NoPrivileges)
    );
    assert_eq!(
        classify("BATCH +opaque-server-token").err(),
        Some(RegistrationGrammarError::UnknownCommand)
    );
    assert_eq!(
        classify("jOiN 0")?,
        RegistrationCommand::PostRegistration(PostRegistrationCommandKind::JoinAll)
    );
    Ok(())
}

#[test]
fn join_part_mode_topic_names_and_list_enforce_all_shape_boundaries() -> Result<(), Box<dyn Error>>
{
    assert_eq!(validate("JOIN 0")?, PostRegistrationCommandKind::JoinAll);
    assert_eq!(
        validate("JOIN #one,&two")?,
        PostRegistrationCommandKind::JoinChannels
    );
    assert_eq!(
        validate("JOIN #one,#two 12345678,abcdefgh")?,
        PostRegistrationCommandKind::JoinChannels
    );
    assert_eq!(
        validate(&format!("JOIN #one {}", "k".repeat(256)))?,
        PostRegistrationCommandKind::JoinChannels
    );
    assert_eq!(
        validate(&format!("JOIN {}", channel(64)))?,
        PostRegistrationCommandKind::JoinChannels
    );
    assert_eq!(
        validate(&format!("JOIN {}", channel(65))).err(),
        Some(RegistrationGrammarError::InputTooLong)
    );
    let twenty_channels = numbered_csv("#c", 20);
    assert_eq!(
        validate(&format!("JOIN {twenty_channels}"))?,
        PostRegistrationCommandKind::JoinChannels
    );
    for line in [
        "JOIN",
        "JOIN :#one",
        "JOIN 0 extra",
        "JOIN #one,#ONE",
        "JOIN #one,#two 12345678,abcdefgh,morekeys",
        "JOIN #one short",
    ] {
        assert!(validate(line).is_err(), "{line}");
    }
    assert!(validate(&format!("JOIN {}", numbered_csv("#c", 21))).is_err());
    assert_eq!(
        validate(&format!("JOIN #one {}", "k".repeat(257))).err(),
        Some(RegistrationGrammarError::InputTooLong)
    );

    for line in [
        "PART #one".to_owned(),
        "PART #one,#two :".to_owned(),
        format!("PART #one :{}", "r".repeat(256)),
    ] {
        assert_eq!(validate(&line)?, PostRegistrationCommandKind::Part);
    }
    assert_eq!(
        validate(&format!("PART #one :{}", "r".repeat(257))).err(),
        Some(RegistrationGrammarError::InputTooLong)
    );
    for line in [
        "PART",
        "PART :#one",
        "PART #one reason",
        "PART #one #two :reason",
    ] {
        assert!(validate(line).is_err(), "{line}");
    }
    assert!(validate(&format!("PART {}", numbered_csv("#c", 21))).is_err());

    for (line, kind) in [
        ("MODE #one", PostRegistrationCommandKind::ModeQuery),
        ("MODE Nick", PostRegistrationCommandKind::ModeQuery),
        ("MODE #one +imnpst", PostRegistrationCommandKind::ModeChange),
        ("MODE #one b", PostRegistrationCommandKind::ModeChange),
        (
            "MODE #one +oooooo a b c d e :f",
            PostRegistrationCommandKind::ModeChange,
        ),
    ] {
        assert_eq!(validate(line)?, kind, "{line}");
    }
    for line in [
        "MODE",
        "MODE :#one",
        "MODE #one +",
        "MODE #one ++i",
        "MODE #one +imnpstk",
        "MODE #one +oooooo a b c d e f g",
    ] {
        assert!(validate(line).is_err(), "{line}");
    }

    assert_eq!(
        validate("TOPIC #one")?,
        PostRegistrationCommandKind::TopicQuery
    );
    assert_eq!(
        validate("TOPIC #one :")?,
        PostRegistrationCommandKind::TopicSet
    );
    assert_eq!(
        validate(&format!("TOPIC #one :{}", "t".repeat(490)))?,
        PostRegistrationCommandKind::TopicSet
    );
    for line in [
        "TOPIC",
        "TOPIC :#one",
        "TOPIC #one topic",
        "TOPIC #one extra :topic",
    ] {
        assert!(validate(line).is_err(), "{line}");
    }

    for (command, all, listed) in [
        (
            "NAMES",
            PostRegistrationCommandKind::NamesAll,
            PostRegistrationCommandKind::NamesChannels,
        ),
        (
            "LIST",
            PostRegistrationCommandKind::ListAll,
            PostRegistrationCommandKind::ListChannels,
        ),
    ] {
        assert_eq!(validate(command)?, all);
        assert_eq!(validate(&format!("{command} {twenty_channels}"))?, listed);
        assert!(validate(&format!("{command} {}", numbered_csv("#c", 21))).is_err());
        assert!(validate(&format!("{command} :#one")).is_err());
        assert!(validate(&format!("{command} #one extra")).is_err());
    }
    Ok(())
}

#[test]
fn invite_kick_and_message_commands_enforce_targets_text_and_tags() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        validate("INVITE Nick #one")?,
        PostRegistrationCommandKind::Invite
    );
    for line in [
        "INVITE",
        "INVITE Nick",
        "INVITE Nick #one extra",
        "INVITE :Nick #one",
    ] {
        assert!(validate(line).is_err(), "{line}");
    }
    assert_eq!(
        validate(&format!("INVITE {} #one", nickname(32)))?,
        PostRegistrationCommandKind::Invite
    );
    assert_eq!(
        validate(&format!("INVITE {} #one", nickname(33))).err(),
        Some(RegistrationGrammarError::InputTooLong)
    );

    assert_eq!(
        validate("KICK #one a,b,c,d :reason")?,
        PostRegistrationCommandKind::Kick
    );
    assert_eq!(
        validate(&format!("KICK #one a :{}", "r".repeat(256)))?,
        PostRegistrationCommandKind::Kick
    );
    for line in [
        "KICK",
        "KICK #one",
        "KICK #one a,b,c,d,e",
        "KICK #one a reason",
    ] {
        assert!(validate(line).is_err(), "{line}");
    }
    assert_eq!(
        validate(&format!("KICK #one a :{}", "r".repeat(257))).err(),
        Some(RegistrationGrammarError::InputTooLong)
    );

    assert_eq!(
        validate("PRIVMSG #one,@#two,Nick,+#three :body")?,
        PostRegistrationCommandKind::Privmsg
    );
    assert_eq!(
        validate("NOTICE #one :")?,
        PostRegistrationCommandKind::Notice
    );
    for line in [
        "PRIVMSG",
        "PRIVMSG #one",
        "PRIVMSG #one :",
        "PRIVMSG #one,#two,#three,#four,#five :body",
        "PRIVMSG #one,#ONE :body",
        "NOTICE",
        "NOTICE #one",
        "NOTICE #one,#two,#three,#four,#five :body",
    ] {
        assert!(validate(line).is_err(), "{line}");
    }

    assert_eq!(
        validate("@+draft/example=value TAGMSG #one")?,
        PostRegistrationCommandKind::Tagmsg
    );
    for line in [
        "TAGMSG #one",
        "@label=one TAGMSG #one",
        "@+draft/example TAGMSG",
        "@+draft/example TAGMSG #one extra",
    ] {
        assert!(validate(line).is_err(), "{line}");
    }

    let message = parsed("@+draft/example TAGMSG #private")?;
    let proof = validate_post_registration_command(&message)?;
    let proof_copy = proof;
    assert_eq!(proof_copy.kind(), PostRegistrationCommandKind::Tagmsg);
    assert_eq!(proof_copy.message().command(), "TAGMSG");
    let debug = format!("{proof:?}");
    assert!(!debug.contains("#private"));
    assert!(!debug.contains("draft/example"));
    Ok(())
}

#[test]
fn local_information_and_presence_queries_enforce_exact_arity_and_counts()
-> Result<(), Box<dyn Error>> {
    for command in [
        "MOTD", "LUSERS", "VERSION", "TIME", "ADMIN", "INFO", "LINKS",
    ] {
        assert!(matches!(
            validate(command)?,
            PostRegistrationCommandKind::LocalInformation(_)
        ));
    }
    for command in ["MOTD", "VERSION", "TIME", "ADMIN", "INFO"] {
        assert!(matches!(
            validate(&format!("{command} irc.example"))?,
            PostRegistrationCommandKind::LocalInformation(_)
        ));
        assert!(validate(&format!("{command} :irc.example")).is_err());
        assert!(validate(&format!("{command} irc.example extra")).is_err());
    }
    for command in ["LUSERS", "LINKS"] {
        assert!(validate(&format!("{command} irc.example")).is_err());
    }
    let server_253 = server_name(61);
    let server_254 = server_name(62);
    assert_eq!(server_253.len(), 253);
    assert_eq!(server_254.len(), 254);
    assert!(validate(&format!("MOTD {server_253}")).is_ok());
    assert_eq!(
        validate(&format!("MOTD {server_254}")).err(),
        Some(RegistrationGrammarError::InputTooLong)
    );

    assert_eq!(validate("WHO")?, PostRegistrationCommandKind::WhoSelf);
    for line in ["WHO Nick", "WHO #one"] {
        assert_eq!(validate(line)?, PostRegistrationCommandKind::WhoTarget);
    }
    for line in ["WHO %tc", "WHO Nick extra", "WHO :Nick"] {
        assert!(validate(line).is_err(), "{line}");
    }
    assert_eq!(validate("WHOIS Nick")?, PostRegistrationCommandKind::Whois);
    for line in ["WHOIS", "WHOIS Nick Other", "WHOIS :Nick"] {
        assert!(validate(line).is_err(), "{line}");
    }

    for line in ["WHOWAS Nick", "WHOWAS Nick 1", "WHOWAS Nick 10"] {
        assert_eq!(validate(line)?, PostRegistrationCommandKind::Whowas);
    }
    for line in [
        "WHOWAS",
        "WHOWAS Nick 0",
        "WHOWAS Nick 01",
        "WHOWAS Nick 11",
        "WHOWAS Nick 1 extra",
    ] {
        assert!(validate(line).is_err(), "{line}");
    }

    for line in [
        "AWAY".to_owned(),
        "AWAY :".to_owned(),
        format!("AWAY :{}", "a".repeat(256)),
    ] {
        assert_eq!(validate(&line)?, PostRegistrationCommandKind::Away);
    }
    assert_eq!(
        validate(&format!("AWAY :{}", "a".repeat(257))).err(),
        Some(RegistrationGrammarError::InputTooLong)
    );
    assert!(validate("AWAY text").is_err());

    // The Appendix-A ISON ceiling is 20, but the global 15-parameter parser
    // ceiling is reached first because each nickname is a separate parameter.
    let fifteen_nicknames = numbered_parameters("n", 15);
    assert_eq!(
        validate(&format!("ISON {fifteen_nicknames}"))?,
        PostRegistrationCommandKind::Ison
    );
    assert!(validate("ISON").is_err());
    assert!(validate(&format!("ISON {}", numbered_parameters("n", 16))).is_err());
    assert!(validate("ISON :Nick").is_err());
    assert_eq!(
        validate("USERHOST a b c d e")?,
        PostRegistrationCommandKind::Userhost
    );
    for line in ["USERHOST", "USERHOST a b c d e f", "USERHOST :a"] {
        assert!(validate(line).is_err(), "{line}");
    }

    for (line, operation) in [
        ("MONITOR + a,b", MonitorCommand::Add),
        ("MONITOR - a,b", MonitorCommand::Remove),
        ("MONITOR C", MonitorCommand::Clear),
        ("MONITOR L", MonitorCommand::List),
        ("MONITOR S", MonitorCommand::Status),
    ] {
        assert_eq!(
            validate(line)?,
            PostRegistrationCommandKind::Monitor(operation)
        );
    }
    assert_eq!(
        validate(&format!("MONITOR + {}", numbered_csv("n", 20)))?,
        PostRegistrationCommandKind::Monitor(MonitorCommand::Add)
    );
    for line in [
        "MONITOR",
        "MONITOR +",
        "MONITOR C extra",
        "MONITOR + a,A",
        "MONITOR c",
    ] {
        assert!(validate(line).is_err(), "{line}");
    }
    assert!(validate(&format!("MONITOR + {}", numbered_csv("n", 21))).is_err());

    assert_eq!(validate("SETNAME :")?, PostRegistrationCommandKind::Setname);
    assert_eq!(
        validate(&format!("SETNAME :{}", "é".repeat(32)))?,
        PostRegistrationCommandKind::Setname
    );
    assert_eq!(
        validate("SETNAME :   ")?,
        PostRegistrationCommandKind::Setname
    );
    assert_eq!(
        validate(&format!("SETNAME :{}", "a".repeat(65))).err(),
        Some(RegistrationGrammarError::InputTooLong)
    );
    for line in ["SETNAME", "SETNAME display", "SETNAME extra :display"] {
        assert!(validate(line).is_err(), "{line}");
    }
    Ok(())
}

#[test]
fn account_channel_and_history_controls_accept_only_closed_productions()
-> Result<(), Box<dyn Error>> {
    let account_id = format!("a_{}", URL_SAFE_NO_PAD.encode([0_u8; 16]));
    let confirmation = URL_SAFE_NO_PAD.encode([1_u8; 16]);
    for (line, operation) in [
        (
            "ACCT LABEL Label-1".to_owned(),
            AccountControlCommand::Label,
        ),
        ("ACCT LABEL *".to_owned(), AccountControlCommand::Label),
        (
            "ACCT PRESENCE PUBLIC".to_owned(),
            AccountControlCommand::Presence,
        ),
        (
            "ACCT PRESENCE PRIVATE".to_owned(),
            AccountControlCommand::Presence,
        ),
        (
            "ACCT GUEST-DM ALLOW".to_owned(),
            AccountControlCommand::GuestDirectMessages,
        ),
        (
            "ACCT GUEST-DM DENY".to_owned(),
            AccountControlCommand::GuestDirectMessages,
        ),
        (
            "ACCT DIRECT-MESSAGES ALLOW".to_owned(),
            AccountControlCommand::DirectMessages,
        ),
        (
            "ACCT DIRECT-MESSAGES CONTACTS".to_owned(),
            AccountControlCommand::DirectMessages,
        ),
        (
            "ACCT DIRECT-MESSAGES DENY".to_owned(),
            AccountControlCommand::DirectMessages,
        ),
        (
            format!("ACCT CONTACT ADD {account_id}"),
            AccountControlCommand::ContactAdd,
        ),
        (
            format!("ACCT CONTACT REMOVE {account_id}"),
            AccountControlCommand::ContactRemove,
        ),
        (
            "ACCT NICK RESERVE Nick".to_owned(),
            AccountControlCommand::NickReserve,
        ),
        (
            "ACCT NICK RELEASE Nick".to_owned(),
            AccountControlCommand::NickRelease,
        ),
        (
            "ACCT DELETE START".to_owned(),
            AccountControlCommand::DeleteStart,
        ),
        (
            format!("ACCT DELETE CONFIRM {confirmation}"),
            AccountControlCommand::DeleteConfirm,
        ),
    ] {
        assert_eq!(
            validate(&line)?,
            PostRegistrationCommandKind::Account(operation),
            "{line}"
        );
        let Some((missing, _)) = line.rsplit_once(' ') else {
            return Err(io::Error::other("ACCT fixture has no removable parameter").into());
        };
        assert!(validate(missing).is_err(), "{missing}");
        assert!(validate(&format!("{line} extra")).is_err(), "{line}");
    }
    assert_eq!(
        validate(&format!("ACCT LABEL {}", "a".repeat(32)))?,
        PostRegistrationCommandKind::Account(AccountControlCommand::Label)
    );
    assert_eq!(
        validate(&format!("ACCT LABEL {}", "a".repeat(33))).err(),
        Some(RegistrationGrammarError::InputTooLong)
    );
    for line in [
        "ACCT",
        "ACCT LABEL",
        "ACCT LABEL label extra",
        "ACCT PRESENCE public",
        "ACCT CONTACT ADD bad-id",
        "ACCT DELETE CONFIRM short",
        "ACCT DELETE START extra",
    ] {
        assert!(validate(line).is_err(), "{line}");
    }

    for (line, operation) in [
        ("CHANCTL REGISTER #one", ChannelControlCommand::Register),
        ("CHANCTL UNREGISTER #one", ChannelControlCommand::Unregister),
        ("CHANCTL HISTORY #one OFF", ChannelControlCommand::History),
        ("CHANCTL HISTORY #one 1H", ChannelControlCommand::History),
        ("CHANCTL HISTORY #one 24H", ChannelControlCommand::History),
        ("CHANCTL HISTORY #one 7D", ChannelControlCommand::History),
    ] {
        assert_eq!(
            validate(line)?,
            PostRegistrationCommandKind::ChannelControl(operation)
        );
        let Some((missing, _)) = line.rsplit_once(' ') else {
            return Err(io::Error::other("CHANCTL fixture has no removable parameter").into());
        };
        assert!(validate(missing).is_err(), "{missing}");
        assert!(validate(&format!("{line} extra")).is_err(), "{line}");
    }
    for line in [
        "CHANCTL",
        "CHANCTL REGISTER",
        "CHANCTL REGISTER #one extra",
        "CHANCTL HISTORY #one 2H",
    ] {
        assert!(validate(line).is_err(), "{line}");
    }

    let message_id = URL_SAFE_NO_PAD.encode([2_u8; 16]);
    let timestamp = "timestamp=2024-02-29T23:59:60.999Z";
    for (line, operation) in [
        (
            "CHATHISTORY LATEST #one * 100".to_owned(),
            ChatHistoryCommand::Latest,
        ),
        (
            format!("CHATHISTORY LATEST #one msgid={message_id} 1"),
            ChatHistoryCommand::Latest,
        ),
        (
            format!("CHATHISTORY BEFORE #one {timestamp} 1"),
            ChatHistoryCommand::Before,
        ),
        (
            format!("CHATHISTORY AFTER #one msgid={message_id} 1"),
            ChatHistoryCommand::After,
        ),
        (
            format!("CHATHISTORY AROUND #one {timestamp} 1"),
            ChatHistoryCommand::Around,
        ),
        (
            format!("CHATHISTORY BETWEEN #one {timestamp} msgid={message_id} 100"),
            ChatHistoryCommand::Between,
        ),
    ] {
        assert_eq!(
            validate(&line)?,
            PostRegistrationCommandKind::ChatHistory(operation),
            "{line}"
        );
        let Some((missing, _)) = line.rsplit_once(' ') else {
            return Err(io::Error::other("CHATHISTORY fixture has no removable parameter").into());
        };
        assert!(validate(missing).is_err(), "{missing}");
        assert!(validate(&format!("{line} extra")).is_err(), "{line}");
    }
    for line in [
        "CHATHISTORY",
        "CHATHISTORY LATEST #one *",
        "CHATHISTORY LATEST #one * 0",
        "CHATHISTORY LATEST #one * 01",
        "CHATHISTORY LATEST #one * 101",
        "CHATHISTORY BEFORE #one * 1",
        "CHATHISTORY BEFORE #one timestamp=2023-02-29T00:00:00.000Z 1",
        "CHATHISTORY BETWEEN #one timestamp=2024-01-01T00:00:00.000Z 1",
        "CHATHISTORY TARGETS timestamp=2024-01-01T00:00:00.000Z timestamp=2024-01-02T00:00:00.000Z 1",
        "CHATHISTORY LATEST #one * 1 extra",
    ] {
        assert!(validate(line).is_err(), "{line}");
    }
    Ok(())
}

#[test]
fn reachable_short_circuit_boundaries_reject_noncanonical_commands() -> Result<(), Box<dyn Error>> {
    for line in [
        "CAP LIST extra",
        "CAP LIST :extra",
        "CAP END extra",
        "ACCTCREATE END :extra",
        "ACCTCREATE START :4726",
    ] {
        assert_eq!(
            classify(line).err(),
            Some(RegistrationGrammarError::InvalidArgument),
            "{line}"
        );
    }

    for line in [
        "INVITE Nick :#one",
        "CHANCTL :REGISTER",
        "CHATHISTORY :LATEST",
        "MODE #one i+",
        "ACCT LABEL _label",
        "ACCT LABEL label+",
        "JOIN #bad!",
        "CHATHISTORY BEFORE #one timestamp=2024-02-28T23:59:60.000Z 1",
    ] {
        assert!(validate(line).is_err(), "{line}");
    }

    assert_eq!(
        classify("AUTHENTICATE YWJjZA==")?,
        RegistrationCommand::Authenticate
    );
    for line in ["AUTHENTICATE abcd====", "AUTHENTICATE AB=="] {
        assert_eq!(
            classify(line).err(),
            Some(RegistrationGrammarError::InvalidArgument),
            "{line}"
        );
    }

    let mut noncanonical_confirmation = URL_SAFE_NO_PAD.encode([0_u8; 16]);
    let Some(last) = noncanonical_confirmation.pop() else {
        return Err(io::Error::other("missing confirmation suffix").into());
    };
    if last != 'A' {
        return Err(io::Error::other("unexpected canonical confirmation suffix").into());
    }
    noncanonical_confirmation.push('B');
    assert_eq!(
        validate(&format!("ACCT DELETE CONFIRM {noncanonical_confirmation}")).err(),
        Some(RegistrationGrammarError::InvalidArgument)
    );
    Ok(())
}

fn valid_post_registration_examples() -> [(&'static str, PostRegistrationCommandKind); 29] {
    [
        ("JOIN 0", PostRegistrationCommandKind::JoinAll),
        ("PART #one", PostRegistrationCommandKind::Part),
        ("MODE #one", PostRegistrationCommandKind::ModeQuery),
        ("TOPIC #one", PostRegistrationCommandKind::TopicQuery),
        ("NAMES", PostRegistrationCommandKind::NamesAll),
        ("LIST", PostRegistrationCommandKind::ListAll),
        ("INVITE Nick #one", PostRegistrationCommandKind::Invite),
        ("KICK #one Nick", PostRegistrationCommandKind::Kick),
        ("PRIVMSG Nick :body", PostRegistrationCommandKind::Privmsg),
        ("NOTICE Nick :", PostRegistrationCommandKind::Notice),
        ("@+example TAGMSG Nick", PostRegistrationCommandKind::Tagmsg),
        (
            "MOTD",
            PostRegistrationCommandKind::LocalInformation(LocalInformationCommand::Motd),
        ),
        (
            "LUSERS",
            PostRegistrationCommandKind::LocalInformation(LocalInformationCommand::Lusers),
        ),
        (
            "VERSION",
            PostRegistrationCommandKind::LocalInformation(LocalInformationCommand::Version),
        ),
        (
            "TIME",
            PostRegistrationCommandKind::LocalInformation(LocalInformationCommand::Time),
        ),
        (
            "ADMIN",
            PostRegistrationCommandKind::LocalInformation(LocalInformationCommand::Admin),
        ),
        (
            "INFO",
            PostRegistrationCommandKind::LocalInformation(LocalInformationCommand::Info),
        ),
        (
            "LINKS",
            PostRegistrationCommandKind::LocalInformation(LocalInformationCommand::Links),
        ),
        ("WHO", PostRegistrationCommandKind::WhoSelf),
        ("WHOIS Nick", PostRegistrationCommandKind::Whois),
        ("WHOWAS Nick", PostRegistrationCommandKind::Whowas),
        ("AWAY", PostRegistrationCommandKind::Away),
        ("ISON Nick", PostRegistrationCommandKind::Ison),
        ("USERHOST Nick", PostRegistrationCommandKind::Userhost),
        (
            "MONITOR C",
            PostRegistrationCommandKind::Monitor(MonitorCommand::Clear),
        ),
        ("SETNAME :", PostRegistrationCommandKind::Setname),
        (
            "ACCT LABEL *",
            PostRegistrationCommandKind::Account(AccountControlCommand::Label),
        ),
        (
            "CHANCTL REGISTER #one",
            PostRegistrationCommandKind::ChannelControl(ChannelControlCommand::Register),
        ),
        (
            "CHATHISTORY LATEST #one * 1",
            PostRegistrationCommandKind::ChatHistory(ChatHistoryCommand::Latest),
        ),
    ]
}

fn numbered_csv(prefix: &str, count: usize) -> String {
    (0..count)
        .map(|index| format!("{prefix}{index}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn numbered_parameters(prefix: &str, count: usize) -> String {
    (0..count)
        .map(|index| format!("{prefix}{index}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn nickname(bytes: usize) -> String {
    let mut value = String::from("N");
    value.push_str(&"a".repeat(bytes.saturating_sub(1)));
    value
}

fn channel(bytes: usize) -> String {
    let mut value = String::from("#");
    value.push_str(&"a".repeat(bytes.saturating_sub(1)));
    value
}

fn server_name(last_label_bytes: usize) -> String {
    format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(last_label_bytes)
    )
}

fn classify(line: &str) -> Result<RegistrationCommand, RegistrationGrammarError> {
    classify_with_policy(line, AccessTokenPolicy::IgnoreCompatibilityPass)
}

fn validate(line: &str) -> Result<PostRegistrationCommandKind, RegistrationGrammarError> {
    let message = parsed(line).map_err(|_| RegistrationGrammarError::InvalidArgument)?;
    validate_post_registration_command(&message).map(|proof| proof.kind())
}

fn classify_with_policy(
    line: &str,
    access_policy: AccessTokenPolicy,
) -> Result<RegistrationCommand, RegistrationGrammarError> {
    let message = parsed(line).map_err(|_| RegistrationGrammarError::InvalidArgument)?;
    parse_registration_command(&message, access_policy)
}

fn parsed(line: &str) -> Result<ParsedMessage, Box<dyn Error>> {
    parse_message(FramedLine::new(line)?)?
        .ok_or_else(|| io::Error::other("missing parsed message").into())
}
