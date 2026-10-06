#![forbid(unsafe_code)]

//! `decode(render(x))` over every server renderer form: each line the base
//! renderers produce frames as one server line and decodes to the command,
//! source, parameters and tags it was rendered from, and rebuilding the line
//! from its decoded parts gives back the rendered bytes.

use std::error::Error;

use agenc_relay_client_wire::{
    BatchStack, CapRequestReply, CapabilityProfile, CapabilitySpec, CapabilityState,
    MAX_NICKNAME_BYTES, MAX_USER_MASK_BYTES, OutputBudget, RenderError, ReplyKind,
    SafeReplyContext, SafeReplyDescription, ServerCommand, ServerMessage, ServerMessageError,
    ServerPrefix, ServerStreamFramer, WireMessage, isupport_messages, labeled_response,
    numeric_reply, parse_server_message, slow_consumer_warning, standard_reply, user_mask,
};
use agenc_relay_types::{
    AccountDeletionToken, AccountId, AccountRandomId, ChannelName, NetworkId, PublicCloak,
    PublicErrorCode, RecoveryEpoch, SERVER_NUMERICS,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

type TestResult = Result<(), Box<dyn Error>>;

const SERVER: &str = "server.example";
const TARGET: &str = "alice";

struct AnyBudget;

impl OutputBudget for AnyBudget {
    type Permit = ();

    fn try_reserve_exact(&mut self, _bytes: usize) -> Result<Self::Permit, RenderError> {
        Ok(())
    }
}

/// The rendered bytes of one plan, CRLF included.
fn rendered(message: &WireMessage) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(message
        .measure()?
        .encode(&mut AnyBudget)?
        .as_bytes()
        .to_vec())
}

/// Frames rendered bytes as exactly one server line.
fn framed(bytes: &[u8]) -> Result<String, Box<dyn Error>> {
    let mut framer = ServerStreamFramer::new()?;
    let mut lines = Vec::new();
    framer.feed(bytes, |line| lines.push(line.as_str().to_owned()))?;
    framer.finish()?;
    match lines.as_slice() {
        [line] => Ok(line.clone()),
        _ => Err(format!("{} lines framed", lines.len()).into()),
    }
}

/// Rebuilds a line from its decoded parts.
fn rebuilt(message: &ServerMessage<'_>) -> String {
    let mut line = String::new();
    if !message.tags().is_empty() {
        line.push('@');
        line.push_str(message.tags().raw_section());
        line.push(' ');
    }
    if let Some(prefix) = message.prefix() {
        line.push(':');
        line.push_str(prefix.as_str());
        line.push(' ');
    }
    match message.command() {
        ServerCommand::Named(name) => line.push_str(name),
        ServerCommand::Numeric(code) => line.push_str(&format!("{code:03}")),
    }
    for middle in message.params().middle() {
        line.push(' ');
        line.push_str(middle);
    }
    if let Some(trailing) = message.params().trailing() {
        line.push_str(" :");
        line.push_str(trailing);
    }
    line
}

/// Renders, frames and decodes one plan, and checks it against the plan.
fn round_trip(message: &WireMessage, prefix: &str) -> Result<String, Box<dyn Error>> {
    let line = framed(&rendered(message)?)?;
    let decoded = parse_server_message(agenc_relay_client_wire::ServerFramedLine::new(&line)?)?;
    let command = match decoded.command() {
        ServerCommand::Named(name) => name.to_owned(),
        ServerCommand::Numeric(code) => format!("{code:03}"),
    };
    assert_eq!(command, message.command());
    assert_eq!(decoded.prefix().map(|prefix| prefix.as_str()), Some(prefix));
    let middle: Vec<&str> = message.middle().iter().map(String::as_str).collect();
    assert_eq!(decoded.params().middle(), middle.as_slice());
    assert_eq!(decoded.params().trailing(), message.trailing());
    assert_eq!(rebuilt(&decoded), line);
    Ok(line)
}

fn capabilities() -> Result<CapabilityState, Box<dyn Error>> {
    let names = [
        "message-tags",
        "batch",
        "server-time",
        "message-ids",
        "draft/chathistory",
        "labeled-response",
        "standard-replies",
    ];
    let profile = CapabilityProfile::new(
        names
            .iter()
            .map(|name| CapabilitySpec::new(name, None))
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    let mut state = CapabilityState::default();
    let CapRequestReply::Ack(_) = state.request(&names.join(" "), &profile)? else {
        return Err("capabilities refused".into());
    };
    Ok(state)
}

fn cloak() -> Result<PublicCloak, Box<dyn Error>> {
    Ok(PublicCloak::parse("abcdefgh23", "ijklmnopqrstuv67")?)
}

/// One standard reply: its kind, operation, code, context values and the
/// context's expected text.
type ReplyCase<'a> = (
    ReplyKind,
    &'static str,
    PublicErrorCode,
    Vec<SafeReplyContext<'a>>,
    Vec<String>,
);

/// One accepted shape of every numeric the base renderer builds; 005 is
/// covered with its mandatory groups as well.
fn numeric_shapes() -> Vec<(u16, Vec<&'static str>, Option<&'static str>)> {
    let user = "u-abcdefgh23";
    let host = "h-ijklmnopqrstuv67.invalid";
    let mut shapes = vec![
        (1, vec![], Some("Welcome to the ARC network alice")),
        (2, vec![], Some("Your host is server.example")),
        (3, vec![], Some("This server was created 2026-10-04")),
        (4, vec![SERVER, "1.0.0-rc.3", "iw", "beIiklmnpst"], None),
        (
            5,
            vec!["AWAYLEN=256", "UTF8ONLY"],
            Some("are supported by this server"),
        ),
        (221, vec!["+w"], None),
        (251, vec![], Some("There are 2 users")),
        (252, vec!["0"], Some("operator(s) online")),
        (253, vec!["0"], Some("unknown connection(s)")),
        (254, vec!["3"], Some("channels formed")),
        (255, vec![], Some("I have 2 clients")),
        (
            263,
            vec!["LIST"],
            Some("Server load is temporarily too heavy"),
        ),
        (265, vec!["2", "10"], Some("Current local users 2, max 10")),
        (266, vec!["2", "10"], Some("Current global users 2, max 10")),
        (301, vec!["bob"], Some("gone fishing")),
        (302, vec![], Some("")),
        (303, vec![], Some("bob carol")),
        (305, vec![], Some("You are no longer marked as being away")),
        (306, vec![], Some("You have been marked as being away")),
        (311, vec!["bob", user, host, "*"], Some("Bob")),
        (312, vec!["bob", SERVER], Some("ARC")),
        (314, vec!["bob", user, host, "*"], Some("*")),
        (315, vec!["#c"], Some("End of /WHO list")),
        (318, vec!["bob"], Some("End of /WHOIS list")),
        (319, vec!["bob"], Some("")),
        (321, vec!["Channel"], Some("Users  Name")),
        (322, vec!["#c", "2"], Some("")),
        (323, vec![], Some("End of /LIST")),
        (324, vec!["#c", "+nt"], None),
        (329, vec!["#c", "1700000000"], None),
        (331, vec!["#c"], Some("No topic is set")),
        (332, vec!["#c"], Some("a topic: with a colon")),
        (333, vec!["#c", "bob", "1700000000"], None),
        (341, vec!["bob", "#c"], None),
        (346, vec!["#c", "*!*@h-ijklmnopqrstuv67.invalid"], None),
        (347, vec!["#c"], Some("End of channel invite list")),
        (348, vec!["#c", "*!*@*"], None),
        (349, vec!["#c"], Some("End of channel exception list")),
        (
            352,
            vec!["#c", user, host, SERVER, "bob", "H"],
            Some("0 Bob"),
        ),
        (353, vec!["=", "#c"], Some("@bob alice")),
        (366, vec!["#c"], Some("End of /NAMES list")),
        (367, vec!["#c", "*!*@*", "alice", "1700000000"], None),
        (368, vec!["#c"], Some("End of channel ban list")),
        (369, vec!["bob"], Some("End of WHOWAS")),
        (371, vec![], Some("ARC relay")),
        (372, vec![], Some("- the message of the day")),
        (374, vec![], Some("End of INFO list")),
        (375, vec![], Some("- server.example Message of the day -")),
        (376, vec![], Some("End of /MOTD command")),
        (391, vec![SERVER], Some("Sunday October 4 2026")),
        (409, vec![], Some("No origin specified")),
        (411, vec![], Some("No recipient given")),
        (412, vec![], Some("No text to send")),
        (417, vec![], Some("Input line was too long")),
        (421, vec!["FOO"], Some("Unknown command")),
        (422, vec![], Some("MOTD File is missing")),
        (431, vec![], Some("No nickname given")),
        (432, vec!["1bad"], Some("Erroneous nickname")),
        (433, vec!["bob"], Some("Nickname is already in use")),
        (441, vec!["bob", "#c"], Some("They aren't on that channel")),
        (442, vec!["#c"], Some("You're not on that channel")),
        (443, vec!["bob", "#c"], Some("is already on channel")),
        (451, vec![], Some("You have not registered")),
        (461, vec!["JOIN"], Some("Not enough parameters")),
        (462, vec![], Some("You may not reregister")),
        (464, vec![], Some("Password incorrect")),
        (465, vec![], Some("You are banned from this server")),
        (472, vec!["x"], Some("is unknown mode char to me")),
        (481, vec![], Some("Permission Denied")),
        (483, vec![], Some("You can't kill a server")),
        (501, vec![], Some("Unknown MODE flag")),
        (502, vec![], Some("Cant change mode for other users")),
        (
            730,
            vec![],
            Some("bob!u-abcdefgh23@h-ijklmnopqrstuv67.invalid"),
        ),
        (731, vec![], Some("bob")),
        (732, vec![], Some("bob")),
        (733, vec![], Some("End of MONITOR list")),
        (734, vec!["100", "bob,carol"], Some("Monitor list is full")),
        (
            900,
            vec!["alice!u-abcdefgh23@h-ijklmnopqrstuv67.invalid", "heron"],
            Some("You are now logged in"),
        ),
        (
            908,
            vec!["AGENC-OPAQUE"],
            Some("are available SASL mechanisms"),
        ),
    ];
    for code in 401..=407 {
        shapes.push((code, vec!["bob"], Some("No such target")));
    }
    for code in [471, 473, 474, 475, 476, 477, 482] {
        shapes.push((code, vec!["#c"], Some("Cannot join channel")));
    }
    for code in 903..=907 {
        shapes.push((code, vec![], Some("SASL")));
    }
    shapes
}

#[test]
fn every_numeric_the_renderer_builds_decodes_as_rendered() -> TestResult {
    let shapes = numeric_shapes();
    let mut covered: Vec<u16> = shapes.iter().map(|(code, _, _)| *code).collect();
    covered.sort_unstable();
    covered.dedup();
    assert_eq!(covered.len(), shapes.len(), "one shape per numeric");
    // Every registered numeric but 901 and 902, which the base renderer has
    // no shape for; the decoder accepts them like any registered numeric.
    let mut renderable: Vec<u16> = SERVER_NUMERICS
        .iter()
        .copied()
        .filter(|code| !matches!(code, 901 | 902))
        .collect();
    renderable.sort_unstable();
    assert_eq!(covered, renderable);
    for code in [901, 902] {
        assert_eq!(
            numeric_reply(SERVER, code, TARGET, &[], Some("text")).err(),
            Some(RenderError::InapplicableReply)
        );
    }
    for (code, middle, trailing) in shapes {
        let message = numeric_reply(SERVER, code, TARGET, &middle, trailing)?;
        round_trip(&message, SERVER)?;
    }
    Ok(())
}

#[test]
fn the_mandatory_isupport_groups_decode_token_for_token() -> TestResult {
    let messages = isupport_messages(SERVER, TARGET, "ARC", &NetworkId::from_bytes([7; 32]))?;
    assert_eq!(messages.len(), 3);
    let mut tokens = Vec::new();
    for message in &messages {
        let line = round_trip(message, SERVER)?;
        let decoded = parse_server_message(agenc_relay_client_wire::ServerFramedLine::new(&line)?)?;
        assert_eq!(decoded.command(), ServerCommand::Numeric(5));
        assert_eq!(
            decoded.params().trailing(),
            Some("are supported by this server")
        );
        tokens.extend(
            decoded
                .params()
                .middle()
                .iter()
                .skip(1)
                .map(|token| (*token).to_owned()),
        );
    }
    for required in [
        "CHANTYPES=#&",
        "PREFIX=(qaohv)~&@%+",
        "STATUSMSG=@+",
        "UTF8ONLY",
        "NETWORK=ARC",
    ] {
        assert!(tokens.iter().any(|token| token == required), "{required}");
    }
    let network = format!("AGENCNET={}", URL_SAFE_NO_PAD.encode([7_u8; 32]));
    assert!(tokens.contains(&network));
    Ok(())
}

#[test]
fn every_public_standard_reply_shape_decodes() -> TestResult {
    let caps = capabilities()?;
    let channel = ChannelName::parse("#garden")?;
    let account = AccountId::from_random(AccountRandomId::from_bytes([3; 16]));
    let epoch = RecoveryEpoch::from_bytes([4; 16]);
    let token = AccountDeletionToken::from_bytes([5; 16]);
    let description = SafeReplyDescription::new("A fixed public description")?;
    let channel_text = "#garden".to_owned();
    let account_text = format!("a_{}", URL_SAFE_NO_PAD.encode([3_u8; 16]));
    let epoch_text = URL_SAFE_NO_PAD.encode([4_u8; 16]);
    let token_text = URL_SAFE_NO_PAD.encode([5_u8; 16]);
    let cases: Vec<ReplyCase<'_>> = vec![
        (
            ReplyKind::Fail,
            "*",
            PublicErrorCode::REGISTRATIONREQUIRED,
            vec![],
            vec![],
        ),
        (
            ReplyKind::Fail,
            "NOTICE",
            PublicErrorCode::INVALIDARGUMENT,
            vec![],
            vec![],
        ),
        (
            ReplyKind::Fail,
            "ACCT",
            PublicErrorCode::BADSTATE,
            vec![],
            vec![],
        ),
        (
            ReplyKind::Fail,
            "JOIN",
            PublicErrorCode::E2EEREQUIRED,
            vec![],
            vec![],
        ),
        (
            ReplyKind::Fail,
            "JOIN",
            PublicErrorCode::E2EEREQUIRED,
            vec![SafeReplyContext::Channel(&channel)],
            vec![channel_text.clone()],
        ),
        (
            ReplyKind::Fail,
            "PRIVMSG",
            PublicErrorCode::E2EEREQUIRED,
            vec![SafeReplyContext::Channel(&channel)],
            vec![channel_text.clone()],
        ),
        (
            ReplyKind::Fail,
            "WHO",
            PublicErrorCode::NETWORKUNAVAILABLE,
            vec![],
            vec![],
        ),
        (
            ReplyKind::Fail,
            "JOIN",
            PublicErrorCode::NETWORKUNAVAILABLE,
            vec![SafeReplyContext::Channel(&channel)],
            vec![channel_text.clone()],
        ),
        (
            ReplyKind::Fail,
            "LIST",
            PublicErrorCode::QUERYEXPIRED,
            vec![],
            vec![],
        ),
        (
            ReplyKind::Fail,
            "TOPIC",
            PublicErrorCode::SECRETUNAVAILABLE,
            vec![SafeReplyContext::Channel(&channel)],
            vec![channel_text.clone()],
        ),
        (
            ReplyKind::Fail,
            "PRIVMSG",
            PublicErrorCode::SERVERBUSY,
            vec![],
            vec![],
        ),
        (
            ReplyKind::Fail,
            "AUTHENTICATE",
            PublicErrorCode::UNAVAILABLE,
            vec![],
            vec![],
        ),
        (
            ReplyKind::Fail,
            "PRIVMSG",
            PublicErrorCode::UNSAFECTCP,
            vec![],
            vec![],
        ),
        (
            ReplyKind::Note,
            "ACCTCRED",
            PublicErrorCode::CHANGED,
            vec![],
            vec![],
        ),
        (
            ReplyKind::Note,
            "ACCTCREATE",
            PublicErrorCode::CREATED,
            vec![SafeReplyContext::AccountId(account)],
            vec![account_text],
        ),
        (
            ReplyKind::Note,
            "*",
            PublicErrorCode::RECOVERYEPOCH,
            vec![SafeReplyContext::RecoveryEpoch(epoch)],
            vec![epoch_text],
        ),
        (
            ReplyKind::Note,
            "ACCT",
            PublicErrorCode::UPDATED,
            vec![],
            vec![],
        ),
        (
            ReplyKind::Note,
            "ACCT",
            PublicErrorCode::DELETECHALLENGE,
            vec![SafeReplyContext::DeletionChallenge(&token)],
            vec![token_text],
        ),
        (
            ReplyKind::Note,
            "CHANCTL",
            PublicErrorCode::UPDATED,
            vec![SafeReplyContext::Channel(&channel)],
            vec![channel_text],
        ),
    ];
    for (kind, operation, code, context, context_text) in cases {
        let message = standard_reply(&caps, SERVER, kind, operation, code, &context, description)?;
        let line = round_trip(&message, SERVER)?;
        let decoded = parse_server_message(agenc_relay_client_wire::ServerFramedLine::new(&line)?)?;
        let mut expected = vec![operation.to_owned(), code.as_str().to_owned()];
        expected.extend(context_text);
        assert_eq!(decoded.params().middle(), expected.as_slice());
    }
    let warning = slow_consumer_warning(&caps, SERVER)?.ok_or("no warning")?;
    let line = round_trip(&warning, SERVER)?;
    assert_eq!(
        line,
        ":server.example WARN * SLOW_CONSUMER :Output queue nearing capacity"
    );
    Ok(())
}

#[test]
fn labeled_responses_decode_with_their_label_and_batch() -> TestResult {
    let caps = capabilities()?;
    let label = "req-1_a";

    // No reply: one labeled ACK.
    let acknowledgement = labeled_response(&caps, SERVER, Some(label), Some("b1"), Vec::new())?;
    let [ack] = acknowledgement.messages() else {
        return Err("not one ACK".into());
    };
    let line = round_trip(ack, SERVER)?;
    let decoded = parse_server_message(agenc_relay_client_wire::ServerFramedLine::new(&line)?)?;
    assert_eq!(decoded.command(), ServerCommand::Named("ACK"));
    assert_eq!(decoded.tags().label(), Some(label));

    // One reply: the label on the reply itself.
    let one = labeled_response(
        &caps,
        SERVER,
        Some(label),
        Some("b1"),
        vec![numeric_reply(SERVER, 391, TARGET, &[SERVER], Some("now"))?],
    )?;
    let [reply] = one.messages() else {
        return Err("not one reply".into());
    };
    let line = round_trip(reply, SERVER)?;
    let decoded = parse_server_message(agenc_relay_client_wire::ServerFramedLine::new(&line)?)?;
    assert_eq!(decoded.tags().label(), Some(label));
    assert_eq!(decoded.tags().batch(), None);

    // Several replies: one labeled batch around them.
    let semantic = vec![
        numeric_reply(SERVER, 375, TARGET, &[], Some("- MOTD -"))?,
        numeric_reply(SERVER, 372, TARGET, &[], Some("- line"))?,
        numeric_reply(SERVER, 376, TARGET, &[], Some("End of /MOTD command"))?,
    ];
    let many = labeled_response(&caps, SERVER, Some(label), Some("motd-1"), semantic)?;
    let messages = many.messages();
    assert_eq!(messages.len(), 5);
    let mut lines = Vec::new();
    for message in messages {
        lines.push(round_trip(message, SERVER)?);
    }
    let decoded: Vec<ServerMessage<'_>> = lines
        .iter()
        .map(|line| {
            parse_server_message(agenc_relay_client_wire::ServerFramedLine::new(line)?)
                .map_err(Into::into)
        })
        .collect::<Result<_, Box<dyn Error>>>()?;
    let opener = decoded.first().ok_or("opener")?;
    assert_eq!(opener.command(), ServerCommand::Named("BATCH"));
    assert_eq!(opener.params().all(), ["+motd-1", "labeled-response"]);
    assert_eq!(opener.tags().label(), Some(label));
    for child in decoded.get(1..4).ok_or("children")? {
        assert_eq!(child.tags().batch(), Some("motd-1"));
        assert_eq!(child.tags().label(), None);
    }
    let close = decoded.last().ok_or("close")?;
    assert_eq!(close.params().all(), ["-motd-1"]);
    assert!(close.tags().is_empty());
    Ok(())
}

#[test]
fn nested_batches_decode_with_their_parent_references() -> TestResult {
    let caps = capabilities()?;
    let mut stack = BatchStack::default();
    let history = stack.open_history(&caps, SERVER, "h1", "#garden")?;
    let mask = user_mask("bob", &cloak()?)?;
    let mut replayed = WireMessage::new(&mask, "PRIVMSG", &["#garden"], Some("old news"))?;
    stack.attach("h1", &mut replayed)?;
    let inner = stack.open(&caps, SERVER, "inner-2", "req-9")?;
    let mut inner_reply = numeric_reply(SERVER, 391, TARGET, &[SERVER], Some("now"))?;
    stack.attach("inner-2", &mut inner_reply)?;
    let inner_close = stack.close(SERVER, "inner-2")?;
    let history_close = stack.close(SERVER, "h1")?;

    let opened = round_trip(&history, SERVER)?;
    assert_eq!(opened, ":server.example BATCH +h1 chathistory #garden");
    let line = round_trip(&replayed, &mask)?;
    let decoded = parse_server_message(agenc_relay_client_wire::ServerFramedLine::new(&line)?)?;
    assert_eq!(decoded.tags().batch(), Some("h1"));
    let Some(ServerPrefix::User(user)) = decoded.prefix() else {
        return Err("no user prefix".into());
    };
    assert!(user.cloak() == cloak()?);
    let line = round_trip(&inner, SERVER)?;
    let decoded = parse_server_message(agenc_relay_client_wire::ServerFramedLine::new(&line)?)?;
    assert_eq!(decoded.tags().label(), Some("req-9"));
    assert_eq!(decoded.tags().batch(), Some("h1"));
    let line = round_trip(&inner_reply, SERVER)?;
    let decoded = parse_server_message(agenc_relay_client_wire::ServerFramedLine::new(&line)?)?;
    assert_eq!(decoded.tags().batch(), Some("inner-2"));
    let line = round_trip(&inner_close, SERVER)?;
    assert_eq!(line, "@batch=h1 :server.example BATCH -inner-2");
    assert_eq!(
        round_trip(&history_close, SERVER)?,
        ":server.example BATCH -h1"
    );
    Ok(())
}

#[test]
fn server_and_relayed_client_tags_decode_raw_and_unescape_to_their_values() -> TestResult {
    let caps = capabilities()?;
    let mask = user_mask("alice", &cloak()?)?;
    let mut message = WireMessage::new(&mask, "PRIVMSG", &["#garden"], Some("hello: world"))?;
    message.add_server_tag("time", Some("2026-10-04T00:00:00.000Z"))?;
    message.add_server_tag("msgid", Some("AAAAAAAAAAAAAAAAAAAAAA"))?;
    message.add_server_tag("account", Some("heron"))?;
    message.add_client_only_tag(&caps, "+typing", Some("active"))?;
    message.add_client_only_tag(&caps, "+example.com/note", Some("a b;c\\d\r\n"))?;
    message.add_client_only_tag(&caps, "+flag", None)?;
    let line = round_trip(&message, &mask)?;
    let decoded = parse_server_message(agenc_relay_client_wire::ServerFramedLine::new(&line)?)?;
    let tags = decoded.tags();
    assert_eq!(tags.len(), 6);
    assert_eq!(tags.client_only_count(), 3);
    let keys: Vec<&str> = tags.iter().map(|tag| tag.key()).collect();
    assert_eq!(
        keys,
        [
            "account",
            "msgid",
            "time",
            "+example.com/note",
            "+flag",
            "+typing"
        ]
    );
    let note = tags.get("+example.com/note").ok_or("note")?;
    assert_eq!(note.raw_value(), Some("a\\sb\\:c\\\\d\\r\\n"));
    assert_eq!(note.unescaped_value()?.as_deref(), Some("a b;c\\d\r\n"));
    assert_eq!(tags.get("+flag").ok_or("flag")?.raw_value(), None);
    assert_eq!(
        tags.get("time")
            .ok_or("time")?
            .unescaped_value()?
            .as_deref(),
        Some("2026-10-04T00:00:00.000Z")
    );

    // A relayed E2EE fragment beyond the ordinary value budget.
    let fragment = format!("v1.{}", "A".repeat(3_000));
    let mut tagmsg = WireMessage::new(&mask, "TAGMSG", &["#garden"], None)?;
    tagmsg.add_client_only_tag(&caps, "+agenc.ag/e2ee", Some(&fragment))?;
    let line = round_trip(&tagmsg, &mask)?;
    let decoded = parse_server_message(agenc_relay_client_wire::ServerFramedLine::new(&line)?)?;
    assert_eq!(
        decoded
            .tags()
            .get("+agenc.ag/e2ee")
            .ok_or("fragment")?
            .raw_value(),
        Some(fragment.as_str())
    );
    Ok(())
}

#[test]
fn the_longest_user_mask_decodes_to_its_cloak() -> TestResult {
    let nickname = "n".repeat(MAX_NICKNAME_BYTES);
    let mask = user_mask(&nickname, &cloak()?)?;
    assert_eq!(mask.len(), MAX_USER_MASK_BYTES);
    let message = WireMessage::new(&mask, "QUIT", &[], Some("connection closed"))?;
    let line = round_trip(&message, &mask)?;
    let decoded = parse_server_message(agenc_relay_client_wire::ServerFramedLine::new(&line)?)?;
    let Some(ServerPrefix::User(user)) = decoded.prefix() else {
        return Err("no user prefix".into());
    };
    assert_eq!(user.nickname(), nickname);
    assert!(user.cloak() == cloak()?);
    Ok(())
}

/// The companion profile's lines (E2EE 11.7) are rendered through
/// `WireMessage::extension_line`, the one bypass of the base command table.
/// The base decoder keeps to the base registries: it refuses the companion
/// commands and codes, which `agenc_relay_e2ee::wire` reads, and accepts a
/// relayed `TAGMSG`, which is a base command.
#[test]
fn companion_lines_are_left_to_the_e2ee_parsers() -> TestResult {
    let hash = "A".repeat(43);
    for (line, expected) in [
        (
            format!("@label=a1 :{SERVER} EGROUP BOUND {hash} {hash}"),
            ServerMessageError::UnregisteredCommand,
        ),
        (
            format!(":{SERVER} EKEY EMPTY ROSTER"),
            ServerMessageError::UnregisteredCommand,
        ),
        (
            format!(
                ":{SERVER} FAIL EGROUP E2EE_INVALID_FRAGMENT :fragment grammar, encoding, or consistency failed"
            ),
            ServerMessageError::UnregisteredReplyCode,
        ),
    ] {
        let message = WireMessage::extension_line(&line)?;
        let framed_line = framed(&rendered(&message)?)?;
        assert_eq!(framed_line, line);
        assert_eq!(
            parse_server_message(agenc_relay_client_wire::ServerFramedLine::new(
                &framed_line
            )?)
            .err(),
            Some(expected),
            "{line}"
        );
    }
    let mask = user_mask("alice", &cloak()?)?;
    let relayed = format!("@+agenc.ag/e2ee=v1.{hash}.0.1.3.AAAA :{mask} TAGMSG #garden");
    let message = WireMessage::extension_line(&relayed)?;
    assert_eq!(round_trip(&message, &mask)?, relayed);
    Ok(())
}
