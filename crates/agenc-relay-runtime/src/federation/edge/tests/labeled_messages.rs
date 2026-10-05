#![forbid(unsafe_code)]

//! A labeled `PRIVMSG`, `NOTICE` or `TAGMSG` sent through an edge gets
//! exactly one labeled logical response, the one the coordinator gives its
//! own client with the same capabilities (Architecture 2.1 and 9.5; IRCv3
//! `labeled-response` with `echo-message`): with `echo-message` its echo,
//! or one labeled batch of its echoes when it named several targets, and
//! otherwise a labeled `ACK`. Every other recipient's copy carries no label.

use super::*;

/// One capability set the requesters negotiate.
struct CapabilitySet {
    name: &'static str,
    request: &'static str,
    labeled: bool,
    echo: bool,
    tags: bool,
}

/// `labeled-response` without `echo-message`, with it, with it but without
/// `message-tags` (a `TAGMSG` reaches no client without `message-tags`, its
/// sender included), and `echo-message` without `labeled-response`.
const CAPABILITY_SETS: [CapabilitySet; 4] = [
    CapabilitySet {
        name: "ack",
        request: "message-tags batch labeled-response",
        labeled: true,
        echo: false,
        tags: true,
    },
    CapabilitySet {
        name: "echo",
        request: "message-tags batch labeled-response echo-message",
        labeled: true,
        echo: true,
        tags: true,
    },
    CapabilitySet {
        name: "untagged",
        request: "batch labeled-response echo-message",
        labeled: true,
        echo: true,
        tags: false,
    },
    CapabilitySet {
        name: "unlabeled",
        request: "echo-message",
        labeled: false,
        echo: true,
        tags: false,
    },
];

/// The messages each requester sends: `<peer>` is the other requester,
/// `<local>` a client of the requester's own node, and the client-only tag,
/// when there is one, follows the label.
const MESSAGES: [(Option<&str>, &str); 12] = [
    (None, "PRIVMSG #cmp :hello"),
    (None, "PRIVMSG <peer> :hello"),
    (None, "PRIVMSG <local> :hello"),
    (None, "PRIVMSG #cmp,#two :hello"),
    (None, "PRIVMSG #cmp,<peer> :hello"),
    (None, "NOTICE #cmp :hello"),
    (None, "NOTICE <peer> :hello"),
    (None, "NOTICE <local> :hello"),
    (None, "NOTICE #cmp,#two :hello"),
    (None, "NOTICE #cmp,<peer> :hello"),
    (Some("+typing=active"), "TAGMSG #cmp"),
    (Some("+typing=active"), "TAGMSG <peer>"),
];

/// The other member on the edge, which negotiated `message-tags`, and the
/// other client of the coordinator, which operates `#order`, whose topic
/// orders each exchange; each is `<local>` to the requester on its node.
const EDGE_MEMBER: &str = "ben";
const HUB_NOTIFIER: &str = "dan";

/// Each capability set has its own pair of requesters, one on the edge and
/// one on the coordinator, so that no guest message budget runs out.
#[tokio::test]
async fn an_edge_gives_a_labeled_message_the_coordinators_one_labeled_response() -> TestResult {
    run_bridge(|hub_inbox, edge_inbox| async move {
        let mut ben = register_when_available(&edge_inbox, 2, EDGE_MEMBER, None).await?;
        let mut dan = Client::open(hub_inbox.clone(), 2).await?;
        register(&mut dan, HUB_NOTIFIER).await?;
        request_capabilities(&mut ben, "message-tags").await?;
        join(&mut ben, EDGE_MEMBER).await?;
        dan.line("JOIN #order").await?;
        dan.wait_for(&format!(" 366 {HUB_NOTIFIER} #order "))
            .await?;
        ben.line("JOIN #order").await?;
        ben.wait_for(&format!(" 366 {EDGE_MEMBER} #order ")).await?;
        let mut exchange = 0;
        for (index, set) in (10_u64..).zip(CAPABILITY_SETS.iter()) {
            let names = (format!("eve{index}"), format!("cal{index}"));
            let mut eve = Client::open(edge_inbox.clone(), index).await?;
            register(&mut eve, &names.0).await?;
            let mut cal = Client::open(hub_inbox.clone(), index).await?;
            register(&mut cal, &names.1).await?;
            for (client, nickname) in [(&mut eve, &names.0), (&mut cal, &names.1)] {
                request_capabilities(client, set.request).await?;
                join(client, nickname).await?;
            }
            for (tags, command) in MESSAGES {
                exchange += 1;
                let label = format!("l{exchange}");
                let mut clients = Clients {
                    eve: &mut eve,
                    cal: &mut cal,
                    ben: &mut ben,
                    dan: &mut dan,
                    names: (&names.0, &names.1),
                };
                let on_edge = clients
                    .exchange(Side::Edge, &label, (tags, command), set)
                    .await?;
                let on_hub = clients
                    .exchange(Side::Hub, &label, (tags, command), set)
                    .await?;
                assert_eq!(on_edge, on_hub, "{}: {command}", set.name);
            }
        }
        Ok(())
    })
    .await
}

/// Which requester sends.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Side {
    Edge,
    Hub,
}

struct Clients<'a> {
    eve: &'a mut Client,
    cal: &'a mut Client,
    ben: &'a mut Client,
    dan: &'a mut Client,
    /// The requesters on the edge and on the coordinator.
    names: (&'a str, &'a str),
}

impl Clients<'_> {
    /// Sends `command` labeled `label` from one requester and returns its
    /// response with the server, the requester and its peer written as
    /// placeholders, after checking that every other recipient's copy
    /// arrived without a label.
    async fn exchange(
        &mut self,
        side: Side,
        label: &str,
        message: (Option<&str>, &str),
        set: &CapabilitySet,
    ) -> TestResult<Vec<String>> {
        let (tags, command) = message;
        let (me, peer, local) = match side {
            Side::Edge => (self.names.0, self.names.1, EDGE_MEMBER),
            Side::Hub => (self.names.1, self.names.0, HUB_NOTIFIER),
        };
        let command = command.replace("<peer>", peer).replace("<local>", local);
        let before = Before {
            eve: self.eve.sink.lines().len(),
            cal: self.cal.sink.lines().len(),
            ben: self.ben.sink.lines().len(),
            dan: self.dan.sink.lines().len(),
        };
        let (requester, from) = match side {
            Side::Edge => (&mut *self.eve, before.eve),
            Side::Hub => (&mut *self.cal, before.cal),
        };
        let tag_section = tags.map_or_else(String::new, |tags| format!(";{tags}"));
        requester
            .line(&format!("@label={label}{tag_section} {command}"))
            .await?;
        let tagmsg = command.starts_with("TAGMSG");
        // As on the coordinator, the sender of a direct message is not among
        // its recipients, so only its channel targets echo.
        let echoes = if set.echo && (set.tags || !tagmsg) {
            channel_targets(&command)
        } else {
            0
        };
        let response = if set.labeled {
            labeled_response(requester, from, label).await?
        } else {
            Vec::new()
        };
        requester.line(&format!("PING :after-{label}")).await?;
        requester.wait_for(&format!(":after-{label}")).await?;
        // The coordinator orders the notifier's topic after the message and
        // the edge applies events in order, so once the member on the edge
        // holds it, every line about the message has reached every client.
        let marker = match side {
            Side::Edge => format!("after-{label}-edge"),
            Side::Hub => format!("after-{label}-hub"),
        };
        self.dan.line(&format!("TOPIC #order :{marker}")).await?;
        wait_after(self.ben, before.ben, &format!(" TOPIC #order :{marker}")).await?;
        let requester = match side {
            Side::Edge => &*self.eve,
            Side::Hub => &*self.cal,
        };
        let lines: Vec<String> = requester.sink.lines().into_iter().skip(from).collect();
        // The requester's own copies, labeled or not, are its echoes and
        // nothing more, in every capability set.
        let verb = command.split(' ').next().unwrap_or_default();
        let own: Vec<&String> = lines
            .iter()
            .filter(|line| source_is(line, me) && line.contains(&format!(" {verb} ")))
            .collect();
        assert_eq!(
            own.len(),
            echoes,
            "{command}: the requester's own copies: {lines:?}"
        );
        let labeled = lines
            .iter()
            .filter(|line| has_tag(line, "label", label))
            .count();
        assert_eq!(
            labeled,
            usize::from(set.labeled),
            "{command}: one labeled logical response: {lines:?}"
        );
        if set.labeled {
            let echoed = response.iter().filter(|line| source_is(line, me)).count();
            assert_eq!(echoed, echoes, "{command}: {response:?}");
            // One echo is labeled itself, several share one labeled batch,
            // and none leaves a labeled ACK.
            let expected = match echoes {
                0 | 1 => 1,
                several => several + 2,
            };
            assert_eq!(response.len(), expected, "{command}: {response:?}");
            if echoes == 0 {
                assert!(
                    response.iter().all(|line| line.ends_with(" ACK")),
                    "{command}: {response:?}"
                );
            }
        }
        self.check_copies(side, &command, set, &before).await?;
        let compared: Vec<&String> = if set.labeled {
            response.iter().collect()
        } else {
            own
        };
        Ok(compared
            .into_iter()
            .map(|line| normalized(line, [(me, "<me>"), (peer, "<peer>"), (local, "<local>")]))
            .collect())
    }

    /// Requires every other recipient's copy, and that none of the lines the
    /// others received during the exchange carries a label or a batch, and
    /// that a `TAGMSG` reached no recipient without `message-tags`. It runs
    /// after the exchange's ordering `AWAY`, so every copy has arrived.
    async fn check_copies(
        &mut self,
        side: Side,
        command: &str,
        set: &CapabilitySet,
        before: &Before,
    ) -> TestResult {
        let tagmsg = command.starts_with("TAGMSG");
        let mut parts = command.split(' ');
        let verb = parts.next().unwrap_or_default();
        let targets: Vec<&str> = parts.next().unwrap_or_default().split(',').collect();
        let (peer, peer_from, peer_name) = match side {
            Side::Edge => (&*self.cal, before.cal, self.names.1),
            Side::Hub => (&*self.eve, before.eve, self.names.0),
        };
        let mut peer_copies = Vec::new();
        let mut member_copies = Vec::new();
        for channel in targets.iter().filter(|target| target.starts_with('#')) {
            peer_copies.push(format!(" {verb} {channel}"));
            member_copies.push(format!(" {verb} {channel}"));
        }
        if targets.contains(&peer_name) {
            peer_copies.push(format!(" {verb} {peer_name}"));
        }
        if targets.contains(&EDGE_MEMBER) {
            member_copies.push(format!(" {verb} {EDGE_MEMBER}"));
        }
        if targets.contains(&HUB_NOTIFIER) {
            wait_after(self.dan, before.dan, &format!(" {verb} {HUB_NOTIFIER}")).await?;
        }
        let peer_receives = set.tags || !tagmsg;
        for copy in &member_copies {
            wait_after(self.ben, before.ben, copy).await?;
        }
        if peer_receives {
            for copy in &peer_copies {
                wait_after(peer, peer_from, copy).await?;
            }
        }
        for (client, from, absent) in [
            (peer, peer_from, (!peer_receives).then_some(&peer_copies)),
            (&*self.ben, before.ben, None),
            (&*self.dan, before.dan, None),
        ] {
            let lines: Vec<String> = client.sink.lines().into_iter().skip(from).collect();
            assert!(
                lines
                    .iter()
                    .all(|line| !line.contains("label=") && !line.contains("batch=")),
                "{command}: another recipient's copy is labeled: {lines:?}"
            );
            if let Some(copies) = absent {
                assert!(
                    lines
                        .iter()
                        .all(|line| !copies.iter().any(|copy| line.contains(copy.as_str()))),
                    "{command}: a TAGMSG reached a client without message-tags: {lines:?}"
                );
            }
        }
        Ok(())
    }
}

/// Where each client's lines stood before an exchange.
struct Before {
    eve: usize,
    cal: usize,
    ben: usize,
    dan: usize,
}

/// Joins `#cmp` and `#two` and waits for the end of their NAMES replies.
async fn join(client: &mut Client, nickname: &str) -> TestResult {
    client.line("JOIN #cmp,#two").await?;
    client.wait_for(&format!(" 366 {nickname} #two ")).await?;
    Ok(())
}

/// Requests `request` and requires its `ACK`.
async fn request_capabilities(client: &mut Client, request: &str) -> TestResult {
    let before = client.sink.lines().len();
    client.line(&format!("CAP REQ :{request}")).await?;
    for _ in 0..5_000 {
        let lines: Vec<String> = client.sink.lines().into_iter().skip(before).collect();
        if lines.iter().any(|line| line.contains(" ACK :")) {
            return Ok(());
        }
        if lines.iter().any(|line| line.contains(" NAK :")) {
            return Err(format!("CAP REQ :{request} refused: {lines:?}").into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    Err(format!("CAP REQ :{request} unanswered: {:?}", client.sink.lines()).into())
}

/// The number of channel targets of `command`.
fn channel_targets(command: &str) -> usize {
    command.split(' ').nth(1).map_or(0, |targets| {
        targets
            .split(',')
            .filter(|target| target.starts_with('#'))
            .count()
    })
}

/// Waits for a line containing `needle` after the first `before` lines.
async fn wait_after(client: &Client, before: usize, needle: &str) -> TestResult {
    for _ in 0..5_000 {
        if client
            .sink
            .lines()
            .iter()
            .skip(before)
            .any(|line| line.contains(needle))
        {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    Err(format!("never received {needle:?}: {:?}", client.sink.lines()).into())
}

/// Waits for the one logical response labeled `label`: a labeled line, or a
/// labeled batch through its end, and returns its lines in order.
async fn labeled_response(client: &Client, before: usize, label: &str) -> TestResult<Vec<String>> {
    let open = format!(" BATCH +{label} labeled-response");
    let close = format!(" BATCH -{label}");
    for _ in 0..5_000 {
        let lines: Vec<String> = client.sink.lines().into_iter().skip(before).collect();
        if let Some(first) = lines.iter().position(|line| has_tag(line, "label", label)) {
            let batched = lines.get(first).is_some_and(|line| line.ends_with(&open));
            if !batched {
                return Ok(lines.get(first..=first).unwrap_or_default().to_vec());
            }
            if let Some(last) = lines.iter().position(|line| line.ends_with(&close)) {
                let response = lines.get(first..=last).unwrap_or_default().to_vec();
                let inner = response.get(1..response.len() - 1).unwrap_or_default();
                assert!(
                    inner.iter().all(|line| has_tag(line, "batch", label)),
                    "{response:?}"
                );
                return Ok(response);
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    Err(format!("no response labeled {label}: {:?}", client.sink.lines()).into())
}

/// Whether `line` carries the tag `key=value`.
fn has_tag(line: &str, key: &str, value: &str) -> bool {
    line.strip_prefix('@')
        .and_then(|line| line.split(' ').next())
        .is_some_and(|tags| tags.split(';').any(|tag| tag == format!("{key}={value}")))
}

/// Whether the source of `line` is the user `nickname`.
fn source_is(line: &str, nickname: &str) -> bool {
    untagged_fields(line)
        .first()
        .is_some_and(|source| source.starts_with(&format!(":{nickname}!")))
}

/// `line` with the server name, each named client and any user mask
/// written as placeholders, so an edge's and a coordinator's lines compare.
fn normalized(line: &str, names: [(&str, &str); 3]) -> String {
    let name = |text: &str| -> String {
        text.split(',')
            .map(|part| {
                names
                    .iter()
                    .find(|(nickname, _)| *nickname == part)
                    .map_or(part, |(_, placeholder)| *placeholder)
            })
            .collect::<Vec<_>>()
            .join(",")
    };
    let mut fields = Vec::new();
    let mut rest = line;
    if line.starts_with('@')
        && let Some((tags, after)) = line.split_once(' ')
    {
        fields.push(tags.to_owned());
        rest = after;
    }
    let (head, trailing) = match rest.split_once(" :") {
        Some((head, trailing)) => (head, Some(trailing)),
        None => (rest, None),
    };
    for (index, field) in head.split(' ').enumerate() {
        let field = if index == 0 {
            match field.strip_prefix(':') {
                Some(EDGE_NAME | HUB_NAME) => ":<server>".to_owned(),
                Some(source) => match source.split_once('!') {
                    Some((nickname, _)) => format!(":{}!<cloak>", name(nickname)),
                    None => format!(":{}", name(source)),
                },
                None => name(field),
            }
        } else {
            name(field)
        };
        fields.push(field);
    }
    let mut text = fields.join(" ");
    if let Some(trailing) = trailing {
        text.push_str(" :");
        text.push_str(trailing);
    }
    text
}

/// Registers `quinn` through the scripted coordinator and joins it to
/// `#edge`, answering the JOIN's NAMES query, and returns the client with
/// its user and the channel.
async fn scripted_member(
    hub: &mut Hub,
    inbox: mpsc::Sender<StateCoreMessage>,
) -> TestResult<(Client, UserId, (ChannelInstanceId, u64))> {
    let mut client = Client::open(inbox, 1).await?;
    hub.ack_origin().await?;
    client.line("NICK quinn").await?;
    client.line("USER quinn 0 * :Quinn Real").await?;
    let (header, _, bytes) = hub.next_request().await?;
    let session_id = SessionId::from_bytes([61; 16]);
    let user_id = UserId::from_bytes([62; 16]);
    hub.state_generation += 1;
    let generation = hub.state_generation;
    hub.event(
        &ProjectedEvent::SessionVisible(SessionEventView {
            source: source(user_id, "quinn", 1)?,
            home_projection: Some(session_record(session_id, user_id, "quinn", generation, 1)?),
        }),
        None,
    )
    .await?;
    let completion = hub
        .event(
            &ProjectedEvent::RequestCompleted {
                resulting_state_generation: generation,
            },
            Some(correlation(&header)),
        )
        .await?;
    hub.result(
        &header,
        &bytes,
        &ResultArm::SessionRegistered(SessionRegistered {
            session_id,
            user_id,
            session_revision: generation,
            account: None,
            resulting_state_generation: generation,
        }),
        Vec::new(),
        Some(completion),
    )
    .await?;
    client.wait_for(" 001 quinn ").await?;
    hub.ack_origin().await?;
    client.line("JOIN #edge").await?;
    let (header, _, bytes) = hub.next_request().await?;
    let channel_id = ChannelInstanceId::from_bytes([63; 16]);
    hub.state_generation += 1;
    let generation = hub.state_generation;
    hub.event(
        &ProjectedEvent::ChannelVisible(ChannelDetailRecord {
            channel_id,
            name: ChannelNameValue::parse("#edge")?,
            channel_revision: Revision::new(generation)?,
            visibility: Visibility::Listed,
            content_policy: ContentPolicy::Plaintext,
            persistence: PersistencePolicy::Ephemeral,
            simple_mode_bits: 4,
            history: HistoryPolicy::Off,
            e2ee_route_binding: None,
        }),
        None,
    )
    .await?;
    hub.event(
        &ProjectedEvent::MemberJoined {
            view: MembershipView {
                membership: MembershipRecord {
                    channel_id,
                    user_id,
                    role: Role::Owner,
                    membership_revision: Revision::new(generation)?,
                    joined_at: UtcSecond::from_unix_seconds(5),
                },
                source: source(user_id, "quinn", 1)?,
            },
            home_session_revision: Some(Revision::new(generation)?),
            display_name: DisplayNameValue::prepare("Quinn Real")?,
        },
        None,
    )
    .await?;
    let completion = hub
        .event(
            &ProjectedEvent::RequestCompleted {
                resulting_state_generation: generation,
            },
            Some(correlation(&header)),
        )
        .await?;
    hub.result(
        &header,
        &bytes,
        &ResultArm::Committed {
            resulting_state_generation: generation,
        },
        vec![agenc_relay_client_wire::numeric_reply(
            COORDINATOR_NAME,
            331,
            "quinn",
            &["#edge"],
            Some("No topic is set"),
        )?],
        Some(completion),
    )
    .await?;
    let (header, _, bytes) = hub.next_request().await?;
    hub.result(
        &header,
        &bytes,
        &ResultArm::ReplyPage {
            snapshot_token: [3; 32],
            page_sequence: 0,
            next_cursor: None,
        },
        vec![agenc_relay_client_wire::numeric_reply(
            COORDINATOR_NAME,
            366,
            "quinn",
            &["#edge"],
            Some("End of NAMES list"),
        )?],
        None,
    )
    .await?;
    client.wait_for(" 366 quinn #edge ").await?;
    Ok((client, user_id, (channel_id, generation)))
}

fn correlation(header: &RequestHeader) -> RequestCorrelation {
    RequestCorrelation {
        replay_key: header.replay_key,
        request_id: header.request_id,
    }
}

/// The message `text` from `user_id` to the channel, accepted at
/// `generation`; the channel kept the revision its JOIN gave it.
fn delivered(
    user_id: UserId,
    channel: (ChannelInstanceId, u64),
    generation: u64,
    text: &str,
) -> TestResult<ProjectedEvent> {
    let (channel_id, revision) = channel;
    Ok(ProjectedEvent::MessageDelivered(
        agenc_relay_domain::federation::DeliveredMessageRecord {
            message_id: agenc_relay_types::MessageId::from_bytes([64; 16]),
            kind: agenc_relay_domain::MessageKind::Privmsg,
            target: agenc_relay_domain::federation::DeliveryTarget::Channel(channel_id),
            sender: source(user_id, "quinn", 1)?,
            target_revision: Revision::new(revision)?,
            channel_event_sequence: generation,
            received_unix_milliseconds: 1,
            tags: Vec::new(),
            body: text.to_owned(),
        },
    ))
}

/// The event ID the scripted coordinator gives its event `sequence`.
fn scripted_event_id(sequence: u64) -> EventId {
    let mut id = [0_u8; 16];
    id[..8].copy_from_slice(&sequence.to_be_bytes());
    id[15] = 1;
    EventId::from_bytes(id)
}

/// The lines of `client` that contain `text`.
fn lines_with(client: &Client, text: &str) -> Vec<String> {
    client
        .sink
        .lines()
        .into_iter()
        .filter(|line| line.contains(text))
        .collect()
}

/// The requester's copy of a labeled message waits for its request to
/// complete, whether the completion or the result arrives last, and is then
/// its one labeled response; without a label it goes out with its event.
#[tokio::test]
async fn a_labeled_echo_waits_for_its_request_to_complete() -> TestResult {
    run_edge(|federation, inbox| async move {
        let mut hub = Hub::new(federation);
        hub.establish().await?;
        hub.synchronize().await?;
        let (mut quinn, user_id, channel) = scripted_member(&mut hub, inbox).await?;
        request_capabilities(
            &mut quinn,
            "message-tags batch labeled-response echo-message",
        )
        .await?;

        // The completion arrives first, then the result.
        quinn.line("@label=m1 PRIVMSG #edge :one").await?;
        let (header, _, bytes) = hub.next_request().await?;
        hub.state_generation += 1;
        let generation = hub.state_generation;
        hub.event(&delivered(user_id, channel, generation, "one")?, None)
            .await?;
        assert!(lines_with(&quinn, ":one").is_empty(), "held with its event");
        let completion = hub
            .event(
                &ProjectedEvent::RequestCompleted {
                    resulting_state_generation: generation,
                },
                Some(correlation(&header)),
            )
            .await?;
        assert!(
            lines_with(&quinn, ":one").is_empty(),
            "held until the result"
        );
        hub.result(
            &header,
            &bytes,
            &ResultArm::Committed {
                resulting_state_generation: generation,
            },
            Vec::new(),
            Some(completion),
        )
        .await?;
        quinn.wait_for(":one").await?;
        let one = lines_with(&quinn, ":one");
        assert_eq!(one.len(), 1, "{one:?}");
        assert!(
            one.iter().all(|line| line.starts_with("@label=m1 :quinn!")),
            "{one:?}"
        );

        // The result arrives first, then the events.
        quinn.line("@label=m2 PRIVMSG #edge :two").await?;
        let (header, _, bytes) = hub.next_request().await?;
        hub.state_generation += 1;
        let generation = hub.state_generation;
        hub.result(
            &header,
            &bytes,
            &ResultArm::Committed {
                resulting_state_generation: generation,
            },
            Vec::new(),
            Some(scripted_event_id(hub.next_sequence + 1)),
        )
        .await?;
        hub.event(&delivered(user_id, channel, generation, "two")?, None)
            .await?;
        assert!(
            lines_with(&quinn, ":two").is_empty(),
            "held until the completion"
        );
        hub.event(
            &ProjectedEvent::RequestCompleted {
                resulting_state_generation: generation,
            },
            Some(correlation(&header)),
        )
        .await?;
        quinn.wait_for(":two").await?;
        let two = lines_with(&quinn, ":two");
        assert_eq!(two.len(), 1, "{two:?}");
        assert!(
            two.iter().all(|line| line.starts_with("@label=m2 :quinn!")),
            "{two:?}"
        );

        // Without a label, the echo goes out with its event and the request
        // ends without a reply.
        quinn.line("PRIVMSG #edge :three").await?;
        let (header, _, bytes) = hub.next_request().await?;
        hub.state_generation += 1;
        let generation = hub.state_generation;
        hub.event(&delivered(user_id, channel, generation, "three")?, None)
            .await?;
        let three = lines_with(&quinn, ":three");
        assert_eq!(three.len(), 1, "sent with its event: {three:?}");
        let completion = hub
            .event(
                &ProjectedEvent::RequestCompleted {
                    resulting_state_generation: generation,
                },
                Some(correlation(&header)),
            )
            .await?;
        let before = quinn.sink.lines().len();
        hub.result(
            &header,
            &bytes,
            &ResultArm::Committed {
                resulting_state_generation: generation,
            },
            Vec::new(),
            Some(completion),
        )
        .await?;
        quinn.line("PING :after-three").await?;
        quinn.wait_for(":after-three").await?;
        let after: Vec<String> = quinn.sink.lines().into_iter().skip(before).collect();
        assert!(
            after
                .iter()
                .all(|line| !line.contains(" ACK") && !line.contains(":three")),
            "{after:?}"
        );
        Ok(())
    })
    .await
}

/// A copy whose event contradicts the request's result ends the link, as
/// other consistency faults do: the request's result commits at one
/// coordinator state and the event that delivers its echo names another.
#[tokio::test]
async fn a_copy_that_contradicts_its_result_ends_the_link() -> TestResult {
    run_edge(|federation, inbox| async move {
        let mut hub = Hub::new(federation);
        hub.establish().await?;
        hub.synchronize().await?;
        let (mut quinn, user_id, channel) = scripted_member(&mut hub, inbox).await?;
        request_capabilities(
            &mut quinn,
            "message-tags batch labeled-response echo-message",
        )
        .await?;
        quinn.line("@label=m1 PRIVMSG #edge :one").await?;
        let (header, _, bytes) = hub.next_request().await?;
        hub.state_generation += 1;
        let committed = hub.state_generation;
        hub.result(
            &header,
            &bytes,
            &ResultArm::Committed {
                resulting_state_generation: committed,
            },
            Vec::new(),
            Some(scripted_event_id(hub.next_sequence + 1)),
        )
        .await?;
        hub.state_generation += 1;
        let generation = hub.state_generation;
        let event = delivered(user_id, channel, generation, "one")?;
        let sequence = hub.next_sequence;
        let header = EventHeader {
            network_id: NETWORK,
            target_server_id: EDGE,
            projection_generation: 1,
            coordinator_state_generation: generation,
            delivery_sequence: sequence,
            event_id: scripted_event_id(sequence),
            event_kind: event.kind(),
            correlation: None,
            cross_profile: None,
        };
        let encoded = header
            .build(&event_arm_object(&event).map_err(|error| format!("{error:?}"))?)
            .map_err(|error| format!("{error:?}"))?
            .encode_canonical()
            .map_err(|error| format!("{error:?}"))?
            .as_slice()
            .to_vec();
        let descriptor = agenc_relay_federation_wire::EventDescriptor {
            target_server_id: EDGE,
            delivery_sequence: sequence,
            event_id: header.event_id,
            object_id: federation_object_id(&encoded),
        };
        hub.object(&encoded, |fragment| FederationFrame::Event {
            descriptor,
            fragment,
        })
        .await?;
        hub.expect_closed().await?;
        assert!(
            lines_with(&quinn, ":one").is_empty(),
            "{:?}",
            quinn.sink.lines()
        );
        Ok(())
    })
    .await
}

/// A result that contradicts a copy the request already holds ends the
/// link: the event that delivers the echo is applied first, at one
/// coordinator state, and the request's result then commits at another.
#[tokio::test]
async fn a_result_that_contradicts_a_held_copy_ends_the_link() -> TestResult {
    run_edge(|federation, inbox| async move {
        let mut hub = Hub::new(federation);
        hub.establish().await?;
        hub.synchronize().await?;
        let (mut quinn, user_id, channel) = scripted_member(&mut hub, inbox).await?;
        request_capabilities(
            &mut quinn,
            "message-tags batch labeled-response echo-message",
        )
        .await?;
        quinn.line("@label=m1 PRIVMSG #edge :one").await?;
        let (header, _, bytes) = hub.next_request().await?;
        hub.state_generation += 1;
        let generation = hub.state_generation;
        hub.event(&delivered(user_id, channel, generation, "one")?, None)
            .await?;
        assert!(lines_with(&quinn, ":one").is_empty(), "held with its event");
        hub.result(
            &header,
            &bytes,
            &ResultArm::Committed {
                resulting_state_generation: generation + 1,
            },
            Vec::new(),
            Some(scripted_event_id(hub.next_sequence)),
        )
        .await?;
        hub.expect_closed().await?;
        assert!(
            lines_with(&quinn, ":one").is_empty(),
            "{:?}",
            quinn.sink.lines()
        );
        Ok(())
    })
    .await
}
