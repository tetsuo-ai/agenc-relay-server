#![forbid(unsafe_code)]

//! The information queries an edge answers itself (Sections 14, 20.5.2 and
//! 20.10): `MOTD`, `LUSERS`, `VERSION`, `TIME`, `ADMIN` and `INFO`, plain and
//! labeled, while the coordinator link is active and while it is down, each
//! after the requests the connection sent before it.

use super::*;

/// The state core's server name in the edge fixture, the source of every
/// reply the edge renders itself. (The fixture's registration router uses
/// `edge.example` for the welcome; a daemon uses its one configured server
/// name for both, which the coordinator-and-edge daemon test checks.)
const LOCAL_SERVER: &str = "server.example";

/// Each query with the numeric that ends its reply on an edge whose
/// configuration holds no MOTD or public information.
const QUERIES: [(&str, &str); 6] = [
    ("MOTD", " 422 "),
    ("LUSERS", " 266 "),
    ("VERSION", " 374 "),
    ("TIME", " 391 "),
    ("ADMIN", " 374 "),
    ("INFO", " 374 "),
];

/// Registers `nickname` on a fresh connection through the scripted
/// coordinator and acknowledges the origin update that carries the session.
async fn registered_client(
    hub: &mut Hub,
    inbox: mpsc::Sender<StateCoreMessage>,
    nickname: &str,
) -> TestResult<Client> {
    let mut client = Client::open(inbox, 1).await?;
    hub.ack_origin().await?;
    client.line(&format!("NICK {nickname}")).await?;
    client
        .line(&format!("USER {nickname} 0 * :{nickname} Real"))
        .await?;
    let (header, operation, bytes) = hub.next_request().await?;
    if !matches!(operation, FederatedOperation::SessionOpen { .. }) {
        return Err("expected session_open".into());
    }
    let session_id = SessionId::from_bytes([81; 16]);
    let user_id = UserId::from_bytes([82; 16]);
    hub.state_generation += 1;
    let generation = hub.state_generation;
    hub.event(
        &ProjectedEvent::SessionVisible(SessionEventView {
            source: source(user_id, nickname, 3)?,
            home_projection: Some(session_record(
                session_id, user_id, nickname, generation, 3,
            )?),
        }),
        None,
    )
    .await?;
    let completion = hub
        .event(
            &ProjectedEvent::RequestCompleted {
                resulting_state_generation: generation,
            },
            Some(RequestCorrelation {
                replay_key: header.replay_key,
                request_id: header.request_id,
            }),
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
    client.wait_for(&format!(" 001 {nickname} ")).await?;
    hub.ack_origin().await?;
    Ok(client)
}

/// Sends each query plain and returns its reply lines, requiring the reply
/// to end with the query's final numeric to the requester.
async fn plain_replies(client: &mut Client, nickname: &str) -> TestResult<Vec<Vec<String>>> {
    let mut replies = Vec::new();
    for (query, ending) in QUERIES {
        let before = client.sink.lines().len();
        client.line(query).await?;
        let reply = new_query_reply(client, before, &format!("{ending}{nickname} ")).await?;
        let last = reply.last().ok_or("empty reply")?;
        assert!(
            last.starts_with(&format!(":{LOCAL_SERVER}{ending}{nickname} ")),
            "{query}: {reply:?}"
        );
        assert!(
            reply.iter().all(|line| !line.contains(" FAIL ")),
            "{query}: {reply:?}"
        );
        replies.push(reply);
    }
    Ok(replies)
}

/// Sends each query with a label and requires its reply to carry that
/// label: one labeled line, or one labeled batch around every line.
async fn labeled_replies(client: &mut Client, nickname: &str) -> TestResult {
    let before = client.sink.lines().len();
    client
        .line("CAP REQ :message-tags batch labeled-response")
        .await?;
    new_query_reply(client, before, " ACK ").await?;
    for (query, ending) in QUERIES {
        let label = query.to_ascii_lowercase();
        let before = client.sink.lines().len();
        client.line(&format!("@label={label} {query}")).await?;
        let closing = format!("BATCH -{label}");
        let reply = new_query_reply(client, before, &format!("{ending}{nickname} ")).await?;
        let reply = if reply.len() == 1 {
            reply
        } else {
            new_query_reply(client, before, &closing).await?
        };
        match reply.as_slice() {
            [line] => assert!(
                line.starts_with(&format!(
                    "@label={label} :{LOCAL_SERVER}{ending}{nickname} "
                )),
                "{query}: {reply:?}"
            ),
            [open, .., close] => {
                assert!(
                    open.starts_with(&format!("@label={label} :{LOCAL_SERVER} BATCH +{label} "))
                        && open.ends_with(" labeled-response"),
                    "{query}: {reply:?}"
                );
                assert!(close.ends_with(&closing), "{query}: {reply:?}");
                let body = reply.get(1..reply.len() - 1).ok_or("empty batch")?;
                assert!(
                    body.iter()
                        .all(|line| line.starts_with(&format!("@batch={label} :{LOCAL_SERVER} "))),
                    "{query}: {reply:?}"
                );
                assert!(
                    body.last()
                        .is_some_and(|line| line.contains(&format!("{ending}{nickname} "))),
                    "{query}: {reply:?}"
                );
            }
            [] => return Err(format!("{query}: no reply").into()),
        }
    }
    Ok(())
}

/// Takes the next request the edge sends and requires it to be a directory
/// query.
async fn next_request_is_a_directory_query(hub: &mut Hub) -> TestResult {
    let (_, operation, _) = hub.next_request().await?;
    if matches!(operation, FederatedOperation::DirectoryQuery { .. }) {
        Ok(())
    } else {
        Err("the next request is not a directory query".into())
    }
}

#[tokio::test]
async fn an_active_edge_answers_its_information_queries_itself() -> TestResult {
    run_edge(|federation, inbox| async move {
        let mut hub = Hub::new(federation);
        hub.establish().await?;
        hub.synchronize().await?;
        let mut client = registered_client(&mut hub, inbox, "lena").await?;
        let replies = plain_replies(&mut client, "lena").await?;
        // LUSERS counts the edge's own projection: lena's session and no
        // channel, on "one server" whatever the topology.
        assert_eq!(
            replies.get(1).map(Vec::as_slice),
            Some(
                &[
                    format!(":{LOCAL_SERVER} 251 lena :There are 1 users on one server"),
                    format!(":{LOCAL_SERVER} 252 lena 0 :operator(s) online"),
                    format!(":{LOCAL_SERVER} 253 lena 0 :unknown connection(s)"),
                    format!(":{LOCAL_SERVER} 254 lena 0 :channels formed"),
                    format!(":{LOCAL_SERVER} 255 lena :There are 1 users on one server"),
                    format!(":{LOCAL_SERVER} 265 lena 1 1 :Current local users 1, max 1"),
                    format!(":{LOCAL_SERVER} 266 lena 1 1 :Current local users 1, max 1"),
                ][..]
            )
        );
        assert_eq!(
            replies.get(2).map(Vec::as_slice),
            Some(
                &[
                    format!(
                        ":{LOCAL_SERVER} 371 lena :arcd-{}",
                        env!("CARGO_PKG_VERSION")
                    ),
                    format!(":{LOCAL_SERVER} 374 lena :End of INFO"),
                ][..]
            )
        );
        labeled_replies(&mut client, "lena").await?;
        // LINKS goes to the coordinator; its directory query is the first
        // request since registration, so none of the six left the edge.
        client.line("LINKS").await?;
        next_request_is_a_directory_query(&mut hub).await
    })
    .await
}

#[tokio::test]
async fn a_partitioned_edge_still_answers_its_information_queries() -> TestResult {
    run_edge(|federation, inbox| async move {
        let mut hub = Hub::new(federation);
        hub.establish().await?;
        hub.synchronize().await?;
        let mut client = registered_client(&mut hub, inbox, "mira").await?;
        hub.send(LinkEvent::Closed(
            crate::federation::LinkCloseReason::PeerClosed,
        ))
        .await?;
        client.line("PRIVMSG #edge :anyone").await?;
        client.wait_for("FAIL PRIVMSG NETWORK_UNAVAILABLE").await?;
        plain_replies(&mut client, "mira").await?;
        labeled_replies(&mut client, "mira").await?;
        // LINKS is the coordinator's directory query, so it fails closed.
        let before = client.sink.lines().len();
        client.line("LINKS").await?;
        let reply = new_query_reply(&client, before, "FAIL LINKS").await?;
        assert!(
            reply
                .iter()
                .any(|line| line.contains("FAIL LINKS NETWORK_UNAVAILABLE")),
            "{reply:?}"
        );
        Ok(())
    })
    .await
}

/// Sends `WHO nora`, then `line` behind the unanswered request and a `PING`,
/// and requires the reply that contains `answer` to arrive only after the
/// WHO's own reply: a `PING` is answered at once, so its `PONG` shows that
/// `line` was read and held.
async fn answer_waits_behind_who(
    hub: &mut Hub,
    client: &mut Client,
    line: &str,
    answer: &str,
) -> TestResult {
    let before = client.sink.lines().len();
    client.line("WHO nora").await?;
    let (header, operation, bytes) = hub.next_request().await?;
    if !matches!(operation, FederatedOperation::DirectoryQuery { .. }) {
        return Err("expected the WHO directory query".into());
    }
    client.line(line).await?;
    client.line("PING :behind").await?;
    let held = new_query_reply(client, before, "PONG").await?;
    assert!(
        held.iter().all(|reply| !reply.contains(answer)),
        "{line} was answered before the WHO: {held:?}"
    );
    hub.result(
        &header,
        &bytes,
        &ResultArm::ReplyPage {
            snapshot_token: [5; 32],
            page_sequence: 0,
            next_cursor: None,
        },
        vec![agenc_relay_client_wire::numeric_reply(
            COORDINATOR_NAME,
            315,
            "nora",
            &["nora"],
            Some("End of WHO list"),
        )?],
        None,
    )
    .await?;
    let lines = new_query_reply(client, before, answer).await?;
    let who = lines
        .iter()
        .position(|reply| reply.contains(" 315 nora nora "))
        .ok_or("no WHO reply")?;
    let local = lines
        .iter()
        .position(|reply| reply.contains(answer))
        .ok_or("no local reply")?;
    assert!(who < local, "{line} overtook the WHO: {lines:?}");
    Ok(())
}

#[tokio::test]
async fn a_local_answer_waits_behind_the_connections_pending_request() -> TestResult {
    run_edge(|federation, inbox| async move {
        let mut hub = Hub::new(federation);
        hub.establish().await?;
        hub.synchronize().await?;
        let mut client = registered_client(&mut hub, inbox, "nora").await?;
        answer_waits_behind_who(&mut hub, &mut client, "TIME", " 391 nora ").await?;
        answer_waits_behind_who(&mut hub, &mut client, "MOTD", " 422 nora ").await?;
        // The user-mode read the edge also answers itself keeps the same
        // order.
        answer_waits_behind_who(&mut hub, &mut client, "MODE nora", " 221 nora ").await?;
        client
            .line("CAP REQ :message-tags batch labeled-response")
            .await?;
        client.wait_for(" ACK ").await?;
        answer_waits_behind_who(&mut hub, &mut client, "@label=later LUSERS", "BATCH -later").await
    })
    .await
}

/// Installs the registered connection's own session in the edge's
/// projection, as the coordinator's events would.
fn project_own_session(edge: &mut EdgeFederation) -> TestResult {
    let user_id = UserId::from_bytes([42; 16]);
    let record = session_record(SessionId::from_bytes([41; 16]), user_id, "member", 1, 42)?;
    edge.replica.install_recovered(
        1,
        vec![agenc_relay_domain::federation::ProjectionRecord::Session(
            record,
        )],
    )?;
    Ok(())
}

#[tokio::test]
async fn a_local_query_needs_the_session_in_the_projection() -> TestResult {
    use super::request_refusals::{command, registered_edge};
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut edge = registered_edge(context)?;
    for (query, _) in QUERIES {
        assert_eq!(
            command(&mut edge, context, query)?,
            Err(agenc_relay_domain::DomainError::RegistrationRequired),
            "{query}"
        );
    }
    assert!(edge.pending.is_empty(), "no query left the edge");
    Ok(())
}

#[tokio::test]
async fn a_local_query_needs_a_registered_connection() -> TestResult {
    use super::request_refusals::{command, registered_edge};
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut edge = registered_edge(context)?;
    project_own_session(&mut edge)?;
    // The projection holds the session, but no connection of the router
    // registered it, so there is no capability set to answer under.
    assert_eq!(
        command(&mut edge, context, "TIME")?,
        Err(agenc_relay_domain::DomainError::RegistrationRequired)
    );
    assert!(edge.pending.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_local_query_is_charged_as_a_registered_command() -> TestResult {
    use super::request_refusals::{command, registered_edge};
    use crate::admission::{BucketDemand, BucketKey, BucketKind, RateLimits};
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut edge = registered_edge(context)?;
    project_own_session(&mut edge)?;
    let limits = RateLimits::defaults();
    context.buckets_mut().reload(limits);
    let exhausted = BucketDemand::new(
        BucketKind::RegisteredCommand,
        BucketKey::Session(UserId::from_bytes([42; 16])),
        limits.rate(BucketKind::RegisteredCommand).burst(),
    )?;
    let now = context.now();
    context
        .buckets_mut()
        .charge_all_or_nothing(now, &[exhausted])
        .map_err(|_| "exhaust the registered-command bucket")?;
    for (query, _) in QUERIES {
        assert_eq!(
            command(&mut edge, context, query)?,
            Err(agenc_relay_domain::DomainError::ServerBusy),
            "{query}"
        );
    }
    assert!(edge.pending.is_empty());
    Ok(())
}
