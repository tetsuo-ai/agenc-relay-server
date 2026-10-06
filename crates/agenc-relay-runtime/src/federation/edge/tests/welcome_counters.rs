#![forbid(unsafe_code)]

//! Every welcome's `RPL_LUSER*` counters are the figures of its node's own
//! `LUSERS` reply (Architecture 10.2 step 3, Section 14): an edge sends its
//! fixed form, which holds no count, alike for every client; a coordinator
//! counts the network's sessions, its own clients' and the edge's; a node
//! without federation counts its own, which are the network's.

use super::*;

/// The `RPL_LUSER*` lines among `lines`, with the server and the nickname
/// written as placeholders.
fn counters(lines: &[String], nickname: &str) -> Vec<String> {
    lines
        .iter()
        .filter_map(|line| {
            let mut fields = line.splitn(4, ' ');
            let (_, code, target, rest) = (
                fields.next()?,
                fields.next()?,
                fields.next()?,
                fields.next()?,
            );
            (matches!(code, "251" | "252" | "253" | "254" | "255" | "265" | "266")
                && target == nickname)
                .then(|| format!(":<server> {code} <nick> {rest}"))
        })
        .collect()
}

/// The fixed form an edge sends, in the placeholders of `counters`.
const STATIC_FORM: [&str; 2] = [
    ":<server> 251 <nick> :User counts are not published by this server",
    ":<server> 255 <nick> :Local counts are not published by this server",
];

/// The client's `LUSERS` reply, in the placeholders of `counters`.
async fn lusers(client: &mut Client, nickname: &str) -> TestResult<Vec<String>> {
    let before = client.sink.lines().len();
    client.line("LUSERS").await?;
    let reply = new_query_reply(client, before, &format!(" 255 {nickname} ")).await?;
    Ok(counters(&reply, nickname))
}

/// The user count a coordinator's `251` gives, in its welcome or its
/// `LUSERS` reply.
fn users(counters: &[String]) -> TestResult<usize> {
    let line = counters
        .iter()
        .find(|line| line.starts_with(":<server> 251 "))
        .ok_or_else(|| format!("no 251 in {counters:?}"))?;
    Ok(line
        .split_once(":There are ")
        .and_then(|(_, rest)| rest.split_once(' '))
        .ok_or_else(|| format!("no count in {line}"))?
        .0
        .parse()?)
}

/// Registers `nickname` on the coordinator and requires its welcome to count
/// `expected` sessions, the count of its `LUSERS` reply.
async fn coordinator_client(
    inbox: &mpsc::Sender<StateCoreMessage>,
    number: u64,
    nickname: &str,
    expected: usize,
) -> TestResult<Client> {
    let mut client = Client::open(inbox.clone(), number).await?;
    register(&mut client, nickname).await?;
    let welcome = counters(&client.sink.lines(), nickname);
    assert_eq!(
        welcome,
        [format!(
            ":<server> 251 <nick> :There are {expected} users and 0 services on 1 servers"
        )],
        "{nickname}"
    );
    let reply = lusers(&mut client, nickname).await?;
    assert_eq!(users(&welcome)?, users(&reply)?, "{nickname}: {reply:?}");
    Ok(client)
}

/// Registers `nickname` on the edge and requires its welcome to send the
/// fixed form, which its `LUSERS` reply also is.
async fn edge_client(
    inbox: &mpsc::Sender<StateCoreMessage>,
    number: u64,
    nickname: &str,
) -> TestResult<Client> {
    let mut client = Client::open(inbox.clone(), number).await?;
    register(&mut client, nickname).await?;
    assert_eq!(
        counters(&client.sink.lines(), nickname),
        STATIC_FORM,
        "{nickname}"
    );
    assert_eq!(
        lusers(&mut client, nickname).await?,
        STATIC_FORM,
        "{nickname}"
    );
    Ok(client)
}

#[tokio::test]
async fn welcome_counters_match_each_nodes_lusers_reply() -> TestResult {
    run_bridge(|hub_inbox, edge_inbox| async move {
        let mut ana = register_when_available(&edge_inbox, 1, "ana", None).await?;
        assert_eq!(counters(&ana.sink.lines(), "ana"), STATIC_FORM);
        assert_eq!(lusers(&mut ana, "ana").await?, STATIC_FORM);
        let _bob = edge_client(&edge_inbox, 2, "bob").await?;
        // The coordinator counts the edge's two sessions with its own.
        let _cid = coordinator_client(&hub_inbox, 1, "cid", 3).await?;
        let _dan = coordinator_client(&hub_inbox, 2, "dan", 4).await?;
        let _eli = edge_client(&edge_inbox, 3, "eli").await?;
        let _fay = coordinator_client(&hub_inbox, 3, "fay", 6).await?;
        Ok(())
    })
    .await
}

/// Runs a node without federation in the actor loop and hands `driver` its
/// client inbox and the physical-close port.
async fn run_plain_node<Driver>(
    driver: impl FnOnce(mpsc::Sender<StateCoreMessage>, ConnectionClosePort) -> Driver,
) -> TestResult
where
    Driver: Future<Output = TestResult>,
{
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let mut parts = fixture.take_run_parts()?;
    let (inbox, inbox_receiver) = mpsc::channel(8);
    let (close_port, close_inbox) = connection_close_channel();
    let (lifecycle, lifecycle_receiver) = lifecycle_channel();
    let token = crate::cancel::CancellationToken::root();
    let driven = async move {
        let output = driver(inbox, close_port).await;
        let _stopped = lifecycle.request(LifecyclePhase::Stop).await;
        output
    };
    let run = parts.state.run(
        inbox_receiver,
        close_inbox,
        lifecycle_receiver,
        parts.storage,
        parts.storage_reads,
        parts.checkpoints,
        parts.crypto,
        token,
    );
    let (exit, output) = tokio::join!(run, driven);
    if !matches!(exit, StateCoreExit::Stopped) {
        return Err(format!("the node exited with {exit:?}").into());
    }
    output
}

/// Registers `nickname` on a node without federation and requires its
/// welcome to count `expected` users, the count of its `LUSERS` reply.
async fn plain_client(
    inbox: &mpsc::Sender<StateCoreMessage>,
    number: u64,
    nickname: &str,
    expected: usize,
) -> TestResult<Client> {
    let mut client = Client::open(inbox.clone(), number).await?;
    register(&mut client, nickname).await?;
    let welcome = counters(&client.sink.lines(), nickname);
    assert_eq!(users(&welcome)?, expected, "{nickname}: {welcome:?}");
    let reply = lusers(&mut client, nickname).await?;
    assert_eq!(users(&reply)?, expected, "{nickname}: {reply:?}");
    Ok(client)
}

/// A node without federation is the whole network, so its welcome counts
/// what its `LUSERS` reply counts, also after a client has left.
#[tokio::test]
async fn a_node_without_federation_counts_what_its_lusers_reply_counts() -> TestResult {
    run_plain_node(|inbox, closes| async move {
        let mut ann = plain_client(&inbox, 1, "ann", 1).await?;
        let bo = plain_client(&inbox, 2, "bo", 2).await?;
        bo.close(&closes)?;
        // The departure is applied once ann's LUSERS reply counts one user.
        let mut remaining = 0;
        for _ in 0..500 {
            remaining = users(&lusers(&mut ann, "ann").await?)?;
            if remaining == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(remaining, 1, "bo's departure was never applied");
        let _cy = plain_client(&inbox, 3, "cy", 2).await?;
        Ok(())
    })
    .await
}
