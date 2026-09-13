//! The same ordered application scenario on all three public transports.
#![forbid(unsafe_code)]

use super::*;

mod phases;
mod state;
mod transcript;

use transcript::Transcript;

const CAPABILITIES: &str = "agenc.ag/account-create agenc.ag/account-credentials sasl echo-message message-tags message-ids server-time standard-replies agenc.ag/account-controls agenc.ag/channel-controls";

#[derive(Debug, Eq, PartialEq)]
struct Outcome {
    transcript: Vec<(String, Vec<String>)>,
    state: state::Snapshot,
}

fn negotiate(client: &mut IrcClient, trace: &mut Transcript, actor: &str) -> TestResult {
    client.send("CAP LS 302")?;
    let lines = read_until(&mut client.reader, |line| {
        line.contains(" CAP * LS ") && !line.contains(" CAP * LS * :")
    })?;
    assert_contains(&lines, "sasl=AGENC-OPAQUE")?;
    trace.record(&format!("{actor} CAP LS 302"), lines);
    trace.command(client, &format!("CAP REQ :{CAPABILITIES}"), " CAP * ACK ")?;
    Ok(())
}

fn registered_guest(
    fixture: &LiveFixture,
    transport: ClientTransport,
    nickname: &str,
    trace: &mut Transcript,
) -> TestResult<IrcClient> {
    let mut client = IrcClient::connect_transport(fixture, transport)?;
    negotiate(&mut client, trace, nickname)?;
    trace.record(
        &format!("register guest {nickname}"),
        client.complete_registration(nickname)?,
    );
    Ok(client)
}

fn scenario(transport: ClientTransport) -> TestResult<Outcome> {
    let fixture = LiveFixture::create()?;
    if !matches!(transport, ClientTransport::Tcp) {
        configure(&fixture)?;
    }
    let mut process = DaemonProcess::start(&fixture.config_path)?;
    let mut trace = Transcript::default();
    let account = {
        let mut creator = IrcClient::connect_transport(&fixture, transport)?;
        negotiate(&mut creator, &mut trace, "creator")?;
        let account = create_live_account(&mut creator, &fixture)?;
        trace.record(
            "authenticated creation response",
            vec!["committed account".into()],
        );
        creator.send("QUIT :creation complete")?;
        trace.record("creator QUIT and EOF", creator_quit_reply(&mut creator)?);
        account
    };
    let mut member = IrcClient::connect_transport(&fixture, transport)?;
    negotiate(&mut member, &mut trace, "member")?;
    authenticate_live_account(&mut member, &fixture, ACCOUNT_PASSWORD, 43, account)?;
    trace.record(
        "authenticated login response",
        vec!["committed same account; SASL 903".into()],
    );
    trace.record(
        "register account Member",
        member.complete_registration("Member")?,
    );
    let mut visitor = registered_guest(&fixture, transport, "Visitor", &mut trace)?;
    phases::commands(&mut member, &mut visitor, &mut trace)?;
    phases::privacy(&mut member, &mut visitor, &mut trace)?;
    phases::normal_close(&mut member, visitor, &mut trace)?;
    phases::malformed_close(&fixture, transport, &mut member, &mut trace)?;
    phases::overload(&fixture, transport, &mut member, &mut trace)?;
    trace.command(&mut member, "WHOIS Member", " 318 ")?;
    member.send("QUIT :equivalence complete")?;
    trace.record("member QUIT and EOF", member.shutdown_lines()?);
    let mut admin = AdminClient::connect(&fixture)?;
    admin.confirm_process("DIE :transport equivalence complete")?;
    assert!(process.wait()?.success(), "{}", fixture.log_excerpt());
    Ok(Outcome {
        transcript: trace.normalized(account)?,
        state: state::snapshot(&fixture, account)?,
    })
}

fn creator_quit_reply(client: &mut IrcClient) -> TestResult<Vec<String>> {
    let mut line = String::new();
    client.reader.read_line(&mut line)?;
    if line != ":node.test ERROR :creation complete\r\n" {
        return Err(failure(format!("unexpected creator QUIT reply: {line:?}")));
    }
    let mut extra = [0_u8; 1];
    if client.reader.read(&mut extra)? != 0 {
        return Err(failure("creator QUIT returned output after its ERROR"));
    }
    Ok(vec![line.trim_end_matches(['\r', '\n']).to_owned()])
}

#[test]
fn tcp_text_and_binary_wss_have_identical_transcripts_and_durable_state() -> TestResult {
    let tcp = scenario(ClientTransport::Tcp).map_err(|error| failure(format!("TCP: {error}")))?;
    let text = scenario(ClientTransport::TextWebSocket)
        .map_err(|error| failure(format!("text WebSocket: {error}")))?;
    let binary = scenario(ClientTransport::BinaryWebSocket)
        .map_err(|error| failure(format!("binary WebSocket: {error}")))?;
    assert_eq!(
        text, tcp,
        "text WebSocket application behavior differs from TCP"
    );
    assert_eq!(
        binary, tcp,
        "binary WebSocket application behavior differs from TCP"
    );
    Ok(())
}
