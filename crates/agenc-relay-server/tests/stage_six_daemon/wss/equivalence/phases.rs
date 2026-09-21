//! Privacy, quota rejection, and session teardown checkpoints.
#![forbid(unsafe_code)]

use super::*;

pub(super) fn commands(
    member: &mut ArcClient,
    visitor: &mut ArcClient,
    trace: &mut Transcript,
) -> TestResult {
    trace.command(member, "OPER root password", " 481 ")?;
    for name in ["#public", "#secret"] {
        trace.command(member, &format!("JOIN {name}"), " 366 ")?;
        trace.command(
            member,
            &format!("CHANCTL REGISTER {name}"),
            "NOTE CHANCTL UPDATED",
        )?;
        trace.command(
            member,
            &format!("TOPIC {name} :{name} retained topic"),
            " TOPIC ",
        )?;
    }
    trace.command(member, "MODE #secret +s", " MODE ")?;
    trace.command(member, "MODE #public +t", " MODE ")?;
    trace.command(visitor, "JOIN #public", " 366 ")?;
    trace.record(
        "member sees visitor join",
        read_until(&mut member.reader, |line| line.contains(" JOIN #public"))?,
    );
    for line in [
        "PRIVMSG #public :identical chat",
        "NOTICE #public :identical notice",
    ] {
        let ending = if line.starts_with("PRIVMSG") {
            " PRIVMSG "
        } else {
            " NOTICE "
        };
        trace.command(member, line, ending)?;
        trace.record(
            "visitor receives channel message",
            read_until(&mut visitor.reader, |line| line.contains(ending))?,
        );
    }
    trace.command(member, "PING :same-keepalive", " PONG ")?;
    trace.command(member, "MODE #public", " 329 ")?;
    trace.command(member, "TOPIC #public", " 333 ")?;
    trace.command(member, "NAMES #public", " 366 ")?;
    Ok(())
}

pub(super) fn privacy(
    member: &mut ArcClient,
    visitor: &mut ArcClient,
    trace: &mut Transcript,
) -> TestResult {
    let listed = trace.command(visitor, "LIST", " 323 ")?;
    assert_contains(&listed, "#public")?;
    assert!(
        !listed.iter().any(|line| line.contains("#secret")),
        "{listed:?}"
    );
    for command in ["TOPIC", "NAMES", "WHO"] {
        let ending = match command {
            "NAMES" => "FAIL NAMES",
            "WHO" => " 315 ",
            _ => "FAIL TOPIC",
        };
        let hidden = trace.command(visitor, &format!("{command} #secret"), ending)?;
        let missing = trace.command(visitor, &format!("{command} #absent"), ending)?;
        assert_eq!(
            hidden
                .iter()
                .map(|line| line.replace("#secret", "#target"))
                .collect::<Vec<_>>(),
            missing
                .iter()
                .map(|line| line.replace("#absent", "#target"))
                .collect::<Vec<_>>()
        );
    }
    let whois = trace.command(visitor, "WHOIS Member", " 318 ")?;
    assert!(
        !whois
            .iter()
            .any(|line| line.contains("#secret") || line.contains("127.0.0.1")),
        "{whois:?}"
    );
    trace.command(visitor, "TOPIC #public :unauthorized replacement", " 482 ")?;
    let topic = trace.command(member, "TOPIC #public", " 333 ")?;
    assert_contains(&topic, "#public retained topic")?;
    assert!(
        !topic
            .iter()
            .any(|line| line.contains("unauthorized replacement"))
    );
    Ok(())
}

pub(super) fn normal_close(
    member: &mut ArcClient,
    mut visitor: ArcClient,
    trace: &mut Transcript,
) -> TestResult {
    visitor.send("QUIT :finished visiting")?;
    trace.record("visitor QUIT and EOF", visitor.shutdown_lines()?);
    let quit = read_until(&mut member.reader, |line| line.contains(" QUIT "))?;
    assert_contains(&quit, "finished visiting")?;
    trace.record("member sees visitor quit", quit);
    let names = trace.command(member, "NAMES #public", " 366 ")?;
    assert!(!names.iter().any(|line| line.contains("Visitor")));
    Ok(())
}

pub(super) fn malformed_close(
    fixture: &LiveFixture,
    transport: ClientTransport,
    member: &mut ArcClient,
    trace: &mut Transcript,
) -> TestResult {
    let mut malformed = registered_guest(fixture, transport, "Malformed", trace)?;
    trace.command(&mut malformed, "JOIN #public", " 366 ")?;
    trace.record(
        "member sees malformed client join",
        read_until(&mut member.reader, |line| line.contains(" JOIN #public"))?,
    );
    malformed.send(":forged PRIVMSG #public :must-never-appear")?;
    trace.record(
        "forbidden client prefix and EOF",
        malformed.shutdown_lines()?,
    );
    let observed = read_until(&mut member.reader, |line| line.contains(" QUIT "))?;
    assert!(
        !observed
            .iter()
            .any(|line| line.contains("must-never-appear"))
    );
    trace.record("member sees protocol close", observed);
    let names = trace.command(member, "NAMES #public", " 366 ")?;
    assert!(!names.iter().any(|line| line.contains("Malformed")));
    Ok(())
}

pub(super) fn overload(
    fixture: &LiveFixture,
    transport: ClientTransport,
    member: &mut ArcClient,
    trace: &mut Transcript,
) -> TestResult {
    let before = trace.command(member, "MODE #public", " 329 ")?;
    let mut config = fs::read_to_string(&fixture.config_path)?;
    replace_once(
        &mut config,
        "[limits.rate.expensive_query]\nrefill_tokens = 2\nrefill_seconds = 1\nburst = 10",
        "[limits.rate.expensive_query]\nrefill_tokens = 1\nrefill_seconds = 3600\nburst = 1",
    )?;
    fs::write(&fixture.config_path, config)?;
    let mut admin = AdminClient::connect(fixture)?;
    assert!(
        admin
            .command_line("REHASH :equivalence query quota")?
            .contains("NOTE REHASH OK")
    );
    let mut limited = registered_guest(fixture, transport, "Limited", trace)?;
    let admitted = trace.command(&mut limited, "LIST", " 323 ")?;
    assert_contains(&admitted, "#public")?;
    let refused = trace.command(&mut limited, "LIST", "FAIL LIST")?;
    assert_contains(&refused, "SERVER_BUSY")?;
    assert!(!refused.iter().any(|line| line.contains(" 322 ")));
    let after = trace.command(member, "MODE #public", " 329 ")?;
    assert_eq!(
        before, after,
        "query admission refusal changed channel state"
    );
    limited.send("QUIT :quota checked")?;
    trace.record("limited QUIT and EOF", limited.shutdown_lines()?);
    Ok(())
}
