//! Architecture 9.5, 14.2 and B.6 on the native coordinator and the issuing edge.
#![forbid(unsafe_code)]

use super::*;

#[test]
fn registered_join_preserves_each_legacy_and_negotiated_target() -> TestResult {
    encrypted_clients::run_network(|network, _, _, _| {
        let fixture = &network.coordinator;
        let login = "join-authority";
        let account = {
            let mut registration = ArcClient::connect(fixture)?;
            registration.negotiate_sasl()?;
            create_live_account(&mut registration, fixture, login, 81)?
        };
        let mut owner = ArcClient::connect(fixture)?;
        owner.negotiate_sasl()?;
        authenticate_live_account(&mut owner, fixture, login, ACCOUNT_PASSWORD, 83, account)?;
        owner.complete_registration("manager")?;
        for channel in ["#acap", "#zkey", "#zsecond"] {
            owner.send_until(
                &format!("JOIN {channel}"),
                &format!(" 366 manager {channel} "),
            )?;
        }
        owner.send_until("MODE #acap +l 1", " MODE #acap +l")?;
        owner.send_until("MODE #zkey +k test-join-key", " MODE #zkey +k")?;
        owner.send_until("MODE #zsecond +k test-join-key", " MODE #zsecond +k")?;
        for (node, name, standard) in [
            (fixture, "corelegacy", false),
            (fixture, "corestandard", true),
            (&network.edge_a, "edgelegacy", false),
            (&network.edge_a, "edgestandard", true),
        ] {
            exercise(node, name, standard).map_err(|e| failure(format!("{name}: {e}")))?;
        }
        Ok(())
    })
}

fn exercise(node: &NodeFixture, nick: &str, standard: bool) -> TestResult {
    let caps = if standard {
        "message-tags batch labeled-response standard-replies"
    } else {
        "message-tags batch labeled-response"
    };
    let (_, _, mut client) = welcome_recovery::guest_welcome(node, nick, caps)
        .map_err(|e| failure(format!("guest welcome: {e}")))?;
    client
        .send_until("JOIN #xagain", &format!(" 366 {nick} #xagain "))
        .map_err(|e| failure(format!("first single JOIN: {e}")))?;
    let original = format!("#zkey,#b{nick},#acap,#xagain,#y{nick}");
    let mixed = exchange(&mut client, "mixed", &original)
        .map_err(|e| failure(format!("mixed JOIN: {e}")))?;
    check_refusals(&mixed, nick, standard)?;
    for name in [format!("#b{nick}"), format!("#y{nick}")] {
        assert_eq!(
            mixed
                .iter()
                .filter(|line| line.contains(&format!(" 366 {nick} {name} ")))
                .count(),
            1
        );
        assert_eq!(
            mixed
                .iter()
                .filter(|line| line.contains(&format!(" JOIN {name}")))
                .count(),
            1
        );
    }
    for (label, names) in [
        ("all-first", "#zkey,#xagain,#acap"),
        ("all-middle", "#xagain,#acap,#zkey"),
        ("all-last", "#acap,#zkey,#xagain"),
    ] {
        let refused =
            exchange(&mut client, label, names).map_err(|e| failure(format!("{label}: {e}")))?;
        check_refusals(&refused, nick, standard)?;
        assert!(
            !refused.iter().any(|line| line.contains(" 366 ")
                || line.contains("!client@") && line.contains(" JOIN "))
        );
    }
    let hidden = exchange(&mut client, "both-hidden", "#zsecond,#zkey")?;
    for name in ["#zkey", "#zsecond"] {
        let code = if standard {
            format!(" FAIL JOIN SECRET_UNAVAILABLE {name} :")
        } else {
            format!(" 403 {nick} {name} :")
        };
        assert_eq!(hidden.iter().filter(|line| line.contains(&code)).count(), 1);
    }
    client.send_until("TIME", &format!(" 391 {nick} "))?;
    Ok(())
}

fn exchange(client: &mut ArcClient, label: &str, names: &str) -> TestResult<Vec<String>> {
    client.send(&format!("@label={label} JOIN {names}"))?;
    let start = format!("@label={label} ");
    let open = client.read_until(|line| line.starts_with(&start))?;
    let opened = open
        .last()
        .and_then(|line| line.split_once(" BATCH +"))
        .and_then(|(_, suffix)| suffix.split_whitespace().next())
        .ok_or("missing labeled JOIN batch")?;
    let close = format!(" BATCH -{opened}");
    let body = client.read_until(|line| line.ends_with(&close))?;
    let tag = format!("@batch={opened} ");
    Ok(body
        .into_iter()
        .filter(|line| line.starts_with(&tag))
        .collect())
}

fn check_refusals(lines: &[String], nick: &str, standard: bool) -> TestResult {
    let secret = if standard {
        " FAIL JOIN SECRET_UNAVAILABLE #zkey :".to_owned()
    } else {
        format!(" 403 {nick} #zkey :")
    };
    let capacity = if standard {
        " FAIL JOIN SERVER_BUSY :".to_owned()
    } else {
        format!(" 481 {nick} :")
    };
    for needle in [secret, capacity, format!(" 482 {nick} #xagain :")] {
        let count = lines.iter().filter(|line| line.contains(&needle)).count();
        if count != 1 {
            return Err(failure(format!(
                "{nick} expected one {needle} and got {count}: {lines:?}"
            )));
        }
    }
    let errors = lines
        .iter()
        .filter(|line| {
            line.contains(" FAIL ")
                || [" 403 ", " 404 ", " 481 ", " 482 "]
                    .iter()
                    .any(|code| line.contains(code))
        })
        .count();
    assert_eq!(errors, 3);
    Ok(())
}
