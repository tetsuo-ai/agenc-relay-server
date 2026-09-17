#![forbid(unsafe_code)]

//! The init template renders and re-parses for every profile, and the onboarding
//! descriptor has the exact line order and literal tokens.

mod support;

use agenc_ircd_config::{
    BASE_PROFILE_SHA256_TOKEN, ConfigError, DisplayLabel, DnsName, E2EE_PROFILE_SHA256_TOKEN,
    InitProfile, InitValues, MAX_ONBOARDING_DESCRIPTOR_BYTES, NodeRole, OnboardingFacts,
    OperatorTemplate, SequencerKeySetFacts, ValidationStage, parse_onboarding_descriptor,
    render_onboarding, render_template,
};
use agenc_ircd_types::{NetworkId, OperatorId, RecoveryEpoch, ServerId};
use support::{DUAL, ONION, PUBLIC, parse};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn values(profile: InitProfile) -> Result<InitValues, Box<dyn std::error::Error>> {
    Ok(InitValues {
        profile,
        network_id: NetworkId::from_bytes([1; 32]),
        server_id: ServerId::from_bytes([2; 16]),
        role: NodeRole::Coordinator,
        coordinator_server_id: ServerId::from_bytes([2; 16]),
        server_name: DnsName::parse("chat.example")?,
        display_name: DisplayLabel::parse("example")?,
        data_dir: "/var/lib/agenc-ircd".into(),
        runtime_dir: "/run/agenc-ircd".into(),
        tls_dir: "/etc/agenc-ircd/tls".into(),
        dns_name: matches!(profile, InitProfile::Public | InitProfile::Dual)
            .then(|| DnsName::parse("chat.example"))
            .transpose()?,
        account_service_hpke_public_key: [5; 32],
        operator: OperatorTemplate {
            local_uid: 0,
            operator_id: OperatorId::from_bytes([4; 16]),
            signing_public_key: [6; 32],
        },
    })
}

#[test]
fn generated_admin_admission_and_operator_identity_use_the_same_uid() -> TestResult {
    for uid in [0, 1001, u32::MAX] {
        let mut values = values(InitProfile::Public)?;
        values.operator.local_uid = uid;
        let text = render_template(&values)?.replace(
            "enabled = false\npurpose = \"client_tls\"",
            "enabled = true\npurpose = \"client_tls\"",
        );
        let config = parse(&text)?;
        let local = config
            .listeners
            .iter()
            .find_map(|listener| listener.local_admin.as_ref())
            .ok_or("missing generated local administrator")?;
        assert_eq!(local.allowed_uids, vec![uid]);
        assert!(local.allowed_gids.is_empty());
        let operator = config
            .moderation
            .operators
            .first()
            .ok_or("missing generated operator")?;
        assert_eq!(operator.local_uids, vec![uid]);
        assert_eq!(
            operator.signing_public_key,
            values.operator.signing_public_key
        );
    }
    Ok(())
}

#[test]
fn every_profile_renders_a_document_that_parses_with_listeners_disabled() -> TestResult {
    for profile in [InitProfile::Public, InitProfile::Onion, InitProfile::Dual] {
        let text = render_template(&values(profile)?)?;
        assert!(text.contains("config_version = 1"));
        assert!(!text.contains("enabled = true\npurpose"));
        assert!(text.contains("[[listeners.endpoint]]"));
        assert!(text.contains("# Every listener starts disabled"));
        match parse(&text) {
            Ok(_) => {}
            Err(report) => assert!(
                report
                    .issues()
                    .iter()
                    .all(|issue| issue.stage == ValidationStage::LocalIdentity
                        && issue.error == ConfigError::Topology)
            ),
        }
        let enabled = text
            .replace(
                "enabled = false\npurpose = \"client_tls\"",
                "enabled = true\npurpose = \"client_tls\"",
            )
            .replace(
                "enabled = false\npurpose = \"client_onion\"",
                "enabled = true\npurpose = \"client_onion\"",
            );
        let enabled = if profile == InitProfile::Onion {
            enabled.replace(
                "coordinator_server_id = \"AgICAgICAgICAgICAgICAg\"\n# Fill",
                "coordinator_server_id = \"AgICAgICAgICAgICAgICAg\"\nonion_address = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion\"\nonion_tls_spki_sha256 = \"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc\"\n# Fill",
            )
        } else {
            enabled
        };
        assert!(
            parse(&enabled).is_ok(),
            "{profile:?}: {:?}",
            parse(&enabled).err().map(|r| r.to_string())
        );
    }
    assert_eq!(InitProfile::parse("public"), Ok(InitProfile::Public));
    assert_eq!(InitProfile::parse("onion"), Ok(InitProfile::Onion));
    assert_eq!(InitProfile::parse("dual"), Ok(InitProfile::Dual));
    assert_eq!(InitProfile::parse("both"), Err(ConfigError::InvalidValue));
    Ok(())
}

fn facts() -> OnboardingFacts {
    OnboardingFacts {
        recovery_epoch: RecoveryEpoch::from_bytes([9; 16]),
        account_service_hpke_key_id: [10; 32],
        sequencer_key_set: Some(SequencerKeySetFacts {
            generation: 3,
            hash: [11; 32],
        }),
    }
}

#[test]
fn descriptor_lines_occur_in_order_and_omit_absent_endpoints_as_units() -> TestResult {
    let dual = render_onboarding(&parse(DUAL)?, &facts())?;
    let lines: Vec<&str> = dual.lines().collect();
    assert_eq!(lines.len(), 14);
    assert!(dual.ends_with('\n'));
    assert_eq!(lines.first().copied(), Some("AGENC-CHAT-CONNECT/1"));
    assert_eq!(
        lines.get(1).copied(),
        Some("network-id=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE")
    );
    assert_eq!(lines.get(2).copied(), Some("server-name=chat.example"));
    assert_eq!(
        lines.get(3).copied(),
        Some("dns-endpoint=chat.example:6697")
    );
    assert!(
        lines.get(4).is_some_and(
            |line| line.starts_with("onion-endpoint=") && line.ends_with(".onion:6697")
        )
    );
    assert_eq!(
        lines.get(5).copied(),
        Some("onion-tls-spki-sha256=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc")
    );
    assert_eq!(
        lines.get(6).copied(),
        Some("recovery-epoch=CQkJCQkJCQkJCQkJCQkJCQ")
    );
    assert_eq!(
        lines.get(7).copied(),
        Some(format!("base-profile-sha256={BASE_PROFILE_SHA256_TOKEN}").as_str())
    );
    assert!(
        lines
            .get(8)
            .is_some_and(|line| line.starts_with("account-service-hpke-key-id="))
    );
    assert_eq!(
        lines.get(9).copied(),
        Some("account-service-hpke-public-key=BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU")
    );
    assert_eq!(lines.get(10).copied(), Some("e2ee-profile=IRC-MLS/1"));
    assert_eq!(
        lines.get(11).copied(),
        Some(format!("e2ee-profile-sha256={E2EE_PROFILE_SHA256_TOKEN}").as_str())
    );
    assert_eq!(
        lines.get(12).copied(),
        Some("sequencer-key-set-generation=3")
    );
    assert!(
        lines
            .get(13)
            .is_some_and(|line| line.starts_with("sequencer-key-set-hash="))
    );
    assert_eq!(
        BASE_PROFILE_SHA256_TOKEN,
        "ewDg0IRCcGJkEdOY8V91ICJOqQYRdzjj2pdBphHcZ7M"
    );
    assert_eq!(
        E2EE_PROFILE_SHA256_TOKEN,
        "YYCAtMkqprkhls6CM2nlwN02tJFgSWcP2Cvauwn3jwc"
    );

    let public = render_onboarding(&parse(PUBLIC)?, &facts())?;
    assert_eq!(public.lines().count(), 12);
    assert!(!public.contains("onion-"));
    let onion = render_onboarding(&parse(ONION)?, &facts())?;
    assert_eq!(onion.lines().count(), 13);
    assert!(!onion.contains("dns-endpoint"));
    assert!(
        onion
            .bytes()
            .all(|byte| byte == b'\n' || byte.is_ascii_graphic())
    );

    let mut none = parse(PUBLIC)?;
    none.network.dns = None;
    assert_eq!(
        render_onboarding(&none, &facts()).err(),
        Some(ConfigError::MissingValue)
    );
    Ok(())
}

#[test]
fn descriptor_parser_requires_exact_order_tokens_and_endpoint_units() -> TestResult {
    let public = render_onboarding(&parse(PUBLIC)?, &facts())?;
    let parsed = parse_onboarding_descriptor(&public)?;
    assert_eq!(parsed.network_id, NetworkId::from_bytes([1; 32]));
    assert_eq!(parsed.server_name, DnsName::parse("chat.example")?);
    assert_eq!(parsed.dns.as_ref().map(|dns| dns.port), Some(6697));
    assert!(parsed.onion.is_none());
    assert_eq!(parsed.recovery_epoch, RecoveryEpoch::from_bytes([9; 16]));
    assert_eq!(parsed.account_service_hpke_key_id, [10; 32]);
    assert_eq!(parsed.account_service_hpke_public_key, [5; 32]);
    assert_eq!(
        parsed.sequencer_key_set,
        Some(SequencerKeySetFacts {
            generation: 3,
            hash: [11; 32],
        })
    );

    let onion = render_onboarding(&parse(ONION)?, &facts())?;
    assert!(parse_onboarding_descriptor(&onion)?.onion.is_some());
    let dual = render_onboarding(&parse(DUAL)?, &facts())?;
    let parsed_dual = parse_onboarding_descriptor(&dual)?;
    assert!(parsed_dual.dns.is_some());
    assert!(parsed_dual.onion.is_some());

    for invalid in [
        public.trim_end().to_owned(),
        public.replace('\n', "\r\n"),
        public.replacen("AGENC-CHAT-CONNECT/1", "AGENC-CHAT-CONNECT/2", 1),
        public.replacen("dns-endpoint=chat.example:6697\n", "", 1),
        public.replacen(BASE_PROFILE_SHA256_TOKEN, "invalid", 1),
        public.replacen(
            "sequencer-key-set-generation=3",
            "sequencer-key-set-generation=03",
            1,
        ),
        format!("{public}extra=value\n"),
        onion.replacen("onion-tls-spki-sha256=", "unexpected-pin=", 1),
    ] {
        assert!(parse_onboarding_descriptor(&invalid).is_err(), "{invalid}");
    }

    let oversized = format!("{}{}", public, "x".repeat(MAX_ONBOARDING_DESCRIPTOR_BYTES));
    assert_eq!(
        parse_onboarding_descriptor(&oversized),
        Err(ConfigError::InvalidDocument)
    );
    Ok(())
}

#[test]
fn descriptor_parser_rejects_noncanonical_scalars_and_reordered_fields() -> TestResult {
    let public = render_onboarding(&parse(PUBLIC)?, &facts())?;
    let key_id_line = public
        .lines()
        .find(|line| line.starts_with("account-service-hpke-key-id="))
        .ok_or("missing HPKE key ID")?;
    let sequencer_hash_line = public
        .lines()
        .find(|line| line.starts_with("sequencer-key-set-hash="))
        .ok_or("missing sequencer hash")?;
    let mut reordered = public.lines().map(str::to_owned).collect::<Vec<_>>();
    reordered.swap(1, 2);
    let reordered = format!("{}\n", reordered.join("\n"));
    let duplicated = public.replacen(
        "server-name=chat.example\n",
        "server-name=chat.example\nserver-name=chat.example\n",
        1,
    );
    for invalid in [
        public.replacen(":6697", ":0", 1),
        public.replacen(":6697", ":65536", 1),
        public.replacen(":6697", ":06697", 1),
        public.replacen(key_id_line, &format!("{key_id_line}="), 1),
        public.replacen(sequencer_hash_line, &format!("{sequencer_hash_line}="), 1),
        public.replacen("e2ee-profile=IRC-MLS/1", "e2ee-profile=IRC-MLS/2", 1),
        public.replacen(E2EE_PROFILE_SHA256_TOKEN, BASE_PROFILE_SHA256_TOKEN, 1),
        reordered,
        duplicated,
    ] {
        assert!(parse_onboarding_descriptor(&invalid).is_err(), "{invalid}");
    }
    assert_eq!(
        parse_onboarding_descriptor(&"x".repeat(MAX_ONBOARDING_DESCRIPTOR_BYTES + 1)),
        Err(ConfigError::InvalidDocument)
    );
    Ok(())
}

#[test]
fn edge_template_omits_every_coordinator_only_secret_path() -> TestResult {
    let mut edge = values(InitProfile::Public)?;
    edge.role = NodeRole::Edge;
    edge.coordinator_server_id = ServerId::from_bytes([7; 16]);
    let text = render_template(&edge)?;
    assert!(text.contains("role = \"edge\""));
    assert!(text.contains(&format!(
        "coordinator_server_id = \"{}\"",
        edge.coordinator_server_id.to_base64url()
    )));
    for forbidden in [
        "account_service_hpke_private_key_file",
        "opaque_server_setup_file",
        "opaque_fake_credential_key_file",
        "sequencer_private_key_file",
        "sequencer_credentials_file",
    ] {
        assert!(!text.contains(forbidden), "{forbidden}");
    }
    Ok(())
}

#[test]
fn a_disabled_profile_omits_the_four_e2ee_lines_as_one_unit() -> TestResult {
    let mut facts = facts();
    facts.sequencer_key_set = None;
    let public = render_onboarding(&parse(PUBLIC)?, &facts)?;
    assert_eq!(public.lines().count(), 8);
    assert!(!public.contains("e2ee-profile") && !public.contains("sequencer-key-set"));
    let parsed = parse_onboarding_descriptor(&public)?;
    assert_eq!(parsed.sequencer_key_set, None);
    // A present block is parsed as a unit: a partial block, or one with
    // another profile, is refused.
    let offered = render_onboarding(&parse(PUBLIC)?, &self::facts())?;
    let generation_line = offered
        .lines()
        .find(|line| line.starts_with("sequencer-key-set-generation="))
        .ok_or("missing generation")?;
    for broken in [
        offered.replacen(&format!("{generation_line}\n"), "", 1),
        offered.replacen("e2ee-profile=IRC-MLS/1\n", "", 1),
        offered.replacen("e2ee-profile=IRC-MLS/1", "e2ee-profile=IRC-MLS/2", 1),
    ] {
        assert!(parse_onboarding_descriptor(&broken).is_err());
    }
    Ok(())
}
