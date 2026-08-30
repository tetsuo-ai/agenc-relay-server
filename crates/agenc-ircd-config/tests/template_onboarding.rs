#![forbid(unsafe_code)]

//! The init template renders and re-parses for every profile, and the onboarding
//! descriptor has the exact line order and literal tokens.

mod support;

use agenc_ircd_config::{
    BASE_PROFILE_SHA256_TOKEN, ConfigError, DisplayLabel, DnsName, E2EE_PROFILE_SHA256_TOKEN,
    InitProfile, InitValues, NodeRole, OnboardingFacts, OperatorTemplate, ValidationStage,
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
            operator_id: OperatorId::from_bytes([4; 16]),
            signing_public_key: [6; 32],
        },
    })
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
        sequencer_key_set_generation: 3,
        sequencer_key_set_hash: [11; 32],
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
        "g3AiB-HhFTyHItXMZop9G6uFulGPzd4DCjaBG0G9zEA"
    );
    assert_eq!(
        E2EE_PROFILE_SHA256_TOKEN,
        "lk0p96oG1QiE3t2W0fUBHPAVUls5iUpFNX-6k9Xou3M"
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
