#![forbid(unsafe_code)]

//! Stage 1 and 2 schema behavior: golden documents, unknown keys, duplicate keys,
//! the forbidden key-log key, structural stop, and the issue cap.

mod support;

use agenc_ircd_config::{
    Config, ConfigError, ListenerPurpose, MAX_REPORTED_ISSUES, NodeRole, PathResolver,
    RegistrationPolicy, SchemaKey, ValidationDepth, ValidationStage,
};
use support::{DUAL, ONION, PUBLIC, append_to_table, mutate, parse};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn golden_documents_parse_and_round_trip_through_typed_equality() -> TestResult {
    for text in [PUBLIC, ONION, DUAL] {
        let first = parse(text)?;
        let second = parse(text)?;
        assert_eq!(first, second);
    }
    let public = parse(PUBLIC)?;
    assert_eq!(public.network.role, NodeRole::Coordinator);
    assert_eq!(public.accounts.registration, RegistrationPolicy::Invite);
    assert_eq!(
        public.enabled_purposes(),
        vec![ListenerPurpose::ClientTls, ListenerPurpose::AdminLocal]
    );
    let onion = parse(ONION)?;
    assert!(onion.network.is_onion_only());
    assert_eq!(onion.accounts.registration, RegistrationPolicy::Closed);
    let dual = parse(DUAL)?;
    assert!(dual.federation.enabled && dual.e2ee.enabled);
    assert_eq!(dual.federation.peers.len(), 1);
    Ok(())
}

#[test]
fn every_table_and_array_element_rejects_an_unknown_key() {
    let tables = [
        "network",
        "server",
        "listeners",
        "tls",
        "federation",
        "storage",
        "accounts",
        "limits",
        "privacy",
        "moderation",
        "e2ee",
    ];
    for table in tables {
        let text = append_to_table(PUBLIC, table, "unknown_key = 1");
        let report = parse(&text).err();
        let issue = report
            .as_ref()
            .and_then(|report| report.issues().first().copied());
        assert_eq!(
            issue.map(|issue| (issue.stage, issue.error)),
            Some((ValidationStage::RootSchema, ConfigError::UnknownKey)),
            "table {table}"
        );
        assert_eq!(issue.map(|issue| issue.key.table()), Some(table));
    }
    for (old, new) in [
        (
            "max_connections = 4\n",
            "max_connections = 4\nunknown_key = 1\n",
        ),
        (
            "enabled = true\n\n[e2ee]",
            "enabled = true\nunknown_key = 1\n\n[e2ee]",
        ),
        ("burst = 8\n", "burst = 8\nunknown_key = 1\n"),
    ] {
        let text = mutate(PUBLIC, old, new);
        let report = parse(&text).err();
        assert!(
            report
                .as_ref()
                .is_some_and(|report| report.first_error() == ConfigError::UnknownKey),
            "element edit {old:?}"
        );
    }
    let peer = mutate(
        DUAL,
        "enabled = true\n\n[storage]",
        "enabled = true\nunknown_key = 1\n\n[storage]",
    );
    assert_eq!(
        parse(&peer).err().map(|report| report.first_error()),
        Some(ConfigError::UnknownKey)
    );
}

#[test]
fn root_rejects_unknown_tables_missing_tables_and_a_wrong_version() {
    let extra = format!("{PUBLIC}\n[extra]\nvalue = 1\n");
    assert_eq!(
        parse(&extra).err().map(|r| r.first_error()),
        Some(ConfigError::UnknownKey)
    );
    let missing = mutate(
        PUBLIC,
        "[tls]\ngroup_policy = \"hybrid_preferred\"\nsession_tickets = true\nticket_rotation_seconds = 21600\nticket_lifetime_seconds = 86400\nrequire_ocsp_staple = false\n",
        "",
    );
    let report = parse(&missing).err();
    assert!(report.as_ref().is_some_and(|report| {
        report.issues().iter().any(|issue| {
            issue.key == SchemaKey::new("tls", "") && issue.error == ConfigError::MissingValue
        })
    }));
    let version = mutate(PUBLIC, "config_version = 1", "config_version = 2");
    assert_eq!(
        parse(&version).err().map(|r| r.first_error()),
        Some(ConfigError::InvalidValue)
    );
    let absent = mutate(PUBLIC, "config_version = 1\n", "");
    assert_eq!(
        parse(&absent).err().map(|r| r.first_error()),
        Some(ConfigError::MissingValue)
    );
    let wrong_type = mutate(
        &missing,
        "config_version = 1\n",
        "config_version = 1\ntls = 5\n",
    );
    assert_eq!(
        parse(&wrong_type).err().map(|r| r.first_error()),
        Some(ConfigError::InvalidDocument)
    );
}

#[test]
fn toml_duplicate_keys_are_rejected_in_all_four_shapes() {
    let shapes = [
        mutate(
            PUBLIC,
            "config_version = 1\n",
            "config_version = 1\nconfig_version = 1\n",
        ),
        mutate(
            PUBLIC,
            "display_name = \"example\"\n",
            "display_name = \"example\"\ndisplay_name = \"example\"\n",
        ),
        mutate(
            PUBLIC,
            "allowed_gids = []\n",
            "allowed_gids = []\nextra = { a = 1, a = 2 }\n",
        ),
        format!("{PUBLIC}\n[tls]\nsession_tickets = false\n"),
    ];
    for text in shapes {
        let report = parse(&text).err();
        assert_eq!(
            report.map(|r| r.first_error()),
            Some(ConfigError::InvalidDocument)
        );
    }
}

#[test]
fn tls_key_log_file_is_an_unknown_key_and_implicit_conversion_is_refused() {
    let key_log = append_to_table(PUBLIC, "tls", "key_log_file = \"/tmp/keys.log\"");
    let report = parse(&key_log).err();
    assert!(report.as_ref().is_some_and(|report| {
        report.issues().iter().any(|issue| {
            issue.key == SchemaKey::new("tls", "") && issue.error == ConfigError::UnknownKey
        })
    }));
    let stringly = mutate(PUBLIC, "dns_port = 6697", "dns_port = \"6697\"");
    assert_eq!(
        parse(&stringly).err().map(|r| r.first_error()),
        Some(ConfigError::MissingValue)
    );
    let negative = mutate(PUBLIC, "dns_port = 6697", "dns_port = -1");
    assert_eq!(
        parse(&negative).err().map(|r| r.first_error()),
        Some(ConfigError::InvalidValue)
    );
    let empty = mutate(PUBLIC, "display_name = \"example\"", "display_name = \"\"");
    assert_eq!(
        parse(&empty).err().map(|r| r.first_error()),
        Some(ConfigError::InvalidValue)
    );
    let boolean = mutate(PUBLIC, "allow_guests = true", "allow_guests = 1");
    assert_eq!(
        parse(&boolean).err().map(|r| r.first_error()),
        Some(ConfigError::MissingValue)
    );
}

#[test]
fn structural_failure_stops_before_cross_field_stages() {
    // A scalar failure plus a cross-field failure: only the structural issue is reported.
    let text = mutate(
        &mutate(PUBLIC, "dns_port = 6697", "dns_port = 70000"),
        "coordinator_server_id = \"AgICAgICAgICAgICAgICAg\"\ndns_name",
        "coordinator_server_id = \"AwMDAwMDAwMDAwMDAwMDAw\"\ndns_name",
    );
    let report = parse(&text).err();
    assert!(
        report
            .as_ref()
            .is_some_and(|report| report.has_structural_issue())
    );
    assert!(report.as_ref().is_some_and(|report| {
        report
            .issues()
            .iter()
            .all(|issue| issue.stage.is_structural())
    }));
}

#[test]
fn issues_accumulate_across_tables_up_to_the_cap() {
    let mut text = PUBLIC.to_owned();
    for name in [
        "client_connections",
        "tls_handshakes",
        "direct_connections_per_address",
        "sessions_per_account",
    ] {
        text = mutate(&text, &format!("{name} = "), &format!("{name} = 0 #"));
    }
    let report = parse(&text).err();
    assert_eq!(report.as_ref().map(|report| report.issues().len()), Some(4));
    let mut flood = String::from("config_version = 1\n[network]\n");
    for index in 0..(MAX_REPORTED_ISSUES + 10) {
        flood.push_str(&format!("unknown_{index} = 1\n"));
    }
    // One unknown-key issue per table at most; the cap is exercised by the sink itself.
    let report = parse(&flood).err();
    assert!(
        report
            .as_ref()
            .is_some_and(|report| !report.issues().is_empty())
    );
    assert!(
        report
            .as_ref()
            .is_some_and(|report| report.issues().len() <= MAX_REPORTED_ISSUES)
    );
}

#[test]
fn relative_paths_resolve_only_against_a_base() -> TestResult {
    let relative = mutate(PUBLIC, "data_dir = \"/srv/agenc\"", "data_dir = \"data\"").replace(
        "state_dir = \"/srv/agenc/state\"",
        "state_dir = \"data/state\"",
    );
    assert_eq!(
        parse(&relative).err().map(|r| r.first_error()),
        Some(ConfigError::InvalidValue)
    );
    let resolver = PathResolver::with_base("/srv/agenc-root".into())?;
    let config = Config::parse_text(&relative, &resolver, ValidationDepth::Document)?;
    assert_eq!(
        config.server.data_dir,
        std::path::PathBuf::from("/srv/agenc-root/data")
    );
    assert_eq!(
        config.storage.state_dir,
        std::path::PathBuf::from("/srv/agenc-root/data/state")
    );
    let dotted = mutate(
        PUBLIC,
        "data_dir = \"/srv/agenc\"",
        "data_dir = \"/srv/../agenc\"",
    );
    assert_eq!(
        parse(&dotted).err().map(|r| r.first_error()),
        Some(ConfigError::InvalidValue)
    );
    assert!(PathResolver::with_base("relative".into()).is_err());
    Ok(())
}

#[test]
fn client_wss_parses_fully_but_enabling_it_is_deferred_to_stage_nine() -> TestResult {
    let disabled = mutate(
        PUBLIC,
        "purpose = \"client_tls\"\nbind = \"203.0.113.1:6697\"",
        "purpose = \"client_wss\"\nbind = \"203.0.113.1:6697\"\nallowed_origins = [\"https://chat.example\"]",
    )
    .replace("name = \"public\"\nenabled = true", "name = \"public\"\nenabled = false");
    let report = parse(&disabled).err();
    // Disabled WSS parses; the only remaining issue is that no client listener serves DNS.
    assert!(report.as_ref().is_some_and(|report| {
        report
            .issues()
            .iter()
            .all(|issue| issue.stage == ValidationStage::LocalIdentity)
    }));
    let enabled = mutate(
        PUBLIC,
        "purpose = \"client_tls\"\nbind = \"203.0.113.1:6697\"",
        "purpose = \"client_wss\"\nbind = \"203.0.113.1:6697\"\nallowed_origins = [\"https://chat.example\"]",
    );
    let report = parse(&enabled).err();
    assert!(report.as_ref().is_some_and(|report| {
        report.issues().iter().any(|issue| {
            issue.error == ConfigError::DeferredTransport
                && issue.stage == ValidationStage::ListenerUnion
        })
    }));
    Ok(())
}
