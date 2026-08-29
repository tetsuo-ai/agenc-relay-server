#![forbid(unsafe_code)]

//! Remaining branch edges: cross-field duplicates, array ceilings, scalar literals,
//! report rendering, path resolution, and secret-file identity checks.

mod support;

use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};

use agenc_ircd_config::{
    Config, ConfigError, HttpsOrigin, PathResolver, RATE_ROWS, RegistrationPolicy, SchemaKey,
    SecretLength, SecretSet, SocksEndpoint, ValidationDepth, ValidationStage, allocation_charge,
    load_config, open_secret_file, open_secret_file_with_hook,
};
use support::{DUAL, PUBLIC, Sandbox, edge, mutate, parse};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn has_issue(text: &str, stage: ValidationStage, key: &SchemaKey) -> bool {
    parse(text).err().is_some_and(|report| {
        report
            .issues()
            .iter()
            .any(|issue| issue.stage == stage && issue.key == *key)
    })
}

fn has_field(text: &str, field: &str) -> bool {
    parse(text).err().is_some_and(|report| {
        report
            .issues()
            .iter()
            .any(|issue| issue.key.field() == field)
    })
}

const SECOND_PEER: &str = "[[federation.peer]]\nserver_id = \"BAQEBAQEBAQEBAQEBAQEBA\"\nserver_name = \"third.example\"\nrole = \"edge\"\nrecovery_epoch = \"CQkJCQkJCQkJCQkJCQkJCQ\"\nendpoints = []\ncertificate_spki_sha256 = \"BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY\"\nsigning_public_key = \"BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU\"\nenabled = true\n";

fn with_second_peer(edit: impl Fn(&str) -> String) -> String {
    let peer = edit(SECOND_PEER);
    mutate(
        DUAL,
        "enabled = true\n\n[storage]",
        &format!("enabled = true\n\n{peer}\n[storage]"),
    )
}

#[test]
fn peer_records_reject_every_duplicate_identity() {
    let stage = ValidationStage::Topology;
    let cases = [
        (
            "BAQEBAQEBAQEBAQEBAQEBA",
            "AwMDAwMDAwMDAwMDAwMDAw",
            "server_id",
        ),
        ("third.example", "edge.example", "server_name"),
        ("third.example", "chat.example", "server_name"),
        (
            "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY",
            "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
            "certificate_spki_sha256",
        ),
        (
            "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU",
            "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg",
            "signing_public_key",
        ),
    ];
    assert!(parse(&with_second_peer(|peer| peer.to_owned())).is_ok());
    for (old, new, field) in cases {
        let text = with_second_peer(|peer| peer.replacen(old, new, 1));
        assert!(
            has_issue(
                &text,
                stage,
                &SchemaKey::indexed("federation.peer", 1, field)
            ),
            "{field}"
        );
    }
    let edge_role = mutate(
        &edge(),
        "server_name = \"hub.example\"\nrole = \"coordinator\"",
        "server_name = \"hub.example\"\nrole = \"edge\"",
    );
    assert!(has_issue(
        &edge_role,
        stage,
        &SchemaKey::indexed("federation.peer", 0, "role")
    ));
    let many: Vec<String> = (0..9)
        .map(|index| format!("\"tcp:203.0.113.{}:7000\"", index + 10))
        .collect();
    let too_many = mutate(
        &edge(),
        "endpoints = [\"tcp:203.0.113.5:7000\"]",
        &format!("endpoints = [{}]", many.join(", ")),
    );
    assert!(has_field(&too_many, "endpoints"));
    let duplicate = mutate(
        &edge(),
        "endpoints = [\"tcp:203.0.113.5:7000\"]",
        "endpoints = [\"tcp:203.0.113.5:7000\", \"tcp:203.0.113.5:7000\"]",
    );
    assert!(has_issue(
        &duplicate,
        ValidationStage::Scalars,
        &SchemaKey::indexed("federation.peer", 0, "endpoints")
    ));
    let with_socks = mutate(
        &mutate(
            &edge(),
            "endpoints = [\"tcp:203.0.113.5:7000\"]",
            &format!("endpoints = [\"onion:{}.onion:6697\"]", "c".repeat(56)),
        ),
        "[federation]\nenabled = true\n",
        "[federation]\nenabled = true\ntor_socks_endpoint = \"127.0.0.1:9050\"\n",
    );
    assert!(
        parse(&with_socks).is_ok(),
        "{:?}",
        parse(&with_socks).err().map(|r| r.to_string())
    );
    let no_signing = mutate(
        DUAL,
        "signing_private_key_file = \"/etc/agenc/keys/federation-signing.key\"\n",
        "",
    );
    assert!(has_issue(
        &no_signing,
        stage,
        &SchemaKey::new("federation", "signing_private_key_file")
    ));
}

const SECOND_OPERATOR: &str = "[[moderation.operator]]\noperator_id = \"BgYGBgYGBgYGBgYGBgYGBg\"\ndisplay_label = \"second\"\nsigning_public_key = \"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc\"\npermissions = [\"observe\"]\nenabled = true\n";

fn with_second_operator(golden: &str, operator: &str) -> String {
    mutate(
        golden,
        "enabled = true\n\n[e2ee]",
        &format!("enabled = true\n\n{operator}\n[e2ee]"),
    )
}

#[test]
fn operator_records_reject_every_duplicate_identity() {
    let stage = ValidationStage::Topology;
    assert!(parse(&with_second_operator(PUBLIC, SECOND_OPERATOR)).is_ok());
    let same_key = SECOND_OPERATOR.replacen(
        "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
        "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY",
        1,
    );
    assert!(has_issue(
        &with_second_operator(PUBLIC, &same_key),
        stage,
        &SchemaKey::indexed("moderation.operator", 1, "signing_public_key")
    ));
    let same_uid = SECOND_OPERATOR.replacen("permissions", "local_uids = [1000]\npermissions", 1);
    assert!(has_issue(
        &with_second_operator(PUBLIC, &same_uid),
        stage,
        &SchemaKey::indexed("moderation.operator", 1, "local_uids")
    ));
    let same_gid = SECOND_OPERATOR.replacen("permissions", "local_gids = [100]\npermissions", 1);
    let base = mutate(
        &mutate(PUBLIC, "local_gids = []", "local_gids = [100]"),
        "allowed_gids = []",
        "allowed_gids = [100]",
    );
    assert!(has_issue(
        &with_second_operator(&base, &same_gid),
        stage,
        &SchemaKey::indexed("moderation.operator", 1, "local_gids")
    ));
    let same_pin = SECOND_OPERATOR.replacen(
        "permissions",
        "certificate_spki_sha256 = \"BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU\"\npermissions",
        1,
    );
    assert!(has_issue(
        &with_second_operator(DUAL, &same_pin),
        stage,
        &SchemaKey::indexed("moderation.operator", 1, "certificate_spki_sha256")
    ));
    let disabled = mutate(
        DUAL,
        "enabled = true\n\n[e2ee]",
        "enabled = false\n\n[e2ee]",
    );
    assert!(has_issue(
        &disabled,
        stage,
        &SchemaKey::new("moderation", "operator")
    ));
    let start = DUAL.find("[[listeners.endpoint]]\nname = \"admin\"\n");
    let end = DUAL.find("[[listeners.endpoint]]\nname = \"admin-tls\"");
    if let (Some(start), Some(end)) = (start, end) {
        let without_local = format!("{}{}", &DUAL[..start], &DUAL[end..]);
        assert!(!has_field(&without_local, "local_uids"));
    } else {
        assert!(
            start.is_some() && end.is_some(),
            "dual golden lost its admin listeners"
        );
    }
}

#[test]
fn listener_unions_cover_the_remaining_shapes() {
    let second_admin_tls = "[[listeners.endpoint]]\nname = \"admin-tls-2\"\nenabled = false\npurpose = \"admin_tls\"\nbind = \"203.0.113.1:7002\"\nmax_connections = 4\ntls_certificate_file = \"/etc/agenc/tls/admin.crt\"\ntls_private_key_file = \"/etc/agenc/tls/admin.key\"\nclient_ca_file = \"/etc/agenc/tls/admin-ca.pem\"\n";
    let text = mutate(
        DUAL,
        "client_ca_file = \"/etc/agenc/tls/admin-ca.pem\"\n",
        &format!("client_ca_file = \"/etc/agenc/tls/admin-ca.pem\"\n\n{second_admin_tls}"),
    );
    assert!(has_issue(
        &text,
        ValidationStage::ListenerUnion,
        &SchemaKey::new("listeners", "endpoint")
    ));

    let wss = |extra: &str| {
        mutate(
            PUBLIC,
            "allowed_gids = []\n",
            &format!(
                "allowed_gids = []\n\n[[listeners.endpoint]]\nname = \"browser\"\nenabled = false\npurpose = \"client_wss\"\nbind = \"203.0.113.1:443\"\nmax_connections = 100\ntls_certificate_file = \"/etc/agenc/tls/server.crt\"\ntls_private_key_file = \"/etc/agenc/tls/server.key\"\n{extra}"
            ),
        )
    };
    assert!(parse(&wss("allow_missing_origin = true\n")).is_ok());
    let origins: Vec<String> = (0..65)
        .map(|index| format!("\"https://o{index}.example\""))
        .collect();
    assert!(has_field(
        &wss(&format!("allowed_origins = [{}]\n", origins.join(", "))),
        "allowed_origins"
    ));
    assert!(has_field(
        &wss("allowed_origins = [\"\"]\n"),
        "allowed_origins"
    ));
    assert!(!has_field(
        &wss(
            "allowed_origins = [\"https://[2001:db8::1]\", \"https://[2001:db8::1]:8443\", \"https://192.0.2.7\"]\n"
        ),
        "allowed_origins"
    ));

    let uids: Vec<String> = (0..65).map(|index| (1000 + index).to_string()).collect();
    assert!(has_field(
        &mutate(
            PUBLIC,
            "allowed_uids = [1000]",
            &format!("allowed_uids = [{}]", uids.join(", "))
        ),
        "allowed_uids"
    ));
    assert!(has_field(
        &mutate(PUBLIC, "max_connections = 50000", "max_connections = 0"),
        "max_connections"
    ));
    assert!(has_field(
        &mutate(
            PUBLIC,
            "allowed_uids = [1000]",
            "allowed_uids = [1000]\ntls_certificate_file = \"/etc/agenc/tls/a.crt\"\ntls_private_key_file = \"/etc/agenc/tls/a.key\""
        ),
        "tls_certificate_file"
    ));
    assert!(has_field(
        &mutate(
            PUBLIC,
            "tls_private_key_file = \"/etc/agenc/tls/server.key\"\n",
            ""
        ),
        "tls_certificate_file"
    ));
    assert!(has_field(
        &mutate(
            PUBLIC,
            "max_connections = 50000",
            "max_connections = 50000\nallow_missing_origin = true"
        ),
        "allowed_origins"
    ));
    assert!(has_field(
        &mutate(
            PUBLIC,
            "max_connections = 50000",
            "max_connections = 50000\nallowed_gids = [5]"
        ),
        "allowed_uids"
    ));
    for (bind, ok) in [
        ("[2001:db8::1]:6697", true),
        ("[::]:6697", false),
        ("[ff02::1]:6697", false),
        ("255.255.255.255:6697", false),
    ] {
        let text = mutate(
            PUBLIC,
            "bind = \"203.0.113.1:6697\"",
            &format!("bind = \"{bind}\""),
        );
        assert_eq!(!has_field(&text, "bind"), ok, "{bind}");
    }
}

#[test]
fn identity_rules_cover_edge_and_directory_edges() {
    let quiet_edge = mutate(
        &mutate(
            &mutate(
                &edge(),
                "[accounts]\n",
                "[accounts]\naccept_clients = false\n",
            ),
            "name = \"public\"\nenabled = true",
            "name = \"public\"\nenabled = false",
        ),
        "name = \"onion\"\nenabled = true",
        "name = \"onion\"\nenabled = false",
    );
    assert!(!has_issue(
        &quiet_edge,
        ValidationStage::LocalIdentity,
        &SchemaKey::new("listeners", "endpoint")
    ));
    let stage = ValidationStage::LocalIdentity;
    assert!(has_issue(
        &mutate(
            PUBLIC,
            "state_dir = \"/srv/agenc/state\"",
            "state_dir = \"/srv/agenc\""
        ),
        stage,
        &SchemaKey::new("storage", "state_dir")
    ));
    assert!(has_field(
        &mutate(
            PUBLIC,
            "backup_dir = \"/srv/agenc-backups\"",
            "backup_dir = \"/run/agenc/backups\""
        ),
        "backup_dir"
    ));
    assert!(has_field(
        &mutate(
            PUBLIC,
            "backup_dir = \"/srv/agenc-backups\"",
            "backup_dir = \"/srv/agenc\""
        ),
        "backup_dir"
    ));
}

#[test]
fn table_arrays_enforce_presence_and_ceilings() {
    let start = PUBLIC.find("[[moderation.operator]]\n");
    let end = PUBLIC.find("[e2ee]");
    let (Some(start), Some(end)) = (start, end) else {
        assert!(
            start.is_some() && end.is_some(),
            "public golden lost its operator"
        );
        return;
    };
    let without = format!("{}{}", &PUBLIC[..start], &PUBLIC[end..]);
    assert!(
        parse(&without)
            .err()
            .is_some_and(|report| report.issues().iter().any(|issue| {
                issue.key.field() == "operator" && issue.error == ConfigError::MissingValue
            }))
    );
    let operators = |count: usize| -> String {
        let blocks: Vec<String> = (0..count)
            .map(|index| {
                let first = char::from(ALPHABET.get(index % 64).copied().unwrap_or(b'A'));
                let second = if index >= 64 { 'B' } else { 'A' };
                format!(
                    "[[moderation.operator]]\noperator_id = \"{first}{second}QEBAQEBAQEBAQEBAQEBA\"\ndisplay_label = \"op{index}\"\nsigning_public_key = \"{first}{second}YGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY\"\npermissions = [\"observe\"]\nenabled = true\n\n"
                )
            })
            .collect();
        format!("{}{}{}", &PUBLIC[..start], blocks.concat(), &PUBLIC[end..])
    };
    assert!(
        parse(&operators(64)).is_ok(),
        "{:?}",
        parse(&operators(64)).err().map(|r| r.to_string())
    );
    assert!(
        parse(&operators(65))
            .err()
            .is_some_and(|report| report.issues().iter().any(|issue| {
                issue.key.field() == "operator" && issue.error == ConfigError::InvalidValue
            }))
    );
}

#[test]
fn optional_rows_and_registration_fall_back_to_defaults() -> TestResult {
    let Some(row) = RATE_ROWS.first() else {
        return Err("rate table is empty".into());
    };
    let block = format!(
        "[limits.rate.{}]\nrefill_tokens = {}\nrefill_seconds = {}\nburst = {}\n",
        row.name, row.default.refill_tokens, row.default.refill_seconds, row.default.burst
    );
    let config = parse(&mutate(PUBLIC, &block, ""))?;
    assert_eq!(config.limits.rates.get(row.key), row.default);
    let config = parse(&mutate(PUBLIC, "registration = \"invite\"\n", ""))?;
    assert_eq!(config.accounts.registration, RegistrationPolicy::Invite);
    for (old, field) in [
        (
            "coordinator_server_id = \"AgICAgICAgICAgICAgICAg\"\nsequencer_private_key_file",
            "coordinator_server_id",
        ),
        (
            "sequencer_credentials_file = \"/etc/agenc/trust/sequencer-credentials.toml\"\n",
            "sequencer_credentials_file",
        ),
    ] {
        let new = if field == "coordinator_server_id" {
            "sequencer_private_key_file"
        } else {
            ""
        };
        let report = parse(&mutate(DUAL, old, new)).err();
        assert!(
            report.is_some_and(|report| report.issues().iter().any(|issue| {
                issue.key == SchemaKey::new("e2ee", field)
                    && issue.error == ConfigError::MissingValue
            }))
        );
    }
    assert_eq!(allocation_charge(0), Some(0));
    assert_eq!(allocation_charge(1), Some(4096));
    assert_eq!(allocation_charge(u64::MAX), None);
    Ok(())
}

#[test]
fn structural_issues_stop_before_cross_field_rules_and_reports_render() {
    let text = mutate(
        &mutate(PUBLIC, "[privacy]\n", "[privacy]\nbogus = 1\n"),
        "crypto_worker_threads = 4",
        "crypto_worker_threads = 13",
    );
    let report = parse(&text).err();
    assert!(
        report
            .as_ref()
            .is_some_and(|report| report.has_structural_issue())
    );
    assert!(
        report
            .as_ref()
            .is_some_and(|report| report.all(|issue| issue.stage == ValidationStage::RootSchema))
    );
    assert!(report.is_some_and(|report| report.to_string()
        == "root-schema: privacy: configuration key is outside the closed schema"));

    let start = PUBLIC.find("[[moderation.operator]]\n").unwrap_or(0);
    let end = PUBLIC.find("[e2ee]").unwrap_or(0);
    assert!(start > 0 && end > start, "public golden lost its operator");
    let operators: Vec<String> = (0..64)
        .map(|index| {
            let first = char::from(ALPHABET.get(index).copied().unwrap_or(b'A'));
            format!("[[moderation.operator]]\noperator_id = \"{first}AQEBAQEBAQEBAQEBAQEBA\"\ndisplay_label = \"bad label\"\nsigning_public_key = \"short\"\npermissions = []\nenabled = true\n\n")
        })
        .collect();
    let flood = format!(
        "{}{}{}",
        &PUBLIC[..start],
        operators.concat(),
        &PUBLIC[end..]
    );
    let report = parse(&flood).err();
    assert!(
        report
            .as_ref()
            .is_some_and(|report| report.is_truncated() && report.issues().len() == 100)
    );
    let rendered = report.map(|report| report.to_string()).unwrap_or_default();
    assert!(rendered.ends_with("; further issues omitted"));
    assert_eq!(rendered.matches("; ").count(), 100);

    assert_eq!(
        SchemaKey::indexed("listeners.endpoint", 2, "bind").to_string(),
        "listeners.endpoint[2].bind"
    );
    assert_eq!(SchemaKey::new("limits.rate", "").to_string(), "limits.rate");
    for stage in [
        ValidationStage::RootSchema,
        ValidationStage::Scalars,
        ValidationStage::PathsAndFileTypes,
        ValidationStage::KeyParsing,
        ValidationStage::LocalIdentity,
        ValidationStage::ListenerUnion,
        ValidationStage::Topology,
        ValidationStage::ResourceArithmetic,
        ValidationStage::DatabaseHeader,
        ValidationStage::E2eeCompatibility,
    ] {
        assert!(
            stage
                .as_str()
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        );
        assert_eq!(
            stage.is_structural(),
            matches!(
                stage,
                ValidationStage::RootSchema | ValidationStage::Scalars
            )
        );
    }
    for error in [
        ConfigError::FileRejected,
        ConfigError::InvalidDocument,
        ConfigError::MissingValue,
        ConfigError::InvalidValue,
        ConfigError::UnknownKey,
        ConfigError::Overflow,
        ConfigError::Topology,
        ConfigError::HostControl,
        ConfigError::DeferredTransport,
    ] {
        assert!(!error.to_string().is_empty());
    }
}

#[test]
fn scalar_literals_cover_ipv6_origins_socks_and_base64_lengths() {
    assert!(has_field(
        &mutate(
            PUBLIC,
            "network_id = \"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE\"",
            "network_id = \"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ\""
        ),
        "network_id"
    ));
    assert!(has_field(
        &mutate(
            PUBLIC,
            "network_id = \"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE\"",
            "network_id = \"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQB\""
        ),
        "network_id"
    ));
    for good in [
        "https://[2001:db8::1]",
        "https://[2001:db8::1]:8443",
        "https://192.0.2.1",
        "https://chat.example:8443",
    ] {
        assert!(
            HttpsOrigin::parse(good).is_ok_and(|origin| origin.as_str() == good),
            "{good}"
        );
    }
    for bad in [
        "https://[::1]x:443",
        "https://[2001:db8::1",
        "https://chat.example:",
        "https://192.0.2.1:70000",
        "https://[2001:DB8::1]",
        "https://exa_mple",
        "https://",
    ] {
        assert_eq!(
            HttpsOrigin::parse(bad).err(),
            Some(ConfigError::InvalidValue),
            "{bad}"
        );
    }
    assert_eq!(
        SocksEndpoint::parse("/run/tor/socks"),
        Ok(SocksEndpoint::Unix(PathBuf::from("/run/tor/socks")))
    );
    assert_eq!(
        SocksEndpoint::parse("/run/../socks").err(),
        Some(ConfigError::InvalidValue)
    );
    assert_eq!(
        SocksEndpoint::parse("10.0.0.1:9050").err(),
        Some(ConfigError::InvalidValue)
    );
    assert!(matches!(
        SocksEndpoint::parse("127.0.0.1:9050"),
        Ok(SocksEndpoint::Loopback(_))
    ));
    assert!(matches!(
        SocksEndpoint::parse("[::1]:9050"),
        Ok(SocksEndpoint::Loopback(_))
    ));
    assert_eq!(
        SocksEndpoint::parse("localhost:9050").err(),
        Some(ConfigError::InvalidValue)
    );
}

#[test]
fn path_resolution_rejects_relative_and_dotted_input() -> TestResult {
    assert!(PathResolver::with_base(PathBuf::from("relative")).is_err());
    assert!(PathResolver::with_base(PathBuf::from("/tmp/../x")).is_err());
    let resolver = PathResolver::with_base(PathBuf::from("/etc/agenc"))?;
    assert!(resolver.resolve("../x").is_err());
    assert!(resolver.resolve("/abs/../x").is_err());
    assert_eq!(
        resolver.resolve("keys/x")?,
        PathBuf::from("/etc/agenc/keys/x")
    );
    assert_eq!(resolver.resolve("/abs/x")?, PathBuf::from("/abs/x"));
    let none = PathResolver::none();
    assert!(none.resolve("keys/x").is_err());
    assert_eq!(none.resolve("/abs/x")?, PathBuf::from("/abs/x"));

    let sandbox = Sandbox::create()?;
    sandbox.populate_host_layout()?;
    let text = sandbox.localize(PUBLIC);
    let path = sandbox.config_file(&text)?;
    let link = sandbox.root().join("etc/link.toml");
    symlink(&path, &link)?;
    assert!(load_config(&link, ValidationDepth::Document).is_err());
    assert!(PathResolver::for_config_file(&path).is_ok());
    assert!(PathResolver::for_config_file(Path::new("/nonexistent-dir/config.toml")).is_err());

    let resolver = PathResolver::with_base(sandbox.root().join("etc"))?;
    let host = |text: &str| Config::parse_text(text, &resolver, ValidationDepth::Host);
    sandbox.file("etc/motd.txt", b"welcome\n", 0o644)?;
    let with_motd = text.replace(
        "[privacy]\n",
        &format!(
            "[privacy]\nmotd_file = \"{}/etc/motd.txt\"\n",
            sandbox.root().display()
        ),
    );
    assert!(
        host(&with_motd).is_ok(),
        "{:?}",
        host(&with_motd).err().map(|r| r.to_string())
    );
    let nested = text.replace(
        "keys/storage-master.key\"",
        "keys/storage-master.key/inner\"",
    );
    assert!(
        host(&nested)
            .err()
            .is_some_and(|report| report.issues().iter().any(|issue| {
                issue.stage == ValidationStage::PathsAndFileTypes
                    && issue.key.field() == "master_key_file"
            }))
    );
    fs::remove_dir_all(sandbox.root().join("data/state"))?;
    sandbox.file("data/state", b"", 0o700)?;
    assert!(host(&text).err().is_some_and(|report| {
        report
            .issues()
            .iter()
            .any(|issue| issue.key.field() == "state_dir")
    }));
    fs::remove_file(sandbox.root().join("data/state"))?;
    sandbox.dir("data/real-state", 0o700)?;
    symlink(
        sandbox.root().join("data/real-state"),
        sandbox.root().join("data/state"),
    )?;
    assert!(host(&text).err().is_some_and(|report| {
        report
            .issues()
            .iter()
            .any(|issue| issue.key.field() == "state_dir")
    }));
    Ok(())
}

#[test]
fn secret_identity_is_rechecked_after_open() -> TestResult {
    assert_eq!(
        open_secret_file(Path::new("/tmp/../x.key"), SecretLength::Exact(32)).err(),
        Some(ConfigError::FileRejected)
    );
    let sandbox = Sandbox::create()?;
    let path = sandbox.file("keys/mode.key", &[7; 32], 0o600)?;
    let loosen = || {
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o640));
    };
    assert_eq!(
        open_secret_file_with_hook(&path, SecretLength::Exact(32), loosen).err(),
        Some(ConfigError::FileRejected)
    );
    let grow = sandbox.file("keys/grow.key", &[7; 32], 0o600)?;
    let append = || {
        let _ = fs::write(&grow, [7; 33]);
    };
    assert_eq!(
        open_secret_file_with_hook(&grow, SecretLength::Exact(32), append).err(),
        Some(ConfigError::FileRejected)
    );

    sandbox.populate_host_layout()?;
    let resolver = PathResolver::with_base(sandbox.root().join("etc"))?;
    let text = sandbox.localize(PUBLIC).replace("login_index_key_file = ", &format!("login_index_previous_key_file = \"{}/etc/keys/login-index-g0.key\"\nlogin_index_key_file = ", sandbox.root().display()));
    sandbox.file("etc/keys/login-index-g0.key", &[1; 32], 0o600)?;
    let config = Config::parse_text(&text, &resolver, ValidationDepth::Host)?;
    assert!(
        SecretSet::load(&config)
            .err()
            .is_some_and(|report| report.issues().iter().any(|issue| {
                issue.stage == ValidationStage::KeyParsing
                    && issue.key.field() == "login_index_previous_key_file"
            }))
    );
    sandbox.file("etc/keys/login-index-g0.key", &[0x33; 32], 0o600)?;
    assert!(SecretSet::load(&config)?.login_index_previous().is_some());
    Ok(())
}
