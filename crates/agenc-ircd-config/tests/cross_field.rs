#![forbid(unsafe_code)]

//! The stage 5 through 8 cross-field matrix: one mutation per rule, asserting the
//! stage and static key of the reported issue.

mod support;

use agenc_ircd_config::{ConfigError, SchemaKey, ValidationStage};
use support::{DUAL, PUBLIC, SRV3, append_to_table, edge, mutate, parse};

struct Case {
    label: &'static str,
    text: String,
    stage: ValidationStage,
    key: SchemaKey,
}

fn case(label: &'static str, text: String, stage: ValidationStage, key: SchemaKey) -> Case {
    Case {
        label,
        text,
        stage,
        key,
    }
}

fn identity_cases() -> Vec<Case> {
    let stage = ValidationStage::LocalIdentity;
    vec![
        case(
            "coordinator id differs from local id",
            mutate(
                PUBLIC,
                "coordinator_server_id = \"AgICAgICAgICAgICAgICAg\"\ndns_name",
                &format!("coordinator_server_id = \"{SRV3}\"\ndns_name"),
            ),
            stage,
            SchemaKey::new("network", "coordinator_server_id"),
        ),
        case(
            "edge id equals coordinator id",
            mutate(PUBLIC, "role = \"coordinator\"", "role = \"edge\""),
            stage,
            SchemaKey::new("network", "coordinator_server_id"),
        ),
        case(
            "e2ee coordinator differs from network coordinator",
            mutate(
                DUAL,
                "coordinator_server_id = \"AgICAgICAgICAgICAgICAg\"\nsequencer_private_key_file",
                &format!("coordinator_server_id = \"{SRV3}\"\nsequencer_private_key_file"),
            ),
            stage,
            SchemaKey::new("e2ee", "coordinator_server_id"),
        ),
        case(
            "federated server name over 127 bytes",
            mutate(
                DUAL,
                "\nname = \"chat.example\"",
                &format!(
                    "\nname = \"{}.{}.{}.example\"",
                    "a".repeat(60),
                    "b".repeat(60),
                    "c".repeat(10)
                ),
            ),
            stage,
            SchemaKey::new("server", "name"),
        ),
        case(
            "no enabled client listener",
            mutate(
                PUBLIC,
                "name = \"public\"\nenabled = true",
                "name = \"public\"\nenabled = false",
            ),
            stage,
            SchemaKey::new("listeners", "endpoint"),
        ),
        case(
            "onion endpoint without an onion listener",
            mutate(
                DUAL,
                "name = \"onion\"\nenabled = true",
                "name = \"onion\"\nenabled = false",
            ),
            stage,
            SchemaKey::new("network", "onion_address"),
        ),
        case(
            "invite registration without a verification key",
            mutate(
                PUBLIC,
                "invite_verification_key_file = \"/etc/agenc/keys/invite-verification.pub\"\n",
                "",
            ),
            stage,
            SchemaKey::new("accounts", "invite_verification_key_file"),
        ),
        case(
            "coordinator material on an edge",
            mutate(
                &edge(),
                "account_service_hpke_public_key = ",
                "opaque_server_setup_file = \"/etc/agenc/keys/opaque-server-setup.key\"\naccount_service_hpke_public_key = ",
            ),
            stage,
            SchemaKey::new("accounts", "opaque_server_setup_file"),
        ),
        case(
            "coordinator without its HPKE private key",
            mutate(
                PUBLIC,
                "account_service_hpke_private_key_file = \"/etc/agenc/keys/account-service-hpke.key\"\n",
                "",
            ),
            stage,
            SchemaKey::new("accounts", "account_service_hpke_private_key_file"),
        ),
        case(
            "sequencer key on a node that is not the E2EE coordinator",
            mutate(
                &edge(),
                "[e2ee]\nenabled = true\n",
                "[e2ee]\nenabled = true\nsequencer_private_key_file = \"/etc/agenc/keys/sequencer.key\"\n",
            ),
            stage,
            SchemaKey::new("e2ee", "sequencer_private_key_file"),
        ),
        case(
            "state directory outside the data directory",
            mutate(
                PUBLIC,
                "state_dir = \"/srv/agenc/state\"",
                "state_dir = \"/srv/elsewhere\"",
            ),
            stage,
            SchemaKey::new("storage", "state_dir"),
        ),
        case(
            "backup directory inside the state directory",
            mutate(
                PUBLIC,
                "backup_dir = \"/srv/agenc-backups\"",
                "backup_dir = \"/srv/agenc/state/backups\"",
            ),
            stage,
            SchemaKey::new("storage", "state_dir"),
        ),
        case(
            "runtime directory equals the data directory",
            mutate(
                PUBLIC,
                "runtime_dir = \"/run/agenc\"",
                "runtime_dir = \"/srv/agenc\"",
            ),
            stage,
            SchemaKey::new("server", "runtime_dir"),
        ),
        case(
            "secret inside the state directory",
            mutate(
                PUBLIC,
                "master_key_file = \"/etc/agenc/keys/storage-master.key\"",
                "master_key_file = \"/srv/agenc/state/master.key\"",
            ),
            stage,
            SchemaKey::new("storage", "master_key_file"),
        ),
    ]
}

fn listener_cases() -> Vec<Case> {
    let stage = ValidationStage::ListenerUnion;
    vec![
        case(
            "duplicate listener names",
            mutate(PUBLIC, "name = \"admin\"", "name = \"public\""),
            stage,
            SchemaKey::indexed("listeners.endpoint", 1, "name"),
        ),
        case(
            "duplicate binds",
            mutate(
                DUAL,
                "bind = \"/run/agenc/admin.sock\"",
                "bind = \"/run/agenc/onion.sock\"",
            ),
            stage,
            SchemaKey::indexed("listeners.endpoint", 3, "bind"),
        ),
        case(
            "client ceiling above the global client limit",
            mutate(PUBLIC, "max_connections = 50000", "max_connections = 50001"),
            stage,
            SchemaKey::indexed("listeners.endpoint", 0, "max_connections"),
        ),
        case(
            "admin ceiling above 64",
            mutate(PUBLIC, "max_connections = 4", "max_connections = 65"),
            stage,
            SchemaKey::indexed("listeners.endpoint", 1, "max_connections"),
        ),
        case(
            "federation ceiling above max_peers",
            mutate(DUAL, "max_connections = 64", "max_connections = 65"),
            stage,
            SchemaKey::indexed("listeners.endpoint", 2, "max_connections"),
        ),
        case(
            "browser WSS listener with an empty origin allowlist",
            mutate(
                PUBLIC,
                "name = \"public\"\nenabled = true\npurpose = \"client_tls\"",
                "name = \"public\"\nenabled = false\npurpose = \"client_wss\"",
            ),
            stage,
            SchemaKey::indexed("listeners.endpoint", 0, "allowed_origins"),
        ),
        case(
            "private key reused across the admin and federation classes",
            mutate(
                DUAL,
                "tls_private_key_file = \"/etc/agenc/tls/admin.key\"",
                "tls_private_key_file = \"/etc/agenc/tls/federation.key\"",
            ),
            stage,
            SchemaKey::indexed("listeners.endpoint", 4, "tls_private_key_file"),
        ),
        case(
            "two local admin listeners",
            mutate(
                PUBLIC,
                "allowed_gids = []\n",
                "allowed_gids = []\n\n[[listeners.endpoint]]\nname = \"admin2\"\nenabled = true\npurpose = \"admin_local\"\nbind = \"/run/agenc/admin2.sock\"\nmax_connections = 4\nallowed_uids = [1000]\n",
            ),
            stage,
            SchemaKey::new("listeners", "endpoint"),
        ),
        case(
            "federation enabled without an enabled federation listener",
            mutate(
                DUAL,
                "name = \"federation\"\nenabled = true",
                "name = \"federation\"\nenabled = false",
            ),
            stage,
            SchemaKey::new("listeners", "endpoint"),
        ),
        case(
            "federation listener while federation is disabled",
            mutate(
                DUAL,
                "[federation]\nenabled = true",
                "[federation]\nenabled = false",
            ),
            stage,
            SchemaKey::new("listeners", "endpoint"),
        ),
    ]
}

fn topology_cases() -> Vec<Case> {
    let stage = ValidationStage::Topology;
    vec![
        case(
            "federation enabled without a private CA",
            mutate(
                DUAL,
                "private_ca_file = \"/etc/agenc/tls/federation-ca.pem\"\n",
                "",
            ),
            stage,
            SchemaKey::new("federation", "private_ca_file"),
        ),
        case(
            "peer records while federation is disabled",
            append_to_table(
                PUBLIC,
                "federation",
                "[[federation.peer]]\nserver_id = \"AwMDAwMDAwMDAwMDAwMDAw\"\nserver_name = \"edge.example\"\nrole = \"edge\"\nrecovery_epoch = \"CQkJCQkJCQkJCQkJCQkJCQ\"\nendpoints = []\ncertificate_spki_sha256 = \"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc\"\nsigning_public_key = \"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg\"\nenabled = true",
            ),
            stage,
            SchemaKey::new("federation", "peer"),
        ),
        case(
            "edge without exactly one peer",
            mutate(
                &edge(),
                "[[federation.peer]]\n",
                "[[federation.peer]]\nserver_id = \"BAQEBAQEBAQEBAQEBAQEBA\"\nserver_name = \"other.example\"\nrole = \"coordinator\"\nrecovery_epoch = \"CQkJCQkJCQkJCQkJCQkJCQ\"\nendpoints = [\"tcp:203.0.113.6:7000\"]\ncertificate_spki_sha256 = \"BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY\"\nsigning_public_key = \"BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU\"\nenabled = true\n\n[[federation.peer]]\n",
            ),
            stage,
            SchemaKey::new("federation", "peer"),
        ),
        case(
            "edge peer without endpoints",
            mutate(
                &edge(),
                "endpoints = [\"tcp:203.0.113.5:7000\"]",
                "endpoints = []",
            ),
            stage,
            SchemaKey::indexed("federation.peer", 0, "endpoints"),
        ),
        case(
            "coordinator peer record with endpoints",
            mutate(
                DUAL,
                "endpoints = []",
                "endpoints = [\"tcp:203.0.113.5:7000\"]",
            ),
            stage,
            SchemaKey::indexed("federation.peer", 0, "endpoints"),
        ),
        case(
            "coordinator peer record with the coordinator role",
            mutate(DUAL, "role = \"edge\"", "role = \"coordinator\""),
            stage,
            SchemaKey::indexed("federation.peer", 0, "role"),
        ),
        case(
            "peer id equals the local id",
            mutate(
                DUAL,
                "server_id = \"AwMDAwMDAwMDAwMDAwMDAw\"",
                "server_id = \"AgICAgICAgICAgICAgICAg\"",
            ),
            stage,
            SchemaKey::indexed("federation.peer", 0, "server_id"),
        ),
        case(
            "peer signing key equals its certificate pin",
            mutate(
                DUAL,
                "signing_public_key = \"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg\"",
                "signing_public_key = \"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc\"",
            ),
            stage,
            SchemaKey::indexed("federation.peer", 0, "signing_public_key"),
        ),
        case(
            "onion dial endpoint without a Tor SOCKS endpoint",
            mutate(
                &edge(),
                "endpoints = [\"tcp:203.0.113.5:7000\"]",
                &format!("endpoints = [\"onion:{}.onion:6697\"]", "c".repeat(56)),
            ),
            stage,
            SchemaKey::new("federation", "tor_socks_endpoint"),
        ),
        case(
            "duplicate operator identity",
            mutate(
                PUBLIC,
                "permissions = [\"observe\", \"configure\", \"sessions\"]\nenabled = true\n",
                "permissions = [\"observe\", \"configure\", \"sessions\"]\nenabled = true\n\n[[moderation.operator]]\noperator_id = \"BAQEBAQEBAQEBAQEBAQEBA\"\ndisplay_label = \"second\"\nsigning_public_key = \"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc\"\npermissions = [\"observe\"]\nenabled = true\n",
            ),
            stage,
            SchemaKey::indexed("moderation.operator", 1, "operator_id"),
        ),
        case(
            "operator uid outside the local admin allowlist",
            mutate(PUBLIC, "local_uids = [1000]", "local_uids = [2000]"),
            stage,
            SchemaKey::indexed("moderation.operator", 0, "local_uids"),
        ),
        case(
            "remote admin without a pinned operator",
            mutate(
                DUAL,
                "certificate_spki_sha256 = \"BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU\"\n",
                "",
            ),
            stage,
            SchemaKey::new("moderation", "operator"),
        ),
    ]
}

fn resource_cases() -> Vec<Case> {
    let stage = ValidationStage::ResourceArithmetic;
    vec![
        case(
            "crypto workers above the job ceilings",
            mutate(
                PUBLIC,
                "crypto_worker_threads = 4",
                "crypto_worker_threads = 13",
            ),
            stage,
            SchemaKey::new("server", "crypto_worker_threads"),
        ),
        case(
            "control output not below total output",
            mutate(
                &mutate(
                    PUBLIC,
                    "client_output_bytes = 1048576",
                    "client_output_bytes = 262144",
                ),
                "client_control_output_bytes = 65536",
                "client_control_output_bytes = 262144",
            ),
            stage,
            SchemaKey::new("limits", "client_control_output_bytes"),
        ),
        case(
            "channel invites above the global ceiling",
            mutate(PUBLIC, "invites_global = 100000", "invites_global = 100"),
            stage,
            SchemaKey::new("limits", "invites_per_channel"),
        ),
        case(
            "snapshot rows above the global ceiling",
            mutate(
                PUBLIC,
                "query_snapshot_rows_global = 100000",
                "query_snapshot_rows_global = 512",
            ),
            stage,
            SchemaKey::new("limits", "query_snapshot_rows"),
        ),
        case(
            "database ceiling above the backup ceiling",
            mutate(
                PUBLIC,
                "backup_max_bytes = 107374182400",
                "backup_max_bytes = 1073741824",
            ),
            stage,
            SchemaKey::new("storage", "database_max_bytes"),
        ),
        case(
            "E2EE burst above ten seconds of rate",
            mutate(
                PUBLIC,
                "federation_peer_bytes_per_second = 16777216",
                "federation_peer_bytes_per_second = 65536",
            ),
            stage,
            SchemaKey::new("e2ee", "federation_peer_burst_bytes"),
        ),
        case(
            "memory budget underflow",
            mutate(
                PUBLIC,
                "memory_budget_bytes = 6442450944",
                "memory_budget_bytes = 536870912",
            ),
            stage,
            SchemaKey::new("server", "memory_budget_bytes"),
        ),
        case(
            "query snapshot bytes above the protocol pool",
            mutate(
                &mutate(
                    PUBLIC,
                    "memory_budget_bytes = 6442450944",
                    "memory_budget_bytes = 1073741824",
                ),
                "query_snapshot_bytes_global = 67108864",
                "query_snapshot_bytes_global = 536870912",
            ),
            stage,
            SchemaKey::new("limits", "query_snapshot_bytes_global"),
        ),
    ]
}

#[test]
fn edge_derivation_is_a_valid_document() -> Result<(), Box<dyn std::error::Error>> {
    let config = parse(&edge())?;
    assert_eq!(config.federation.peers.len(), 1);
    assert!(config.accounts.opaque_server_setup_file.is_none());
    Ok(())
}

#[test]
fn every_cross_field_rule_reports_its_stage_and_key() {
    let mut cases = identity_cases();
    cases.extend(listener_cases());
    cases.extend(topology_cases());
    cases.extend(resource_cases());
    for case in cases {
        let report = parse(&case.text).err();
        let matched = report.as_ref().is_some_and(|report| {
            report
                .issues()
                .iter()
                .any(|issue| issue.stage == case.stage && issue.key == case.key)
        });
        assert!(
            matched,
            "{}: expected {:?} at {}, got {:?}",
            case.label,
            case.stage,
            case.key,
            report.map(|r| r.to_string())
        );
        assert!(
            report
                .as_ref()
                .is_some_and(|report| !report.has_structural_issue()),
            "{}: cross-field case must not be structural",
            case.label
        );
    }
}

#[test]
fn required_ocsp_staples_are_explicit_and_public_tls_only() {
    let required = mutate(
        PUBLIC,
        "require_ocsp_staple = false",
        "require_ocsp_staple = true",
    );
    let report = parse(&required).err();
    assert!(report.as_ref().is_some_and(|report| {
        report.issues().iter().any(|issue| {
            issue.stage == ValidationStage::ListenerUnion
                && issue.key == SchemaKey::indexed("listeners.endpoint", 0, "tls_ocsp_staple_file")
                && issue.error == ConfigError::MissingValue
        })
    }));

    let configured = mutate(
        &required,
        "tls_certificate_file = \"/etc/agenc/tls/server.crt\"",
        "tls_certificate_file = \"/etc/agenc/tls/server.crt\"\n\
         tls_ocsp_staple_file = \"/etc/agenc/tls/server.ocsp\"",
    );
    assert!(parse(&configured).is_ok());

    let onion = mutate(
        DUAL,
        "tls_certificate_file = \"/etc/agenc/tls/onion.crt\"",
        "tls_certificate_file = \"/etc/agenc/tls/onion.crt\"\n\
         tls_ocsp_staple_file = \"/etc/agenc/tls/onion.ocsp\"",
    );
    let report = parse(&onion).err();
    assert!(report.as_ref().is_some_and(|report| {
        report.issues().iter().any(|issue| {
            issue.key == SchemaKey::indexed("listeners.endpoint", 1, "tls_ocsp_staple_file")
                && issue.error == ConfigError::InvalidValue
        })
    }));
}

#[test]
#[cfg(feature = "wss")]
fn required_ocsp_staples_support_enabled_websocket_listeners() {
    let wss = mutate(
        PUBLIC,
        "purpose = \"client_tls\"",
        "purpose = \"client_wss\"\nallowed_origins = [\"https://chat.example\"]",
    );
    let required = mutate(
        &wss,
        "require_ocsp_staple = false",
        "require_ocsp_staple = true",
    );
    let report = parse(&required).err();
    assert!(report.as_ref().is_some_and(|report| {
        report.issues().iter().any(|issue| {
            issue.key == SchemaKey::indexed("listeners.endpoint", 0, "tls_ocsp_staple_file")
                && issue.error == ConfigError::MissingValue
        })
    }));
    for text in [&wss, &required] {
        let configured = mutate(
            text,
            "tls_certificate_file = \"/etc/agenc/tls/server.crt\"",
            "tls_certificate_file = \"/etc/agenc/tls/server.crt\"\n\
             tls_ocsp_staple_file = \"/etc/agenc/tls/server.ocsp\"",
        );
        let parsed = parse(&configured);
        assert!(parsed.is_ok(), "WSS staple rejected: {parsed:?}");
        assert!(parsed.ok().is_some_and(|config| {
            config.listeners.first().is_some_and(|listener| {
                listener.tls.as_ref().is_some_and(|tls| {
                    tls.ocsp_staple_file.as_deref()
                        == Some(std::path::Path::new("/etc/agenc/tls/server.ocsp"))
                })
            })
        }));
    }
}

#[test]
fn ocsp_staples_remain_forbidden_for_non_public_listener_purposes() {
    for purpose in ["client_onion", "federation", "admin_local", "admin_tls"] {
        let text = mutate(
            PUBLIC,
            "purpose = \"client_tls\"",
            &format!(
                "purpose = \"{purpose}\"\ntls_ocsp_staple_file = \"/etc/agenc/tls/server.ocsp\""
            ),
        );
        let report = parse(&text).err();
        assert!(
            report.as_ref().is_some_and(|report| {
                report.issues().iter().any(|issue| {
                    issue.key == SchemaKey::indexed("listeners.endpoint", 0, "tls_ocsp_staple_file")
                        && issue.error == ConfigError::InvalidValue
                })
            }),
            "{purpose} must reject a public OCSP staple"
        );
    }
}

#[test]
fn cross_field_issues_accumulate_together() {
    let text = mutate(
        &mutate(
            PUBLIC,
            "crypto_worker_threads = 4",
            "crypto_worker_threads = 13",
        ),
        "invites_global = 100000",
        "invites_global = 10",
    );
    let report = parse(&text).err();
    let fields: Vec<&str> = report
        .as_ref()
        .map(|report| {
            report
                .issues()
                .iter()
                .map(|issue| issue.key.field())
                .collect()
        })
        .unwrap_or_default();
    assert!(fields.contains(&"crypto_worker_threads"));
    assert!(fields.contains(&"invites_per_channel"));
    assert!(fields.contains(&"invites_per_principal"));
    assert!(report.is_some_and(|report| {
        report
            .issues()
            .iter()
            .all(|issue| issue.error != ConfigError::UnknownKey)
    }));
}

#[test]
fn enabled_client_listener_requires_an_onboarding_target() {
    let text = mutate(PUBLIC, "dns_name = \"chat.example\"\ndns_port = 6697\n", "");
    let report = parse(&text).err();

    assert!(report.as_ref().is_some_and(|report| {
        report.issues().iter().any(|issue| {
            issue.stage == ValidationStage::LocalIdentity
                && issue.key == SchemaKey::new("network", "dns_name")
                && issue.error == ConfigError::Topology
        })
    }));
}
