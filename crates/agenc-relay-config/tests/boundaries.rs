#![forbid(unsafe_code)]

//! Every Appendix C scalar boundary: minimum minus one, minimum, maximum, and
//! maximum plus one, plus the fixed-value keys and the rate table rows.

mod support;

use agenc_relay_config::{
    ACCOUNT_SANCTION_DAYS, AUDIT_RETENTION_DAYS, Bound, CRYPTO_WORKER_THREADS, ConfigError,
    DATABASE_MAX_BYTES, DIRECTORY_BYTES_PER_ACCOUNT, DISK_RESERVE_BYTES, DISK_RESERVE_PERCENT,
    DRAIN_SECONDS, E2EE_GLOBAL_DISK_BYTES, ENDPOINT_PORT, FEDERATION_PEER_BURST_BYTES,
    FEDERATION_PEER_BYTES_PER_SECOND, FLUSH_SECONDS, INTEGRITY_CHECKPOINT_MANIFESTS, LIMIT_ROWS,
    LOG_RETENTION_HOURS, MAILBOX_BYTES_PER_ACCOUNT, MAX_CONTACTS, MAX_DEVICES_PER_ACCOUNT,
    MAX_GROUP_LEAVES, MEMORY_BUDGET_BYTES, QUIESCE_SECONDS, RATE_ROWS,
    SECRET_LOOKUP_FLOOR_MILLISECONDS, SESSION_SANCTION_HOURS, STOP_SECONDS,
    STORED_BYTES_PER_CONVERSATION, TOKIO_WORKER_THREADS, ValidationStage, WHOWAS_RECORDS,
};
use support::{PUBLIC, mutate, parse};

/// Returns whether the document is rejected with a scalar-stage issue on `field`.
fn scalar_rejects(text: &str, field: &str) -> bool {
    parse(text).err().is_some_and(|report| {
        report.issues().iter().any(|issue| {
            issue.stage == ValidationStage::Scalars
                && issue.key.field() == field
                && issue.error == ConfigError::InvalidValue
        })
    })
}

/// Returns whether the document carries no scalar-stage issue on `field`; later
/// cross-field stages may still reject a boundary value legitimately.
fn scalar_accepts(text: &str, field: &str) -> bool {
    match parse(text) {
        Ok(_) => true,
        Err(report) => !report
            .issues()
            .iter()
            .any(|issue| issue.stage == ValidationStage::Scalars && issue.key.field() == field),
    }
}

fn with_value(text: &str, field: &str, value: u64) -> String {
    let prefix = format!("\n{field} = ");
    let start = text.find(&prefix).map(|position| position + 1);
    assert!(start.is_some(), "golden document lacks {field}");
    let start = start.unwrap_or(0);
    let end = text[start..]
        .find('\n')
        .map_or(text.len(), |offset| start + offset);
    format!("{}{field} = {value}{}", &text[..start], &text[end..])
}

fn check_bound(text: &str, field: &str, bound: Bound) {
    if bound.minimum > 0 {
        assert!(
            scalar_rejects(&with_value(text, field, bound.minimum - 1), field),
            "{field} accepted minimum minus one"
        );
    }
    assert!(
        scalar_accepts(&with_value(text, field, bound.minimum), field),
        "{field} rejected minimum"
    );
    assert!(
        scalar_accepts(&with_value(text, field, bound.maximum), field),
        "{field} rejected maximum"
    );
    assert!(
        scalar_rejects(&with_value(text, field, bound.maximum + 1), field),
        "{field} accepted maximum plus one"
    );
}

#[test]
fn every_resource_limit_row_is_range_checked() {
    for row in &LIMIT_ROWS {
        check_bound(PUBLIC, row.name, row.bound);
    }
}

#[test]
fn every_rate_row_is_checked_against_its_hard_ceiling() {
    for row in &RATE_ROWS {
        let header = format!("[limits.rate.{}]\n", row.name);
        let default = format!(
            "{header}refill_tokens = {}\nrefill_seconds = {}\nburst = {}\n",
            row.default.refill_tokens, row.default.refill_seconds, row.default.burst
        );
        let hard = format!(
            "{header}refill_tokens = {}\nrefill_seconds = {}\nburst = {}\n",
            row.hard.refill_tokens, row.hard.refill_seconds, row.hard.burst
        );
        assert!(
            parse(&mutate(PUBLIC, &default, &hard)).is_ok(),
            "{} rejected its hard row",
            row.name
        );
        let faster = format!(
            "{header}refill_tokens = {}\nrefill_seconds = {}\nburst = {}\n",
            row.hard.refill_tokens + 1,
            row.hard.refill_seconds,
            row.hard.burst
        );
        assert!(
            scalar_rejects(&mutate(PUBLIC, &default, &faster), row.name),
            "{} accepted a faster rate",
            row.name
        );
        let burstier = format!(
            "{header}refill_tokens = {}\nrefill_seconds = {}\nburst = {}\n",
            row.hard.refill_tokens,
            row.hard.refill_seconds,
            row.hard.burst + 1
        );
        assert!(
            scalar_rejects(&mutate(PUBLIC, &default, &burstier), row.name),
            "{} accepted a larger burst",
            row.name
        );
        let zero = format!("{header}refill_tokens = 0\nrefill_seconds = 1\nburst = 1\n");
        assert!(
            scalar_rejects(&mutate(PUBLIC, &default, &zero), row.name),
            "{} accepted zero tokens",
            row.name
        );
        let slow = format!("{header}refill_tokens = 1\nrefill_seconds = 3601\nburst = 1\n");
        assert!(
            scalar_rejects(&mutate(PUBLIC, &default, &slow), row.name),
            "{} accepted 3601 seconds",
            row.name
        );
        let missing = format!("{header}refill_tokens = 1\nrefill_seconds = 1\n");
        assert!(
            parse(&mutate(PUBLIC, &default, &missing)).is_err(),
            "{} accepted a missing burst",
            row.name
        );
    }
}

#[test]
fn every_other_bounded_scalar_is_range_checked() {
    let rows: [(&str, Bound); 21] = [
        ("dns_port", ENDPOINT_PORT),
        ("memory_budget_bytes", MEMORY_BUDGET_BYTES),
        ("tokio_worker_threads", TOKIO_WORKER_THREADS),
        ("crypto_worker_threads", CRYPTO_WORKER_THREADS),
        ("quiesce_seconds", QUIESCE_SECONDS),
        ("drain_seconds", DRAIN_SECONDS),
        ("flush_seconds", FLUSH_SECONDS),
        ("stop_seconds", STOP_SECONDS),
        ("database_max_bytes", DATABASE_MAX_BYTES),
        ("disk_reserve_bytes", DISK_RESERVE_BYTES),
        ("disk_reserve_percent", DISK_RESERVE_PERCENT),
        (
            "integrity_checkpoint_manifests",
            INTEGRITY_CHECKPOINT_MANIFESTS,
        ),
        ("max_contacts", MAX_CONTACTS),
        ("log_retention_hours", LOG_RETENTION_HOURS),
        (
            "secret_lookup_floor_milliseconds",
            SECRET_LOOKUP_FLOOR_MILLISECONDS,
        ),
        ("whowas_records", WHOWAS_RECORDS),
        ("audit_retention_days", AUDIT_RETENTION_DAYS),
        ("session_sanction_hours", SESSION_SANCTION_HOURS),
        ("account_sanction_days", ACCOUNT_SANCTION_DAYS),
        ("max_group_leaves", MAX_GROUP_LEAVES),
        ("max_devices_per_account", MAX_DEVICES_PER_ACCOUNT),
    ];
    for (field, bound) in rows {
        check_bound(PUBLIC, field, bound);
    }
    let e2ee: [(&str, Bound); 6] = [
        ("mailbox_bytes_per_account", MAILBOX_BYTES_PER_ACCOUNT),
        ("directory_bytes_per_account", DIRECTORY_BYTES_PER_ACCOUNT),
        (
            "stored_bytes_per_conversation",
            STORED_BYTES_PER_CONVERSATION,
        ),
        ("global_disk_bytes", E2EE_GLOBAL_DISK_BYTES),
        (
            "federation_peer_bytes_per_second",
            FEDERATION_PEER_BYTES_PER_SECOND,
        ),
        ("federation_peer_burst_bytes", FEDERATION_PEER_BURST_BYTES),
    ];
    for (field, bound) in e2ee {
        check_bound(PUBLIC, field, bound);
    }
}

#[test]
fn fixed_values_accept_only_their_exact_value() {
    for (field, value) in [
        ("ticket_rotation_seconds", 21_600),
        ("ticket_lifetime_seconds", 86_400),
        ("reconnect_max_seconds", 60),
        ("max_peers", 64),
        ("max_reserved_nicknames", 5),
        ("auth_transaction_seconds", 30),
        ("create_transaction_seconds", 60),
        ("credential_change_transaction_seconds", 60),
        ("whowas_retention_seconds", 900),
        ("free_reason_bytes", 512),
        ("profile_version", 1),
    ] {
        assert!(
            scalar_accepts(&with_value(PUBLIC, field, value), field),
            "{field} rejected its fixed value"
        );
        assert!(
            scalar_rejects(&with_value(PUBLIC, field, value + 1), field),
            "{field} accepted a change"
        );
        assert!(
            scalar_rejects(&with_value(PUBLIC, field, value - 1), field),
            "{field} accepted a change"
        );
    }
}

#[test]
fn shutdown_phases_reject_a_sum_above_the_ceiling() {
    let text = with_value(
        &with_value(
            &with_value(PUBLIC, "drain_seconds", 60),
            "flush_seconds",
            30,
        ),
        "stop_seconds",
        30,
    );
    // 5 + 60 + 30 + 30 = 125 exceeds 120.
    assert!(scalar_rejects(&text, "stop_seconds"));
    let exact = with_value(
        &with_value(
            &with_value(PUBLIC, "drain_seconds", 60),
            "flush_seconds",
            30,
        ),
        "stop_seconds",
        25,
    );
    // 5 + 60 + 30 + 25 = 120 is accepted.
    assert!(scalar_accepts(&exact, "stop_seconds"));
}

#[test]
fn string_grammars_reject_noncanonical_input() {
    let cases = [
        (
            "display_name = \"example\"",
            "display_name = \"exa mple\"",
            "display_name",
        ),
        (
            "display_name = \"example\"",
            "display_name = \"abcdefghijklmnopqrstuvwxyzabcdefg\"",
            "display_name",
        ),
        (
            "dns_name = \"chat.example\"",
            "dns_name = \"Chat.Example\"",
            "dns_name",
        ),
        (
            "network_id = \"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE\"",
            "network_id = \"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ\"",
            "network_id",
        ),
        ("role = \"coordinator\"", "role = \"Coordinator\"", "role"),
        (
            "bind = \"203.0.113.1:6697\"",
            "bind = \"0.0.0.0:6697\"",
            "bind",
        ),
        (
            "bind = \"203.0.113.1:6697\"",
            "bind = \"203.0.113.1:0\"",
            "bind",
        ),
        (
            "bind = \"203.0.113.1:6697\"",
            "bind = \"chat.example:6697\"",
            "bind",
        ),
        (
            "bind = \"203.0.113.1:6697\"",
            "bind = \"224.0.0.1:6697\"",
            "bind",
        ),
        (
            "purpose = \"admin_local\"",
            "purpose = \"admin\"",
            "purpose",
        ),
        (
            "registration = \"invite\"",
            "registration = \"anyone\"",
            "registration",
        ),
        (
            "default_direct_messages = \"allow\"",
            "default_direct_messages = \"none\"",
            "default_direct_messages",
        ),
        (
            "history_default = \"24h\"",
            "history_default = \"48h\"",
            "history_default",
        ),
        (
            "group_policy = \"hybrid_preferred\"",
            "group_policy = \"x25519\"",
            "group_policy",
        ),
        (
            "display_label = \"ops\"",
            "display_label = \"ops team\"",
            "display_label",
        ),
        (
            "permissions = [\"observe\", \"configure\", \"sessions\"]",
            "permissions = [\"*\"]",
            "permissions",
        ),
        (
            "permissions = [\"observe\", \"configure\", \"sessions\"]",
            "permissions = [\"observe\", \"observe\"]",
            "permissions",
        ),
        (
            "permissions = [\"observe\", \"configure\", \"sessions\"]",
            "permissions = []",
            "permissions",
        ),
        (
            "account_service_hpke_public_key = \"BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU\"",
            "account_service_hpke_public_key = \"BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQV\"",
            "account_service_hpke_public_key",
        ),
        (
            "allowed_uids = [1000]",
            "allowed_uids = [1000, 1000]",
            "allowed_uids",
        ),
        ("allowed_uids = [1000]", "allowed_uids = []", "allowed_uids"),
        (
            "operator_id = \"BAQEBAQEBAQEBAQEBAQEBA\"",
            "operator_id = \"short\"",
            "operator_id",
        ),
    ];
    for (old, new, field) in cases {
        let text = mutate(PUBLIC, old, new);
        let report = parse(&text).err();
        assert!(
            report.as_ref().is_some_and(|report| report
                .issues()
                .iter()
                .any(|issue| issue.key.field() == field)),
            "{new} was accepted for {field}"
        );
    }
}

#[test]
fn onion_and_origin_grammars_are_exact() {
    let onion_base = mutate(PUBLIC, "dns_name = \"chat.example\"\ndns_port = 6697\n", "");
    let with_onion = |address: &str, pin: bool| {
        let mut text = mutate(
            &onion_base,
            "role = \"coordinator\"\ncoordinator_server_id = \"AgICAgICAgICAgICAgICAg\"\n",
            &format!(
                "role = \"coordinator\"\ncoordinator_server_id = \"AgICAgICAgICAgICAgICAg\"\nonion_address = \"{address}\"\n"
            ),
        );
        if pin {
            text = mutate(
                &text,
                "onion_address = ",
                "onion_tls_spki_sha256 = \"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc\"\nonion_address = ",
            );
        }
        text
    };
    let good = format!("{}.onion", "b".repeat(56));
    assert!(scalar_accepts(&with_onion(&good, true), "onion_address"));
    assert!(scalar_rejects(
        &with_onion(&format!("{}.onion", "B".repeat(56)), true),
        "onion_address"
    ));
    assert!(scalar_rejects(
        &with_onion(&format!("{}.onion", "b".repeat(55)), true),
        "onion_address"
    ));
    assert!(scalar_rejects(
        &with_onion(&format!("{}.com", "b".repeat(56)), true),
        "onion_address"
    ));
    assert!(scalar_rejects(
        &with_onion(&format!("{}.onion", "1".repeat(56)), true),
        "onion_address"
    ));
    // An address without its pin, and a pin without its address, are both missing values.
    let report = parse(&with_onion(&good, false)).err();
    assert!(report.as_ref().is_some_and(|report| {
        report.issues().iter().any(|issue| {
            issue.key.field() == "onion_tls_spki_sha256" && issue.error == ConfigError::MissingValue
        })
    }));
    let pin_only = mutate(
        PUBLIC,
        "dns_port = 6697\n",
        "dns_port = 6697\nonion_tls_spki_sha256 = \"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc\"\n",
    );
    assert!(parse(&pin_only).is_err());

    let wss = |origins: &str| {
        mutate(
            PUBLIC,
            "purpose = \"client_tls\"\nbind = \"203.0.113.1:6697\"",
            &format!(
                "purpose = \"client_wss\"\nbind = \"203.0.113.1:6697\"\nallowed_origins = [{origins}]"
            ),
        )
    };
    assert!(scalar_accepts(
        &wss("\"https://chat.example\", \"https://chat.example:8443\""),
        "allowed_origins"
    ));
    for bad in [
        "\"http://chat.example\"",
        "\"https://Chat.example\"",
        "\"https://chat.example/irc\"",
        "\"https://chat.example:0\"",
        "\"https://user@chat.example\"",
        "\"https://chat.example\", \"https://chat.example\"",
        "\"https://\"",
    ] {
        assert!(
            scalar_rejects(&wss(bad), "allowed_origins"),
            "{bad} accepted"
        );
    }
}
