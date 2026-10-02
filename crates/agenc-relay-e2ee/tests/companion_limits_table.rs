#![forbid(unsafe_code)]

//! Companion Section 16 is the normative table of profile limits and
//! defaults, and `agenc_relay_e2ee::limits` is their shared code owner. This
//! test parses every row of the pinned companion's table and compares its
//! default, in canonical units, with the constant that names it: a changed
//! value, a row without a constant, or a constant left behind by a removed
//! row fails here.

use std::error::Error;

use agenc_relay_e2ee::limits as l;

type TestResult = Result<(), Box<dyn Error>>;

const COMPANION: &str = include_str!("../../../docs/arc-mls-e2ee-extension.md");

/// What one Section 16 row must state.
#[derive(Debug, PartialEq)]
enum Expected {
    /// Its default, one value per stated quantity, durations in seconds.
    Values(Vec<u64>),
    /// A retention rule with no scalar, compared as exact text.
    Rule(&'static str),
}

/// One constant in the table's canonical unit.
fn value<T>(constant: T) -> Result<u64, Box<dyn Error>>
where
    u64: TryFrom<T>,
    <u64 as TryFrom<T>>::Error: Error + 'static,
{
    Ok(u64::try_from(constant)?)
}

/// Every row of the companion's Section 16 table as `(name, default)`.
fn section_16_rows() -> Result<Vec<(String, String)>, Box<dyn Error>> {
    let (_, rest) = COMPANION
        .split_once("\n## 16. Resource and timing limits\n")
        .ok_or("the companion has no Section 16")?;
    let (section, _) = rest
        .split_once("\n## 17. ")
        .ok_or("the companion has no Section 17")?;
    let mut rows = Vec::new();
    for line in section.lines().filter(|line| line.starts_with("| `")) {
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        let [name, default] = cells.as_slice() else {
            return Err(format!("a Section 16 row is not two cells: {line}").into());
        };
        let name = name
            .strip_prefix('`')
            .and_then(|name| name.strip_suffix('`'))
            .ok_or_else(|| format!("a Section 16 name is not code: {line}"))?;
        rows.push((name.to_owned(), (*default).to_owned()));
    }
    Ok(rows)
}

/// One stated quantity in canonical units: durations in seconds, everything
/// else as written. An unknown unit is an error, so new grammar is noticed.
fn quantity(text: &str) -> Result<u64, Box<dyn Error>> {
    let mut words = text.split_whitespace();
    let number: u64 = words
        .next()
        .ok_or("an empty Section 16 default")?
        .replace(',', "")
        .parse()?;
    let unit: Vec<&str> = words.collect();
    let scale: u64 = match unit.as_slice() {
        []
        | ["bytes"]
        | ["bytes/second"]
        | ["generations"]
        | ["serialized", "bytes"]
        | ["per", "conversation"]
        | ["seconds"]
        | ["seconds", "idle"] => 1,
        ["minutes"] | ["minutes", "absolute"] => 60,
        ["hour"] | ["hours"] => 60 * 60,
        ["days"] => 24 * 60 * 60,
        other => return Err(format!("unknown Section 16 unit {other:?} in {text:?}").into()),
    };
    Ok(number
        .checked_mul(scale)
        .ok_or("a Section 16 default overflows")?)
}

/// A default cell: the quantities before any `;` qualifier, separated by
/// `, ` (numbers group thousands with a bare comma).
fn quantities(cell: &str) -> Result<Vec<u64>, Box<dyn Error>> {
    let stated = cell.split(';').next().unwrap_or(cell);
    stated.split(", ").map(quantity).collect()
}

/// The expected table, in companion order.
fn expected() -> Result<Vec<(&'static str, Expected)>, Box<dyn Error>> {
    Ok(vec![
        (
            "MAX_APPLICATION_PLAINTEXT",
            Expected::Values(vec![value(l::MAX_APPLICATION_PLAINTEXT)?]),
        ),
        (
            "MAX_PRIVATE_TOPIC_BYTES",
            Expected::Values(vec![value(l::MAX_PRIVATE_TOPIC_BYTES)?]),
        ),
        (
            "MAX_APPLICATION_MLS_OBJECT",
            Expected::Values(vec![value(l::MAX_APPLICATION_MLS_OBJECT)?]),
        ),
        (
            "MAX_KEY_PACKAGE_OBJECT",
            Expected::Values(vec![value(l::MAX_KEY_PACKAGE_OBJECT)?]),
        ),
        (
            "MAX_IDENTITY_OBJECT",
            Expected::Values(vec![value(l::MAX_IDENTITY_OBJECT)?]),
        ),
        (
            "MAX_ROOT_CHAIN_OBJECT",
            Expected::Values(vec![value(l::MAX_ROOT_CHAIN_OBJECT)?]),
        ),
        (
            "MAX_ROSTER_OBJECT",
            Expected::Values(vec![value(l::MAX_ROSTER_OBJECT)?]),
        ),
        (
            "MAX_CAPABILITY_OBJECT",
            Expected::Values(vec![value(l::MAX_CAPABILITY_OBJECT)?]),
        ),
        (
            "MAX_CREDENTIAL_BUNDLE",
            Expected::Values(vec![value(l::MAX_CREDENTIAL_BUNDLE)?]),
        ),
        (
            "MAX_POLICY_BYTES",
            Expected::Values(vec![value(l::MAX_POLICY_BYTES)?]),
        ),
        (
            "MAX_POLICY_OBJECT",
            Expected::Values(vec![value(l::MAX_POLICY_OBJECT)?]),
        ),
        (
            "MAX_BINDING_OBJECT",
            Expected::Values(vec![value(l::MAX_BINDING_OBJECT)?]),
        ),
        (
            "MAX_BINDING_CHAIN_BYTES",
            Expected::Values(vec![value(l::MAX_BINDING_CHAIN_BYTES)?]),
        ),
        (
            "MAX_ARC_MLS_CONTEXT_EXTENSION",
            Expected::Values(vec![value(l::MAX_ARC_MLS_CONTEXT_EXTENSION)?]),
        ),
        (
            "MAX_POLICY_CHAIN_BYTES",
            Expected::Values(vec![value(l::MAX_POLICY_CHAIN_BYTES)?]),
        ),
        (
            "MAX_LIVE_OBJECT",
            Expected::Values(vec![value(l::MAX_LIVE_OBJECT)?]),
        ),
        (
            "MAX_COMMIT_APPROVAL_OBJECT",
            Expected::Values(vec![value(l::MAX_COMMIT_APPROVAL_OBJECT)?]),
        ),
        (
            "MAX_COMMIT_ACK_OBJECT",
            Expected::Values(vec![value(l::MAX_COMMIT_ACK_OBJECT)?]),
        ),
        (
            "MAX_REINIT_ACK_OBJECT",
            Expected::Values(vec![value(l::MAX_REINIT_ACK_OBJECT)?]),
        ),
        (
            "MAX_FINALIZATION_OBJECT",
            Expected::Values(vec![value(l::MAX_FINALIZATION_OBJECT)?]),
        ),
        (
            "MAX_ABORT_OBJECT",
            Expected::Values(vec![value(l::MAX_ABORT_OBJECT)?]),
        ),
        (
            "MAX_REINIT_OBJECT",
            Expected::Values(vec![value(l::MAX_REINIT_OBJECT)?]),
        ),
        (
            "MAX_REINIT_INITIAL_COMMIT_BYTES",
            Expected::Values(vec![value(l::MAX_REINIT_INITIAL_COMMIT_BYTES)?]),
        ),
        (
            "MAX_RESERVATION_OBJECT",
            Expected::Values(vec![value(l::MAX_RESERVATION_OBJECT)?]),
        ),
        (
            "MAX_SEQUENCER_RECORD_OBJECT",
            Expected::Values(vec![value(l::MAX_SEQUENCER_RECORD_OBJECT)?]),
        ),
        (
            "MAX_CLOSE_OBJECT",
            Expected::Values(vec![value(l::MAX_CLOSE_OBJECT)?]),
        ),
        (
            "MAX_DEVICE_ATTACH_OBJECT",
            Expected::Values(vec![value(l::MAX_DEVICE_ATTACH_OBJECT)?]),
        ),
        (
            "MAX_FEDERATION_CONTROL_OBJECT",
            Expected::Values(vec![value(l::MAX_FEDERATION_CONTROL_OBJECT)?]),
        ),
        (
            "MAX_FEDERATION_STATE_ENTRIES_PER_EDGE",
            Expected::Values(vec![value(l::MAX_FEDERATION_STATE_ENTRIES_PER_EDGE)?]),
        ),
        (
            "MAX_FEDERATION_STATE_SNAPSHOT_BYTES_PER_EDGE",
            Expected::Values(vec![value(
                l::MAX_FEDERATION_STATE_SNAPSHOT_BYTES_PER_EDGE,
            )?]),
        ),
        (
            "FEDERATION_STATE_SNAPSHOT_TIMEOUT",
            Expected::Values(vec![value(l::FEDERATION_STATE_SNAPSHOT_TIMEOUT_SECONDS)?]),
        ),
        (
            "MAX_UNACKED_E2EE_EVENTS_PER_EDGE",
            Expected::Values(vec![value(l::MAX_UNACKED_E2EE_EVENTS_PER_EDGE)?]),
        ),
        (
            "MAX_UNACKED_E2EE_EVENT_BYTES_PER_EDGE",
            Expected::Values(vec![value(l::MAX_UNACKED_E2EE_EVENT_BYTES_PER_EDGE)?]),
        ),
        (
            "MAX_CROSS_PROFILE_EVENT_PARTS_PER_EDGE",
            Expected::Values(vec![value(l::MAX_CROSS_PROFILE_EVENT_PARTS_PER_EDGE)?]),
        ),
        (
            "MAX_CROSS_PROFILE_EVENT_BYTES_PER_EDGE",
            Expected::Values(vec![value(l::MAX_CROSS_PROFILE_EVENT_BYTES_PER_EDGE)?]),
        ),
        (
            "ACKED_E2EE_EVENT_REPLAY_TARGET",
            Expected::Values(vec![value(l::ACKED_E2EE_EVENT_REPLAY_TARGET_SECONDS)?]),
        ),
        (
            "MAX_ACKED_E2EE_EVENT_REPLAY_ROWS_PER_EDGE",
            Expected::Values(vec![value(l::MAX_ACKED_E2EE_EVENT_REPLAY_ROWS_PER_EDGE)?]),
        ),
        (
            "MAX_ACKED_E2EE_EVENT_REPLAY_BYTES_PER_EDGE",
            Expected::Values(vec![value(l::MAX_ACKED_E2EE_EVENT_REPLAY_BYTES_PER_EDGE)?]),
        ),
        (
            "MAX_WELCOME_MAILBOX_OBJECT",
            Expected::Values(vec![value(l::MAX_WELCOME_MAILBOX_OBJECT)?]),
        ),
        (
            "MAX_EMBEDDED_MLS_WELCOME_BYTES",
            Expected::Values(vec![value(l::MAX_EMBEDDED_MLS_WELCOME_BYTES)?]),
        ),
        (
            "MAX_JOIN_TRANSITION_PROOF_BUNDLE_BYTES",
            Expected::Values(vec![value(l::MAX_JOIN_TRANSITION_PROOF_BUNDLE_BYTES)?]),
        ),
        (
            "MAX_E2EE_SERVER_PREFIX_BYTES",
            Expected::Values(vec![value(l::MAX_E2EE_SERVER_PREFIX_BYTES)?]),
        ),
        (
            "MAX_SERIALIZED_ACCOUNT_TAG",
            Expected::Values(vec![value(l::MAX_SERIALIZED_ACCOUNT_TAG)?]),
        ),
        (
            "MAX_CANDIDATE_RECEIPT_TAG",
            Expected::Values(vec![value(l::MAX_CANDIDATE_RECEIPT_TAG)?]),
        ),
        (
            "MAX_FRAGMENT_RAW",
            Expected::Values(vec![value(l::MAX_FRAGMENT_RAW)?]),
        ),
        (
            "MAX_LIVE_FRAGMENT_COUNT",
            Expected::Values(vec![value(l::MAX_LIVE_FRAGMENT_COUNT)?]),
        ),
        (
            "MAX_MAILBOX_FRAGMENT_COUNT",
            Expected::Values(vec![value(l::MAX_MAILBOX_FRAGMENT_COUNT)?]),
        ),
        (
            "MAX_OPEN_REASSEMBLIES_PER_LOCAL_SENDER",
            Expected::Values(vec![value(l::MAX_OPEN_REASSEMBLIES_PER_LOCAL_SENDER)?]),
        ),
        (
            "MAX_OPEN_REMOTE_OBJECTS_PER_SENDER",
            Expected::Values(vec![value(l::MAX_OPEN_REMOTE_OBJECTS_PER_SENDER)?]),
        ),
        (
            "MAX_OPEN_REMOTE_OBJECTS_PER_CONNECTION",
            Expected::Values(vec![value(l::MAX_OPEN_REMOTE_OBJECTS_PER_CONNECTION)?]),
        ),
        (
            "MAX_LIVE_REASSEMBLY_BYTES_PER_CONNECTION",
            Expected::Values(vec![value(l::MAX_LIVE_REASSEMBLY_BYTES_PER_CONNECTION)?]),
        ),
        (
            "MAX_OPEN_REASSEMBLIES_PER_ACCOUNT",
            Expected::Values(vec![value(l::MAX_OPEN_REASSEMBLIES_PER_ACCOUNT)?]),
        ),
        (
            "MAX_REASSEMBLY_BYTES_PER_ACCOUNT",
            Expected::Values(vec![value(l::MAX_REASSEMBLY_BYTES_PER_ACCOUNT)?]),
        ),
        (
            "MAX_OPEN_REASSEMBLIES_PER_ROUTE",
            Expected::Values(vec![value(l::MAX_OPEN_REASSEMBLIES_PER_ROUTE)?]),
        ),
        (
            "MAX_REASSEMBLY_BYTES_PER_ROUTE",
            Expected::Values(vec![value(l::MAX_REASSEMBLY_BYTES_PER_ROUTE)?]),
        ),
        (
            "MAX_OPEN_REASSEMBLIES_PER_FEDERATION_PEER",
            Expected::Values(vec![value(l::MAX_OPEN_REASSEMBLIES_PER_FEDERATION_PEER)?]),
        ),
        (
            "MAX_REASSEMBLY_BYTES_PER_FEDERATION_PEER",
            Expected::Values(vec![value(l::MAX_REASSEMBLY_BYTES_PER_FEDERATION_PEER)?]),
        ),
        (
            "MAX_OPEN_REASSEMBLIES_GLOBAL",
            Expected::Values(vec![value(l::MAX_OPEN_REASSEMBLIES_GLOBAL)?]),
        ),
        (
            "MAX_REASSEMBLY_BYTES_GLOBAL",
            Expected::Values(vec![value(l::MAX_REASSEMBLY_BYTES_GLOBAL)?]),
        ),
        (
            "LIVE_REASSEMBLY_TIMEOUT",
            Expected::Values(vec![
                value(l::LIVE_REASSEMBLY_ABSOLUTE_SECONDS)?,
                value(l::LIVE_REASSEMBLY_IDLE_SECONDS)?,
            ]),
        ),
        (
            "MAILBOX_REASSEMBLY_TIMEOUT",
            Expected::Values(vec![
                value(l::MAILBOX_REASSEMBLY_ABSOLUTE_SECONDS)?,
                value(l::MAILBOX_REASSEMBLY_IDLE_SECONDS)?,
            ]),
        ),
        (
            "MIN_ADMITTED_E2EE_INGRESS_RATE",
            Expected::Values(vec![value(l::MIN_ADMITTED_E2EE_INGRESS_RATE)?]),
        ),
        (
            "MAX_RECIPIENT_E2EE_SENDQ",
            Expected::Values(vec![value(l::MAX_RECIPIENT_E2EE_SENDQ)?]),
        ),
        (
            "MAX_BATCH_OBJECTS",
            Expected::Values(vec![value(l::MAX_BATCH_OBJECTS)?]),
        ),
        (
            "MAX_BATCH_FRAGMENTS",
            Expected::Values(vec![value(l::MAX_BATCH_FRAGMENTS)?]),
        ),
        (
            "MAX_BATCH_DECODED_BYTES",
            Expected::Values(vec![value(l::MAX_BATCH_DECODED_BYTES)?]),
        ),
        (
            "RECENT_OBJECT_IDEMPOTENCY_RETENTION",
            Expected::Values(vec![value(l::RECENT_OBJECT_IDEMPOTENCY_RETENTION_SECONDS)?]),
        ),
        (
            "S2S_IDEMPOTENCY_RETENTION",
            Expected::Values(vec![value(l::S2S_IDEMPOTENCY_RETENTION_SECONDS)?]),
        ),
        (
            "MAX_ACTIVE_COMMIT_CANDIDATES",
            Expected::Values(vec![value(l::MAX_ACTIVE_COMMIT_CANDIDATES)?]),
        ),
        (
            "MAX_FINALITY_PRINCIPALS",
            Expected::Values(vec![value(l::MAX_FINALITY_PRINCIPALS)?]),
        ),
        (
            "MAX_BINDING_PRINCIPALS",
            Expected::Values(vec![value(l::MAX_BINDING_PRINCIPALS)?]),
        ),
        (
            "MAX_BINDING_APPROVALS",
            Expected::Values(vec![value(l::MAX_BINDING_APPROVALS)?]),
        ),
        (
            "MAX_CANDIDATE_ATTEMPTS_PER_EPOCH",
            Expected::Values(vec![value(l::MAX_CANDIDATE_ATTEMPTS_PER_EPOCH)?]),
        ),
        (
            "ENROLLMENT_CHALLENGE_TIMEOUT",
            Expected::Values(vec![value(l::ENROLLMENT_CHALLENGE_TIMEOUT_SECONDS)?]),
        ),
        (
            "RESERVATION_TIMEOUT",
            Expected::Values(vec![value(l::RESERVATION_TIMEOUT_SECONDS)?]),
        ),
        (
            "ATTACH_CHALLENGE_TIMEOUT",
            Expected::Values(vec![value(l::ATTACH_CHALLENGE_TIMEOUT_SECONDS)?]),
        ),
        (
            "MAILBOX_DELIVERY_TOKEN_TIMEOUT",
            Expected::Values(vec![value(l::MAILBOX_DELIVERY_TOKEN_TIMEOUT_SECONDS)?]),
        ),
        (
            "DIRECTORY_CURSOR_TIMEOUT",
            Expected::Values(vec![value(l::DIRECTORY_CURSOR_TIMEOUT_SECONDS)?]),
        ),
        (
            "MAX_COMMIT_CLOCK_SKEW",
            Expected::Values(vec![value(l::MAX_COMMIT_CLOCK_SKEW_SECONDS)?]),
        ),
        (
            "COMMIT_STAGING_TIMEOUT",
            Expected::Values(vec![value(l::COMMIT_STAGING_TIMEOUT_SECONDS)?]),
        ),
        (
            "JOIN_CONFIRMATION_TIMEOUT",
            Expected::Values(vec![value(l::JOIN_CONFIRMATION_TIMEOUT_SECONDS)?]),
        ),
        (
            "KEY_PACKAGE_CLAIM_TIMEOUT",
            Expected::Values(vec![value(l::KEY_PACKAGE_CLAIM_TIMEOUT_SECONDS)?]),
        ),
        (
            "MAILBOX_ACK_RETENTION",
            Expected::Values(vec![value(l::MAILBOX_ACK_RETENTION_SECONDS)?]),
        ),
        (
            "REINIT_STAGING_TIMEOUT",
            Expected::Values(vec![value(l::REINIT_STAGING_TIMEOUT_SECONDS)?]),
        ),
        (
            "MAX_COMMIT_SUBMISSIONS_PER_LEAF_PER_MINUTE",
            Expected::Values(vec![value(l::MAX_COMMIT_SUBMISSIONS_PER_LEAF_PER_MINUTE)?]),
        ),
        (
            "MAX_COMMIT_SUBMISSIONS_PER_CONVERSATION_PER_MINUTE",
            Expected::Values(vec![value(
                l::MAX_COMMIT_SUBMISSIONS_PER_CONVERSATION_PER_MINUTE,
            )?]),
        ),
        (
            "MAX_RATCHET_FORWARD_JUMP",
            Expected::Values(vec![value(l::MAX_RATCHET_FORWARD_JUMP)?]),
        ),
        (
            "MAX_SKIPPED_KEYS_PER_SENDER",
            Expected::Values(vec![value(l::MAX_SKIPPED_KEYS_PER_SENDER)?]),
        ),
        (
            "MAX_SKIPPED_KEY_BYTES_PER_CONVERSATION",
            Expected::Values(vec![value(l::MAX_SKIPPED_KEY_BYTES_PER_CONVERSATION)?]),
        ),
        (
            "SKIPPED_KEY_RETENTION",
            Expected::Values(vec![value(l::SKIPPED_KEY_RETENTION_SECONDS)?]),
        ),
        (
            "MAX_RETAINED_PAST_EPOCHS",
            Expected::Values(vec![value(l::MAX_RETAINED_PAST_EPOCHS)?]),
        ),
        (
            "PAST_EPOCH_RECEIVE_RETENTION",
            Expected::Values(vec![value(l::PAST_EPOCH_RECEIVE_RETENTION_SECONDS)?]),
        ),
        (
            "MAX_APPLICATION_SEQUENCE_FORWARD_JUMP",
            Expected::Values(vec![value(l::MAX_APPLICATION_SEQUENCE_FORWARD_JUMP)?]),
        ),
        (
            "MAX_APPLICATION_SEQUENCE_GAPS",
            Expected::Values(vec![value(l::MAX_APPLICATION_SEQUENCE_GAPS)?]),
        ),
        (
            "MAX_RECENT_MESSAGE_IDS_PER_LEAF",
            Expected::Values(vec![value(l::MAX_RECENT_MESSAGE_IDS_PER_LEAF)?]),
        ),
        (
            "MAX_REPLAY_GAP_STATE_BYTES_PER_CONVERSATION",
            Expected::Values(vec![value(l::MAX_REPLAY_GAP_STATE_BYTES_PER_CONVERSATION)?]),
        ),
        (
            "MAX_PROPOSALS_PER_COMMIT",
            Expected::Values(vec![value(l::MAX_PROPOSALS_PER_COMMIT)?]),
        ),
        (
            "MAX_GROUP_LEAVES",
            Expected::Values(vec![value(l::MAX_GROUP_LEAVES)?]),
        ),
        (
            "MAX_ACTIVE_DEVICES_PER_ACCOUNT",
            Expected::Values(vec![value(l::MAX_ACTIVE_DEVICES_PER_ACCOUNT)?]),
        ),
        (
            "MAX_KEY_PACKAGE_LIFETIME",
            Expected::Values(vec![value(l::MAX_KEY_PACKAGE_LIFETIME_SECONDS)?]),
        ),
        (
            "MAX_CAPABILITY_LIFETIME",
            Expected::Values(vec![value(l::MAX_CAPABILITY_LIFETIME_SECONDS)?]),
        ),
        (
            "MIN_KEY_PACKAGE_CLAIM_VALIDITY",
            Expected::Values(vec![value(l::MIN_KEY_PACKAGE_CLAIM_VALIDITY_SECONDS)?]),
        ),
        (
            "MAX_ROSTER_AGE_AT_ADD",
            Expected::Values(vec![value(l::MAX_ROSTER_AGE_AT_ADD_SECONDS)?]),
        ),
        (
            "MAX_ROSTER_LIFETIME",
            Expected::Values(vec![value(l::MAX_ROSTER_LIFETIME_SECONDS)?]),
        ),
        (
            "ROSTER_STALE_SEND_GRACE",
            Expected::Values(vec![value(l::ROSTER_STALE_SEND_GRACE_SECONDS)?]),
        ),
        (
            "MAX_MAILBOX_BYTES_PER_ACCOUNT",
            Expected::Values(vec![value(l::MAX_MAILBOX_BYTES_PER_ACCOUNT)?]),
        ),
        (
            "MAX_DIRECTORY_BYTES_PER_ACCOUNT",
            Expected::Values(vec![value(l::MAX_DIRECTORY_BYTES_PER_ACCOUNT)?]),
        ),
        (
            "MAX_STORED_BYTES_PER_CONVERSATION",
            Expected::Values(vec![value(l::MAX_STORED_BYTES_PER_CONVERSATION)?]),
        ),
        (
            "WELCOME_RETENTION",
            Expected::Values(vec![value(l::WELCOME_RETENTION_SECONDS)?]),
        ),
        (
            "SEQUENCER_RECORD_RETENTION",
            Expected::Values(vec![value(l::SEQUENCER_RECORD_RETENTION_SECONDS)?]),
        ),
        (
            "SECURITY_PROOF_RETENTION",
            Expected::Rule("live semantic lineage plus `WELCOME_RETENTION` after final close"),
        ),
        (
            "MAX_SEQUENCER_KEY_OVERLAP",
            Expected::Values(vec![value(l::MAX_SEQUENCER_KEY_OVERLAP_SECONDS)?]),
        ),
        (
            "MAX_LEAF_MEMBERSHIP_OBJECT",
            Expected::Values(vec![value(l::MAX_LEAF_MEMBERSHIP_OBJECT)?]),
        ),
        (
            "MAX_RECOVERY_SUBMISSION_OBJECT",
            Expected::Values(vec![value(l::MAX_RECOVERY_SUBMISSION_OBJECT)?]),
        ),
        (
            "MAX_OPEN_RECOVERY_SUBMISSIONS",
            Expected::Values(vec![value(l::MAX_OPEN_RECOVERY_SUBMISSIONS)?]),
        ),
        (
            "MAX_RECOVERY_CHAIN_BYTES",
            Expected::Values(vec![value(l::MAX_RECOVERY_CHAIN_BYTES)?]),
        ),
        (
            "MAX_RECOVERY_SUBMISSION_SECONDS",
            Expected::Values(vec![value(l::MAX_RECOVERY_SUBMISSION_SECONDS)?]),
        ),
        (
            "MAX_WITNESS_RESOLUTION_RECORDS",
            Expected::Values(vec![value(l::MAX_WITNESS_RESOLUTION_RECORDS)?]),
        ),
        (
            "MAX_WITNESS_RESOLUTION_BYTES",
            Expected::Values(vec![value(l::MAX_WITNESS_RESOLUTION_BYTES)?]),
        ),
        (
            "MAX_WITNESS_RESOLUTION_SECONDS",
            Expected::Values(vec![value(l::MAX_WITNESS_RESOLUTION_SECONDS)?]),
        ),
        (
            "REINIT_RESUMPTION_PSK_RETENTION",
            Expected::Values(vec![value(l::REINIT_RESUMPTION_PSK_RETENTION_SECONDS)?]),
        ),
        (
            "MAX_SIGNATURE_VERIFICATIONS_PER_ACCOUNT_PER_MINUTE",
            Expected::Values(vec![value(
                l::MAX_SIGNATURE_VERIFICATIONS_PER_ACCOUNT_PER_MINUTE,
            )?]),
        ),
        (
            "DEFAULT_ACTIVE_UPDATE_PERIOD",
            Expected::Values(vec![value(l::DEFAULT_ACTIVE_UPDATE_PERIOD_SECONDS)?]),
        ),
        (
            "DEFAULT_ACTIVE_UPDATE_MESSAGES",
            Expected::Values(vec![value(l::DEFAULT_ACTIVE_UPDATE_MESSAGES)?]),
        ),
        (
            "DEFAULT_IDLE_DEVICE_EVICTION",
            Expected::Values(vec![value(l::DEFAULT_IDLE_DEVICE_EVICTION_SECONDS)?]),
        ),
    ])
}

#[test]
fn every_section_16_row_equals_its_limits_constant() -> TestResult {
    let rows = section_16_rows()?;
    let expected = expected()?;
    let names: Vec<&str> = rows.iter().map(|(name, _)| name.as_str()).collect();
    let listed: Vec<&str> = expected.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        names, listed,
        "the table and this test name the same rows in order"
    );
    for ((name, default), (_, expected)) in rows.iter().zip(&expected) {
        match expected {
            Expected::Values(values) => {
                assert_eq!(&quantities(default)?, values, "{name}: {default}");
            }
            Expected::Rule(rule) => assert_eq!(default, rule, "{name}"),
        }
    }
    Ok(())
}

#[test]
fn the_endpoint_scalars_are_named_by_the_table() -> TestResult {
    let rows = section_16_rows()?;
    for name in [
        "MAX_RATCHET_FORWARD_JUMP",
        "MAX_SKIPPED_KEYS_PER_SENDER",
        "MAX_SKIPPED_KEY_BYTES_PER_CONVERSATION",
        "SKIPPED_KEY_RETENTION",
        "MAX_RETAINED_PAST_EPOCHS",
        "PAST_EPOCH_RECEIVE_RETENTION",
        "MAX_APPLICATION_SEQUENCE_FORWARD_JUMP",
        "MAX_APPLICATION_SEQUENCE_GAPS",
        "MAX_RECENT_MESSAGE_IDS_PER_LEAF",
        "MAX_REPLAY_GAP_STATE_BYTES_PER_CONVERSATION",
        "DEFAULT_ACTIVE_UPDATE_PERIOD",
        "DEFAULT_ACTIVE_UPDATE_MESSAGES",
        "DEFAULT_IDLE_DEVICE_EVICTION",
    ] {
        assert_eq!(
            rows.iter().filter(|(row, _)| row == name).count(),
            1,
            "{name} is one Section 16 row"
        );
    }
    Ok(())
}

#[test]
fn the_default_grammar_is_read_in_canonical_units() -> TestResult {
    assert_eq!(quantities("32,768 bytes")?, vec![32_768]);
    assert_eq!(
        quantities("2 minutes absolute, 15 seconds idle")?,
        vec![120, 15]
    );
    assert_eq!(quantities("5 minutes; zero for removed leaves")?, vec![300]);
    assert_eq!(quantities("1 hour")?, vec![3_600]);
    assert_eq!(quantities("30 days")?, vec![2_592_000]);
    assert_eq!(quantities("8 per conversation")?, vec![8]);
    assert!(quantities("3 fortnights").is_err());
    assert!(quantities("live semantic lineage").is_err());
    assert!(quantities("18446744073709551615 days").is_err());
    Ok(())
}
