#![forbid(unsafe_code)]

//! The domain crate's copies of the companion limits equal the e2ee table.

use agenc_relay_domain::e2ee::limits as domain;
use agenc_relay_e2ee::limits as e2ee;

#[test]
fn the_domain_limit_copies_match_the_companion_table() {
    assert_eq!(
        domain::MAX_CANDIDATE_ATTEMPTS_PER_EPOCH,
        e2ee::MAX_CANDIDATE_ATTEMPTS_PER_EPOCH
    );
    assert_eq!(
        domain::MIN_KEY_PACKAGE_CLAIM_VALIDITY_SECONDS,
        e2ee::MIN_KEY_PACKAGE_CLAIM_VALIDITY_SECONDS
    );
    assert_eq!(
        domain::MAX_KEY_PACKAGE_LIFETIME_SECONDS,
        e2ee::MAX_KEY_PACKAGE_LIFETIME_SECONDS
    );
    assert_eq!(
        domain::KEY_PACKAGE_CLAIM_TIMEOUT_SECONDS,
        e2ee::KEY_PACKAGE_CLAIM_TIMEOUT_SECONDS
    );
    assert_eq!(
        domain::JOIN_CONFIRMATION_TIMEOUT_SECONDS,
        e2ee::JOIN_CONFIRMATION_TIMEOUT_SECONDS
    );
    assert_eq!(
        domain::ATTACH_CHALLENGE_TIMEOUT_SECONDS,
        e2ee::ATTACH_CHALLENGE_TIMEOUT_SECONDS
    );
    assert_eq!(
        domain::MAILBOX_DELIVERY_TOKEN_TIMEOUT_SECONDS,
        e2ee::MAILBOX_DELIVERY_TOKEN_TIMEOUT_SECONDS
    );
    assert_eq!(
        domain::MAILBOX_ACK_RETENTION_SECONDS,
        e2ee::MAILBOX_ACK_RETENTION_SECONDS
    );
    assert_eq!(
        domain::WELCOME_RETENTION_SECONDS,
        e2ee::WELCOME_RETENTION_SECONDS
    );
    assert_eq!(domain::MAX_BATCH_OBJECTS, e2ee::MAX_BATCH_OBJECTS);
    assert_eq!(
        domain::MAX_ACTIVE_DEVICES_PER_ACCOUNT,
        usize::from(e2ee::MAX_ACTIVE_DEVICES_PER_ACCOUNT)
    );
    assert_eq!(
        domain::MAX_UNACKED_E2EE_EVENTS_PER_EDGE,
        e2ee::MAX_UNACKED_E2EE_EVENTS_PER_EDGE
    );
    assert_eq!(
        domain::MAX_UNACKED_E2EE_EVENT_BYTES_PER_EDGE,
        e2ee::MAX_UNACKED_E2EE_EVENT_BYTES_PER_EDGE
    );
    assert_eq!(domain::MAX_CROSS_PROFILE_PARTS, 2_048);
    assert_eq!(domain::MAX_CROSS_PROFILE_AGGREGATE_BYTES, 16_777_216);
}
