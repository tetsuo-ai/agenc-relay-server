#![forbid(unsafe_code)]

//! Reply codes.

use std::collections::BTreeSet;

use super::*;

#[test]
fn the_registry_holds_twenty_distinct_codes() {
    let tokens: BTreeSet<&str> = E2eeReplyCode::ALL.iter().map(|code| code.token()).collect();
    assert_eq!(tokens.len(), 20);
    for code in E2eeReplyCode::ALL {
        assert!(code.token().starts_with("E2EE_"));
        assert_eq!(E2eeReplyCode::from_token(code.token()), Some(code));
        assert!(!code.description().is_empty());
        assert_eq!(code.to_string(), code.token());
    }
    assert_eq!(E2eeReplyCode::from_token("E2EE_UNKNOWN"), None);
    assert_eq!(E2eeReplyCode::Required.token(), "E2EE_REQUIRED");
    assert_eq!(E2eeReplyCode::Syncing.token(), "E2EE_SYNCING");
    assert_eq!(E2eeReplyCode::CapRequired.token(), "E2EE_CAP_REQUIRED");
    assert_eq!(
        E2eeReplyCode::DeliveryUncertain.token(),
        "E2EE_DELIVERY_UNCERTAIN"
    );
}

#[test]
fn fail_lines_follow_the_standard_replies_form() {
    assert_eq!(
        E2eeReplyCode::InvalidFragment.render_fail("EGROUP", None),
        "FAIL EGROUP E2EE_INVALID_FRAGMENT :fragment grammar, encoding, or consistency failed"
    );
    assert_eq!(
        E2eeReplyCode::Required.render_fail("PRIVMSG", Some("#room")),
        "FAIL PRIVMSG E2EE_REQUIRED #room :plaintext is forbidden for the target"
    );
    assert_eq!(
        E2eeReplyCode::AccountRequired.render_fail("*", None),
        "FAIL * E2EE_ACCOUNT_REQUIRED :an authenticated account is required"
    );
}
