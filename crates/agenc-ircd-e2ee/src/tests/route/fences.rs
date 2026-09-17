#![forbid(unsafe_code)]

//! A semantic route carries exactly the fields of its own kind, and a
//! replacement binding carries no approval of its own.

use super::*;

type FenceResult = Result<(), Box<dyn Error>>;

#[test]
fn a_route_of_a_later_profile_is_refused_before_its_kind_is_read() -> FenceResult {
    let mut later = channel_route(b"#room", [5; 32])?;
    later.profile_version = PROFILE_VERSION.saturating_add(1);
    assert_eq!(
        verify_semantic_route(&NETWORK, &later).map(|_| ()),
        Err(E2eeError::ProfileMismatch),
        "the profile version is refused although the network matches"
    );
    later.profile_version = PROFILE_VERSION;
    assert_eq!(
        verify_semantic_route(&NETWORK, &later)?.kind,
        IrcConversationKind::Channel
    );
    Ok(())
}

#[test]
fn a_channel_route_carries_no_direct_account_and_a_direct_route_no_authority() -> FenceResult {
    let accepted = verify_semantic_route(&NETWORK, &channel_route(b"#room", [5; 32])?)?;
    assert!(matches!(accepted.key, SemanticRouteKey::Channel { .. }));

    let mut first_account = channel_route(b"#room", [5; 32])?;
    first_account.direct_account_a = Opaque::from_slice(&ACCOUNT)?;
    assert_eq!(
        verify_semantic_route(&NETWORK, &first_account).map(|_| ()),
        Err(E2eeError::InvalidValue),
        "a channel route names no first direct account"
    );

    let mut second_account = channel_route(b"#room", [5; 32])?;
    second_account.direct_account_b = Opaque::from_slice(&OTHER_ACCOUNT)?;
    assert!(
        second_account.direct_account_a.is_empty(),
        "only the second account differs from the accepted route"
    );
    assert_eq!(
        verify_semantic_route(&NETWORK, &second_account).map(|_| ()),
        Err(E2eeError::InvalidValue),
        "a channel route names no second direct account"
    );

    let direct = verify_semantic_route(&NETWORK, &direct_route(&ACCOUNT, &OTHER_ACCOUNT)?)?;
    assert!(matches!(direct.key, SemanticRouteKey::Direct { .. }));
    let mut pinned_authority = direct_route(&ACCOUNT, &OTHER_ACCOUNT)?;
    pinned_authority.channel_authority_root_fingerprint = [9; 32];
    assert!(
        pinned_authority.canonical_channel_name.is_empty(),
        "only the authority root differs from the accepted route"
    );
    assert_eq!(
        verify_semantic_route(&NETWORK, &pinned_authority).map(|_| ()),
        Err(E2eeError::InvalidValue),
        "a direct route pins no channel authority root"
    );
    Ok(())
}

#[test]
fn a_replacement_binding_carries_neither_approvals_nor_locks() -> FenceResult {
    let principals = vec![principal(42, &ACCOUNT, &[7])?];
    let rosters = rosters(&principals)?;
    let authority = root_fingerprint(&principals.first().ok_or("principal")?.root)?;
    let spec = BindingSpec {
        principals: &principals,
        route: channel_route(b"#room", authority)?,
        channel_instance_id: Some([1; 16]),
        conversation_nonce: None,
        group_id: [26; 32],
        generation: 0,
        previous_binding_id: [0; 32],
        lock_sequence: 0,
        plan_devices: vec![(&ACCOUNT, authority, 7)],
    };
    let first = binding_package(&spec)?;
    let verified = verify_binding_package(&NETWORK, &first, &rosters)?;
    let replacement = binding_package(&BindingSpec {
        route: channel_route(b"#room", authority)?,
        generation: 1,
        previous_binding_id: verified.binding_id,
        plan_devices: vec![(&ACCOUNT, authority, 7)],
        ..spec
    })?;
    assert_eq!(
        verify_binding_package(&NETWORK, &replacement, &rosters)?.generation,
        1,
        "the replacement is accepted with no proof of its own"
    );

    let mut approved_replacement = replacement;
    approved_replacement.binding.approvals = first.binding.approvals.clone();
    assert!(
        approved_replacement.root_binding_locks.is_empty(),
        "only the approvals differ from the accepted replacement"
    );
    assert_eq!(
        verify_binding_package(&NETWORK, &approved_replacement, &rosters),
        Err(E2eeError::InvalidValue),
        "only an initial binding carries unanimous approvals"
    );
    Ok(())
}
